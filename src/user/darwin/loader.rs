//! Loading a Mach-O program into a fresh address space (`exec`).
//!
//! [`load`] performs what `exec_mach_imgact` does after the image
//! activators have chosen a slice: map the executable (`load_machfile`),
//! map the dynamic linker after it (`load_dylinker`), reserve the stack
//! (`create_unix_stack`), map the commpage (`vm_map_exec`), build the
//! `apple[]` strings (`exec_add_apple_strings`), and copy the argument
//! vectors onto the stack (`exec_copyout_strings`), pushing the
//! executable's Mach-O header address for `dyld`. ASLR is disabled, as for
//! a process spawned with `_POSIX_SPAWN_DISABLE_ASLR`: every slide is zero.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::abi::DarwinAbi;
use super::commpage::{self, MachineInfo};
use super::stack::{self, StackError, StackStrings};
use super::vm::{self, VmFlags};
use crate::user::image::macho::{
    self, EntryCommand, ImageRole, LoadOptions, MachOError, MachOImage, ThreadState,
};
use crate::user::mm::{AddressSpace, Backing, BytesSource, Mapping, MmError, Perms};

/// `DFLSSIZ`: the default `RLIMIT_STACK` soft limit (8 MiB, less one
/// 16 KiB page on Apple silicon).
pub fn default_stack_limit(abi: DarwinAbi) -> u64 {
    match abi {
        DarwinAbi::X86_64 => 8 << 20,
        DarwinAbi::Arm64 => (8 << 20) - (16 << 10),
    }
}

/// The path `load_dylinker` requires (`DEFAULT_DYLD_PATH`).
pub const DYLD_PATH: &str = "/usr/lib/dyld";

/// An executable file read for `exec`.
#[derive(Clone)]
pub struct ImageFile {
    /// Guest path.
    pub path: String,
    /// Host path it was read from.
    pub host_path: PathBuf,
    /// Contents.
    pub bytes: Arc<[u8]>,
    /// `(st_dev, st_ino)` of the file.
    pub file_id: (u64, u64),
}

impl fmt::Debug for ImageFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageFile")
            .field("path", &self.path)
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl ImageFile {
    /// Reads `host_path` as the executable at guest path `path`.
    pub fn read(path: impl Into<String>, host_path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(host_path)?;
        let bytes = std::fs::read(host_path)?;
        Ok(ImageFile {
            path: path.into(),
            host_path: host_path.to_path_buf(),
            bytes: bytes.into(),
            file_id: (meta.dev(), meta.ino()),
        })
    }
}

/// Why a program could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The image is not an executable the kernel accepts.
    Image(MachOError),
    /// The dynamic linker could not be read.
    Dylinker(String, std::io::Error),
    /// The dynamic linker is not acceptable.
    DylinkerImage(MachOError),
    /// A mapping failed.
    Memory(MmError),
    /// The stack could not be built.
    Stack(StackError),
}

impl LoadError {
    /// The `errno` `execve` reports.
    pub fn errno(&self) -> i32 {
        match self {
            LoadError::Image(e) | LoadError::DylinkerImage(e) => e.errno(),
            // get_macho_vnode: LOAD_ENOENT, otherwise LOAD_FAILURE.
            LoadError::Dylinker(_, e) if e.kind() == std::io::ErrorKind::NotFound => 2,
            LoadError::Dylinker(..) => 85,
            LoadError::Memory(_) => 12,
            LoadError::Stack(StackError::TooBig) => 7,
            LoadError::Stack(StackError::Fault(_)) => 14,
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Image(e) => write!(f, "{e}"),
            LoadError::Dylinker(p, e) => write!(f, "cannot read dynamic linker {p}: {e}"),
            LoadError::DylinkerImage(e) => write!(f, "dynamic linker: {e}"),
            LoadError::Memory(e) => write!(f, "{e}"),
            LoadError::Stack(StackError::TooBig) => f.write_str("argument list too long"),
            LoadError::Stack(StackError::Fault(a)) => write!(f, "stack write faulted at {a:#x}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<MmError> for LoadError {
    fn from(e: MmError) -> Self {
        LoadError::Memory(e)
    }
}

/// The main thread's stack, as `main_stack=` reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MainStack {
    /// Top of the stack (`user_stack`).
    pub top: u64,
    /// Usable size (`user_stack_size`).
    pub size: u64,
    /// Base of the reservation, guard included (`user_stack_alloc`).
    pub alloc: u64,
    /// Size of the reservation (`user_stack_alloc_size`).
    pub alloc_size: u64,
}

/// A loaded program, ready for its first thread.
#[derive(Clone, Debug)]
pub struct LoadedProgram {
    /// The ABI.
    pub abi: DarwinAbi,
    /// The executable's guest path.
    pub path: String,
    /// The executable.
    pub main: MachOImage,
    /// The dynamic linker, when the executable uses one.
    pub dyld: Option<MachOImage>,
    /// Where the first thread starts.
    pub entry: u64,
    /// The register state `LC_UNIXTHREAD` supplies (dyld's when it runs
    /// the program).
    pub thread_state: Option<ThreadState>,
    /// The first thread's stack pointer.
    pub sp: u64,
    /// The main thread's stack.
    pub stack: MainStack,
    /// Where the initial stack's vectors are.
    pub layout: stack::StackLayout,
    /// The executable's Mach-O header address.
    pub mach_header: u64,
    /// `dyld`'s `__all_image_info` section (`TASK_DYLD_INFO`).
    pub all_image_info: Option<(u64, u64)>,
    /// The lowest address the process may map (the end of page zero).
    pub vm_min: u64,
    /// Where anonymous allocations start (after the executable and dyld).
    pub mmap_base: u64,
    /// The executable file.
    pub image: ImageFile,
}

/// What `exec` needs besides the image.
#[derive(Clone, Debug)]
pub struct ExecParams<'a> {
    /// `argv`.
    pub argv: &'a [Vec<u8>],
    /// `envp`.
    pub envp: &'a [Vec<u8>],
    /// The dynamic linker's file (read by the caller through the root).
    pub dyld: Option<&'a ImageFile>,
    /// `RLIMIT_STACK` soft limit.
    pub stack_limit: u64,
    /// Random bytes for the entropy strings (`stack_guard`,
    /// `malloc_entropy`, `ptr_munge`): 32 bytes.
    pub entropy: [u8; 32],
    /// The main thread's port name (`th_port=`).
    pub thread_port: u32,
    /// Machine facts for the commpage.
    pub machine: MachineInfo,
}

/// Selects the slice of `image` for `abi` and parses it as the main
/// executable.
pub fn parse_executable(
    image: &ImageFile,
    abi: DarwinAbi,
) -> Result<(u64, MachOImage), MachOError> {
    let (offset, slice) = macho::select_slice(&image.bytes, abi.host_cpu())?;
    let img = MachOImage::parse(
        slice,
        &LoadOptions {
            host: abi.host_cpu(),
            role: ImageRole::Executable,
            slide: 0,
            slice_offset: offset,
        },
    )?;
    Ok((offset, img))
}

/// The ABI a file's best slice runs as, trying `preferred` first.
pub fn choose_abi(bytes: &[u8], preferred: Option<DarwinAbi>) -> Result<DarwinAbi, MachOError> {
    let order: Vec<DarwinAbi> = match preferred {
        Some(p) => vec![p],
        None => match macho::identify(bytes)? {
            macho::Identity::Thin(h) => {
                return DarwinAbi::from_cputype(h.cputype).ok_or(MachOError::Load(
                    macho::LoadReturn::BadArch,
                    "unsupported CPU type",
                ));
            }
            // A fat file: the host's own architecture first.
            macho::Identity::Fat => {
                if cfg!(target_arch = "x86_64") {
                    vec![DarwinAbi::X86_64, DarwinAbi::Arm64]
                } else {
                    vec![DarwinAbi::Arm64, DarwinAbi::X86_64]
                }
            }
        },
    };
    let mut last = MachOError::Load(macho::LoadReturn::BadArch, "no runnable slice");
    for abi in order {
        match macho::select_slice(bytes, abi.host_cpu()) {
            Ok(_) => return Ok(abi),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn map_segments(
    space: &AddressSpace,
    img: &MachOImage,
    file: &ImageFile,
    slice_offset: u64,
) -> Result<(), LoadError> {
    let source = Arc::new(BytesSource::new(file.bytes.clone()));
    for m in &img.mappings {
        let flags = VmFlags::new(m.maxprot, vm::VM_INHERIT_COPY, 0).bits();
        let name: Arc<str> = Arc::from(file.path.as_str());
        if m.file_len > 0 {
            space.map(
                m.vm_start,
                m.file_len,
                Mapping {
                    perms: vm::perms(m.initprot),
                    backing: Backing::Source {
                        source: source.clone(),
                        offset: slice_offset + m.file_start,
                    },
                    shared: false,
                    name: Some(name.clone()),
                    flags,
                },
            )?;
        }
        if m.zero_len > 0 {
            space.map(
                m.vm_start + m.file_len,
                m.zero_len,
                Mapping {
                    flags,
                    ..Mapping::anonymous(vm::perms(m.initprot)).named(name)
                },
            )?;
        }
    }
    Ok(())
}

fn hex_list(key: &str, values: &[u64]) -> Vec<u8> {
    let mut s = String::from(key);
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{v:#x}"));
    }
    s.into_bytes()
}

/// Loads `image` into the empty `space` and builds the first thread's
/// stack.
pub fn load(
    space: &AddressSpace,
    abi: DarwinAbi,
    image: &ImageFile,
    params: &ExecParams<'_>,
) -> Result<LoadedProgram, LoadError> {
    let page = abi.page_size();
    let page_mask = page - 1;
    let (slice_offset, main) = parse_executable(image, abi).map_err(LoadError::Image)?;
    map_segments(space, &main, image, slice_offset)?;

    // The dynamic linker, after the executable.
    let mut dyld_img = None;
    let mut max_vm = main.max_vm_addr;
    if let Some(name) = &main.dylinker {
        // load_dylinker: release kernels load only /usr/lib/dyld.
        if name != DYLD_PATH {
            return Err(LoadError::Image(MachOError::Load(
                macho::LoadReturn::BadMachO,
                "the dynamic linker is not /usr/lib/dyld",
            )));
        }
        let file = params.dyld.ok_or_else(|| {
            LoadError::Dylinker(
                DYLD_PATH.into(),
                std::io::Error::from(std::io::ErrorKind::NotFound),
            )
        })?;
        let (offset, slice) = match macho::identify(&file.bytes)
            .map_err(LoadError::DylinkerImage)?
        {
            macho::Identity::Fat => {
                let arches =
                    macho::fat_arches(&file.bytes, page).map_err(LoadError::DylinkerImage)?;
                let a = macho::arch_for_cputype(&arches, abi.host_cpu(), abi.host_cpu().cputype)
                    .map_err(LoadError::DylinkerImage)?;
                let start = a.offset as usize;
                (
                    u64::from(a.offset),
                    &file.bytes[start..start + a.size as usize],
                )
            }
            macho::Identity::Thin(h) => {
                if h.cputype != abi.host_cpu().cputype {
                    return Err(LoadError::DylinkerImage(MachOError::Load(
                        macho::LoadReturn::BadArch,
                        "dyld is for another CPU",
                    )));
                }
                (0, &file.bytes[..])
            }
        };
        let d = MachOImage::parse(
            slice,
            &LoadOptions {
                host: abi.host_cpu(),
                role: ImageRole::Dylinker {
                    main_max_vm_addr: main.max_vm_addr,
                },
                slide: 0,
                slice_offset: offset,
            },
        )
        .map_err(LoadError::DylinkerImage)?;
        map_segments(space, &d, file, offset)?;
        max_vm = max_vm.max(d.max_vm_addr);
        dyld_img = Some(d);
    }

    // create_unix_stack.
    let top = main.user_stack;
    let mut stack = MainStack {
        top,
        size: main.user_stack_size,
        alloc: 0,
        alloc_size: 0,
    };
    if main.user_stack_alloc_size > 0 {
        let size = (main.user_stack_alloc_size + page_mask) & !page_mask;
        let base = (top - size) & !page_mask;
        space.map(
            base,
            top - base,
            Mapping {
                flags: VmFlags::new(
                    vm::VM_PROT_DEFAULT,
                    vm::VM_INHERIT_COPY,
                    vm::VM_MEMORY_STACK,
                )
                .bits(),
                ..Mapping::anonymous(Perms::READ | Perms::WRITE).named("[stack]")
            },
        )?;
        let prot_size = if stack.size == 0 {
            stack.size = params.stack_limit;
            (size.saturating_sub(stack.size)) & !page_mask
        } else {
            page
        };
        if prot_size > 0 {
            space.protect(base, prot_size, Perms::empty())?;
        }
        stack.alloc = base;
        stack.alloc_size = top - base;
    }

    // The commpage.
    for p in commpage::build(abi, &params.machine) {
        let perms = if p.exec {
            Perms::READ | Perms::EXEC
        } else {
            Perms::READ
        };
        space.map(
            p.addr,
            p.bytes.len() as u64,
            Mapping {
                perms,
                backing: Backing::Source {
                    source: Arc::new(BytesSource::new(p.bytes.into())),
                    offset: 0,
                },
                shared: false,
                name: Some(Arc::from("[commpage]")),
                flags: VmFlags::new(
                    if p.exec {
                        vm::VM_PROT_READ | vm::VM_PROT_EXECUTE
                    } else {
                        vm::VM_PROT_READ
                    },
                    vm::VM_INHERIT_SHARE,
                    0,
                )
                .bits(),
            },
        )?;
    }

    // exec_add_apple_strings.
    let e = &params.entropy;
    let word = |i: usize| u64::from_le_bytes(e[8 * i..8 * i + 8].try_into().expect("8 bytes"));
    // The stack guard embeds a NUL in its second byte.
    let guard = word(0) & !(0xff << 8);
    let mut apple = vec![
        format!("pfz={:#x}", commpage::text_address(abi)).into_bytes(),
        hex_list("stack_guard=", &[guard]),
        hex_list("malloc_entropy=", &[word(1), word(2)]),
        hex_list("ptr_munge=", &[word(3)]),
        hex_list(
            "main_stack=",
            &[stack.top, stack.size, stack.alloc, stack.alloc_size],
        ),
        hex_list("executable_file=", &[image.file_id.0, image.file_id.1]),
    ];
    if let Some(d) = params.dyld
        && dyld_img.is_some()
    {
        apple.push(hex_list("dyld_file=", &[d.file_id.0, d.file_id.1]));
    }
    apple.push(format!("th_port={:#x}", params.thread_port).into_bytes());
    apple.push(b"security_config=0x0".to_vec());

    let strings = StackStrings {
        exec_path: image.path.clone().into_bytes(),
        argv: params.argv.to_vec(),
        envp: params.envp.to_vec(),
        apple,
    };
    let mh = dyld_img.as_ref().map(|_| main.mach_header);
    let layout = stack::write(space, &strings, top, mh).map_err(LoadError::Stack)?;

    let (entry, thread_state) = match &dyld_img {
        Some(d) => (
            d.entry_point.unwrap_or(0),
            match &d.entry {
                Some(EntryCommand::UnixThread(s)) => Some(s.clone()),
                _ => None,
            },
        ),
        None => (
            main.entry_point.unwrap_or(0),
            match &main.entry {
                Some(EntryCommand::UnixThread(s)) => Some(s.clone()),
                _ => None,
            },
        ),
    };
    let all_image_info = dyld_img.as_ref().and_then(|d| d.all_image_info);
    let mmap_base = (max_vm + page_mask) & !page_mask;
    Ok(LoadedProgram {
        abi,
        path: image.path.clone(),
        mach_header: main.mach_header,
        vm_min: main.pagezero_end,
        main,
        dyld: dyld_img,
        entry,
        thread_state,
        sp: layout.sp,
        stack,
        layout,
        all_image_info,
        mmap_base,
        image: image.clone(),
    })
}
