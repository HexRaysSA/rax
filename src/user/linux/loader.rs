//! Linux `binfmt_elf` program loading.
//!
//! Reproduces `load_elf_binary`, `load_elf_interp`, and `elf_load` of Linux
//! 6.19 (`fs/binfmt_elf.c`) with address-space randomization disabled
//! (`personality(ADDR_NO_RANDOMIZE)`, `setarch -R`), so an image lands at the
//! addresses a real kernel would choose:
//!
//! - `ET_EXEC` segments map at their link addresses;
//! - an `ET_DYN` program with `PT_INTERP` (a PIE) loads at `ELF_ET_DYN_BASE`
//!   rounded down to `maximum_alignment()`;
//! - an `ET_DYN` program without `PT_INTERP` (a static PIE or a directly
//!   invoked loader), and every interpreter, loads where a top-down `mmap`
//!   of its whole span lands below the mmap base.
//!
//! Each `PT_LOAD` maps its file pages privately with the segment's
//! permissions. When `p_memsz > p_filesz` the rest of the last file page is
//! zeroed if the segment is writable (`padzero`; for a read-only segment the
//! kernel's write fails and is ignored, leaving the file bytes), and the
//! remaining pages are anonymous read-write memory, executable only if the
//! segment is (`vm_brk_flags`).

use std::sync::Arc;

use super::abi::{LinuxAbi, MMAP_MIN_ADDR, PAGE_SIZE, vma_flags};
use crate::user::image::elf::{
    ET_DYN, ET_EXEC, ElfError, ElfImage, PF_R, PF_W, PF_X, ProgramHeader, identify,
};
use crate::user::mm::{AddressSpace, Backing, BytesSource, Mapping, MmError, PageSource, Perms};

const PAGE_MASK: u64 = PAGE_SIZE - 1;

fn page_start(x: u64) -> u64 {
    x & !PAGE_MASK
}

fn page_align(x: u64) -> Option<u64> {
    x.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK)
}

/// Why `execve` of an image failed. [`LoadError::errno`] is the value the
/// kernel returns.
#[derive(Debug)]
pub enum LoadError {
    /// The file is not an ELF image this ABI executes (`ENOEXEC`).
    NotExecutable(String),
    /// The ELF image is malformed (`ENOEXEC` or `EIO`).
    Elf(ElfError),
    /// The interpreter named by `PT_INTERP` could not be opened.
    Interpreter { path: String, error: std::io::Error },
    /// The interpreter image is malformed or of the wrong architecture.
    BadInterpreter(String),
    /// A segment does not fit in the user address space (`EINVAL`/`ENOMEM`).
    BadSegment(String),
    /// A fixed mapping collides with an existing one (`EEXIST`).
    Collision(u64),
    /// A mapping lies below `vm.mmap_min_addr` (`EPERM`).
    BelowMinAddr(u64),
    /// Address-space failure (`ENOMEM`).
    Memory(MmError),
}

impl LoadError {
    /// The `errno` `execve` reports.
    pub fn errno(&self) -> i32 {
        use super::abi::errno_table::*;
        match self {
            LoadError::NotExecutable(_) | LoadError::BadInterpreter(_) => ENOEXEC,
            LoadError::Elf(ElfError::Truncated { .. } | ElfError::PhdrTableOutOfBounds { .. }) => {
                EIO
            }
            LoadError::Elf(_) => ENOEXEC,
            LoadError::Interpreter { error, .. } => super::abi::errno::from_io_error(error),
            LoadError::BadSegment(_) => EINVAL,
            LoadError::Collision(_) => EEXIST,
            LoadError::BelowMinAddr(_) => EPERM,
            LoadError::Memory(_) => ENOMEM,
        }
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NotExecutable(why) => write!(f, "not executable: {why}"),
            LoadError::Elf(e) => write!(f, "{e}"),
            LoadError::Interpreter { path, error } => {
                write!(f, "cannot open interpreter {path}: {error}")
            }
            LoadError::BadInterpreter(why) => write!(f, "bad interpreter: {why}"),
            LoadError::BadSegment(why) => write!(f, "bad segment: {why}"),
            LoadError::Collision(addr) => {
                write!(f, "segment at {addr:#x} collides with an existing mapping")
            }
            LoadError::BelowMinAddr(addr) => {
                write!(f, "segment at {addr:#x} lies below vm.mmap_min_addr")
            }
            LoadError::Memory(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<ElfError> for LoadError {
    fn from(e: ElfError) -> Self {
        LoadError::Elf(e)
    }
}

impl From<MmError> for LoadError {
    fn from(e: MmError) -> Self {
        LoadError::Memory(e)
    }
}

/// An executable file's bytes and diagnostic name.
#[derive(Clone)]
pub struct ImageFile {
    /// The whole file.
    pub bytes: Arc<[u8]>,
    /// Name shown in `/proc/self/maps` (the path the guest used).
    pub name: Arc<str>,
}

impl ImageFile {
    /// Wraps `bytes` named `name`.
    pub fn new(bytes: impl Into<Arc<[u8]>>, name: impl Into<Arc<str>>) -> Self {
        ImageFile {
            bytes: bytes.into(),
            name: name.into(),
        }
    }

    fn source(&self) -> Arc<dyn PageSource> {
        Arc::new(BytesSource::new(self.bytes.clone()))
    }
}

/// The result of loading a program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedProgram {
    /// Where execution starts: the interpreter's entry if there is one.
    pub entry: u64,
    /// `AT_ENTRY`: the program's own entry point.
    pub program_entry: u64,
    /// `AT_PHDR`.
    pub phdr: u64,
    /// `AT_PHENT`.
    pub phent: u64,
    /// `AT_PHNUM`.
    pub phnum: u64,
    /// `AT_BASE`: the interpreter's load address, or zero.
    pub interp_base: u64,
    /// The program's load bias (zero for `ET_EXEC`).
    pub load_bias: u64,
    /// Initial program break (`mm->start_brk`).
    pub brk: u64,
    /// `PT_GNU_STACK` requests an executable stack.
    pub exec_stack: bool,
    /// The interpreter path from `PT_INTERP`, if any.
    pub interp_path: Option<Vec<u8>>,
    /// Lowest executable segment start (`mm->start_code`).
    pub start_code: u64,
    /// End of executable file data (`mm->end_code`).
    pub end_code: u64,
    /// Highest segment start (`mm->start_data`).
    pub start_data: u64,
    /// End of file-backed data (`mm->end_data`).
    pub end_data: u64,
}

/// Resolves the path in `PT_INTERP` to the interpreter image.
pub trait InterpreterResolver {
    /// Opens the interpreter at guest path `path`.
    fn open_interpreter(&mut self, path: &[u8]) -> std::io::Result<ImageFile>;
}

impl<F: FnMut(&[u8]) -> std::io::Result<ImageFile>> InterpreterResolver for F {
    fn open_interpreter(&mut self, path: &[u8]) -> std::io::Result<ImageFile> {
        self(path)
    }
}

/// Converts `p_flags` to effective page permissions for `abi`
/// (`make_prot` plus the architecture's `protection_map`).
pub fn segment_perms(abi: LinuxAbi, p_flags: u32) -> Perms {
    prot_to_perms(
        abi,
        p_flags & PF_R != 0,
        p_flags & PF_W != 0,
        p_flags & PF_X != 0,
    )
}

/// Effective page permissions of an `mmap`/`mprotect` protection on `abi`:
/// write implies read on every supported architecture, and execute implies
/// read except on RISC-V.
pub fn prot_to_perms(abi: LinuxAbi, read: bool, write: bool, exec: bool) -> Perms {
    let mut p = Perms::empty();
    if read || write || (exec && abi.exec_implies_read()) {
        p |= Perms::READ;
    }
    if write {
        p |= Perms::WRITE;
    }
    if exec {
        p |= Perms::EXEC;
    }
    p
}

/// Loader state for one `execve`.
struct Loader<'a> {
    abi: LinuxAbi,
    space: &'a AddressSpace,
    task_size: u64,
    mmap_base: u64,
}

impl Loader<'_> {
    fn bad_addr(&self, addr: u64) -> bool {
        addr >= self.task_size
    }

    /// `elf_check_arch`.
    fn check_arch(&self, image: &ElfImage<'_>) -> bool {
        let class = identify(image.bytes()).ok().and_then(|i| i.elf_class());
        LinuxAbi::from_elf(image.header().e_machine, class) == Some(self.abi)
    }

    /// The per-segment checks of `load_elf_binary`/`load_elf_interp`:
    /// `BAD_ADDR(k) || p_filesz > p_memsz || p_memsz > TASK_SIZE ||
    /// TASK_SIZE - p_memsz < k`, with `k = p_vaddr + bias`.
    fn check_segment(&self, ph: &ProgramHeader, bias: u64) -> Result<(), LoadError> {
        let k = ph.p_vaddr.wrapping_add(bias);
        if self.bad_addr(k)
            || ph.p_filesz > ph.p_memsz
            || ph.p_memsz > self.task_size
            || self.task_size - ph.p_memsz < k
        {
            return Err(LoadError::BadSegment(format!(
                "segment [{k:#x}, +{:#x}) exceeds the user address space",
                ph.p_memsz
            )));
        }
        Ok(())
    }

    /// `get_unmapped_area` for a non-fixed mapping of `len` bytes: the
    /// page-aligned `hint` if the whole range is free and inside
    /// `[mmap_min_addr, TASK_SIZE)`, otherwise the highest free range below
    /// the mmap base (`vm_unmapped_area` top-down).
    fn place(&self, hint: u64, len: u64) -> Result<u64, LoadError> {
        let hint = page_start(hint);
        if hint != 0
            && hint >= MMAP_MIN_ADDR
            && hint
                .checked_add(len)
                .is_some_and(|end| end <= self.task_size)
            && self.space.is_free(hint, len)
        {
            return Ok(hint);
        }
        self.space
            .find_free_top_down(len, PAGE_SIZE, MMAP_MIN_ADDR, self.mmap_base)
            .ok_or(LoadError::Memory(MmError::OutOfMemory))
    }

    /// `elf_load`: maps one `PT_LOAD` at `p_vaddr + bias`.
    fn map_segment(
        &self,
        file: &ImageFile,
        ph: &ProgramHeader,
        bias: u64,
    ) -> Result<(), LoadError> {
        let vaddr = ph.p_vaddr.wrapping_add(bias);
        let page_off = vaddr & PAGE_MASK;
        let perms = segment_perms(self.abi, ph.p_flags);
        if page_start(vaddr) < MMAP_MIN_ADDR {
            return Err(LoadError::BelowMinAddr(page_start(vaddr)));
        }
        let mem_end = vaddr
            .checked_add(ph.p_memsz)
            .ok_or_else(|| LoadError::BadSegment("segment end overflows".into()))?;
        let zero_start;
        if ph.p_filesz != 0 {
            // elf_map(): the file mapping starts at the page holding p_vaddr
            // and must be file-page aligned (vm_mmap rejects an unaligned
            // offset with EINVAL).
            let file_off = ph.p_offset.wrapping_sub(page_off);
            if file_off & PAGE_MASK != 0 || ph.p_offset < page_off {
                return Err(LoadError::BadSegment(format!(
                    "p_offset {:#x} is not congruent to p_vaddr {:#x} modulo the page size",
                    ph.p_offset, ph.p_vaddr
                )));
            }
            let map_len = page_align(ph.p_filesz + page_off)
                .ok_or_else(|| LoadError::BadSegment("segment size overflows".into()))?;
            self.space.map(
                page_start(vaddr),
                map_len,
                Mapping {
                    perms,
                    backing: Backing::Source {
                        source: file.source(),
                        offset: file_off,
                    },
                    shared: false,
                    name: Some(file.name.clone()),
                    // elf_map: make_prot gives PROT_READ only for PF_R.
                    flags: if ph.p_flags & PF_R == 0 {
                        vma_flags::NO_READ
                    } else {
                        0
                    },
                },
            )?;
            zero_start = vaddr + ph.p_filesz;
            if ph.p_memsz > ph.p_filesz {
                // padzero(): clear the tail of the last file page. The write
                // fails harmlessly on a read-only segment in the kernel, and
                // the file bytes stay visible.
                let tail_end = page_align(zero_start).unwrap_or(zero_start);
                if ph.p_flags & PF_W != 0 && tail_end > zero_start {
                    let zeros = vec![0u8; (tail_end - zero_start) as usize];
                    self.space
                        .write_raw(zero_start, &zeros)
                        .map_err(|_| LoadError::Memory(MmError::OutOfMemory))?;
                }
            }
        } else {
            zero_start = page_start(vaddr);
        }
        if ph.p_memsz > ph.p_filesz {
            // vm_brk_flags(): anonymous read-write pages, executable only if
            // the segment asked for it.
            let anon_start = page_align(zero_start).unwrap();
            let anon_end = page_align(mem_end)
                .ok_or_else(|| LoadError::BadSegment("segment end overflows".into()))?;
            if anon_end > anon_start {
                let mut anon = Perms::READ | Perms::WRITE;
                if ph.p_flags & PF_X != 0 {
                    anon |= Perms::EXEC;
                }
                self.space
                    .map(anon_start, anon_end - anon_start, Mapping::anonymous(anon))?;
            }
        }
        Ok(())
    }

    /// `load_elf_interp`: maps the interpreter and returns its load address
    /// and entry point. `no_base` is the program's load bias.
    fn load_interp(&self, file: &ImageFile, no_base: u64) -> Result<(u64, u64), LoadError> {
        let (class, data) = self.abi.elf_encoding();
        let image = ElfImage::parse(&file.bytes, class, data)
            .map_err(|e| LoadError::BadInterpreter(e.to_string()))?;
        let et = image.header().e_type;
        if (et != ET_EXEC && et != ET_DYN) || !self.check_arch(&image) {
            return Err(LoadError::BadInterpreter(format!(
                "{}: not an interpreter for {}",
                file.name,
                self.abi.machine()
            )));
        }
        let total = image
            .total_mapping_size(PAGE_SIZE)
            .and_then(page_align)
            .filter(|&t| t != 0)
            .ok_or_else(|| LoadError::BadInterpreter("empty load span".into()))?;
        let mut load_addr = 0u64;
        let mut load_addr_set = false;
        for ph in image.load_segments() {
            if et == ET_DYN && !load_addr_set {
                // The first segment maps the whole span without MAP_FIXED at
                // `load_addr + p_vaddr`, where `load_addr` is `-p_vaddr` when
                // the program itself was relocated (so the hint is zero).
                if no_base != 0 {
                    load_addr = 0u64.wrapping_sub(ph.p_vaddr);
                }
                let map_addr = self.place(load_addr.wrapping_add(ph.p_vaddr), total)?;
                load_addr = map_addr.wrapping_sub(page_start(ph.p_vaddr));
                load_addr_set = true;
            }
            self.check_segment(ph, load_addr)?;
            self.map_segment(file, ph, load_addr)?;
        }
        let entry = image.header().e_entry.wrapping_add(load_addr);
        Ok((load_addr, entry))
    }
}

/// Loads `file` into `space` (which must be empty apart from the stack) as
/// `execve` does, resolving `PT_INTERP` through `resolver`.
///
/// `stack_limit` is the `RLIMIT_STACK` soft limit, which positions the mmap
/// base.
pub fn load_program(
    abi: LinuxAbi,
    space: &AddressSpace,
    file: &ImageFile,
    resolver: &mut dyn InterpreterResolver,
    stack_limit: u64,
) -> Result<LoadedProgram, LoadError> {
    let (class, data) = abi.elf_encoding();
    let image = ElfImage::parse(&file.bytes, class, data)?;
    let loader = Loader {
        abi,
        space,
        task_size: abi.task_size(),
        mmap_base: abi.mmap_base(stack_limit),
    };
    if !loader.check_arch(&image) {
        return Err(LoadError::NotExecutable(format!(
            "ELF machine {} is not {}",
            image.header().e_machine,
            abi.machine()
        )));
    }
    let header = *image.header();

    let interp_path = image.interpreter().map(<[u8]>::to_vec);
    let interp_file = match &interp_path {
        Some(path) => {
            Some(
                resolver
                    .open_interpreter(path)
                    .map_err(|error| LoadError::Interpreter {
                        path: String::from_utf8_lossy(path).into_owned(),
                        error,
                    })?,
            )
        }
        None => None,
    };

    let loads: Vec<ProgramHeader> = image.load_segments().copied().collect();
    if loads.is_empty() {
        return Err(LoadError::NotExecutable("no PT_LOAD segment".into()));
    }

    let first = loads[0];
    let total = image
        .total_mapping_size(PAGE_SIZE)
        .and_then(page_align)
        .filter(|&t| t != 0)
        .ok_or_else(|| LoadError::BadSegment("empty or wrapping load span".into()))?;
    let mut load_bias = 0u64;
    if header.e_type == ET_DYN {
        let alignment = image.max_load_alignment(PAGE_SIZE);
        if interp_file.is_some() {
            // A PIE: ELF_ET_DYN_BASE, aligned down to maximum_alignment(),
            // then `ELF_PAGESTART(load_bias - vaddr)`.
            let mut base = abi.elf_et_dyn_base();
            if alignment != 0 {
                base &= !(alignment - 1);
            }
            load_bias = page_start(base.wrapping_sub(first.p_vaddr));
        } else if alignment > PAGE_SIZE {
            // A loader or static PIE with a large alignment: map the span at
            // hint zero to discover its top-down address, align it down.
            let map_addr = loader.place(0, total)?;
            load_bias = page_start((map_addr & !(alignment - 1)).wrapping_sub(first.p_vaddr));
        } else {
            // Otherwise the first mapping is placed like mmap(p_vaddr, span)
            // and the bias follows from where it landed.
            let map_addr = loader.place(first.p_vaddr, total)?;
            load_bias = map_addr.wrapping_sub(page_start(first.p_vaddr));
        }
    }
    // The first PT_LOAD reserves the whole span with MAP_FIXED_NOREPLACE
    // (ET_EXEC and relocated ET_DYN alike).
    let span_start = page_start(first.p_vaddr).wrapping_add(load_bias);
    loader.check_segment(&first, load_bias)?;
    if !space.is_free(span_start, total) {
        return Err(LoadError::Collision(span_start));
    }

    let mut start_code = u64::MAX;
    let mut end_code = 0u64;
    let mut start_data = 0u64;
    let mut end_data = 0u64;
    let mut elf_brk = 0u64;
    let mut phdr_addr = 0u64;
    for ph in &loads {
        loader.check_segment(ph, load_bias)?;
        loader.map_segment(file, ph, load_bias)?;
        // AT_PHDR: the segment whose file range contains the header table.
        if ph.p_offset <= header.e_phoff && header.e_phoff < ph.p_offset + ph.p_filesz {
            phdr_addr = header.e_phoff - ph.p_offset + ph.p_vaddr;
        }
        let k = ph.p_vaddr;
        if ph.p_flags & PF_X != 0 && k < start_code {
            start_code = k;
        }
        if start_data < k {
            start_data = k;
        }
        let k = ph.p_vaddr + ph.p_filesz;
        if ph.p_flags & PF_X != 0 && end_code < k {
            end_code = k;
        }
        if end_data < k {
            end_data = k;
        }
        elf_brk = elf_brk.max(ph.p_vaddr + ph.p_memsz);
    }
    let program_entry = header.e_entry.wrapping_add(load_bias);
    let (interp_base, entry) = match &interp_file {
        Some(interp) => loader.load_interp(interp, load_bias)?,
        None => (0, program_entry),
    };
    if loader.bad_addr(entry) {
        return Err(LoadError::BadSegment(format!(
            "entry point {entry:#x} is outside the user address space"
        )));
    }
    let brk = page_align(elf_brk.wrapping_add(load_bias))
        .ok_or_else(|| LoadError::BadSegment("program break overflows".into()))?;
    Ok(LoadedProgram {
        entry,
        program_entry,
        phdr: phdr_addr.wrapping_add(load_bias),
        phent: header.e_phentsize.into(),
        phnum: header.e_phnum.into(),
        interp_base,
        load_bias,
        brk,
        exec_stack: image.gnu_stack_executable().unwrap_or(false),
        interp_path,
        start_code: if start_code == u64::MAX {
            load_bias
        } else {
            start_code.wrapping_add(load_bias)
        },
        end_code: end_code.wrapping_add(load_bias),
        start_data: start_data.wrapping_add(load_bias),
        end_data: end_data.wrapping_add(load_bias),
    })
}
