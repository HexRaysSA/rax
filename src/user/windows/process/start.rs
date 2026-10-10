//! PE process construction and Windows process parameters.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use super::{Proc, SpawnError, WindowsConfig, thread};
use crate::user::image::pe::{IMAGE_FILE_DLL, IMAGE_FILE_LARGE_ADDRESS_AWARE, PeImage};
use crate::user::mm::{AddressSpace, SpaceConfig};
use crate::user::windows::arch::WinArch;
use crate::user::windows::layout::{self, kuser, offsets};
use crate::user::windows::memory::{AllocKind, Mem, VirtualMemory, prot};
use crate::user::windows::objects::{Object, Objects, StdStream};
use crate::user::windows::{heap::Heaps, loader};

fn memory(e: impl std::fmt::Display) -> SpawnError {
    SpawnError::Memory(e.to_string())
}

/// Quotes one argument using the Microsoft C runtime backslash/quote rules.
/// Time and space are O(n) in UTF-8 bytes, with no change to Unicode scalars.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            slashes += 1;
        } else {
            out.extend(std::iter::repeat_n(
                '\\',
                if ch == '"' { 2 * slashes + 1 } else { slashes },
            ));
            out.push(ch);
            slashes = 0;
        }
    }
    out.extend(std::iter::repeat_n('\\', 2 * slashes));
    out.push('"');
    out
}

/// argv[0] follows the distinct Microsoft C program-name rule: quotes toggle
/// grouping, but backslashes are literal, including before the closing quote.
fn quote_program(arg: &str) -> Result<String, SpawnError> {
    if arg.contains(['"', '\0']) {
        return Err(SpawnError::BadImage(
            "program argument cannot contain a quotation mark or NUL".into(),
        ));
    }
    Ok(if arg.is_empty() || arg.contains([' ', '\t']) {
        format!("\"{arg}\"")
    } else {
        arg.to_owned()
    })
}

impl WindowsConfig {
    /// Default guest environment independent of the host's Unix environment.
    pub fn default_environment(&self, arch: WinArch) -> Vec<(String, String)> {
        vec![
            ("SystemRoot".into(), "C:\\Windows".into()),
            ("WINDIR".into(), "C:\\Windows".into()),
            ("COMSPEC".into(), "C:\\Windows\\System32\\cmd.exe".into()),
            ("PATH".into(), "C:\\Windows\\System32;C:\\Windows".into()),
            ("TEMP".into(), "C:\\Temp".into()),
            ("TMP".into(), "C:\\Temp".into()),
            ("OS".into(), "Windows_NT".into()),
            ("PROCESSOR_ARCHITECTURE".into(), arch.env_name().into()),
            ("NUMBER_OF_PROCESSORS".into(), "1".into()),
            ("USERNAME".into(), self.user_name.clone()),
            ("COMPUTERNAME".into(), self.computer_name.clone()),
        ]
    }
}

fn alloc(p: &mut Proc, size: u64) -> Result<u64, SpawnError> {
    p.heaps
        .alloc(&mut p.vm, p.process_heap, size, true)
        .ok_or_else(|| memory("process heap exhausted"))
}

fn unicode(p: &mut Proc, field: u64, value: &str) -> Result<(), SpawnError> {
    let units: Vec<_> = value.encode_utf16().collect();
    let bytes = units
        .len()
        .checked_mul(2)
        .filter(|n| *n <= 0xFFFC)
        .ok_or_else(|| {
            SpawnError::BadImage("process parameter exceeds UNICODE_STRING length".into())
        })?;
    let buffer = alloc(p, bytes as u64 + 2)?;
    p.space
        .put_wstr(buffer, &units)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w16(field, bytes as u16)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w16(field + 2, bytes as u16 + 2)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .wptr(field + p.arch.ptr_size(), p.arch.ptr_size(), buffer)
        .map_err(|e| memory(format!("{e:?}")))
}

fn params(p: &mut Proc, image_path: &str) -> Result<(), SpawnError> {
    let o = *offsets(p.arch);
    p.params = alloc(p, o.pp_size)?;
    let at = p.params;
    p.space
        .w32(at + o.pp_maximum_length, o.pp_size as u32)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w32(at + o.pp_length, o.pp_size as u32)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w32(at + o.pp_flags, 1)
        .map_err(|e| memory(format!("{e:?}")))?;
    for (stream, off) in [
        (StdStream::In, o.pp_std_input),
        (StdStream::Out, o.pp_std_output),
        (StdStream::Err, o.pp_std_error),
    ] {
        let handle = p.objects.insert(Object::Console(stream));
        p.space
            .wptr(at + off, o.ptr, u64::from(handle))
            .map_err(|e| memory(format!("{e:?}")))?;
    }
    let cwd = String::from_utf16_lossy(&p.cwd);
    unicode(p, at + o.pp_current_directory, &cwd)?;
    unicode(p, at + o.pp_image_path_name, image_path)?;
    let command = if let Some(command) = &p.cfg.command_line {
        command.clone()
    } else {
        let mut command = quote_program(p.cfg.argv0.as_deref().unwrap_or(image_path))?;
        for argument in &p.cfg.args {
            command.push(' ');
            command.push_str(&quote_arg(argument));
        }
        command
    };
    unicode(p, at + o.pp_command_line, &command)?;
    let dll_path = p
        .native
        .as_ref()
        .map(|runtime| runtime.guest_directory.clone())
        .unwrap_or_else(|| loader::system_dir(p.arch).into());
    unicode(p, at + o.pp_dll_path, &dll_path)?;
    let mut env = p
        .cfg
        .env
        .clone()
        .unwrap_or_else(|| p.cfg.default_environment(p.arch));
    if p.cfg.env.is_none()
        && let Some(runtime) = p.native.as_ref()
    {
        let root = runtime.guest_root.clone();
        for (name, value) in &mut env {
            match name.as_str() {
                "SystemRoot" | "WINDIR" => *value = root.clone(),
                "COMSPEC" => *value = format!("{}\\cmd.exe", runtime.guest_directory),
                "PATH" => *value = format!("{dll_path};{root}"),
                _ => {}
            }
        }
    }
    let mut values = BTreeMap::new();
    for (name, value) in env.into_iter().chain(p.cfg.env_overrides.iter().cloned()) {
        if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
            return Err(SpawnError::BadImage("invalid environment variable".into()));
        }
        values.insert(name.to_uppercase(), (name, value));
    }
    let mut block = Vec::new();
    for (_, (name, value)) in values {
        block.extend(format!("{name}={value}").encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    let buffer = alloc(p, block.len() as u64 * 2)?;
    p.space
        .put_wunits(buffer, &block)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .wptr(at + o.pp_environment, o.ptr, buffer)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .wptr(at + o.pp_environment_size, o.ptr, block.len() as u64 * 2)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .wptr(p.peb + o.peb_process_parameters, o.ptr, at)
        .map_err(|e| memory(format!("{e:?}")))?;
    Ok(())
}

pub(super) fn spawn(config: WindowsConfig) -> Result<Proc, SpawnError> {
    if !config.host_filesystem {
        return Err(SpawnError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "host filesystem disabled; supply executable bytes",
        )));
    }
    let bytes = std::fs::read(&config.exe_host_path).map_err(SpawnError::Io)?;
    spawn_image(config, bytes)
}

pub(super) fn spawn_image(mut config: WindowsConfig, bytes: Vec<u8>) -> Result<Proc, SpawnError> {
    if !config.host_filesystem
        && (config.seed.is_none()
            || config.trace
            || config.guest_image_path.is_none()
            || !matches!(config.console, crate::user::console::Console::Captured(_)))
    {
        return Err(SpawnError::BadImage("closed filesystem configuration requires a seed, guest image path, captured console, and disabled host trace".into()));
    }
    let mut images = BTreeMap::new();
    for (name, bytes) in std::mem::take(&mut config.supplied_dlls) {
        let path = crate::user::windows::fs::full_path(&name, "C:\\")
            .filter(|_| {
                name.as_bytes().get(1) == Some(&b':')
                    && matches!(name.as_bytes().get(2), Some(b'\\' | b'/'))
                    && !name.contains('\0')
            })
            .ok_or_else(|| {
                SpawnError::BadImage("supplied DLL keys must be absolute Windows paths".into())
            })?
            .to_string_path()
            .to_ascii_lowercase();
        if images.insert(path, bytes).is_some() {
            return Err(SpawnError::BadImage(
                "case-colliding supplied DLL paths".into(),
            ));
        }
    }
    config.supplied_dlls = images;
    let pe = PeImage::parse(bytes).map_err(|e| SpawnError::BadImage(e.to_string()))?;
    let h = pe.headers();
    let arch = WinArch::from_machine(h.machine)
        .ok_or_else(|| SpawnError::BadImage(format!("unsupported PE machine {:#x}", h.machine)))?;
    if h.characteristics & IMAGE_FILE_DLL != 0 {
        return Err(SpawnError::BadImage(
            "DLL cannot be started as a process executable".into(),
        ));
    }
    let native = if config.native_libraries {
        let runtime =
            crate::user::windows::native::NativeRuntime::select(arch).map_err(SpawnError::Io)?;
        config.version = runtime.version.clone();
        Some(runtime)
    } else {
        None
    };
    let high = layout::user_limit(
        arch,
        h.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0,
    );
    // PEB/TEB and KUSER_SHARED_DATA fit below the allocation ceiling even
    // for non-large-address-aware x86: 0x7FFE1000 < 0x7FFF0000.
    let reserved_phys = if arch == WinArch::Arm64 {
        Vec::new()
    } else {
        crate::user::cpu::x86_64::RESERVED_PHYS.to_vec()
    };
    let unavailable: u64 = reserved_phys
        .iter()
        .map(|&(base, len)| config.arena_bytes.saturating_sub(base).min(len))
        .sum();
    let commit_limit = config.arena_bytes.saturating_sub(unavailable);
    let space = AddressSpace::new(SpaceConfig {
        va_limit: high,
        arena_bytes: config.arena_bytes,
        reserved_phys,
    })
    .map_err(memory)?;
    let mut vm = VirtualMemory::new_with_commit_limit(
        space.clone(),
        layout::LOWEST_USER_ADDRESS,
        high,
        commit_limit,
    );
    vm.reserve(
        Some(layout::SYSTEM_AREA),
        layout::SYSTEM_AREA_END - layout::SYSTEM_AREA,
        prot::READWRITE,
        AllocKind::Private,
        false,
        Some(Arc::from("[PEB/TEB]")),
    )
    .map_err(memory)?;
    vm.commit(layout::PEB_ADDRESS, 0x1000, prot::READWRITE)
        .map_err(memory)?;
    vm.reserve(
        Some(layout::KUSER_SHARED_DATA),
        0x1000,
        prot::READONLY,
        AllocKind::Private,
        false,
        Some(Arc::from("[KUSER_SHARED_DATA]")),
    )
    .map_err(memory)?;
    vm.commit(layout::KUSER_SHARED_DATA, 0x1000, prot::READONLY)
        .map_err(memory)?;
    let image_path = match &config.guest_image_path {
        Some(path) => crate::user::windows::fs::full_path(path, "C:\\")
            .ok_or_else(|| SpawnError::BadImage("invalid guest image path".into()))?
            .to_string_path(),
        None => config.drives.to_windows(&config.exe_host_path),
    };
    if config.guest_image_path.is_some() {
        config.guest_image_path = Some(image_path.clone());
    }
    let cwd = config.cwd.clone().unwrap_or_else(|| {
        if !config.host_filesystem {
            return "C:\\".into();
        }
        config
            .drives
            .to_windows(&std::env::current_dir().unwrap_or_default())
    });
    let cwd = crate::user::windows::fs::full_path(&cwd, "C:\\")
        .ok_or_else(|| SpawnError::BadImage("invalid Windows current directory".into()))?
        .to_string_path();
    let cwd = if cwd.ends_with('\\') {
        cwd
    } else {
        format!("{cwd}\\")
    };
    let seed = match config.seed {
        Some(seed) => seed,
        None => {
            let mut bytes = [0; 8];
            getrandom::fill(&mut bytes)
                .map_err(|e| SpawnError::Io(std::io::Error::other(e.to_string())))?;
            u64::from_le_bytes(bytes)
        }
    };
    let registry = native
        .as_ref()
        .map(|r| r.registry.clone())
        .unwrap_or_default();
    let mut p = Proc {
        arch,
        space,
        vm,
        cfg: Arc::new(config),
        native,
        registry,
        pid: 4,
        peb: layout::PEB_ADDRESS,
        params: 0,
        ansi_command_line: None,
        process_heap: 0,
        modules: Default::default(),
        loader: Default::default(),
        fibers: Default::default(),
        traps: Default::default(),
        objects: Objects::default(),
        heaps: Heaps::new(if arch.is64() { 16 } else { 8 }),
        tls: Default::default(),
        seh: Default::default(),
        sync: Default::default(),
        crt: Default::default(),
        threads: BTreeMap::new(),
        next_tid: 8,
        exit_code: None,
        failure: None,
        start_time: Instant::now(),
        rng: seed,
        // Keep cookie derivation independent of the existing random stream.
        process_cookie: (seed ^ (seed >> 32)) as u32 ^ 0xA5A5_5A5A,
        cwd: cwd.encode_utf16().collect(),
        exe_stack_reserve: h.stack_reserve,
        exe_stack_commit: h.stack_commit,
    };
    let host_path = p.cfg.exe_host_path.clone();
    loader::load_exe(&mut p, &pe, &host_path, image_path.clone()).map_err(|e| {
        SpawnError::Load {
            status: e.status,
            message: e.message,
        }
    })?;
    p.process_heap = p
        .heaps
        .create(&mut p.vm, 0, h.heap_commit, 0)
        .ok_or_else(|| memory("cannot create process heap"))?;
    let o = *offsets(arch);
    p.space
        .wptr(p.peb + o.peb_image_base, o.ptr, p.modules.exe().base)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .wptr(p.peb + o.peb_process_heap, o.ptr, p.process_heap)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w32(p.peb + o.peb_number_of_processors, 1)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w32(p.peb + o.peb_os_major, p.cfg.version.major)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w32(p.peb + o.peb_os_minor, p.cfg.version.minor)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w16(p.peb + o.peb_os_build, p.cfg.version.build as u16)
        .map_err(|e| memory(format!("{e:?}")))?;
    p.space
        .w32(p.peb + o.peb_os_platform_id, 2)
        .map_err(|e| memory(format!("{e:?}")))?;
    params(&mut p, &image_path)?;
    if let Some(runtime) = p.native.as_ref() {
        let schema = runtime.apisets.bytes.clone();
        let base =
            p.vm.reserve(
                None,
                schema.len() as u64,
                prot::READONLY,
                AllocKind::Private,
                false,
                Some(Arc::from("[ApiSetMap]")),
            )
            .map_err(memory)?;
        p.vm.commit(base, schema.len() as u64, prot::READONLY)
            .map_err(memory)?;
        p.vm.poke(base, &schema)
            .map_err(|e| memory(format!("{e:?}")))?;
        // Modern private PEB layout; native schema header is checked by the
        // Windows integration probe rather than inferred from public padding.
        p.space
            .wptr(p.peb + o.peb_api_set_map, o.ptr, base)
            .map_err(|e| memory(format!("{e:?}")))?;
        let traps =
            p.vm.reserve(
                None,
                0x1000,
                prot::READONLY,
                AllocKind::Private,
                false,
                Some(Arc::from("[native process frontiers]")),
            )
            .map_err(|e| memory(format!("{e:?}")))?;
        p.vm.commit(traps, 0x1000, prot::READONLY).map_err(memory)?;
        p.vm.set_reported(traps, 0x1000, prot::EXECUTE_READ);
        use crate::user::windows::traps::SlotKind;
        p.traps.add(
            traps,
            vec![
                SlotKind::CallbackReturn,
                SlotKind::ThreadStart,
                SlotKind::FiberStart,
                SlotKind::DispatcherRetry,
            ],
            0x1000 / 16,
        );
    }
    // Pseudo process handles must resolve independently of whether a real
    // process handle has ever been duplicated. The internal reference keeps
    // this object alive until the entire table is drained at shutdown.
    let process_object = p
        .objects
        .try_create(Object::Process {
            pid: p.pid,
            exit_code: None,
        })
        .ok_or_else(|| memory("process object capacity exhausted"))?;
    p.objects.retain(process_object);
    loader::ldr::init(&mut p).map_err(|e| SpawnError::Load {
        status: e.status,
        message: e.message,
    })?;
    (if p.native.is_some() && h.subsystem == 1 {
        loader::load_dll(&mut p, "ntdll.dll").map(|_| ())
    } else {
        loader::load_system_dlls(&mut p)
    })
    .and_then(|_| loader::finish_exe(&mut p, &pe))
    .map_err(|e| SpawnError::Load {
        status: e.status,
        message: e.message,
    })?;
    let shared = layout::KUSER_SHARED_DATA;
    let physical_pages = u32::try_from(p.vm.commit_limit() / crate::user::mm::PAGE_SIZE)
        .map_err(|_| memory("Windows physical page count exceeds ULONG"))?;
    for (off, value) in [
        (kuser::NT_BUILD_NUMBER, p.cfg.version.build),
        (kuser::NT_MAJOR_VERSION, p.cfg.version.major),
        (kuser::NT_MINOR_VERSION, p.cfg.version.minor),
        (
            kuser::NT_PRODUCT_TYPE,
            u32::from(p.cfg.version.product_type),
        ),
        (kuser::ACTIVE_PROCESSOR_COUNT, 1),
        (kuser::NUMBER_OF_PHYSICAL_PAGES, physical_pages),
        (kuser::TICK_COUNT_MULTIPLIER, 1 << 24),
    ] {
        p.vm.poke(shared + off, &value.to_le_bytes())
            .map_err(|e| memory(format!("{e:?}")))?;
    }
    p.vm.poke(shared + kuser::PRODUCT_TYPE_IS_VALID, &[1])
        .map_err(|e| memory(format!("{e:?}")))?;
    p.vm.poke(
        shared + kuser::NATIVE_PROCESSOR_ARCHITECTURE,
        &arch.processor_architecture().to_le_bytes(),
    )
    .map_err(|e| memory(format!("{e:?}")))?;
    let system_root = p
        .native
        .as_ref()
        .map(|runtime| runtime.guest_root.clone())
        .unwrap_or_else(|| "C:\\Windows".into());
    if system_root.encode_utf16().count() >= 260 {
        return Err(memory("Windows root exceeds KUSER_SHARED_DATA capacity"));
    }
    p.vm.poke(
        shared + kuser::NT_SYSTEM_ROOT,
        &format!("{system_root}\0")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .map_err(|e| memory(format!("{e:?}")))?;
    let entry = p.modules.exe().entry;
    let tid = thread::create(&mut p, entry, 0, 0, true).map_err(|status| SpawnError::Load {
        status,
        message: "cannot create main thread".into(),
    })?;
    // The shared array covers baseline PF indices 0..64. Class 250 covers
    // the separate extended indices 64..192. Use the actual created CPU;
    // the readonly guest page must never expose the host's capabilities.
    let cpu = &p.threads[&tid].cpu;
    let features: [u8; 64] = std::array::from_fn(|feature| {
        u8::from(crate::user::windows::dll::processor_feature_present(
            cpu,
            feature as u32,
        ))
    });
    p.vm.poke(shared + kuser::PROCESSOR_FEATURES, &features)
        .map_err(|e| memory(format!("{e:?}")))?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::{quote_arg, quote_program};
    #[test]
    fn quotes_empty_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("a b\\"), "\"a b\\\\\"");
    }

    #[test]
    fn program_quoting_does_not_double_literal_trailing_backslashes() {
        assert_eq!(quote_program("a b\\").unwrap(), "\"a b\\\"");
        assert_eq!(quote_program("a b\\\\").unwrap(), "\"a b\\\\\"");
        assert_eq!(quote_program("").unwrap(), "\"\"");
        assert_eq!(quote_program("plain\\").unwrap(), "plain\\");
        assert!(quote_program("a\"b").is_err());
        assert!(quote_program("a\0b").is_err());
    }
}
