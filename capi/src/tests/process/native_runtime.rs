//! Installed runtime grants exercised through the exported C process interface.
use super::*;

#[cfg(all(windows, target_pointer_width = "64"))]
#[path = "native_runtime/token_duplicate.rs"]
mod token_duplicate;

fn refused(image: &[u8], options: &str, supplied: &[RaxProcessImage], status: RaxStatus) -> String {
    let mut handle = ptr::null_mut();
    assert_eq!(
        rax_process_open_image(
            image.as_ptr(),
            image.len(),
            options.as_ptr().cast(),
            options.len(),
            supplied.as_ptr(),
            supplied.len(),
            &mut handle,
        ),
        status,
        "{}",
        error(),
    );
    assert!(handle.is_null(), "refused open published a process");
    error()
}

#[test]
fn native_option_is_strict_and_host_mismatch_never_falls_back() {
    let image = fixtures()[0].1;
    for value in ["null", "0", "1", "\"true\"", "[]", "{}"] {
        let message = refused(
            image,
            &format!("{{\"native_runtime\":{value}}}"),
            &[],
            RaxStatus::Arg,
        );
        assert_eq!(message, "native_runtime must be a boolean");
    }
    for (personality, matching_host) in [
        ("windows", cfg!(windows)),
        ("linux", cfg!(target_os = "linux")),
        ("darwin", cfg!(target_os = "macos")),
    ] {
        if !matching_host {
            let message = refused(
                image,
                &format!("{{\"personality\":\"{personality}\",\"native_runtime\":true}}"),
                &[],
                RaxStatus::Unsupported,
            );
            assert!(message.contains("host"), "{message}");
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn installed_dynamic_programs_run_without_supplied_dependencies_or_general_host_access() {
    let personality = if cfg!(target_os = "linux") {
        "linux"
    } else {
        "darwin"
    };
    for (path, arguments, expected) in [
        (
            if cfg!(target_os = "linux") {
                "/bin/true"
            } else {
                "/usr/bin/true"
            },
            serde_json::json!([]),
            "",
        ),
        (
            "/usr/bin/printf",
            serde_json::json!(["%s\\n", "native-c-api"]),
            "native-c-api\n",
        ),
    ] {
        let image = std::fs::read(path).expect("installed system program");
        let options = serde_json::json!({
            "personality":personality, "native_runtime":true, "arguments":arguments,
            "memory_bytes":268435456, "slice_instructions":4096,
        })
        .to_string();
        let process = open(&image, &options);
        let before = info(&process);
        assert_eq!(before["capabilities"]["native_runtime"], true);
        assert_eq!(before["capabilities"]["host_filesystem"], false);
        assert_eq!(before["capabilities"]["host_services"], false);
        #[cfg(target_os = "macos")]
        assert_eq!(
            before["architecture"],
            if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            }
        );
        let result = run_installed_posix(&process, path);
        assert_eq!(result.exit_code, 0);
        let mut output = vec![0; 65536];
        let mut size = 0;
        assert_eq!(
            rax_process_output_read(
                process.0,
                RAX_PROCESS_STDOUT,
                output.as_mut_ptr(),
                output.len(),
                &mut size
            ),
            RaxStatus::Ok
        );
        assert_eq!(&output[..size], expected.as_bytes());

        // A supplied malformed interpreter/dyld must be used ahead of installed
        // bytes; otherwise this same executable would open successfully again.
        #[cfg(target_os = "macos")]
        let dependency = "/usr/lib/dyld".to_owned();
        #[cfg(target_os = "linux")]
        let dependency = String::from_utf8(
            rax_engine::user::image::elf::ElfImage::parse_self_described(&image)
                .unwrap()
                .interpreter()
                .expect("dynamic ELF interpreter")
                .to_vec(),
        )
        .unwrap();
        let broken = b"invalid supplied interpreter";
        let supplied = RaxProcessImage {
            path: dependency.as_ptr().cast(),
            path_size: dependency.len(),
            data: broken.as_ptr(),
            data_size: broken.len(),
        };
        let message = refused(&image, &options, &[supplied], RaxStatus::Format);
        assert!(!message.is_empty());
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_installed_posix(process: &Owned, path: &str) -> RaxProcessResult {
    // Bound guest work independently of host speed or descheduling.
    const MAX_TURNS: u64 = 16_384;
    let mut remaining = MAX_TURNS;
    let mut result = RaxProcessResult::default();
    loop {
        assert!(
            remaining != 0,
            "{path}: exceeded {MAX_TURNS} scheduler turns"
        );
        let turns = remaining.min(256);
        assert_eq!(
            rax_process_run(process.0, turns, 0, &mut result),
            RaxStatus::Ok
        );
        assert!(result.turns_started <= turns);
        remaining -= result.turns_started;
        if result.reason != RAX_PROCESS_BUDGET {
            break;
        }
        assert_ne!(result.turns_started, 0, "{path}: budget made no progress");
    }
    eprintln!(
        "{path}: completed within {} scheduler turns",
        MAX_TURNS - remaining
    );
    assert_eq!(
        result.reason,
        RAX_PROCESS_EXITED,
        "{path}: {}",
        info(process)
    );
    result
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "run explicitly with the Linux x64 CI multilib program and installed i386 libc"]
fn installed_i386_glibc_matches_native_through_closed_c_abi() {
    let path = std::env::var("RAX_LINUX_MULTILIB_PROGRAM").expect("path to the i386 fixture");
    let image = std::fs::read(&path).expect("read i386 fixture");
    let elf = rax_engine::user::image::elf::ElfImage::parse_self_described(&image).unwrap();
    assert_eq!(elf.interpreter(), Some(b"/lib/ld-linux.so.2".as_slice()));
    let loader = std::fs::canonicalize("/lib/ld-linux.so.2").expect("installed i386 loader");
    assert!(
        loader.starts_with("/lib32") || loader.starts_with("/usr/lib32"),
        "expected a biarch glibc loader under lib32, got {loader:?}"
    );
    let native = std::process::Command::new(&path)
        .env_clear()
        .output()
        .expect("run the i386 fixture natively");
    assert_eq!(native.status.code(), Some(23));
    assert_eq!(native.stdout, b"installed i386 libc\n");
    assert!(native.stderr.is_empty());

    let process = open(
        &image,
        r#"{"personality":"linux","native_runtime":true,"memory_bytes":268435456,"slice_instructions":4096}"#,
    );
    let before = info(&process);
    assert_eq!(before["architecture"], "x86");
    assert_eq!(before["capabilities"]["native_runtime"], true);
    assert_eq!(before["capabilities"]["host_filesystem"], false);
    assert_eq!(before["capabilities"]["host_services"], false);
    let exit_code = run_installed_posix(&process, &path).exit_code;
    let mut output = [Vec::new(), Vec::new()];
    for (stream, captured) in [RAX_PROCESS_STDOUT, RAX_PROCESS_STDERR]
        .into_iter()
        .zip(&mut output)
    {
        let mut bytes = [0u8; 4096];
        let mut size = 0;
        assert_eq!(
            rax_process_output_read(
                process.0,
                stream,
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut size
            ),
            RaxStatus::Ok
        );
        captured.extend_from_slice(&bytes[..size]);
    }
    let [stdout, stderr] = output;
    assert_eq!(
        exit_code,
        23,
        "i386 guest stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(windows)]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_cmd_ver_matches_native_through_closed_c_abi() {
    let native = compare_windows_installed_program("cmd.exe", &["/d", "/c", "ver"], None);
    assert!(native.status.success());
    assert!(!native.stdout.is_empty());
}

#[cfg(windows)]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_findstr_matches_native_through_closed_c_abi() {
    check_native_extension_point_policy();
    let arguments = &["/l", "/c:rax-witness"];
    let matched = compare_windows_installed_program(
        "findstr.exe",
        arguments,
        Some(b"ignored\r\nrax-witness\r\n"),
    );
    assert_eq!(matched.status.code(), Some(0));
    assert_eq!(matched.stdout, b"rax-witness\r\n");
    assert!(matched.stderr.is_empty());

    let unmatched =
        compare_windows_installed_program("findstr.exe", arguments, Some(b"ignored\r\n"));
    assert_eq!(unmatched.status.code(), Some(1));
    assert!(unmatched.stdout.is_empty());
    assert!(unmatched.stderr.is_empty());
}

#[cfg(windows)]
fn check_native_extension_point_policy() {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetProcessMitigationPolicy(
            process: *mut c_void,
            selector: u32,
            output: *mut c_void,
            length: usize,
        ) -> i32;
    }

    let mut flags = u32::MAX;
    let ok = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            6,
            (&raw mut flags).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
    assert_eq!(flags, 0, "installed process extension-point policy");
    eprintln!("native extension-point policy: flags=0x{flags:x}");
}

#[cfg(windows)]
fn compare_windows_installed_program(
    image: &str,
    arguments: &[&str],
    stdin: Option<&[u8]>,
) -> std::process::Output {
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    let system_root = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"));
    let system32 = system_root.join("System32");
    let current_directory = system32.to_str().expect("Unicode system library path");
    let program = system32.join(image);
    let program_path = program.to_str().expect("Unicode system program path");
    let command_interpreter = system32.join("cmd.exe");
    let environment = [
        (
            "SystemRoot",
            system_root.to_str().expect("Unicode system root"),
        ),
        ("windir", system_root.to_str().expect("Unicode system root")),
        (
            "ComSpec",
            command_interpreter.to_str().expect("Unicode cmd path"),
        ),
        ("PATH", current_directory),
    ];
    let mut command = Command::new(&program);
    command
        .args(arguments)
        .current_dir(&system32)
        .env_clear()
        .envs(environment);
    let native = if let Some(input) = stdin {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start native installed program");
        let mut pipe = child.stdin.take().expect("native standard input");
        pipe.write_all(input).expect("write native standard input");
        drop(pipe);
        child.wait_with_output().expect("native installed output")
    } else {
        command.output().expect("native installed output")
    };

    let bytes = std::fs::read(&program).expect("installed Windows executable");
    let options = serde_json::json!({
        "personality": "windows",
        "native_runtime": true,
        "guest_path": program_path,
        "current_directory": current_directory,
        "arguments": arguments,
        "environment": environment.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
        "memory_bytes": 268435456,
        "slice_instructions": 4096,
    })
    .to_string();
    let process = open(&bytes, &options);
    if let Some(input) = stdin {
        assert_eq!(
            rax_process_stdin_feed(process.0, input.as_ptr(), input.len()),
            RaxStatus::Ok,
            "{}",
            error()
        );
    }
    let opened = info(&process);
    assert_eq!(opened["capabilities"]["native_runtime"], true);
    assert_eq!(opened["capabilities"]["host_filesystem"], false);
    let modules = opened["modules"].as_array().expect("opened guest modules");
    assert!(modules.iter().any(|module| {
        module["name"] == "ntdll.dll"
            && module["path"]
                .as_str()
                .is_some_and(|path| path.to_ascii_lowercase().contains("system32"))
    }));

    let mut result = RaxProcessResult::default();
    const MAX_TURNS: u64 = 16_384;
    let mut remaining = MAX_TURNS;
    loop {
        assert_ne!(
            remaining, 0,
            "{program_path}: guest exceeded {MAX_TURNS} turns"
        );
        let turns = remaining.min(256);
        assert_eq!(
            rax_process_run(process.0, turns, 0, &mut result),
            RaxStatus::Ok,
            "{}",
            error()
        );
        assert!(result.turns_started <= turns);
        remaining -= result.turns_started;
        if result.reason != RAX_PROCESS_BUDGET {
            break;
        }
        assert_ne!(result.turns_started, 0);
    }
    if result.reason != RAX_PROCESS_EXITED {
        eprintln!(
            "{program_path}: native exit status {:?}, stdout {} bytes, stderr {} bytes",
            native.status.code(),
            native.stdout.len(),
            native.stderr.len()
        );
        let stopped = info(&process);
        if let Some((service, name)) = stopped_native_request(&process, &stopped) {
            eprintln!("guest {service} requested {name:?}");
        }
        if let Some(shape) = stopped_token_duplicate_shape(&process, &stopped) {
            eprintln!("guest NtDuplicateToken request {shape}");
        }
        panic!(
            "guest {} stopped after {} scheduler turns: {}",
            opened["architecture"],
            MAX_TURNS - remaining,
            stopped["diagnostic"]
        );
    }
    assert_eq!(
        Some(result.exit_code),
        native.status.code().map(i32::cast_unsigned),
        "{program_path}: exit status"
    );
    for (stream, expected) in [
        (RAX_PROCESS_STDOUT, &native.stdout),
        (RAX_PROCESS_STDERR, &native.stderr),
    ] {
        let mut bytes = vec![0; 65536];
        let mut size = 0;
        assert_eq!(
            rax_process_output_read(
                process.0,
                stream,
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut size
            ),
            RaxStatus::Ok
        );
        assert_eq!(
            &bytes[..size],
            expected.as_slice(),
            "{program_path}: console stream {stream}"
        );
    }
    native
}

#[cfg(windows)]
fn stopped_token_duplicate_shape(process: &Owned, stopped: &serde_json::Value) -> Option<String> {
    let diagnostic = stopped["diagnostic"].as_str()?;
    let suffix =
        diagnostic.strip_prefix("emulator failure: native NTDLL service NtDuplicateToken")?;
    if !suffix.starts_with([':', ' ']) {
        return None;
    }
    let thread = ready_native_thread(stopped)?;
    let hex = |value: &serde_json::Value| {
        u64::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok()
    };
    let register = |index| hex(thread["registers"].get(index)?);
    let read = |address, bytes: &mut [u8]| {
        rax_process_mem_read(process.0, address, bytes.as_mut_ptr(), bytes.len()) == RaxStatus::Ok
    };
    let (source, access, attributes, effective, kind, output) =
        match stopped["architecture"].as_str()? {
            "x64" => {
                let sp = hex(&thread["sp"])?;
                let mut stack = [0; 16];
                if !read(sp.checked_add(40)?, &mut stack) {
                    return None;
                }
                (
                    register(10usize)?,
                    register(2)?,
                    register(8)?,
                    register(9)?,
                    u64::from_le_bytes(stack[..8].try_into().ok()?),
                    u64::from_le_bytes(stack[8..].try_into().ok()?),
                )
            }
            "arm64" => (
                register(0)?,
                register(1)?,
                register(2)?,
                register(3)?,
                register(4)?,
                register(5)?,
            ),
            _ => return None,
        };
    let role = match source {
        0 => "null",
        u64::MAX => "current-process",
        n if n == u64::MAX - 1 => "current-thread",
        n if n == u64::MAX - 3 => "current-process-token",
        n if n == u64::MAX - 4 => "current-thread-token",
        n if n == u64::MAX - 5 => "current-thread-effective-token",
        _ => "handle",
    };
    let mut shape = format!(
        "source={role} access={:#x} effective={} kind={} output_present={}",
        access as u32,
        effective as u8,
        kind as u32,
        output != 0
    );
    if attributes == 0 {
        shape.push_str(" attributes=absent");
        return Some(shape);
    }
    let mut header = [0; 48];
    if !read(attributes, &mut header) {
        shape.push_str(" attributes=unreadable");
        return Some(shape);
    }
    let word = |offset| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
    let pointer = |offset| u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap());
    let quality = pointer(40);
    shape.push_str(&format!(
        " attributes_bytes={} flags={:#x} named={} descriptor_present={}",
        word(0),
        word(24),
        pointer(8) != 0 || pointer(16) != 0,
        pointer(32) != 0
    ));
    if quality == 0 {
        shape.push_str(" quality=absent");
    } else {
        let mut qos = [0; 12];
        if read(quality, &mut qos) {
            let length = u32::from_le_bytes(qos[..4].try_into().ok()?);
            let level = u32::from_le_bytes(qos[4..8].try_into().ok()?);
            shape.push_str(&format!(
                " quality_bytes={length} level={level} tracking={} quality_effective={}",
                qos[8], qos[9]
            ));
        } else {
            shape.push_str(" quality=unreadable");
        }
    }
    Some(shape)
}

#[cfg(windows)]
fn ready_native_thread(stopped: &serde_json::Value) -> Option<&serde_json::Value> {
    let mut ready = stopped["threads"]
        .as_array()?
        .iter()
        .filter(|thread| thread["state"] == "ready");
    let thread = ready.next()?;
    ready.next().is_none().then_some(thread)
}

#[cfg(windows)]
fn stopped_native_request(
    process: &Owned,
    stopped: &serde_json::Value,
) -> Option<(&'static str, String)> {
    let diagnostic = stopped["diagnostic"].as_str()?;
    let (service, argument) = match diagnostic
        .strip_prefix("emulator failure: native NTDLL service ")?
        .split_once(": ")?
        .0
    {
        "NtOpenKey" if diagnostic.contains("registry key outside selected runtime snapshot") => {
            ("NtOpenKey", 2)
        }
        "NtOpenFile"
            if diagnostic.contains("NT metadata name outside mapped DOS drive namespace") =>
        {
            ("NtOpenFile", 2)
        }
        "NtQueryLicenseValue" if diagnostic.contains("unmeasured NtQueryLicenseValue profile") => {
            ("NtQueryLicenseValue", 0)
        }
        "NtConnectPort" if diagnostic.contains("requires a matched selected guest server") => {
            ("NtConnectPort", 1)
        }
        _ => return None,
    };
    // At the native x64 syscall boundary, R10 holds the first argument.
    let register = match stopped["architecture"].as_str()? {
        "x64" => [10, 2, 8][argument],
        "arm64" => argument,
        _ => return None,
    };
    let thread = ready_native_thread(stopped)?;
    let address = thread["registers"]
        .get(register)?
        .as_str()?
        .strip_prefix("0x")?;
    let mut descriptor = u64::from_str_radix(address, 16).ok()?;
    let read = |address, bytes: &mut [u8]| {
        rax_process_mem_read(process.0, address, bytes.as_mut_ptr(), bytes.len()) == RaxStatus::Ok
    };
    if matches!(service, "NtOpenKey" | "NtOpenFile") {
        // These stops are expected for absolute names. Resolve the native64
        // OBJECT_ATTRIBUTES.ObjectName only when RootDirectory is null.
        let mut attributes = [0; 48];
        if !read(descriptor, &mut attributes)
            || attributes[..4] != 48_u32.to_le_bytes()
            || attributes[8..16] != [0; 8]
        {
            return None;
        }
        descriptor = u64::from_le_bytes(attributes[16..24].try_into().ok()?);
    }
    let mut header = [0; 16];
    if !read(descriptor, &mut header) {
        return None;
    }
    let length = usize::from(u16::from_le_bytes([header[0], header[1]]));
    let maximum = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let buffer = u64::from_le_bytes(header[8..].try_into().ok()?);
    let mut storage = [0; 512];
    let bytes = storage.get_mut(..length)?;
    if length == 0 || length % 2 != 0 || length > maximum || !read(buffer, bytes) {
        return None;
    }
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some((service, String::from_utf16(&units).ok()?))
}

#[cfg(windows)]
#[test]
fn installed_ntdll_is_selected_and_its_termination_leaf_runs_through_c_abi() {
    use rax_engine::user::image::pe::exports::{ExportDirectory, ExportTarget};
    use rax_engine::user::image::pe::{DataDirectory, RvaFault, RvaSource, dir};
    use rax_engine::user::windows::{dll, loader::builtin};
    let arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let base = if arch.is64() { 0x140000000 } else { 0x400000 };
    let mut image = builtin::build(dll::find("ntdll.dll").unwrap(), arch, base, &[]).bytes;
    let pe = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    let flags = u16::from_le_bytes(image[pe + 22..pe + 24].try_into().unwrap()) & !0x2000;
    image[pe + 22..pe + 24].copy_from_slice(&flags.to_le_bytes());
    image[pe + 24 + 68..pe + 24 + 70].copy_from_slice(&1u16.to_le_bytes());
    let options =
        r#"{"native_runtime":true,"guest_path":"C:\\app\\probe.exe","memory_bytes":268435456}"#;
    let process = open(&image, options);
    let before = info(&process);
    assert_eq!(before["capabilities"]["native_runtime"], true);
    assert_eq!(before["capabilities"]["host_filesystem"], false);
    let ntdll = before["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "ntdll.dll")
        .unwrap();
    assert!(
        ntdll["path"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("system32")
    );
    struct Guest<'a> {
        process: &'a Owned,
        base: u64,
    }
    impl RvaSource for Guest<'_> {
        fn read_rva(&self, rva: u64, bytes: &mut [u8]) -> Result<(), RvaFault> {
            let address = self.base.checked_add(rva).ok_or(RvaFault { rva })?;
            if rax_process_mem_read(self.process.0, address, bytes.as_mut_ptr(), bytes.len())
                == RaxStatus::Ok
            {
                Ok(())
            } else {
                Err(RvaFault { rva })
            }
        }
    }
    let guest = Guest {
        process: &process,
        base: address(&ntdll["base"]),
    };
    let pe = u64::from(guest.u32_at(0x3c).unwrap());
    let directories = pe + 24 + if arch.is64() { 112 } else { 96 };
    let at = directories + dir::EXPORT as u64 * 8;
    let range = DataDirectory {
        rva: guest.u32_at(at).unwrap(),
        size: guest.u32_at(at + 4).unwrap(),
    };
    let exports = ExportDirectory::read(&guest, range).unwrap().unwrap();
    let (_, ExportTarget::Rva(rva)) = exports
        .by_name(&guest, b"NtTerminateProcess", None)
        .unwrap()
        .unwrap()
    else {
        panic!("installed termination leaf is a forwarder");
    };
    let tid = before["threads"][0]["id"].as_u64().unwrap() as u32;
    let mut registers = RegContext::from_bytes(arch, context(&process, tid));
    registers.set_pc(guest.base + u64::from(rva));
    if arch == WinArch::X64 {
        registers.set_gpr(1, u64::MAX);
        registers.set_gpr(2, 73);
    } else if arch == WinArch::Arm64 {
        registers.set_gpr(0, u64::MAX);
        registers.set_gpr(1, 73);
    } else {
        let arguments = [0u32, u32::MAX, 73]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            rax_process_mem_write(
                process.0,
                registers.sp(),
                arguments.as_ptr(),
                arguments.len()
            ),
            RaxStatus::Ok
        );
    }
    assert_eq!(
        rax_process_context_write(
            process.0,
            tid,
            registers.bytes().as_ptr(),
            registers.bytes().len()
        ),
        RaxStatus::Ok
    );
    let mut result = RaxProcessResult::default();
    assert_eq!(
        rax_process_run(process.0, 16, 5_000_000, &mut result),
        RaxStatus::Ok
    );
    assert_eq!(result.reason, RAX_PROCESS_EXITED, "{}", info(&process));
    assert_eq!(result.exit_code, 73);

    let name = "C:\\app\\ntdll.dll";
    let broken = b"invalid supplied NTDLL";
    let supplied = RaxProcessImage {
        path: name.as_ptr().cast(),
        path_size: name.len(),
        data: broken.as_ptr(),
        data_size: broken.len(),
    };
    assert!(!refused(&image, options, &[supplied], RaxStatus::Format).is_empty());
}
