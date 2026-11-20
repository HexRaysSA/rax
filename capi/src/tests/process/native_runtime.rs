//! Installed runtime grants exercised through the exported C process interface.
use super::*;

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
        let mut result = RaxProcessResult::default();
        // Bound guest work independently of host speed or descheduling. The
        // separate timeout/cancellation tests exercise those API contracts.
        const MAX_TURNS: u64 = 16_384;
        let mut remaining = MAX_TURNS;
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
            info(&process)
        );
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

#[cfg(windows)]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_cmd_ver_matches_native_through_closed_c_abi() {
    use std::path::PathBuf;
    use std::process::Command;

    let system_root = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"));
    let system32 = system_root.join("System32");
    let current_directory = system32.to_str().expect("Unicode system library path");
    let program = system32.join("cmd.exe");
    let program_path = program.to_str().expect("Unicode system program path");
    let arguments = ["/d", "/c", "ver"];
    let environment = [
        (
            "SystemRoot",
            system_root.to_str().expect("Unicode system root"),
        ),
        ("windir", system_root.to_str().expect("Unicode system root")),
        ("ComSpec", program_path),
        ("PATH", current_directory),
    ];
    let native = Command::new(&program)
        .args(arguments)
        .current_dir(&system32)
        .env_clear()
        .envs(environment)
        .output()
        .expect("native installed cmd");
    assert!(native.status.success());
    assert!(!native.stdout.is_empty());

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
    assert_eq!(
        result.reason,
        RAX_PROCESS_EXITED,
        "guest {} stopped after {} scheduler turns: {}",
        opened["architecture"],
        MAX_TURNS - remaining,
        info(&process)["diagnostic"]
    );
    assert_eq!(
        Some(result.exit_code),
        native.status.code().map(i32::cast_unsigned)
    );
    for (stream, expected) in [
        (RAX_PROCESS_STDOUT, native.stdout),
        (RAX_PROCESS_STDERR, native.stderr),
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
            "console stream {stream}"
        );
    }
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
