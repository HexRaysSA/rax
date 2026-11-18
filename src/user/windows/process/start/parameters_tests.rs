//! Modern process-parameter fields and their strings form one relocatable block.
//! Sizes/tail offsets come from the independently compiled PHNT layout and the
//! suspended-child observations in specifications/windows/native-process-parameters.

use super::*;
use crate::user::windows::process::WindowsProcess;

#[test]
fn modern_parameter_tail_is_zero_and_disjoint_from_strings_all_abis() {
    for arch in WinArch::ALL {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        for image_path in ["C:\\app\\probe.exe", "C:\\long directory\\program name.exe"] {
            let mut config =
                WindowsConfig::embedded(image_path, vec!["a b".into(), "tail\\".into()], vec![], 0)
                    .unwrap();
            config.seed = Some(1);
            config.env = Some(vec![("TEST".into(), "value".into())]);
            config.arena_bytes = 64 << 20;
            config.cwd = Some("C:\\working directory\\".into());
            let process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
            let p = process.state();
            let o = offsets(arch);
            let (tail, extent, partition) = if arch.is64() {
                (0x410, 0x448, 0x420)
            } else {
                (0x2A4, 0x2C4, 0x2AC)
            };
            let declared = p.space.u32(p.params + o.pp_length).unwrap();
            assert!(declared > extent);
            assert_eq!(
                p.space.u32(p.params + o.pp_maximum_length).unwrap(),
                declared
            );
            assert_eq!(u64::from(declared) % o.ptr, 0);
            assert_eq!(
                p.space
                    .bytes(p.params + tail, (extent as u64 - tail) as usize)
                    .unwrap(),
                vec![0; (extent as u64 - tail) as usize]
            );
            assert_eq!(p.space.u16(p.params + partition).unwrap(), 0);
            assert_eq!(p.space.ptr(p.params + partition + o.ptr, o.ptr).unwrap(), 0);
            let strings_offset = if arch.is64() { 0x450 } else { 0x2C8 };
            assert_eq!(
                p.space
                    .bytes(
                        p.params + u64::from(extent),
                        (strings_offset - u64::from(extent)) as usize
                    )
                    .unwrap(),
                vec![0; (strings_offset - u64::from(extent)) as usize]
            );
            for field in [
                o.pp_current_directory,
                o.pp_image_path_name,
                o.pp_command_line,
                o.pp_dll_path,
            ] {
                let length = u64::from(p.space.u16(p.params + field).unwrap());
                let maximum = u64::from(p.space.u16(p.params + field + 2).unwrap());
                assert_eq!(maximum, length + 2);
                let buffer = p.space.ptr(p.params + field + o.ptr, o.ptr).unwrap();
                assert!(
                    buffer >= p.params + strings_offset,
                    "{arch}: string {field:#x} aliases process-parameter tail"
                );
                assert!(buffer + maximum <= p.params + u64::from(declared));
                assert_eq!(p.space.u16(buffer + length).unwrap(), 0);
            }
            let image_buffer = p
                .space
                .ptr(p.params + o.pp_image_path_name + o.ptr, o.ptr)
                .unwrap();
            assert_eq!(
                p.space.wstr(image_buffer, 256).unwrap(),
                image_path.encode_utf16().collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn declared_parameter_block_survives_rtl_copy_and_rebase_all_abis() {
    for arch in WinArch::ALL {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        let mut config = WindowsConfig::embedded(
            "C:\\program directory\\caf\u{00e9}-\u{1f9ea}.exe",
            vec!["".into(), "quoted \"argument\"".into(), "tail\\".into()],
            vec![],
            0,
        )
        .unwrap();
        config.cwd = Some("C:\\working directory\\\u{65e5}\u{672c}\\".into());
        config.env = Some(vec![("TEST".into(), "value".into())]);
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let o = offsets(arch);
        let original = p.params;
        let declared = u64::from(p.space.u32(original + o.pp_maximum_length).unwrap());
        let fields = [
            o.pp_current_directory,
            o.pp_image_path_name,
            o.pp_command_line,
            o.pp_dll_path,
        ];
        let strings: Vec<_> = fields
            .iter()
            .map(|&field| {
                let length = p.space.u16(original + field).unwrap();
                let buffer = p.space.ptr(original + field + o.ptr, o.ptr).unwrap();
                (
                    field,
                    buffer - original,
                    p.space.bytes(buffer, usize::from(length) + 2).unwrap(),
                )
            })
            .collect();
        let environment = p.space.ptr(original + o.pp_environment, o.ptr).unwrap();
        let environment_size = p
            .space
            .ptr(original + o.pp_environment_size, o.ptr)
            .unwrap();
        let expected_environment = p
            .space
            .bytes(environment, environment_size as usize)
            .unwrap();
        // Installed RTL copies MaximumLength bytes, preserves relative Unicode
        // offsets and publishes a replacement PEB.ProcessParameters pointer.
        let replacement = alloc(p, declared).unwrap();
        let bytes = p.space.bytes(original, declared as usize).unwrap();
        p.space.wr(replacement, &bytes).unwrap();
        for &(field, offset, _) in &strings {
            p.space
                .wptr(replacement + field + o.ptr, o.ptr, replacement + offset)
                .unwrap();
        }
        p.space
            .wptr(p.peb + o.peb_process_parameters, o.ptr, replacement)
            .unwrap();
        p.space
            .wr(original, &vec![0xDD; declared as usize])
            .unwrap();
        assert_eq!(p.current_parameters().unwrap(), replacement);
        assert_eq!(
            p.params, original,
            "initial allocation identity is retained"
        );
        for (field, offset, expected) in strings {
            assert!(
                offset >= o.pp_size && offset + expected.len() as u64 <= declared,
                "{arch}: {field:#x}"
            );
            let buffer = p.space.ptr(replacement + field + o.ptr, o.ptr).unwrap();
            assert_eq!(buffer, replacement + offset);
            assert_eq!(
                p.space.bytes(buffer, expected.len()).unwrap(),
                expected,
                "{arch}: {field:#x}"
            );
        }
        assert_eq!(
            p.space.ptr(replacement + o.pp_environment, o.ptr).unwrap(),
            environment
        );
        assert_eq!(
            p.space
                .bytes(environment, environment_size as usize)
                .unwrap(),
            expected_environment
        );
    }
}

#[test]
fn parameter_unicode_length_includes_terminator_without_ushort_overflow() {
    assert_eq!(
        ParameterString::new(0, &"x".repeat(32766)).unwrap().bytes,
        65532
    );
    assert!(ParameterString::new(0, &"x".repeat(32767)).is_err());
    assert_eq!(ParameterString::new(0, "\u{1f9ea}").unwrap().bytes, 4);
}

#[test]
fn wow64_process_create_companion_parameter_record_owns_strings_and_shares_child_io() {
    let image = include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe");
    let image_path = r"C:\working directory\probe.exe";
    let mut config =
        WindowsConfig::embedded(image_path, vec!["space and λ".into()], vec![], 0).unwrap();
    config.seed = Some(1);
    config.env = Some(vec![("TEST".into(), "λ".into())]);
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    super::super::wow64::initialize_test_profile(p, WinArch::X64.machine()).unwrap();
    let source = p.params;
    let native_peb = p.wow64.as_ref().unwrap().native_peb;
    let guest = offsets(WinArch::X86);
    let native = offsets(WinArch::X64);
    p.space.w32(source + guest.pp_flags, 0x6001).unwrap();
    let view = wow64_child_parameters(p, native_peb).unwrap();
    assert_ne!(source, view);
    assert_eq!(p.space.u32(view + native.pp_flags).unwrap(), 0x6001);
    assert_eq!(
        p.space
            .u64(native_peb + native.peb_process_parameters)
            .unwrap(),
        view
    );
    assert_eq!(
        p.space.u32(p.peb + guest.peb_process_parameters).unwrap() as u64,
        source
    );
    assert_eq!(
        p.space.u64(view + native.pp_console_handle).unwrap(),
        u64::MAX
    );
    let max = u64::from(p.space.u32(view + native.pp_maximum_length).unwrap());
    for (from, to) in [
        (guest.pp_current_directory, native.pp_current_directory),
        (guest.pp_image_path_name, native.pp_image_path_name),
        (guest.pp_command_line, native.pp_command_line),
        (guest.pp_dll_path, native.pp_dll_path),
    ] {
        let from_ptr = p.space.ptr(source + from + guest.ptr, guest.ptr).unwrap();
        let to_ptr = p.space.ptr(view + to + native.ptr, native.ptr).unwrap();
        let count = p.space.u16(source + from).unwrap() as usize;
        assert_ne!(from_ptr, to_ptr);
        assert!(to_ptr >= view + native.pp_size && to_ptr + count as u64 + 2 <= view + max);
        assert_eq!(
            p.space.bytes(from_ptr, count + 2).unwrap(),
            p.space.bytes(to_ptr, count + 2).unwrap()
        );
    }
    for (from, to) in [
        (guest.pp_environment, native.pp_environment),
        (guest.pp_environment_size, native.pp_environment_size),
        (guest.pp_std_input, native.pp_std_input),
        (guest.pp_std_output, native.pp_std_output),
        (guest.pp_std_error, native.pp_std_error),
    ] {
        assert_eq!(
            p.space.ptr(source + from, guest.ptr).unwrap(),
            p.space.ptr(view + to, native.ptr).unwrap()
        );
    }
}
