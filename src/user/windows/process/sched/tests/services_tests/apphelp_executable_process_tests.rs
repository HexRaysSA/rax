//! Replay ordinary installed `BasepQueryAppCompat` observations.
use super::*;
use crate::user::windows::registry::creator_compat_layer_fixture;

#[derive(serde::Deserialize)]
struct Observation {
    image: String,
    request: u32,
    flags: u32,
    capacity: u32,
    returned: u32,
    driver_status: u32,
    status: u32,
    written: u32,
    records: Vec<u32>,
}

fn prepare(p: &mut Proc, input: u64, row: &Observation) -> (u64, u64) {
    let name = input + PAGE_SIZE;
    let output = name + PAGE_SIZE;
    let path = format!("C:\\Windows\\System32\\{}", row.image);
    let bytes: Vec<_> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    p.space.wr(input, &[0; 392]).unwrap();
    p.space.wr(name, &bytes).unwrap();
    p.space.wr(output, &[0xa5; 177]).unwrap();
    p.space.w32(input, row.request).unwrap();
    p.space.w32(input + 4, row.flags).unwrap();
    p.space.w16(input + 0x30, bytes.len() as u16).unwrap();
    p.space.w64(input + 0x38, name).unwrap();
    p.space.w64(input + 0x178, output).unwrap();
    p.space.w32(input + 0x180, row.capacity).unwrap();
    (name, output)
}

fn observations() -> Vec<Observation> {
    serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-apphelp-cache/executable-process-29708-arm64.json"
    ))
    .unwrap()
}

#[test]
fn apphelp_executable_process_replays_all_stock_native_records() {
    let observations = observations();
    assert_eq!(observations.len(), 13);
    for row in observations {
        let (mut process, mut thread) = fixture(WinArch::Arm64, "NtApphelpCacheControl", SERVICE);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
        p.registry = creator_compat_layer_fixture(Some("C:\\Windows\\System32\\unrelated.exe"));
        let input = scratch(p);
        let (_, output) = prepare(p, input, &row);
        assert_eq!(call(p, &mut thread, 11, input), row.status);
        assert_eq!(p.space.u32(input + 0x170).unwrap(), row.driver_status);
        assert_eq!(p.space.u32(input + 0x180).unwrap(), row.written);
        assert_eq!(p.space.u32(input + 0x184).unwrap(), row.returned);
        assert_eq!(row.records.len() * 4, row.written as usize);
        for (word, expected) in row.records.into_iter().enumerate() {
            assert_eq!(p.space.u32(output + word as u64 * 4).unwrap(), expected);
        }
        assert_eq!(p.space.u8(output + u64::from(row.written)).unwrap(), 0xa5);
    }
}

#[test]
fn apphelp_executable_process_returns_the_captured_amd64_server_cmd_record() {
    let mut cmd = observations()
        .into_iter()
        .find(|row| row.image == "cmd.exe")
        .unwrap();
    let expected = [2, 0, 8, 8, 0, 0, 4, 8, 0, 0, 16, 8, 0, 0, 1, 0];
    for build in [20348, 26100] {
        for flags in [0x30, 0x34] {
            let (mut process, mut thread) = fixture(WinArch::X64, "NtApphelpCacheControl", SERVICE);
            let p = process.state_mut();
            super::super::native_profile::kernel_profile(p, build, WinArch::X64.machine());
            p.registry = creator_compat_layer_fixture(None);
            let input = scratch(p);
            cmd.flags = flags;
            let (_, output) = prepare(p, input, &cmd);
            assert_eq!(call(p, &mut thread, 11, input), STATUS_SUCCESS);
            assert_eq!(p.space.u32(input + 0x180).unwrap(), 64);
            for (word, value) in expected.into_iter().enumerate() {
                assert_eq!(p.space.u32(output + word as u64 * 4).unwrap(), value);
            }
            assert_eq!(p.space.u8(output + 64).unwrap(), 0xa5);
        }
    }
}

#[test]
fn apphelp_executable_process_returns_the_captured_windows_11_arm_cmd_record() {
    let mut cmd = observations()
        .into_iter()
        .find(|row| row.image == "cmd.exe")
        .unwrap();
    let observed_group = [2, 0, 8, 8, 0, 0, 4, 8, 0, 0, 16, 8, 0, 0];
    let expected: Vec<_> = observed_group
        .repeat(3)
        .into_iter()
        .chain([1, 0])
        .flat_map(u32::to_le_bytes)
        .collect();
    assert_eq!(expected.len(), 176);
    for flags in [0x10, 0x14, 0x30, 0x34] {
        let (mut process, mut thread) = fixture(WinArch::Arm64, "NtApphelpCacheControl", SERVICE);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, 26200, WinArch::Arm64.machine());
        p.registry = creator_compat_layer_fixture(None);
        let input = scratch(p);
        cmd.flags = flags;
        let (_, output) = prepare(p, input, &cmd);
        assert_eq!(call(p, &mut thread, 11, input), STATUS_SUCCESS);
        assert_eq!(p.space.u32(input + 0x180).unwrap(), 176);
        assert_eq!(p.space.bytes(output, 176).unwrap(), expected);
        assert_eq!(p.space.u8(output + 176).unwrap(), 0xa5);
    }
}

#[test]
fn apphelp_executable_process_replays_arm_29708_cmd_flags_with_a_file_handle() {
    use crate::user::windows::fs::{FileIdentity, FileLifetime};
    use crate::user::windows::objects::{FileObj, Object};
    use std::sync::Arc;

    let mut cmd = observations()
        .into_iter()
        .find(|row| row.image == "cmd.exe")
        .unwrap();
    let executable = r"C:\Windows\System32\cmd.exe";
    let (mut process, mut thread) = fixture(WinArch::Arm64, "NtApphelpCacheControl", SERVICE);
    let p = process.state_mut();
    super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
    p.registry = creator_compat_layer_fixture(None);
    let input = scratch(p);
    let handle = p.objects.insert(Object::File(FileObj {
        host: None,
        host_path: Default::default(),
        path: format!(r"\??\{executable}"),
        access: 0x120089,
        share: 7,
        lifetime: Arc::new(FileLifetime::new(FileIdentity::Path(executable.into()))),
        null: false,
        append: false,
        delete_on_close: false,
        directory: false,
        overlapped: false,
    }));
    let expected: Vec<_> = cmd
        .records
        .iter()
        .copied()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert_eq!(expected.len(), 64);
    for flags in [0x14, 0x34] {
        cmd.flags = flags;
        let (_, output) = prepare(p, input, &cmd);
        assert_eq!(call(p, &mut thread, 11, input), STATUS_INVALID_HANDLE);
        assert_eq!(p.space.u32(input + 0x180).unwrap(), cmd.capacity);
        assert_eq!(p.space.bytes(output, 65).unwrap(), [0xa5; 65]);
        p.space.w64(input + 0x18, u64::from(handle)).unwrap();
        assert_eq!(call(p, &mut thread, 11, input), STATUS_SUCCESS);
        assert_eq!(p.space.u32(input + 0x180).unwrap(), 64);
        assert_eq!(p.space.bytes(output, 64).unwrap(), expected);
        assert_eq!(p.space.u8(output + 64).unwrap(), 0xa5);
    }
}

#[test]
fn apphelp_executable_process_preserves_the_output_for_an_override_or_unknown_image() {
    let cmd = observations()
        .into_iter()
        .find(|row| row.image == "cmd.exe")
        .unwrap();
    for (path, flags, override_path) in [
        (
            "C:\\Windows\\System32\\cmd.exe",
            cmd.flags,
            Some("C:\\Windows\\System32\\cmd.exe"),
        ),
        ("C:\\Windows\\System32\\new.exe", cmd.flags, None),
        ("C:\\Windows\\System32\\find.exe", 0x34, None),
        (
            "C:\\Windows\\System32\\cmd.exe",
            0x14,
            Some("C:\\Windows\\System32\\cmd.exe"),
        ),
        (
            "C:\\Windows\\System32\\findstr.exe",
            0x10,
            Some("C:\\Windows\\System32\\findstr.exe"),
        ),
        (
            "C:\\Windows\\System32\\findstr.exe",
            0x30,
            Some("C:\\Windows\\System32\\findstr.exe"),
        ),
        ("C:\\Temp\\findstr.exe", 0x30, None),
        (
            "C:\\Windows\\System32\\sort.exe",
            0x10,
            Some("C:\\Windows\\System32\\sort.exe"),
        ),
        (
            "C:\\Windows\\System32\\sort.exe",
            0x30,
            Some("C:\\Windows\\System32\\sort.exe"),
        ),
        ("C:\\Temp\\sort.exe", 0x30, None),
        (
            "C:\\Windows\\System32\\find.exe",
            0x10,
            Some("C:\\Windows\\System32\\find.exe"),
        ),
        (
            "C:\\Windows\\System32\\find.exe",
            0x30,
            Some("C:\\Windows\\System32\\find.exe"),
        ),
        ("C:\\Temp\\find.exe", 0x30, None),
    ] {
        let (mut process, mut thread) = fixture(WinArch::Arm64, "NtApphelpCacheControl", SERVICE);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
        p.registry = creator_compat_layer_fixture(override_path);
        let input = scratch(p);
        let (name, output) = prepare(p, input, &cmd);
        let bytes: Vec<_> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        p.space.wr(name, &bytes).unwrap();
        p.space.w16(input + 0x30, bytes.len() as u16).unwrap();
        p.space.w32(input + 4, flags).unwrap();
        thread.cpu.set_pc(0x1234_0004);
        thread.cpu.set_gpr(0, 11);
        thread.cpu.set_gpr(1, input);
        let outcome = handle_stop(p, &mut thread, stop(WinArch::Arm64, SERVICE));
        assert!(
            matches!(outcome, Outcome::Fail(message) if message.contains("not captured for this image"))
        );
        assert_eq!(p.space.u32(input + 0x180).unwrap(), cmd.capacity);
        assert_eq!(p.space.u32(output).unwrap(), 0xa5a5a5a5);
    }
}

#[test]
fn apphelp_executable_process_preflights_both_output_destinations() {
    let row = &observations()[0];
    let (mut process, mut thread) = fixture(WinArch::Arm64, "NtApphelpCacheControl", SERVICE);
    let p = process.state_mut();
    super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
    p.registry = creator_compat_layer_fixture(None);
    let input = scratch(p);
    let (_, output) = prepare(p, input, row);
    p.vm.protect(input, PAGE_SIZE, prot::READONLY).unwrap();
    assert_eq!(call(p, &mut thread, 11, input), STATUS_ACCESS_VIOLATION);
    assert_eq!(p.space.u32(input + 0x180).unwrap(), row.capacity);
    assert_eq!(p.space.bytes(output, 64).unwrap(), [0xa5; 64]);
}

#[derive(serde::Deserialize)]
struct Wow64Observation {
    path: String,
    flags: u32,
    handle_offset: u64,
    status: u32,
    driver_status: u32,
    output_size: u32,
    output: Vec<u32>,
}

#[test]
fn apphelp_executable_process_replays_wow64_cmd_lookup_and_invalid_handle() {
    use crate::user::windows::fs::{FileIdentity, FileLifetime};
    use crate::user::windows::objects::{FileObj, Object};
    use std::sync::Arc;

    let observations: Vec<Wow64Observation> = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-apphelp-cache/executable-process-29708-wow64.json"
    ))
    .unwrap();
    assert_eq!(observations.len(), 6);
    for row in observations {
        let (mut process, mut thread) = fixture(WinArch::X86, "NtApphelpCacheControl", SERVICE);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
        p.native.as_mut().unwrap().guest_directory = "C:\\Windows\\SysWOW64".into();
        p.registry = creator_compat_layer_fixture(None);
        let base = scratch(p);
        let input = base + PAGE_SIZE - 204;
        let name = base + 2 * PAGE_SIZE;
        let output = base + 3 * PAGE_SIZE;
        let bytes: Vec<_> = row.path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        p.space.wr(input, &[0; 204]).unwrap();
        p.space.wr(name, &bytes).unwrap();
        p.space.wr(output, &[0xa5; 128]).unwrap();
        p.space.w32(input, 0x1f).unwrap();
        p.space.w32(input + 4, row.flags).unwrap();
        p.space.w16(input + 0x1c, bytes.len() as u16).unwrap();
        p.space.w16(input + 0x1e, bytes.len() as u16 + 2).unwrap();
        p.space.w32(input + 0x20, name as u32).unwrap();
        p.space.w32(input + 0xc4, output as u32).unwrap();
        p.space.w32(input + 0xc8, 4096).unwrap();
        p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let handle = p.objects.insert(Object::File(FileObj {
            host: None,
            host_path: Default::default(),
            path: format!(r"\??\{}", row.path),
            access: 0x120089,
            share: 7,
            lifetime: Arc::new(FileLifetime::new(FileIdentity::Path(row.path.into()))),
            null: false,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        }));
        p.space.w32(input + row.handle_offset, handle).unwrap();
        assert_eq!(call(p, &mut thread, 11, input), row.status);
        assert_eq!(p.space.u32(input + 0xc0).unwrap(), row.driver_status);
        assert_eq!(p.space.u32(input + 0xc8).unwrap(), row.output_size);
        assert_eq!(row.output.len(), 32);
        for (index, expected) in row.output.into_iter().enumerate() {
            assert_eq!(p.space.u32(output + index as u64 * 4).unwrap(), expected);
        }
    }
}
