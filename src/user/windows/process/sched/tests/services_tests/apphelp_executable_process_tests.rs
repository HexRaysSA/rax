//! Replay ordinary installed ARM64 `BasepQueryAppCompat` observations.
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
    p.space.wr(output, &[0xa5; 128]).unwrap();
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
    assert_eq!(observations.len(), 8);
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
