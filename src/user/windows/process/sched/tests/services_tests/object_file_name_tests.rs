use super::*;
use crate::user::windows::hle::{ApiErr, Ctx, Flow, Value};
use crate::user::windows::nt::status::*;
use crate::user::windows::{dll, memory::Mem};
use serde::Deserialize;

type Ordinary = (bool, u32, Option<u64>, bool, u8, u32, u32, Option<u16>);
type Threshold = (u32, u32, u32, Option<u16>);

#[derive(Deserialize)]
struct Capture {
    version: [u32; 3],
    machine: String,
    name_bytes: usize,
    device_units: usize,
    needed: u32,
    opened_name_matches: bool,
    ordinary: Vec<Ordinary>,
    thresholds: Vec<Threshold>,
    aliases: Vec<(u32, i64, u8, u32)>,
}

fn capture() -> Capture {
    let capture: Capture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-object-file-name/arm64-29708.json"
    )))
    .unwrap();
    assert_eq!(capture.version, [10, 0, 29708]);
    assert_eq!(capture.machine, "ARM64");
    assert!(capture.opened_name_matches);
    assert_eq!(capture.needed as usize, 16 + capture.name_bytes + 2);
    capture
}

const BYTES: usize = 576;

fn replay(
    p: &mut Proc,
    t: &mut Thread,
    output: u64,
    length: u32,
    returned: u64,
    resolve: impl FnOnce() -> Option<(Vec<u16>, usize)>,
) -> u32 {
    let sp = t.cpu.sp();
    let c = Ctx {
        p,
        t,
        api: dll::nt_service("NtQueryObject", WinArch::Arm64).unwrap(),
        entry_pc: 0x1234_0000,
        entry_sp: sp,
        ret_addr: 0x1234_0004,
        cursor: sp - 32,
    };
    match dll::object_name_replay(&c, output, length, returned, || Ok(resolve())) {
        Ok(Flow::Ret(Value::Int(status))) => status as u32,
        Err(ApiErr::Fault(fault)) if fault.write && fault.addr == 0 => STATUS_ACCESS_VIOLATION,
        other => panic!("unexpected object name flow: {}", other.is_ok()),
    }
}

fn synthetic_name(oracle: &Capture) -> Vec<u16> {
    let mut name: Vec<_> = "\\Device\\HarddiskVolume9".encode_utf16().collect();
    assert_eq!(name.len(), oracle.device_units);
    name.extend("\\Owned Fixture α".encode_utf16());
    name.resize(oracle.name_bytes / 2, u16::from(b'x'));
    name
}

fn expected_record(expected: &mut [u8], name: &[u16], address: u64, copied: Option<u16>) {
    let Some(copied) = copied else { return };
    expected[..2].copy_from_slice(&copied.to_le_bytes());
    expected[2..4].copy_from_slice(&(copied + 2).to_le_bytes());
    expected[8..16].copy_from_slice(&(address + 16).to_le_bytes());
    let units = name[..usize::from(copied) / 2].iter().copied().chain([0]);
    for (bytes, unit) in expected[16..].chunks_exact_mut(2).zip(units) {
        bytes.copy_from_slice(&unit.to_le_bytes());
    }
}

#[test]
fn native_object_file_name_replays_480_native_status_probe_and_copy_cases() {
    let oracle = capture();
    let name = synthetic_name(&oracle);
    let (mut process, mut t, base) = query_fixture(WinArch::Arm64);
    let p = process.state_mut();
    let ret = base + BYTES as u64;
    assert_eq!(oracle.ordinary.len(), 480);
    for (valid, length, alignment, with_return, poison, status, returned, copied) in oracle.ordinary
    {
        let mut expected = [poison; BYTES];
        p.space.wr(base, &expected).unwrap();
        p.space.w32(ret, 0xDEAD_BEEF).unwrap();
        let output = alignment.map_or(0, |offset| base + offset);
        assert_eq!(
            replay(
                p,
                &mut t,
                output,
                length,
                if with_return { ret } else { 0 },
                || { valid.then(|| (name.clone(), oracle.device_units)) }
            ),
            status,
            "length={length}, alignment={alignment:?}, valid={valid}"
        );
        expected_record(
            &mut expected[alignment.unwrap_or(0) as usize..],
            &name,
            output,
            copied,
        );
        assert_eq!(p.space.bytes(base, BYTES).unwrap(), expected);
        assert_eq!(p.space.u32(ret).unwrap(), returned);
    }
}

#[test]
fn native_object_file_name_replays_562_length_and_144_alias_cases() {
    let oracle = capture();
    let name = synthetic_name(&oracle);
    let (mut process, mut t, base) = query_fixture(WinArch::Arm64);
    let p = process.state_mut();
    let ret = base + BYTES as u64;
    assert_eq!((oracle.thresholds.len(), oracle.aliases.len()), (281, 144));
    let resolve = || Some((name.clone(), oracle.device_units));
    for &(length, status, returned, copied) in &oracle.thresholds {
        for offset in [0, 4] {
            let mut expected = [0xa5; BYTES];
            let output = base + offset;
            p.space.wr(base, &expected).unwrap();
            p.space.w32(ret, 0xDEAD_BEEF).unwrap();
            assert_eq!(replay(p, &mut t, output, length, ret, resolve), status);
            expected_record(&mut expected[offset as usize..], &name, output, copied);
            assert_eq!(
                p.space.bytes(base, BYTES).unwrap(),
                expected,
                "length={length}"
            );
            assert_eq!(p.space.u32(ret).unwrap(), returned);
        }
    }
    for (length, delta, poison, status) in oracle.aliases {
        let start = 32;
        let output = base + start as u64;
        let alias = output.checked_add_signed(delta).unwrap();
        let mut expected = [poison; BYTES];
        p.space.wr(base, &expected).unwrap();
        let (returned, copied) = if let Some(&(_, _, returned, copied)) =
            oracle.thresholds.iter().find(|&&(size, ..)| size == length)
        {
            (returned, copied)
        } else if length < 12 {
            (oracle.needed, None)
        } else {
            assert!(length > oracle.needed);
            (oracle.needed, Some(oracle.name_bytes as u16))
        };
        expected_record(&mut expected[start..], &name, output, copied);
        let at = (alias - base) as usize;
        expected[at..at + 4].copy_from_slice(&returned.to_le_bytes());
        assert_eq!(replay(p, &mut t, output, length, alias, resolve), status);
        assert_eq!(p.space.bytes(base, BYTES).unwrap(), expected);
    }
}

#[cfg(all(windows, target_arch = "aarch64"))]
#[test]
fn native_object_file_name_projects_retained_windows_file_through_the_guest_volume() {
    use super::file_open_tests::Harness;
    let mut harness = Harness::new(WinArch::Arm64);
    let base = harness.base;
    let attrs = harness.attrs();
    assert_eq!(
        harness.invoke_api("NtOpenFile", &[base, 0x100021, attrs, base + 8, 7, 0x60]),
        STATUS_SUCCESS
    );
    let handle = harness.process.state_mut().space.u64(base).unwrap();
    native_profile::kernel_profile(harness.process.state_mut(), 29708, 0xAA64);
    let output = base + 64;
    let ret = output + 1024;
    let arguments = [handle, 1, output, 1024, ret];
    assert_eq!(
        harness.invoke_api("NtQueryObject", &arguments),
        STATUS_SUCCESS
    );
    let p = harness.process.state_mut();
    let length = p.space.u16(output).unwrap();
    assert_eq!(p.space.u16(output + 2).unwrap(), length + 2);
    assert_eq!(p.space.u64(output + 8).unwrap(), output + 16);
    assert_eq!(p.space.u32(ret).unwrap(), 16 + u32::from(length) + 2);
    let wire = p.space.bytes(output + 16, usize::from(length)).unwrap();
    let units: Vec<_> = wire
        .chunks_exact(2)
        .map(|n| u16::from_le_bytes([n[0], n[1]]))
        .collect();
    let name = String::from_utf16(&units).unwrap();
    let (volume, relative) = name
        .strip_prefix("\\Device\\HarddiskVolume")
        .unwrap()
        .split_once('\\')
        .unwrap();
    assert!(!volume.is_empty() && volume.bytes().all(|byte| byte.is_ascii_digit()));
    assert_eq!(relative, "fixture.bin");
    assert_eq!(p.space.u16(output + 16 + u64::from(length)).unwrap(), 0);
    p.objects.close(handle).unwrap();
    assert_eq!(
        harness.invoke_api("NtQueryObject", &arguments),
        STATUS_INVALID_HANDLE
    );
}
