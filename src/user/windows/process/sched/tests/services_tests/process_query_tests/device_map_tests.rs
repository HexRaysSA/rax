//! ProcessDeviceMap records describe the guest's mapped drives.
use super::{Outcome, WinArch, arguments, dispatch, setup};
use crate::user::windows::memory::Mem;
use std::sync::Arc;

#[test]
fn native_process_device_map_reports_default_and_custom_guest_drives_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut current, output) = setup(arch);
        let p = process.state_mut();
        let sp = current.cpu.sp();
        for custom in [false, true] {
            if custom {
                Arc::make_mut(&mut p.cfg).drives.set('z', "mapped-z");
            }
            p.space.wr(output, &[0xa5; 96]).unwrap();
            current.cpu.set_sp(sp);
            arguments(
                p,
                &mut current,
                arch.ptr(u64::MAX),
                23,
                output,
                36,
                output + 64,
            );
            assert_eq!(dispatch(p, &mut current), Outcome::Continue);
            assert_eq!(current.cpu.gpr(0), 0);
            let mut expected = [0; 36];
            let mask: u32 = 4 | if custom { 1 << 25 } else { 0 };
            expected[..4].copy_from_slice(&mask.to_le_bytes());
            expected[4 + 2] = 3;
            if custom {
                expected[4 + 25] = 3;
            }
            assert_eq!(p.space.bytes(output, 36).unwrap(), expected);
            assert_eq!(p.space.bytes(output + 36, 28).unwrap(), [0xa5; 28]);
            assert_eq!(p.space.u32(output + 64).unwrap(), 36);
            assert_eq!(current.cpu.pc(), 0x1234_0004);
            assert_eq!(
                current.cpu.sp(),
                sp + if arch == WinArch::X86 { 4 } else { 0 }
            );
            assert!(current.frames.is_empty());
        }
    }
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn native_process_device_map_replays_202_independent_native_and_wow64_observations() {
    use crate::user::windows::fs::DriveMap;
    use crate::user::windows::objects::Object;
    let capture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-process-device-map/observations-v2.json"
    ))
    .unwrap();
    let all: [u8; 36] = bytes(capture["all_device_map"].as_str().unwrap())
        .try_into()
        .unwrap();
    let logon: [u8; 36] = bytes(capture["logon_device_map"].as_str().unwrap())
        .try_into()
        .unwrap();
    let mask = u32::from_le_bytes(all[..4].try_into().unwrap());
    let mut replayed = 0;
    for arch in WinArch::ALL {
        for run in capture["runs"].as_array().unwrap() {
            if (run["pointer_bytes"] == 4) != (arch == WinArch::X86) {
                continue;
            }
            for row in run["device_map"].as_array().unwrap() {
                let label = row["label"].as_str().unwrap();
                if label == "logical-drives" {
                    continue;
                }
                let (mut process, mut current, output) = setup(arch);
                let p = process.state_mut();
                let mut drives = DriveMap::empty();
                for index in 0..26 {
                    if mask & (1 << index) != 0 {
                        drives.set(char::from(b'A' + index), format!("mapped-{index}"));
                    }
                }
                drives.apply_device_maps(all, logon).unwrap();
                Arc::make_mut(&mut p.cfg).drives = drives;
                let handle = if label.starts_with("access-") {
                    let access: u32 = label.rsplit_once('-').unwrap().1.parse().unwrap();
                    let object = p.objects.create(Object::Process {
                        pid: p.pid,
                        exit_code: None,
                    });
                    u64::from(p.objects.open_access(object, false, access).unwrap())
                } else {
                    arch.ptr(row["handle"].as_i64().unwrap() as u64)
                };
                p.space
                    .wr(output, &bytes(row["before"].as_str().unwrap()))
                    .unwrap();
                p.space.w32(output + 128, 0xa5a5_a5a5).unwrap();
                let destination = if row["bad_output"].as_bool().unwrap() {
                    1
                } else {
                    let offset = row["output_offset"].as_i64().unwrap();
                    if offset < 0 {
                        0
                    } else {
                        output + offset as u64
                    }
                };
                let returned = if row["bad_returned"].as_bool().unwrap() {
                    1
                } else {
                    output + 128
                };
                let sp = current.cpu.sp();
                arguments(
                    p,
                    &mut current,
                    handle,
                    23,
                    destination,
                    row["length"].as_u64().unwrap() as u32,
                    returned,
                );
                assert_eq!(
                    dispatch(p, &mut current),
                    Outcome::Continue,
                    "{arch}/{label}"
                );
                assert_eq!(
                    current.cpu.gpr(0),
                    row["status"].as_u64().unwrap(),
                    "{arch}/{label}"
                );
                assert_eq!(
                    p.space.bytes(output, 96).unwrap(),
                    bytes(row["after"].as_str().unwrap()),
                    "{arch}/{label}"
                );
                assert_eq!(
                    u64::from(p.space.u32(output + 128).unwrap()),
                    row["returned"].as_u64().unwrap(),
                    "{arch}/{label}"
                );
                assert_eq!(current.cpu.pc(), 0x1234_0004);
                assert_eq!(
                    current.cpu.sp(),
                    sp + if arch == WinArch::X86 { 4 } else { 0 }
                );
                assert!(current.frames.is_empty());
                replayed += 1;
            }
        }
    }
    assert_eq!(replayed, 303, "101 native observations per guest ABI");
}

#[test]
fn native_process_device_map_replays_partial_publication_and_guard_visitation() {
    use crate::user::mm::PAGE_SIZE;
    use crate::user::windows::fs::DriveMap;
    use crate::user::windows::memory::{mem, prot};
    let capture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-process-device-map/boundary-observations-v2.json"
    ))
    .unwrap();
    let all: [u8; 36] = bytes(capture["all_device_map"].as_str().unwrap())
        .try_into()
        .unwrap();
    let logon: [u8; 36] = bytes(capture["logon_device_map"].as_str().unwrap())
        .try_into()
        .unwrap();
    let mask = u32::from_le_bytes(all[..4].try_into().unwrap());
    let mut replayed = 0;
    for arch in WinArch::ALL {
        let run = capture["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| (run["pointer_bytes"] == 4) == (arch == WinArch::X86))
            .unwrap();
        for row in run["observations"].as_array().unwrap() {
            let (mut process, mut current, scratch) = setup(arch);
            let p = process.state_mut();
            let mut drives = DriveMap::empty();
            for index in 0..26 {
                if mask & (1 << index) != 0 {
                    drives.set(char::from(b'A' + index), format!("mapped-{index}"));
                }
            }
            drives.apply_device_maps(all, logon).unwrap();
            Arc::make_mut(&mut p.cfg).drives = drives;
            let pages =
                p.vm.allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
            let second = pages + PAGE_SIZE;
            let available = row["available"].as_u64().unwrap();
            let output = second - available;
            let protection = row["protection"].as_u64().unwrap() as u32;
            let length = row["length"].as_u64().unwrap() as u32;
            let label =
                format!("{arch}/length{length}/available{available}/protection{protection:#x}");
            p.space
                .wr(output, &bytes(row["before"].as_str().unwrap()))
                .unwrap();
            p.space.w32(scratch, 0xa5a5_a5a5).unwrap();
            p.vm.protect(second, PAGE_SIZE, protection).unwrap();
            arguments(
                p,
                &mut current,
                arch.ptr(u64::MAX),
                23,
                output,
                length,
                scratch,
            );
            assert_eq!(dispatch(p, &mut current), Outcome::Continue, "{label}");
            assert_eq!(
                current.cpu.gpr(0),
                row["status"].as_u64().unwrap(),
                "{label}"
            );
            assert_eq!(
                u64::from(p.space.u32(scratch).unwrap()),
                row["returned"].as_u64().unwrap(),
                "{label}"
            );
            assert_eq!(
                u64::from(p.vm.query(second).unwrap().protect),
                row["remaining_protection"].as_u64().unwrap(),
                "{label}"
            );
            p.vm.protect(second, PAGE_SIZE, prot::READWRITE).unwrap();
            assert_eq!(
                p.space.bytes(output, 96).unwrap(),
                bytes(row["after"].as_str().unwrap()),
                "{label}"
            );
            replayed += 1;
        }
    }
    assert_eq!(replayed, 1176, "392 independent native cases per guest ABI");
}
