//! Guest-owned image extension queries; independent build29683 native evidence.
use super::*;
use crate::user::windows::memory::AllocKind;
use std::collections::HashMap;
#[path = "image_extension_owner_tests.rs"]
mod owner;

#[cfg(windows)]
#[path = "image_extension_leaf_tests.rs"]
mod installed;

#[path = "image_extension_amd64_tests.rs"]
mod amd64;

fn fields(line: &str) -> HashMap<&str, &str> {
    line.split_whitespace()
        .filter_map(|part| part.split_once('='))
        .collect()
}
fn number(fields: &HashMap<&str, &str>, name: &str, radix: u32) -> u64 {
    u64::from_str_radix(fields[name], radix).unwrap()
}
fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

const MATRIX: [(WinArch, &str); 4] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-query-probe-arm64.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-query-probe-x64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-query-probe-x86.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-query-probe-x86-laa.log"
        ),
    ),
];
const BOUNDARIES: [(WinArch, &str); 4] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-boundaries-v2-arm64.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-boundaries-v2-x64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-boundaries-v2-x86.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-boundaries-v2-x86-laa.log"
        ),
    ),
];
const LIMITS: [(WinArch, &str); 4] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-limits-arm64.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-limits-x64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-limits-x86.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-image-extension/native-image-extension-limits-x86-laa.log"
        ),
    ),
];

fn image(p: &mut Proc) -> u64 {
    let base =
        p.vm.reserve(
            None,
            PAGE_SIZE * 3,
            prot::EXECUTE_WRITECOPY,
            AllocKind::Image,
            false,
            None,
        )
        .unwrap();
    p.vm.commit(base, PAGE_SIZE * 3, prot::EXECUTE_READ)
        .unwrap();
    base
}

#[test]
fn native_image_extension_matrix_replays_absent_images_and_abi_availability() {
    let (replayed, present_controls) = replay_query_profiles(&MATRIX, None);
    assert_eq!(replayed, 14280);
    assert_eq!(present_controls, 2520);
}

fn replay_query_profiles(
    inputs: &[(WinArch, &str)],
    availability: Option<crate::user::windows::object_namespace::ExtensionQuery>,
) -> (u64, u64) {
    let mut replayed = 0;
    let mut present_controls = 0;
    for &(arch, log) in inputs {
        let (mut process, mut t, base) = setup(arch);
        let caller_sp = t.cpu.sp();
        let p = process.state_mut();
        p.object_namespace.image_extension_query = availability;
        let target_image = image(p);
        let mapped =
            p.vm.reserve(
                None,
                PAGE_SIZE,
                prot::READWRITE,
                AllocKind::Mapped,
                false,
                None,
            )
            .unwrap();
        p.vm.commit(mapped, PAGE_SIZE, prot::READWRITE).unwrap();
        let mut count = 0;
        for line in log.lines().filter(|line| line.starts_with("case=")) {
            let f = fields(line);
            assert_eq!(number(&f, "case", 10), count);
            count += 1;
            let target = number(&f, "target", 10);
            assert_eq!(number(&f, "exception", 16), 0);
            // This fixture models absent images. Present NTDLL controls belong
            // to the separate owner tests and are excluded from this corpus.
            if arch.is64() && [0, 2, 3].contains(&target) {
                present_controls += 1;
                continue;
            }
            let address = match target {
                0 | 1 => target_image,
                2 => target_image + 1,
                3 => target_image + PAGE_SIZE * 3,
                4 => base + PAGE_SIZE * 2,
                5 => 0,
                6 => 1,
                7 => arch.ptr(u64::MAX),
                8 => target_image + PAGE_SIZE * 3 - 1,
                9 => mapped,
                _ => panic!("unknown native target"),
            };
            let out = base + 128;
            let returned = base + 256;
            p.space
                .wr(base, &vec![0xa5; PAGE_SIZE as usize * 4])
                .unwrap();
            p.space.w32(out, number(&f, "type", 16) as u32).unwrap();
            p.space
                .w32(out + 4, number(&f, "flags", 16) as u32)
                .unwrap();
            p.space
                .wptr(returned, arch.ptr_size(), arch.ptr(u64::MAX))
                .unwrap();
            // Raw WoW64 dispatch stops before the caller's RET cleanup. Each
            // captured invocation begins from its own balanced caller frame.
            t.cpu.set_sp(caller_sp);
            let result = query(
                p,
                &mut t,
                address,
                14,
                out,
                number(&f, "length", 10),
                returned,
            );
            assert_eq!(result, number(&f, "status", 16) as u32, "{arch} {line}");
            assert_eq!(
                p.space.bytes(out, 64).unwrap(),
                hex(f["bytes"]),
                "{arch} {line}"
            );
            assert_eq!(
                read_ptr(p, returned),
                number(&f, "returned", 16),
                "{arch} {line}"
            );
            replayed += 1;
        }
        assert_eq!(count, 4200);
    }
    (replayed, present_controls)
}

#[test]
fn native_image_extension_boundaries_replay_status_bytes_guards_and_process_rights() {
    replay_boundaries(BOUNDARIES, 15480);
}

#[test]
fn native_image_extension_limits_replay_without_consuming_range_rejected_guards() {
    replay_boundaries(LIMITS, 1092);
}

fn replay_boundaries(inputs: [(WinArch, &str); 4], expected: u64) {
    assert_eq!(
        replay_boundary_profiles(&inputs, expected, None, 0),
        expected * 4
    );
}

fn replay_boundary_profiles(
    inputs: &[(WinArch, &str)],
    expected: u64,
    availability: Option<crate::user::windows::object_namespace::ExtensionQuery>,
    valid_type: u32,
) -> u64 {
    let mut total = 0;
    for &(arch, log) in inputs {
        let (mut process, mut t, base) = setup(arch);
        let caller_sp = t.cpu.sp();
        let p = process.state_mut();
        p.object_namespace.image_extension_query = availability;
        let target_image = image(p);
        let mut handles = vec![arch.ptr(u64::MAX), 0, arch.ptr(u64::MAX - 1), 0x1234];
        for access in [0, 0x10, 0x400, 0x1000, 0x1400] {
            let object = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            handles.push(p.objects.open_access(object, false, access).unwrap().into());
        }
        let event = p.objects.create(Object::Event {
            manual: false,
            signaled: 0,
        });
        handles.push(p.objects.open(event, false).into());
        let objects_before = p.objects.iter().count();
        let mut count = 0;
        for line in log.lines().filter(|line| line.starts_with("case=")) {
            let f = fields(line);
            assert_eq!(number(&f, "case", 10), count);
            count += 1;
            for page in 0..4 {
                p.vm.protect(base + page * PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
                    .unwrap();
            }
            p.space
                .wr(base, &vec![0xa5; PAGE_SIZE as usize * 4])
                .unwrap();
            let om = number(&f, "output", 10);
            let rm = number(&f, "returned", 10);
            let selector = number(&f, "selector", 10);
            let out = match om {
                0 => base + 128,
                1 => 0,
                2 => 1,
                3 => base + 129,
                4 => base + 132,
                5..=7 => base + PAGE_SIZE,
                8..=10 => base + PAGE_SIZE - 16,
                11 => base + PAGE_SIZE - 24,
                12 => arch.ptr(u64::MAX - 7),
                13 => 0x7fff_0000,
                _ => panic!("unknown output mode"),
            };
            if om < 12 && om != 1 && om != 2 {
                p.space
                    .w32(out, if selector == 1 { 2 } else { valid_type })
                    .unwrap();
                p.space.w32(out + 4, u32::from(selector == 2)).unwrap();
            }
            let returned = match rm {
                0 => base + 256,
                1 => 0,
                2 => 1,
                3 => base + 257,
                4..=6 => base + PAGE_SIZE * 2,
                7 => base + PAGE_SIZE,
                8 => out,
                9 => base + PAGE_SIZE * 2 - 4,
                _ => panic!("unknown returned mode"),
            };
            if [5, 8, 11].contains(&om) {
                p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
            }
            if [6, 9].contains(&om) {
                p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            if [7, 10].contains(&om) {
                p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
                    .unwrap();
            }
            if [4, 9].contains(&rm) {
                p.vm.protect(base + PAGE_SIZE * 2, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
            }
            if rm == 5 {
                p.vm.protect(
                    base + PAGE_SIZE * 2,
                    PAGE_SIZE,
                    prot::READWRITE | prot::GUARD,
                )
                .unwrap();
            }
            if rm == 6 {
                p.vm.protect(base + PAGE_SIZE * 2, PAGE_SIZE, prot::READONLY)
                    .unwrap();
            }
            let address = match number(&f, "target", 10) {
                0 => target_image,
                1 => base + PAGE_SIZE * 3,
                2 => 1,
                3 => 0,
                4 => arch.ptr(u64::MAX),
                _ => panic!("unknown target mode"),
            };
            let process_handle = handles[number(&f, "process", 10) as usize];
            t.cpu.set_sp(caller_sp);
            arguments(
                p,
                &mut t,
                &[
                    process_handle,
                    address,
                    14,
                    out,
                    number(&f, "length", 16),
                    returned,
                ],
            );
            assert_eq!(dispatch(p, &mut t), Outcome::Continue, "{arch} {line}");
            assert!(t.frames.is_empty());
            assert_eq!(
                t.cpu.gpr(0) as u32,
                number(&f, "status", 16) as u32,
                "{arch} {line}"
            );
            assert_eq!(number(&f, "exception", 16), 0);
            let native: Vec<_> = f["protection"]
                .split(',')
                .filter(|v| !v.is_empty())
                .map(|v| u32::from_str_radix(v, 16).unwrap())
                .collect();
            for (page, expected) in native.iter().enumerate() {
                assert_eq!(
                    p.vm.query(base + page as u64 * PAGE_SIZE).unwrap().protect,
                    *expected,
                    "{arch} {line}"
                );
                p.vm.protect(base + page as u64 * PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
                    .unwrap();
            }
            for (name, offset, length) in [
                ("bytes0", 120, 160),
                ("bytes1", 4064, 96),
                ("bytes2", 8176, 48),
            ] {
                assert_eq!(
                    p.space.bytes(base + offset, length).unwrap(),
                    hex(f[name]),
                    "{arch} {name} {line}"
                );
            }
            total += 1;
        }
        assert_eq!(count, expected);
        assert_eq!(p.objects.iter().count(), objects_before);
    }
    total
}

#[test]
fn native_image_extension_absent_metadata_matches_image_flags_and_aliases() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        for kind in [0, 1] {
            for offset in [0, 1, PAGE_SIZE * 3 - 1] {
                for alias in [false, true] {
                    let (mut process, mut t, base) = setup(arch);
                    let p = process.state_mut();
                    let target = image(p);
                    assert_eq!(
                        query(p, &mut t, target, 6, base + 512, 24, 0),
                        STATUS_SUCCESS
                    );
                    assert_eq!(p.space.u32(base + 528).unwrap(), 0);
                    let out = base + 128;
                    let returned = if alias { out } else { base + 256 };
                    p.space.w32(out, kind).unwrap();
                    p.space.w32(out + 4, 0).unwrap();
                    assert_eq!(
                        query(p, &mut t, target + offset, 14, out, 64, returned),
                        STATUS_SUCCESS
                    );
                    assert_eq!(
                        p.space.u64(out).unwrap(),
                        if alias { 24 } else { u64::from(kind) }
                    );
                    assert_eq!(p.space.bytes(out + 8, 16).unwrap(), vec![0; 16]);
                    assert_eq!(p.space.u64(returned).unwrap(), 24);
                    assert_eq!(p.space.u8(out + 24).unwrap(), 0xa5);
                    assert!(p.vm.is_free(target + PAGE_SIZE * 3, PAGE_SIZE));
                    p.vm.release(target).unwrap();
                    p.space.w32(out, kind).unwrap();
                    p.space.w32(out + 4, 0).unwrap();
                    assert_eq!(
                        query(p, &mut t, target, 14, out, 24, 0),
                        STATUS_MEMORY_NOT_ALLOCATED
                    );
                }
            }
        }
    }
}

#[test]
fn native_image_extension_native_validation_priority_and_wow_unavailable() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let target = image(p);
        let out = base + 128;
        let returned = base + PAGE_SIZE * 2;
        p.vm.protect(returned, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        if arch == WinArch::X86 {
            assert_eq!(
                query(p, &mut t, target, 14, 1, 0, returned),
                STATUS_INVALID_INFO_CLASS
            );
            assert_eq!(p.vm.query(returned).unwrap().protect, prot::READWRITE);
            assert_eq!(p.space.u32(returned).unwrap(), 0xa5a5_a5a5);
            assert_eq!(
                query(p, &mut t, arch.ptr(u64::MAX), 14, 0, 0, 1),
                STATUS_INVALID_INFO_CLASS
            );
            continue;
        }
        assert_eq!(
            query(p, &mut t, p.arch.ptr(u64::MAX), 14, 1, 0, returned),
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            query(p, &mut t, target, 14, 1, 23, returned),
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            query(p, &mut t, 0, 14, 1, 0, returned),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            query(p, &mut t, 0, 14, 1, 24, returned),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            p.vm.query(returned).unwrap().protect,
            prot::READWRITE | prot::GUARD
        );
        p.space.w32(out, 0).unwrap();
        p.space.w32(out + 4, 1).unwrap();
        assert_eq!(
            query(p, &mut t, target, 14, out, 24, returned),
            STATUS_GUARD_PAGE_VIOLATION
        );
        assert_eq!(p.vm.query(returned).unwrap().protect, prot::READWRITE);
        assert_eq!(
            query(p, &mut t, target, 14, out, 24, returned),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(p.space.u64(returned).unwrap(), 0xa5a5_a5a5_a5a5_a5a5);
        p.space.w32(out + 4, 0).unwrap();
        p.space.w32(out, 2).unwrap();
        assert_eq!(
            query(p, &mut t, base + PAGE_SIZE * 3, 14, out, 24, 0),
            STATUS_INVALID_ADDRESS
        );
        assert_eq!(
            query(p, &mut t, 1, 14, out, 24, 0),
            STATUS_MEMORY_NOT_ALLOCATED
        );
        assert_eq!(
            query(p, &mut t, target, 14, out, 24, 0),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            query(p, &mut t, target, 14, out + 4, 24, 0),
            STATUS_DATATYPE_MISALIGNMENT
        );
    }
}
