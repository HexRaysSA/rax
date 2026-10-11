//! Class 107 / RelationGroup buffer contract measured on Windows build 29683.

use super::*;

const SERVICE: u32 = 0x16E; // Synthetic table identity, not a host-build table.

#[cfg(windows)]
#[path = "topology_leaf_tests.rs"]
mod leaf_tests;

fn group_fixture(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtQuerySystemInformationEx", SERVICE);
    let p = process.state_mut();
    let scratch =
        p.vm.allocate(
            None,
            4 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.space
        .wr(scratch, &vec![0xA5; (4 * PAGE_SIZE) as usize])
        .unwrap();
    p.space.w32(scratch, 4).unwrap();
    (process, t, scratch)
}

fn group_call(p: &mut Proc, t: &mut Thread, args: [u64; 6]) -> Outcome {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            for (index, value) in [0x1234_0004, 0x1234_0000]
                .into_iter()
                .chain(args)
                .enumerate()
            {
                p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(10, args[0]);
            t.cpu.set_gpr(1, 0x1234_0004);
            for (register, value) in [2, 8, 9].into_iter().zip(args[1..4].iter().copied()) {
                t.cpu.set_gpr(register, value);
            }
            for (index, value) in args[4..].iter().copied().enumerate() {
                p.space.w64(sp + 40 + index as u64 * 8, value).unwrap();
            }
        }
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
    }
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    if outcome == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    outcome
}

fn group_record(arch: WinArch) -> Vec<u8> {
    let size = if arch == WinArch::X86 { 76 } else { 80 };
    let mut record = vec![0; size];
    record[..4].copy_from_slice(&4u32.to_le_bytes());
    record[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    record[8..12].copy_from_slice(&[1, 0, 1, 0]);
    record[32..34].copy_from_slice(&[1, 1]);
    record[72] = 1;
    record
}

#[test]
fn native_group_topology_sizes_projected_cpu_and_untouched_suffix_all_abis() {
    for arch in WinArch::ALL {
        for input_bytes in [0, 1, 2, 3, 4, 5, 8, 16] {
            for output_bytes in [0, 1, 4, 75, 76, 79, 80, 81, 96] {
                let (mut process, mut t, scratch) = group_fixture(arch);
                let p = process.state_mut();
                let output = scratch + PAGE_SIZE;
                let returned = scratch + 2 * PAGE_SIZE;
                assert_eq!(
                    group_call(
                        p,
                        &mut t,
                        [107, scratch, input_bytes, output, output_bytes, returned]
                    ),
                    Outcome::Continue,
                    "{arch}/{input_bytes}/{output_bytes}"
                );
                let record = group_record(arch);
                let expected = if input_bytes < 4 {
                    STATUS_INVALID_PARAMETER
                } else if output_bytes < record.len() as u64 {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_SUCCESS
                };
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(expected),
                    "{arch}/{input_bytes}/{output_bytes}"
                );
                let mut data = vec![0xA5; 128];
                if expected == STATUS_SUCCESS {
                    data[..record.len()].copy_from_slice(&record);
                }
                assert_eq!(p.space.bytes(output, 128).unwrap(), data);
                assert_eq!(
                    p.space.u32(returned).unwrap(),
                    if input_bytes < 4 {
                        0xA5A5_A5A5
                    } else {
                        record.len() as u32
                    }
                );
            }
        }
    }
}

#[test]
fn native_group_topology_fault_order_and_destination_write_order_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..12 {
            let (mut process, mut t, scratch) = group_fixture(arch);
            let p = process.state_mut();
            let (mut input, mut input_bytes, mut output, mut output_bytes, mut returned) =
                (scratch, 4, scratch + PAGE_SIZE, 96, scratch + 2 * PAGE_SIZE);
            let expected = match role {
                0 => {
                    input = 0;
                    output = 0;
                    returned = 1;
                    STATUS_INVALID_PARAMETER
                }
                1 => {
                    input_bytes = 0;
                    input += 1;
                    output = 0;
                    returned = 1;
                    STATUS_INVALID_PARAMETER
                }
                2 => {
                    input += 1;
                    input_bytes = 3;
                    output = 0;
                    STATUS_DATATYPE_MISALIGNMENT
                }
                3 => {
                    input_bytes = 3;
                    p.vm.protect(scratch, PAGE_SIZE, prot::NOACCESS).unwrap();
                    STATUS_INVALID_PARAMETER
                }
                4 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::NOACCESS).unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                5 => {
                    input_bytes = 3;
                    p.vm.protect(output, PAGE_SIZE, prot::READONLY).unwrap();
                    if arch == WinArch::X86 {
                        STATUS_INVALID_PARAMETER
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }
                }
                6 => {
                    input_bytes = 3;
                    p.vm.protect(returned, PAGE_SIZE, prot::READONLY).unwrap();
                    if arch == WinArch::X86 {
                        STATUS_INVALID_PARAMETER
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }
                }
                7 => {
                    p.vm.protect(returned, PAGE_SIZE, prot::READONLY).unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                8 => {
                    output = 0;
                    output_bytes = 0;
                    STATUS_INFO_LENGTH_MISMATCH
                }
                9 => {
                    output = 0;
                    STATUS_ACCESS_VIOLATION
                }
                10 => {
                    returned = 0;
                    STATUS_SUCCESS
                }
                11 => {
                    returned += 1;
                    STATUS_SUCCESS
                }
                _ => unreachable!(),
            };
            assert_eq!(
                group_call(
                    p,
                    &mut t,
                    [107, input, input_bytes, output, output_bytes, returned]
                ),
                Outcome::Continue,
                "{arch}/{role}"
            );
            assert_eq!(t.cpu.gpr(0), u64::from(expected), "{arch}/{role}");
            let original_output = scratch + PAGE_SIZE;
            let record = group_record(arch);
            let copied = expected == STATUS_SUCCESS || (role == 7 && arch == WinArch::X86);
            let mut data = vec![0xA5; 128];
            if copied {
                data[..record.len()].copy_from_slice(&record);
            }
            assert_eq!(
                p.space.bytes(original_output, 128).unwrap(),
                data,
                "{arch}/{role}"
            );
            if role == 8 || expected == STATUS_SUCCESS && role != 10 {
                assert_eq!(p.space.u32(returned).unwrap(), record.len() as u32);
            } else {
                assert_eq!(p.space.u32(scratch + 2 * PAGE_SIZE).unwrap(), 0xA5A5_A5A5);
            }
        }
    }
}

#[test]
fn native_group_topology_alignment_and_optional_returned_length_all_abis() {
    for arch in WinArch::ALL {
        for (role, offsets) in [
            (0, &[1, 2, 3, 4, 7][..]),
            (1, &[1, 2, 3, 4, 7]),
            (2, &[1, 2, 3]),
        ] {
            for &offset in offsets {
                let (mut process, mut t, scratch) = group_fixture(arch);
                let p = process.state_mut();
                let (mut input, mut output, mut returned) =
                    (scratch, scratch + PAGE_SIZE, scratch + 2 * PAGE_SIZE);
                match role {
                    0 => {
                        input += offset;
                        p.space.w32(input, 4).unwrap();
                    }
                    1 => output += offset,
                    2 => returned += offset,
                    _ => unreachable!(),
                }
                assert_eq!(
                    group_call(p, &mut t, [107, input, 4, output, 96, returned]),
                    Outcome::Continue
                );
                let misaligned =
                    offset % 4 != 0 && (role == 0 || role == 1 && arch != WinArch::X86);
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if misaligned {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else {
                        STATUS_SUCCESS
                    }),
                    "{arch}/{role}/{offset}"
                );
                if !misaligned {
                    assert_eq!(
                        p.space.bytes(output, group_record(arch).len()).unwrap(),
                        group_record(arch)
                    );
                    assert_eq!(
                        p.space.u32(returned).unwrap(),
                        group_record(arch).len() as u32
                    );
                }
            }
        }
    }
}

#[test]
fn native_group_topology_ignores_unmapped_extra_input_span_all_abis() {
    for arch in WinArch::ALL {
        for input_bytes in [3, 4, 8, 16, u32::MAX] {
            let (mut process, mut t, scratch) = group_fixture(arch);
            let p = process.state_mut();
            let input = scratch + PAGE_SIZE - 4;
            p.space.w32(input, 4).unwrap();
            p.vm.protect(
                scratch + PAGE_SIZE,
                PAGE_SIZE,
                prot::READWRITE | prot::GUARD,
            )
            .unwrap();
            let output = scratch + 2 * PAGE_SIZE;
            assert_eq!(
                group_call(p, &mut t, [107, input, input_bytes.into(), output, 96, 0]),
                Outcome::Continue
            );
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if input_bytes < 4 {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_SUCCESS
                }),
                "{arch}/{input_bytes}"
            );
            assert_eq!(
                p.vm.query(scratch + PAGE_SIZE).unwrap().protect & prot::GUARD,
                prot::GUARD
            );
        }
    }
}

#[test]
fn native_group_topology_partial_conversion_at_every_field_boundary_all_abis() {
    for arch in WinArch::ALL {
        for protection in [prot::NOACCESS, prot::READONLY] {
            for prefix in 1..=96 {
                let (mut process, mut t, scratch) = group_fixture(arch);
                let p = process.state_mut();
                let output = scratch + 2 * PAGE_SIZE - prefix;
                p.vm.protect(scratch + 2 * PAGE_SIZE, PAGE_SIZE, protection)
                    .unwrap();
                let returned = scratch + 3 * PAGE_SIZE;
                assert_eq!(
                    group_call(p, &mut t, [107, scratch, 4, output, 128, returned]),
                    Outcome::Continue
                );
                let expected = if arch != WinArch::X86 && prefix % 4 != 0 {
                    STATUS_DATATYPE_MISALIGNMENT
                } else if arch == WinArch::X86 && prefix >= 76 {
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_VIOLATION
                };
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(expected),
                    "{arch}/{prefix}/{protection:#x}"
                );
                let mut data = vec![0xA5; prefix as usize];
                if arch == WinArch::X86 {
                    if prefix >= 76 {
                        data[..76].copy_from_slice(&group_record(arch));
                    } else {
                        if prefix >= 12 {
                            data[8..12].copy_from_slice(&[1, 0, 1, 0]);
                        }
                        if prefix >= 28 {
                            data[12..28].fill(0);
                        }
                        if prefix >= 32 {
                            data[28..32].fill(0);
                        }
                        if prefix >= 33 {
                            data[32] = 1;
                        }
                        if prefix >= 34 {
                            data[33] = 1;
                        }
                    }
                }
                assert_eq!(
                    p.space.bytes(output, prefix as usize).unwrap(),
                    data,
                    "{arch}/{prefix}"
                );
                assert_eq!(
                    p.space.u32(returned).unwrap(),
                    if expected == STATUS_SUCCESS {
                        76
                    } else {
                        0xA5A5_A5A5
                    }
                );
            }
        }
    }
}

#[test]
fn native_group_topology_guards_order_capture_and_conversion_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = group_fixture(arch);
        let p = process.state_mut();
        let output = scratch + PAGE_SIZE;
        for address in [scratch, output] {
            p.vm.protect(address, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        for repeat in 0..3 {
            assert_eq!(
                group_call(p, &mut t, [107, scratch, 4, output, 96, 0]),
                Outcome::Continue
            );
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if repeat < 2 {
                    STATUS_GUARD_PAGE_VIOLATION
                } else {
                    STATUS_SUCCESS
                })
            );
            if repeat == 0 {
                let untouched = if arch == WinArch::X86 {
                    output
                } else {
                    scratch
                };
                assert_eq!(
                    p.vm.query(untouched).unwrap().protect & prot::GUARD,
                    prot::GUARD
                );
            }
        }
        assert_eq!(
            p.space.bytes(output, group_record(arch).len()).unwrap(),
            group_record(arch)
        );
    }
}

#[test]
fn native_group_topology_aliases_capture_input_and_publish_returned_last_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..8 {
            let (mut process, mut t, scratch) = group_fixture(arch);
            let p = process.state_mut();
            let output = if role == 0 {
                scratch
            } else {
                scratch + PAGE_SIZE
            };
            let returned = match role {
                0 => scratch + 2 * PAGE_SIZE,
                1 => scratch,
                _ => output + [0, 0, 0, 4, 8, 32, 72, 1][role],
            };
            assert_eq!(
                group_call(p, &mut t, [107, scratch, 4, output, 96, returned]),
                Outcome::Continue
            );
            assert_eq!(t.cpu.gpr(0), 0);
            let mut data = group_record(arch);
            let required = data.len() as u32;
            if role >= 2 {
                let offset = (returned - output) as usize;
                data[offset..offset + 4].copy_from_slice(&required.to_le_bytes());
            }
            assert_eq!(
                p.space.bytes(output, data.len()).unwrap(),
                data,
                "{arch}/{role}"
            );
            assert_eq!(p.space.u32(returned).unwrap(), required);
        }
    }
}

#[test]
fn native_group_topology_unmodeled_classes_and_relationships_stop_explicitly_all_abis() {
    for arch in WinArch::ALL {
        for (class, relationship) in [
            (0, 4),
            (50, 4),
            (62, 4),
            (250, 4),
            (107, 0),
            (107, 0xFFFF),
            (107, u32::MAX),
        ] {
            let (mut process, mut t, scratch) = group_fixture(arch);
            let p = process.state_mut();
            p.space.w32(scratch, relationship).unwrap();
            assert!(
                matches!(group_call(p, &mut t, [class, scratch, 4, scratch + PAGE_SIZE, 96, scratch + 2 * PAGE_SIZE]), Outcome::Fail(reason) if reason.contains("NtQuerySystemInformationEx class")),
                "{arch}/{class}/{relationship}"
            );
            assert_eq!(p.space.bytes(scratch + PAGE_SIZE, 96).unwrap(), [0xA5; 96]);
            assert_eq!(p.space.u32(scratch + 2 * PAGE_SIZE).unwrap(), 0xA5A5_A5A5);
        }
    }
}

#[test]
fn native_group_topology_returned_guards_and_cross_page_faults_preserve_order_all_abis() {
    for arch in WinArch::ALL {
        for (input_bytes, output_bytes) in [(3, 96), (4, 0), (4, 96)] {
            let (mut process, mut t, scratch) = group_fixture(arch);
            let p = process.state_mut();
            let (output, returned) = (scratch + PAGE_SIZE, scratch + 2 * PAGE_SIZE);
            p.vm.protect(returned, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            assert_eq!(
                group_call(
                    p,
                    &mut t,
                    [107, scratch, input_bytes, output, output_bytes, returned]
                ),
                Outcome::Continue
            );
            let touches = arch != WinArch::X86 || input_bytes >= 4;
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if touches {
                    STATUS_GUARD_PAGE_VIOLATION
                } else {
                    STATUS_INVALID_PARAMETER
                })
            );
            assert_eq!(
                p.vm.query(returned).unwrap().protect & prot::GUARD,
                if touches { 0 } else { prot::GUARD }
            );
            let mut expected = vec![0xA5; 96];
            if arch == WinArch::X86 && input_bytes >= 4 && output_bytes >= 76 {
                expected[..76].copy_from_slice(&group_record(arch));
            }
            assert_eq!(p.space.bytes(output, 96).unwrap(), expected);
        }
        for prefix in 1..=4 {
            let (mut process, mut t, scratch) = group_fixture(arch);
            let p = process.state_mut();
            let returned = scratch + 3 * PAGE_SIZE - prefix;
            p.vm.protect(scratch + 3 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            let output = scratch + PAGE_SIZE;
            assert_eq!(
                group_call(p, &mut t, [107, scratch, 4, output, 96, returned]),
                Outcome::Continue
            );
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if prefix == 4 {
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_VIOLATION
                })
            );
            let mut expected = vec![0xA5; 96];
            if arch == WinArch::X86 || prefix == 4 {
                let record = group_record(arch);
                expected[..record.len()].copy_from_slice(&record);
            }
            assert_eq!(p.space.bytes(output, 96).unwrap(), expected);
            if prefix < 4 {
                assert_eq!(
                    p.space.bytes(returned, prefix as usize).unwrap(),
                    vec![0xA5; prefix as usize]
                );
            } else {
                assert_eq!(
                    p.space.u32(returned).unwrap(),
                    group_record(arch).len() as u32
                );
            }
        }
    }
}

#[test]
fn native_group_topology_input_user_range_checks_precede_short_length_dispatch_all_abis() {
    for arch in WinArch::ALL {
        for address in [
            4,
            0x7FFF_FFFE_FFFC,
            0x7FFF_FFFF_0000,
            0x7FFF_FFFF_FFFC,
            u64::MAX - 3,
        ] {
            for input_bytes in [0, 1, 3, 4, 8, u32::MAX] {
                let (mut process, mut t, scratch) = group_fixture(arch);
                let p = process.state_mut();
                let input = arch.ptr(address);
                assert_eq!(
                    group_call(
                        p,
                        &mut t,
                        [
                            107,
                            input,
                            input_bytes.into(),
                            scratch + PAGE_SIZE,
                            0,
                            scratch + 2 * PAGE_SIZE
                        ]
                    ),
                    Outcome::Continue
                );
                let range_invalid = arch != WinArch::X86
                    && input
                        .checked_add(input_bytes.into())
                        .is_none_or(|end| end > p.vm.high());
                let expected = if input == 0 || input_bytes == 0 {
                    STATUS_INVALID_PARAMETER
                } else if range_invalid {
                    STATUS_ACCESS_VIOLATION
                } else if input_bytes < 4 {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_ACCESS_VIOLATION
                };
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(expected),
                    "{arch}/{input:#x}/{input_bytes}"
                );
                assert_eq!(p.space.u32(scratch + 2 * PAGE_SIZE).unwrap(), 0xA5A5_A5A5);
            }
        }
    }
}

#[test]
fn native_group_topology_upper_spans_and_returned_pointer_have_distinct_guard_order_native_64_bit()
{
    for arch in [WinArch::X64, WinArch::Arm64] {
        for role in 0..3 {
            let (mut process, mut t, scratch) = group_fixture(arch);
            let p = process.state_mut();
            let high = p.vm.high();
            p.vm.allocate(
                Some(high - PAGE_SIZE),
                PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE | prot::GUARD,
            )
            .unwrap();
            let (mut input, mut input_bytes, mut output, mut output_bytes, mut returned) =
                (scratch, 4, scratch + PAGE_SIZE, 96, scratch + 2 * PAGE_SIZE);
            match role {
                0 => {
                    input = high - 4;
                    input_bytes = 8;
                }
                1 => {
                    output = high - 4;
                    output_bytes = 8;
                }
                2 => returned = high - 2,
                _ => unreachable!(),
            }
            assert_eq!(
                group_call(
                    p,
                    &mut t,
                    [107, input, input_bytes, output, output_bytes, returned]
                ),
                Outcome::Continue
            );
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if role == 2 {
                    STATUS_GUARD_PAGE_VIOLATION
                } else {
                    STATUS_ACCESS_VIOLATION
                }),
                "{arch}/{role}"
            );
            assert_eq!(
                p.vm.query(high - PAGE_SIZE).unwrap().protect & prot::GUARD,
                if role == 2 { 0 } else { prot::GUARD }
            );
            assert_eq!(p.space.bytes(scratch + PAGE_SIZE, 96).unwrap(), [0xA5; 96]);
        }
    }
}
