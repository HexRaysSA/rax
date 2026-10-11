//! Class107 NUMA record sizes and fault publication independently observed on Windows29683.
use super::*;

#[cfg(windows)]
#[path = "numa_node_leaf_tests.rs"]
mod leaf_tests;

fn numa_fixture(
    arch: WinArch,
) -> (
    super::super::super::super::super::WindowsProcess,
    Thread,
    u64,
) {
    let (mut process, t, scratch) = group_fixture(arch);
    process.state_mut().space.w32(scratch, 6).unwrap();
    (process, t, scratch)
}

fn numa_record(arch: WinArch) -> Vec<u8> {
    let size: u32 = if arch == WinArch::X86 { 44 } else { 48 };
    let mut record = vec![0; size as usize];
    record[..4].copy_from_slice(&1u32.to_le_bytes());
    record[4..8].copy_from_slice(&size.to_le_bytes());
    record[30..32].copy_from_slice(&1u16.to_le_bytes());
    record[32] = 1; // Node0/group0/CPU0 agrees with existing topology queries.
    record
}

#[test]
fn native_numa_node_legacy_and_extended_requests_return_relation_numa_node_all_abis() {
    for arch in WinArch::ALL {
        for relationship in [1, 6] {
            let (mut process, mut t, scratch) = numa_fixture(arch);
            let p = process.state_mut();
            p.space.w32(scratch, relationship).unwrap();
            assert_eq!(
                group_call(
                    p,
                    &mut t,
                    [
                        107,
                        scratch,
                        4,
                        scratch + PAGE_SIZE,
                        96,
                        scratch + 2 * PAGE_SIZE
                    ]
                ),
                Outcome::Continue
            );
            assert_eq!(t.cpu.gpr(0), 0);
            let record = numa_record(arch);
            assert_eq!(
                p.space.bytes(scratch + PAGE_SIZE, record.len()).unwrap(),
                record
            );
            assert_eq!(
                p.space.u32(scratch + 2 * PAGE_SIZE).unwrap(),
                record.len() as u32
            );
        }
    }
}

#[test]
fn native_numa_node_sizes_projected_cpu_and_untouched_suffix_all_abis() {
    for arch in WinArch::ALL {
        for input_bytes in [0, 1, 2, 3, 4, 5, 8, 16] {
            for output_bytes in [0, 1, 4, 43, 44, 47, 48, 49, 96] {
                let (mut process, mut t, scratch) = numa_fixture(arch);
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
                let record = numa_record(arch);
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
fn native_numa_node_fault_order_and_destination_write_order_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..12 {
            let (mut process, mut t, scratch) = numa_fixture(arch);
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
            let record = numa_record(arch);
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
fn native_numa_node_alignment_and_optional_returned_length_all_abis() {
    for arch in WinArch::ALL {
        for (role, offsets) in [
            (0, &[1, 2, 3, 4, 7][..]),
            (1, &[1, 2, 3, 4, 7]),
            (2, &[1, 2, 3]),
        ] {
            for &offset in offsets {
                let (mut process, mut t, scratch) = numa_fixture(arch);
                let p = process.state_mut();
                let (mut input, mut output, mut returned) =
                    (scratch, scratch + PAGE_SIZE, scratch + 2 * PAGE_SIZE);
                match role {
                    0 => {
                        input += offset;
                        p.space.w32(input, 6).unwrap();
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
                        p.space.bytes(output, numa_record(arch).len()).unwrap(),
                        numa_record(arch)
                    );
                    assert_eq!(
                        p.space.u32(returned).unwrap(),
                        numa_record(arch).len() as u32
                    );
                }
            }
        }
    }
}

#[test]
fn native_numa_node_ignores_unmapped_extra_input_span_all_abis() {
    for arch in WinArch::ALL {
        for input_bytes in [3, 4, 8, 16, u32::MAX] {
            let (mut process, mut t, scratch) = numa_fixture(arch);
            let p = process.state_mut();
            let input = scratch + PAGE_SIZE - 4;
            p.space.w32(input, 6).unwrap();
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
fn native_numa_node_partial_conversion_at_every_field_boundary_all_abis() {
    for arch in WinArch::ALL {
        for protection in [prot::NOACCESS, prot::READONLY] {
            for prefix in 1..=96 {
                let (mut process, mut t, scratch) = numa_fixture(arch);
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
                } else if arch == WinArch::X86 && prefix >= 44 {
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
                    if prefix >= 44 {
                        data[..44].copy_from_slice(&numa_record(arch));
                    } else {
                        // Independently measured native WoW64 conversion:
                        // node DWORD, reserved SIMD16/WORD, count WORD,
                        // zero affinity QWORD/DWORD, group WORD, mask DWORD,
                        // then header. Faulting stores publish no prefix.
                        if prefix >= 12 {
                            data[8..12].fill(0);
                        }
                        if prefix >= 28 {
                            data[12..28].fill(0);
                        }
                        if prefix >= 30 {
                            data[28..30].fill(0);
                        }
                        if prefix >= 32 {
                            data[30..32].copy_from_slice(&1u16.to_le_bytes());
                        }
                        if prefix >= 40 {
                            data[32..40].fill(0);
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
                        44
                    } else {
                        0xA5A5_A5A5
                    }
                );
            }
        }
    }
}

#[test]
fn native_numa_node_guards_order_capture_and_conversion_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = numa_fixture(arch);
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
            p.space.bytes(output, numa_record(arch).len()).unwrap(),
            numa_record(arch)
        );
    }
}

#[test]
fn native_numa_node_aliases_capture_input_and_publish_returned_last_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..8 {
            let (mut process, mut t, scratch) = numa_fixture(arch);
            let p = process.state_mut();
            let output = if role == 0 {
                scratch
            } else {
                scratch + PAGE_SIZE
            };
            let returned = match role {
                0 => scratch + 2 * PAGE_SIZE,
                1 => scratch,
                _ => output + [0, 0, 0, 4, 8, 32, 40, 1][role],
            };
            assert_eq!(
                group_call(p, &mut t, [107, scratch, 4, output, 96, returned]),
                Outcome::Continue
            );
            assert_eq!(t.cpu.gpr(0), 0);
            let mut data = numa_record(arch);
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
fn native_numa_node_unmodeled_classes_and_relationships_stop_explicitly_all_abis() {
    for arch in WinArch::ALL {
        for (class, relationship) in [
            (0, 6),
            (50, 6),
            (62, 6),
            (250, 6),
            (107, 0),
            (107, 0xFFFF),
            (107, u32::MAX),
        ] {
            let (mut process, mut t, scratch) = numa_fixture(arch);
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
fn native_numa_node_returned_guards_and_cross_page_faults_preserve_order_all_abis() {
    for arch in WinArch::ALL {
        for (input_bytes, output_bytes) in [(3, 96), (4, 0), (4, 96)] {
            let (mut process, mut t, scratch) = numa_fixture(arch);
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
            if arch == WinArch::X86 && input_bytes >= 4 && output_bytes >= 44 {
                expected[..44].copy_from_slice(&numa_record(arch));
            }
            assert_eq!(p.space.bytes(output, 96).unwrap(), expected);
        }
        for prefix in 1..=4 {
            let (mut process, mut t, scratch) = numa_fixture(arch);
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
                let record = numa_record(arch);
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
                    numa_record(arch).len() as u32
                );
            }
        }
    }
}

#[test]
fn native_numa_node_input_user_range_checks_precede_short_length_dispatch_all_abis() {
    for arch in WinArch::ALL {
        for address in [
            4,
            0x7FFF_FFFE_FFFC,
            0x7FFF_FFFF_0000,
            0x7FFF_FFFF_FFFC,
            u64::MAX - 3,
        ] {
            for input_bytes in [0, 1, 3, 4, 8, u32::MAX] {
                let (mut process, mut t, scratch) = numa_fixture(arch);
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
fn native_numa_node_upper_spans_and_returned_pointer_have_distinct_guard_order_native_64_bit() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        for role in 0..3 {
            let (mut process, mut t, scratch) = numa_fixture(arch);
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
