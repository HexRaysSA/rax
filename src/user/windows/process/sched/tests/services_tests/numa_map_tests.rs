//! Selected Windows29683 class55: variable native extent and WoW64 in-place conversion.
use super::*;
use crate::user::windows::memory::ALLOCATION_GRANULARITY;

#[cfg(windows)]
#[path = "numa_map_leaf_tests.rs"]
mod leaf_tests;

fn numa_call(p: &mut Proc, t: &mut Thread, output: u64, length: u32, returned: u64) {
    let sp = t.cpu.sp();
    query_arguments(p, t, 55, output, length, returned);
    assert_eq!(dispatch_query(p, t), Outcome::Continue);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
}

fn numa_fixture(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t, _) = query_fixture(arch);
    let p = process.state_mut();
    let data =
        p.vm.allocate(
            None,
            4 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.space
        .wr(data, &vec![0xA5; (4 * PAGE_SIZE) as usize])
        .unwrap();
    (process, t, data)
}

fn expected_record(length: u32, size: usize) -> Vec<u8> {
    let mut bytes = vec![0xA5; size];
    if length >= 4 {
        bytes[..4].fill(0);
    }
    if length >= 24 {
        bytes[8..24].fill(0);
        bytes[8] = 1;
    }
    bytes
}

fn returned_length(arch: WinArch, length: u32) -> u32 {
    if length < 4 && arch == WinArch::X86 {
        0xA5A5_A5A5
    } else if length >= 24 {
        if arch == WinArch::X86 { 20 } else { 24 }
    } else {
        4
    }
}

#[test]
fn native_numa_map_lengths_publish_highest_node_then_one_group_and_keep_padding_all_abis() {
    for arch in WinArch::ALL {
        for length in (0..=40).chain([263, 264, 265, 1031, 1032, 1033, 2048]) {
            for optional in [false, true] {
                let (mut process, mut t, data) = numa_fixture(arch);
                let p = process.state_mut();
                let returned = if optional { 0 } else { data + PAGE_SIZE };
                numa_call(p, &mut t, data, length, returned);
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if length < 4 {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_SUCCESS
                    }),
                    "{arch}/{length}"
                );
                assert_eq!(
                    p.space.bytes(data, 64).unwrap(),
                    expected_record(length, 64)
                );
                if returned != 0 {
                    assert_eq!(
                        p.space.u32(returned).unwrap(),
                        returned_length(arch, length)
                    );
                }
            }
        }
    }
}

#[test]
fn native_numa_map_alignment_and_null_output_precede_short_length_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 1, 2, 3, 4, 20, 23, 24, 1032] {
            for offset in 0..=4 {
                let (mut process, mut t, data) = numa_fixture(arch);
                let p = process.state_mut();
                let returned = data + PAGE_SIZE;
                numa_call(p, &mut t, data + offset, length, returned);
                let aligned = length == 0 || offset % 4 == 0;
                let status = if !aligned {
                    STATUS_DATATYPE_MISALIGNMENT
                } else if length < 4 {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_SUCCESS
                };
                assert_eq!(t.cpu.gpr(0), u64::from(status), "{arch}/{length}/{offset}");
                assert_eq!(
                    p.space.u32(returned).unwrap(),
                    if aligned {
                        returned_length(arch, length)
                    } else {
                        0xA5A5_A5A5
                    }
                );
            }
            let (mut process, mut t, data) = numa_fixture(arch);
            let p = process.state_mut();
            numa_call(p, &mut t, 0, length, data + PAGE_SIZE);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if length == 0 {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_ACCESS_VIOLATION
                })
            );
            assert_eq!(
                p.space.u32(data + PAGE_SIZE).unwrap(),
                if length == 0 {
                    returned_length(arch, length)
                } else {
                    0xA5A5_A5A5
                }
            );
        }
    }
}

#[test]
fn native_numa_map_probes_the_entire_output_before_any_publication_all_abis() {
    for arch in WinArch::ALL {
        for length in [1, 3, 4, 8, 23, 24, 1032] {
            for prefix in (0..=32).chain([1032]) {
                for protection in [prot::NOACCESS, prot::READONLY] {
                    let (mut process, mut t, data) = numa_fixture(arch);
                    let p = process.state_mut();
                    p.vm.protect(data + PAGE_SIZE, PAGE_SIZE, protection)
                        .unwrap();
                    let output = data + PAGE_SIZE - prefix;
                    let returned = data + 2 * PAGE_SIZE;
                    numa_call(p, &mut t, output, length, returned);
                    let status = if output % 4 != 0 {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else if prefix < u64::from(length) {
                        STATUS_ACCESS_VIOLATION
                    } else if length < 4 {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_SUCCESS
                    };
                    assert_eq!(
                        t.cpu.gpr(0),
                        u64::from(status),
                        "{arch}/{length}/{prefix}/{protection}"
                    );
                    let count = (prefix as usize).min(32);
                    let expected = if status == STATUS_SUCCESS {
                        expected_record(length, 32)[..count].to_vec()
                    } else {
                        vec![0xA5; count]
                    };
                    assert_eq!(p.space.bytes(output, count).unwrap(), expected);
                    assert_eq!(
                        p.space.u32(returned).unwrap(),
                        if status == STATUS_SUCCESS || status == STATUS_INFO_LENGTH_MISMATCH {
                            returned_length(arch, length)
                        } else {
                            0xA5A5_A5A5
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn native_numa_map_return_faults_follow_wow64_success_and_leave_short_returns_untouched() {
    for arch in WinArch::ALL {
        for length in [0, 1, 3, 4, 20, 24, 1032] {
            for readonly in [false, true] {
                let (mut process, mut t, data) = numa_fixture(arch);
                let p = process.state_mut();
                let returned = if readonly {
                    p.vm.protect(data + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
                        .unwrap();
                    data + PAGE_SIZE
                } else {
                    1
                };
                numa_call(p, &mut t, data, length, returned);
                let short_wow = arch == WinArch::X86 && length < 4;
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if short_wow {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_ACCESS_VIOLATION
                    })
                );
                assert_eq!(
                    p.space.bytes(data, 32).unwrap(),
                    if arch == WinArch::X86 {
                        expected_record(length, 32)
                    } else {
                        vec![0xA5; 32]
                    }
                );
            }
        }
    }
}

#[test]
fn native_numa_map_guards_and_readonly_pairs_preserve_probe_priority_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 1, 3, 4, 24] {
            for output_guard in [false, true] {
                for other_readonly in [false, true] {
                    let (mut process, mut t, data) = numa_fixture(arch);
                    let p = process.state_mut();
                    let returned = data + PAGE_SIZE;
                    let (guarded, other) = if output_guard {
                        (data, returned)
                    } else {
                        (returned, data)
                    };
                    p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    if other_readonly {
                        p.vm.protect(other, PAGE_SIZE, prot::READONLY).unwrap();
                    }
                    numa_call(p, &mut t, data, length, returned);
                    let output_touched = length != 0;
                    let ret_touched = arch != WinArch::X86 || length >= 4;
                    let consumes = if output_guard {
                        output_touched
                    } else {
                        ret_touched && !(other_readonly && output_touched)
                    };
                    let other_fault = other_readonly
                        && if output_guard {
                            ret_touched
                        } else {
                            output_touched
                        };
                    let status = if consumes {
                        STATUS_GUARD_PAGE_VIOLATION
                    } else if other_fault {
                        STATUS_ACCESS_VIOLATION
                    } else if length < 4 {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_SUCCESS
                    };
                    assert_eq!(
                        t.cpu.gpr(0),
                        u64::from(status),
                        "{arch}/{length}/{output_guard}/{other_readonly}"
                    );
                    assert_eq!(
                        p.vm.query(guarded).unwrap().protect & prot::GUARD,
                        if consumes { 0 } else { prot::GUARD }
                    );
                    if consumes {
                        numa_call(p, &mut t, data, length, returned);
                        assert_eq!(
                            t.cpu.gpr(0),
                            u64::from(if other_fault {
                                STATUS_ACCESS_VIOLATION
                            } else if length < 4 {
                                STATUS_INFO_LENGTH_MISMATCH
                            } else {
                                STATUS_SUCCESS
                            })
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn native_numa_map_return_alias_and_cross_page_publication_are_last_and_atomic_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 3, 4, 20, 24, 1032] {
            for offset in 0..=24 {
                let (mut process, mut t, data) = numa_fixture(arch);
                let p = process.state_mut();
                numa_call(p, &mut t, data, length, data + offset);
                let mut expected = expected_record(length, 64);
                if length >= 4 || arch != WinArch::X86 {
                    expected[offset as usize..offset as usize + 4]
                        .copy_from_slice(&returned_length(arch, length).to_le_bytes());
                }
                assert_eq!(
                    p.space.bytes(data, 64).unwrap(),
                    expected,
                    "{arch}/{length}/{offset}"
                );
            }
            for prefix in 0..=4 {
                let (mut process, mut t, data) = numa_fixture(arch);
                let p = process.state_mut();
                p.vm.protect(data + 2 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
                let returned = data + 2 * PAGE_SIZE - prefix;
                numa_call(p, &mut t, data, length, returned);
                let untouched = arch == WinArch::X86 && length < 4;
                let faults = !untouched && prefix < 4;
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if faults {
                        STATUS_ACCESS_VIOLATION
                    } else if length < 4 {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_SUCCESS
                    })
                );
                assert_eq!(
                    p.space.bytes(data, 32).unwrap(),
                    if faults && arch != WinArch::X86 {
                        vec![0xA5; 32]
                    } else {
                        expected_record(length, 32)
                    }
                );
                let bytes = if prefix == 4 && !untouched {
                    returned_length(arch, length).to_le_bytes().to_vec()
                } else {
                    vec![0xA5; prefix as usize]
                };
                assert_eq!(p.space.bytes(returned, prefix as usize).unwrap(), bytes);
            }
        }
    }
}

#[test]
fn native_numa_map_upper_output_span_rejection_and_direct_return_guard_differ_native64() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        for return_guard in [false, true] {
            let (mut process, mut t, data) = numa_fixture(arch);
            let p = process.state_mut();
            let high = p.vm.high();
            p.vm.allocate(
                Some(high - ALLOCATION_GRANULARITY),
                ALLOCATION_GRANULARITY,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap();
            p.vm.protect(high - PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            let output = if return_guard { data } else { high - 4 };
            let returned = if return_guard {
                high - 2
            } else {
                data + PAGE_SIZE
            };
            numa_call(p, &mut t, output, 8, returned);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if return_guard {
                    STATUS_GUARD_PAGE_VIOLATION
                } else {
                    STATUS_ACCESS_VIOLATION
                })
            );
            assert_eq!(
                p.vm.query(high - PAGE_SIZE).unwrap().protect & prot::GUARD,
                if return_guard { 0 } else { prot::GUARD }
            );
            assert_eq!(p.space.bytes(data, 32).unwrap(), [0xA5; 32]);
        }
    }
}

#[test]
fn native_numa_map_ulong_max_uses_output_probes_without_wow64_capture_allocation() {
    for arch in WinArch::ALL {
        for guarded_output in [false, true] {
            let (mut process, mut t, data) = numa_fixture(arch);
            let p = process.state_mut();
            // ReturnLength lies beyond an inaccessible gap, as in the native
            // producer's independent regions. It must not itself be the first
            // fault encountered while probing ULONG_MAX bytes from output.
            p.vm.protect(data + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            let returned = data + 2 * PAGE_SIZE;
            let guarded = if guarded_output { data } else { returned };
            p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            let committed = p.vm.committed_bytes();
            numa_call(p, &mut t, data, u32::MAX, returned);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if guarded_output {
                    STATUS_GUARD_PAGE_VIOLATION
                } else {
                    STATUS_ACCESS_VIOLATION
                })
            );
            assert_eq!(
                p.vm.query(guarded).unwrap().protect & prot::GUARD,
                if guarded_output { 0 } else { prot::GUARD }
            );
            assert_eq!(p.vm.committed_bytes(), committed);
            if guarded_output {
                numa_call(p, &mut t, data, u32::MAX, returned);
                assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
            }
        }
    }
}
