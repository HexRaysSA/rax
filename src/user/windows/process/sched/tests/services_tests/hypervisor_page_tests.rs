//! Class197 absent hypervisor page: original Windows29683 buffer observations.
use super::*;

#[cfg(windows)]
#[path = "hypervisor_page_leaf_tests.rs"]
mod leaf_tests;

fn page_call(p: &mut Proc, t: &mut Thread, output: u64, length: u32, returned: u64) {
    let sp = t.cpu.sp();
    query_arguments(p, t, 197, output, length, returned);
    assert_eq!(dispatch_query(p, t), Outcome::Continue);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
}

fn page_fixture(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t, scratch) = query_fixture(arch);
    let p = process.state_mut();
    // Keep output and ReturnLength pages independently protectable.
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
    p.space.w32(scratch, 0xA5A5_A5A5).unwrap();
    (process, t, data)
}

#[test]
fn native_hypervisor_page_ulong_max_length_and_wrapping_output_do_not_allocate_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, data) = page_fixture(arch);
        let p = process.state_mut();
        let returned = data + PAGE_SIZE;
        page_call(p, &mut t, data, u32::MAX, returned);
        assert_eq!(
            t.cpu.gpr(0),
            u64::from(if arch == WinArch::X86 {
                STATUS_NO_MEMORY
            } else {
                STATUS_ACCESS_VIOLATION
            })
        );
        assert_eq!(p.space.u32(data).unwrap(), 0xA5A5_A5A5);
        assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
        for length in [0, 1, 3, 4, 8, 32] {
            let (mut process, mut t, data) = page_fixture(arch);
            let p = process.state_mut();
            let returned = data + PAGE_SIZE;
            page_call(p, &mut t, arch.ptr(u64::MAX - 3), length, returned);
            let mismatch = length == 0 || arch == WinArch::X86 && length < 4;
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if mismatch {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_ACCESS_VIOLATION
                })
            );
            assert_eq!(
                p.space.u32(returned).unwrap(),
                if mismatch {
                    arch.ptr_size() as u32
                } else {
                    0xA5A5_A5A5
                }
            );
            assert_eq!(p.space.bytes(data, 64).unwrap(), [0xA5; 64]);
        }
    }
}

#[test]
fn native_hypervisor_page_width_lengths_optional_return_and_alignment_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 1, 2, 3, 4, 5, 7, 8, 9, 12, 16, 32] {
            for offset in [0, 1, 2, 3, 4] {
                for optional in [false, true] {
                    let (mut process, mut t, data) = page_fixture(arch);
                    let p = process.state_mut();
                    let output = data + offset;
                    let returned = if optional { 0 } else { data + PAGE_SIZE + 1 };
                    page_call(p, &mut t, output, length, returned);
                    let width = arch.ptr_size() as usize;
                    let aligned = arch == WinArch::X86 || length == 0 || offset % 4 == 0;
                    let expected = if !aligned {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else if (length as usize) < width {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_SUCCESS
                    };
                    assert_eq!(
                        t.cpu.gpr(0),
                        u64::from(expected),
                        "{arch}/{length}/{offset}/{optional}"
                    );
                    let mut bytes = vec![0xA5; 64];
                    if expected == STATUS_SUCCESS {
                        bytes[offset as usize..offset as usize + width].fill(0);
                    }
                    assert_eq!(p.space.bytes(data, 64).unwrap(), bytes);
                    if returned != 0 {
                        assert_eq!(
                            p.space.u32(returned).unwrap(),
                            if aligned { width as u32 } else { 0xA5A5_A5A5 }
                        );
                        assert_eq!(p.space.u8(returned + 4).unwrap(), 0xA5);
                    }
                }
            }
        }
    }
}

#[test]
fn wow64_hypervisor_page_temporary_backing_budget_precedes_destination_probes() {
    for failure in [false, true] {
        for guard_return in [false, true] {
            let (mut process, mut t, data) = page_fixture(WinArch::X86);
            let p = process.state_mut();
            let available = p.vm.commit_limit() - p.vm.committed_bytes();
            assert_eq!(available % PAGE_SIZE, 0);
            // capture = align_up(length + 4,16) +16; then page-round the charge.
            // At available-20 it fits exactly; the next byte needs another page.
            let length = u32::try_from(available - if failure { 19 } else { 20 }).unwrap();
            let returned = data + PAGE_SIZE;
            let guarded = if guard_return { returned } else { data };
            p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            let committed = p.vm.committed_bytes();
            page_call(p, &mut t, data, length, returned);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if failure {
                    STATUS_NO_MEMORY
                } else {
                    STATUS_GUARD_PAGE_VIOLATION
                })
            );
            assert_eq!(
                p.vm.query(guarded).unwrap().protect & prot::GUARD,
                if failure { prot::GUARD } else { 0 }
            );
            assert_eq!(p.vm.committed_bytes(), committed);
            if guard_return || !failure {
                assert_eq!(
                    p.space.u32(data).unwrap(),
                    if guard_return && !failure {
                        0
                    } else {
                        0xA5A5_A5A5
                    }
                );
            }
            if !guard_return || !failure {
                assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
            }
        }
    }
    let (mut process, mut t, data) = page_fixture(WinArch::X86);
    let p = process.state_mut();
    let returned = data + PAGE_SIZE;
    p.vm.protect(returned, PAGE_SIZE, prot::READWRITE | prot::GUARD)
        .unwrap();
    page_call(p, &mut t, 0, u32::MAX, returned);
    assert_eq!(t.cpu.gpr(0), u64::from(STATUS_GUARD_PAGE_VIOLATION));
    page_call(p, &mut t, 0, u32::MAX, returned);
    assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
    assert_eq!(p.space.u32(returned).unwrap(), 0xFFFF_FFFC);
}

#[test]
fn native_hypervisor_page_null_output_precedes_wow64_short_length_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 1, 3, 4, 8, 9] {
            for returned_bad in [false, true] {
                let (mut process, mut t, data) = page_fixture(arch);
                let p = process.state_mut();
                let returned = if returned_bad { 1 } else { data + PAGE_SIZE };
                page_call(p, &mut t, 0, length, returned);
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if length == 0 && !returned_bad {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }),
                    "{arch}/{length}/{returned_bad}"
                );
                assert_eq!(p.space.bytes(data, 64).unwrap(), [0xA5; 64]);
                if !returned_bad {
                    let value = if length == 0 {
                        arch.ptr_size() as u32
                    } else if arch == WinArch::X86 {
                        0xFFFF_FFFC
                    } else {
                        0xA5A5_A5A5
                    };
                    assert_eq!(p.space.u32(returned).unwrap(), value);
                }
            }
        }
    }
}

#[test]
fn native_hypervisor_page_readonly_destinations_preserve_conversion_write_order_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 3, 8] {
            for output_readonly in [false, true] {
                let (mut process, mut t, data) = page_fixture(arch);
                let p = process.state_mut();
                let returned = data + PAGE_SIZE;
                p.vm.protect(
                    if output_readonly { data } else { returned },
                    PAGE_SIZE,
                    prot::READONLY,
                )
                .unwrap();
                page_call(p, &mut t, data, length, returned);
                let short = length < arch.ptr_size() as u32;
                let output_touched = if arch == WinArch::X86 {
                    !short
                } else {
                    length != 0
                };
                let mismatch = output_readonly && !output_touched;
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if mismatch {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_ACCESS_VIOLATION
                    })
                );
                let published = arch == WinArch::X86 && !short && !output_readonly;
                let mut expected = vec![0xA5; 32];
                if published {
                    expected[..4].fill(0);
                }
                assert_eq!(p.space.bytes(data, 32).unwrap(), expected);
                assert_eq!(
                    p.space.u32(returned).unwrap(),
                    if mismatch {
                        arch.ptr_size() as u32
                    } else {
                        0xA5A5_A5A5
                    }
                );
            }
        }
    }
}

#[test]
fn native_hypervisor_page_guards_are_one_shot_and_short_wow64_output_is_untouched_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 3, 8] {
            for returned_guard in [false, true] {
                let (mut process, mut t, data) = page_fixture(arch);
                let p = process.state_mut();
                let returned = data + PAGE_SIZE;
                let guarded = if returned_guard { returned } else { data };
                p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                let short = length < arch.ptr_size() as u32;
                let touches = returned_guard
                    || if arch == WinArch::X86 {
                        !short
                    } else {
                        length != 0
                    };
                page_call(p, &mut t, data, length, returned);
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if touches {
                        STATUS_GUARD_PAGE_VIOLATION
                    } else {
                        STATUS_INFO_LENGTH_MISMATCH
                    })
                );
                assert_eq!(
                    p.vm.query(guarded).unwrap().protect & prot::GUARD,
                    if touches { 0 } else { prot::GUARD }
                );
                if returned_guard {
                    assert_eq!(
                        p.space.u32(data).unwrap(),
                        if arch == WinArch::X86 && !short {
                            0
                        } else {
                            0xA5A5_A5A5
                        }
                    );
                    assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
                }
                page_call(p, &mut t, data, length, returned);
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if short {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_SUCCESS
                    })
                );
                assert_eq!(p.space.u32(returned).unwrap(), arch.ptr_size() as u32);
            }
        }
    }
}

#[test]
fn native_hypervisor_page_guard_readonly_pairs_preserve_probe_priority_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 3, 8] {
            for output_guard in [false, true] {
                let (mut process, mut t, data) = page_fixture(arch);
                let p = process.state_mut();
                let returned = data + PAGE_SIZE;
                let (guarded, readonly) = if output_guard {
                    (data, returned)
                } else {
                    (returned, data)
                };
                p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                p.vm.protect(readonly, PAGE_SIZE, prot::READONLY).unwrap();
                let out_touched = if arch == WinArch::X86 {
                    length >= 4
                } else {
                    length != 0
                };
                let consumes = output_guard == out_touched;
                page_call(p, &mut t, data, length, returned);
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if consumes {
                        STATUS_GUARD_PAGE_VIOLATION
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }),
                    "{arch}/{length}/{output_guard}"
                );
                assert_eq!(
                    p.vm.query(guarded).unwrap().protect & prot::GUARD,
                    if consumes { 0 } else { prot::GUARD }
                );
            }
        }
    }
}

#[test]
fn native_hypervisor_page_return_aliases_are_written_after_pointer_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 32] {
            for offset in 0..=10 {
                let (mut process, mut t, data) = page_fixture(arch);
                let p = process.state_mut();
                page_call(p, &mut t, data, length, data + offset);
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if length == 0 {
                        STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        STATUS_SUCCESS
                    })
                );
                let width = arch.ptr_size() as usize;
                let mut expected = vec![0xA5; 64];
                if length != 0 {
                    expected[..width].fill(0);
                }
                expected[offset as usize..offset as usize + 4]
                    .copy_from_slice(&(width as u32).to_le_bytes());
                assert_eq!(
                    p.space.bytes(data, 64).unwrap(),
                    expected,
                    "{arch}/{length}/{offset}"
                );
            }
        }
    }
}

#[test]
fn native_hypervisor_page_output_boundaries_probe_native_extent_and_wow64_pointer_only_all_abis() {
    for arch in WinArch::ALL {
        for length in [8, 32] {
            for prefix in 1..=32 {
                for readonly in [false, true] {
                    let (mut process, mut t, data) = page_fixture(arch);
                    let p = process.state_mut();
                    let output = data + PAGE_SIZE - prefix;
                    let returned = data + 2 * PAGE_SIZE;
                    p.vm.protect(
                        data + PAGE_SIZE,
                        PAGE_SIZE,
                        if readonly {
                            prot::READONLY
                        } else {
                            prot::NOACCESS
                        },
                    )
                    .unwrap();
                    page_call(p, &mut t, output, length, returned);
                    let aligned = arch == WinArch::X86 || prefix % 4 == 0;
                    let success = aligned
                        && prefix
                            >= if arch == WinArch::X86 {
                                4
                            } else {
                                u64::from(length)
                            };
                    let expected = if !aligned {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else if success {
                        STATUS_SUCCESS
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                    assert_eq!(
                        t.cpu.gpr(0),
                        u64::from(expected),
                        "{arch}/{length}/{prefix}/{readonly}"
                    );
                    let mut bytes = vec![0xA5; prefix as usize];
                    if success {
                        bytes[..arch.ptr_size() as usize].fill(0);
                    }
                    assert_eq!(p.space.bytes(output, prefix as usize).unwrap(), bytes);
                    assert_eq!(
                        p.space.u32(returned).unwrap(),
                        if success {
                            arch.ptr_size() as u32
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
fn native_hypervisor_page_return_boundaries_are_atomic_after_wow64_publication_all_abis() {
    for arch in WinArch::ALL {
        for prefix in 1..=4 {
            let (mut process, mut t, data) = page_fixture(arch);
            let p = process.state_mut();
            let returned = data + 3 * PAGE_SIZE - prefix;
            p.vm.protect(data + 3 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            page_call(p, &mut t, data, 8, returned);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if prefix == 4 {
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_VIOLATION
                })
            );
            let published = prefix == 4 || arch == WinArch::X86;
            let mut bytes = vec![0xA5; 32];
            if published {
                bytes[..arch.ptr_size() as usize].fill(0);
            }
            assert_eq!(p.space.bytes(data, 32).unwrap(), bytes);
            assert_eq!(
                p.space.bytes(returned, prefix as usize).unwrap(),
                if prefix == 4 {
                    (arch.ptr_size() as u32).to_le_bytes().to_vec()
                } else {
                    vec![0xA5; prefix as usize]
                }
            );
        }
    }
}

#[test]
fn native_hypervisor_page_upper_output_span_and_direct_return_have_distinct_guard_order_native64() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        for return_guard in [false, true] {
            let (mut process, mut t, data) = page_fixture(arch);
            let p = process.state_mut();
            let high = p.vm.high();
            p.vm.allocate(
                Some(high - PAGE_SIZE),
                PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE | prot::GUARD,
            )
            .unwrap();
            let output = if return_guard { data } else { high - 4 };
            let returned = if return_guard {
                high - 2
            } else {
                data + PAGE_SIZE
            };
            page_call(p, &mut t, output, 8, returned);
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
