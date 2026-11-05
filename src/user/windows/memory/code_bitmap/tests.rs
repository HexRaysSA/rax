use super::*;
use crate::user::mm::SpaceConfig;

const BASE: u64 = 0x7df4_51a1_0000;

fn memory(limit: u64) -> VirtualMemory {
    VirtualMemory::new_with_commit_limit(
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 4 << 20,
            reserved_phys: vec![],
        })
        .unwrap(),
        65536,
        1 << 47,
        limit,
    )
}

#[test]
fn native_bitmap_geometry_tags_only_intersecting_ec_pages_with_sparse_readonly_storage() {
    let mut vm = memory(1 << 20);
    assert_eq!(vm.code_bitmap_address().unwrap(), None);
    let plan = CodeBitmapPlan {
        base: Some(BASE),
        ranges: vec![
            (0x180000, 0x316fc0),
            (0x335000, 0x33526c),
            (0x338000, 0x339100),
        ],
    };
    let module = 0x7ffa_1b31_0000;
    vm.publish_ec_image(&plan, module, 0x473000).unwrap();
    assert_eq!(vm.code_bitmap_address().unwrap(), Some(BASE));
    assert_eq!(vm.committed_bytes(), PAGE_SIZE);
    let reserved = vm.query(BASE).unwrap();
    assert_eq!(
        (
            reserved.allocation_base,
            reserved.allocation_protect,
            reserved.kind,
            reserved.state,
            reserved.protect
        ),
        (BASE, prot::NOACCESS, mem::MAPPED, mem::RESERVE, 0)
    );
    for (rva, expected) in [
        (0x1000, 0),
        (0x17ffbb, 0),
        (0x180000, 1),
        (0x316fbf, 1),
        (0x317000, 0),
        (0x32a06f, 0),
        (0x335000, 1),
        (0x33526b, 1),
        (0x336000, 0),
        (0x338000, 1),
        (0x3390ff, 1),
    ] {
        let address = module + rva;
        let byte = BASE + (address >> 15);
        let query = vm.query(byte).unwrap();
        assert_eq!(
            (query.kind, query.state, query.protect),
            (mem::MAPPED, mem::COMMIT, prot::READONLY)
        );
        assert_eq!(
            (vm.space.u8(byte).unwrap() >> ((address >> 12) & 7)) & 1,
            expected,
            "RVA {rva:x}"
        );
        assert!(vm.space.w8(byte, 0).is_err());
        assert_eq!(
            vm.protect(byte, 1, prot::READWRITE),
            Err(VmError::SectionProtection)
        );
        assert_eq!(
            vm.commit(byte, 1, prot::READONLY),
            Err(VmError::AlreadyCommitted)
        );
        assert_eq!(vm.decommit(byte, 1), Err(VmError::CannotDeleteSection));
    }
}

#[test]
fn partial_pages_and_guest_reuse_preserve_sticky_tags_without_copying_host_bits() {
    let mut vm = memory(1 << 20);
    let module = 0x4000_0000;
    let plan = CodeBitmapPlan {
        base: Some(BASE),
        ranges: vec![(0, 1), (0x7ffc, 0x8001)],
    };
    vm.publish_ec_image(&plan, module, 65536).unwrap();
    assert_eq!(vm.space.u8(BASE + (module >> 15)).unwrap(), 0x81);
    assert_eq!(vm.space.u8(BASE + (module >> 15) + 1).unwrap(), 1);
    vm.allocate(
        Some(module),
        65536,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    vm.release(module).unwrap();
    vm.allocate(
        Some(module),
        65536,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    assert_eq!(vm.space.u8(BASE + (module >> 15)).unwrap(), 0x81);
    let mut other = memory(1 << 20);
    other
        .publish_ec_image(
            &CodeBitmapPlan {
                base: Some(BASE),
                ranges: vec![(4096, 8192)],
            },
            module,
            65536,
        )
        .unwrap();
    assert_eq!(other.space.u8(BASE + (module >> 15)).unwrap(), 2);
    assert_eq!(vm.space.u8(BASE + (module >> 15)).unwrap(), 0x81);
}

#[test]
fn native_execute_permission_commits_readable_zero_tags_while_ordinary_rw_stays_sparse() {
    let mut vm = memory(1 << 20);
    let module = 0x7ffa_1b31_0000;
    vm.publish_ec_image(
        &CodeBitmapPlan {
            base: Some(BASE),
            ranges: vec![(0x180000, 0x181000)],
        },
        module,
        0x473000,
    )
    .unwrap();
    let target = 0x8000_120000;
    vm.allocate(
        Some(target),
        PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    let byte = BASE + (target >> 15);
    assert_eq!(vm.query(byte).unwrap().state, mem::RESERVE);
    vm.protect(target, PAGE_SIZE, prot::EXECUTE_READWRITE)
        .unwrap();
    assert_eq!(vm.query(byte).unwrap().protect, prot::READONLY);
    assert_eq!(vm.space.u8(byte).unwrap(), 0);
    vm.release(target).unwrap();
    assert_eq!(vm.space.u8(byte).unwrap(), 0);
    let next = target + (1 << 28);
    vm.allocate(
        Some(next),
        PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::EXECUTE_READWRITE,
    )
    .unwrap();
    assert_eq!(vm.space.u8(BASE + (next >> 15)).unwrap(), 0);
    assert_eq!(vm.committed_bytes(), 4 * PAGE_SIZE);
}

#[test]
fn executable_ranges_existing_before_bitmap_creation_receive_zero_coverage() {
    let mut vm = memory(1 << 20);
    let target = 0x1_4000_0000;
    vm.allocate(
        Some(target),
        PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::EXECUTE_READ,
    )
    .unwrap();
    vm.publish_ec_image(
        &CodeBitmapPlan {
            base: Some(BASE),
            ranges: vec![(0x180000, 0x181000)],
        },
        0x7ffa_1b31_0000,
        0x473000,
    )
    .unwrap();
    assert_eq!(vm.space.u8(BASE + (target >> 15)).unwrap(), 0);
    assert_eq!(vm.committed_bytes(), 3 * PAGE_SIZE);
}

#[test]
fn execute_admission_preflights_combined_guest_and_bitmap_commitment() {
    for protect_existing in [false, true] {
        let mut vm = memory(2 * PAGE_SIZE);
        vm.publish_ec_image(
            &CodeBitmapPlan {
                base: Some(BASE),
                ranges: vec![(0, 4096)],
            },
            0x7ffa_1b31_0000,
            65536,
        )
        .unwrap();
        let target = 0x8000_120000;
        vm.reserve(
            Some(target),
            PAGE_SIZE,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
        if protect_existing {
            vm.commit(target, PAGE_SIZE, prot::READWRITE).unwrap();
        }
        let before = vm.committed_bytes();
        let result = if protect_existing {
            vm.protect(target, PAGE_SIZE, prot::EXECUTE_READ)
                .map(|_| ())
        } else {
            vm.commit(target, PAGE_SIZE, prot::EXECUTE_READ).map(|_| ())
        };
        assert_eq!(result, Err(VmError::CommitmentLimit));
        assert_eq!(vm.committed_bytes(), before);
        assert_eq!(vm.query(BASE + (target >> 15)).unwrap().state, mem::RESERVE);
        assert_eq!(
            vm.query(target).unwrap().protect,
            if protect_existing { prot::READWRITE } else { 0 }
        );
    }
}

#[test]
fn stale_bitmap_ownership_and_failed_admission_preserve_replacement_and_commit_budget() {
    let plan = CodeBitmapPlan {
        base: Some(BASE),
        ranges: vec![(0, 4096)],
    };
    let mut vm = memory(0);
    assert_eq!(
        vm.publish_ec_image(&plan, 0x4000_0000, 65536),
        Err(VmError::CommitmentLimit)
    );
    assert!(vm.code_bitmap.is_none());
    assert!(vm.is_free(BASE, BITMAP_BYTES));
    assert_eq!(vm.committed_bytes(), 0);
    let mut vm = memory(1 << 20);
    vm.allocate(
        Some(BASE),
        65536,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    vm.space.w8(BASE, 0x5a).unwrap();
    assert_eq!(
        vm.publish_ec_image(&plan, 0x4000_0000, 65536),
        Err(VmError::Conflicting)
    );
    assert_eq!(vm.space.u8(BASE).unwrap(), 0x5a);
    vm.release(BASE).unwrap();
    assert_eq!(vm.code_bitmap_address().unwrap(), None);
    vm.publish_ec_image(&plan, 0x4000_0000, 65536).unwrap();
    vm.release(BASE).unwrap();
    assert_eq!(vm.code_bitmap_address(), Err(VmError::InvalidAddress));
    vm.allocate(
        Some(BASE),
        65536,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    vm.space.w8(BASE, 0x7b).unwrap();
    assert_eq!(
        vm.publish_ec_image(&plan, 0x4000_0000, 65536),
        Err(VmError::InvalidAddress)
    );
    assert_eq!(vm.space.u8(BASE).unwrap(), 0x7b);
}

fn enable_private_ec(vm: &mut VirtualMemory) {
    vm.publish_ec_image(
        &CodeBitmapPlan {
            base: Some(BASE),
            ranges: vec![],
        },
        0,
        0,
    )
    .unwrap();
}

#[test]
fn private_ec_reserve_commit_and_sticky_reuse_follow_native_page_tags() {
    for flags in [mem::RESERVE, mem::COMMIT, mem::RESERVE | mem::COMMIT] {
        let mut vm = memory(1 << 20);
        enable_private_ec(&mut vm);
        let target = 0x8000_120000;
        let size = if flags == mem::COMMIT {
            PAGE_SIZE
        } else {
            65536
        };
        let (base, len) = vm
            .allocate_extended_attributes(
                if flags == mem::COMMIT {
                    None
                } else {
                    Some(target)
                },
                size,
                flags,
                prot::EXECUTE_READWRITE,
                AddressRequirements::default(),
                PrivateAttributes {
                    node: Some(0),
                    ec_code: true,
                },
            )
            .unwrap();
        let byte = BASE + (base >> 15);
        assert_eq!(
            vm.space.u8(byte).unwrap(),
            if len == PAGE_SIZE { 1 } else { 255 }
        );
        if len == 65536 {
            assert_eq!(vm.space.u8(byte + 1).unwrap(), 255);
        }
        assert_eq!(vm.query(byte).unwrap().protect, prot::READONLY);
        assert_eq!(
            vm.private_code_kind(base).unwrap(),
            if flags == mem::RESERVE {
                None
            } else {
                Some(CodeKind::Arm64Ec)
            }
        );
        vm.release(base).unwrap();
        assert_eq!(vm.private_code_kind(base).unwrap(), None);
        let retained = vm.space.u8(byte).unwrap();
        vm.allocate(Some(base), len, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
        assert_eq!(vm.private_code_kind(base).unwrap(), None);
        vm.protect(base, len, prot::EXECUTE_READ).unwrap();
        assert_eq!(vm.private_code_kind(base).unwrap(), Some(CodeKind::Arm64Ec));
        assert_eq!(vm.space.u8(byte).unwrap(), retained);
    }
}

#[test]
fn private_ec_existing_commit_tags_only_rounded_pages_and_keeps_other_bytes() {
    let mut vm = memory(1 << 20);
    enable_private_ec(&mut vm);
    let target = 0x8000_120000;
    vm.allocate(
        Some(target),
        65536,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    vm.space.w64(target + 4096, 0x12345678).unwrap();
    vm.allocate_extended_attributes(
        Some(target + 4097),
        4096,
        mem::COMMIT,
        prot::EXECUTE_READWRITE,
        AddressRequirements::default(),
        PrivateAttributes {
            node: None,
            ec_code: true,
        },
    )
    .unwrap();
    assert_eq!(vm.space.u8(BASE + (target >> 15)).unwrap(), 0b00000110);
    assert_eq!(vm.space.u64(target + 4096).unwrap(), 0x12345678);
    assert_eq!(vm.private_code_kind(target).unwrap(), None);
    assert_eq!(
        vm.private_code_kind(target + 4096).unwrap(),
        Some(CodeKind::Arm64Ec)
    );
    assert_eq!(vm.query(target + 12288).unwrap().protect, prot::READWRITE);
}

#[test]
fn private_ec_combined_quota_failure_rolls_back_new_reservation_and_existing_commit() {
    for existing in [false, true] {
        let mut vm = memory(PAGE_SIZE);
        enable_private_ec(&mut vm);
        let target = 0x8000_120000;
        if existing {
            vm.allocate(
                Some(target),
                PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap();
            vm.space.w64(target, 0x5a5a).unwrap();
        }
        let before = vm.committed_bytes();
        let count = vm.allocations().count();
        assert_eq!(
            vm.allocate_extended_attributes(
                Some(target),
                PAGE_SIZE,
                if existing {
                    mem::COMMIT
                } else {
                    mem::RESERVE | mem::COMMIT
                },
                prot::EXECUTE_READWRITE,
                AddressRequirements::default(),
                PrivateAttributes {
                    node: Some(0),
                    ec_code: true
                },
            ),
            Err(VmError::CommitmentLimit)
        );
        assert_eq!(vm.committed_bytes(), before);
        assert_eq!(vm.allocations().count(), count);
        assert_eq!(vm.query(BASE + (target >> 15)).unwrap().state, mem::RESERVE);
        if existing {
            assert_eq!(vm.space.u64(target).unwrap(), 0x5a5a);
            assert_eq!(vm.query(target).unwrap().protect, prot::READWRITE);
        } else {
            assert_eq!(vm.query(target).unwrap().state, mem::FREE);
        }
    }
}

#[test]
fn private_decoder_uses_actual_protection_and_never_reuses_retired_bitmap_ownership() {
    let mut vm = memory(1 << 20);
    enable_private_ec(&mut vm);
    let target = 0x8000_120000;
    vm.allocate(
        Some(target),
        PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::EXECUTE_READ,
    )
    .unwrap();
    assert_eq!(vm.private_code_kind(target).unwrap(), Some(CodeKind::Amd64));
    vm.protect(target, PAGE_SIZE, prot::READONLY).unwrap();
    vm.set_reported(target, PAGE_SIZE, prot::EXECUTE_READ);
    assert_eq!(vm.query(target).unwrap().protect, prot::EXECUTE_READ);
    assert_eq!(vm.private_code_kind(target).unwrap(), None);
    vm.protect(target, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
    vm.release(BASE).unwrap();
    assert_eq!(vm.private_code_kind(target), Err(VmError::InvalidAddress));
    vm.allocate(
        Some(BASE),
        65536,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    vm.space.w8(BASE, 0xff).unwrap();
    assert_eq!(vm.private_code_kind(target), Err(VmError::InvalidAddress));
    assert_eq!(vm.space.u8(BASE).unwrap(), 0xff);
}

#[test]
fn private_ec_reset_has_no_unqualified_success_or_bitmap_mutation() {
    let mut vm = memory(1 << 20);
    enable_private_ec(&mut vm);
    let target = vm
        .allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0;
    vm.space.w64(target, 0x12345678).unwrap();
    let before = vm.committed_bytes();
    for flags in [mem::RESET, mem::RESET_UNDO] {
        assert_eq!(
            vm.allocate_extended_attributes(
                Some(target),
                PAGE_SIZE,
                flags,
                prot::EXECUTE_READWRITE,
                AddressRequirements::default(),
                PrivateAttributes {
                    node: None,
                    ec_code: true
                }
            ),
            Err(VmError::NotSupported)
        );
        assert_eq!(vm.space.u64(target).unwrap(), 0x12345678);
        assert_eq!(vm.query(target).unwrap().protect, prot::READWRITE);
        assert_eq!(vm.committed_bytes(), before);
    }
}
