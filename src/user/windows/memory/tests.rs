use super::*;
use crate::user::mm::{CodeChanges, SpaceConfig};

fn vm(high: u64) -> VirtualMemory {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: high,
        arena_bytes: 4 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    VirtualMemory::new(space, ALLOCATION_GRANULARITY, high)
}

fn reservation(vm: &mut VirtualMemory, size: u64) -> u64 {
    vm.reserve(None, size, prot::READWRITE, AllocKind::Private, false, None)
        .unwrap()
}

#[test]
fn protection_combinations_follow_documented_constraints() {
    for base in [
        prot::NOACCESS,
        prot::READONLY,
        prot::READWRITE,
        prot::WRITECOPY,
        prot::EXECUTE,
        prot::EXECUTE_READ,
        prot::EXECUTE_READWRITE,
        prot::EXECUTE_WRITECOPY,
    ] {
        assert!(valid_protection(base));
        assert_eq!(valid_protection(base | prot::GUARD), base != prot::NOACCESS);
        assert_eq!(
            valid_protection(base | prot::NOCACHE),
            base != prot::NOACCESS
        );
        assert_eq!(
            valid_protection(base | prot::WRITECOMBINE),
            base != prot::NOACCESS
        );
        assert!(!valid_protection(base | prot::GUARD | prot::NOCACHE));
        assert!(!valid_protection(base | prot::GUARD | prot::WRITECOMBINE));
        assert!(!valid_protection(base | prot::NOCACHE | prot::WRITECOMBINE));
    }
    for invalid in [0, prot::READONLY | prot::READWRITE, 0x800, 0x4000_0010] {
        assert!(!valid_protection(invalid));
    }
    assert_eq!(perms_of(prot::EXECUTE), Perms::EXEC);
    assert_eq!(perms_of(prot::EXECUTE_READ), Perms::READ | Perms::EXEC);
}

#[test]
fn reservation_rounds_base_and_inclusive_byte_coverage() {
    let mut vm = vm(1 << 32);
    let base = vm
        .reserve(
            Some(0x2_0801),
            0x1000,
            prot::READONLY,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    assert_eq!(base, 0x2_0000);
    assert_eq!(vm.allocation(base).unwrap().size, 0x2000);
    assert_eq!(vm.query(base).unwrap().state, mem::RESERVE);
    assert!(!vm.accessible(base, MemoryAccessKind::Read));
    assert_eq!(
        vm.reserve(
            Some(base),
            PAGE_SIZE,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None
        ),
        Err(VmError::Conflicting)
    );
}

#[test]
fn commitment_crosses_pages_and_preserves_existing_contents() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, 4 * PAGE_SIZE);
    assert_eq!(
        vm.commit(base + PAGE_SIZE - 1, 2, prot::READWRITE),
        Ok((base, 2 * PAGE_SIZE))
    );
    assert_eq!(vm.space().u32(base).unwrap(), 0);
    vm.space().w32(base, 0xC0DE_1234).unwrap();
    vm.commit(base, 2 * PAGE_SIZE, prot::READONLY).unwrap();
    assert_eq!(vm.space().u32(base).unwrap(), 0xC0DE_1234);
    assert!(!vm.accessible(base, MemoryAccessKind::Write));
    assert_eq!(vm.query(base).unwrap().size, 2 * PAGE_SIZE);
    assert_eq!(vm.query(base + 2 * PAGE_SIZE).unwrap().state, mem::RESERVE);
}

#[test]
fn decommit_is_idempotent_and_recommit_is_zeroed() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, 3 * PAGE_SIZE);
    vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
    vm.space().w32(base, u32::MAX).unwrap();
    vm.decommit(base, 2 * PAGE_SIZE).unwrap();
    vm.decommit(base, 2 * PAGE_SIZE).unwrap();
    assert!(!vm.accessible(base, MemoryAccessKind::Read));
    vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
    assert_eq!(vm.space().u32(base).unwrap(), 0);
    assert_eq!(vm.decommit(base + PAGE_SIZE, 0), Err(VmError::NotAtBase));
    assert_eq!(vm.decommit(base, 0), Ok((base, 3 * PAGE_SIZE)));
    assert_eq!(vm.allocation(base).unwrap().pages.len(), 1);
}

#[test]
fn invalid_ranges_do_not_wrap_or_mutate_memory() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, 2 * PAGE_SIZE);
    vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
    for result in [
        vm.commit(base, 0, prot::READONLY),
        vm.commit(base, u64::MAX, prot::READONLY),
    ] {
        assert_eq!(result, Err(VmError::InvalidParameter));
    }
    assert_eq!(
        vm.protect(base, 0, prot::READONLY),
        Err(VmError::InvalidParameter)
    );
    assert_eq!(
        vm.protect(base, u64::MAX, prot::READONLY),
        Err(VmError::InvalidParameter)
    );
    assert_eq!(vm.decommit(base, u64::MAX), Err(VmError::InvalidParameter));
    assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
    assert!(vm.accessible(base, MemoryAccessKind::Write));
    assert_eq!(vm.find_free(0, 0, 0, u64::MAX, false), None);
    assert_eq!(vm.find_free(1, 3, 0, u64::MAX, true), None);
    assert_eq!(
        vm.find_free(PAGE_SIZE, PAGE_SIZE, 0x2000, 0x1000, false),
        None
    );
}

#[test]
fn protection_checks_every_page_before_changing_any() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, 3 * PAGE_SIZE);
    vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
    assert_eq!(
        vm.protect(base, 2 * PAGE_SIZE, prot::READONLY),
        Err(VmError::NotCommitted)
    );
    assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
    vm.commit(base, 3 * PAGE_SIZE, prot::READWRITE).unwrap();
    // An inconsistent shared AddressSpace must also fail before metadata
    // or another page's actual permissions change.
    vm.space().unmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();
    assert_eq!(
        vm.protect(base, 3 * PAGE_SIZE, prot::READONLY),
        Err(VmError::NotCommitted)
    );
    assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
    assert!(vm.accessible(base, MemoryAccessKind::Write));
}

#[test]
fn distinct_reservations_are_not_one_protection_region() {
    let mut vm = vm(1 << 32);
    let base = vm
        .reserve(
            Some(0x2_0000),
            ALLOCATION_GRANULARITY,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    vm.reserve(
        Some(base + ALLOCATION_GRANULARITY),
        ALLOCATION_GRANULARITY,
        prot::READWRITE,
        AllocKind::Private,
        false,
        None,
    )
    .unwrap();
    vm.commit(base, ALLOCATION_GRANULARITY, prot::READWRITE)
        .unwrap();
    assert_eq!(
        vm.protect(base + ALLOCATION_GRANULARITY - 1, 2, prot::READONLY),
        Err(VmError::InvalidAddress)
    );
    assert_eq!(
        vm.query(base + PAGE_SIZE).unwrap().size,
        ALLOCATION_GRANULARITY - PAGE_SIZE
    );
}

#[test]
fn release_requires_original_base_and_zero_size() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, 3 * PAGE_SIZE);
    vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
    assert_eq!(vm.free(base + 1, 0, mem::RELEASE), Err(VmError::NotAtBase));
    assert_eq!(vm.free(base, 1, mem::RELEASE), Err(VmError::UnableToFree));
    assert_eq!(
        vm.free(base, 0, mem::RELEASE | mem::DECOMMIT),
        Err(VmError::InvalidParameter)
    );
    assert_eq!(vm.free(base, 0, mem::RELEASE), Ok((base, 3 * PAGE_SIZE)));
    assert_eq!(vm.query(base).unwrap().state, mem::FREE);
    assert!(!vm.accessible(base, MemoryAccessKind::Read));
}

#[test]
fn guard_is_one_shot_for_each_page() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, 2 * PAGE_SIZE);
    vm.commit(base, 2 * PAGE_SIZE, prot::READWRITE | prot::GUARD)
        .unwrap();
    assert!(!vm.accessible(base, MemoryAccessKind::Read));
    assert!(vm.take_guard(base + 3));
    assert!(!vm.take_guard(base));
    assert!(vm.accessible(base, MemoryAccessKind::Write));
    assert!(!vm.accessible(base + PAGE_SIZE, MemoryAccessKind::Read));
    assert_eq!(vm.query(base).unwrap().size, PAGE_SIZE);
    assert!(vm.take_guard(base + PAGE_SIZE));
    assert_eq!(vm.allocation(base).unwrap().pages.len(), 1);
}

#[test]
fn huge_reservations_use_only_state_boundaries() {
    let mut vm = vm(1 << 47);
    let size = 1 << 42;
    let base = reservation(&mut vm, size);
    assert_eq!(vm.allocation(base).unwrap().pages.len(), 1);
    assert_eq!(vm.query(base).unwrap().size, size);
    vm.commit(base + size - PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
        .unwrap();
    assert_eq!(vm.allocation(base).unwrap().pages.len(), 2);
    assert_eq!(vm.query(base).unwrap().size, size - PAGE_SIZE);
    assert_eq!(vm.space().u32(base + size - PAGE_SIZE).unwrap(), 0);
    vm.decommit(base + size - PAGE_SIZE, PAGE_SIZE).unwrap();
    assert_eq!(vm.allocation(base).unwrap().pages.len(), 1);
}

#[test]
fn free_search_handles_limits_alignment_overlap_and_both_directions() {
    let mut vm = vm(0x10_0000);
    let base = vm
        .reserve(
            Some(0x4_0000),
            3 * ALLOCATION_GRANULARITY,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    vm.commit(base + ALLOCATION_GRANULARITY, PAGE_SIZE, prot::READWRITE)
        .unwrap();
    assert_eq!(
        vm.find_free(
            ALLOCATION_GRANULARITY,
            ALLOCATION_GRANULARITY,
            base,
            base + 4 * ALLOCATION_GRANULARITY,
            true
        ),
        Some(0x7_0000)
    );
    assert_eq!(
        vm.find_free(
            ALLOCATION_GRANULARITY,
            ALLOCATION_GRANULARITY,
            base,
            base + 3 * ALLOCATION_GRANULARITY,
            true
        ),
        None
    );
    assert_eq!(
        vm.find_free(
            ALLOCATION_GRANULARITY,
            ALLOCATION_GRANULARITY,
            0x3_0001,
            0x8_0000,
            false
        ),
        Some(0x7_0000)
    );
    vm.space()
        .map(0x7_0000, PAGE_SIZE, Mapping::anonymous(Perms::READ))
        .unwrap();
    assert_eq!(
        vm.reserve(
            Some(0x7_0000),
            PAGE_SIZE,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None
        ),
        Err(VmError::Conflicting)
    );
    assert_eq!(
        vm.find_free(
            ALLOCATION_GRANULARITY,
            ALLOCATION_GRANULARITY,
            0x3_0001,
            0x9_0000,
            false
        ),
        Some(0x8_0000)
    );
}

#[test]
fn commit_never_replaces_untracked_existing_bytes() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, 2 * PAGE_SIZE);
    vm.space()
        .map(
            base + PAGE_SIZE,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    vm.space().w32(base + PAGE_SIZE, 0x1234_5678).unwrap();
    assert_eq!(
        vm.commit(base, 2 * PAGE_SIZE, prot::READWRITE),
        Err(VmError::Conflicting)
    );
    assert_eq!(vm.query(base).unwrap().state, mem::RESERVE);
    assert!(!vm.accessible(base, MemoryAccessKind::Read));
    assert_eq!(vm.space().u32(base + PAGE_SIZE).unwrap(), 0x1234_5678);
}

#[test]
fn allocate_flags_are_supported_or_explicitly_rejected() {
    let mut vm = vm(1 << 32);
    let (base, size) = vm
        .allocate(Some(0), 1, mem::COMMIT, prot::READWRITE)
        .unwrap();
    assert_eq!(size, PAGE_SIZE);
    assert_eq!(vm.query(base).unwrap().state, mem::COMMIT);
    vm.space().w32(base, 0x1234_5678).unwrap();
    vm.allocate(Some(base), 1, mem::RESET, prot::NOACCESS)
        .unwrap();
    assert_eq!(vm.space().u32(base).unwrap(), 0x1234_5678);
    assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
    for flags in [
        mem::RESET_UNDO,
        mem::RESERVE | mem::WRITE_WATCH,
        mem::RESERVE | mem::PHYSICAL,
        mem::RESERVE | mem::COMMIT | mem::LARGE_PAGES,
    ] {
        assert_eq!(
            vm.allocate(Some(base), PAGE_SIZE, flags, prot::READWRITE),
            Err(VmError::NotSupported)
        );
    }
    for flags in [0, mem::TOP_DOWN, mem::COMMIT | mem::RESET, 0x8000_0000] {
        assert_eq!(
            vm.allocate(None, PAGE_SIZE, flags, prot::READWRITE),
            Err(VmError::InvalidParameter)
        );
    }
    for protect in [
        prot::WRITECOPY,
        prot::EXECUTE_WRITECOPY,
        prot::NOACCESS | prot::GUARD,
    ] {
        assert_eq!(
            vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, protect),
            Err(VmError::InvalidProtection)
        );
    }
}

#[test]
fn query_reports_forward_runs_and_distinct_initial_protection() {
    let mut vm = vm(0x10_0000);
    let base = reservation(&mut vm, 4 * PAGE_SIZE);
    vm.commit(base, 3 * PAGE_SIZE, prot::READONLY).unwrap();
    let r = vm.query(base + PAGE_SIZE + 31).unwrap();
    assert_eq!(r.base, base + PAGE_SIZE);
    assert_eq!(r.size, 2 * PAGE_SIZE);
    assert_eq!(r.allocation_protect, prot::READWRITE);
    assert_eq!(r.protect, prot::READONLY);
    assert_eq!(r.kind, mem::PRIVATE);
    assert_eq!(vm.query(vm.high()), None);
    assert_eq!(vm.query(vm.high() - 1).unwrap().size, PAGE_SIZE);
}

#[test]
fn image_reported_protection_preserves_trap_mapping() {
    let mut vm = vm(1 << 32);
    let base = vm
        .reserve(
            None,
            2 * PAGE_SIZE,
            prot::EXECUTE_WRITECOPY,
            AllocKind::Image,
            false,
            None,
        )
        .unwrap();
    vm.commit(base, 2 * PAGE_SIZE, prot::READONLY).unwrap();
    vm.set_reported(base, 2 * PAGE_SIZE, prot::EXECUTE_READ);
    assert_eq!(vm.query(base).unwrap().protect, prot::EXECUTE_READ);
    assert!(!vm.accessible(base, MemoryAccessKind::Fetch));
    vm.set_reported(base, 0, prot::READWRITE);
    vm.set_reported(base, u64::MAX, prot::READWRITE);
    assert_eq!(vm.query(base).unwrap().protect, prot::EXECUTE_READ);
    assert_eq!(
        vm.protect(base, PAGE_SIZE, prot::READWRITE),
        Ok(prot::EXECUTE_READ)
    );
    assert_eq!(vm.query(base).unwrap().size, PAGE_SIZE);
}

#[test]
fn guest_memory_information_abi_matches_both_pointer_widths() {
    let mut vm = vm(1 << 32);
    let (base, _) = vm
        .allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap();
    let r = RegionInfo {
        base: 0x1234_5000,
        allocation_base: 0x1234_0000,
        allocation_protect: prot::READONLY,
        size: 0x6000,
        state: mem::COMMIT,
        protect: prot::READWRITE,
        kind: mem::PRIVATE,
    };
    assert_eq!(r.write(vm.space(), base, 4).unwrap(), 28);
    assert_eq!(vm.space().u32(base + 12).unwrap(), 0x6000);
    assert_eq!(vm.space().u32(base + 24).unwrap(), mem::PRIVATE);
    assert_eq!(r.write(vm.space(), base, 8).unwrap(), 48);
    assert_eq!(vm.space().u64(base).unwrap(), 0x1234_5000);
    assert_eq!(vm.space().u64(base + 24).unwrap(), 0x6000);
    assert_eq!(vm.space().u32(base + 40).unwrap(), mem::PRIVATE);
    assert_eq!(vm.space().u32(base + 20).unwrap(), 0);
    assert_eq!(vm.space().u32(base + 44).unwrap(), 0);
}

#[test]
fn protection_and_decommit_invalidate_executable_code() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, PAGE_SIZE);
    vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
    let epoch = vm.space().code_epoch();
    vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
    assert!(matches!(
        vm.space().code_changes_since(epoch).0,
        CodeChanges::Ranges(_)
    ));
    vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
        .unwrap();
    let epoch = vm.space().code_epoch();
    vm.decommit(base, PAGE_SIZE).unwrap();
    assert!(matches!(
        vm.space().code_changes_since(epoch).0,
        CodeChanges::Ranges(_)
    ));
}

#[test]
fn state_run_boundaries_match_independent_page_model() {
    let mut vm = vm(1 << 32);
    let base = reservation(&mut vm, 64 * PAGE_SIZE);
    let mut expected = [None; 64];
    let mut seed = 0x67E3_29B1_u32;
    for step in 0..128 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let first = (seed & 63) as usize;
        let end = (first + 1 + ((seed >> 6) & 15) as usize).min(64);
        let at = base + first as u64 * PAGE_SIZE;
        let len = (end - first) as u64 * PAGE_SIZE;
        let protect = if seed & 0x10000 == 0 {
            prot::READWRITE
        } else {
            prot::READONLY
        };
        match step % 3 {
            0 => {
                vm.commit(at, len, protect).unwrap();
                expected[first..end].fill(Some(protect));
            }
            1 => {
                vm.decommit(at, len).unwrap();
                expected[first..end].fill(None);
            }
            _ => {
                let result = vm.protect(at, len, protect);
                if expected[first..end].iter().all(Option::is_some) {
                    assert_eq!(result, Ok(expected[first].unwrap()));
                    expected[first..end].fill(Some(protect));
                } else {
                    assert_eq!(result, Err(VmError::NotCommitted));
                }
            }
        }
        for i in 0..64 {
            let r = vm.query(base + i as u64 * PAGE_SIZE).unwrap();
            let count = expected[i..]
                .iter()
                .take_while(|&&p| p == expected[i])
                .count();
            assert_eq!(
                r.size,
                count as u64 * PAGE_SIZE,
                "seed={seed:#x} step={step} page={i}"
            );
            assert_eq!(
                r.state,
                if expected[i].is_some() {
                    mem::COMMIT
                } else {
                    mem::RESERVE
                }
            );
            assert_eq!(r.protect, expected[i].unwrap_or(0));
        }
    }
}

#[test]
fn commitment_charge_counts_only_new_pages_and_returns_on_free() {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 32,
        arena_bytes: 4 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    let mut vm = VirtualMemory::new_with_commit_limit(space, 0x10000, 1 << 32, 2 * PAGE_SIZE);
    let base = reservation(&mut vm, 4 * PAGE_SIZE);
    assert_eq!(vm.committed_bytes(), 0);
    assert_eq!(vm.commit_limit(), 2 * PAGE_SIZE);
    vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
    vm.commit(base, PAGE_SIZE, prot::READONLY).unwrap();
    assert_eq!(vm.committed_bytes(), PAGE_SIZE);
    vm.commit(base, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
    assert_eq!(vm.committed_bytes(), 2 * PAGE_SIZE);
    assert_eq!(
        vm.commit(base + PAGE_SIZE, 2 * PAGE_SIZE, prot::READONLY),
        Err(VmError::CommitmentLimit)
    );
    assert_eq!(vm.committed_bytes(), 2 * PAGE_SIZE);
    assert_eq!(vm.query(base + PAGE_SIZE).unwrap().protect, prot::READWRITE);
    assert_eq!(vm.query(base + 2 * PAGE_SIZE).unwrap().state, mem::RESERVE);
    vm.decommit(base, PAGE_SIZE).unwrap();
    vm.decommit(base, PAGE_SIZE).unwrap();
    assert_eq!(vm.committed_bytes(), PAGE_SIZE);
    vm.commit(base + 2 * PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
        .unwrap();
    vm.release(base).unwrap();
    assert_eq!(vm.committed_bytes(), 0);
    assert_eq!(VmError::CommitmentLimit.status(), 0xC000_012D);
}

#[test]
fn exhausted_combined_allocation_rolls_back_new_reservation() {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 32,
        arena_bytes: 4 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    let mut vm = VirtualMemory::new_with_commit_limit(space, 0x10000, 1 << 32, PAGE_SIZE);
    let (base, _) = vm
        .allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap();
    assert_eq!(
        vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE),
        Err(VmError::CommitmentLimit)
    );
    assert_eq!(vm.allocations().count(), 1);
    assert_eq!(vm.committed_bytes(), PAGE_SIZE);
    assert_eq!(vm.space().u32(base).unwrap(), 0);
    vm.release(base).unwrap();
    assert_eq!(
        vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0,
        base
    );
}

#[test]
fn utf16_unit_count_cannot_wrap_byte_length() {
    let vm = vm(1 << 32);
    assert_eq!(
        vm.space().wunits(0x10000, usize::MAX),
        Err(MemFault {
            addr: 0x10000,
            write: false
        })
    );
}
