use crate::error::MemoryAccessKind;
use crate::user::mm::{AddressSpace, PAGE_SIZE, SpaceConfig};
use crate::user::windows::memory::{
    AllocKind, VirtualMemory, VmError, mem, prot, valid_protection,
};

use super::{BITMAP_COVERAGE, Runs, TargetState};
use sha2::{Digest, Sha256};

fn vm() -> VirtualMemory {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 4 << 20,
        reserved_phys: Vec::new(),
    })
    .unwrap();
    VirtualMemory::new(space, 0x1_0000, 1 << 47)
}

fn allocate(vm: &mut VirtualMemory, protection: u32) -> u64 {
    vm.allocate(
        Some(0x40_0000),
        0x1_0000,
        mem::RESERVE | mem::COMMIT,
        protection,
    )
    .unwrap()
    .0
}

#[test]
fn cfg_requests_are_normalized_without_weakening_section_validation() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::EXECUTE_READWRITE | prot::TARGETS_INVALID);
    let region = vm.query(base).unwrap();
    assert_eq!(region.allocation_protect, prot::EXECUTE_READWRITE);
    assert_eq!(region.protect, prot::EXECUTE_READWRITE);
    assert!(!vm.valid_call_target(base));
    assert_eq!(
        vm.protect(
            base,
            PAGE_SIZE,
            prot::EXECUTE_READ | prot::TARGETS_NO_UPDATE
        ),
        Ok(prot::EXECUTE_READWRITE)
    );
    assert_eq!(vm.query(base).unwrap().protect, prot::EXECUTE_READ);
    assert!(!valid_protection(
        prot::EXECUTE_READ | prot::TARGETS_INVALID
    ));
    assert_eq!(
        vm.reserve(
            Some(0x50_0000),
            PAGE_SIZE,
            prot::EXECUTE_READ | prot::TARGETS_INVALID,
            AllocKind::Image,
            false,
            None
        ),
        Err(VmError::InvalidProtection)
    );
}

#[test]
fn request_errors_match_native_operation_specific_statuses() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::READWRITE);
    for protection in [prot::NOACCESS, prot::READONLY, prot::READWRITE] {
        assert_eq!(
            vm.allocate(
                None,
                PAGE_SIZE,
                mem::RESERVE,
                protection | prot::TARGETS_INVALID
            ),
            Err(VmError::InvalidParameter)
        );
        assert_eq!(
            vm.protect(base, PAGE_SIZE, protection | prot::TARGETS_NO_UPDATE),
            Err(VmError::InvalidParameter4)
        );
    }
    for protection in [
        0x50,
        prot::EXECUTE_WRITECOPY,
        prot::EXECUTE_READWRITE | prot::WRITECOMBINE,
    ] {
        assert_eq!(
            vm.allocate(
                None,
                PAGE_SIZE,
                mem::RESERVE,
                protection | prot::TARGETS_INVALID
            ),
            Err(VmError::InvalidProtection)
        );
    }
    assert_eq!(
        vm.protect(
            base,
            PAGE_SIZE,
            prot::EXECUTE_WRITECOPY | prot::TARGETS_NO_UPDATE
        ),
        Err(VmError::InvalidParameter4)
    );
    assert_eq!(
        vm.protect(base, PAGE_SIZE, 0x50 | prot::TARGETS_NO_UPDATE),
        Err(VmError::InvalidProtection)
    );
    assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
    assert!(!vm.valid_call_target(base));
}

#[test]
fn default_slots_admit_all_offsets_explicit_registration_only_aligned_target() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::EXECUTE_READWRITE);
    for offset in 0..32 {
        assert!(vm.valid_call_target(base + offset));
    }
    vm.set_call_target(base, true).unwrap();
    assert!(vm.valid_call_target(base));
    for offset in 1..16 {
        assert!(!vm.valid_call_target(base + offset));
    }
    assert!(vm.valid_call_target(base + 16));
    vm.set_call_target(base, false).unwrap();
    assert!(!vm.valid_call_target(base));
    assert!(vm.valid_call_target(base + 16));
    assert_eq!(
        vm.set_call_target(base + 1, true),
        Err(VmError::InvalidParameter)
    );
}

#[test]
fn reserved_and_decommitted_targets_register_without_committing_or_executing() {
    for decommitted in [false, true] {
        let mut vm = vm();
        let base = vm
            .allocate(
                Some(0x40_0000),
                0x1_0000,
                mem::RESERVE | if decommitted { mem::COMMIT } else { 0 },
                prot::EXECUTE_READWRITE | prot::TARGETS_INVALID,
            )
            .unwrap()
            .0;
        if decommitted {
            vm.decommit(base, 0x1_0000).unwrap();
        }
        let committed = vm.committed_bytes();
        assert_eq!(vm.set_call_target(base, true), Ok(()));
        assert!(vm.valid_call_target(base));
        assert!(!vm.valid_call_target(base + 1));
        assert!(!vm.accessible(base, MemoryAccessKind::Fetch));
        assert_eq!(vm.committed_bytes(), committed);
        assert_eq!(vm.query(base).unwrap().state, mem::RESERVE);
        vm.release(base).unwrap();
        assert_eq!(vm.set_call_target(base, false), Err(VmError::NotAllocated));
        assert!(vm.valid_call_target(base));
    }
}

#[test]
fn invalid_targets_survive_protect_recommit_and_decommit() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::EXECUTE_READWRITE | prot::TARGETS_INVALID);
    vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
    vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
        .unwrap();
    assert!(!vm.valid_call_target(base));
    vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
    assert!(!vm.valid_call_target(base));
    vm.decommit(base, PAGE_SIZE).unwrap();
    assert!(!vm.valid_call_target(base));
    vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
    assert!(!vm.valid_call_target(base));
    vm.set_call_target(base, true).unwrap();
    assert!(vm.valid_call_target(base));
    assert!(!vm.valid_call_target(base + 4));
}

#[test]
fn executable_recommit_with_targets_invalid_replaces_default_bits() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::EXECUTE_READWRITE);
    vm.commit(
        base,
        PAGE_SIZE,
        prot::EXECUTE_READWRITE | prot::TARGETS_INVALID,
    )
    .unwrap();
    assert!(!vm.valid_call_target(base));
    assert!(vm.valid_call_target(base + PAGE_SIZE));
    assert_eq!(vm.query(base).unwrap().protect, prot::EXECUTE_READWRITE);
}

#[test]
fn validity_survives_free_but_cannot_grant_execute_rights() {
    for invalid in [false, true] {
        let mut vm = vm();
        let base = allocate(
            &mut vm,
            prot::EXECUTE_READWRITE | if invalid { prot::TARGETS_INVALID } else { 0 },
        );
        vm.decommit(base, PAGE_SIZE).unwrap();
        assert_eq!(vm.valid_call_target(base), !invalid);
        assert!(!vm.accessible(base, MemoryAccessKind::Fetch));
        vm.release(base).unwrap();
        assert_eq!(vm.valid_call_target(base), !invalid);
        assert!(!vm.accessible(base, MemoryAccessKind::Fetch));
        allocate(&mut vm, prot::READWRITE);
        assert_eq!(vm.valid_call_target(base), !invalid);
        assert!(!vm.accessible(base, MemoryAccessKind::Fetch));
        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
            .unwrap();
        assert!(vm.valid_call_target(base));
    }
}

#[test]
fn executable_reservations_establish_cfg_before_commit() {
    for invalid in [false, true] {
        let mut vm = vm();
        let base = vm
            .reserve(
                None,
                PAGE_SIZE,
                prot::EXECUTE_READWRITE | if invalid { prot::TARGETS_INVALID } else { 0 },
                AllocKind::Private,
                false,
                None,
            )
            .unwrap();
        assert_eq!(vm.valid_call_target(base), !invalid);
        assert!(!vm.accessible(base, MemoryAccessKind::Fetch));
        vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
        assert_eq!(vm.valid_call_target(base), !invalid);
    }
}

#[test]
fn no_update_preserves_and_ordinary_execution_updates_initially_nonexec_pages() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::READWRITE);
    assert!(!vm.valid_call_target(base));
    vm.protect(
        base,
        PAGE_SIZE,
        prot::EXECUTE_READWRITE | prot::TARGETS_NO_UPDATE,
    )
    .unwrap();
    assert!(!vm.valid_call_target(base));
    vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
    vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
        .unwrap();
    assert!(vm.valid_call_target(base));
    assert!(!vm.valid_call_target(base + PAGE_SIZE));
    vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::EXECUTE_READWRITE)
        .unwrap();
    assert!(vm.valid_call_target(base + PAGE_SIZE));
}

#[test]
fn writable_target_registration_requires_existing_storage_not_execute_rights() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::READWRITE);
    assert_eq!(
        vm.set_call_target(base, true),
        Err(VmError::CallTargetStorage)
    );
    assert_eq!(VmError::CallTargetStorage.status(), 0xc000_0005);
    vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::EXECUTE_READWRITE)
        .unwrap();
    vm.set_call_target(base, true).unwrap();
    assert!(vm.valid_call_target(base));
    assert!(!vm.accessible(base, MemoryAccessKind::Fetch));
    vm.protect(
        base,
        PAGE_SIZE,
        prot::EXECUTE_READWRITE | prot::TARGETS_NO_UPDATE,
    )
    .unwrap();
    assert!(vm.valid_call_target(base));
    assert!(!vm.valid_call_target(base + 4));
}

#[test]
fn bitmap_storage_coverage_stops_at_the_256_kib_boundary() {
    for distance in [
        0x1000, 0x1_0000, 0x2_0000, 0x3_f000, 0x4_0000, 0x8_0000, 0x10_0000,
    ] {
        let mut vm = vm();
        let base = vm
            .allocate(
                Some(0x40_0000),
                4 << 20,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        assert_eq!(
            vm.set_call_target(base, true),
            Err(VmError::CallTargetStorage)
        );
        vm.protect(base + distance, PAGE_SIZE, prot::EXECUTE_READWRITE)
            .unwrap();
        assert_eq!(
            vm.set_call_target(base, true),
            if distance < BITMAP_COVERAGE {
                Ok(())
            } else {
                Err(VmError::CallTargetStorage)
            }
        );
    }
}

#[test]
fn nonprivate_executable_mapping_provides_storage_without_private_target_initialization() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::READWRITE);
    let image = vm
        .reserve(
            Some(base + 0x1_0000),
            PAGE_SIZE,
            prot::EXECUTE_READ,
            AllocKind::Image,
            false,
            None,
        )
        .unwrap();
    vm.commit(image, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
    vm.set_call_target(base, true).unwrap();
    assert!(vm.valid_call_target(base));
    assert!(!vm.valid_call_target(image));
}

#[test]
fn first_default_execution_initializes_over_prior_writable_target_updates() {
    for valid in [false, true] {
        let mut vm = vm();
        let base = allocate(&mut vm, prot::READWRITE);
        vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::EXECUTE_READWRITE)
            .unwrap();
        vm.set_call_target(base, valid).unwrap();
        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
            .unwrap();
        assert!(vm.valid_call_target(base + 4));
    }
}

#[test]
fn repeated_default_execution_uses_original_protection_after_explicit_updates() {
    for original in [
        prot::NOACCESS,
        prot::READONLY,
        prot::READWRITE,
        prot::EXECUTE,
        prot::EXECUTE_READ,
        prot::EXECUTE_READWRITE,
    ] {
        let original_execute = original & 0xf0 != 0;
        for registered in [false, true] {
            for operation in 0..3 {
                let mut vm = vm();
                let base = allocate(&mut vm, original);
                vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                    .unwrap();
                vm.set_call_target(base, registered).unwrap();
                match operation {
                    0 => {
                        vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
                        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                            .unwrap();
                    }
                    1 => {
                        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                            .unwrap();
                    }
                    _ => {
                        vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
                    }
                }
                assert_eq!(
                    vm.valid_call_target(base),
                    !original_execute || registered,
                    "original={original:x} registered={registered} operation={operation}"
                );
                assert_eq!(
                    vm.valid_call_target(base + 4),
                    !original_execute,
                    "original={original:x} registered={registered} operation={operation}"
                );
                assert_eq!(vm.query(base).unwrap().allocation_protect, original);
            }
        }
    }
}

#[test]
fn commit_targets_invalid_does_not_replace_original_reservation_protection() {
    for original in [
        prot::NOACCESS,
        prot::READONLY,
        prot::READWRITE,
        prot::EXECUTE,
        prot::EXECUTE_READ,
        prot::EXECUTE_READWRITE,
    ] {
        let mut vm = vm();
        let base = allocate(&mut vm, original);
        vm.commit(
            base,
            PAGE_SIZE,
            prot::EXECUTE_READWRITE | prot::TARGETS_INVALID,
        )
        .unwrap();
        assert!(!vm.valid_call_target(base));
        vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
            .unwrap();
        assert_eq!(vm.valid_call_target(base), original & 0xf0 == 0);
        assert_eq!(vm.query(base).unwrap().allocation_protect, original);
    }
}

#[test]
fn bitmap_storage_rounding_cannot_overflow_the_host_address_type() {
    let mut targets = super::CallTargets::default();
    targets.storage(u64::MAX - PAGE_SIZE, u64::MAX - 1);
    assert!(targets.resident.get(u64::MAX - 1));
    assert!(!targets.resident.get(u64::MAX));
}

#[test]
fn failed_mapping_operations_leave_target_state_unchanged() {
    let mut vm = vm();
    let base = vm
        .reserve(
            Some(0x40_0000),
            PAGE_SIZE,
            prot::EXECUTE_READWRITE | prot::TARGETS_INVALID,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    vm.release(base).unwrap();
    vm.commit_limit = 0;
    assert_eq!(
        vm.allocate(
            Some(base),
            PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::EXECUTE_READWRITE
        ),
        Err(VmError::CommitmentLimit)
    );
    assert!(vm.allocation(base).is_none());
    assert!(!vm.valid_call_target(base));
    assert!(!vm.call_targets.original_execute.contains_key(&base));
    let base = vm
        .reserve(
            Some(base),
            PAGE_SIZE,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    assert_eq!(
        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE),
        Err(VmError::NotCommitted)
    );
    assert!(!vm.valid_call_target(base));
}

#[test]
fn failed_new_executable_commit_does_not_publish_neighbor_bitmap_storage() {
    let mut vm = vm();
    let base = allocate(&mut vm, prot::READWRITE);
    vm.commit_limit = vm.committed_bytes();
    assert_eq!(
        vm.allocate(
            Some(base + 0x1_0000),
            PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::EXECUTE_READ
        ),
        Err(VmError::CommitmentLimit)
    );
    assert_eq!(
        vm.set_call_target(base, true),
        Err(VmError::CallTargetStorage)
    );
}

#[test]
fn huge_reservations_remain_sparse_and_reuse_resets_only_owned_range() {
    let mut vm = vm();
    let base = vm
        .reserve(
            Some(1 << 40),
            1 << 40,
            prot::EXECUTE_READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    assert!(vm.valid_call_target(base + (1 << 40) - 1));
    assert!(!vm.valid_call_target(base - 1));
    assert!(!vm.valid_call_target(base + (1 << 40)));
    assert_eq!(vm.call_targets.slots.boundaries.len(), 3);
    assert!(vm.call_targets.resident.boundaries.len() <= 3);
    vm.release(base).unwrap();
    vm.reserve(
        Some(base),
        PAGE_SIZE,
        prot::EXECUTE_READ | prot::TARGETS_INVALID,
        AllocKind::Private,
        false,
        None,
    )
    .unwrap();
    assert!(!vm.valid_call_target(base));
    assert!(vm.valid_call_target(base + PAGE_SIZE));
    assert!(BITMAP_COVERAGE.is_power_of_two());
}

#[test]
fn sparse_replacement_matches_independent_dense_state_and_coalesces() {
    let mut runs = Runs::<TargetState>::default();
    let mut dense = [TargetState::Invalid; 257];
    let mut seed = 0x7b92_187a_u64;
    for _ in 0..1000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let first = (seed >> 32) as usize % 256;
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let end = first + 1 + (seed >> 32) as usize % (256 - first);
        let value = match seed % 3 {
            0 => TargetState::Invalid,
            1 => TargetState::Aligned,
            _ => TargetState::Any,
        };
        dense[first..end].fill(value);
        runs.set(first as u64, end as u64, value);
        for (address, &expected) in dense.iter().enumerate() {
            assert_eq!(runs.get(address as u64), expected);
        }
        let values: Vec<_> = runs.boundaries.values().collect();
        assert!(values.windows(2).all(|pair| pair[0] != pair[1]));
    }
    runs.set(0, 256, TargetState::Invalid);
    assert_eq!(runs.boundaries.len(), 1);
}

#[test]
fn retained_native_private_call_controls_match_guest_memory_state() {
    let controls: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-cfg-private-code/memory-state-arm64-29698-v1.json"
    )))
    .unwrap();
    let producer = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-cfg-private-code/native-memory-state-v1.rs"
    ));
    assert_eq!(
        format!("{:x}", Sha256::digest(producer)),
        controls["source_sha256"].as_str().unwrap()
    );
    let mut count = 0;
    for report in controls["reports"].as_array().unwrap() {
        for row in report["qualified_calls"].as_array().unwrap() {
            let case = row["case"].as_str().unwrap();
            let mut vm = vm();
            let initial = if case.starts_with("initial-rw") {
                prot::READWRITE
            } else if case.starts_with("default")
                || case.starts_with("rw")
                || case == "reserve-default-call"
            {
                prot::EXECUTE_READWRITE
            } else {
                prot::EXECUTE_READWRITE | prot::TARGETS_INVALID
            };
            let flags = if case.starts_with("reserve") {
                mem::RESERVE
            } else {
                mem::RESERVE | mem::COMMIT
            };
            let base = vm
                .allocate(Some(0x40_0000), 0x1_0000, flags, initial)
                .unwrap()
                .0;
            match case {
                "default"
                | "invalid"
                | "initial-rw-call"
                | "reserve-default-call"
                | "reserve-invalid-call"
                | "default-decommit-call"
                | "invalid-decommit-call"
                | "default-release-call"
                | "invalid-release-call"
                | "default-unaligned" => {}
                "initial-rw-exec-default" => {
                    vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                        .unwrap();
                }
                "initial-rw-exec-no-update" => {
                    vm.protect(
                        base,
                        PAGE_SIZE,
                        prot::EXECUTE_READWRITE | prot::TARGETS_NO_UPDATE,
                    )
                    .unwrap();
                }
                "invalid-mark-valid"
                | "invalid-mark-valid-unaligned"
                | "invalid-mark-valid-wrong-slot"
                | "default-mark-valid-unaligned" => {
                    vm.set_call_target(base, true).unwrap();
                }
                "default-mark-invalid" | "default-mark-invalid-other-slot" => {
                    vm.set_call_target(base, false).unwrap();
                }
                "invalid-mark-valid-other-slot" => {
                    vm.set_call_target(base + 16, true).unwrap();
                }
                "invalid-mark-invalid-then-valid" | "default-mark-invalid-then-valid-unaligned" => {
                    vm.set_call_target(base, false).unwrap();
                    vm.set_call_target(base, true).unwrap();
                }
                "invalid-protect-no-update" | "invalid-protect-default" => {
                    vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
                    vm.protect(
                        base,
                        PAGE_SIZE,
                        prot::EXECUTE_READWRITE
                            | if case.ends_with("no-update") {
                                prot::TARGETS_NO_UPDATE
                            } else {
                                0
                            },
                    )
                    .unwrap();
                }
                "invalid-recommit-default" | "reserve-invalid-commit-default" => {
                    vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
                }
                "default-recommit-invalid" | "reserve-invalid-commit-invalid" => {
                    vm.commit(
                        base,
                        PAGE_SIZE,
                        prot::EXECUTE_READWRITE | prot::TARGETS_INVALID,
                    )
                    .unwrap();
                }
                "invalid-decommit-recommit" => {
                    vm.decommit(base, PAGE_SIZE).unwrap();
                    vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
                }
                "invalid-release-reuse" => {
                    vm.release(base).unwrap();
                    allocate(&mut vm, prot::EXECUTE_READWRITE);
                }
                "rw-mark-valid-no-update"
                | "rw-mark-invalid-no-update"
                | "rw-mark-invalid-default" => {
                    vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
                    vm.set_call_target(base, case == "rw-mark-valid-no-update")
                        .unwrap();
                    vm.protect(
                        base,
                        PAGE_SIZE,
                        prot::EXECUTE_READWRITE
                            | if case.ends_with("no-update") {
                                prot::TARGETS_NO_UPDATE
                            } else {
                                0
                            },
                    )
                    .unwrap();
                }
                "initial-rw-neighbor-exec-valid"
                | "initial-rw-neighbor-exec-invalid"
                | "initial-rw-neighbor-invalid-default"
                | "initial-rw-neighbor-valid-default" => {
                    vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::EXECUTE_READWRITE)
                        .unwrap();
                    vm.set_call_target(
                        base,
                        matches!(
                            case,
                            "initial-rw-neighbor-exec-valid" | "initial-rw-neighbor-valid-default"
                        ),
                    )
                    .unwrap();
                    vm.protect(
                        base,
                        PAGE_SIZE,
                        prot::EXECUTE_READWRITE
                            | if case.ends_with("default") {
                                0
                            } else {
                                prot::TARGETS_NO_UPDATE
                            },
                    )
                    .unwrap();
                }
                "initial-rw-neighbor-default" => {
                    vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::EXECUTE_READWRITE)
                        .unwrap();
                    vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                        .unwrap();
                }
                "initial-rw-no-update-then-default" => {
                    vm.protect(
                        base,
                        PAGE_SIZE,
                        prot::EXECUTE_READWRITE | prot::TARGETS_NO_UPDATE,
                    )
                    .unwrap();
                    vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
                    vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                        .unwrap();
                }
                "default-release-rw-register"
                | "default-release-rw-call"
                | "invalid-release-rw-call"
                | "invalid-release-rw-exec" => {
                    vm.release(base).unwrap();
                    allocate(&mut vm, prot::READWRITE);
                    if case.ends_with("register") {
                        vm.set_call_target(base, true).unwrap();
                        vm.protect(
                            base,
                            PAGE_SIZE,
                            prot::EXECUTE_READWRITE | prot::TARGETS_NO_UPDATE,
                        )
                        .unwrap();
                    }
                    if case.ends_with("exec") {
                        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                            .unwrap();
                    }
                }
                unknown => panic!("native control has no guest replay: {unknown}"),
            }
            if matches!(case, "default-decommit-call" | "invalid-decommit-call") {
                vm.decommit(base, PAGE_SIZE).unwrap();
            }
            if matches!(case, "default-release-call" | "invalid-release-call") {
                vm.release(base).unwrap();
            }
            let target = base + row["offset"].as_u64().unwrap();
            assert_eq!(
                vm.valid_call_target(target),
                row["valid_target"].as_bool().unwrap(),
                "{} {case}",
                report["process_view"]
            );
            if row["instruction_fetch_fault"].as_bool() == Some(true) {
                assert!(!vm.accessible(target, MemoryAccessKind::Fetch), "{case}");
            } else if row["exit_code"] == "00000000" {
                assert!(vm.accessible(target, MemoryAccessKind::Fetch), "{case}");
            }
            count += 1;
        }
    }
    assert_eq!(count, 84);
}

#[test]
fn retained_native_repeated_transitions_replace_the_rejected_once_only_model() {
    let controls: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/specifications/windows/native-cfg-private-code/repeated-protection-arm64-29698-v1.json"))).unwrap();
    let producer = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-cfg-private-code/native-repeated-protection-v1.rs"
    ));
    assert_eq!(
        format!("{:x}", Sha256::digest(producer)),
        controls["source_sha256"].as_str().unwrap()
    );
    let mut count = 0;
    for report in controls["reports"].as_array().unwrap() {
        for row in report["qualified_calls"].as_array().unwrap() {
            let mut vm = vm();
            let original = row["allocation_protection"].as_u64().unwrap() as u32;
            let base = allocate(&mut vm, original);
            let case = row["case"].as_str().unwrap();
            match case {
                "initial-rw-commit-invalid-default" => {
                    vm.commit(
                        base,
                        PAGE_SIZE,
                        prot::EXECUTE_READWRITE | prot::TARGETS_INVALID,
                    )
                    .unwrap();
                    vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
                    vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                        .unwrap();
                }
                "initial-rw-repeat-default-invalid"
                | "initial-rw-repeat-default-aligned"
                | "initial-rw-repeat-exec-invalid"
                | "initial-rw-repeat-commit-invalid"
                | "initial-rw-neighbor-default-aligned" => {
                    if case == "initial-rw-neighbor-default-aligned" {
                        vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::EXECUTE_READWRITE)
                            .unwrap();
                    }
                    vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                        .unwrap();
                    vm.set_call_target(base, case.ends_with("aligned")).unwrap();
                    if case == "initial-rw-repeat-commit-invalid" {
                        vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
                    } else {
                        if case != "initial-rw-repeat-exec-invalid" {
                            vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
                        }
                        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
                            .unwrap();
                    }
                }
                unknown => panic!("missing native repeat replay: {unknown}"),
            }
            let target = base + row["offset"].as_u64().unwrap();
            assert_eq!(
                vm.valid_call_target(target),
                row["valid_target"].as_bool().unwrap(),
                "{} {case}",
                report["process_view"]
            );
            assert!(vm.accessible(target, MemoryAccessKind::Fetch));
            count += 1;
        }
    }
    assert_eq!(count, 12);
}
