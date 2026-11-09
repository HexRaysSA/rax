//! Byte telemetry follows successful guest charges and their full lifetime.
use super::*;
use crate::user::mm::{SharedObject, SpaceConfig};

fn memory(pages: u64) -> VirtualMemory {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 32,
        arena_bytes: 4 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    VirtualMemory::new_with_commit_limit(space, 65536, 1 << 32, pages * PAGE_SIZE)
}

fn check(vm: &VirtualMemory, current: u64, shared: u64, peak: u64) {
    let usage = vm.memory_usage().unwrap();
    assert_eq!(usage.total_physical_bytes, vm.commit_limit());
    assert_eq!(usage.commit_limit_bytes, vm.commit_limit());
    assert_eq!(usage.committed_bytes, current * PAGE_SIZE);
    assert_eq!(
        usage.available_bytes,
        vm.commit_limit() - current * PAGE_SIZE
    );
    assert_eq!(usage.resident_available_bytes, usage.available_bytes as i64);
    assert_eq!(usage.shared_committed_bytes, shared * PAGE_SIZE);
    assert_eq!(usage.peak_commitment_bytes, peak * PAGE_SIZE);
}

#[test]
fn memory_usage_private_commit_failures_and_decommit_preserve_high_water() {
    let mut vm = memory(3);
    check(&vm, 0, 0, 0);
    let base = vm
        .reserve(
            None,
            4 * PAGE_SIZE,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    check(&vm, 0, 0, 0);
    vm.commit(base, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
    vm.commit(base, PAGE_SIZE, prot::READONLY).unwrap();
    check(&vm, 2, 0, 2);
    assert_eq!(
        vm.commit(base, 4 * PAGE_SIZE, prot::READWRITE),
        Err(VmError::CommitmentLimit)
    );
    check(&vm, 2, 0, 2);
    vm.decommit(base, PAGE_SIZE).unwrap();
    vm.decommit(base, PAGE_SIZE).unwrap();
    check(&vm, 1, 0, 2);
    vm.commit(base + 2 * PAGE_SIZE, 2 * PAGE_SIZE, prot::READWRITE)
        .unwrap();
    check(&vm, 3, 0, 3);
    assert_eq!(
        vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE),
        Err(VmError::CommitmentLimit)
    );
    check(&vm, 3, 0, 3);
    vm.release(base).unwrap();
    check(&vm, 0, 0, 3);
}

#[test]
fn memory_usage_shared_aliases_count_unique_pages_until_final_retirement() {
    let mut vm = memory(3);
    let object = Arc::new(SharedObject::anonymous(4 * PAGE_SIZE).unwrap());
    let first = vm
        .map_shared_view(object.clone(), None, 0, 2 * PAGE_SIZE)
        .unwrap();
    check(&vm, 2, 2, 2);
    let second = vm
        .map_shared_view(object.clone(), None, PAGE_SIZE, 2 * PAGE_SIZE)
        .unwrap();
    check(&vm, 3, 3, 3);
    assert_eq!(
        vm.map_shared_view(object, Some(0x4000_0000), 3 * PAGE_SIZE, PAGE_SIZE)
            .unwrap_err(),
        VmError::CommitmentLimit
    );
    check(&vm, 3, 3, 3);
    vm.retire_shared_view(&first).unwrap();
    check(&vm, 2, 2, 3);
    vm.release(second.base).unwrap();
    check(&vm, 0, 0, 3);
}

#[test]
fn memory_usage_serializes_seven_little_endian_explicit_width_fields() {
    let usage = MemoryUsage {
        total_physical_bytes: 0x0102_0304_0506_0708,
        available_bytes: 2,
        resident_available_bytes: -3,
        committed_bytes: 4,
        shared_committed_bytes: 5,
        commit_limit_bytes: 6,
        peak_commitment_bytes: 7,
    };
    let data = usage.to_bytes();
    assert_eq!(data.len(), 7 * 8);
    assert_eq!(&data[..8], &[8, 7, 6, 5, 4, 3, 2, 1]);
    let fields: Vec<_> = data
        .chunks_exact(8)
        .map(|b| i64::from_le_bytes(b.try_into().unwrap()))
        .collect();
    assert_eq!(&fields[1..], &[2, -3, 4, 5, 6, 7]);
    let mut vm = memory(1);
    vm.commit_limit = u64::MAX;
    assert_eq!(vm.memory_usage(), Err(VmError::InvalidParameter));
}
