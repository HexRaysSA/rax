//! Observable exclusive rights across real user CPU/address-space adapters.
use super::*;
use crate::isa::arm::common::cpu::AccessType;
use crate::isa::arm::common::memory::{ArmMemory, MemoryError};
use crate::user::cpu::aarch64::UserArmMemory;

fn thread(space: &AddressSpace, pc: u64) -> A64UserCpu {
    let mut cpu = A64UserCpu::new(space);
    cpu.core_mut().set_pc(pc);
    cpu.core_mut().set_x(1, DATA);
    cpu
}

fn shared_space() -> AddressSpace {
    space(&words(&[A64_LDXR_X0_X1, A64_STXR_W2_X0_X1, A64_STR_X0_X1]))
}

#[test]
fn identical_and_aba_peer_stores_revoke_the_other_threads_rights() {
    for values in [&[0u64][..], &[99u64, 0][..]] {
        let shared = shared_space();
        let mut a = thread(&shared, CODE);
        let mut b = thread(&shared, CODE + 8);
        assert_eq!(a.run(1), A64Exit::Yield);
        a.core_mut().set_x(0, 123);
        for &value in values {
            b.core_mut().set_pc(CODE + 8);
            b.core_mut().set_x(0, value);
            assert_eq!(b.run(1), A64Exit::Yield);
        }
        assert_eq!(a.run(1), A64Exit::Yield);
        assert_eq!(a.core().get_x(2), 1, "values={values:?}");
        let mut bytes = [0; 8];
        shared.read(DATA, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 8]);
    }
}

#[test]
fn a_tracked_address_space_writer_revokes_a_guest_reservation() {
    let shared = shared_space();
    let mut cpu = thread(&shared, CODE);
    assert_eq!(cpu.run(1), A64Exit::Yield);
    shared.write(DATA, &[0; 8]).unwrap();
    assert_eq!(cpu.run(1), A64Exit::Yield);
    assert_eq!(cpu.core().get_x(2), 1);
}

#[test]
fn a_successful_conditional_write_excludes_the_second_thread() {
    let shared = shared_space();
    let mut a = thread(&shared, CODE);
    let mut b = thread(&shared, CODE);
    for cpu in [&mut a, &mut b] {
        assert_eq!(cpu.run(1), A64Exit::Yield);
    }
    a.core_mut().set_x(0, 111);
    b.core_mut().set_x(0, 222);
    assert_eq!(a.run(1), A64Exit::Yield);
    assert_eq!(a.core().get_x(2), 0);
    assert_eq!(b.run(1), A64Exit::Yield);
    assert_eq!(b.core().get_x(2), 1);
    let mut bytes = [0; 8];
    shared.read(DATA, &mut bytes).unwrap();
    assert_eq!(u64::from_le_bytes(bytes), 111);
}

#[test]
fn the_next_reservation_granule_remains_independent() {
    for (offset, failed) in [(64, 0), (63, 1)] {
        let shared = shared_space();
        let mut cpu = thread(&shared, CODE);
        assert_eq!(cpu.run(1), A64Exit::Yield);
        shared.write(DATA + offset, &[0]).unwrap();
        assert_eq!(cpu.run(1), A64Exit::Yield);
        assert_eq!(cpu.core().get_x(2), failed, "offset={offset}");
    }
}

#[test]
fn equal_virtual_addresses_in_distinct_spaces_do_not_share_rights() {
    let first = shared_space();
    let second = shared_space();
    let mut a = thread(&first, CODE);
    let mut b = thread(&second, CODE + 8);
    assert_eq!(a.run(1), A64Exit::Yield);
    assert_eq!(b.run(1), A64Exit::Yield);
    assert_eq!(a.run(1), A64Exit::Yield);
    assert_eq!(a.core().get_x(2), 0);
}

#[test]
fn store_exclusive_rechecks_write_permissions_before_ram_mutation() {
    let shared = shared_space();
    let mut memory = UserArmMemory::new(shared.clone());
    assert_eq!(memory.read_exclusive(RODATA, 8).unwrap(), [0; 8]);
    assert!(matches!(
        memory.write_exclusive(RODATA, &[1; 8]),
        Err(MemoryError::Permission {
            access: AccessType::Write,
            ..
        })
    ));
    let mut bytes = [0; 8];
    shared.read(RODATA, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 8]);
}
