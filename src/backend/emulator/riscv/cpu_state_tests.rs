//! State transfer of the RV64 vCPU: privilege, CSRs, and vector state
//! round-trip, and a state that leaves them at their defaults (`None`, no
//! CSRs) keeps the hart's values.

use std::sync::Arc;

use vm_memory::{GuestAddress, GuestMemoryMmap};

use super::*;
use crate::isa::riscv::RiscVConfig;
use crate::vm::vcpu::{CpuState, RiscVRegisters, VCpu};

fn vcpu() -> RiscVVcpu {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    RiscVVcpu::new_embedded(0, mem, RiscVConfig::rv64gc())
}

fn regs(v: &RiscVVcpu) -> RiscVRegisters {
    match v.get_state().unwrap() {
        CpuState::RiscV(s) => s.regs,
        other => panic!("expected RISC-V state, got {other:?}"),
    }
}

#[test]
fn privilege_csrs_and_vectors_round_trip() {
    let mut a = vcpu();
    let mut r = regs(&a);
    assert_eq!(r.privilege, Some(3));
    r.privilege = Some(1);
    r.csrs.iter_mut().find(|(n, _)| *n == 0x340).unwrap().1 = 0xABCD; // mscratch
    let vector = r.vector.as_mut().unwrap();
    vector.vl = 2;
    vector.v[16 * 7] = 0x5A; // v7 byte 0
    a.set_state(&CpuState::riscv(r.clone())).unwrap();
    let back = regs(&a);
    assert_eq!(back.privilege, Some(1));
    assert_eq!(back.csrs, r.csrs);
    assert_eq!(back.vector, r.vector);

    let mut b = vcpu();
    b.set_state(&CpuState::riscv(back.clone())).unwrap();
    assert_eq!(regs(&b).csrs, back.csrs);
}

#[test]
fn default_fields_leave_the_hart_unchanged() {
    let mut v = vcpu();
    let mut r = regs(&v);
    r.privilege = Some(1);
    r.csrs.iter_mut().find(|(n, _)| *n == 0x340).unwrap().1 = 7;
    v.set_state(&CpuState::riscv(r)).unwrap();
    let mut fresh = RiscVRegisters::default();
    fresh.pc = 0x100;
    v.set_state(&CpuState::riscv(fresh)).unwrap();
    let after = regs(&v);
    assert_eq!(after.pc, 0x100);
    assert_eq!(after.privilege, Some(1));
    assert_eq!(after.csrs.iter().find(|(n, _)| *n == 0x340).unwrap().1, 7);

    let mut bad = regs(&v);
    bad.privilege = Some(2);
    assert!(v.set_state(&CpuState::riscv(bad)).is_err());
}
