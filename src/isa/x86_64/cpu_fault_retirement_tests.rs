//! Attempt-local accounting at the wrapping counter boundary.
use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
#[test]
fn fault_marker_and_counter_wrap_do_not_leak_across_attempts() {
    let m = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap());
    m.write_slice(&[0x90, 0x90], GuestAddress(0)).unwrap();
    let mut c = X86_64Vcpu::new(0, m);
    c.regs.rip = 0;
    c.sregs.cs.base = 0;
    c.insn_count = u64::MAX;
    c.instruction_faulted = true;
    c.step().unwrap();
    assert_eq!(c.insn_count, 0);
    c.regs.rip = 0x1000;
    assert!(c.step().is_err());
    assert_eq!(c.insn_count, 0);
    c.regs.rip = 1;
    c.step().unwrap();
    assert_eq!(c.insn_count, 1);
}
#[test]
fn reset_discards_the_attempt_local_marker() {
    let m = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap());
    let mut c = X86_64Vcpu::new(0, m);
    c.instruction_faulted = true;
    c.reset_state();
    assert!(!c.instruction_faulted);
    assert_eq!(c.insn_count, 0);
}
