//! Direct execution, interrupt-boundary, and snapshot coverage for x86 STI.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn vcpu_with_code(code: &[u8]) -> X86_64Vcpu {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory.write_slice(code, GuestAddress(0)).unwrap();
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.cr0 = 0;
    vcpu.regs.rflags = 0x2;
    vcpu
}

fn install_real_mode_vector(memory: &GuestMemoryMmap, idt_base: u64, vector: u8, handler: u16) {
    let mut entry = [0_u8; 4];
    entry[0..2].copy_from_slice(&handler.to_le_bytes());
    entry[2..4].copy_from_slice(&0_u16.to_le_bytes());
    memory
        .write_slice(&entry, GuestAddress(idt_base + u64::from(vector) * 4))
        .unwrap();
}

#[test]
fn sti_cli_sequence_never_exposes_an_interruptible_boundary() {
    let mut vcpu = vcpu_with_code(&[0xFB, 0xFA, 0xF4]);

    assert!(vcpu.step().unwrap().is_none());
    assert_eq!(vcpu.regs.rip, 1);
    assert_ne!(vcpu.regs.rflags & flags::bits::IF, 0);
    assert!(vcpu.interrupt_inhibit);
    assert!(!vcpu.can_inject_interrupt());

    assert!(vcpu.step().unwrap().is_none());
    assert_eq!(vcpu.regs.rip, 2);
    assert_eq!(vcpu.regs.rflags & flags::bits::IF, 0);
    assert!(!vcpu.interrupt_inhibit);
    assert!(!vcpu.can_inject_interrupt());
}

#[test]
fn sti_nop_exposes_interrupts_only_after_the_nop_boundary() {
    let mut vcpu = vcpu_with_code(&[0xFB, 0x90, 0xF4]);

    assert!(vcpu.step().unwrap().is_none());
    assert!(vcpu.interrupt_inhibit);
    assert!(!vcpu.can_inject_interrupt());

    assert!(vcpu.step().unwrap().is_none());
    assert_eq!(vcpu.regs.rip, 2);
    assert!(!vcpu.interrupt_inhibit);
    assert!(vcpu.can_inject_interrupt());
}

#[test]
fn sti_hlt_consumes_the_shadow_before_halt_and_allows_wakeup() {
    let mut vcpu = vcpu_with_code(&[0xFB, 0xF4]);

    assert!(vcpu.step().unwrap().is_none());
    assert!(vcpu.interrupt_inhibit);
    assert!(matches!(vcpu.step().unwrap(), Some(VcpuExit::Hlt)));
    assert!(vcpu.halted);
    assert!(!vcpu.interrupt_inhibit);
    assert!(vcpu.can_inject_interrupt());
}

#[test]
fn maskable_injection_is_blocked_but_nmi_delivery_consumes_the_sti_shadow() {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory.write_slice(&[0xFB, 0x90], GuestAddress(0)).unwrap();
    install_real_mode_vector(&memory, 0x1000, 2, 0x2000);
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.cr0 = 0;
    vcpu.sregs.idt.base = 0x1000;
    vcpu.sregs.idt.limit = 0x03FF;
    vcpu.regs.rflags = 0x2;
    vcpu.regs.rsp = 0x3800;

    assert!(vcpu.step().unwrap().is_none());
    let rsp_after_sti = vcpu.regs.rsp;
    assert!(!vcpu.inject_interrupt(0x20).unwrap());
    assert_eq!(vcpu.regs.rip, 1);
    assert_eq!(vcpu.regs.rsp, rsp_after_sti);
    assert!(vcpu.interrupt_inhibit);

    assert!(vcpu.inject_nmi().unwrap());
    assert_eq!(vcpu.regs.rip, 0x2000);
    assert_eq!(vcpu.regs.rsp, rsp_after_sti - 3 * 2);
    assert!(!vcpu.interrupt_inhibit);
}

#[test]
fn sti_with_if_already_set_creates_no_interrupt_shadow() {
    let mut vcpu = vcpu_with_code(&[0xFB]);
    vcpu.regs.rflags |= flags::bits::IF;

    assert!(vcpu.step().unwrap().is_none());
    assert!(!vcpu.interrupt_inhibit);
    assert!(vcpu.can_inject_interrupt());
}

#[test]
fn sti_pvi_sets_vif_without_enabling_physical_interrupts_or_shadow() {
    let mut vcpu = vcpu_with_code(&[0xFB]);
    vcpu.sregs.cr0 = 1;
    vcpu.sregs.cr4 = 1 << 1;
    vcpu.sregs.cs.selector = 3;

    assert!(vcpu.step().unwrap().is_none());
    assert_eq!(vcpu.regs.rflags & flags::bits::IF, 0);
    assert_ne!(vcpu.regs.rflags & flags::bits::VIF, 0);
    assert!(!vcpu.interrupt_inhibit);
    assert!(!vcpu.can_inject_interrupt());
}

#[test]
fn sti_pvi_vip_fault_is_noncommitting_and_ends_a_prior_shadow() {
    let mut vcpu = vcpu_with_code(&[0xFB]);
    vcpu.sregs.cr0 = 1;
    vcpu.sregs.cr4 = 1 << 1;
    vcpu.sregs.cs.selector = 3;
    vcpu.regs.rflags |= flags::bits::VIP;
    vcpu.interrupt_inhibit = true;
    let before = vcpu.regs.rflags;

    let error = vcpu
        .step()
        .expect_err("missing IDT must expose the #GP delivery attempt");
    assert!(error.to_string().contains("IDT entry 13 not present"));
    assert_eq!(vcpu.regs.rflags, before);
    assert_eq!(vcpu.regs.rip, 0);
    assert!(!vcpu.interrupt_inhibit);
}

#[test]
fn a_faulting_shadowed_instruction_consumes_the_sti_shadow() {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap());
    memory.write_slice(&[0xFB], GuestAddress(0x0FFF)).unwrap();
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.cr0 = 0;
    vcpu.regs.rflags = 0x2;
    vcpu.regs.rip = 0x0FFF;

    assert!(vcpu.step().unwrap().is_none());
    assert_eq!(vcpu.regs.rip, 0x1000);
    assert!(vcpu.interrupt_inhibit);
    assert!(vcpu.step().is_err());
    assert!(!vcpu.interrupt_inhibit);
}

#[test]
fn sti_shadow_round_trips_snapshots_but_external_state_injection_clears_it() {
    let mut source = vcpu_with_code(&[0xFB]);
    assert!(source.step().unwrap().is_none());
    assert!(source.interrupt_inhibit);

    let architectural = source.get_state().unwrap();
    let emulator = source.get_emulator_state().unwrap();
    assert!(emulator.interrupt_inhibit);

    let mut restored = vcpu_with_code(&[0x90]);
    restored.set_state(&architectural).unwrap();
    assert!(!restored.interrupt_inhibit);
    restored.set_emulator_state(&emulator).unwrap();
    assert!(restored.interrupt_inhibit);

    restored.set_state(&architectural).unwrap();
    assert!(!restored.interrupt_inhibit);
    restored.interrupt_inhibit = true;
    restored.reset_state();
    assert!(!restored.interrupt_inhibit);
}

fn vcpu_in_nmi() -> X86_64Vcpu {
    let mut vcpu = vcpu_with_code(&[0xf4]);
    let memory = vcpu.mmu.checkpoint_memory();
    install_real_mode_vector(&memory, 0x1000, 2, 0x2000);
    memory
        .write_slice(&[0x90, 0xcf], GuestAddress(0x2000))
        .unwrap();
    vcpu.sregs.idt.base = 0x1000;
    vcpu.sregs.idt.limit = 0x03ff;
    vcpu.regs.rsp = 0x3800;
    assert!(vcpu.inject_nmi().unwrap());
    vcpu
}

#[test]
fn nmi_blocks_reentry_until_iret() {
    let mut vcpu = vcpu_in_nmi();
    assert!(vcpu.step().unwrap().is_none()); // NOP within the NMI handler.
    let handler_rsp = vcpu.regs.rsp;
    assert!(!vcpu.inject_nmi().unwrap());
    assert_eq!((vcpu.regs.rip, vcpu.regs.rsp), (0x2001, handler_rsp));
    assert!(vcpu.step().unwrap().is_none()); // IRET.
    assert_eq!((vcpu.regs.rip, vcpu.regs.rsp), (0, 0x3800));
    assert!(vcpu.inject_nmi().unwrap());
}

#[test]
fn nmi_block_releases_on_faulting_iret() {
    let mut vcpu = vcpu_in_nmi();
    assert!(vcpu.step().unwrap().is_none());
    assert!(!vcpu.inject_nmi().unwrap());
    // Stack begins immediately above RAM, so IRET faults on its first pop.
    vcpu.regs.rsp = 0x4000;
    assert!(vcpu.step().is_err());
    assert_eq!(vcpu.regs.rip, 0x2001);
    vcpu.regs.rsp = 0x3800;
    assert!(vcpu.inject_nmi().unwrap());
}
