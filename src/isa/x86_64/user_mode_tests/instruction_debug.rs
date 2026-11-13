//! Intel SDM086 Vol.3B19.3.1.1: execution #DB faults precede retirement.
use super::*;
use crate::isa::x86_64::flags::bits::{IOPL_MASK, RF, TF};

fn arm(h: &mut Harness, address: u64, control: u64) {
    h.vcpu.sregs.dr0 = address;
    h.vcpu.sregs.dr6 = 0;
    h.vcpu.sregs.dr7 = control;
}

fn fault(h: &mut Harness, pc: u64, slots: u64) {
    let count = h.vcpu.insn_count;
    assert!(matches!(
        h.vcpu.step_with_faults(),
        Err(Error::GuestEvent { vector: 1 })
    ));
    let event = event(h);
    assert_eq!(
        (event.vector, event.insn_rip, event.return_rip),
        (1, pc, pc)
    );
    assert_eq!(event.source, X86EventSource::Exception);
    assert_eq!(h.vcpu.insn_count, count);
    assert_eq!(h.vcpu.sregs.dr6 & 15, slots);
    assert_eq!(h.vcpu.user_rflags() & RF, 0);
}

#[test]
fn instruction_debug_matches_each_local_and_global_slot_before_retirement() {
    for slot in 0..4 {
        for enabled in [1, 2, 3] {
            let mut h = harness(&[0x48, 0xff, 0xc0]); // INC RAX.
            h.vcpu.sregs.dr6 = 0;
            h.vcpu.sregs.dr7 = enabled << (slot * 2);
            match slot {
                0 => h.vcpu.sregs.dr0 = CODE,
                1 => h.vcpu.sregs.dr1 = CODE,
                2 => h.vcpu.sregs.dr2 = CODE,
                _ => h.vcpu.sregs.dr3 = CODE,
            }
            fault(&mut h, CODE, 1 << slot);
            assert_eq!(h.vcpu.regs.rax, 0);
        }
    }
}

#[test]
fn instruction_debug_reports_all_matching_slots_and_wins_over_decode_and_tf() {
    let mut h = harness(&[0x0f, 0x0b]); // UD2 never executes.
    arm(&mut h, CODE, 0x11);
    h.vcpu.sregs.dr2 = CODE;
    h.vcpu.set_user_rflags(0x202 | TF);
    fault(&mut h, CODE, 5);
    assert_eq!(h.vcpu.sregs.dr6 & (1 << 14), 0);
}

#[test]
fn instruction_debug_ignores_disabled_data_and_nonmatching_slots() {
    for control in [0, 1 << 16 | 1, 2 << 16 | 1, 3 << 16 | 1] {
        let mut h = harness(&[0x90]);
        arm(&mut h, CODE, control);
        assert!(h.vcpu.step_with_faults().unwrap().is_none());
        assert_eq!(h.vcpu.regs.rip, CODE + 1);
        assert_eq!(h.vcpu.sregs.dr6, 0);
    }
    let mut h = harness(&[0x90]);
    arm(&mut h, CODE + 1, 1);
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
}

#[test]
fn instruction_debug_rf_suppresses_one_instruction_but_does_not_mask_tf() {
    let mut h = harness(&[0x90, 0x90]);
    arm(&mut h, CODE, 1);
    h.vcpu.set_user_rflags(0x202 | RF);
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    assert_eq!(h.vcpu.user_rflags() & RF, 0);
    h.vcpu.sregs.dr0 = CODE + 1;
    fault(&mut h, CODE + 1, 1);

    let mut h = harness(&[0x90]);
    arm(&mut h, CODE, 1);
    h.vcpu.set_user_rflags(0x202 | RF | TF);
    assert!(matches!(
        h.vcpu.step_with_faults(),
        Err(Error::GuestEvent { vector: 1 })
    ));
    assert_eq!(event(&mut h).return_rip, CODE + 1);
    assert_eq!(h.vcpu.insn_count, 1);
    assert_eq!(h.vcpu.sregs.dr6 & 0x400f, 0x4000);
}

#[test]
fn instruction_debug_mov_ss_shadow_suppresses_only_the_following_instruction() {
    let mut h = harness(&[0x8e, 0xd0, 0x90, 0x90]);
    h.vcpu.regs.rax = u64::from(h.vcpu.sregs.ss.selector);
    arm(&mut h, CODE + 2, 1);
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    assert_eq!(h.vcpu.regs.rip, CODE + 3);
    h.vcpu.sregs.dr0 = CODE + 3;
    fault(&mut h, CODE + 3, 1);
}

#[test]
fn instruction_debug_sti_does_not_suppress_an_execution_breakpoint() {
    let mut h = harness(&[0xfb, 0x90]);
    h.vcpu.set_user_rflags(2 | IOPL_MASK);
    arm(&mut h, CODE + 1, 1);
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    fault(&mut h, CODE + 1, 1);
}

#[test]
fn instruction_debug_compatibility_mode_compares_linear_cs_addresses() {
    let mut h = harness(&[0x90]);
    h.vcpu.set_user_compat(true);
    h.vcpu.sregs.cs.base = 0x1_0000_0000 + CODE;
    h.vcpu.regs.rip = 0;
    arm(&mut h, CODE, 1);
    fault(&mut h, 0, 1);
}

#[test]
fn instruction_debug_ss_shadow_survives_a_user_context_roundtrip() {
    let mut h = harness(&[0x8e, 0xd0, 0x90, 0x90]);
    h.vcpu.regs.rax = u64::from(h.vcpu.sregs.ss.selector);
    arm(&mut h, CODE + 2, 1);
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    let raw = h.vcpu.save_context().unwrap();
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    h.vcpu.restore_context(&raw).unwrap();
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    assert_eq!(h.vcpu.regs.rip, CODE + 3);
    h.vcpu.sregs.dr0 = CODE + 3;
    fault(&mut h, CODE + 3, 1);
}

#[test]
fn instruction_debug_clears_general_detect_without_changing_fault_rf() {
    let mut h = harness(&[0x90]);
    arm(&mut h, CODE, 1 | (1 << 13));
    h.vcpu.sregs.dr6 = 1 << 13; // Stale BD does not reclassify an execution #DB.
    fault(&mut h, CODE, 1);
    assert_eq!(h.vcpu.sregs.dr7 & (1 << 13), 0);
}

#[test]
fn instruction_debug_trace_entry_also_clears_general_detect() {
    let mut h = harness(&[0x90]);
    h.vcpu.sregs.dr7 = 1 << 13;
    h.vcpu.set_user_rflags(0x202 | TF);
    assert!(matches!(
        h.vcpu.step_with_faults(),
        Err(Error::GuestEvent { vector: 1 })
    ));
    assert_eq!(event(&mut h).return_rip, CODE + 1);
    assert_eq!(h.vcpu.sregs.dr7 & (1 << 13), 0);
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn instruction_debug_jit_cannot_skip_an_enabled_comparator_even_with_rf() {
    let mut h = harness(&[0x90]);
    assert!(!h.vcpu.jit_disabled_for_debugger());
    for slot in 0..4 {
        for enable in [1, 2] {
            h.vcpu.sregs.dr7 = enable << (slot * 2);
            for flags in [0x202, 0x202 | RF] {
                h.vcpu.set_user_rflags(flags);
                assert!(h.vcpu.jit_disabled_for_debugger());
                assert!(!h.vcpu.jit_try_block().unwrap());
                assert_eq!(h.vcpu.regs.rip, CODE);
                assert_eq!(h.vcpu.insn_count, 0);
            }
        }
    }
    h.vcpu.sregs.dr7 = 0;
    assert!(!h.vcpu.jit_disabled_for_debugger());
}
