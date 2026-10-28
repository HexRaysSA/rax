//! Intel SDM 086, Vol. 3B 19.3.1.4 and Vol. 3A 7.8.3.
//! TF is sampled before retirement; MOV/POP SS suppress their own trace
//! trap, while LSS and STI do not have that debug suppression.

use super::*;
use crate::isa::x86_64::flags::bits::{IOPL_MASK, TF};

fn trace(h: &mut Harness, pc: u64) {
    assert!(matches!(
        h.vcpu.step_with_faults(),
        Err(Error::GuestEvent { vector: 1 })
    ));
    let trap = event(h);
    assert_eq!(trap.return_rip, pc);
    assert_eq!(trap.source, X86EventSource::Exception);
    assert_eq!(h.vcpu.regs.rip, pc);
    assert_ne!(h.vcpu.sregs.dr6 & (1 << 14), 0);
}

#[test]
fn an_incoming_tf_traps_after_the_retired_instruction() {
    let mut h = harness(&[0x90, 0x0f, 0x0b]); // NOP; UD2.
    h.vcpu.set_user_rflags(0x202 | TF);
    trace(&mut h, CODE + 1);
    assert_eq!(h.vcpu.insn_count, 1);
}

#[test]
fn popf_setting_tf_steps_the_following_instruction() {
    let mut h = harness(&[0x9d, 0x90, 0x0f, 0x0b]);
    h.mem
        .write_obj(0x202u64 | TF, GuestAddress(0x3f00))
        .unwrap();
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    assert_eq!(h.vcpu.regs.rip, CODE + 1);
    assert_ne!(h.vcpu.user_rflags() & TF, 0);
    trace(&mut h, CODE + 2);
}

#[test]
fn popf_clearing_an_incoming_tf_still_traps() {
    let mut h = harness(&[0x9d, 0x90, 0x0f, 0x0b]);
    h.mem.write_obj(0x202u64, GuestAddress(0x3f00)).unwrap();
    h.vcpu.set_user_rflags(0x202 | TF);
    trace(&mut h, CODE + 1);
    assert_eq!(h.vcpu.user_rflags() & TF, 0);
}

#[test]
fn mov_ss_suppresses_its_trace_and_the_next_instruction_steps() {
    let mut h = harness(&[0x8e, 0xd0, 0x90, 0x0f, 0x0b]); // MOV SS,AX; NOP; UD2.
    h.vcpu.regs.rax = u64::from(h.vcpu.sregs.ss.selector);
    h.vcpu.set_user_rflags(0x202 | TF);
    assert!(h.vcpu.step_with_faults().unwrap().is_none());
    assert_eq!(h.vcpu.regs.rip, CODE + 2);
    trace(&mut h, CODE + 3);
}

#[test]
fn a_faulting_ss_load_does_not_retire_or_publish_a_trace() {
    let mut h = harness(&[0x8e, 0xd0]); // MOV SS,AX with a null selector.
    let ss = h.vcpu.sregs.ss.selector;
    h.vcpu.regs.rax = 0;
    h.vcpu.set_user_rflags(0x202 | TF);
    assert!(matches!(
        h.vcpu.step_with_faults(),
        Err(Error::GuestEvent { vector: 13 })
    ));
    let fault = event(&mut h);
    assert_eq!(
        (fault.vector, fault.return_rip, fault.error_code),
        (13, CODE, Some(0))
    );
    assert_eq!(h.vcpu.sregs.ss.selector, ss);
    assert_eq!(h.vcpu.insn_count, 0);
    assert_eq!(h.vcpu.sregs.dr6 & (1 << 14), 0);
    assert_ne!(h.vcpu.user_rflags() & (1 << 16), 0);
}

#[test]
fn a_traced_branch_reports_the_target_frontier() {
    let mut h = harness(&[0xeb, 0x07]); // JMP CODE+9.
    h.vcpu.set_user_rflags(0x202 | TF);
    trace(&mut h, CODE + 9);
    assert_eq!(h.vcpu.insn_count, 1);
}

#[test]
fn sti_with_sufficient_iopl_does_not_suppress_the_trace() {
    let mut h = harness(&[0xfb, 0x90, 0x0f, 0x0b]); // STI; NOP; UD2.
    h.vcpu.set_user_rflags(2 | IOPL_MASK | TF);
    trace(&mut h, CODE + 1);
    assert_ne!(h.vcpu.user_rflags() & (1 << 9), 0);
}

#[test]
fn lss_does_not_suppress_the_trace() {
    let mut bytes = vec![0x48, 0x0f, 0xb2, 0x25]; // LSS RSP,[RIP+disp32].
    let displacement = i32::try_from(DATA as i64 - (CODE + 8) as i64).unwrap();
    bytes.extend_from_slice(&displacement.to_le_bytes());
    bytes.extend_from_slice(&[0x0f, 0x0b]);
    let mut h = harness(&bytes);
    let stack = STACK + 0x800;
    h.mem.write_obj(stack, GuestAddress(0x1000)).unwrap();
    h.mem
        .write_obj(h.vcpu.sregs.ss.selector, GuestAddress(0x1008))
        .unwrap();
    h.vcpu.set_user_rflags(0x202 | TF);
    trace(&mut h, CODE + 8);
    assert_eq!(h.vcpu.regs.rsp, stack);
}

#[test]
fn an_instruction_fault_or_int3_wins_over_the_trace() {
    for (code, vector, pc) in [
        (&[0x0f, 0x0b][..], 6, CODE), // UD2.
        (&[0xcc][..], 3, CODE + 1),   // INT3.
    ] {
        let mut h = harness(code);
        h.vcpu.set_user_rflags(0x202 | TF);
        assert!(matches!(
            h.vcpu.step_with_faults(),
            Err(Error::GuestEvent { vector: v }) if v == vector
        ));
        let trap = event(&mut h);
        assert_eq!(trap.vector, vector);
        assert_eq!(trap.return_rip, pc);
    }
}

#[test]
fn rep_movsb_traces_each_iteration_with_precise_memory_and_resume_flags() {
    let mut h = harness(&[0xf3, 0xa4, 0x0f, 0x0b]);
    h.mem.write_slice(&[7, 8, 9], GuestAddress(0x1000)).unwrap();
    h.vcpu.regs.rsi = DATA;
    h.vcpu.regs.rdi = DATA + 0x100;
    h.vcpu.regs.rcx = 3;
    h.vcpu.set_user_rflags(0x202 | TF);
    for done in 1..=3 {
        trace(&mut h, if done == 3 { CODE + 2 } else { CODE });
        assert_eq!(h.vcpu.regs.rcx, 3 - done);
        assert_eq!(h.vcpu.regs.rsi, DATA + done);
        assert_eq!(h.vcpu.regs.rdi, DATA + 0x100 + done);
        let mut actual = [0; 3];
        h.mem.read_slice(&mut actual, GuestAddress(0x1100)).unwrap();
        let mut expected = [0; 3];
        expected[..done as usize].copy_from_slice(&[7, 8, 9][..done as usize]);
        assert_eq!(actual, expected);
        assert_eq!(h.vcpu.user_rflags() & (1 << 16) != 0, done != 3);
        assert_eq!(h.vcpu.insn_count, u64::from(done == 3));
    }
}

#[test]
fn compat_pop_ss_suppresses_only_its_own_trace() {
    for (code, width) in [(&[0x17, 0x90][..], 4), (&[0x66, 0x17, 0x90][..], 2)] {
        let mut h = harness(code);
        h.vcpu.set_user_compat(true);
        h.mem
            .write_obj(u32::from(h.vcpu.sregs.ss.selector), GuestAddress(0x3f00))
            .unwrap();
        h.vcpu.set_user_rflags(0x202 | TF);
        assert!(h.vcpu.step_with_faults().unwrap().is_none());
        assert_eq!(h.vcpu.regs.rsp, STACK + 0xf00 + width);
        assert_eq!(h.vcpu.regs.rip, CODE + code.len() as u64 - 1);
        trace(&mut h, CODE + code.len() as u64);
    }
}

#[test]
fn repeated_memory_strings_step_each_element_at_all_widths_and_directions() {
    // Intel SDM REP operation: update the used indexes by +/- element width,
    // decrement the address-size count, and retain the prefix PC until done.
    for opcode in [0xa4u8, 0xaa, 0xac, 0xa6, 0xae] {
        for width in [1u64, 2, 4, 8] {
            for backward in [false, true] {
                for addr32 in [false, true] {
                    let mut code = vec![0xf3];
                    if addr32 {
                        code.push(0x67);
                    }
                    if width == 2 {
                        code.push(0x66);
                    }
                    if width == 8 {
                        code.push(0x48);
                    }
                    code.push(opcode + u8::from(width != 1));
                    let len = code.len() as u64;
                    let mut h = harness(&code);
                    h.mem
                        .write_slice(&[0x5a; 0x200], GuestAddress(0x1000))
                        .unwrap();
                    let offset = if backward { 2 * width } else { 0 };
                    let source = DATA + offset;
                    let destination = DATA + 0x100 + offset;
                    let high = if addr32 { 0xa5a5_1234_0000_0000 } else { 0 };
                    h.vcpu.regs.rsi = high | source;
                    h.vcpu.regs.rdi = high | destination;
                    h.vcpu.regs.rcx = high | 3;
                    h.vcpu.regs.rax = 0x5a5a_5a5a_5a5a_5a5a;
                    h.vcpu
                        .set_user_rflags(0x202 | TF | if backward { 1 << 10 } else { 0 });
                    for done in 1..=3u64 {
                        trace(&mut h, if done == 3 { CODE + len } else { CODE });
                        assert_eq!(
                            h.vcpu.regs.rcx,
                            3 - done,
                            "opcode={opcode:#x}, width={width}"
                        );
                        let delta = done * width;
                        if matches!(opcode, 0xa4 | 0xac | 0xa6) {
                            assert_eq!(
                                h.vcpu.regs.rsi,
                                if backward {
                                    source - delta
                                } else {
                                    source + delta
                                }
                            );
                        }
                        if matches!(opcode, 0xa4 | 0xaa | 0xa6 | 0xae) {
                            assert_eq!(
                                h.vcpu.regs.rdi,
                                if backward {
                                    destination - delta
                                } else {
                                    destination + delta
                                }
                            );
                        }
                        if opcode == 0xac {
                            let expected = if width == 4 {
                                0x5a5a_5a5a
                            } else {
                                0x5a5a_5a5a_5a5a_5a5a
                            };
                            assert_eq!(h.vcpu.regs.rax, expected);
                        }
                        assert_eq!(h.vcpu.insn_count, u64::from(done == 3));
                        assert_eq!(h.vcpu.user_rflags() & (1 << 16) != 0, done != 3);
                    }
                }
            }
        }
    }
}

#[test]
fn repeat_comparison_termination_and_zero_count_retire_before_trapping() {
    for (opcode, prefix, equal, count) in [
        (0xa6, 0xf3, false, 3),
        (0xa6, 0xf2, true, 3),
        (0xae, 0xf3, false, 3),
        (0xae, 0xf2, true, 3),
        (0xa4, 0xf3, false, 0),
    ] {
        let mut h = harness(&[prefix, opcode]);
        h.mem.write_obj(1u8, GuestAddress(0x1000)).unwrap();
        h.mem
            .write_obj(if equal { 1u8 } else { 2u8 }, GuestAddress(0x1100))
            .unwrap();
        h.vcpu.regs.rax = 1;
        h.vcpu.regs.rsi = DATA;
        h.vcpu.regs.rdi = DATA + 0x100;
        h.vcpu.regs.rcx = count;
        h.vcpu.set_user_rflags(0x202 | TF);
        trace(&mut h, CODE + 2);
        assert_eq!(h.vcpu.regs.rcx, count.saturating_sub(1));
        assert_eq!(h.vcpu.insn_count, 1);
        assert_eq!(h.vcpu.user_rflags() & (1 << 16), 0);
    }
}

#[test]
fn repeat_fault_after_a_traced_element_preserves_the_next_frontier() {
    let mut h = harness(&[0xf3, 0xa4]);
    h.mem.write_slice(&[7, 8], GuestAddress(0x1000)).unwrap();
    h.vcpu.regs.rsi = DATA;
    h.vcpu.regs.rdi = DATA + 0xfff;
    h.vcpu.regs.rcx = 2;
    h.vcpu.set_user_rflags(0x202 | TF);
    trace(&mut h, CODE);
    h.vcpu.capture_user_debug_status();
    assert!(matches!(
        h.vcpu.step_with_faults(),
        Err(Error::GuestAccess(_))
    ));
    assert_eq!(h.vcpu.regs.rip, CODE);
    assert_eq!(h.vcpu.regs.rsi, DATA + 1);
    assert_eq!(h.vcpu.regs.rdi, DATA + 0x1000);
    assert_eq!(h.vcpu.regs.rcx, 1);
    assert_eq!(h.vcpu.insn_count, 0);
    assert_ne!(h.vcpu.user_rflags() & (1 << 16), 0);
    assert_eq!(h.vcpu.sregs.dr6 & (1 << 14), 0);
    assert!(h.vcpu.take_user_trap().is_none());
    assert_eq!(h.mem.read_obj::<u8>(GuestAddress(0x1fff)).unwrap(), 7);
}
