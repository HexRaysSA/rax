//! Instruction-level Cortex-M execution for embedders. Encodings are from
//! LLVM 23 `llvm-mc -triple=thumbv7em`; expected exception state follows
//! the Armv7-M ARM (DDI 0403E.e) B1.5 pseudocode. Instruction semantics are
//! covered against QEMU by `cortex_m_oracle_tests.rs`.

use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::*;
use crate::isa::arm::cortex_m::scb::{ccr, cfsr, hfsr, shcsr};
use crate::vm::vcpu::{CortexMRegisters, CortexMSystemRegisters};

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;
const HANDLER: u64 = 0x3000;
const STACK_TOP: u32 = 0x3F00;

/// 16 KiB of guest memory at 0: a vector table at 0 whose exceptions 2-15
/// all enter [`HANDLER`], `code` at [`CODE`], and MSP at [`STACK_TOP`].
fn new_vcpu(code: &[u8]) -> (CortexMVcpu, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    for exception in 2..16u64 {
        mem.write_slice(
            &(HANDLER as u32 | 1).to_le_bytes(),
            GuestAddress(4 * exception),
        )
        .unwrap();
    }
    mem.write_slice(code, GuestAddress(CODE)).unwrap();
    let mut vcpu = CortexMVcpu::new(0, mem.clone());
    let mut regs = CortexMRegisters::default();
    regs.pc = CODE as u32;
    regs.msp = STACK_TOP;
    vcpu.set_state(&CpuState::cortex_m(regs, Default::default()))
        .unwrap();
    (vcpu, mem)
}

fn state(vcpu: &CortexMVcpu) -> (CortexMRegisters, CortexMSystemRegisters) {
    match vcpu.get_state().unwrap() {
        CpuState::CortexM(state) => (state.regs, state.sregs),
        other => panic!("expected Cortex-M state, got {other:?}"),
    }
}

fn regs(vcpu: &CortexMVcpu) -> CortexMRegisters {
    state(vcpu).0
}

fn edit(
    vcpu: &mut CortexMVcpu,
    f: impl FnOnce(&mut CortexMRegisters, &mut CortexMSystemRegisters),
) {
    let (mut regs, mut sregs) = state(vcpu);
    f(&mut regs, &mut sregs);
    vcpu.set_state(&CpuState::cortex_m(regs, sregs)).unwrap();
}

fn word(mem: &GuestMemoryMmap, addr: u64) -> u32 {
    let mut b = [0u8; 4];
    mem.read_slice(&mut b, GuestAddress(addr)).unwrap();
    u32::from_le_bytes(b)
}

#[test]
fn thumb_and_thumb2_code_executes_from_guest_memory() {
    // movs r0,#42 ; str r0,[r1] ; movw r2,#0x1234
    let (mut vcpu, mem) = new_vcpu(&[0x2A, 0x20, 0x08, 0x60, 0x41, 0xF2, 0x34, 0x22]);
    edit(&mut vcpu, |r, _| r.r[1] = DATA as u32);
    assert!(vcpu.supports_stepping());
    for expected_pc in [CODE + 2, CODE + 4, CODE + 8] {
        assert!(vcpu.step_insn().unwrap().is_none());
        assert_eq!(vcpu.current_pc(), expected_pc);
    }
    let r = regs(&vcpu);
    assert_eq!((r.r[0], r.r[2]), (42, 0x1234));
    assert_eq!(word(&mem, DATA), 42);
    assert_eq!(vcpu.instruction_count(), 3);
}

#[test]
fn svc_enters_svcall_and_bx_lr_returns() {
    // svc #7 ; movs r0,#1 — the handler: adds r0,#1 ; bx lr
    let (mut vcpu, mem) = new_vcpu(&[0x07, 0xDF, 0x01, 0x20]);
    mem.write_slice(&[0x01, 0x30, 0x70, 0x47], GuestAddress(HANDLER))
        .unwrap();
    edit(&mut vcpu, |r, _| {
        r.r[0] = 5;
        r.xpsr |= 0x2000_0000; // C
    });
    assert!(vcpu.step_insn().unwrap().is_none());
    let r = regs(&vcpu);
    assert_eq!(r.pc, HANDLER as u32);
    assert_eq!(r.xpsr & 0x1FF, 11, "IPSR = SVCall");
    assert_eq!(r.lr, 0xFFFF_FFF9, "EXC_RETURN: Thread mode, main stack");
    assert_eq!(r.msp, STACK_TOP - 32, "basic frame, already 8-byte aligned");
    assert_eq!(word(&mem, u64::from(r.msp)), 5, "stacked R0");
    assert_eq!(
        word(&mem, u64::from(r.msp) + 24),
        CODE as u32 + 2,
        "return address"
    );
    assert_eq!(
        word(&mem, u64::from(r.msp) + 28),
        0x2100_0000,
        "stacked xPSR: C, T"
    );
    // The handler's `adds` changes R0 and the flags; the return restores both.
    for _ in 0..2 {
        assert!(vcpu.step_insn().unwrap().is_none());
    }
    let r = regs(&vcpu);
    assert_eq!((r.pc, r.msp, r.r[0]), (CODE as u32 + 2, STACK_TOP, 5));
    assert_eq!(r.xpsr, 0x2100_0000, "Thread mode, flags as stacked");
}

#[test]
fn exception_entry_realigns_the_stack_and_return_undoes_it() {
    let (mut vcpu, mem) = new_vcpu(&[0x07, 0xDF]); // svc #7
    mem.write_slice(&[0x70, 0x47], GuestAddress(HANDLER))
        .unwrap(); // bx lr
    edit(&mut vcpu, |r, _| r.msp = STACK_TOP - 4);
    vcpu.step_insn().unwrap();
    let r = regs(&vcpu);
    // (0x3EFC - 0x20) with bit 2 cleared (CCR.STKALIGN is 1 at reset).
    assert_eq!(r.msp, 0x3ED8);
    assert_eq!(
        word(&mem, 0x3ED8 + 28) & (1 << 9),
        1 << 9,
        "stacked xPSR[9] records it"
    );
    vcpu.step_insn().unwrap();
    assert_eq!(regs(&vcpu).msp, STACK_TOP - 4);
}

#[test]
fn process_stack_frames_and_exc_return() {
    let (mut vcpu, mem) = new_vcpu(&[0x07, 0xDF]); // svc #7
    mem.write_slice(&[0x70, 0x47], GuestAddress(HANDLER))
        .unwrap(); // bx lr
    edit(&mut vcpu, |r, _| {
        r.psp = 0x2F00;
        r.control = 0b010; // SPSEL
    });
    vcpu.step_insn().unwrap();
    let r = regs(&vcpu);
    assert_eq!((r.psp, r.msp), (0x2F00 - 32, STACK_TOP));
    assert_eq!(r.lr, 0xFFFF_FFFD, "EXC_RETURN: Thread mode, process stack");
    assert_eq!(r.control & 2, 0, "Handler mode runs on the main stack");
    vcpu.step_insn().unwrap();
    let r = regs(&vcpu);
    assert_eq!((r.pc, r.psp, r.control), (CODE as u32 + 2, 0x2F00, 0b010));
}

#[test]
fn bkpt_escalates_to_hardfault_returning_to_itself() {
    let (mut vcpu, mem) = new_vcpu(&[0x03, 0xBE]); // bkpt #3
    assert!(vcpu.step_insn().unwrap().is_none());
    let (r, s) = state(&vcpu);
    assert_eq!((r.pc, r.xpsr & 0x1FF), (HANDLER as u32, 3));
    assert_eq!(word(&mem, u64::from(r.msp) + 24), CODE as u32);
    assert_eq!(s.hfsr, hfsr::DEBUGEVT);
    assert_eq!(vcpu.instruction_count(), 0, "a breakpoint does not retire");
}

#[test]
fn svc_that_cannot_preempt_escalates_to_hardfault() {
    // In the SVCall handler another SVC has the same priority.
    let (mut vcpu, mem) = new_vcpu(&[0x07, 0xDF]); // svc #7
    mem.write_slice(&[0x01, 0xDF], GuestAddress(HANDLER))
        .unwrap(); // svc #1
    vcpu.step_insn().unwrap();
    vcpu.step_insn().unwrap();
    let (r, s) = state(&vcpu);
    assert_eq!(r.xpsr & 0x1FF, 3);
    assert_eq!(r.lr, 0xFFFF_FFF1, "EXC_RETURN: Handler mode");
    assert_eq!(s.hfsr, hfsr::FORCED);
    assert_eq!(
        s.shcsr & shcsr::SVCALLACT,
        shcsr::SVCALLACT,
        "SVCall stays active"
    );
}

#[test]
fn illegal_exc_return_takes_invpc() {
    // Handler: mvn lr,#10 (0xFFFFFFF5) ; bx lr
    let (mut vcpu, mem) = new_vcpu(&[0x07, 0xDF]);
    mem.write_slice(&[0x6F, 0xF0, 0x0A, 0x0E, 0x70, 0x47], GuestAddress(HANDLER))
        .unwrap();
    for _ in 0..3 {
        vcpu.step_insn().unwrap();
    }
    let (r, s) = state(&vcpu);
    // UsageFault is disabled at reset, so INVPC escalates to HardFault; no
    // new frame is stacked and LR holds the rejected EXC_RETURN.
    assert_eq!(r.xpsr & 0x1FF, 3);
    assert_eq!(s.cfsr, cfsr::INVPC);
    assert_eq!(s.hfsr, hfsr::FORCED);
    assert_eq!(r.lr, 0xFFFF_FFF5);
    assert_eq!(r.msp, STACK_TOP - 32);
}

#[test]
fn enabled_usage_fault_reports_division_by_zero() {
    let (mut vcpu, mem) = new_vcpu(&[0x91, 0xFB, 0xF2, 0xF0]); // sdiv r0,r1,r2
    edit(&mut vcpu, |r, s| {
        r.r[0] = 9;
        s.ccr = ccr::STKALIGN | ccr::DIV_0_TRP;
        s.shcsr = shcsr::USGFAULTENA;
    });
    assert!(vcpu.step_insn().unwrap().is_none());
    let (r, s) = state(&vcpu);
    assert_eq!(r.xpsr & 0x1FF, 6, "UsageFault itself, not HardFault");
    assert_eq!(s.cfsr, cfsr::DIVBYZERO);
    assert_eq!(s.hfsr, 0);
    assert_eq!(word(&mem, u64::from(r.msp)), 9, "R0 unchanged, stacked");
    assert_eq!(
        word(&mem, u64::from(r.msp) + 24),
        CODE as u32,
        "the faulting SDIV"
    );
    assert_eq!(vcpu.instruction_count(), 0);

    // Without DIV_0_TRP the quotient is 0.
    let (mut vcpu, _) = new_vcpu(&[0x91, 0xFB, 0xF2, 0xF0]);
    edit(&mut vcpu, |r, _| r.r[0] = 9);
    vcpu.step_insn().unwrap();
    assert_eq!(regs(&vcpu).r[0], 0);
}

#[test]
fn unaligned_trap_applies_to_word_loads() {
    let (mut vcpu, mem) = new_vcpu(&[0xD1, 0xF8, 0x01, 0x00]); // ldr.w r0,[r1,#1]
    mem.write_slice(&[0x11, 0x22, 0x33, 0x44, 0x55], GuestAddress(DATA))
        .unwrap();
    edit(&mut vcpu, |r, _| r.r[1] = DATA as u32);
    vcpu.step_insn().unwrap();
    assert_eq!(
        regs(&vcpu).r[0],
        0x5544_3322,
        "unaligned access is permitted"
    );

    let (mut vcpu, _) = new_vcpu(&[0xD1, 0xF8, 0x01, 0x00]);
    edit(&mut vcpu, |r, s| {
        r.r[1] = DATA as u32;
        s.ccr = ccr::STKALIGN | ccr::UNALIGN_TRP;
    });
    vcpu.step_insn().unwrap();
    let (r, s) = state(&vcpu);
    assert_eq!(
        (r.xpsr & 0x1FF, s.cfsr, s.hfsr),
        (3, cfsr::UNALIGNED, hfsr::FORCED)
    );
}

#[test]
fn a_fault_at_hardfault_priority_locks_up() {
    let (mut vcpu, mem) = new_vcpu(&[0x03, 0xBE]); // bkpt #3
    mem.write_slice(&[0x03, 0xBE], GuestAddress(HANDLER))
        .unwrap(); // bkpt in HardFault
    vcpu.step_insn().unwrap();
    let before = regs(&vcpu);
    match vcpu.step_insn() {
        Err(Error::Emulator(message)) => assert!(message.contains("lockup"), "{message}"),
        other => panic!("expected a lockup, got {other:?}"),
    }
    assert_eq!(regs(&vcpu).pc, before.pc, "the BKPT does not retire");
}

#[test]
fn memory_faults_and_undefined_instructions_return_to_the_embedder() {
    let (mut vcpu, _) = new_vcpu(&[0x08, 0x68]); // ldr r0,[r1]
    edit(&mut vcpu, |r, _| {
        r.r[0] = 7;
        r.r[1] = 0x8000;
    });
    match vcpu.step_insn() {
        Err(Error::GuestAccess(f)) => {
            assert_eq!(
                (f.kind, f.access, f.address),
                (MemoryFaultKind::Unmapped, MemoryAccessKind::Read, 0x8000)
            );
        }
        other => panic!("expected a fault, got {other:?}"),
    }
    assert_eq!((vcpu.current_pc(), regs(&vcpu).r[0]), (CODE, 7));

    // An SVC whose frame cannot be stacked does not retire either.
    let (mut vcpu, _) = new_vcpu(&[0x07, 0xDF]);
    edit(&mut vcpu, |r, _| r.msp = 0x8020);
    match vcpu.step_insn() {
        Err(Error::GuestAccess(f)) => assert_eq!(f.access, MemoryAccessKind::Write),
        other => panic!("expected a stacking fault, got {other:?}"),
    }
    let r = regs(&vcpu);
    assert_eq!((r.pc, r.msp, r.xpsr & 0x1FF), (CODE as u32, 0x8020, 0));
    assert_eq!(vcpu.instruction_count(), 0);

    // UDF, and a floating-point instruction (no FPU), are invalid
    // instructions at their own address.
    for code in [&[0x00, 0xDE][..], &[0x30, 0xEE, 0x81, 0x0A]] {
        let (mut vcpu, _) = new_vcpu(code);
        match vcpu.step_insn() {
            Err(Error::InvalidInstruction { pc, .. }) => assert_eq!(pc, CODE),
            other => panic!("expected an invalid instruction, got {other:?}"),
        }
        assert_eq!(vcpu.current_pc(), CODE);
    }
}

#[test]
fn wfi_waits_until_woken() {
    let (mut vcpu, _) = new_vcpu(&[0x30, 0xBF, 0x2A, 0x20]); // wfi ; movs r0,#42
    assert!(matches!(vcpu.run().unwrap(), VcpuExit::Hlt));
    assert!(matches!(vcpu.step_insn().unwrap(), Some(VcpuExit::Hlt)));
    assert_eq!(regs(&vcpu).r[0], 0);
    vcpu.wake();
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(regs(&vcpu).r[0], 42);
}

#[test]
fn state_round_trips_special_and_system_registers() {
    let (mut vcpu, _) = new_vcpu(&[]);
    edit(&mut vcpu, |r, s| {
        r.psp = 0x2F03;
        r.control = 0b111; // FPCA is RAZ/WI without an FPU
        r.primask = 1;
        r.basepri = 0x40;
        r.s[5] = 0x3F80_0000;
        s.vtor = 0x0000_0880;
        s.ccr = ccr::STKALIGN | ccr::DIV_0_TRP;
        s.shcsr = shcsr::USGFAULTENA;
        s.cfsr = cfsr::UNDEFINSTR;
        s.hfsr = hfsr::FORCED;
        s.aircr = 0x0000_0300;
    });
    let (r, s) = state(&vcpu);
    assert_eq!(r.psp, 0x2F00, "SP bits [1:0] read as zero");
    assert_eq!(r.control, 0b011);
    assert_eq!((r.primask, r.basepri), (1, 0x40));
    assert_eq!(r.s[5], 0, "no FP registers without an FPU");
    assert_eq!(s.vtor, 0x880);
    assert_eq!(s.ccr, ccr::STKALIGN | ccr::DIV_0_TRP);
    assert_eq!(s.shcsr, shcsr::USGFAULTENA);
    assert_eq!((s.cfsr, s.hfsr), (cfsr::UNDEFINSTR, hfsr::FORCED));
    assert_eq!(s.aircr, 0xFA05_0300, "VECTKEYSTAT and PRIGROUP");
}

#[test]
fn imported_handler_mode_can_return() {
    // A context in the SVCall handler with a frame on the main stack.
    let (mut vcpu, mem) = new_vcpu(&[0x70, 0x47]); // bx lr
    let frame = STACK_TOP - 32;
    for (i, value) in [1u32, 2, 3, 4, 12, 0xDEAD, HANDLER as u32, 0x0100_0000]
        .iter()
        .enumerate()
    {
        mem.write_slice(
            &value.to_le_bytes(),
            GuestAddress(u64::from(frame) + 4 * i as u64),
        )
        .unwrap();
    }
    edit(&mut vcpu, |r, _| {
        r.xpsr = 0x0100_000B;
        r.msp = frame;
        r.lr = 0xFFFF_FFF9;
    });
    vcpu.step_insn().unwrap();
    let r = regs(&vcpu);
    assert_eq!(
        (r.pc, r.xpsr & 0x1FF, r.msp),
        (HANDLER as u32, 0, STACK_TOP)
    );
    assert_eq!((r.r[0], r.r[3], r.r[12], r.lr), (1, 4, 12, 0xDEAD));
}
