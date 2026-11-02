//! Retirement frontiers through the actual S5L platform path.
use super::*;
use crate::vm::vcpu::RetirementStop;
const CODE: u32 = 0x1000;
fn fixture(words: &[u32]) -> S5L8900Vcpu {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000usize)]).unwrap());
    let bytes: Vec<_> = words.iter().flat_map(|v| v.to_le_bytes()).collect();
    mem.write_slice(&bytes, GuestAddress(u64::from(CODE)))
        .unwrap();
    let mut cpu = S5L8900Vcpu::new(0, mem);
    cpu.cpu.regs[15] = CODE;
    cpu.det_timer = 1;
    cpu.timer_mul = 1;
    cpu
}
#[test]
fn bounded_arm_thumb_steps_preserve_zero_budget_and_counter_wrap() {
    for thumb in [false, true] {
        let mut cpu = fixture(&[0xe320_f000; 4]);
        if thumb {
            cpu.bridge
                .mem
                .write_slice(
                    &[0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf],
                    GuestAddress(u64::from(CODE)),
                )
                .unwrap();
        }
        cpu.cpu.cpsr.t = thumb;
        cpu.insn_count = u64::MAX - 1;
        let zero = cpu.run_retirement_budget(0).unwrap();
        assert_eq!(zero.retired, 0);
        assert_eq!(cpu.timer_irq_clock, 0);
        assert_eq!(cpu.cpu.regs[15], CODE);
        assert!(cpu.supports_stepping());
        let run = cpu.run_retirement_budget(2).unwrap();
        assert_eq!(run.retired, 2);
        assert!(matches!(run.stop, RetirementStop::BudgetExhausted));
        assert_eq!(cpu.insn_count, 0);
        assert_eq!(cpu.cpu.regs[15], CODE + if thumb { 4 } else { 8 });
        assert_eq!(cpu.timer_irq_clock, 2);
    }
}
#[test]
fn executed_fp_access_faults_preserve_registers_and_retire_nothing() {
    let raw = 0xeea0_0a81u32; // VFMA.F32 S0,S1,S2; denied by CPACR.
    for thumb in [false, true] {
        let mut cpu = fixture(&[if thumb { raw.rotate_left(16) } else { raw }]);
        cpu.cpu.cpsr.t = thumb;
        cpu.cpu.cp15.cpacr = crate::isa::arm::cp15::Cpacr::from_bits(0);
        let before = (cpu.cpu.vfp.dregs, cpu.cpu.vfp.fpscr.bits());
        assert!(matches!(cpu.step(), StepOutcome::Progress));
        assert_eq!(cpu.cpu.regs[15], 4);
        assert_eq!((cpu.cpu.vfp.dregs, cpu.cpu.vfp.fpscr.bits()), before);
        assert_eq!(
            cpu.instruction_count(),
            0,
            "denied FP attempt was charged as completed"
        );
    }
}

#[test]
fn selected_synchronous_fp_traps_keep_fpexc_and_do_not_retire() {
    for thumb in [false, true] {
        let raw = 0xee810a02u32;
        let mut cpu = fixture(&[if thumb { raw.rotate_left(16) } else { raw }]);
        cpu.cpu.cpsr.t = thumb;
        cpu.cpu.vfp.mvfr0 |= 1 << 12;
        cpu.cpu.vfp.fpscr = crate::isa::arm::aarch32::vfp::Fpscr::from_bits(0x100);
        cpu.cpu.vfp.write_s_bits(0, 0xdeadbeef);
        let before = cpu.cpu.vfp.dregs;
        assert!(matches!(cpu.step(), StepOutcome::Progress));
        assert_eq!(cpu.cpu.regs[15], 4);
        assert_eq!(cpu.cpu.regs[14], CODE + if thumb { 2 } else { 4 });
        assert_eq!(cpu.cpu.vfp.dregs, before);
        assert_eq!(cpu.cpu.vfp.fpexc & 0x2400009f, 0x24000001);
        assert_eq!(cpu.instruction_count(), 0);
    }
}
#[test]
fn executed_data_abort_does_not_retire_the_faulting_load() {
    let mut cpu = fixture(&[0xe591_0000]); // LDR r0,[r1].
    cpu.cpu.regs[0] = 0x1234;
    cpu.cpu.regs[1] = 0x7000_0000;
    assert!(matches!(cpu.step(), StepOutcome::Progress));
    assert_eq!(cpu.cpu.regs[15], 0x10);
    assert_eq!(cpu.cpu.regs[0], 0x1234);
    assert_eq!(
        cpu.instruction_count(),
        0,
        "aborted load was charged as completed"
    );
}
#[test]
fn bounded_wfi_and_wake_stop_at_the_completed_instruction() {
    let mut cpu = fixture(&[0xe320_f003, 0xe3a0_002a, 0xe320_f003]);
    let first = cpu.run_retirement_budget(64).unwrap();
    assert_eq!(first.retired, 1);
    assert!(matches!(first.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    assert_eq!(cpu.cpu.regs[15], CODE + 4);
    let idle = cpu.run_retirement_budget(64).unwrap();
    assert_eq!(idle.retired, 0);
    assert!(matches!(idle.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    assert_eq!(cpu.cpu.regs[0], 0);
    cpu.wake();
    let resumed = cpu.run_retirement_budget(64).unwrap();
    assert_eq!(resumed.retired, 2);
    assert!(matches!(resumed.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    assert_eq!(cpu.cpu.regs[0], 42);
    assert_eq!(cpu.cpu.regs[15], CODE + 12);
}
#[test]
fn irq_entry_yields_before_the_handler_and_svc_completes_once() {
    let mut cpu = fixture(&[0xe320_f000]);
    cpu.bridge
        .mem
        .write_slice(&ARM_LDR_PC_PC_0X18.to_le_bytes(), GuestAddress(0x18))
        .unwrap();
    cpu.cpu.cpsr.i = false;
    {
        let mut i = cpu.bridge.inner.borrow_mut();
        i.vic0.write(0x10, 1 << 9);
        i.vic0.write(0x18, 1 << 9);
    }
    let irq = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(irq.retired, 0);
    assert!(matches!(irq.stop, RetirementStop::StateChange));
    assert_eq!(cpu.cpu.regs[15], 0x18);
    let mut svc = fixture(&[0xef00_0001]);
    let out = svc.run_retirement_budget(1).unwrap();
    assert_eq!(out.retired, 1);
    assert!(matches!(out.stop, RetirementStop::BudgetExhausted));
    assert_eq!(svc.cpu.regs[15], 8);
}
#[test]
fn shutdown_detected_during_the_attempt_is_returned_immediately() {
    let mut cpu = fixture(&[0]);
    cpu.derail_trace = true;
    cpu.zero_slide = 47;
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
    assert_eq!(cpu.instruction_count(), 0);
    assert_eq!(cpu.cpu.regs[15], CODE);
    let clock = cpu.timer_irq_clock;
    assert!(matches!(cpu.step_insn().unwrap(), Some(VcpuExit::Shutdown)));
    assert_eq!(cpu.timer_irq_clock, clock);
}
#[test]
fn platform_timer_is_reached_by_the_public_step_path() {
    let mut cpu = fixture(&[0xe591_0084]); // LDR r0,[r1,#0x84] (TICKSLOW).
    cpu.cpu.regs[1] = TIMER1_BASE;
    let out = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(out.retired, 1);
    assert!(matches!(out.stop, RetirementStop::BudgetExhausted));
    assert_eq!(cpu.cpu.regs[0], 1);
}

#[test]
fn fault_delivery_yields_before_any_handler_instruction() {
    for (word, fetch_fault, vector) in [
        (0xe7f0_00f0, false, 4),
        (0xe591_0000, false, 0x10),
        (0xeea0_0a81, false, 4),
        (0xe320_f000, true, 0x0c),
    ] {
        let mut cpu = fixture(&[word]);
        cpu.cpu.regs[0] = 0x1234;
        cpu.cpu.regs[1] = 0x7000_0000;
        cpu.cpu.cp15.cpacr = crate::isa::arm::cp15::Cpacr::from_bits(0);
        cpu.bridge
            .mem
            .write_slice(&0xe3a0_002au32.to_le_bytes(), GuestAddress(vector))
            .unwrap();
        if fetch_fault {
            cpu.cpu.regs[15] = 0x7000_0000;
        }
        let first = cpu.run_retirement_budget(1000).unwrap();
        assert_eq!(first.retired, 0, "word {word:#x}, fetch {fetch_fault}");
        assert!(matches!(first.stop, RetirementStop::StateChange));
        assert_eq!(cpu.cpu.regs[15], vector as u32);
        assert_eq!(cpu.cpu.regs[0], 0x1234);
        let handler = cpu.run_retirement_budget(1).unwrap();
        assert_eq!(handler.retired, 1);
        assert!(matches!(handler.stop, RetirementStop::BudgetExhausted));
        assert_eq!(cpu.cpu.regs[0], 42);
    }
}

#[test]
fn failed_fp_predicates_complete_without_access_or_fp_effects() {
    for thumb in [false, true] {
        let raw = 0xeea0_0a81u32;
        let mut cpu = fixture(&[if thumb {
            raw.rotate_left(16)
        } else {
            raw & 0x0fff_ffff
        }]);
        cpu.cpu.cpsr.t = thumb;
        cpu.cpu.cpsr.z = false;
        if thumb {
            cpu.cpu.cpsr.set_it_state(0, 8);
        }
        cpu.cpu.cp15.cpacr = crate::isa::arm::cp15::Cpacr::from_bits(0);
        let before = (cpu.cpu.vfp.dregs, cpu.cpu.vfp.fpscr.bits());
        let run = cpu.run_retirement_budget(1).unwrap();
        assert_eq!(run.retired, 1);
        assert!(matches!(run.stop, RetirementStop::BudgetExhausted));
        assert_eq!(cpu.cpu.regs[15], CODE + 4);
        assert!(!cpu.cpu.cpsr.in_it_block());
        assert_eq!((cpu.cpu.vfp.dregs, cpu.cpu.vfp.fpscr.bits()), before);
    }
}
