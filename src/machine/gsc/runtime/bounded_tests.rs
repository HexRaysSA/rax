//! Actual guest effects through the production one-instruction entry.
use super::*;
use crate::vm::vcpu::RetirementStop;

const CODE: u64 = 0x1000;
fn fixture(words: &[u32]) -> GscVcpu {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000usize)]).unwrap());
    for (i, word) in words.iter().enumerate() {
        mem.write_slice(&word.to_le_bytes(), GuestAddress(CODE + 4 * i as u64))
            .unwrap();
    }
    let mut cpu = GscVcpu::new(0, mem);
    let mut registers = RiscVRegisters::default();
    registers.pc = CODE;
    cpu.set_state(&CpuState::riscv(registers)).unwrap();
    cpu
}

#[test]
fn bounded_entry_publishes_timer_and_pc_before_guest_mmio() {
    // 24 ADDI x0,x0,0; LW a0,0(a1). The modeled timer divides instret by 24.
    let mut words = vec![0x0000_0013; TIMER_DEFAULT_DIV as usize];
    words.push(0x0005_a503);
    let mut cpu = fixture(&words);
    assert_eq!(cpu.cfg.timer_div, TIMER_DEFAULT_DIV);
    cpu.cpu.set_x(11, TIMER_COUNT_LO);
    let outcome = cpu.run_retirement_budget(TIMER_DEFAULT_DIV + 1).unwrap();
    assert_eq!(outcome.retired, TIMER_DEFAULT_DIV + 1);
    assert!(matches!(outcome.stop, RetirementStop::BudgetExhausted));
    assert_eq!(cpu.cpu.x(10), 1, "bounded GSC timer remained frozen");
    assert_eq!(
        cpu.pc_cell.load(Ordering::Relaxed),
        CODE + 4 * TIMER_DEFAULT_DIV
    );
    assert_eq!(cpu.time_cell.load(Ordering::Relaxed), TIMER_DEFAULT_DIV);
}

#[test]
fn bounded_entry_delivers_an_armed_uart_interrupt_before_retirement() {
    let mut cpu = fixture(&[0x0000_0013]);
    {
        let mut shared = cpu.shared.lock().unwrap();
        shared.uart_rx.push_back(b'Q');
        shared.uart_irq_armed = true;
    }
    cpu.cpu.csr_write(0x305, 0x1100).unwrap();
    cpu.cpu.csr_write(0x304, MIP_MEIP).unwrap();
    cpu.cpu.csr_write(0x300, 8).unwrap();
    let outcome = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(outcome.retired, 0, "GSC skipped the pending platform IRQ");
    assert!(matches!(outcome.stop, RetirementStop::StateChange));
    assert_eq!(cpu.cpu.pc(), 0x1100);
    assert_eq!(cpu.cpu.csr_read(0x342).unwrap(), 0x8000_000b);
    assert_eq!(cpu.cpu.csr_read(0x341).unwrap(), CODE);
}

#[test]
fn bounded_wfi_arms_the_seeded_uart_for_the_following_entry() {
    let mut cpu = fixture(&[0x1050_0073, 0x0000_0013]);
    cpu.shared.lock().unwrap().uart_rx.push_back(b'R');
    let first = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(first.retired, 1);
    assert!(
        cpu.shared.lock().unwrap().uart_irq_armed,
        "WFI omitted UART arming"
    );
    let second = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(second.retired, 1);
    assert_ne!(cpu.cpu.csr_read(0x344).unwrap() & MIP_MEIP, 0);
}

#[test]
fn bounded_reset_store_reboots_without_losing_scheduler_retirement() {
    // LUI a0,0x40000; LUI a1,0x07041; ADDI a1,a1,0x776; SW a1,8(a0).
    let mut cpu = fixture(&[0x4000_0537, 0x0704_15b7, 0x7765_8593, 0x00b5_2423]);
    let outcome = cpu.run_retirement_budget(4).unwrap();
    assert_eq!(outcome.retired, 4);
    assert!(matches!(outcome.stop, RetirementStop::BudgetExhausted));
    assert_eq!(
        cpu.reset_count, 1,
        "bounded entry did not drain the warm reset"
    );
    assert_eq!(cpu.current_pc(), CODE);
    assert_eq!(
        cpu.cpu.instret(),
        4,
        "modeled diagnostic counter survives warm reset"
    );
    assert_eq!(
        cpu.instruction_count(),
        4,
        "scheduler retirement survives reset"
    );
    assert_eq!(cpu.shared.lock().unwrap().rstsrc, cpu.cfg.rstsrc_warm);
}

#[test]
fn bounded_entropy_hook_yields_without_executing_the_replacement_pc() {
    let mut cpu = fixture(&[0x0010_0073]);
    cpu.cpu.set_pc(TPM_RAND_GENERATE);
    cpu.cpu.set_x(1, CODE);
    cpu.cpu.set_x(11, 0x2000);
    cpu.cpu.set_x(12, 8);
    let mut before = [0; 8];
    cpu.cpu.read_memory(0x2000, &mut before).unwrap();
    let outcome = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(outcome.retired, 0);
    assert!(
        matches!(outcome.stop, RetirementStop::StateChange),
        "{outcome:?}"
    );
    assert_eq!(cpu.current_pc(), CODE);
    assert_eq!(cpu.cpu.x(10), 8);
    let mut after = [0; 8];
    cpu.cpu.read_memory(0x2000, &mut after).unwrap();
    assert_ne!(after, before);
    assert!(matches!(cpu.step_insn().unwrap(), Some(VcpuExit::Debug)));
}

#[test]
fn zero_budget_does_not_run_gsc_hooks_or_consume_an_armed_interrupt() {
    let mut cpu = fixture(&[0x0000_0013]);
    cpu.cpu.set_pc(TPM_RAND_GENERATE);
    cpu.cpu.set_x(1, CODE);
    cpu.cpu.set_x(11, 0x2000);
    cpu.cpu.set_x(12, 8);
    cpu.shared.lock().unwrap().uart_irq_armed = true;
    cpu.shared.lock().unwrap().uart_rx.push_back(b'Z');
    let old_entropy = cpu.entropy_state;
    let outcome = cpu.run_retirement_budget(0).unwrap();
    assert_eq!(outcome.retired, 0);
    assert!(matches!(outcome.stop, RetirementStop::BudgetExhausted));
    assert_eq!(cpu.current_pc(), TPM_RAND_GENERATE);
    assert_eq!(cpu.entropy_state, old_entropy);
    assert_eq!(cpu.time_cell.load(Ordering::Relaxed), 0);
    assert_eq!(cpu.shared.lock().unwrap().uart_rx.front(), Some(&b'Z'));
}

#[test]
fn timer_irq_delivery_and_source_deassertion_are_entry_synchronized() {
    let mut cpu = fixture(&[0x0000_0013, 0x0000_0013]);
    cpu.shared.lock().unwrap().timer_compare = 0;
    cpu.cpu.csr_write(0x305, 0x1100).unwrap();
    cpu.cpu.csr_write(0x304, MIP_MTIP).unwrap();
    cpu.cpu.csr_write(0x300, 8).unwrap();
    let outcome = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(outcome.retired, 0);
    assert!(matches!(outcome.stop, RetirementStop::StateChange));
    assert_eq!(cpu.cpu.csr_read(0x342).unwrap(), 0x8000_0007);
    assert_eq!(cpu.cpu.pc(), 0x1100);

    // Deassert both platform sources before executing the next ordinary NOP.
    cpu.cpu.set_pc(CODE);
    cpu.cpu.csr_write(0x300, 0).unwrap();
    cpu.cpu.set_interrupt_pending(MIP_MEIP, true);
    cpu.shared.lock().unwrap().timer_compare = u64::MAX;
    assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
    assert_eq!(cpu.cpu.csr_read(0x344).unwrap() & (MIP_MEIP | MIP_MTIP), 0);
}

#[test]
fn counter_wrap_charges_each_completed_nop_once() {
    let mut cpu = fixture(&[0x0000_0013, 0x0000_0013]);
    cpu.cpu.import_csrs(&[(0xc02, u64::MAX)]);
    let outcome = cpu.run_retirement_budget(2).unwrap();
    assert_eq!(outcome.retired, 2);
    assert!(matches!(outcome.stop, RetirementStop::BudgetExhausted));
    assert_eq!(cpu.cpu.instret(), 1);
    assert_eq!(cpu.instruction_count(), 1);
}

#[test]
fn bounded_warm_reset_guard_conserves_every_store_before_terminal_exit() {
    let mut cpu = fixture(&[0x4000_0537, 0x0704_15b7, 0x7765_8593, 0x00b5_2423]);
    let outcome = cpu.run_retirement_budget(1000).unwrap();
    let expected = u64::from(MAX_RESETS + 1) * 4;
    assert_eq!(outcome.retired, expected);
    assert_eq!(cpu.instruction_count(), expected);
    assert_eq!(cpu.reset_count, MAX_RESETS + 1);
    assert!(
        matches!(outcome.stop, RetirementStop::Exit(VcpuExit::Unknown(ref s))
        if s.contains("reboot loop"))
    );
    let stopped = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(stopped.retired, 0);
    assert!(matches!(stopped.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    assert_eq!(cpu.instruction_count(), expected);
}

#[test]
fn run_and_budget_preserve_the_same_uart_vendor_and_retirement_effects() {
    let words = [
        0x404d_0537,
        0x04f0_0593,
        0x00b5_2223,
        0x04b0_0593,
        0x00b5_2223,
        0x0070_0613,
        0x0006_368b,
        0x0306_8693,
        0x00d5_2223,
        0x0010_0073,
    ];
    let mut full = fixture(&words);
    let mut bounded = fixture(&words);
    assert!(matches!(full.run().unwrap(), VcpuExit::Debug));
    let outcome = bounded.run_retirement_budget(1000).unwrap();
    assert!(matches!(
        outcome.stop,
        RetirementStop::Exit(VcpuExit::Debug)
    ));
    assert_eq!(outcome.retired, 9);
    assert_eq!(full.instruction_count(), 9);
    assert_eq!(bounded.instruction_count(), 9);
    assert_eq!(full.console(), b"OK3");
    assert_eq!(bounded.console(), b"OK3");
    assert_eq!(
        crate::codec::serialize(&full.get_state().unwrap()).unwrap(),
        crate::codec::serialize(&bounded.get_state().unwrap()).unwrap()
    );
}

#[test]
fn platform_reset_event_yields_before_any_guest_instruction() {
    let mut cpu = fixture(&[0x0000_0013, 0x0000_0013]);
    cpu.plt_rst_event = true;
    cpu.tpm_trigger = CODE + 4;
    cpu.cpu.set_pc(CODE + 4);
    cpu.shared
        .lock()
        .unwrap()
        .console
        .extend_from_slice(b"TPM SPI dis");
    let outcome = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(outcome.retired, 0);
    assert!(matches!(outcome.stop, RetirementStop::StateChange));
    assert!(cpu.plt_rst_fired);
    assert_eq!(cpu.reset_count, 1);
    assert_eq!(cpu.current_pc(), CODE);
    let shared = cpu.shared.lock().unwrap();
    assert!(!shared.reset_requested);
    assert_ne!(shared.store[&GPIO_INPUT_BANK0] & GPIO_PLT_RST_L_MASK, 0);
}

#[test]
fn host_break_stop_has_no_retirement_and_blocks_the_following_entry() {
    let mut cpu = fixture(&[0x0000_0013]);
    cpu.break_pc = Some(CODE);
    cpu.break_stop = true;
    let outcome = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(outcome.retired, 0);
    assert!(
        matches!(outcome.stop, RetirementStop::Exit(VcpuExit::Unknown(ref s))
        if s.contains("breakpoint stop"))
    );
    assert!(cpu.broke);
    assert_eq!(cpu.current_pc(), CODE);
    assert!(matches!(cpu.step_insn().unwrap(), Some(VcpuExit::Hlt)));
}

#[test]
fn disabled_entropy_hook_executes_the_actual_guest_instruction() {
    let mut cpu = fixture(&[0x0000_0013]);
    cpu.entropy_hooks = false;
    cpu.cpu
        .write_memory(TPM_RAND_GENERATE, &0x0000_0013u32.to_le_bytes())
        .unwrap();
    cpu.cpu.set_pc(TPM_RAND_GENERATE);
    cpu.cpu.set_x(1, CODE);
    cpu.cpu.set_x(11, 0x2000);
    cpu.cpu.set_x(12, 8);
    let old_entropy = cpu.entropy_state;
    let outcome = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(outcome.retired, 1);
    assert!(matches!(outcome.stop, RetirementStop::BudgetExhausted));
    assert_eq!(cpu.current_pc(), TPM_RAND_GENERATE + 4);
    assert_eq!(cpu.entropy_state, old_entropy);
}
