use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::RetirementStop;
use vm_memory::Bytes;

const ENTRY: u64 = 0x100;
const HANDLER: u64 = 0x1200;

fn machine(micro: bool) -> (Aarch64Vcpu, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    mem.write_slice(&0x1e22_2820u32.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap();
    mem.write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(HANDLER))
        .unwrap(); // ADD X9,X9,#1
    let mut cpu = if micro {
        Aarch64Vcpu::new_micro(0, mem.clone())
    } else {
        Aarch64Vcpu::new(0, mem.clone())
    };
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = ENTRY;
    state.regs.pstate = 5;
    state.sregs.vbar_el1 = 0x1000;
    let sys = &mut state.sregs.execution.as_mut().unwrap().sysregs;
    sys.el1.vbar = 0x1000;
    sys.el1.cpacr = 0;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    (cpu, mem)
}

#[test]
fn fp_exception_returns_to_scheduler_without_spending_budget_or_virtual_time() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _binding = clock.enter();
    let (mut cpu, _) = machine(false);
    assert_eq!(cpu.run_retirement_budget(0).unwrap().retired, 0);
    assert_eq!(cpu.current_pc(), ENTRY);
    let result = cpu.run_retirement_budget(1000).unwrap();
    assert_eq!(result.retired, 0);
    assert!(matches!(result.stop, RetirementStop::StateChange));
    assert_eq!(cpu.current_pc(), HANDLER);
    assert_eq!(cpu.instruction_count(), 0);
    assert_eq!(clock.checkpoint_state().retired_units, 0);
    assert_eq!(cpu.cpu.get_gpr(9), 0, "handler has not executed");
    let result = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 1);
    assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
    assert_eq!(cpu.cpu.get_gpr(9), 1);
    assert_eq!(clock.checkpoint_state().retired_units, 1);
}

#[test]
fn diagnostic_fp_fault_preserves_retry_pc_and_retries_once_when_enabled() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _binding = clock.enter();
    let (mut cpu, _) = machine(true);
    let result = cpu.run_retirement_budget(1).unwrap();
    assert!(matches!(result.stop, RetirementStop::Fault(_)));
    assert_eq!(result.retired, 0);
    assert_eq!(cpu.current_pc(), ENTRY);
    assert_eq!(cpu.instruction_count(), 0);
    assert_eq!(clock.checkpoint_state().retired_units, 0);
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.sregs.execution.as_mut().unwrap().sysregs.el1.cpacr = 3 << 20;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
    assert_eq!(cpu.current_pc(), ENTRY + 4);
    assert_eq!(clock.checkpoint_state().retired_units, 1);
}

#[test]
fn checkpoint_before_and_after_fp_delivery_preserves_exact_handler_frontier() {
    for delivered in [false, true] {
        let (mut source, mem) = machine(false);
        if delivered {
            assert_eq!(source.run_retirement_budget(1).unwrap().retired, 0);
        }
        let state = source.get_state().unwrap();
        let raw = source.capture_backend_context().unwrap().unwrap();
        assert!(raw.data.starts_with(b"RAXA6402"));
        let mut target = Aarch64Vcpu::new(0, mem);
        target
            .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
            .unwrap();
        if !delivered {
            let result = target.run_retirement_budget(1000).unwrap();
            assert!(matches!(result.stop, RetirementStop::StateChange));
            assert_eq!(result.retired, 0);
        }
        assert_eq!(target.current_pc(), HANDLER);
        assert_eq!(target.instruction_count(), 0);
        assert_eq!(target.run_retirement_budget(1).unwrap().retired, 1);
        assert_eq!(target.cpu.get_gpr(9), 1);
    }
}
