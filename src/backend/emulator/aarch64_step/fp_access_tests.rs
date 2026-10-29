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
    for instruction in [
        0x1e22_2820u32,
        0xd53b_4400,
        0xd53b_4420,
        0xd51b_4400,
        0xd51b_4420,
    ] {
        for delivered in [false, true] {
            let (mut source, mem) = machine(false);
            mem.write_slice(&instruction.to_le_bytes(), GuestAddress(ENTRY))
                .unwrap();
            if delivered {
                assert_eq!(source.run_retirement_budget(1).unwrap().retired, 0);
            }
            let state = source.get_state().unwrap();
            let raw = source.capture_backend_context().unwrap().unwrap();
            assert!(raw.data.starts_with(b"RAXA6403"));
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
}

#[test]
fn fp_sysreg_higher_trap_controls_survive_private_checkpoint_and_retirement_boundary() {
    let (mut source, mem) = machine(false);
    mem.write_slice(&0xd53b_4400u32.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap();
    mem.write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(0x2400))
        .unwrap();
    let CpuState::Aarch64(mut state) = source.get_state().unwrap() else {
        panic!()
    };
    let sys = &mut state.sregs.execution.as_mut().unwrap().sysregs;
    sys.scr_el3 = 0x501;
    sys.hcr_el2 = 1 << 31;
    sys.el1.cpacr = 3 << 20;
    sys.el2.vbar = 0x2000;
    sys.impl_defined.insert(
        crate::isa::arm::common::sysreg::Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(),
        1 << 10,
    );
    source.set_state(&CpuState::Aarch64(state)).unwrap();
    let state = source.get_state().unwrap();
    let raw = source.capture_backend_context().unwrap().unwrap();
    let mut target = Aarch64Vcpu::new(0, mem);
    target
        .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
        .unwrap();
    let result = target.run_retirement_budget(1000).unwrap();
    assert!(matches!(result.stop, RetirementStop::StateChange));
    assert_eq!((result.retired, target.current_pc()), (0, 0x2400));
    let CpuState::Aarch64(state) = target.get_state().unwrap() else {
        panic!()
    };
    let sys = &state.sregs.execution.as_ref().unwrap().sysregs;
    assert_eq!((sys.el2.elr, sys.el2.esr >> 26), (ENTRY, 7));
    assert_eq!(target.run_retirement_budget(1).unwrap().retired, 1);
    assert_eq!(target.cpu.get_gpr(9), 1);
}

#[test]
fn fp16_admission_checkpoint_retains_undefined_fault_and_zero_retirement() {
    use crate::isa::arm::common::features::ArmFeatures;
    for delivered in [false, true] {
        let (mut source, mem) = machine(false);
        mem.write_slice(&0x1ee2_2820u32.to_le_bytes(), GuestAddress(ENTRY))
            .unwrap();
        let CpuState::Aarch64(mut state) = source.get_state().unwrap() else {
            panic!()
        };
        let execution = state.sregs.execution.as_mut().unwrap();
        execution.features &= !(ArmFeatures::FP16 | ArmFeatures::FHM).bits();
        execution.sysregs.el1.cpacr = 3 << 20;
        state.regs.v[1][0] = 0x3c00;
        state.regs.v[2][0] = 0x3c00;
        source.set_state(&CpuState::Aarch64(state)).unwrap();
        if delivered {
            let result = source.run_retirement_budget(1).unwrap();
            assert_eq!(result.retired, 0);
            assert!(matches!(result.stop, RetirementStop::StateChange));
        }
        let state = source.get_state().unwrap();
        let private = source.capture_backend_context().unwrap().unwrap();
        assert!(private.data.starts_with(b"RAXA6403"));
        let mut target = Aarch64Vcpu::new(0, mem);
        target
            .restore_checkpoint_context(&state, &Default::default(), Some(&private))
            .unwrap();
        if !delivered {
            let result = target.run_retirement_budget(1).unwrap();
            assert_eq!(result.retired, 0);
            assert!(matches!(result.stop, RetirementStop::StateChange));
        }
        assert_eq!(
            (target.current_pc(), target.instruction_count()),
            (HANDLER, 0)
        );
        let CpuState::Aarch64(after) = target.get_state().unwrap() else {
            panic!()
        };
        let execution = after.sregs.execution.as_ref().unwrap();
        assert_eq!(execution.features & ArmFeatures::FP16.bits(), 0);
        assert_eq!(execution.sysregs.el1.esr >> 26, 0);
        assert_eq!(execution.sysregs.el1.elr, ENTRY);
        assert_eq!(after.regs.v[0][0], 0);
        assert_eq!(target.run_retirement_budget(1).unwrap().retired, 1);
        assert_eq!(target.cpu.get_gpr(9), 1);
    }
}
