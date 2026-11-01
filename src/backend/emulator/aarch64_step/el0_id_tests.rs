//! Both system and diagnostic adapters preserve the EL0 fault frontier.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::RetirementStop;
use vm_memory::Bytes;

const ENTRY: u64 = 0x100;
const HANDLER: u64 = 0x1400;
fn machine(word: u32, diagnostic: bool) -> (Aarch64Vcpu, Arc<GuestMemoryMmap>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    memory
        .write_slice(&word.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap();
    memory
        .write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(HANDLER))
        .unwrap();
    let mut cpu = if diagnostic {
        Aarch64Vcpu::new_micro(0, memory.clone())
    } else {
        Aarch64Vcpu::new(0, memory.clone())
    };
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = ENTRY;
    state.regs.pstate = 0;
    state.regs.x[0] = 123;
    state.sregs.vbar_el1 = 0x1000;
    state.sregs.execution.as_mut().unwrap().sysregs.el1.vbar = 0x1000;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    (cpu, memory)
}

#[test]
fn el0_id_and_privilege_faults_deliver_or_diagnose_without_retirement() {
    for word in [
        0xd538_0000,
        0xd538_00a0,
        0xd538_0300,
        0xd538_0400,
        0xd538_1000,
    ] {
        for diagnostic in [false, true] {
            let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
            let _binding = clock.enter();
            let (mut cpu, _) = machine(word, diagnostic);
            let outcome = cpu.run_retirement_budget(1).unwrap();
            assert_eq!(
                (
                    outcome.retired,
                    cpu.instruction_count(),
                    clock.checkpoint_state().retired_units
                ),
                (0, 0, 0)
            );
            let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(state.regs.x[0], 123);
            if diagnostic {
                assert!(matches!(
                    outcome.stop,
                    RetirementStop::Fault(Error::InvalidInstruction { pc: ENTRY, .. })
                ));
                assert_eq!(state.regs.pc, ENTRY);
            } else {
                assert!(matches!(outcome.stop, RetirementStop::StateChange));
                assert_eq!(
                    (state.regs.pc, state.sregs.elr_el1, state.sregs.esr_el1),
                    (HANDLER, ENTRY, 1 << 25)
                );
                assert_eq!(state.sregs.spsr_el1 & 31, 0);
                assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
                assert_eq!(cpu.current_pc(), HANDLER + 4);
            }
        }
    }
}

#[test]
fn el0_id_fault_context_roundtrips_before_and_after_guest_delivery() {
    for attempted in [false, true] {
        let (mut source, memory) = machine(0xd538_0000, false);
        if attempted {
            assert_eq!(source.run_retirement_budget(1).unwrap().retired, 0);
        }
        let public = source.get_state().unwrap();
        let emulator = source.get_emulator_state().unwrap_or_default();
        let context = source.capture_backend_context().unwrap();
        let mut restored = Aarch64Vcpu::new(0, memory);
        restored
            .restore_checkpoint_context(&public, &emulator, context.as_ref())
            .unwrap();
        if !attempted {
            assert_eq!(restored.run_retirement_budget(1).unwrap().retired, 0);
        }
        assert_eq!(restored.current_pc(), HANDLER);
        assert_eq!(restored.instruction_count(), 0);
        assert_eq!(restored.run_retirement_budget(1).unwrap().retired, 1);
        let CpuState::Aarch64(state) = restored.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(
            (state.regs.x[0], state.regs.x[9], state.regs.pc),
            (123, 1, HANDLER + 4)
        );
    }
}
