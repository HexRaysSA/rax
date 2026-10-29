//! Architectural and diagnostic Undefined transitions conserve retirement.
use super::*;
use crate::isa::arm::common::features::ArmFeatures;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::RetirementStop;
use vm_memory::Bytes;

const ENTRY: u64 = 0x100;
const HANDLER: u64 = 0x1200;

fn features() -> u64 {
    (ArmFeatures::FP16
        | ArmFeatures::FHM
        | ArmFeatures::JSCVT
        | ArmFeatures::FCMA
        | ArmFeatures::FRINTTS
        | ArmFeatures::BF16
        | ArmFeatures::I8MM
        | ArmFeatures::DOTPROD)
        .bits()
}

fn words() -> Vec<u32> {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-undefined-retirement/corpus.json"
    )))
    .unwrap();
    corpus["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["word"].as_u64().unwrap() as u32)
        .collect()
}

fn machine(word: u32, micro: bool) -> (Aarch64Vcpu, Arc<GuestMemoryMmap>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    memory
        .write_slice(&word.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap();
    memory
        .write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(HANDLER))
        .unwrap();
    let mut cpu = if micro {
        Aarch64Vcpu::new_micro(0, memory.clone())
    } else {
        Aarch64Vcpu::new(0, memory.clone())
    };
    cpu.set_aarch64_fp_features(features()).unwrap();
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = ENTRY;
    state.regs.pstate = 5 | (2 << 10);
    state.regs.x[0] = 0xfeed;
    state.sregs.vbar_el1 = 0x1000;
    let system = &mut state.sregs.execution.as_mut().unwrap().sysregs;
    system.el1.vbar = 0x1000;
    system.el1.cpacr = 3 << 20;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    (cpu, memory)
}

#[test]
fn undefined_backend_boundaries_preserve_all_62_fault_pcs_and_retired_clock() {
    for word in words() {
        for micro in [false, true] {
            let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
            let _binding = clock.enter();
            let (mut cpu, memory) = machine(word, micro);
            assert_eq!(cpu.run_retirement_budget(0).unwrap().retired, 0);
            assert_eq!(cpu.current_pc(), ENTRY);
            let result = cpu.run_retirement_budget(1000).unwrap();
            assert_eq!(result.retired, 0, "{word:08x}");
            assert_eq!(cpu.instruction_count(), 0);
            assert_eq!(clock.checkpoint_state().retired_units, 0);
            let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!((state.regs.x[0], state.regs.x[9]), (0xfeed, 0));
            if micro {
                assert!(matches!(
                    result.stop,
                    RetirementStop::Fault(Error::InvalidInstruction { pc: ENTRY, .. })
                ));
                assert_eq!(cpu.current_pc(), ENTRY);
                assert_eq!((state.regs.pstate >> 10) & 3, 2);
                memory
                    .write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(ENTRY))
                    .unwrap();
            } else {
                assert!(matches!(result.stop, RetirementStop::StateChange));
                assert_eq!(cpu.current_pc(), HANDLER);
                let system = &state.sregs.execution.as_ref().unwrap().sysregs;
                assert_eq!((system.el1.elr, system.el1.esr), (ENTRY, 1 << 25));
                assert_eq!((system.el1.spsr >> 10) & 3, 2);
            }
            let result = cpu.run_retirement_budget(1).unwrap();
            assert_eq!(result.retired, 1);
            assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
            assert_eq!(cpu.instruction_count(), 1);
            assert_eq!(
                cpu.current_pc(),
                if micro { ENTRY + 4 } else { HANDLER + 4 }
            );
            assert_eq!(clock.checkpoint_state().retired_units, 1);
        }
    }
}

#[test]
fn undefined_private_context_preserves_before_and_after_delivery_frontiers() {
    for word in [0xce02_9420, 0x3e3e_0820, 0x4e29_6820] {
        for micro in [false, true] {
            for attempted in [false, true] {
                let (mut source, memory) = machine(word, micro);
                if attempted {
                    assert_eq!(source.run_retirement_budget(1).unwrap().retired, 0);
                }
                let state = source.get_state().unwrap();
                let raw = source.capture_backend_context().unwrap().unwrap();
                let mut target = if micro {
                    Aarch64Vcpu::new_micro(0, memory.clone())
                } else {
                    Aarch64Vcpu::new(0, memory.clone())
                };
                target
                    .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
                    .unwrap();
                assert_eq!(target.instruction_count(), 0);
                if micro || !attempted {
                    let result = target.run_retirement_budget(1000).unwrap();
                    assert_eq!(result.retired, 0);
                    if micro {
                        assert!(matches!(
                            result.stop,
                            RetirementStop::Fault(Error::InvalidInstruction { pc: ENTRY, .. })
                        ));
                    } else {
                        assert!(matches!(result.stop, RetirementStop::StateChange));
                    }
                }
                if micro {
                    assert_eq!(target.current_pc(), ENTRY);
                    memory
                        .write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(ENTRY))
                        .unwrap();
                } else {
                    assert_eq!(target.current_pc(), HANDLER);
                }
                assert_eq!(target.run_retirement_budget(1).unwrap().retired, 1);
                let CpuState::Aarch64(state) = target.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!((target.instruction_count(), state.regs.x[9]), (1, 1));
            }
        }
    }
}
