//! Actual software entry, retirement clocks and private vector-mode continuations.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::RetirementStop;
fn fixture(thumb: bool) -> (Aarch32Vcpu, Arc<GuestMemoryMmap>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let mut cpu = Aarch32Vcpu::new(0, memory.clone());
    cpu.cpu.vfp.mvfr0 |= 1 << 24;
    cpu.cpu.vfp.fpscr = Fpscr::from_bits(7 << 16);
    cpu.cpu.cpsr.t = thumb;
    cpu.cpu.regs[15] = 0x100;
    for i in 0..8 {
        cpu.cpu.vfp.write_s(16 + i, (i + 1) as f32);
        cpu.cpu.vfp.write_s(24 + i, 10.0 * (i + 1) as f32);
    }
    let add = 0xee384a0cu32;
    let bytes = if thumb {
        [
            ((add >> 16) as u16).to_le_bytes(),
            (add as u16).to_le_bytes(),
        ]
        .concat()
    } else {
        add.to_le_bytes().to_vec()
    };
    memory.write_slice(&bytes, GuestAddress(0x100)).unwrap();
    let wfi = if thumb {
        0xbf30u16.to_le_bytes().to_vec()
    } else {
        0xe320f003u32.to_le_bytes().to_vec()
    };
    memory.write_slice(&wfi, GuestAddress(0x104)).unwrap();
    (cpu, memory)
}
#[test]
fn eight_vector_elements_retire_once_and_private_boundaries_resume_identically() {
    for thumb in [false, true] {
        for completed in [false, true] {
            let (mut source, memory) = fixture(thumb);
            let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
            if completed {
                let _guard = clock.enter();
                let run = source.run_retirement_budget(1).unwrap();
                assert_eq!(run.retired, 1);
                assert!(matches!(run.stop, RetirementStop::BudgetExhausted));
            }
            let public = source.get_state().unwrap();
            let private = source.capture_backend_context().unwrap();
            let mut restored = Aarch32Vcpu::new(0, memory);
            restored
                .restore_checkpoint_context(
                    &public,
                    &source.get_emulator_state().unwrap_or_default(),
                    private.as_ref(),
                )
                .unwrap();
            assert_eq!(
                source.save_context().unwrap(),
                restored.save_context().unwrap()
            );
            if !completed {
                for cpu in [&mut source, &mut restored] {
                    let _guard = clock.enter();
                    let run = cpu.run_retirement_budget(1).unwrap();
                    assert_eq!(run.retired, 1);
                    assert!(matches!(run.stop, RetirementStop::BudgetExhausted));
                }
            }
            for cpu in [&mut source, &mut restored] {
                assert_eq!(cpu.instruction_count(), 1);
                assert_eq!(cpu.current_pc(), 0x104);
                for i in 0..8 {
                    assert_eq!(cpu.cpu.vfp.read_s(8 + i), (i + 1) as f32 * 11.0);
                }
                assert_eq!(cpu.cpu.vfp.fpscr.bits(), 7 << 16);
                let _guard = clock.enter();
                let run = cpu.run_retirement_budget(1).unwrap();
                assert_eq!(run.retired, 1);
                assert!(matches!(run.stop, RetirementStop::Exit(VcpuExit::Hlt)));
            }
            assert_eq!(
                source.save_context().unwrap(),
                restored.save_context().unwrap()
            );
            assert_eq!(
                clock.checkpoint_state().retired_units,
                if completed { 3 } else { 4 }
            );
        }
    }
}
#[test]
fn invalid_vector_diagnostic_keeps_fp_pc_and_retirement_frontier() {
    for thumb in [false, true] {
        let (mut cpu, _) = fixture(thumb);
        cpu.cpu.vfp.fpscr = Fpscr::from_bits(0x00370000);
        let before = cpu.cpu.vfp.dregs;
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _guard = clock.enter();
        let run = cpu.run_retirement_budget(8).unwrap();
        assert_eq!(run.retired, 0);
        assert!(matches!(run.stop, RetirementStop::Fault(_)));
        assert_eq!(cpu.current_pc(), 0x100);
        assert_eq!(cpu.instruction_count(), 0);
        assert_eq!(clock.checkpoint_state().retired_units, 0);
        assert_eq!(cpu.cpu.vfp.dregs, before);
        let bytes = cpu.save_context().unwrap();
        cpu.restore_context(&bytes).unwrap();
        assert_eq!(cpu.save_context().unwrap(), bytes);
    }
}
