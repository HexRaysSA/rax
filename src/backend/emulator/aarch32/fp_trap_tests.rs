//! Local Undefined entry and complete private-state retry through the embedder.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::RetirementStop;

#[test]
fn synchronous_fp_trap_is_zero_retirement_and_private_restore_retries_precisely() {
    for thumb in [false, true] {
        for delivered in [false, true] {
            let memory =
                Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
            let mut source = Aarch32Vcpu::new(0, memory.clone());
            source.cpu.regs[15] = 0x100;
            source.cpu.cpsr.t = thumb;
            source.cpu.vfp.mvfr0 |= 1 << 12;
            source.cpu.vfp.fpscr = Fpscr::from_bits(0x100);
            source.cpu.vfp.write_s_bits(0, 0xdeadbeef);
            let raw = 0xee810a02u32;
            memory
                .write_slice(
                    &if thumb { raw.rotate_left(16) } else { raw }.to_le_bytes(),
                    GuestAddress(0x100),
                )
                .unwrap();
            let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
            let binding = clock.enter();
            if delivered {
                let result = source.run_retirement_budget(1).unwrap();
                assert_eq!(result.retired, 0);
                assert!(matches!(result.stop, RetirementStop::StateChange));
            }
            let private = source.capture_backend_context().unwrap();
            let mut restored = Aarch32Vcpu::new(0, memory);
            restored
                .restore_checkpoint_context(
                    &source.get_state().unwrap(),
                    &source.get_emulator_state().unwrap_or_default(),
                    private.as_ref(),
                )
                .unwrap();
            assert_eq!(
                restored.save_context().unwrap(),
                source.save_context().unwrap()
            );
            for cpu in [&mut source, &mut restored] {
                if !delivered {
                    assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 0);
                }
                assert_eq!(cpu.current_pc(), 4);
                assert_eq!(cpu.cpu.cpsr.mode, ProcessorMode::Undefined as u8);
                assert_eq!(cpu.cpu.regs[14], 0x100 + if thumb { 2 } else { 4 });
                assert_eq!(cpu.cpu.vfp.fpexc & 0x2400009f, 0x24000001);
                assert_eq!(cpu.cpu.vfp.read_s_bits(0), 0xdeadbeef);
                assert_eq!(cpu.instruction_count(), 0);
                // Emulate the guest's acknowledgment/return and retry once with
                // enables clear. The instruction now commits the default NaN.
                cpu.cpu.vfp.write_fpexc(1 << 30);
                cpu.cpu.vfp.write_fpscr(0);
                cpu.cpu.cpsr = cpu.cpu.spsr_und.clone();
                cpu.cpu.regs[15] = 0x100;
                assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
                assert_eq!(cpu.cpu.vfp.read_s_bits(0), 0x7fc00000);
                assert_eq!(cpu.cpu.vfp.fpscr.bits(), 1);
            }
            assert_eq!(clock.checkpoint_state().retired_units, 2);
            assert_eq!(
                restored.save_context().unwrap(),
                source.save_context().unwrap()
            );
            drop(binding);
        }
    }
}
