//! Selected VM clock domain shared by direct and JIT timestamp operations.
use super::X86_64Vcpu;
use crate::vm::timing;
impl X86_64Vcpu {
    /// Selected retired clock: exact wrapping units, including fractional ns.
    /// Wall/unbound clock: existing 3 GHz conversion from elapsed nanoseconds.
    /// IA32_TSC_ADJUST applies in the same wrapping cycle domain in both modes.
    #[inline(always)]
    pub(in crate::isa::x86_64) fn tsc(&self) -> u64 {
        timing::retired_counter()
            .unwrap_or_else(|| timing::elapsed_nanos().wrapping_mul(3))
            .wrapping_add(self.tsc_adjust)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::timing::{ClockMode, TimingContext};
    use std::sync::Arc;
    use vm_memory::{GuestAddress, GuestMemoryMmap};
    #[test]
    fn selected_counter_and_native_helper_preserve_fraction_wrap_and_destinations() {
        let memory =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let mut cpu = X86_64Vcpu::new(0, memory);
        for units in [0, 1, 2, 1000, 0x1_0000_0001, u64::MAX] {
            let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
            clock.advance_retired(units).unwrap();
            let _binding = clock.enter();
            for offset in [0, 1, u64::MAX] {
                cpu.tsc_adjust = offset;
                let expected = units.wrapping_add(offset);
                assert_eq!(cpu.tsc(), expected);
                #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
                {
                    let mut registers = crate::smir::lower::runtime::GuestRegs::default();
                    registers.ctx = (&cpu as *const X86_64Vcpu) as u64;
                    registers.gpr = [u64::MAX; crate::smir::lower::X86_GUEST_GPR_COUNT];
                    let mut wanted = registers;
                    wanted.gpr[0] = u64::from(expected as u32);
                    wanted.gpr[2] = u64::from((expected >> 32) as u32);
                    unsafe {
                        super::super::jit_tsc::rax_jit_tsc(&mut registers);
                    }
                    assert_eq!(registers, wanted);
                }
            }
        }
    }
}
