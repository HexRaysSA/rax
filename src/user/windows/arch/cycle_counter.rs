//! Windows ARM64 makes PMCCNTR_EL0 readable in user mode.
//!
//! Native ARM64 Windows samples the real processor counter, including its
//! native per-processor epoch and frequency behavior. Other hosts use the
//! emulated core's one-cycle-per-retired-instruction model. Neither source is
//! a wall clock or a replacement for QueryPerformanceCounter.
use crate::user::cpu::aarch64::A64UserCpu;

pub(super) fn bind(cpu: &mut A64UserCpu) {
    cpu.core_mut().bind_el0_cycle_counter(read);
}

fn read(virtual_cycles: u64) -> u64 {
    #[cfg(all(windows, target_arch = "aarch64"))]
    {
        let _ = virtual_cycles;
        let value: u64;
        // SAFETY: the Windows ARM64 ABI guarantees this register is readable
        // at EL0. This reads only a processor counter; no guest value becomes
        // a host address or register selector. MRS changes no flags or stack.
        // Keep the assembly impure so even an XZR destination still samples.
        unsafe {
            std::arch::asm!(
                "mrs {value}, pmccntr_el0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }
    #[cfg(not(all(windows, target_arch = "aarch64")))]
    {
        virtual_cycles
    }
}
