//! Segment-relative linear addresses. Outside 64-bit mode a linear address is
//! 32 bits and wraps at 4 GiB: real and protected mode have 32-bit linear
//! addresses, and compatibility mode "access[es] only the first 4 GByte of
//! linear-address space" (Intel SDM Vol. 1 §3.1.1) and "ignores the upper 32
//! bits [of the FS and GS bases] when calculating an effective address"
//! (Vol. 3A §3.4.4). In 64-bit mode the CS, DS, ES, and SS bases count as
//! zero (Vol. 1 §3.7.4.1; `get_segment_base`) and nothing wraps.
//!
//! Every segment-relative access goes through [`X86_64Vcpu::segment_linear`]:
//! ModR/M and moffs operands, the stack, instruction fetch, the string
//! instructions, XLAT, MASKMOV's implicit destination, MOVDIR64B, VSIB
//! gathers and scatters, and MONITOR/UMONITOR. The CPU's own
//! descriptor-table, TSS, and interrupt-stack accesses are not segment
//! relative and keep their addresses.

use super::cpu::X86_64Vcpu;
use crate::vm::vcpu::SystemRegisters;

impl X86_64Vcpu {
    /// The linear address of `offset` in a segment with `base`.
    #[inline]
    pub(crate) fn segment_linear(&self, base: u64, offset: u64) -> u64 {
        let linear = base.wrapping_add(offset);
        if self.sregs.cs.l {
            linear
        } else {
            linear & 0xFFFF_FFFF
        }
    }

    /// The linear address of stack offset `offset` (SS-relative).
    #[inline(always)]
    pub(super) fn stack_linear(&self, offset: u64) -> u64 {
        self.segment_linear(self.stack_segment_base(), offset)
    }
}

/// The next page of an access that crosses pages: outside 64-bit mode an
/// access that began below 4 GiB continues at 0; a 64-bit address (a system
/// structure while compatibility code runs) goes on unwrapped.
pub(super) fn crossing_next(vaddr: u64, addr: u64, advance: u64, sregs: &SystemRegisters) -> u64 {
    let next = addr.wrapping_add(advance);
    if !sregs.cs.l && vaddr <= 0xFFFF_FFFF {
        next & 0xFFFF_FFFF
    } else {
        next
    }
}

#[cfg(test)]
#[path = "linear_tests.rs"]
mod tests;
