//! Verification-only replay to an exact partially completed VSIB frontier.

use super::X86_64Vcpu;

/// Requested lane comes from native failure metadata, never the native result
/// mask. Direct execution independently computes and commits all earlier active
/// lanes. An invalid, inactive, or wrong-PC request cannot become `Reached`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::isa::x86_64) enum JitVerifyVsibStop {
    Requested { pc: u64, lane: u8 },
    Reached { pc: u64, lane: u8 },
}

impl X86_64Vcpu {
    /// Called only for active lanes, before calculating or accessing memory.
    /// A true result is an intentional verifier stop, not an architectural
    /// exception or instruction completion; the direct handler retains RIP.
    #[inline]
    pub(in crate::isa::x86_64) fn jit_verify_stop_before_vsib_lane(&mut self, lane: u8) -> bool {
        let requested = JitVerifyVsibStop::Requested {
            pc: self.regs.rip,
            lane,
        };
        if self.jit_verify_vsib_stop == Some(requested) {
            self.jit_verify_vsib_stop = Some(JitVerifyVsibStop::Reached {
                pc: self.regs.rip,
                lane,
            });
            true
        } else {
            false
        }
    }
}
