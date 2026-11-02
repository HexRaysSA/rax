//! Shared optional scalar/SIMD floating-point trap policy.
use super::*;
use crate::isa::arm::aarch32::fp_traps::{ENABLES, STATUS};
use std::cell::Cell;

#[derive(Clone, Copy)]
struct UnderflowCollection {
    trapped: bool,
    fpcr: u32,
}
thread_local! {
    static UNDERFLOW: Cell<Option<UnderflowCollection>> = const { Cell::new(None) };
}

struct UnderflowScope(Option<UnderflowCollection>);
impl UnderflowScope {
    fn begin(fpcr: u32) -> Self {
        Self(UNDERFLOW.replace(Some(UnderflowCollection {
            trapped: false,
            fpcr,
        })))
    }
    fn trapped(&self) -> bool {
        UNDERFLOW.get().is_some_and(|state| state.trapped)
    }
}
impl Drop for UnderflowScope {
    fn drop(&mut self) {
        UNDERFLOW.set(self.0);
    }
}

/// Typed FPRound status: exact tiny results trap with UFE; output flushing
/// sets cumulative UFC directly and never traps. No state is recorded outside
/// an admitted interpreted instruction. The scope is local to its host thread.
pub(super) fn collect_underflow(esize: usize, result: u64, status: u32, fpcr: u32) -> u32 {
    if fpcr & (1 << 11) == 0 || (fpcr & (1 << if esize == 2 { 19 } else { 24 }) != 0) {
        return status;
    }
    if status & 8 == 0 && !super::fp_is_tiny_bits(esize, result) {
        return status;
    }
    UNDERFLOW.update(|state| {
        state.map(|mut state| {
            state.trapped = true;
            state
        })
    });
    status | 8
}

pub(super) fn collect_sve_underflow(esize: usize, result: u64, status: u32) -> u32 {
    UNDERFLOW.get().map_or(status, |state| {
        collect_underflow(esize, result, status, state.fpcr)
    })
}

impl AArch64Cpu {
    fn aarch32_fpexc_view(&self) -> crate::isa::arm::aarch32::vfp::VfpState {
        let mut view = crate::isa::arm::aarch32::vfp::VfpState::default();
        view.mvfr0 = self.sysregs.aarch32_fp_ids()[0];
        view.fpexc = self
            .sysregs
            .impl_defined
            .get(&Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode())
            .copied()
            .unwrap_or(0) as u32;
        view
    }
    pub(super) fn read_aarch32_fpexc(&self) -> u64 {
        u64::from(self.aarch32_fpexc_view().read_fpexc())
    }
    pub(super) fn write_aarch32_fpexc(&mut self, value: u64) {
        let mut view = self.aarch32_fpexc_view();
        view.write_fpexc(value as u32);
        self.sysregs.impl_defined.insert(
            Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode(),
            u64::from(view.fpexc),
        );
    }
    pub(crate) fn fp_trapping_profile(&self) -> bool {
        (self.sysregs.aarch32_fp_ids()[0] >> 12) & 15 == 1
    }
    pub(crate) fn fp_traps_enabled(&self) -> bool {
        self.fpcr & ENABLES != 0 && self.fp_trapping_profile()
    }
    /// Pure FP/SIMD data and non-memory SVE groups. System transfers and memory
    /// instructions retain their own read/partial-completion semantics.
    fn fp_transaction_word(word: u32) -> bool {
        matches!((word >> 25) & 15, 7 | 15) || ((word >> 25) & 15 == 2 && word & (1 << 31) == 0)
    }
    pub(super) fn decode_with_fp_traps(&mut self, word: u32) -> Result<CpuExit, ArmError> {
        if !self.fp_traps_enabled() || !Self::fp_transaction_word(word) {
            return self.decode_and_execute(word);
        }
        let enabled = (self.fpcr >> 8) & STATUS;
        let old_fpsr = self.fpsr;
        let underflow = UnderflowScope::begin(self.fpcr);
        let saved = (self.x, self.v, self.nzcv, self.sve_p, self.sve_ffr);
        self.fpsr &= !STATUS;
        let result = self.decode_and_execute(word);
        let raised = self.fpsr & STATUS;
        if result.is_err() || matches!(result, Ok(CpuExit::Undefined(_))) {
            self.fpsr = (self.fpsr & !STATUS) | (old_fpsr & STATUS);
            return result;
        }
        let trapped = (raised & enabled & !8)
            | if underflow.trapped() {
                raised & enabled & 8
            } else {
                0
            };
        if trapped == 0 {
            self.fpsr |= old_fpsr & STATUS;
            return result;
        }
        (self.x, self.v, self.nzcv, self.sve_p, self.sve_ffr) = saved;
        self.fpsr = old_fpsr | (raised & !trapped);
        Err(ArmError::ArchitecturalException {
            ec: 0x2c,
            iss: (1 << 23) | trapped,
            target_el: Some(if self.current_el > 1 {
                self.current_el
            } else if self.pauth_controls().el2_enabled() && self.sysregs.hcr_el2 & (1 << 27) != 0 {
                2
            } else {
                1
            }),
        })
    }
}
