//! Exact one-instruction PAuth admission for the EL0 embedder adapter.

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
use super::A64_JIT_HOT_THRESHOLD;
use super::AArch64Cpu;
use crate::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};

impl AArch64Cpu {
    /// Preserve the direct EL0 stepping contract, admitting only framed,
    /// single-instruction PAuth regions. The adapter disables this path while
    /// recording memory accesses, including compilation and validation fetches.
    pub(crate) fn step_user_pauth(&mut self, allow_native: bool) -> Result<CpuExit, ArmError> {
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        {
            let eligible = allow_native
                && self.current_el == 0
                && self.aarch32.is_none()
                && !self.halted
                && !self.wfi
                && !self.wfe
                && self.pending_exceptions.is_empty();
            if eligible {
                if let Some(region) = self.jit_lookup(self.pc)
                    && region.pauth_instruction.is_some()
                {
                    let ran = self.jit_run_region(&region);
                    if let Some(error) = self.jit.native_fault.take() {
                        return Err(error);
                    }
                    if ran {
                        return Ok(CpuExit::Continue);
                    }
                }
                let pc_before = self.pc;
                let result = self.step();
                if matches!(result, Ok(CpuExit::Continue)) {
                    self.sample_user_pauth_backedge(pc_before);
                }
                return result;
            }
        }
        self.step()
    }

    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    fn sample_user_pauth_backedge(&mut self, pc_before: u64) {
        if self.jit.disabled || self.pc >= pc_before || std::env::var_os("RAX_NO_JIT").is_some() {
            return;
        }
        let key = (self.pc, self.jit_mode_tag());
        if self.jit.cache.contains_key(&key) {
            return;
        }
        let hot = self.jit.hot.entry(self.pc).or_insert(0);
        *hot = hot.saturating_add(1);
        if *hot < A64_JIT_HOT_THRESHOLD {
            return;
        }
        self.jit.hot.remove(&self.pc);
        // User memory is side-effect-free supplied RAM with checked flat
        // translation. A failed speculative compilation fetch does not deliver
        // a fault before the next instruction's actual execution boundary.
        let region = self
            .fetch_instruction()
            .ok()
            .and_then(|raw| self.jit_compile_pauth_instruction(raw))
            .map(std::sync::Arc::new);
        self.jit.cache.insert(key, region);
    }

    pub(crate) fn native_pauth_entry_count(&self) -> u64 {
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        {
            return self.jit.pauth_native_runs;
        }
        #[cfg(not(all(feature = "smir-jit", target_arch = "aarch64")))]
        {
            0
        }
    }
}
