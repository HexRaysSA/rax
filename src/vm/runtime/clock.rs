//! Select the VM clock before any device or vCPU retains its timing identity.
use super::Vmm;
use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::vm::timing::ClockMode;

impl Vmm {
    /// Build a fresh machine using an explicitly selected clock.
    ///
    /// Retired mode is supported by the software backend: each validated
    /// instruction (Hexagon packet) advances one 3 GHz clock unit. Host delay,
    /// diagnostic ticks and zero-retirement waits do not advance that clock.
    /// Independent board clocks, RTC and entropy sources are not replaced by
    /// this selection. Whole-machine determinism still requires their wiring.
    /// This is not a physical cycle model or an external-event replay mode.
    /// Native backends reject Retired before host VM/resource construction.
    pub fn new_with_clock(config: VmConfig, mode: ClockMode) -> Result<Self> {
        Self::build_with_contexts(config, false, false, None, mode)
    }

    /// Build an empty machine for restoration with an explicit clock.
    ///
    /// The clock mode must match an incoming bundle. Prefer
    /// [`new_resume_bundle`](Self::new_resume_bundle) for complete files: it
    /// selects the saved mode before constructing devices and vCPUs. Legacy
    /// base-only snapshots contain no complete clock phase/retirement record.
    pub fn new_resume_with_clock(config: VmConfig, mode: ClockMode) -> Result<Self> {
        Self::build_with_contexts(config, true, false, None, mode)
    }
}

impl Vmm {
    pub(super) fn validate_base_snapshot_clock(&self) -> Result<()> {
        if self.timing_context.mode() == ClockMode::Retired {
            return Err(Error::InvalidConfig(
                "retired VM clock requires a complete snapshot bundle".into(),
            ));
        }
        Ok(())
    }
}
