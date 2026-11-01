//! Complete represented core/controller state, excluding memory and host debug controls.
use super::*;
use crate::error::{Error, Result};
use crate::isa::arm::cortex_m::exec::Snapshot;
use serde::{Deserialize, Serialize};

// Bound decoded queue storage as well as the outer 16 MiB wire record.
const MAX_PENDING: usize = 262_144;
const _: () = assert!(std::mem::size_of::<ArmException>() <= 64);
fn pending<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<ArmException>, D::Error> {
    crate::devices::checkpoint_serde::vector::<ArmException, D, MAX_PENDING>(d)
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CoreCheckpoint {
    variant: CortexMVariant,
    registers: Snapshot,
    nvic: Nvic,
    scb: Scb,
    systick: SysTick,
    vfp: Option<VfpState>,
    halted: bool,
    #[serde(deserialize_with = "pending")]
    pending_exceptions: Vec<ArmException>,
    insn_addr: u32,
    it_rewritten: bool,
    features: u64,
    version: ArmVersion,
}

impl CoreCheckpoint {
    pub(crate) fn capture(cpu: &CortexMCpu) -> Result<Self> {
        if cpu.pending_exceptions.len() > MAX_PENDING {
            return Err(Error::InvalidConfig(
                "Cortex-M checkpoint pending exceptions exceed budget".into(),
            ));
        }
        let image = Self {
            variant: cpu.variant,
            registers: cpu.snapshot(),
            nvic: cpu.nvic.clone(),
            scb: cpu.scb.clone(),
            systick: cpu.systick.clone(),
            vfp: cpu.vfp.clone(),
            halted: cpu.halted,
            pending_exceptions: cpu.pending_exceptions.clone(),
            insn_addr: cpu.insn_addr,
            it_rewritten: cpu.it_rewritten,
            features: cpu.features.bits(),
            version: cpu.version,
        };
        image.validate(cpu)?;
        Ok(image)
    }
    pub(crate) fn validate(&self, target: &CortexMCpu) -> Result<()> {
        if self.variant != target.variant
            || self.features != target.features.bits()
            || self.version != target.version
            || self.vfp.is_some()
            || self.pending_exceptions.len() > MAX_PENDING
        {
            return Err(Error::InvalidConfig(
                "Cortex-M checkpoint model/profile differs or unsupported FPU state".into(),
            ));
        }
        self.registers.validate_checkpoint()?;
        self.nvic.validate_checkpoint(&target.nvic)?;
        self.scb.validate_checkpoint(target.variant)?;
        self.systick.validate_checkpoint(&target.systick)
    }
    /// Only a detached, already admitted core is modified; no register callbacks.
    pub(crate) fn install(self, target: &mut CortexMCpu) {
        target.restore(self.registers);
        target.nvic = self.nvic;
        target.scb = self.scb;
        target.systick = self.systick;
        target.vfp = self.vfp;
        target.halted = self.halted;
        target.pending_exceptions = self.pending_exceptions;
        target.insn_addr = self.insn_addr;
        target.it_rewritten = self.it_rewritten;
    }
}

impl CortexMCpu {
    pub(crate) fn retain_checkpoint_host_controls(&mut self, target: &Self) {
        self.breakpoints = target.breakpoints.clone();
        self.watchpoints = target.watchpoints.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::arm::cpu_trait::{ArmCpu, WatchpointKind};

    #[test]
    fn imported_counter_boundary_wraps_without_losing_controller_state() {
        let mut source = CortexMCpu::new_m4(0x4000);
        source.memory_mut().write(0x1000, &[0x00, 0xbf]).unwrap();
        source.set_pc(0x1000);
        source.insn_count = u64::MAX;
        source.cycle_count = u64::MAX;
        // Raw set_sp is an existing API; admission must retain even this value.
        source.set_sp(0x3001);
        let image = CoreCheckpoint::capture(&source).unwrap();
        let mut target = CortexMCpu::new_m4(0x4000);
        target.memory_mut().write(0x1000, &[0x00, 0xbf]).unwrap();
        image.validate(&target).unwrap();
        image.install(&mut target);
        assert_eq!(target.get_sp(), 0x3001);
        target.execute_one().unwrap();
        assert_eq!(target.instruction_count(), 0);
        assert_eq!(target.cycle_count(), Some(0));
    }

    #[test]
    fn checkpoint_rebind_keeps_target_debug_controls() {
        let mut source = CortexMCpu::new_m4(0x4000);
        source.set_breakpoint(0x1000).unwrap();
        source
            .set_watchpoint(0x2000, 4, WatchpointKind::Write)
            .unwrap();
        let mut target = CortexMCpu::new_m4(0x4000);
        target.set_breakpoint(0x3000).unwrap();
        target
            .set_watchpoint(0x2100, 2, WatchpointKind::Read)
            .unwrap();
        let mut candidate = CortexMCpu::new_m4(0x4000);
        CoreCheckpoint::capture(&source)
            .unwrap()
            .install(&mut candidate);
        candidate.retain_checkpoint_host_controls(&target);
        assert_eq!(candidate.breakpoints, target.breakpoints);
        assert_eq!(candidate.watchpoints, target.watchpoints);
    }

    #[test]
    fn decoded_pending_queue_cannot_exceed_the_storage_budget() {
        let mut source = CortexMCpu::new_m4(0x4000);
        source.pending_exceptions = vec![ArmException::UndefinedInstruction; MAX_PENDING + 1];
        assert!(CoreCheckpoint::capture(&source).is_err());
        let mut image = CoreCheckpoint::capture(&CortexMCpu::new_m4(0x4000)).unwrap();
        image.pending_exceptions = source.pending_exceptions;
        let raw = crate::codec::serialize(&image).unwrap();
        assert!(crate::codec::deserialize::<CoreCheckpoint>(&raw).is_err());
    }
}
