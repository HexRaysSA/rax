//! Complete represented GIC state, retaining target-owned IRQ line handles.
use super::{CpuInterface, Gic, GicConfig, InterruptConfig};
use crate::error::{Error, Result};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GicCheckpoint {
    config: GicConfig,
    dist_enabled: bool,
    security_enabled: bool,
    are_s: bool,
    are_ns: bool,
    spis: Vec<InterruptConfig>,
    cpu_interfaces: Vec<CpuInterface>,
}

impl GicCheckpoint {
    pub(crate) fn validate_shape(&self, count: usize) -> Result<()> {
        let invalid =
            || Error::Emulator("GIC checkpoint topology or interrupt state is invalid".into());
        if count == 0
            || count != usize::from(self.config.num_cpus)
            || self.cpu_interfaces.len() != count
            || self.spis.len() != usize::from(self.config.num_spis)
            || self.spis.len() > 992
        {
            return Err(invalid());
        }
        for (id, cpu) in self.cpu_interfaces.iter().enumerate() {
            if usize::from(cpu.cpu_id) != id
                || cpu.affinity != id as u64
                || cpu.active_priorities.len() > 1024
                || cpu.pending_lpis.len() > 65536
                || cpu.private_interrupts.iter().any(|irq| irq.group > 1)
                || cpu
                    .active_priorities
                    .iter()
                    .any(|(intid, _)| *intid >= 1020)
                || cpu.bpr0 > 7
                || cpu.bpr1 > 7
            {
                return Err(invalid());
            }
        }
        if self.spis.iter().any(|irq| irq.group > 1) {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Gic {
    pub fn checkpoint(&self) -> GicCheckpoint {
        GicCheckpoint {
            config: self.config.clone(),
            dist_enabled: self.dist_enabled,
            security_enabled: self.security_enabled,
            are_s: self.are_s,
            are_ns: self.are_ns,
            spis: self.spis.clone(),
            cpu_interfaces: self.cpu_interfaces.clone(),
        }
    }

    pub fn validate_checkpoint(&self, state: &GicCheckpoint) -> Result<()> {
        state.validate_shape(self.cpu_interfaces.len())?;
        let a = &state.config;
        let b = &self.config;
        if a.version != b.version
            || a.num_spis != b.num_spis
            || a.dist_base != b.dist_base
            || a.redist_base != b.redist_base
            || a.redist_stride != b.redist_stride
        {
            return Err(Error::Emulator(
                "GIC checkpoint configuration mismatch".into(),
            ));
        }
        Ok(())
    }

    /// The caller validated this state before publication. IRQ mirrors are
    /// recomputed into existing Arcs, so every PE retains its live binding.
    pub fn restore_checkpoint(&mut self, state: GicCheckpoint) {
        self.dist_enabled = state.dist_enabled;
        self.security_enabled = state.security_enabled;
        self.are_s = state.are_s;
        self.are_ns = state.are_ns;
        self.spis = state.spis;
        self.cpu_interfaces = state.cpu_interfaces;
        self.update_all_cpus();
    }
}
