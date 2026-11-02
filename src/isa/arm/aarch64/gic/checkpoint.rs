//! Complete represented GIC state, retaining target-owned IRQ line handles.
use super::sources::SourceBank;
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
    sources: SourceBank,
}

/// Frozen positional GIC layout used before physical source state was retained.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct LegacyGicCheckpoint {
    config: GicConfig,
    dist_enabled: bool,
    security_enabled: bool,
    are_s: bool,
    are_ns: bool,
    spis: Vec<InterruptConfig>,
    cpu_interfaces: Vec<CpuInterface>,
}

impl LegacyGicCheckpoint {
    pub(crate) fn upgrade(self) -> Result<GicCheckpoint> {
        // For a level input, aggregate pending = physical OR software. Only
        // aggregate false uniquely determines both sources. Edge inputs also
        // require the lost physical input history, even when not pending.
        if self
            .spis
            .iter()
            .chain(
                self.cpu_interfaces
                    .iter()
                    .flat_map(|cpu| &cpu.private_interrupts[super::NUM_SGI..]),
            )
            .any(|config| config.trigger != super::TriggerType::Level || config.state.is_pending())
        {
            return Err(Error::Emulator(
                "legacy GIC pending or edge sources are ambiguous".into(),
            ));
        }
        let sources = SourceBank::new(self.cpu_interfaces.len(), self.spis.len());
        let result = GicCheckpoint {
            config: self.config,
            dist_enabled: self.dist_enabled,
            security_enabled: self.security_enabled,
            are_s: self.are_s,
            are_ns: self.are_ns,
            spis: self.spis,
            cpu_interfaces: self.cpu_interfaces,
            sources,
        };
        result.validate_shape(result.cpu_interfaces.len())?;
        Ok(result)
    }
}

impl GicCheckpoint {
    pub(crate) fn validate_timer_inputs(&self, cpu: usize, levels: (bool, bool)) -> Result<()> {
        self.validate_shape(self.cpu_interfaces.len())?;
        if self.sources.ppi_level(cpu, 27) != Some(levels.0)
            || self.sources.ppi_level(cpu, 30) != Some(levels.1)
        {
            return Err(Error::Emulator(
                "GIC physical timer inputs disagree with last published CPU outputs".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_shape(&self, count: usize) -> Result<()> {
        let invalid =
            || Error::Emulator("GIC checkpoint topology or interrupt state is invalid".into());
        if count == 0
            || count != usize::from(self.config.num_cpus)
            || self.cpu_interfaces.len() != count
            || self.spis.len() != usize::from(self.config.num_spis)
            || self.spis.len() > 992
            || !self.sources.valid(&self.cpu_interfaces, &self.spis)
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
        let mut state = GicCheckpoint {
            config: self.config.clone(),
            dist_enabled: self.dist_enabled,
            security_enabled: self.security_enabled,
            are_s: self.are_s,
            are_ns: self.are_ns,
            spis: self.spis.clone(),
            cpu_interfaces: self.cpu_interfaces.clone(),
            sources: self.sources.clone(),
        };
        state
            .sources
            .reconcile(&mut state.cpu_interfaces, &mut state.spis);
        for cpu in &mut state.cpu_interfaces {
            cpu.update_pending(&state.spis);
        }
        state
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
        self.sources = state.sources;
        self.update_all_cpus();
    }
}
