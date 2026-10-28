//! Additive extension container without changing the public base Snapshot shape.
use super::{CpuSnapshot, CpuSnapshots, PciSnapshot, PhysicalMemorySnapshot, Snapshot, codec};
use crate::error::{Error, Result};
use crate::vm::runtime::pci_state::PciDeviceCheckpoint;
use std::path::Path;
pub struct SnapshotBundle {
    pub(super) resources: Option<super::ResourcesSnapshot>,
    pub(super) backend_contexts: Option<super::BackendContexts>,
    pub(super) execution: Option<super::ExecutionSnapshot>,
    pub(super) clock: Option<crate::vm::timing::ClockState>,
    pub(super) base: Snapshot,
    pub(super) cpus: Option<CpuSnapshots>,
    pub(super) pci: Option<PciSnapshot>,
    pub(super) physical_memory: Option<PhysicalMemorySnapshot>,
}
impl std::fmt::Debug for SnapshotBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotBundle")
            .field("base", &self.base.summary())
            .field("resources", &self.resources)
            .field("backend_contexts", &self.backend_contexts.is_some())
            .field("execution", &self.execution.is_some())
            .field("clock", &self.clock)
            .field("pci", &self.pci.is_some())
            .field("cpus", &self.cpus.as_ref().map(|c| c.entries().len()))
            .field("physical_memory", &self.physical_memory.is_some())
            .finish_non_exhaustive()
    }
}
impl SnapshotBundle {
    pub fn new(base: Snapshot) -> Self {
        Self {
            base,
            resources: None,
            backend_contexts: None,
            execution: None,
            clock: None,
            cpus: None,
            pci: None,
            physical_memory: None,
        }
    }
    pub fn base(&self) -> &Snapshot {
        &self.base
    }
    pub fn resources(&self) -> Option<&super::ResourcesSnapshot> {
        self.resources.as_ref()
    }
    /// Store complete immutable media once, independently of CPU record limits.
    pub fn with_resources(mut self, resources: Vec<super::CheckpointResource>) -> Result<Self> {
        if self.cpus.is_none() || self.backend_contexts.is_none() {
            return Err(Error::Emulator(
                "checkpoint resources require CPU and backend context sets".into(),
            ));
        }
        self.resources = Some(super::ResourcesSnapshot::capture(resources)?);
        self.validate()?;
        Ok(self)
    }
    pub fn take_resources(&mut self) -> Option<super::ResourcesSnapshot> {
        self.resources.take()
    }
    pub fn backend_contexts(&self) -> Option<&super::BackendContexts> {
        self.backend_contexts.as_ref()
    }
    pub fn with_backend_contexts(
        mut self,
        entries: Vec<Option<super::BackendContext>>,
    ) -> Result<Self> {
        if self.cpus.is_none() {
            return Err(Error::Emulator(
                "backend contexts require the complete CPU set".into(),
            ));
        }
        self.backend_contexts = Some(super::BackendContexts::capture(
            entries,
            self.base.config.vcpus,
        )?);
        Ok(self)
    }
    pub fn take_backend_contexts(&mut self) -> Option<super::BackendContexts> {
        self.backend_contexts.take()
    }
    pub fn execution(&self) -> Option<&super::ExecutionSnapshot> {
        self.execution.as_ref()
    }
    pub(crate) fn with_execution(mut self, state: super::ExecutionSnapshot) -> Result<Self> {
        state.validate(&self.base)?;
        self.execution = Some(state);
        Ok(self)
    }
    pub fn take_execution(&mut self) -> Option<super::ExecutionSnapshot> {
        self.execution.take()
    }
    pub fn clock(&self) -> Option<&crate::vm::timing::ClockState> {
        self.clock.as_ref()
    }
    pub fn with_clock(mut self, state: crate::vm::timing::ClockState) -> Result<Self> {
        self.base.validate_for_restore()?;
        super::clock::validate(&state, &self.base)?;
        self.clock = Some(state);
        Ok(self)
    }
    pub fn take_clock(&mut self) -> Option<crate::vm::timing::ClockState> {
        self.clock.take()
    }
    pub fn cpus(&self) -> Option<&CpuSnapshots> {
        self.cpus.as_ref()
    }
    pub fn with_cpus(mut self, entries: Vec<CpuSnapshot>) -> Result<Self> {
        self.cpus = Some(CpuSnapshots::capture(entries, &self.base)?);
        Ok(self)
    }
    pub fn take_cpus(&mut self) -> Option<CpuSnapshots> {
        self.cpus.take()
    }
    pub fn pci(&self) -> Option<&PciSnapshot> {
        self.pci.as_ref()
    }
    pub fn with_pci(mut self, state: PciDeviceCheckpoint) -> Result<Self> {
        self.base.validate_memory_metadata()?;
        self.pci = Some(PciSnapshot::capture(state, &self.base)?);
        self.validate_physical_metadata()?;
        Ok(self)
    }
    pub fn physical_memory(&self) -> Option<&PhysicalMemorySnapshot> {
        self.physical_memory.as_ref()
    }
    pub fn with_physical_memory(mut self, state: PhysicalMemorySnapshot) -> Result<Self> {
        state.verify_projection(&self.base.memory_data, self.base.memory_size)?;
        self.physical_memory = Some(state);
        self.validate()?;
        Ok(self)
    }
    /// Required extensions must be handled explicitly before taking the base.
    pub fn take_physical_memory(&mut self) -> Option<PhysicalMemorySnapshot> {
        self.physical_memory.take()
    }
    pub fn take_pci(&mut self) -> Option<PciSnapshot> {
        self.pci.take()
    }
    /// Compatibility with the immediately preceding unreleased bundle API.
    /// Required physical state cannot be silently discarded by pair extraction.
    pub fn into_parts(self) -> Result<(Snapshot, Option<PciSnapshot>)> {
        if self.resources.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required resources".into(),
            ));
        }
        if self.backend_contexts.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required backend contexts".into(),
            ));
        }
        if self.execution.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required execution state".into(),
            ));
        }
        if self.clock.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required clock state".into(),
            ));
        }
        if self.cpus.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required CPU set".to_string(),
            ));
        }
        if self.physical_memory.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required physical memory".to_string(),
            ));
        }
        Ok((self.base, self.pci))
    }
    pub fn into_base(self) -> Result<Snapshot> {
        if self.resources.is_some()
            || self.backend_contexts.is_some()
            || self.execution.is_some()
            || self.pci.is_some()
            || self.physical_memory.is_some()
            || self.cpus.is_some()
            || self.clock.is_some()
        {
            return Err(Error::Emulator(
                "checkpoint contains required extensions; use SnapshotBundle::load".to_string(),
            ));
        }
        Ok(self.base)
    }
    /// Verify all represented physical bytes and the reported-RAM projection.
    /// PCI media/controller validation remains available through PciSnapshot.
    pub fn verify_physical_memory(&self) -> Result<()> {
        self.validate()?;
        if let Some(state) = &self.physical_memory {
            state.verify_projection(&self.base.memory_data, self.base.memory_size)?;
        }
        Ok(())
    }
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        codec::save_bundle_atomic(self, path.as_ref())
    }
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bundle = codec::load_bundle(path.as_ref())?;
        bundle.validate()?;
        Ok(bundle)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.base.validate_for_restore()?;
        if let Some(resources) = &self.resources {
            if self.cpus.is_none() || self.backend_contexts.is_none() {
                return Err(Error::Emulator(
                    "checkpoint resources require CPU and backend context sets".into(),
                ));
            }
            resources.validate_metadata()?;
        }
        if let Some(contexts) = &self.backend_contexts {
            if self.cpus.is_none() {
                return Err(Error::Emulator(
                    "backend contexts require the complete CPU set".into(),
                ));
            }
            contexts.validate(self.base.config.vcpus)?;
        }
        if let Some(execution) = &self.execution {
            if self.cpus.is_none() {
                return Err(Error::Emulator(
                    "execution checkpoint requires the complete CPU set".into(),
                ));
            }
            execution.validate(&self.base)?;
        }
        if let Some(clock) = &self.clock {
            super::clock::validate(clock, &self.base)?;
        }
        if let Some(cpus) = &self.cpus {
            cpus.validate(&self.base)?;
        }
        if let Some(pci) = &self.pci {
            pci.validate(&self.base.config, self.base.memory_size)?;
        }
        self.validate_physical_metadata()
    }
    fn validate_physical_metadata(&self) -> Result<()> {
        let media = self.pci.as_ref().map_or(0, |p| {
            p.nvme_media().map_or(0, |m| m.size()) + p.ahci_media().map_or(0, |m| m.size())
        });
        let resources = self.resources.as_ref().map_or(0, |r| r.total_bytes());
        if self.resources.is_some()
            && resources > super::resources::remaining_budget(self.base.memory_size, media)?
        {
            return Err(Error::Emulator(
                "RAM plus media/resources exceeds bundle budget".into(),
            ));
        }
        if let Some(state) = &self.physical_memory {
            let total = media
                .checked_add(resources)
                .ok_or_else(|| Error::Emulator("checkpoint media/resource size overflow".into()))?;
            state.validate_metadata(total)?;
        }
        Ok(())
    }
}
