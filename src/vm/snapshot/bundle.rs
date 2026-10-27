//! Additive extension container without changing the public base Snapshot shape.
use super::{CpuSnapshot, CpuSnapshots, PciSnapshot, PhysicalMemorySnapshot, Snapshot, codec};
use crate::error::{Error, Result};
use crate::vm::runtime::pci_state::PciDeviceCheckpoint;
use std::path::Path;
pub struct SnapshotBundle {
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
            clock: None,
            cpus: None,
            pci: None,
            physical_memory: None,
        }
    }
    pub fn base(&self) -> &Snapshot {
        &self.base
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
        if self.pci.is_some()
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
    pub(super) fn validate(&self) -> Result<()> {
        self.base.validate_for_restore()?;
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
        if let Some(state) = &self.physical_memory {
            let media = self.pci.as_ref().map_or(0, |p| {
                p.nvme_media().map_or(0, |m| m.size()) + p.ahci_media().map_or(0, |m| m.size())
            });
            state.validate_metadata(media)?;
        }
        Ok(())
    }
}
