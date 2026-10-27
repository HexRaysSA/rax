//! Additive extension container without changing the public base Snapshot shape.
use super::{PciSnapshot, Snapshot, codec};
use crate::error::{Error, Result};
use crate::vm::runtime::pci_state::PciDeviceCheckpoint;
use std::path::Path;
pub struct SnapshotBundle {
    pub(super) base: Snapshot,
    pub(super) pci: Option<PciSnapshot>,
}
impl std::fmt::Debug for SnapshotBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotBundle")
            .field("base", &self.base.summary())
            .field("pci", &self.pci.is_some())
            .finish_non_exhaustive()
    }
}
impl SnapshotBundle {
    pub fn new(base: Snapshot) -> Self {
        Self { base, pci: None }
    }
    pub fn base(&self) -> &Snapshot {
        &self.base
    }
    pub fn pci(&self) -> Option<&PciSnapshot> {
        self.pci.as_ref()
    }
    pub fn with_pci(mut self, state: PciDeviceCheckpoint) -> Result<Self> {
        self.base.validate_memory_metadata()?;
        self.pci = Some(PciSnapshot::capture(state, &self.base)?);
        Ok(self)
    }
    pub fn into_parts(self) -> (Snapshot, Option<PciSnapshot>) {
        (self.base, self.pci)
    }
    pub fn into_base(self) -> Result<Snapshot> {
        if self.pci.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required PCI state; use SnapshotBundle::load".to_string(),
            ));
        }
        Ok(self.base)
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
        if let Some(pci) = &self.pci {
            pci.validate(&self.base.config, self.base.memory_size)?;
        }
        Ok(())
    }
}
