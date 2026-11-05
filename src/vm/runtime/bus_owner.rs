//! One mutable device bus for normal dispatch and stopped checkpoint settling.
//! Registration remains exclusive to VMM construction and mutable callers.
use crate::devices::bus::{IoBus, MmioBus};
use crate::error::{Error, Result};
use std::sync::Mutex;

pub(super) struct BusOwner<T> {
    bus: Mutex<T>,
}

impl<T> BusOwner<T> {
    pub(super) fn new(bus: T) -> Self {
        Self {
            bus: Mutex::new(bus),
        }
    }

    pub(super) fn get_mut(&mut self) -> Result<&mut T> {
        self.bus
            .get_mut()
            .map_err(|_| Error::Emulator("VMM device bus ownership poisoned".into()))
    }

    /// Called before checkpoint device/RAM publication locks. The caller owns
    /// a stopped VMM and releases its CPU owner before invoking this callback.
    /// This private owner is neither cloneable nor exposed to device models;
    /// a callback cannot reenter this same bus through another safe alias.
    pub(super) fn with_stopped<R>(&self, operation: impl FnOnce(&mut T) -> Result<R>) -> Result<R> {
        let mut bus = self
            .bus
            .lock()
            .map_err(|_| Error::Emulator("VMM device bus ownership poisoned".into()))?;
        operation(&mut bus)
    }
}

impl BusOwner<IoBus> {
    pub(super) fn register(
        &mut self,
        range: crate::devices::bus::IoRange,
        device: Box<dyn crate::devices::bus::IoDevice>,
    ) -> Result<()> {
        self.get_mut()?.register(range, device)
    }

    pub(super) fn read(&mut self, port: u16, bytes: &mut [u8]) -> Result<()> {
        self.get_mut()?.read(port, bytes)
    }
    pub(super) fn write(&mut self, port: u16, bytes: &[u8]) -> Result<()> {
        self.get_mut()?.write(port, bytes)
    }
}

impl BusOwner<MmioBus> {
    pub(super) fn register(
        &mut self,
        range: crate::devices::bus::MmioRange,
        device: Box<dyn crate::devices::bus::MmioDevice>,
    ) -> Result<()> {
        self.get_mut()?.register(range, device)
    }

    pub(super) fn ranges(&self) -> Result<Vec<crate::devices::bus::MmioRange>> {
        self.with_stopped(|bus| Ok(bus.ranges()))
    }

    pub(super) fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<()> {
        self.get_mut()?.read(address, bytes)
    }
    pub(super) fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        self.get_mut()?.write(address, bytes)
    }
}
