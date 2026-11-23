//! Native MMIO fallbacks: PCI BARs first, then collateral RAM, then open bus.
//! Configuration and device servicing are serialized by the VMM owner.
use super::{MmioRmwOp, Result};
use crate::devices::pci::PciStub;
use crate::error::Error;
use crate::machine::pc::ram::Layout;
use crate::vm::memory::reservations::{preflight_read, preflight_write};
use std::sync::{Arc, Mutex};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[derive(Clone, Copy)]
pub(super) enum Access {
    Read,
    Write,
    Rmw,
}

#[derive(Default)]
pub(super) struct Fallback {
    pub pci: Option<Arc<Mutex<PciStub>>>,
    pub ram: Option<(Arc<GuestMemoryMmap>, Layout)>,
}
impl Fallback {
    pub fn chunk(&self, address: u64, remaining: usize, access: Access) -> Result<usize> {
        let mut count = remaining as u64;
        let mut pci_owns_start = false;
        if let Some(pci) = &self.pci {
            for range in pci
                .lock()
                .map_err(|_| Error::Emulator("MMIO PCI lock poisoned".into()))?
                .mmio_ranges()
            {
                pci_owns_start |= range.contains(address);
                for boundary in [range.base, range.base + range.len] {
                    if boundary > address {
                        count = count.min(boundary - address);
                    }
                }
            }
        }
        if let Some((ram, layout)) = &self.ram {
            for range in layout.ranges() {
                for boundary in [range.start, range.end] {
                    if boundary > address {
                        count = count.min(boundary - address);
                    }
                }
            }
            if !pci_owns_start && layout.contains(address, count) {
                match access {
                    Access::Read => preflight_read(ram, address, count as usize)?,
                    Access::Write => preflight_write(ram, address, count as usize)?,
                    Access::Rmw => (), // The atomic RAM operation preflights its own extent.
                }
            }
        }
        Ok(count as usize)
    }
    pub fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<()> {
        if let Some(pci) = &self.pci {
            if pci
                .lock()
                .map_err(|_| Error::Emulator("MMIO PCI lock poisoned".into()))?
                .mmio_read(address, bytes)
            {
                return Ok(());
            }
        }
        if let Some((ram, layout)) = &self.ram {
            if layout.contains(address, bytes.len() as u64) {
                ram.read_slice(bytes, GuestAddress(address))?;
                return Ok(());
            }
        }
        bytes.fill(0xff);
        Ok(())
    }
    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        if let Some(pci) = &self.pci {
            if pci
                .lock()
                .map_err(|_| Error::Emulator("MMIO PCI lock poisoned".into()))?
                .mmio_write(address, bytes)
            {
                return Ok(());
            }
        }
        if let Some((ram, layout)) = &self.ram {
            if layout.contains(address, bytes.len() as u64) {
                crate::vm::memory::write_guest_memory(ram, address, bytes)?;
            }
        }
        Ok(())
    }
    pub fn rmw(&mut self, address: u64, size: u8, operation: MmioRmwOp) -> Result<Vec<u8>> {
        if let Some(pci) = &self.pci {
            let mut bridge = pci
                .lock()
                .map_err(|_| Error::Emulator("MMIO PCI lock poisoned".into()))?;
            if let Some(old) = bridge.mmio_read_modify_write(address, size, operation)? {
                return Ok(old);
            }
        }
        if let Some((ram, layout)) = &self.ram {
            if layout.contains(address, u64::from(size)) {
                return crate::vm::memory::reservations::MemoryDomain::for_memory(ram)
                    .read_modify_write(ram, address, size, operation);
            }
        }
        Ok(vec![0xff; usize::from(size)])
    }
}
