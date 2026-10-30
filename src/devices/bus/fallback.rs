//! Native MMIO fallbacks: PCI BARs first, then collateral RAM, then open bus.
//! Configuration and device servicing are serialized by the VMM owner.
use super::{MmioRmwOp, Result};
use crate::devices::pci::PciStub;
use crate::error::Error;
use std::sync::{Arc, Mutex};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[derive(Default)]
pub(super) struct Fallback {
    pub pci: Option<Arc<Mutex<PciStub>>>,
    pub ram: Option<(Arc<GuestMemoryMmap>, u64)>,
}
impl Fallback {
    pub fn chunk(&self, address: u64, remaining: usize) -> Result<usize> {
        let mut count = remaining as u64;
        if let Some(pci) = &self.pci {
            for range in pci
                .lock()
                .map_err(|_| Error::Emulator("MMIO PCI lock poisoned".into()))?
                .mmio_ranges()
            {
                for boundary in [range.base, range.base + range.len] {
                    if boundary > address {
                        count = count.min(boundary - address);
                    }
                }
            }
        }
        if let Some((_, end)) = &self.ram {
            if *end > address {
                count = count.min(*end - address);
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
        if let Some((ram, end)) = &self.ram {
            if address < *end {
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
        if let Some((ram, end)) = &self.ram {
            if address < *end {
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
        if let Some((ram, end)) = &self.ram {
            if address < *end {
                return crate::vm::memory::reservations::MemoryDomain::for_memory(ram)
                    .read_modify_write(ram, address, size, operation);
            }
        }
        Ok(vec![0xff; usize::from(size)])
    }
}
