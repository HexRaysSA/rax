//! Preflighted RAM inspection without guest MMU or device side effects.
use super::*;
use crate::isa::x86_64::inspection::PhysicalMemory;
use crate::vm::vcpu::DebugAddressSpace;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryRegion};

/// qSupported advertises PacketSize=4096 (hex); memory bytes require two hex digits.
const MAX_BYTES: usize = 0x4096 / 2;
struct Ram<'a> {
    memory: &'a vm_memory::GuestMemoryMmap,
    reported: Option<u64>,
    holes: Vec<crate::devices::bus::MmioRange>,
}
impl Ram<'_> {
    fn preflight(&self, address: u64, size: usize, write: bool) -> Result<()> {
        let end = address
            .checked_add(size as u64)
            .ok_or_else(|| Error::InvalidConfig("debug memory range wraps".into()))?;
        if self.reported.is_some_and(|limit| end > limit)
            || self
                .holes
                .iter()
                .any(|h| size != 0 && address < h.base.saturating_add(h.len) && end > h.base)
        {
            return Err(Error::InvalidConfig(
                "debug memory range is not ordinary RAM".into(),
            ));
        }
        let mut done = 0;
        while done < size {
            let current = address + done as u64;
            let region = self
                .memory
                .find_region(GuestAddress(current))
                .ok_or_else(|| Error::InvalidConfig("debug memory has no backing".into()))?;
            #[cfg(unix)]
            {
                let protection = if write {
                    libc::PROT_WRITE
                } else {
                    libc::PROT_READ
                };
                if region.prot() & protection == 0 {
                    return Err(Error::InvalidConfig(
                        "debug memory host permissions deny access".into(),
                    ));
                }
            }
            done += ((region.len() - (current - region.start_addr().0)) as usize).min(size - done);
        }
        Ok(())
    }
}
impl PhysicalMemory for Ram<'_> {
    fn contains_ram(&self, address: u64, size: usize) -> bool {
        self.preflight(address, size, false).is_ok()
    }
    fn read_physical(&mut self, address: u64, bytes: &mut [u8]) -> std::result::Result<(), String> {
        self.preflight(address, bytes.len(), false)
            .map_err(|e| e.to_string())?;
        self.memory
            .read_slice(bytes, GuestAddress(address))
            .map_err(|e| e.to_string())
    }
}
#[derive(Debug)]
struct Piece {
    physical: u64,
    offset: usize,
    size: usize,
}
impl Vmm {
    fn debug_ram(&self) -> Result<Ram<'_>> {
        let software_x86 = self.checkpoint_config.arch == ArchKind::X86_64
            && self
                .vm
                .as_any()
                .is::<crate::backend::emulator::EmulatorVm>();
        let mut holes = self.mmio_bus.ranges();
        if self
            .vm
            .as_any()
            .downcast_ref::<crate::backend::emulator::EmulatorVm>()
            .and_then(|vm| vm.riscv_platform())
            .is_some_and(|platform| platform.enabled())
        {
            holes.push(crate::devices::bus::MmioRange {
                base: crate::backend::emulator::riscv::platform::BASE,
                len: crate::backend::emulator::riscv::platform::LEN,
            });
        }
        if let Some(devices) = &self.pci_devices {
            // The software MMU diverts this entire aperture, including
            // unassigned BAR space, from the modeled physical backing.
            if software_x86 && self.checkpoint_config.pci_devices {
                holes.push(crate::devices::bus::MmioRange {
                    base: PCI_MMIO_AP_BASE,
                    len: PCI_MMIO_AP_END - PCI_MMIO_AP_BASE,
                });
            }
            holes.extend(
                devices
                    .bridge()
                    .lock()
                    .map_err(|_| Error::Emulator("debug PCI lock poisoned".into()))?
                    .mmio_ranges(),
            );
        }
        Ok(Ram {
            memory: self.guest_mem.memory(),
            // Software x86 deliberately models the overflow backing as RAM.
            // Native Intel registration maps the reported RAM window only.
            reported: (self.checkpoint_config.arch == ArchKind::X86_64 && !software_x86)
                .then_some(self.guest_mem.size()),
            holes,
        })
    }
    fn debug_memory_plan(
        &self,
        ram: &mut Ram<'_>,
        address: u64,
        size: usize,
        write: bool,
    ) -> Result<Vec<Piece>> {
        if size > MAX_BYTES || (size != 0 && address.checked_add(size as u64 - 1).is_none()) {
            return Err(Error::InvalidConfig(
                "debug memory packet is too large or wraps".into(),
            ));
        }
        let space = if self.debugger.physical_memory {
            DebugAddressSpace::Physical
        } else {
            self.vcpus[self.debugger.general].debug_address_space()?
        };
        let mut result = Vec::new();
        let mut done = 0;
        while done < size {
            let linear = address + done as u64;
            let chunk = (0x1000 - (linear & 0xfff) as usize).min(size - done);
            let physical = space.translate(ram, linear)?;
            ram.preflight(physical, chunk, write)?;
            result.push(Piece {
                physical,
                offset: done,
                size: chunk,
            });
            done += chunk;
        }
        Ok(result)
    }
    pub(super) fn read_debug_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let mut ram = self.debug_ram()?;
        let plan = self.debug_memory_plan(&mut ram, address, size, false)?;
        let mut bytes = vec![0; size];
        for p in plan {
            ram.read_physical(p.physical, &mut bytes[p.offset..p.offset + p.size])
                .map_err(Error::Emulator)?;
        }
        Ok(bytes)
    }
    pub(super) fn write_debug_memory(&mut self, address: u64, bytes: &[u8]) -> Result<bool> {
        self.debugger.ready()?;
        let plan = {
            let mut ram = match self.debug_ram() {
                Ok(r) => r,
                Err(_) => return Ok(false),
            };
            match self.debug_memory_plan(&mut ram, address, bytes.len(), true) {
                Ok(p) => p,
                Err(_) => return Ok(false),
            }
        };
        if bytes.is_empty() {
            return Ok(true);
        }
        let pages: Vec<_> = (0..bytes.len())
            .step_by(0x1000)
            .map(|n| (address + n as u64) & !0xfff)
            .chain(std::iter::once((address + bytes.len() as u64 - 1) & !0xfff))
            .collect();
        // Invalidate while stopped and before publishing data. Software x86
        // flushes all aliases; adapters without translated views retain their
        // established per-page callback. A failed SDK mutation fences all entry.
        for cpu in &mut self.vcpus {
            if let Err(error) = cpu.debug_memory_changed(&pages) {
                self.debugger.failure = Some(error.to_string());
                self.gdb_stopped = true;
                return Err(error);
            }
        }
        let pieces: Vec<_> = plan
            .iter()
            .map(|p| (p.physical, &bytes[p.offset..p.offset + p.size]))
            .collect();
        if let Err(error) =
            crate::vm::memory::reservations::write_scatter(self.guest_mem.memory(), &pieces)
        {
            self.debugger.failure = Some(format!("debug RAM publication failed: {error}"));
            self.gdb_stopped = true;
            return Err(Error::Emulator(self.debugger.failure.clone().unwrap()));
        }
        Ok(true)
    }
}
