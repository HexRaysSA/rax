//! VM-owned I/O APIC access precedes all RAM paths and never copies model state.
use super::{LAPIC_BASE, Mmu};
use crate::devices::{
    bus::MmioDevice,
    ioapic::{IOAPIC_BASE, IOAPIC_SIZE, IoApic},
};
use crate::error::{Error, Result};
use std::sync::{Arc, Mutex, MutexGuard};

impl Mmu {
    pub(crate) fn attach_ioapic(&mut self, controller: Arc<Mutex<IoApic>>) {
        self.shared_ioapic = Some(controller);
        self.ioapic_mmio = true;
        self.refresh_ram_fast_limit();
        self.flush_tlb();
    }

    pub(super) fn refresh_ram_fast_limit(&mut self) {
        self.ram_fast_len = self.ram_len.min(LAPIC_BASE).min(self.pci_ap_lo);
        if self.ioapic_mmio {
            self.ram_fast_len = self.ram_fast_len.min(IOAPIC_BASE);
        }
    }

    #[inline]
    pub(super) fn overlaps_ioapic(&self, address: u64, size: u64) -> bool {
        self.ioapic_mmio
            && size != 0
            && address < IOAPIC_BASE + IOAPIC_SIZE
            && address
                .checked_add(size)
                .is_none_or(|end| end > IOAPIC_BASE)
    }

    fn ioapic_access(&self, address: u64, size: usize) -> Result<Option<MutexGuard<'_, IoApic>>> {
        if !self.overlaps_ioapic(address, size as u64) {
            return Ok(None);
        }
        if address < IOAPIC_BASE
            || address
                .checked_add(size as u64)
                .is_none_or(|end| end > IOAPIC_BASE + IOAPIC_SIZE)
        {
            return Err(Error::Emulator(
                "access crosses the I/O APIC boundary".into(),
            ));
        }
        let controller = self
            .shared_ioapic
            .as_ref()
            .ok_or_else(|| Error::Emulator("I/O APIC binding is missing".into()))?;
        controller
            .lock()
            .map(Some)
            .map_err(|_| Error::Emulator("I/O APIC MMIO lock poisoned".into()))
    }

    pub(super) fn read_shared_ioapic(&self, address: u64, data: &mut [u8]) -> Result<bool> {
        let Some(mut controller) = self.ioapic_access(address, data.len())? else {
            return Ok(false);
        };
        controller.read(address, data);
        Ok(true)
    }

    pub(super) fn write_shared_ioapic(&self, address: u64, data: &[u8]) -> Result<bool> {
        let Some(mut controller) = self.ioapic_access(address, data.len())? else {
            return Ok(false);
        };
        controller.write(address, data);
        Ok(true)
    }
}

#[cfg(all(test, target_pointer_width = "64"))]
mod tests {
    use super::*;
    use crate::vm::vcpu::SystemRegisters;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn mapped() -> (Mmu, Arc<Mutex<IoApic>>) {
        // A contiguous mapping exercises the typed RAM shortcut as well as
        // read_phys/write_phys. Only the sentinel pages are committed.
        let memory = Arc::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), IOAPIC_BASE as usize + 4096)])
                .unwrap(),
        );
        memory
            .write_obj(0x1234_5678u32, GuestAddress(IOAPIC_BASE + 16))
            .unwrap();
        let mut mmu = Mmu::new(memory);
        let controller = Arc::new(Mutex::new(IoApic::new()));
        mmu.attach_ioapic(controller.clone());
        (mmu, controller)
    }

    #[test]
    fn typed_accesses_use_the_owned_controller_instead_of_contiguous_ram() {
        let (mut mmu, controller) = mapped();
        let registers = SystemRegisters::default();
        mmu.write_u32(IOAPIC_BASE, 1, &registers).unwrap();
        assert_eq!(mmu.read_u8(IOAPIC_BASE + 16, &registers).unwrap(), 0x20);
        assert_eq!(mmu.read_u16(IOAPIC_BASE + 16, &registers).unwrap(), 0x20);
        assert_eq!(
            mmu.read_u32(IOAPIC_BASE + 16, &registers).unwrap(),
            0x0017_0020
        );
        assert_eq!(
            mmu.read_u64(IOAPIC_BASE + 16, &registers).unwrap(),
            0x0017_0020
        );
        mmu.write_u8(IOAPIC_BASE, 0, &registers).unwrap();
        mmu.write_u32(IOAPIC_BASE + 16, 0x0f00_0000, &registers)
            .unwrap();
        assert_eq!(controller.lock().unwrap().apic_id(), 15);
        assert_eq!(
            mmu.memory
                .read_obj::<u32>(GuestAddress(IOAPIC_BASE + 16))
                .unwrap(),
            0x1234_5678
        );

        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            assert!(!mmu.read_range_is_plain_ram(IOAPIC_BASE + 16, 4, &registers));
            assert!(!mmu.write_range_is_plain_ram(IOAPIC_BASE + 16, 4, &registers));
            assert!(!mmu.read_range_is_plain_ram(IOAPIC_BASE - 1, 2, &registers));
            assert!(mmu.read_range_is_plain_ram(0x2000, 8, &registers));
        }
    }

    #[test]
    fn straddling_accesses_preserve_the_entire_buffer_ram_and_controller() {
        let (mmu, controller) = mapped();
        mmu.write_phys(IOAPIC_BASE, &1u32.to_le_bytes()).unwrap();
        for address in [IOAPIC_BASE - 1, IOAPIC_BASE + IOAPIC_SIZE - 1] {
            mmu.memory
                .write_slice(&[0xa5; 2], GuestAddress(address))
                .unwrap();
            let mut output = [0x5a; 2];
            assert!(mmu.read_phys(address, &mut output).is_err());
            assert_eq!(output, [0x5a; 2]);
            assert!(mmu.write_phys(address, &[0xff; 2]).is_err());
            let mut backing = [0; 2];
            mmu.memory
                .read_slice(&mut backing, GuestAddress(address))
                .unwrap();
            assert_eq!(backing, [0xa5; 2]);
            let mut select = [0; 4];
            controller.lock().unwrap().read(IOAPIC_BASE, &mut select);
            assert_eq!(u32::from_le_bytes(select), 1);
        }
    }
}
