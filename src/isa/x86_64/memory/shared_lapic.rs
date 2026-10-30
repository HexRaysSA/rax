//! VM-owned local APIC dispatch; standalone MMUs retain their inline controller.
use std::sync::{Arc, Mutex};

use crate::devices::lapic::LocalApic;
use crate::error::{Error, Result};

use super::{LAPIC_BASE, Mmu};

impl Mmu {
    /// Seed a fresh standalone controller only; restored current IDs remain intact.
    pub(in crate::isa::x86_64) fn new_for_cpu(
        memory: Arc<vm_memory::GuestMemoryMmap>,
        id: u32,
    ) -> Self {
        let mmu = Self::new(memory);
        mmu.lapic.borrow_mut().id = (id & 255) << 24;
        mmu
    }

    pub(in crate::isa::x86_64) fn import_cr8(&self, value: u64) -> Result<()> {
        let tpr = crate::devices::lapic::priority::import_value(self.task_priority()?, value)
            .ok_or_else(|| Error::InvalidConfig("invalid CR8/TPR priority projection".into()))?;
        self.set_task_priority(tpr)
    }
    pub(crate) fn attach_local_apic(&mut self, lapic: Arc<Mutex<LocalApic>>) {
        self.shared_priority = lapic.lock().ok().map(|v| v.priority_handle());
        self.shared_lapic = Some(lapic);
    }

    pub(in crate::isa::x86_64) fn task_priority(&self) -> Result<u32> {
        if let Some(priority) = &self.shared_priority {
            let value = priority.load();
            return if value <= 255 {
                Ok(value)
            } else {
                Err(Error::InvalidConfig(
                    "local APIC TPR has reserved bits".into(),
                ))
            };
        }
        if self.shared_lapic.is_some() {
            return Err(Error::Emulator(
                "local APIC priority binding unavailable".into(),
            ));
        }
        let value = self.lapic.borrow().tpr.load();
        if value > 255 {
            return Err(Error::InvalidConfig(
                "inline APIC TPR has reserved bits".into(),
            ));
        }
        Ok(value)
    }
    pub(in crate::isa::x86_64) fn set_task_priority(&self, value: u32) -> Result<()> {
        if let Some(priority) = &self.shared_priority {
            priority.store(value & 0xff);
            return Ok(());
        }
        if self.shared_lapic.is_some() {
            return Err(Error::Emulator(
                "local APIC priority binding unavailable".into(),
            ));
        }
        self.lapic.borrow().tpr.store(value & 0xff);
        Ok(())
    }

    pub(super) fn read_shared_lapic(&self, address: u64, data: &mut [u8]) -> Result<bool> {
        let Some(controller) = self
            .shared_lapic
            .as_ref()
            .filter(|_| Self::is_lapic_addr(address))
        else {
            return Ok(false);
        };
        let lapic = controller
            .lock()
            .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?;
        let offset = address - LAPIC_BASE;
        let register = offset & !3;
        let value = lapic.read_register(register);
        match data.len() {
            1 => data[0] = (value >> ((offset & 3) * 8)) as u8,
            2 => data.copy_from_slice(&((value >> ((offset & 2) * 8)) as u16).to_le_bytes()),
            4 => data.copy_from_slice(&value.to_le_bytes()),
            8 => {
                // Preserve the existing software MMU's paired-register access.
                // Architectural xAPIC software uses aligned 32-bit accesses.
                data[..4].copy_from_slice(&value.to_le_bytes());
                data[4..].copy_from_slice(&lapic.read_register(register + 0x10).to_le_bytes());
            }
            _ => data.fill(0),
        }
        Ok(true)
    }

    pub(super) fn write_shared_lapic(&self, address: u64, data: &[u8]) -> Result<bool> {
        let Some(controller) = self
            .shared_lapic
            .as_ref()
            .filter(|_| Self::is_lapic_addr(address))
        else {
            return Ok(false);
        };
        let mut lapic = controller
            .lock()
            .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?;
        let register = (address - LAPIC_BASE) & !3;
        let value = match data.len() {
            1 => u32::from(data[0]),
            2 => u32::from(u16::from_le_bytes([data[0], data[1]])),
            4 => u32::from_le_bytes(data.try_into().expect("four-byte LAPIC value")),
            8 => {
                lapic.write_register(
                    register,
                    u32::from_le_bytes(data[..4].try_into().expect("four-byte low value")),
                );
                lapic.write_register(
                    register + 0x10,
                    u32::from_le_bytes(data[4..].try_into().expect("four-byte high value")),
                );
                return Ok(true);
            }
            _ => return Ok(true),
        };
        lapic.write_register(register, value);
        Ok(true)
    }
}
