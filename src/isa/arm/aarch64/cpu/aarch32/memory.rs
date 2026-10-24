//! Checked AArch32 scalar memory through the enclosing PE's memory plane.

use std::cell::{Cell, RefCell};

use crate::isa::arm::aarch32::cpu::{ArmMemory, MemoryError};
use crate::isa::arm::aarch32::instructions::{ExclusiveAccess, ExclusiveMonitor};
use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::common::cpu::{AccessType, ArmError, MemoryFaultInfo, MemoryFaultType};

pub(super) struct Aarch32Memory<'a> {
    cpu: &'a mut AArch64Cpu,
    pub fault: RefCell<Option<ArmError>>,
    pub access: Option<ExclusiveAccess>,
    pub exclusive_failed: bool,
    read_cache: Cell<Option<u64>>,
    read_pa: Cell<Option<u64>>,
    read_performed: Cell<bool>,
    write_checked: bool,
    write_complete: bool,
}

impl<'a> Aarch32Memory<'a> {
    pub fn new(cpu: &'a mut AArch64Cpu) -> Self {
        Self {
            cpu,
            fault: RefCell::new(None),
            access: None,
            exclusive_failed: false,
            read_cache: Cell::new(None),
            read_pa: Cell::new(None),
            read_performed: Cell::new(false),
            write_checked: false,
            write_complete: false,
        }
    }

    pub fn preflight(
        &self,
        instruction: &crate::isa::arm::decoder::DecodedInsn,
    ) -> Result<(), ArmError> {
        self.cpu.check_aarch32_instruction(instruction)
    }

    fn result<T>(&self, address: u32, result: Result<T, ArmError>) -> Result<T, MemoryError> {
        result.map_err(|error| {
            *self.fault.borrow_mut() = Some(error);
            MemoryError::OutOfBounds(address)
        })
    }

    fn swap(&self) -> bool {
        self.cpu.aarch32.is_some_and(|state| state.e) != self.cpu.memory.is_big_endian()
    }

    fn exclusive_read(&self) -> Result<(), MemoryError> {
        if let Some(access) = self.access.filter(|access| access.status.is_none()) {
            if self.read_pa.get().is_none() {
                let result = self
                    .cpu
                    .translate_address(u64::from(access.address), false, false);
                self.read_pa.set(Some(self.result(access.address, result)?));
            }
            self.read_performed.set(true);
        }
        Ok(())
    }

    fn exclusive_write(&mut self) -> Result<bool, MemoryError> {
        if let Some(access) = self.access.filter(|access| access.status.is_some()) {
            if !self.write_checked {
                let result = self
                    .cpu
                    .translate_address(u64::from(access.address), true, false);
                let pa = self.result(access.address, result)?;
                self.exclusive_failed = !self.cpu.memory.check_exclusive(pa, access.size);
                self.write_checked = true;
            }
            return Ok(!self.exclusive_failed);
        }
        Ok(true)
    }

    pub fn finish(&mut self, monitor: &mut ExclusiveMonitor, successful: bool, clear: bool) {
        if let Some(access) = self.access {
            if access.status.is_some() || !successful {
                self.cpu.memory.clear_exclusive();
                monitor.clear();
            } else if self.read_performed.get() {
                if let Some(pa) = self.read_pa.get() {
                    self.cpu.memory.mark_exclusive(pa, access.size);
                }
            }
        } else if clear {
            self.cpu.memory.clear_exclusive();
        }
    }
}

impl ArmMemory for Aarch32Memory<'_> {
    fn read_word(&self, address: u32) -> Result<u32, MemoryError> {
        self.exclusive_read()?;
        if let Some(access) = self
            .access
            .filter(|access| access.status.is_none() && access.size == 8)
        {
            let value = if let Some(value) = self.read_cache.get() {
                value
            } else {
                let result = self.cpu.mem_read_u64(u64::from(access.address));
                let raw = self.result(access.address, result)?;
                let value = if self.swap() { raw.swap_bytes() } else { raw };
                self.read_cache.set(Some(value));
                value
            };
            let high = (address != access.address) != self.cpu.aarch32.is_some_and(|state| state.e);
            return Ok(if high {
                (value >> 32) as u32
            } else {
                value as u32
            });
        }
        let result = self.cpu.mem_read_u32(u64::from(address));
        self.result(address, result).map(|value| {
            if self.swap() {
                value.swap_bytes()
            } else {
                value
            }
        })
    }
    fn read_halfword(&self, address: u32) -> Result<u16, MemoryError> {
        self.exclusive_read()?;
        let result = self.cpu.mem_read_u16(u64::from(address));
        self.result(address, result).map(|value| {
            if self.swap() {
                value.swap_bytes()
            } else {
                value
            }
        })
    }
    fn read_byte(&self, address: u32) -> Result<u8, MemoryError> {
        self.exclusive_read()?;
        self.result(address, self.cpu.mem_read_u8(u64::from(address)))
    }
    fn write_word(&mut self, address: u32, value: u32) -> Result<(), MemoryError> {
        if !self.exclusive_write()? {
            return Ok(());
        }
        if let Some(access) = self
            .access
            .filter(|access| access.status.is_some() && access.size == 8)
        {
            if self.write_complete {
                return Ok(());
            }
            let value = if self.swap() {
                access.value.swap_bytes()
            } else {
                access.value
            };
            let result = self.cpu.mem_write_u64(u64::from(access.address), value);
            self.result(access.address, result)?;
            self.write_complete = true;
            return Ok(());
        }
        let value = if self.swap() {
            value.swap_bytes()
        } else {
            value
        };
        let result = self.cpu.mem_write_u32(u64::from(address), value);
        self.result(address, result)
    }
    fn write_halfword(&mut self, address: u32, value: u16) -> Result<(), MemoryError> {
        if !self.exclusive_write()? {
            return Ok(());
        }
        let value = if self.swap() {
            value.swap_bytes()
        } else {
            value
        };
        let result = self.cpu.mem_write_u16(u64::from(address), value);
        self.result(address, result)
    }
    fn write_byte(&mut self, address: u32, value: u8) -> Result<(), MemoryError> {
        if !self.exclusive_write()? {
            return Ok(());
        }
        let result = self.cpu.mem_write_u8(u64::from(address), value);
        self.result(address, result)
    }
    fn allows_unaligned(&self) -> bool {
        true
    }
}

pub(super) fn architectural_error(error: MemoryError, access: AccessType) -> ArmError {
    let (address, fault_type) = match error {
        MemoryError::Unaligned(address) => (address, MemoryFaultType::Alignment),
        MemoryError::OutOfBounds(address) => (address, MemoryFaultType::Translation),
        MemoryError::PermissionDenied(address) => (address, MemoryFaultType::Permission),
        MemoryError::BusError(address) => (address, MemoryFaultType::External),
    };
    ArmError::MemoryError(MemoryFaultInfo {
        address: u64::from(address),
        access,
        fault_type,
        stage2: false,
    })
}
