//! Checked AArch32 scalar memory through the enclosing PE's memory plane.

use std::cell::{Cell, RefCell};

use crate::isa::arm::aarch32::cpu::{ArmMemory, MemoryError};
use crate::isa::arm::aarch32::instructions::{ExclusiveAccess, ExclusiveMonitor};
use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::common::cpu::{AccessType, ArmError, MemoryFaultInfo, MemoryFaultType};

pub(super) struct Aarch32Memory<'a> {
    cpu: RefCell<&'a mut AArch64Cpu>,
    pub fault: RefCell<Option<ArmError>>,
    pub access: Option<ExclusiveAccess>,
    pub exclusive_failed: bool,
    read_cache: Cell<Option<u64>>,
    write_complete: bool,
}

impl<'a> Aarch32Memory<'a> {
    pub fn new(cpu: &'a mut AArch64Cpu) -> Self {
        Self {
            cpu: RefCell::new(cpu),
            fault: RefCell::new(None),
            access: None,
            exclusive_failed: false,
            read_cache: Cell::new(None),
            write_complete: false,
        }
    }

    pub fn preflight(
        &self,
        instruction: &crate::isa::arm::decoder::DecodedInsn,
    ) -> Result<(), ArmError> {
        self.cpu.borrow().check_aarch32_instruction(instruction)
    }

    fn result<T>(&self, address: u32, result: Result<T, ArmError>) -> Result<T, MemoryError> {
        result.map_err(|error| {
            *self.fault.borrow_mut() = Some(error);
            MemoryError::OutOfBounds(address)
        })
    }

    fn big_endian(&self) -> bool {
        self.cpu.borrow().aarch32.is_some_and(|state| state.e)
    }

    fn swap(&self) -> bool {
        self.big_endian() != self.cpu.borrow().memory.is_big_endian()
    }

    /// Read and reserve in one physical transaction. The instruction executor
    /// reaches this method only after its operand/alignment admission checks.
    fn exclusive_read(&self) -> Result<Option<u64>, MemoryError> {
        let Some(access) = self.access.filter(|access| access.status.is_none()) else {
            return Ok(None);
        };
        if let Some(value) = self.read_cache.get() {
            return Ok(Some(value));
        }
        let result = (|| {
            let mut cpu = self.cpu.borrow_mut();
            let pa = cpu.translate_address(u64::from(access.address), false, false)?;
            cpu.memory
                .read_exclusive(pa, usize::from(access.size))
                .map_err(ArmError::from)
        })();
        let data = self.result(access.address, result)?;
        let mut bytes = [0; 8];
        let value = if self.big_endian() {
            bytes[8 - data.len()..].copy_from_slice(&data);
            u64::from_be_bytes(bytes)
        } else {
            bytes[..data.len()].copy_from_slice(&data);
            u64::from_le_bytes(bytes)
        };
        self.read_cache.set(Some(value));
        Ok(Some(value))
    }

    /// Perform the complete conditional write once, including doublewords.
    /// The local executor monitor remains an additional admission condition.
    fn exclusive_write(&mut self) -> Result<bool, MemoryError> {
        let Some(access) = self.access.filter(|access| access.status.is_some()) else {
            return Ok(false);
        };
        if !self.write_complete {
            let bytes = if self.big_endian() {
                access.value.to_be_bytes()
            } else {
                access.value.to_le_bytes()
            };
            let data = if self.big_endian() {
                &bytes[8 - usize::from(access.size)..]
            } else {
                &bytes[..usize::from(access.size)]
            };
            let result = (|| {
                let mut cpu = self.cpu.borrow_mut();
                let pa = cpu.translate_address(u64::from(access.address), true, false)?;
                cpu.memory.write_exclusive(pa, data).map_err(ArmError::from)
            })();
            self.exclusive_failed = !self.result(access.address, result)?;
            self.write_complete = true;
        }
        Ok(true)
    }

    pub fn finish(&mut self, monitor: &mut ExclusiveMonitor, successful: bool, clear: bool) {
        if let Some(access) = self.access {
            if access.status.is_some() || !successful {
                self.cpu.borrow_mut().memory.clear_exclusive();
                monitor.clear();
            }
            // A successful load has already established its physical lease.
            // Re-marking here could resurrect a lease invalidated by a writer.
        } else if clear {
            self.cpu.borrow_mut().memory.clear_exclusive();
        }
    }
}

impl ArmMemory for Aarch32Memory<'_> {
    fn read_word(&self, address: u32) -> Result<u32, MemoryError> {
        if let Some(value) = self.exclusive_read()? {
            let access = self.access.unwrap();
            let high = access.size == 8 && ((address != access.address) != self.big_endian());
            return Ok(if high {
                (value >> 32) as u32
            } else {
                value as u32
            });
        }
        let result = self.cpu.borrow().mem_read_u32(u64::from(address));
        self.result(address, result).map(|value| {
            if self.swap() {
                value.swap_bytes()
            } else {
                value
            }
        })
    }
    fn read_halfword(&self, address: u32) -> Result<u16, MemoryError> {
        if let Some(value) = self.exclusive_read()? {
            return Ok(value as u16);
        }
        let result = self.cpu.borrow().mem_read_u16(u64::from(address));
        self.result(address, result).map(|value| {
            if self.swap() {
                value.swap_bytes()
            } else {
                value
            }
        })
    }
    fn read_byte(&self, address: u32) -> Result<u8, MemoryError> {
        if let Some(value) = self.exclusive_read()? {
            return Ok(value as u8);
        }
        let result = self.cpu.borrow().mem_read_u8(u64::from(address));
        self.result(address, result)
    }
    fn write_word(&mut self, address: u32, value: u32) -> Result<(), MemoryError> {
        if self.exclusive_write()? {
            return Ok(());
        }
        let value = if self.swap() {
            value.swap_bytes()
        } else {
            value
        };
        let result = self
            .cpu
            .borrow_mut()
            .mem_write_u32(u64::from(address), value);
        self.result(address, result)
    }
    fn write_halfword(&mut self, address: u32, value: u16) -> Result<(), MemoryError> {
        if self.exclusive_write()? {
            return Ok(());
        }
        let value = if self.swap() {
            value.swap_bytes()
        } else {
            value
        };
        let result = self
            .cpu
            .borrow_mut()
            .mem_write_u16(u64::from(address), value);
        self.result(address, result)
    }
    fn write_byte(&mut self, address: u32, value: u8) -> Result<(), MemoryError> {
        if self.exclusive_write()? {
            return Ok(());
        }
        let result = self
            .cpu
            .borrow_mut()
            .mem_write_u8(u64::from(address), value);
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
