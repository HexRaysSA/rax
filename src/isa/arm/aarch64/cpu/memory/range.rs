//! Scalar virtual accesses, split only at an actual mapping boundary.

#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
mod tests;

use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::aarch64::mmu::MemoryType;
use crate::isa::arm::aarch64::sctlr;
use crate::isa::arm::common::cpu::{AccessType, ArmError, MemoryFaultInfo, MemoryFaultType};

impl AArch64Cpu {
    fn check_data_alignment(
        &self,
        va: u64,
        width: usize,
        device_memory: bool,
        write: bool,
    ) -> Result<(), ArmError> {
        let controls = self.pauth_controls();
        let required = controls.sctlr[controls.regime_el()] & sctlr::A != 0
            || self.memory.requires_alignment()
            || device_memory;
        if required && va & (width as u64 - 1) != 0 {
            return Err(ArmError::MemoryError(MemoryFaultInfo {
                address: va,
                access: if write {
                    AccessType::Write
                } else {
                    AccessType::Read
                },
                fault_type: MemoryFaultType::Alignment,
                stage2: false,
            }));
        }
        Ok(())
    }

    fn read_scalar(&self, va: u64, pa: u64, width: usize) -> Result<u64, ArmError> {
        let result = match width {
            1 => self.memory.read_u8(pa).map(u64::from),
            2 => self.memory.read_u16(pa).map(u64::from),
            4 => self.memory.read_u32(pa).map(u64::from),
            8 => self.memory.read_u64(pa),
            _ => {
                return Err(ArmError::Internal(
                    "unsupported scalar read width".to_string(),
                ));
            }
        };
        result.map_err(|error| self.physical_memory_error(error, va, pa, width, AccessType::Read))
    }

    pub(super) fn read_data_value(
        &self,
        va: u64,
        width: usize,
        privileged: bool,
    ) -> Result<u64, ArmError> {
        if !matches!(width, 1 | 2 | 4 | 8) {
            return Err(ArmError::Internal(
                "unsupported scalar read width".to_string(),
            ));
        }
        // SCTLR.A applies before address translation (AArch64.CheckAlignment).
        self.check_data_alignment(va, width, false, false)?;
        let (mut mapping, mut span) = self.translate_address_span(va, false, false, privileged)?;
        self.check_data_alignment(
            va,
            width,
            matches!(mapping.attributes.mem_type, MemoryType::Device(_)),
            false,
        )?;
        let available = span - (va & (span - 1));
        if !self.mmu.is_enabled() || width as u64 <= available {
            return self.read_scalar(va, mapping.pa, width);
        }

        let mut bytes = [0; 8];
        let mut done = 0;
        while done < width {
            let current = va.wrapping_add(done as u64);
            if done != 0 {
                (mapping, span) = self.translate_address_span(current, false, false, privileged)?;
                self.check_data_alignment(
                    va,
                    width,
                    matches!(mapping.attributes.mem_type, MemoryType::Device(_)),
                    false,
                )?;
            }
            let count = (width - done).min((span - (current & (span - 1))) as usize);
            self.memory
                .read(mapping.pa, &mut bytes[done..done + count])
                .map_err(|error| {
                    self.physical_memory_error(error, current, mapping.pa, count, AccessType::Read)
                })?;
            done += count;
        }
        if self.memory.is_big_endian() {
            let mut padded = [0; 8];
            padded[8 - width..].copy_from_slice(&bytes[..width]);
            Ok(u64::from_be_bytes(padded))
        } else {
            Ok(u64::from_le_bytes(bytes))
        }
    }

    fn write_scalar(&mut self, va: u64, pa: u64, width: usize, value: u64) -> Result<(), ArmError> {
        let result = match width {
            1 => self.memory.write_u8(pa, value as u8),
            2 => self.memory.write_u16(pa, value as u16),
            4 => self.memory.write_u32(pa, value as u32),
            8 => self.memory.write_u64(pa, value),
            _ => {
                return Err(ArmError::Internal(
                    "unsupported scalar write width".to_string(),
                ));
            }
        };
        result
            .map_err(|error| self.physical_memory_error(error, va, pa, width, AccessType::Write))?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.note_data_write(va, width);
        Ok(())
    }

    pub(super) fn write_data_value(
        &mut self,
        va: u64,
        value: u64,
        width: usize,
        privileged: bool,
    ) -> Result<(), ArmError> {
        if !matches!(width, 1 | 2 | 4 | 8) {
            return Err(ArmError::Internal(
                "unsupported scalar write width".to_string(),
            ));
        }
        self.check_data_alignment(va, width, false, true)?;
        let (mut mapping, mut span) = self.translate_address_span(va, true, false, privileged)?;
        self.check_data_alignment(
            va,
            width,
            matches!(mapping.attributes.mem_type, MemoryType::Device(_)),
            true,
        )?;
        let available = span - (va & (span - 1));
        if !self.mmu.is_enabled() || width as u64 <= available {
            return self.write_scalar(va, mapping.pa, width, value);
        }

        let bytes = if self.memory.is_big_endian() {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        let bytes = if self.memory.is_big_endian() {
            &bytes[8 - width..]
        } else {
            &bytes[..width]
        };
        let mut done = 0;
        while done < width {
            let current = va.wrapping_add(done as u64);
            if done != 0 {
                (mapping, span) = self.translate_address_span(current, true, false, privileged)?;
                self.check_data_alignment(
                    va,
                    width,
                    matches!(mapping.attributes.mem_type, MemoryType::Device(_)),
                    true,
                )?;
            }
            let count = (width - done).min((span - (current & (span - 1))) as usize);
            // Ordinary unaligned stores can complete an earlier range before a
            // later range faults. This is not an atomic transaction primitive.
            self.memory
                .write(mapping.pa, &bytes[done..done + count])
                .map_err(|error| {
                    self.physical_memory_error(error, current, mapping.pa, count, AccessType::Write)
                })?;
            #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
            self.note_data_write(current, count);
            done += count;
        }
        Ok(())
    }

    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    fn note_data_write(&mut self, va: u64, width: usize) {
        let start = self.effective_data_address(va, self.current_el);
        let end = self.effective_data_address(va.wrapping_add(width as u64 - 1), self.current_el);
        self.jit_note_write(start);
        if start >> 12 != end >> 12 {
            self.jit_note_write(end);
        }
    }
}
