//! Architectural memory access helpers for the Sv39 integration.

use super::sv39::{Access, PAGE_SIZE, SATP_MODE_SHIFT, SATP_MODE_SV39, Sv39};
use super::{Insn, Priv, RiscVCpu, Trap, Xlen, decode_with_parcel_fetch};
use crate::isa::riscv::csr::SATP;

const MSTATUS_MPP_SHIFT: u32 = 11;
const MSTATUS_MPRV: u64 = 1 << 17;
const MSTATUS_SUM: u64 = 1 << 18;
const MSTATUS_MXR: u64 = 1 << 19;
const CACHE_BLOCK_SIZE: usize = 64;
const CACHE_BLOCK_MASK: u64 = !(CACHE_BLOCK_SIZE as u64 - 1);

impl RiscVCpu {
    pub(super) fn supplies_sv39(&self) -> bool {
        self.cfg.xlen == Xlen::Rv64 && !self.cfg.isa.xsoteria && self.mem.supports_sv39()
    }

    pub(super) fn satp(&self) -> u64 {
        if self.supplies_sv39() {
            return self.ext_csr.get(&SATP).copied().unwrap_or(0);
        }
        0
    }

    pub(super) fn write_satp(&mut self, value: u64) {
        if !self.supplies_sv39() {
            return;
        }
        match value >> SATP_MODE_SHIFT {
            0 => {
                self.ext_csr.remove(&SATP);
            }
            SATP_MODE_SV39 => {
                self.ext_csr.insert(SATP, value);
            }
            _ => {}
        }
    }

    pub(super) fn active_translation(&self, access: Access) -> Option<Sv39> {
        let satp = self.ext_csr.get(&SATP).copied()?;
        if satp >> SATP_MODE_SHIFT != SATP_MODE_SV39 || !self.supplies_sv39() {
            return None;
        }
        let privilege = match (self.priv_, self.mstatus & MSTATUS_MPRV != 0, access) {
            (Priv::Machine, true, Access::Load | Access::Store | Access::CacheManagement) => {
                match (self.mstatus >> MSTATUS_MPP_SHIFT) & 3 {
                    0 => Priv::User,
                    1 => Priv::Supervisor,
                    _ => Priv::Machine,
                }
            }
            _ => self.priv_,
        };
        (privilege != Priv::Machine).then_some(Sv39 {
            satp,
            privilege,
            sum: self.mstatus & MSTATUS_SUM != 0,
            mxr: self.mstatus & MSTATUS_MXR != 0,
        })
    }

    pub(super) fn data_address(
        &mut self,
        virtual_address: u64,
        access: Access,
    ) -> Result<u64, Trap> {
        match self.active_translation(access) {
            Some(state) => state.translate(self.mem.as_mut(), virtual_address, access),
            None => Ok(virtual_address),
        }
    }

    pub(super) fn load_bytes(&mut self, address: u64, mut data: &mut [u8]) -> Result<(), Trap> {
        let Some(state) = self.active_translation(Access::Load) else {
            return self
                .mem
                .read(address, data)
                .map_err(|_| Access::Load.access_fault(address));
        };
        let mut next = address;
        while !data.is_empty() {
            let size = page_extent(next, data.len());
            let (chunk, rest) = data.split_at_mut(size);
            let physical = state.translate(self.mem.as_mut(), next, Access::Load)?;
            self.mem
                .read(physical, chunk)
                .map_err(|_| Access::Load.access_fault(next))?;
            next = next.wrapping_add(size as u64);
            data = rest;
        }
        Ok(())
    }

    pub(super) fn load_value(&mut self, address: u64, size: usize) -> Result<u64, Trap> {
        let mut data = [0; 8];
        self.load_bytes(address, &mut data[..size])?;
        Ok(u64::from_le_bytes(data))
    }

    pub(super) fn store_bytes(&mut self, address: u64, mut data: &[u8]) -> Result<(), Trap> {
        let Some(state) = self.active_translation(Access::Store) else {
            return self
                .mem
                .write(address, data)
                .map_err(|_| Access::Store.access_fault(address));
        };
        let mut next = address;
        while !data.is_empty() {
            let size = page_extent(next, data.len());
            let (chunk, rest) = data.split_at(size);
            let physical = state.translate(self.mem.as_mut(), next, Access::Store)?;
            self.mem
                .write(physical, chunk)
                .map_err(|_| Access::Store.access_fault(next))?;
            next = next.wrapping_add(size as u64);
            data = rest;
        }
        Ok(())
    }

    pub(super) fn fetch_instruction_parcels(&mut self, pc: u64) -> Result<Insn, Trap> {
        let cfg = self.cfg;
        let access = Access::Fetch;
        let Some(state) = self.active_translation(access) else {
            return decode_with_parcel_fetch(pc, cfg.xlen, &cfg.isa, |address| {
                self.mem
                    .fetch_u16(address)
                    .map_err(|_| access.access_fault(address))
            });
        };

        let first_physical = state.translate(self.mem.as_mut(), pc, access)?;
        decode_with_parcel_fetch(pc, cfg.xlen, &cfg.isa, |address| {
            let physical = if address / PAGE_SIZE == pc / PAGE_SIZE {
                // Both parcels in one page have the same mapping and permissions.
                // The translation belongs to this instruction only.
                (first_physical & !(PAGE_SIZE - 1)) | (address & (PAGE_SIZE - 1))
            } else {
                state.translate(self.mem.as_mut(), address, access)?
            };
            self.read_translated_parcel(physical, address)
        })
    }

    pub(super) fn manage_cache_block(&mut self, address: u64) -> Result<(), Trap> {
        let access = Access::CacheManagement;
        if let Some(state) = self.active_translation(access) {
            let physical = state.translate(self.mem.as_mut(), address, access)? & CACHE_BLOCK_MASK;
            self.mem
                .probe_cache_block(physical, CACHE_BLOCK_SIZE, false)
                .map_err(|_| access.access_fault(address))?;
        }
        Ok(())
    }

    pub(super) fn zero_cache_block(&mut self, address: u64) -> Result<(), Trap> {
        if let Some(state) = self.active_translation(Access::Store) {
            let physical =
                state.translate(self.mem.as_mut(), address, Access::Store)? & CACHE_BLOCK_MASK;
            self.mem
                .probe_cache_block(physical, CACHE_BLOCK_SIZE, true)
                .and_then(|()| self.mem.write(physical, &[0; CACHE_BLOCK_SIZE]))
                .map_err(|_| Access::Store.access_fault(address))
        } else {
            self.store_bytes(address & CACHE_BLOCK_MASK, &[0; CACHE_BLOCK_SIZE])
        }
    }

    pub(super) fn inspect_instruction(&self, address: u64) -> Result<Insn, Trap> {
        decode_with_parcel_fetch(address, self.cfg.xlen, &self.cfg.isa, |parcel| {
            self.inspect_parcel(parcel)
        })
    }

    fn inspect_parcel(&self, address: u64) -> Result<u16, Trap> {
        if let Some(state) = self.active_translation(Access::Fetch) {
            let physical = state.inspect_fetch(self.mem.as_ref(), address)?;
            return self.read_translated_parcel(physical, address);
        }
        self.mem
            .fetch_u16(address)
            .map_err(|_| Access::Fetch.access_fault(address))
    }

    fn read_translated_parcel(&self, physical: u64, virtual_address: u64) -> Result<u16, Trap> {
        let mut bytes = [0; 2];
        self.mem
            .read_translated_fetch(physical, &mut bytes)
            .map_err(|_| Access::Fetch.access_fault(virtual_address))?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub(super) fn fetch_table_entry(&mut self, address: u64, size: usize) -> Result<u64, Trap> {
        let mut bytes = [0; 8];
        let data = &mut bytes[..size];
        let result = if let Some(state) = self.active_translation(Access::Fetch) {
            let physical = state.translate(self.mem.as_mut(), address, Access::Fetch)?;
            self.mem.read_translated_fetch(physical, data)
        } else {
            self.mem.read(address, data)
        };
        result.map_err(|_| Access::Fetch.access_fault(address))?;
        Ok(u64::from_le_bytes(bytes))
    }
}

fn page_extent(address: u64, remaining: usize) -> usize {
    let offset = address & (PAGE_SIZE - 1);
    remaining.min((PAGE_SIZE - offset) as usize)
}
