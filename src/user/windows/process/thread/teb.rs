//! Host-owned allocation identity for ordinary and companion TEB views.

use crate::user::windows::arch::WinArch;
use crate::user::windows::layout;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::process::Proc;

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

#[cfg(test)]
mod tests;

#[derive(Debug, Default)]
pub(crate) struct Arena {
    parent: Option<Arc<str>>,
    slots: BTreeMap<u64, (u64, Weak<()>)>,
}

#[derive(Clone, Debug)]
pub(crate) struct Allocation {
    base: u64,
    bytes: u64,
    pub(crate) teb: u64,
    companion: Option<u64>,
    claim: Option<Arc<()>>,
    owner: Option<Arc<str>>,
}

impl Allocation {
    #[cfg(test)]
    pub(crate) fn single(base: u64, bytes: u64) -> Self {
        Self {
            base,
            bytes,
            teb: base,
            companion: None,
            claim: None,
            owner: None,
        }
    }

    pub(crate) fn allocate(p: &mut Proc) -> Result<Self, u32> {
        let companion = p.wow64.is_some();
        let native_bytes = if companion {
            layout::teb_stride(WinArch::X64)
        } else {
            0
        };
        let bytes = native_bytes + layout::teb_stride(p.arch);
        p.teb_arena
            .slots
            .retain(|_, (_, token)| token.strong_count() != 0);
        let owner =
            p.vm.allocation(layout::SYSTEM_AREA)
                .filter(|allocation| allocation.base == layout::SYSTEM_AREA)
                .and_then(|allocation| allocation.name.clone())
                .ok_or(STATUS_NO_MEMORY)?;
        if let Some(parent) = &p.teb_arena.parent {
            if !Arc::ptr_eq(parent, &owner) {
                return Err(STATUS_NO_MEMORY);
            }
        } else {
            p.teb_arena.parent = Some(owner.clone());
        }
        let mut base = layout::PEB_ADDRESS
            .checked_sub(bytes)
            .ok_or(STATUS_NO_MEMORY)?;
        while base >= layout::SYSTEM_AREA {
            let occupied = p
                .teb_arena
                .slots
                .range(..base + bytes)
                .next_back()
                .is_some_and(|(&start, (length, _))| start + length > base);
            if !occupied
                && p.vm
                    .query(base)
                    .is_some_and(|region| region.state == mem::RESERVE && region.size >= bytes)
            {
                p.vm.commit(base, bytes, prot::READWRITE)
                    .map_err(|error| error.status())?;
                let claim = Arc::new(());
                p.teb_arena
                    .slots
                    .insert(base, (bytes, Arc::downgrade(&claim)));
                return Ok(Self {
                    base,
                    bytes,
                    teb: base + native_bytes,
                    companion: companion.then_some(base),
                    claim: Some(claim),
                    owner: Some(owner),
                });
            }
            base = base.checked_sub(bytes).ok_or(STATUS_NO_MEMORY)?;
        }
        Err(STATUS_NO_MEMORY)
    }

    pub(crate) fn initialize_companion(
        &self,
        p: &Proc,
        tid: u32,
        stack_base: u64,
        stack_limit: u64,
        stack_allocation: u64,
    ) -> Result<(), u32> {
        let Some(native) = self.companion else {
            return Ok(());
        };
        let state = p.wow64.as_ref().ok_or(STATUS_INVALID_PARAMETER)?;
        let offsets = layout::offsets(WinArch::X64);
        for (offset, value) in [
            (offsets.teb_exception_list, self.teb),
            (offsets.teb_self, native),
            (offsets.teb_stack_base, stack_base),
            (offsets.teb_stack_limit, stack_limit),
            (offsets.teb_client_id, u64::from(p.pid)),
            (offsets.teb_client_id + 8, u64::from(tid)),
            (offsets.teb_peb, state.native_peb),
            (offsets.teb_deallocation_stack, stack_allocation),
            (offsets.teb_tls_slots + 10 * 8, state.information),
            (offsets.teb_tls_links, native + offsets.teb_tls_links),
            (offsets.teb_tls_links + 8, native + offsets.teb_tls_links),
        ] {
            p.space
                .w64(native + offset, value)
                .map_err(|_| STATUS_NO_MEMORY)?;
        }
        p.space
            .w32(native + offsets.teb_current_locale, 0x409)
            .map_err(|_| STATUS_NO_MEMORY)?;
        p.space
            .w32(native + 0x180c, 0x2000)
            .map_err(|_| STATUS_NO_MEMORY)?;
        p.space
            .w32(self.teb + 0xfdc, (-0x2000i32) as u32)
            .map_err(|_| STATUS_NO_MEMORY)?;
        Ok(())
    }

    pub(crate) fn release(self, p: &mut Proc) {
        if let Some(claim) = &self.claim {
            let owned = p
                .teb_arena
                .slots
                .get(&self.base)
                .and_then(|(_, token)| token.upgrade())
                .is_some_and(|token| Arc::ptr_eq(claim, &token));
            if !owned {
                return;
            }
            p.teb_arena.slots.remove(&self.base);
            let same_allocation =
                p.vm.allocation(self.base)
                    .and_then(|allocation| allocation.name.as_ref())
                    .zip(self.owner.as_ref())
                    .is_some_and(|(current, original)| Arc::ptr_eq(current, original));
            if !same_allocation {
                return;
            }
        }
        let _ = p.vm.decommit(self.base, self.bytes);
    }
}
