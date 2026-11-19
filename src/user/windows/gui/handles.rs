//! The installed USER shared handle table in the guest kernel data view.
use super::State;
use crate::user::windows::memory::{KernelDataView, Mem, VirtualMemory, VmError};
use crate::user::windows::object_namespace::csr::client_data::{
    CsrClientData, USER_HANDLE_ENTRY_BYTES,
};

const FIRST_USER_SLOT: u64 = 16;
const LAST_USER_GENERATION: u16 = 0x7fff;

#[derive(Clone, Copy)]
pub(super) enum HandleKind {
    Window = 1,
    InputContext = 17,
}

pub(super) struct HandleTable {
    view: KernelDataView,
    entries: u64,
}

impl HandleTable {
    pub(super) fn slot(&self, vm: &VirtualMemory, kind: HandleKind) -> Result<u32, VmError> {
        let first = FIRST_USER_SLOT + u64::from(matches!(kind, HandleKind::InputContext));
        for index in (first..self.entries).step_by(2) {
            let address = self.address(index);
            let mut entry = [0; USER_HANDLE_ENTRY_BYTES as usize];
            vm.space()
                .rd(address, &mut entry)
                .map_err(|_| VmError::InvalidAddress)?;
            if entry[..26] == [0; 26] && entry[28..] == [0; 4] {
                let generation = u16::from_le_bytes([entry[26], entry[27]]).max(1);
                if generation < LAST_USER_GENERATION {
                    return Ok((u32::from(generation) << 16) | index as u32);
                }
            }
        }
        Err(VmError::NoMemory)
    }

    pub(super) fn owned_by(&self, vm: &VirtualMemory) -> bool {
        vm.owns_kernel_data_view(&self.view)
    }

    pub(super) fn canonical(&self, vm: &VirtualMemory, raw: u64, kind: HandleKind) -> Option<u32> {
        let generation_mask = match kind {
            HandleKind::Window => u16::MAX,
            HandleKind::InputContext => LAST_USER_GENERATION,
        };
        let handle = raw as u32 & ((u32::from(generation_mask) << 16) | 0xffff);
        if (handle >> 16) as u16 != generation_mask {
            return Some(handle);
        }
        let index = u64::from(handle as u16);
        if index >= self.entries {
            return None;
        }
        let generation = vm.space().u16(self.address(index) + 26).ok()?;
        Some((u32::from(generation) << 16) | index as u32)
    }

    fn address(&self, index: u64) -> u64 {
        self.view.base + index * USER_HANDLE_ENTRY_BYTES
    }

    pub(super) fn publish(
        &self,
        vm: &mut VirtualMemory,
        kind: HandleKind,
        handle: u32,
        offset: u64,
        tid: u32,
        desktop_identity: u64,
    ) -> Result<(), VmError> {
        let mut entry = [0; USER_HANDLE_ENTRY_BYTES as usize];
        entry[0..8].copy_from_slice(&offset.to_le_bytes());
        entry[8..16].copy_from_slice(&u64::from(tid).to_le_bytes());
        entry[16..24].copy_from_slice(&desktop_identity.to_le_bytes());
        entry[24] = kind as u8;
        entry[26..28].copy_from_slice(&(handle >> 16).to_le_bytes()[..2]);
        vm.write_kernel_data_view(&self.view, self.address(u64::from(handle as u16)), &entry)
    }

    pub(super) fn retire(&self, vm: &mut VirtualMemory, handle: u32) -> Result<(), VmError> {
        let slot = self.address(u64::from(handle as u16));
        let mut entry = [0; USER_HANDLE_ENTRY_BYTES as usize];
        entry[26..28].copy_from_slice(&((handle >> 16) as u16 + 1).to_le_bytes());
        vm.write_kernel_data_view(&self.view, slot, &entry)
    }
}

impl State {
    pub(super) fn bind_handle_table(
        &mut self,
        vm: &mut VirtualMemory,
        csr: &CsrClientData,
    ) -> Result<(), VmError> {
        if self.handles.is_none() {
            let (view, entries) = csr.user_handle_table(vm)?;
            self.handles = Some(HandleTable { view, entries });
        }
        Ok(())
    }
}
