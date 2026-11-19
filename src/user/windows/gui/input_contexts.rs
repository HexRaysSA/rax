//! The default input context owned by a converted guest USER thread.
use super::State;
use super::handles::HandleKind;
use crate::user::windows::memory::{Mem, VirtualMemory, VmError};
use crate::user::windows::object_namespace::csr::client_data::CsrClientData;
use std::collections::BTreeMap;

const INPUT_CONTEXT_BYTES: usize = 0x30;
const CLIENT_CONTEXT_OFFSET: u64 = 0x18;
const ASSOCIATED_WINDOW_OFFSET: u64 = 0x20;

pub(crate) enum Change {
    ClientContext(u64),
    AssociatedWindow(u64),
}

pub(super) struct InputContext {
    owner: u32,
    address: u64,
}

#[derive(Default)]
pub(super) struct InputContexts {
    entries: BTreeMap<u32, InputContext>,
    free: Vec<u64>,
}

impl State {
    pub(crate) fn default_input_context(
        &mut self,
        vm: &mut VirtualMemory,
        csr: &CsrClientData,
        tid: u32,
    ) -> Result<u32, VmError> {
        let thread = self.threads.get(&tid).ok_or(VmError::InvalidAddress)?;
        if let Some(handle) = thread.default_input_context {
            return Ok(handle);
        }
        self.bind_handle_table(vm, csr)?;
        let handles = self.handles.as_ref().expect("selected USER handle table");
        let handle = handles.slot(vm, HandleKind::InputContext)?;
        let mappings = self.mappings.as_mut().ok_or(VmError::InvalidAddress)?;
        let address = self
            .input_contexts
            .free
            .last()
            .copied()
            .unwrap_or(mappings.cursor);
        let end = address
            .checked_add(INPUT_CONTEXT_BYTES as u64)
            .filter(|&end| end <= mappings.desktop.base + mappings.desktop.size)
            .ok_or(VmError::NoMemory)?;
        let desktop_identity = vm
            .space()
            .u64(mappings.inputs.client[4])
            .map_err(|_| VmError::InvalidAddress)?;
        let offset = address - mappings.desktop.base;
        let mut record = [0; INPUT_CONTEXT_BYTES];
        record[..4].copy_from_slice(&handle.to_le_bytes());
        record[8..16].copy_from_slice(&offset.to_le_bytes());

        vm.commit_kernel_data_view(&mappings.desktop, address, INPUT_CONTEXT_BYTES as u64)?;
        vm.write_kernel_data_view(&mappings.desktop, address, &record)?;
        if let Err(error) = handles.publish(
            vm,
            HandleKind::InputContext,
            handle,
            offset,
            tid,
            desktop_identity,
        ) {
            vm.write_kernel_data_view(&mappings.desktop, address, &[0; INPUT_CONTEXT_BYTES])?;
            return Err(error);
        }
        if self.input_contexts.free.pop().is_none() {
            mappings.cursor = end;
        }
        self.input_contexts.entries.insert(
            handle,
            InputContext {
                owner: tid,
                address,
            },
        );
        self.threads
            .get_mut(&tid)
            .expect("existing USER thread")
            .default_input_context = Some(handle);
        Ok(handle)
    }

    pub(crate) fn input_context(&self, vm: &VirtualMemory, raw: u64) -> Option<(u32, u32)> {
        let handle = self
            .handles
            .as_ref()?
            .canonical(vm, raw, HandleKind::InputContext)?;
        self.input_contexts
            .entries
            .get(&handle)
            .map(|context| (handle, context.owner))
    }

    pub(crate) fn update_input_context(
        &self,
        vm: &mut VirtualMemory,
        handle: u32,
        change: Change,
    ) -> Result<bool, VmError> {
        let context = self
            .input_contexts
            .entries
            .get(&handle)
            .ok_or(VmError::InvalidAddress)?;
        let mappings = self.mappings.as_ref().ok_or(VmError::InvalidAddress)?;
        let (offset, value) = match change {
            Change::ClientContext(value) => {
                let previous = vm
                    .space()
                    .u64(context.address + CLIENT_CONTEXT_OFFSET)
                    .map_err(|_| VmError::InvalidAddress)?;
                if previous != 0 {
                    return Ok(false);
                }
                (CLIENT_CONTEXT_OFFSET, value)
            }
            Change::AssociatedWindow(value) => (ASSOCIATED_WINDOW_OFFSET, value),
        };
        vm.write_kernel_data_view(
            &mappings.desktop,
            context.address + offset,
            &value.to_le_bytes(),
        )?;
        Ok(true)
    }

    pub(super) fn close_thread_input_context(
        &mut self,
        vm: &mut VirtualMemory,
        tid: u32,
    ) -> Result<(), VmError> {
        let Some(handle) = self
            .threads
            .get(&tid)
            .and_then(|thread| thread.default_input_context)
        else {
            return Ok(());
        };
        let context = self
            .input_contexts
            .entries
            .get(&handle)
            .ok_or(VmError::InvalidAddress)?;
        let handles = self.handles.as_ref().ok_or(VmError::InvalidAddress)?;
        let mappings = self.mappings.as_ref().ok_or(VmError::InvalidAddress)?;
        if !handles.owned_by(vm) || !vm.owns_kernel_data_view(&mappings.desktop) {
            return Err(VmError::InvalidAddress);
        }
        handles.retire(vm, handle)?;
        vm.write_kernel_data_view(
            &mappings.desktop,
            context.address,
            &[0; INPUT_CONTEXT_BYTES],
        )?;
        self.input_contexts.free.push(context.address);
        self.input_contexts.entries.remove(&handle);
        self.threads
            .get_mut(&tid)
            .expect("existing USER thread")
            .default_input_context = None;
        Ok(())
    }
}
