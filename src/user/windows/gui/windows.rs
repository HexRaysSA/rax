//! Guest-owned USER window lifetime and the address exposed to USER callbacks.

use super::State;
use super::window_classes::{Class, Name};
use crate::user::windows::memory::{KernelDataView, Mem, VirtualMemory, VmError};
use crate::user::windows::object_namespace::csr::client_data::{
    CsrClientData, USER_HANDLE_ENTRY_BYTES,
};
use std::collections::BTreeMap;
use std::rc::Rc;

pub(crate) const WCA_NCRENDERING_ENABLED: u32 = 1;

const WINDOW_BYTES: usize = 0x160;
const WINDOW_DPI_CONTEXT_OFFSET: usize = 0x120;
const WINDOW_DPI_UNAWARE: u32 = 0x6010;
const WINDOW_THEME_VALUE: u64 = 0xf0;
const USER_TYPE_WINDOW: u8 = 1;
const FIRST_WINDOW_SLOT: u64 = 16;
const LAST_WINDOW_GENERATION: u16 = 0x7fff;

struct HandleTable {
    view: KernelDataView,
    entries: u64,
}

impl HandleTable {
    fn slot(&self, vm: &VirtualMemory) -> Result<(u64, u32), VmError> {
        for index in (FIRST_WINDOW_SLOT..self.entries).step_by(2) {
            let address = self.address(index);
            let mut entry = [0; USER_HANDLE_ENTRY_BYTES as usize];
            vm.space()
                .rd(address, &mut entry)
                .map_err(|_| VmError::InvalidAddress)?;
            if entry[..26] == [0; 26] && entry[28..] == [0; 4] {
                let generation = u16::from_le_bytes([entry[26], entry[27]]).max(1);
                if generation < LAST_WINDOW_GENERATION {
                    return Ok((address, (u32::from(generation) << 16) | index as u32));
                }
            }
        }
        Err(VmError::NoMemory)
    }

    fn address(&self, index: u64) -> u64 {
        self.view.base + index * USER_HANDLE_ENTRY_BYTES
    }

    fn publish(
        &self,
        vm: &mut VirtualMemory,
        slot: u64,
        handle: u32,
        offset: u64,
        tid: u32,
        desktop_identity: u64,
    ) -> Result<(), VmError> {
        let mut entry = [0; USER_HANDLE_ENTRY_BYTES as usize];
        entry[0..8].copy_from_slice(&offset.to_le_bytes());
        entry[8..16].copy_from_slice(&u64::from(tid).to_le_bytes());
        entry[16..24].copy_from_slice(&desktop_identity.to_le_bytes());
        entry[24] = USER_TYPE_WINDOW;
        entry[26..28].copy_from_slice(&(handle >> 16).to_le_bytes()[..2]);
        vm.write_kernel_data_view(&self.view, slot, &entry)
    }

    fn retire(&self, vm: &mut VirtualMemory, handle: u32) -> Result<(), VmError> {
        let slot = self.address(u64::from(handle as u16));
        let mut entry = [0; USER_HANDLE_ENTRY_BYTES as usize];
        entry[26..28].copy_from_slice(&((handle >> 16) as u16 + 1).to_le_bytes());
        vm.write_kernel_data_view(&self.view, slot, &entry)
    }
}

pub(crate) const OVERLAPPED_STYLE: u32 = 0x00cf_0000;

pub(crate) enum WindowKind {
    MessageOnly,
    Overlapped {
        limits: [i32; 10],
        tracking_size: [i32; 2],
    },
}

pub(crate) struct Creation {
    pub(crate) kind: WindowKind,
    pub(crate) module: u64,
    pub(crate) class_argument: Name,
    pub(crate) title: u64,
    pub(crate) argument: u64,
    /// Window origin and dimensions, before the nonclient calculation.
    pub(crate) geometry: [i32; 4],
}

impl Creation {
    pub(crate) fn rectangle(&self) -> [u8; 16] {
        let [x, y, width, height] = self.geometry;
        let [width, height] = match self.kind {
            WindowKind::MessageOnly => [width, height],
            WindowKind::Overlapped { tracking_size, .. } => tracking_size,
        };
        let mut rectangle = [0; 16];
        for (coordinate, bytes) in [x, y, x.saturating_add(width), y.saturating_add(height)]
            .into_iter()
            .zip(rectangle.chunks_exact_mut(4))
        {
            bytes.copy_from_slice(&coordinate.to_le_bytes());
        }
        rectangle
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    LoadTheme,
    Measure,
    NonClientCreate,
    NonClientRectangle,
    Create,
    BeginDestroy,
    Destroy,
    NonClientDestroy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Continuation {
    pub(crate) handle: u32,
    pub(crate) phase: Phase,
    pub(crate) result: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PropertyOperation {
    Get,
    Set(u64),
    Remove,
}

pub(crate) struct Window {
    pub(crate) owner: u32,
    pub(crate) class: Rc<Class>,
    pub(crate) client_address: u64,
    pub(crate) destroying: bool,
    pub(crate) creation: Creation,
    properties: BTreeMap<u16, u64>,
}

impl Window {
    /// Only the installed DPI-unaware creation profile is currently modeled.
    pub(crate) fn nonclient_dpi_scaling(&self, vm: &VirtualMemory) -> Option<bool> {
        match vm
            .space()
            .u32(self.client_address + WINDOW_DPI_CONTEXT_OFFSET as u64)
            .ok()?
        {
            WINDOW_DPI_UNAWARE => Some(false),
            _ => None,
        }
    }
}

#[derive(Default)]
pub(super) struct Windows {
    pub(super) entries: BTreeMap<u32, Window>,
    free: Vec<u64>,
    handles: Option<HandleTable>,
}

impl State {
    pub(crate) fn open_window(
        &mut self,
        vm: &mut VirtualMemory,
        pid: u32,
        owner: u32,
        class: Rc<Class>,
        creation: Creation,
        csr: &CsrClientData,
    ) -> Result<u32, VmError> {
        if self.windows.handles.is_none() {
            let (view, entries) = csr.window_handle_table(vm)?;
            self.windows.handles = Some(HandleTable { view, entries });
        }
        let handles = self
            .windows
            .handles
            .as_ref()
            .expect("selected USER handle table");
        let mappings = self.mappings.as_mut().ok_or(VmError::InvalidAddress)?;
        let address = self.windows.free.last().copied().unwrap_or(mappings.cursor);
        let end = address
            .checked_add(WINDOW_BYTES as u64)
            .filter(|&end| end <= mappings.desktop.base + mappings.desktop.size)
            .ok_or(VmError::NoMemory)?;
        let (slot, handle) = handles.slot(vm)?;
        let desktop_identity = vm
            .space()
            .u64(mappings.inputs.client[4])
            .map_err(|_| VmError::InvalidAddress)?;
        let offset = address - mappings.desktop.base;

        let mut record = [0; WINDOW_BYTES];
        record[..4].copy_from_slice(&handle.to_le_bytes());
        record[8..16].copy_from_slice(&offset.to_le_bytes());
        record[0x20..0x28].copy_from_slice(&creation.module.to_le_bytes());
        match creation.kind {
            WindowKind::MessageOnly => record[0x58..0x68].copy_from_slice(&creation.rectangle()),
            WindowKind::Overlapped { .. } => {
                // A hidden overlapped window receives a window edge and a
                // server-side clipping bit before WM_NCCREATE.
                record[0x18..0x1c].copy_from_slice(&0x100u32.to_le_bytes());
                record[0x1c..0x20].copy_from_slice(&(OVERLAPPED_STYLE | 0x0400_0000).to_le_bytes());
            }
        }
        record[0x78..0x80].copy_from_slice(&class.definition.procedure().to_le_bytes());
        record[WINDOW_DPI_CONTEXT_OFFSET..WINDOW_DPI_CONTEXT_OFFSET + 4]
            .copy_from_slice(&WINDOW_DPI_UNAWARE.to_le_bytes());
        record[0x148..0x14c].copy_from_slice(&owner.to_le_bytes());
        record[0x14c..0x150].copy_from_slice(&pid.to_le_bytes());

        vm.commit_kernel_data_view(&mappings.desktop, address, WINDOW_BYTES as u64)?;
        vm.write_kernel_data_view(&mappings.desktop, address, &record)?;
        if let Err(error) = handles.publish(vm, slot, handle, offset, owner, desktop_identity) {
            vm.write_kernel_data_view(&mappings.desktop, address, &[0; WINDOW_BYTES])?;
            return Err(error);
        }
        if self.windows.free.pop().is_none() {
            mappings.cursor = end;
        }
        self.windows.entries.insert(
            handle,
            Window {
                owner,
                class,
                client_address: address,
                destroying: false,
                creation,
                properties: BTreeMap::new(),
            },
        );
        Ok(handle)
    }

    pub(crate) fn window(&self, handle: u64) -> Option<&Window> {
        self.windows.entries.get(&u32::try_from(handle).ok()?)
    }

    /// The upper 32 bits are ignored. Generation 0xffff selects the live
    /// occupant of the 16-bit slot in the guest USER handle table.
    pub(crate) fn window_accepting_wildcard_generation(
        &self,
        vm: &VirtualMemory,
        handle: u64,
    ) -> Option<&Window> {
        let mut handle = handle as u32;
        if handle >> 16 == u32::from(u16::MAX) {
            let index = u64::from(handle as u16);
            let table = self.windows.handles.as_ref()?;
            if index >= table.entries {
                return None;
            }
            let generation = vm.space().u16(table.address(index) + 26).ok()?;
            handle = (u32::from(generation) << 16) | u32::from(index as u16);
        }
        self.windows.entries.get(&handle)
    }

    pub(crate) fn window_mut(&mut self, handle: u32) -> Option<&mut Window> {
        self.windows.entries.get_mut(&handle)
    }

    pub(crate) fn window_properties(&mut self, handle: u32) -> Option<&mut BTreeMap<u16, u64>> {
        self.windows
            .entries
            .get_mut(&handle)
            .map(|window| &mut window.properties)
    }

    /// USER32 can read index -2 directly from the private window data view.
    pub(crate) fn set_window_theme_value(
        &self,
        vm: &mut VirtualMemory,
        handle: u32,
        value: u64,
    ) -> Result<u64, VmError> {
        let buffer = self
            .window(u64::from(handle))
            .ok_or(VmError::InvalidAddress)?
            .client_address
            + WINDOW_THEME_VALUE;
        let desktop = &self
            .mappings
            .as_ref()
            .ok_or(VmError::InvalidAddress)?
            .desktop;
        let previous = vm
            .space()
            .u64(buffer)
            .map_err(|_| VmError::InvalidAddress)?;
        vm.write_kernel_data_view(desktop, buffer, &value.to_le_bytes())?;
        Ok(previous)
    }

    pub(crate) fn start_window_destruction(&mut self, handle: u64, owner: u32) -> Option<u64> {
        let window = self.windows.entries.get_mut(&u32::try_from(handle).ok()?)?;
        if window.owner != owner || window.destroying {
            return None;
        }
        window.destroying = true;
        Some(window.client_address)
    }

    pub(crate) fn set_window_client_rectangle(
        &mut self,
        vm: &mut VirtualMemory,
        handle: u32,
        rectangle: [u8; 16],
    ) -> Result<(), VmError> {
        let window = self
            .window(u64::from(handle))
            .ok_or(VmError::InvalidAddress)?;
        let mappings = self.mappings.as_ref().ok_or(VmError::InvalidAddress)?;
        let mut rectangles = [0; 32];
        rectangles[..16].copy_from_slice(&window.creation.rectangle());
        rectangles[16..].copy_from_slice(&rectangle);
        vm.write_kernel_data_view(&mappings.desktop, window.client_address + 0x58, &rectangles)
    }

    pub(crate) fn close_thread_windows(
        &mut self,
        vm: &mut VirtualMemory,
        tid: u32,
    ) -> Result<(), VmError> {
        let owned: Vec<_> = self
            .windows
            .entries
            .iter()
            .filter_map(|(&handle, window)| (window.owner == tid).then_some(handle))
            .collect();
        for handle in owned {
            self.close_window(vm, handle)?;
        }
        Ok(())
    }

    pub(crate) fn close_window(
        &mut self,
        vm: &mut VirtualMemory,
        handle: u32,
    ) -> Result<(), VmError> {
        let window = self
            .windows
            .entries
            .get(&handle)
            .ok_or(VmError::InvalidAddress)?;
        let mappings = self.mappings.as_ref().ok_or(VmError::InvalidAddress)?;
        let handles = self
            .windows
            .handles
            .as_ref()
            .ok_or(VmError::InvalidAddress)?;
        if !vm.owns_kernel_data_view(&handles.view) || !vm.owns_kernel_data_view(&mappings.desktop)
        {
            return Err(VmError::InvalidAddress);
        }
        handles.retire(vm, handle)?;
        vm.write_kernel_data_view(&mappings.desktop, window.client_address, &[0; WINDOW_BYTES])?;
        self.windows.free.push(window.client_address);
        self.windows.entries.remove(&handle);
        Ok(())
    }
}
