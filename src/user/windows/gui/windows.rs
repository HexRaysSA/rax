//! Guest-owned USER window lifetime and the address exposed to USER callbacks.

use super::State;
use super::handles::HandleKind;
use super::window_classes::{Class, Name};
use crate::user::windows::memory::{Mem, VirtualMemory, VmError};
use crate::user::windows::object_namespace::csr::client_data::CsrClientData;
use std::collections::BTreeMap;
use std::rc::Rc;

pub(crate) const WCA_NCRENDERING_ENABLED: u32 = 1;

const WINDOW_BYTES: usize = 0x160;
const WINDOW_DPI_CONTEXT_OFFSET: usize = 0x120;
const WINDOW_DPI_UNAWARE: u32 = 0x6010;
const WINDOW_THEME_VALUE: u64 = 0xf0;
const WINDOW_OWNER_OFFSET: u64 = 0x40;
const WINDOW_CLIENT_EXTRA_OFFSET: usize = 0x128;
const WINDOW_FNID_OFFSET: u64 = 0x2a;
const WINDOW_TITLE_OFFSET: u64 = 0xb8;
const WINDOW_INPUT_CONTEXT_OFFSET: usize = 0xd0;

pub(crate) const OVERLAPPED_STYLE: u32 = 0x00cf_0000;
pub(crate) const DEFAULT_IME_STYLE: u32 = 0x8800_0000;
pub(crate) const DEFAULT_IME_TITLE: &str = "Default IME";

pub(crate) enum WindowKind {
    MessageOnly,
    DefaultIme {
        owner_window: u32,
        client_extra: u64,
    },
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
            WindowKind::MessageOnly | WindowKind::DefaultIme { .. } => [width, height],
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
    AllocateImeExtra,
    ImeNonClientCreate,
    ImeNonClientRectangle,
    ImeCreate,
    ImeSize,
    ImeMove,
    ImeStartup,
    ImeBeginDestroy,
    ImeDestroy,
    ImeNonClientDestroy,
    FreeImeExtra,
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
    order: u64,
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
    next_order: u64,
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
        self.bind_handle_table(vm, csr)?;
        let handles = self.handles.as_ref().expect("selected USER handle table");
        let ime_owner_address = match creation.kind {
            WindowKind::DefaultIme { owner_window, .. } => Some(
                self.window(u64::from(owner_window))
                    .ok_or(VmError::InvalidAddress)?
                    .client_address,
            ),
            _ => None,
        };
        let mappings = self.mappings.as_mut().ok_or(VmError::InvalidAddress)?;
        let address = self.windows.free.last().copied().unwrap_or(mappings.cursor);
        let end = address
            .checked_add(WINDOW_BYTES as u64)
            .filter(|&end| end <= mappings.desktop.base + mappings.desktop.size)
            .ok_or(VmError::NoMemory)?;
        let handle = handles.slot(vm, HandleKind::Window)?;
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
            WindowKind::DefaultIme { client_extra, .. } => {
                let owner_offset =
                    ime_owner_address.expect("validated IME owner") - mappings.desktop.base;
                let field = WINDOW_OWNER_OFFSET as usize;
                record[field..field + 8].copy_from_slice(&owner_offset.to_le_bytes());
                record[0x1c..0x20]
                    .copy_from_slice(&(DEFAULT_IME_STYLE | 0x0400_0000).to_le_bytes());
                record[0x14..0x18].copy_from_slice(&0x700u32.to_le_bytes());
                record[0xb0..0xb8].copy_from_slice(&offset.to_le_bytes());
                record[0xc8..0xcc].copy_from_slice(&8u32.to_le_bytes());
                record[WINDOW_CLIENT_EXTRA_OFFSET..WINDOW_CLIENT_EXTRA_OFFSET + 8]
                    .copy_from_slice(&client_extra.to_le_bytes());
            }
            WindowKind::Overlapped { .. } => {
                // A hidden overlapped window receives a window edge and a
                // server-side clipping bit before WM_NCCREATE.
                record[0x18..0x1c].copy_from_slice(&0x100u32.to_le_bytes());
                record[0x1c..0x20].copy_from_slice(&(OVERLAPPED_STYLE | 0x0400_0000).to_le_bytes());
                let thread = self.threads.get(&owner).ok_or(VmError::InvalidAddress)?;
                if !thread.ime_disabled
                    && let Some(context) = thread.default_input_context
                {
                    record[WINDOW_INPUT_CONTEXT_OFFSET..WINDOW_INPUT_CONTEXT_OFFSET + 8]
                        .copy_from_slice(&u64::from(context).to_le_bytes());
                }
            }
        }
        record[0x78..0x80].copy_from_slice(&class.definition.procedure().to_le_bytes());
        record[WINDOW_DPI_CONTEXT_OFFSET..WINDOW_DPI_CONTEXT_OFFSET + 4]
            .copy_from_slice(&WINDOW_DPI_UNAWARE.to_le_bytes());
        record[0x148..0x14c].copy_from_slice(&owner.to_le_bytes());
        record[0x14c..0x150].copy_from_slice(&pid.to_le_bytes());

        vm.commit_kernel_data_view(&mappings.desktop, address, WINDOW_BYTES as u64)?;
        vm.write_kernel_data_view(&mappings.desktop, address, &record)?;
        if let Err(error) = handles.publish(
            vm,
            HandleKind::Window,
            handle,
            offset,
            owner,
            desktop_identity,
        ) {
            vm.write_kernel_data_view(&mappings.desktop, address, &[0; WINDOW_BYTES])?;
            return Err(error);
        }
        if self.windows.free.pop().is_none() {
            mappings.cursor = end;
        }
        let order = self.windows.next_order;
        self.windows.next_order += 1;
        self.windows.entries.insert(
            handle,
            Window {
                owner,
                class,
                client_address: address,
                destroying: false,
                creation,
                order,
                properties: BTreeMap::new(),
            },
        );
        Ok(handle)
    }

    pub(crate) fn window(&self, handle: u64) -> Option<&Window> {
        self.windows.entries.get(&u32::try_from(handle).ok()?)
    }

    /// Resolve the canonical HWND and window in the guest USER handle table.
    /// The upper 32 bits are ignored. Generation 0xffff selects the live
    /// occupant of the 16-bit slot.
    pub(crate) fn window_accepting_wildcard_generation(
        &self,
        vm: &VirtualMemory,
        handle: u64,
    ) -> Option<(u32, &Window)> {
        let handle = self
            .handles
            .as_ref()?
            .canonical(vm, handle, HandleKind::Window)?;
        self.windows
            .entries
            .get(&handle)
            .map(|window| (handle, window))
    }

    pub(crate) fn next_ime_owner(&self, tid: u32) -> Option<u32> {
        // Fixed hidden windows enter the modeled Z order at the top. The
        // supported positioning operation preserves that order.
        self.windows
            .entries
            .iter()
            .filter(|(_, window)| {
                window.owner == tid
                    && !window.destroying
                    && matches!(window.creation.kind, WindowKind::Overlapped { .. })
            })
            .max_by_key(|(_, window)| window.order)
            .map(|(&handle, _)| handle)
    }

    pub(crate) fn move_ime_owner(
        &mut self,
        vm: &mut VirtualMemory,
        ime: u32,
        owner: u32,
    ) -> Result<(), VmError> {
        let owner_address = self
            .window(u64::from(owner))
            .ok_or(VmError::InvalidAddress)?
            .client_address;
        let wnd = self
            .windows
            .entries
            .get_mut(&ime)
            .ok_or(VmError::InvalidAddress)?;
        let WindowKind::DefaultIme { owner_window, .. } = &mut wnd.creation.kind else {
            return Err(VmError::InvalidAddress);
        };
        let mappings = self.mappings.as_ref().ok_or(VmError::InvalidAddress)?;
        let offset = owner_address - mappings.desktop.base;
        vm.write_kernel_data_view(
            &mappings.desktop,
            wnd.client_address + WINDOW_OWNER_OFFSET,
            &offset.to_le_bytes(),
        )?;
        *owner_window = owner;
        Ok(())
    }

    pub(crate) fn set_ime_title(
        &mut self,
        vm: &mut VirtualMemory,
        handle: u32,
    ) -> Result<(), VmError> {
        let address = self
            .window(u64::from(handle))
            .ok_or(VmError::InvalidAddress)?
            .client_address;
        let mappings = self.mappings.as_mut().ok_or(VmError::InvalidAddress)?;
        let title: Vec<_> = DEFAULT_IME_TITLE
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let guest_title = match mappings.default_ime_title {
            Some(title) => title,
            None => {
                let start = mappings.cursor;
                let bytes = (title.len() as u64).next_multiple_of(8);
                let end = start
                    .checked_add(bytes)
                    .filter(|&end| end <= mappings.desktop.base + mappings.desktop.size)
                    .ok_or(VmError::NoMemory)?;
                vm.commit_kernel_data_view(&mappings.desktop, start, bytes)?;
                vm.write_kernel_data_view(&mappings.desktop, start, &title)?;
                mappings.default_ime_title = Some(start);
                mappings.cursor = end;
                start
            }
        };
        let maximum = title.len() as u32;
        let offset = guest_title - mappings.desktop.base;
        let mut descriptor = [0; 16];
        descriptor[..4].copy_from_slice(&(maximum - 2).to_le_bytes());
        descriptor[4..8].copy_from_slice(&maximum.to_le_bytes());
        descriptor[8..].copy_from_slice(&offset.to_le_bytes());
        vm.write_kernel_data_view(
            &mappings.desktop,
            address + WINDOW_TITLE_OFFSET,
            &descriptor,
        )
    }

    pub(crate) fn set_ime_fnid(
        &self,
        vm: &mut VirtualMemory,
        window: &Window,
        value: u16,
    ) -> Result<(), VmError> {
        let field = window.client_address + WINDOW_FNID_OFFSET;
        let current = vm.space().u16(field).map_err(|_| VmError::InvalidAddress)?;
        let mappings = self.mappings.as_ref().ok_or(VmError::InvalidAddress)?;
        vm.write_kernel_data_view(&mappings.desktop, field, &(current | value).to_le_bytes())
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
        let handles = self.handles.as_ref().ok_or(VmError::InvalidAddress)?;
        if !handles.owned_by(vm) || !vm.owns_kernel_data_view(&mappings.desktop) {
            return Err(VmError::InvalidAddress);
        }
        handles.retire(vm, handle)?;
        vm.write_kernel_data_view(&mappings.desktop, window.client_address, &[0; WINDOW_BYTES])?;
        self.windows.free.push(window.client_address);
        if let Some(thread) = self.threads.get_mut(&window.owner)
            && thread.default_ime_window == Some(handle)
        {
            thread.default_ime_window = None;
        }
        self.windows.entries.remove(&handle);
        Ok(())
    }
}
