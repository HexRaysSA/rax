//! Selected GUI input views and guest-owned Win32k process/thread bookkeeping.
//! Captured addresses name private guest mappings; no guest pointer reaches a host API.
use super::arch::WinArch;
use super::memory::{KernelDataView, VirtualMemory, VmError};
use super::object_namespace::DataSection;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::num::{NonZeroU32, NonZeroU64};
use std::rc::Rc;
use std::sync::Arc;

pub(crate) mod cursor_icons;
mod handles;
pub(crate) mod input_contexts;
mod message_atoms;
pub(crate) mod message_queue;
pub(crate) mod system_parameters;
pub(crate) mod window_classes;
pub(crate) mod windows;

pub(crate) const CLIENT_SEED_BYTES: usize = 32;
const CI_INITTHREAD: u64 = 8;
const WOW64_COMPANION_TI_FLAGS: u64 = 0x100 << 32;

#[derive(Debug)]
pub(crate) struct View {
    pub(crate) base: u64,
    pub(crate) section: Arc<DataSection>,
}

#[derive(Debug)]
pub(crate) struct Inputs {
    pub(crate) arch: WinArch,
    pub(crate) gdi: View,
    pub(crate) desktop: View,
    /// Kernel-provided 64-bit words from TEB+0x800..TEB+0x8A0.
    /// The executable version and client-thread pointer are replaced per guest.
    pub(crate) client: [u64; 20],
    pub(crate) client_seed: [u8; CLIENT_SEED_BYTES],
    pub(crate) first_reserved: u64,
    /// Fixed current-session query captured on the native GUI helper.
    pub(crate) remote_connect_state: u32,
    /// Fixed native Win32u query. The public USER32 API additionally virtualizes DPI.
    pub(crate) process_dpi: Option<NonZeroU32>,
    pub(crate) assigned_desktop: Arc<super::objects::Desktop>,
    /// Fixed current-process UI context; absence does not disable other GUI inputs.
    pub(crate) process_ui_context: Result<[u32; 2], String>,
    pub(crate) system_parameters: Result<system_parameters::Snapshot, String>,
    pub(crate) cursor_icons: Result<cursor_icons::Catalog, String>,
    pub(crate) message_cursor: [i32; 2],
    /// Default input locale of the selected native GUI context.
    pub(crate) keyboard_layout: Option<NonZeroU64>,
    pub(crate) window_station: Result<Arc<super::objects::WindowStation>, String>,
    pub(crate) overlapped_window_limits: Result<[i32; 10], String>,
    pub(crate) overlapped_nonclient_rendering: Result<bool, String>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Inputs {
    pub(crate) fn qualify_wow64_companion(&self) -> io::Result<()> {
        let views = [&self.gdi, &self.desktop];
        if self.arch != WinArch::Arm64
            || views.iter().any(|view| view.base < 1 << 32)
            || self.desktop.section.size != 0x1401000
            || self.first_reserved != 0x34000
            || self.client[18] > u64::from(u32::MAX)
            || self.client[19] > u64::from(u16::MAX)
        {
            return Err(invalid("WoW64 GUI companion view profile differs"));
        }
        for view in views {
            for region in &view.section.regions {
                let Some(bytes) = &region.bytes else { continue };
                if bytes.chunks_exact(8).any(|word| {
                    let value = u64::from_le_bytes(word.try_into().expect("complete word"));
                    views.iter().any(|target| {
                        value >= target.base && value - target.base < target.section.size
                    })
                }) {
                    return Err(invalid(
                        "WoW64 GUI companion contains an unresolved view pointer",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn selected(
        arch: WinArch,
        gdi: View,
        desktop: View,
        mut client: [u64; 20],
        remote_connect_state: u32,
        process_dpi: Option<NonZeroU32>,
        assigned_desktop: Arc<super::objects::Desktop>,
        process_ui_context: Result<[u32; 2], String>,
    ) -> io::Result<Arc<Self>> {
        if arch == WinArch::X86 {
            return Err(invalid(
                "native WoW64 GUI inputs require paired native process/thread contexts",
            ));
        }
        if remote_connect_state > 4 {
            return Err(invalid(
                "selected remote connection state differs from the measured profile",
            ));
        }
        if process_ui_context
            .as_ref()
            .is_ok_and(|words| words.iter().any(|word| *word > 3))
        {
            return Err(invalid(
                "selected process UI context exceeds the recorded field domains",
            ));
        }
        let valid_view = |view: &View| {
            view.base >= 65536
                && view.base % 65536 == 0
                && view
                    .base
                    .checked_add(view.section.size)
                    .is_some_and(|end| end <= 1 << 47)
                && view.section.path.is_empty()
        };
        if !valid_view(&gdi)
            || !valid_view(&desktop)
            || gdi.section.size != 0x181000
            || gdi.section.regions.len() != 1
            || gdi.section.regions[0].bytes.is_none()
            || desktop.section.regions.len() != 2
            || desktop.section.regions[0].bytes.is_none()
            || desktop.section.regions[1].bytes.is_some()
            || (gdi.base < desktop.base + desktop.section.size
                && desktop.base < gdi.base + gdi.section.size)
        {
            return Err(invalid(
                "selected GUI view extent/commitment profile differs",
            ));
        }
        let first_reserved = desktop.section.regions[1].offset;
        let bytes = desktop.section.regions[0]
            .bytes
            .as_ref()
            .expect("validated commitment");
        let contains = |address: u64, count: usize| {
            address.checked_sub(desktop.base).is_some_and(|offset| {
                offset
                    .checked_add(count as u64)
                    .is_some_and(|end| end <= first_reserved)
            })
        };
        let permitted = [0, 2, 4, 5, 12, 18, 19];
        // The clean native helper can carry either observed scalar profile.
        // Build 29708 also returns CI_INITTHREAD with the high flag absent.
        let client_flags = client[0] & !CI_INITTHREAD;
        if !matches!(client_flags, 0 | 0x2000_0000)
            || client[5] != desktop.base
            || !contains(client[4], 8)
            || !contains(client[12], CLIENT_SEED_BYTES)
            || client
                .iter()
                .enumerate()
                .any(|(index, value)| !permitted.contains(&index) && *value != 0)
        {
            return Err(invalid(
                "selected GUI client words differ from the observed clean-thread profile",
            ));
        }
        let offset = (client[12] - desktop.base) as usize;
        let client_seed: [u8; CLIENT_SEED_BYTES] = bytes[offset..offset + CLIENT_SEED_BYTES]
            .try_into()
            .expect("bounded seed");
        if client_seed[..20] != [0; 20] || client_seed[24..] != [0; 8] {
            return Err(invalid(
                "selected GUI thread seed is not an idle, pointer-free initial record",
            ));
        }
        // CI_INITTHREAD and the remaining USER-owned words are written by the
        // actual guest callback, never copied from the observing host thread.
        client[0] = client_flags;
        Ok(Arc::new(Self {
            arch,
            gdi,
            desktop,
            client,
            client_seed,
            first_reserved,
            remote_connect_state,
            process_dpi,
            assigned_desktop,
            process_ui_context,
            system_parameters: Err("selected GUI system parameters were not captured".into()),
            window_station: Err("assigned window station was not captured".into()),
            cursor_icons: Err("selected GUI cursor/icon cache was not captured".into()),
            message_cursor: [0; 2],
            keyboard_layout: None,
            overlapped_window_limits: Err(
                "selected overlapped window limits were not captured".into()
            ),
            overlapped_nonclient_rendering: Err(
                "selected overlapped non-client rendering was not captured".into(),
            ),
        }))
    }
}

#[derive(Debug)]
pub(crate) enum Availability {
    Available(Arc<Inputs>),
    Wow64Companion(Arc<Inputs>),
    Unavailable(String),
}

impl Default for Availability {
    fn default() -> Self {
        Self::Unavailable("native GUI inputs were not selected".into())
    }
}

impl Availability {
    pub(crate) fn select(
        arch: WinArch,
        user: std::path::PathBuf,
        win32u: std::path::PathBuf,
    ) -> Self {
        let acquired = std::thread::Builder::new()
            .name("rax-gui-inputs".into())
            .spawn(move || super::object_namespace::gui_snapshot(arch, &user, &win32u));
        match acquired {
            Ok(thread) => match thread.join() {
                Ok(Ok(inputs)) => Self::Available(inputs),
                Ok(Err(error)) => Self::Unavailable(error.to_string()),
                Err(_) => Self::Unavailable("native GUI input helper did not complete".into()),
            },
            Err(error) => Self::Unavailable(format!("native GUI input helper: {error}")),
        }
    }
}

struct Mappings {
    inputs: Arc<Inputs>,
    relocated: bool,
    gdi: KernelDataView,
    desktop: KernelDataView,
    cursor: u64,
    free_records: Vec<u64>,
    default_ime_title: Option<u64>,
}

pub(crate) struct ThreadState {
    pub(crate) record: u64,
    pub(crate) initialized: bool,
    pub(crate) ime_disabled: bool,
    pub(crate) default_ime_window: Option<u32>,
    pub(crate) default_input_context: Option<u32>,
    pub(crate) messages: message_queue::Queue,
    pub(crate) callbacks: Vec<Callback>,
}

pub(crate) struct Callback {
    pub(crate) context: super::context::RegContext,
    pub(crate) callback_sp: u64,
    pub(crate) hle_depth: usize,
    pub(crate) saved_window_client_info: Option<[u8; 16]>,
    pub(crate) completion: Completion,
}

/// The interrupted operation runs after successful cold thread conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Completion {
    Value(u64),
    QueryUserObject([u64; 5]),
    QueryGuiThread([u64; 2]),
    CloseWindowStation([u64; 1]),
    RegisterLpk(u32),
    RegisterWindowMessage(u64),
    PostThreadMessage([u64; 4]),
    PostQuitMessage([u64; 1]),
    PeekMessage([u64; 5]),
    GetMessage([u64; 4]),
    GetKeyboardLayout([u64; 1]),
    FindCursorIcon([u64; 3]),
    RegisterWindowClass([u64; 7]),
    GetWindowClass([u64; 5]),
    UnregisterWindowClass([u64; 3]),
    CreateWindow([u64; 18]),
    DisableThreadIme([u64; 1]),
    QueryWindow([u64; 2]),
    IsTopLevelWindow([u64; 1]),
    IsNonClientDpiScalingEnabled([u64; 1]),
    GetWindowCompositionAttribute([u64; 2]),
    GetAncestor([u64; 2]),
    SetWindowPos([u64; 7]),
    GetThreadState([u64; 1]),
    QueryInputContext([u64; 2]),
    UpdateInputContext([u64; 3]),
    QueryWindowClassName([u64; 3]),
    SetWindowLongPtr([u64; 4]),
    SetWindowFnid([u64; 2]),
    MessageCall([u64; 7]),
    GetImeInfo([u64; 2]),
    WindowProperty([u64; 2], windows::PropertyOperation),
    DestroyWindow([u64; 1]),
    ResumeWindow(windows::Continuation),
    SystemParameter {
        action: u32,
        parameter: u32,
        output: u64,
    },
    ProcessUiContext {
        process: u64,
        output: u64,
    },
}

#[derive(Default)]
pub(crate) struct State {
    pub(crate) executable_version: (u16, u16),
    pub(crate) value: Option<u64>,
    /// Full process-local DWORD; the selected kernel stores every input bit.
    pub(crate) lpk_registration: Option<u32>,
    pub(crate) threads: BTreeMap<u32, ThreadState>,
    message_atoms: Rc<RefCell<message_atoms::Table>>,
    classes: window_classes::Classes,
    windows: windows::Windows,
    handles: Option<handles::HandleTable>,
    input_contexts: input_contexts::InputContexts,
    pub(crate) theme_hook_started: bool,
    mappings: Option<Mappings>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.windows.entries.clear();
        self.retire_classes();
    }
}

impl State {
    pub(crate) fn new(executable_version: (u16, u16)) -> Self {
        let mut state = Self::default();
        state.executable_version = executable_version;
        state
    }

    pub(crate) fn inherit_message_atoms(&mut self, parent: &Self) {
        self.retire_classes();
        self.message_atoms = Rc::clone(&parent.message_atoms);
    }

    pub(crate) fn register_message(&self, upcase: &[u16], name: &[u16]) -> Result<u16, u32> {
        self.message_atoms.borrow_mut().register(upcase, name)
    }

    pub(crate) fn prepare_thread(
        &mut self,
        vm: &mut VirtualMemory,
        inputs: Arc<Inputs>,
        tid: u32,
        tick: u32,
    ) -> Result<u64, VmError> {
        self.prepare_thread_views(vm, inputs, tid, tick, false)
    }

    pub(crate) fn prepare_wow64_thread(
        &mut self,
        vm: &mut VirtualMemory,
        inputs: Arc<Inputs>,
        tid: u32,
        tick: u32,
        version: u64,
    ) -> Result<(u64, [u64; 20]), VmError> {
        let record = self.prepare_thread_views(vm, inputs.clone(), tid, tick, true)?;
        let mappings = self
            .mappings
            .as_ref()
            .expect("prepared companion GUI views");
        let mut client = inputs.client;
        client[0] |= CI_INITTHREAD;
        client[2] = version;
        client[3] = WOW64_COMPANION_TI_FLAGS;
        client[4] = mappings.desktop.base + (inputs.client[4] - inputs.desktop.base);
        client[5] = mappings.desktop.base;
        client[12] = record;
        Ok((mappings.gdi.base, client))
    }

    fn prepare_thread_views(
        &mut self,
        vm: &mut VirtualMemory,
        inputs: Arc<Inputs>,
        tid: u32,
        tick: u32,
        relocate: bool,
    ) -> Result<u64, VmError> {
        if let Some(mappings) = &mut self.mappings {
            if mappings.relocated != relocate
                || !Arc::ptr_eq(&mappings.inputs, &inputs)
                || !vm.owns_kernel_data_view(&mappings.gdi)
                || !vm.owns_kernel_data_view(&mappings.desktop)
            {
                return Err(VmError::InvalidAddress);
            }
            if let Some(thread) = self.threads.get(&tid) {
                return Ok(thread.record);
            }
            return Self::create_thread(vm, mappings, &mut self.threads, tid, tick);
        }
        let map = |vm: &mut VirtualMemory, view: &View| {
            let base = if relocate {
                vm.find_free(view.section.size, 65536, vm.low(), 1 << 32, true)
                    .ok_or(VmError::NoMemory)?
            } else {
                view.base
            };
            vm.map_kernel_data_view(view.section.clone(), base)
        };
        let gdi = map(vm, &inputs.gdi)?;
        let desktop = match map(vm, &inputs.desktop) {
            Ok(view) => view,
            Err(error) => {
                vm.retire_kernel_data_view(&gdi)?;
                return Err(error);
            }
        };
        let mut mappings = Mappings {
            cursor: desktop.base + inputs.first_reserved,
            inputs,
            relocated: relocate,
            gdi,
            desktop,
            free_records: Vec::new(),
            default_ime_title: None,
        };
        match Self::create_thread(vm, &mut mappings, &mut self.threads, tid, tick) {
            Ok(address) => {
                self.mappings = Some(mappings);
                Ok(address)
            }
            Err(error) => {
                vm.retire_kernel_data_view(&mappings.desktop)?;
                vm.retire_kernel_data_view(&mappings.gdi)?;
                Err(error)
            }
        }
    }

    fn create_thread(
        vm: &mut VirtualMemory,
        mappings: &mut Mappings,
        threads: &mut BTreeMap<u32, ThreadState>,
        tid: u32,
        tick: u32,
    ) -> Result<u64, VmError> {
        let address = mappings
            .free_records
            .last()
            .copied()
            .unwrap_or(mappings.cursor);
        if address
            .checked_add(CLIENT_SEED_BYTES as u64)
            .is_none_or(|end| end > mappings.desktop.base + mappings.desktop.size)
        {
            return Err(VmError::NoMemory);
        }
        vm.commit_kernel_data_view(&mappings.desktop, address, CLIENT_SEED_BYTES as u64)?;
        let mut seed = mappings.inputs.client_seed;
        seed[20..24].copy_from_slice(&tick.to_le_bytes());
        vm.write_kernel_data_view(&mappings.desktop, address, &seed)?;
        if mappings.free_records.pop().is_none() {
            mappings.cursor += CLIENT_SEED_BYTES as u64;
        }
        threads.insert(
            tid,
            ThreadState {
                record: address,
                initialized: false,
                ime_disabled: false,
                default_ime_window: None,
                default_input_context: None,
                messages: message_queue::Queue::default(),
                callbacks: Vec::new(),
            },
        );
        Ok(address)
    }

    pub(crate) fn retire_thread(
        &mut self,
        vm: &mut VirtualMemory,
        tid: u32,
    ) -> Result<(), VmError> {
        self.close_thread_input_context(vm, tid)?;
        if let Some(thread) = self.threads.remove(&tid)
            && let Some(mappings) = self.mappings.as_mut()
        {
            mappings.free_records.push(thread.record);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
