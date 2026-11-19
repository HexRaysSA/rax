//! Measured 64-bit USER window creation, callbacks, and destruction.

use super::{
    CallbackFrame, Completion, Mem, Outcome, Proc, Thread, WinArch, failure, query_error,
    window_classes,
};
use crate::user::windows::gui::window_classes::Name;
use crate::user::windows::gui::windows::{
    Continuation, Creation, OVERLAPPED_STYLE, Phase, PropertyOperation, Window, WindowKind,
};
use crate::user::windows::memory::MemFault;
use crate::user::windows::nt::error::{
    ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_NOACCESS,
};
use crate::user::windows::nt::status::{STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION};

const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
const ERROR_CANNOT_FIND_WND_CLASS: u32 = 1407;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;
const HWND_MESSAGE: u64 = u64::MAX - 2;
// These guest HWNDs occupy the reserved slots below the first guest
// allocation. Neither value comes from a host handle lookup.
const DESKTOP_PARENT: u32 = 0x0001_000c;
const MESSAGE_PARENT: u32 = 0x0001_000e;
const GA_PARENT: u32 = 1;
const GA_ROOT: u32 = 2;
const GA_ROOTOWNER: u32 = 3;
const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_NOSENDCHANGING: u32 = 0x0400;
const SWP_KEEP_CURRENT: u32 =
    SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING;
const CALLBACK_RETURN_BYTES: u32 = 24;
const DEFAULT_IME_HANDLE: u32 = 8;
const THREAD_DEFAULT_IME_HANDLE: u32 = 3;
const DEFAULT_DIMENSION: i32 = i32::MIN;

fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("callback DWORD"))
}

fn qword(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("callback pointer"))
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

enum CaptureError {
    Fault(MemFault),
    Parameter,
    Unsupported(&'static str),
}

impl From<MemFault> for CaptureError {
    fn from(error: MemFault) -> Self {
        Self::Fault(error)
    }
}

fn report(p: &mut Proc, t: &Thread, error: CaptureError) -> Result<u64, Outcome> {
    match error {
        CaptureError::Fault(fault) if p.vm.take_guard(fault.addr) => query_error(
            p,
            t,
            STATUS_GUARD_PAGE_VIOLATION,
            Some(STATUS_GUARD_PAGE_VIOLATION),
        ),
        CaptureError::Fault(_) => query_error(p, t, ERROR_NOACCESS, Some(STATUS_ACCESS_VIOLATION)),
        CaptureError::Parameter => query_error(p, t, ERROR_INVALID_PARAMETER, None),
        CaptureError::Unsupported(detail) => Err(failure(detail)),
    }
}

fn descriptor(mem: &impl Mem, address: u64) -> Result<(usize, u64), CaptureError> {
    let mut buffer = [0; 16];
    mem.rd(address, &mut buffer)?;
    let length = dword(&buffer, 0);
    let capacity = dword(&buffer, 4);
    if capacity >> 31 != 0 {
        return Err(CaptureError::Unsupported(
            "ANSI window creation has no measured callback profile",
        ));
    }
    if length > capacity || length % 2 != 0 || length > u16::MAX.into() {
        return Err(CaptureError::Parameter);
    }
    Ok(((length / 2) as usize, qword(&buffer, 8)))
}

fn class_argument(mem: &impl Mem, address: u64) -> Result<Name, CaptureError> {
    if let Ok(atom) = u16::try_from(address) {
        return Ok(Name::Ordinal(atom));
    }
    let (length, buffer) = descriptor(mem, address)?;
    if length > 255 {
        return Err(CaptureError::Parameter);
    }
    Ok(Name::Counted(mem.wunits(buffer, length)?))
}

/// The selected ARM64 NTDLL image carries the USER procedure bridge measured in
/// the installed 29708 callback control. Verify the installed code before use.
fn procedure_bridge(p: &Proc) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 {
        return Err(failure(
            "window procedure callbacks lack a selected profile for this architecture",
        ));
    }
    let module = p
        .modules
        .by_name("ntdll.dll")
        .ok_or_else(|| failure("selected NTDLL is absent"))?;
    let address = p.modules.list[module]
        .base
        .checked_add(0x31e500)
        .ok_or_else(|| failure("selected NTDLL procedure bridge address overflow"))?;
    let expected = [0xb0ff_f310, 0x9133_4210, 0xd61f_0200];
    if !expected
        .into_iter()
        .enumerate()
        .all(|(index, instruction)| p.space.u32(address + index as u64 * 4) == Ok(instruction))
    {
        return Err(failure(
            "selected NTDLL procedure bridge differs from the measured profile",
        ));
    }
    Ok(address)
}

pub(super) fn disable_thread_ime(
    p: &mut Proc,
    t: &Thread,
    [thread]: [u64; 1],
) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 || thread as u32 != 0 {
        return Err(failure(
            "only the measured current-thread IME disable is supported",
        ));
    }
    p.gui
        .threads
        .get_mut(&t.tid)
        .ok_or_else(|| failure("IME disable requires a converted thread"))?
        .ime_disabled = true;
    Ok(1)
}

pub(super) fn query(p: &Proc, t: &Thread, [handle, query]: [u64; 2]) -> Result<u64, Outcome> {
    if query as u32 != DEFAULT_IME_HANDLE {
        return Err(failure(format!(
            "unmeasured USER window query {:#x}",
            query as u32
        )));
    }
    if p.arch == WinArch::Arm64 && is_system_root(handle) {
        return Ok(0);
    }
    let Some((_, window)) = p.gui.window_accepting_wildcard_generation(&p.vm, handle) else {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    };
    default_ime_window(p, window.owner)
}

pub(super) fn is_top_level(p: &Proc, t: &Thread, [handle]: [u64; 1]) -> Result<u64, Outcome> {
    let Some((_, window)) = p.gui.window_accepting_wildcard_generation(&p.vm, handle) else {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    };
    Ok(u64::from(matches!(
        window.creation.kind,
        WindowKind::Overlapped { .. }
    )))
}

pub(super) fn is_nonclient_dpi_scaling_enabled(
    p: &Proc,
    t: &Thread,
    [handle]: [u64; 1],
) -> Result<u64, Outcome> {
    let Some((_, window)) = p.gui.window_accepting_wildcard_generation(&p.vm, handle) else {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    };
    window
        .nonclient_dpi_scaling(&p.vm)
        .map(u64::from)
        .ok_or_else(|| failure("window non-client DPI context is outside the measured profile"))
}

fn is_system_root(handle: u64) -> bool {
    let raw = handle as u32;
    let system_handle = if raw >> 16 == u32::from(u16::MAX) {
        0x0001_0000 | u32::from(raw as u16)
    } else {
        raw
    };
    matches!(system_handle, DESKTOP_PARENT | MESSAGE_PARENT)
}

pub(super) fn get_ancestor(
    p: &Proc,
    t: &Thread,
    [handle, flags]: [u64; 2],
) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 {
        return Err(failure(
            "window ancestor lookup lacks a selected architecture profile",
        ));
    }
    let window = if is_system_root(handle) {
        None
    } else if let Some(window) = p.gui.window_accepting_wildcard_generation(&p.vm, handle) {
        Some(window)
    } else {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    };

    let value = match (flags as u32, window) {
        (GA_PARENT, Some((_, window))) => match window.creation.kind {
            WindowKind::MessageOnly => MESSAGE_PARENT,
            WindowKind::Overlapped { .. } => DESKTOP_PARENT,
        },
        (GA_ROOT | GA_ROOTOWNER, Some((hwnd, _))) => hwnd,
        (GA_PARENT | GA_ROOT | GA_ROOTOWNER, None) => 0,
        _ => return query_error(p, t, ERROR_INVALID_PARAMETER, None),
    };
    Ok(u64::from(value))
}

pub(super) fn set_position(
    p: &Proc,
    t: &Thread,
    [handle, insert_after, _, _, _, _, flags]: [u64; 7],
) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 {
        return Err(failure(
            "window positioning lacks a selected architecture profile",
        ));
    }
    if is_system_root(handle) {
        return Ok(0);
    }
    if p.gui
        .window_accepting_wildcard_generation(&p.vm, handle)
        .is_none()
    {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    }
    let flags = flags as u32;
    if flags & 0x8000_0000 != 0 {
        return query_error(p, t, ERROR_INVALID_FLAGS, None);
    }
    if flags != SWP_KEEP_CURRENT {
        return Err(failure(format!(
            "unmeasured window positioning flags {flags:#x}"
        )));
    }

    // NOZORDER suppresses reordering, but native USER still resolves the
    // insertion handle. The four special values are full-width HWND values.
    if matches!(insert_after as i64, -2..=1) {
        return Ok(1);
    }
    if is_system_root(insert_after) {
        return Ok(0);
    }
    if p.gui
        .window_accepting_wildcard_generation(&p.vm, insert_after)
        .is_none()
    {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    }
    Ok(1)
}

pub(super) fn get_thread_state(p: &Proc, t: &Thread, [query]: [u64; 1]) -> Result<u64, Outcome> {
    if query as u32 != THREAD_DEFAULT_IME_HANDLE {
        return Err(failure(format!(
            "unmeasured USER thread-state query {:#x}",
            query as u32
        )));
    }
    default_ime_window(p, t.tid)
}

fn default_ime_window(p: &Proc, tid: u32) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 || !p.gui.threads.contains_key(&tid) {
        return Err(failure(
            "default IME window query requires a selected USER thread",
        ));
    }
    // Message-only windows do not start a default IME window. The supported
    // overlapped creation profile requires IME to be disabled.
    Ok(0)
}

pub(super) fn create(p: &mut Proc, t: &mut Thread, arguments: [u64; 18]) -> Result<u64, Outcome> {
    let [
        extended_style,
        supplied,
        lookup,
        title,
        style,
        x,
        y,
        width,
        height,
        parent,
        menu,
        instance,
        parameter,
        flags,
        expected_version,
        activation,
        policy,
        band,
    ] = arguments;
    if parent != HWND_MESSAGE && parent != 0 && p.gui.window(parent).is_none() {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    }
    let lookup = match class_argument(&p.space, lookup) {
        Ok(value) => value,
        Err(error) => return report(p, t, error),
    };
    let upcase = p.registry.upcase_table();
    if upcase.len() != 65_536 {
        return Err(failure("window creation requires the installed case table"));
    }
    let instance = if instance == 0 {
        p.modules.exe().base
    } else {
        instance
    };
    let Some(class) =
        p.gui
            .class_for_window(&upcase, &lookup, instance, window_classes::user_module(p))
    else {
        return query_error(p, t, ERROR_CANNOT_FIND_WND_CLASS, None);
    };
    if extended_style as u32 != 0
        || menu != 0
        || flags as u32 != 0
        || expected_version as u32 & 0xffff_0000 != 0x4000_0000
        || activation as u32 != 0
        || policy != 0
        || class.definition.ansi_procedure
    {
        return Err(failure(
            "window creation arguments are outside the measured profiles",
        ));
    }
    let geometry = [x as i32, y as i32, width as i32, height as i32];
    let kind = match (parent, style as u32) {
        (HWND_MESSAGE, 0) if band as u32 == 1 => WindowKind::MessageOnly,
        (0, OVERLAPPED_STYLE)
            if p.gui
                .threads
                .get(&t.tid)
                .is_some_and(|thread| thread.ime_disabled)
                && !geometry.contains(&DEFAULT_DIMENSION)
                && geometry[2..].iter().all(|&size| size >= 0)
                && class.definition.record[4..8] == [0; 4]
                && class.definition.record[16..24] == [0; 8]
                && class.definition.record[32..64] == [0; 32]
                && class.definition.record[72..80] == [0; 8]
                && class.definition.menu == [0; 2] =>
        {
            let crate::user::windows::gui::Availability::Available(inputs) = &p
                .native
                .as_ref()
                .ok_or_else(|| failure("overlapped window needs native GUI inputs"))?
                .gui
            else {
                return Err(failure("overlapped window needs native GUI inputs"));
            };
            let limits = *inputs.overlapped_window_limits.as_ref().map_err(failure)?;
            WindowKind::Overlapped {
                limits,
                tracking_size: [geometry[2], geometry[3]],
            }
        }
        _ => {
            return Err(failure(
                "window creation is outside the measured message-only and IME-disabled overlapped profiles",
            ));
        }
    };
    let supplied = match class_argument(&p.space, supplied) {
        Ok(value) => value,
        Err(error) => return report(p, t, error),
    };
    let title = if title == 0 {
        0
    } else {
        match descriptor(&p.space, title).and_then(|(length, address)| {
            p.space.wunits(address, length)?;
            Ok(address)
        }) {
            Ok(address) => address,
            Err(error) => return report(p, t, error),
        }
    };
    procedure_bridge(p)?;
    let creation = Creation {
        kind,
        module: instance,
        title,
        class_argument: supplied,
        argument: parameter,
        geometry,
    };
    let csr = p
        .object_namespace
        .selected_csr_server()
        .ok()
        .and_then(|server| server.client_data.clone())
        .ok_or_else(|| failure("window creation requires the selected CSR USER table"))?;
    let handle = p
        .gui
        .open_window(&mut p.vm, p.pid, t.tid, class, creation, &csr)
        .map_err(|error| failure(format!("GUI window data view: {error:?}")))?;
    let phase = if p.gui.theme_hook_started {
        Phase::Measure
    } else {
        p.gui.theme_hook_started = true;
        Phase::LoadTheme
    };
    match deliver(
        p,
        t,
        Continuation {
            handle,
            phase,
            result: u64::from(handle),
        },
    ) {
        Ok(()) => Err(Outcome::Continue),
        Err(outcome) => {
            let _ = p.gui.close_window(&mut p.vm, handle);
            if phase == Phase::LoadTheme {
                p.gui.theme_hook_started = false;
            }
            Err(outcome)
        }
    }
}

pub(super) fn class_name(
    p: &mut Proc,
    t: &Thread,
    [handle, real, output]: [u64; 3],
) -> Result<u64, Outcome> {
    let message_parent = "Message".encode_utf16().collect::<Vec<_>>();
    let name = if handle == u64::from(MESSAGE_PARENT) && p.gui.theme_hook_started {
        &message_parent
    } else {
        let Some(window) = p.gui.window(handle) else {
            return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
        };
        match &window.class.spelling {
            Name::Counted(name) => name,
            Name::Ordinal(_) => return Err(failure("ordinal class spelling is unavailable")),
        }
    };
    if real != 0 {
        return Err(failure(
            "real class query lacks a measured subclass profile",
        ));
    }
    // Counted Unicode output uses byte lengths while the service result is a
    // character count. Leave room for the NUL and preserve the unused tail.
    let copy = (|| -> Result<Option<usize>, MemFault> {
        let mut record = [0; 16];
        p.space.rd(output, &mut record)?;
        let maximum = u16::from_le_bytes([record[2], record[3]]) as usize;
        if maximum < 4 {
            return Ok(None);
        }
        let units = (maximum / 2 - 1).min(name.len());
        let bytes: Vec<_> = name[..units]
            .iter()
            .copied()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        p.space.wr(qword(&record, 8), &bytes)?;
        p.space.w16(output, (units * 2) as u16)?;
        Ok(Some(units))
    })();
    match copy {
        Ok(Some(units)) => Ok(units as u64),
        Ok(None) => query_error(
            p,
            t,
            ERROR_INSUFFICIENT_BUFFER,
            Some(STATUS_BUFFER_TOO_SMALL),
        ),
        Err(error) => report(p, t, error.into()),
    }
}

pub(super) fn set_window_long_ptr(
    p: &mut Proc,
    t: &Thread,
    [handle, index, value, ansi]: [u64; 4],
) -> Result<u64, Outcome> {
    if index as u32 as i32 != -2 || ansi as u32 != 0 {
        return Err(failure(
            "window-long pointer index or encoding is outside the measured theme profile",
        ));
    }
    let handle = handle as u32;
    if p.gui.window(u64::from(handle)).is_none() {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    }
    p.gui
        .set_window_theme_value(&mut p.vm, handle, value)
        .map_err(|error| failure(format!("GUI window theme value: {error:?}")))
}

pub(super) fn property(
    p: &mut Proc,
    t: &Thread,
    [handle, atom]: [u64; 2],
    operation: PropertyOperation,
) -> Result<u64, Outcome> {
    // The native services read HWND's low DWORD and the atom's low WORD.
    let Some(properties) = p.gui.window_properties(handle as u32) else {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    };
    let atom = atom as u16;
    match operation {
        PropertyOperation::Get => Ok(properties.get(&atom).copied().unwrap_or(0)),
        PropertyOperation::Set(_) if atom == 0 => query_error(p, t, ERROR_INVALID_PARAMETER, None),
        PropertyOperation::Set(data) => {
            properties.insert(atom, data);
            Ok(1)
        }
        PropertyOperation::Remove => Ok(properties.remove(&atom).unwrap_or(0)),
    }
}

pub(super) fn destroy(p: &mut Proc, t: &mut Thread, [handle]: [u64; 1]) -> Result<u64, Outcome> {
    let Some(window) = p.gui.window(handle) else {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    };
    if window.owner != t.tid || window.destroying {
        return query_error(p, t, 5, None);
    }
    procedure_bridge(p)?;
    p.gui
        .start_window_destruction(handle, t.tid)
        .expect("validated window");
    let continuation = Continuation {
        handle: handle as u32,
        phase: Phase::BeginDestroy,
        result: 1,
    };
    deliver(p, t, continuation)?;
    Err(Outcome::Continue)
}

fn fixed_message(window: &Window, bridge: u64, message: u32) -> Vec<u8> {
    let mut bytes = vec![0; 48];
    put64(&mut bytes, 0, window.client_address);
    put32(&mut bytes, 8, message);
    put64(&mut bytes, 0x20, window.class.definition.procedure());
    put64(&mut bytes, 0x28, bridge);
    bytes
}

fn measure(window: &Window, bridge: u64) -> Vec<u8> {
    let mut bytes = vec![0; 80];
    put64(&mut bytes, 0, window.client_address);
    put32(&mut bytes, 8, 0x24);
    let limits = match window.creation.kind {
        WindowKind::MessageOnly => [314, 50, 116, 116, -8, -8, 136, 39, 1524, 866],
        WindowKind::Overlapped { limits, .. } => limits,
    };
    for (index, value) in limits.into_iter().enumerate() {
        put32(&mut bytes, 0x18 + index * 4, value as u32);
    }
    put64(&mut bytes, 0x40, window.class.definition.procedure());
    put64(&mut bytes, 0x48, bridge);
    bytes
}

fn calculate_rectangle(window: &Window, bridge: u64) -> Vec<u8> {
    let mut bytes = vec![0; 56];
    put64(&mut bytes, 0, window.client_address);
    put32(&mut bytes, 8, 0x83);
    put64(&mut bytes, 0x18, window.class.definition.procedure());
    put64(&mut bytes, 0x20, bridge);
    bytes[0x28..0x38].copy_from_slice(&window.creation.rectangle());
    bytes
}

fn create_message(window: &Window, bridge: u64, message: u32) -> Vec<u8> {
    let mut bytes = vec![0; 0xb0];
    let creation = &window.creation;
    match &creation.class_argument {
        Name::Ordinal(atom) => put64(&mut bytes, 0x88, u64::from(*atom)),
        Name::Counted(class) => {
            put32(&mut bytes, 8, 1);
            put64(&mut bytes, 0x18, 0xa8);
            put64(&mut bytes, 0x88, 0xb0);
            put32(&mut bytes, 0xa8, 0x88);
            bytes.extend(class.iter().copied().chain([0]).flat_map(u16::to_le_bytes));
            bytes.resize(bytes.len().next_multiple_of(8), 0);
        }
    }
    let length = bytes.len() as u32;
    put32(&mut bytes, 0, length);
    put32(&mut bytes, 4, 0x30);
    put64(&mut bytes, 0x28, window.client_address);
    put32(&mut bytes, 0x30, message);
    put64(&mut bytes, 0x40, 1);
    put64(&mut bytes, 0x48, creation.argument);
    put64(&mut bytes, 0x50, creation.module);
    match creation.kind {
        WindowKind::MessageOnly => put64(&mut bytes, 0x60, u64::from(MESSAGE_PARENT)),
        WindowKind::Overlapped { .. } => {
            put32(&mut bytes, 0x78, OVERLAPPED_STYLE);
            put32(&mut bytes, 0x90, 0x100);
        }
    }
    let [x, y, width, height] = creation.geometry;
    for (index, value) in [height, width, y, x].into_iter().enumerate() {
        put32(&mut bytes, 0x68 + index * 4, value as u32);
    }
    put64(&mut bytes, 0x80, creation.title);
    put64(&mut bytes, 0x98, window.class.definition.procedure());
    put64(&mut bytes, 0xa0, bridge);
    bytes
}

fn load_theme(p: &Proc) -> Result<Vec<u8>, Outcome> {
    let runtime = p
        .native
        .as_ref()
        .ok_or_else(|| failure("selected GUI inputs are absent"))?;
    let dll = format!(
        "{}\\uxtheme.dll",
        runtime.guest_directory.trim_end_matches('\\')
    );
    let dll: Vec<_> = dll.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let entry: Vec<_> = "ThemeInitApiHook"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let entry_offset = (0x58 + dll.len() + 2).next_multiple_of(8);
    let length = (entry_offset + entry.len() + 2).next_multiple_of(8);
    let mut bytes = vec![0; length];
    put32(&mut bytes, 0, length as u32);
    put32(&mut bytes, 4, 0x70);
    put32(&mut bytes, 8, 2);
    put64(&mut bytes, 0x18, 0x48);
    put32(
        &mut bytes,
        0x28,
        dll.len() as u32 | ((dll.len() as u32 + 2) << 16),
    );
    put64(&mut bytes, 0x30, 0x58);
    put32(
        &mut bytes,
        0x38,
        entry.len() as u32 | ((entry.len() as u32 + 2) << 16),
    );
    put64(&mut bytes, 0x40, entry_offset as u64);
    put32(&mut bytes, 0x48, 0x30);
    put32(&mut bytes, 0x4c, 0x40);
    bytes[0x58..0x58 + dll.len()].copy_from_slice(&dll);
    bytes[entry_offset..entry_offset + entry.len()].copy_from_slice(&entry);
    Ok(bytes)
}

fn deliver(p: &mut Proc, t: &mut Thread, next: Continuation) -> Result<(), Outcome> {
    let window = p
        .gui
        .window(u64::from(next.handle))
        .ok_or_else(|| failure("pending USER window is unavailable"))?;
    let bridge = procedure_bridge(p)?;
    let (index, payload) = match next.phase {
        Phase::LoadTheme => (75, load_theme(p)?),
        Phase::Measure => (18, measure(window, bridge)),
        Phase::NonClientCreate => (10, create_message(window, bridge, 0x81)),
        Phase::NonClientRectangle => (21, calculate_rectangle(window, bridge)),
        Phase::Create => (10, create_message(window, bridge, 1)),
        Phase::BeginDestroy => (2, fixed_message(window, bridge, 0x90)),
        Phase::Destroy => (2, fixed_message(window, bridge, 2)),
        Phase::NonClientDestroy => (3, fixed_message(window, bridge, 0x82)),
    };
    let frame = CallbackFrame::prepare(p, t, t.cpu.sp(), t.cpu.pc(), index, &payload)?;
    let client_info =
        (next.phase != Phase::LoadTheme).then_some([u64::from(next.handle), window.client_address]);
    match frame.enter(p, t, Completion::ResumeWindow(next), client_info) {
        Outcome::Continue => Ok(()),
        outcome => Err(outcome),
    }
}

fn measure_reply(p: &mut Proc, handle: u32, response: &[u8]) -> Result<(), Outcome> {
    let window = p
        .gui
        .window_mut(handle)
        .ok_or_else(|| failure("pending USER window is unavailable"))?;
    let WindowKind::Overlapped { tracking_size, .. } = &mut window.creation.kind else {
        return Ok(());
    };
    let mut limits = [0; 40];
    if qword(response, 8) != limits.len() as u64 {
        return Err(failure(
            "overlapped window callback returned a different MINMAXINFO layout",
        ));
    }
    p.space
        .rd(qword(response, 16), &mut limits)
        .map_err(|error| {
            failure(format!(
                "overlapped window limits are inaccessible: {error:?}"
            ))
        })?;
    for (axis, size) in tracking_size.iter_mut().enumerate() {
        let minimum = dword(&limits, 24 + 4 * axis) as i32;
        let maximum = dword(&limits, 32 + 4 * axis) as i32;
        if minimum < 0 || maximum < minimum {
            return Err(failure(
                "overlapped window callback returned unsupported tracking limits",
            ));
        }
        *size = (*size).clamp(minimum, maximum);
    }
    let [x, y, _, _] = window.creation.geometry;
    if x.checked_add(tracking_size[0]).is_none() || y.checked_add(tracking_size[1]).is_none() {
        return Err(failure(
            "overlapped window rectangle exceeds the measured coordinate range",
        ));
    }
    Ok(())
}

pub(super) fn resume(
    p: &mut Proc,
    t: &mut Thread,
    mut pending: Continuation,
    [output, length, status]: [u64; 3],
) -> Result<u64, Outcome> {
    if (status as u32 as i32) < 0 || length as u32 != CALLBACK_RETURN_BYTES {
        let _ = p.gui.close_window(&mut p.vm, pending.handle);
        return Err(failure(
            "USER window callback did not return its measured result",
        ));
    }
    let mut response = [0; CALLBACK_RETURN_BYTES as usize];
    p.space.rd(output, &mut response).map_err(|error| {
        failure(format!(
            "USER window callback result is inaccessible: {error:?}"
        ))
    })?;
    let value = qword(&response, 0);
    pending.phase = match pending.phase {
        Phase::LoadTheme => Phase::Measure,
        Phase::Measure => {
            if let Err(outcome) = measure_reply(p, pending.handle, &response) {
                let _ = p.gui.close_window(&mut p.vm, pending.handle);
                return Err(outcome);
            }
            Phase::NonClientCreate
        }
        Phase::NonClientCreate if value == 0 => {
            pending.result = 0;
            p.gui
                .start_window_destruction(u64::from(pending.handle), t.tid);
            Phase::NonClientDestroy
        }
        Phase::NonClientCreate => Phase::NonClientRectangle,
        Phase::NonClientRectangle => {
            let mut rectangle = [0; 16];
            p.space
                .rd(qword(&response, 16), &mut rectangle)
                .map_err(|error| {
                    failure(format!("nonclient rectangle is inaccessible: {error:?}"))
                })?;
            p.gui
                .set_window_client_rectangle(&mut p.vm, pending.handle, rectangle)
                .map_err(|error| failure(format!("nonclient rectangle write failed: {error:?}")))?;
            Phase::Create
        }
        Phase::Create if value == u64::MAX => {
            pending.result = 0;
            p.gui
                .start_window_destruction(u64::from(pending.handle), t.tid);
            Phase::BeginDestroy
        }
        Phase::Create => return Ok(pending.result),
        Phase::BeginDestroy => Phase::Destroy,
        Phase::Destroy => Phase::NonClientDestroy,
        Phase::NonClientDestroy => {
            p.gui
                .close_window(&mut p.vm, pending.handle)
                .map_err(|error| failure(format!("GUI window removal failed: {error:?}")))?;
            return Ok(pending.result);
        }
    };
    deliver(p, t, pending)?;
    Err(Outcome::Continue)
}
