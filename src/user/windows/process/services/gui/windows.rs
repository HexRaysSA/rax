//! Measured 64-bit USER window creation, callbacks, and destruction.

use super::{
    CallbackFrame, Completion, Mem, Outcome, Proc, Thread, WinArch, failure, query_error,
    window_classes,
};
use crate::user::windows::gui::window_classes::Name;
use crate::user::windows::gui::windows::{
    Continuation, Creation, Phase, PropertyOperation, Window,
};
use crate::user::windows::memory::MemFault;
use crate::user::windows::nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOACCESS};
use crate::user::windows::nt::status::{STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION};

const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
const ERROR_CANNOT_FIND_WND_CLASS: u32 = 1407;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;
const HWND_MESSAGE: u64 = u64::MAX - 2;
const MESSAGE_PARENT: u64 = 0x0001_000e;
const CALLBACK_RETURN_BYTES: u32 = 24;

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
    if parent != HWND_MESSAGE
        || style as u32 != 0
        || extended_style as u32 != 0
        || menu != 0
        || flags as u32 != 0
        || expected_version as u32 & 0xffff_0000 != 0x4000_0000
        || activation as u32 != 0
        || policy != 0
        || band as u32 != 1
        || class.definition.ansi_procedure
    {
        return Err(failure(
            "window creation arguments are outside the measured message-only window profile",
        ));
    }
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
        module: instance,
        title,
        class_argument: supplied,
        argument: parameter,
        geometry: [x as i32, y as i32, width as i32, height as i32],
    };
    let csr = p
        .object_namespace
        .selected_csr_server()
        .ok()
        .and_then(|server| server.client_data.clone())
        .ok_or_else(|| failure("window creation requires the selected CSR USER table"))?;
    let handle = p
        .gui
        .open_message_window(&mut p.vm, p.pid, t.tid, class, creation, &csr)
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
            let _ = p.gui.close_message_window(&mut p.vm, handle);
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
    let name = if handle == MESSAGE_PARENT && p.gui.theme_hook_started {
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
    for (index, value) in [314i32, 50, 116, 116, -8, -8, 136, 39, 1524, 866]
        .into_iter()
        .enumerate()
    {
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
    let [x, y, width, height] = window.creation.geometry;
    for (index, value) in [x, y, x.saturating_add(width), y.saturating_add(height)]
        .into_iter()
        .enumerate()
    {
        put32(&mut bytes, 0x28 + index * 4, value as u32);
    }
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
    put64(&mut bytes, 0x60, MESSAGE_PARENT);
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

pub(super) fn resume(
    p: &mut Proc,
    t: &mut Thread,
    mut pending: Continuation,
    [output, length, status]: [u64; 3],
) -> Result<u64, Outcome> {
    if (status as u32 as i32) < 0 || length as u32 != CALLBACK_RETURN_BYTES {
        let _ = p.gui.close_message_window(&mut p.vm, pending.handle);
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
        Phase::Measure => Phase::NonClientCreate,
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
                .close_message_window(&mut p.vm, pending.handle)
                .map_err(|error| failure(format!("GUI window removal failed: {error:?}")))?;
            return Ok(pending.result);
        }
    };
    deliver(p, t, pending)?;
    Err(Outcome::Continue)
}
