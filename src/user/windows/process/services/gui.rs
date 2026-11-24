//! Win32k conversion and thread-owned kernel-to-user callback continuations.
use super::*;
use crate::error::MemoryAccessKind;
use crate::user::windows::gui::{Availability, Callback, Completion, Wow64Gdi};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOACCESS};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_INVALID_PARAMETER,
};
use crate::user::windows::object_namespace::csr::client_data::CsrClientData;
use crate::user::windows::objects::Object;
use std::sync::Arc;

mod composition;
mod cursor_icons;
mod input_contexts;
mod message_queue;
mod system_parameters;
mod thread_info;
mod user_objects;
mod window_classes;
mod windows;

const NO_CALLBACK_ACTIVE: u32 = 0xc000_0258;
const CLIENT_THREAD_SETUP: u32 = 84;
const WINDOW_CALLBACK_CLIENT_INFO: u64 = 0x840;

fn returned(t: &mut Thread, value: u64, sp: u64, resume: u64, wow64: bool) -> Outcome {
    write_value(&mut t.cpu, Value::Int(value));
    if wow64 {
        t.cpu.set_sp(sp);
        t.cpu.set_pc(resume);
    }
    Outcome::Continue
}

fn failure(message: impl std::fmt::Display) -> Outcome {
    Outcome::Fail(format!("{message}"))
}

pub(super) fn initialize(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    if let Some((inputs, gdi)) = wow64_inputs(p, wow64) {
        if matches!(gdi, Wow64Gdi::Legacy) {
            return failure("not implemented for unmeasured native NtGdiInit2 profile");
        }
        return initialize_wow64(p, t, sp, resume, inputs, gdi, None);
    }
    convert(p, t, sp, resume, wow64, None)
}

pub(super) fn initialize_legacy(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    if let Some((inputs, gdi @ Wow64Gdi::Legacy)) = wow64_inputs(p, wow64) {
        return initialize_wow64(p, t, sp, resume, inputs, gdi, Some(1));
    }
    if wow64
        || !p
            .native
            .as_ref()
            .is_some_and(|runtime| runtime.uses_legacy_gdi_init(p.arch))
    {
        return failure("not implemented for unmeasured native NtGdiInit profile");
    }
    convert(p, t, sp, resume, false, Some(Completion::Value(1)))
}

fn wow64_inputs(
    p: &Proc,
    wow64: bool,
) -> Option<(Arc<crate::user::windows::gui::Inputs>, Wow64Gdi)> {
    if p.arch == WinArch::X86
        && wow64
        && let Availability::Wow64Companion(inputs, gdi) = &p.native.as_ref()?.gui
    {
        Some((inputs.clone(), *gdi))
    } else {
        None
    }
}

fn initialize_wow64(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    inputs: Arc<crate::user::windows::gui::Inputs>,
    profile: Wow64Gdi,
    result: Option<u32>,
) -> Outcome {
    let Some((state, teb)) = p.wow64.as_ref().zip(t.teb_allocation.companion()) else {
        return failure("WoW64 GUI requires the process and thread companions");
    };
    let Some(client_data) = state.user_data.as_ref() else {
        return failure("WoW64 GUI requires the selected USER startup connection");
    };
    if !client_data.owns_views(&p.vm) {
        return failure("WoW64 GUI lost the selected USER startup views");
    }

    // On the measured pairs, native USER initializes the companion TEB only.
    // Repeated leaf calls preserve the process value and the thread record.
    let peb = state.native_peb;
    let first = !p
        .gui
        .threads
        .get(&t.tid)
        .is_some_and(|thread| thread.initialized);
    if first {
        for (address, length) in [
            (peb + 0xf8, 8),
            (peb + 0x108, 4),
            (teb + 0x78, 8),
            (teb + 0x800, 160),
        ] {
            if let Err(error) = p.space.probe(address, length, MemoryAccessKind::Write) {
                return failure(format!(
                    "WoW64 GUI companion state is inaccessible: {error:?}"
                ));
            }
        }
    }
    let tick = p.uptime_ms() as u32;
    let version =
        u64::from(p.gui.executable_version.0) << 8 | u64::from(p.gui.executable_version.1 & 0xff);
    let (gdi, client) = match p
        .gui
        .prepare_wow64_thread(&mut p.vm, inputs, t.tid, tick, version)
    {
        Ok(state) => state,
        Err(error) => return failure(format!("WoW64 GUI views or thread record: {error:?}")),
    };
    let value = p
        .gui
        .value
        .unwrap_or_else(|| u64::from(profile.process_value(p.random() as u32)));
    if first {
        let mut client_bytes = [0; 160];
        for (word, bytes) in client.iter().zip(client_bytes.chunks_exact_mut(8)) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        let write = || {
            p.space.w64(peb + 0xf8, gdi)?;
            p.space.w32(peb + 0x108, value as u32)?;
            p.space.w64(teb + 0x78, u64::from(t.tid))?;
            p.space.wr(teb + 0x800, &client_bytes)
        };
        if let Err(error) = write() {
            return failure(format!("WoW64 GUI companion state was lost: {error:?}"));
        }
        p.gui
            .threads
            .get_mut(&t.tid)
            .expect("prepared companion thread")
            .initialized = true;
        p.gui.value = Some(value);
    }
    returned(t, result.map_or(value, u64::from), sp, resume, true)
}

pub(super) fn remote_connect_state(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    if let Some((inputs, gdi)) = wow64_inputs(p, wow64) {
        let value = inputs.remote_connect_state;
        return initialize_wow64(p, t, sp, resume, inputs, gdi, Some(value));
    }
    let value = match p.native.as_ref().map(|runtime| &runtime.gui) {
        Some(Availability::Available(inputs)) if inputs.arch == p.arch => {
            inputs.remote_connect_state
        }
        Some(Availability::Unavailable(reason)) => {
            return failure(format!("remote connection query unavailable: {reason}"));
        }
        _ => return failure("remote connection query requires selected native GUI inputs"),
    };
    convert(
        p,
        t,
        sp,
        resume,
        wow64,
        Some(Completion::Value(u64::from(value))),
    )
}

pub(super) fn process_dpi(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    if let Some((inputs, gdi)) = wow64_inputs(p, wow64) {
        let Some(dpi) = inputs.process_dpi else {
            return failure("selected Win32u has no usable process DPI query");
        };
        return initialize_wow64(p, t, sp, resume, inputs, gdi, Some(dpi.get()));
    }
    let dpi = match p.native.as_ref().map(|runtime| &runtime.gui) {
        Some(Availability::Available(inputs)) if inputs.arch == p.arch => inputs.process_dpi,
        Some(Availability::Unavailable(reason)) => {
            return failure(format!("process DPI query unavailable: {reason}"));
        }
        _ => return failure("process DPI query requires selected native GUI inputs"),
    };
    let Some(dpi) = dpi else {
        return failure("selected Win32u has no usable process DPI query");
    };
    convert(
        p,
        t,
        sp,
        resume,
        wow64,
        Some(Completion::Value(u64::from(dpi.get()))),
    )
}

pub(super) fn set_process_dpi_awareness(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let selected = p.native.as_ref().is_some_and(|runtime| {
        (
            runtime.version.major,
            runtime.version.minor,
            runtime.version.build,
            runtime.version.product_type,
        ) == (10, 0, 29708, 1)
            && runtime.object_namespace.native_machine == Some(WinArch::Arm64.machine())
    });
    let session_zero = p
        .objects
        .wnf_queries()
        .is_some_and(|queries| queries.session == 0);
    if !selected || !session_zero || p.arch != WinArch::Arm64 || wow64 {
        return failure("process DPI awareness setter requires the observed ARM64 session 0");
    }
    let Some([context, fallback]) = arguments(p, t, sp) else {
        return failure("process DPI awareness setter arguments are unreadable");
    };
    if (context as u32, fallback as u32) != (0x12, 0) {
        return failure("process DPI awareness setter arguments are outside the observed profile");
    }

    // This raw session-0 call returns FALSE with the existing context and
    // last error intact. The public USER32 setter can set last error itself.
    convert(p, t, sp, resume, wow64, Some(Completion::Value(0)))
}

fn first_argument(p: &Proc, t: &Thread, sp: u64) -> Option<u64> {
    match t.cpu.instruction_arch() {
        WinArch::Arm64 => Some(t.cpu.call_gpr(0)),
        WinArch::X64 => Some(t.cpu.gpr(10)),
        WinArch::X86 => sp
            .checked_add(4)
            .and_then(|address| p.space.u32(address).ok())
            .map(u64::from),
    }
}

pub(super) fn register_window_message(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let Some(name) = first_argument(p, t, sp) else {
        return failure("window message argument capture is unreadable");
    };
    convert(
        p,
        t,
        sp,
        resume,
        wow64,
        Some(Completion::RegisterWindowMessage(name)),
    )
}

pub(super) fn register_lpk(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let Some(value) = first_argument(p, t, sp) else {
        return failure("LPK registration argument capture is unreadable");
    };
    convert(
        p,
        t,
        sp,
        resume,
        wow64,
        Some(Completion::RegisterLpk(value as u32)),
    )
}

pub(super) fn thread_desktop(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let inputs = match p.native.as_ref().map(|runtime| &runtime.gui) {
        Some(Availability::Available(inputs)) if inputs.arch == p.arch => inputs.clone(),
        Some(Availability::Unavailable(reason)) => {
            return failure(format!("thread desktop query unavailable: {reason}"));
        }
        _ => return failure("thread desktop query requires selected native GUI inputs"),
    };
    let Some(id) = first_argument(p, t, sp) else {
        return failure("thread desktop argument capture is unreadable");
    };
    let id = id as u32 & !3;
    // CID lookup retains low-tag aliases and ended threads while an object
    // reference remains. No guest identifier is passed to the observing host.
    let known = id == t.tid || p.objects.iter().any(|(_, object)| {
        matches!(object, crate::user::windows::objects::Object::Thread { tid, .. } if *tid == id)
    });
    let value = if known {
        let Some(handle) = p.objects.desktop_handle(&inputs.assigned_desktop) else {
            return failure("selected assigned-desktop handle identity was lost");
        };
        u64::from(handle)
    } else {
        0
    };
    convert(p, t, sp, resume, wow64, Some(Completion::Value(value)))
}

pub(super) fn process_window_station(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    match user_objects::station(p) {
        Ok(value) => convert(p, t, sp, resume, wow64, Some(Completion::Value(value))),
        Err(outcome) => outcome,
    }
}

pub(super) fn user_object_operation<const N: usize>(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
    operation: fn([u64; N]) -> Completion,
) -> Outcome {
    let Some(arguments) = arguments(p, t, sp) else {
        return failure("USER object service arguments are unreadable");
    };
    convert(p, t, sp, resume, wow64, Some(operation(arguments)))
}

pub(super) fn process_ui_context(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let arguments = match t.cpu.instruction_arch() {
        WinArch::Arm64 => Some((t.cpu.call_gpr(0), t.cpu.call_gpr(1))),
        WinArch::X64 => Some((t.cpu.gpr(10), t.cpu.gpr(2))),
        WinArch::X86 => sp.checked_add(8).and_then(|last| {
            Some((
                u64::from(p.space.u32(last - 4).ok()?),
                u64::from(p.space.u32(last).ok()?),
            ))
        }),
    };
    let Some((process, output)) = arguments else {
        return failure("process UI context argument capture is unreadable");
    };
    // The cold native entry converts the thread before checking either argument.
    convert(
        p,
        t,
        sp,
        resume,
        wow64,
        Some(Completion::ProcessUiContext { process, output }),
    )
}

fn arguments<const N: usize>(p: &Proc, t: &Thread, sp: u64) -> Option<[u64; N]> {
    let mut values = [0; N];
    for (index, value) in values.iter_mut().enumerate() {
        *value = match t.cpu.instruction_arch() {
            WinArch::Arm64 if index < 8 => t.cpu.call_gpr(index),
            WinArch::Arm64 => p.space.u64(sp.checked_add(8 * (index as u64 - 8))?).ok()?,
            WinArch::X64 => match [10, 2, 8, 9].get(index) {
                Some(&register) => t.cpu.gpr(register),
                None => p
                    .space
                    .u64(sp.checked_add(0x28 + 8 * (index as u64 - 4))?)
                    .ok()?,
            },
            WinArch::X86 => u64::from(p.space.u32(sp.checked_add(4 * (index as u64 + 1))?).ok()?),
        };
    }
    Some(values)
}

pub(super) fn find_cursor_icon(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let Some(arguments) = arguments(p, t, sp) else {
        return failure("cursor/icon lookup arguments are unreadable");
    };
    convert(
        p,
        t,
        sp,
        resume,
        wow64,
        Some(Completion::FindCursorIcon(arguments)),
    )
}

pub(super) fn window_operation<const N: usize>(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
    operation: fn([u64; N]) -> Completion,
) -> Outcome {
    if p.arch.ptr_size() != 8 {
        return failure("window services require a native 64-bit GUI layout");
    }
    let Some(arguments) = arguments(p, t, sp) else {
        return failure("window service arguments are unreadable");
    };
    convert(p, t, sp, resume, wow64, Some(operation(arguments)))
}

pub(super) fn system_parameters(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let Some([action, parameter, output]) = arguments(p, t, sp) else {
        return failure("system parameters argument capture is unreadable");
    };
    convert(
        p,
        t,
        sp,
        resume,
        wow64,
        Some(Completion::SystemParameter {
            action: action as u32,
            parameter: parameter as u32,
            output,
        }),
    )
}

fn selected_user_client_data(p: &Proc) -> Result<Arc<CsrClientData>, Outcome> {
    p.wow64
        .as_ref()
        .and_then(|state| state.user_data.clone())
        .or_else(|| {
            p.object_namespace
                .selected_csr_server()
                .ok()
                .and_then(|server| server.client_data.clone())
        })
        .ok_or_else(|| failure("the selected CSR USER handle table is unavailable"))
}

fn query_error(p: &Proc, t: &Thread, error: u32, status: Option<u32>) -> Result<u64, Outcome> {
    let offsets = crate::user::windows::layout::offsets(p.arch);
    p.space
        .w32(t.teb + offsets.teb_last_error, error)
        .map_err(|_| failure("GUI service cannot write the guest last error"))?;
    if let Some(status) = status {
        p.space
            .w32(t.teb + offsets.teb_last_status, status)
            .map_err(|_| failure("GUI service cannot write the guest last status"))?;
    }
    Ok(0)
}

fn guest_memory_status(p: &mut Proc, address: u64) -> u32 {
    if p.vm.take_guard(address) {
        STATUS_GUARD_PAGE_VIOLATION
    } else {
        STATUS_ACCESS_VIOLATION
    }
}

fn write_guest(p: &mut Proc, address: u64, data: &[u8]) -> Result<(), u32> {
    p.space
        .wr(address, data)
        .map_err(|fault| guest_memory_status(p, fault.addr))
}

fn probe_guest_write(p: &mut Proc, address: u64, bytes: usize) -> Result<(), u32> {
    p.space
        .probe(address, bytes, MemoryAccessKind::Write)
        .map_err(|fault| guest_memory_status(p, fault.address))
}

fn check_guest_alignment(address: u64, alignment: u64) -> Result<(), u32> {
    if address.is_multiple_of(alignment) {
        Ok(())
    } else {
        Err(STATUS_DATATYPE_MISALIGNMENT)
    }
}

fn complete_window_message(p: &Proc, t: &Thread, descriptor: u64) -> Result<u64, Outcome> {
    let invalid = || {
        query_error(
            p,
            t,
            ERROR_INVALID_PARAMETER,
            Some(STATUS_INVALID_PARAMETER),
        )
    };
    let width = p.arch.ptr_size() as usize;
    let Ok(record) = p.space.bytes(descriptor, 2 * width) else {
        return invalid();
    };
    let length = usize::from(u16::from_le_bytes([record[0], record[1]]));
    let maximum = usize::from(u16::from_le_bytes([record[2], record[3]]));
    if length > maximum || length % 2 != 0 {
        return query_error(p, t, ERROR_INVALID_PARAMETER, Some(STATUS_ACCESS_VIOLATION));
    }
    if length > 255 * 2 {
        return query_error(p, t, ERROR_INVALID_PARAMETER, None);
    }
    let mut pointer = [0; 8];
    pointer[..width].copy_from_slice(&record[width..]);
    let buffer = u64::from_le_bytes(pointer);
    let Ok(mut units) = p.space.wunits(buffer, (length / 2).max(1)) else {
        return invalid();
    };
    units.truncate(length / 2);
    if let Some(end) = units.iter().position(|&unit| unit == 0) {
        units.truncate(end);
    }

    let upcase = p.registry.upcase_table();
    if upcase.len() != 65_536 {
        return Err(failure(
            "window message registration requires the installed case table",
        ));
    }
    match p.gui.register_message(&upcase, &units) {
        Ok(atom) => Ok(u64::from(atom)),
        Err(ERROR_INVALID_PARAMETER) => invalid(),
        Err(error) => query_error(p, t, error, None),
    }
}

fn complete(p: &mut Proc, t: &mut Thread, operation: Completion) -> Result<u64, Outcome> {
    let (process, output) = match operation {
        Completion::Value(value) => return Ok(value),
        Completion::QueryGuiThread(arguments) => return thread_info::query(p, t, arguments),
        Completion::QueryUserObject(arguments) => {
            return user_objects::information(p, t, arguments);
        }
        Completion::CloseWindowStation(arguments) => {
            return user_objects::close_station(p, t, arguments);
        }
        Completion::RegisterLpk(value) => {
            p.gui.lpk_registration = Some(value);
            return Ok(1);
        }
        Completion::RegisterWindowMessage(name) => return complete_window_message(p, t, name),
        Completion::PostThreadMessage(arguments) => return message_queue::post(p, t, arguments),
        Completion::PostQuitMessage(arguments) => return message_queue::quit(p, t, arguments),
        Completion::PeekMessage(arguments) => return message_queue::peek(p, t, arguments),
        Completion::GetMessage(arguments) => return message_queue::get(p, t, arguments),
        Completion::GetKeyboardLayout(arguments) => {
            return thread_info::keyboard_layout(p, t, arguments);
        }
        Completion::FindCursorIcon(arguments) => return cursor_icons::complete(p, t, arguments),
        Completion::RegisterWindowClass(arguments) => {
            return window_classes::register(p, t, arguments);
        }
        Completion::GetWindowClass(arguments) => return window_classes::get(p, t, arguments),
        Completion::UnregisterWindowClass(arguments) => {
            return window_classes::unregister(p, t, arguments);
        }
        Completion::CreateWindow(arguments) => return windows::create(p, t, arguments),
        Completion::DisableThreadIme(arguments) => {
            return windows::disable_thread_ime(p, t, arguments);
        }
        Completion::QueryWindow(arguments) => return windows::query(p, t, arguments),
        Completion::IsTopLevelWindow(arguments) => return windows::is_top_level(p, t, arguments),
        Completion::IsNonClientDpiScalingEnabled(arguments) => {
            return windows::is_nonclient_dpi_scaling_enabled(p, t, arguments);
        }
        Completion::GetWindowCompositionAttribute(arguments) => {
            return composition::complete(p, t, arguments);
        }
        Completion::GetAncestor(arguments) => return windows::get_ancestor(p, t, arguments),
        Completion::SetWindowPos(arguments) => return windows::set_position(p, t, arguments),
        Completion::GetThreadState(arguments) => return windows::get_thread_state(p, t, arguments),
        Completion::QueryInputContext(arguments) => return input_contexts::query(p, t, arguments),
        Completion::UpdateInputContext(arguments) => {
            return input_contexts::update(p, t, arguments);
        }
        Completion::QueryWindowClassName(arguments) => return windows::class_name(p, t, arguments),
        Completion::SetWindowLongPtr(arguments) => {
            return windows::set_window_long_ptr(p, t, arguments);
        }
        Completion::SetWindowFnid(arguments) => return windows::set_window_fnid(p, t, arguments),
        Completion::MessageCall(arguments) => return windows::message_call(p, t, arguments),
        Completion::GetImeInfo(arguments) => return windows::get_ime_info(p, t, arguments),
        Completion::WindowProperty(arguments, operation) => {
            return windows::property(p, t, arguments, operation);
        }
        Completion::DestroyWindow(arguments) => return windows::destroy(p, t, arguments),
        Completion::ResumeWindow(_) => {
            return Err(failure("unexpected window callback continuation"));
        }
        Completion::SystemParameter {
            action,
            parameter,
            output,
        } => return system_parameters::complete(p, t, action, parameter, output),
        Completion::ProcessUiContext { process, output } => (process, output),
    };
    if process != p.arch.ptr(u64::MAX) {
        let Some(Object::Process { pid, .. }) = p.objects.get(process) else {
            return query_error(p, t, ERROR_INVALID_PARAMETER, None);
        };
        if p.objects.access(process).unwrap_or(0) & 0x1000 == 0 {
            return query_error(p, t, ERROR_INVALID_PARAMETER, None);
        }
        if *pid != p.pid {
            return Err(failure(
                "process UI context for another virtual process is not captured",
            ));
        }
    }
    let words = match p.native.as_ref().map(|runtime| &runtime.gui) {
        Some(Availability::Available(inputs)) if inputs.arch == p.arch => inputs
            .process_ui_context
            .as_ref()
            .map_err(|reason| failure(format!("process UI context unavailable: {reason}")))?,
        _ => {
            return Err(failure(
                "process UI context requires selected native GUI inputs",
            ));
        }
    };
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&words[0].to_le_bytes());
    bytes[4..].copy_from_slice(&words[1].to_le_bytes());
    // AddressSpace validates the complete span before copying any byte. A
    // rejected crossing therefore preserves the writable prefix as observed.
    if let Err(fault) = p.space.wr(output, &bytes) {
        let guard = p.vm.take_guard(fault.addr);
        return query_error(
            p,
            t,
            if guard {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                ERROR_NOACCESS
            },
            Some(if guard {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            }),
        );
    }
    Ok(1)
}

struct CallbackFrame {
    saved: RegContext,
    address: u64,
    dispatcher: u64,
    bytes: Vec<u8>,
}

impl CallbackFrame {
    fn prepare(
        p: &Proc,
        t: &Thread,
        sp: u64,
        resume: u64,
        index: u32,
        payload: &[u8],
    ) -> Result<Self, Outcome> {
        let dispatcher = p
            .native
            .as_ref()
            .and_then(|runtime| runtime.startup)
            .and_then(|entries| entries.callback)
            .ok_or_else(|| failure("selected NTDLL has no validated kernel callback dispatcher"))?;
        if p.arch == WinArch::X86 {
            return Err(failure(
                "paired WoW64 process/thread GUI contexts are not implemented",
            ));
        }
        let table = match p.space.u64(p.peb + 0x58) {
            Ok(table) if table != 0 => table,
            _ => return Err(failure("USER callback table is absent or unreadable")),
        };
        let target = table
            .checked_add(u64::from(index) * 8)
            .and_then(|slot| p.space.u64(slot).ok())
            .filter(|&target| target != 0);
        if target.is_none() {
            return Err(failure(format!(
                "USER callback {index} is absent or unreadable"
            )));
        }

        let (header, extra) = if p.arch == WinArch::Arm64 {
            (48, 16)
        } else {
            (88, 0)
        };
        let length = u32::try_from(payload.len())
            .map_err(|_| failure("kernel callback payload exceeds the ABI length"))?;
        let frame_size = (header + u64::from(length) + extra + 15) & !15;
        let address = sp
            .checked_sub(frame_size)
            .map(|value| value & !15)
            .ok_or_else(|| failure("kernel callback stack underflow"))?;
        p.space
            .probe(address, frame_size as usize, MemoryAccessKind::Write)
            .map_err(|_| failure("kernel callback stack is not writable"))?;

        let mut saved = RegContext::capture(&t.cpu);
        saved.set_sp(sp);
        saved.set_pc(resume);
        let mut bytes = vec![0; frame_size as usize];
        let mut word = |offset: usize, value: u64| {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        };
        let sizes = u64::from(length) | (u64::from(index) << 32);
        if p.arch == WinArch::Arm64 {
            word(0, address + header);
            word(8, sizes);
            word(16, t.cpu.gpr(29));
            word(24, t.cpu.gpr(30));
            word(32, sp);
            word(40, resume);
        } else {
            word(32, address + header);
            word(40, sizes);
            word(48, resume);
            word(56, 0x33);
            word(64, u64::from(saved.flags_register()));
            word(72, sp);
            word(80, 0x2b);
        }
        let payload_offset = header as usize;
        bytes[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
        Ok(Self {
            saved,
            address,
            dispatcher,
            bytes,
        })
    }

    fn enter(
        self,
        p: &mut Proc,
        t: &mut Thread,
        completion: Completion,
        window_client_info: Option<[u64; 2]>,
    ) -> Outcome {
        if let Err(error) = p.space.wr(self.address, &self.bytes) {
            return failure(format!("GUI callback frame is inaccessible: {error:?}"));
        }
        let saved_window_client_info = if let Some([handle, window]) = window_client_info {
            // Installed USER32 reads the active HWND and its window view from
            // Win32ClientInfo before calling the guest window procedure.
            let address = t.teb + WINDOW_CALLBACK_CLIENT_INFO;
            let mut previous = [0; 16];
            let mut selected = [0; 16];
            selected[..8].copy_from_slice(&handle.to_le_bytes());
            selected[8..].copy_from_slice(&window.to_le_bytes());
            if let Err(error) = p
                .space
                .rd(address, &mut previous)
                .and_then(|_| p.space.wr(address, &selected))
            {
                return failure(format!(
                    "GUI window callback client info is inaccessible: {error:?}"
                ));
            }
            Some(previous)
        } else {
            None
        };
        let thread = p.gui.threads.get_mut(&t.tid).expect("prepared GUI thread");
        thread.callbacks.push(Callback {
            context: self.saved,
            callback_sp: self.address,
            hle_depth: t.frames.len(),
            saved_window_client_info,
            completion,
        });
        t.cpu.set_sp(self.address);
        t.cpu.set_pc(self.dispatcher);
        Outcome::Continue
    }
}

fn convert(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
    completion: Option<Completion>,
) -> Outcome {
    let inputs = match p.native.as_ref().map(|runtime| &runtime.gui) {
        Some(Availability::Available(inputs)) if inputs.arch == p.arch => inputs.clone(),
        Some(Availability::Unavailable(reason)) => {
            return failure(format!(
                "not implemented for unavailable GUI inputs: {reason}"
            ));
        }
        _ => return failure("not implemented without selected native GUI inputs"),
    };
    if let Some(thread) = p.gui.threads.get(&t.tid)
        && (thread.initialized || !thread.callbacks.is_empty())
    {
        let tick = p.uptime_ms() as u32;
        if let Err(error) = p.gui.prepare_thread(&mut p.vm, inputs, t.tid, tick) {
            return failure(format!("GUI view ownership was lost: {error:?}"));
        }
        let operation = completion
            .unwrap_or_else(|| Completion::Value(p.gui.value.expect("converted process value")));
        let value = match complete(p, t, operation) {
            Ok(value) => value,
            Err(outcome) => return outcome,
        };
        return returned(t, value, sp, resume, wow64);
    }
    let frame = match CallbackFrame::prepare(p, t, sp, resume, CLIENT_THREAD_SETUP, &[]) {
        Ok(frame) => frame,
        Err(outcome) => return outcome,
    };
    let tick = p.uptime_ms() as u32;
    let record = match p.gui.prepare_thread(&mut p.vm, inputs.clone(), t.tid, tick) {
        Ok(record) => record,
        Err(error) => return failure(format!("GUI mappings or thread record: {error:?}")),
    };
    let value = match p.gui.value {
        Some(value) => value,
        None => {
            let value = p.random().max(1);
            p.gui.value = Some(value);
            value
        }
    };
    let prepared = (|| {
        p.space.w64(p.peb + 0xf8, inputs.gdi.base)?;
        p.space.w32(p.peb + 0x108, value as u32)?;
        p.space.w64(t.teb + 0x78, u64::from(t.tid))?;
        // Native conversion retains only the low minor-version byte, including
        // executable headers whose subsystem minor version exceeds 255.
        let version = (u64::from(p.gui.executable_version.0) << 8)
            | u64::from(p.gui.executable_version.1 & 0xff);
        for (index, &word) in inputs.client.iter().enumerate() {
            let word = if index == 2 {
                version
            } else if index == 12 {
                record
            } else {
                word
            };
            p.space.w64(t.teb + 0x800 + index as u64 * 8, word)?;
        }
        Ok::<(), crate::user::windows::memory::MemFault>(())
    })();
    if let Err(error) = prepared {
        return failure(format!("GUI entry state is inaccessible: {error:?}"));
    }
    frame.enter(p, t, completion.unwrap_or(Completion::Value(value)), None)
}

pub(in crate::user::windows::process) fn resume_posted_message(
    p: &mut Proc,
    t: &mut Thread,
    output: u64,
    minimum: u32,
    maximum: u32,
) -> Outcome {
    match message_queue::take_or_wait(p, t, output, minimum, maximum) {
        Ok(result) => {
            write_value(&mut t.cpu, Value::Int(result));
            Outcome::Continue
        }
        Err(outcome) => outcome,
    }
}

pub(super) fn callback_return(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let arguments = match t.cpu.instruction_arch() {
        WinArch::Arm64 => Ok([t.cpu.call_gpr(0), t.cpu.call_gpr(1), t.cpu.call_gpr(2)]),
        WinArch::X64 => Ok([t.cpu.gpr(10), t.cpu.gpr(2), t.cpu.gpr(8)]),
        WinArch::X86 => (|| {
            Ok([
                u64::from(p.space.u32(sp + 4)?),
                u64::from(p.space.u32(sp + 8)?),
                u64::from(p.space.u32(sp + 12)?),
            ])
        })(),
    };
    let arguments = match arguments {
        Ok(arguments) => arguments,
        Err(crate::user::windows::memory::MemFault { .. }) => {
            return returned(t, u64::from(STATUS_ACCESS_VIOLATION), sp, resume, wow64);
        }
    };
    let Some(thread) = p.gui.threads.get_mut(&t.tid) else {
        return returned(t, u64::from(NO_CALLBACK_ACTIVE), sp, resume, wow64);
    };
    let Some(callback) = thread.callbacks.pop() else {
        return returned(t, u64::from(NO_CALLBACK_ACTIVE), sp, resume, wow64);
    };
    // The observed CLIENTTHREADSETUP caller consumes status only. Its output
    // pointer and length are not dereferenced or converted into host pointers.
    let success = arguments[2] as u32 as i32 >= 0;
    if !matches!(callback.completion, Completion::ResumeWindow(_)) {
        thread.initialized = success;
        if !success && p.space.w64(t.teb + 0x78, 0).is_err() {
            return failure("failed thread conversion cannot clear its owned TEB state");
        }
    }
    if let Some(previous) = callback.saved_window_client_info
        && let Err(error) = p.space.wr(t.teb + WINDOW_CALLBACK_CLIENT_INFO, &previous)
    {
        return failure(format!(
            "GUI window callback client info could not be restored: {error:?}"
        ));
    }
    if let Err(status) = callback.context.apply(&mut t.cpu) {
        return failure(format!(
            "kernel callback frame {:#x} restoration rejected {status:#010x}",
            callback.callback_sp
        ));
    }
    t.frames.truncate(callback.hle_depth);
    let result = match callback.completion {
        Completion::ResumeWindow(pending) => windows::resume(p, t, pending, arguments),
        operation if success => complete(p, t, operation),
        _ => Ok(0),
    };
    let value = match result {
        Ok(value) => value,
        Err(outcome) => return outcome,
    };
    write_value(&mut t.cpu, Value::Int(value));
    Outcome::Continue
}
