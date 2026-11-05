//! Win32k conversion and thread-owned kernel-to-user callback continuations.
use super::*;
use crate::error::MemoryAccessKind;
use crate::user::windows::gui::{Availability, Callback, Completion};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOACCESS};
use crate::user::windows::nt::status::STATUS_GUARD_PAGE_VIOLATION;
use crate::user::windows::objects::Object;

const NO_CALLBACK_ACTIVE: u32 = 0xc000_0258;
const CLIENT_THREAD_SETUP: u32 = 84;

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
    convert(p, t, sp, resume, wow64, None)
}

pub(super) fn remote_connect_state(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
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

fn first_dword(p: &Proc, t: &Thread, sp: u64) -> Option<u32> {
    match t.cpu.instruction_arch() {
        WinArch::Arm64 => Some(t.cpu.call_gpr(0) as u32),
        WinArch::X64 => Some(t.cpu.gpr(10) as u32),
        WinArch::X86 => sp
            .checked_add(4)
            .and_then(|address| p.space.u32(address).ok()),
    }
}

pub(super) fn register_lpk(
    p: &mut Proc,
    t: &mut Thread,
    sp: u64,
    resume: u64,
    wow64: bool,
) -> Outcome {
    let Some(value) = first_dword(p, t, sp) else {
        return failure("LPK registration argument capture is unreadable");
    };
    convert(
        p,
        t,
        sp,
        resume,
        wow64,
        Some(Completion::RegisterLpk(value)),
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
    let Some(id) = first_dword(p, t, sp) else {
        return failure("thread desktop argument capture is unreadable");
    };
    let id = id & !3;
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

fn query_error(p: &Proc, t: &Thread, error: u32, status: Option<u32>) -> Result<u64, Outcome> {
    let offsets = crate::user::windows::layout::offsets(p.arch);
    p.space
        .w32(t.teb + offsets.teb_last_error, error)
        .map_err(|_| failure("process UI context cannot write the guest last error"))?;
    if let Some(status) = status {
        p.space
            .w32(t.teb + offsets.teb_last_status, status)
            .map_err(|_| failure("process UI context cannot write the guest last status"))?;
    }
    Ok(0)
}

fn complete(p: &mut Proc, t: &Thread, operation: Completion) -> Result<u64, Outcome> {
    let (process, output) = match operation {
        Completion::Value(value) => return Ok(value),
        Completion::RegisterLpk(value) => {
            p.gui.lpk_registration = Some(value);
            return Ok(1);
        }
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
    let Some(entry) = p
        .native
        .as_ref()
        .and_then(|runtime| runtime.startup)
        .and_then(|entries| entries.callback)
    else {
        return failure("selected NTDLL has no validated kernel callback dispatcher");
    };
    if p.arch == WinArch::X86 {
        return failure("paired WoW64 process/thread GUI contexts are not implemented");
    }
    let table = match p.space.u64(p.peb + 0x58) {
        Ok(table) if table != 0 => table,
        _ => return failure("USER callback table is absent or unreadable"),
    };
    let Some(slot) = table.checked_add(u64::from(CLIENT_THREAD_SETUP) * 8) else {
        return failure("USER callback table address overflow");
    };
    if !p.space.u64(slot).is_ok_and(|target| target != 0) {
        return failure("USER thread-setup callback is absent or unreadable");
    }
    let frame_size = if p.arch == WinArch::Arm64 { 64 } else { 96 };
    let Some(frame) = sp.checked_sub(frame_size).map(|value| value & !15) else {
        return failure("kernel callback stack underflow");
    };
    if p.space
        .probe(frame, frame_size as usize, MemoryAccessKind::Write)
        .is_err()
    {
        return failure("kernel callback stack is not writable");
    }
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
    let mut saved = RegContext::capture(&t.cpu);
    saved.set_sp(sp);
    saved.set_pc(resume);
    let mut bytes = [0u8; 96];
    let mut put64 =
        |offset: usize, value: u64| bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    if p.arch == WinArch::Arm64 {
        put64(0, frame + 48);
        put64(16, t.cpu.gpr(29));
        put64(24, t.cpu.gpr(30));
        put64(32, sp);
        put64(40, resume);
        bytes[12..16].copy_from_slice(&CLIENT_THREAD_SETUP.to_le_bytes());
    } else {
        put64(32, frame + 88);
        put64(48, resume);
        put64(56, 0x33);
        put64(64, u64::from(saved.flags_register()));
        put64(72, sp);
        put64(80, 0x2b);
        bytes[44..48].copy_from_slice(&CLIENT_THREAD_SETUP.to_le_bytes());
    }
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
        p.space.wr(frame, &bytes[..frame_size as usize])
    })();
    if let Err(error) = prepared {
        return failure(format!("GUI entry state is inaccessible: {error:?}"));
    }
    let thread = p.gui.threads.get_mut(&t.tid).expect("prepared GUI thread");
    thread.callbacks.push(Callback {
        context: saved,
        callback_sp: frame,
        hle_depth: t.frames.len(),
        completion: completion.unwrap_or(Completion::Value(value)),
    });
    t.cpu.set_sp(frame);
    t.cpu.set_pc(entry);
    Outcome::Continue
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
    thread.initialized = success;
    if !success && p.space.w64(t.teb + 0x78, 0).is_err() {
        return failure("failed thread conversion cannot clear its owned TEB state");
    }
    if let Err(status) = callback.context.apply(&mut t.cpu) {
        return failure(format!(
            "kernel callback frame {:#x} restoration rejected {status:#010x}",
            callback.callback_sp
        ));
    }
    t.frames.truncate(callback.hle_depth);
    let value = if success {
        match complete(p, t, callback.completion) {
            Ok(value) => value,
            Err(outcome) => return outcome,
        }
    } else {
        0
    };
    write_value(&mut t.cpu, Value::Int(value));
    Outcome::Continue
}
