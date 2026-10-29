//! Kernel entry from admitted native NTDLL/Win32u images. A return resumes the leaf stub,
//! with its stack intact; it must not apply the HLE export's callee cleanup.

use super::{Proc, Thread};
use crate::user::windows::arch::WinArch;
use crate::user::windows::context::RegContext;
use crate::user::windows::dll;
use crate::user::windows::hle::dispatch::{Outcome, prune_resumed_context, write_value};
use crate::user::windows::hle::{ApiErr, Ctx, Flow, Value};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::STATUS_ACCESS_VIOLATION;

mod gui;
mod wait;

pub(super) fn dispatch(p: &mut Proc, t: &mut Thread, number: u32, pc: u64) -> Option<Outcome> {
    enter(p, t, number, pc, t.cpu.sp(), t.cpu.pc(), false)
}

pub(super) fn wow64(p: &mut Proc, t: &mut Thread, pc: u64) -> Outcome {
    if p.arch != WinArch::X86 {
        return Outcome::Fail("WoW64 transition requires an x86 guest".into());
    }
    let sp = t.cpu.sp();
    let Ok(resume) = p.space.u32(sp) else {
        return Outcome::Fail("WoW64 transition return address is unreadable".into());
    };
    let Some(entry_sp) = sp.checked_add(4) else {
        return Outcome::Fail("WoW64 transition stack overflow".into());
    };
    let Some(outcome) = enter(
        p,
        t,
        t.cpu.gpr(0) as u32,
        pc,
        entry_sp,
        u64::from(resume),
        true,
    ) else {
        return Outcome::Fail("WoW64 transition has no live selected NTDLL".into());
    };
    outcome
}

fn enter(
    p: &mut Proc,
    t: &mut Thread,
    number: u32,
    pc: u64,
    sp: u64,
    resume: u64,
    wow64_return: bool,
) -> Option<Outcome> {
    let (idx, table) = p.modules.nt_services.as_ref()?;
    if !p.modules.is_live(*idx) {
        return None;
    }
    let nt_name = table.name(p.arch, number);
    let win32u_name = p
        .modules
        .win32u_services
        .as_ref()
        .filter(|(idx, _)| p.modules.is_live(*idx))
        .and_then(|(_, table)| table.name(p.arch, number));
    if nt_name.is_some() && win32u_name.is_some() {
        return Some(Outcome::Fail(format!(
            "raw Windows {} service {number:#x} at {pc:#x} has conflicting selected NTDLL and Win32u identities",
            p.arch
        )));
    }
    let Some((source, name)) = nt_name
        .map(|name| ("NTDLL", name.to_owned()))
        .or_else(|| win32u_name.map(|name| ("Win32u", name.to_owned())))
    else {
        return Some(Outcome::Fail(format!(
            "raw Windows {} service {number:#x} at {pc:#x} has no admitted stub in the selected NTDLL or Win32u",
            p.arch
        )));
    };
    if source == "Win32u"
        && matches!(
            name.as_str(),
            "NtGdiInit2"
                | "NtUserRemoteConnectState"
                | "NtUserGetThreadDesktop"
                | "NtUserRegisterLPK"
                | "NtUserGetProcessUIContextInformation"
        )
    {
        let outcome = match name.as_str() {
            "NtGdiInit2" => gui::initialize(p, t, sp, resume, wow64_return),
            "NtUserRemoteConnectState" => gui::remote_connect_state(p, t, sp, resume, wow64_return),
            "NtUserGetThreadDesktop" => gui::thread_desktop(p, t, sp, resume, wow64_return),
            "NtUserRegisterLPK" => gui::register_lpk(p, t, sp, resume, wow64_return),
            _ => gui::process_ui_context(p, t, sp, resume, wow64_return),
        };
        return Some(match outcome {
            Outcome::Fail(reason) => Outcome::Fail(format!(
                "native {source} service {name} ({number:#x}) at {pc:#x}: {reason}"
            )),
            outcome => outcome,
        });
    }
    if source == "NTDLL" && name == "NtCallbackReturn" {
        return Some(gui::callback_return(p, t, sp, resume, wow64_return));
    }
    // Other Win32k operations remain explicit and cannot borrow an identically
    // named NTDLL implementation from the other namespace.
    let api = (source == "NTDLL")
        .then(|| dll::nt_service(&name, p.arch))
        .flatten();
    let Some(api) = api else {
        return Some(Outcome::Fail(format!(
            "native {source} service {name} ({number:#x}) at {pc:#x} is not implemented"
        )));
    };
    // SYSCALL has overwritten RCX with its resume PC. The native wrapper
    // saved argument 0 in R10. Remaining arguments retain the ordinary
    // Windows x64 positions, including the stack return-address slot.
    let saved_rcx = (p.arch == WinArch::X64).then(|| t.cpu.gpr(1));
    if saved_rcx.is_some() {
        t.cpu.set_gpr(1, t.cpu.gpr(10));
    }
    let result = (api.imp)(&mut Ctx {
        p,
        t,
        api,
        entry_pc: pc,
        entry_sp: sp,
        ret_addr: resume,
        cursor: sp.saturating_sub(32) & !0xF,
    });
    if let Some(rcx) = saved_rcx {
        t.cpu.set_gpr(1, rcx);
    }
    if let Err(error) = super::registry_notify::finish(p, t) {
        return Some(Outcome::Fail(error));
    }
    if let Err(error) = p.reclaim_scheduler_views() {
        return Some(Outcome::Fail(format!(
            "scheduler view cleanup failed: {error}"
        )));
    }
    Some(match result {
        Ok(Flow::Block { wait, then }) => {
            wait::park(p, t, api, sp, resume, wow64_return, wait, then)
        }
        Ok(Flow::Ret(Value::Int(status))) => {
            write_value(&mut t.cpu, Value::Int(status));
            if wow64_return {
                t.cpu.set_sp(sp);
                t.cpu.set_pc(resume);
            }
            Outcome::Continue
        }
        Err(ApiErr::Fault(_)) => {
            write_value(&mut t.cpu, Value::Int(u64::from(STATUS_ACCESS_VIOLATION)));
            if wow64_return {
                t.cpu.set_sp(sp);
                t.cpu.set_pc(resume);
            }
            Outcome::Continue
        }
        Ok(Flow::Resume(context)) => resume_context(p, t, &name, &context, false),
        Ok(Flow::ResumeAlertable(context)) => resume_context(p, t, &name, &context, true),
        Ok(Flow::RaiseIn { record, context }) => {
            crate::user::windows::seh::raise(p, t, record, *context)
        }
        Ok(Flow::Raise(record)) => {
            // The record belongs to the caller, not to the stub: the x64 stub
            // leaves the return address on the stack, the ARM64 stub keeps it
            // in the link register, and a WoW64 transition has already popped
            // it into `resume`.
            let mut context = RegContext::capture(&t.cpu);
            let caller = match p.arch {
                WinArch::X64 => p.space.ptr(sp, 8).unwrap_or(resume),
                WinArch::Arm64 => t.cpu.gpr(30),
                WinArch::X86 => resume,
            };
            context.set_pc(caller);
            context.set_sp(if p.arch == WinArch::X64 {
                sp.saturating_add(8)
            } else {
                sp
            });
            let mut record = record;
            if record.address == 0 {
                record.address = caller;
            }
            crate::user::windows::seh::raise(p, t, record, context)
        }
        Ok(Flow::TerminateProcess(status)) => Outcome::ProcessTerminate(status),
        Ok(Flow::TerminateThread(status)) => Outcome::ThreadTerminate(status),
        Err(error) => Outcome::Fail(format!("native {source} service {name}: {error:?}")),
        Ok(_) => Outcome::Fail(format!(
            "native {source} service {name} requires an unsupported kernel continuation"
        )),
    })
}

fn resume_context(
    p: &mut Proc,
    t: &mut Thread,
    name: &str,
    context: &RegContext,
    alertable: bool,
) -> Outcome {
    if let Err(status) = context.apply(&mut t.cpu) {
        return Outcome::Fail(format!(
            "{name}: context restoration rejected with status {status:#010x}"
        ));
    }
    prune_resumed_context(t);
    if alertable {
        super::continue_alertable(p, t)
    } else {
        Outcome::Continue
    }
}
