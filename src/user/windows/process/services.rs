//! Kernel entry from admitted native NTDLL/Win32u images. A return resumes the leaf stub,
//! with its stack intact; it must not apply the HLE export's callee cleanup.

use super::{Proc, Thread};
use crate::user::windows::arch::WinArch;
use crate::user::windows::context::RegContext;
use crate::user::windows::dll;
use crate::user::windows::gui::{Completion, windows::PropertyOperation};
use crate::user::windows::hle::dispatch::{Outcome, prune_resumed_context, write_value};
use crate::user::windows::hle::{ApiErr, Ctx, Flow, Value};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::STATUS_ACCESS_VIOLATION;

mod argument_stack;
mod gui;
mod kernel_context;
mod wait;

pub(super) use gui::resume_posted_message;

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
        .and_then(|(_, table)| table.name(p.arch, number))
        .or_else(|| {
            let binding = p.modules.mapped_win32u.as_ref()?;
            if wow64_return {
                binding.wow64_name(&p.vm, number, pc, resume)
            } else {
                binding.name(&p.vm, p.arch, number, pc)
            }
        });
    let kernelbase_api = p
        .modules
        .mapped_wow64_kernelbase
        .as_ref()
        .filter(|_| wow64_return)
        .and_then(|binding| binding.api(&p.vm, number, resume, sp));
    let user32_api = p
        .modules
        .mapped_wow64_user32
        .as_ref()
        .filter(|_| wow64_return)
        .and_then(|binding| binding.api(&p.vm, number, resume, sp));
    let private = match (kernelbase_api, user32_api) {
        (Some(_), Some(_)) => {
            return Some(Outcome::Fail(format!(
                "raw Windows {} service {number:#x} at {pc:#x} has conflicting selected KernelBase and User32 identities",
                p.arch
            )));
        }
        (Some(api), None) => Some(("KernelBase", api)),
        (None, Some(api)) => Some(("User32", api)),
        (None, None) => None,
    };
    if nt_name.is_some() && win32u_name.is_some() {
        return Some(Outcome::Fail(format!(
            "raw Windows {} service {number:#x} at {pc:#x} has conflicting selected NTDLL and Win32u identities",
            p.arch
        )));
    }
    if let Some((library, _)) = private
        && (nt_name.is_some() || win32u_name.is_some())
    {
        return Some(Outcome::Fail(format!(
            "raw Windows {} service {number:#x} at {pc:#x} has conflicting selected {library} and kernel-service identities",
            p.arch
        )));
    }
    let Some((source, name)) = nt_name
        .map(|name| ("NTDLL", name.to_owned()))
        .or_else(|| win32u_name.map(|name| ("Win32u", name.to_owned())))
        .or_else(|| private.map(|(library, api)| (library, api.name.to_owned())))
    else {
        return Some(Outcome::Fail(format!(
            "raw Windows {} service {number:#x} at {pc:#x} has no admitted stub in the selected NTDLL or Win32u",
            p.arch
        )));
    };
    if source == "Win32u"
        && matches!(
            name.as_str(),
            "NtGdiInit"
                | "NtGdiInit2"
                | "NtUserGetDpiForCurrentProcess"
                | "NtUserSetProcessDpiAwarenessContext"
                | "NtUserRemoteConnectState"
                | "NtUserFindExistingCursorIcon"
                | "NtUserGetThreadDesktop"
                | "NtUserGetGUIThreadInfo"
                | "NtUserGetProcessWindowStation"
                | "NtUserGetObjectInformation"
                | "NtUserCloseWindowStation"
                | "NtUserRegisterLPK"
                | "NtUserRegisterWindowMessage"
                | "NtUserPostThreadMessage"
                | "NtUserPostQuitMessage"
                | "NtUserPeekMessage"
                | "NtUserGetMessage"
                | "NtUserGetKeyboardLayout"
                | "NtUserRegisterClassExWOW"
                | "NtUserGetClassInfoEx"
                | "NtUserUnregisterClass"
                | "NtUserCreateWindowEx"
                | "NtUserDisableThreadIme"
                | "NtUserQueryWindow"
                | "NtUserIsTopLevelWindow"
                | "NtUserIsNonClientDpiScalingEnabled"
                | "NtUserGetWindowCompositionAttribute"
                | "NtUserGetAncestor"
                | "NtUserSetWindowPos"
                | "NtUserGetThreadState"
                | "NtUserQueryInputContext"
                | "NtUserUpdateInputContext"
                | "NtUserGetClassName"
                | "NtUserSetWindowLongPtr"
                | "NtUserSetWindowFNID"
                | "NtUserMessageCall"
                | "NtUserGetImeInfoEx"
                | "NtUserGetProp"
                | "NtUserSetProp"
                | "NtUserRemoveProp"
                | "NtUserDestroyWindow"
                | "NtUserSystemParametersInfo"
                | "NtUserGetProcessUIContextInformation"
        )
    {
        let outcome = match name.as_str() {
            "NtGdiInit" => gui::initialize_legacy(p, t, sp, resume, wow64_return),
            "NtGdiInit2" => gui::initialize(p, t, sp, resume, wow64_return),
            "NtUserGetDpiForCurrentProcess" => gui::process_dpi(p, t, sp, resume, wow64_return),
            "NtUserSetProcessDpiAwarenessContext" => {
                gui::set_process_dpi_awareness(p, t, sp, resume, wow64_return)
            }
            "NtUserRemoteConnectState" => gui::remote_connect_state(p, t, sp, resume, wow64_return),
            "NtUserFindExistingCursorIcon" => gui::find_cursor_icon(p, t, sp, resume, wow64_return),
            "NtUserGetThreadDesktop" => gui::thread_desktop(p, t, sp, resume, wow64_return),
            "NtUserGetGUIThreadInfo" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::QueryGuiThread)
            }
            "NtUserGetProcessWindowStation" => {
                gui::process_window_station(p, t, sp, resume, wow64_return)
            }
            "NtUserGetObjectInformation" => gui::user_object_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::QueryUserObject,
            ),
            "NtUserCloseWindowStation" => gui::user_object_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::CloseWindowStation,
            ),
            "NtUserRegisterLPK" => gui::register_lpk(p, t, sp, resume, wow64_return),
            "NtUserRegisterWindowMessage" => {
                gui::register_window_message(p, t, sp, resume, wow64_return)
            }
            "NtUserPostThreadMessage" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::PostThreadMessage,
            ),
            "NtUserPostQuitMessage" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::PostQuitMessage)
            }
            "NtUserPeekMessage" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::PeekMessage)
            }
            "NtUserGetMessage" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::GetMessage)
            }
            "NtUserGetKeyboardLayout" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::GetKeyboardLayout,
            ),
            "NtUserRegisterClassExWOW" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::RegisterWindowClass,
            ),
            "NtUserGetClassInfoEx" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::GetWindowClass)
            }
            "NtUserUnregisterClass" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::UnregisterWindowClass,
            ),
            "NtUserCreateWindowEx" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::CreateWindow)
            }
            "NtUserDisableThreadIme" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::DisableThreadIme)
            }
            "NtUserQueryWindow" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::QueryWindow)
            }
            "NtUserIsTopLevelWindow" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::IsTopLevelWindow)
            }
            "NtUserIsNonClientDpiScalingEnabled" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::IsNonClientDpiScalingEnabled,
            ),
            "NtUserGetWindowCompositionAttribute" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::GetWindowCompositionAttribute,
            ),
            "NtUserGetAncestor" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::GetAncestor)
            }
            "NtUserSetWindowPos" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::SetWindowPos)
            }
            "NtUserGetThreadState" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::GetThreadState)
            }
            "NtUserQueryInputContext" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::QueryInputContext,
            ),
            "NtUserUpdateInputContext" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::UpdateInputContext,
            ),
            "NtUserGetClassName" => gui::window_operation(
                p,
                t,
                sp,
                resume,
                wow64_return,
                Completion::QueryWindowClassName,
            ),
            "NtUserSetWindowLongPtr" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::SetWindowLongPtr)
            }
            "NtUserSetWindowFNID" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::SetWindowFnid)
            }
            "NtUserMessageCall" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::MessageCall)
            }
            "NtUserGetImeInfoEx" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::GetImeInfo)
            }
            "NtUserGetProp" => gui::window_operation(p, t, sp, resume, wow64_return, |args| {
                Completion::WindowProperty(args, PropertyOperation::Get)
            }),
            "NtUserSetProp" => {
                gui::window_operation(p, t, sp, resume, wow64_return, |[window, atom, value]| {
                    Completion::WindowProperty([window, atom], PropertyOperation::Set(value))
                })
            }
            "NtUserRemoveProp" => gui::window_operation(p, t, sp, resume, wow64_return, |args| {
                Completion::WindowProperty(args, PropertyOperation::Remove)
            }),
            "NtUserDestroyWindow" => {
                gui::window_operation(p, t, sp, resume, wow64_return, Completion::DestroyWindow)
            }
            "NtUserSystemParametersInfo" => gui::system_parameters(p, t, sp, resume, wow64_return),
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
    let api = match source {
        "NTDLL" => dll::nt_service(&name, p.arch),
        "KernelBase" | "User32" => private.map(|(_, api)| api),
        _ => None,
    };
    let Some(api) = api else {
        return Some(Outcome::Fail(format!(
            "native {source} service {name} ({number:#x}) at {pc:#x} is not implemented"
        )));
    };
    // SYSCALL has overwritten RCX with its resume PC. The native wrapper
    // saved argument 0 in R10. Remaining arguments retain the ordinary
    // Windows x64 positions, including the stack return-address slot.
    let saved_rcx = (t.cpu.instruction_arch() == WinArch::X64).then(|| t.cpu.gpr(1));
    if saved_rcx.is_some() {
        t.cpu.set_gpr(1, t.cpu.gpr(10));
    }
    let argument_sp = if source == "NTDLL" {
        match argument_stack::entry_sp(p, t, number, pc, sp) {
            Ok(address) => address,
            Err(error) => return Some(Outcome::Fail(error)),
        }
    } else {
        sp
    };
    let result = kernel_context::call(
        source,
        &mut Ctx {
            p,
            t,
            api,
            entry_pc: pc,
            entry_sp: argument_sp,
            ret_addr: resume,
            cursor: sp.saturating_sub(32) & !0xF,
        },
    );
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
        Ok(flow @ (Flow::Ret(Value::Int(status)) | Flow::Yield(Value::Int(status)))) => {
            tracing::trace!(target: "rax::windows::ntstatus", pid = p.pid, service = name, status = %format_args!("{status:#010x}"), "guest service returned");
            write_value(&mut t.cpu, Value::Int(status));
            if wow64_return {
                t.cpu.set_sp(sp);
                t.cpu.set_pc(resume);
            }
            match flow {
                Flow::Yield(_) => Outcome::Yield,
                _ => Outcome::Continue,
            }
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
    if let Err(status) = t.cpu.apply_kernel_context(context) {
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
