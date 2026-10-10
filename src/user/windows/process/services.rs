//! Kernel entry from an admitted native NTDLL. A return resumes the leaf stub,
//! with its stack intact; it must not apply the HLE export's callee cleanup.

use super::{Proc, Thread};
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll;
use crate::user::windows::hle::dispatch::{Outcome, prune, write_value};
use crate::user::windows::hle::{ApiErr, Ctx, Flow, Value};
use crate::user::windows::nt::status::STATUS_ACCESS_VIOLATION;

pub(super) fn dispatch(p: &mut Proc, t: &mut Thread, number: u32, pc: u64) -> Option<Outcome> {
    let (idx, table) = p.modules.nt_services.as_ref()?;
    if !p.modules.is_live(*idx) {
        return None;
    }
    let Some(name) = table.name(p.arch, number).map(str::to_owned) else {
        return Some(Outcome::Fail(format!(
            "raw Windows {} service {number:#x} at {pc:#x} has no admitted stub in the selected NTDLL",
            p.arch
        )));
    };
    let Some(api) = dll::nt_service(&name, p.arch) else {
        return Some(Outcome::Fail(format!(
            "native NTDLL service {name} ({number:#x}) at {pc:#x} is not implemented"
        )));
    };
    let resume = t.cpu.pc();
    let sp = t.cpu.sp();
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
    Some(match result {
        Ok(Flow::Ret(Value::Int(status))) => {
            write_value(&mut t.cpu, Value::Int(status));
            Outcome::Continue
        }
        Err(ApiErr::Fault(_)) => {
            write_value(&mut t.cpu, Value::Int(u64::from(STATUS_ACCESS_VIOLATION)));
            Outcome::Continue
        }
        Ok(Flow::Resume(context)) => match context.apply(&mut t.cpu) {
            Ok(()) => {
                prune(t, t.cpu.sp());
                Outcome::Continue
            }
            Err(status) => Outcome::Fail(format!(
                "{name}: context restoration rejected with status {status:#010x}"
            )),
        },
        Ok(Flow::TerminateProcess(status)) => Outcome::ProcessTerminate(status),
        Ok(Flow::TerminateThread(status)) => Outcome::ThreadTerminate(status),
        Err(error) => Outcome::Fail(format!("native NTDLL service {name}: {error:?}")),
        Ok(_) => Outcome::Fail(format!(
            "native NTDLL service {name} requires an unsupported kernel continuation"
        )),
    })
}
