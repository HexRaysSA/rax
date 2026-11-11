//! Park a status-returning native service without applying HLE callee cleanup.
use super::*;
use crate::user::windows::context::RegContext;
use crate::user::windows::hle::dispatch::{self, CallSite};
use crate::user::windows::hle::{Api, Cont};
use crate::user::windows::sync::Wait;

pub(super) fn park(
    p: &mut Proc,
    t: &mut Thread,
    api: &'static Api,
    sp: u64,
    resume: u64,
    wow64_return: bool,
    wait: Wait,
    then: Cont,
) -> Outcome {
    let mut context = RegContext::capture(&t.cpu);
    // The saved context uses the logical ABI. ARM64EC executes the native
    // return in X0, whose AMD64 context alias is RCX rather than RAX.
    // Capture the choice now; a callback may change the live instruction mode.
    let result_register = match (t.cpu.arch(), t.cpu.instruction_arch()) {
        (WinArch::X64, WinArch::Arm64) => 1,
        _ => 0,
    };
    if wow64_return {
        context.set_sp(sp);
        context.set_pc(resume);
    }
    let site = CallSite {
        api,
        entry_pc: t.cpu.pc(),
        entry_sp: sp,
        ret_addr: resume,
        cursor: sp.saturating_sub(32) & !0xF,
        framed: false,
    };
    let then = Box::new(move |c: &mut Ctx, status| {
        let value = match then(c, status) {
            Ok(Flow::Ret(Value::Int(value))) => value,
            Err(ApiErr::Fault(_)) => u64::from(STATUS_ACCESS_VIOLATION),
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(ApiErr::Internal(
                    "native wait continuation did not return an NTSTATUS".into(),
                ));
            }
        };
        context.set_gpr(result_register, value);
        Ok(Flow::Resume(Box::new(context)))
    });
    dispatch::complete(p, t, site, Ok(Flow::Block { wait, then }))
}
