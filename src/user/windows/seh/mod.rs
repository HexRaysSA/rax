//! Structured exception handling: exception dispatch.
//!
//! [`raise`] performs what the kernel and `ntdll!KiUserExceptionDispatcher`
//! do for an exception on a user thread:
//!
//! 1. The `CONTEXT` and `EXCEPTION_RECORD` are written to the thread's
//!    stack below the exception's stack pointer (keeping the ARM64 16-byte
//!    reserved area intact), with an `EXCEPTION_POINTERS` pair.
//! 2. Vectored exception handlers run in registration order; one that
//!    returns `EXCEPTION_CONTINUE_EXECUTION` (-1) resumes the (possibly
//!    modified) context.
//! 3. Frame-based handlers run: on x86 the `EXCEPTION_REGISTRATION_RECORD`
//!    chain from `TEB.NtTib.ExceptionList` ([`x86`]); on x64 and ARM64 the
//!    language handlers found by virtually unwinding the stack with the
//!    images' unwind data ([`unwind`]).
//! 4. Without a handler, the unhandled-exception filter registered with
//!    `SetUnhandledExceptionFilter` runs; unless it returns
//!    `EXCEPTION_CONTINUE_EXECUTION`, the process ends with the exception
//!    code as its exit code.
//!
//! A fail-fast request (`int 0x29`, `brk #0xF003`) bypasses dispatch and
//! ends the process with `STATUS_STACK_BUFFER_OVERRUN` ("no exception
//! handlers are invoked").

pub mod arm64;
pub mod unwind;
pub mod x64;
pub mod x86;

use super::arch::WinArch;
use super::context::{EXCEPTION_NONCONTINUABLE, ExceptionRecord, RegContext};
use super::hle::dispatch::{self, CallSite, Outcome};
use super::hle::{Api, ApiResult, Arg, Conv, Ctx, Flow};
use super::memory::Mem;
use super::nt::status::*;
use super::process::{Proc, Thread};

/// `EXCEPTION_CONTINUE_EXECUTION` (a filter or vectored handler result).
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// `EXCEPTION_CONTINUE_SEARCH`.
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
/// `EXCEPTION_EXECUTE_HANDLER`.
pub const EXCEPTION_EXECUTE_HANDLER: i32 = 1;

/// `EXCEPTION_DISPOSITION` values a frame handler returns.
pub mod disposition {
    /// `ExceptionContinueExecution`.
    pub const CONTINUE_EXECUTION: u32 = 0;
    /// `ExceptionContinueSearch`.
    pub const CONTINUE_SEARCH: u32 = 1;
    /// `ExceptionNestedException`.
    pub const NESTED_EXCEPTION: u32 = 2;
    /// `ExceptionCollidedUnwind`.
    pub const COLLIDED_UNWIND: u32 = 3;
}

/// Per-process exception-handling registrations.
#[derive(Debug, Default)]
pub struct SehState {
    /// Vectored exception handlers: (registration handle, handler).
    pub veh: Vec<(u64, u64)>,
    /// Vectored continue handlers: (registration handle, handler).
    pub vch: Vec<(u64, u64)>,
    /// The unhandled-exception filter (0: none).
    pub unhandled_filter: u64,
    /// Next registration handle.
    pub next_handle: u64,
}

/// The `STATUS_*` name of an exception code, when it is one.
pub fn exception_name(code: u32) -> Option<&'static str> {
    Some(match code {
        STATUS_ACCESS_VIOLATION => "STATUS_ACCESS_VIOLATION",
        STATUS_BREAKPOINT => "STATUS_BREAKPOINT",
        STATUS_SINGLE_STEP => "STATUS_SINGLE_STEP",
        STATUS_DATATYPE_MISALIGNMENT => "STATUS_DATATYPE_MISALIGNMENT",
        STATUS_GUARD_PAGE_VIOLATION => "STATUS_GUARD_PAGE_VIOLATION",
        STATUS_ILLEGAL_INSTRUCTION => "STATUS_ILLEGAL_INSTRUCTION",
        STATUS_PRIVILEGED_INSTRUCTION => "STATUS_PRIVILEGED_INSTRUCTION",
        STATUS_INTEGER_DIVIDE_BY_ZERO => "STATUS_INTEGER_DIVIDE_BY_ZERO",
        STATUS_INTEGER_OVERFLOW => "STATUS_INTEGER_OVERFLOW",
        STATUS_ARRAY_BOUNDS_EXCEEDED => "STATUS_ARRAY_BOUNDS_EXCEEDED",
        STATUS_FLOAT_DENORMAL_OPERAND => "STATUS_FLOAT_DENORMAL_OPERAND",
        STATUS_FLOAT_DIVIDE_BY_ZERO => "STATUS_FLOAT_DIVIDE_BY_ZERO",
        STATUS_FLOAT_INEXACT_RESULT => "STATUS_FLOAT_INEXACT_RESULT",
        STATUS_FLOAT_INVALID_OPERATION => "STATUS_FLOAT_INVALID_OPERATION",
        STATUS_FLOAT_OVERFLOW => "STATUS_FLOAT_OVERFLOW",
        STATUS_FLOAT_STACK_CHECK => "STATUS_FLOAT_STACK_CHECK",
        STATUS_FLOAT_UNDERFLOW => "STATUS_FLOAT_UNDERFLOW",
        STATUS_FLOAT_MULTIPLE_FAULTS => "STATUS_FLOAT_MULTIPLE_FAULTS",
        STATUS_FLOAT_MULTIPLE_TRAPS => "STATUS_FLOAT_MULTIPLE_TRAPS",
        STATUS_STACK_OVERFLOW => "STATUS_STACK_OVERFLOW",
        STATUS_STACK_BUFFER_OVERRUN => "STATUS_STACK_BUFFER_OVERRUN",
        STATUS_HEAP_CORRUPTION => "STATUS_HEAP_CORRUPTION",
        STATUS_NONCONTINUABLE_EXCEPTION => "STATUS_NONCONTINUABLE_EXCEPTION",
        STATUS_INVALID_DISPOSITION => "STATUS_INVALID_DISPOSITION",
        STATUS_ASSERTION_FAILURE => "STATUS_ASSERTION_FAILURE",
        STATUS_DLL_NOT_FOUND => "STATUS_DLL_NOT_FOUND",
        STATUS_ENTRYPOINT_NOT_FOUND => "STATUS_ENTRYPOINT_NOT_FOUND",
        STATUS_ORDINAL_NOT_FOUND => "STATUS_ORDINAL_NOT_FOUND",
        STATUS_DLL_INIT_FAILED => "STATUS_DLL_INIT_FAILED",
        STATUS_INVALID_IMAGE_FORMAT => "STATUS_INVALID_IMAGE_FORMAT",
        STATUS_CONTROL_C_EXIT => "STATUS_CONTROL_C_EXIT",
        STATUS_BAD_STACK => "STATUS_BAD_STACK",
        STATUS_INVALID_UNWIND_TARGET => "STATUS_INVALID_UNWIND_TARGET",
        _ => return None,
    })
}

fn kiuser_dispatcher(_: &mut Ctx) -> ApiResult {
    Flow::void()
}

/// The pseudo-export whose frame an exception dispatch runs in.
pub static DISPATCHER: Api = Api {
    name: "KiUserExceptionDispatcher",
    args: &[Arg::Ptr, Arg::Ptr],
    conv: Conv::Stdcall,
    imp: kiuser_dispatcher,
};

/// Where the dispatch's records live in guest memory.
#[derive(Clone, Copy, Debug)]
pub struct Records {
    /// `EXCEPTION_RECORD`.
    pub record: u64,
    /// `CONTEXT`.
    pub context: u64,
    /// `EXCEPTION_POINTERS` (`{ ExceptionRecord, ContextRecord }`).
    pub pointers: u64,
}

/// Ends the process for fail-fast code `code` (the first exception
/// parameter).
pub fn fail_fast(_code: u64) -> Outcome {
    Outcome::ProcessTerminate(STATUS_STACK_BUFFER_OVERRUN)
}

/// Dispatches exception `rec` raised on `t` in context `ctx`.
pub fn raise(p: &mut Proc, t: &mut Thread, rec: ExceptionRecord, ctx: RegContext) -> Outcome {
    let arch = p.arch;
    let psize = arch.ptr_size();
    // Below the exception's stack pointer: the ARM64 area reserved for
    // interrupted code, then CONTEXT, EXCEPTION_RECORD, and the pointers.
    let mut sp = ctx.sp();
    sp = sp.saturating_sub(if arch == WinArch::Arm64 { 16 } else { 0 });
    sp = sp.saturating_sub(RegContext::size(arch) as u64) & !(RegContext::align(arch) - 1);
    let context_addr = sp;
    sp = sp.saturating_sub(ExceptionRecord::size(arch)) & !0xF;
    let record_addr = sp;
    sp = sp.saturating_sub(2 * psize) & !0xF;
    let pointers = sp;
    let prepared = super::process::stack::prepare(p, t, sp, ctx.sp().saturating_sub(sp));
    if prepared.is_err() {
        return Outcome::ProcessTerminate(if rec.code == STATUS_STACK_OVERFLOW {
            STATUS_STACK_OVERFLOW
        } else {
            STATUS_BAD_STACK
        });
    }
    let writes = ctx
        .write(&p.space, context_addr)
        .and_then(|_| rec.write(&p.space, arch, record_addr))
        .and_then(|_| p.space.wptr(pointers, psize, record_addr))
        .and_then(|_| p.space.wptr(pointers + psize, psize, context_addr));
    if writes.is_err() {
        // No stack left to dispatch on: Windows terminates the process.
        return Outcome::ProcessTerminate(if rec.code == STATUS_STACK_OVERFLOW {
            STATUS_STACK_OVERFLOW
        } else {
            STATUS_BAD_STACK
        });
    }
    let recs = Records {
        record: record_addr,
        context: context_addr,
        pointers,
    };
    let site = CallSite {
        api: &DISPATCHER,
        entry_pc: 0,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp.saturating_sub(32) & !0xF,
        framed: false,
    };
    // A callback belonging to this pseudo-export has no guest return address.
    // Retain the actual exception caller so nested exception search can cross
    // the dispatcher without a fabricated return-to-zero or callback return.
    dispatch::frame_for(t, &site).exception_caller = Some(Box::new(ctx));
    let site = CallSite {
        framed: true,
        ..site
    };
    let first = rec.clone();
    dispatch::run(p, t, site, move |c| vectored(c, first, recs, 0))
}

/// Calls vectored handler `i`, then the next, then the frame handlers.
fn vectored(c: &mut Ctx, rec: ExceptionRecord, recs: Records, i: usize) -> ApiResult {
    let Some(&(_, handler)) = c.p.seh.veh.get(i) else {
        return frames(c, rec, recs);
    };
    Flow::call(handler, vec![recs.pointers], move |c, ret| {
        if ret as u32 as i32 == EXCEPTION_CONTINUE_EXECUTION {
            continue_execution(c, recs)
        } else {
            vectored(c, rec, recs, i + 1)
        }
    })
}

/// Resumes the (possibly modified) exception context, after running the
/// vectored continue handlers.
pub fn continue_execution(c: &mut Ctx, recs: Records) -> ApiResult {
    let rec = ExceptionRecord::read(&c.p.space, c.p.arch, recs.record)?;
    if rec.flags & EXCEPTION_NONCONTINUABLE != 0 {
        return noncontinuable(&rec, recs);
    }
    continue_handlers(c, recs, 0)
}

fn continue_handlers(c: &mut Ctx, recs: Records, i: usize) -> ApiResult {
    if let Some(&(_, handler)) = c.p.seh.vch.get(i) {
        return Flow::call(handler, vec![recs.pointers], move |c, ret| {
            if ret as u32 as i32 == EXCEPTION_CONTINUE_EXECUTION {
                resume_context(c, recs)
            } else {
                continue_handlers(c, recs, i + 1)
            }
        });
    }
    resume_context(c, recs)
}

fn resume_context(c: &mut Ctx, recs: Records) -> ApiResult {
    let ctx = RegContext::read(&c.p.space, c.p.arch, recs.context)?;
    Ok(Flow::Resume(Box::new(ctx)))
}

/// Runs the frame-based handlers.
fn frames(c: &mut Ctx, rec: ExceptionRecord, recs: Records) -> ApiResult {
    match c.p.arch {
        WinArch::X86 => x86::dispatch(c, rec, recs),
        _ => unwind::dispatch(c, rec, recs),
    }
}

/// A handler returned `ExceptionContinueExecution`: resume, unless the
/// exception is noncontinuable.
pub fn handler_continue(c: &mut Ctx, rec: &ExceptionRecord, recs: Records) -> ApiResult {
    if rec.flags & EXCEPTION_NONCONTINUABLE != 0 {
        return noncontinuable(rec, recs);
    }
    continue_execution(c, recs)
}

fn noncontinuable(rec: &ExceptionRecord, recs: Records) -> ApiResult {
    Ok(Flow::Raise(ExceptionRecord {
        code: STATUS_NONCONTINUABLE_EXCEPTION,
        flags: EXCEPTION_NONCONTINUABLE,
        nested: recs.record,
        address: rec.address,
        params: Vec::new(),
    }))
}

/// No frame handler handled the exception: the unhandled-exception
/// filter, then process termination with the exception code.
pub fn unhandled(c: &mut Ctx, rec: ExceptionRecord, recs: Records) -> ApiResult {
    let filter = c.p.seh.unhandled_filter;
    if filter == 0 {
        return Ok(Flow::TerminateProcess(rec.code));
    }
    Flow::call(filter, vec![recs.pointers], move |c, ret| {
        if ret as u32 as i32 == EXCEPTION_CONTINUE_EXECUTION {
            continue_execution(c, recs)
        } else {
            Ok(Flow::TerminateProcess(rec.code))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::hle::ApiErr;
    use crate::user::windows::memory::prot;
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    fn with_records(arch: WinArch, test: impl FnOnce(&mut Ctx, ExceptionRecord, Records)) {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        let mut cfg = WindowsConfig::new("continuation-test.exe", Vec::new());
        cfg.seed = Some(1);
        cfg.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let sp = t.cpu.sp();
        let mut c = Ctx {
            p,
            t: &mut t,
            api: &DISPATCHER,
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        let context = c.stack_alloc(RegContext::size(arch) as u64, RegContext::align(arch));
        RegContext::capture(&c.t.cpu)
            .write(&c.p.space, context)
            .unwrap();
        let record = c.stack_alloc(ExceptionRecord::size(arch), 16);
        let pointers = c.stack_alloc(2 * arch.ptr_size(), 16);
        c.p.space.wptr(pointers, arch.ptr_size(), record).unwrap();
        c.p.space
            .wptr(pointers + arch.ptr_size(), arch.ptr_size(), context)
            .unwrap();
        let mut rec = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1234, Vec::new());
        rec.flags = EXCEPTION_NONCONTINUABLE;
        rec.write(&c.p.space, arch, record).unwrap();
        test(
            &mut c,
            rec,
            Records {
                record,
                context,
                pointers,
            },
        );
    }

    fn assert_noncontinuable(result: ApiResult, recs: Records) {
        assert!(matches!(result.unwrap(), Flow::Raise(ref rec)
            if rec.code == STATUS_NONCONTINUABLE_EXCEPTION
                && rec.flags == EXCEPTION_NONCONTINUABLE
                && rec.nested == recs.record
                && rec.address == 0x1234));
    }

    #[test]
    fn terminal_exception_paths_are_forced_all_abis() {
        assert_eq!(
            fail_fast(7),
            Outcome::ProcessTerminate(STATUS_STACK_BUFFER_OVERRUN)
        );
        for arch in WinArch::ALL {
            with_records(arch, |c, rec, recs| {
                let code = rec.code;
                assert!(matches!(unhandled(c, rec.clone(), recs).unwrap(),
                    Flow::TerminateProcess(status) if status == code));
                c.p.seh.unhandled_filter = 0x5678;
                let Flow::Call { then, .. } = unhandled(c, rec, recs).unwrap() else {
                    panic!("expected filter callback");
                };
                assert!(matches!(then(c, 1).unwrap(),
                    Flow::TerminateProcess(status) if status == code));
                for (raised, expected) in [
                    (STATUS_STACK_OVERFLOW, STATUS_STACK_OVERFLOW),
                    (STATUS_ACCESS_VIOLATION, STATUS_BAD_STACK),
                ] {
                    let mut context = RegContext::capture(&c.t.cpu);
                    context.set_sp(0);
                    assert_eq!(
                        raise(
                            c.p,
                            c.t,
                            ExceptionRecord::new(raised, 0x1234, vec![]),
                            context
                        ),
                        Outcome::ProcessTerminate(expected),
                        "{arch}"
                    );
                }
            });
        }
    }

    #[test]
    fn noncontinuable_vectored_and_unhandled_filter_cannot_resume() {
        // EXCEPTION_RECORD.ExceptionFlags: any continuation attempt on a
        // noncontinuable exception raises EXCEPTION_NONCONTINUABLE_EXCEPTION.
        for arch in WinArch::ALL {
            for filter in [false, true] {
                with_records(arch, |c, rec, recs| {
                    let original = RegContext::capture(&c.t.cpu);
                    let call = if filter {
                        c.p.seh.unhandled_filter = 0x5678;
                        unhandled(c, rec, recs)
                    } else {
                        c.p.seh.veh.push((1, 0x5678));
                        vectored(c, rec, recs, 0)
                    };
                    let Flow::Call { then, .. } = call.unwrap() else {
                        panic!("expected guest handler call");
                    };
                    assert_noncontinuable(then(c, u64::from(u32::MAX)), recs);
                    assert_eq!(RegContext::capture(&c.t.cpu).bytes(), original.bytes());
                });
            }
        }
    }

    #[test]
    fn continuation_checks_flags_before_continue_handlers_and_admits_continuable_context() {
        for arch in WinArch::ALL {
            with_records(arch, |c, mut rec, recs| {
                c.p.seh.vch.push((2, 0x5678));
                assert_noncontinuable(continue_execution(c, recs), recs);
                c.p.seh.vch.clear();
                rec.flags = 0;
                rec.write(&c.p.space, arch, recs.record).unwrap();
                assert!(matches!(
                    continue_execution(c, recs).unwrap(),
                    Flow::Resume(_)
                ));
            });
        }
    }

    #[test]
    fn continuation_cannot_fabricate_flags_when_guest_record_is_unreadable() {
        for arch in WinArch::ALL {
            with_records(arch, |c, _, recs| {
                c.p.vm
                    .protect(recs.record & !0xFFF, 0x1000, prot::NOACCESS)
                    .unwrap();
                assert!(matches!(continue_execution(c, recs), Err(ApiErr::Fault(_))));
            });
        }
    }
}
