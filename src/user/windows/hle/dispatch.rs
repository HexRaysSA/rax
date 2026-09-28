//! Entering and leaving built-in code.
//!
//! [`enter`] runs an export whose trap slot a thread fetched,
//! [`callback_return`] resumes the continuation of a built-in call whose
//! guest callback returned, and [`resume_return`] completes a return from
//! an export's resume trap. Each funnels the implementation's result
//! through [`complete`], which applies it to the thread: writes the return
//! value and returns to the caller, starts a guest call, parks the thread,
//! loads a context, raises an exception, or ends the thread or process.

use super::args::stdcall_bytes;
use super::{Api, ApiErr, ApiResult, Cont, Conv, Ctx, Flow, Frame, Value};
use crate::user::windows::arch::{WinArch, WinCpu};
use crate::user::windows::context::{ExceptionRecord, RegContext};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::process::{Proc, Thread, ThreadState};
use crate::user::windows::seh;
use crate::user::windows::sync;
use crate::user::windows::traps::RESUME_OFFSET;

/// What the scheduler does after built-in code ran.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The thread keeps running.
    Continue,
    /// The thread's time slice ends.
    Yield,
    /// The thread parked on a wait.
    Park,
    /// Normal thread exit; the scheduler delivers DLL notifications.
    ThreadExit(u32),
    /// Normal process exit; the scheduler delivers DLL notifications.
    ProcessExit(u32),
    /// Forced thread termination; no guest termination callbacks execute.
    ThreadTerminate(u32),
    /// Forced process termination; no guest termination callbacks execute.
    ProcessTerminate(u32),
    /// The emulator cannot continue.
    Fail(String),
}

/// Where a built-in call returns and which frame it owns.
#[derive(Clone, Copy, Debug)]
pub struct CallSite {
    /// The export.
    pub api: &'static Api,
    /// The trap slot entered.
    pub entry_pc: u64,
    /// Stack pointer at entry.
    pub entry_sp: u64,
    /// Return address.
    pub ret_addr: u64,
    /// Guest-stack cursor.
    pub cursor: u64,
    /// Whether a [`Frame`] for this call is on top of the thread's frames.
    pub framed: bool,
}

/// Bytes kept free below the entry stack pointer before the frame's own
/// allocations (the ARM64 16-byte area that must survive interruption, and
/// alignment slack).
const FRAME_GAP: u64 = 32;

/// Maximum setup faults retained by one synthetic dispatcher frame. A guest
/// handler can re-arm the same guard on every continuation; that loop is
/// diagnosed instead of recursively redispatching indefinitely.
const MAX_DISPATCHER_SETUP_RETRIES: u8 = 4;

/// Discards frames abandoned by a `longjmp`, unwind, or context load:
/// those whose entry stack pointer lies below `sp`.
pub fn prune(t: &mut Thread, sp: u64) {
    while t.frames.last().is_some_and(|f| f.entry_sp < sp) {
        t.frames.pop();
    }
}

/// Leaving a waiting operation at its original stack height abandons it,
/// including ARM64 callers whose SP is unchanged by return. Lower handler
/// and callback stacks retain it instead. Never fabricate its completion.
fn prune_same_height_frontier(t: &mut Thread, pc: u64, sp: u64) {
    if t.frames.last().is_some_and(|f| {
        f.entry_sp == sp
            && ((f.cont.is_some() && (f.checked_call || f.entry_pc != pc))
                || (f.retry.is_some() && f.entry_pc != pc))
    }) {
        t.frames.pop();
    }
}

/// Runs export `api`, entered at trap slot `pc`.
pub fn enter(p: &mut Proc, t: &mut Thread, api: &'static Api, pc: u64) -> Outcome {
    let entry_sp = t.cpu.sp();
    prune(t, entry_sp);
    prune_same_height_frontier(t, pc, entry_sp);
    if let Some(frame) = t.frames.last_mut()
        && frame.entry_sp == entry_sp
        && frame.entry_pc == pc
        && std::ptr::eq(frame.api, api)
        && let Some(retry) = frame.retry.take()
    {
        let site = CallSite {
            api: frame.api,
            entry_pc: frame.entry_pc,
            entry_sp: frame.entry_sp,
            ret_addr: frame.ret_addr,
            cursor: frame.cursor,
            framed: true,
        };
        return run(p, t, site, |ctx| retry(ctx, 0));
    }
    let ret_addr = match p.arch {
        WinArch::Arm64 => t.cpu.gpr(30),
        _ => match p.space.ptr(entry_sp, p.arch.ptr_size()) {
            Ok(address) => address,
            Err(fault) => {
                let record = memory_exception(p, t, pc, fault);
                return seh::raise(p, t, record, RegContext::capture(&t.cpu));
            }
        },
    };
    prune(t, entry_sp);
    let site = CallSite {
        api,
        entry_pc: pc,
        entry_sp,
        ret_addr,
        cursor: entry_sp.saturating_sub(FRAME_GAP) & !0xF,
        framed: false,
    };
    if p.cfg.trace {
        trace_entry(p, t, &site);
    }
    run(p, t, site, |ctx| (api.imp)(ctx))
}

/// Re-enters only a previously saved pseudo-dispatcher checked operation. This
/// trap is private to `ntdll` and is not an export: a fresh guest jump cannot
/// synthesize a dispatcher frame or invoke its no-op implementation.
pub(crate) fn dispatcher_retry(p: &mut Proc, t: &mut Thread, pc: u64) -> Outcome {
    let sp = t.cpu.sp();
    prune(t, sp);
    prune_same_height_frontier(t, pc, sp);
    if pc == 0
        || pc != p.traps.dispatcher_retry()
        || !t.frames.last().is_some_and(|f| {
            std::ptr::eq(f.api, &seh::DISPATCHER)
                && f.entry_pc == pc
                && f.entry_sp == sp
                && f.retry.is_some()
                && f.exception_caller.is_some()
        })
    {
        return Outcome::Fail("dispatcher retry trap has no matching checked callback".into());
    }
    enter(p, t, &seh::DISPATCHER, pc)
}

/// Runs `f` as built-in code at `site`, then applies its result.
pub fn run(
    p: &mut Proc,
    t: &mut Thread,
    site: CallSite,
    f: impl FnOnce(&mut Ctx) -> ApiResult,
) -> Outcome {
    let mut ctx = Ctx {
        p,
        t,
        api: site.api,
        entry_pc: site.entry_pc,
        entry_sp: site.entry_sp,
        ret_addr: site.ret_addr,
        cursor: site.cursor,
    };
    let result = f(&mut ctx);
    let cursor = ctx.cursor;
    complete(p, t, CallSite { cursor, ..site }, result)
}

/// A guest callback returned to the callback-return trap.
pub fn callback_return(p: &mut Proc, t: &mut Thread) -> Outcome {
    let sp = t.cpu.sp();
    prune(t, sp);
    let Some(frame) = t.frames.last_mut() else {
        return Outcome::Fail("a guest callback returned with no built-in call waiting".into());
    };
    let Some(cont) = frame.cont.take() else {
        return Outcome::Fail(format!(
            "a guest callback returned to {}, which is not waiting for one",
            frame.api.name
        ));
    };
    frame.callback_sp = None;
    let site = CallSite {
        api: frame.api,
        entry_pc: frame.entry_pc,
        entry_sp: frame.entry_sp,
        ret_addr: frame.ret_addr,
        cursor: frame.cursor,
        framed: true,
    };
    let ret = t.cpu.gpr(0);
    run(p, t, site, |ctx| cont(ctx, ret))
}

/// A parked thread's wait completed with `status`: resume its
/// continuation.
pub fn wait_complete(p: &mut Proc, t: &mut Thread, status: u64) -> Outcome {
    let Some(frame) = t.frames.last_mut() else {
        return Outcome::Fail("a wait completed with no built-in call waiting".into());
    };
    let Some(cont) = frame.cont.take() else {
        return Outcome::Fail(format!("{} was not waiting", frame.api.name));
    };
    frame.callback_sp = None;
    let site = CallSite {
        api: frame.api,
        entry_pc: frame.entry_pc,
        entry_sp: frame.entry_sp,
        ret_addr: frame.ret_addr,
        cursor: frame.cursor,
        framed: true,
    };
    run(p, t, site, |ctx| cont(ctx, status))
}

/// A context resumed at an export's resume trap: return from the export
/// with the registers as they are.
pub fn resume_return(p: &mut Proc, t: &mut Thread, api: &'static Api) -> Outcome {
    let sp = t.cpu.sp();
    let pc = t.cpu.pc();
    prune(t, sp);
    prune_same_height_frontier(t, t.cpu.pc(), sp);
    match p.arch {
        WinArch::Arm64 => {
            let lr = t.cpu.gpr(30);
            t.cpu.set_pc(lr);
        }
        arch => {
            let ret = match p.space.ptr(sp, arch.ptr_size()) {
                Ok(address) => address,
                Err(fault) => {
                    let record = memory_exception(p, t, t.cpu.pc(), fault);
                    return seh::raise(p, t, record, RegContext::capture(&t.cpu));
                }
            };
            let pop = arch.ptr_size()
                + if arch == WinArch::X86 && api.conv == Conv::Stdcall {
                    stdcall_bytes(api.args)
                } else {
                    0
                };
            t.cpu.set_pc(ret);
            t.cpu.set_sp(sp.wrapping_add(pop));
        }
    }
    prune(t, t.cpu.sp());
    if t.frames.last().is_some_and(|frame| {
        frame.entry_sp == sp
            && std::ptr::eq(frame.api, api)
            && frame.entry_pc.checked_add(RESUME_OFFSET) == Some(pc)
    }) {
        t.frames.pop();
    }
    Outcome::Continue
}

/// Pops the frame of `site` if it is on top.
fn pop_frame(t: &mut Thread, site: &CallSite) {
    if site.framed
        && t.frames
            .last()
            .is_some_and(|f| f.entry_sp == site.entry_sp && std::ptr::eq(f.api, site.api))
    {
        t.frames.pop();
    }
}

/// Makes sure `site` has a frame on top of the thread's frames and
/// returns it.
pub(crate) fn frame_for<'t>(t: &'t mut Thread, site: &CallSite) -> &'t mut Frame {
    let on_top = site.framed
        && t.frames
            .last()
            .is_some_and(|f| f.entry_sp == site.entry_sp && std::ptr::eq(f.api, site.api));
    if !on_top {
        t.frames.push(Frame {
            api: site.api,
            entry_pc: site.entry_pc,
            entry_sp: site.entry_sp,
            ret_addr: site.ret_addr,
            cursor: site.cursor,
            cont: None,
            checked_call: false,
            callback_sp: None,
            exception_caller: None,
            retry: None,
            dispatcher_setup_retries: 0,
            exception: Vec::new(),
        });
    }
    let f = t.frames.last_mut().expect("frame pushed");
    f.cursor = site.cursor;
    f
}

/// Layout shared by checked preflight and the guest-call writer. Reserved ABI
/// padding and x64 shadow space are not writes by the call setup itself.
struct CallStackLayout {
    sp: u64,
    stack_args: u64,
    stack_arg_bytes: u64,
    return_bytes: u64,
}

fn call_stack_layout(arch: WinArch, cursor: u64, argc: usize) -> Result<CallStackLayout, MemFault> {
    let fault = MemFault {
        addr: cursor,
        write: true,
    };
    let count = u64::try_from(argc).map_err(|_| fault)?;
    let align16 = |v: u64| v.checked_add(15).map(|n| n & !15).ok_or(fault);
    let aligned = cursor & !15;
    let (reserved, return_bytes, stack_arg_bytes) = match arch {
        WinArch::X86 => {
            let args = count.checked_mul(4).ok_or(fault)?;
            (align16(args)?, 4, args)
        }
        WinArch::X64 => {
            let args = count.max(4).checked_mul(8).ok_or(fault)?;
            let stacked = count.saturating_sub(4).checked_mul(8).ok_or(fault)?;
            (align16(args)?, 8, stacked)
        }
        WinArch::Arm64 => {
            let stacked = count.saturating_sub(8).checked_mul(8).ok_or(fault)?;
            (align16(stacked)?, 0, stacked)
        }
    };
    let arg_base = aligned.checked_sub(reserved).ok_or(fault)?;
    let sp = arg_base.checked_sub(return_bytes).ok_or(fault)?;
    let stack_args = if arch == WinArch::X64 {
        arg_base.checked_add(32).ok_or(fault)?
    } else {
        arg_base
    };
    Ok(CallStackLayout {
        sp,
        stack_args,
        stack_arg_bytes,
        return_bytes,
    })
}

/// Probe only the argument and return-slot bytes that `call_guest_on` writes,
/// in the same order. A register-only ARM64 call probes no guest memory.
fn prepare_call(
    p: &mut Proc,
    t: &mut Thread,
    cursor: u64,
    argc: usize,
) -> Result<(), super::super::process::stack::StackFault> {
    use super::super::process::stack::{self, StackFault};
    let layout = call_stack_layout(p.arch, cursor, argc).map_err(StackFault::Access)?;
    if layout.stack_arg_bytes != 0 {
        stack::prepare(p, t, layout.stack_args, layout.stack_arg_bytes)?;
    }
    if layout.return_bytes != 0 {
        stack::prepare(p, t, layout.sp, layout.return_bytes)?;
    }
    Ok(())
}

fn retry_call(
    p: &mut Proc,
    t: &mut Thread,
    site: CallSite,
    target: u64,
    args: Vec<u64>,
    then: Cont,
    fault: super::super::process::stack::StackFault,
) -> Outcome {
    retry_operation(
        p,
        t,
        site,
        Box::new(move |_, _| Ok(Flow::CallChecked { target, args, then })),
        fault,
    )
}

/// Keeps a checked operation owned across a setup fault. The pseudo-dispatcher
/// uses a private PC/SP frontier; ordinary exports retain their entry frontier.
fn retry_operation(
    p: &mut Proc,
    t: &mut Thread,
    site: CallSite,
    retry: Cont,
    fault: super::super::process::stack::StackFault,
) -> Outcome {
    use super::super::process::stack::StackFault;
    let dispatcher = std::ptr::eq(site.api, &seh::DISPATCHER);
    let fault_pc = if dispatcher {
        p.traps.dispatcher_retry()
    } else {
        site.entry_pc
    };
    if dispatcher
        && (fault_pc == 0
            || !site.framed
            || !t.frames.last().is_some_and(|frame| {
                std::ptr::eq(frame.api, &seh::DISPATCHER)
                    && frame.entry_pc == site.entry_pc
                    && frame.entry_sp == site.entry_sp
                    && frame.exception_caller.is_some()
            }))
    {
        return Outcome::Fail("checked dispatcher callback has no owned retry frontier".into());
    }
    let record = match fault {
        StackFault::Access(fault) => memory_exception(p, t, fault_pc, fault),
        StackFault::Overflow(address) => {
            ExceptionRecord::new(STATUS_STACK_OVERFLOW, fault_pc, vec![1, address])
        }
    };
    // Publish ownership before entering any guest exception handler. A handler
    // may change ABI argument registers, repair memory, or abandon this frame.
    let frame = frame_for(t, &site);
    if dispatcher {
        if frame.dispatcher_setup_retries >= MAX_DISPATCHER_SETUP_RETRIES {
            return Outcome::Fail(format!(
                "dispatcher callback setup exceeded {MAX_DISPATCHER_SETUP_RETRIES} retries: status {:#010x}, address {:#x}",
                record.code, record.address
            ));
        }
        frame.dispatcher_setup_retries += 1;
        // The original dispatcher records and language-handler scratch occupy
        // [cursor, original entry_sp). Rebase the waiting frame to its private
        // retry frontier so nested records are allocated strictly below them.
        // Existing same-height pruning then discards an abandoned retry.
        frame.entry_pc = fault_pc;
        frame.entry_sp = site.cursor;
    }
    frame.retry = Some(retry);
    if dispatcher {
        let mut ctx = RegContext::capture(&t.cpu);
        ctx.set_pc(fault_pc);
        ctx.set_sp(site.cursor);
        if p.arch == WinArch::Arm64 {
            ctx.set_gpr(30, site.ret_addr);
        }
        return seh::raise(p, t, record, ctx);
    }
    raise_from_site(p, t, &site, record)
}

fn complete_call(
    p: &mut Proc,
    t: &mut Thread,
    site: CallSite,
    target: u64,
    args: Vec<u64>,
    then: Cont,
    checked: bool,
) -> Outcome {
    // A protected operation must not drop its owner merely because an
    // otherwise unchecked callback's stack setup faults inside the scope.
    let checked = checked
        || (site.framed
            && t.frames.last().is_some_and(|frame| {
                frame.entry_sp == site.entry_sp
                    && std::ptr::eq(frame.api, site.api)
                    && !frame.exception.is_empty()
            }));
    if let Err(fault) = prepare_call(p, t, site.cursor, args.len()) {
        if checked {
            return retry_call(p, t, site, target, args, then, fault);
        }
        // Preserve the original unchecked Call contract: dropping its unpublished
        // continuation queues any lifecycle abandonment receipt for cleanup.
        drop(then);
        let error = fault.into_api(site.entry_pc);
        return complete(p, t, site, Err(error));
    }
    let ret_trap = p.traps.callback_return();
    if checked {
        // call_guest publishes registers only after all stack writes succeed.
        // A checked late-write failure therefore retains both owner and target.
        match call_guest(p, &mut t.cpu, site.cursor, target, &args, ret_trap) {
            Ok(()) => {
                let callback_sp = t.cpu.sp();
                let frame = frame_for(t, &site);
                frame.checked_call = true;
                frame.callback_sp = Some(callback_sp);
                frame.cont = Some(then);
                Outcome::Continue
            }
            Err(fault) => retry_call(p, t, site, target, args, then, fault.into()),
        }
    } else {
        let frame = frame_for(t, &site);
        frame.checked_call = false;
        frame.cont = Some(then);
        match call_guest(p, &mut t.cpu, site.cursor, target, &args, ret_trap) {
            Ok(()) => {
                let callback_sp = t.cpu.sp();
                // The unchecked branch already published its continuation.
                // An unframed site must not create a second, empty owner here.
                t.frames
                    .last_mut()
                    .expect("callback owner published")
                    .callback_sp = Some(callback_sp);
                Outcome::Continue
            }
            Err(fault) => {
                t.frames.pop();
                let record = memory_exception(p, t, site.entry_pc, fault);
                raise_at(p, t, &site, record)
            }
        }
    }
}

/// Applies a built-in call's result.
pub fn complete(p: &mut Proc, t: &mut Thread, site: CallSite, result: ApiResult) -> Outcome {
    match result {
        Ok(Flow::Ret(v)) => {
            if p.cfg.trace {
                trace_return(p, t, &site, v);
            }
            pop_frame(t, &site);
            return_to_caller(p, t, &site, v);
            Outcome::Continue
        }
        Ok(Flow::Yield(v)) => {
            pop_frame(t, &site);
            return_to_caller(p, t, &site, v);
            Outcome::Yield
        }
        Ok(Flow::Call { target, args, then }) => {
            complete_call(p, t, site, target, args, then, false)
        }
        Ok(Flow::CallChecked { target, args, then }) => {
            complete_call(p, t, site, target, args, then, true)
        }
        Ok(Flow::Protected {
            code,
            handler,
            then,
        }) => {
            let frame = frame_for(t, &site);
            if frame.exception.try_reserve(1).is_err() {
                return Outcome::Fail("synthetic SEH scope allocation failed".into());
            }
            frame
                .exception
                .push(super::exception::ExceptionBoundary::new(
                    code,
                    site.cursor,
                    handler,
                ));
            let site = CallSite {
                framed: true,
                ..site
            };
            run(p, t, site, |c| then(c, 0))
        }
        Ok(Flow::Block { wait, then }) => {
            if let Err(error) = sync::on_block(p, t.tid, &wait) {
                return complete(p, t, site, Err(error.into()));
            }
            let frame = frame_for(t, &site);
            frame.checked_call = false;
            frame.callback_sp = None;
            frame.cont = Some(then);
            t.state = ThreadState::Waiting(wait);
            Outcome::Park
        }
        Ok(Flow::Resume(ctx)) => {
            pop_frame(t, &site);
            if let Err(status) = ctx.apply(&mut t.cpu) {
                return Outcome::Fail(format!(
                    "{}: context restoration rejected with status {status:#010x}",
                    site.api.name
                ));
            }
            prune(t, t.cpu.sp());
            prune_same_height_frontier(t, t.cpu.pc(), t.cpu.sp());
            Outcome::Continue
        }
        Ok(Flow::Raise(rec)) => {
            // The repaired pseudo-dispatcher has no guest return address at
            // its private +8 half-slot. Raising from the generic export
            // frontier would unwind its scratch as a fabricated guest frame.
            // The native nested-raise context for this case is not established;
            // stop rather than dispatch from a synthetic address.
            if std::ptr::eq(site.api, &seh::DISPATCHER)
                && site.entry_pc != 0
                && site.entry_pc == p.traps.dispatcher_retry()
            {
                return Outcome::Fail(format!(
                    "repaired dispatcher cannot raise from its private retry frontier: status {:#010x}",
                    rec.code
                ));
            }
            pop_unprotected_frame(t, &site);
            // The context is the caller's state inside the export: PC at
            // its resume trap, the stack as at entry.
            let mut ctx = RegContext::capture(&t.cpu);
            ctx.set_pc(site.entry_pc + RESUME_OFFSET);
            ctx.set_sp(site.entry_sp);
            if p.arch == WinArch::Arm64 {
                ctx.set_gpr(30, site.ret_addr);
            }
            let mut rec = rec;
            if rec.address == 0 {
                rec.address = site.entry_pc + RESUME_OFFSET;
            }
            seh::raise(p, t, rec, ctx)
        }
        Ok(Flow::RetryFault { fault, retry }) => retry_operation(
            p,
            t,
            site,
            retry,
            super::super::process::stack::StackFault::Access(fault),
        ),
        Ok(Flow::RetryOverflow { address, retry }) => retry_operation(
            p,
            t,
            site,
            retry,
            super::super::process::stack::StackFault::Overflow(address),
        ),
        Ok(Flow::ExitThread(code)) => {
            pop_frame(t, &site);
            Outcome::ThreadExit(code)
        }
        Ok(Flow::ExitProcess(code)) => {
            pop_frame(t, &site);
            Outcome::ProcessExit(code)
        }
        Ok(Flow::TerminateThread(code)) => {
            pop_frame(t, &site);
            Outcome::ThreadTerminate(code)
        }
        Ok(Flow::TerminateProcess(code)) => {
            pop_frame(t, &site);
            Outcome::ProcessTerminate(code)
        }
        Ok(Flow::SwitchFiber(target)) => {
            pop_frame(t, &site);
            return_to_caller(p, t, &site, Value::None);
            match super::super::process::fiber::switch(p, t, target) {
                Ok(()) => Outcome::Continue,
                Err(status) => Outcome::Fail(format!(
                    "fiber switch rejected after validation: {status:#010x}"
                )),
            }
        }
        Ok(Flow::Done) => {
            pop_frame(t, &site);
            prune(t, t.cpu.sp());
            prune_same_height_frontier(t, t.cpu.pc(), t.cpu.sp());
            Outcome::Continue
        }
        Err(ApiErr::Fault(fault)) => {
            let record = memory_exception(p, t, site.entry_pc, fault);
            raise_at(p, t, &site, record)
        }
        Err(ApiErr::Raise(rec)) => raise_at(p, t, &site, rec),
        Err(ApiErr::Unimplemented(what)) => Outcome::Fail(format!("unimplemented: {what}")),
        Err(ApiErr::Internal(msg)) => Outcome::Fail(msg),
    }
}

/// A parked synchronization primitive failed before its continuation could
/// resume. Preserve its original export frontier for fault classification.
pub fn wait_failed(p: &mut Proc, t: &mut Thread, error: sync::SyncError) -> Outcome {
    let Some(frame) = t.frames.last() else {
        return Outcome::Fail(format!("wait failed without an export frame: {error:?}"));
    };
    let site = CallSite {
        api: frame.api,
        entry_pc: frame.entry_pc,
        entry_sp: frame.entry_sp,
        ret_addr: frame.ret_addr,
        cursor: frame.cursor,
        framed: true,
    };
    complete(p, t, site, Err(error.into()))
}

/// Every checked access made by built-in code follows the same one-shot guard
/// semantics, including implicit return-address reads and callback writes.
/// <https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages>
fn memory_exception(p: &mut Proc, t: &Thread, pc: u64, fault: MemFault) -> ExceptionRecord {
    let guard = p.vm.take_guard(fault.addr);
    let code = if guard && fault.addr >= t.stack_alloc && fault.addr < t.stack_limit {
        STATUS_STACK_OVERFLOW
    } else if guard {
        STATUS_GUARD_PAGE_VIOLATION
    } else {
        STATUS_ACCESS_VIOLATION
    };
    ExceptionRecord::new(code, pc, vec![u64::from(fault.write), fault.addr])
}

/// Raises `rec` as a fault inside the export at `site`: the context's PC
/// is the export's entry and its stack is as at entry.
fn raise_at(p: &mut Proc, t: &mut Thread, site: &CallSite, rec: ExceptionRecord) -> Outcome {
    pop_unprotected_frame(t, site);
    raise_from_site(p, t, site, rec)
}

fn pop_unprotected_frame(t: &mut Thread, site: &CallSite) {
    if !site.framed
        || t.frames
            .last()
            .is_none_or(|frame| frame.exception.is_empty())
    {
        pop_frame(t, site);
    }
}

fn raise_from_site(p: &mut Proc, t: &mut Thread, site: &CallSite, rec: ExceptionRecord) -> Outcome {
    // A persistent TEB/record fault cannot be synchronously redispatched
    // through the same broken walker: that would exhaust the host stack.
    // The caller already classified/consumed guards. This terminal diagnostic
    // is a personality policy, not a native nested-fault status oracle.
    if std::ptr::eq(site.api, &seh::DISPATCHER) {
        return Outcome::Fail(format!(
            "exception dispatch cannot redispatch its own fault: status {:#010x}, address {:#x}, parameters {:?}",
            rec.code, rec.address, rec.params
        ));
    }
    let mut ctx = RegContext::capture(&t.cpu);
    ctx.set_pc(site.entry_pc);
    ctx.set_sp(site.entry_sp);
    if p.arch == WinArch::Arm64 {
        ctx.set_gpr(30, site.ret_addr);
    }
    let mut rec = rec;
    if rec.address == 0 {
        rec.address = site.entry_pc;
    }
    seh::raise(p, t, rec, ctx)
}

/// Writes `v` to the return registers and returns from the export.
fn return_to_caller(p: &mut Proc, t: &mut Thread, site: &CallSite, v: Value) {
    write_value(&mut t.cpu, v);
    match p.arch {
        WinArch::X86 => {
            let pop = 4 + if site.api.conv == Conv::Stdcall {
                stdcall_bytes(site.api.args)
            } else {
                0
            };
            t.cpu.set_sp(site.entry_sp.wrapping_add(pop));
        }
        WinArch::X64 => t.cpu.set_sp(site.entry_sp.wrapping_add(8)),
        WinArch::Arm64 => t.cpu.set_sp(site.entry_sp),
    }
    t.cpu.set_pc(site.ret_addr);
}

/// Writes a return value as the calling convention requires.
pub fn write_value(cpu: &mut WinCpu, v: Value) {
    let arch = cpu.arch();
    match v {
        Value::None => {}
        Value::Int(x) => cpu.set_gpr(0, x),
        Value::I64(x) => {
            cpu.set_gpr(
                0,
                if arch == WinArch::X86 {
                    x & 0xFFFF_FFFF
                } else {
                    x
                },
            );
            if arch == WinArch::X86 {
                cpu.set_gpr(2, x >> 32);
            }
        }
        Value::F64(f) => write_float(cpu, f, f.to_bits(), 8),
        Value::F32(f) => write_float(cpu, f64::from(f), u64::from(f.to_bits()), 4),
    }
}

fn write_float(cpu: &mut WinCpu, value: f64, bits: u64, width: u32) {
    match cpu {
        WinCpu::X86(x, WinArch::X86) => x87_push(x.vcpu_mut(), value),
        WinCpu::X86(x, _) => {
            let mask = if width == 8 { u64::MAX } else { 0xFFFF_FFFF };
            let r = &mut x.vcpu_mut().user_regs_mut().xmm[0];
            r[0] = (r[0] & !mask) | (bits & mask);
        }
        WinCpu::Arm64(a) => a.core_mut().set_simd(0, u128::from(bits)),
    }
}

/// Pushes `value` onto the x87 stack (`FLD`), as a `__cdecl` function
/// returning `float`/`double` on x86 leaves it in ST(0).
fn x87_push(v: &mut crate::isa::x86_64::X86_64Vcpu, value: f64) {
    let mut fx = v.xsave_image(3).bytes;
    fx.truncate(512);
    let fsw = u16::from_le_bytes([fx[2], fx[3]]);
    let top = (fsw >> 11) & 7;
    let new_top = (top + 7) & 7;
    // Registers are stored in stack order: shift ST(i) to ST(i+1).
    for i in (1..8).rev() {
        let (dst, src) = (32 + 16 * i, 32 + 16 * (i - 1));
        let tmp: [u8; 16] = fx[src..src + 16].try_into().unwrap();
        fx[dst..dst + 16].copy_from_slice(&tmp);
    }
    let raw = crate::smir::interpret::SmirInterpreter::x86_x87_from_f64(value);
    fx[32..42].copy_from_slice(&raw);
    fx[42..48].fill(0);
    let fsw = (fsw & !0x3800) | (new_top << 11);
    fx[2..4].copy_from_slice(&fsw.to_le_bytes());
    fx[4] |= 1 << new_top;
    let _ = v.fxrstor_image(&fx);
}

/// Sets up a call of guest function `target` with integer `args` on the
/// stack below `cursor`, returning to `ret_trap`.
pub fn call_guest(
    p: &Proc,
    cpu: &mut WinCpu,
    cursor: u64,
    target: u64,
    args: &[u64],
    ret_trap: u64,
) -> Result<(), MemFault> {
    call_guest_on(&p.space, cpu, cursor, target, args, ret_trap)
}

fn call_guest_on(
    mem: &crate::user::mm::AddressSpace,
    cpu: &mut WinCpu,
    cursor: u64,
    target: u64,
    args: &[u64],
    ret_trap: u64,
) -> Result<(), MemFault> {
    let layout = call_stack_layout(cpu.arch(), cursor, args.len())?;
    match cpu.arch() {
        WinArch::X64 => {
            for (i, &a) in args.iter().skip(4).enumerate() {
                mem.w64(layout.stack_args + 8 * i as u64, a)?;
            }
            mem.w64(layout.sp, ret_trap)?;
            for (i, reg) in [1usize, 2, 8, 9].iter().enumerate() {
                cpu.set_gpr(*reg, args.get(i).copied().unwrap_or(0));
            }
        }
        WinArch::X86 => {
            for (i, &a) in args.iter().enumerate() {
                mem.w32(layout.stack_args + 4 * i as u64, a as u32)?;
            }
            mem.w32(layout.sp, ret_trap as u32)?;
        }
        WinArch::Arm64 => {
            for (j, &a) in args.iter().skip(8).enumerate() {
                mem.w64(layout.stack_args + 8 * j as u64, a)?;
            }
            for i in 0..8 {
                cpu.set_gpr(i, args.get(i).copied().unwrap_or(0));
            }
            cpu.set_gpr(30, ret_trap);
        }
    }
    cpu.set_sp(layout.sp);
    cpu.set_pc(target);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, Mapping, Perms, SpaceConfig};
    use crate::user::windows::memory::{mem, prot};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    pub(super) static TEST_API: Api = Api {
        name: "guard-test",
        args: &[],
        conv: Conv::Stdcall,
        imp: |_| Flow::void(),
    };

    pub(super) fn process(arch: WinArch) -> WindowsProcess {
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
        let mut config = WindowsConfig::new("guard-test.exe", Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        WindowsProcess::spawn_image(config, image.to_vec()).unwrap()
    }

    fn alternate_stack(p: &mut Proc, t: &mut Thread, stack_guard: bool) -> (u64, u64) {
        let (base, size) =
            p.vm.allocate(None, 0x10000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap();
        let page = base + 0x8000;
        t.stack_alloc = base;
        t.stack_limit = if stack_guard { page + 0x1000 } else { base };
        t.stack_base = base + size;
        (base, page)
    }

    #[test]
    fn normal_and_forced_terminal_flows_remain_distinct_all_abis() {
        for arch in WinArch::ALL {
            for (flow, expected) in [
                (Flow::ExitThread(37), Outcome::ThreadExit(37)),
                (Flow::ExitProcess(38), Outcome::ProcessExit(38)),
                (Flow::TerminateThread(39), Outcome::ThreadTerminate(39)),
                (Flow::TerminateProcess(40), Outcome::ProcessTerminate(40)),
            ] {
                let mut process = process(arch);
                let p = process.state_mut();
                let tid = *p.threads.keys().next().unwrap();
                let mut t = p.threads.remove(&tid).unwrap();
                t.attached = true;
                let site = CallSite {
                    api: &TEST_API,
                    entry_pc: t.cpu.pc(),
                    entry_sp: t.cpu.sp(),
                    ret_addr: 0,
                    cursor: t.cpu.sp(),
                    framed: false,
                };
                assert_eq!(run(p, &mut t, site, |_| Ok(flow)), expected, "{arch}");
                assert!(t.frames.is_empty());
                assert!(
                    t.attached,
                    "terminal dispatch must not alter lifecycle admission"
                );
            }
        }
    }

    fn space() -> AddressSpace {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 16 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        space
            .map(
                0x10000,
                0x10000,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        space
    }

    #[test]
    fn callback_integer_abi_all_register_stack_boundaries() {
        for arch in WinArch::ALL {
            for count in 0..18 {
                let mem = space();
                let mut cpu = WinCpu::new(arch, &mem);
                let args: Vec<_> = (0..count).map(|i| 0x12340000 + i as u64).collect();
                call_guest_on(&mem, &mut cpu, 0x20000, 0x1234, &args, 0x5678).unwrap();
                assert_eq!(cpu.pc(), 0x1234);
                let (registers, bias) = match arch {
                    WinArch::X86 => (0, 4),
                    WinArch::X64 => (4, 40),
                    WinArch::Arm64 => (8, 0),
                };
                assert_eq!(
                    cpu.sp() & 15,
                    if arch == WinArch::X64 {
                        8
                    } else if arch == WinArch::X86 {
                        12
                    } else {
                        0
                    }
                );
                if arch == WinArch::Arm64 {
                    assert_eq!(cpu.gpr(30), 0x5678);
                } else {
                    assert_eq!(mem.ptr(cpu.sp(), arch.ptr_size()).unwrap(), 0x5678);
                }
                for (i, &expected) in args.iter().enumerate() {
                    let actual = if i < registers {
                        cpu.gpr(if arch == WinArch::X64 {
                            [1, 2, 8, 9][i]
                        } else {
                            i
                        })
                    } else {
                        mem.ptr(
                            cpu.sp() + bias + (i - registers) as u64 * arch.ptr_size(),
                            arch.ptr_size(),
                        )
                        .unwrap()
                    };
                    assert_eq!(actual, expected, "{arch}, arg {i}, count {count}");
                }
            }
        }
    }

    #[test]
    fn failed_callback_setup_preserves_cpu_and_rejects_underflow() {
        for arch in WinArch::ALL {
            let mem = space();
            let mut cpu = WinCpu::new(arch, &mem);
            cpu.set_pc(0x1111);
            cpu.set_sp(0x2222);
            cpu.set_gpr(0, 0x3333);
            assert!(call_guest_on(&mem, &mut cpu, 8, 0x4444, &[1; 17], 0x5555).is_err());
            assert_eq!((cpu.pc(), cpu.sp(), cpu.gpr(0)), (0x1111, 0x2222, 0x3333));
            assert!(call_guest_on(&mem, &mut cpu, 0x30000, 0x4444, &[1; 17], 0x5555).is_err());
            assert_eq!((cpu.pc(), cpu.sp(), cpu.gpr(0)), (0x1111, 0x2222, 0x3333));
        }
    }

    #[test]
    fn entry_and_resume_stack_reads_classify_and_consume_guards() {
        for arch in [WinArch::X86, WinArch::X64] {
            for resume in [false, true] {
                for (protection, stack_guard, expected) in [
                    (prot::NOACCESS, false, STATUS_ACCESS_VIOLATION),
                    (
                        prot::READWRITE | prot::GUARD,
                        false,
                        STATUS_GUARD_PAGE_VIOLATION,
                    ),
                    (prot::READWRITE | prot::GUARD, true, STATUS_STACK_OVERFLOW),
                ] {
                    let mut process = process(arch);
                    let p = process.state_mut();
                    let tid = *p.threads.keys().next().unwrap();
                    let mut t = p.threads.remove(&tid).unwrap();
                    let (_, page) = alternate_stack(p, &mut t, stack_guard);
                    // Fault exactly at the page boundary; exception records
                    // can be written into the accessible pages below it.
                    p.space.wptr(page, arch.ptr_size(), 0).unwrap();
                    p.vm.protect(page, 0x1000, protection).unwrap();
                    t.cpu.set_sp(page);
                    t.cpu.set_pc(0x1234);
                    let outcome = if resume {
                        resume_return(p, &mut t, &TEST_API)
                    } else {
                        enter(p, &mut t, &TEST_API, 0x1234)
                    };
                    assert_eq!(
                        outcome,
                        Outcome::ProcessTerminate(expected),
                        "{arch}, resume={resume}"
                    );
                    if protection & prot::GUARD != 0 {
                        assert_eq!(p.vm.query(page).unwrap().protect, prot::READWRITE);
                        assert!(!p.vm.take_guard(page), "guard is one-shot");
                    }
                }
            }
        }
    }

    #[test]
    fn readonly_return_address_reads_succeed_at_entry_and_resume() {
        for arch in [WinArch::X86, WinArch::X64] {
            for resume in [false, true] {
                let mut process = process(arch);
                let p = process.state_mut();
                let tid = *p.threads.keys().next().unwrap();
                let mut t = p.threads.remove(&tid).unwrap();
                let (_, page) = alternate_stack(p, &mut t, false);
                p.space.wptr(page, arch.ptr_size(), 0x4321).unwrap();
                p.vm.protect(page, 0x1000, prot::READONLY).unwrap();
                t.cpu.set_sp(page);
                let outcome = if resume {
                    resume_return(p, &mut t, &TEST_API)
                } else {
                    enter(p, &mut t, &TEST_API, 0x1234)
                };
                assert_eq!(outcome, Outcome::Continue);
                assert_eq!(t.cpu.pc(), 0x4321);
                assert_eq!(t.cpu.sp(), page + arch.ptr_size());
            }
        }
    }

    #[test]
    fn callback_stack_writes_classify_protection_and_both_guard_types() {
        for arch in WinArch::ALL {
            for (protection, stack_guard, expected) in [
                (prot::READONLY, false, STATUS_ACCESS_VIOLATION),
                (
                    prot::READWRITE | prot::GUARD,
                    false,
                    STATUS_GUARD_PAGE_VIOLATION,
                ),
                (prot::READWRITE | prot::GUARD, true, STATUS_STACK_OVERFLOW),
            ] {
                let mut process = process(arch);
                let p = process.state_mut();
                let tid = *p.threads.keys().next().unwrap();
                let mut t = p.threads.remove(&tid).unwrap();
                let (base, page) = alternate_stack(p, &mut t, stack_guard);
                p.vm.protect(page, 0x1000, protection).unwrap();
                t.cpu.set_sp(base + 0xF000);
                t.cpu.set_pc(0x1234);
                if arch == WinArch::Arm64 {
                    t.cpu.set_gpr(30, 0);
                }
                let site = CallSite {
                    api: &TEST_API,
                    entry_pc: 0x1234,
                    entry_sp: t.cpu.sp(),
                    ret_addr: 0,
                    cursor: page + 0x40,
                    framed: false,
                };
                let result = Flow::call(0x4321, vec![1; 9], |_, _| Flow::void());
                assert_eq!(
                    complete(p, &mut t, site, result),
                    Outcome::ProcessTerminate(expected),
                    "{arch}"
                );
                if protection & prot::GUARD != 0 {
                    assert_eq!(p.vm.query(page).unwrap().protect, prot::READWRITE);
                    assert!(!p.vm.take_guard(page));
                }
            }
        }
    }

    #[test]
    fn callback_preflight_preserves_first_actual_write_fault_order() {
        for (arch, cursor, argc, arg_fault_offset) in
            [(WinArch::X86, 0x10, 4, 0), (WinArch::X64, 0x20, 5, 0x10)]
        {
            let mut process = process(arch);
            let p = process.state_mut();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let (_, page) = alternate_stack(p, &mut t, false);
            p.vm.protect(page - 0x1000, 0x1000, prot::NOACCESS).unwrap();
            p.vm.protect(page, 0x1000, prot::READWRITE | prot::GUARD)
                .unwrap();

            // Argument writes precede the return-slot write. The argument
            // page must fault first, despite the return slot lying on the
            // inaccessible preceding page.
            assert_eq!(
                prepare_call(p, &mut t, page + cursor, argc),
                Err(super::super::super::process::stack::StackFault::Access(
                    MemFault {
                        addr: page + arg_fault_offset,
                        write: true,
                    }
                )),
                "{arch}"
            );
            // This direct preflight call reports the fault; the caller's
            // exception-classification path consumes a non-stack guard.
            assert_eq!(
                p.vm.query(page).unwrap().protect,
                prot::READWRITE | prot::GUARD
            );
        }
    }

    #[test]
    fn memory_exception_preserves_direction_and_fault_address() {
        for arch in WinArch::ALL {
            let mut process = process(arch);
            let p = process.state_mut();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let (_, page) = alternate_stack(p, &mut t, false);
            for write in [false, true] {
                p.vm.protect(page, 0x1000, prot::READWRITE | prot::GUARD)
                    .unwrap();
                let record = memory_exception(
                    p,
                    &t,
                    0xABCD,
                    MemFault {
                        addr: page + 3,
                        write,
                    },
                );
                assert_eq!(record.code, STATUS_GUARD_PAGE_VIOLATION);
                assert_eq!(record.address, 0xABCD);
                assert_eq!(record.params, [u64::from(write), page + 3]);
                assert_eq!(p.vm.query(page).unwrap().protect, prot::READWRITE);
            }
        }
    }

    #[test]
    fn active_exception_dispatch_fault_is_terminal_and_still_consumes_guards() {
        for arch in WinArch::ALL {
            for (protection, stack_guard, status) in [
                (prot::NOACCESS, false, STATUS_ACCESS_VIOLATION),
                (
                    prot::READWRITE | prot::GUARD,
                    false,
                    STATUS_GUARD_PAGE_VIOLATION,
                ),
                (prot::READWRITE | prot::GUARD, true, STATUS_STACK_OVERFLOW),
            ] {
                let mut process = process(arch);
                let p = process.state_mut();
                let tid = *p.threads.keys().next().unwrap();
                let mut t = p.threads.remove(&tid).unwrap();
                let (_, page) = alternate_stack(p, &mut t, stack_guard);
                p.vm.protect(page, 0x1000, protection).unwrap();
                let original = RegContext::capture(&t.cpu);
                let site = CallSite {
                    api: &seh::DISPATCHER,
                    entry_pc: 0x1234,
                    entry_sp: t.cpu.sp(),
                    ret_addr: 0,
                    cursor: t.cpu.sp(),
                    framed: false,
                };
                let outcome = complete(
                    p,
                    &mut t,
                    site,
                    Err(MemFault {
                        addr: page,
                        write: false,
                    }
                    .into()),
                );
                assert!(
                    matches!(outcome, Outcome::Fail(ref message) if message.contains(&format!("{status:#010x}"))),
                    "{arch}: {outcome:?}"
                );
                assert_eq!(RegContext::capture(&t.cpu).bytes(), original.bytes());
                if protection & prot::GUARD != 0 {
                    assert_eq!(p.vm.query(page).unwrap().protect, prot::READWRITE);
                    assert!(!p.vm.take_guard(page));
                }
            }
        }
    }

    #[test]
    fn unreadable_x86_teb_during_exception_dispatch_cannot_recurse_on_host() {
        let mut process = process(WinArch::X86);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        p.vm.protect(t.teb, 0x1000, prot::NOACCESS).unwrap();
        let ctx = RegContext::capture(&t.cpu);
        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1234, vec![0, 0x4321]);
        let outcome = seh::raise(p, &mut t, record, ctx);
        assert!(
            matches!(outcome, Outcome::Fail(ref message) if message.contains("0xc0000005")),
            "{outcome:?}"
        );
    }
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod retry_tests;

#[cfg(test)]
#[path = "x86_retry_tests.rs"]
mod x86_retry_tests;

fn trace_entry(p: &Proc, t: &Thread, site: &CallSite) {
    let module = p
        .modules
        .by_address(site.entry_pc)
        .map(|(_, m)| m.name.as_str())
        .unwrap_or("?");
    let ctx_args: Vec<String> = (0..site.api.args.len())
        .map(|i| {
            match super::args::read_arg(
                &t.cpu,
                &p.space,
                site.entry_sp,
                site.api.args,
                site.api.conv,
                i,
            ) {
                Ok(value) => format!("{value:#x}"),
                Err(fault) => format!("<fault at {:#x}>", fault.addr),
            }
        })
        .collect();
    eprintln!(
        "[{:04x}] {}!{}({}) from {:#x}",
        t.tid,
        module,
        site.api.name,
        ctx_args.join(", "),
        site.ret_addr
    );
}

fn trace_return(_p: &Proc, t: &Thread, site: &CallSite, v: Value) {
    match v {
        Value::None => eprintln!("[{:04x}] {} returned", t.tid, site.api.name),
        Value::Int(x) | Value::I64(x) => {
            eprintln!("[{:04x}] {} = {x:#x}", t.tid, site.api.name)
        }
        Value::F64(f) => eprintln!("[{:04x}] {} = {f}", t.tid, site.api.name),
        Value::F32(f) => eprintln!("[{:04x}] {} = {f}", t.tid, site.api.name),
    }
}
