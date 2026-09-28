//! Cooperative Windows scheduling and the CPU/HLE/exception frontier.
//!
//! All guest threads execute on one host thread: a mapping change or an
//! HLE operation cannot race another CPU's translation. Ready threads run
//! bounded instruction slices in round-robin order. Object/address waits
//! are polled before selection; an idle process sleeps until its next
//! deadline (at most 1 ms per host sleep), including waitable timers.
//!
//! Exception parameters follow `EXCEPTION_RECORD`:
//! <https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-exception_record>.
//! APC delivery follows `QueueUserAPC` (alertable, FIFO, all pending APCs):
//! <https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc>.
//! Raw NT service numbers depend on architecture and Windows build; no
//! verified service table is present. Such calls stop with a diagnostic
//! instead of assigning an invented service or forwarding to the host.

use std::time::{Duration, Instant};

use super::{ExitStatus, Proc, Thread, ThreadState, lifecycle, thread};
use crate::error::MemoryAccessKind;
use crate::isa::x86_64::{X86EventSource, X86UserEvent};
use crate::user::cpu::{AccessFault, AccessFaultKind};
use crate::user::windows::arch::CpuStop;
use crate::user::windows::context::{ExceptionRecord, RegContext};
use crate::user::windows::hle::dispatch::{self, CallSite, Outcome};
use crate::user::windows::hle::{Api, ApiResult, Conv, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::seh;
use crate::user::windows::sync;
use crate::user::windows::traps::Trap;

const IDLE_POLL: Duration = Duration::from_millis(1);
// NtStatus.h / MS-ERREF; AccessFault::Bus does not expose a more specific
// underlying source error, so the third exception parameter is generic.
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;

/// Runs all threads until a guest process exit or an explicit emulation
/// failure. An indefinitely blocked guest remains blocked, as on Windows.
pub(super) fn run(p: &mut Proc) -> ExitStatus {
    let mut previous = 0;
    let mut last_exit = 0;
    loop {
        if let Some(message) = &p.failure {
            return ExitStatus::Internal(message.clone());
        }
        if let Some(code) = p.exit_code {
            return shutdown(p, code);
        }
        if p.threads.is_empty() {
            p.exit_code = Some(last_exit);
            continue;
        }

        let now = Instant::now();
        tick_timers(p, now);
        // Extract each thread while invoking personality code so a guest
        // callback may create/modify other threads without borrow aliases.
        let tids: Vec<u32> = p.threads.keys().copied().collect();
        for tid in tids {
            let Some(mut t) = p.threads.remove(&tid) else {
                continue;
            };
            let outcome = if let Some(code) = t.terminate.take() {
                if let ThreadState::Waiting(wait) = &t.state {
                    if let Err(error) = sync::on_cancel(p, tid, wait) {
                        p.threads.insert(tid, t);
                        p.fail(format!("thread cancellation failed: {error:?}"));
                        break;
                    }
                }
                Outcome::ThreadTerminate(code)
            } else if let ThreadState::Exited(code) = t.state {
                Outcome::ThreadExit(code)
            } else if t.suspend == 0 {
                if let ThreadState::Waiting(wait) = &t.state {
                    let wait = wait.clone();
                    match sync::poll(p, tid, &wait, now, !t.apcs.is_empty()) {
                        Ok(Some(status)) => {
                            if let Err(error) = sync::on_cancel(p, tid, &wait) {
                                p.threads.insert(tid, t);
                                p.fail(format!("completed wait cleanup failed: {error:?}"));
                                break;
                            }
                            t.state = ThreadState::Ready;
                            if status == sync::WAIT_IO_COMPLETION && !t.apcs.is_empty() {
                                begin_apcs(p, &mut t, Some(status))
                            } else {
                                dispatch::wait_complete(p, &mut t, status)
                            }
                        }
                        Ok(None) => Outcome::Park,
                        Err(error) => {
                            if let Err(cleanup) = sync::on_cancel(p, tid, &wait) {
                                p.threads.insert(tid, t);
                                p.fail(format!(
                                    "faulted wait cleanup failed: {cleanup:?}; original: {error:?}"
                                ));
                                break;
                            }
                            t.state = ThreadState::Ready;
                            dispatch::wait_failed(p, &mut t, error)
                        }
                    }
                } else {
                    Outcome::Continue
                }
            } else {
                Outcome::Continue
            };
            apply_outcome(p, t, outcome, &mut last_exit);
            if p.exit_code.is_some() || p.failure.is_some() {
                break;
            }
        }
        if p.exit_code.is_some() || p.failure.is_some() {
            continue;
        }

        let Some(tid) = select(p, previous) else {
            if p.threads.is_empty() {
                continue;
            }
            let deadline = next_deadline(p);
            let delay = deadline
                .map(|d| d.saturating_duration_since(Instant::now()))
                .unwrap_or(IDLE_POLL)
                .min(IDLE_POLL);
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            continue;
        };
        clear_on_thread_switch(p, previous, tid);
        previous = tid;
        let mut t = p.threads.remove(&tid).expect("selected thread");
        let outcome = if let Some(status) = t.wait_status.take() {
            dispatch::wait_complete(p, &mut t, status)
        } else if t.cpu.pc() == p.traps.thread_start() && !t.apcs.is_empty() {
            begin_apcs(p, &mut t, None)
        } else {
            let stop = t.cpu.run(p.cfg.slice_insns.max(1));
            handle_stop(p, &mut t, stop)
        };
        apply_outcome(p, t, outcome, &mut last_exit);
    }
}

fn shutdown(p: &mut Proc, code: u32) -> ExitStatus {
    // A terminated address space must not be written merely to unregister
    // dormant lock waiters. Drop host registrations/pins before thread teardown.
    sync::on_process_exit(p);
    for (_, thread) in std::mem::take(&mut p.threads) {
        // ExitProcess documents the supplied code for the process/all threads.
        thread::destroy(p, thread, code);
    }
    if let Err(status) = super::fiber::destroy_all(p) {
        let message = format!("process fiber teardown failed: {status:#010x}");
        p.fail(message.clone());
        return ExitStatus::Internal(message);
    }
    crate::user::windows::dll::crt::onexit::discard_process(p);
    let termination_failure = crate::user::windows::dll::crt::termination::discard_process(p).err();
    let stdio_failure = crate::user::windows::dll::crt::stdio::discard_process(p).err();
    p.tls.fls_discard_all();
    for (_, object) in p.objects.iter_mut() {
        if let Object::Process { pid, exit_code } = object
            && *pid == p.pid
        {
            *exit_code = Some(code);
        }
    }
    let objects: Vec<_> = p.objects.drain().collect();
    for object in objects {
        if let Err(error) = crate::user::windows::dll::finish_close(Some(object)) {
            let message = format!("process file cleanup failed with Win32 error {error}");
            p.fail(message.clone());
            return ExitStatus::Internal(message);
        }
    }
    if let Some(message) = termination_failure.or(stdio_failure) {
        p.fail(message.clone());
        ExitStatus::Internal(message)
    } else {
        ExitStatus::Exited(code)
    }
}

fn apply_outcome(p: &mut Proc, mut t: Thread, mut outcome: Outcome, last_exit: &mut u32) {
    if let Outcome::ProcessTerminate(code) = outcome {
        // The address space is dying: guest rollback/LDR writes and DLL/FLS
        // callbacks must not override forced termination or its exit status.
        t.frames.clear();
        sync::on_process_exit(p);
        for other in p.threads.values_mut() {
            other.frames.clear();
        }
        super::fiber::discard_continuations(p);
        crate::user::windows::dll::crt::onexit::discard_process(p);
        if let Err(error) = crate::user::windows::dll::crt::termination::discard_process(p) {
            tracing::debug!("forced CRT global teardown: {error}");
        }
        if let Err(error) = crate::user::windows::dll::crt::stdio::discard_process(p) {
            // Forced termination retains its deliberate supplied status. The
            // attempted host cleanup failure remains a trace diagnostic.
            tracing::debug!("forced CRT stdio teardown: {error}");
        }
        p.tls.fls_discard_abandoned();
        crate::user::windows::dll::libraries::abort_process(p);
        p.exit_code = Some(code);
        p.threads.insert(t.tid, t);
        return;
    }
    if matches!(
        outcome,
        Outcome::ThreadExit(_) | Outcome::ProcessExit(_) | Outcome::ThreadTerminate(_)
    ) {
        // Cancellation runs before destroying the TLS/TEB needed by a loader
        // journal. A held DLL entrypoint cannot silently escape through exit.
        t.frames.clear();
        super::fiber::discard_thread_continuations(p, t.tid);
    }
    // A terminal callback does not return through the abandoned API. Retire
    // its host receipt, but do not turn a deliberate normal/forced exit into
    // fabricated API success or an unrelated emulator failure. Nonterminal
    // escapes (NtContinue/longjmp) still report the unfinished continuation.
    let terminal_owner = matches!(
        outcome,
        Outcome::ThreadExit(_) | Outcome::ProcessExit(_) | Outcome::ThreadTerminate(_)
    );
    if let Err(error) = crate::user::windows::dll::crt::onexit::cleanup_abandoned(
        p,
        terminal_owner.then_some(t.tid),
    ) {
        outcome = Outcome::Fail(error);
    }
    let abandoned = p.tls.fls_take_abandoned();
    if let Err(error) = crate::user::windows::dll::crt::termination::cleanup_abandoned(
        p,
        terminal_owner.then_some(t.tid),
    ) {
        outcome = Outcome::Fail(error);
    }
    if let Some(receipt) = abandoned
        .into_iter()
        .find(|receipt| !terminal_owner || receipt.tid != t.tid)
    {
        outcome = Outcome::Fail(format!(
            "FLS continuation abandoned: {} on thread {}",
            receipt.kind, receipt.tid
        ));
    }
    if let Err(error) = crate::user::windows::dll::libraries::cleanup_abandoned(p, &mut t) {
        outcome = Outcome::Fail(error);
    }
    if let Outcome::ThreadExit(code) = outcome
        && t.attached
        && !p.modules.list.is_empty()
        && p.loader.exiting_threads.insert(t.tid)
    {
        outcome = lifecycle::thread_exit(p, &mut t, code);
    }
    if let Outcome::ThreadExit(code) = outcome
        && p.threads.is_empty()
        && p.loader.exiting_threads.contains(&t.tid)
        && !p.modules.list.is_empty()
    {
        // Keep the final normally exiting caller's TLS/TEB until the process
        // notification stage completes. Forced termination remains distinct.
        outcome = Outcome::ProcessExit(code);
    }
    if let Outcome::ProcessExit(code) = outcome
        && !p.loader.exiting_process
        && !p.modules.list.is_empty()
    {
        p.loader.exiting_process = true;
        // ExitProcess terminates other threads without DLL_THREAD_DETACH;
        // only the caller retains its environment for PROCESS_DETACH.
        for other in p.threads.values_mut() {
            other.frames.clear();
        }
        let tids: Vec<_> = p.threads.keys().copied().collect();
        for tid in tids {
            super::fiber::discard_thread_continuations(p, tid);
        }
        p.tls.fls_discard_abandoned();
        let cleanup = sync::on_normal_process_exit(p, t.tid)
            .map_err(|error| format!("normal process-exit wait retirement failed: {error:?}"))
            .and_then(|()| crate::user::windows::dll::crt::onexit::retire_process_drains(p))
            .and_then(|()| crate::user::windows::dll::crt::termination::retire_process_drains(p))
            .and_then(|()| crate::user::windows::dll::libraries::cleanup_abandoned(p, &mut t));
        if let Err(error) = cleanup {
            outcome = Outcome::Fail(error);
        } else {
            for (_, other) in std::mem::take(&mut p.threads) {
                thread::destroy(p, other, code);
            }
            outcome = if let Some(error) = &p.failure {
                // Failed peer teardown can invalidate guest callback state.
                // Do not resume DLL_PROCESS_DETACH in that partial state.
                Outcome::Fail(error.clone())
            } else {
                lifecycle::process_exit(p, &mut t, code)
            };
        }
    }
    let final_exit = match outcome {
        Outcome::ThreadExit(code) => Some((code, false)),
        Outcome::ProcessExit(code) => Some((code, true)),
        _ => None,
    };
    if let Some((code, process)) = final_exit
        && !t.fls_exiting
    {
        t.fls_exiting = true;
        outcome = super::fls_exit::begin(p, &mut t, code, process);
    }
    match outcome {
        Outcome::ThreadExit(code) | Outcome::ThreadTerminate(code) => {
            *last_exit = code;
            p.loader.exiting_threads.remove(&t.tid);
            thread::destroy(p, t, code);
        }
        Outcome::ProcessExit(code) | Outcome::ProcessTerminate(code) => {
            p.exit_code = Some(code);
            p.threads.insert(t.tid, t);
        }
        Outcome::Fail(message) => {
            p.fail(message);
            p.threads.insert(t.tid, t);
        }
        Outcome::Continue | Outcome::Yield | Outcome::Park => {
            p.threads.insert(t.tid, t);
        }
    }
}

/// The initial process attach precedes a created thread's entry point. Later
/// entrypoint serialization is implemented by the reentrant loader lock, not
/// by stopping already attached guest threads when its owner blocks.
fn select(p: &Proc, previous: u32) -> Option<u32> {
    let initial_attach = p.threads.values().any(|t| t.main && !t.attached);
    p.threads
        .range((
            std::ops::Bound::Excluded(previous),
            std::ops::Bound::Unbounded,
        ))
        .chain(p.threads.range(..=previous))
        .find_map(|(&tid, t)| {
            (t.runnable() && (!initial_attach || t.main || t.attached)).then_some(tid)
        })
}

fn clear_on_thread_switch(p: &mut Proc, previous: u32, next: u32) {
    // A budget yield can resume the same guest thread without an exception.
    // Only switching away invalidates that ARM64 thread's local reservation.
    if previous != next
        && let Some(cpu) = p.threads.get_mut(&previous).and_then(|t| t.cpu.a64_mut())
    {
        cpu.core_mut().clear_exclusive_monitor();
    }
}

fn tick_timers(p: &mut Proc, now: Instant) {
    for (_, object) in p.objects.iter_mut() {
        if let Object::Timer {
            signaled,
            due,
            period_ms,
            ..
        } = object
            && let Some(at) = *due
            && at <= now
        {
            *signaled = true;
            *due = if *period_ms == 0 {
                None
            } else {
                let period = u128::from(*period_ms);
                let periods = now.saturating_duration_since(at).as_millis() / period + 1;
                let elapsed = periods
                    .checked_mul(period)
                    .and_then(|v| u64::try_from(v).ok());
                elapsed.and_then(|ms| at.checked_add(Duration::from_millis(ms)))
            };
        }
    }
}

fn next_deadline(p: &mut Proc) -> Option<Instant> {
    let thread_deadline = p
        .threads
        .values()
        .filter_map(|t| match &t.state {
            ThreadState::Waiting(wait) if t.suspend == 0 => wait.deadline(),
            _ => None,
        })
        .min();
    let timer_deadline = p
        .objects
        .iter()
        .filter_map(|(_, object)| match object {
            Object::Timer { due, .. } => *due,
            _ => None,
        })
        .min();
    thread_deadline.into_iter().chain(timer_deadline).min()
}

fn access_parameter(access: MemoryAccessKind) -> u64 {
    match access {
        MemoryAccessKind::Read => 0,
        MemoryAccessKind::Write => 1,
        MemoryAccessKind::Fetch => 8,
    }
}

fn raise(
    p: &mut Proc,
    t: &mut Thread,
    code: u32,
    address: u64,
    params: Vec<u64>,
    resume_pc: u64,
) -> Outcome {
    let mut ctx = RegContext::capture(&t.cpu);
    ctx.set_pc(resume_pc);
    seh::raise(p, t, ExceptionRecord::new(code, address, params), ctx)
}

fn access_fault(p: &mut Proc, t: &mut Thread, f: AccessFault) -> Outcome {
    let params = vec![access_parameter(f.access), f.addr];
    if p.vm.take_guard(f.addr) {
        match super::stack::grow(p, t, f.addr) {
            Ok(super::stack::Growth::Grown) => return Outcome::Continue,
            Err(fault) => {
                return raise(
                    p,
                    t,
                    STATUS_ACCESS_VIOLATION,
                    f.pc,
                    vec![u64::from(fault.write), fault.addr],
                    f.pc,
                );
            }
            Ok(super::stack::Growth::Overflow) => {
                return raise(p, t, STATUS_STACK_OVERFLOW, f.pc, params, f.pc);
            }
            Ok(super::stack::Growth::NotStack) => {}
        }
        let stack_guard = f.addr >= t.stack_alloc && f.addr < t.stack_limit;
        return raise(
            p,
            t,
            if stack_guard {
                STATUS_STACK_OVERFLOW
            } else {
                STATUS_GUARD_PAGE_VIOLATION
            },
            f.pc,
            params,
            f.pc,
        );
    }
    if f.access == MemoryAccessKind::Fetch
        && f.addr == f.pc
        && f.kind == AccessFaultKind::Permission
        && p.vm.query(f.pc).is_some_and(|r| {
            r.state == crate::user::windows::memory::mem::COMMIT
                && crate::user::windows::memory::perms_of(r.protect)
                    .contains(crate::user::mm::Perms::EXEC)
        })
        && let Some(trap) = p.traps.lookup(f.pc)
    {
        return match trap {
            Trap::Entry(api) => dispatch::enter(p, t, api, f.pc),
            Trap::Resume(api) => dispatch::resume_return(p, t, api),
            Trap::CallbackReturn => dispatch::callback_return(p, t),
            Trap::ThreadStart => lifecycle::thread_start(p, t),
            Trap::FiberStart => crate::user::windows::dll::fibers::fiber_start(p, t),
            Trap::DispatcherRetry => dispatch::dispatcher_retry(p, t, f.pc),
            Trap::Missing(name) => Outcome::Fail(format!(
                "unimplemented Windows export: {name} at {:#x}",
                f.pc
            )),
        };
    }
    match f.kind {
        AccessFaultKind::Alignment => raise(p, t, STATUS_DATATYPE_MISALIGNMENT, f.pc, vec![], f.pc),
        AccessFaultKind::Bus => {
            let mut params = params;
            params.push(u64::from(STATUS_UNSUCCESSFUL));
            raise(p, t, STATUS_IN_PAGE_ERROR, f.pc, params, f.pc)
        }
        AccessFaultKind::Unmapped | AccessFaultKind::Permission => {
            raise(p, t, STATUS_ACCESS_VIOLATION, f.pc, params, f.pc)
        }
    }
}

fn floating_status(flags: u32, mask: u32, stack_fault: bool) -> u32 {
    let active = flags & !mask & 0x3F;
    if active & 1 != 0 {
        if stack_fault {
            STATUS_FLOAT_STACK_CHECK
        } else {
            STATUS_FLOAT_INVALID_OPERATION
        }
    } else if active & 2 != 0 {
        STATUS_FLOAT_DENORMAL_OPERAND
    } else if active & 4 != 0 {
        STATUS_FLOAT_DIVIDE_BY_ZERO
    } else if active & 8 != 0 {
        STATUS_FLOAT_OVERFLOW
    } else if active & 16 != 0 {
        STATUS_FLOAT_UNDERFLOW
    } else if active & 32 != 0 {
        STATUS_FLOAT_INEXACT_RESULT
    } else {
        STATUS_FLOAT_INVALID_OPERATION
    }
}

fn x86_event(p: &mut Proc, t: &mut Thread, e: X86UserEvent) -> Outcome {
    if e.source == X86EventSource::SoftwareInterrupt && e.vector == 0x29 {
        return seh::fail_fast(t.cpu.gpr(1));
    }
    if e.source == X86EventSource::SoftwareInterrupt && !matches!(e.vector, 1 | 3 | 4) {
        return raise(
            p,
            t,
            STATUS_PRIVILEGED_INSTRUCTION,
            e.insn_rip,
            vec![],
            e.insn_rip,
        );
    }
    let code = match e.vector {
        0 => STATUS_INTEGER_DIVIDE_BY_ZERO,
        1 => STATUS_SINGLE_STEP,
        3 => STATUS_BREAKPOINT,
        4 => STATUS_INTEGER_OVERFLOW,
        5 => STATUS_ARRAY_BOUNDS_EXCEEDED,
        6 | 7 => STATUS_ILLEGAL_INSTRUCTION,
        10..=13 => STATUS_PRIVILEGED_INSTRUCTION,
        17 => STATUS_DATATYPE_MISALIGNMENT,
        16 => {
            let Some(x) = t.cpu.x86() else {
                return Outcome::Fail("x87 event on non-x86 CPU".into());
            };
            let fx = x.vcpu().xsave_image(3).bytes;
            let control = u16::from_le_bytes([fx[0], fx[1]]);
            let status = u16::from_le_bytes([fx[2], fx[3]]);
            floating_status(u32::from(status), u32::from(control), status & 0x40 != 0)
        }
        19 => {
            let Some(x) = t.cpu.x86() else {
                return Outcome::Fail("SIMD event on non-x86 CPU".into());
            };
            let mxcsr = x.vcpu().mxcsr();
            floating_status(mxcsr, mxcsr >> 7, false)
        }
        vector => {
            return Outcome::Fail(format!(
                "unclassified x86 user exception vector {vector:#x} at {:#x}",
                e.insn_rip
            ));
        }
    };
    // Windows normalizes an INT3 breakpoint to the byte immediately before
    // the architectural saved PC. Other traps preserve their saved PC.
    let pc = if e.vector == 3 {
        e.return_rip.saturating_sub(1)
    } else {
        e.return_rip
    };
    let address = if e.vector == 3 { pc } else { e.insn_rip };
    raise(p, t, code, address, vec![], pc)
}

fn handle_stop(p: &mut Proc, t: &mut Thread, stop: CpuStop) -> Outcome {
    match stop {
        CpuStop::Fault(f) => access_fault(p, t, f),
        CpuStop::X86Event(e) => x86_event(p, t, e),
        CpuStop::X86Syscall { insn, insn_rip } => Outcome::Fail(format!(
            "raw Windows {} {insn:?} service {:#x} at {insn_rip:#x}: service table for build {} is unknown",
            p.arch,
            t.cpu.gpr(0) as u32,
            p.cfg.version.build
        )),
        CpuStop::Svc { imm, pc } => Outcome::Fail(format!(
            "raw Windows ARM64 SVC #{imm:#x} service {:#x} at {pc:#x}: service table for build {} is unknown",
            t.cpu.gpr(8) as u32,
            p.cfg.version.build
        )),
        CpuStop::Brk { imm: 0xF003, .. } => seh::fail_fast(t.cpu.gpr(0)),
        CpuStop::Brk { pc, imm } => raise(p, t, STATUS_BREAKPOINT, pc, vec![u64::from(imm)], pc),
        CpuStop::Undefined { pc, .. } => raise(p, t, STATUS_ILLEGAL_INSTRUCTION, pc, vec![], pc),
        CpuStop::Yield => Outcome::Yield,
        CpuStop::Internal(message) => Outcome::Fail(message),
    }
}

fn unused_apc_entry(_: &mut Ctx) -> ApiResult {
    Ok(Flow::Done)
}

static APC: Api = Api {
    name: "KiUserApcDispatcher",
    args: &[],
    conv: Conv::Custom,
    imp: unused_apc_entry,
};

fn begin_apcs(p: &mut Proc, t: &mut Thread, wait_status: Option<u64>) -> Outcome {
    let saved = RegContext::capture(&t.cpu);
    let sp = t.cpu.sp();
    let site = CallSite {
        api: &APC,
        entry_pc: t.cpu.pc(),
        entry_sp: sp,
        ret_addr: t.cpu.pc(),
        cursor: sp.saturating_sub(32) & !15,
        framed: false,
    };
    dispatch::run(p, t, site, move |c| next_apc(c, saved, wait_status))
}

fn next_apc(c: &mut Ctx, saved: RegContext, wait_status: Option<u64>) -> ApiResult {
    if let Some((routine, argument)) = c.t.apcs.pop_front() {
        Flow::call(routine, vec![argument], move |c, _| {
            next_apc(c, saved, wait_status)
        })
    } else {
        c.t.wait_status = wait_status;
        Ok(Flow::Resume(Box::new(saved)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, PAGE_SIZE, SpaceConfig};
    use crate::user::windows::arch::{WinArch, WinCpu};
    use crate::user::windows::heap::Heaps;
    use crate::user::windows::hle::Frame;
    use crate::user::windows::memory::{Mem, VirtualMemory, mem, prot};
    use crate::user::windows::objects::Objects;
    use crate::user::windows::process::WindowsConfig;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    #[path = "exit_tests.rs"]
    mod exit_tests;

    #[path = "monitor_tests.rs"]
    mod monitor_tests;

    fn process(arch: WinArch) -> Proc {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 4 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        Proc {
            arch,
            vm: VirtualMemory::new(space.clone(), 0x10000, 1 << 32),
            space,
            cfg: Arc::new(WindowsConfig::new("unused-test.exe", vec![])),
            pid: 4,
            peb: 0,
            params: 0,
            ansi_command_line: None,
            process_heap: 0,
            modules: Default::default(),
            loader: Default::default(),
            fibers: Default::default(),
            traps: Default::default(),
            objects: Objects::default(),
            heaps: Heaps::new(if arch.is64() { 16 } else { 8 }),
            tls: Default::default(),
            seh: Default::default(),
            sync: Default::default(),
            crt: Default::default(),
            threads: BTreeMap::new(),
            next_tid: 8,
            exit_code: None,
            failure: None,
            start_time: Instant::now(),
            rng: 1,
            cwd: vec![],
            exe_stack_reserve: 0x10000,
            exe_stack_commit: PAGE_SIZE,
        }
    }

    fn thread(p: &mut Proc, tid: u32) -> Thread {
        let (stack, size) =
            p.vm.allocate(None, 0x10000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap();
        let (teb, _) =
            p.vm.allocate(
                None,
                crate::user::windows::layout::teb_stride(p.arch),
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap();
        if p.arch == WinArch::X86 {
            p.space.w32(teb, u32::MAX).unwrap();
        }
        let mut cpu = WinCpu::new(p.arch, &p.space);
        cpu.set_sp(stack + size - 0x40);
        cpu.set_pc(0x1234_0000);
        cpu.set_teb(teb);
        let obj = p.objects.create(Object::Thread {
            tid,
            exit_code: None,
        });
        p.objects.retain(obj);
        Thread {
            tid,
            cpu,
            teb,
            stack_base: stack + size,
            stack_limit: stack,
            stack_alloc: stack,
            thread_stack_alloc: stack,
            current_fiber: None,
            fls_exiting: false,
            state: ThreadState::Ready,
            frames: vec![],
            obj,
            start: 0,
            param: 0,
            main: false,
            suspend: 0,
            apcs: VecDeque::new(),
            wait_status: None,
            terminate: None,
            tls_array: 0,
            tls_blocks: vec![],
            attached: true,
        }
    }

    fn park(t: &mut Thread, wait: sync::Wait) {
        t.frames.push(Frame {
            api: &APC,
            entry_pc: t.cpu.pc(),
            entry_sp: t.cpu.sp(),
            ret_addr: 0,
            cursor: t.cpu.sp().saturating_sub(32),
            cont: Some(Box::new(|_, status| Ok(Flow::ExitThread(status as u32)))),
            checked_call: false,
            callback_sp: None,
            retry: None,
            dispatcher_setup_retries: 0,
            exception: Vec::new(),
            exception_caller: None,
        });
        t.state = ThreadState::Waiting(wait);
    }

    fn terminal_fixture(arch: WinArch) -> (super::super::WindowsProcess, Thread, usize) {
        use crate::user::windows::loader::{self, Module, ModuleKind, ModuleTls};
        use crate::user::windows::process::WindowsProcess;
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
        let mut config = WindowsConfig::new("forced-exit-test.exe", vec![]);
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        t.attached = true;
        t.main = false;
        let base =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space
            .wptr(base + 0x200, arch.ptr_size(), base + 0x80)
            .unwrap();
        p.space
            .wptr(base + 0x200 + arch.ptr_size(), arch.ptr_size(), 0)
            .unwrap();
        let index = p.modules.list.len();
        p.modules.list.push(Module {
            name: "termination-test.dll".into(),
            path: "termination-test.dll".into(),
            host_path: None,
            base,
            size: PAGE_SIZE,
            entry: base + 0x100,
            kind: ModuleKind::Native,
            timestamp: 0,
            exports: Default::default(),
            pdata: Default::default(),
            no_seh: false,
            safe_seh: None,
            tls: Some(ModuleTls {
                index: 0,
                template: 0,
                raw_size: 0,
                zero_fill: 0,
                callbacks: base + 0x200,
            }),
            ldr_entry: 0,
            load_count: 1,
            thread_calls: true,
            initialized: false,
            builtin_symbols: Default::default(),
            builtin_ordinals: vec![],
            text: 0,
            stubs: Default::default(),
        });
        p.modules.init_order.push(index);
        loader::attach_started(p, index, true).unwrap();
        loader::attach_succeeded(p, index).unwrap();
        (process, t, index)
    }

    #[test]
    fn forced_thread_exit_skips_callbacks_but_signals_and_frees_resources_all_abis() {
        for arch in WinArch::ALL {
            let (mut process, t, index) = terminal_fixture(arch);
            let p = process.state_mut();
            let (tid, obj, stack, teb) = (t.tid, t.obj, t.stack_alloc, t.teb);
            let handle = p.objects.open(obj, false);
            let mut last = 0;
            apply_outcome(p, t, Outcome::ThreadTerminate(0xDEAD_BEEF), &mut last);
            assert_eq!(last, 0xDEAD_BEEF);
            assert!(!p.threads.contains_key(&tid));
            assert!(p.exit_code.is_none());
            assert!(p.failure.is_none());
            assert!(p.modules.list[index].initialized);
            assert!(p.loader.is_idle());
            assert!(matches!(
                p.objects.get(u64::from(handle)),
                Some(Object::Thread {
                    exit_code: Some(0xDEAD_BEEF),
                    ..
                })
            ));
            assert_eq!(p.vm.query(stack).unwrap().state, mem::FREE);
            assert!(p.space.probe(teb, 1, MemoryAccessKind::Read).is_err());

            let (mut normal, t, index) = terminal_fixture(arch);
            let p = normal.state_mut();
            let tid = t.tid;
            apply_outcome(p, t, Outcome::ThreadExit(0xDEAD_BEEF), &mut last);
            assert_eq!(p.threads[&tid].cpu.pc(), p.modules.list[index].entry);
            assert!(
                !p.threads[&tid].frames.is_empty(),
                "normal exit must await DLL_THREAD_DETACH"
            );
            assert!(p.exit_code.is_none());
        }
    }

    #[test]
    fn access_violation_parameters_distinguish_read_write_and_dep() {
        assert_eq!(access_parameter(MemoryAccessKind::Read), 0);
        assert_eq!(access_parameter(MemoryAccessKind::Write), 1);
        assert_eq!(access_parameter(MemoryAccessKind::Fetch), 8);
    }

    #[test]
    fn process_exit_cancels_wait_pins_destroys_threads_and_closes_protected_handles() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            let stack = t.stack_alloc;
            let teb = t.teb;
            let handle = p.objects.insert(Object::Event {
                manual: true,
                signaled: false,
            });
            let id = p.objects.id(u64::from(handle)).unwrap();
            let wait = sync::Wait::Objects {
                objs: vec![id],
                all: false,
                deadline: None,
                alertable: false,
            };
            sync::on_block(&mut p, t.tid, &wait).unwrap();
            p.objects.close(u64::from(handle)).unwrap();
            park(&mut t, wait);
            p.threads.insert(t.tid, t);
            let protected = p.objects.insert(Object::Null);
            p.objects.set_flags(u64::from(protected), 2, 2);
            let t = thread(&mut p, 12);
            p.threads.insert(t.tid, t);
            p.exit_code = Some(0x1234_5678);
            assert_eq!(run(&mut p), ExitStatus::Exited(0x1234_5678));
            assert!(p.threads.is_empty());
            assert_eq!(p.objects.handle_count(), 0);
            assert_eq!(p.objects.iter().count(), 0);
            assert_eq!(p.vm.query(stack).unwrap().state, mem::FREE);
            assert!(p.space.probe(teb, 1, MemoryAccessKind::Read).is_err());
            assert_eq!(
                run(&mut p),
                ExitStatus::Exited(0x1234_5678),
                "shutdown is idempotent"
            );
        }
    }

    #[test]
    fn floating_exception_selection_respects_masks_and_stack_fault() {
        let statuses = [
            STATUS_FLOAT_INVALID_OPERATION,
            STATUS_FLOAT_DENORMAL_OPERAND,
            STATUS_FLOAT_DIVIDE_BY_ZERO,
            STATUS_FLOAT_OVERFLOW,
            STATUS_FLOAT_UNDERFLOW,
            STATUS_FLOAT_INEXACT_RESULT,
        ];
        for (bit, expected) in statuses.into_iter().enumerate() {
            assert_eq!(floating_status(1 << bit, 0, false), expected);
            assert_eq!(floating_status(0x3F, (1 << bit) - 1, false), expected);
        }
        assert_eq!(floating_status(1, 0, true), STATUS_FLOAT_STACK_CHECK);
        assert_eq!(floating_status(1 | 4, 1, true), STATUS_FLOAT_DIVIDE_BY_ZERO);
    }

    #[test]
    fn secondary_dll_notifications_do_not_freeze_attached_application_threads_all_abis() {
        for arch in WinArch::ALL {
            let (mut process, mut owner, _) = terminal_fixture(arch);
            let p = process.state_mut();
            owner.attached = false;
            assert_eq!(lifecycle::thread_start(p, &mut owner), Outcome::Continue);
            assert!(!p.loader.is_idle());
            assert!(
                owner
                    .frames
                    .iter()
                    .any(|frame| frame.api.name == "RtlUserThreadStart")
            );
            let owner_tid = owner.tid;
            let peer_tid = owner_tid.checked_add(4).unwrap();
            let peer = thread(p, peer_tid);
            assert!(peer.attached && peer.runnable());
            p.threads.insert(owner_tid, owner);
            p.threads.insert(peer_tid, peer);
            assert_eq!(select(p, owner_tid), Some(peer_tid));
            p.threads.get_mut(&owner_tid).unwrap().state =
                ThreadState::Waiting(sync::Wait::Sleep {
                    deadline: None,
                    alertable: false,
                });
            assert_eq!(
                select(p, 0),
                Some(peer_tid),
                "a parked notifier cannot freeze an attached peer"
            );
        }
    }

    #[test]
    fn timed_wait_completes_and_last_thread_exit_ends_process() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            park(
                &mut t,
                sync::Wait::Sleep {
                    deadline: Some(Instant::now()),
                    alertable: false,
                },
            );
            p.threads.insert(8, t);
            assert_eq!(run(&mut p), ExitStatus::Exited(0));
            assert!(p.threads.is_empty());
        }
    }

    #[test]
    fn timer_signal_completes_object_wait_without_skipping_guest_wait() {
        let mut p = process(WinArch::X64);
        let obj = p.objects.create(Object::Timer {
            manual: false,
            signaled: false,
            due: Some(Instant::now()),
            period_ms: 0,
        });
        p.objects.retain(obj);
        let mut t = thread(&mut p, 8);
        park(
            &mut t,
            sync::Wait::Objects {
                objs: vec![obj],
                all: false,
                deadline: None,
                alertable: false,
            },
        );
        if let ThreadState::Waiting(wait) = &t.state {
            sync::on_block(&mut p, t.tid, wait).unwrap();
        }
        t.frames.last_mut().unwrap().cont = Some(Box::new(move |c, status| {
            assert_eq!(status, 0);
            assert!(matches!(
                c.p.objects.obj(obj),
                Some(Object::Timer {
                    signaled: false,
                    due: None,
                    ..
                })
            ));
            Ok(Flow::ExitThread(0))
        }));
        p.threads.insert(8, t);
        assert_eq!(run(&mut p), ExitStatus::Exited(0));
        assert!(
            p.objects.obj(obj).is_none(),
            "process shutdown drains local objects"
        );
    }

    #[test]
    fn periodic_timer_advances_by_full_periods() {
        let mut p = process(WinArch::X64);
        let now = Instant::now();
        let due = now - Duration::from_millis(35);
        let obj = p.objects.create(Object::Timer {
            manual: true,
            signaled: false,
            due: Some(due),
            period_ms: 10,
        });
        p.objects.retain(obj);
        tick_timers(&mut p, now);
        match p.objects.obj(obj) {
            Some(Object::Timer {
                signaled,
                due: Some(at),
                ..
            }) => {
                assert!(*signaled);
                assert_eq!(*at, due + Duration::from_millis(40));
            }
            _ => panic!("periodic timer lost"),
        }
    }

    #[test]
    fn forced_thread_termination_signals_preserved_handle() {
        let mut p = process(WinArch::X64);
        let mut t = thread(&mut p, 8);
        let obj = t.obj;
        let _handle = p.objects.open(obj, false);
        t.suspend = 1;
        t.terminate = Some(37);
        p.threads.insert(8, t);
        let mut observer = thread(&mut p, 12);
        let wait = sync::Wait::Objects {
            objs: vec![obj],
            all: false,
            deadline: None,
            alertable: false,
        };
        sync::on_block(&mut p, observer.tid, &wait).unwrap();
        park(&mut observer, wait);
        observer.frames.last_mut().unwrap().cont = Some(Box::new(move |c, status| {
            assert_eq!(status, 0);
            assert!(matches!(
                c.p.objects.obj(obj),
                Some(Object::Thread {
                    exit_code: Some(37),
                    ..
                })
            ));
            Ok(Flow::ExitThread(44))
        }));
        p.threads.insert(observer.tid, observer);
        assert_eq!(run(&mut p), ExitStatus::Exited(44));
        assert!(
            p.objects.obj(obj).is_none(),
            "signal observed before process teardown"
        );
    }

    #[test]
    fn raw_nt_services_never_infer_build_specific_numbers() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            let stop = if arch == WinArch::Arm64 {
                t.cpu.set_gpr(8, 0x37);
                CpuStop::Svc {
                    imm: 0,
                    pc: 0x1234_0000,
                }
            } else {
                t.cpu.set_gpr(0, 0x37);
                CpuStop::X86Syscall {
                    insn: crate::isa::x86_64::X86SyscallInsn::Syscall,
                    insn_rip: 0x1234_0000,
                }
            };
            match handle_stop(&mut p, &mut t, stop) {
                Outcome::Fail(reason) => {
                    assert!(reason.contains("service 0x37"));
                    assert!(reason.contains("build 26100 is unknown"));
                }
                other => panic!("raw service executed: {other:?}"),
            }
        }
    }

    #[test]
    fn normal_fls_exit_keeps_environment_until_callback_returns_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let t = thread(&mut p, 8);
            let teb = t.teb;
            let stack = t.thread_stack_alloc;
            let slot = p.tls.fls_alloc(0x1234_5678).unwrap();
            p.tls.fls_set(t.fls_key(), slot, 91).unwrap();
            let mut last = 0;
            apply_outcome(&mut p, t, Outcome::ThreadExit(37), &mut last);
            let mut t = p.threads.remove(&8).unwrap();
            assert_eq!(t.cpu.pc(), 0x1234_5678);
            assert!(t.fls_exiting);
            assert!(p.vm.query(teb).is_some_and(|r| r.state == mem::COMMIT));
            assert!(p.vm.query(stack).is_some_and(|r| r.state == mem::COMMIT));
            assert_eq!(p.tls.fls_get(t.fls_key(), slot), Ok(0));
            let outcome = dispatch::callback_return(&mut p, &mut t);
            assert_eq!(outcome, Outcome::ThreadExit(37));
            apply_outcome(&mut p, t, outcome, &mut last);
            assert!(p.threads.is_empty());
            assert!(p.failure.is_none(), "{:?}", p.failure);
            assert_eq!(last, 37);
            assert_eq!(p.vm.query(stack).unwrap().state, mem::FREE);
            assert_eq!(p.vm.query(teb).unwrap().state, mem::RESERVE);
        }
    }

    #[test]
    fn terminal_fls_callback_aborts_api_without_replacing_exit_all_abis() {
        for arch in WinArch::ALL {
            for forced in [false, true] {
                let mut p = process(arch);
                let mut t = thread(&mut p, 8);
                let slot = p.tls.fls_alloc(0x1234_5678).unwrap();
                p.tls.fls_set(t.fls_key(), slot, 91).unwrap();
                let mut plan = p.tls.fls_begin_free(slot).unwrap();
                plan.set_owner(t.tid);
                assert!(plan.next().is_some());
                t.frames.push(Frame {
                    api: &APC,
                    entry_pc: t.cpu.pc(),
                    entry_sp: t.cpu.sp(),
                    ret_addr: 0,
                    cursor: t.cpu.sp(),
                    cont: Some(Box::new(move |_, _| {
                        drop(plan);
                        Flow::void()
                    })),
                    checked_call: false,
                    callback_sp: None,
                    retry: None,
                    dispatcher_setup_retries: 0,
                    exception: Vec::new(),
                    exception_caller: None,
                });
                let mut last = 0;
                let outcome = if forced {
                    Outcome::ThreadTerminate(38)
                } else {
                    Outcome::ThreadExit(38)
                };
                apply_outcome(&mut p, t, outcome, &mut last);
                assert!(
                    p.failure.is_none(),
                    "{arch}, forced={forced}: {:?}",
                    p.failure
                );
                assert!(p.threads.is_empty());
                assert_eq!(last, 38);
                assert!(p.tls.fls_take_abandoned().is_empty());
                assert_eq!(p.tls.fls_alloc(0), Ok(slot));
            }
        }
    }

    #[test]
    fn nonterminal_fls_escape_reports_receipt_before_more_guest_execution_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let t = thread(&mut p, 8);
            let slot = p.tls.fls_alloc(0x1234_5678).unwrap();
            p.tls.fls_set(t.fls_key(), slot, 91).unwrap();
            let mut plan = p.tls.fls_begin_free(slot).unwrap();
            plan.set_owner(t.tid);
            assert!(plan.next().is_some());
            drop(plan);
            apply_outcome(&mut p, t, Outcome::Continue, &mut 0);
            assert!(
                p.failure
                    .as_ref()
                    .is_some_and(|m| m.contains("FLS continuation abandoned"))
            );
        }
    }

    #[test]
    fn unhandled_cpu_exceptions_preserve_guest_status() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            let stop = match arch {
                WinArch::Arm64 => CpuStop::Undefined {
                    pc: t.cpu.pc(),
                    reason: "reserved encoding".into(),
                },
                _ => CpuStop::X86Event(X86UserEvent {
                    vector: 6,
                    error_code: None,
                    source: X86EventSource::Exception,
                    insn_rip: t.cpu.pc(),
                    return_rip: t.cpu.pc(),
                }),
            };
            assert_eq!(
                handle_stop(&mut p, &mut t, stop),
                Outcome::ProcessTerminate(STATUS_ILLEGAL_INSTRUCTION)
            );
            let pc = t.cpu.pc();
            assert_eq!(
                access_fault(
                    &mut p,
                    &mut t,
                    AccessFault {
                        addr: 0xDEAD_0000,
                        access: MemoryAccessKind::Fetch,
                        kind: AccessFaultKind::Unmapped,
                        pc
                    }
                ),
                Outcome::ProcessTerminate(STATUS_ACCESS_VIOLATION)
            );
        }
    }

    #[test]
    fn ordinary_and_stack_guards_are_consumed_before_exception_dispatch() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            let (guard, _) =
                p.vm.allocate(
                    None,
                    PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE | prot::GUARD,
                )
                .unwrap();
            let pc = t.cpu.pc();
            let outcome = access_fault(
                &mut p,
                &mut t,
                AccessFault {
                    addr: guard,
                    access: MemoryAccessKind::Write,
                    kind: AccessFaultKind::Permission,
                    pc,
                },
            );
            assert_eq!(
                outcome,
                Outcome::ProcessTerminate(STATUS_GUARD_PAGE_VIOLATION)
            );
            assert_eq!(p.vm.query(guard).unwrap().protect, prot::READWRITE);
            p.vm.protect(t.stack_alloc, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            t.stack_limit = t.stack_alloc + PAGE_SIZE;
            let addr = t.stack_alloc;
            assert_eq!(
                access_fault(
                    &mut p,
                    &mut t,
                    AccessFault {
                        addr,
                        access: MemoryAccessKind::Read,
                        kind: AccessFaultKind::Permission,
                        pc
                    }
                ),
                Outcome::ProcessTerminate(STATUS_STACK_OVERFLOW)
            );
        }
    }

    #[test]
    fn exhausted_stack_guard_dispatches_veh_on_consumed_emergency_page_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            let bottom = t.stack_alloc;
            let emergency = bottom + PAGE_SIZE;
            let limit = bottom + 2 * PAGE_SIZE;
            p.vm.decommit(bottom, PAGE_SIZE).unwrap();
            p.vm.protect(emergency, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            t.stack_limit = limit;
            p.space
                .wptr(
                    t.teb + crate::user::windows::layout::offsets(arch).teb_stack_limit,
                    arch.ptr_size(),
                    limit,
                )
                .unwrap();
            t.cpu.set_sp(limit);
            let fault_pc = t.cpu.pc();
            let fault_addr = limit - arch.ptr_size();
            let handler = 0x2345_0000;
            p.seh.veh.push((1, handler));
            assert_eq!(
                access_fault(
                    &mut p,
                    &mut t,
                    AccessFault {
                        addr: fault_addr,
                        access: MemoryAccessKind::Write,
                        kind: AccessFaultKind::Permission,
                        pc: fault_pc,
                    }
                ),
                Outcome::Continue,
                "{arch}: consumed emergency page must permit exception dispatch"
            );
            assert_eq!(t.cpu.pc(), handler);
            assert_eq!(p.vm.query(bottom).unwrap().state, mem::RESERVE);
            assert_eq!(p.vm.query(emergency).unwrap().protect, prot::READWRITE);
            let pointers = match arch {
                WinArch::X86 => p.space.ptr(t.cpu.sp() + 4, 4).unwrap(),
                WinArch::X64 => t.cpu.gpr(1),
                WinArch::Arm64 => t.cpu.gpr(0),
            };
            let record_addr = p.space.ptr(pointers, arch.ptr_size()).unwrap();
            let context_addr = p
                .space
                .ptr(pointers + arch.ptr_size(), arch.ptr_size())
                .unwrap();
            let record = ExceptionRecord::read(&p.space, arch, record_addr).unwrap();
            let context = RegContext::read(&p.space, arch, context_addr).unwrap();
            assert_eq!(record.code, STATUS_STACK_OVERFLOW);
            assert_eq!(record.address, fault_pc);
            assert_eq!(record.params, vec![1, fault_addr]);
            assert_eq!(context.pc(), fault_pc);
            assert_eq!(context.sp(), limit);
            assert!(record_addr >= emergency && context_addr >= emergency);
            // Model the handler's ordinary EXCEPTION_CONTINUE_EXECUTION return.
            t.cpu.set_gpr(0, arch.ptr(u64::MAX));
            assert_eq!(dispatch::callback_return(&mut p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.pc(), fault_pc);
            assert_eq!(t.cpu.sp(), limit);
            assert!(t.frames.is_empty());
            assert!(p.failure.is_none());
        }
    }

    #[test]
    fn hle_fetch_traps_require_live_committed_executable_guest_state() {
        let mut p = process(WinArch::X64);
        let mut t = thread(&mut p, 8);
        let at =
            p.vm.reserve(
                None,
                PAGE_SIZE,
                prot::EXECUTE_READ,
                crate::user::windows::memory::AllocKind::Image,
                false,
                None,
            )
            .unwrap();
        p.vm.commit(at, PAGE_SIZE, prot::READONLY).unwrap();
        p.vm.set_reported(at, PAGE_SIZE, prot::EXECUTE_READ);
        p.traps.add(
            at,
            vec![crate::user::windows::traps::SlotKind::Missing(Arc::from(
                "test.dll!Absent",
            ))],
            1,
        );
        let f = AccessFault {
            addr: at,
            access: MemoryAccessKind::Fetch,
            kind: AccessFaultKind::Permission,
            pc: at,
        };
        assert!(
            matches!(access_fault(&mut p, &mut t, f), Outcome::Fail(reason) if reason.contains("test.dll!Absent"))
        );
        p.vm.protect(at, PAGE_SIZE, prot::NOACCESS).unwrap();
        assert_eq!(
            access_fault(&mut p, &mut t, f),
            Outcome::ProcessTerminate(STATUS_ACCESS_VIOLATION)
        );
        p.vm.decommit(at, PAGE_SIZE).unwrap();
        let f = AccessFault {
            kind: AccessFaultKind::Unmapped,
            ..f
        };
        assert_eq!(
            access_fault(&mut p, &mut t, f),
            Outcome::ProcessTerminate(STATUS_ACCESS_VIOLATION)
        );
    }

    #[test]
    fn private_dispatcher_retry_fetch_requires_an_owned_checked_call() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            let at =
                p.vm.reserve(
                    None,
                    PAGE_SIZE,
                    prot::EXECUTE_READ,
                    crate::user::windows::memory::AllocKind::Image,
                    false,
                    None,
                )
                .unwrap();
            p.vm.commit(at, PAGE_SIZE, prot::READONLY).unwrap();
            p.vm.set_reported(at, PAGE_SIZE, prot::EXECUTE_READ);
            p.traps.add(
                at,
                vec![crate::user::windows::traps::SlotKind::DispatcherRetry],
                1,
            );
            t.cpu.set_pc(at);
            let f = AccessFault {
                addr: at,
                access: MemoryAccessKind::Fetch,
                kind: AccessFaultKind::Permission,
                pc: at,
            };
            assert!(
                matches!(access_fault(&mut p, &mut t, f), Outcome::Fail(reason)
                if reason.contains("no matching checked callback"))
            );
            assert!(t.frames.is_empty());
        }
    }

    #[test]
    fn apcs_deliver_fifo_and_restore_interrupted_context() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            let pc = t.cpu.pc();
            let sp = t.cpu.sp();
            t.cpu.set_gpr(3, 0xCC55);
            t.apcs.extend([(0x50000, 0x1111), (0x50100, 0x2222)]);
            assert_eq!(
                begin_apcs(&mut p, &mut t, Some(sync::WAIT_IO_COMPLETION)),
                Outcome::Continue
            );
            assert_eq!(t.cpu.pc(), 0x50000);
            assert_eq!(t.apcs.len(), 1);
            assert_eq!(dispatch::callback_return(&mut p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.pc(), 0x50100);
            assert!(t.apcs.is_empty());
            assert_eq!(dispatch::callback_return(&mut p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.pc(), pc);
            assert_eq!(t.cpu.sp(), sp);
            assert_eq!(t.cpu.gpr(3), 0xCC55);
            assert_eq!(t.wait_status, Some(sync::WAIT_IO_COMPLETION));
            assert!(t.frames.is_empty());
        }
    }

    #[test]
    fn apc_restoration_preserves_same_height_wait_parent_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch);
            let mut t = thread(&mut p, 8);
            let pc = t.cpu.pc();
            let sp = t.cpu.sp();
            park(
                &mut t,
                sync::Wait::Sleep {
                    deadline: None,
                    alertable: true,
                },
            );
            t.state = ThreadState::Ready;
            t.apcs.push_back((0x50000, 0x1111));
            assert_eq!(
                begin_apcs(&mut p, &mut t, Some(sync::WAIT_IO_COMPLETION)),
                Outcome::Continue
            );
            assert_eq!(t.frames.len(), 2);
            assert_eq!(dispatch::callback_return(&mut p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.pc(), pc);
            assert_eq!(t.cpu.sp(), sp);
            assert_eq!(
                t.frames.len(),
                1,
                "APC return must not abandon the interrupted wait"
            );
            assert!(!t.frames[0].checked_call);
            assert!(t.frames[0].cont.is_some());
            let status = t.wait_status.take().unwrap();
            assert_eq!(status, sync::WAIT_IO_COMPLETION);
            assert_eq!(
                dispatch::wait_complete(&mut p, &mut t, status),
                Outcome::ThreadExit(status as u32)
            );
            assert!(t.frames.is_empty());
        }
    }
}
