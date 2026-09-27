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
            signal_process_exit(p, code);
            return ExitStatus::Exited(code);
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
                    sync::on_cancel(p, tid, wait);
                }
                Outcome::ThreadExit(code)
            } else if let ThreadState::Exited(code) = t.state {
                Outcome::ThreadExit(code)
            } else if t.suspend == 0 {
                if let ThreadState::Waiting(wait) = &t.state {
                    let wait = wait.clone();
                    match sync::poll(p, tid, &wait, now, !t.apcs.is_empty()) {
                        Some(status) => {
                            t.state = ThreadState::Ready;
                            if status == sync::WAIT_IO_COMPLETION && !t.apcs.is_empty() {
                                begin_apcs(p, &mut t, Some(status))
                            } else {
                                dispatch::wait_complete(p, &mut t, status)
                            }
                        }
                        None => Outcome::Park,
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

fn signal_process_exit(p: &mut Proc, code: u32) {
    for (_, object) in p.objects.iter_mut() {
        if let Object::Process { pid, exit_code } = object
            && *pid == p.pid
        {
            *exit_code = Some(code);
        }
    }
}

fn apply_outcome(p: &mut Proc, t: Thread, outcome: Outcome, last_exit: &mut u32) {
    match outcome {
        Outcome::ThreadExit(code) => {
            *last_exit = code;
            thread::destroy(p, t, code);
        }
        Outcome::ProcessExit(code) => {
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

/// Startup notifications execute with the loader serialization contract:
/// while one thread is in its initializer continuations, another thread
/// cannot begin DLL initialization. The main process initializer precedes
/// a created thread's entry point.
fn select(p: &Proc, previous: u32) -> Option<u32> {
    let owner = p
        .threads
        .values()
        .find(|t| !t.attached && t.frames.iter().any(|f| f.api.name == "RtlUserThreadStart"));
    if let Some(owner) = owner {
        return owner.runnable().then_some(owner.tid);
    }
    if let Some(main) = p.threads.values().find(|t| t.main && !t.attached) {
        return main.runnable().then_some(main.tid);
    }
    p.threads
        .range((
            std::ops::Bound::Excluded(previous),
            std::ops::Bound::Unbounded,
        ))
        .chain(p.threads.range(..=previous))
        .find_map(|(&tid, t)| t.runnable().then_some(tid))
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
    // Objects exposes a mutable iterator but no immutable one; timer state
    // is polled every millisecond even when no thread deadline is known.
    thread_deadline
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
            process_heap: 0,
            modules: Default::default(),
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
        }
    }

    fn thread(p: &mut Proc, tid: u32) -> Thread {
        let (stack, size) =
            p.vm.allocate(None, 0x10000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap();
        let (teb, _) =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
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
        });
        t.state = ThreadState::Waiting(wait);
    }

    #[test]
    fn access_violation_parameters_distinguish_read_write_and_dep() {
        assert_eq!(access_parameter(MemoryAccessKind::Read), 0);
        assert_eq!(access_parameter(MemoryAccessKind::Write), 1);
        assert_eq!(access_parameter(MemoryAccessKind::Fetch), 8);
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
    fn round_robin_selection_excludes_suspended_and_blocked_threads() {
        let mut p = process(WinArch::X64);
        let t1 = thread(&mut p, 8);
        let t2 = thread(&mut p, 12);
        p.threads.insert(8, t1);
        p.threads.insert(12, t2);
        assert_eq!(select(&p, 0), Some(8));
        assert_eq!(select(&p, 8), Some(12));
        assert_eq!(select(&p, 12), Some(8));
        p.threads.get_mut(&8).unwrap().suspend = 1;
        assert_eq!(select(&p, 12), Some(12));
        p.threads.get_mut(&12).unwrap().state = ThreadState::Waiting(sync::Wait::Sleep {
            deadline: None,
            alertable: false,
        });
        assert_eq!(select(&p, 12), None);
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
        p.threads.insert(8, t);
        assert_eq!(run(&mut p), ExitStatus::Exited(0));
        assert!(matches!(
            p.objects.obj(obj),
            Some(Object::Timer {
                signaled: false,
                due: None,
                ..
            })
        ));
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
        assert_eq!(run(&mut p), ExitStatus::Exited(37));
        assert!(matches!(
            p.objects.obj(obj),
            Some(Object::Thread {
                exit_code: Some(37),
                ..
            })
        ));
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
                Outcome::ProcessExit(STATUS_ILLEGAL_INSTRUCTION)
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
                Outcome::ProcessExit(STATUS_ACCESS_VIOLATION)
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
            assert_eq!(outcome, Outcome::ProcessExit(STATUS_GUARD_PAGE_VIOLATION));
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
                Outcome::ProcessExit(STATUS_STACK_OVERFLOW)
            );
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
            Outcome::ProcessExit(STATUS_ACCESS_VIOLATION)
        );
        p.vm.decommit(at, PAGE_SIZE).unwrap();
        let f = AccessFault {
            kind: AccessFaultKind::Unmapped,
            ..f
        };
        assert_eq!(
            access_fault(&mut p, &mut t, f),
            Outcome::ProcessExit(STATUS_ACCESS_VIOLATION)
        );
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
}
