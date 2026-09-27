//! Mach traps.

pub mod guard;
pub mod kmsg;
pub mod msg;
pub mod port;
pub mod reclaim;
pub mod sync;
pub mod timer;
pub mod vm;
pub mod voucher;

use std::sync::Arc;

use crate::user::darwin::abi::{self, DarwinAbi, tables::trap};
use crate::user::darwin::arch::ARM64_COUNTER_HZ;
use crate::user::darwin::commpage;
use crate::user::darwin::mach::ipc::{KObject, MACH_PORT_NULL, PortName};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::process::{Proc, Thread};
use crate::user::darwin::syscall::Ctx;

/// `mach_absolute_time` for `abi`: nanoseconds on Intel, 24 MHz ticks on
/// Apple silicon, from the emulator's clock epoch (the same clock the
/// commpage and the CPU counters use).
pub fn absolute_time(abi: DarwinAbi) -> u64 {
    let ns = crate::vm::timing::elapsed_nanos();
    match abi {
        DarwinAbi::X86_64 => ns,
        DarwinAbi::Arm64 => (u128::from(ns) * u128::from(ARM64_COUNTER_HZ) / 1_000_000_000) as u64,
    }
}

/// Runs Mach trap `nr`.
pub fn trap(proc: &mut Proc, thread: &mut Thread, nr: u32) {
    let info = abi::mach_trap(nr).expect("dispatched traps exist");
    let args = match thread.cpu.mach_args(info.nargs as usize) {
        Ok(a) => a,
        Err(_) => {
            thread.cpu.set_mach_result(kr::KERN_INVALID_ARGUMENT);
            return;
        }
    };
    let pc = thread.cpu.pc();
    proc.task.syscalls.0 += 1;
    // A restarted trap keeps its progress only if it is the same trap at
    // the same place.
    if thread
        .resume
        .is_some_and(|r| r.pc != pc || r.call != -i64::from(nr))
    {
        thread.resume = None;
    }
    let mut ctx = Ctx {
        proc,
        thread,
        nr: -i64::from(nr),
        pc,
    };
    let r = call(&mut ctx, nr, &args);
    if ctx.proc.config.strace {
        let a: Vec<String> = args[..info.nargs as usize]
            .iter()
            .map(|v| super::util::fmt_arg(*v))
            .collect();
        eprintln!(
            "[{:#x}] {}({}) = {:#x}",
            ctx.thread.tid,
            info.name,
            a.join(", "),
            r
        );
    }
    kmsg::flush(ctx.proc);
    match r {
        JUST_RETURN => {}
        RESTART => ctx.thread.cpu.restart_syscall(),
        r => {
            ctx.thread.resume = None;
            ctx.thread.cpu.set_mach_result(r);
        }
    }
}

/// A handler result meaning "registers already set".
pub const JUST_RETURN: KernReturn = i32::MIN;

/// A handler result meaning "the thread sleeps; run the trap again when it
/// wakes" (the handler registered the wait with [`sleep`]).
pub const RESTART: KernReturn = i32::MIN + 1;

/// Parks the running thread on `wait` for a Mach trap; `KERN_ABORTED`
/// (the wait's `THREAD_INTERRUPTED`) without parking when a signal is
/// deliverable.
pub fn sleep(ctx: &mut Ctx<'_>, wait: crate::user::darwin::wait::Wait) -> KernReturn {
    let r = crate::user::darwin::syscall::sleep(ctx, wait);
    if crate::user::darwin::syscall::interrupted(ctx, &r) {
        return kr::KERN_ABORTED;
    }
    RESTART
}

/// Traps whose first argument names the target task
/// (`port_name_to_current_task_noref`): only the caller's own task port
/// is accepted, as on macOS for everything but `mach_vm_*` on a
/// debugger-held task.
fn targets_task(nr: u32) -> bool {
    matches!(
        nr,
        trap::KERNELRPC_MACH_VM_ALLOCATE_TRAP
            | trap::KERNELRPC_MACH_VM_DEALLOCATE_TRAP
            | trap::KERNELRPC_MACH_VM_PROTECT_TRAP
            | trap::KERNELRPC_MACH_VM_MAP_TRAP
            | trap::KERNELRPC_MACH_PORT_ALLOCATE_TRAP
            | trap::KERNELRPC_MACH_PORT_DEALLOCATE_TRAP
            | trap::KERNELRPC_MACH_PORT_MOD_REFS_TRAP
            | trap::KERNELRPC_MACH_PORT_MOVE_MEMBER_TRAP
            | trap::KERNELRPC_MACH_PORT_INSERT_RIGHT_TRAP
            | trap::KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP
            | trap::KERNELRPC_MACH_PORT_EXTRACT_MEMBER_TRAP
            | trap::KERNELRPC_MACH_PORT_CONSTRUCT_TRAP
            | trap::KERNELRPC_MACH_PORT_DESTRUCT_TRAP
            | trap::KERNELRPC_MACH_PORT_GET_ATTRIBUTES_TRAP
            | trap::KERNELRPC_MACH_PORT_GUARD_TRAP
            | trap::KERNELRPC_MACH_PORT_UNGUARD_TRAP
            | trap::KERNELRPC_MACH_PORT_TYPE_TRAP
            | trap::KERNELRPC_MACH_PORT_REQUEST_NOTIFICATION_TRAP
            | trap::MACH_VM_RECLAIM_UPDATE_KERNEL_ACCOUNTING_TRAP
    )
}

/// A result written to user memory by a trap: `mach_copyout` failures
/// become `KERN_MEMORY_ERROR`.
fn out32(ctx: &Ctx<'_>, addr: u64, v: u32) -> KernReturn {
    match ctx.write_u32(addr, v) {
        Ok(()) => kr::KERN_SUCCESS,
        Err(_) => kr::KERN_MEMORY_ERROR,
    }
}

fn call(ctx: &mut Ctx<'_>, nr: u32, a: &[u64; 9]) -> KernReturn {
    if targets_task(nr) && !port::is_self_task(ctx.proc, a[0] as PortName) {
        return kr::MACH_SEND_INVALID_DEST;
    }
    let name = |i: usize| a[i] as PortName;
    match nr {
        trap::KERNELRPC_MACH_VM_ALLOCATE_TRAP => vm::allocate(ctx, a[1], a[2], a[3] as u32),
        trap::KERNELRPC_MACH_VM_DEALLOCATE_TRAP => vm::deallocate(ctx, a[1], a[2]),
        trap::MACH_VM_RECLAIM_UPDATE_KERNEL_ACCOUNTING_TRAP => {
            reclaim::update_accounting_trap(ctx, a[1], a[2])
        }
        trap::KERNELRPC_MACH_VM_PROTECT_TRAP => {
            vm::protect(ctx, a[1], a[2], a[3] as u32 != 0, a[4] as u32)
        }
        trap::KERNELRPC_MACH_VM_MAP_TRAP => {
            vm::map(ctx, a[1], a[2], a[3], a[4] as u32, a[5] as u32)
        }
        trap::KERNELRPC_MACH_PORT_ALLOCATE_TRAP => match port::allocate(ctx.proc, a[1] as u32) {
            Ok(n) => out32(ctx, a[2], n),
            Err(k) => k,
        },
        trap::KERNELRPC_MACH_PORT_DEALLOCATE_TRAP => port::deallocate(ctx.proc, name(1)),
        trap::KERNELRPC_MACH_PORT_MOD_REFS_TRAP => {
            port::mod_refs(ctx.proc, name(1), a[2] as u32, a[3] as i32)
        }
        trap::KERNELRPC_MACH_PORT_MOVE_MEMBER_TRAP => port::move_member(ctx.proc, name(1), name(2)),
        trap::KERNELRPC_MACH_PORT_INSERT_RIGHT_TRAP => {
            // The disposition must be a port right (MACH_MSG_TYPE_PORT_ANY_RIGHT
            // is checked after the copy-in, as mach_port_insert_right does).
            port::insert_right_trap(ctx.proc, name(1), name(2), a[3] as u32)
        }
        trap::KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP => {
            port::insert_member(ctx.proc, name(1), name(2))
        }
        trap::KERNELRPC_MACH_PORT_EXTRACT_MEMBER_TRAP => {
            port::extract_member(ctx.proc, name(1), name(2))
        }
        trap::KERNELRPC_MACH_PORT_CONSTRUCT_TRAP => {
            let Ok(opts) = ctx.read(a[1], port::OPTIONS_SIZE) else {
                return kr::KERN_MEMORY_ERROR;
            };
            match port::construct(ctx.proc, &opts, a[2]) {
                Ok(n) => out32(ctx, a[3], n),
                Err(k) => k,
            }
        }
        trap::KERNELRPC_MACH_PORT_DESTRUCT_TRAP => {
            port::destruct(ctx.proc, name(1), a[2] as i32, a[3])
        }
        trap::KERNELRPC_MACH_PORT_GET_ATTRIBUTES_TRAP => {
            let Ok(count) = ctx.read_u32(a[4]) else {
                return kr::KERN_MEMORY_ERROR;
            };
            match port::get_attributes(ctx.proc, name(1), a[2] as i32, count.min(17)) {
                Ok(words) => {
                    let r = out32(ctx, a[4], words.len() as u32);
                    if r != kr::KERN_SUCCESS || words.is_empty() {
                        return r;
                    }
                    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
                    match ctx.write(a[3], &b) {
                        Ok(()) => kr::KERN_SUCCESS,
                        Err(_) => kr::KERN_MEMORY_ERROR,
                    }
                }
                Err(k) => k,
            }
        }
        trap::KERNELRPC_MACH_PORT_GUARD_TRAP => {
            port::guard(ctx.proc, name(1), a[2], a[3] as u32 != 0)
        }
        trap::KERNELRPC_MACH_PORT_UNGUARD_TRAP => port::unguard(ctx.proc, name(1), a[2]),
        trap::KERNELRPC_MACH_PORT_TYPE_TRAP => match port::port_type(ctx.proc, name(1)) {
            Ok(t) => out32(ctx, a[2], t),
            Err(k) => k,
        },
        trap::KERNELRPC_MACH_PORT_REQUEST_NOTIFICATION_TRAP => request_notification_trap(ctx, a),
        trap::MACH_MSG2_TRAP => msg::msg2(ctx, a),
        trap::MACH_MSG_TRAP => msg::overwrite(ctx, a, false),
        trap::MACH_MSG_OVERWRITE_TRAP => msg::overwrite(ctx, a, true),
        trap::SEMAPHORE_SIGNAL_TRAP => sync::signal(ctx, name(0), false),
        trap::SEMAPHORE_SIGNAL_ALL_TRAP => sync::signal(ctx, name(0), true),
        trap::SEMAPHORE_SIGNAL_THREAD_TRAP => sync::signal_thread(ctx, name(0), name(1)),
        trap::SEMAPHORE_WAIT_TRAP => sync::wait(ctx, name(0), MACH_PORT_NULL, None),
        trap::SEMAPHORE_WAIT_SIGNAL_TRAP => sync::wait(ctx, name(0), name(1), None),
        trap::SEMAPHORE_TIMEDWAIT_TRAP => sync::wait(
            ctx,
            name(0),
            MACH_PORT_NULL,
            Some((a[1] as u32, a[2] as u32)),
        ),
        trap::SEMAPHORE_TIMEDWAIT_SIGNAL_TRAP => {
            sync::wait(ctx, name(0), name(1), Some((a[2] as u32, a[3] as u32)))
        }
        trap::MACH_REPLY_PORT => match ctx.proc.ipc.alloc_receive() {
            Ok((name, _)) => name as KernReturn,
            Err(_) => MACH_PORT_NULL as KernReturn,
        },
        trap::THREAD_GET_SPECIAL_REPLY_PORT => {
            // The thread's special reply port: a fresh receive right each
            // call, as XNU replaces the previous one.
            match ctx.proc.ipc.alloc_receive() {
                Ok((name, _)) => name as KernReturn,
                Err(_) => MACH_PORT_NULL as KernReturn,
            }
        }
        trap::THREAD_SELF_TRAP => {
            let port = ctx.thread.kport.clone();
            ctx.proc.insert_send(&port) as KernReturn
        }
        trap::TASK_SELF_TRAP => {
            // The task's pinned control port name is stable: the space
            // already holds a send right to it.
            let port = ctx.proc.task_port.clone();
            match ctx.proc.ipc.name_of(&port) {
                Some(name) => name as KernReturn,
                None => ctx.proc.insert_send(&port) as KernReturn,
            }
        }
        trap::HOST_SELF_TRAP => {
            let port = ctx.proc.host_port.clone();
            ctx.proc.insert_send(&port) as KernReturn
        }
        trap::PID_FOR_TASK => {
            // Any flavor of the caller's own task port names this process;
            // the copy-out's failure is ignored.
            let ok = ctx
                .proc
                .ipc
                .lookup(name(0))
                .ok()
                .filter(|e| e.send > 0)
                .and_then(|e| e.port().cloned())
                .is_some_and(|p| {
                    Arc::ptr_eq(&p, &ctx.proc.task_port)
                        || matches!(
                            p.kobject,
                            KObject::TaskName | KObject::TaskRead | KObject::TaskInspect
                        )
                });
            let (k, pid) = if ok {
                (kr::KERN_SUCCESS, ctx.proc.pid)
            } else {
                (kr::KERN_FAILURE, -1)
            };
            let _ = ctx.write_u32(a[1], pid as u32);
            k
        }
        trap::TASK_FOR_PID | trap::TASK_NAME_FOR_PID => {
            // The caller's own pid yields its task (or name) port; other
            // pids are refused as for an unentitled process. MACH_PORT_NULL
            // is stored on failure; copy-out failures are ignored.
            let pid = a[1] as i32;
            if pid == 0 || pid != ctx.proc.pid || !port::is_self_task(ctx.proc, name(0)) {
                let _ = ctx.write_u32(a[2], MACH_PORT_NULL);
                return kr::KERN_FAILURE;
            }
            let port = if nr == trap::TASK_FOR_PID {
                ctx.proc.task_port.clone()
            } else {
                ctx.proc
                    .task
                    .name_port
                    .get_or_insert_with(|| {
                        crate::user::darwin::mach::ipc::Port::new(KObject::TaskName)
                    })
                    .clone()
            };
            let n = ctx.proc.insert_send(&port);
            let _ = ctx.write_u32(a[2], n);
            kr::KERN_SUCCESS
        }
        // Every trap ends the thread's slice and the scheduler runs the
        // next runnable thread, so these yield by returning.
        trap::SWTCH_PRI | trap::SWTCH => {
            // Whether other threads could run (the running thread is out of
            // the table while it runs).
            KernReturn::from(ctx.proc.threads.values().any(|t| t.runnable()))
        }
        trap::THREAD_SWITCH => kr::KERN_SUCCESS,
        trap::MACH_TIMEBASE_INFO_TRAP => {
            // The copy-out's failure is ignored.
            let (numer, denom) = commpage::timebase(ctx.proc.abi);
            let mut b = [0u8; 8];
            b[..4].copy_from_slice(&numer.to_le_bytes());
            b[4..].copy_from_slice(&denom.to_le_bytes());
            let _ = ctx.write(a[0], &b);
            kr::KERN_SUCCESS
        }
        trap::MACH_WAIT_UNTIL_TRAP => wait_until(ctx, a[0]),
        trap::HOST_CREATE_MACH_VOUCHER_TRAP => {
            voucher::host_create(ctx, name(0), a[1], a[2] as i32, a[3])
        }
        trap::MACH_VOUCHER_EXTRACT_ATTR_RECIPE_TRAP => {
            voucher::extract_recipe(ctx, name(0), a[1] as u32, a[2], a[3])
        }
        trap::MACH_GENERATE_ACTIVITY_ID => voucher::generate_activity_id(ctx, a[1] as i32, a[2]),
        trap::MK_TIMER_CREATE_TRAP => timer::create(ctx),
        trap::MK_TIMER_DESTROY_TRAP => timer::destroy(ctx, name(0)),
        trap::MK_TIMER_ARM_TRAP => timer::arm(ctx, name(0), 0, a[1], 0),
        trap::MK_TIMER_ARM_LEEWAY_TRAP => timer::arm(ctx, name(0), a[1], a[2], a[3]),
        trap::MK_TIMER_CANCEL_TRAP => timer::cancel(ctx, name(0), a[1]),
        _ => {
            if ctx.proc.config.strace || std::env::var_os("RAX_DARWIN_WARN").is_some() {
                eprintln!(
                    "rax-user: unimplemented Mach trap {nr} ({})",
                    abi::mach_trap(nr).map_or("?", |t| t.name)
                );
            }
            kr::KERN_FAILURE
        }
    }
}

/// `_kernelrpc_mach_port_request_notification_trap(target, name, msgid,
/// sync, notify, notifyPoly, previous)`.
fn request_notification_trap(ctx: &mut Ctx<'_>, a: &[u64; 9]) -> KernReturn {
    use crate::user::darwin::mach::ipc::{MACH_PORT_DEAD, Right, disp};
    let (name, id, sync, notify, poly) = (
        a[1] as PortName,
        a[2] as i32,
        a[3] as u32,
        a[4] as PortName,
        a[5] as u32,
    );
    if disp::copyin_type(poly) != disp::MOVE_SEND_ONCE {
        return kr::MACH_SEND_INVALID_DEST;
    }
    let right = if notify != MACH_PORT_NULL && notify != MACH_PORT_DEAD {
        match ctx.proc.ipc.copyin(notify, poly) {
            Ok(r) => Some(r),
            Err(k) => return k,
        }
    } else if notify == MACH_PORT_DEAD {
        Some(Right::Dead)
    } else {
        None
    };
    match port::request_notification(ctx.proc, name, id, sync, right) {
        Ok(previous) => {
            let prev_name = match previous {
                None => MACH_PORT_NULL,
                Some(r) => match ctx.proc.ipc.insert(r) {
                    Ok(n) => n,
                    Err(_) => return kr::MACH_MSG_IPC_SPACE,
                },
            };
            out32(ctx, a[6], prev_name)
        }
        Err(k) => k,
    }
}

/// The time from now until absolute time `deadline` of `abi`, rounded up
/// to whole nanoseconds so that a sleep of that length reaches the
/// deadline.
pub fn until_absolute(abi: DarwinAbi, deadline: u64) -> std::time::Duration {
    let now = absolute_time(abi);
    let ticks = deadline.saturating_sub(now);
    let ns = match abi {
        DarwinAbi::X86_64 => ticks,
        DarwinAbi::Arm64 => {
            let hz = u128::from(ARM64_COUNTER_HZ);
            ((u128::from(ticks) * 1_000_000_000).div_ceil(hz)).min(u128::from(u64::MAX)) as u64
        }
    };
    std::time::Duration::from_nanos(ns)
}

/// `mach_wait_until(deadline)`: sleeps until absolute time `deadline`;
/// `KERN_ABORTED` when a signal ends the wait early.
fn wait_until(ctx: &mut Ctx<'_>, deadline: u64) -> KernReturn {
    use crate::user::darwin::wait::Wait;
    let remaining = until_absolute(ctx.proc.abi, deadline);
    if remaining.is_zero() {
        return kr::KERN_SUCCESS;
    }
    if ctx.thread.resume.is_some() {
        // Re-executed before the deadline: only a signal wakes this wait.
        return kr::KERN_ABORTED;
    }
    sleep(
        ctx,
        Wait::until(Some(std::time::Instant::now() + remaining)),
    )
}
