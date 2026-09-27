//! The task subsystem (`task.defs`, `osfmk/kern/task.c`, `ipc_tt.c`,
//! `sync_sema.c`) and task restartable ranges (`restartable.defs`,
//! `osfmk/kern/restartable.c`) for the calling task.

use std::sync::Arc;

use super::exception;
use super::{
    Buf, MigResult, Out, OutDesc, Req, copy_send, ids, info_reply, is_task, make_send, null_port,
};
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::mach::exception::{EXC_MASK_VALID, Handler};
use crate::user::darwin::mach::ipc::{KObject, Port, Right, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::sync::Semaphore;
use crate::user::darwin::mach::task::{PORT_REGISTER_MAX, RestartableRange, special};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::mach::kmsg;

/// `task_info` flavors (`osfmk/mach/task_info.h`).
mod flavor {
    pub const ABSOLUTETIME_INFO: i32 = 1;
    pub const EVENTS_INFO: i32 = 2;
    pub const THREAD_TIMES_INFO: i32 = 3;
    pub const BASIC_INFO_32: i32 = 4;
    pub const BASIC_INFO_64: i32 = 5;
    pub const BASIC2_INFO_32: i32 = 6;
    pub const KERNELMEMORY_INFO: i32 = 7;
    pub const SCHED_FIFO_INFO: i32 = 10;
    pub const SCHED_RR_INFO: i32 = 11;
    pub const SCHED_TIMESHARE_INFO: i32 = 12;
    pub const SECURITY_TOKEN: i32 = 13;
    pub const SCHED_INFO: i32 = 14;
    pub const AUDIT_TOKEN: i32 = 15;
    pub const AFFINITY_TAG_INFO: i32 = 16;
    pub const DYLD_INFO: i32 = 17;
    pub const BASIC_INFO_64_2: i32 = 18;
    pub const EXTMOD_INFO: i32 = 19;
    pub const MACH_TASK_BASIC_INFO: i32 = 20;
    pub const POWER_INFO: i32 = 21;
    pub const VM_INFO: i32 = 22;
    pub const VM_INFO_PURGEABLE: i32 = 23;
    pub const POWER_INFO_V2: i32 = 26;
    pub const FLAGS_INFO: i32 = 28;
}

/// `POLICY_TIMESHARE`.
const POLICY_TIMESHARE: u32 = 1;
/// `BASEPRI_DEFAULT`: a user task's base priority.
const BASEPRI_DEFAULT: u32 = 31;
/// `KERN_INVALID_POLICY`.
const KERN_INVALID_POLICY: KernReturn = 16;
/// `KERN_DENIED`.
const KERN_DENIED: KernReturn = kr::KERN_DENIED;

/// Serves the task and task-restartable subsystems.
pub fn serve(ctx: &mut Ctx<'_>, req: &mut Req) -> MigResult {
    use ids::task as t;
    let task = is_task(ctx, req);
    let readable = task
        || matches!(
            req.port.kobject,
            KObject::TaskRead | KObject::TaskInspect | KObject::TaskName
        );
    match req.id {
        t::TASK_INFO => {
            req.simple(40)?;
            if !readable {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let count = req.u32(36).min(94);
            Ok(info_reply(&task_info(ctx, req.i32(32), count)?))
        }
        t::TASK_GET_SPECIAL_PORT => {
            req.simple(36)?;
            if !readable {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let port = get_special_port(ctx, &req.port.kobject, req.i32(32))?;
            Ok(Out::Complex(vec![port], Vec::new()))
        }
        t::TASK_SET_SPECIAL_PORT => {
            req.complex_of(1, 52)?;
            let right = req.take_port(28, &[disp::MOVE_SEND, disp::MOVE_SEND_ONCE])?;
            if !task {
                kmsg::release(ctx.proc, right);
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            set_special_port(ctx.proc, req.i32(48), right)?;
            Ok(Out::Simple(Vec::new()))
        }
        t::KERNELRPC_MACH_PORTS_REGISTER3 => {
            req.complex_of(3, 64)?;
            let mut rights = Vec::with_capacity(PORT_REGISTER_MAX);
            for off in [28, 40, 52] {
                match req.take_port(off, &[disp::MOVE_SEND]) {
                    Ok(r) => rights.push(r),
                    Err(e) => {
                        kmsg::release(ctx.proc, rights.into_iter().flatten());
                        return Err(e);
                    }
                }
            }
            register_ports(ctx.proc, task, rights)?;
            Ok(Out::Simple(Vec::new()))
        }
        t::KERNELRPC_MACH_PORTS_LOOKUP3 => {
            req.simple(24)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let ports = ctx.proc.task.registered.iter().map(|h| match h {
                Handler::None => null_port(),
                Handler::Dead => OutDesc::Port(Some(Right::Dead), disp::MOVE_SEND),
                Handler::Port(p) => copy_send(p),
            });
            Ok(Out::Complex(ports.collect(), Vec::new()))
        }
        t::TASK_THREADS => {
            req.simple(24)?;
            if !readable {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            // The calling thread is out of the table while it runs; the
            // list is in creation order.
            let mut ports: Vec<(u64, Arc<Port>)> = ctx
                .proc
                .threads
                .values()
                .filter(|t| !t.exited)
                .map(|t| (t.tid, t.kport.clone()))
                .collect();
            ports.push((ctx.thread.tid, ctx.thread.kport.clone()));
            ports.sort_by_key(|p| p.0);
            let rights: Vec<Option<Right>> = ports
                .iter()
                .map(|(_, p)| {
                    p.state.lock().unwrap().srights += 1;
                    Some(Right::Send(p.clone()))
                })
                .collect();
            let n = rights.len() as u32;
            Ok(Out::Complex(
                vec![OutDesc::OolPorts(rights, disp::MOVE_SEND)],
                Buf::new().u32(n).done(),
            ))
        }
        t::SEMAPHORE_CREATE => {
            req.simple(40)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let (policy, value) = (req.i32(32), req.i32(36));
            // SYNC_POLICY_USER_MASK: FIFO, LIFO, PREPOST.
            if value < 0 || policy & !0x7 != 0 {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let sem = Arc::new(Semaphore::new(policy as u32, i64::from(value)));
            let port = Port::new(KObject::Semaphore(sem));
            Ok(Out::Complex(vec![make_send(&port)], Vec::new()))
        }
        t::SEMAPHORE_DESTROY => {
            req.complex_of(1, 40)?;
            let right = req.take_port(28, &[disp::MOVE_SEND])?;
            let sem = right
                .as_ref()
                .and_then(|r| r.port())
                .and_then(|p| match &p.kobject {
                    KObject::Semaphore(s) => Some(s.clone()),
                    _ => None,
                });
            kmsg::release(ctx.proc, right);
            let Some(sem) = sem else {
                return Err(kr::KERN_INVALID_ARGUMENT);
            };
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            super::super::syscall::mach::sync::destroy(ctx.proc, &sem);
            Ok(Out::Simple(Vec::new()))
        }
        t::TASK_POLICY_SET => {
            let n = req.simple_array(40, 4, 16, 36)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let fl = req.i32(32);
            // TASK_CATEGORY_POLICY (1) records the role; the QoS and
            // suppression flavors have no effect on one-CPU scheduling.
            match fl {
                1 => {
                    if n < 1 {
                        return Err(kr::KERN_INVALID_ARGUMENT);
                    }
                    ctx.proc.task.role = req.i32(40);
                }
                3 | 8..=11 => {}
                _ => return Err(kr::KERN_INVALID_ARGUMENT),
            }
            Ok(Out::Simple(Vec::new()))
        }
        t::TASK_POLICY_GET => {
            req.simple(44)?;
            if !readable {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let fl = req.i32(32);
            let count = req.u32(36).min(16);
            let default = req.u32(40) != 0;
            let words: Vec<u32> = match fl {
                1 if count >= 1 => vec![if default {
                    0
                } else {
                    ctx.proc.task.role as u32
                }],
                // TASK_BASE/OVERRIDE_QOS_POLICY: task_latency_qos_tier,
                // task_throughput_qos_tier (LATENCY_QOS_TIER_UNSPECIFIED,
                // THROUGHPUT_QOS_TIER_UNSPECIFIED).
                8 | 9 if count >= 2 => vec![0, 0],
                10 | 11 if count >= 1 => vec![0],
                1 | 8..=11 => return Err(kr::KERN_INVALID_ARGUMENT),
                _ => return Err(kr::KERN_INVALID_ARGUMENT),
            };
            // policy_infoCnt, the array trimmed to it, then get_default.
            let mut b = Buf::new().u32(words.len() as u32);
            for w in &words {
                b = b.u32(*w);
            }
            let v = b.u32(u32::from(default)).done();
            Ok(Out::Simple(v))
        }
        t::TASK_SET_EXCEPTION_PORTS | t::TASK_SWAP_EXCEPTION_PORTS => {
            req.complex_of(1, 60)?;
            let handler = exception::take_handler(req)?;
            let (mask, behavior, flv) = (req.u32(48), req.i32(52), req.i32(56));
            let checked = if task {
                exception::validate(ctx.proc.abi, mask, &handler, behavior, flv)
            } else {
                Err(kr::KERN_INVALID_ARGUMENT)
            };
            if let Err(k) = checked {
                exception::release(ctx.proc, &handler);
                return Err(k);
            }
            let old = (req.id == t::TASK_SWAP_EXCEPTION_PORTS)
                .then(|| exception::view(&ctx.proc.task.exc, mask));
            let replaced =
                exception::install(&mut ctx.proc.task.exc, mask, &handler, behavior, flv);
            exception::release(ctx.proc, &handler);
            for p in replaced {
                kmsg::release_send(ctx.proc, &p);
            }
            match old {
                None => Ok(Out::Simple(Vec::new())),
                Some(o) => Ok(exception::ports_reply(&o)),
            }
        }
        t::TASK_CREATE_IDENTITY_TOKEN => {
            // A new token for the task, a send right to its port
            // (task_ident.c); the target is the control port.
            req.simple(24)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            Ok(Out::Complex(
                vec![make_send(&identity_token(ctx.proc))],
                Vec::new(),
            ))
        }
        t::TASK_IDENTITY_TOKEN_GET_TASK_PORT => {
            // The token's task port of a flavor: the control port, then
            // the read, inspect, and name ports. A token outlives the
            // image it names (KERN_NOT_FOUND).
            req.simple(36)?;
            let KObject::TaskIdToken(id) = req.port.kobject else {
                return Err(kr::KERN_INVALID_ARGUMENT);
            };
            let which = match req.i32(32) {
                0 => special::KERNEL,
                1 => special::READ,
                2 => special::INSPECT,
                3 => special::NAME,
                _ => return Err(kr::KERN_INVALID_ARGUMENT),
            };
            if id != ctx.proc.task_port.id {
                return Err(kr::KERN_NOT_FOUND);
            }
            let port = if which == special::KERNEL {
                make_send(&ctx.proc.task_port)
            } else {
                get_special_port(ctx, &KObject::Task, which)?
            };
            Ok(Out::Complex(vec![port], Vec::new()))
        }
        t::TASK_GET_EXCEPTION_PORTS | t::TASK_GET_EXCEPTION_PORTS_INFO => {
            // The info variant takes a read port; the plain one the
            // control port only.
            req.simple(36)?;
            let info = req.id == t::TASK_GET_EXCEPTION_PORTS_INFO;
            if !(task || info && req.port.kobject == KObject::TaskRead) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let mask = req.u32(32);
            if mask & !EXC_MASK_VALID != 0 {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let o = exception::view(&ctx.proc.task.exc, mask);
            Ok(if info {
                exception::info_reply(&o, ctx.proc.pid as u32 | 1)
            } else {
                exception::ports_reply(&o)
            })
        }
        t::TASK_GET_EXC_GUARD_BEHAVIOR => {
            req.simple(24)?;
            Ok(Out::Simple(Buf::new().u32(ctx.proc.task.exc_guard).done()))
        }
        t::TASK_SET_EXC_GUARD_BEHAVIOR => {
            req.simple(36)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            ctx.proc.task.exc_guard = req.u32(32);
            Ok(Out::Simple(Vec::new()))
        }
        t::TASK_REGISTER_DYLD_SET_DYLD_STATE => {
            req.simple(36)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            ctx.proc.task.dyld_state = req.raw[32];
            Ok(Out::Simple(Vec::new()))
        }
        t::TASK_REGISTER_DYLD_IMAGE_INFOS | t::TASK_UNREGISTER_DYLD_IMAGE_INFOS => {
            // The kernel keeps dyld's image list only for corpses and
            // stackshots; the out-of-line list is consumed.
            req.complex_of(1, 48)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            Ok(Out::Simple(Vec::new()))
        }
        t::TASK_REGISTER_DYLD_SHARED_CACHE_IMAGE_INFO => {
            // dyld_kernel_image_info_t (40 bytes), no_cache, private_cache.
            req.simple(80)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            Ok(Out::Simple(Vec::new()))
        }
        ids::task_restartable::TASK_RESTARTABLE_RANGES_REGISTER => {
            let n = req.simple_array(36, 16, 64, 32)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            restartable_register(ctx, req, n)?;
            Ok(Out::Simple(Vec::new()))
        }
        ids::task_restartable::TASK_RESTARTABLE_RANGES_SYNCHRONIZE => {
            req.simple(24)?;
            if !task {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            // Every other thread whose PC lies in a range restarts at the
            // range's recovery code (AST_RESET_PCS on the way back to user
            // space; the other threads are all off-CPU here).
            let ranges = ctx.proc.task.restartable.clone();
            for t in ctx.proc.threads.values_mut().filter(|t| !t.exited) {
                if let Some(pc) = restartable_lookup(&ranges, t.cpu.pc()) {
                    t.cpu.set_pc(pc);
                }
            }
            Ok(Out::Simple(Vec::new()))
        }
        // Task vouchers are placeholders (`task.c`): none to get, a set
        // that keeps nothing, and no swap.
        t::TASK_GET_MACH_VOUCHER => {
            req.simple(36)?;
            if !(task || req.port.kobject == KObject::TaskRead) {
                return Err(kr::KERN_INVALID_TASK);
            }
            Ok(Out::Complex(vec![null_port()], Vec::new()))
        }
        t::TASK_SET_MACH_VOUCHER => {
            req.complex_of(1, 40)?;
            let v = req.take_port(28, &[disp::MOVE_SEND])?;
            kmsg::release(ctx.proc, v);
            if !task {
                return Err(kr::KERN_INVALID_TASK);
            }
            Ok(Out::Simple(Vec::new()))
        }
        t::TASK_SWAP_MACH_VOUCHER => {
            req.complex_of(2, 52)?;
            let new = req.take_port(28, &[disp::MOVE_SEND])?;
            let old = req.take_port(40, &[disp::MOVE_SEND])?;
            kmsg::release(ctx.proc, new.into_iter().chain(old));
            Err(kr::KERN_NOT_SUPPORTED)
        }
        _ => {
            if ctx.proc.config.strace || std::env::var_os("RAX_DARWIN_WARN").is_some() {
                eprintln!(
                    "rax-user: unimplemented MIG routine {} ({})",
                    req.id,
                    ids::name(req.id).unwrap_or("?")
                );
            }
            Err(kr::MIG_BAD_ID)
        }
    }
}

/// The task's read port (`convert_task_read_to_port`).
pub fn read_port(proc: &mut Proc) -> Arc<Port> {
    proc.task
        .read_port
        .get_or_insert_with(|| Port::new(KObject::TaskRead))
        .clone()
}

/// The task's inspect port (`convert_task_inspect_to_port`).
pub fn inspect_port(proc: &mut Proc) -> Arc<Port> {
    proc.task
        .inspect_port
        .get_or_insert_with(|| Port::new(KObject::TaskInspect))
        .clone()
}

/// A new identity token of the calling task (`task_create_identity_token`).
pub fn identity_token(proc: &Proc) -> Arc<Port> {
    Port::new(KObject::TaskIdToken(proc.task_port.id))
}

/// `task_get_special_port_internal`.
fn get_special_port(ctx: &mut Ctx<'_>, kind: &KObject, which: i32) -> Result<OutDesc, KernReturn> {
    // special_port_allowed_with_task_flavor
    let allowed = match kind {
        KObject::Task => true,
        KObject::TaskRead => matches!(which, special::READ | special::INSPECT | special::NAME),
        KObject::TaskInspect => matches!(which, special::INSPECT | special::NAME),
        _ => false,
    };
    if !allowed {
        return Err(if matches!(kind, KObject::TaskName) {
            kr::KERN_INVALID_ARGUMENT
        } else {
            kr::KERN_INVALID_CAPABILITY
        });
    }
    let t = &mut ctx.proc.task;
    Ok(match which {
        // task_get_special_port_from_user: a task asking for its own
        // movable control port is refused by the MAC policy
        // (mac_task_check_get_movable_control_port), as macOS refuses it
        // to unentitled processes.
        special::KERNEL if matches!(kind, KObject::Task) => return Err(KERN_DENIED),
        special::KERNEL => copy_send(&ctx.proc.task_port),
        special::HOST => copy_send(&ctx.proc.host_port),
        special::NAME => {
            let p = t
                .name_port
                .get_or_insert_with(|| Port::new(KObject::TaskName))
                .clone();
            make_send(&p)
        }
        // One read and one inspect port per task.
        special::READ => make_send(&read_port(ctx.proc)),
        special::INSPECT => make_send(&inspect_port(ctx.proc)),
        special::BOOTSTRAP
        | special::ACCESS
        | special::DEBUG_CONTROL
        | special::RESOURCE_NOTIFY => match &t.special[which as usize] {
            Some(p) => copy_send(p),
            None => null_port(),
        },
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    })
}

/// `_kernelrpc_mach_ports_register3` on the caller's task (`task`: the
/// request came through its control port): the three rights replace the
/// stashed ones, unless one may not move (`KERN_INVALID_RIGHT`); the rights
/// a refused request carries are released.
fn register_ports(
    proc: &mut Proc,
    task: bool,
    rights: Vec<Option<Right>>,
) -> Result<(), KernReturn> {
    let refused = if !task {
        Some(kr::KERN_INVALID_ARGUMENT)
    } else if rights
        .iter()
        .flatten()
        .any(|r| r.port().is_some_and(|p| !p.movable_send()))
    {
        Some(kr::KERN_INVALID_RIGHT)
    } else {
        None
    };
    if let Some(e) = refused {
        kmsg::release(proc, rights.into_iter().flatten());
        return Err(e);
    }
    let mut new: [Handler; PORT_REGISTER_MAX] = Default::default();
    for (slot, r) in new.iter_mut().zip(rights) {
        *slot = match r {
            None => Handler::None,
            Some(Right::Send(p)) => Handler::Port(p),
            Some(_) => Handler::Dead,
        };
    }
    // The old rights are released once the new ones are in place.
    let old = std::mem::replace(&mut proc.task.registered, new);
    for h in old {
        if let Handler::Port(p) = h {
            kmsg::release_send(proc, &p);
        }
    }
    Ok(())
}

/// `task_set_special_port`.
fn set_special_port(proc: &mut Proc, which: i32, right: Option<Right>) -> Result<(), KernReturn> {
    let port = match right {
        None => None,
        Some(Right::Send(p)) if p.movable_send() => Some(p),
        Some(Right::Dead) => None,
        // A right that may not be stashed (ipc_can_stash_naked_send).
        Some(other) => {
            kmsg::release(proc, [other]);
            return Err(kr::KERN_INVALID_RIGHT);
        }
    };
    let give_back = |proc: &mut Proc, p: Option<Arc<Port>>| {
        if let Some(p) = p {
            kmsg::release_send(proc, &p);
        }
    };
    match which {
        // Settable only with SIP's kernel-debugger exemption.
        special::KERNEL | special::HOST => {
            give_back(proc, port);
            Err(kr::KERN_NO_ACCESS)
        }
        special::ACCESS if proc.task.special[special::ACCESS as usize].is_some() => {
            give_back(proc, port);
            Err(kr::KERN_NO_ACCESS)
        }
        special::BOOTSTRAP
        | special::ACCESS
        | special::DEBUG_CONTROL
        | special::RESOURCE_NOTIFY => {
            let old = std::mem::replace(&mut proc.task.special[which as usize], port);
            give_back(proc, old);
            Ok(())
        }
        _ => {
            give_back(proc, port);
            Err(kr::KERN_INVALID_ARGUMENT)
        }
    }
}

/// `TASK_RESTARTABLE_OFFSET_MAX`.
const RESTARTABLE_OFFSET_MAX: u16 = 4096;

/// `task_restartable_ranges_register` (`osfmk/kern/restartable.c`): one
/// registration per task, made while it has a single thread, of sorted,
/// non-overlapping ranges (`_ranges_validate`).
fn restartable_register(ctx: &mut Ctx<'_>, req: &Req, n: usize) -> Result<(), KernReturn> {
    let mut ranges = Vec::with_capacity(n);
    for i in 0..n {
        let o = 36 + 16 * i;
        ranges.push(RestartableRange {
            location: req.u64(o),
            length: u16::from_le_bytes([req.raw[o + 8], req.raw[o + 9]]),
            recovery_offs: u16::from_le_bytes([req.raw[o + 10], req.raw[o + 11]]),
            flags: req.u32(o + 12),
        });
    }
    ranges.sort_by_key(|r| r.location);
    if ranges.is_empty() {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    for (i, r) in ranges.iter().enumerate() {
        if r.length > RESTARTABLE_OFFSET_MAX
            || r.recovery_offs > RESTARTABLE_OFFSET_MAX
            || r.flags != 0
        {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
        let end = r
            .location
            .checked_add(u64::from(r.length))
            .ok_or(kr::KERN_INVALID_ARGUMENT)?;
        r.location
            .checked_add(u64::from(r.recovery_offs))
            .ok_or(kr::KERN_INVALID_ARGUMENT)?;
        if ranges.get(i + 1).is_some_and(|next| end > next.location) {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
    }
    let threads = 1 + ctx.proc.threads.values().filter(|t| !t.exited).count();
    if threads > 1 || !ctx.proc.task.restartable.is_empty() {
        return Err(kr::KERN_NOT_SUPPORTED);
    }
    ctx.proc.task.restartable = ranges;
    Ok(())
}

/// `_ranges_lookup`: the recovery address of the range holding `pc`.
pub fn restartable_lookup(ranges: &[RestartableRange], pc: u64) -> Option<u64> {
    ranges
        .iter()
        .find(|r| pc >= r.location && pc < r.location + u64::from(r.length))
        .map(|r| r.location + u64::from(r.recovery_offs))
}

/// Seconds and microseconds of `ns` (`time_value_t`).
fn time_value(ns: u64) -> [u32; 2] {
    [
        (ns / 1_000_000_000) as u32,
        ((ns % 1_000_000_000) / 1000) as u32,
    ]
}

/// The task's (user, system) CPU time: live threads and terminated ones.
fn task_times(ctx: &Ctx<'_>) -> ((u64, u64), (u64, u64)) {
    let mut live = (ctx.thread.mach.user_ns, ctx.thread.mach.system_ns);
    for t in ctx.proc.threads.values().filter(|t| !t.exited) {
        live.0 += t.mach.user_ns;
        live.1 += t.mach.system_ns;
    }
    (live, ctx.proc.task.dead_times)
}

fn u64s(v: u64) -> [u32; 2] {
    [v as u32, (v >> 32) as u32]
}

/// Nanoseconds to Mach absolute-time units.
fn to_abs(abi: DarwinAbi, ns: u64) -> u64 {
    match abi {
        DarwinAbi::X86_64 => ns,
        DarwinAbi::Arm64 => {
            (u128::from(ns) * u128::from(crate::user::darwin::arch::ARM64_COUNTER_HZ)
                / 1_000_000_000) as u64
        }
    }
}

/// `task_info(flavor)` for the calling task with the caller's `count`.
fn task_info(ctx: &Ctx<'_>, f: i32, count: u32) -> Result<Vec<u32>, KernReturn> {
    let abi = ctx.proc.abi;
    let need = |n: u32| {
        if count < n {
            Err(kr::KERN_INVALID_ARGUMENT)
        } else {
            Ok(())
        }
    };
    let vmas = ctx.proc.space.vma_snapshot();
    let vsize: u64 = vmas.iter().map(|v| v.len()).sum();
    let resident = ctx.proc.space.resident_pages() * crate::user::mm::PAGE_SIZE;
    let ((lu, ls), (du, ds)) = task_times(ctx);
    let (euid, egid) = (ctx.proc.creds.1, ctx.proc.creds.3);
    let mut w: Vec<u32> = Vec::new();
    match f {
        flavor::BASIC_INFO_32 | flavor::BASIC2_INFO_32 => {
            need(8)?;
            let t = [time_value(du), time_value(ds)];
            w.extend_from_slice(&[
                0,
                vsize.min(u64::from(u32::MAX)) as u32,
                resident.min(u64::from(u32::MAX)) as u32,
            ]);
            w.extend_from_slice(&t[0]);
            w.extend_from_slice(&t[1]);
            w.push(POLICY_TIMESHARE);
        }
        flavor::BASIC_INFO_64 if abi == DarwinAbi::Arm64 => {
            return task_info(ctx, flavor::BASIC_INFO_32, count);
        }
        flavor::BASIC_INFO_64 | flavor::BASIC_INFO_64_2 => {
            // task_basic_info_64(_2): suspend_count, virtual_size,
            // resident_size, user_time, system_time, policy.
            if f == flavor::BASIC_INFO_64_2 && abi != DarwinAbi::Arm64 {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            need(10)?;
            w.push(0);
            w.extend_from_slice(&u64s(vsize));
            w.extend_from_slice(&u64s(resident));
            w.extend_from_slice(&time_value(du));
            w.extend_from_slice(&time_value(ds));
            w.push(POLICY_TIMESHARE);
        }
        flavor::MACH_TASK_BASIC_INFO => {
            need(12)?;
            w.extend_from_slice(&u64s(vsize));
            w.extend_from_slice(&u64s(resident));
            w.extend_from_slice(&u64s(resident));
            w.extend_from_slice(&time_value(du));
            w.extend_from_slice(&time_value(ds));
            w.push(POLICY_TIMESHARE);
            w.push(0);
        }
        flavor::THREAD_TIMES_INFO => {
            need(4)?;
            w.extend_from_slice(&time_value(lu));
            w.extend_from_slice(&time_value(ls));
        }
        flavor::ABSOLUTETIME_INFO => {
            need(8)?;
            w.extend_from_slice(&u64s(to_abs(abi, lu + du)));
            w.extend_from_slice(&u64s(to_abs(abi, ls + ds)));
            w.extend_from_slice(&u64s(to_abs(abi, lu)));
            w.extend_from_slice(&u64s(to_abs(abi, ls)));
        }
        flavor::DYLD_INFO => {
            // TASK_LEGACY_DYLD_INFO_COUNT 4, TASK_DYLD_INFO_COUNT 5.
            need(4)?;
            let (addr, size) = ctx.proc.task.dyld_info;
            w.extend_from_slice(&u64s(addr));
            w.extend_from_slice(&u64s(size));
            if count >= 5 {
                w.push(1); // TASK_DYLD_ALL_IMAGE_INFO_64
            }
        }
        flavor::EXTMOD_INFO => {
            // task_uuid[16] and vm_extmod_statistics (6 u64).
            need(16)?;
            let uuid = ctx.proc.program.main.uuid.unwrap_or([0; 16]);
            for c in uuid.chunks(4) {
                w.push(u32::from_le_bytes(c.try_into().expect("4 bytes")));
            }
            w.extend_from_slice(&[0; 12]);
        }
        flavor::KERNELMEMORY_INFO => {
            need(8)?;
            w.extend_from_slice(&[0; 8]);
        }
        flavor::SCHED_FIFO_INFO => {
            need(1)?;
            return Err(KERN_INVALID_POLICY);
        }
        flavor::SCHED_RR_INFO => {
            need(2)?;
            return Err(KERN_INVALID_POLICY);
        }
        flavor::SCHED_TIMESHARE_INFO => {
            need(1)?;
            w.push(BASEPRI_DEFAULT);
        }
        flavor::SECURITY_TOKEN => {
            need(2)?;
            w.extend_from_slice(&[euid, egid]);
        }
        flavor::AUDIT_TOKEN => {
            need(8)?;
            w.extend_from_slice(&ctx.proc.audit);
        }
        flavor::SCHED_INFO => return Err(kr::KERN_INVALID_ARGUMENT),
        flavor::EVENTS_INFO => {
            need(8)?;
            let t = &ctx.proc.task;
            let csw: u64 =
                ctx.thread.mach.csw + ctx.proc.threads.values().map(|t| t.mach.csw).sum::<u64>();
            let c = |v: u64| v.min(i32::MAX as u64) as u32;
            w.extend_from_slice(&[
                0,
                0,
                0,
                c(t.messages.0),
                c(t.messages.1),
                c(t.syscalls.0),
                c(t.syscalls.1),
                c(csw),
            ]);
        }
        flavor::AFFINITY_TAG_INFO => {
            // No affinity sets: set_count 0, min/max -1, task_count 0.
            need(4)?;
            w.extend_from_slice(&[0, u32::MAX, u32::MAX, 0]);
        }
        flavor::POWER_INFO => {
            // task_power_info: total_user, total_system (absolute time),
            // task_interrupt_wakeups, task_platform_idle_wakeups,
            // task_timer_wakeups_bin_1, _bin_2.
            need(10)?;
            w.extend_from_slice(&u64s(to_abs(abi, lu + du)));
            w.extend_from_slice(&u64s(to_abs(abi, ls + ds)));
            w.extend_from_slice(&[0; 6]);
        }
        flavor::POWER_INFO_V2 => {
            // TASK_POWER_INFO_V2_COUNT_OLD 18 (with gpu_energy), full 26
            // (task_energy and task_ptime/pset_switches).
            need(18)?;
            w.extend_from_slice(&u64s(to_abs(abi, lu + du)));
            w.extend_from_slice(&u64s(to_abs(abi, ls + ds)));
            w.extend_from_slice(&[0; 6]);
            w.extend_from_slice(&[0; 8]);
            if count >= 26 {
                w.extend_from_slice(&[0; 8]);
            }
        }
        flavor::VM_INFO | flavor::VM_INFO_PURGEABLE => {
            // Revisions: REV0 36, REV1 38, REV2 42, REV3 84, REV4 86,
            // REV5 87, REV6 89, REV7 93 words.
            need(36)?;
            let page = abi.user_page_size();
            let mut v = vec![0u32; 93];
            v[0..2].copy_from_slice(&u64s(vsize));
            v[2] = vmas.len() as u32;
            v[3] = page as u32;
            v[4..6].copy_from_slice(&u64s(resident));
            v[6..8].copy_from_slice(&u64s(resident));
            // internal / internal_peak: anonymous resident memory.
            v[12..14].copy_from_slice(&u64s(resident));
            v[14..16].copy_from_slice(&u64s(resident));
            v[36..38].copy_from_slice(&u64s(resident)); // phys_footprint
            v[38..40].copy_from_slice(&u64s(ctx.proc.vm.min));
            v[40..42].copy_from_slice(&u64s(ctx.proc.vm.max));
            v[42..44].copy_from_slice(&u64s(resident)); // ledger_phys_footprint_peak
            v[84..86].copy_from_slice(&u64s(u64::MAX)); // limit_bytes_remaining
            let n = [93, 89, 87, 86, 84, 42, 38, 36]
                .into_iter()
                .find(|&n| n <= count)
                .expect("count >= 36");
            v.truncate(n as usize);
            w = v;
        }
        flavor::FLAGS_INFO => {
            need(1)?;
            // TF_LP64 | TF_64B_DATA
            w.push(0x3);
        }
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    }
    Ok(w)
}
