//! The task subsystem (`task.defs`, `osfmk/kern/task.c`, `ipc_tt.c`,
//! `sync_sema.c`) and task restartable ranges (`restartable.defs`,
//! `osfmk/kern/restartable.c`) for the calling task.

use std::sync::Arc;

use super::{
    Buf, MigResult, Out, OutDesc, Req, copy_send, ids, info_reply, is_task, make_send, null_port,
};
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::mach::ipc::{KObject, Port, Right, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::sync::Semaphore;
use crate::user::darwin::mach::task::{EXC_TYPES_COUNT, ExcAction, RestartableRange, special};
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
            let right = req.take_port(28, &[disp::MOVE_SEND, disp::MOVE_SEND_ONCE])?;
            if !task {
                kmsg::release(ctx.proc, right);
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let (mask, behavior, flv) = (req.u32(48), req.i32(52), req.i32(56));
            let old = if req.id == t::TASK_SWAP_EXCEPTION_PORTS {
                Some(get_exception_ports(&ctx.proc.task.exc, mask))
            } else {
                None
            };
            set_exception_ports(ctx.proc, mask, right, behavior, flv)?;
            match old {
                None => Ok(Out::Simple(Vec::new())),
                Some(o) => Ok(exception_ports_reply(o)),
            }
        }
        t::TASK_GET_EXCEPTION_PORTS => {
            req.simple(36)?;
            if !readable {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let mask = req.u32(32);
            if mask & !valid_exc_mask() != 0 {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let o = get_exception_ports(&ctx.proc.task.exc, mask);
            Ok(exception_ports_reply(o))
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
        special::READ | special::INSPECT => {
            let kind = if which == special::READ {
                KObject::TaskRead
            } else {
                KObject::TaskInspect
            };
            make_send(&Port::new(kind))
        }
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

/// `task_set_special_port`.
fn set_special_port(proc: &mut Proc, which: i32, right: Option<Right>) -> Result<(), KernReturn> {
    let port = match right {
        None => None,
        Some(Right::Send(p)) => Some(p),
        Some(Right::Dead) => None,
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

/// `EXC_MASK_VALID`: exception types 1 ..= 14 (`EXC_MASK_ALL` plus
/// `EXC_MASK_CORPSE_NOTIFY`).
fn valid_exc_mask() -> u32 {
    ((1u32 << EXC_TYPES_COUNT) - 1) & !1
}

/// `EXCEPTION_*` behaviors with optional `MACH_EXCEPTION_*` flags.
fn valid_behavior(b: i32) -> bool {
    // EXCEPTION_DEFAULT 1, STATE 2, STATE_IDENTITY 3, IDENTITY_PROTECTED
    // 4, STATE_IDENTITY_PROTECTED 5; flags MACH_EXCEPTION_CODES
    // 0x80000000, ERRORS 0x40000000, BACKTRACE_PREFERRED 0x20000000.
    let base = b & !(0x8000_0000u32 as i32 | 0x4000_0000 | 0x2000_0000);
    (1..=5).contains(&base)
}

/// `task_set_exception_ports`.
pub fn set_exception_ports(
    proc: &mut Proc,
    mask: u32,
    right: Option<Right>,
    behavior: i32,
    flv: i32,
) -> Result<(), KernReturn> {
    let port = match right {
        None | Some(Right::Dead) => None,
        Some(Right::Send(p)) => Some(p),
        Some(other) => {
            kmsg::release(proc, [other]);
            return Err(kr::KERN_INVALID_RIGHT);
        }
    };
    if mask & !valid_exc_mask() != 0 || (port.is_some() && !valid_behavior(behavior)) {
        if let Some(p) = port {
            kmsg::release_send(proc, &p);
        }
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let old = replace_exception_actions(&mut proc.task.exc, mask, port.as_ref(), behavior, flv);
    // The right the message carried was copied into each action.
    if let Some(p) = port {
        kmsg::release_send(proc, &p);
    }
    for p in old {
        kmsg::release_send(proc, &p);
    }
    Ok(())
}

/// Installs `port` (a send right copied for each action) as the handler
/// of every exception type in `mask`; returns the handlers it replaced,
/// whose send rights the caller releases.
pub fn replace_exception_actions(
    exc: &mut [ExcAction],
    mask: u32,
    port: Option<&Arc<Port>>,
    behavior: i32,
    flv: i32,
) -> Vec<Arc<Port>> {
    let mut old = Vec::new();
    for (i, action) in exc.iter_mut().enumerate().skip(1) {
        if mask & (1 << i) == 0 {
            continue;
        }
        if let Some(p) = port {
            p.state.lock().unwrap().srights += 1;
        }
        let a = std::mem::replace(
            action,
            ExcAction {
                port: port.cloned(),
                behavior,
                flavor: flv,
            },
        );
        old.extend(a.port);
    }
    old
}

/// `task_get_exception_ports`: the distinct handlers covering `mask` with
/// their combined masks.
pub fn get_exception_ports(
    exc: &[ExcAction],
    mask: u32,
) -> Vec<(u32, Option<Arc<Port>>, i32, i32)> {
    let mut out: Vec<(u32, Option<Arc<Port>>, i32, i32)> = Vec::new();
    for (i, a) in exc.iter().enumerate().skip(1) {
        if mask & (1 << i) == 0 {
            continue;
        }
        let same = out.iter_mut().find(|o| {
            o.2 == a.behavior
                && o.3 == a.flavor
                && match (&o.1, &a.port) {
                    (Some(x), Some(y)) => Arc::ptr_eq(x, y),
                    (None, None) => true,
                    _ => false,
                }
        });
        match same {
            Some(o) => o.0 |= 1 << i,
            None => out.push((1 << i, a.port.clone(), a.behavior, a.flavor)),
        }
    }
    out
}

/// The `task_get_exception_ports` reply: 32 port descriptors (the
/// handlers, then nulls), then `masksCnt` and the three arrays.
pub fn exception_ports_reply(o: Vec<(u32, Option<Arc<Port>>, i32, i32)>) -> Out {
    let n = o.len();
    let mut descs = Vec::with_capacity(32);
    for (_, p, _, _) in &o {
        descs.push(match p {
            Some(p) => copy_send(p),
            None => null_port(),
        });
    }
    while descs.len() < 32 {
        descs.push(null_port());
    }
    let mut b = Buf::new().u32(n as u32);
    for e in &o {
        b = b.u32(e.0);
    }
    for e in &o {
        b = b.i32(e.2);
    }
    for e in &o {
        b = b.i32(e.3);
    }
    Out::Complex(descs, b.done())
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
            let (addr, size) = ctx.proc.program.all_image_info.unwrap_or((0, 0));
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
