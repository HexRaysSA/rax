//! Mach timers (`osfmk/kern/mk_timer.c`): `mk_timer_create`,
//! `mk_timer_destroy`, `mk_timer_arm`, `mk_timer_arm_leeway`, and
//! `mk_timer_cancel`.
//!
//! A timer is a receive right in the caller's space to a port the kernel
//! labels as a timer (an ordinary queue, not a kernel object's) and holds
//! a send right to itself, so the port always has a sender. Arming it
//! schedules its expiration: at the deadline [`expire`] queues the timer's
//! message (`mk_timer_expire_msg_t`: id 0, a zero body, sent with a copy of
//! the kernel's send right) unless the last one is still queued, as the
//! kernel preallocates one message per timer and reuses it only once it
//! has been received. A deadline already past expires at once; arming
//! again moves the deadline. The deadline a cancelled timer reports carries
//! the slop the kernel added when it armed the timer (`timer_call_slop`,
//! `thread_call_enter_delayed_internal`): for a normal timer a quarter of
//! the time left, at most 5 ms (the latency-QoS tier 1 row of the
//! coalescing parameters, `latency_qos_scale[1]` and `latency_qos_ns_max[1]`
//! in `osfmk/arm/arm_timer.c` and `osfmk/i386/i386_timer.c`, the tier the
//! processes of a login session run with), none for a critical one, and the
//! caller's leeway where that is larger. The emulator fires at the
//! deadline itself, the earliest time the kernel may.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Instant;

use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::mach::ipc::{KObject, MACH_PORT_NULL, Port, PortName, Right, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::msg::{Message, Sender, bits};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;

use super::kmsg;

/// `MK_TIMER_CRITICAL`: no coalescing slop.
const MK_TIMER_CRITICAL: u64 = 0x1;

/// `mk_timer_expire_msg_t` after its header: `uint64_t unused[3]`.
const EXPIRE_BODY: usize = 24;

/// The slop of a normal timer: the time left shifted right by this ...
const SLOP_SHIFT: u32 = 2;
/// ... and at most this many nanoseconds.
const SLOP_MAX_NS: u64 = 5_000_000;

/// The process's timers, by timer number (the port's
/// [`KObject::Timer`]).
#[derive(Default)]
pub struct Timers {
    next: u64,
    timers: HashMap<u64, Timer>,
}

struct Timer {
    port: Weak<Port>,
    armed: Option<Armed>,
}

#[derive(Clone, Copy)]
struct Armed {
    /// When the timer expires (`None`: beyond any representable instant).
    at: Option<Instant>,
    /// The deadline `mk_timer_cancel` reports (`thread_call_get_armed_deadline`):
    /// the caller's with the slop added, 0 for a timer armed to expire at once.
    deadline: u64,
}

impl Timers {
    /// When the next armed timer expires.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.timers.values().filter_map(|t| t.armed?.at).min()
    }
}

/// The slop limit in `abi`'s absolute-time units.
fn slop_max(abi: DarwinAbi) -> u64 {
    match abi {
        DarwinAbi::X86_64 => SLOP_MAX_NS,
        DarwinAbi::Arm64 => {
            let hz = u128::from(crate::user::darwin::arch::ARM64_COUNTER_HZ);
            (u128::from(SLOP_MAX_NS) * hz / 1_000_000_000) as u64
        }
    }
}

/// `mk_timer_create`: a new timer's receive right, or `MACH_PORT_NULL`
/// when the space is full.
pub fn create(ctx: &mut Ctx<'_>) -> KernReturn {
    let timers = &mut ctx.proc.mk_timers;
    let number = timers.next;
    timers.next += 1;
    let port = Port::new(KObject::Timer(number));
    {
        // The timer's own send right (ipc_port_make_send_any_locked).
        let mut st = port.state.lock().unwrap();
        st.srights += 1;
        st.mscount += 1;
    }
    match ctx.proc.ipc.insert(Right::Receive(port.clone())) {
        Ok(name) => {
            ctx.proc.mk_timers.timers.insert(
                number,
                Timer {
                    port: Arc::downgrade(&port),
                    armed: None,
                },
            );
            name as KernReturn
        }
        Err(_) => MACH_PORT_NULL as KernReturn,
    }
}

/// The timer number of the receive right `name` (`ipc_port_translate_receive`
/// and `ip_is_timer`): `KERN_INVALID_NAME` for a name the space does not
/// hold or a dead name, `KERN_INVALID_RIGHT` for any other right,
/// `KERN_INVALID_ARGUMENT` for a port that is not a timer.
fn timer_of(ctx: &Ctx<'_>, name: PortName) -> Result<u64, KernReturn> {
    let e = ctx.proc.ipc.lookup(name)?;
    if e.dead != 0 {
        return Err(kr::KERN_INVALID_NAME);
    }
    match e.port() {
        Some(p) if e.receive => match p.kobject {
            KObject::Timer(n) => Ok(n),
            _ => Err(kr::KERN_INVALID_ARGUMENT),
        },
        _ => Err(kr::KERN_INVALID_RIGHT),
    }
}

/// `mk_timer_destroy(name)`: destroys the timer's receive right (and any
/// send right the name also holds) as `mach_port_destroy` does; a name
/// the space holds without a receive right is `KERN_INVALID_RIGHT`, dead
/// names included (`ipc_right_lookup_write`).
pub fn destroy(ctx: &mut Ctx<'_>, name: PortName) -> KernReturn {
    let e = match ctx.proc.ipc.lookup(name) {
        Ok(e) => e,
        Err(k) => return k,
    };
    let number = match e.port() {
        Some(p) if e.receive => match p.kobject {
            KObject::Timer(n) => n,
            _ => return kr::KERN_INVALID_ARGUMENT,
        },
        _ => return kr::KERN_INVALID_RIGHT,
    };
    let r = super::port::destroy(ctx.proc, name);
    if r == kr::KERN_SUCCESS {
        ctx.proc.mk_timers.timers.remove(&number);
    }
    r
}

/// `mk_timer_arm_leeway(name, flags, expire_time, leeway)` (and
/// `mk_timer_arm`, with no flags or leeway): the timer expires at absolute
/// time `expire_time` (continuous time for `MK_TIMER_CONTINUOUS`, which
/// runs with absolute time here), or at once when that has passed. Unknown
/// flags are ignored.
pub fn arm(ctx: &mut Ctx<'_>, name: PortName, flags: u64, expire: u64, leeway: u64) -> KernReturn {
    let number = match timer_of(ctx, name) {
        Ok(n) => n,
        Err(k) => return k,
    };
    let abi = ctx.proc.abi;
    let now = super::absolute_time(abi);
    let armed = if expire > now {
        let mut slop = if flags & MK_TIMER_CRITICAL != 0 {
            0
        } else {
            ((expire - now) >> SLOP_SHIFT).min(slop_max(abi))
        };
        if leeway > slop {
            slop = leeway;
        }
        Armed {
            at: Instant::now().checked_add(super::until_absolute(abi, expire)),
            deadline: expire.saturating_add(slop),
        }
    } else {
        Armed {
            at: Some(Instant::now()),
            deadline: 0,
        }
    };
    if let Some(t) = ctx.proc.mk_timers.timers.get_mut(&number) {
        t.armed = Some(armed);
    }
    kr::KERN_SUCCESS
}

/// `mk_timer_cancel(name, result_time)`: disarms the timer and stores the
/// deadline it was armed for (0 when it was not armed) at `result_time`
/// unless that is 0; a failed store is `KERN_FAILURE`, the timer
/// cancelled all the same. A message already queued stays.
pub fn cancel(ctx: &mut Ctx<'_>, name: PortName, result_time: u64) -> KernReturn {
    let number = match timer_of(ctx, name) {
        Ok(n) => n,
        Err(k) => return k,
    };
    let deadline = ctx
        .proc
        .mk_timers
        .timers
        .get_mut(&number)
        .and_then(|t| t.armed.take())
        .map_or(0, |a| a.deadline);
    if result_time != 0 && ctx.write_u64(result_time, deadline).is_err() {
        return kr::KERN_FAILURE;
    }
    kr::KERN_SUCCESS
}

/// Whether `m` is a timer's expiration message: the only message the
/// kernel sends with a send right as its destination.
fn is_expiration(m: &Message) -> bool {
    m.sender == Sender::KERNEL && matches!(m.dest, Right::Send(_)) && m.id == 0
}

/// Expires the timers whose deadlines have passed (`mk_timer_expire`):
/// each queues its message on its port unless the previous one is still
/// queued there. Timers whose ports died are forgotten.
pub fn expire(proc: &mut Proc) {
    if proc.mk_timers.timers.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut due = Vec::new();
    proc.mk_timers.timers.retain(|_, t| {
        let Some(port) = t.port.upgrade().filter(|p| !p.is_dead()) else {
            return false;
        };
        if t.armed.is_some_and(|a| a.at.is_some_and(|at| at <= now)) {
            t.armed = None;
            due.push(port);
        }
        true
    });
    for port in due {
        let pending = port.state.lock().unwrap().queue.iter().any(is_expiration);
        if pending {
            continue;
        }
        // A copy of the timer's send right travels with the message.
        port.state.lock().unwrap().srights += 1;
        kmsg::enqueue(
            proc,
            Message {
                bits: bits::set(disp::MOVE_SEND, 0, 0, 0),
                dest: Right::Send(port),
                reply: None,
                voucher: None,
                voucher_name: MACH_PORT_NULL,
                id: 0,
                body: vec![0; EXPIRE_BODY],
                items: Vec::new(),
                sender: Sender::KERNEL,
                aux: Vec::new(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slop_limit_is_five_milliseconds_in_each_timebase() {
        assert_eq!(slop_max(DarwinAbi::X86_64), 5_000_000);
        // 24 MHz: 5 ms is 120 000 ticks.
        assert_eq!(slop_max(DarwinAbi::Arm64), 120_000);
    }
}
