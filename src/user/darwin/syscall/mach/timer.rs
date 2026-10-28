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
//! `thread_call_enter_delayed_internal`): none for a critical one, the
//! caller's leeway where that is larger, and otherwise a share of the time
//! left bounded by the latency-QoS tier of the process (its row of the
//! coalescing parameters, `latency_qos_scale` and `latency_qos_ns_max` in
//! `osfmk/arm/arm_timer.c` and `osfmk/i386/i386_timer.c`). The process is a
//! host process, whose tier the host kernel decides from its role and the
//! system's state: on a macOS host the slop is what the host gives a timer
//! armed the same way; elsewhere it is tier 1's (a quarter of the time
//! left, at most 5 ms), the tier of a login session's processes. The
//! emulator fires at the deadline itself, the earliest time the kernel may.

use crate::host::time::Instant;
use std::collections::HashMap;
use std::sync::{Arc, Weak};

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

/// `abi`'s absolute-time units as nanoseconds, and back.
#[cfg(test)]
fn to_ns(abi: DarwinAbi, t: u64) -> u64 {
    match abi {
        DarwinAbi::X86_64 => t,
        DarwinAbi::Arm64 => {
            let hz = u128::from(crate::user::darwin::arch::ARM64_COUNTER_HZ);
            (u128::from(t) * 1_000_000_000 / hz).min(u128::from(u64::MAX)) as u64
        }
    }
}

#[cfg(test)]
fn from_ns(abi: DarwinAbi, ns: u64) -> u64 {
    match abi {
        DarwinAbi::X86_64 => ns,
        DarwinAbi::Arm64 => {
            let hz = u128::from(crate::user::darwin::arch::ARM64_COUNTER_HZ);
            (u128::from(ns) * hz / 1_000_000_000) as u64
        }
    }
}

// Keep the guest/host ratio intact until the final division: going through
// integer nanoseconds first loses an Arm guest tick even on a matching host.
#[cfg(any(target_os = "macos", test))]
fn guest_frequency(abi: DarwinAbi) -> u128 {
    match abi {
        DarwinAbi::X86_64 => 1_000_000_000,
        DarwinAbi::Arm64 => u128::from(crate::user::darwin::arch::ARM64_COUNTER_HZ),
    }
}

#[cfg(any(target_os = "macos", test))]
fn to_host_units(abi: DarwinAbi, ticks: u64, numer: u32, denom: u32) -> u64 {
    (u128::from(ticks) * 1_000_000_000 * u128::from(denom)
        / (guest_frequency(abi) * u128::from(numer)))
    .min(u128::from(u64::MAX)) as u64
}

#[cfg(any(target_os = "macos", test))]
fn from_host_units(abi: DarwinAbi, ticks: u64, numer: u32, denom: u32) -> u64 {
    (u128::from(ticks) * u128::from(numer) * guest_frequency(abi)
        / (u128::from(denom) * 1_000_000_000))
        .min(u128::from(u64::MAX)) as u64
}

/// One hardware timebase period, rounded up in the process's reported units.
/// Rosetta reports nanosecond units even when the kernel uses a 24 MHz clock.
#[cfg(any(target_os = "macos", test))]
fn deadline_quantum(numer: u32, denom: u32, frequency: u64) -> u64 {
    if numer == 0 || denom == 0 || frequency == 0 {
        return 1;
    }
    (1_000_000_000_u128 * u128::from(denom))
        .div_ceil(u128::from(frequency) * u128::from(numer))
        .clamp(1, u128::from(u64::MAX)) as u64
}

#[cfg(any(target_os = "macos", test))]
fn sampled_slop(
    abi: DarwinAbi,
    expire: u64,
    canceled: u64,
    leeway: u64,
    numer: u32,
    denom: u32,
    quantum: u64,
) -> Option<u64> {
    // Zero denotes a timer that is no longer armed. A live translated deadline
    // can round down by one hardware period; larger discrepancies fail.
    if numer == 0
        || denom == 0
        || quantum == 0
        || canceled == 0
        || canceled.saturating_add(quantum) < expire
    {
        return None;
    }
    let observed = from_host_units(abi, canceled.saturating_sub(expire), numer, denom);
    // XNU's explicit leeway can only extend the kernel-selected slop. Input
    // duration rounding, deadline rounding, and final guest truncation can
    // account for less than two hardware periods plus one guest unit. Recover only
    // that bounded loss; do not fabricate a large missing leeway.
    let rounding_bound =
        from_host_units(abi, quantum.saturating_mul(2), numer, denom).saturating_add(2);
    if observed < leeway && leeway - observed > rounding_bound {
        return None;
    }
    Some(observed.max(leeway))
}

/// The slop, in `abi`'s units, the host kernel gives a timer of this
/// process armed `delta` ahead with `flags` and `leeway`: a host timer
/// armed so and cancelled reports its deadline. `None` without a macOS
/// host.
fn host_slop(abi: DarwinAbi, delta: u64, flags: u64, leeway: u64) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        use std::sync::OnceLock;
        unsafe extern "C" {
            fn mk_timer_create() -> u32;
            fn mk_timer_destroy(name: u32) -> i32;
            fn mk_timer_arm_leeway(name: u32, flags: u64, expire: u64, leeway: u64) -> i32;
            fn mk_timer_cancel(name: u32, result: *mut u64) -> i32;
        }
        struct HostTimer(u32);
        impl Drop for HostTimer {
            fn drop(&mut self) {
                // SAFETY: this name is the live receive right created below,
                // owned only by this query. Cancellation does not destroy it.
                // No pointer or borrowed state crosses the native call.
                unsafe { mk_timer_destroy(self.0) };
            }
        }
        static TIMEBASE: OnceLock<(u32, u32, u64)> = OnceLock::new();
        // Each probe owns a timer: sharing an arm/cancel pair across owner
        // threads can cancel another process's probe and mix its deadline.
        // SAFETY: mk_timer_create has no arguments. A nonzero returned name
        // owns a receive right, released by HostTimer on every exit path.
        let name = unsafe { mk_timer_create() };
        if name == 0 {
            return None;
        }
        let _timer = HostTimer(name);
        let (numer, denom, quantum) = *TIMEBASE.get_or_init(|| {
            let mut tb = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: `tb` is a live mach_timebase_info.
            unsafe { libc::mach_timebase_info(&mut tb) };
            let mut frequency = 0_u64;
            let mut size = std::mem::size_of_val(&frequency);
            // SAFETY: the name is NUL-terminated and the output is a writable
            // u64 with its exact size. No new sysctl value is supplied.
            let status = unsafe {
                libc::sysctlbyname(
                    c"hw.tbfrequency".as_ptr(),
                    (&mut frequency as *mut u64).cast(),
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if status != 0 || size != std::mem::size_of_val(&frequency) {
                frequency = 0;
            }
            // If frequency is unavailable, tolerate only one reported unit;
            // larger discrepancies still defer to the modeled fallback.
            (
                tb.numer,
                tb.denom,
                deadline_quantum(tb.numer, tb.denom, frequency),
            )
        });
        if numer == 0 || denom == 0 {
            return None;
        }
        let to_host = |ticks| to_host_units(abi, ticks, numer, denom);
        // SAFETY: mach_absolute_time reads the host's clock.
        let expire = unsafe { libc::mach_absolute_time() }.saturating_add(to_host(delta));
        let mut result = 0u64;
        // SAFETY: `name` is a host timer and `result` a live u64.
        let ok = unsafe {
            mk_timer_arm_leeway(name, flags & MK_TIMER_CRITICAL, expire, to_host(leeway)) == 0
                && mk_timer_cancel(name, &mut result) == 0
        };
        if !ok {
            return None;
        }
        sampled_slop(abi, expire, result, leeway, numer, denom, quantum)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (abi, delta, flags, leeway);
        None
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
        let host = if ctx.proc.config.host_services {
            host_slop(abi, expire - now, flags, leeway)
        } else {
            None
        };
        let slop = host.unwrap_or_else(|| {
            let slop = if flags & MK_TIMER_CRITICAL != 0 {
                0
            } else {
                ((expire - now) >> SLOP_SHIFT).min(slop_max(abi))
            };
            slop.max(leeway)
        });
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
    fn hardware_period_bounds_translated_deadline_rounding() {
        assert_eq!(deadline_quantum(125, 3, 24_000_000), 1);
        assert_eq!(deadline_quantum(1, 1, 24_000_000), 42);
        assert_eq!(deadline_quantum(1, 1, 1_000_000_000), 1);
        assert_eq!(deadline_quantum(1, 1, u64::MAX), 1);
        assert_eq!(deadline_quantum(1, u32::MAX, 1), 4_294_967_295_000_000_000);
        assert_eq!(deadline_quantum(1, 1, 0), 1);
        for loss in 0..=42 {
            assert_eq!(
                sampled_slop(DarwinAbi::X86_64, 100, 100 - loss, 0, 1, 1, 42),
                Some(0)
            );
        }
        assert_eq!(sampled_slop(DarwinAbi::X86_64, 100, 57, 0, 1, 1, 42), None);
        assert_eq!(sampled_slop(DarwinAbi::X86_64, 100, 101, 0, 1, 1, 0), None);
        assert_eq!(
            sampled_slop(DarwinAbi::X86_64, 100, 1_000_058, 1_000_000, 1, 1, 42),
            Some(1_000_000)
        );
    }

    #[test]
    fn exact_duration_ratios_preserve_all_matching_arm_ticks() {
        for ticks in [0, 1, 2, 3, 4, 5, 23, 24, 25, u32::MAX as u64, u64::MAX] {
            assert_eq!(to_host_units(DarwinAbi::Arm64, ticks, 125, 3), ticks);
            assert_eq!(from_host_units(DarwinAbi::Arm64, ticks, 125, 3), ticks);
            assert_eq!(to_host_units(DarwinAbi::X86_64, ticks, 1, 1), ticks);
            assert_eq!(from_host_units(DarwinAbi::X86_64, ticks, 1, 1), ticks);
        }
        assert_eq!(to_host_units(DarwinAbi::Arm64, 1, 1, 1), 41);
        assert_eq!(from_host_units(DarwinAbi::Arm64, 125, 1, 1), 3);
        assert_eq!(
            to_host_units(DarwinAbi::X86_64, u64::MAX, 1, u32::MAX),
            u64::MAX
        );
        assert_eq!(
            from_host_units(DarwinAbi::X86_64, u64::MAX, u32::MAX, 1),
            u64::MAX
        );
    }

    #[test]
    fn translated_deadline_rounding_preserves_zero_and_explicit_minimum_slop() {
        assert_eq!(
            sampled_slop(DarwinAbi::X86_64, 100, 99, 0, 1, 1, 1),
            Some(0)
        );
        assert_eq!(sampled_slop(DarwinAbi::X86_64, 100, 98, 0, 1, 1, 1), None);
        assert_eq!(
            sampled_slop(DarwinAbi::X86_64, 100, 149, 50, 1, 1, 1),
            Some(50)
        );
        assert_eq!(
            sampled_slop(DarwinAbi::Arm64, 100, 5_000_099, 120_000, 1, 1, 1),
            Some(120_000)
        );
        assert_eq!(
            sampled_slop(DarwinAbi::X86_64, 100, 200, 50, 1, 1, 1),
            Some(100)
        );
        assert_eq!(
            sampled_slop(DarwinAbi::X86_64, 100, 100, 500, 1, 1, 1),
            None
        );
        assert_eq!(sampled_slop(DarwinAbi::Arm64, 100, 0, 0, 125, 3, 1), None);
        assert_eq!(sampled_slop(DarwinAbi::X86_64, 100, 101, 0, 0, 1, 1), None);
        assert_eq!(sampled_slop(DarwinAbi::X86_64, 100, 101, 0, 1, 0, 1), None);
    }

    #[test]
    fn time_units_convert_both_ways() {
        // 24 MHz: 20 ms is 480 000 ticks.
        assert_eq!(to_ns(DarwinAbi::Arm64, 480_000), 20_000_000);
        assert_eq!(from_ns(DarwinAbi::Arm64, 20_000_000), 480_000);
        assert_eq!(to_ns(DarwinAbi::X86_64, 7), 7);
    }

    /// Critical timers suppress QoS-derived coalescing, while explicit
    /// leeway still applies. Ordinary timer slop is chosen by the host's
    /// current QoS tier; CI need not run as a foreground application.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_host_computes_the_slop() {
        for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
            let delta = from_ns(abi, 60_000_000_000);
            assert_eq!(host_slop(abi, delta, MK_TIMER_CRITICAL, 0), Some(0));
            // 150 ms = 150,000,000 Intel ticks = 3,600,000 Arm64 ticks.
            // Explicit leeway overrides zero critical-timer slop.
            let leeway = from_ns(abi, 150_000_000);
            assert_eq!(
                host_slop(abi, delta, MK_TIMER_CRITICAL, leeway),
                Some(leeway)
            );
            assert!(host_slop(abi, delta, 0, 0).is_some());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn concurrent_host_timer_probes_keep_their_own_deadlines() {
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for n in 0..8u64 {
                let start = &start;
                scope.spawn(move || {
                    let abi = if n % 2 == 0 {
                        DarwinAbi::X86_64
                    } else {
                        DarwinAbi::Arm64
                    };
                    let delta = from_ns(abi, (60 + n * 10) * 1_000_000_000);
                    let leeway = from_ns(abi, n * 5_000_000);
                    start.wait();
                    for _ in 0..128 {
                        // Critical removes host-QoS-dependent coalescing, but
                        // explicit leeway still applies (thread_call.c).
                        assert_eq!(
                            host_slop(abi, delta, MK_TIMER_CRITICAL, leeway),
                            Some(leeway)
                        );
                    }
                });
            }
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn critical_host_timer_probes_cover_nonintegral_hardware_periods() {
        for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
            let base = from_ns(abi, 60_000_000_000);
            for phase in 0..125 {
                assert_eq!(host_slop(abi, base + phase, MK_TIMER_CRITICAL, 0), Some(0));
                assert_eq!(
                    host_slop(abi, base + phase, MK_TIMER_CRITICAL, 1_000_000 + phase),
                    Some(1_000_000 + phase)
                );
            }
        }
    }

    #[test]
    fn slop_limit_is_five_milliseconds_in_each_timebase() {
        assert_eq!(slop_max(DarwinAbi::X86_64), 5_000_000);
        // 24 MHz: 5 ms is 120 000 ticks.
        assert_eq!(slop_max(DarwinAbi::Arm64), 120_000);
    }
}
