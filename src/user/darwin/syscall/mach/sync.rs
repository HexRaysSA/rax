//! Mach semaphore traps (`osfmk/kern/sync_sema.c`) and the semaphore
//! form of `__semwait_signal` (`bsd/kern/kern_sig.c`).
//!
//! A semaphore's count is its stored wake-ups. A thread that finds none
//! parks on [`WaitKey::Semaphore`]; a signal hands itself to the oldest
//! such waiter (the thread's restarted trap sees the targeted wake and
//! succeeds) or, with no waiter, is stored (`SEMAPHORE_SIGNAL_PREPOST`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{RESTART, sleep};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::SysResult;
use crate::user::darwin::mach::ipc::{KObject, MACH_PORT_DEAD, MACH_PORT_NULL, PortName};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::sync::Semaphore;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::wait::{Wait, WaitKey};

/// `port_name_to_semaphore`: the semaphore a send right names.
fn semaphore(proc: &Proc, name: PortName) -> Result<Arc<Semaphore>, KernReturn> {
    if name == MACH_PORT_NULL || name == MACH_PORT_DEAD {
        return Err(kr::KERN_INVALID_NAME);
    }
    let e = proc.ipc.lookup(name)?;
    if e.send == 0 {
        return Err(kr::KERN_INVALID_RIGHT);
    }
    match e.port().map(|p| &p.kobject) {
        Some(KObject::Semaphore(s)) => Ok(s.clone()),
        _ => Err(kr::KERN_INVALID_CAPABILITY),
    }
}

/// `semaphore_signal_internal` without a target thread: wakes the oldest
/// waiter, or stores the wake-up when `prepost`. `KERN_NOT_WAITING` when
/// no thread woke.
fn signal_internal(proc: &mut Proc, s: &Semaphore, all: bool, prepost: bool) -> KernReturn {
    if *s.destroyed.lock().unwrap() {
        return kr::KERN_TERMINATED;
    }
    let key = WaitKey::Semaphore(s.id);
    if all {
        return if proc.wake(key, usize::MAX) > 0 {
            kr::KERN_SUCCESS
        } else {
            if prepost {
                *s.count.lock().unwrap() += 1;
            }
            kr::KERN_NOT_WAITING
        };
    }
    if proc.wake(key, 1) == 1 {
        return kr::KERN_SUCCESS;
    }
    if prepost {
        *s.count.lock().unwrap() += 1;
    }
    kr::KERN_NOT_WAITING
}

/// `semaphore_signal_trap` / `semaphore_signal_all_trap`.
pub fn signal(ctx: &mut Ctx<'_>, name: PortName, all: bool) -> KernReturn {
    let s = match semaphore(ctx.proc, name) {
        Ok(s) => s,
        Err(k) => return k,
    };
    // semaphore_signal_all_trap passes no PREPOST: with no waiter it is a
    // no-op.
    match signal_internal(ctx.proc, &s, all, !all) {
        kr::KERN_NOT_WAITING => kr::KERN_SUCCESS,
        k => k,
    }
}

/// `semaphore_signal_thread_trap`: wakes `thread` if it waits on the
/// semaphore (`KERN_NOT_WAITING` otherwise); a null thread signals as
/// `semaphore_signal` does without storing the wake-up.
pub fn signal_thread(ctx: &mut Ctx<'_>, name: PortName, thread: PortName) -> KernReturn {
    let target = if thread != MACH_PORT_NULL {
        let kport = ctx
            .proc
            .ipc
            .lookup(thread)
            .ok()
            .filter(|e| e.send > 0)
            .and_then(|e| e.port().cloned())
            .filter(|p| matches!(p.kobject, KObject::Thread(_)));
        match kport {
            Some(p) => Some(p),
            None => return kr::KERN_INVALID_ARGUMENT,
        }
    } else {
        None
    };
    let s = match semaphore(ctx.proc, name) {
        Ok(s) => s,
        Err(k) => return k,
    };
    if *s.destroyed.lock().unwrap() {
        return kr::KERN_TERMINATED;
    }
    let key = WaitKey::Semaphore(s.id);
    match target {
        None => signal_internal(ctx.proc, &s, false, false),
        Some(p) => {
            let KObject::Thread(tid) = p.kobject else {
                unreachable!("filtered above")
            };
            let waiting = ctx.proc.threads.get(&tid).is_some_and(|t| {
                !t.woken && t.wait.as_ref().is_some_and(|w| w.keys.contains(&key))
            });
            if !waiting {
                return kr::KERN_NOT_WAITING;
            }
            let t = ctx.proc.threads.get_mut(&tid).expect("checked");
            t.woken = true;
            t.wake_event = true;
            kr::KERN_SUCCESS
        }
    }
}

/// A relative Mach timeout (`mach_timespec_t`); `BAD_MACH_TIMESPEC`
/// rejects nanoseconds outside `0 .. NSEC_PER_SEC`.
fn timeout(sec: u32, nsec: u32) -> Result<Duration, KernReturn> {
    let nsec = nsec as i32;
    if !(0..1_000_000_000).contains(&nsec) {
        return Err(kr::KERN_INVALID_VALUE);
    }
    Ok(Duration::new(u64::from(sec), nsec as u32))
}

/// `semaphore_(timed)wait(_signal)_trap`: waits on `wait_name`, first
/// signalling `signal_name` when it is not null, with an optional
/// relative timeout (zero polls).
pub fn wait(
    ctx: &mut Ctx<'_>,
    wait_name: PortName,
    signal_name: PortName,
    tmo: Option<(u32, u32)>,
) -> KernReturn {
    let tmo = match tmo.map(|(s, n)| timeout(s, n)).transpose() {
        Ok(t) => t,
        Err(k) => return k,
    };
    let signal = if signal_name != MACH_PORT_NULL {
        match semaphore(ctx.proc, signal_name) {
            Ok(s) => Some(s),
            Err(k) => return k,
        }
    } else {
        None
    };
    let s = match semaphore(ctx.proc, wait_name) {
        Ok(s) => s,
        Err(k) => return k,
    };
    if let Some(r) = ctx.thread.resume {
        // Restarted: a targeted wake handed the semaphore over.
        if std::mem::take(&mut ctx.thread.wake_event) {
            return kr::KERN_SUCCESS;
        }
        if *s.destroyed.lock().unwrap() {
            return kr::KERN_TERMINATED;
        }
        if r.deadline.is_some_and(|d| d <= Instant::now()) {
            return kr::KERN_OPERATION_TIMED_OUT;
        }
        // Woken by a signal.
        return kr::KERN_ABORTED;
    }
    let result = {
        if *s.destroyed.lock().unwrap() {
            Some(kr::KERN_TERMINATED)
        } else {
            let mut count = s.count.lock().unwrap();
            if *count > 0 {
                *count -= 1;
                Some(kr::KERN_SUCCESS)
            } else if tmo == Some(Duration::ZERO) {
                // SEMAPHORE_TIMEOUT_NOBLOCK
                Some(kr::KERN_OPERATION_TIMED_OUT)
            } else {
                None
            }
        }
    };
    // The signal happens after the wait is decided (or queued).
    if let Some(sig) = signal {
        let k = signal_internal(ctx.proc, &sig, false, true);
        if k == kr::KERN_TERMINATED && result.is_none() {
            return kr::KERN_TERMINATED;
        }
    }
    if let Some(r) = result {
        return r;
    }
    let deadline = tmo.map(|d| Instant::now() + d);
    sleep(ctx, Wait::key(WaitKey::Semaphore(s.id), deadline))
}

/// Destroys a semaphore (`semaphore_destroy_internal`): its waiters
/// return `KERN_TERMINATED` and later operations fail.
pub fn destroy(proc: &mut Proc, s: &Semaphore) {
    *s.destroyed.lock().unwrap() = true;
    *s.count.lock().unwrap() = 0;
    // Waiters restart and see the destruction (not a targeted wake).
    let key = WaitKey::Semaphore(s.id);
    for t in proc.threads.values_mut() {
        if !t.woken && t.wait.as_ref().is_some_and(|w| w.keys.contains(&key)) {
            t.woken = true;
        }
    }
}

/// `__semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec,
/// tv_nsec)`: the semaphore wait with BSD errors (`EINTR`, `ETIMEDOUT`,
/// `EINVAL`).
pub fn semwait_signal(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let (cond, mutex, has_timeout, relative) =
        (a[0] as u32, a[1] as u32, a[2] as i32 != 0, a[3] as i32 != 0);
    let (sec, nsec) = (a[4] as i64, a[5] as i32);
    let mut truncated = false;
    let tmo = if has_timeout {
        let (mut s, mut n) = (sec, nsec);
        if (s as u64) & 0xFFFF_FFFF_0000_0000 != 0 {
            s = 0xFFFF_FFFF;
            n = 0;
            truncated = true;
        }
        if relative {
            Some((s as u32, n as u32))
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let (ns, nn) = (now.as_secs() as i64, now.subsec_nanos() as i32);
            if (ns, nn) > (s, n) && !(ns == s && nn <= n) {
                Some((0, 0))
            } else {
                let mut ts = s - ns;
                let mut tn = n - nn;
                if tn < 0 {
                    tn += 1_000_000_000;
                    ts -= 1;
                }
                Some((ts as u32, tn as u32))
            }
        }
    } else {
        None
    };
    // A restarted wait keeps the deadline it computed the first time (in
    // its Resume record).
    let k = wait(ctx, cond, mutex, tmo);
    match k {
        RESTART => Err(Errno::ERESTART),
        kr::KERN_SUCCESS if truncated => Err(Errno::EINTR),
        kr::KERN_SUCCESS => Ok(crate::user::darwin::arch::Rv::one(0)),
        kr::KERN_ABORTED => Err(Errno::EINTR),
        kr::KERN_OPERATION_TIMED_OUT => Err(Errno::ETIMEDOUT),
        _ => Err(Errno::EINVAL),
    }
}
