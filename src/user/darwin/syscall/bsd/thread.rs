//! Thread identity, pthread registration, and user-space synchronization
//! waits (`ulock`, `__semwait_signal`).

use std::time::{Duration, Instant};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::bsd::file::{deadline, expired};
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::{Wait, WaitKey};

/// `thread_selfid()`: the thread's 64-bit ID.
pub fn thread_selfid(ctx: &mut Ctx<'_>) -> SysResult {
    Ok(Rv::one(ctx.thread.tid))
}

/// `PTHREAD_FEATURE_SUPPORTED`.
const PTHREAD_FEATURES: u64 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80 | 0x4000_0000;
/// `MAX_PTHREAD_SIZE`.
const MAX_PTHREAD_SIZE: i64 = 64 * 1024;
/// `sizeof(struct _pthread_registration_data)` (packed).
const REG_DATA_SIZE: u64 = 56;
/// `_pthread_priority_make_from_thread_qos(THREAD_QOS_LEGACY, 0, 0)`:
/// the main thread's QoS when none was requested.
const MAIN_QOS_LEGACY: u64 = (1 << (8 + 4 - 1)) | 0xff;

/// `bsdthread_register(threadstart, wqthread, pthsize, init_data,
/// init_data_size, dispatchqueue_offset)` (`_bsdthread_register`).
pub fn bsdthread_register(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let (threadstart, wqthread, pthsize, data_addr, data_size, dq_offset) =
        (a[0], a[1], a[2] as i32 as i64, a[3], a[4], a[5]);
    if !(0..=MAX_PTHREAD_SIZE).contains(&pthsize) {
        return Err(Errno::EINVAL);
    }
    let mut data = [0u8; REG_DATA_SIZE as usize];
    let sz = if data_addr != 0 {
        if data_size < 8 {
            return Err(Errno::EINVAL);
        }
        let sz = REG_DATA_SIZE.min(data_size) as usize;
        data[..sz].copy_from_slice(&ctx.read(data_addr, sz)?);
        if u64::from_le_bytes(data[..8].try_into().expect("8 bytes")) != data_size {
            return Err(Errno::EINVAL);
        }
        sz
    } else {
        data[8..16].copy_from_slice(&dq_offset.to_le_bytes());
        0
    };
    if ctx.proc.pthread.registered {
        return Err(Errno::EINVAL);
    }
    let u32_at = |d: &[u8], o: usize| u32::from_le_bytes(d[o..o + 4].try_into().expect("4 bytes"));
    let reg = &mut ctx.proc.pthread;
    reg.thread_start = threadstart;
    reg.wqthread_start = wqthread;
    reg.pthread_size = pthsize as u32;
    reg.registered = true;
    let mut tsd_offset = u32_at(&data, 24);
    let max_tsd = if pthsize >= 8 && i64::from(tsd_offset) <= pthsize - 8 {
        pthsize as u32 - tsd_offset - 8
    } else {
        tsd_offset = 0;
        0
    };
    reg.tsd_offset = tsd_offset;
    reg.dispatch_queue_offset = u64::from_le_bytes(data[8..16].try_into().expect("8 bytes"));
    let clamp = |v: u32| if v > max_tsd { 0 } else { v };
    reg.return_to_kernel_offset = clamp(u32_at(&data, 28));
    reg.mach_thread_self_offset = clamp(u32_at(&data, 32));
    if sz > 0 {
        // Reply: the consumed version, the main thread's QoS, the stack
        // address hint, and the default mutex policy.
        let stack_hint = match ctx.proc.abi {
            crate::user::darwin::abi::DarwinAbi::X86_64 => 0x7000_0000_0000u64,
            crate::user::darwin::abi::DarwinAbi::Arm64 => {
                ctx.proc.program.stack.top & !(ctx.proc.vm.page - 1)
            }
        };
        data[0..8].copy_from_slice(&REG_DATA_SIZE.to_le_bytes());
        data[16..24].copy_from_slice(&MAIN_QOS_LEGACY.to_le_bytes());
        data[36..44].copy_from_slice(&stack_hint.to_le_bytes());
        data[44..48].copy_from_slice(&0u32.to_le_bytes());
        ctx.write(data_addr, &data[..sz])?;
    }
    Ok(Rv::one(PTHREAD_FEATURES))
}

/// `ulock` operations and flags (`bsd/sys/ulock.h`).
mod ul {
    pub const COMPARE_AND_WAIT: u32 = 1;
    pub const UNFAIR_LOCK: u32 = 2;
    pub const COMPARE_AND_WAIT_SHARED: u32 = 3;
    pub const UNFAIR_LOCK64_SHARED: u32 = 4;
    pub const COMPARE_AND_WAIT64: u32 = 5;
    pub const COMPARE_AND_WAIT64_SHARED: u32 = 6;
    pub const OPCODE_MASK: u32 = 0xff;
    pub const WAKE_ALL: u32 = 0x100;
    pub const WAKE_THREAD: u32 = 0x200;
    pub const WAKE_ALLOW_NON_OWNER: u32 = 0x400;
    pub const WAIT_WORKQ_DATA_CONTENTION: u32 = 0x1_0000;
    pub const WAIT_CANCEL_POINT: u32 = 0x2_0000;
    pub const WAIT_ADAPTIVE_SPIN: u32 = 0x4_0000;
    pub const NO_ERRNO: u32 = 0x100_0000;
    pub const DEADLINE: u32 = 0x200_0000;
    pub const WAIT_MASK: u32 =
        NO_ERRNO | DEADLINE | WAIT_WORKQ_DATA_CONTENTION | WAIT_CANCEL_POINT | WAIT_ADAPTIVE_SPIN;
    pub const WAKE_MASK: u32 = NO_ERRNO | WAKE_ALL | WAKE_THREAD | WAKE_ALLOW_NON_OWNER;
}

/// With `ULF_NO_ERRNO`, an error comes back as its negation in the result
/// register with the carry clear.
fn munge(flags: u32, r: SysResult) -> SysResult {
    match r {
        Err(e) if flags & ul::NO_ERRNO != 0 && e.0 > 0 => Ok(Rv::one((-e.0) as i64 as u64)),
        r => r,
    }
}

/// `ulock_wait(operation, addr, value, timeout_us)` and `ulock_wait2(...,
/// timeout_ns, value2)`.
pub fn ulock_wait(ctx: &mut Ctx<'_>, op: u32, addr: u64, value: u64, timeout_ns: u64) -> SysResult {
    let flags = op & !ul::OPCODE_MASK;
    let r = ulock_wait_inner(ctx, op & ul::OPCODE_MASK, flags, addr, value, timeout_ns);
    if r == Err(Errno::ERESTART) {
        return r;
    }
    munge(flags, r)
}

fn ulock_wait_inner(
    ctx: &mut Ctx<'_>,
    opcode: u32,
    flags: u32,
    addr: u64,
    value: u64,
    timeout_ns: u64,
) -> SysResult {
    if flags & ul::WAIT_MASK != flags {
        return Err(Errno::EINVAL);
    }
    let size = match opcode {
        ul::UNFAIR_LOCK | ul::COMPARE_AND_WAIT | ul::COMPARE_AND_WAIT_SHARED => 4,
        ul::COMPARE_AND_WAIT64 | ul::COMPARE_AND_WAIT64_SHARED => 8,
        _ => return Err(Errno::EINVAL),
    };
    if addr == 0 || addr & (size - 1) != 0 {
        return Err(Errno::EINVAL);
    }
    // A thread woken by ulock_wake returns from its wait.
    if ctx.thread.resume.is_some() && std::mem::take(&mut ctx.thread.wake_event) {
        return Ok(Rv::one(0));
    }
    if expired(ctx) {
        return Err(Errno::ETIMEDOUT);
    }
    let cur = if size == 4 {
        u64::from(ctx.read_u32(addr)?)
    } else {
        ctx.read_u64(addr)?
    };
    let want = if size == 4 {
        value & 0xffff_ffff
    } else {
        value
    };
    if cur != want {
        return Ok(Rv::one(0));
    }
    let timeout = (timeout_ns != 0).then(|| {
        if flags & ul::DEADLINE != 0 {
            let now = super::super::mach::absolute_time(ctx.proc.abi);
            let (n, d) = crate::user::darwin::commpage::timebase(ctx.proc.abi);
            let ticks = timeout_ns.saturating_sub(now);
            Duration::from_nanos((u128::from(ticks) * u128::from(n) / u128::from(d)) as u64)
        } else {
            Duration::from_nanos(timeout_ns)
        }
    });
    let deadline = deadline(ctx, timeout);
    syscall::sleep(ctx, Wait::key(WaitKey::Address(addr), deadline))
}

/// `ulock_wake(operation, addr, wake_value)`.
pub fn ulock_wake(ctx: &mut Ctx<'_>, op: u32, addr: u64, wake_value: u64) -> SysResult {
    let flags = op & !ul::OPCODE_MASK;
    let r = (|| {
        if flags & ul::WAKE_MASK != flags {
            return Err(Errno::EINVAL);
        }
        match op & ul::OPCODE_MASK {
            ul::UNFAIR_LOCK
            | ul::COMPARE_AND_WAIT
            | ul::COMPARE_AND_WAIT_SHARED
            | ul::UNFAIR_LOCK64_SHARED
            | ul::COMPARE_AND_WAIT64
            | ul::COMPARE_AND_WAIT64_SHARED => {}
            _ => return Err(Errno::EINVAL),
        }
        if addr == 0 {
            return Err(Errno::EINVAL);
        }
        let key = WaitKey::Address(addr);
        let woken = if flags & ul::WAKE_THREAD != 0 {
            ctx.proc.wake_thread_port(key, wake_value as u32)
        } else if flags & ul::WAKE_ALL != 0 {
            ctx.proc.wake(key, usize::MAX)
        } else {
            ctx.proc.wake(key, 1)
        };
        if woken == 0 {
            // No thread waits: ENOENT (EALREADY for a targeted wake of a
            // thread that is not waiting).
            return Err(if flags & ul::WAKE_THREAD != 0 {
                Errno::EALREADY
            } else {
                Errno::ENOENT
            });
        }
        Ok(Rv::one(0))
    })();
    munge(flags, r)
}

/// `__semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec,
/// tv_nsec)`: a Mach semaphore wait (Libc's `nanosleep` waits on a
/// semaphore nothing signals).
pub fn semwait_signal(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    super::super::mach::sync::semwait_signal(ctx, a)
}
