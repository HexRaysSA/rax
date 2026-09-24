//! Signal system calls (`kernel/signal.c`): dispositions, masks, the
//! alternate stack, generation (`kill`, `tgkill`, `rt_sigqueueinfo`),
//! waiting (`rt_sigsuspend`, `pause`, `rt_sigtimedwait`), and
//! `rt_sigreturn`.

use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::process::SigAction;
use super::super::signal::deliver::{self, restart::ERESTARTNOHAND};
use super::super::signal::frame::{self, SigreturnError};
use super::super::signal::info::{KERNEL_SIGINFO_SIZE, SIGINFO_SIZE};
use super::super::signal::{
    AltStack, KERNEL_ONLY_MASK, SIG_DFL, SIG_IGN, SigInfo, code, default_ignored, minsigstksz,
    sigmask, uapi_sa_flags, valid_signal,
};
use super::super::wait::{self, Wake};
use super::{Ctx, Outcome, RestartBlock, SysResult};

/// `sizeof(sigset_t)` in the kernel ABI.
const SIGSET_SIZE: u64 = 8;

/// `rt_sigaction`. The user structure is `{handler, flags, restorer,
/// mask}` where the ABI has `SA_RESTORER`, `{handler, flags, mask}` on
/// riscv.
pub fn rt_sigaction(c: &mut Ctx<'_>, sig: i32, act: u64, oact: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    let has_restorer = c.p.abi.has_sa_restorer();
    let len = if has_restorer { 32 } else { 24 };
    let new = if act != 0 {
        let b = c.read_mem(act, len)?;
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Some(if has_restorer {
            SigAction {
                handler: w(0),
                flags: w(1),
                restorer: w(2),
                mask: w(3),
            }
        } else {
            SigAction {
                handler: w(0),
                flags: w(1),
                restorer: 0,
                mask: w(2),
            }
        })
    } else {
        None
    };
    // do_sigaction.
    if !valid_signal(sig) || (new.is_some() && sigmask(sig) & KERNEL_ONLY_MASK != 0) {
        return Err(Errno(EINVAL));
    }
    let idx = (sig - 1) as usize;
    let old = c.p.sigactions[idx];
    if let Some(mut a) = new {
        // Unknown flag bits are cleared so user space can detect them.
        a.flags &= uapi_sa_flags(c.p.abi);
        a.mask &= !KERNEL_ONLY_MASK;
        c.p.sigactions[idx] = a;
        // POSIX 3.3.1.3: setting a pending signal's action to ignore
        // discards it, whether or not it is blocked.
        if a.handler == SIG_IGN || (a.handler == SIG_DFL && default_ignored(sig)) {
            c.p.shared_pending.flush(sigmask(sig));
            c.t.pending.flush(sigmask(sig));
        }
    }
    if oact != 0 {
        let mut b = Vec::with_capacity(len);
        b.extend_from_slice(&old.handler.to_le_bytes());
        b.extend_from_slice(&old.flags.to_le_bytes());
        if has_restorer {
            b.extend_from_slice(&old.restorer.to_le_bytes());
        }
        b.extend_from_slice(&old.mask.to_le_bytes());
        c.write_mem(oact, &b)?;
    }
    Ok(0)
}

/// `rt_sigprocmask`.
pub fn rt_sigprocmask(c: &mut Ctx<'_>, how: i32, set: u64, oset: u64, size: u64) -> SysResult {
    const SIG_BLOCK: i32 = 0;
    const SIG_UNBLOCK: i32 = 1;
    const SIG_SETMASK: i32 = 2;
    if size != SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    let old = c.t.sigmask;
    if set != 0 {
        let s = c.read_u64(set)? & !KERNEL_ONLY_MASK;
        c.t.sigmask = match how {
            SIG_BLOCK => old | s,
            SIG_UNBLOCK => old & !s,
            SIG_SETMASK => s,
            _ => return Err(Errno(EINVAL)),
        };
    }
    if oset != 0 {
        c.write_u64(oset, old)?;
    }
    Ok(0)
}

/// `sigaltstack` (`stack_t`: `ss_sp`, `ss_flags`, `ss_size`; 24 bytes).
/// The old stack is written only after a successful change.
pub fn sigaltstack(c: &mut Ctx<'_>, ss: u64, old: u64) -> SysResult {
    let new = if ss != 0 {
        let b: [u8; 24] = c.read_mem(ss, 24)?.try_into().unwrap();
        Some(AltStack::decode_stack_t(&b))
    } else {
        None
    };
    let sp = c.t.cpu.sp();
    let reported = c.t.altstack.report(sp);
    if let Some(new) = new {
        c.t.altstack
            .install(new, sp, minsigstksz(c.p.abi))
            .map_err(Errno)?;
    }
    if old != 0 {
        let (s, f, z) = reported;
        c.write_mem(old, &AltStack::encode_stack_t(s, f, z))?;
    }
    Ok(0)
}

/// `rt_sigpending`: the thread's and the process's pending signals that
/// are blocked.
pub fn rt_sigpending(c: &mut Ctx<'_>, set: u64, size: u64) -> SysResult {
    if size > SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    let pending = (c.t.pending.set() | c.p.shared_pending.set()) & c.t.sigmask;
    c.write_mem(set, &pending.to_le_bytes()[..size as usize])?;
    Ok(0)
}

/// `prepare_kill_siginfo`: the sender's TGID and real UID.
fn kill_info(c: &Ctx<'_>, sig: i32, code: i32) -> SigInfo {
    SigInfo::kill(sig, code, c.p.pid, c.p.creds.0)
}

/// `kill`. Only this process exists in the emulated system, so it is the
/// only target a positive PID, its own process group (0 or `-pgid`), or
/// `-1` (every process but the caller) can reach.
pub fn kill(c: &mut Ctx<'_>, pid: i32, sig: i32) -> SysResult {
    let own_group = pid == 0 || pid == -c.p.pid;
    if pid == -1 || pid == i32::MIN || !(pid == c.p.pid || own_group) {
        return Err(Errno(ESRCH));
    }
    if !valid_signal(sig) && sig != 0 {
        return Err(Errno(EINVAL));
    }
    if sig != 0 {
        let info = kill_info(c, sig, code::SI_USER);
        deliver::send_signal(c.p, c.t, info, false, false);
    }
    Ok(0)
}

/// `tgkill`.
pub fn tgkill(c: &mut Ctx<'_>, tgid: i32, tid: i32, sig: i32) -> SysResult {
    if tid <= 0 || tgid <= 0 {
        return Err(Errno(EINVAL));
    }
    send_specific(c, tgid, tid, sig, None)
}

/// `tkill`: `tgkill` without a thread-group check.
pub fn tkill(c: &mut Ctx<'_>, tid: i32, sig: i32) -> SysResult {
    if tid <= 0 {
        return Err(Errno(EINVAL));
    }
    send_specific(c, 0, tid, sig, None)
}

/// `do_send_specific`: a signal to one thread, `tgid <= 0` matching any
/// thread group.
fn send_specific(
    c: &mut Ctx<'_>,
    tgid: i32,
    tid: i32,
    sig: i32,
    info: Option<SigInfo>,
) -> SysResult {
    if tid != c.t.tid || (tgid > 0 && tgid != c.p.pid) {
        return Err(Errno(ESRCH));
    }
    if !valid_signal(sig) && sig != 0 {
        return Err(Errno(EINVAL));
    }
    if sig != 0 {
        let info = info.unwrap_or_else(|| kill_info(c, sig, code::SI_TKILL));
        deliver::send_signal(c.p, c.t, info, true, false);
    }
    Ok(0)
}

/// `__copy_siginfo_from_user`: the record with `si_signo` replaced by
/// `sig`; an unknown layout must not use bytes 48-127.
fn read_user_siginfo(c: &Ctx<'_>, sig: i32, addr: u64) -> Result<SigInfo, Errno> {
    let b = c.read_mem(addr, KERNEL_SIGINFO_SIZE)?;
    let mut info = SigInfo::decode(&b);
    info.signo = sig;
    if !info.known_layout() {
        let rest = c.read_mem(
            addr + KERNEL_SIGINFO_SIZE as u64,
            SIGINFO_SIZE - KERNEL_SIGINFO_SIZE,
        )?;
        if rest.iter().any(|&x| x != 0) {
            return Err(Errno(E2BIG));
        }
    }
    Ok(info)
}

/// Whether a user-supplied record may be sent to `pid`: not even root may
/// forge a kernel-, `kill`-, or `tgkill`-generated signal to another
/// process.
fn may_queue(c: &Ctx<'_>, info: &SigInfo, pid: i32) -> bool {
    !((info.code >= 0 || info.code == code::SI_TKILL) && pid != c.p.pid)
}

/// `rt_sigqueueinfo`.
pub fn rt_sigqueueinfo(c: &mut Ctx<'_>, pid: i32, sig: i32, uinfo: u64) -> SysResult {
    let info = read_user_siginfo(c, sig, uinfo)?;
    if !may_queue(c, &info, pid) {
        return Err(Errno(EPERM));
    }
    if pid != c.p.pid {
        return Err(Errno(ESRCH));
    }
    if !valid_signal(sig) && sig != 0 {
        return Err(Errno(EINVAL));
    }
    if sig != 0 {
        deliver::send_signal(c.p, c.t, info, false, false);
    }
    Ok(0)
}

/// `rt_tgsigqueueinfo`.
pub fn rt_tgsigqueueinfo(c: &mut Ctx<'_>, tgid: i32, tid: i32, sig: i32, uinfo: u64) -> SysResult {
    let info = read_user_siginfo(c, sig, uinfo)?;
    if tid <= 0 || tgid <= 0 {
        return Err(Errno(EINVAL));
    }
    if !may_queue(c, &info, tid) {
        return Err(Errno(EPERM));
    }
    send_specific(c, tgid, tid, sig, Some(info))
}

/// `sigsuspend`: waits with `set` as the mask and returns
/// `-ERESTARTNOHAND`; the old mask comes back on the return to user mode
/// unless a handler frame records it.
fn sigsuspend(c: &mut Ctx<'_>, set: u64) -> Result<Outcome, Errno> {
    let saved = c.t.sigmask;
    c.t.sigmask = set & !KERNEL_ONLY_MASK;
    let blocked = c.t.sigmask;
    if let Err(dead) = wait::block(c.p, c.t, &[], None, blocked) {
        return Ok(Outcome::Fatal(dead.message()));
    }
    c.t.saved_sigmask = Some(saved);
    Ok(Outcome::Return(-(ERESTARTNOHAND as i64) as u64))
}

/// `rt_sigsuspend`.
pub fn rt_sigsuspend(c: &mut Ctx<'_>, set: u64, size: u64) -> Result<Outcome, Errno> {
    if size != SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    let set = c.read_u64(set)?;
    sigsuspend(c, set)
}

/// `pause` (x86-64).
pub fn pause(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    let blocked = c.t.sigmask;
    if let Err(dead) = wait::block(c.p, c.t, &[], None, blocked) {
        return Ok(Outcome::Fatal(dead.message()));
    }
    Ok(Outcome::Return(-(ERESTARTNOHAND as i64) as u64))
}

/// `rt_sigtimedwait`: dequeues a pending signal in `set`, waiting until the
/// timeout for one to arrive.
pub fn rt_sigtimedwait(
    c: &mut Ctx<'_>,
    set: u64,
    uinfo: u64,
    uts: u64,
    size: u64,
) -> Result<Outcome, Errno> {
    if size != SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    let these = c.read_u64(set)? & !KERNEL_ONLY_MASK;
    let timeout = if uts != 0 {
        let b: [u8; 16] = c.read_mem(uts, 16)?.try_into().unwrap();
        let t = super::super::abi::types::Timespec::decode(&b);
        if t.sec < 0 || !(0..1_000_000_000).contains(&t.nsec) {
            return Err(Errno(EINVAL));
        }
        Some(Duration::new(t.sec as u64, t.nsec as u32))
    } else {
        None
    };
    // The waited-for signals count as unblocked for dequeueing.
    let mask = !these;
    let mut got = deliver::dequeue_signal(c.p, c.t, mask);
    if got.is_none() && timeout != Some(Duration::ZERO) {
        // While waiting, the set is also unblocked for wakeups.
        let deadline = timeout.map(|d| Instant::now() + d);
        let blocked = c.t.sigmask & mask;
        let interrupted = match wait::block(c.p, c.t, &[], deadline, blocked) {
            Err(dead) => return Ok(Outcome::Fatal(dead.message())),
            Ok(Wake::Signal) => true,
            Ok(_) => false,
        };
        got = deliver::dequeue_signal(c.p, c.t, mask);
        if got.is_none() && interrupted {
            return Err(Errno(EINTR));
        }
    }
    let Some(info) = got else {
        return Err(Errno(EAGAIN));
    };
    if uinfo != 0 {
        c.write_mem(uinfo, &info.encode())?;
    }
    Ok(Outcome::Return(info.signo as u64))
}

/// `rt_sigreturn`: restores the frame at the stack pointer. On a bad frame
/// the result register is zero and `SIGSEGV` is forced.
pub fn rt_sigreturn(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    // "Always make any pending restarted system calls return -EINTR."
    c.t.restart = None;
    match frame::rt_sigreturn(c.t, &c.p.space, minsigstksz(c.p.abi)) {
        Ok(()) => Ok(Outcome::Unchanged),
        Err(SigreturnError::Bad(bad)) => {
            c.t.cpu.set_syscall_result(0);
            c.t.fault.apply(bad.fault);
            deliver::force_signal(c.p, c.t, bad.info, deliver::ForceMode::Current);
            Ok(Outcome::Unchanged)
        }
        Err(SigreturnError::Unsupported(why)) => Ok(Outcome::Fatal(why.into())),
    }
}

/// `restart_syscall`: continues the interrupted call the thread's restart
/// block describes; without one (`do_no_restart_syscall`) it is `-EINTR`.
pub fn restart_syscall(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    match c.t.restart.take() {
        Some(RestartBlock::Nanosleep { deadline, rmtp }) => {
            super::time::nanosleep_restart(c, deadline, rmtp)
        }
        Some(RestartBlock::Poll {
            fds,
            nfds,
            deadline,
        }) => super::io::poll_restart(c, fds, nfds, deadline),
        None => Err(Errno(EINTR)),
    }
}
