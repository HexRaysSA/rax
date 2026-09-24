//! Signal system calls (`kernel/signal.c`): dispositions, masks, the
//! alternate stack, generation (`kill`, `tgkill`, `rt_sigqueueinfo`),
//! waiting (`rt_sigsuspend`, `pause`, `rt_sigtimedwait`), and
//! `rt_sigreturn`.

use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::process::SigAction;
use super::super::signal::deliver::{self, Dest, restart::ERESTARTNOHAND};
use super::super::signal::frame::{self, SigreturnError};
use super::super::signal::info::{KERNEL_SIGINFO_SIZE, SIGINFO_SIZE};
use super::super::signal::{
    AltStack, KERNEL_ONLY_MASK, SIG_DFL, SIG_IGN, SigInfo, code, default_ignored, minsigstksz,
    sigmask, uapi_sa_flags, valid_signal,
};
use super::super::wait::{Resume, Wait};
use super::{Ctx, Outcome, RestartBlock, SysResult, is_blocked};

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
        // discards it from every queue, whether or not it is blocked.
        if a.handler == SIG_IGN || (a.handler == SIG_DFL && default_ignored(sig)) {
            let (p, mut th) = c.split();
            p.shared_pending.flush(sigmask(sig));
            for t in th.iter_mut() {
                t.pending.flush(sigmask(sig));
            }
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
        let new = match how {
            SIG_BLOCK => old | s,
            SIG_UNBLOCK => old & !s,
            SIG_SETMASK => s,
            _ => return Err(Errno(EINVAL)),
        };
        c.set_blocked(new);
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

/// The thread a positive PID names in this process (its PID or any of its
/// thread IDs; `find_vpid`), for a process-directed signal.
fn process_target(c: &Ctx<'_>, pid: i32) -> Option<i32> {
    (pid > 0 && (pid == c.p.pid || c.is_own_tid(pid))).then_some(pid)
}

/// Sends `info` to the process through thread `target`.
fn send_process(c: &mut Ctx<'_>, info: SigInfo, target: i32) {
    let (p, mut th) = c.split();
    deliver::send_signal(p, &mut th, info, Dest::Process(target), false);
}

/// `kill`. This process (by its PID or one of its thread IDs) gets the
/// signal with its exact `siginfo`. With processes enabled
/// ([`LinuxConfig::processes`](crate::user::linux::LinuxConfig::processes)),
/// other processes, process groups, and `-1` are reached through the
/// host (`SI_USER` from this process; a signal the host lacks, such as a
/// real-time one, reaches only this process); `-1` then means this
/// process's children rather than every host process. Otherwise only this
/// process exists: its process group (0, `-pgid`) is itself and `-1` finds
/// no process.
pub fn kill(c: &mut Ctx<'_>, pid: i32, sig: i32) -> SysResult {
    if pid == i32::MIN {
        return Err(Errno(ESRCH));
    }
    let processes = c.p.config.processes;
    let own_pgid = if processes {
        super::super::host::getpgid(0)?
    } else {
        c.p.pid
    };
    let own_group = pid == 0 || pid == -own_pgid;
    if let Some(target) = process_target(c, pid) {
        if !valid_signal(sig) && sig != 0 {
            return Err(Errno(EINVAL));
        }
        if sig != 0 {
            let info = kill_info(c, sig, code::SI_USER);
            send_process(c, info, target);
        }
        return Ok(0);
    }
    if !processes {
        if !own_group {
            return Err(Errno(ESRCH));
        }
        if !valid_signal(sig) && sig != 0 {
            return Err(Errno(EINVAL));
        }
        if sig != 0 {
            let info = kill_info(c, sig, code::SI_USER);
            let me = c.p.pid;
            send_process(c, info, me);
        }
        return Ok(0);
    }
    if !valid_signal(sig) && sig != 0 {
        return Err(Errno(EINVAL));
    }
    use super::super::host;
    if pid == -1 {
        let children: Vec<i32> = c.p.children.list.iter().map(|ch| ch.pid).collect();
        let mut sent = false;
        for child in children {
            sent |= host::kill(child, sig).is_ok();
        }
        return if sent { Ok(0) } else { Err(Errno(ESRCH)) };
    }
    if own_group {
        // The other members through the host, this process directly.
        if host::host_signal(sig).is_some() || sig == 0 {
            host::kill_group_but_self(own_pgid, sig)?;
        }
        if sig != 0 {
            let info = kill_info(c, sig, code::SI_USER);
            let me = c.p.pid;
            send_process(c, info, me);
        }
        return Ok(0);
    }
    other_process(c, pid, sig)
}

/// A signal to another process (`pid > 0`) or process group (`pid < 0`)
/// through the host, with the kernel's error order: no such process
/// (`ESRCH`), an invalid signal (`EINVAL`), then permission (`EPERM`).
/// A child that ended but was not waited for is a zombie only in this
/// process's records (the host has reaped its PID and may reuse it): it is
/// still found, and the signal goes nowhere, as `group_send_sig_info` to a
/// zombie does; it is never asked of the host.
fn other_process(c: &Ctx<'_>, pid: i32, sig: i32) -> SysResult {
    use super::super::host;
    let zombie = c.p.children.list.iter().any(|ch| {
        ch.zombie.is_some()
            && if pid > 0 {
                ch.pid == pid
            } else {
                ch.pgid == -pid
            }
    });
    let checked = || {
        if !valid_signal(sig) && sig != 0 {
            Err(Errno(EINVAL))
        } else {
            Ok(0)
        }
    };
    if pid > 0 && zombie {
        return checked();
    }
    let probe = host::kill(pid, 0);
    if let Err(Errno(ESRCH)) = probe {
        return if zombie { checked() } else { Err(Errno(ESRCH)) };
    }
    checked()?;
    probe?;
    if sig == 0 {
        return Ok(0);
    }
    host::kill(pid, sig).map(|()| 0)
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
/// thread group. The exited leader is still found (a zombie); a signal
/// sent to it is never delivered.
fn send_specific(
    c: &mut Ctx<'_>,
    tgid: i32,
    tid: i32,
    sig: i32,
    info: Option<SigInfo>,
) -> SysResult {
    let live = c.is_own_tid(tid);
    let zombie_leader = tid == c.p.pid && c.p.leader_exit.is_some();
    if !(live || zombie_leader) && c.p.config.processes && tgid != c.p.pid {
        // Another process: its leader through the host; its other threads
        // cannot be named.
        if tgid > 0 && tgid != tid {
            return Err(Errno(ESRCH));
        }
        return other_process(c, tid, sig);
    }
    if !(live || zombie_leader) || (tgid > 0 && tgid != c.p.pid) {
        return Err(Errno(ESRCH));
    }
    if !valid_signal(sig) && sig != 0 {
        return Err(Errno(EINVAL));
    }
    if sig != 0 && live {
        let info = info.unwrap_or_else(|| kill_info(c, sig, code::SI_TKILL));
        let (p, mut th) = c.split();
        deliver::send_signal(p, &mut th, info, Dest::Thread(tid), false);
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
/// forge a kernel-, `kill`-, or `tgkill`-generated signal to anyone but
/// the calling thread itself (`task_pid_vnr(current)`).
fn may_queue(c: &Ctx<'_>, info: &SigInfo, pid: i32) -> bool {
    !((info.code >= 0 || info.code == code::SI_TKILL) && pid != c.t.tid)
}

/// `rt_sigqueueinfo`.
pub fn rt_sigqueueinfo(c: &mut Ctx<'_>, pid: i32, sig: i32, uinfo: u64) -> SysResult {
    let info = read_user_siginfo(c, sig, uinfo)?;
    if !may_queue(c, &info, pid) {
        return Err(Errno(EPERM));
    }
    let Some(target) = process_target(c, pid) else {
        // Another process gets a plain signal: the record cannot travel.
        return if c.p.config.processes && pid > 0 {
            other_process(c, pid, sig)
        } else {
            Err(Errno(ESRCH))
        };
    };
    if !valid_signal(sig) && sig != 0 {
        return Err(Errno(EINVAL));
    }
    if sig != 0 {
        send_process(c, info, target);
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

/// `sigsuspend`: waits with `set` as the mask for a signal and returns
/// `-ERESTARTNOHAND`; the old mask comes back on the return to user mode
/// unless a handler frame records it.
fn sigsuspend(c: &mut Ctx<'_>, set: u64) -> Result<Outcome, Errno> {
    if c.resume.take().is_none() {
        c.t.saved_sigmask = Some(c.t.sigmask);
        c.set_blocked(set);
    }
    if c.signal_pending() {
        return Err(Errno(ERESTARTNOHAND));
    }
    Err(c.block(Wait::event(), Resume::Retry))
}

/// `rt_sigsuspend`.
pub fn rt_sigsuspend(c: &mut Ctx<'_>, set: u64, size: u64) -> Result<Outcome, Errno> {
    if c.resume.is_some() {
        return sigsuspend(c, 0);
    }
    if size != SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    let set = c.read_u64(set)?;
    sigsuspend(c, set)
}

/// `pause` (x86-64).
pub fn pause(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    if c.signal_pending() {
        return Err(Errno(ERESTARTNOHAND));
    }
    Err(c.block(Wait::event(), Resume::Retry))
}

/// `rt_sigtimedwait` (`do_sigtimedwait`): dequeues a pending signal in
/// `set`; with none, sleeps with the set unblocked until one arrives
/// (its number), the timeout (`EAGAIN`), or another signal (`EINTR`).
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
    // The waited-for signals count as unblocked for dequeueing.
    let mask = !these;
    let got = if let Some(Resume::SigWait {
        deadline,
        real_blocked,
    }) = c.resume.take()
    {
        // Woken: the real mask comes back, then another dequeue.
        c.t.real_blocked = 0;
        c.set_blocked(real_blocked);
        match deliver::dequeue_signal(c.p, c.t, mask) {
            Some(info) => info,
            None if deadline.is_some_and(|d| Instant::now() >= d) => return Err(Errno(EAGAIN)),
            None => return Err(Errno(EINTR)),
        }
    } else {
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
        match deliver::dequeue_signal(c.p, c.t, mask) {
            Some(info) => info,
            None if timeout == Some(Duration::ZERO) => return Err(Errno(EAGAIN)),
            None => {
                // Sleep with the set temporarily unblocked so that its
                // signals wake the thread.
                let real_blocked = c.t.sigmask;
                let deadline = timeout.map(|d| Instant::now() + d);
                c.t.real_blocked = real_blocked;
                c.t.sigmask = real_blocked & mask;
                c.t.sigpending = deliver::recalc_sigpending(c.p, c.t);
                return Err(c.block(
                    Wait::until(deadline),
                    Resume::SigWait {
                        deadline,
                        real_blocked,
                    },
                ));
            }
        }
    };
    c.t.sigpending = deliver::recalc_sigpending(c.p, c.t);
    if uinfo != 0 {
        c.write_mem(uinfo, &got.encode())?;
    }
    Ok(Outcome::Return(got.signo as u64))
}

/// `rt_sigreturn`: restores the frame at the stack pointer. On a bad frame
/// the result register is zero and `SIGSEGV` is forced.
pub fn rt_sigreturn(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    // "Always make any pending restarted system calls return -EINTR."
    c.t.restart = None;
    let old = c.t.sigmask;
    match frame::rt_sigreturn(c.t, &c.p.space, minsigstksz(c.p.abi)) {
        Ok(()) => {
            // set_current_blocked with the saved mask.
            let restored = c.t.sigmask;
            c.t.sigmask = old;
            c.set_blocked(restored);
            Ok(Outcome::Unchanged)
        }
        Err(SigreturnError::Bad(bad)) => {
            c.t.sigmask = old;
            c.t.cpu.set_syscall_result(0);
            c.t.fault.apply(bad.fault);
            let (p, mut th) = c.split();
            deliver::force_signal(p, &mut th, bad.info, deliver::ForceMode::Current);
            Ok(Outcome::Unchanged)
        }
        Err(SigreturnError::Unsupported(why)) => Ok(Outcome::Fatal(why.into())),
    }
}

/// `restart_syscall`: continues the interrupted call the thread's restart
/// block describes; without one (`do_no_restart_syscall`) it is `-EINTR`.
pub fn restart_syscall(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    let block = c.t.restart.take();
    let result = match block {
        Some(RestartBlock::Nanosleep { deadline, rmtp }) => {
            super::time::nanosleep_restart(c, deadline, rmtp)
        }
        Some(RestartBlock::Poll {
            fds,
            nfds,
            deadline,
        }) => super::io::poll_restart(c, fds, nfds, deadline),
        Some(RestartBlock::Futex {
            uaddr,
            val,
            bitset,
            shared,
            deadline,
        }) => super::futex::wait_restart(c, uaddr, val, bitset, shared, deadline),
        None => Err(Errno(EINTR)),
    };
    // A continuation that sleeps keeps its block for when it runs again.
    if is_blocked(&result) {
        c.t.restart = block;
    }
    result
}
