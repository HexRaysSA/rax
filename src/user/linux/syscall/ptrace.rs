//! `ptrace` (`kernel/ptrace.c`, Linux 6.19): the tracer's requests. The
//! links, messages, and records are [`ptrace`](super::super::ptrace), and
//! the tracee's side is [`tracee`](super::super::ptrace::tracee).
//!
//! A request that needs the tracee travels along the link and the tracer
//! sleeps until the answer comes back; the tracee answers as its process
//! reads its links, whether its traced thread is stopped or not. Resuming
//! marks the tracee running at once, so a stop that follows is not lost.

use super::super::abi::LinuxAbi;
use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::ptrace::{
    LinkId, Msg, NSIG, PEEKSIGINFO_SHARED, RSEQ_CONFIGURATION, SECCOMP_METADATA, SIGINFO, SIGSET,
    Traced, call, link_mut, offered, opt, regs, req, resumes, send,
};
use super::super::seccomp::MODE_DISABLED;
use super::super::wait::{Resume, Wait};
use super::{Ctx, SysResult};

/// `sizeof(struct user_i387_struct)`.
const USER_I387: usize = 512;

/// `ptrace`.
pub fn ptrace(c: &mut Ctx<'_>, request: u64, pid: i64, addr: u64, data: u64) -> SysResult {
    if request == req::TRACEME {
        return traceme(c);
    }
    let resumed = match c.resume.take() {
        Some(Resume::Ptrace { link }) => Some(link),
        _ => None,
    };
    let pid = pid as i32;
    if request == req::ATTACH || request == req::SEIZE {
        return attach(c, request, pid, addr, data, resumed);
    }
    // The answer to a request already sent (a detach has already dropped
    // its tracee).
    if let Some(link) = resumed {
        return answer(c, request, addr, data, link);
    }
    // ptrace_check_attach: a tracee of this thread, stopped unless the
    // request is PTRACE_KILL or PTRACE_INTERRUPT.
    if pid <= 0 {
        return Err(Errno(ESRCH));
    }
    let me = c.t.tid;
    let Some(tracee) = c.p.tracees.get(pid).cloned() else {
        return Err(Errno(ESRCH));
    };
    if tracee.tracer != me {
        return Err(Errno(ESRCH));
    }
    let any_state = request == req::KILL || request == req::INTERRUPT;
    if !any_state && tracee.stopped.is_none() {
        return Err(Errno(ESRCH));
    }
    ask(c, &tracee, request, addr, data)
}

/// `ptrace_traceme`: once only (`EPERM`); the parent traces the calling
/// thread from now on.
fn traceme(c: &mut Ctx<'_>) -> SysResult {
    if c.t.ptrace.is_some() {
        return Err(Errno(EPERM));
    }
    let tid = c.t.tid;
    let ppid = c.p.ppid;
    // A parent that is not a rax-user process has no link: the thread is
    // traced all the same, and a stop waits for a tracer that never comes,
    // as for a parent that does not trace.
    if c.p.parent_link.is_some() {
        send(c.p, LinkId::Parent, &Msg::Traceme { tid });
    }
    c.t.ptrace = Some(Traced::new(ppid, LinkId::Parent, false, 0));
    Ok(0)
}

/// `ptrace_attach` (and `PTRACE_SEIZE`'s checks before it): a task in
/// reach is one of this process's children or its parent (along their
/// links); any other is refused as by `ptrace_may_access` (`EPERM`), the
/// caller's own threads too.
fn attach(
    c: &mut Ctx<'_>,
    request: u64,
    pid: i32,
    addr: u64,
    data: u64,
    resumed: Option<LinkId>,
) -> SysResult {
    let seize = request == req::SEIZE;
    if let Some(link) = resumed {
        let Some((ret, _)) = c.p.tracees.take_reply(link) else {
            return wait_answer(c, link);
        };
        if ret < 0 {
            c.p.tracees.remove(pid);
            return Err(Errno(-ret as i32));
        }
        return Ok(0);
    }
    if pid <= 0 {
        return Err(Errno(ESRCH));
    }
    let own = c.t.tid == pid
        || c.peers
            .lo
            .iter()
            .chain(c.peers.hi.iter())
            .any(|t| t.tid == pid);
    let link = if c
        .p
        .children
        .list
        .iter()
        .any(|ch| ch.pid == pid && ch.link.is_some())
    {
        Some(LinkId::Child(pid))
    } else if pid == c.p.ppid && c.p.parent_link.is_some() {
        Some(LinkId::Parent)
    } else {
        None
    };
    // find_get_task_by_vpid: another process exists if the host can
    // signal it or is refused doing so.
    let exists = || !matches!(super::super::host::kill(pid, 0), Err(Errno(ESRCH)));
    if !own && link.is_none() && !exists() {
        return Err(Errno(ESRCH));
    }
    if seize {
        if addr != 0 || data & !opt::MASK != 0 {
            return Err(Errno(EIO));
        }
        check_options(c, data)?;
    }
    let Some(link) = link.filter(|_| !own) else {
        return Err(Errno(EPERM));
    };
    if c.p.tracees.get(pid).is_some() {
        return Err(Errno(EPERM));
    }
    let (uid, gid) = (c.p.creds.0, c.p.creds.2);
    let capable = c.p.creds.1 == 0;
    let m = Msg::Attach {
        tid: pid,
        seize,
        options: if seize { data } else { 0 },
        uid,
        gid,
        capable,
    };
    if !send(c.p, link, &m) {
        return Err(Errno(ESRCH));
    }
    // Recorded as the attach goes out: the tracee stops (PTRACE_ATTACH's
    // SIGSTOP) as soon as it answers, and that stop may arrive with the
    // answer, before this thread takes it.
    let tracer = c.t.tid;
    c.p.tracees.add(pid, tracer, link, seize);
    let r = wait_answer(c, link);
    if r == Err(Errno(ESRCH)) {
        c.p.tracees.remove(pid);
    }
    r
}

/// `check_ptrace_options`: unknown options (`EINVAL`), and
/// `PTRACE_O_SUSPEND_SECCOMP` (checkpoint and restore), which needs
/// `CAP_SYS_ADMIN` and a tracer neither under seccomp nor itself traced
/// with seccomp suspended (`EPERM`).
fn check_options(c: &Ctx<'_>, data: u64) -> Result<(), Errno> {
    if data & !opt::MASK != 0 {
        return Err(Errno(EINVAL));
    }
    if data & opt::SUSPEND_SECCOMP != 0 {
        let suspended = super::super::ptrace::tracee::seccomp_suspended(c.t);
        if !admin(c) || c.t.seccomp.mode != MODE_DISABLED || suspended {
            return Err(Errno(EPERM));
        }
    }
    Ok(())
}

/// `capable(CAP_SYS_ADMIN)`: only root holds it.
fn admin(c: &Ctx<'_>) -> bool {
    c.p.creds.1 == 0
}

/// Sleeps until the answer on `link` comes (or the link goes: `ESRCH`).
fn wait_answer(c: &mut Ctx<'_>, link: LinkId) -> SysResult {
    let Some(l) = link_mut(c.p, link) else {
        return Err(Errno(ESRCH));
    };
    if l.closed {
        return Err(Errno(ESRCH));
    }
    let fd = l.fd();
    let mut wait = Wait::fd(fd, true, false);
    // The tracee answers at once: nothing but the process's end ends it.
    wait.interruptible = false;
    Err(c.block(wait, Resume::Ptrace { link }))
}

/// Sends a request to a tracee after the checks the tracer makes itself,
/// in `ptrace_request`'s and `arch_ptrace`'s order.
fn ask(
    c: &mut Ctx<'_>,
    tracee: &super::super::ptrace::Tracee,
    request: u64,
    addr: u64,
    data: u64,
) -> SysResult {
    let x86 = c.p.abi == LinuxAbi::X86_64;
    let mut payload = Vec::new();
    let mut data = data;
    match request {
        req::PEEKTEXT
        | req::PEEKDATA
        | req::POKETEXT
        | req::POKEDATA
        | req::PEEKUSR
        | req::POKEUSR => {}
        req::GETREGS | req::SETREGS if x86 => {
            if request == req::SETREGS {
                payload = c.read_mem(data, 27 * 8)?;
            }
        }
        req::GETREGSET | req::SETREGSET => {
            let iov = c.read_mem(data, 16)?;
            let base = u64::from_le_bytes(iov[..8].try_into().unwrap());
            let len = u64::from_le_bytes(iov[8..].try_into().unwrap());
            let (unit, size) = regs::layout(&c.t.cpu, addr)?;
            if len % unit != 0 {
                return Err(Errno(EINVAL));
            }
            let len = len.min(size);
            if !super::events::access_ok(c, base, len) {
                return Err(Errno(EFAULT));
            }
            if request == req::SETREGSET {
                payload = c.read_mem(base, len as usize)?;
            }
            data = len;
        }
        req::GETFPREGS | req::SETFPREGS if x86 => {
            if request == req::SETFPREGS {
                payload = c.read_mem(data, USER_I387)?;
            }
        }
        req::ARCH_PRCTL if x86 => {}
        req::GETSIGINFO | req::GETEVENTMSG | req::GET_RSEQ_CONFIGURATION => {}
        req::SETSIGINFO => payload = c.read_mem(data, SIGINFO)?,
        req::PEEKSIGINFO => {
            // ptrace_peek_siginfo: struct ptrace_peeksiginfo_args (off,
            // flags, nr); `off` always fits an unsigned long here.
            payload = c.read_mem(addr, 16)?;
            let flags = u32::from_le_bytes(payload[8..12].try_into().unwrap());
            let nr = i32::from_le_bytes(payload[12..16].try_into().unwrap());
            if flags & !PEEKSIGINFO_SHARED != 0 || nr < 0 {
                return Err(Errno(EINVAL));
            }
        }
        req::SETOPTIONS => check_options(c, data)?,
        req::GETSIGMASK | req::SETSIGMASK => {
            if addr != SIGSET {
                return Err(Errno(EINVAL));
            }
            if request == req::SETSIGMASK {
                payload = c.read_mem(data, SIGSET as usize)?;
            }
        }
        req::CONT
        | req::SYSCALL
        | req::SINGLESTEP
        | req::SYSEMU
        | req::SYSEMU_SINGLESTEP
        | req::DETACH
            if offered(c.p.abi, request) =>
        {
            if data > NSIG {
                return Err(Errno(EIO));
            }
        }
        req::KILL | req::INTERRUPT | req::LISTEN | req::GET_SYSCALL_INFO => {}
        req::SET_SYSCALL_INFO => {
            if addr < call::INFO_SIZE as u64 {
                return Err(Errno(EINVAL));
            }
            payload = c.read_mem(data, call::INFO_SIZE)?;
        }
        // seccomp_get_filter and seccomp_get_metadata: CAP_SYS_ADMIN and a
        // tracer without seccomp (EACCES); the metadata's size (at least
        // its filter_off, EINVAL) and filter_off, read from the tracer.
        req::SECCOMP_GET_FILTER | req::SECCOMP_GET_METADATA => {
            if !admin(c) || c.t.seccomp.mode != MODE_DISABLED {
                return Err(Errno(EACCES));
            }
            if request == req::SECCOMP_GET_METADATA {
                if addr.min(SECCOMP_METADATA) < 8 {
                    return Err(Errno(EINVAL));
                }
                payload = c.read_mem(data, 8)?;
            }
        }
        _ => return Err(Errno(EIO)),
    }
    let m = Msg::Request {
        tid: tracee.tid,
        req: request,
        addr,
        data,
        payload,
    };
    if !send(c.p, tracee.link, &m) {
        return Err(Errno(ESRCH));
    }
    // Resuming: the tracee runs from now on, and a stop after it is new;
    // after a detach it is no tracee. RISC-V cannot step: the tracee stays
    // stopped (EIO).
    let steps = matches!(request, req::SINGLESTEP | req::SYSEMU_SINGLESTEP);
    let resumed = resumes(request) && !(steps && c.p.abi == LinuxAbi::Riscv64);
    if request == req::DETACH {
        c.p.tracees.remove(tracee.tid);
    } else if (resumed || request == req::KILL)
        && let Some(t) = c.p.tracees.get_mut(tracee.tid)
    {
        t.stopped = None;
        t.reported = false;
    }
    wait_answer(c, tracee.link)
}

/// Finishes a request once its answer came: copies out what the tracer
/// receives.
fn answer(c: &mut Ctx<'_>, request: u64, addr: u64, data: u64, link: LinkId) -> SysResult {
    let Some((ret, payload)) = c.p.tracees.take_reply(link) else {
        return wait_answer(c, link);
    };
    if ret < 0 {
        return Err(Errno(-ret as i32));
    }
    match request {
        req::PEEKTEXT | req::PEEKDATA | req::PEEKUSR | req::GETEVENTMSG => {
            c.write_mem(data, &payload[..8])?;
        }
        req::GETREGS | req::GETFPREGS | req::GETSIGINFO | req::GETSIGMASK => {
            c.write_mem(data, &payload)?
        }
        // do_arch_prctl_64's put_user of a base, into the tracer.
        req::ARCH_PRCTL if !payload.is_empty() => c.write_mem(addr, &payload)?,
        // Each record copied in turn: a fault ends the copy, an error only
        // for the first.
        req::PEEKSIGINFO => {
            for (i, rec) in payload.chunks_exact(SIGINFO).enumerate() {
                if c.write_mem(data + (i * SIGINFO) as u64, rec).is_err() {
                    return if i > 0 {
                        Ok(i as u64)
                    } else {
                        Err(Errno(EFAULT))
                    };
                }
            }
        }
        req::GET_RSEQ_CONFIGURATION => {
            let n = RSEQ_CONFIGURATION.min(addr) as usize;
            c.write_mem(data, &payload[..n])?;
        }
        // ptrace_get_syscall_info: as much of the structure as both the
        // caller's size and the stop's meaningful size allow.
        req::GET_SYSCALL_INFO => {
            let n = (ret as u64).min(addr) as usize;
            c.write_mem(data, &payload[..n])?;
        }
        // The filter's instructions, when the tracer gave a buffer.
        req::SECCOMP_GET_FILTER if data != 0 => {
            if c.write_mem(data, &payload).is_err() {
                return Err(Errno(EFAULT));
            }
        }
        // As much of struct seccomp_metadata as the tracer's size allows.
        req::SECCOMP_GET_METADATA => {
            let size = addr.min(SECCOMP_METADATA);
            if c.write_mem(data, &payload[..size as usize]).is_err() {
                return Err(Errno(EFAULT));
            }
            return Ok(size);
        }
        req::GETREGSET | req::SETREGSET => {
            let base = c.read_u64(data)?;
            if request == req::GETREGSET {
                c.write_mem(base, &payload)?;
            }
            let len = if request == req::GETREGSET {
                payload.len() as u64
            } else {
                u64::from_le_bytes(payload[..8].try_into().unwrap())
            };
            c.write_u64(data + 8, len)?;
        }
        _ => {}
    }
    Ok(ret as u64)
}
