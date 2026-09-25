//! `ptrace` (`kernel/ptrace.c`, Linux 6.19): the tracer's requests, and the
//! tracee's side of tracing: its answers, its stops, and going on when
//! resumed. The links, messages, and records are
//! [`ptrace`](super::super::ptrace).
//!
//! A request that needs the tracee travels along the link and the tracer
//! sleeps until the answer comes back; the tracee answers from
//! [`poll_links`], which the process runs as it looks for outside events,
//! whether its traced thread is stopped or not. Resuming marks the tracee
//! running at once, so a stop that follows is not lost.

use super::super::abi::LinuxAbi;
use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::process::{ProcState, Thread, Threads};
use super::super::ptrace::{
    EVENT_EXEC, Link, LinkId, Msg, Resumption, Stopped, Traced, opt, regs, req, stop_status,
};
use super::super::signal::deliver::{self, Dest};
use super::super::signal::{
    SIG_IGN, SIGCHLD, SIGKILL, SIGSTOP, SIGTRAP, SigInfo, code, sa, sigmask,
};
use super::super::wait::{Resume, Wait};
use super::{Ctx, SysResult};

/// `_NSIG`: a resumption's signal beyond it is `EIO` (`valid_signal`).
const NSIG: u64 = 64;
/// `sizeof(sigset_t)`.
const SIGSET: u64 = 8;
/// `sizeof(siginfo_t)`.
const SIGINFO: usize = 128;

/// The link with this identity, if it is still there.
pub fn link_mut(p: &mut ProcState, id: LinkId) -> Option<&mut Link> {
    match id {
        LinkId::Parent => p.parent_link.as_mut(),
        LinkId::Child(pid) => p.children.get_mut(pid).and_then(|c| c.link.as_mut()),
    }
}

/// The PID at the other end of a link.
fn peer_pid(p: &ProcState, id: LinkId) -> i32 {
    match id {
        LinkId::Parent => p.ppid,
        LinkId::Child(pid) => pid,
    }
}

/// The descriptors of every link, for a sleep that a message must end.
pub fn link_fds(p: &ProcState) -> Vec<(i32, bool, bool)> {
    let mut fds: Vec<(i32, bool, bool)> = p
        .children
        .list
        .iter()
        .filter_map(|c| c.link.as_ref())
        .map(|l| (l.fd(), true, false))
        .collect();
    if let Some(l) = &p.parent_link {
        fds.push((l.fd(), true, false));
    }
    fds
}

/// Sends a message along a link; false when it is gone.
fn send(p: &mut ProcState, id: LinkId, m: &Msg) -> bool {
    link_mut(p, id).is_some_and(|l| l.send(m))
}

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
/// `PTRACE_O_SUSPEND_SECCOMP`, which only a kernel with checkpoint and
/// restore offers to `CAP_SYS_ADMIN`: not offered here (`EINVAL`).
fn check_options(_c: &Ctx<'_>, data: u64) -> Result<(), Errno> {
    if data & !opt::MASK != 0 || data & opt::SUSPEND_SECCOMP != 0 {
        return Err(Errno(EINVAL));
    }
    Ok(())
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

/// A register set's element and whole sizes on this ABI (`EINVAL` for one
/// it does not have).
fn regset(abi: LinuxAbi, nt: u64) -> Result<(u64, u64), Errno> {
    let size = match (nt, abi) {
        (regs::NT_PRSTATUS, LinuxAbi::X86_64) => 27 * 8,
        (regs::NT_PRSTATUS, LinuxAbi::Aarch64) => 34 * 8,
        (regs::NT_PRSTATUS, LinuxAbi::Riscv64) => 32 * 8,
        _ => return Err(Errno(EINVAL)),
    };
    Ok((8, size))
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
            let (unit, size) = regset(c.p.abi, addr)?;
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
        req::GETSIGINFO | req::GETEVENTMSG => {}
        req::SETSIGINFO => payload = c.read_mem(data, SIGINFO)?,
        req::SETOPTIONS => check_options(c, data)?,
        req::GETSIGMASK | req::SETSIGMASK => {
            if addr != SIGSET {
                return Err(Errno(EINVAL));
            }
            if request == req::SETSIGMASK {
                payload = c.read_mem(data, SIGSET as usize)?;
            }
        }
        req::CONT | req::DETACH => {
            if data > NSIG {
                return Err(Errno(EIO));
            }
        }
        req::KILL => {}
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
    // after a detach it is no tracee.
    match request {
        req::CONT | req::KILL => {
            if let Some(t) = c.p.tracees.get_mut(tracee.tid) {
                t.stopped = None;
                t.reported = false;
            }
        }
        req::DETACH => c.p.tracees.remove(tracee.tid),
        _ => {}
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
        req::GETREGS | req::GETSIGINFO | req::GETSIGMASK => c.write_mem(data, &payload)?,
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
    let _ = addr;
    Ok(ret as u64)
}

/// Reads the messages that arrived on every link and acts on them: a
/// tracer records `PTRACE_TRACEME`, stops (with `SIGCHLD`, `CLD_TRAPPED`),
/// departures, and answers; a tracee attaches, answers requests, and
/// resumes. A link that ended detaches what went along it.
pub fn poll_links(p: &mut ProcState, th: &mut Threads<'_>) {
    let mut ids: Vec<LinkId> = p
        .children
        .list
        .iter()
        .filter(|c| c.link.is_some())
        .map(|c| LinkId::Child(c.pid))
        .collect();
    if p.parent_link.is_some() {
        ids.push(LinkId::Parent);
    }
    for id in ids {
        let (msgs, closed) = match link_mut(p, id) {
            Some(l) if !l.closed => {
                let m = l.recv();
                (m, l.closed)
            }
            _ => continue,
        };
        for m in msgs {
            on_message(p, th, id, m);
        }
        if closed {
            link_ended(p, th, id);
        }
    }
}

fn on_message(p: &mut ProcState, th: &mut Threads<'_>, link: LinkId, m: Msg) {
    match m {
        Msg::Traceme { tid } => {
            // The tracer is the thread that made the child.
            let creator = match link {
                LinkId::Child(pid) => p.children.get_mut(pid).map_or(p.pid, |c| c.creator),
                LinkId::Parent => p.pid,
            };
            p.tracees.add(tid, creator, link, false);
        }
        Msg::Stop { tid, code: exit } => {
            if let Some(t) = p.tracees.get_mut(tid) {
                t.stopped = Some(exit);
                t.reported = false;
                notify_trapped(p, th, tid, exit);
            }
        }
        Msg::Gone { tid } => p.tracees.remove(tid),
        Msg::Reply { ret, payload } => p.tracees.replies.push((link, ret, payload)),
        Msg::Attach {
            tid,
            seize,
            options,
            uid,
            gid,
            capable,
        } => {
            let ret = serve_attach(p, th, link, tid, seize, options, (uid, gid, capable));
            send(
                p,
                link,
                &Msg::Reply {
                    ret,
                    payload: Vec::new(),
                },
            );
        }
        Msg::Request {
            tid,
            req: request,
            addr,
            data,
            payload,
        } => {
            let (ret, out) = serve(p, th, link, tid, request, addr, data, &payload);
            send(p, link, &Msg::Reply { ret, payload: out });
        }
    }
    // A wait or a request asleep for this looks again.
    for t in th.iter_mut() {
        if let Some(b) = t.blocked.as_mut()
            && matches!(b.resume, Resume::WaitChild | Resume::Ptrace { .. })
        {
            b.woken = true;
        }
    }
}

/// `do_notify_parent_cldstop(..., CLD_TRAPPED)` for the tracer: `SIGCHLD`
/// unless it is ignored or `SA_NOCLDSTOP`.
fn notify_trapped(p: &mut ProcState, th: &mut Threads<'_>, tid: i32, exit: i32) {
    let chld = p.sigactions[(SIGCHLD - 1) as usize];
    if chld.handler == SIG_IGN || chld.flags & sa::NOCLDSTOP != 0 {
        return;
    }
    let info = SigInfo::child(code::CLD_TRAPPED, tid, p.creds.0, exit & 0x7f, 0, 0);
    let me = p.pid;
    deliver::send_signal(p, th, info, Dest::Process(me), false);
}

/// `ptrace_attach` in the tracee: its thread, not yet traced, and a tracer
/// `__ptrace_may_access` lets in (its UID and GID the thread's, or
/// `CAP_SYS_PTRACE`; the process dumpable unless the tracer is capable).
/// `PTRACE_ATTACH` sends the thread `SIGSTOP`.
fn serve_attach(
    p: &mut ProcState,
    th: &mut Threads<'_>,
    link: LinkId,
    tid: i32,
    seize: bool,
    options: u64,
    (uid, gid, capable): (u32, u32, bool),
) -> i64 {
    let tracer = peer_pid(p, link);
    let creds = p.creds;
    let dumpable = p.dumpable == 1;
    let Some(t) = th.get_mut(tid) else {
        return -(ESRCH as i64);
    };
    let same = uid == creds.0 && uid == creds.1 && gid == creds.2 && gid == creds.3;
    if !(same || capable) || !(dumpable || capable) {
        return -(EPERM as i64);
    }
    if t.ptrace.is_some() {
        return -(EPERM as i64);
    }
    t.ptrace = Some(Traced::new(tracer, link, seize, options));
    if !seize {
        let info = SigInfo::kernel(SIGSTOP);
        deliver::send_signal(p, th, info, Dest::Thread(tid), false);
    }
    0
}

/// A request to a stopped tracee: its answer and bytes.
#[allow(clippy::too_many_arguments)]
fn serve(
    p: &mut ProcState,
    th: &mut Threads<'_>,
    link: LinkId,
    tid: i32,
    request: u64,
    addr: u64,
    data: u64,
    payload: &[u8],
) -> (i64, Vec<u8>) {
    let fail = |e: i32| (-(e as i64), Vec::new());
    let Some(t) = th.get_mut(tid) else {
        return fail(ESRCH);
    };
    let Some(tr) = t.ptrace.as_ref() else {
        return fail(ESRCH);
    };
    if tr.link != link || (request != req::KILL && !tr.stopped()) {
        return fail(ESRCH);
    }
    match request {
        req::PEEKTEXT | req::PEEKDATA => {
            // ptrace_access_vm with FOLL_FORCE: any mapped page.
            let mut b = [0u8; 8];
            match p.space.read_raw(addr, &mut b) {
                Ok(()) => (0, b.to_vec()),
                Err(_) => fail(EIO),
            }
        }
        req::POKETEXT | req::POKEDATA => match p.space.write_raw(addr, &data.to_le_bytes()) {
            Ok(()) => (0, Vec::new()),
            Err(_) => fail(EIO),
        },
        req::PEEKUSR => match regs::peek_user(&t.cpu, t.syscall, addr) {
            Ok(v) => (0, v.to_le_bytes().to_vec()),
            Err(e) => fail(e.0),
        },
        req::POKEUSR => match regs::poke_user(&mut t.cpu, &mut t.syscall, addr, data) {
            Ok(()) => (0, Vec::new()),
            Err(e) => fail(e.0),
        },
        req::GETREGS => (0, regs::prstatus(&t.cpu, t.syscall)),
        req::SETREGS => match regs::set_prstatus(&mut t.cpu, &mut t.syscall, payload) {
            Ok(()) => (0, Vec::new()),
            Err(e) => fail(e.0),
        },
        req::GETREGSET => {
            let mut all = regs::prstatus(&t.cpu, t.syscall);
            all.truncate(data as usize);
            (0, all)
        }
        req::SETREGSET => match regs::set_prstatus(&mut t.cpu, &mut t.syscall, payload) {
            Ok(()) => (0, data.to_le_bytes().to_vec()),
            Err(e) => fail(e.0),
        },
        // ptrace_getsiginfo and ptrace_setsiginfo: a stop without
        // last_siginfo (a group stop) has none to give or take (EINVAL).
        req::GETSIGINFO => match tr.stop.as_ref().and_then(|s| s.info.as_ref()) {
            Some(info) => (0, info.encode().to_vec()),
            None => fail(EINVAL),
        },
        req::SETSIGINFO => match t.ptrace.as_mut().and_then(|tr| tr.stop.as_mut()) {
            Some(s) if s.info.is_some() => {
                s.info = Some(SigInfo::decode(payload));
                (0, Vec::new())
            }
            _ => fail(EINVAL),
        },
        req::GETEVENTMSG => (0, tr.message.to_le_bytes().to_vec()),
        req::SETOPTIONS => {
            if let Some(tr) = t.ptrace.as_mut() {
                tr.options = data;
            }
            (0, Vec::new())
        }
        req::GETSIGMASK => (0, t.sigmask.to_le_bytes().to_vec()),
        req::SETSIGMASK => {
            let mask = u64::from_le_bytes(payload[..8].try_into().unwrap());
            t.sigmask = mask & !(sigmask(SIGKILL) | sigmask(SIGSTOP));
            t.saved_sigmask = None;
            t.sigpending = deliver::recalc_sigpending(p, t);
            (0, Vec::new())
        }
        req::CONT => {
            resume(t, data as i32);
            (0, Vec::new())
        }
        req::DETACH => {
            // __ptrace_detach: the thread goes on with the tracer's signal
            // and is traced no more.
            resume(t, data as i32);
            detach(t);
            (0, Vec::new())
        }
        req::KILL => {
            // ptrace_resume(child, PTRACE_KILL, SIGKILL).
            if t.ptrace.as_ref().is_some_and(Traced::stopped) {
                resume(t, SIGKILL);
            }
            let me = p.pid;
            deliver::send_signal(p, th, SigInfo::kernel(SIGKILL), Dest::Process(me), true);
            (0, Vec::new())
        }
        _ => fail(EIO),
    }
}

/// `ptrace_resume` for a stop: the tracer's signal (`exit_code`) is kept
/// for the thread to take on.
fn resume(t: &mut Thread, sig: i32) {
    if let Some(s) = t.ptrace.as_mut().and_then(|tr| tr.stop.as_mut()) {
        s.resumed = Some(Resumption::Continue(sig));
    }
}

/// Detaches a thread: at once when it is running, else once it has taken
/// its resumption (its record marked with no tracer).
fn detach(t: &mut Thread) {
    let Some(tr) = t.ptrace.as_mut() else {
        return;
    };
    if tr.stop.is_none() {
        t.ptrace = None;
        return;
    }
    tr.options = 0;
    tr.seized = false;
    tr.tracer = -1;
}

/// A link ended: its tracees are gone for the tracer; for the tracee, a
/// tracer that went is `exit_ptrace`: its threads are detached, stopped
/// ones going on with the signal they stopped for, or killed with
/// `PTRACE_O_EXITKILL`.
fn link_ended(p: &mut ProcState, th: &mut Threads<'_>, link: LinkId) {
    // Answers that came before the end stand: a tracee may answer and die
    // at once (PTRACE_KILL, or a PTRACE_CONT to its exit).
    p.tracees.list.retain(|t| t.link != link);
    let mut kill = false;
    for t in th.iter_mut() {
        let Some(tr) = t.ptrace.as_ref() else {
            continue;
        };
        if tr.link != link || tr.tracer < 0 {
            continue;
        }
        kill |= tr.options & opt::EXITKILL != 0;
        let code = tr
            .stop
            .as_ref()
            .filter(|s| s.resumed.is_none())
            .map(|s| s.code);
        if let Some(code) = code {
            resume(t, code & 0x7f);
        }
        detach(t);
    }
    if let Some(l) = link_mut(p, link) {
        l.closed = true;
    }
    if kill {
        let me = p.pid;
        deliver::send_signal(p, th, SigInfo::kernel(SIGKILL), Dest::Process(me), true);
    }
}

/// Stops a traced thread for its tracer with exit code `exit` and
/// `last_siginfo` `info` (`ptrace_stop`), telling the tracer. A thread
/// whose tracer is not a `rax-user` process (no link) stays stopped.
pub fn stop(p: &mut ProcState, t: &mut Thread, exit: i32, info: Option<SigInfo>, signal: bool) {
    let Some(tr) = t.ptrace.as_mut() else {
        return;
    };
    tr.stop = Some(Stopped {
        code: exit,
        info,
        signal,
        resumed: None,
    });
    let link = tr.link;
    let tid = t.tid;
    send(p, link, &Msg::Stop { tid, code: exit });
}

/// Whether a thread is stopped for its tracer and not yet resumed (it does
/// not run).
pub fn parked(t: &Thread) -> bool {
    t.ptrace.as_ref().is_some_and(Traced::stopped)
}

/// The tracer's verdict on a resumed signal-delivery-stop, for
/// `get_signal` (`ptrace_signal`): `None` when there is none; `Some(None)`
/// when the tracer cancelled the signal or the stop was no signal's; else
/// the signal to deliver, its `siginfo` rewritten as sent by the tracer
/// when the tracer changed it. A detached thread leaves tracing here.
pub fn take_verdict(p: &ProcState, t: &mut Thread) -> Option<Option<SigInfo>> {
    let tr = t.ptrace.as_mut()?;
    let s = tr.stop.as_ref()?;
    let Resumption::Continue(sig) = s.resumed?;
    let s = tr.stop.take().expect("stop");
    if tr.tracer < 0 {
        t.ptrace = None;
    }
    if !s.signal || sig == 0 {
        return Some(None);
    }
    let mut info = s.info.unwrap_or_else(|| SigInfo::kernel(sig));
    if sig != info.signo {
        info = SigInfo::kill(sig, code::SI_USER, p.ppid, p.creds.0);
    }
    Some(Some(info))
}

/// `ptrace_event(PTRACE_EVENT_EXEC, old_vpid)` after a successful
/// `execve`: an event stop with `PTRACE_O_TRACEEXEC`, else (not seized) a
/// `SIGTRAP` the thread sends itself.
pub fn exec_event(p: &mut ProcState, t: &mut Thread, old_tid: i32) {
    let Some(tr) = t.ptrace.as_mut() else {
        return;
    };
    if tr.options & opt::TRACEEXEC != 0 {
        tr.message = old_tid as u64;
        let exit = SIGTRAP | (EVENT_EXEC << 8);
        let info = SigInfo::kill(SIGTRAP, exit, t.tid, p.creds.0);
        stop(p, t, exit, Some(info), false);
    } else if !tr.seized {
        let info = SigInfo::kill(SIGTRAP, code::SI_USER, p.pid, p.creds.0);
        t.pending.enqueue(info);
        t.sigpending = deliver::recalc_sigpending(p, t);
    }
}

/// `/proc/<pid>/status`'s `TracerPid` for a thread.
pub fn tracer_pid(t: &Thread) -> i32 {
    t.ptrace.as_ref().map_or(0, |tr| tr.tracer.max(0))
}

/// The wait status of a tracee's unreported stop.
pub fn tracee_status(code: i32) -> i32 {
    stop_status(code)
}
