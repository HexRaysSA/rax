//! The tracee's side of tracing (`kernel/ptrace.c`, `kernel/signal.c`,
//! Linux 6.19), and what a process does with the messages on its links: a
//! tracer's attach and requests, answered on the traced thread's own
//! memory and registers; a tracee's stops, departures, and answers, kept
//! for its tracer; a link's end. A traced thread's stops, the tracer's
//! verdicts on them, and its events are here too.

use super::super::abi::LinuxAbi;
use super::super::abi::errno_table::*;
use super::super::arch::GuestCpu;
use super::super::process::{ProcState, Thread, Threads};
use super::super::seccomp::FILTER_FLAG_LOG;
use super::super::signal::deliver::{self, Dest};
use super::super::signal::{
    SIG_IGN, SIGCHLD, SIGKILL, SIGSTOP, SIGTRAP, SigInfo, code, sa, sigmask,
};
use super::super::wait::Resume;
use super::{
    EVENT_EXEC, EVENT_EXIT, EVENT_STOP, EVENTMSG_SYSCALL_ENTRY, EVENTMSG_SYSCALL_EXIT, Exiting,
    LinkId, Mode, Msg, NSIG, PEEKSIGINFO_SHARED, RSEQ_CONFIGURATION, Resumption, SIGINFO, StopKind,
    Stopped, Traced, call, link_ids, link_mut, offered, opt, peer_pid, regs, req, resumes, send,
};

/// `arch_prctl` codes `do_arch_prctl_64` takes for another task.
mod arch {
    pub const SET_GS: u64 = 0x1001;
    pub const SET_FS: u64 = 0x1002;
    pub const GET_FS: u64 = 0x1003;
    pub const GET_GS: u64 = 0x1004;
}

/// Reads the messages that arrived on every link and acts on them: a
/// tracer records `PTRACE_TRACEME`, stops (with `SIGCHLD`, `CLD_TRAPPED`),
/// departures, and answers; a tracee attaches, answers requests, and
/// resumes. A link that ended detaches what went along it.
pub fn poll_links(p: &mut ProcState, th: &mut Threads<'_>) {
    for id in link_ids(p) {
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
                _ => p.pid,
            };
            p.tracees.add(tid, creator, link, false);
        }
        Msg::Stop {
            tid,
            code: exit,
            why,
            status,
            uid,
        } => {
            if let Some(t) = p.tracees.get_mut(tid) {
                t.stopped = Some(exit);
                t.reported = false;
                notify_trapped(p, th, tid, why, status, uid);
            }
        }
        Msg::Kill { sig, pid, uid } => {
            let info = SigInfo::kill(sig, code::SI_USER, pid, uid);
            let me = p.pid;
            deliver::send_signal(p, th, info, Dest::Process(me), false);
        }
        // A listening tracee is not in a stop its tracer sees.
        Msg::Listening { tid } => {
            if let Some(t) = p.tracees.get_mut(tid) {
                t.stopped = None;
                t.reported = false;
            }
        }
        // A traced thread that exited is its tracer's to reap (and to be
        // told of: do_notify_parent); a detached one is simply gone.
        Msg::Gone {
            tid,
            status: Some(status),
        } => {
            if let Some(t) = p.tracees.get_mut(tid) {
                t.exited = Some(status);
                t.stopped = None;
                let (why, si_status) = exit_cause(status);
                let chld = p.sigactions[(SIGCHLD - 1) as usize];
                if chld.handler != SIG_IGN {
                    let info = SigInfo::child(why, tid, p.creds.0, si_status, 0, 0);
                    let me = p.pid;
                    deliver::send_signal(p, th, info, Dest::Process(me), false);
                }
            }
        }
        Msg::Gone { tid, status: None } => p.tracees.remove(tid),
        // A tracee's fork: the link to the new tracee, whose tracer is the
        // thread tracing the one that forked it.
        Msg::Adopt {
            tid,
            parent,
            seized,
        } => {
            if let Some(fd) = link_mut(p, link).and_then(|l| l.take_fd()) {
                p.adopted.retain(|a| a.0 != tid);
                p.adopted.push((tid, super::Link::from_fd(fd)));
                let tracer = p.tracees.get(parent).map_or(p.pid, |t| t.tracer);
                p.tracees.add(tid, tracer, LinkId::Adopted(tid), seized);
            }
        }
        Msg::GroupExit { status } => {
            for t in p.tracees.list.iter_mut().filter(|t| t.link == link) {
                if t.exited.is_some() {
                    t.exited = Some(status);
                }
            }
        }
        // A thread its tracee made, traced by the thread tracing its maker.
        Msg::Traced {
            tid,
            parent,
            seized,
        } => {
            let tracer = p.tracees.get(parent).map_or(p.pid, |t| t.tracer);
            p.tracees.add(tid, tracer, link, seized);
        }
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

/// The `SIGCHLD` code and status of an exit with wait status `status`.
fn exit_cause(status: i32) -> (i32, i32) {
    match status & 0x7f {
        0 => (code::CLD_EXITED, (status >> 8) & 0xff),
        sig if status & 0x80 != 0 => (code::CLD_DUMPED, sig),
        sig => (code::CLD_KILLED, sig),
    }
}

/// `do_notify_parent_cldstop(..., why)` for the tracer: `SIGCHLD` unless
/// it is ignored or `SA_NOCLDSTOP`.
fn notify_trapped(
    p: &mut ProcState,
    th: &mut Threads<'_>,
    tid: i32,
    why: i32,
    status: i32,
    uid: u32,
) {
    let chld = p.sigactions[(SIGCHLD - 1) as usize];
    if chld.handler == SIG_IGN || chld.flags & sa::NOCLDSTOP != 0 {
        return;
    }
    let info = SigInfo::child(why, tid, uid, status, 0, 0);
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
    let any_state = request == req::KILL || request == req::INTERRUPT;
    if tr.link != link || (!any_state && !tr.stopped()) {
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
            let mut all = regs::get(&t.cpu, t.syscall, addr);
            all.truncate(data as usize);
            (0, all)
        }
        req::SETREGSET => match regs::set(&mut t.cpu, &mut t.syscall, addr, payload) {
            Ok(()) => (0, data.to_le_bytes().to_vec()),
            Err(e) => fail(e.0),
        },
        req::GETFPREGS => (0, regs::fpregs(&t.cpu)),
        req::SETFPREGS => match regs::set_fpregs(&mut t.cpu, payload) {
            Ok(()) => (0, Vec::new()),
            Err(e) => fail(e.0),
        },
        req::ARCH_PRCTL => arch_prctl(t, data, addr),
        req::PEEKSIGINFO => {
            let off = u64::from_le_bytes(payload[..8].try_into().unwrap());
            let flags = u32::from_le_bytes(payload[8..12].try_into().unwrap());
            let nr = i32::from_le_bytes(payload[12..16].try_into().unwrap());
            let pending = if flags & PEEKSIGINFO_SHARED != 0 {
                &p.shared_pending
            } else {
                &t.pending
            };
            let out: Vec<u8> = pending
                .records()
                .skip(usize::try_from(off).unwrap_or(usize::MAX))
                .take(nr as usize)
                .flat_map(|info| info.encode())
                .collect();
            ((out.len() / SIGINFO) as i64, out)
        }
        // seccomp_get_filter (the tracer holds CAP_SYS_ADMIN): the
        // instruction count of filter `addr`, and its instructions.
        req::SECCOMP_GET_FILTER => match t.seccomp.nth(addr) {
            Ok(f) => {
                let b = f.prog().iter().flat_map(|i| i.encode()).collect();
                (f.prog().len() as i64, b)
            }
            Err(e) => fail(e),
        },
        // seccomp_get_metadata: struct seccomp_metadata of filter
        // `filter_off`, its flags SECCOMP_FILTER_FLAG_LOG or none.
        req::SECCOMP_GET_METADATA => {
            let off = u64::from_le_bytes(payload[..8].try_into().unwrap());
            match t.seccomp.nth(off) {
                Ok(f) => {
                    let flags = if f.log { FILTER_FLAG_LOG } else { 0 };
                    let mut b = off.to_le_bytes().to_vec();
                    b.extend_from_slice(&u64::from(flags).to_le_bytes());
                    (0, b)
                }
                Err(e) => fail(e),
            }
        }
        req::GET_RSEQ_CONFIGURATION => {
            // ptrace_get_rseq_configuration: the registration, no flags.
            let (addr, len, sig) = t
                .rseq
                .as_ref()
                .map_or((0, 0, 0), |r| (r.addr, r.len, r.sig));
            let mut b = addr.to_le_bytes().to_vec();
            b.extend_from_slice(&len.to_le_bytes());
            b.extend_from_slice(&sig.to_le_bytes());
            b.extend_from_slice(&[0; 8]);
            (RSEQ_CONFIGURATION as i64, b)
        }
        req::GET_SYSCALL_INFO => {
            let s = tr.stop.as_ref();
            let op = call::op(s.and_then(|s| s.info.as_ref()), tr.message);
            let (b, size) = call::info(p.abi, &t.cpu, t.syscall, op, tr.compat, tr.message);
            (size as i64, b.to_vec())
        }
        req::SET_SYSCALL_INFO => {
            let op = call::op(tr.stop.as_ref().and_then(|s| s.info.as_ref()), tr.message);
            let compat = tr.compat;
            match call::set_info(&mut t.cpu, &mut t.syscall, compat, op, payload) {
                Ok(()) => (0, Vec::new()),
                Err(e) => fail(e.0),
            }
        }
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
        _ if resumes(request) && offered(p.abi, request) => {
            // ptrace_resume: the stepping is set before an architecture
            // that cannot step refuses (EIO), leaving the thread stopped.
            let steps = matches!(request, req::SINGLESTEP | req::SYSEMU_SINGLESTEP);
            let mode = Mode {
                syscall: request == req::SYSCALL,
                emu: matches!(request, req::SYSEMU | req::SYSEMU_SINGLESTEP),
                step: steps,
            };
            let riscv = p.abi == LinuxAbi::Riscv64;
            if let Some(tr) = t.ptrace.as_mut() {
                tr.mode = Mode {
                    step: mode.step && !riscv,
                    ..mode
                };
            }
            if steps && riscv {
                return fail(EIO);
            }
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
        // A trap without side effects on signals or job control: due at
        // once for a running thread (its sleep ends), after the current stop
        // for a stopped one, and now for a listening one. Seized only.
        req::INTERRUPT => {
            let Some(tr) = t.ptrace.as_mut().filter(|tr| tr.seized) else {
                return fail(EIO);
            };
            tr.trap_stop = true;
            trap_wake(t);
            (0, Vec::new())
        }
        // Stays stopped, out of the tracer's sight, until a job-control
        // change (or PTRACE_INTERRUPT) traps it again. Only a seized
        // thread in a PTRACE_EVENT_STOP trap listens.
        req::LISTEN => {
            let Some(tr) = t.ptrace.as_mut().filter(|tr| tr.seized) else {
                return fail(EIO);
            };
            let event_stop = tr
                .stop
                .as_ref()
                .and_then(|s| s.info.as_ref())
                .is_some_and(|i| i.code >> 8 == EVENT_STOP);
            if !event_stop {
                return fail(EIO);
            }
            tr.listening = true;
            let notify = tr.trap_notify;
            send(p, link, &Msg::Listening { tid });
            if notify {
                trap_wake(t);
            }
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

/// `do_arch_prctl_64` on a traced thread (x86-64): a base in user space
/// set (`EPERM` beyond it), or read for the tracer to store.
fn arch_prctl(t: &mut Thread, code: u64, value: u64) -> (i64, Vec<u8>) {
    let GuestCpu::X86_64(cpu) = &mut t.cpu else {
        return (-(EIO as i64), Vec::new());
    };
    let v = cpu.vcpu_mut();
    match code {
        arch::SET_FS | arch::SET_GS => {
            if value >= LinuxAbi::X86_64.task_size() {
                return (-(EPERM as i64), Vec::new());
            }
            if code == arch::SET_FS {
                v.set_fs_base(value);
            } else {
                v.set_gs_base(value);
            }
            (0, Vec::new())
        }
        arch::GET_FS => (0, v.fs_base().to_le_bytes().to_vec()),
        arch::GET_GS => (0, v.gs_base().to_le_bytes().to_vec()),
        _ => (-(EINVAL as i64), Vec::new()),
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
    // ptrace_disable and __ptrace_unlink: no stepping, no system-call
    // stops.
    tr.mode = Mode::default();
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
    // at once (PTRACE_KILL, or a PTRACE_CONT to its exit). So do the
    // records of tracees that exited, for the tracer to reap.
    p.tracees
        .list
        .retain(|t| t.link != link || t.exited.is_some());
    let mut kill = false;
    for t in th.iter_mut() {
        let Some(tr) = t.ptrace.as_ref() else {
            continue;
        };
        if tr.link != link || tr.tracer < 0 {
            continue;
        }
        kill |= tr.options & opt::EXITKILL != 0;
        // The stop's own exit code is what ptrace_stop returns: a
        // signal-delivery-stop's signal is delivered, a system-call stop's
        // SIGTRAP sent (none with TRACESYSGOOD's 0x80: not a signal).
        let code = tr
            .stop
            .as_ref()
            .filter(|s| s.resumed.is_none())
            .map(|s| s.code);
        if let Some(code) = code {
            resume(t, code);
        }
        detach(t);
    }
    if let Some(l) = link_mut(p, link) {
        l.closed = true;
    }
    // Links that only tracing made go with it.
    match link {
        LinkId::Adopted(pid) => p.adopted.retain(|a| a.0 != pid),
        LinkId::Tracer => p.tracer_link = None,
        _ => {}
    }
    if kill {
        let me = p.pid;
        deliver::send_signal(p, th, SigInfo::kernel(SIGKILL), Dest::Process(me), true);
    }
}

/// Stops a traced thread for its tracer with exit code `exit`,
/// `last_siginfo` `info`, and `ptrace_message` `message` (`ptrace_stop`),
/// telling the tracer (`CLD_TRAPPED`). A thread whose tracer is not a
/// `rax-user` process (no link) stays stopped.
pub fn stop(
    p: &mut ProcState,
    t: &mut Thread,
    exit: i32,
    info: Option<SigInfo>,
    kind: StopKind,
    message: u64,
) {
    let why = (code::CLD_TRAPPED, exit & 0x7f);
    report(p, t, exit, info, kind, message, why);
}

/// `ptrace_stop` with the tracer's `SIGCHLD` code and status: any stop
/// satisfies a pending `PTRACE_INTERRUPT` (`JOBCTL_TRAP_STOP`), and a
/// `PTRACE_EVENT_STOP` trap reports the job-control change that was due.
fn report(
    p: &mut ProcState,
    t: &mut Thread,
    exit: i32,
    info: Option<SigInfo>,
    kind: StopKind,
    message: u64,
    (why, status): (i32, i32),
) {
    let Some(tr) = t.ptrace.as_mut() else {
        return;
    };
    tr.message = message;
    tr.trap_stop = false;
    if info.as_ref().is_some_and(|i| i.code >> 8 == EVENT_STOP) {
        tr.trap_notify = false;
    }
    tr.stop = Some(Stopped {
        code: exit,
        info,
        kind,
        saved: None,
        resumed: None,
    });
    let link = tr.link;
    let (tid, uid) = (t.tid, p.creds.0);
    let m = Msg::Stop {
        tid,
        code: exit,
        why,
        status,
        uid,
    };
    send(p, link, &m);
}

/// `do_jobctl_trap`: a group stop's or a pending trap's stop, reported to
/// the tracer as `CLD_STOPPED` with the group's stop signal. A seized
/// thread traps with `PTRACE_EVENT_STOP` (its signal the group stop's, or
/// `SIGTRAP` when the process is not group-stopped); another stops with the
/// group stop's signal and no siginfo.
pub fn jobctl_trap(p: &mut ProcState, t: &mut Thread) {
    let Some(tr) = t.ptrace.as_ref() else {
        return;
    };
    let status = p.group_stop.unwrap_or(0) & 0x7f;
    if tr.seized {
        let signr = p.group_stop.unwrap_or(SIGTRAP);
        let exit = signr | (EVENT_STOP << 8);
        let info = SigInfo::kill(signr, exit, t.tid, p.creds.0);
        report(
            p,
            t,
            exit,
            Some(info),
            StopKind::Quiet,
            0,
            (code::CLD_STOPPED, status),
        );
    } else {
        let exit = p.group_stop.unwrap_or(SIGSTOP);
        report(
            p,
            t,
            exit,
            None,
            StopKind::Quiet,
            0,
            (code::CLD_STOPPED, status),
        );
    }
}

/// `ptrace_signal_wake_up` after a trap became due: an interruptible sleep
/// ends (`TIF_SIGPENDING`), and a listening thread leaves its stop to trap
/// again.
pub fn trap_wake(t: &mut Thread) {
    t.sigpending = true;
    let Some(tr) = t.ptrace.as_mut() else {
        return;
    };
    if std::mem::take(&mut tr.listening)
        && let Some(s) = tr.stop.as_mut()
        && s.resumed.is_none()
    {
        s.resumed = Some(Resumption::Continue(0));
    }
}

/// Another thread's part in a group stop that began (`do_signal_stop`): a
/// seized thread is told (`ptrace_trap_notify`), another traced one stops
/// with the group (`JOBCTL_STOP_PENDING`, then its trap).
pub fn join_group_stop(t: &mut Thread) {
    match t.ptrace.as_mut() {
        Some(tr) if tr.seized => trap_notify(t),
        Some(tr) => {
            tr.trap_stop = true;
            trap_wake(t);
        }
        None => {}
    }
}

/// `ptrace_trap_notify` for a seized thread: a job-control change is due
/// to be reported.
pub fn trap_notify(t: &mut Thread) {
    let Some(tr) = t.ptrace.as_mut().filter(|tr| tr.seized) else {
        return;
    };
    tr.trap_notify = true;
    trap_wake(t);
}

/// `ptrace_notify(exit, message)`: a stop for `SIGTRAP` whose siginfo
/// carries the exit code as its `si_code` and the thread as its sender.
pub fn notify(p: &mut ProcState, t: &mut Thread, exit: i32, message: u64, kind: StopKind) {
    let info = SigInfo::kill(SIGTRAP, exit, t.tid, p.creds.0);
    stop(p, t, exit, Some(info), kind, message);
}

/// `ptrace_report_syscall` at a system call's entry or exit: `SIGTRAP`,
/// with `0x80` under `PTRACE_O_TRACESYSGOOD`, and the direction as the
/// message.
pub fn syscall_stop(p: &mut ProcState, t: &mut Thread, exit: bool) {
    let Some(tr) = t.ptrace.as_ref() else {
        return;
    };
    let good = if tr.options & opt::TRACESYSGOOD != 0 {
        0x80
    } else {
        0
    };
    let (kind, message) = if exit {
        (StopKind::Exit, EVENTMSG_SYSCALL_EXIT)
    } else {
        let emu = tr.mode.emu;
        (StopKind::Entry { emu }, EVENTMSG_SYSCALL_ENTRY)
    };
    notify(p, t, SIGTRAP | good, message, kind);
}

/// Whether a thread is stopped for its tracer and not yet resumed (it does
/// not run).
pub fn parked(t: &Thread) -> bool {
    t.ptrace.as_ref().is_some_and(Traced::stopped)
}

/// What the tracer let a thread do (`mode`), untraced threads running
/// freely.
pub fn mode(t: &Thread) -> Mode {
    t.ptrace.as_ref().map_or(Mode::default(), |tr| tr.mode)
}

/// What becomes of a resumed stop's signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing more (cancelled, or the stop's signal is dropped).
    Drop,
    /// Deliver this signal (a signal-delivery-stop).
    Deliver(SigInfo),
    /// Send the thread this signal (`send_sig(signr, current, 1)`: from
    /// the kernel), after a system-call stop.
    Send(i32),
}

/// Takes a resumed stop: puts back what the stop changed (AArch64's `x7`),
/// drops tracing for a thread detached meanwhile, and decides on the
/// tracer's signal. `None` when the thread is in no resumed stop.
fn take_resumed(t: &mut Thread) -> Option<(Stopped, i32, i32)> {
    let tr = t.ptrace.as_mut()?;
    let Resumption::Continue(sig) = tr.stop.as_ref()?.resumed?;
    let s = tr.stop.take().expect("stop");
    let tracer = tr.tracer;
    if tracer < 0 {
        t.ptrace = None;
    }
    if let Some(x7) = s.saved
        && let GuestCpu::Aarch64(c) = &mut t.cpu
    {
        c.core_mut().set_x(7, x7);
    }
    Some((s, sig, tracer))
}

/// The tracer's verdict on a resumed stop, for `get_signal`
/// (`ptrace_signal` for a signal-delivery-stop): the signal to deliver,
/// its `siginfo` rewritten as sent by the tracer when the tracer changed
/// it; a system-call stop's signal to send; else nothing. `None` when
/// the thread is in no resumed stop.
pub fn take_verdict(p: &ProcState, t: &mut Thread) -> Option<Verdict> {
    let (s, sig, tracer) = take_resumed(t)?;
    Some(match s.kind {
        _ if sig == 0 => Verdict::Drop,
        StopKind::Signal => {
            let mut info = s.info.unwrap_or_else(|| SigInfo::kernel(sig));
            if sig != info.signo {
                let from = if tracer > 0 { tracer } else { p.ppid };
                info = SigInfo::kill(sig, code::SI_USER, from, p.creds.0);
            }
            Verdict::Deliver(info)
        }
        // send_sig refuses what is not a signal (TRACESYSGOOD's 0x80).
        StopKind::Entry { .. } | StopKind::Exit if (1..=NSIG as i32).contains(&sig) => {
            Verdict::Send(sig)
        }
        _ => Verdict::Drop,
    })
}

/// A resumed stop inside a system call, which the scheduler finishes
/// before the thread returns to user mode: a system-call-entry stop (the
/// call is made next) or an event stop (the call's exit work follows).
/// Returns the kind and the signal to send (0: none).
pub fn take_in_call(t: &mut Thread) -> Option<(StopKind, i32)> {
    let s = t.ptrace.as_ref()?.stop.as_ref()?;
    if s.resumed.is_none() || !in_call(s.kind) {
        return None;
    }
    let (s, sig, _) = take_resumed(t)?;
    let send = if s.kind.syscall() && (1..=NSIG as i32).contains(&sig) {
        sig
    } else {
        0
    };
    Some((s.kind, send))
}

/// A stop the scheduler finishes itself: inside a system call, or on the
/// way out of the thread.
fn in_call(kind: StopKind) -> bool {
    matches!(
        kind,
        StopKind::Entry { .. } | StopKind::Event | StopKind::Exiting | StopKind::Seccomp
    )
}

/// Whether a thread is in a resumed stop inside a system call.
pub fn resumed_in_call(t: &Thread) -> bool {
    t.ptrace
        .as_ref()
        .and_then(|tr| tr.stop.as_ref())
        .is_some_and(|s| s.resumed.is_some() && in_call(s.kind))
}

/// `ptrace_event(PTRACE_EVENT_EXEC, old_vpid)` after a successful
/// `execve`: an event stop with `PTRACE_O_TRACEEXEC`, else (not seized) a
/// `SIGTRAP` the thread sends itself.
pub fn exec_event(p: &mut ProcState, t: &mut Thread, old_tid: i32) {
    let Some(tr) = t.ptrace.as_mut() else {
        return;
    };
    if tr.options & opt::TRACEEXEC != 0 {
        let exit = SIGTRAP | (EVENT_EXEC << 8);
        notify(p, t, exit, old_tid as u64, StopKind::Event);
    } else if !tr.seized {
        let info = SigInfo::kill(SIGTRAP, code::SI_USER, p.pid, p.creds.0);
        t.pending.enqueue(info);
        t.sigpending = deliver::recalc_sigpending(p, t);
    }
}

/// Makes event `event` (with `message`) due as the thread's system call
/// finishes, if its tracer asked for it (`ptrace_event_pid` after
/// `clone`).
pub fn due_event(t: &mut Thread, event: i32, message: u64) {
    if let Some(tr) = t
        .ptrace
        .as_mut()
        .filter(|tr| tr.tracer >= 0 && tr.event_enabled(event))
    {
        tr.events.push_back((event, message));
    }
}

/// Stops the thread for the next event due as its call finishes
/// (`SIGTRAP | event << 8`, its message). True when it stopped.
pub fn event_stop(p: &mut ProcState, t: &mut Thread) -> bool {
    let Some((event, message)) = t.ptrace.as_mut().and_then(|tr| tr.events.pop_front()) else {
        return false;
    };
    notify(p, t, SIGTRAP | (event << 8), message, StopKind::Event);
    true
}

/// How a forked process is traced (`ptrace_init_task` with `kernel_clone`'s
/// event): by the forker's tracer, along a link of its own.
pub struct ForkTrace {
    /// The event to report (`PTRACE_EVENT_FORK`, `_VFORK`, or `_CLONE`),
    /// when the tracer asked for it (none for `CLONE_PTRACE` alone).
    pub event: Option<i32>,
    /// The tracer's PID and the forker's tracing.
    pub tracer: i32,
    pub seized: bool,
    pub options: u64,
    /// The new link: the tracer's end, then the child's.
    pub ends: (super::Link, super::Link),
}

/// Whether and how a process thread `t` forks is traced: the event is
/// `PTRACE_EVENT_VFORK` with `CLONE_VFORK`, `PTRACE_EVENT_CLONE` for an exit
/// signal other than `SIGCHLD`, else `PTRACE_EVENT_FORK`; traced when the
/// tracer asked for it or `CLONE_PTRACE` asks, never with `CLONE_UNTRACED`
/// (which drops the event only).
pub fn fork_trace(
    t: &Thread,
    vfork: bool,
    untraced: bool,
    ptrace_flag: bool,
    exit_signal: u64,
) -> Result<Option<ForkTrace>, super::super::abi::errno::Errno> {
    use super::{EVENT_CLONE, EVENT_FORK, EVENT_VFORK};
    let Some(tr) = t.ptrace.as_ref().filter(|tr| tr.tracer >= 0) else {
        return Ok(None);
    };
    let event = if vfork {
        EVENT_VFORK
    } else if exit_signal != SIGCHLD as u64 {
        EVENT_CLONE
    } else {
        EVENT_FORK
    };
    let event = (!untraced && tr.event_enabled(event)).then_some(event);
    if event.is_none() && !ptrace_flag {
        return Ok(None);
    }
    Ok(Some(ForkTrace {
        event,
        tracer: tr.tracer,
        seized: tr.seized,
        options: tr.options,
        ends: super::Link::pair()?,
    }))
}

/// The forked process's side: traced along its end of the new link,
/// starting with `SIGSTOP` (a trap when seized).
pub fn forked_traced(p: &mut ProcState, t: &mut Thread, trace: ForkTrace) {
    let mut tr = Traced::new(trace.tracer, LinkId::Tracer, trace.seized, trace.options);
    if trace.seized {
        tr.trap_stop = true;
    } else {
        t.pending
            .enqueue(SigInfo::kill(SIGSTOP, code::SI_USER, 0, 0));
    }
    t.sigpending = true;
    t.ptrace = Some(tr);
    p.tracer_link = Some((trace.tracer, trace.ends.1));
}

/// The forker's side: the tracer gets its end of the link to the new
/// process, then the forker's event (with the new PID) is due.
pub fn forker_traced(p: &mut ProcState, t: &mut Thread, trace: ForkTrace, pid: i32) {
    let Some(tr) = t.ptrace.as_ref() else {
        return;
    };
    let m = Msg::Adopt {
        tid: pid,
        parent: t.tid,
        seized: trace.seized,
    };
    let link = tr.link;
    if let Some(l) = link_mut(p, link) {
        l.send_passing(&m, &trace.ends.0);
    }
    if let Some(event) = trace.event {
        due_event(t, event, pid as u64);
    }
}

/// Whether a thread about to exit stops for `PTRACE_EVENT_EXIT`: its
/// tracer asked for it and it is not dying of `SIGKILL` (`ptrace_stop`
/// does not stop a thread with a fatal signal pending).
pub fn exit_traced(p: &ProcState, t: &Thread) -> bool {
    t.ptrace
        .as_ref()
        .is_some_and(|tr| tr.tracer >= 0 && tr.event_enabled(EVENT_EXIT))
        && !t.pending.contains(SIGKILL)
        && !p.shared_pending.contains(SIGKILL)
}

/// `ptrace_event(PTRACE_EVENT_EXIT, code)` in `do_exit`: stops the thread,
/// the exit code (`(status & 0xff) << 8`, or the signal) as the message,
/// keeping how it ends for its resumption.
pub fn exit_event(p: &mut ProcState, t: &mut Thread, code: i32, how: Exiting) {
    if let Some(tr) = t.ptrace.as_mut() {
        tr.exiting = Some(how);
    }
    notify(
        p,
        t,
        SIGTRAP | (EVENT_EXIT << 8),
        code as u32 as u64,
        StopKind::Exiting,
    );
}

/// A traced thread ends (`exit_notify`): its tracer is told, with the wait
/// status when the tracer is to reap it (a thread other than the leader,
/// or a leader whose tracer is not its parent, which reaps it anyway).
pub fn gone(p: &mut ProcState, t: &Thread, status: i32) {
    let Some(tr) = t.ptrace.as_ref().filter(|tr| tr.tracer >= 0) else {
        return;
    };
    let reaped = t.tid != p.pid || tr.link != LinkId::Parent;
    let m = Msg::Gone {
        tid: t.tid,
        status: reaped.then_some(status),
    };
    let link = tr.link;
    send(p, link, &m);
}

/// A group exit begins with `status` (`do_group_exit`): the tracers along
/// every link learn of it, for the threads they have yet to reap.
pub fn group_exit(p: &mut ProcState, status: i32) {
    for link in link_ids(p) {
        send(p, link, &Msg::GroupExit { status });
    }
}

/// Whether the thread's seccomp is suspended: its tracer set
/// `PTRACE_O_SUSPEND_SECCOMP` (`PT_SUSPEND_SECCOMP`, which
/// `__secure_computing` honors before any mode).
pub fn seccomp_suspended(t: &Thread) -> bool {
    t.ptrace
        .as_ref()
        .is_some_and(|tr| tr.tracer >= 0 && tr.options & opt::SUSPEND_SECCOMP != 0)
}

/// `/proc/<pid>/status`'s `TracerPid` for a thread.
pub fn tracer_pid(t: &Thread) -> i32 {
    t.ptrace.as_ref().map_or(0, |tr| tr.tracer.max(0))
}
