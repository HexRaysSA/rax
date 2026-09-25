//! Process tracing between `rax-user` processes (`kernel/ptrace.c`,
//! Linux 6.19): the links tracing travels along, the messages on them, and
//! each side's record.
//!
//! A tracer and its tracee are separate host processes, so the tracee
//! carries out its tracer's requests on its own memory and registers while
//! its traced thread is stopped. Every process has a link to its parent and
//! one to each child it forks (an `AF_UNIX` stream pair made at `fork`),
//! and tracing goes along them: a process traces its children or its
//! parent. Nothing else is within reach (`EPERM`, as a denied
//! `ptrace_may_access`), and a thread of another process is reached only as
//! that process's main thread.
//!
//! A message is a frame: a little-endian `u32` length, then a tag byte and
//! the fields. The tracee tells its tracer of a `PTRACE_TRACEME` and of
//! each stop, and answers requests; the tracer attaches, asks, and resumes.
//! A link that ends (its process exited) detaches whatever went along it.
//!
//! [`regs`] lays out the register sets, [`call`] reads and writes the system
//! call a stopped thread is in, [`tracee`] is the tracee's side (with what a
//! process does with its links' messages), and the scheduler's side of
//! system-call stops and single steps is in `stops`. The tracer's requests
//! are the `ptrace` system call (`syscall::ptrace`).

pub mod call;
pub mod regs;
mod stops;
pub mod tracee;

use std::os::fd::{AsRawFd, OwnedFd};

use super::abi::LinuxAbi;
use super::abi::errno::Errno;
use super::abi::errno_table::*;
use super::process::ProcState;
use super::signal::SigInfo;

/// `PTRACE_*` requests (`include/uapi/linux/ptrace.h` and the
/// architectures' `asm/ptrace-abi.h`).
pub mod req {
    pub const TRACEME: u64 = 0;
    pub const PEEKTEXT: u64 = 1;
    pub const PEEKDATA: u64 = 2;
    pub const PEEKUSR: u64 = 3;
    pub const POKETEXT: u64 = 4;
    pub const POKEDATA: u64 = 5;
    pub const POKEUSR: u64 = 6;
    pub const CONT: u64 = 7;
    pub const KILL: u64 = 8;
    pub const SINGLESTEP: u64 = 9;
    /// x86-64 only.
    pub const GETREGS: u64 = 12;
    pub const SETREGS: u64 = 13;
    pub const GETFPREGS: u64 = 14;
    pub const SETFPREGS: u64 = 15;
    pub const ATTACH: u64 = 16;
    pub const DETACH: u64 = 17;
    pub const SYSCALL: u64 = 24;
    /// x86-64 only (`arch_prctl` on the tracee, its arguments swapped).
    pub const ARCH_PRCTL: u64 = 30;
    /// x86-64 only.
    pub const SYSEMU: u64 = 31;
    pub const SYSEMU_SINGLESTEP: u64 = 32;
    /// x86-64 only (branch stepping, not offered here).
    pub const SINGLEBLOCK: u64 = 33;
    pub const SETOPTIONS: u64 = 0x4200;
    pub const GETEVENTMSG: u64 = 0x4201;
    pub const GETSIGINFO: u64 = 0x4202;
    pub const SETSIGINFO: u64 = 0x4203;
    pub const GETREGSET: u64 = 0x4204;
    pub const SETREGSET: u64 = 0x4205;
    pub const SEIZE: u64 = 0x4206;
    pub const INTERRUPT: u64 = 0x4207;
    pub const LISTEN: u64 = 0x4208;
    pub const PEEKSIGINFO: u64 = 0x4209;
    /// `PTRACE_SECCOMP_GET_FILTER` and `PTRACE_SECCOMP_GET_METADATA`
    /// (checkpoint and restore).
    pub const SECCOMP_GET_FILTER: u64 = 0x420c;
    pub const SECCOMP_GET_METADATA: u64 = 0x420d;
    pub const GETSIGMASK: u64 = 0x420a;
    pub const SETSIGMASK: u64 = 0x420b;
    pub const GET_SYSCALL_INFO: u64 = 0x420e;
    pub const GET_RSEQ_CONFIGURATION: u64 = 0x420f;
    pub const SET_SYSCALL_INFO: u64 = 0x4212;
}

/// `PTRACE_O_*` options and `PTRACE_O_MASK`.
pub mod opt {
    pub const TRACESYSGOOD: u64 = 1;
    pub const TRACEFORK: u64 = 0x2;
    pub const TRACEVFORK: u64 = 0x4;
    pub const TRACECLONE: u64 = 0x8;
    pub const TRACEEXEC: u64 = 0x10;
    pub const TRACEVFORKDONE: u64 = 0x20;
    pub const TRACEEXIT: u64 = 0x40;
    pub const TRACESECCOMP: u64 = 0x80;
    pub const EXITKILL: u64 = 0x10_0000;
    pub const SUSPEND_SECCOMP: u64 = 0x20_0000;
    pub const MASK: u64 = 0xff | EXITKILL | SUSPEND_SECCOMP;
}

/// `PTRACE_EVENT_*`: an event's number, whose option is `1 << event`
/// (`PT_EVENT_FLAG`).
pub const EVENT_FORK: i32 = 1;
pub const EVENT_VFORK: i32 = 2;
pub const EVENT_CLONE: i32 = 3;
pub const EVENT_EXEC: i32 = 4;
pub const EVENT_VFORK_DONE: i32 = 5;
pub const EVENT_EXIT: i32 = 6;
pub const EVENT_SECCOMP: i32 = 7;
/// `PTRACE_EVENT_STOP`: a seized tracee's group stop or trap.
pub const EVENT_STOP: i32 = 128;

/// `PTRACE_EVENTMSG_SYSCALL_ENTRY` and `PTRACE_EVENTMSG_SYSCALL_EXIT`: the
/// message of a system-call stop.
pub const EVENTMSG_SYSCALL_ENTRY: u64 = 1;
pub const EVENTMSG_SYSCALL_EXIT: u64 = 2;

/// Which link a relationship goes along.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkId {
    /// The link to this process's parent.
    Parent,
    /// The link to the child with this PID.
    Child(i32),
    /// The link to a tracee with this PID that is not a child (its parent,
    /// a tracee, passed the link over when it forked it).
    Adopted(i32),
    /// The link to this process's tracer when that is neither its parent
    /// nor a child (it came from the parent that forked it traced).
    Tracer,
}

/// A message on a link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    /// `PTRACE_TRACEME`: the sender's thread `tid` is traced by the
    /// receiver.
    Traceme { tid: i32 },
    /// Attach to thread `tid` (`PTRACE_ATTACH`, or `PTRACE_SEIZE` with
    /// `options`) for a tracer of these credentials (its UID, its GID, and
    /// whether it has `CAP_SYS_PTRACE`); answered by a [`Msg::Reply`].
    Attach {
        tid: i32,
        seize: bool,
        options: u64,
        uid: u32,
        gid: u32,
        capable: bool,
    },
    /// Thread `tid` stopped for its tracer: the wait status's exit code
    /// (`exit_code`: a signal, `SIGTRAP | event << 8`, ...), and the
    /// `SIGCHLD` the tracer gets: its `si_code` (`CLD_TRAPPED`, or
    /// `CLD_STOPPED` for a group stop or a trap), `si_status`, and the
    /// thread's UID (`si_uid`).
    Stop {
        tid: i32,
        code: i32,
        why: i32,
        status: i32,
        uid: u32,
    },
    /// Thread `tid` listens (`PTRACE_LISTEN`): still stopped, but not in a
    /// stop its tracer sees until it traps again.
    Listening { tid: i32 },
    /// `kill(pid, sig)` from process `pid` (user `uid`) to the receiver: the
    /// host cannot deliver `SIGSTOP` without stopping the host process, so
    /// a process sends it along its link instead, and the receiver takes it
    /// as a guest signal (which a traced thread reports).
    Kill { sig: i32, pid: i32, uid: u32 },
    /// Thread `tid` is no longer traced: it exited, with this wait status
    /// when its tracer is to reap it (a thread other than the leader, or a
    /// leader whose tracer is not its parent), or was detached.
    Gone { tid: i32, status: Option<i32> },
    /// Thread `tid`, which thread `parent` made, is traced as its maker is
    /// (`ptrace_init_task`: `PTRACE_O_TRACECLONE` or `CLONE_PTRACE`).
    Traced { tid: i32, parent: i32, seized: bool },
    /// Process `tid`, which thread `parent` of the sender forked, is traced
    /// as `parent` is; the frame carries the descriptor of the tracer's
    /// end of a link to it (`SCM_RIGHTS`).
    Adopt { tid: i32, parent: i32, seized: bool },
    /// The sender's process began a group exit with this status
    /// (`SIGNAL_GROUP_EXIT`): its threads reaped from now on report it
    /// (`wait_task_zombie`).
    GroupExit { status: i32 },
    /// A request to the stopped thread `tid`; answered by a
    /// [`Msg::Reply`].
    Request {
        tid: i32,
        req: u64,
        addr: u64,
        data: u64,
        payload: Vec<u8>,
    },
    /// The answer to an attach or a request: its result and bytes.
    Reply { ret: i64, payload: Vec<u8> },
}

impl Msg {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let i32s = |b: &mut Vec<u8>, v: i32| b.extend_from_slice(&v.to_le_bytes());
        let u64s = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_le_bytes());
        match self {
            Msg::Traceme { tid } => {
                b.push(b'T');
                i32s(&mut b, *tid);
            }
            Msg::Attach {
                tid,
                seize,
                options,
                uid,
                gid,
                capable,
            } => {
                b.push(b'A');
                i32s(&mut b, *tid);
                b.push(u8::from(*seize));
                u64s(&mut b, *options);
                b.extend_from_slice(&uid.to_le_bytes());
                b.extend_from_slice(&gid.to_le_bytes());
                b.push(u8::from(*capable));
            }
            Msg::Stop {
                tid,
                code,
                why,
                status,
                uid,
            } => {
                b.push(b'S');
                i32s(&mut b, *tid);
                i32s(&mut b, *code);
                i32s(&mut b, *why);
                i32s(&mut b, *status);
                b.extend_from_slice(&uid.to_le_bytes());
            }
            Msg::Listening { tid } => {
                b.push(b'L');
                i32s(&mut b, *tid);
            }
            Msg::Kill { sig, pid, uid } => {
                b.push(b'K');
                i32s(&mut b, *sig);
                i32s(&mut b, *pid);
                b.extend_from_slice(&uid.to_le_bytes());
            }
            Msg::Gone { tid, status } => {
                b.push(b'G');
                i32s(&mut b, *tid);
                b.push(u8::from(status.is_some()));
                i32s(&mut b, status.unwrap_or(0));
            }
            Msg::GroupExit { status } => {
                b.push(b'X');
                i32s(&mut b, *status);
            }
            Msg::Adopt {
                tid,
                parent,
                seized,
            } => {
                b.push(b'D');
                i32s(&mut b, *tid);
                i32s(&mut b, *parent);
                b.push(u8::from(*seized));
            }
            Msg::Traced {
                tid,
                parent,
                seized,
            } => {
                b.push(b'C');
                i32s(&mut b, *tid);
                i32s(&mut b, *parent);
                b.push(u8::from(*seized));
            }
            Msg::Request {
                tid,
                req,
                addr,
                data,
                payload,
            } => {
                b.push(b'Q');
                i32s(&mut b, *tid);
                u64s(&mut b, *req);
                u64s(&mut b, *addr);
                u64s(&mut b, *data);
                b.extend_from_slice(payload);
            }
            Msg::Reply { ret, payload } => {
                b.push(b'R');
                b.extend_from_slice(&ret.to_le_bytes());
                b.extend_from_slice(payload);
            }
        }
        let mut frame = (b.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&b);
        frame
    }

    fn decode(b: &[u8]) -> Option<Msg> {
        let (&tag, f) = b.split_first()?;
        let i32at = |at: usize| Some(i32::from_le_bytes(f.get(at..at + 4)?.try_into().ok()?));
        let u64at = |at: usize| Some(u64::from_le_bytes(f.get(at..at + 8)?.try_into().ok()?));
        Some(match tag {
            b'T' => Msg::Traceme { tid: i32at(0)? },
            b'A' => Msg::Attach {
                tid: i32at(0)?,
                seize: *f.get(4)? != 0,
                options: u64at(5)?,
                uid: i32at(13)? as u32,
                gid: i32at(17)? as u32,
                capable: *f.get(21)? != 0,
            },
            b'S' => Msg::Stop {
                tid: i32at(0)?,
                code: i32at(4)?,
                why: i32at(8)?,
                status: i32at(12)?,
                uid: i32at(16)? as u32,
            },
            b'L' => Msg::Listening { tid: i32at(0)? },
            b'K' => Msg::Kill {
                sig: i32at(0)?,
                pid: i32at(4)?,
                uid: i32at(8)? as u32,
            },
            b'G' => Msg::Gone {
                tid: i32at(0)?,
                status: (*f.get(4)? != 0).then_some(i32at(5)?),
            },
            b'X' => Msg::GroupExit { status: i32at(0)? },
            b'D' => Msg::Adopt {
                tid: i32at(0)?,
                parent: i32at(4)?,
                seized: *f.get(8)? != 0,
            },
            b'C' => Msg::Traced {
                tid: i32at(0)?,
                parent: i32at(4)?,
                seized: *f.get(8)? != 0,
            },
            b'Q' => Msg::Request {
                tid: i32at(0)?,
                req: u64at(4)?,
                addr: u64at(12)?,
                data: u64at(20)?,
                payload: f.get(28..)?.to_vec(),
            },
            b'R' => Msg::Reply {
                ret: u64at(0)? as i64,
                payload: f.get(8..)?.to_vec(),
            },
            _ => return None,
        })
    }
}

/// One end of a link: a host stream socket and the bytes read from it that
/// do not yet make a whole frame.
#[derive(Debug)]
pub struct Link {
    fd: OwnedFd,
    inbox: Vec<u8>,
    /// Descriptors that arrived with the bytes (`SCM_RIGHTS`), in order.
    fds: std::collections::VecDeque<OwnedFd>,
    /// The other end is gone.
    pub closed: bool,
}

impl Link {
    /// A new link's two ends.
    pub fn pair() -> Result<(Link, Link), Errno> {
        let (a, b) = super::host::link_pair()?;
        Ok((Link::from_fd(a), Link::from_fd(b)))
    }

    /// A link over a descriptor another process passed (an end of a pair
    /// it made).
    pub fn from_fd(fd: OwnedFd) -> Link {
        Link {
            fd,
            inbox: Vec::new(),
            fds: Default::default(),
            closed: false,
        }
    }

    /// Sends a message whose frame carries descriptor `fd`
    /// (`SCM_RIGHTS` with its first bytes); false when the other end is
    /// gone.
    pub fn send_passing(&self, m: &Msg, fd: &impl AsRawFd) -> bool {
        #[cfg(target_os = "linux")]
        let quiet = libc::MSG_NOSIGNAL;
        #[cfg(not(target_os = "linux"))]
        let quiet = 0;
        let frame = m.encode();
        let fds = [fd.as_raw_fd()];
        let sent = loop {
            match super::net::sys::sendmsg(&self.fd, &frame, quiet, None, &fds) {
                Ok(n) => break n,
                Err(Errno(EINTR)) => {}
                Err(Errno(EAGAIN)) => {
                    let _ = super::host::poll(&[(self.fd(), false, true)], -1);
                }
                Err(_) => return false,
            }
        };
        super::host::write_all_waiting(&self.fd, &frame[sent..]).is_ok()
    }

    /// The oldest descriptor that arrived, for the message that carried it.
    pub fn take_fd(&mut self) -> Option<OwnedFd> {
        self.fds.pop_front()
    }

    /// The host descriptor, for a sleep to wake on.
    pub fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Sends a message (the whole frame, waiting for room if it must);
    /// false when the other end is gone.
    pub fn send(&self, m: &Msg) -> bool {
        super::host::write_all_waiting(&self.fd, &m.encode()).is_ok()
    }

    /// The messages that have arrived, in order; marks the link closed when
    /// the other end is gone.
    pub fn recv(&mut self) -> Vec<Msg> {
        let mut buf = [0u8; 4096];
        loop {
            match super::net::sys::recvmsg(&self.fd, &mut buf, 0) {
                Ok(r) if r.len == 0 && r.fds.is_empty() => {
                    self.closed = true;
                    break;
                }
                Ok(r) => {
                    self.inbox.extend_from_slice(&buf[..r.len]);
                    self.fds.extend(r.fds);
                }
                Err(Errno(EAGAIN)) => break,
                Err(Errno(EINTR)) => continue,
                Err(_) => {
                    self.closed = true;
                    break;
                }
            }
        }
        let mut out = Vec::new();
        while self.inbox.len() >= 4 {
            let len = u32::from_le_bytes(self.inbox[..4].try_into().unwrap()) as usize;
            if self.inbox.len() < 4 + len {
                break;
            }
            let frame: Vec<u8> = self.inbox.drain(..4 + len).skip(4).collect();
            if let Some(m) = Msg::decode(&frame) {
                out.push(m);
            }
        }
        out
    }
}

impl AsRawFd for Link {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

/// How a traced thread is to go on when its tracer resumes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resumption {
    /// Resumed (`PTRACE_CONT`, `PTRACE_SYSCALL`, a step, `PTRACE_DETACH`)
    /// with this `exit_code` (0: no signal).
    Continue(i32),
}

/// What the thread runs until, as its last resumption set it
/// (`ptrace_resume`): `SYSCALL_WORK_SYSCALL_TRACE`,
/// `SYSCALL_WORK_SYSCALL_EMU`, and `TIF_SINGLESTEP`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mode {
    /// `PTRACE_SYSCALL`: a stop at each system call's entry and exit.
    pub syscall: bool,
    /// `PTRACE_SYSEMU`: a stop at each entry, the call not made.
    pub emu: bool,
    /// `PTRACE_SINGLESTEP`: a `SIGTRAP` after each instruction.
    pub step: bool,
}

/// The kind of a stop, which decides what becomes of the signal the tracer
/// resumes it with and what the thread does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopKind {
    /// A signal-delivery-stop (`ptrace_signal`): the signal the tracer
    /// leaves is delivered.
    Signal,
    /// A group stop, or a `ptrace_notify` outside a system call: the
    /// signal is dropped.
    Quiet,
    /// An event stop inside a system call (`ptrace_event`): the signal is
    /// dropped, and the call's exit work follows.
    Event,
    /// A system-call-entry stop (`ptrace_report_syscall_entry`): the call
    /// is made once resumed, unless the thread stopped under
    /// `PTRACE_SYSEMU` (`emu`: the work flags `syscall_trace_enter` read
    /// before stopping).
    Entry { emu: bool },
    /// A system-call-exit stop (`ptrace_report_syscall_exit`).
    Exit,
    /// `PTRACE_EVENT_EXIT`: the thread finishes exiting once resumed.
    Exiting,
    /// `PTRACE_EVENT_SECCOMP`: the call is looked at again once resumed.
    Seccomp,
}

impl StopKind {
    /// A system-call stop, whose resumption's signal is sent to the thread
    /// (`send_sig(signr, current, 1)`).
    pub fn syscall(self) -> bool {
        matches!(self, StopKind::Entry { .. } | StopKind::Exit)
    }
}

/// What a traced thread stopped for.
#[derive(Clone, Debug)]
pub struct Stopped {
    /// `exit_code`: the stop's signal, `SIGTRAP | event << 8`, or a
    /// system-call stop's `SIGTRAP` (with `0x80` under
    /// `PTRACE_O_TRACESYSGOOD`).
    pub code: i32,
    /// `last_siginfo` (none in a group stop).
    pub info: Option<SigInfo>,
    /// What stopped it.
    pub kind: StopKind,
    /// AArch64's `x7` as it was before a system-call stop put the stop's
    /// direction in it (`report_syscall`); restored as the thread goes on.
    pub saved: Option<u64>,
    /// The tracer's verdict, once it resumed the thread.
    pub resumed: Option<Resumption>,
}

/// A traced thread's side (`task->ptrace` and the fields beside it).
#[derive(Clone, Debug)]
pub struct Traced {
    /// The tracer's PID and the link to it.
    pub tracer: i32,
    pub link: LinkId,
    /// `PT_SEIZED`.
    pub seized: bool,
    /// `PTRACE_O_*`.
    pub options: u64,
    /// `ptrace_message` (`PTRACE_GETEVENTMSG`).
    pub message: u64,
    /// The stop it is in, if any.
    pub stop: Option<Stopped>,
    /// What the last resumption set it running until.
    pub mode: Mode,
    /// The system call it is in came through x86-64's `INT 0x80`
    /// (`TS_COMPAT`).
    pub compat: bool,
    /// `JOBCTL_TRAP_STOP`: a trap is due (`PTRACE_INTERRUPT`).
    pub trap_stop: bool,
    /// `JOBCTL_TRAP_NOTIFY`: a job-control change is due to be reported
    /// (a group stop begun or ended), for a seized thread.
    pub trap_notify: bool,
    /// `JOBCTL_LISTENING`: stopped but listening (`PTRACE_LISTEN`).
    pub listening: bool,
    /// Event stops due as the system call finishes (`ptrace_event`, after
    /// `clone`; a `vfork`'s two), in order: the event and its message.
    pub events: std::collections::VecDeque<(i32, u64)>,
    /// How the thread ends once resumed from `PTRACE_EVENT_EXIT`.
    pub exiting: Option<Exiting>,
}

/// How a thread stopped at `PTRACE_EVENT_EXIT` ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exiting {
    /// `exit(code)`: the thread alone.
    Thread(i32),
    /// `exit_group(code)`: the process.
    Group(i32),
    /// Killed by `signal` alone (seccomp's `SECCOMP_RET_KILL_THREAD`).
    Killed(i32),
    /// The process dies of the signal `info` (its default action), the
    /// thread at `pc`.
    Signaled { info: SigInfo, pc: u64, core: bool },
}

impl Traced {
    /// Tracing by `tracer` along `link`.
    pub fn new(tracer: i32, link: LinkId, seized: bool, options: u64) -> Self {
        Traced {
            tracer,
            link,
            seized,
            options,
            message: 0,
            stop: None,
            mode: Mode::default(),
            compat: false,
            trap_stop: false,
            trap_notify: false,
            listening: false,
            events: Default::default(),
            exiting: None,
        }
    }

    /// `ptrace_event_enabled`: the option of event `event` is set.
    pub fn event_enabled(&self, event: i32) -> bool {
        self.options & (1 << event) != 0
    }

    /// A trap is pending (`JOBCTL_TRAP_MASK`).
    pub fn trap_pending(&self) -> bool {
        self.trap_stop || self.trap_notify
    }

    /// Whether the thread is stopped for its tracer and not yet resumed.
    pub fn stopped(&self) -> bool {
        self.stop.as_ref().is_some_and(|s| s.resumed.is_none())
    }
}

/// A tracee as its tracer records it (`tracer->ptraced`).
#[derive(Clone, Debug)]
pub struct Tracee {
    /// The traced thread.
    pub tid: i32,
    /// The thread tracing it (`task->parent`): only it may make requests.
    pub tracer: i32,
    /// The link to its process.
    pub link: LinkId,
    /// Attached with `PTRACE_SEIZE`.
    pub seized: bool,
    /// Stopped with this exit code, as its last message said.
    pub stopped: Option<i32>,
    /// That stop was reported by `wait`.
    pub reported: bool,
    /// It exited with this wait status, for its tracer to reap.
    pub exited: Option<i32>,
}

/// A tracer's tracees and the answer awaited on each link.
#[derive(Debug, Default)]
pub struct Tracees {
    pub list: Vec<Tracee>,
    /// Answers that arrived, by link, for a waiting request.
    pub replies: Vec<(LinkId, i64, Vec<u8>)>,
}

impl Tracees {
    /// The tracee with thread ID `tid`.
    pub fn get(&self, tid: i32) -> Option<&Tracee> {
        self.list.iter().find(|t| t.tid == tid)
    }

    pub fn get_mut(&mut self, tid: i32) -> Option<&mut Tracee> {
        self.list.iter_mut().find(|t| t.tid == tid)
    }

    /// Records a tracee (again), traced by thread `tracer`.
    pub fn add(&mut self, tid: i32, tracer: i32, link: LinkId, seized: bool) {
        self.list.retain(|t| t.tid != tid);
        self.list.push(Tracee {
            tid,
            tracer,
            link,
            seized,
            stopped: None,
            reported: false,
            exited: None,
        });
    }

    /// Drops a tracee.
    pub fn remove(&mut self, tid: i32) {
        self.list.retain(|t| t.tid != tid);
    }

    /// Takes the answer that arrived on `link`.
    pub fn take_reply(&mut self, link: LinkId) -> Option<(i64, Vec<u8>)> {
        let i = self.replies.iter().position(|r| r.0 == link)?;
        let (_, ret, payload) = self.replies.remove(i);
        Some((ret, payload))
    }
}

/// `_NSIG`: a resumption's signal beyond it is `EIO` (`valid_signal`).
pub const NSIG: u64 = 64;
/// `sizeof(sigset_t)`.
pub const SIGSET: u64 = 8;
/// `sizeof(siginfo_t)`.
pub const SIGINFO: usize = 128;
/// `sizeof(struct ptrace_rseq_configuration)`.
pub const RSEQ_CONFIGURATION: u64 = 24;
/// `PTRACE_PEEKSIGINFO_SHARED`.
pub const PEEKSIGINFO_SHARED: u32 = 1;
/// `sizeof(struct seccomp_metadata)`: `filter_off` and `flags`.
pub const SECCOMP_METADATA: u64 = 16;

/// The link with this identity, if it is still there.
pub fn link_mut(p: &mut ProcState, id: LinkId) -> Option<&mut Link> {
    match id {
        LinkId::Parent => p.parent_link.as_mut(),
        LinkId::Child(pid) => p.children.get_mut(pid).and_then(|c| c.link.as_mut()),
        LinkId::Adopted(pid) => p.adopted.iter_mut().find(|a| a.0 == pid).map(|a| &mut a.1),
        LinkId::Tracer => p.tracer_link.as_mut().map(|t| &mut t.1),
    }
}

/// The PID at the other end of a link.
pub fn peer_pid(p: &ProcState, id: LinkId) -> i32 {
    match id {
        LinkId::Parent => p.ppid,
        LinkId::Child(pid) | LinkId::Adopted(pid) => pid,
        LinkId::Tracer => p.tracer_link.as_ref().map_or(0, |t| t.0),
    }
}

/// Every link's identity.
pub fn link_ids(p: &ProcState) -> Vec<LinkId> {
    let mut ids: Vec<LinkId> = p
        .children
        .list
        .iter()
        .filter(|c| c.link.is_some())
        .map(|c| LinkId::Child(c.pid))
        .collect();
    ids.extend(p.adopted.iter().map(|a| LinkId::Adopted(a.0)));
    if p.parent_link.is_some() {
        ids.push(LinkId::Parent);
    }
    if p.tracer_link.is_some() {
        ids.push(LinkId::Tracer);
    }
    ids
}

/// The link with this identity, to look at.
pub fn link_ref(p: &ProcState, id: LinkId) -> Option<&Link> {
    match id {
        LinkId::Parent => p.parent_link.as_ref(),
        LinkId::Child(pid) => p.children.list.iter().find(|c| c.pid == pid)?.link.as_ref(),
        LinkId::Adopted(pid) => p.adopted.iter().find(|a| a.0 == pid).map(|a| &a.1),
        LinkId::Tracer => p.tracer_link.as_ref().map(|t| &t.1),
    }
}

/// The descriptors of every link, for a sleep that a message must end.
pub fn link_fds(p: &ProcState) -> Vec<(i32, bool, bool)> {
    link_ids(p)
        .into_iter()
        .filter_map(|id| link_ref(p, id).map(|l| (l.fd(), true, false)))
        .collect()
}

/// The link to process `pid`, when it is this process's child (not yet
/// reaped) or its parent.
pub fn link_to(p: &ProcState, pid: i32) -> Option<LinkId> {
    if p.children
        .list
        .iter()
        .any(|c| c.pid == pid && c.zombie.is_none() && c.link.as_ref().is_some_and(|l| !l.closed))
    {
        Some(LinkId::Child(pid))
    } else if pid == p.ppid && p.parent_link.as_ref().is_some_and(|l| !l.closed) {
        Some(LinkId::Parent)
    } else if p.adopted.iter().any(|a| a.0 == pid && !a.1.closed) {
        Some(LinkId::Adopted(pid))
    } else if p
        .tracer_link
        .as_ref()
        .is_some_and(|t| t.0 == pid && !t.1.closed)
    {
        Some(LinkId::Tracer)
    } else {
        None
    }
}

/// Sends a message along a link; false when it is gone.
pub fn send(p: &mut ProcState, id: LinkId, m: &Msg) -> bool {
    link_mut(p, id).is_some_and(|l| l.send(m))
}

/// Whether `request` resumes the thread (`ptrace_resume`'s requests).
pub fn resumes(request: u64) -> bool {
    matches!(
        request,
        req::CONT | req::SYSCALL | req::SINGLESTEP | req::SYSEMU | req::SYSEMU_SINGLESTEP
    )
}

/// Whether this ABI has `request`: `PTRACE_SYSEMU` and
/// `PTRACE_SYSEMU_SINGLESTEP` exist on x86-64 and AArch64 only (RISC-V's
/// `ptrace_request` does not know them: `EIO`).
pub fn offered(abi: LinuxAbi, request: u64) -> bool {
    match request {
        req::SYSEMU | req::SYSEMU_SINGLESTEP => abi != LinuxAbi::Riscv64,
        _ => true,
    }
}

/// The wait status of a stop with exit code `code` (`code << 8 | 0x7f`).
pub fn stop_status(code: i32) -> i32 {
    (code << 8) | 0x7f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let all = [
            Msg::Traceme { tid: 7 },
            Msg::Attach {
                tid: 9,
                seize: true,
                options: opt::EXITKILL | opt::TRACESYSGOOD,
                uid: 1000,
                gid: 100,
                capable: false,
            },
            Msg::Stop {
                tid: 9,
                code: 5 | (EVENT_EXEC << 8),
                why: 4,
                status: 5,
                uid: 1000,
            },
            Msg::Listening { tid: 9 },
            Msg::Kill {
                sig: 19,
                pid: 4,
                uid: 1000,
            },
            Msg::Gone {
                tid: 9,
                status: None,
            },
            Msg::Gone {
                tid: 10,
                status: Some(0x300),
            },
            Msg::Traced {
                tid: 10,
                parent: 9,
                seized: true,
            },
            Msg::GroupExit { status: 0x300 },
            Msg::Adopt {
                tid: 11,
                parent: 9,
                seized: false,
            },
            Msg::Request {
                tid: 9,
                req: req::POKEDATA,
                addr: 0x1000,
                data: u64::MAX,
                payload: vec![1, 2, 3],
            },
            Msg::Reply {
                ret: -5,
                payload: vec![9; 300],
            },
        ];
        let (mut a, b) = Link::pair().unwrap();
        for m in &all {
            assert!(b.send(m));
        }
        let mut got = Vec::new();
        while got.len() < all.len() {
            got.extend(a.recv());
        }
        assert_eq!(got, all);
        drop(b);
        assert!(a.recv().is_empty());
        assert!(a.closed);
    }
}
