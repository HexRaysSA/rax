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

pub mod regs;

use std::os::fd::{AsRawFd, OwnedFd};

use super::abi::errno::Errno;
use super::abi::errno_table::*;
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
    /// x86-64 only.
    pub const SYSEMU: u64 = 31;
    pub const SYSEMU_SINGLESTEP: u64 = 32;
    pub const SETOPTIONS: u64 = 0x4200;
    pub const GETEVENTMSG: u64 = 0x4201;
    pub const GETSIGINFO: u64 = 0x4202;
    pub const SETSIGINFO: u64 = 0x4203;
    pub const GETREGSET: u64 = 0x4204;
    pub const SETREGSET: u64 = 0x4205;
    pub const SEIZE: u64 = 0x4206;
    pub const INTERRUPT: u64 = 0x4207;
    pub const LISTEN: u64 = 0x4208;
    pub const GETSIGMASK: u64 = 0x420a;
    pub const SETSIGMASK: u64 = 0x420b;
}

/// `PTRACE_O_*` options and `PTRACE_O_MASK`.
pub mod opt {
    pub const TRACESYSGOOD: u64 = 1;
    pub const TRACEEXEC: u64 = 0x10;
    pub const EXITKILL: u64 = 0x10_0000;
    pub const SUSPEND_SECCOMP: u64 = 0x20_0000;
    pub const MASK: u64 = 0xff | EXITKILL | SUSPEND_SECCOMP;
}

/// `PTRACE_EVENT_EXEC`.
pub const EVENT_EXEC: i32 = 4;

/// Which link a relationship goes along.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkId {
    /// The link to this process's parent.
    Parent,
    /// The link to the child with this PID.
    Child(i32),
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
    /// (`exit_code`: a signal, `SIGTRAP | event << 8`, ...).
    Stop { tid: i32, code: i32 },
    /// Thread `tid` is no longer traced (it exited or was detached).
    Gone { tid: i32 },
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
            Msg::Stop { tid, code } => {
                b.push(b'S');
                i32s(&mut b, *tid);
                i32s(&mut b, *code);
            }
            Msg::Gone { tid } => {
                b.push(b'G');
                i32s(&mut b, *tid);
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
            },
            b'G' => Msg::Gone { tid: i32at(0)? },
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
    /// The other end is gone.
    pub closed: bool,
}

impl Link {
    /// A new link's two ends.
    pub fn pair() -> Result<(Link, Link), Errno> {
        let (a, b) = super::host::link_pair()?;
        let end = |fd| Link {
            fd,
            inbox: Vec::new(),
            closed: false,
        };
        Ok((end(a), end(b)))
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
            match super::host::read_nonblocking(&self.fd, &mut buf) {
                Ok(0) => {
                    self.closed = true;
                    break;
                }
                Ok(n) => self.inbox.extend_from_slice(&buf[..n]),
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

/// How a traced thread is to go on when its tracer resumes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resumption {
    /// `PTRACE_CONT` (and `PTRACE_DETACH`) with this signal (0: none).
    Continue(i32),
}

/// What a traced thread stopped for.
#[derive(Clone, Debug)]
pub struct Stopped {
    /// `exit_code`: the stop's signal, or `SIGTRAP | event << 8`.
    pub code: i32,
    /// `last_siginfo` (none in a group stop).
    pub info: Option<SigInfo>,
    /// The stop is a signal-delivery-stop: the signal the tracer leaves is
    /// delivered (else a resumption's signal is sent, as after an event).
    pub signal: bool,
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
        }
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
            },
            Msg::Gone { tid: 9 },
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
