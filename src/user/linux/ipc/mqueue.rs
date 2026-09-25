//! POSIX message queues (`ipc/mqueue.c`): the queues every emulated process
//! of a user shares, as the processes of an IPC namespace share its
//! `mqueue` file system.
//!
//! A queue is a host file in the namespace directory (`mq.<id>`) holding
//! its attributes, owner, notification, messages, and waiting tasks; a
//! description holds the host file open, so a queue whose name is gone
//! lives on, as an unlinked inode does, until its last description closes
//! (in every process: forked children share the host descriptors). The
//! names are a table (`mqueue.table`) from each name to its queue. Every
//! change happens under the namespace's `mqueue` lock.
//!
//! Messages are kept highest priority first, first in first out within a
//! priority (`msg_insert`, `msg_get`). A task that waits registers in the
//! queue (`wq_add`: first in first out, every task having one priority)
//! and renews its registration as it retries; a send finding a registered
//! receiver hands it the message without queueing it (`pipelined_send`),
//! and a receive that frees a slot queues the message of a registered
//! sender (`pipelined_receive`). A registration not renewed for
//! [`STALE_MS`] belongs to a task that is gone and is passed over.
//!
//! `RLIMIT_MSGQUEUE` and `queues_max` count the queues that have names:
//! the kernel also counts an unlinked queue until its last close.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::{Caller, Namespace, Table};

/// `MQ_PRIO_MAX`.
pub const MQ_PRIO_MAX: u32 = 32768;
/// `DFLT_MSG`, `DFLT_MSGSIZE`: a new queue's size without attributes.
pub const DFLT_MSG: i64 = 10;
pub const DFLT_MSGSIZE: i64 = 8192;
/// `DFLT_MSGMAX`, `DFLT_MSGSIZEMAX`, `DFLT_QUEUESMAX`: the namespace's
/// limits for callers without `CAP_SYS_RESOURCE` (`fs.mqueue.*`).
pub const MSG_MAX: i64 = 10;
pub const MSGSIZE_MAX: i64 = 8192;
pub const QUEUES_MAX: usize = 256;
/// `HARD_MSGMAX`, `HARD_MSGSIZEMAX`: the limits with `CAP_SYS_RESOURCE`.
pub const HARD_MSGMAX: i64 = 65536;
pub const HARD_MSGSIZEMAX: i64 = 16 * 1024 * 1024;
/// `FILENT_SIZE`: a queue file's size.
pub const FILENT_SIZE: i64 = 80;
/// `NAME_MAX`.
pub const NAME_MAX: usize = 255;
/// `sizeof(struct msg_msg)` and `sizeof(struct posix_msg_tree_node)` on
/// 64-bit kernels, which a queue's accounting counts.
const MSG_MSG: u64 = 48;
const TREE_NODE: u64 = 48;
/// How long a waiting task's registration lasts without renewal.
pub const STALE_MS: u64 = 1000;
/// How old a registration gets before its task renews it.
pub const RENEW_MS: u64 = STALE_MS / 4;
/// `SIGEV_SIGNAL`, `SIGEV_NONE`.
pub const SIGEV_SIGNAL: i32 = 0;
pub const SIGEV_NONE: i32 = 1;
const TABLE: &str = "mqueue";

/// A message (`struct msg_msg`: `m_type` is its priority).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    pub prio: u32,
    pub text: Vec<u8>,
}

/// A registered notification (`info->notify`, `info->notify_owner`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notify {
    /// The registering process.
    pub owner: i32,
    /// `SIGEV_SIGNAL` or `SIGEV_NONE`.
    pub kind: i32,
    pub signo: i32,
    pub value: u64,
}

/// A task waiting to receive, and the message a sender handed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receiver {
    pub pid: i32,
    pub tid: i32,
    pub beat: u64,
    pub handed: Option<Msg>,
}

/// A task waiting to send its message, and whether a receiver queued it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sender {
    pub pid: i32,
    pub tid: i32,
    pub beat: u64,
    pub msg: Msg,
    pub done: bool,
}

/// A queue (`struct mqueue_inode_info` and its inode).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queue {
    pub maxmsg: i64,
    pub msgsize: i64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
    /// `i_size`.
    pub size: i64,
    /// Whether a name refers to it.
    pub linked: bool,
    /// Access, modification, and change times.
    pub times: [(i64, i64); 3],
    pub notify: Option<Notify>,
    /// Highest priority first; in order of arrival within a priority.
    pub messages: Vec<Msg>,
    pub receivers: Vec<Receiver>,
    pub senders: Vec<Sender>,
}

impl Queue {
    /// `info->qsize`: the bytes queued.
    pub fn qsize(&self) -> u64 {
        self.messages.iter().map(|m| m.text.len() as u64).sum()
    }

    /// `msg_insert`: after every message of its priority or higher.
    pub fn insert(&mut self, m: Msg) {
        let at = self
            .messages
            .iter()
            .position(|q| q.prio < m.prio)
            .unwrap_or(self.messages.len());
        self.messages.insert(at, m);
    }

    /// `msg_get`: the first message of the highest priority.
    pub fn take(&mut self) -> Option<Msg> {
        (!self.messages.is_empty()).then(|| self.messages.remove(0))
    }

    /// Passes over waiting tasks whose registrations lapsed: a message
    /// handed to a receiver that is gone goes back to the head of its
    /// priority, and a sender that is gone sends nothing.
    pub fn prune(&mut self, now_ms: u64) {
        let live = |beat: u64| now_ms.saturating_sub(beat) <= STALE_MS;
        let mut back = Vec::new();
        self.receivers.retain_mut(|r| {
            let keep = live(r.beat);
            if !keep && let Some(m) = r.handed.take() {
                back.push(m);
            }
            keep
        });
        for m in back {
            let at = self
                .messages
                .iter()
                .position(|q| q.prio <= m.prio)
                .unwrap_or(self.messages.len());
            self.messages.insert(at, m);
        }
        self.senders.retain(|s| live(s.beat));
    }

    /// Sets the times in `which` (bits 0, 1, 2: access, modification,
    /// change) to `now`.
    pub fn touch(&mut self, which: u32, now: (i64, i64)) {
        for i in 0..3 {
            if which & (1 << i) != 0 {
                self.times[i] = now;
            }
        }
    }

    /// The first line of the file's contents (`mqueue_read_file`).
    pub fn status(&self) -> String {
        let (kind, signo, pid) = match self.notify {
            Some(n) => (
                n.kind,
                if n.kind == SIGEV_SIGNAL { n.signo } else { 0 },
                n.owner,
            ),
            None => (0, 0, 0),
        };
        format!(
            "QSIZE:{:<10} NOTIFY:{:<5} SIGNO:{:<5} NOTIFY_PID:{:<6}\n",
            self.qsize(),
            kind,
            signo,
            pid
        )
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer(b"RAXMQ01\n".to_vec());
        w.i64(self.maxmsg).i64(self.msgsize);
        w.u32(self.mode).u32(self.uid).u32(self.gid).u64(self.ino);
        w.i64(self.size).u32(u32::from(self.linked));
        for &(s, ns) in &self.times {
            w.i64(s).i64(ns);
        }
        match self.notify {
            Some(n) => {
                w.u32(1)
                    .u32(n.owner as u32)
                    .u32(n.kind as u32)
                    .u32(n.signo as u32)
                    .u64(n.value);
            }
            None => {
                w.u32(0);
            }
        }
        w.u32(self.messages.len() as u32);
        for m in &self.messages {
            w.msg(m);
        }
        w.u32(self.receivers.len() as u32);
        for r in &self.receivers {
            w.u32(r.pid as u32).u32(r.tid as u32).u64(r.beat);
            match &r.handed {
                Some(m) => {
                    w.u32(1).msg(m);
                }
                None => {
                    w.u32(0);
                }
            }
        }
        w.u32(self.senders.len() as u32);
        for s in &self.senders {
            w.u32(s.pid as u32).u32(s.tid as u32).u64(s.beat);
            w.msg(&s.msg).u32(u32::from(s.done));
        }
        w.0
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader { b, at: 0 };
        if r.take(8)? != b"RAXMQ01\n" {
            return None;
        }
        let maxmsg = r.i64()?;
        let msgsize = r.i64()?;
        let (mode, uid, gid, ino) = (r.u32()?, r.u32()?, r.u32()?, r.u64()?);
        let size = r.i64()?;
        let linked = r.u32()? != 0;
        let mut times = [(0, 0); 3];
        for t in &mut times {
            *t = (r.i64()?, r.i64()?);
        }
        let notify = match r.u32()? {
            0 => None,
            _ => Some(Notify {
                owner: r.u32()? as i32,
                kind: r.u32()? as i32,
                signo: r.u32()? as i32,
                value: r.u64()?,
            }),
        };
        let messages = (0..r.u32()?).map(|_| r.msg()).collect::<Option<Vec<_>>>()?;
        let mut receivers = Vec::new();
        for _ in 0..r.u32()? {
            let (pid, tid, beat) = (r.u32()? as i32, r.u32()? as i32, r.u64()?);
            let handed = match r.u32()? {
                0 => None,
                _ => Some(r.msg()?),
            };
            receivers.push(Receiver {
                pid,
                tid,
                beat,
                handed,
            });
        }
        let mut senders = Vec::new();
        for _ in 0..r.u32()? {
            let (pid, tid, beat) = (r.u32()? as i32, r.u32()? as i32, r.u64()?);
            let msg = r.msg()?;
            let done = r.u32()? != 0;
            senders.push(Sender {
                pid,
                tid,
                beat,
                msg,
                done,
            });
        }
        Some(Queue {
            maxmsg,
            msgsize,
            mode,
            uid,
            gid,
            ino,
            size,
            linked,
            times,
            notify,
            messages,
            receivers,
            senders,
        })
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn i64(&mut self, v: i64) -> &mut Self {
        self.u64(v as u64)
    }
    fn msg(&mut self, m: &Msg) -> &mut Self {
        self.u32(m.prio).u32(m.text.len() as u32);
        self.0.extend_from_slice(&m.text);
        self
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn i64(&mut self) -> Option<i64> {
        self.u64().map(|v| v as i64)
    }
    fn msg(&mut self) -> Option<Msg> {
        let prio = self.u32()?;
        let len = self.u32()? as usize;
        Some(Msg {
            prio,
            text: self.take(len)?.to_vec(),
        })
    }
}

/// A named queue in the table: its file and what its creator is charged.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    id: u64,
    /// The creator's real user ID (`current_ucounts`).
    uid: u32,
    /// `mq_bytes`.
    bytes: u64,
}

/// The names, and the next queue file and inode numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Names {
    next_id: u64,
    next_ino: u64,
    entries: BTreeMap<Vec<u8>, Entry>,
}

impl Table for Names {
    fn parse(text: &str) -> Self {
        let mut t = Names {
            next_id: 1,
            next_ino: 1000,
            entries: BTreeMap::new(),
        };
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                ["next", id, ino] => {
                    t.next_id = id.parse().unwrap_or(1);
                    t.next_ino = ino.parse().unwrap_or(1000);
                }
                [name, id, uid, bytes] => {
                    if let (Some(name), Ok(id), Ok(uid), Ok(bytes)) =
                        (unhex(name), id.parse(), uid.parse(), bytes.parse())
                    {
                        t.entries.insert(name, Entry { id, uid, bytes });
                    }
                }
                _ => {}
            }
        }
        t
    }

    fn render(&self) -> String {
        let mut out = format!("next {} {}\n", self.next_id, self.next_ino);
        for (name, e) in &self.entries {
            out.push_str(&format!("{} {} {} {}\n", hex(name), e.id, e.uid, e.bytes));
        }
        out
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `lookup_noperm_common` and `simple_lookup`: a name for the queue file
/// system's root (`EACCES` for `.`, `..`, or a name holding `/`;
/// `ENAMETOOLONG` past `NAME_MAX`).
pub fn check_name(name: &[u8]) -> Result<(), Errno> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(Errno(EACCES));
    }
    if name.len() > NAME_MAX {
        return Err(Errno(ENAMETOOLONG));
    }
    Ok(())
}

/// `generic_permission` on a queue: the owner's, the group's, or the
/// others' bits of `mode`, or `CAP_DAC_OVERRIDE`.
fn permitted(q: &Queue, who: &Caller, want: u32) -> bool {
    let bits = if who.euid == q.uid {
        q.mode >> 6
    } else if who.egid == q.gid || who.groups.contains(&q.gid) {
        q.mode >> 3
    } else {
        q.mode
    };
    want & !bits & 0o7 == 0 || who.capable()
}

/// What `mq_open` creates a queue with.
#[derive(Clone, Copy, Debug)]
pub struct Create {
    /// `mode & ~umask` (`vfs_mkobj` keeps its `S_IALLUGO` bits).
    pub mode: u32,
    /// `(mq_maxmsg, mq_msgsize)` from the caller's attributes.
    pub attr: Option<(i64, i64)>,
    /// The creator's real user ID and `RLIMIT_MSGQUEUE`.
    pub ruid: u32,
    pub rlimit: u64,
    /// The time.
    pub now: (i64, i64),
}

/// An open queue: its host file (which keeps it alive) and its name.
#[derive(Debug)]
pub struct Handle {
    pub file: File,
    pub name: Vec<u8>,
    pub ns: Namespace,
    pub ino: u64,
}

fn path(ns: &Namespace, id: u64) -> PathBuf {
    ns.dir().join(format!("mq.{id}"))
}

fn load(file: &File) -> Result<Queue, Errno> {
    let len = file.metadata().map_err(Errno::from)?.len() as usize;
    let mut b = vec![0u8; len];
    file.read_exact_at(&mut b, 0).map_err(Errno::from)?;
    Queue::decode(&b).ok_or(Errno(EIO))
}

fn store(file: &File, q: &Queue) -> Result<(), Errno> {
    let b = q.encode();
    file.write_all_at(&b, 0).map_err(Errno::from)?;
    file.set_len(b.len() as u64).map_err(Errno::from)
}

/// `mq_open`'s look-up (`prepare_open`), after the name's checks: the
/// named queue opened with access mode `acc` (`O_ACCMODE`), or with
/// `O_CREAT` (`create`) a new one; `EEXIST` with `excl` for one that
/// exists.
pub fn open(
    ns: &Namespace,
    name: &[u8],
    acc: u32,
    create: Option<Create>,
    excl: bool,
    who: &Caller,
) -> Result<Handle, Errno> {
    ns.with_table(TABLE, |t: &mut Names| {
        if let Some(e) = t.entries.get(name) {
            if create.is_some() && excl {
                return Err(Errno(EEXIST));
            }
            if acc == 3 {
                return Err(Errno(EINVAL));
            }
            let file = File::options()
                .read(true)
                .write(true)
                .open(path(ns, e.id))
                .map_err(Errno::from)?;
            let q = load(&file)?;
            let want = [0o4, 0o2, 0o6][acc as usize];
            if !permitted(&q, who, want) {
                return Err(Errno(EACCES));
            }
            return Ok(Handle {
                file,
                name: name.to_vec(),
                ns: ns.clone(),
                ino: q.ino,
            });
        }
        let Some(c) = create else {
            return Err(Errno(ENOENT));
        };
        // mqueue_create_attr, then mqueue_get_inode.
        if t.entries.len() >= QUEUES_MAX && !who.capable() {
            return Err(Errno(ENOSPC));
        }
        let (maxmsg, msgsize) = c.attr.unwrap_or((DFLT_MSG, DFLT_MSGSIZE));
        let (max, size_max) = if who.capable() {
            (HARD_MSGMAX, HARD_MSGSIZEMAX)
        } else {
            (MSG_MAX, MSGSIZE_MAX)
        };
        if maxmsg <= 0 || msgsize <= 0 || maxmsg > max || msgsize > size_max {
            return Err(Errno(EINVAL));
        }
        let (maxmsg_u, msgsize_u) = (maxmsg as u64, msgsize as u64);
        let tree = maxmsg_u * MSG_MSG + maxmsg_u.min(u64::from(MQ_PRIO_MAX)) * TREE_NODE;
        let bytes = maxmsg_u
            .checked_mul(msgsize_u)
            .and_then(|b| b.checked_add(tree))
            .ok_or(Errno(EOVERFLOW))?;
        let charged: u64 = t
            .entries
            .values()
            .filter(|e| e.uid == c.ruid)
            .map(|e| e.bytes)
            .sum();
        if charged.saturating_add(bytes) > c.rlimit {
            return Err(Errno(EMFILE));
        }
        let id = t.next_id;
        let ino = t.next_ino;
        t.next_id += 1;
        t.next_ino += 1;
        let q = Queue {
            maxmsg,
            msgsize,
            mode: c.mode & 0o7777,
            uid: who.euid,
            gid: who.egid,
            ino,
            size: FILENT_SIZE,
            linked: true,
            times: [c.now; 3],
            notify: None,
            messages: Vec::new(),
            receivers: Vec::new(),
            senders: Vec::new(),
        };
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path(ns, id))
            .map_err(Errno::from)?;
        store(&file, &q)?;
        t.entries.insert(
            name.to_vec(),
            Entry {
                id,
                uid: c.ruid,
                bytes,
            },
        );
        Ok(Handle {
            file,
            name: name.to_vec(),
            ns: ns.clone(),
            ino,
        })
    })
}

/// `mq_unlink`, after the name's checks: the name removed (`ENOENT` for
/// none; `EPERM` for another user's queue, the directory being sticky and
/// root's), its queue left to its open descriptions.
pub fn unlink(ns: &Namespace, name: &[u8], who: &Caller, now: (i64, i64)) -> Result<(), Errno> {
    ns.with_table(TABLE, |t: &mut Names| {
        let e = t.entries.get(name).ok_or(Errno(ENOENT))?.clone();
        let p = path(ns, e.id);
        let file = File::options()
            .read(true)
            .write(true)
            .open(&p)
            .map_err(Errno::from)?;
        let mut q = load(&file)?;
        // may_delete in the sticky root (owned by root): the queue's
        // owner, or CAP_FOWNER.
        if who.euid != q.uid && !who.capable() {
            return Err(Errno(EPERM));
        }
        q.linked = false;
        q.touch(4, now);
        store(&file, &q)?;
        std::fs::remove_file(&p).map_err(Errno::from)?;
        t.entries.remove(name);
        Ok(())
    })
}

impl Handle {
    /// Runs `f` on the queue under the namespace lock, writing back what
    /// `f` leaves unless it fails.
    pub fn with<R>(&self, f: impl FnOnce(&mut Queue) -> Result<R, Errno>) -> Result<R, Errno> {
        self.ns.locked(TABLE, || {
            let mut q = load(&self.file)?;
            let before = q.clone();
            let r = f(&mut q)?;
            if q != before {
                store(&self.file, &q)?;
            }
            Ok(r)
        })
    }

    /// The queue as it is.
    pub fn get(&self) -> Result<Queue, Errno> {
        self.with(|q| Ok(q.clone()))
    }
}
