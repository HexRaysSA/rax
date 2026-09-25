//! POSIX message queue calls (`ipc/mqueue.c`): `mq_open`, `mq_unlink`,
//! `mq_timedsend`, `mq_timedreceive`, `mq_notify`, and `mq_getsetattr`, and
//! what a queue's descriptor does as a file (see [`ipc::mqueue`] for where
//! queues live).
//!
//! Each call checks in the kernel's order. A send to a full queue and a
//! receive from an empty one wait (without `O_NONBLOCK`) until they can,
//! their absolute `CLOCK_REALTIME` timeout passes (`ETIMEDOUT`), or a
//! signal ends them (`-ERESTARTSYS`); while waiting, a task is registered
//! in the queue, so a message sent meanwhile is handed to the first
//! waiting receiver, and a receive that frees a slot queues the first
//! waiting sender's message. Another process's change is seen when the
//! waiter next tries, every [`RETRY`](super::locks::RETRY).
//!
//! A notification (`mq_notify`) is sent when a message arrives in an
//! empty queue without a waiting receiver: `SIGEV_SIGNAL`'s signal with
//! `SI_MESGQ`, the sender's process and real user IDs, and the
//! registration's value, to this process directly and to another one
//! through the host (see [`sigmail`](super::super::sigmail)).
//! `SIGEV_THREAD` notifications, which the kernel sends to a netlink
//! socket, are refused with `ENOSYS` after their checks.
//!
//! [`ipc::mqueue`]: super::super::ipc::mqueue

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::abi::types::{Stat, Timespec, mode};
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::host::{self, HostClock, SetTime};
use super::super::ipc::mqueue::{self, Create, Handle, Msg, Notify, Queue, Receiver, Sender};
use super::super::signal::code::SI_MESGQ;
use super::super::signal::deliver::restart::ERESTARTSYS;
use super::super::signal::info::SigInfo;
use super::super::wait::{Resume, Wait};
use super::ready::{Polled, ev};
use super::{Ctx, SysResult};

/// `sizeof(struct mq_attr)`: four `long`s and four reserved.
const MQ_ATTR: usize = 64;
/// `sizeof(struct sigevent)`.
const SIGEVENT: usize = 64;
/// `SIGEV_THREAD`.
const SIGEV_THREAD: i32 = 2;
/// `NOTIFY_COOKIE_LEN`.
const NOTIFY_COOKIE_LEN: usize = 32;
/// `RLIMIT_MSGQUEUE`.
const RLIMIT_MSGQUEUE: usize = 12;
/// The device of the `mqueue` file system (an anonymous block device).
pub const MQUEUE_DEV_MINOR: u32 = 0x13;
/// Time bits of [`Queue::touch`].
const ATIME: u32 = 1;
const MTIME: u32 = 2;
const CTIME: u32 = 4;

fn now() -> (i64, i64) {
    host::clock_gettime(HostClock::Realtime)
}

fn now_ms() -> u64 {
    let (s, ns) = host::clock_gettime(HostClock::Monotonic);
    s as u64 * 1000 + ns as u64 / 1_000_000
}

fn ts((sec, nsec): (i64, i64)) -> Timespec {
    Timespec { sec, nsec }
}

/// The queue behind descriptor `fd` (`EBADF` for none, or another file).
fn queue_of(c: &Ctx<'_>, fd: i32) -> Result<Arc<OpenFile>, Errno> {
    let file = c.p.fds.file(fd)?;
    if !matches!(file.object, FileObject::Mqueue(_)) {
        return Err(Errno(EBADF));
    }
    Ok(file)
}

fn handle(file: &OpenFile) -> &Handle {
    let FileObject::Mqueue(h) = &file.object else {
        unreachable!("queue_of checked the object")
    };
    h
}

/// A queue file's metadata (`mqueue_get_inode`, `simple_getattr`).
pub fn stat(q: &Queue) -> Stat {
    Stat {
        dev_minor: MQUEUE_DEV_MINOR,
        ino: q.ino,
        mode: mode::S_IFREG | q.mode,
        nlink: u64::from(q.linked),
        uid: q.uid,
        gid: q.gid,
        size: q.size,
        blksize: 4096,
        atime: ts(q.times[0]),
        mtime: ts(q.times[1]),
        ctime: ts(q.times[2]),
        ..Default::default()
    }
}

/// What `/proc/<pid>/fd` shows for a queue: its path in the queue file
/// system, marked once its name is gone.
pub fn link(h: &Handle) -> String {
    let name = String::from_utf8_lossy(&h.name);
    match h.get() {
        Ok(q) if !q.linked => format!("/{name} (deleted)"),
        _ => format!("/{name}"),
    }
}

/// `setattr_prepare`'s owner test: the owner or `CAP_FOWNER`.
fn owner(c: &Ctx<'_>, q: &Queue) -> bool {
    c.p.creds.1 == q.uid || c.p.creds.1 == 0
}

/// `utimensat` on a queue's descriptor: explicit times need its owner,
/// the current time its owner or write access.
pub fn set_times(c: &Ctx<'_>, h: &Handle, t: [SetTime; 2]) -> SysResult {
    let now = now();
    let euid = c.p.creds.1;
    h.with(|q| {
        let explicit = t.iter().any(|t| matches!(t, SetTime::At(..)));
        if !owner(c, q) {
            if explicit {
                return Err(Errno(EPERM));
            }
            let bits = if euid == q.uid { q.mode >> 6 } else { q.mode };
            if bits & 0o2 == 0 {
                return Err(Errno(EACCES));
            }
        }
        for (i, t) in t.iter().enumerate() {
            match *t {
                SetTime::Now => q.times[i] = now,
                SetTime::At(s, ns) => q.times[i] = (s, ns),
                SetTime::Omit => {}
            }
        }
        q.times[2] = now;
        Ok(0)
    })
}

/// `fchmod` on a queue's descriptor (`simple_setattr`).
pub fn chmod(c: &Ctx<'_>, h: &Handle, perm: u32) -> SysResult {
    h.with(|q| {
        if !owner(c, q) {
            return Err(Errno(EPERM));
        }
        q.mode = perm & 0o7777;
        q.touch(CTIME, now());
        Ok(0)
    })
}

/// `fchown` on a queue's descriptor: a new owner needs `CAP_CHOWN`; its
/// owner may change the group to one of its own.
pub fn chown(c: &Ctx<'_>, h: &Handle, uid: u32, gid: u32) -> SysResult {
    let root = c.p.creds.1 == 0;
    let in_group = |g: u32| c.p.creds.3 == g || c.p.groups.contains(&g);
    let euid = c.p.creds.1;
    h.with(|q| {
        let new_uid = (uid != u32::MAX).then_some(uid);
        let new_gid = (gid != u32::MAX).then_some(gid);
        // chown_ok and chgrp_ok.
        if new_uid.is_some_and(|u| !(euid == q.uid && u == q.uid)) && !root {
            return Err(Errno(EPERM));
        }
        if new_gid.is_some_and(|g| !(euid == q.uid && (g == q.gid || in_group(g)))) && !root {
            return Err(Errno(EPERM));
        }
        if let Some(u) = new_uid {
            q.uid = u;
        }
        if let Some(g) = new_gid {
            q.gid = g;
        }
        q.touch(CTIME, now());
        Ok(0)
    })
}

/// `ftruncate` on a queue's descriptor: its size (`simple_setattr`).
pub fn truncate(file: &OpenFile, h: &Handle, len: i64) -> SysResult {
    if !file.fmode().1 {
        return Err(Errno(EINVAL));
    }
    h.with(|q| {
        q.size = len;
        q.touch(MTIME | CTIME, now());
        Ok(0)
    })
}

/// `mqueue_poll_file`: readable while messages are queued, writable while
/// there is room. The waiter looks again after
/// [`RETRY`](super::locks::RETRY), another process's send or receive
/// having no host descriptor to wake it.
pub fn poll(h: &Handle) -> (Polled, Wait) {
    let mut p = Polled::default();
    if let Ok(q) = h.get() {
        if !q.messages.is_empty() {
            p.mask |= ev::IN | ev::RDNORM;
        }
        if (q.messages.len() as i64) < q.maxmsg {
            p.mask |= ev::OUT | ev::WRNORM;
        }
        p.level = q.messages.len() as u64;
    }
    (p, Wait::until(Some(Instant::now() + super::locks::RETRY)))
}

/// `mqueue_flush_file`, as process `pid` closes a descriptor of the
/// queue: its notification, if it registered one, is removed.
pub fn flush(h: &Handle, pid: i32) {
    let _ = h.with(|q| {
        if q.notify.is_some_and(|n| n.owner == pid) {
            q.notify = None;
        }
        Ok(())
    });
}

/// `getname` of a queue name, then its look-up checks.
fn queue_name(c: &Ctx<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    let name = c.read_cstr_raw(addr, super::super::fs::PATH_MAX - 1)?;
    if name.is_empty() {
        return Err(Errno(ENOENT));
    }
    Ok(name)
}

/// `mq_open`: the attributes' copy, the name, a descriptor
/// (close-on-exec), the name's look-up, then `prepare_open`.
pub fn mq_open(c: &mut Ctx<'_>, name: u64, oflag: i32, perm: u32, uattr: u64) -> SysResult {
    let attr = if uattr != 0 {
        let b = c.read_mem(uattr, MQ_ATTR)?;
        let word = |i: usize| i64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Some((word(1), word(2)))
    } else {
        None
    };
    let name = queue_name(c, name)?;
    c.p.fds.free_fds(1, super::io::nofile(c))?;
    mqueue::check_name(&name)?;
    let oflag = oflag as u32;
    let create = (oflag & O_CREAT != 0).then(|| Create {
        mode: perm & !c.p.umask,
        attr,
        ruid: c.p.creds.0,
        rlimit: c.p.rlimits[RLIMIT_MSGQUEUE].0,
        now: now(),
    });
    let who = super::ipc::caller(c.p);
    let h = mqueue::open(
        &c.p.ipc.ns,
        &name,
        oflag & O_ACCMODE,
        create,
        oflag & O_EXCL != 0,
        &who,
    )?;
    // dentry_open keeps the flags but those of creation.
    let status = oflag & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_CLOEXEC);
    let path = format!("/{}", String::from_utf8_lossy(&name));
    let file = OpenFile::new(FileObject::Mqueue(h), FileType::Regular, path, None, status);
    super::io::install(c, file, true)
}

/// `mq_unlink`: the name, its look-up, then the removal.
pub fn mq_unlink(c: &mut Ctx<'_>, name: u64) -> SysResult {
    let name = queue_name(c, name)?;
    mqueue::check_name(&name)?;
    let who = super::ipc::caller(c.p);
    mqueue::unlink(&c.p.ipc.ns, &name, &who, now())?;
    Ok(0)
}

/// `prepare_timeout`: an absolute `CLOCK_REALTIME` time, as an instant.
fn prepare_timeout(c: &Ctx<'_>, addr: u64) -> Result<Instant, Errno> {
    let t = Timespec::decode(&c.read_mem(addr, 16)?.try_into().unwrap());
    if t.sec < 0 || !(0..1_000_000_000).contains(&t.nsec) {
        return Err(Errno(EINVAL));
    }
    let (s, ns) = now();
    let target = i128::from(t.sec) * 1_000_000_000 + i128::from(t.nsec);
    let cur = i128::from(s) * 1_000_000_000 + i128::from(ns);
    let left = (target - cur).clamp(0, i128::from(u64::MAX)) as u64;
    Ok(Instant::now() + Duration::from_nanos(left))
}

/// The absolute timeout of a send or receive: read when the call starts,
/// kept while it waits.
fn deadline(c: &mut Ctx<'_>, addr: u64) -> Result<(bool, Option<Instant>), Errno> {
    match c.resume.take() {
        Some(Resume::Until(d)) => Ok((true, d)),
        _ => Ok((
            false,
            if addr != 0 {
                Some(prepare_timeout(c, addr)?)
            } else {
                None
            },
        )),
    }
}

/// What a send or receive does next.
enum Step<T> {
    Done(T),
    Wait,
    Fail(Errno),
}

/// A task that cannot go on (`wq_sleep`): a signal ends it
/// (`-ERESTARTSYS`), then its timeout (`ETIMEDOUT`); else it waits.
fn must_wait<T>(signal: bool, deadline: Option<Instant>) -> Step<T> {
    if signal {
        Step::Fail(Errno(ERESTARTSYS))
    } else if deadline.is_some_and(|d| Instant::now() >= d) {
        Step::Fail(Errno(ETIMEDOUT))
    } else {
        Step::Wait
    }
}

/// Renews a waiting task's registration once it is [`RENEW_MS`] old, so
/// that a queue is not rewritten at every try.
///
/// [`RENEW_MS`]: mqueue::RENEW_MS
fn renew(beat: &mut u64, now: u64) {
    if now.saturating_sub(*beat) >= mqueue::RENEW_MS {
        *beat = now;
    }
}

/// Sleeps until the timeout or the next try.
fn sleep(c: &mut Ctx<'_>, deadline: Option<Instant>) -> Errno {
    let retry = Instant::now() + super::locks::RETRY;
    let wake = deadline.map_or(retry, |d| d.min(retry));
    c.block(Wait::until(Some(wake)), Resume::Until(deadline))
}

/// `__do_notify`: after a message arrived in an empty queue that no
/// receiver waited on, the registration is consumed and, for
/// `SIGEV_SIGNAL` with a signal, returned to be sent.
fn take_notify(q: &mut Queue) -> Option<Notify> {
    let n = q.notify.take()?;
    if !super::super::ipc::alive(n.owner) {
        return None;
    }
    (n.kind == mqueue::SIGEV_SIGNAL && n.signo != 0).then_some(n)
}

/// Sends notification `n` from this process (`SI_MESGQ` with its process
/// ID and real user ID), bypassing the permission checks of `kill`.
fn notify(c: &mut Ctx<'_>, n: Notify) {
    let (pid, uid) = (c.p.pid, c.p.creds.0);
    if n.owner == pid {
        let info = SigInfo::queued(n.signo, SI_MESGQ, pid, uid, n.value);
        super::signal::send_process(c, info, pid);
    } else {
        let sent = super::super::sigmail::Sent {
            sender: (pid, uid),
            code: SI_MESGQ,
            value: n.value,
        };
        let _ = host::send_sent(n.owner, n.signo, sent);
    }
}

/// `mq_timedsend`: the timeout, the priority, the descriptor (open for
/// writing), the size, the message's copy, then the send.
pub fn mq_timedsend(
    c: &mut Ctx<'_>,
    fd: i32,
    msg: u64,
    len: u64,
    prio: u32,
    timeout: u64,
) -> SysResult {
    let (resumed, deadline) = deadline(c, timeout)?;
    if prio >= mqueue::MQ_PRIO_MAX {
        return Err(Errno(EINVAL));
    }
    let file = queue_of(c, fd)?;
    if !file.fmode().1 {
        return Err(Errno(EBADF));
    }
    let h = handle(&file);
    if len > h.get()?.msgsize as u64 {
        return Err(Errno(EMSGSIZE));
    }
    let m = Msg {
        prio,
        text: c.read_mem(msg, len as usize)?,
    };
    let nonblock = file.flags() & O_NONBLOCK != 0;
    let me = (c.p.pid, c.t.tid);
    let signal = c.signal_pending();
    let (step, notified) = h.with(|q| {
        let beat = now_ms();
        q.prune(beat);
        let mine = q.senders.iter().position(|s| (s.pid, s.tid) == me);
        let full = q.messages.len() as i64 >= q.maxmsg;
        if resumed && let Some(i) = mine {
            if q.senders[i].done {
                q.senders.remove(i);
                return Ok((Step::Done(0), None));
            }
            if full {
                let step = must_wait(signal, deadline);
                match step {
                    Step::Wait => renew(&mut q.senders[i].beat, beat),
                    _ => {
                        q.senders.remove(i);
                    }
                }
                return Ok((step, None));
            }
            q.senders.remove(i);
        } else if full {
            if nonblock {
                return Ok((Step::Fail(Errno(EAGAIN)), None));
            }
            let step = must_wait(signal, deadline);
            if matches!(step, Step::Wait) {
                q.senders.push(Sender {
                    pid: me.0,
                    tid: me.1,
                    beat,
                    msg: m,
                    done: false,
                });
            }
            return Ok((step, None));
        }
        // pipelined_send, or msg_insert and __do_notify.
        let mut notified = None;
        if let Some(r) = q.receivers.iter_mut().find(|r| r.handed.is_none()) {
            r.handed = Some(m);
        } else {
            q.insert(m);
            if q.messages.len() == 1 {
                notified = take_notify(q);
            }
        }
        q.touch(ATIME | MTIME | CTIME, now());
        Ok((Step::Done(0), notified))
    })?;
    if let Some(n) = notified {
        notify(c, n);
    }
    match step {
        Step::Done(v) => Ok(v),
        Step::Fail(e) => Err(e),
        Step::Wait => Err(sleep(c, deadline)),
    }
}

/// `mq_timedreceive`: the timeout, the descriptor (open for reading), the
/// buffer's size, then the receive; the message is taken even when
/// copying it (after its priority) faults.
pub fn mq_timedreceive(
    c: &mut Ctx<'_>,
    fd: i32,
    msg: u64,
    len: u64,
    prio: u64,
    timeout: u64,
) -> SysResult {
    let (resumed, deadline) = deadline(c, timeout)?;
    let file = queue_of(c, fd)?;
    if !file.fmode().0 {
        return Err(Errno(EBADF));
    }
    let h = handle(&file);
    if len < h.get()?.msgsize as u64 {
        return Err(Errno(EMSGSIZE));
    }
    let nonblock = file.flags() & O_NONBLOCK != 0;
    let me = (c.p.pid, c.t.tid);
    let signal = c.signal_pending();
    let step = h.with(|q| {
        let beat = now_ms();
        q.prune(beat);
        let mine = q.receivers.iter().position(|r| (r.pid, r.tid) == me);
        if resumed && let Some(i) = mine {
            if let Some(m) = q.receivers[i].handed.take() {
                q.receivers.remove(i);
                return Ok(Step::Done(m));
            }
            if q.messages.is_empty() {
                let step = must_wait(signal, deadline);
                match step {
                    Step::Wait => renew(&mut q.receivers[i].beat, beat),
                    _ => {
                        q.receivers.remove(i);
                    }
                }
                return Ok(step);
            }
            q.receivers.remove(i);
        } else if q.messages.is_empty() {
            if nonblock {
                return Ok(Step::Fail(Errno(EAGAIN)));
            }
            let step = must_wait(signal, deadline);
            if matches!(step, Step::Wait) {
                q.receivers.push(Receiver {
                    pid: me.0,
                    tid: me.1,
                    beat,
                    handed: None,
                });
            }
            return Ok(step);
        }
        let m = q.take().expect("the queue holds a message");
        q.touch(ATIME | MTIME | CTIME, now());
        // pipelined_receive: the first waiting sender's message fills the
        // slot.
        if let Some(s) = q.senders.iter_mut().find(|s| !s.done) {
            s.done = true;
            let waiting = s.msg.clone();
            q.insert(waiting);
        }
        Ok(Step::Done(m))
    })?;
    match step {
        Step::Done(m) => {
            if prio != 0 {
                c.write_u32(prio, m.prio)?;
            }
            c.write_mem(msg, &m.text)?;
            Ok(m.text.len() as u64)
        }
        Step::Fail(e) => Err(e),
        Step::Wait => Err(sleep(c, deadline)),
    }
}

/// `mq_notify`: the `struct sigevent`'s copy and checks (a
/// `SIGEV_THREAD` one's cookie and netlink socket), the descriptor, then
/// the registration: removed (by its owner) without one, `EBUSY` while
/// another process holds it.
pub fn mq_notify(c: &mut Ctx<'_>, fd: i32, sev: u64) -> SysResult {
    let reg = if sev != 0 {
        let b = c.read_mem(sev, SIGEVENT)?;
        let value = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let signo = i32::from_le_bytes(b[8..12].try_into().unwrap());
        let kind = i32::from_le_bytes(b[12..16].try_into().unwrap());
        if kind != mqueue::SIGEV_NONE && kind != mqueue::SIGEV_SIGNAL && kind != SIGEV_THREAD {
            return Err(Errno(EINVAL));
        }
        // valid_signal takes the number as unsigned.
        if kind == mqueue::SIGEV_SIGNAL && signo as u32 > 64 {
            return Err(Errno(EINVAL));
        }
        if kind == SIGEV_THREAD {
            c.read_mem(value, NOTIFY_COOKIE_LEN)?;
            // netlink_getsockbyfd.
            let sock = c.p.fds.file(signo)?;
            if sock.flags() & O_PATH != 0 {
                return Err(Errno(EBADF));
            }
            let FileObject::Socket(s) = &sock.object else {
                return Err(Errno(ENOTSOCK));
            };
            if s.domain != super::super::net::lx::AF_NETLINK {
                return Err(Errno(EINVAL));
            }
            return Err(Errno(ENOSYS));
        }
        Some(Notify {
            owner: c.p.pid,
            kind,
            signo,
            value,
        })
    } else {
        None
    };
    let file = queue_of(c, fd)?;
    let pid = c.p.pid;
    handle(&file).with(|q| {
        let held = q
            .notify
            .filter(|n| super::super::ipc::alive(n.owner) || n.owner == pid);
        match reg {
            None => {
                if held.is_some_and(|n| n.owner == pid) {
                    q.notify = None;
                    q.touch(ATIME | CTIME, now());
                }
            }
            Some(_) if held.is_some() => return Err(Errno(EBUSY)),
            Some(n) => {
                q.notify = Some(n);
                q.touch(ATIME | CTIME, now());
            }
        }
        Ok(0)
    })
}

/// `mq_getsetattr`: the new attributes' copy and flags (only
/// `O_NONBLOCK`), the descriptor, then the old attributes (with the
/// description's `O_NONBLOCK`) and the new flags.
pub fn mq_getsetattr(c: &mut Ctx<'_>, fd: i32, new: u64, old: u64) -> SysResult {
    let flags = if new != 0 {
        let b = c.read_mem(new, MQ_ATTR)?;
        let flags = u64::from_le_bytes(b[0..8].try_into().unwrap());
        if flags & !u64::from(O_NONBLOCK) != 0 {
            return Err(Errno(EINVAL));
        }
        Some(flags as u32)
    } else {
        None
    };
    let file = queue_of(c, fd)?;
    let q = handle(&file).with(|q| {
        let before = q.clone();
        if flags.is_some() {
            q.touch(ATIME | CTIME, now());
        }
        Ok(before)
    })?;
    let was = file.flags() & O_NONBLOCK;
    if let Some(f) = flags {
        let mut st = file.state.lock().unwrap();
        st.flags = (st.flags & !O_NONBLOCK) | f;
    }
    if old != 0 {
        let mut b = [0u8; MQ_ATTR];
        for (i, v) in [
            u64::from(was),
            q.maxmsg as u64,
            q.msgsize as u64,
            q.messages.len() as u64,
        ]
        .into_iter()
        .enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        c.write_mem(old, &b)?;
    }
    Ok(0)
}
