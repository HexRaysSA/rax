//! Linux AIO (`fs/aio.c`, Linux 6.19): `io_setup`, `io_destroy`,
//! `io_submit`, `io_cancel`, `io_getevents`, and `io_pgetevents`, on the
//! contexts of [`aio`](super::super::aio).
//!
//! Reads, writes, and syncs complete while `io_submit` runs, as they do in
//! the kernel for files without direct I/O: a read of an empty pipe makes
//! the caller sleep inside the call, and a signal then completes that
//! request with `-EINTR` while the submission goes on. The checks
//! `io_submit` itself fails on come first (`aio_prep_rw`, the access
//! mode, the vectors, `rw_verify_area`); what the transfer then returns,
//! error or not, is the request's completion. `IOCB_CMD_POLL` completes at
//! once when its file is ready and otherwise waits; waiting requests are
//! polled again as a thread enters each system call, and a thread sleeping
//! in any call wakes for their files, rather than completing at the file's
//! wake-up itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::vma_flags;
use super::super::aio::{AIO_MAX_NR, Context, EVENT_SIZE, Event, Handle, PendingPoll};
use super::super::fs::anon::Anon;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::process::ProcState;
use super::super::signal::deliver::restart::{
    ERESTART_RESTARTBLOCK, ERESTARTNOHAND, ERESTARTNOINTR, ERESTARTSYS,
};
use super::super::wait::{Resume, Wait};
use super::iov::import_iovec;
use super::ready::{ev, poll_files};
use super::{Ctx, SysResult, is_blocked};
use crate::user::mm::{Backing, Mapping, Perms, SharedObject, Vma};

/// `IOCB_CMD_*`.
mod cmd {
    pub const PREAD: u16 = 0;
    pub const PWRITE: u16 = 1;
    pub const FSYNC: u16 = 2;
    pub const FDSYNC: u16 = 3;
    pub const POLL: u16 = 5;
    pub const PREADV: u16 = 7;
    pub const PWRITEV: u16 = 8;
}
/// `IOCB_FLAG_RESFD`, `IOCB_FLAG_IOPRIO`.
const FLAG_RESFD: u32 = 1;
const FLAG_IOPRIO: u32 = 2;
/// `KIOCB_KEY`.
const KIOCB_KEY: u32 = 0;
/// How often a waiting `io_getevents` looks at the ring again.
const RECHECK: Duration = Duration::from_millis(2);

/// A `struct iocb`.
#[derive(Clone, Copy, Debug)]
struct Iocb {
    data: u64,
    rw_flags: u32,
    opcode: u16,
    reqprio: i16,
    fildes: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
    reserved2: u64,
    flags: u32,
    resfd: u32,
}

impl Iocb {
    fn decode(b: &[u8]) -> Self {
        let q = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let d = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Iocb {
            data: q(0),
            rw_flags: d(12),
            opcode: u16::from_le_bytes([b[16], b[17]]),
            reqprio: i16::from_le_bytes([b[18], b[19]]),
            fildes: d(20),
            buf: q(24),
            nbytes: q(32),
            offset: q(40) as i64,
            reserved2: q(48),
            flags: d(56),
            resfd: d(60),
        }
    }
}

/// `lookup_ioctx`: the ring's `id` field, read through the process's
/// mapping, names the table slot; the context there must have this
/// identifier.
fn lookup(c: &mut Ctx<'_>, id: u64) -> Result<Handle, Errno> {
    let index = c
        .read_u32(id + Context::ring_id_offset())
        .map_err(|_| Errno(EINVAL))?;
    let ctx = c.p.aio.lookup(id, index).ok_or(Errno(EINVAL))?;
    Ok(Handle {
        slot: index as usize,
        serial: ctx.serial,
    })
}

/// The context a call looked up; nothing kills it while the call runs.
fn context<'a>(c: &'a mut Ctx<'_>, h: Handle) -> &'a mut Context {
    c.p.aio.get(h).expect("held context")
}

/// `ioctx_alloc`'s limits: `EINVAL` beyond what the ring can index,
/// `EAGAIN` beyond `aio-max-nr`; the ring's slots and size.
fn geometry(max_reqs: u32) -> Result<(u32, u64), Errno> {
    let nr = max_reqs
        .max(super::super::aio::POSSIBLE_CPUS * 4)
        .wrapping_mul(2);
    if u64::from(nr) > 0x1000_0000 / EVENT_SIZE {
        return Err(Errno(EINVAL));
    }
    if nr == 0 || u64::from(max_reqs) > AIO_MAX_NR {
        return Err(Errno(EAGAIN));
    }
    Context::ring_geometry(max_reqs).ok_or(Errno(EINVAL))
}

/// `io_setup`: `*ctxp` must be 0 and `nr_events` not; the ring is mapped
/// shared (`/[aio]`), the context counted against `aio-max-nr`, and its
/// identifier stored (a failure there destroys it: `EFAULT`).
pub fn io_setup(c: &mut Ctx<'_>, nr_events: u32, ctxp: u64) -> SysResult {
    let old = c.read_u64(ctxp)?;
    if old != 0 || nr_events == 0 {
        return Err(Errno(EINVAL));
    }
    let (slots, size) = geometry(nr_events)?;
    // do_mmap checks MCL_FUTURE's lock against RLIMIT_MEMLOCK, though the
    // ring (VM_DONTEXPAND) then stays unlocked and uncounted.
    let at = super::mem::unmapped_area(c, 0, size, 0).map_err(|_| Errno(ENOMEM))?;
    if !super::mlock::future_ok(c.p, c.p.mm.def_lock, size) {
        return Err(Errno(ENOMEM));
    }
    let object = Arc::new(SharedObject::anonymous(size).map_err(|_| Errno(ENOMEM))?);
    c.p.space
        .map(
            at,
            size,
            Mapping {
                perms: Perms::READ | Perms::WRITE,
                backing: Backing::Shared {
                    object: object.clone(),
                    offset: 0,
                },
                shared: true,
                name: Some("/[aio] (deleted)".into()),
                flags: vma_flags::SPECIAL | vma_flags::AIO_RING,
            },
        )
        .map_err(|_| Errno(ENOMEM))?;
    if c.p.aio.aio_nr + u64::from(nr_events) > AIO_MAX_NR {
        unmap_ring(c, at, size);
        return Err(Errno(EAGAIN));
    }
    let index = c.p.aio.free_index();
    let h =
        c.p.aio
            .insert(Context::new(at, index, object, size, slots, nr_events));
    c.p.aio.aio_nr += u64::from(nr_events);
    if c.write_u64(ctxp, at).is_err() {
        kill(c, h);
        return Err(Errno(EFAULT));
    }
    Ok(0)
}

/// Unmaps a ring's range (`vm_munmap`), unless it is sealed.
fn unmap_ring(c: &mut Ctx<'_>, at: u64, size: u64) {
    if super::mseal::sealed_in(c.p, at, size) {
        return;
    }
    super::mlock::unmapped(c.p, at, size);
    let _ = c.p.space.unmap(at, size);
}

/// `aio_poll_cancel` and `aio_poll_complete_work`: a cancelled poll
/// request completes with whatever of its events the file reports then.
fn cancel_poll(c: &Ctx<'_>, ctx: &mut Context, p: PendingPoll) {
    let (polled, _) = poll_files(c, &[(&p.file, p.events)]);
    let mask = polled[0].mask & p.events;
    complete(ctx, p.obj, p.data, i64::from(mask), p.resfd.as_deref());
}

/// `kill_ioctx`: waiting polls complete as cancelled, the ring is
/// unmapped, and the context leaves the table and the count.
fn kill(c: &mut Ctx<'_>, h: Handle) {
    let mut ctx = c.p.aio.contexts[h.slot].take().expect("live context");
    for poll in std::mem::take(&mut ctx.polls) {
        cancel_poll(c, &mut ctx, poll);
    }
    c.p.aio.aio_nr -= u64::from(ctx.max_reqs);
    unmap_ring(c, ctx.id, ctx.mmap_size);
}

/// `aio_ring_mremap`, before a VMA moves: for a ring, the live context it
/// maps (`EINVAL` without one, as in a forked child whose table is empty).
pub fn ring_owner(p: &ProcState, vma: &Vma) -> Result<Option<usize>, Errno> {
    if vma.flags & vma_flags::AIO_RING == 0 {
        return Ok(None);
    }
    let Backing::Shared { object, .. } = &vma.backing else {
        return Err(Errno(EINVAL));
    };
    p.aio
        .contexts
        .iter()
        .position(|x| x.as_ref().is_some_and(|x| Arc::ptr_eq(&x.ring, object)))
        .map(Some)
        .ok_or(Errno(EINVAL))
}

/// `aio_ring_mremap`, once the ring moved: the context's identifier is its
/// new start (so `io_destroy` unmaps from there).
pub fn ring_moved(p: &mut ProcState, owner: Option<usize>, to: u64) {
    if let Some(ctx) = owner.and_then(|i| p.aio.contexts[i].as_mut()) {
        ctx.id = to;
    }
}

/// `io_destroy`.
pub fn io_destroy(c: &mut Ctx<'_>, id: u64) -> SysResult {
    let h = lookup(c, id)?;
    kill(c, h);
    Ok(0)
}

/// `aio_complete`, then the `eventfd` signal (`IOCB_FLAG_RESFD`), which
/// wakes its readers.
fn complete(ctx: &mut Context, obj: u64, data: u64, res: i64, resfd: Option<&OpenFile>) {
    ctx.complete(Event {
        data,
        obj,
        res,
        res2: 0,
    });
    if let Some(f) = resfd
        && let FileObject::Anon(Anon::Event(e)) = &f.object
    {
        e.signal();
        f.woke(ev::IN | ev::RDNORM);
    }
}

/// What submitting one request came to.
enum Submitted {
    /// Queued (completed or waiting).
    Done,
    /// It failed, and `io_submit` stops with this error.
    Failed(Errno),
    /// Its transfer sleeps.
    Blocked(Errno),
}

/// `io_submit`: up to the ring's size of the `iocb`s at `iocbpp`, in
/// order, until one fails; the count submitted, or the first one's error.
/// A request whose transfer sleeps resumes where it slept; if another
/// thread destroyed the context meanwhile, the call returns the requests
/// before it.
pub fn io_submit(c: &mut Ctx<'_>, id: u64, nr: i64, iocbpp: u64) -> SysResult {
    let (h, start, mut inner) = match c.resume.take() {
        Some(Resume::Aio { ctx, index, inner }) => {
            if c.p.aio.get(ctx).is_none() {
                return if index > 0 {
                    Ok(index)
                } else {
                    Err(Errno(EINVAL))
                };
            }
            (ctx, index, Some(*inner))
        }
        _ => {
            if nr < 0 {
                return Err(Errno(EINVAL));
            }
            (lookup(c, id)?, 0, None)
        }
    };
    let nr = (nr as u64).min(u64::from(context(c, h).nr_events));
    for i in start..nr {
        let Ok(ptr) = c.read_u64(iocbpp + 8 * i) else {
            return if i > 0 { Ok(i) } else { Err(Errno(EFAULT)) };
        };
        c.resume = inner.take();
        match submit_one(c, h, ptr) {
            Submitted::Done => {}
            Submitted::Failed(e) => return if i > 0 { Ok(i) } else { Err(e) },
            Submitted::Blocked(e) => {
                if let Some((_, resume)) = c.block.as_mut() {
                    let own = std::mem::replace(resume, Resume::Retry);
                    *resume = Resume::Aio {
                        ctx: h,
                        index: i,
                        inner: Box::new(own),
                    };
                }
                return Err(e);
            }
        }
    }
    Ok(nr)
}

/// `io_submit_one` and `__io_submit_one`.
fn submit_one(c: &mut Ctx<'_>, h: Handle, ptr: u64) -> Submitted {
    use Submitted::*;
    let Ok(raw) = c.read_mem(ptr, 64) else {
        return Failed(Errno(EFAULT));
    };
    let iocb = Iocb::decode(&raw);
    if iocb.reserved2 != 0 {
        return Failed(Errno(EINVAL));
    }
    if (iocb.nbytes as i64) < 0 {
        return Failed(Errno(EINVAL));
    }
    if !context(c, h).get_req() {
        return Failed(Errno(EAGAIN));
    }
    let r = queue(c, h, ptr, &iocb);
    if !matches!(r, Done) {
        // iocb_destroy: the slot goes back.
        context(c, h).put_reqs(1);
    }
    r
}

/// `__io_submit_one` after the slot: the descriptor, the `eventfd`, the
/// key, then the operation.
fn queue(c: &mut Ctx<'_>, h: Handle, ptr: u64, iocb: &Iocb) -> Submitted {
    use Submitted::*;
    let file = match c.p.fds.file(iocb.fildes as i32) {
        Ok(f) if !matches!(f.object, FileObject::PathOnly) => f,
        _ => return Failed(Errno(EBADF)),
    };
    // eventfd_ctx_fdget: fdget passes over O_PATH descriptors too.
    let resfd = if iocb.flags & FLAG_RESFD != 0 {
        match c.p.fds.file(iocb.resfd as i32) {
            Ok(f) if matches!(f.object, FileObject::Anon(Anon::Event(_))) => Some(f),
            Ok(f) if !matches!(f.object, FileObject::PathOnly) => return Failed(Errno(EINVAL)),
            _ => return Failed(Errno(EBADF)),
        }
    } else {
        None
    };
    if c.write_u32(ptr + 8, KIOCB_KEY).is_err() {
        return Failed(Errno(EFAULT));
    }
    let result = match iocb.opcode {
        cmd::PREAD | cmd::PREADV | cmd::PWRITE | cmd::PWRITEV => rw(c, &file, iocb),
        cmd::FSYNC | cmd::FDSYNC => fsync(c, iocb),
        cmd::POLL => return poll(c, h, ptr, iocb, file, resfd),
        _ => return Failed(Errno(EINVAL)),
    };
    match result {
        Ok(res) => {
            complete(context(c, h), ptr, iocb.data, res, resfd.as_deref());
            Done
        }
        Err(Err2::Submit(e)) => Failed(e),
        Err(Err2::Blocked(e)) => Blocked(e),
    }
}

/// An operation's failure: of the submission, or a sleep.
enum Err2 {
    Submit(Errno),
    Blocked(Errno),
}

/// The completion result of a transfer's outcome (`aio_rw_done`: a
/// restart is `-EINTR`).
fn result(r: SysResult) -> Result<i64, Err2> {
    match r {
        Ok(n) => Ok(n as i64),
        Err(e) if is_blocked::<u64>(&Err(e)) => Err(Err2::Blocked(e)),
        Err(Errno(e))
            if e == ERESTARTSYS
                || e == ERESTARTNOINTR
                || e == ERESTARTNOHAND
                || e == ERESTART_RESTARTBLOCK =>
        {
            Ok(-(EINTR as i64))
        }
        Err(Errno(e)) => Ok(-(e as i64)),
    }
}

/// `aio_read` and `aio_write`: `aio_prep_rw` (the I/O priority, the
/// `RWF_*` flags), the access mode (`EBADF`), a file that cannot do it
/// (`EINVAL`), the buffer or vectors, and `rw_verify_area`; then the
/// transfer, positioned on files with positions and not on streams.
fn rw(c: &mut Ctx<'_>, file: &OpenFile, iocb: &Iocb) -> Result<i64, Err2> {
    let write = matches!(iocb.opcode, cmd::PWRITE | cmd::PWRITEV);
    let vectored = matches!(iocb.opcode, cmd::PREADV | cmd::PWRITEV);
    let fail = |e: i32| Err(Err2::Submit(Errno(e)));
    if iocb.flags & FLAG_IOPRIO != 0 {
        let root = c.p.creds.1 == 0;
        if let Err(e) = super::super::priority::ioprio_check(i32::from(iocb.reqprio), root) {
            return Err(Err2::Submit(e));
        }
    }
    super::io::check_rw_flags(file, u64::from(iocb.rw_flags)).map_err(Err2::Submit)?;
    if (write && !file.writable()) || (!write && !file.readable()) {
        return fail(EBADF);
    }
    // Files without read_iter or write_iter.
    let unsupported = file.ftype == FileType::Directory
        || matches!(
            file.object,
            FileObject::Anon(Anon::Epoll(_) | Anon::Pid(_) | Anon::Inotify(_))
                | FileObject::Mqueue(_)
        );
    if unsupported {
        return fail(EINVAL);
    }
    let count = if vectored {
        match import_iovec(c, iocb.buf, iocb.nbytes) {
            Ok(v) => v.iter().map(|&(_, l)| l).sum::<u64>(),
            Err(e) => return Err(Err2::Submit(e)),
        }
    } else {
        let len = iocb.nbytes.min(super::io::MAX_RW_COUNT);
        if !super::events::access_ok(c, iocb.buf, len) {
            return fail(EFAULT);
        }
        len
    };
    // rw_verify_area with the request's position.
    if iocb.offset < 0 || iocb.offset.checked_add(count as i64).is_none() {
        return fail(EINVAL);
    }
    let fd = iocb.fildes as i32;
    let positioned = matches!(file.ftype, FileType::Regular | FileType::BlockDevice);
    let pos = iocb.offset;
    let (buf, n) = (iocb.buf, iocb.nbytes);
    c.sigpipe_decided = false;
    c.nosignal = u64::from(iocb.rw_flags) & super::io::rwf::NOSIGNAL != 0;
    let r = match (write, vectored, positioned) {
        (false, false, true) => super::io::pread(c, fd, buf, n, pos),
        (false, false, false) => super::io::read(c, fd, buf, n),
        (false, true, true) => super::io::preadv(c, fd, buf, n, pos, 0),
        (false, true, false) => super::io::readv(c, fd, buf, n),
        (true, false, true) => super::io::pwrite(c, fd, buf, n, pos),
        (true, false, false) => super::io::write(c, fd, buf, n),
        (true, true, true) => super::io::pwritev(c, fd, buf, n, pos, 0),
        (true, true, false) => super::io::writev(c, fd, buf, n),
    };
    // pipe_write's SIGPIPE (the socket protocols send their own).
    if write && matches!(r, Err(Errno(EPIPE))) && !c.sigpipe_decided {
        c.send_sigpipe();
    }
    c.nosignal = false;
    result(r)
}

/// `aio_fsync`: no buffer, offset, length, or flags (`EINVAL`), and a
/// file that can be synced (`EINVAL`); the sync's result completes it.
fn fsync(c: &mut Ctx<'_>, iocb: &Iocb) -> Result<i64, Err2> {
    if iocb.buf != 0 || iocb.offset != 0 || iocb.nbytes != 0 || iocb.rw_flags != 0 {
        return Err(Err2::Submit(Errno(EINVAL)));
    }
    match super::io::fsync(c, iocb.fildes as i32) {
        Err(Errno(EINVAL)) => Err(Err2::Submit(Errno(EINVAL))),
        r => result(r),
    }
}

/// `aio_poll`: events within 16 bits and no offset, length, or flags
/// (`EINVAL`); ready events complete it at once, a file that can be
/// waited on keeps it waiting, and one that cannot (no poll queue) with
/// nothing ready is `EINVAL`.
fn poll(
    c: &mut Ctx<'_>,
    h: Handle,
    ptr: u64,
    iocb: &Iocb,
    file: Arc<OpenFile>,
    resfd: Option<Arc<OpenFile>>,
) -> Submitted {
    if iocb.buf > u64::from(u16::MAX) {
        return Submitted::Failed(Errno(EINVAL));
    }
    if iocb.offset != 0 || iocb.nbytes != 0 || iocb.rw_flags != 0 {
        return Submitted::Failed(Errno(EINVAL));
    }
    let events = iocb.buf as u32 | ev::ERR | ev::HUP;
    let (polled, _) = poll_files(c, &[(&file, events)]);
    let mask = polled[0].mask & events;
    if mask != 0 {
        complete(
            context(c, h),
            ptr,
            iocb.data,
            i64::from(mask),
            resfd.as_deref(),
        );
        return Submitted::Done;
    }
    if !has_poll(&file) {
        return Submitted::Failed(Errno(EINVAL));
    }
    context(c, h).polls.push(PendingPoll {
        obj: ptr,
        data: iocb.data,
        file,
        events,
        resfd,
    });
    Submitted::Done
}

/// Whether the file has a `poll` operation, which an `IOCB_CMD_POLL`
/// request waits on (`aio_poll_queue_proc`): the anonymous files, message
/// queues, sockets, pipes, and character devices (terminals; the memory
/// devices, which have none, are taken to have one), not regular files,
/// directories, or block devices.
fn has_poll(file: &OpenFile) -> bool {
    match &file.object {
        FileObject::Anon(_) | FileObject::Mqueue(_) | FileObject::Socket(_) => true,
        _ => matches!(
            file.ftype,
            FileType::Fifo | FileType::CharDevice | FileType::Socket
        ),
    }
}

/// The key of the wake-up that readied a waiting poll request, whose
/// requested events are now `ready`: `aio_poll_wake` completes the request
/// with the whole key. Data or space wakes with one on a pipe
/// (`pipe_write`, `pipe_read`), a socket (`sock_def_readable`,
/// `sock_def_write_space`, `unix_write_space`), an `eventfd`, a `timerfd`,
/// or an `epoll` instance (`ep_poll_safewake`). A hang-up or an error, and
/// any other file, wakes without one (`wake_up_interruptible_all`,
/// `wake_up`): `aio_poll_complete_work` polls the file again (`None`).
fn wake_key(file: &OpenFile, ready: u32) -> Option<u32> {
    use ev::*;
    if ready & (HUP | ERR | RDHUP) != 0 {
        return None;
    }
    let (reads, writes) = match &file.object {
        FileObject::Anon(Anon::Event(_)) => (IN, OUT),
        FileObject::Anon(Anon::Timer(_) | Anon::Epoll(_)) => (IN, 0),
        FileObject::Socket(_) => (IN | PRI | RDNORM | RDBAND, OUT | WRNORM | WRBAND),
        _ if file.ftype == FileType::Fifo => (IN | RDNORM, OUT | WRNORM),
        _ => return None,
    };
    if ready & (IN | RDNORM) != 0 && reads != 0 {
        Some(reads)
    } else if ready & (OUT | WRNORM) != 0 && writes != 0 {
        Some(writes)
    } else {
        None
    }
}

/// Polls the waiting `IOCB_CMD_POLL` requests of every context again,
/// completing those whose file is ready; returns what to wait on for the
/// rest.
pub fn poll_pending(c: &mut Ctx<'_>) -> Wait {
    let mut wait = Wait::event();
    for index in 0..c.p.aio.contexts.len() {
        let Some(polls) = c.p.aio.contexts[index]
            .as_mut()
            .map(|x| std::mem::take(&mut x.polls))
        else {
            continue;
        };
        let mut keep = Vec::new();
        for p in polls {
            let (polled, w) = poll_files(c, &[(&p.file, p.events)]);
            let mask = polled[0].mask & p.events;
            let ctx = c.p.aio.contexts[index].as_mut().expect("polled context");
            if mask != 0 {
                let res = wake_key(&p.file, mask).unwrap_or(mask);
                complete(ctx, p.obj, p.data, i64::from(res), p.resfd.as_deref());
            } else {
                wait.fds.extend(w.fds);
                keep.push(p);
            }
        }
        c.p.aio.contexts[index]
            .as_mut()
            .expect("polled context")
            .polls = keep;
    }
    wait
}

/// `io_cancel`: the key (`EFAULT`, `EINVAL`), the context (`EINVAL`), then
/// a waiting poll request, which completes with what its file reports
/// (`EINPROGRESS`: the event goes to the ring, never to `result`); any
/// other request cannot be cancelled (`EINVAL`).
pub fn io_cancel(c: &mut Ctx<'_>, id: u64, iocb: u64, _result: u64) -> SysResult {
    if c.read_u32(iocb + 8)? != KIOCB_KEY {
        return Err(Errno(EINVAL));
    }
    let h = lookup(c, id)?;
    let ctx = context(c, h);
    let Some(at) = ctx.polls.iter().position(|p| p.obj == iocb) else {
        return Err(Errno(EINVAL));
    };
    let p = ctx.polls.remove(at);
    let mut ctx = c.p.aio.contexts[h.slot].take().expect("held context");
    cancel_poll(c, &mut ctx, p);
    c.p.aio.contexts[h.slot] = Some(ctx);
    Err(Errno(EINPROGRESS))
}

/// A relative timeout as `timespec64_to_ktime` makes it: `None` waits
/// forever (`KTIME_MAX`, which `KTIME_SEC_MAX` seconds or more give), else
/// nanoseconds, where 0 reads once and a negative time has already passed.
fn ktime((sec, nsec): (i64, i64)) -> Option<i64> {
    const KTIME_SEC_MAX: i64 = i64::MAX / 1_000_000_000;
    if sec >= KTIME_SEC_MAX {
        return None;
    }
    Some(sec.wrapping_mul(1_000_000_000).wrapping_add(nsec)).filter(|&t| t != i64::MAX)
}

/// `aio_read_events`: copies up to `nr - got` events after the `got`
/// already copied, moving the ring's head past them only once all are out
/// (a fault leaves every one in the ring: the count so far, or `EFAULT`);
/// a context killed meanwhile ends the read (the count so far, or
/// `EINVAL`). Whether the read is over: an error, or `min_nr` reached.
fn read_events(
    c: &mut Ctx<'_>,
    h: Handle,
    min_nr: i64,
    nr: i64,
    events: u64,
    got: &mut i64,
) -> Result<bool, Errno> {
    let Some(ctx) = c.p.aio.get(h) else {
        return if *got > 0 {
            Ok(true)
        } else {
            Err(Errno(EINVAL))
        };
    };
    let (taken, head) = ctx.peek_events((nr - *got) as usize);
    if !taken.is_empty() {
        let bytes: Vec<u8> = taken.iter().flat_map(Event::encode).collect();
        let at = events.wrapping_add(*got as u64 * EVENT_SIZE);
        if c.write_mem(at, &bytes).is_err() {
            return if *got > 0 {
                Ok(true)
            } else {
                Err(Errno(EFAULT))
            };
        }
        *got += taken.len() as i64;
    }
    if let Some(head) = head {
        context(c, h).set_head(head);
    }
    Ok(*got >= min_nr)
}

/// `do_io_getevents` and `read_events`: at least `min_nr` and at most `nr`
/// events copied out, waiting for them until `timeout` or a signal; the
/// count copied, which the caller turns into `-EINTR` or `-ERESTARTNOHAND`
/// when it is 0 and a signal is pending. Waiting `IOCB_CMD_POLL` requests
/// are polled again each time the ring is read.
fn getevents(
    c: &mut Ctx<'_>,
    id: u64,
    min_nr: i64,
    nr: i64,
    events: u64,
    timeout: Option<(i64, i64)>,
) -> SysResult {
    let (h, mut got, deadline) = match c.resume.take() {
        Some(Resume::AioEvents { ctx, got, deadline }) => (ctx, got as i64, deadline),
        _ => {
            let h = lookup(c, id)?;
            if min_nr > nr || min_nr < 0 {
                return Err(Errno(EINVAL));
            }
            let until = timeout.and_then(ktime);
            let mut got = 0;
            poll_pending(c);
            let done = read_events(c, h, min_nr, nr, events, &mut got)?;
            if done || until == Some(0) {
                return Ok(got as u64);
            }
            let deadline = until.map(|ns| {
                let d = Duration::from_nanos(ns.max(0) as u64);
                Instant::now().checked_add(d)
            });
            (h, got, deadline.flatten())
        }
    };
    // The wait ends at the deadline or a signal, after one more read.
    let now = Instant::now();
    let stop = deadline.is_some_and(|d| d <= now) || c.signal_pending();
    let mut wait = poll_pending(c);
    if read_events(c, h, min_nr, nr, events, &mut got)? || stop {
        return Ok(got as u64);
    }
    let recheck = now + RECHECK;
    wait.deadline = Some(deadline.map_or(recheck, |d| d.min(recheck)));
    Err(c.block(
        wait,
        Resume::AioEvents {
            ctx: h,
            got: got as u64,
            deadline,
        },
    ))
}

/// Reads a `struct __kernel_timespec` (`EFAULT`); `None` for no pointer.
fn read_timeout(c: &Ctx<'_>, at: u64) -> Result<Option<(i64, i64)>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    let b = c.read_mem(at, 16)?;
    let sec = i64::from_le_bytes(b[..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(b[8..].try_into().unwrap());
    Ok(Some((sec, nsec)))
}

/// `io_getevents`: 0 events and a pending signal is `-EINTR`.
pub fn io_getevents(
    c: &mut Ctx<'_>,
    id: u64,
    min_nr: i64,
    nr: i64,
    events: u64,
    timeout: u64,
) -> SysResult {
    let resumed = matches!(c.resume, Some(Resume::AioEvents { .. }));
    let ts = if resumed {
        None
    } else {
        read_timeout(c, timeout)?
    };
    let got = getevents(c, id, min_nr, nr, events, ts)?;
    if got == 0 && c.signal_pending() {
        return Err(Errno(EINTR));
    }
    Ok(got)
}

/// `io_pgetevents`: the timeout (`EFAULT`), the `struct __aio_sigset`
/// (`EFAULT`) and its mask (`set_user_sigmask`), then the wait; 0 events
/// and a pending signal is `-ERESTARTNOHAND`, with the caller's mask
/// restored after the handler runs.
pub fn io_pgetevents(
    c: &mut Ctx<'_>,
    id: u64,
    min_nr: i64,
    nr: i64,
    events: u64,
    timeout: u64,
    usig: u64,
) -> SysResult {
    let resumed = matches!(c.resume, Some(Resume::AioEvents { .. }));
    let ts = if resumed {
        None
    } else {
        let ts = read_timeout(c, timeout)?;
        if usig != 0 {
            let b = c.read_mem(usig, 16)?;
            let mask = u64::from_le_bytes(b[..8].try_into().unwrap());
            let size = u64::from_le_bytes(b[8..].try_into().unwrap());
            if mask != 0 {
                super::io::set_user_sigmask(c, mask, size)?;
            }
        }
        ts
    };
    let r = getevents(c, id, min_nr, nr, events, ts);
    if is_blocked(&r) {
        return r;
    }
    let interrupted = c.signal_pending();
    // restore_saved_sigmask_unless(interrupted).
    if !interrupted && let Some(mask) = c.t.saved_sigmask.take() {
        let (p, mut th) = c.split();
        super::super::signal::deliver::set_blocked(p, &mut th, mask);
    }
    let got = r?;
    if got == 0 && interrupted {
        return Err(Errno(ERESTARTNOHAND));
    }
    Ok(got)
}
