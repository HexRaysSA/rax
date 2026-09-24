//! `epoll` system calls (`fs/eventpoll.c`): `epoll_create`,
//! `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`, and
//! `epoll_pwait2`. The instance is [`Epoll`].
//!
//! `struct epoll_event` is packed on x86-64 (12 bytes: `events` at 0,
//! `data` at 4) and naturally aligned elsewhere (16 bytes: `data` at 8).
//! A wait is never restarted after a signal handler: it ends with `EINTR`
//! (`ep_poll`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::abi::LinuxAbi;
use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::{O_CLOEXEC, O_RDWR};
use super::super::fs::anon::Anon;
use super::super::fs::epoll::{
    EP_PRIVATE_BITS, EPOLLET, EPOLLEXCLUSIVE, EPOLLWAKEUP, Epoll, is_epoll,
};
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::wait::{Resume, Wait};
use super::ready::{Polled, earlier, ev, poll_files};
use super::{Ctx, Outcome, SysResult};

const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;
/// `EP_MAX_NESTS`.
const EP_MAX_NESTS: usize = 4;
/// `EPOLLEXCLUSIVE_OK_BITS`.
const EPOLLEXCLUSIVE_OK_BITS: u32 =
    ev::IN | ev::OUT | ev::ERR | ev::HUP | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;

/// `sizeof(struct epoll_event)`.
fn event_size(abi: LinuxAbi) -> u64 {
    match abi {
        LinuxAbi::X86_64 => 12,
        _ => 16,
    }
}

/// Reads a `struct epoll_event`.
fn read_event(c: &Ctx<'_>, addr: u64) -> Result<(u32, u64), Errno> {
    let b = c.read_mem(addr, event_size(c.p.abi) as usize)?;
    let events = u32::from_le_bytes(b[..4].try_into().unwrap());
    let at = if c.p.abi == LinuxAbi::X86_64 { 4 } else { 8 };
    let data = u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    Ok((events, data))
}

/// Encodes a `struct epoll_event`.
fn encode_event(abi: LinuxAbi, events: u32, data: u64) -> Vec<u8> {
    let mut b = vec![0u8; event_size(abi) as usize];
    b[..4].copy_from_slice(&events.to_le_bytes());
    let at = if abi == LinuxAbi::X86_64 { 4 } else { 8 };
    b[at..at + 8].copy_from_slice(&data.to_le_bytes());
    b
}

/// `epoll_create1`.
pub fn epoll_create1(c: &mut Ctx<'_>, flags: u32) -> SysResult {
    if flags & !O_CLOEXEC != 0 {
        return Err(Errno(EINVAL));
    }
    let file = OpenFile::new(
        FileObject::Anon(Anon::Epoll(Epoll::new())),
        FileType::Anon,
        "anon_inode:[eventpoll]",
        None,
        O_RDWR,
    );
    super::io::install(c, file, flags & O_CLOEXEC != 0)
}

/// `epoll_create`: the size hint must be positive.
pub fn epoll_create(c: &mut Ctx<'_>, size: i32) -> SysResult {
    if size <= 0 {
        return Err(Errno(EINVAL));
    }
    epoll_create1(c, 0)
}

fn as_epoll(file: &OpenFile) -> &Epoll {
    match &file.object {
        FileObject::Anon(Anon::Epoll(ep)) => ep,
        _ => unreachable!("checked with is_epoll"),
    }
}

/// `file_can_poll`: files without a `poll` operation (regular files and
/// directories on the usual file systems, synthesized files) cannot be
/// watched.
fn can_poll(file: &OpenFile) -> bool {
    match &file.object {
        FileObject::Synthetic(_) => false,
        FileObject::Host(_) => !matches!(file.ftype, FileType::Regular | FileType::Directory),
        _ => true,
    }
}

/// The instances reachable from the descriptor table and the instances
/// each of them watches, by description address.
fn instance_graph(c: &Ctx<'_>) -> Vec<(Arc<OpenFile>, Vec<Arc<OpenFile>>)> {
    let mut nodes: Vec<(Arc<OpenFile>, Vec<Arc<OpenFile>>)> = Vec::new();
    let mut todo: Vec<Arc<OpenFile>> = (0..c.p.fds.max_fds() as i32)
        .filter_map(|fd| c.p.fds.file(fd).ok())
        .filter(|f| is_epoll(f))
        .collect();
    while let Some(f) = todo.pop() {
        if nodes.iter().any(|(n, _)| Arc::ptr_eq(n, &f)) {
            continue;
        }
        let nested = as_epoll(&f).nested();
        todo.extend(nested.iter().cloned());
        nodes.push((f, nested));
    }
    nodes
}

/// `ep_loop_check`: whether watching instance `to` from instance `ep`
/// would close a loop or nest instances more than `EP_MAX_NESTS` deep.
fn loop_check(c: &Ctx<'_>, ep: &Arc<OpenFile>, to: &Arc<OpenFile>) -> bool {
    let graph = instance_graph(c);
    let children = |f: &Arc<OpenFile>| -> Vec<Arc<OpenFile>> {
        graph
            .iter()
            .find(|(n, _)| Arc::ptr_eq(n, f))
            .map(|(_, k)| k.clone())
            .unwrap_or_default()
    };
    // Downward from `to`; reaching `ep` is a loop.
    fn down(
        f: &Arc<OpenFile>,
        ep: &Arc<OpenFile>,
        depth: usize,
        children: &dyn Fn(&Arc<OpenFile>) -> Vec<Arc<OpenFile>>,
    ) -> usize {
        let mut result = 0;
        for k in children(f) {
            if Arc::ptr_eq(&k, ep) || depth > EP_MAX_NESTS {
                return usize::MAX;
            }
            result = result.max(down(&k, ep, depth + 1, children).saturating_add(1));
            if result > EP_MAX_NESTS {
                break;
            }
        }
        result
    }
    let depth = down(to, ep, 0, &children);
    if depth > EP_MAX_NESTS {
        return true;
    }
    // Upward from `ep`: the longest chain of instances watching it.
    fn up(f: &Arc<OpenFile>, graph: &[(Arc<OpenFile>, Vec<Arc<OpenFile>>)], seen: usize) -> usize {
        if seen > graph.len() {
            return usize::MAX / 2;
        }
        graph
            .iter()
            .filter(|(_, kids)| kids.iter().any(|k| Arc::ptr_eq(k, f)))
            .map(|(parent, _)| up(parent, graph, seen + 1) + 1)
            .max()
            .unwrap_or(0)
    }
    depth + 1 + up(ep, &graph, 0) > EP_MAX_NESTS
}

/// Polls one file for `events`.
fn poll_one(c: &Ctx<'_>, file: &OpenFile, events: u32) -> Polled {
    poll_files(c, &[(file, events)]).0[0]
}

/// `epoll_ctl`, with the kernel's order of checks (`do_epoll_ctl`).
pub fn epoll_ctl(c: &mut Ctx<'_>, epfd: i32, op: i32, fd: i32, event: u64) -> SysResult {
    let has_event = op != EPOLL_CTL_DEL;
    let (mut events, data) = if has_event {
        read_event(c, event)?
    } else {
        (0, 0)
    };
    let epf = c.p.fds.file(epfd)?;
    let tf = c.p.fds.file(fd)?;
    // fdget refuses O_PATH descriptions.
    if matches!(epf.object, FileObject::PathOnly) || matches!(tf.object, FileObject::PathOnly) {
        return Err(Errno(EBADF));
    }
    if !can_poll(&tf) {
        return Err(Errno(EPERM));
    }
    // ep_take_care_of_epollwakeup: without CAP_BLOCK_SUSPEND the flag is
    // dropped.
    if has_event && c.p.creds.1 != 0 {
        events &= !EPOLLWAKEUP;
    }
    if Arc::ptr_eq(&epf, &tf) || !is_epoll(&epf) {
        return Err(Errno(EINVAL));
    }
    if has_event && events & EPOLLEXCLUSIVE != 0 {
        if op == EPOLL_CTL_MOD {
            return Err(Errno(EINVAL));
        }
        if op == EPOLL_CTL_ADD && (is_epoll(&tf) || events & !EPOLLEXCLUSIVE_OK_BITS != 0) {
            return Err(Errno(EINVAL));
        }
    }
    if op == EPOLL_CTL_ADD && is_epoll(&tf) && loop_check(c, &epf, &tf) {
        return Err(Errno(ELOOP));
    }
    let ep = as_epoll(&epf);
    match op {
        EPOLL_CTL_ADD => {
            if ep.contains(&tf, fd) {
                return Err(Errno(EEXIST));
            }
            events |= ev::ERR | ev::HUP;
            let now = poll_one(c, &tf, events);
            ep.insert(&epf, &tf, fd, events, data, now);
            Ok(0)
        }
        EPOLL_CTL_DEL => {
            if ep.remove(&tf, fd) {
                Ok(0)
            } else {
                Err(Errno(ENOENT))
            }
        }
        EPOLL_CTL_MOD => {
            let now = poll_one(c, &tf, events | ev::ERR | ev::HUP);
            match ep.modify(&tf, fd, events | ev::ERR | ev::HUP, data, now) {
                Some(true) => Ok(0),
                Some(false) => Err(Errno(EINVAL)),
                None => Err(Errno(ENOENT)),
            }
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// An instance's readiness for `poll`, `select`, and an enclosing
/// instance (`ep_eventpoll_poll`): readable while an item on its ready
/// list reports a wanted event; its level is how many items are ready.
pub fn poll_instance(c: &Ctx<'_>, ep: &Epoll, events: u32) -> (Polled, Wait) {
    let items = ep.items();
    let refs: Vec<(&OpenFile, u32)> = items
        .iter()
        .map(|(_, f, e)| (&**f, *e & !EP_PRIVATE_BITS))
        .collect();
    let (polled, wait) = poll_files(c, &refs);
    ep.scan(&items, &polled);
    let ready = ep.has_ready(&items, &polled);
    let level = items
        .iter()
        .zip(&polled)
        .filter(|((_, _, e), p)| p.mask & e & !EP_PRIVATE_BITS != 0)
        .count() as u64;
    let p = Polled {
        mask: if ready { ev::IN | ev::RDNORM } else { 0 },
        level,
    };
    let wait = if events & (ev::IN | ev::RDNORM) != 0 {
        wait
    } else {
        Wait::event()
    };
    (p, wait)
}

/// `do_epoll_wait` until `deadline` (`None`: no limit; `zero`: do not
/// sleep).
fn wait_events(
    c: &mut Ctx<'_>,
    epfd: i32,
    events: u64,
    maxevents: i32,
    deadline: Option<Instant>,
    zero: bool,
) -> Result<Outcome, Errno> {
    let size = event_size(c.p.abi);
    if maxevents <= 0 || maxevents as u64 > i32::MAX as u64 / size {
        return Err(Errno(EINVAL));
    }
    let len = maxevents as u64 * size;
    if events
        .checked_add(len)
        .is_none_or(|end| end > c.p.abi.task_size())
    {
        return Err(Errno(EFAULT));
    }
    let file = c.p.fds.file(epfd)?;
    if matches!(file.object, FileObject::PathOnly) {
        return Err(Errno(EBADF));
    }
    if !is_epoll(&file) {
        return Err(Errno(EINVAL));
    }
    let ep = as_epoll(&file);
    let items = ep.items();
    let refs: Vec<(&OpenFile, u32)> = items
        .iter()
        .map(|(_, f, e)| (&**f, *e & !EP_PRIVATE_BITS))
        .collect();
    let (polled, mut wait) = poll_files(c, &refs);
    ep.scan(&items, &polled);
    // As many events as the buffer takes before a fault; an event that
    // cannot be copied stays ready (EFAULT when it is the first).
    let fit = writable_prefix(c, events, len) / size;
    if fit == 0 {
        if ep.has_ready(&items, &polled) {
            return Err(Errno(EFAULT));
        }
    } else {
        let got = ep.send(fit.min(maxevents as u64) as usize, &items, &polled);
        if !got.is_empty() {
            let mut b = Vec::with_capacity(got.len() * size as usize);
            for &(e, d) in &got {
                b.extend(encode_event(c.p.abi, e, d));
            }
            c.write_mem(events, &b)?;
            return Ok(Outcome::Return(got.len() as u64));
        }
    }
    if zero || deadline.is_some_and(|d| d <= Instant::now()) {
        return Ok(Outcome::Return(0));
    }
    if c.signal_pending() {
        return Err(Errno(EINTR));
    }
    wait.deadline = earlier(wait.deadline, deadline);
    Err(c.block(wait, Resume::Until(deadline)))
}

/// The bytes from `addr` the guest can write, up to `len`.
fn writable_prefix(c: &Ctx<'_>, addr: u64, len: u64) -> u64 {
    use crate::error::MemoryAccessKind;
    match c.p.space.probe(addr, len as usize, MemoryAccessKind::Write) {
        Ok(()) => len,
        Err(f) => f.address.saturating_sub(addr).min(len),
    }
}

/// The deadline of a call that slept and runs again, if it did.
fn resumed(c: &mut Ctx<'_>) -> Option<Option<Instant>> {
    match c.resume.take() {
        Some(Resume::Until(d)) => Some(d),
        _ => None,
    }
}

/// A millisecond timeout (`ep_timeout_to_timespec`): negative waits
/// forever, zero does not wait.
fn ms_deadline(ms: i32) -> (Option<Instant>, bool) {
    if ms < 0 {
        (None, false)
    } else if ms == 0 {
        (Some(Instant::now()), true)
    } else {
        (
            Some(Instant::now() + Duration::from_millis(ms as u64)),
            false,
        )
    }
}

/// `epoll_wait`.
pub fn epoll_wait(
    c: &mut Ctx<'_>,
    epfd: i32,
    events: u64,
    maxevents: i32,
    timeout: i32,
) -> Result<Outcome, Errno> {
    let (deadline, zero) = match resumed(c) {
        Some(d) => (d, false),
        None => ms_deadline(timeout),
    };
    wait_events(c, epfd, events, maxevents, deadline, zero)
}

/// Runs a wait with a temporary signal mask (`set_user_sigmask`), which
/// is restored unless the wait ends with `EINTR` (then after the handler).
fn with_mask(
    c: &mut Ctx<'_>,
    first: bool,
    mask: u64,
    size: u64,
    wait: impl FnOnce(&mut Ctx<'_>) -> Result<Outcome, Errno>,
) -> Result<Outcome, Errno> {
    if first {
        super::io::set_user_sigmask(c, mask, size)?;
    }
    let result = wait(c);
    if super::is_blocked(&result) {
        return result;
    }
    if !matches!(result, Err(Errno(EINTR)))
        && let Some(saved) = c.t.saved_sigmask.take()
    {
        c.set_blocked(saved);
    }
    result
}

/// `epoll_pwait`.
#[allow(clippy::too_many_arguments)]
pub fn epoll_pwait(
    c: &mut Ctx<'_>,
    epfd: i32,
    events: u64,
    maxevents: i32,
    timeout: i32,
    mask: u64,
    size: u64,
) -> Result<Outcome, Errno> {
    let (deadline, zero, first) = match resumed(c) {
        Some(d) => (d, false, false),
        None => {
            let (d, z) = ms_deadline(timeout);
            (d, z, true)
        }
    };
    with_mask(c, first, mask, size, |c| {
        wait_events(c, epfd, events, maxevents, deadline, zero)
    })
}

/// `epoll_pwait2`: the timeout is a `struct __kernel_timespec`, `NULL` for
/// none.
#[allow(clippy::too_many_arguments)]
pub fn epoll_pwait2(
    c: &mut Ctx<'_>,
    epfd: i32,
    events: u64,
    maxevents: i32,
    timeout: u64,
    mask: u64,
    size: u64,
) -> Result<Outcome, Errno> {
    let (deadline, zero, first) = match resumed(c) {
        Some(d) => (d, false, false),
        None if timeout == 0 => (None, false, true),
        None => {
            let b = c.read_mem(timeout, 16)?;
            let ts = super::super::abi::types::Timespec::decode(&b.try_into().unwrap());
            if !super::timer::timespec_valid(ts) {
                return Err(Errno(EINVAL));
            }
            let zero = ts.sec == 0 && ts.nsec == 0;
            let d = Instant::now()
                .checked_add(Duration::new(ts.sec as u64, ts.nsec as u32))
                .or(None);
            (d, zero, true)
        }
    };
    with_mask(c, first, mask, size, |c| {
        wait_events(c, epfd, events, maxevents, deadline, zero)
    })
}
