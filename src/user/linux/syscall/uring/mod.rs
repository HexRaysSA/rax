//! `io_uring_setup`, `io_uring_enter`, and `io_uring_register`
//! (`io_uring/io_uring.c`, `io_uring/register.c`, `io_uring/memmap.c`,
//! `io_uring/fdinfo.c`, Linux 6.19), and what the ring file does for
//! `mmap`, `poll`, and `/proc/<pid>/fdinfo`.
//!
//! Not modelled, and refused at setup with `EINVAL`: a submission queue
//! polling thread (`IORING_SETUP_SQPOLL`), polled completions
//! (`IORING_SETUP_IOPOLL`, `IORING_SETUP_HYBRID_IOPOLL`), rings in the
//! process's own memory (`IORING_SETUP_NO_MMAP`,
//! `IORING_SETUP_REGISTERED_FD_ONLY`), and mixed-size entries
//! (`IORING_SETUP_CQE_MIXED`, `IORING_SETUP_SQE_MIXED`).

mod cancel;
mod fs;
mod kbuf;
#[cfg(unix)]
mod net;
mod openclose;
mod ops;
mod poll;
mod register;
mod rsrc;
mod rw;
mod submit;
mod sync;
mod task;
mod timeout;
mod xattr;

pub use register::io_uring_register;
pub use task::{drive, exec_cancel, forked, next_deadline, wait_fds};

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::O_RDWR;
use super::super::fs::anon::Anon;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::posix_timers::{Base, instant_at};
use super::super::uring::abi::{
    self, MAX_CQ_ENTRIES, MAX_ENTRIES, OP_NAMES, Params, enter, feat, off, rings, setup,
};
use super::super::uring::rsrc::Account;
use super::super::uring::{Layout, Ring, State, Waiting};
use super::super::wait::{Resume, Wait};
use super::ready::Polled;
use super::{Ctx, SysResult, is_blocked};
use crate::user::mm::Backing;

/// How often a waiting call looks at the rings again: completions another
/// process (or a forked child sharing the ring) posts raise no event here.
const RECHECK: Duration = Duration::from_millis(2);

/// `RLIMIT_MEMLOCK`.
const RLIMIT_MEMLOCK: usize = 8;

/// The flags refused at setup (see the module documentation).
const UNMODELLED: u32 = setup::SQPOLL
    | setup::IOPOLL
    | setup::HYBRID_IOPOLL
    | setup::NO_MMAP
    | setup::REGISTERED_FD_ONLY
    | setup::CQE_MIXED
    | setup::SQE_MIXED;

/// The ring behind descriptor `fd`: `EBADF` if it is not open,
/// `EOPNOTSUPP` if it is not a ring.
pub(super) fn ring_of(c: &Ctx<'_>, fd: i32) -> Result<Arc<Ring>, Errno> {
    let file = ops::fget(c, fd)?;
    ring_file(&file).ok_or(Errno(EOPNOTSUPP))
}

/// The ring an open file is, if it is one.
pub fn ring_file(file: &OpenFile) -> Option<Arc<Ring>> {
    match &file.object {
        FileObject::Anon(Anon::Uring(r)) => Some(r.clone()),
        _ => None,
    }
}

/// `ctx->user` and `ctx->mm_account`: the caller's user (by real user
/// ID) unless it holds `CAP_IPC_LOCK` (is root), and its address space.
fn account(c: &mut Ctx<'_>) -> Account {
    let (uid, euid, ..) = c.p.creds;
    let user = (euid != 0).then(|| c.p.locked_vm_users.entry(uid).or_default().clone());
    Account {
        user,
        mm: c.p.mm.pinned_vm.clone(),
    }
}

/// `rlimit(RLIMIT_MEMLOCK)` in pages: what a user may charge.
pub(super) fn memlock_pages(c: &Ctx<'_>) -> u64 {
    c.p.rlimits[RLIMIT_MEMLOCK].0 >> 12
}

/// `io_uring_sanitise_params`.
fn sanitise(flags: u32) -> Result<(), Errno> {
    let bad = flags & !setup::ALL != 0
        || (flags & setup::REGISTERED_FD_ONLY != 0 && flags & setup::NO_MMAP == 0)
        || (flags & setup::SQPOLL != 0
            && flags & (setup::COOP_TASKRUN | setup::TASKRUN_FLAG | setup::DEFER_TASKRUN) != 0)
        || (flags & setup::TASKRUN_FLAG != 0
            && flags & (setup::COOP_TASKRUN | setup::DEFER_TASKRUN) == 0)
        || (flags & setup::HYBRID_IOPOLL != 0 && flags & setup::IOPOLL == 0)
        || (flags & setup::DEFER_TASKRUN != 0 && flags & setup::SINGLE_ISSUER == 0)
        || flags & (setup::CQE32 | setup::CQE_MIXED) == setup::CQE32 | setup::CQE_MIXED
        || flags & (setup::SQE128 | setup::SQE_MIXED) == setup::SQE128 | setup::SQE_MIXED;
    if bad { Err(Errno(EINVAL)) } else { Ok(()) }
}

/// `io_uring_fill_params`: the entry counts rounded up to powers of two,
/// the CQ twice the SQ unless `IORING_SETUP_CQSIZE` sets it (never
/// smaller); too many is `EINVAL` unless `IORING_SETUP_CLAMP` caps it.
fn fill_params(p: &mut Params) -> Result<(), Errno> {
    let mut entries = p.sq_entries;
    if entries == 0 {
        return Err(Errno(EINVAL));
    }
    if entries > MAX_ENTRIES {
        if p.flags & setup::CLAMP == 0 {
            return Err(Errno(EINVAL));
        }
        entries = MAX_ENTRIES;
    }
    p.sq_entries = entries.next_power_of_two();
    if p.flags & setup::CQSIZE != 0 {
        if p.cq_entries == 0 {
            return Err(Errno(EINVAL));
        }
        if p.cq_entries > MAX_CQ_ENTRIES {
            if p.flags & setup::CLAMP == 0 {
                return Err(Errno(EINVAL));
            }
            p.cq_entries = MAX_CQ_ENTRIES;
        }
        p.cq_entries = p.cq_entries.next_power_of_two();
        if p.cq_entries < p.sq_entries {
            return Err(Errno(EINVAL));
        }
    } else {
        p.cq_entries = 2 * p.sq_entries;
    }
    Ok(())
}

/// `io_uring_setup`: reads the parameters (reserved words zero), checks
/// and rounds them, creates the rings, writes the parameters back with the
/// ring offsets and `IORING_FEAT_FLAGS`, and installs the ring as an
/// `O_RDWR`, close-on-exec descriptor.
pub fn io_uring_setup(c: &mut Ctx<'_>, entries: u32, uptr: u64) -> SysResult {
    let raw = c.read_mem(uptr, abi::PARAMS_SIZE)?;
    let mut p = Params::decode(&raw);
    if p.resv != [0; 3] {
        return Err(Errno(EINVAL));
    }
    p.sq_entries = entries;
    sanitise(p.flags)?;
    fill_params(&mut p)?;
    let layout = Layout::new(p.flags, p.sq_entries, p.cq_entries)?;
    if p.flags & UNMODELLED != 0 {
        return Err(Errno(EINVAL));
    }
    p.sq_off = [
        rings::SQ_HEAD as u32,
        rings::SQ_TAIL as u32,
        rings::SQ_RING_MASK as u32,
        rings::SQ_RING_ENTRIES as u32,
        rings::SQ_FLAGS as u32,
        rings::SQ_DROPPED as u32,
        layout.sq_array.map_or(p.sq_off[6], |a| a as u32),
        0,
    ];
    p.sq_user_addr = 0;
    p.cq_off = [
        rings::CQ_HEAD as u32,
        rings::CQ_TAIL as u32,
        rings::CQ_RING_MASK as u32,
        rings::CQ_RING_ENTRIES as u32,
        rings::CQ_OVERFLOW as u32,
        rings::CQES as u32,
        rings::CQ_FLAGS as u32,
        0,
    ];
    p.cq_user_addr = 0;
    let account = account(c);
    let ring = Ring::new(
        p.flags,
        p.sq_entries,
        p.cq_entries,
        layout,
        c.compat,
        account,
        memlock_pages(c),
    )?;
    // io_sq_offload_create: an async-worker pool to share must be another
    // ring's; a CPU for a polling thread needs one.
    if p.flags & setup::ATTACH_WQ != 0 {
        let file = ops::fget(c, p.wq_fd as i32).map_err(|_| Errno(ENXIO))?;
        if ring_file(&file).is_none() {
            return Err(Errno(EINVAL));
        }
    }
    if p.flags & setup::SQ_AFF != 0 {
        return Err(Errno(EINVAL));
    }
    p.features = feat::ALL;
    c.write_mem(uptr, &p.encode())?;
    if p.flags & setup::SINGLE_ISSUER != 0 && p.flags & setup::R_DISABLED == 0 {
        ring.state().submitter = Some(c.t.tid);
    }
    let file = OpenFile::new(
        FileObject::Anon(Anon::Uring(ring)),
        FileType::Anon,
        "anon_inode:[io_uring]",
        None,
        O_RDWR,
    );
    super::io::install(c, file, true)
}

/// The region a ring `mmap` of `len` bytes at offset `off` maps, from its
/// start whatever the offset's low bits (`io_uring_get_unmapped_area`,
/// `io_uring_mmap`): no address may be asked for (`EINVAL`), and an offset
/// naming no region is `ENOMEM`. Either ring offset maps the ring region,
/// as much of it as the mapping holds; the SQEs map whole, so a shorter
/// mapping is `EFAULT` (`vm_insert_pages`).
pub(super) fn mmap_region(
    ring: &Ring,
    addr: u64,
    fixed: bool,
    off: u64,
    len: u64,
) -> Result<Backing, Errno> {
    let hint = if fixed {
        addr
    } else {
        addr & !(super::super::abi::PAGE_SIZE - 1)
    };
    if hint != 0 {
        return Err(Errno(EINVAL));
    }
    let object = match off & self::off::MMAP_MASK {
        self::off::SQ_RING | self::off::CQ_RING => ring.rings.clone(),
        self::off::SQES => ring.sqes.clone(),
        // A buffer ring's own pages (io_pbuf_get_region): none for a group
        // without them or a ring in the process's memory.
        self::off::PBUF_RING => {
            let bgid = (off & !self::off::MMAP_MASK) >> self::off::PBUF_SHIFT;
            u16::try_from(bgid)
                .ok()
                .and_then(|g| kbuf::region(ring, g))
                .ok_or(Errno(ENOMEM))?
        }
        _ => return Err(Errno(ENOMEM)),
    };
    // io_region_mmap: every page of any other region goes in (EFAULT past
    // the mapping's end).
    if off & self::off::MMAP_MASK > self::off::CQ_RING && len < object.len() {
        return Err(Errno(EFAULT));
    }
    Ok(Backing::Shared { object, offset: 0 })
}

/// `io_uring_poll`: writable while the SQ has room, readable while the CQ
/// has entries or overflowed ones wait. Posting raises no host event, so a
/// sleeper looks again shortly.
pub fn poll(ring: &Ring, events: u32) -> (Polled, Wait) {
    use super::ready::ev::*;
    let st = ring.state();
    let mut p = Polled::default();
    if !ring.sq_full(&st) {
        p.mask |= OUT | WRNORM;
    }
    if ring.cq_ready() != 0 || !st.overflow.is_empty() || local_work_pending(ring, &st) {
        p.mask |= IN | RDNORM;
    }
    p.level = u64::from(ring.cq_ready());
    let wait = if p.mask & events != 0 {
        Wait::event()
    } else {
        Wait::until(Some(Instant::now() + RECHECK))
    };
    (p, wait)
}

/// `io_local_work_pending`: a deferring ring's task work waits.
fn local_work_pending(ring: &Ring, st: &State) -> bool {
    ring.flags & setup::DEFER_TASKRUN != 0 && !st.task_work.is_empty()
}

/// `io_uring_show_fdinfo`: the rings' state, the SQEs and CQEs waiting in
/// them (the CQ listing indexes 16-byte slots even on a 32-byte ring, as
/// the kernel's does), the registered files and buffers, the poll table,
/// and the overflow list.
pub fn fdinfo(ring: &Ring, path_of: &dyn Fn(&OpenFile) -> String) -> String {
    let st = ring.state();
    let sq_mask = ring.sq_entries - 1;
    let cq_mask = ring.cq_entries - 1;
    let sq_head = ring.get32(rings::SQ_HEAD);
    let sq_tail = ring.get32(rings::SQ_TAIL);
    let cq_head = ring.get32(rings::CQ_HEAD);
    let cq_tail = ring.get32(rings::CQ_TAIL);
    let mut s = String::new();
    let _ = write!(
        s,
        "SqMask:\t0x{sq_mask:x}\nSqHead:\t{sq_head}\nSqTail:\t{sq_tail}\nCachedSqHead:\t{}\n\
         CqMask:\t0x{cq_mask:x}\nCqHead:\t{cq_head}\nCqTail:\t{cq_tail}\nCachedCqTail:\t{}\n\
         SQEs:\t{}\n",
        st.cached_sq_head,
        st.cached_cq_tail,
        sq_tail.wrapping_sub(sq_head)
    );
    let sqe128 = ring.flags & setup::SQE128 != 0;
    for i in 0..sq_tail.wrapping_sub(sq_head).min(ring.sq_entries) {
        let entry = sq_head.wrapping_add(i);
        let idx = match ring.layout.sq_array {
            Some(a) => ring.get32(a + 4 * u64::from(entry & sq_mask)),
            None => entry & sq_mask,
        };
        if idx > sq_mask {
            continue;
        }
        let sqe = ring.sqe_at(idx);
        if sqe.opcode >= abi::op::LAST {
            continue;
        }
        if !sqe128 && abi::OP_DEFS[usize::from(sqe.opcode)].is_128 {
            let _ = writeln!(s, "{idx:5}: invalid sqe, 128B entry on non-mixed sq");
            break;
        }
        let _ = write!(
            s,
            "{idx:5}: opcode:{}, fd:{}, flags:{:x}, off:{}, addr:0x{:x}, rw_flags:0x{:x}, \
             buf_index:{} user_data:{}",
            OP_NAMES[usize::from(sqe.opcode)],
            sqe.fd,
            sqe.flags,
            sqe.off,
            sqe.addr,
            sqe.op_flags,
            sqe.buf_index,
            sqe.user_data
        );
        if sqe128 {
            let mut b = [0u8; 64];
            let _ = ring.sqes.read_at(ring.sqe_offset(idx) + 64, &mut b);
            for j in 0..8 {
                let v = u64::from_le_bytes(b[8 * j..8 * j + 8].try_into().unwrap());
                let _ = write!(s, ", e{j}:0x{v:x}");
            }
        }
        s.push('\n');
    }
    let _ = writeln!(s, "CQEs:\t{}", cq_tail.wrapping_sub(cq_head));
    let cqe32 = ring.flags & setup::CQE32 != 0;
    let mut head = cq_head;
    let mut i = 0;
    while i < cq_tail.wrapping_sub(cq_head).min(ring.cq_entries) {
        let mut b = [0u8; 32];
        let slot = head & cq_mask;
        let _ = ring
            .rings
            .read_at(rings::CQES + u64::from(slot) * abi::CQE_SIZE, &mut b);
        let word = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let res = i32::from_le_bytes(b[8..12].try_into().unwrap());
        let flags = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let big = cqe32 || flags & abi::cqe_flags::F_32 != 0;
        let _ = write!(
            s,
            "{slot:5}: user_data:{}, res:{res}, flags:{flags:x}",
            word(0)
        );
        if big {
            let _ = write!(s, ", extra1:{}, extra2:{}", word(16), word(24));
        }
        s.push('\n');
        head = head.wrapping_add(1);
        if big {
            head = head.wrapping_add(1);
            i += 1;
        }
        i += 1;
    }
    s.push_str("SqThread:\t-1\nSqThreadCpu:\t-1\nSqTotalTime:\t0\nSqWorkTime:\t0\n");
    let t = &st.rsrc;
    let _ = writeln!(s, "UserFiles:\t{}", t.files.len());
    for (i, slot) in t.files.iter().enumerate() {
        if let Some(f) = slot.and_then(|id| t.node_file(id)) {
            let _ = writeln!(s, "{i:5}: {}", mangle_path(&path_of(f)));
        }
    }
    let _ = writeln!(s, "UserBufs:\t{}", t.bufs.len());
    for (i, slot) in t.bufs.iter().enumerate() {
        match slot.and_then(|id| t.node_buf(id)) {
            Some(b) => {
                let _ = writeln!(s, "{i:5}: 0x{:x}/{}", b.addr, b.len);
            }
            None => {
                let _ = writeln!(s, "{i:5}: <none>");
            }
        }
    }
    s.push_str("PollList:\n");
    s.push_str(&poll::poll_list(ring, &st));
    s.push_str("CqOverflowList:\n");
    for cqe in &st.overflow {
        let _ = writeln!(
            s,
            "  user_data={}, res={}, flags={:x}",
            cqe.user_data, cqe.res, cqe.flags
        );
    }
    s.push_str("NAPI:\tdisabled\n");
    s
}

/// `seq_file_path` with the escapes `" \t\n\\"` (`mangle_path`): each
/// of those bytes as a backslash and three octal digits.
fn mangle_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for ch in path.chars() {
        if matches!(ch, ' ' | '\t' | '\n' | '\\') {
            let _ = write!(out, "\\{:03o}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    out
}

/// The ring `io_uring_enter` works on: a descriptor, or with
/// `IORING_ENTER_REGISTERED_RING` an index into the caller's registered
/// rings (`EINVAL` past them, `EBADF` for an empty slot).
fn enter_ring(c: &Ctx<'_>, fd: u32, flags: u32) -> Result<Arc<Ring>, Errno> {
    if flags & enter::REGISTERED_RING != 0 {
        if fd >= abi::RINGFD_REG_MAX {
            return Err(Errno(EINVAL));
        }
        return c
            .t
            .uring_rings
            .get(fd as usize)
            .cloned()
            .flatten()
            .ok_or(Errno(EBADF));
    }
    ring_of(c, fd as i32)
}

/// `io_uring_enter`: submits up to `to_submit` SQEs, then with
/// `IORING_ENTER_GETEVENTS` waits for `min_complete` completions; the
/// number submitted, or the wait's result if none was. A submission that
/// stops short returns at once. What the call released is dropped once
/// the ring's lock is let go.
pub fn io_uring_enter(
    c: &mut Ctx<'_>,
    fd: u32,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    argp: u64,
    argsz: u64,
) -> SysResult {
    if let Some(Resume::Uring(w)) = c.resume.take() {
        let ring = enter_ring(c, fd, flags)?;
        let r = wait_again(c, &ring, w);
        ring.reap();
        return r;
    }
    if flags & !enter::ALL != 0 {
        return Err(Errno(EINVAL));
    }
    let ring = enter_ring(c, fd, flags)?;
    let r = enter(c, &ring, to_submit, min_complete, flags, argp, argsz);
    ring.reap();
    r
}

fn enter(
    c: &mut Ctx<'_>,
    ring: &Ring,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    argp: u64,
    argsz: u64,
) -> SysResult {
    let mut st = ring.state();
    if st.disabled {
        return Err(Errno(EBADFD));
    }
    let mut ret: i64 = 0;
    if to_submit != 0 {
        // io_uring_add_tctx_node: a single-issuer ring's submitter only.
        if st.submitter.is_some_and(|t| t != c.t.tid) {
            return Err(Errno(EEXIST));
        }
        ret = submit::submit(c, ring, &mut st, to_submit);
        if ret != i64::from(to_submit) {
            finish(c, ring, &mut st);
            return Ok(ret as u64);
        }
    }
    if flags & enter::GETEVENTS != 0 {
        let r2 = start_wait(c, ring, &mut st, min_complete, flags, argp, argsz, ret);
        if is_blocked(&r2) {
            return r2.map(|v| v as u64);
        }
        if ret == 0 {
            ret = match r2 {
                Ok(v) => v,
                Err(e) => {
                    finish(c, ring, &mut st);
                    return Err(e);
                }
            };
        }
    }
    finish(c, ring, &mut st);
    Ok(ret as u64)
}

/// The return to user mode: task work runs (not a deferring ring's).
fn finish(c: &mut Ctx<'_>, ring: &Ring, st: &mut State) {
    if ring.flags & setup::DEFER_TASKRUN == 0 {
        submit::run_task_work(c, ring, st);
    }
}

/// `io_allowed_run_tw`: a deferring ring's task work only runs in its
/// submitter.
fn allowed_run_tw(c: &Ctx<'_>, ring: &Ring, st: &State) -> bool {
    ring.flags & setup::DEFER_TASKRUN == 0 || st.submitter == Some(c.t.tid)
}

/// `io_get_ext_arg` and the start of `io_cqring_wait`: the timeout
/// (relative, or absolute on the ring's clock with
/// `IORING_ENTER_ABS_TIMER`), the minimum wait, and the signal mask; task
/// work and overflowed completions first; enough completions end it at
/// once.
#[allow(clippy::too_many_arguments)]
fn start_wait(
    c: &mut Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    min_complete: u32,
    flags: u32,
    argp: u64,
    argsz: u64,
    submitted: i64,
) -> Result<i64, Errno> {
    let (mut sig, mut sigsz, mut ts, mut min_ns) = (argp, argsz, None, 0u64);
    if flags & enter::EXT_ARG != 0 {
        // Registered wait regions are not modelled: none can be registered.
        if flags & enter::EXT_ARG_REG != 0 {
            return Err(Errno(EINVAL));
        }
        if argsz != 24 {
            return Err(Errno(EINVAL));
        }
        let b = c.read_mem(argp, 24)?;
        let word = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        sig = word(0);
        sigsz = u64::from(u32::from_le_bytes(b[8..12].try_into().unwrap()));
        min_ns = u64::from(u32::from_le_bytes(b[12..16].try_into().unwrap())) * 1000;
        let tsp = word(16);
        if tsp != 0 {
            let t = c.get_timespec(tsp)?;
            ts = Some(t.sec.saturating_mul(1_000_000_000).saturating_add(t.nsec));
        }
    }
    let min_events = min_complete.min(ring.cq_entries);
    if !allowed_run_tw(c, ring, st) {
        return Err(Errno(EEXIST));
    }
    submit::run_task_work(c, ring, st);
    submit::flush_overflow(ring, st);
    if ring.cq_ready() >= min_events {
        return Ok(0);
    }
    let now = Instant::now();
    let deadline = ts.map(|ns| {
        if flags & enter::ABS_TIMER != 0 {
            instant_at(Base::Monotonic, ns)
        } else {
            now + Duration::from_nanos(ns.max(0) as u64)
        }
    });
    if sig != 0 {
        super::io::set_user_sigmask(c, sig, sigsz)?;
    }
    let w = Waiting {
        submitted,
        target: ring.get32(rings::CQ_HEAD).wrapping_add(min_events),
        min_tail: ring.get32(rings::CQ_TAIL),
        deadline,
        min_deadline: (min_ns != 0).then(|| now + Duration::from_nanos(min_ns)),
        nr_timeouts: st.cq_timeouts,
    };
    check_wait(c, ring, st, w)
}

/// A wait that slept looks again.
fn wait_again(c: &mut Ctx<'_>, ring: &Ring, w: Waiting) -> SysResult {
    let mut st = ring.state();
    let r = check_wait(c, ring, &mut st, w.clone());
    if is_blocked(&r) {
        return r.map(|v| v as u64);
    }
    let ret = if w.submitted != 0 { Ok(w.submitted) } else { r };
    finish(c, ring, &mut st);
    ret.map(|v| v as u64)
}

/// `io_should_wake`: the CQ tail reached the target, or a timeout expired
/// or was satisfied since the wait began.
fn should_wake(ring: &Ring, st: &State, w: &Waiting) -> bool {
    ring.get32(rings::CQ_TAIL).wrapping_sub(w.target) as i32 >= 0 || st.cq_timeouts != w.nr_timeouts
}

/// One pass of `io_cqring_wait`'s loop: task work and the overflow list
/// first; enough completions, a signal (`EINTR`), or the timeout (`ETIME`)
/// end it; the result is 0 whenever the CQ holds anything then. (No CQE is
/// ever dropped, so no wait reports `EBADR`: the overflow list takes every
/// one.) The minimum wait ends early once a completion arrived
/// since the wait began, and otherwise hands over to the timeout.
fn check_wait(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, mut w: Waiting) -> Result<i64, Errno> {
    submit::run_task_work(c, ring, st);
    let now = Instant::now();
    let mut result = None;
    submit::flush_overflow(ring, st);
    if should_wake(ring, st, &w) {
        result = Some(Ok(0));
    } else if c.signal_pending() {
        result = Some(Err(Errno(EINTR)));
    } else if let Some(min) = w.min_deadline
        && now >= min
    {
        // io_cqring_min_timer_wakeup.
        let done = w.deadline.is_none_or(|d| min >= d)
            || ring.get32(rings::CQ_TAIL) != w.min_tail
            || ring.cq_ready() != 0;
        if done {
            result = Some(Err(Errno(ETIME)));
        } else {
            w.min_deadline = None;
            w.target = w.min_tail;
        }
    } else if w.min_deadline.is_none() && w.deadline.is_some_and(|d| now >= d) {
        result = Some(Err(Errno(ETIME)));
    }
    let Some(r) = result else {
        let next = w.min_deadline.or(w.deadline);
        // Another ring's timer: the recheck; this one's: as it expires.
        let recheck = (Instant::now() + RECHECK).min(timeout::next(st).unwrap_or(now + RECHECK));
        let deadline = Some(next.map_or(recheck, |d| d.min(recheck)));
        let mut wait = Wait::until(deadline);
        wait.interruptible = true;
        return Err(c.block(wait, Resume::Uring(w)));
    };
    // restore_saved_sigmask_unless(ret == -EINTR).
    if !matches!(r, Err(Errno(EINTR)))
        && let Some(saved) = c.t.saved_sigmask.take()
    {
        c.set_blocked(saved);
    }
    if ring.cq_ready() != 0 {
        return Ok(0);
    }
    r
}
