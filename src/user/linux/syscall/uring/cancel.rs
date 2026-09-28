//! Cancellation (`io_uring/cancel.c`, Linux 6.19): `IORING_OP_ASYNC_CANCEL`,
//! `IORING_REGISTER_SYNC_CANCEL`, and `io_try_cancel`, which a linked
//! timeout also uses.
//!
//! A cancellation looks for a request by its user data, or by its file,
//! its operation, or none of those (`IORING_ASYNC_CANCEL_ANY`), among the
//! requests queued for the async workers (which complete with
//! `-ECANCELED` before they run), the poll table (whose entries complete
//! with `-ECANCELED` through their task work), and the timeouts (unless
//! it goes by file). With `IORING_ASYNC_CANCEL_ALL` or `_ANY` it cancels
//! every request it matches, each once (`cancel_seq`), and counts them.
//! Requests the workers are running cannot be cancelled here, as none is
//! ever running when a cancellation is issued.

use std::sync::Arc;

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::fd::OpenFile;
use super::super::super::uring::{Req, Ring, State, Work, req_flags as rf};
use super::super::{Ctx, SysResult};
use super::{ops, poll, rsrc, timeout};

/// `IORING_ASYNC_CANCEL_*`.
const ALL: u32 = 1 << 0;
const FD: u32 = 1 << 1;
const ANY: u32 = 1 << 2;
const FD_FIXED: u32 = 1 << 3;
const USERDATA: u32 = 1 << 4;
const OP: u32 = 1 << 5;
/// `CANCEL_FLAGS`.
const CANCEL_FLAGS: u32 = ALL | FD | ANY | FD_FIXED | USERDATA | OP;

/// What a cancellation matches (`struct io_cancel_data`).
#[derive(Clone, Debug, Default)]
pub(super) struct Match {
    pub data: u64,
    pub flags: u32,
    pub file: Option<Arc<OpenFile>>,
    pub opcode: u8,
    pub seq: u32,
}

impl Match {
    /// A match of the user data alone.
    pub(super) fn user_data(data: u64) -> Self {
        Match {
            data,
            ..Match::default()
        }
    }

    /// Whether it goes by file, operation, or any request rather than by
    /// user data alone.
    pub(super) fn by_file_or_op(&self) -> bool {
        self.flags & (FD | OP | ANY) != 0
    }

    /// `IORING_ASYNC_CANCEL_ALL`.
    pub(super) fn all(&self) -> bool {
        self.flags & ALL != 0
    }
}

/// `io_cancel_match_sequence`: whether this pass (`seq`) matched the
/// request already, which it now has.
pub(super) fn seen(req: &mut Req, seq: u32) -> bool {
    if req.cancel_seq == Some(seq) {
        return true;
    }
    req.cancel_seq = Some(seq);
    false
}

/// `io_cancel_req_match` for a request whose file is `file`: with
/// `IORING_ASYNC_CANCEL_ANY` any request, otherwise one with the file, the
/// operation, and the user data asked for (the user data unless file or
/// operation are, or with `IORING_ASYNC_CANCEL_USERDATA`); with `_ALL` or
/// `_ANY` not one this pass matched already (`io_cancel_match_sequence`).
pub(super) fn matches(req: &mut Req, file: Option<&Arc<OpenFile>>, cd: &Match) -> bool {
    if cd.flags & ANY == 0 {
        let by_data = cd.flags & USERDATA != 0 || cd.flags & (FD | OP) == 0;
        if cd.flags & FD != 0 {
            let same = match (file, &cd.file) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            };
            if !same {
                return false;
            }
        }
        if cd.flags & OP != 0 && req.sqe.opcode != cd.opcode {
            return false;
        }
        if by_data && req.sqe.user_data != cd.data {
            return false;
        }
        if cd.flags & ALL == 0 {
            return true;
        }
    }
    !seen(req, cd.seq)
}

/// `io_async_cancel_one`: the requests queued for the workers that `cd`
/// matches (the first, or with `_ALL` or `_ANY` all of them) fail with
/// `-ECANCELED` through task work (`io_req_task_queue_fail`).
fn cancel_queued(st: &mut State, cd: &Match) -> Result<(), Errno> {
    let all = cd.flags & (ALL | ANY) != 0;
    let mut found = false;
    let mut kept = std::collections::VecDeque::new();
    while let Some(mut chain) = st.iowq.pop_front() {
        let file = chain[0].file.clone();
        if (all || !found) && matches(&mut chain[0], file.as_ref(), cd) {
            found = true;
            chain[0].defer_failed(-ECANCELED);
            st.task_work.push_back(Work::Complete(chain));
        } else {
            kept.push_back(chain);
        }
    }
    st.iowq = kept;
    if found { Ok(()) } else { Err(Errno(ENOENT)) }
}

/// `io_try_cancel`: the workers' queue, then the poll table, then (unless
/// by file) the timeouts; `ENOENT` if nothing matches.
pub(super) fn try_cancel(ring: &Ring, st: &mut State, cd: &Match) -> Result<(), Errno> {
    if cancel_queued(st, cd).is_ok() {
        return Ok(());
    }
    match poll::cancel(ring, st, cd) {
        Err(Errno(ENOENT)) => {}
        r => return r,
    }
    if cd.flags & FD != 0 {
        return Err(Errno(ENOENT));
    }
    timeout::cancel(st, cd)
}

/// `__io_async_cancel`: one request, or with `_ALL` or `_ANY` each one it
/// matches, counted.
fn async_cancel(ring: &Ring, st: &mut State, cd: &Match) -> Result<u64, Errno> {
    let all = cd.flags & (ALL | ANY) != 0;
    let mut nr = 0;
    loop {
        match try_cancel(ring, st, cd) {
            Err(Errno(ENOENT)) => break,
            r if !all => return r.map(|()| 0),
            _ => nr += 1,
        }
    }
    // The other tasks' workers: this process's are the only ones.
    if all { Ok(nr) } else { Err(Errno(ENOENT)) }
}

/// `io_async_cancel_prep`: no offset or file slot (`EINVAL`); the user
/// data at `addr`; known flags, of which `IORING_ASYNC_CANCEL_ANY` takes
/// neither a file (from `fd`) nor an operation (from `len`) (`EINVAL`).
pub(super) fn prep(req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.off != 0 || sqe.file_index != 0 {
        return Err(Errno(EINVAL));
    }
    let flags = sqe.op_flags;
    if flags & !CANCEL_FLAGS != 0 || (flags & ANY != 0 && flags & (FD | OP) != 0) {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// `io_async_cancel`: the file asked for, registered (`IOSQE_FIXED_FILE` or
/// `IORING_ASYNC_CANCEL_FD_FIXED`) or not, which the request then holds
/// (`EBADF` if there is none); the cancellation's result, 0 or a count;
/// the request fails with an error.
pub(super) fn issue(c: &Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) {
    st.cancel_seq = st.cancel_seq.wrapping_add(1);
    let sqe = req.sqe;
    let mut cd = Match {
        data: sqe.addr,
        flags: sqe.op_flags,
        file: None,
        opcode: if sqe.op_flags & OP != 0 {
            sqe.len as u8
        } else {
            0
        },
        seq: st.cancel_seq,
    };
    let r = (|| {
        if cd.flags & FD != 0 {
            let file = if req.flags & rf::FIXED_FILE != 0 || cd.flags & FD_FIXED != 0 {
                req.flags |= rf::FIXED_FILE;
                rsrc::get_fixed_file(st, req, sqe.fd)
            } else {
                let f = ops::fget(c, sqe.fd).ok();
                req.file = f.clone();
                f
            };
            cd.file = Some(file.ok_or(Errno(EBADF))?);
        }
        async_cancel(ring, st, &cd)
    })();
    match r {
        Ok(n) => {
            req.res = n as i32;
            req.cflags = 0;
        }
        Err(Errno(e)) => req.fail(-e),
    }
}

/// `sizeof(struct io_uring_sync_cancel_reg)`.
const SYNC_CANCEL_SIZE: usize = 64;

/// `io_sync_cancel` (`IORING_REGISTER_SYNC_CANCEL`): the `struct
/// io_uring_sync_cancel_reg` at `arg` (`EFAULT`), its flags known and its
/// padding zero (`EINVAL`), a descriptor's file (`EBADF`) or a registered
/// one; the cancellation's result. (Only a request the workers are running
/// makes it wait, with the timeout it gives, and none ever is.)
pub(super) fn sync_cancel(c: &mut Ctx<'_>, ring: &Ring, arg: u64) -> SysResult {
    let b = c.read_mem(arg, SYNC_CANCEL_SIZE)?;
    let word = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let fd = i32::from_le_bytes(b[8..12].try_into().unwrap());
    let flags = u32::from_le_bytes(b[12..16].try_into().unwrap());
    if flags & !CANCEL_FLAGS != 0 || b[33..40] != [0; 7] || b[40..64] != [0; 24] {
        return Err(Errno(EINVAL));
    }
    let mut st = ring.state();
    st.cancel_seq = st.cancel_seq.wrapping_add(1);
    let mut cd = Match {
        data: word(0),
        flags,
        file: None,
        opcode: b[32],
        seq: st.cancel_seq,
    };
    if flags & FD != 0 {
        cd.file = Some(if flags & FD_FIXED != 0 {
            // io_rsrc_node_lookup and io_slot_file, no reference taken.
            let node = st.rsrc.file(fd as u32).ok_or(Errno(EBADF))?;
            st.rsrc.node_file(node).cloned().ok_or(Errno(EBADF))?
        } else {
            ops::fget(c, fd)?
        });
    }
    let r = async_cancel(ring, &mut st, &cd);
    drop(st);
    super::task::note(c, ring);
    r
}
