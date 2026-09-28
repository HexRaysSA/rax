//! The operations' `prep` and `issue` (`io_uring/opdef.c` and the files
//! it names, Linux 6.19). An operation not modelled here fails its `prep`
//! with `EOPNOTSUPP`, as one a kernel is built without does
//! (`io_eopnotsupp_prep`), and `IORING_REGISTER_PROBE` reports it
//! unsupported.

use std::sync::Arc;

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::fd::{FileObject, OpenFile};
use super::super::super::uring::abi::{nop, op, setup};
use super::super::super::uring::{Req, Ring, State, req_flags as rf};
use super::super::Ctx;
use super::{cancel, fs, openclose, poll, rsrc, rw, sync, timeout, xattr};

/// How an issued request completes.
#[derive(Clone, Debug)]
pub(super) enum Done {
    /// Now (`IOU_COMPLETE`).
    Inline,
    /// Through task work (`IOU_ISSUE_SKIP_COMPLETE` after
    /// `io_req_task_work_add`).
    TaskWork,
    /// Not yet: it waits for its file to report an event of the mask
    /// (`-EAGAIN` to `io_queue_async`, then `io_arm_poll_handler`).
    Park(Arc<OpenFile>, u32),
    /// Armed on its file (`IOU_ISSUE_SKIP_COMPLETE` after `io_poll_add`):
    /// the poll completes it.
    Poll(poll::Arm),
    /// A timeout to arm (`IOU_ISSUE_SKIP_COMPLETE` after `io_timeout`).
    Timeout,
}

/// Whether an operation is modelled (`io_uring_op_supported`).
pub(super) fn supported(opcode: u8) -> bool {
    matches!(
        opcode,
        op::NOP
            | op::NOP128
            | op::FILES_UPDATE
            | op::READ
            | op::WRITE
            | op::READV
            | op::WRITEV
            | op::READ_FIXED
            | op::WRITE_FIXED
            | op::READV_FIXED
            | op::WRITEV_FIXED
            | op::FSYNC
            | op::SYNC_FILE_RANGE
            | op::FALLOCATE
            | op::FADVISE
            | op::MADVISE
            | op::FTRUNCATE
            | op::OPENAT
            | op::OPENAT2
            | op::CLOSE
            | op::FIXED_FD_INSTALL
            | op::PIPE
            | op::STATX
            | op::RENAMEAT
            | op::UNLINKAT
            | op::MKDIRAT
            | op::SYMLINKAT
            | op::LINKAT
            | op::FGETXATTR
            | op::GETXATTR
            | op::FSETXATTR
            | op::SETXATTR
            | op::POLL_ADD
            | op::POLL_REMOVE
            | op::TIMEOUT
            | op::TIMEOUT_REMOVE
            | op::LINK_TIMEOUT
            | op::ASYNC_CANCEL
    )
}

/// The operation's `prep`.
pub(super) fn prep(c: &Ctx<'_>, ring: &Ring, req: &mut Req) -> Result<(), Errno> {
    match req.sqe.opcode {
        op::NOP | op::NOP128 => nop_prep(ring, req),
        op::FILES_UPDATE => rsrc::files_update_prep(req),
        op::READ
        | op::WRITE
        | op::READV
        | op::WRITEV
        | op::READ_FIXED
        | op::WRITE_FIXED
        | op::READV_FIXED
        | op::WRITEV_FIXED => rw::prep(c, ring, req),
        op::FSYNC
        | op::SYNC_FILE_RANGE
        | op::FALLOCATE
        | op::FADVISE
        | op::MADVISE
        | op::FTRUNCATE => sync::prep(req),
        op::OPENAT | op::OPENAT2 => openclose::open_prep(c, req),
        op::CLOSE => openclose::close_prep(req),
        op::FIXED_FD_INSTALL => openclose::install_prep(req),
        op::PIPE => openclose::pipe_prep(c, req),
        op::STATX | op::RENAMEAT | op::UNLINKAT | op::MKDIRAT | op::SYMLINKAT | op::LINKAT => {
            fs::prep(c, req)
        }
        op::FGETXATTR | op::GETXATTR | op::FSETXATTR | op::SETXATTR => xattr::prep(c, req),
        op::POLL_ADD => poll::add_prep(req),
        op::POLL_REMOVE => poll::remove_prep(req),
        op::TIMEOUT => timeout::prep(c, req, false),
        op::LINK_TIMEOUT => timeout::prep(c, req, true),
        op::TIMEOUT_REMOVE => timeout::remove_prep(c, req),
        op::ASYNC_CANCEL => cancel::prep(req),
        _ => Err(Errno(EOPNOTSUPP)),
    }
}

/// `getname` (`getname_uflags` with `empty`): the name at `addr`, kept for
/// the issue: `EFAULT`, `ENAMETOOLONG` past `PATH_MAX - 1` bytes, `ENOENT`
/// if empty unless `empty`.
pub(super) fn getname(c: &Ctx<'_>, req: &mut Req, addr: u64, empty: bool) -> Result<(), Errno> {
    let raw = c.read_cstr_raw(addr, super::super::super::fs::PATH_MAX - 1)?;
    if raw.is_empty() && !empty {
        return Err(Errno(ENOENT));
    }
    req.names.push((addr, raw));
    Ok(())
}

/// `fget` as io_uring uses it: an open descriptor, not an `O_PATH` one
/// (`EBADF`).
pub(super) fn fget(c: &Ctx<'_>, fd: i32) -> Result<Arc<OpenFile>, Errno> {
    let file = c.p.fds.file(fd).map_err(|_| Errno(EBADF))?;
    if matches!(file.object, FileObject::PathOnly) {
        return Err(Errno(EBADF));
    }
    Ok(file)
}

/// `io_assign_file`: the request's file, looked up once (`EBADF` if
/// missing): a registered one with `IOSQE_FIXED_FILE`, which the request
/// then holds a node of, or its descriptor's.
pub(super) fn assign_file(
    c: &Ctx<'_>,
    st: &mut State,
    req: &mut Req,
) -> Result<Arc<OpenFile>, Errno> {
    if req.flags & rf::FIXED_FILE != 0 {
        if let Some(id) = req.file_node {
            return st.rsrc.node_file(id).cloned().ok_or(Errno(EBADF));
        }
        return rsrc::get_fixed_file(st, req, req.sqe.fd).ok_or(Errno(EBADF));
    }
    if let Some(f) = &req.file {
        return Ok(f.clone());
    }
    let file = fget(c, req.sqe.fd)?;
    req.file = Some(file.clone());
    Ok(file)
}

/// The operation's `issue`: sets the request's result (and fails it, as
/// the operation's `req_set_fail` does). An issue never sleeps: where the
/// call it makes would, it gets `EAGAIN` ([`Ctx::nowait`]).
pub(super) fn issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Done {
    let nowait = c.nowait;
    c.nowait = true;
    let done = issue_op(c, ring, st, req);
    c.nowait = nowait;
    done
}

fn issue_op(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Done {
    match req.sqe.opcode {
        op::NOP | op::NOP128 => nop_issue(c, st, req),
        op::FILES_UPDATE => {
            rsrc::files_update_issue(c, ring, st, req);
            Done::Inline
        }
        op::READ
        | op::WRITE
        | op::READV
        | op::WRITEV
        | op::READ_FIXED
        | op::WRITE_FIXED
        | op::READV_FIXED
        | op::WRITEV_FIXED => rw::issue(c, st, req),
        op::FSYNC
        | op::SYNC_FILE_RANGE
        | op::FALLOCATE
        | op::FADVISE
        | op::MADVISE
        | op::FTRUNCATE => {
            sync::issue(c, st, req);
            Done::Inline
        }
        op::OPENAT | op::OPENAT2 => {
            openclose::open_issue(c, ring, st, req);
            Done::Inline
        }
        op::CLOSE => {
            openclose::close_issue(c, ring, st, req);
            Done::Inline
        }
        op::FIXED_FD_INSTALL => {
            openclose::install_issue(c, st, req);
            Done::Inline
        }
        op::PIPE => {
            openclose::pipe_issue(c, ring, st, req);
            Done::Inline
        }
        op::STATX | op::RENAMEAT | op::UNLINKAT | op::MKDIRAT | op::SYMLINKAT | op::LINKAT => {
            fs::issue(c, req);
            Done::Inline
        }
        op::FGETXATTR | op::GETXATTR | op::FSETXATTR | op::SETXATTR => {
            xattr::issue(c, st, req);
            Done::Inline
        }
        op::POLL_ADD => poll::add_issue(c, st, req),
        op::POLL_REMOVE => poll::remove_issue(c, ring, st, req),
        op::TIMEOUT => Done::Timeout,
        op::TIMEOUT_REMOVE => {
            timeout::remove_issue(c, ring, st, req);
            Done::Inline
        }
        op::ASYNC_CANCEL => {
            cancel::issue(c, ring, st, req);
            Done::Inline
        }
        // io_no_issue: a linked timeout is never issued.
        op::LINK_TIMEOUT => {
            req.fail(-ECANCELED);
            Done::Inline
        }
        // prep refused it.
        _ => {
            req.res = -EOPNOTSUPP;
            req.set_fail();
            Done::Inline
        }
    }
}

/// `NOP_FLAGS`.
const NOP_FLAGS: u32 =
    nop::INJECT_RESULT | nop::FIXED_FILE | nop::FIXED_BUFFER | nop::FILE | nop::TW | nop::CQE32;

/// `io_nop_prep`: known flags only; a 32-byte CQE needs a ring that posts
/// them.
fn nop_prep(ring: &Ring, req: &Req) -> Result<(), Errno> {
    let flags = req.sqe.op_flags;
    if flags & !NOP_FLAGS != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & nop::CQE32 != 0 && ring.flags & (setup::CQE32 | setup::CQE_MIXED) == 0 {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// `io_nop`: the injected result (`len`) or 0. With `IORING_NOP_FILE` the
/// descriptor (or registered file) must exist and with
/// `IORING_NOP_FIXED_BUFFER` the registered buffer; a missing one fails the
/// request (its link with it), though its CQE still carries the injected
/// result. The request holds what it looked up until it is freed.
/// `IORING_NOP_CQE32` puts `off` and `addr` in the CQE's extra words;
/// `IORING_NOP_TW` completes through task work.
fn nop_issue(c: &Ctx<'_>, st: &mut State, req: &mut Req) -> Done {
    let flags = req.sqe.op_flags;
    let result = if flags & nop::INJECT_RESULT != 0 {
        req.sqe.len as i32
    } else {
        0
    };
    let mut ret = result;
    let mut file_ok = true;
    if flags & nop::FILE != 0 {
        let fd = req.sqe.fd;
        file_ok = if flags & nop::FIXED_FILE != 0 {
            let found = rsrc::get_fixed_file(st, req, fd).is_some();
            req.flags |= rf::FIXED_FILE;
            found
        } else {
            req.file = fget(c, fd).ok();
            req.file.is_some()
        };
        if !file_ok {
            ret = -EBADF;
        }
    }
    if file_ok && flags & nop::FIXED_BUFFER != 0 && rsrc::find_buf_node(st, req).is_none() {
        ret = -EFAULT;
    }
    if ret < 0 {
        req.set_fail();
    }
    req.res = result;
    req.cflags = 0;
    if flags & nop::CQE32 != 0 {
        req.big = [req.sqe.off, req.sqe.addr];
    }
    if flags & nop::TW != 0 {
        Done::TaskWork
    } else {
        Done::Inline
    }
}
