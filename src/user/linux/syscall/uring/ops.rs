//! The operations' `prep` and `issue` (`io_uring/opdef.c` and the files
//! it names, Linux 6.19). An operation not modelled here fails its `prep`
//! with `EOPNOTSUPP`, as one a kernel is built without does
//! (`io_eopnotsupp_prep`), and `IORING_REGISTER_PROBE` reports it
//! unsupported.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::uring::abi::{nop, op, setup};
use super::super::super::uring::{Req, Ring, State, req_flags as rf};
use super::super::Ctx;
use super::rsrc;

/// How an issued request completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Done {
    /// Now (`IOU_COMPLETE`).
    Inline,
    /// Through task work (`IOU_ISSUE_SKIP_COMPLETE` after
    /// `io_req_task_work_add`).
    TaskWork,
}

/// Whether an operation is modelled (`io_uring_op_supported`).
pub(super) fn supported(opcode: u8) -> bool {
    matches!(opcode, op::NOP | op::NOP128 | op::FILES_UPDATE)
}

/// The operation's `prep`.
pub(super) fn prep(_c: &Ctx<'_>, ring: &Ring, req: &mut Req) -> Result<(), Errno> {
    match req.sqe.opcode {
        op::NOP | op::NOP128 => nop_prep(ring, req),
        op::FILES_UPDATE => rsrc::files_update_prep(req),
        _ => Err(Errno(EOPNOTSUPP)),
    }
}

/// The operation's `issue`: sets the request's result (and fails it, as
/// the operation's `req_set_fail` does).
pub(super) fn issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Done {
    match req.sqe.opcode {
        op::NOP | op::NOP128 => nop_issue(c, st, req),
        op::FILES_UPDATE => {
            rsrc::files_update_issue(c, ring, st, req);
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
            req.file = c.p.fds.file(fd).ok();
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
