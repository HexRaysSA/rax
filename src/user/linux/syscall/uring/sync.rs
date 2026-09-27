//! The file operations that move no data (`io_uring/sync.c`,
//! `io_uring/advise.c`, `io_uring/truncate.c`, Linux 6.19):
//! `IORING_OP_FSYNC`, `_SYNC_FILE_RANGE`, `_FALLOCATE`, `_FADVISE`,
//! `_MADVISE`, and `_FTRUNCATE`.
//!
//! Each runs on the async workers (`REQ_F_FORCE_ASYNC`), as they may
//! sleep, except `IORING_OP_FADVISE` with advice that only sets the read
//! pattern. Each completes with the call's result; only a failed
//! `IORING_OP_FADVISE` fails its request (and its link), the others
//! (without `req_set_fail`) let their link go on.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::uring::abi::op;
use super::super::super::uring::{Req, State, req_flags as rf};
use super::super::io::{
    fadvise_file, fallocate_file, fsync_file, ftruncate_file, sync_file_range_file,
};
use super::super::{Ctx, SysResult};
use super::ops::assign_file;

/// `IORING_FSYNC_DATASYNC`.
const FSYNC_DATASYNC: u32 = 1;
/// `POSIX_FADV_NORMAL`, `_RANDOM`, and `_SEQUENTIAL`.
const FADV_SEQUENTIAL: u32 = 2;

/// The operation's `prep` (`io_fsync_prep`, `io_sfr_prep`,
/// `io_fallocate_prep`, `io_fadvise_prep`, `io_madvise_prep`,
/// `io_ftruncate_prep`): the fields it does not use zero (`EINVAL`).
pub(super) fn prep(req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    let unused = match sqe.opcode {
        op::FSYNC | op::SYNC_FILE_RANGE => {
            sqe.addr != 0 || sqe.buf_index != 0 || sqe.file_index != 0
        }
        op::FALLOCATE => sqe.buf_index != 0 || sqe.op_flags != 0 || sqe.file_index != 0,
        op::FADVISE | op::MADVISE => sqe.buf_index != 0 || sqe.file_index != 0,
        op::FTRUNCATE => {
            sqe.op_flags != 0
                || sqe.addr != 0
                || sqe.len != 0
                || sqe.buf_index != 0
                || sqe.file_index != 0
                || sqe.addr3 != 0
        }
        _ => return Err(Errno(EINVAL)),
    };
    if unused {
        return Err(Errno(EINVAL));
    }
    if sqe.opcode == op::FSYNC && sqe.op_flags & !FSYNC_DATASYNC != 0 {
        return Err(Errno(EINVAL));
    }
    // io_fadvise_force_async: advice that sets only the read pattern runs
    // inline.
    if sqe.opcode != op::FADVISE || sqe.op_flags > FADV_SEQUENTIAL {
        req.flags |= rf::FORCE_ASYNC;
    }
    Ok(())
}

/// `addr` or, when zero, `len` (`io_fadvise_prep`, `io_madvise_prep`
/// take their length from whichever is set).
fn addr_or_len(v: u64, len: u32) -> u64 {
    if v != 0 { v } else { u64::from(len) }
}

/// The operation's `issue`: the call on the request's file (or, for
/// `IORING_OP_MADVISE`, the address space), its result the request's.
pub(super) fn issue(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) {
    let r = run(c, st, req);
    let res = match r {
        Ok(v) => v as i32,
        Err(Errno(e)) => {
            // io_fadvise alone marks its failure.
            if req.sqe.opcode == op::FADVISE {
                req.set_fail();
            }
            -e
        }
    };
    req.res = res;
    req.cflags = 0;
}

fn run(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) -> SysResult {
    let sqe = req.sqe;
    if sqe.opcode == op::MADVISE {
        // do_madvise on the submitter's address space; the length is
        // `off`, or `len` when that is zero.
        let len = addr_or_len(sqe.off, sqe.len);
        return super::super::mem::madvise(c, sqe.addr, len, sqe.op_flags);
    }
    let file = assign_file(c, st, req)?;
    match sqe.opcode {
        // vfs_fsync_range over off..off+len (the whole file when that
        // end is not positive).
        op::FSYNC => fsync_file(&file),
        op::SYNC_FILE_RANGE => {
            sync_file_range_file(&file, sqe.off as i64, i64::from(sqe.len), sqe.op_flags)
        }
        // vfs_fallocate: the mode in `len`, the length in `addr`.
        op::FALLOCATE => fallocate_file(&file, sqe.len, sqe.off as i64, sqe.addr as i64),
        // vfs_fadvise: the length in `addr`, or `len` when that is zero.
        op::FADVISE => fadvise_file(&file, addr_or_len(sqe.addr, sqe.len) as i64, sqe.op_flags),
        // do_ftruncate.
        op::FTRUNCATE => ftruncate_file(c, &file, sqe.off as i64),
        _ => Err(Errno(EINVAL)),
    }
}
