//! Path operations (`io_uring/fs.c`, `io_uring/statx.c`, Linux 6.19):
//! `IORING_OP_RENAMEAT`, `_UNLINKAT`, `_MKDIRAT`, `_SYMLINKAT`, `_LINKAT`,
//! and `_STATX`.
//!
//! Preparation takes the names (`getname`), which issue uses whatever the
//! memory then holds; each runs on the async workers, as the calls do,
//! and completes with the call's result. None fails its request on an
//! error, so a link goes on after a failure.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::uring::abi::op;
use super::super::super::uring::{Req, req_flags as rf};
use super::super::path;
use super::super::{Ctx, SysResult};
use super::ops::getname;

/// `AT_REMOVEDIR` and `AT_EMPTY_PATH`.
const AT_REMOVEDIR: u32 = 0x200;
const AT_EMPTY_PATH: u32 = 0x1000;

/// The operation's `prep` (`io_renameat_prep`, `io_unlinkat_prep`,
/// `io_mkdirat_prep`, `io_symlinkat_prep`, `io_linkat_prep`,
/// `io_statx_prep`): the fields it does not use zero (`EINVAL`), no
/// registered file (`EBADF`), its flags (unlink: only `AT_REMOVEDIR`), and
/// its names, of which only `IORING_OP_LINKAT`'s old one and
/// `IORING_OP_STATX`'s may be empty, with `AT_EMPTY_PATH`.
pub(super) fn prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    let unused = match sqe.opcode {
        op::RENAMEAT | op::LINKAT | op::STATX => sqe.buf_index != 0 || sqe.file_index != 0,
        op::UNLINKAT => sqe.off != 0 || sqe.len != 0 || sqe.buf_index != 0 || sqe.file_index != 0,
        op::MKDIRAT => {
            sqe.off != 0 || sqe.op_flags != 0 || sqe.buf_index != 0 || sqe.file_index != 0
        }
        op::SYMLINKAT => {
            sqe.len != 0 || sqe.op_flags != 0 || sqe.buf_index != 0 || sqe.file_index != 0
        }
        _ => return Err(Errno(EINVAL)),
    };
    if unused {
        return Err(Errno(EINVAL));
    }
    if req.flags & rf::FIXED_FILE != 0 {
        return Err(Errno(EBADF));
    }
    let empty = sqe.op_flags & AT_EMPTY_PATH != 0;
    match sqe.opcode {
        op::UNLINKAT => {
            if sqe.op_flags & !AT_REMOVEDIR != 0 {
                return Err(Errno(EINVAL));
            }
            getname(c, req, sqe.addr, false)?;
        }
        op::MKDIRAT => getname(c, req, sqe.addr, false)?,
        op::STATX => getname(c, req, sqe.addr, empty)?,
        op::LINKAT => {
            getname(c, req, sqe.addr, empty)?;
            getname(c, req, sqe.off, false)?;
        }
        // RENAMEAT, SYMLINKAT: the old name (or target), then the new.
        _ => {
            getname(c, req, sqe.addr, false)?;
            getname(c, req, sqe.off, false)?;
        }
    }
    req.flags |= rf::FORCE_ASYNC;
    Ok(())
}

/// The operation's `issue`: the call with the names prepared.
pub(super) fn issue(c: &mut Ctx<'_>, req: &mut Req) {
    c.names = req.names.clone();
    let r = run(c, req);
    c.names.clear();
    req.res = match r {
        Ok(v) => v as i32,
        Err(Errno(e)) => -e,
    };
    req.cflags = 0;
}

fn run(c: &mut Ctx<'_>, req: &Req) -> SysResult {
    let sqe = req.sqe;
    let dfd = sqe.fd;
    match sqe.opcode {
        // do_renameat2: the new directory in `len`, the flags in
        // `rename_flags`.
        #[cfg(unix)]
        op::RENAMEAT => path::renameat2(c, dfd, sqe.addr, sqe.len as i32, sqe.off, sqe.op_flags),
        #[cfg(unix)]
        op::UNLINKAT => path::unlinkat(c, dfd, sqe.addr, sqe.op_flags),
        // do_mkdirat: the mode in `len`.
        #[cfg(unix)]
        op::MKDIRAT => path::mkdirat(c, dfd, sqe.addr, sqe.len),
        // do_symlinkat: the target at `addr`, the link at `addr2` in `fd`.
        #[cfg(unix)]
        op::SYMLINKAT => path::symlinkat(c, sqe.addr, dfd, sqe.off),
        #[cfg(unix)]
        op::LINKAT => path::linkat(c, dfd, sqe.addr, sqe.len as i32, sqe.off, sqe.op_flags),
        // do_statx: the mask in `len`, the buffer at `addr2`.
        op::STATX => path::statx(c, dfd, sqe.addr, sqe.op_flags, sqe.len, sqe.off),
        _ => Err(Errno(EINVAL)),
    }
}
