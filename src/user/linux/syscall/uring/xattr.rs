//! Extended attributes (`io_uring/xattr.c`, Linux 6.19):
//! `IORING_OP_FGETXATTR`, `_GETXATTR`, `_FSETXATTR`, and `_SETXATTR`, of the
//! request's file or of the path at `addr3` (followed, from the working
//! directory).
//!
//! Preparation reads the name (`import_xattr_name`) and a set's value
//! (`setxattr_copy`), which issue uses whatever the memory then holds; a
//! get's value is written at issue. Each runs on the async workers and
//! completes with the call's result, never failing its request.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::uring::abi::op;
use super::super::super::uring::{Req, State, req_flags as rf};
use super::super::{Ctx, SysResult, xattr};
use super::ops::{assign_file, getname};

/// The operation's `prep` (`io_getxattr_prep`, `io_fgetxattr_prep`,
/// `io_setxattr_prep`, `io_fsetxattr_prep`): a path form takes no
/// registered file (`EBADF`, first); a get takes no flags (`EINVAL`); the
/// name, a set's value, and a path form's path.
pub(super) fn prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    let path = matches!(sqe.opcode, op::GETXATTR | op::SETXATTR);
    if path && req.flags & rf::FIXED_FILE != 0 {
        return Err(Errno(EBADF));
    }
    if matches!(sqe.opcode, op::GETXATTR | op::FGETXATTR) {
        if sqe.op_flags != 0 {
            return Err(Errno(EINVAL));
        }
        let name = xattr::import_name(c, sqe.addr)?;
        req.names.push((sqe.addr, name));
    } else {
        // The value at `addr2`, `len` bytes of it.
        let (name, data) =
            xattr::setxattr_copy(c, sqe.addr, sqe.off, u64::from(sqe.len), sqe.op_flags)?;
        req.names.push((sqe.addr, name));
        req.data = data;
    }
    if path {
        getname(c, req, sqe.addr3, false)?;
    }
    req.flags |= rf::FORCE_ASYNC;
    Ok(())
}

/// The operation's `issue`: the attribute read or set.
pub(super) fn issue(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) {
    c.names = req.names.clone();
    let r = run(c, st, req);
    c.names.clear();
    req.res = match r {
        Ok(v) => v as i32,
        Err(Errno(e)) => -e,
    };
    req.cflags = 0;
}

fn run(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) -> SysResult {
    let sqe = req.sqe;
    let name = req.names[0].1.clone();
    let (value, size) = (sqe.off, u64::from(sqe.len));
    match sqe.opcode {
        op::FGETXATTR => {
            let file = assign_file(c, st, req)?;
            xattr::file_getxattr(c, file, &name, value, size)
        }
        op::GETXATTR => xattr::filename_getxattr(c, sqe.addr3, &name, value, size),
        op::FSETXATTR => {
            let file = assign_file(c, st, req)?;
            xattr::file_setxattr(c, file, &name, &req.data, sqe.op_flags)
        }
        op::SETXATTR => xattr::filename_setxattr(c, sqe.addr3, &name, &req.data, sqe.op_flags),
        _ => Err(Errno(EINVAL)),
    }
}
