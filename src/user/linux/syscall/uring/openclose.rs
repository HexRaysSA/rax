//! Opening and closing (`io_uring/openclose.c`, Linux 6.19):
//! `IORING_OP_OPENAT`, `_OPENAT2`, `_CLOSE`, `_FIXED_FD_INSTALL`, and
//! `_PIPE`, into the descriptor table or, with `file_index`, the
//! registered-file table (direct descriptors: slot `file_index - 1`, or
//! the next free one for `IORING_FILE_INDEX_ALLOC`).
//!
//! An open first tries without sleeping, `O_NONBLOCK` added for the try
//! (so a FIFO opened for writing without a reader is `ENXIO`) and taken
//! away again; one that may create or truncate runs on the async workers.
//! The descriptor limit is the one at preparation, and a free descriptor
//! is taken before the path is looked up.

use std::sync::Arc;

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::abi::open::{
    O_CLOEXEC, O_CREAT, O_NONBLOCK, O_PATH, O_TMPFILE_BIT, O_TRUNC,
};
use super::super::super::fs::fd::OpenFile;
use super::super::super::uring::abi::op;
use super::super::super::uring::rsrc::FILE_INDEX_ALLOC;
use super::super::super::uring::{Req, Ring, State, req_flags as rf};
use super::super::fcntl::set_host_nonblocking;
use super::super::io::{nofile, pipe_files};
use super::super::path::{open_file, open_how_flags};
use super::super::{Ctx, io};
use super::ops::{assign_file, getname};
use super::{ring_file, rsrc};

/// `IORING_FIXED_FD_NO_CLOEXEC`.
const FIXED_FD_NO_CLOEXEC: u32 = 1;
/// `OPEN_HOW_SIZE_VER0`.
const OPEN_HOW_SIZE_VER0: u32 = 24;

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `copy_struct_from_user` of a `struct open_how` of `len` bytes: the
/// bytes past it zero (`E2BIG`), all readable (`EFAULT`).
fn copy_open_how(c: &Ctx<'_>, addr: u64, len: u32) -> Result<[u64; 3], Errno> {
    let mut at = u64::from(OPEN_HOW_SIZE_VER0);
    while at < u64::from(len) {
        let n = (u64::from(len) - at).min(4096);
        let b = c
            .read_mem(addr.wrapping_add(at), n as usize)
            .map_err(|_| Errno(EFAULT))?;
        if b.iter().any(|&x| x != 0) {
            return Err(Errno(E2BIG));
        }
        at += n;
    }
    let b = c
        .read_mem(addr, OPEN_HOW_SIZE_VER0 as usize)
        .map_err(|_| Errno(EFAULT))?;
    Ok([le64(&b, 0), le64(&b, 8), le64(&b, 16)])
}

/// `io_openat_prep` (`build_open_how` of `open_flags` and `len`) and
/// `io_openat2_prep` (the `struct open_how` at `addr2`, `len` bytes of
/// it), then `__io_openat_prep`: no buffer index, no registered file
/// (`EBADF`), `O_LARGEFILE` unless `O_PATH` (`force_o_largefile`), the
/// name, and no `O_CLOEXEC` for a direct descriptor.
pub(super) fn open_prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    let (mut flags, mode, resolve) = if sqe.opcode == op::OPENAT2 {
        if sqe.len < OPEN_HOW_SIZE_VER0 {
            return Err(Errno(EINVAL));
        }
        let how = copy_open_how(c, sqe.off, sqe.len)?;
        (how[0], how[1], how[2])
    } else {
        (u64::from(sqe.op_flags), u64::from(sqe.len), 0)
    };
    if sqe.buf_index != 0 {
        return Err(Errno(EINVAL));
    }
    if req.flags & rf::FIXED_FILE != 0 {
        return Err(Errno(EBADF));
    }
    if flags & u64::from(O_PATH) == 0 {
        flags |= u64::from(c.p.abi.open_flags().largefile);
    }
    getname(c, req, sqe.addr, false)?;
    if sqe.file_index != 0 && flags & u64::from(O_CLOEXEC) != 0 {
        return Err(Errno(EINVAL));
    }
    req.how = [flags, mode, resolve, nofile(c)];
    if flags & u64::from(O_TRUNC | O_CREAT | O_TMPFILE_BIT) != 0 {
        req.flags |= rf::FORCE_ASYNC;
    }
    Ok(())
}

/// `io_openat2`: the file opened (an `IORING_OP_OPENAT2`'s flags checked
/// first, `build_open_flags`) and installed; the descriptor, or the slot
/// allocated (0 for one named).
pub(super) fn open_issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) {
    c.names = req.names.clone();
    let r = open(c, ring, st, req);
    c.names.clear();
    complete(req, r);
}

fn open(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &Req) -> Result<i32, Errno> {
    let [flags, mode, resolve, limit] = req.how;
    let (flags, mode) = if req.sqe.opcode == op::OPENAT2 {
        open_how_flags(c, flags, mode, resolve)?
    } else {
        (flags as u32, mode as u32)
    };
    let slot = req.sqe.file_index;
    let fd = if slot == 0 {
        Some(c.p.fds.free_fds(1, limit)?[0])
    } else {
        None
    };
    // The try without sleeping (not on the workers).
    let tried = req.flags & rf::FORCE_ASYNC == 0;
    let open_flags = if tried { flags | O_NONBLOCK } else { flags };
    let file = open_file(c, req.sqe.fd, req.sqe.addr, open_flags, mode)?;
    if tried && flags & O_NONBLOCK == 0 {
        file.state.lock().unwrap().flags &= !O_NONBLOCK;
        set_host_nonblocking(&file, false)?;
    }
    match fd {
        Some(fd) => {
            c.p.fds
                .install_at(fd, file, flags & O_CLOEXEC != 0, limit)?;
            Ok(fd)
        }
        None => rsrc::fixed_fd_install(ring, st, file, slot).map(|n| n as i32),
    }
}

/// A result, failing the request if it is an error (`req_set_fail`).
fn complete(req: &mut Req, r: Result<i32, Errno>) {
    req.res = match r {
        Ok(v) => v,
        Err(Errno(e)) => {
            req.set_fail();
            -e
        }
    };
    req.cflags = 0;
}

/// `io_close_prep`: no offset, address, length, flags, or buffer index
/// (`EINVAL`), no registered file (`EBADF`), and not both a descriptor
/// and a slot.
pub(super) fn close_prep(req: &Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.off != 0 || sqe.addr != 0 || sqe.len != 0 || sqe.op_flags != 0 || sqe.buf_index != 0 {
        return Err(Errno(EINVAL));
    }
    if req.flags & rf::FIXED_FILE != 0 {
        return Err(Errno(EBADF));
    }
    if sqe.file_index != 0 && sqe.fd != 0 {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// `io_close`: slot `file_index - 1` emptied (`io_fixed_fd_remove`), or the
/// descriptor closed, unless it is not open or is a ring (`EBADF`).
pub(super) fn close_issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) {
    let r = (|| {
        let slot = req.sqe.file_index;
        if slot != 0 {
            return rsrc::fixed_fd_remove(ring, st, slot.wrapping_sub(1)).map(|()| 0);
        }
        let fd = req.sqe.fd;
        let open = c.p.fds.get(fd).map_err(|_| Errno(EBADF))?;
        if ring_file(&open.file).is_some() {
            return Err(Errno(EBADF));
        }
        let closed = c.p.fds.close(fd)?;
        // Dropped once the ring's lock is let go.
        st.rsrc
            .dead
            .push(super::super::super::uring::rsrc::Rsrc::File(closed.file));
        Ok(0)
    })();
    complete(req, r);
}

/// `io_install_fixed_fd_prep`: no offset, address, length, buffer index,
/// `file_index`, or `addr3` (`EINVAL`); a registered file (`EBADF`); only
/// `IORING_FIXED_FD_NO_CLOEXEC` (`EINVAL`); and the caller's own
/// credentials (`EPERM` with a personality).
pub(super) fn install_prep(req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.off != 0
        || sqe.addr != 0
        || sqe.len != 0
        || sqe.buf_index != 0
        || sqe.file_index != 0
        || sqe.addr3 != 0
    {
        return Err(Errno(EINVAL));
    }
    if req.flags & rf::FIXED_FILE == 0 {
        return Err(Errno(EBADF));
    }
    if sqe.op_flags & !FIXED_FD_NO_CLOEXEC != 0 {
        return Err(Errno(EINVAL));
    }
    if req.flags & rf::CREDS != 0 {
        return Err(Errno(EPERM));
    }
    Ok(())
}

/// `io_install_fixed_fd`: the registered file at a new descriptor
/// (`receive_fd`), close-on-exec unless `IORING_FIXED_FD_NO_CLOEXEC`.
pub(super) fn install_issue(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) {
    let r = (|| {
        let file = assign_file(c, st, req)?;
        let cloexec = req.sqe.op_flags & FIXED_FD_NO_CLOEXEC == 0;
        io::install(c, file, cloexec).map(|fd| fd as i32)
    })();
    complete(req, r);
}

/// `io_pipe_prep`: no descriptor, offset, or `addr3` (`EINVAL`); the
/// pipe flags (`EINVAL` beyond `pipe2`'s); the descriptor limit now.
pub(super) fn pipe_prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.fd != 0 || sqe.off != 0 || sqe.addr3 != 0 {
        return Err(Errno(EINVAL));
    }
    let direct = c.p.abi.open_flags().direct;
    let notification = super::super::super::abi::open::O_EXCL;
    if sqe.op_flags & !(O_CLOEXEC | O_NONBLOCK | direct | notification) != 0 {
        return Err(Errno(EINVAL));
    }
    req.how[3] = nofile(c);
    Ok(())
}

/// `io_pipe`: a new pipe's ends at two descriptors, or at two slots (the
/// named one and the next, or two allocated; not close-on-exec, `EINVAL`),
/// their numbers written to `addr` (for named slots, 0 each, as
/// `__io_fixed_fd_install` returns them); `EFAULT` there undoes it.
pub(super) fn pipe_issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) {
    let r = pipe(c, ring, st, req);
    complete(req, r);
}

fn pipe(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &Req) -> Result<i32, Errno> {
    let flags = req.sqe.op_flags;
    let (rf, wf) = pipe_files(c, flags)?;
    let at = req.sqe.addr;
    let slot = req.sqe.file_index;
    let put = |c: &Ctx<'_>, fds: [i32; 2]| {
        let b: Vec<u8> = fds.iter().flat_map(|f| f.to_le_bytes()).collect();
        c.write_mem(at, &b).map_err(|_| Errno(EFAULT))
    };
    if slot == 0 {
        let limit = req.how[3];
        let fds = c.p.fds.free_fds(2, limit)?;
        put(c, [fds[0], fds[1]])?;
        let cloexec = flags & O_CLOEXEC != 0;
        c.p.fds.install_at(fds[0], rf, cloexec, limit)?;
        c.p.fds.install_at(fds[1], wf, cloexec, limit)?;
        return Ok(0);
    }
    if flags & O_CLOEXEC != 0 {
        return Err(Errno(EINVAL));
    }
    let mut fds = [-1i32; 2];
    let r = pipe_fixed(c, ring, st, [rf, wf], slot, &mut fds, put);
    if r.is_err() {
        // io_pipe_fixed's undoing, by the numbers it got.
        for fd in fds {
            if fd != -1 {
                let _ = rsrc::fixed_fd_remove(ring, st, fd as u32);
            }
        }
    }
    r.map(|()| 0)
}

fn pipe_fixed(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    files: [Arc<OpenFile>; 2],
    slot: u32,
    fds: &mut [i32; 2],
    put: impl Fn(&Ctx<'_>, [i32; 2]) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let [rf, wf] = files;
    fds[0] = rsrc::fixed_fd_install(ring, st, rf, slot)? as i32;
    let next = if slot != FILE_INDEX_ALLOC {
        slot.wrapping_add(1)
    } else {
        slot
    };
    fds[1] = rsrc::fixed_fd_install(ring, st, wf, next)? as i32;
    put(c, *fds)
}
