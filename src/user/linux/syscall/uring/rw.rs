//! Reads and writes (`io_uring/rw.c`, Linux 6.19): `IORING_OP_READ`,
//! `_WRITE`, `_READV`, `_WRITEV`, `_READ_FIXED`, `_WRITE_FIXED`,
//! `_READV_FIXED`, and `_WRITEV_FIXED`.
//!
//! Preparation reads the buffer or vectors (`IORING_FEAT_SUBMIT_STABLE`).
//! Issue checks the file and flags, then tries the transfer without
//! sleeping (`IO_URING_F_NONBLOCK`): one its file cannot do now waits for
//! the file ([`Done::Park`], `io_arm_poll_handler`) and is issued again
//! when the file is ready, unless `RWF_NOWAIT` asked for `EAGAIN`. A
//! regular file's transfer is done at once, as a warm page cache does it.
//! The result is the bytes moved, and a count short of the request's fails
//! the request (and so its link: `__io_complete_rw_common`). Errors found
//! before the transfer, and a read's own, complete the request at once
//! (`io_req_defer_failed`); a write's own completes it through task work
//! (`io_rw_done`). An offset of -1 is the file position, which a transfer
//! on a file with positions moves; another offset is ignored by a stream
//! (a pipe or socket) but must not be negative (`rw_verify_area`).

use std::sync::Arc;

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::super::signal::deliver::restart::{ERESTARTNOHAND, ERESTARTNOINTR, ERESTARTSYS};
use super::super::super::uring::abi::op;
use super::super::super::uring::rsrc::Imu;
use super::super::super::uring::{Req, Ring, State, req_flags as rf};
use super::super::io::{MAX_RW_COUNT, check_rw_flags, readv_file, rwf, writev_file};
use super::super::iov::{import_iovec_as, iovec_from_user_as};
use super::super::ready::ev;
use super::super::{Ctx, events, notify};
use super::ops::{Done, assign_file};
use super::rsrc;

/// `IORING_RW_ATTR_FLAG_PI` and `sizeof(struct io_uring_attr_pi)`.
const ATTR_FLAG_PI: u64 = 1;
const ATTR_PI_SIZE: usize = 32;
/// `KMALLOC_MAX_SIZE` (4 KiB pages, `MAX_PAGE_ORDER` 10) and
/// `sizeof(struct bio_vec)`.
const KMALLOC_MAX_SIZE: u64 = 4 << 20;
const BIO_VEC_SIZE: u64 = 16;
/// `RWF_HIPRI` and `RWF_NOWAIT`.
const RWF_HIPRI: u32 = 0x1;
const RWF_NOWAIT: u32 = 0x8;

fn is_write(opcode: u8) -> bool {
    matches!(
        opcode,
        op::WRITE | op::WRITEV | op::WRITE_FIXED | op::WRITEV_FIXED
    )
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `import_ubuf`: one buffer, capped at `MAX_RW_COUNT`, within user space
/// (`EFAULT`).
fn import_ubuf(c: &Ctx<'_>, addr: u64, len: u64) -> Result<(u64, u64), Errno> {
    let len = len.min(MAX_RW_COUNT);
    if !events::access_ok(c, addr, len) {
        return Err(Errno(EFAULT));
    }
    Ok((addr, len))
}

/// The operation's `prep` (`io_prep_read`, `io_prep_readv`,
/// `io_prep_read_fixed`, `io_prep_readv_fixed`, and their writes):
/// `__io_prep_rw` (the I/O priority, protection information), then the
/// buffer, the vectors, or (for a fixed vectored one) the vectors to check
/// against the registered buffer at issue.
pub(super) fn prep(c: &Ctx<'_>, ring: &Ring, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.ioprio != 0 {
        super::super::super::priority::ioprio_check(i32::from(sqe.ioprio), c.p.creds.1 == 0)?;
    }
    // attr_type_mask: only protection information, whose buffer is read
    // here (io_prep_rw_pi).
    if sqe.pad2 != 0 {
        if sqe.pad2 != ATTR_FLAG_PI {
            return Err(Errno(EINVAL));
        }
        let b = c
            .read_mem(sqe.addr3, ATTR_PI_SIZE)
            .map_err(|_| Errno(EFAULT))?;
        if le64(&b, 24) != 0 {
            return Err(Errno(EINVAL));
        }
        import_ubuf(c, le64(&b, 8), u64::from(le32(&b, 4)))?;
        req.flags |= rf::HAS_METADATA;
    }
    let select = req.flags & rf::BUFFER_SELECT != 0;
    match sqe.opcode {
        op::READ | op::WRITE => {
            if !select {
                req.vecs = vec![import_ubuf(c, sqe.addr, u64::from(sqe.len))?];
            }
        }
        op::READV | op::WRITEV => {
            if !select {
                req.vecs = import_iovec_as(c, sqe.addr, u64::from(sqe.len), ring.compat)?;
            } else {
                // io_iov_buffer_select_prep: one vector, for its length.
                if sqe.len != 1 {
                    return Err(Errno(EINVAL));
                }
                iovec_from_user_as(c, sqe.addr, 1, ring.compat)?;
            }
        }
        op::READV_FIXED | op::WRITEV_FIXED => {
            req.vecs = iovec_from_user_as(c, sqe.addr, u64::from(sqe.len), ring.compat)?;
        }
        _ => {}
    }
    Ok(())
}

/// `validate_fixed_range`: within the registered buffer and at most
/// `MAX_RW_COUNT` (`EFAULT`).
fn validate_fixed_range(addr: u64, len: u64, imu: &Imu) -> Result<(), Errno> {
    let end = addr.checked_add(len).ok_or(Errno(EFAULT))?;
    if addr < imu.addr || end > imu.addr + u64::from(imu.len) || len > MAX_RW_COUNT {
        return Err(Errno(EFAULT));
    }
    Ok(())
}

/// The registered buffer the request names (`io_find_buf_node`, `EFAULT`
/// without one).
fn fixed_buffer(st: &mut State, req: &mut Req) -> Result<Arc<Imu>, Errno> {
    rsrc::find_buf_node(st, req)
        .and_then(|id| st.rsrc.node_buf(id).cloned())
        .ok_or(Errno(EFAULT))
}

/// `io_import_reg_vec` for a user buffer: `io_estimate_bvec_size` (a
/// vector too long to count in pages is `EOVERFLOW`), the array of that
/// many `bio_vec`s (`io_vec_realloc`: `ENOMEM` past `KMALLOC_MAX_SIZE`),
/// then each vector within the buffer (`EFAULT`), none empty (`EFAULT`),
/// their total not wrapping (`EOVERFLOW`) nor past `MAX_RW_COUNT`
/// (`EINVAL`).
fn import_reg_vec(st: &mut State, req: &mut Req) -> Result<(), Errno> {
    let imu = fixed_buffer(st, req)?;
    let mut segs = 0u64;
    for &(_, len) in &req.vecs {
        segs = segs.saturating_add((len >> 12) + 2);
        if segs > i32::MAX as u64 {
            return Err(Errno(EOVERFLOW));
        }
    }
    if segs > req.vecs.len() as u64 && segs * BIO_VEC_SIZE > KMALLOC_MAX_SIZE {
        return Err(Errno(ENOMEM));
    }
    let mut total = 0u64;
    for &(addr, len) in &req.vecs {
        validate_fixed_range(addr, len, &imu)?;
        if len == 0 {
            return Err(Errno(EFAULT));
        }
        total = total.checked_add(len).ok_or(Errno(EOVERFLOW))?;
    }
    if total > MAX_RW_COUNT {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// `kiocb_set_rw_flags` for a request: the refusals the synchronous calls
/// share, `RWF_ATOMIC` for a read (`EOPNOTSUPP`), and `RWF_HIPRI`, which
/// only a polled ring takes (`EINVAL`, `io_rw_init_file`).
fn set_rw_flags(file: &OpenFile, flags: u32, write: bool) -> Result<(), Errno> {
    check_rw_flags(file, u64::from(flags))?;
    if !write && u64::from(flags) & rwf::ATOMIC != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    if flags & RWF_HIPRI != 0 {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// A file with a read or write operation (`io_iter_do_read`: `EINVAL`
/// without).
fn can_transfer(file: &OpenFile, write: bool) -> bool {
    if write {
        !matches!(file.object, FileObject::Anon(_)) || events::can_write(file)
    } else {
        events::can_read(file)
    }
}

/// The operation's `issue` (`io_read`, `io_write`, `io_read_fixed`,
/// `io_write_fixed`).
pub(super) fn issue(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) -> Done {
    let write = is_write(req.sqe.opcode);
    match issue_rw(c, st, req, write) {
        Ok(done) => done,
        // io_req_defer_failed (io_rw_fail keeps the error: nothing was
        // moved before it).
        Err(e) => {
            req.res = -e.0;
            req.cflags = 0;
            req.set_fail();
            Done::Inline
        }
    }
}

fn issue_rw(c: &mut Ctx<'_>, st: &mut State, req: &mut Req, write: bool) -> Result<Done, Errno> {
    let file = assign_file(c, st, req)?;
    match req.sqe.opcode {
        // io_init_rw_fixed.
        op::READ_FIXED | op::WRITE_FIXED => {
            let imu = fixed_buffer(st, req)?;
            let (addr, len) = (req.sqe.addr, u64::from(req.sqe.len));
            validate_fixed_range(addr, len, &imu)?;
            req.vecs = vec![(addr, len)];
        }
        op::READV_FIXED | op::WRITEV_FIXED => import_reg_vec(st, req)?,
        _ => {}
    }
    // io_buffer_select: no buffer group is ever provided.
    if req.flags & rf::BUFFER_SELECT != 0 {
        return Err(Errno(ENOBUFS));
    }
    // io_rw_init_file.
    let allowed = if write {
        file.writable()
    } else {
        file.readable()
    };
    if !allowed {
        return Err(Errno(EBADF));
    }
    let flags = req.sqe.op_flags;
    set_rw_flags(&file, flags, write)?;
    if flags & RWF_NOWAIT != 0 {
        req.flags |= rf::NOWAIT;
    }
    if req.flags & rf::HAS_METADATA != 0 {
        // No file here has FMODE_HAS_METADATA.
        return Err(Errno(EINVAL));
    }
    let count: u64 = req.vecs.iter().map(|&(_, l)| l).sum();
    // io_kiocb_update_pos and rw_verify_area.
    let off = req.sqe.off as i64;
    let positioned = matches!(file.ftype, FileType::Regular | FileType::BlockDevice);
    let pos = if off == -1 {
        None
    } else {
        if off < 0 || off.checked_add(count as i64).is_none() {
            return Err(Errno(EINVAL));
        }
        positioned.then_some(off as u64)
    };
    if !can_transfer(&file, write) {
        return Err(Errno(EINVAL));
    }
    if file.ftype == FileType::Directory {
        return Err(Errno(EISDIR));
    }
    let anon = matches!(file.object, FileObject::Anon(_));
    c.nowait = true;
    c.nosignal = u64::from(flags) & rwf::NOSIGNAL != 0;
    c.sigpipe_decided = false;
    let r = if count == 0 && !anon {
        Ok(0)
    } else if write && anon {
        events::write(c, &file, &req.vecs)
    } else if write {
        writev_file(c, &file, &req.vecs, pos)
    } else {
        readv_file(c, &file, &req.vecs, pos)
    };
    c.nowait = false;
    // pipe_write's SIGPIPE (the socket protocols send their own).
    if write && matches!(r, Err(Errno(EPIPE))) && !c.sigpipe_decided {
        c.send_sigpipe();
    }
    c.nosignal = false;
    match r {
        Ok(n) => {
            // kiocb_done: __io_complete_rw_common, io_req_io_end.
            if n != count {
                req.set_fail();
            }
            if write {
                notify::allocated(&file);
            } else {
                notify::access(&file, n, true);
            }
            req.res = n as i32;
            req.cflags = 0;
            Ok(Done::Inline)
        }
        // The file cannot do it now: without RWF_NOWAIT, wait for it.
        Err(Errno(EAGAIN | ERESTARTSYS | ERESTARTNOINTR | ERESTARTNOHAND)) => {
            if req.flags & rf::NOWAIT == 0 {
                let mask = if write {
                    ev::OUT | ev::WRNORM
                } else {
                    ev::IN | ev::RDNORM
                };
                return Ok(Done::Park(file, mask));
            }
            if !write {
                return Err(Errno(EAGAIN));
            }
            Ok(write_failed(req, &file, EAGAIN))
        }
        Err(e) if !write => Err(e),
        Err(Errno(e)) => Ok(write_failed(req, &file, e)),
    }
}

/// `kiocb_done` for a write's own error: `io_rw_done` completes it
/// through task work (`io_req_rw_complete`, which reports a modification
/// even so).
fn write_failed(req: &mut Req, file: &OpenFile, e: i32) -> Done {
    req.set_fail();
    req.res = -e;
    req.cflags = 0;
    notify::allocated(file);
    Done::TaskWork
}
