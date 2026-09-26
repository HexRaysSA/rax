//! Copies between two descriptors inside the kernel (`fs/read_write.c`):
//! `sendfile` (with a `loff_t` or, for a 32-bit call, a `compat_off_t`
//! offset) and `copy_file_range`.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::O_APPEND;
use super::super::fs::fd::FileType;
use super::super::signal::deliver::restart::ERESTARTSYS;
use super::super::wait::Resume;
use super::io::{CHUNK, MAX_RW_COUNT, may_block, ready_now, wait_ready};
use super::{Ctx, SysResult};

/// `sendfile`: copies from `in_fd` (at `*off_ptr`, or its position) to
/// `out_fd`. Bytes the output does not take are left in the input. A pipe
/// or socket output without `O_NONBLOCK` that is full sleeps as `write`
/// does; a signal ends the copy with what was copied, or `-ERESTARTSYS`.
pub fn sendfile(c: &mut Ctx<'_>, out_fd: i32, in_fd: i32, off_ptr: u64, count: u64) -> SysResult {
    sendfile_as(c, out_fd, in_fd, off_ptr, count, SendfileOffset::Loff)
}

/// The offset a `sendfile` call reads and writes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendfileOffset {
    /// A `loff_t` (`sendfile64`, and `sendfile` of the 64-bit ABIs):
    /// transfers up to the file-size limit.
    Loff,
    /// A `compat_off_t` (`compat_sys_sendfile`): sign-extended, written
    /// back truncated, and the transfer ends at `MAX_NON_LFS` (`EOVERFLOW`
    /// from there).
    Compat,
}

/// `do_sendfile` with the offset at `off_ptr` (none for 0) in `width`.
pub fn sendfile_as(
    c: &mut Ctx<'_>,
    out_fd: i32,
    in_fd: i32,
    off_ptr: u64,
    count: u64,
    width: SendfileOffset,
) -> SysResult {
    let input = c.p.fds.file(in_fd)?;
    let output = c.p.fds.file(out_fd)?;
    if !input.readable() || !output.writable() {
        return Err(Errno(EBADF));
    }
    let mut pos = if off_ptr != 0 {
        let v = match width {
            SendfileOffset::Loff => c.read_u64(off_ptr)? as i64,
            SendfileOffset::Compat => i64::from(c.read_u32(off_ptr)? as i32),
        };
        if v < 0 {
            return Err(Errno(EINVAL));
        }
        Some(v as u64)
    } else {
        None
    };
    let mut count = count.min(MAX_RW_COUNT);
    if let (Some(p), SendfileOffset::Compat) = (pos, width) {
        let max = super::super::abi::types::MAX_NON_LFS as u64;
        if p + count > max {
            if p >= max {
                return Err(Errno(EOVERFLOW));
            }
            count = max - p;
        }
    }
    let waits = may_block(&output) && matches!(output.ftype, FileType::Fifo | FileType::Socket);
    // After a sleep the offset in memory is still the original one.
    let mut done = match c.resume.take() {
        Some(Resume::Written(n)) => n,
        _ => 0,
    };
    if let Some(p) = pos.as_mut() {
        *p += done;
    }
    let mut buf = vec![0u8; (count as usize).min(CHUNK)];
    let mut stop = None;
    while done < count {
        if waits && !ready_now(&output, true) {
            if c.signal_pending() {
                if done == 0 {
                    stop = Some(Errno(ERESTARTSYS));
                }
                break;
            }
            return Err(wait_ready(c, &output, true, Resume::Written(done)));
        }
        let want = ((count - done) as usize).min(buf.len());
        let n = match pos {
            Some(p) => input.read_at(&mut buf[..want], p)?,
            None => input.read(&mut buf[..want])?,
        };
        if n == 0 {
            break;
        }
        let w = match output.write(&buf[..n]) {
            Ok(w) => w,
            Err(Errno(EAGAIN)) if waits => 0,
            Err(e) => {
                if pos.is_none() {
                    input.seek(-(n as i64), 1)?;
                }
                if done == 0 {
                    return Err(e);
                }
                break;
            }
        };
        if pos.is_none() && w < n {
            input.seek(-((n - w) as i64), 1)?;
        }
        done += w as u64;
        if let Some(p) = pos.as_mut() {
            *p += w as u64;
        }
        if w < n && !waits {
            break;
        }
    }
    if let (Some(p), true) = (pos, off_ptr != 0) {
        match width {
            SendfileOffset::Loff => c.write_u64(off_ptr, p)?,
            SendfileOffset::Compat => c.write_u32(off_ptr, p as u32)?,
        }
    }
    match stop {
        Some(e) => Err(e),
        None => {
            super::notify::access(&input, done, false);
            super::notify::modify(&output, done);
            Ok(done)
        }
    }
}

/// `copy_file_range` (emulated with positioned reads and writes).
pub fn copy_file_range(
    c: &mut Ctx<'_>,
    in_fd: i32,
    in_off: u64,
    out_fd: i32,
    out_off: u64,
    len: u64,
) -> SysResult {
    let input = c.p.fds.file(in_fd)?;
    let output = c.p.fds.file(out_fd)?;
    if !input.readable() || !output.writable() || output.flags() & O_APPEND != 0 {
        return Err(Errno(EBADF));
    }
    if input.ftype != FileType::Regular || output.ftype != FileType::Regular {
        return Err(Errno(EINVAL));
    }
    let mut ipos = if in_off != 0 {
        c.read_u64(in_off)?
    } else {
        input.seek(0, 1)?
    };
    let mut opos = if out_off != 0 {
        c.read_u64(out_off)?
    } else {
        output.seek(0, 1)?
    };
    let len = len.min(MAX_RW_COUNT);
    let mut done = 0;
    let mut buf = vec![0u8; (len as usize).min(CHUNK)];
    while done < len {
        let want = ((len - done) as usize).min(buf.len());
        let n = input.read_at(&mut buf[..want], ipos)?;
        if n == 0 {
            break;
        }
        let w = output.write_at(&buf[..n], opos)?;
        done += w as u64;
        ipos += w as u64;
        opos += w as u64;
        if w < n {
            break;
        }
    }
    if in_off != 0 {
        c.write_u64(in_off, ipos)?;
    } else {
        input.seek(ipos as i64, 0)?;
    }
    if out_off != 0 {
        c.write_u64(out_off, opos)?;
    } else {
        output.seek(opos as i64, 0)?;
    }
    super::notify::access(&input, done, false);
    super::notify::modify(&output, done);
    Ok(done)
}
