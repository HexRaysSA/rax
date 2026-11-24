//! Copies between two descriptors inside the kernel (`fs/read_write.c`):
//! `sendfile` (with a `loff_t` or, for a 32-bit call, a `compat_off_t`
//! offset) and `copy_file_range`.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::{O_APPEND, O_PATH};
use super::super::abi::types::MAX_NON_LFS;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::signal::SIGXFSZ;
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
    flags: u32,
) -> SysResult {
    let input = c.p.fds.file(in_fd)?;
    let output = c.p.fds.file(out_fd)?;
    if (input.flags() | output.flags()) & O_PATH != 0 {
        return Err(Errno(EBADF));
    }
    let in_position = (in_off != 0).then(|| c.read_u64(in_off)).transpose()?;
    let out_position = (out_off != 0).then(|| c.read_u64(out_off)).transpose()?;
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    if input.ftype == FileType::Directory || output.ftype == FileType::Directory {
        return Err(Errno(EISDIR));
    }
    if input.ftype != FileType::Regular || output.ftype != FileType::Regular {
        return Err(Errno(EINVAL));
    }
    if !input.readable() || !output.writable() || output.flags() & O_APPEND != 0 {
        return Err(Errno(EBADF));
    }
    let workspace_file = |file: &OpenFile| matches!(&file.object, FileObject::Supplied(entry) if entry.workspace_file().is_some());
    let memfd_mount = |file: &OpenFile| file.memfd.as_ref().map(|memfd| memfd.hugetlb);
    // Installed inputs and the workspace are distinct filesystems. The
    // ordinary and huge-page memfd mounts are separate from the workspace
    // and each other, even though they share its backing implementation.
    if !c.p.config.host_services
        && (!workspace_file(&input)
            || !workspace_file(&output)
            || memfd_mount(&input) != memfd_mount(&output))
    {
        return Err(Errno(EXDEV));
    }
    let ipos = match in_position {
        Some(pos) => pos,
        None => input.seek(0, 1)?,
    };
    let opos = match out_position {
        Some(pos) => pos,
        None => output.seek(0, 1)?,
    };
    if ipos.checked_add(len).is_none() || opos.checked_add(len).is_none() {
        return Err(Errno(EOVERFLOW));
    }
    if (ipos as i64) < 0 || (opos as i64) < 0 {
        return Err(Errno(EINVAL));
    }

    let source = super::path::stat_file(c, &input)?;
    let target = super::path::stat_file(c, &output)?;
    let limit = c.p.rlimits[1].0; // RLIMIT_FSIZE
    if opos >= limit {
        c.send_signal_to_caller(SIGXFSZ);
        return Err(Errno(EFBIG));
    }
    let max_offset = if output.flags() & c.p.abi.open_flags().largefile != 0 {
        i64::MAX as u64
    } else {
        MAX_NON_LFS as u64
    };
    if opos >= max_offset {
        return Err(Errno(EFBIG));
    }
    let len = len
        .min((source.size.max(0) as u64).saturating_sub(ipos))
        .min(limit - opos)
        .min(max_offset - opos);
    let same_inode = (source.dev_major, source.dev_minor, source.ino)
        == (target.dev_major, target.dev_minor, target.ino);
    if same_inode && opos + len > ipos && opos < ipos + len {
        return Err(Errno(EINVAL));
    }

    let len = len.min(MAX_RW_COUNT);
    let mut done = 0;
    let mut buf = vec![0u8; (len as usize).min(CHUNK)];
    while done < len {
        let want = ((len - done) as usize).min(buf.len());
        let n = match input.read_at(&mut buf[..want], ipos + done) {
            Err(_) if done > 0 => break,
            result => result?,
        };
        if n == 0 {
            break;
        }
        let w = match output.write_at(&buf[..n], opos + done) {
            Err(_) if done > 0 => break,
            result => result?,
        };
        done += w as u64;
        if w < n {
            break;
        }
    }
    if done == 0 {
        return Ok(0);
    }
    super::notify::access(&input, done, false);
    super::notify::modify(&output, done);
    // Both positions are published after a transfer, even when one user
    // pointer is read-only and the copy ultimately reports EFAULT.
    let input_update = if in_off != 0 {
        c.write_u64(in_off, ipos + done)
    } else {
        input.seek((ipos + done) as i64, 0).map(|_| ())
    };
    let output_update = if out_off != 0 {
        c.write_u64(out_off, opos + done)
    } else {
        output.seek((opos + done) as i64, 0).map(|_| ())
    };
    input_update?;
    output_update?;
    Ok(done)
}
