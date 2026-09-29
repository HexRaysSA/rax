//! Control messages: the descriptors `SCM_RIGHTS` carries between the
//! guest's table and the host's, and the copy of received control data
//! into the caller's buffer (`copyout_control`).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use super::{SCM_RIGHTS, SOL_SOCKET, free_slots, msg};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::fd::{FileKind, OpenFile};
use crate::user::darwin::io;
use crate::user::darwin::syscall::Ctx;

/// `sizeof(struct cmsghdr)`.
const CMSG_HDR: usize = 12;

/// `CMSG_ALIGN`: control messages are 4-byte aligned on Darwin.
fn align(n: usize) -> usize {
    (n + 3) & !3
}

/// A control message header at `off`: `(cmsg_len, cmsg_level, cmsg_type)`.
fn header(buf: &[u8], off: usize) -> Option<(usize, i32, i32)> {
    let h = buf.get(off..off + CMSG_HDR)?;
    let word = |i: usize| i32::from_le_bytes(h[i..i + 4].try_into().expect("4 bytes"));
    Some((word(0) as u32 as usize, word(4), word(8)))
}

/// What a guest descriptor carried by `SCM_RIGHTS` becomes on the host:
/// its host descriptor; -1 for one not open (the host then fails with
/// `EBADF` where `unp_internalize` checks it); a host kqueue for one that
/// cannot be sent (the host then fails with `EINVAL`).
fn outgoing(ctx: &Ctx<'_>, fd: i32, unsendable: &mut Option<OwnedFd>) -> RawFd {
    let Ok(file) = ctx.proc.fds.file(fd) else {
        return -1;
    };
    match file.host_fd() {
        Some(h) => h,
        None => unsendable
            .get_or_insert_with(|| {
                // SAFETY: kqueue(2) takes no arguments; the descriptor is
                // owned here.
                unsafe { OwnedFd::from_raw_fd(libc::kqueue()) }
            })
            .as_raw_fd(),
    }
}

/// Translates the control data of a send on an `AF_UNIX` socket for the
/// host: the descriptors of an `SCM_RIGHTS` message that is the whole
/// buffer, the only form `unp_internalize` takes (the host refuses the
/// others untouched). Errors are left for the host to report in its
/// order; `keep` holds what the translation made until the send is done.
pub(super) fn internalize(ctx: &Ctx<'_>, buf: &mut [u8], keep: &mut Option<OwnedFd>) {
    let Some((len, level, ty)) = header(buf, 0) else {
        return;
    };
    if level != SOL_SOCKET || ty != SCM_RIGHTS || len != buf.len() {
        return;
    }
    for off in (CMSG_HDR..len).step_by(4).take_while(|o| o + 4 <= len) {
        let fd = i32::from_le_bytes(buf[off..off + 4].try_into().expect("4 bytes"));
        let h = outgoing(ctx, fd, keep);
        buf[off..off + 4].copy_from_slice(&h.to_le_bytes());
    }
}

/// The kind of a descriptor received from the host.
fn kind(h: OwnedFd) -> FileKind {
    let raw = h.as_raw_fd();
    if crate::user::darwin::host::fstat(raw)
        .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFSOCK)
    {
        return FileKind::Socket(h);
    }
    // A POSIX semaphore answers PROC_PIDFDPSEMINFO (4).
    let mut info = [0u8; 1192];
    // SAFETY: `info` holds more than the 1184 bytes of `struct psem_fdinfo`.
    let n = unsafe { libc::proc_pidfdinfo(libc::getpid(), raw, 4, info.as_mut_ptr().cast(), 1184) };
    if n > 0 {
        return FileKind::Sem(h);
    }
    // A POSIX shared memory object answers PROC_PIDFDPSHMINFO (5).
    // SAFETY: `info` holds the 1192 bytes of `struct pshm_fdinfo`.
    let n = unsafe {
        libc::proc_pidfdinfo(
            libc::getpid(),
            raw,
            5,
            info.as_mut_ptr().cast(),
            info.len() as i32,
        )
    };
    if n > 0 {
        FileKind::Shm(h)
    } else {
        FileKind::Host(h)
    }
}

/// Installs the descriptors every `SCM_RIGHTS` message of received
/// control data `buf` carries in the guest's table (`unp_externalize`:
/// each at the lowest free descriptor, not close-on-exec) and rewrites
/// them to the guest's numbers. When the table cannot hold them all,
/// every one is closed: `EMSGSIZE`.
pub(super) fn externalize(ctx: &mut Ctx<'_>, buf: &mut [u8]) -> Result<(), Errno> {
    let mut slots = Vec::new();
    let mut off = 0;
    while let Some((len, level, ty)) = header(buf, off) {
        if len < CMSG_HDR || off + len > buf.len() {
            break;
        }
        if level == SOL_SOCKET && ty == SCM_RIGHTS {
            slots.extend(
                (off + CMSG_HDR..off + len)
                    .step_by(4)
                    .filter(|o| o + 4 <= off + len),
            );
        }
        off += align(len);
    }
    let fds: Vec<OwnedFd> = slots
        .iter()
        .map(|&o| i32::from_le_bytes(buf[o..o + 4].try_into().expect("4 bytes")))
        // SAFETY: the host just installed each descriptor for this
        // process; nothing else owns it.
        .map(|h| unsafe { OwnedFd::from_raw_fd(h) })
        .collect();
    if fds.len() as u64 > free_slots(ctx) {
        return Err(Errno::EMSGSIZE);
    }
    let limit = ctx.proc.rlimits[8].0;
    for (o, h) in slots.into_iter().zip(fds) {
        let raw = h.as_raw_fd();
        // SAFETY: fcntl on a live descriptor takes an integer or nothing.
        let fl = unsafe {
            libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(raw, libc::F_GETFL)
        };
        let file = OpenFile {
            kind: kind(h),
            path: None,
            flags: std::sync::Mutex::new(io::host_to_guest_oflags(fl.max(0))),
        };
        let fd = ctx.proc.fds.install(Arc::new(file), false, 0, limit)?;
        buf[o..o + 4].copy_from_slice(&fd.to_le_bytes());
    }
    Ok(())
}

/// `copyout_control`: received control data into the caller's buffer of
/// `cap` bytes at `addr`, each message rounded to `CMSG_ALIGN`, the last
/// one that does not fit cut short with `MSG_CTRUNC`. Returns the bytes
/// copied and the flag.
pub(super) fn copyout(ctx: &Ctx<'_>, addr: u64, cap: u32, buf: &[u8]) -> Result<(u32, i32), Errno> {
    let mut left = cap as usize;
    let mut out = 0usize;
    let mut flags = 0;
    let mut off = 0;
    while left > 0 {
        let Some((len, ..)) = header(buf, off) else {
            break;
        };
        let size = align(len).min(buf.len() - off);
        if size == 0 {
            break;
        }
        let n = if left >= size {
            size
        } else {
            flags |= msg::CTRUNC;
            left
        };
        ctx.write(addr + out as u64, &buf[off..off + n])?;
        out += n;
        left -= n;
        off += size;
    }
    Ok((out as u32, flags))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmsg(level: i32, ty: i32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((CMSG_HDR + data.len()) as u32).to_le_bytes());
        v.extend_from_slice(&level.to_le_bytes());
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(data);
        v.resize(align(v.len()), 0);
        v
    }

    #[test]
    fn messages_are_four_byte_aligned() {
        assert_eq!(align(13), 16);
        assert_eq!(align(16), 16);
        let m = cmsg(0, 24, &[64]);
        assert_eq!(m.len(), 16);
        assert_eq!(header(&m, 0), Some((13, 0, 24)));
        assert_eq!(header(&m, 8), None);
    }
}
