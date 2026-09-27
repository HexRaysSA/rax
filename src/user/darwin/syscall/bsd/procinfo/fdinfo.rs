//! `PROC_INFO_CALL_PIDFDINFO` about the calling process's descriptors
//! (`proc_pidfdinfo`).
//!
//! A descriptor for a host file, socket, pipe, or shared memory object is
//! the host's answer about the host descriptor behind it, with the
//! descriptor-level part (`proc_fileinfo`) the guest's: its close-on-exec
//! flag and whether its open file is shared by another descriptor. A
//! kqueue is the emulated kqueue.

use super::{Args, Out, call, canonical, host_call};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{FileKind, FileRef};
use crate::user::darwin::kevent::{KevApi, KqKind};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::wait::WaitKey;

/// `PROC_PIDFD*` flavors.
mod f {
    pub const VNODEINFO: i32 = 1;
    pub const VNODEPATHINFO: i32 = 2;
    pub const SOCKETINFO: i32 = 3;
    pub const PSEMINFO: i32 = 4;
    pub const PSHMINFO: i32 = 5;
    pub const PIPEINFO: i32 = 6;
    pub const KQUEUEINFO: i32 = 7;
    pub const ATALKINFO: i32 = 8;
    pub const KQUEUE_EXTINFO: i32 = 9;
    pub const CHANNELINFO: i32 = 10;
}

/// `DTYPE_*` (`bsd/sys/file_internal.h`).
pub mod dtype {
    pub const VNODE: u32 = 1;
    pub const SOCKET: u32 = 2;
    pub const PSXSHM: u32 = 3;
    pub const KQUEUE: u32 = 5;
    pub const PIPE: u32 = 6;
}

/// `PROC_PIDFDKQUEUE_KNOTES_MAX`: the most knotes reported.
pub(super) const KNOTES_MAX: usize = 131_072;

/// `PROC_FP_*` status bits.
const PROC_FP_SHARED: u32 = 1;
const PROC_FP_CLEXEC: u32 = 2;
const PROC_FP_CLFORK: u32 = 8;

/// `KQ_*` state bits `proc_info` reports.
const KQ_SLEEP: u32 = 0x2;
const KQ_KEV32: u32 = 0x8;
const KQ_KEV64: u32 = 0x10;
const KQ_KEV_QOS: u32 = 0x20;
const KQ_WORKQ: u32 = 0x40;

/// The type of an open file (`fg_type`).
pub fn dtype(file: &FileRef) -> u32 {
    match &file.kind {
        FileKind::Kqueue(_) => dtype::KQUEUE,
        FileKind::Shm(_) => dtype::PSXSHM,
        FileKind::Host(fd) => {
            use std::os::fd::AsRawFd;
            let h = fd.as_raw_fd();
            match crate::user::darwin::host::fstat(h).map(|st| st.st_mode & libc::S_IFMT) {
                Ok(libc::S_IFSOCK) => dtype::SOCKET,
                // An anonymous pipe has no path; a named one is a vnode.
                Ok(libc::S_IFIFO) if crate::user::darwin::host::fd_path(h).is_none() => dtype::PIPE,
                _ => dtype::VNODE,
            }
        }
    }
}

/// A flavor's size and the file type it requires with the error for
/// another type.
fn flavor(flavor: i32, null: bool) -> Option<(u32, Option<(u32, Errno)>)> {
    Some(match flavor {
        f::VNODEINFO => (176, Some((dtype::VNODE, Errno::EBADF))),
        f::VNODEPATHINFO => (1200, Some((dtype::VNODE, Errno::EBADF))),
        f::SOCKETINFO => (792, Some((dtype::SOCKET, Errno::ENOTSOCK))),
        f::PSEMINFO => (1184, Some((4, Errno::EBADF))),
        f::PSHMINFO => (1192, Some((dtype::PSXSHM, Errno::EBADF))),
        f::PIPEINFO => (184, Some((dtype::PIPE, Errno::EBADF))),
        f::KQUEUEINFO => (168, Some((dtype::KQUEUE, Errno::EBADF))),
        f::ATALKINFO => (160, None),
        f::KQUEUE_EXTINFO => (
            if null { 0 } else { 104 },
            Some((dtype::KQUEUE, Errno::EBADF)),
        ),
        f::CHANNELINFO => (56, Some((10, Errno::EBADF))),
        _ => return None,
    })
}

/// `proc_pidfdinfo` for the calling process.
pub fn own(ctx: &mut Ctx<'_>, a: &Args) -> SysResult {
    let (size, wants) = flavor(a.flavor, a.buffer == 0).ok_or(Errno::EINVAL)?;
    if a.size < size {
        return Err(Errno::ENOMEM);
    }
    let Some((want, mismatch)) = wants else {
        // No handler for AppleTalk.
        return Err(Errno::EINVAL);
    };
    let fd = a.arg as i32;
    // fd -1 names the work queue's kqueue.
    if fd == -1 && matches!(a.flavor, f::KQUEUEINFO | f::KQUEUE_EXTINFO) {
        let Some(kq) = ctx.proc.kq.workq else {
            return Ok(Rv::one(0));
        };
        return kqueue(ctx, a, kq, None);
    }
    let (file, flags) = {
        let slot = ctx.proc.fds.get(fd).map_err(|_| Errno::EBADF)?;
        if dtype(&slot.file) != want {
            return Err(mismatch);
        }
        let flags = Flags {
            cloexec: slot.cloexec,
            shared: std::sync::Arc::strong_count(&slot.file) > 1,
        };
        (slot.file.clone(), flags)
    };
    match &file.kind {
        FileKind::Kqueue(kq) => kqueue(ctx, a, *kq, Some(flags)),
        FileKind::Host(h) | FileKind::Shm(h) => {
            use std::os::fd::AsRawFd;
            let h = h.as_raw_fd();
            let mut buf = vec![0u8; size as usize];
            let host = Args {
                callnum: call::PIDFDINFO,
                pid: ctx.proc.pid,
                flavor: a.flavor,
                flags: 0,
                ext_id: 0,
                extended: false,
                arg: h as u64,
                buffer: 0,
                size,
            };
            host_call(&host, buf.as_mut_ptr(), size)?;
            let mut o = Out(buf);
            fileinfo(&mut o, flags);
            if a.flavor == f::VNODEPATHINFO {
                // The path as the guest names it.
                let end = 24 + 152;
                let host_path: Vec<u8> = o.0[end..end + 1024]
                    .iter()
                    .copied()
                    .take_while(|&c| c != 0)
                    .collect();
                let path = canonical(
                    ctx,
                    std::path::Path::new(std::ffi::OsStr::new(
                        &String::from_utf8_lossy(&host_path).into_owned(),
                    )),
                );
                o.path(end, 1024, &path);
            }
            ctx.write(a.buffer, &o.0)?;
            Ok(Rv::one(u64::from(size)))
        }
    }
}

/// A descriptor's flags as `proc_fileinfo` reports them.
#[derive(Clone, Copy)]
struct Flags {
    /// Close-on-exec.
    cloexec: bool,
    /// Its open file has another descriptor in the process.
    shared: bool,
}

/// The descriptor's `proc_fileinfo` (the first 24 bytes): close-on-exec
/// is the guest slot's; the open file is shared when another guest
/// descriptor names it or, as the host says, another process holds it.
fn fileinfo(o: &mut Out, flags: Flags) {
    let status = u32::from_le_bytes(o.0[4..8].try_into().expect("4 bytes"));
    let mut status = status & !PROC_FP_CLEXEC;
    if flags.shared {
        status |= PROC_FP_SHARED;
    }
    if flags.cloexec {
        status |= PROC_FP_CLEXEC;
    }
    o.u32(4, status);
}

/// `kqueue_fdinfo` (`fill_kqueueinfo`) or the knotes of kqueue `kq`
/// (`PROC_PIDFDKQUEUE_EXTINFO`); `flags` are the descriptor naming it's.
fn kqueue(ctx: &Ctx<'_>, a: &Args, kq: u64, flags: Option<Flags>) -> SysResult {
    let Some(k) = ctx.proc.kq.kqueues.get(&kq) else {
        return Ok(Rv::one(0));
    };
    if a.flavor == f::KQUEUE_EXTINFO {
        let records: Vec<[u8; 104]> = k.knotes.values().map(extinfo).collect();
        let n = records.len().min(KNOTES_MAX);
        if a.buffer != 0 {
            let fit = n.min(a.size as usize / 104);
            let bytes: Vec<u8> = records[..fit].iter().flatten().copied().collect();
            ctx.write(a.buffer, &bytes)?;
        }
        return Ok(Rv::one(n as u64));
    }
    let pending: usize = k.queues.iter().map(|q| q.len()).sum();
    let (api_bit, blksize) = match k.api {
        Some(KevApi::Kev32) => (KQ_KEV32, 32),
        Some(KevApi::Kev64) => (KQ_KEV64, 48),
        Some(KevApi::Qos) => (KQ_KEV_QOS, 72),
        None => (0, 0),
    };
    let sleeping = ctx.proc.threads.values().any(|t| {
        t.wait
            .as_ref()
            .is_some_and(|w| w.keys.contains(&WaitKey::Kqueue(kq)))
    });
    let mut state = api_bit | if sleeping { KQ_SLEEP } else { 0 };
    if k.kind == KqKind::Workq {
        state |= KQ_WORKQ | KQ_KEV_QOS;
    }
    let mut o = Out::new(168);
    // FREAD | FWRITE; kqueues are close-on-fork and, unless cleared,
    // close-on-exec.
    let cloexec = flags.is_none_or(|f| f.cloexec);
    let shared = flags.is_some_and(|f| f.shared);
    o.u32(0, 3)
        .u32(
            4,
            PROC_FP_CLFORK
                | if cloexec { PROC_FP_CLEXEC } else { 0 }
                | if shared { PROC_FP_SHARED } else { 0 },
        )
        .u32(16, dtype::KQUEUE)
        .u16(24 + 4, 0o010000) // S_IFIFO
        .u64(24 + 88, pending as u64)
        .u32(24 + 104, blksize)
        .u32(24 + 136, state);
    ctx.write(a.buffer, &o.0)?;
    Ok(Rv::one(168))
}

/// A knote as `struct kevent_extinfo` (`pid_kqueue_extinfo`).
pub(super) fn extinfo(n: &crate::user::darwin::kevent::Knote) -> [u8; 104] {
    let mut o = Out::new(104);
    o.u64(0, n.ident)
        .u16(8, (n.filter as u16) | 0xff00)
        .u16(10, n.flags)
        .u32(12, n.qos as u32)
        .u64(16, n.udata)
        .u32(24, n.fflags)
        .u64(40, n.ext[0])
        .u64(48, n.ext[1])
        .u64(56, n.ext[2])
        .u64(64, n.ext[3])
        .u64(72, n.sdata as u64)
        .u32(80, u32::from(n.status))
        .u32(84, n.sfflags);
    o.0.try_into().expect("104 bytes")
}
