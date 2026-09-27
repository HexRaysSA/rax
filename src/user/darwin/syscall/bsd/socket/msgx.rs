//! `sendmsg_x` and `recvmsg_x`: arrays of `struct msghdr_x` (a
//! `msghdr` with `msg_datalen`), sent or received in one call.
//!
//! The host is given a copy of the guest's array whose buffers are the
//! emulator's; where the guest's memory cannot be read, the copy points
//! at an address the host cannot read either (1), so that the host fails
//! at the same message, in the same way, as XNU does with the guest's.

use std::os::fd::{OwnedFd, RawFd};

use super::{
    Block, blocking, control, copyout_sa, host_result, moved_before, msg, park, sigpipe, so, sock,
    timed_out,
};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;

/// `sizeof(struct user64_msghdr_x)`.
const MSGHDR_X: usize = 56;
/// `UIO_MAXIOV`.
const UIO_MAXIOV: i32 = 1024;
/// The most a message's data is given to the host.
const DATA_MAX: u64 = 8 << 20;
/// Room for one message's control data.
const CONTROL_MAX: usize = 8192;
/// An address the host cannot touch: its copies fault as the guest's
/// would.
const FAULT: usize = 1;

/// The host's `recvmsg_x` and `sendmsg_x`.
mod sys {
    unsafe extern "C" {
        pub fn recvmsg_x(s: i32, msgp: *mut super::HostMsg, cnt: u32, flags: i32) -> isize;
        pub fn sendmsg_x(s: i32, msgp: *const super::HostMsg, cnt: u32, flags: i32) -> isize;
    }
}

/// A host `struct msghdr_x`.
#[repr(C)]
#[derive(Clone, Copy)]
struct HostMsg {
    name: usize,
    namelen: u32,
    iov: usize,
    iovlen: i32,
    control: usize,
    controllen: u32,
    flags: i32,
    datalen: usize,
}

const _: () = assert!(std::mem::size_of::<HostMsg>() == MSGHDR_X);

/// One guest message: its header as read (`None`: unreadable) and the
/// emulator's buffers behind the host's copy.
struct Slot {
    raw: Option<[u8; MSGHDR_X]>,
    iov: Option<Vec<(u64, u64)>>,
    data: Vec<u8>,
    host_iov: libc::iovec,
    name: Vec<u8>,
    ctl: Vec<u8>,
}

impl Slot {
    fn u64(&self, off: usize) -> u64 {
        self.raw.map_or(0, |r| {
            u64::from_le_bytes(r[off..off + 8].try_into().expect("8 bytes"))
        })
    }
    fn u32(&self, off: usize) -> u32 {
        self.raw.map_or(0, |r| {
            u32::from_le_bytes(r[off..off + 4].try_into().expect("4 bytes"))
        })
    }
}

/// Reads message `i` of the guest's array at `msgp`: its header and, for
/// a valid count, its scatter-gather list.
fn slot(ctx: &Ctx<'_>, msgp: u64, i: u32) -> Slot {
    let mut raw = [0u8; MSGHDR_X];
    let raw = ctx
        .read_into(msgp + u64::from(i) * MSGHDR_X as u64, &mut raw)
        .ok()
        .map(|_| raw);
    let mut s = Slot {
        raw,
        iov: None,
        data: Vec::new(),
        host_iov: libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        },
        name: Vec::new(),
        ctl: Vec::new(),
    };
    let iovlen = s.u32(24) as i32;
    if s.raw.is_some() && iovlen > 0 && iovlen <= UIO_MAXIOV {
        s.iov = super::io::iovecs(ctx, s.u64(16), iovlen)
            .ok()
            .map(|(v, _)| v);
    }
    s
}

/// The host's copy of a slot's header, its scatter-gather list one
/// buffer of `data`, or [`FAULT`] where the guest's could not be read.
fn host_msg(s: &mut Slot, name: Option<usize>, control: Option<usize>) -> HostMsg {
    let iovlen = s.u32(24) as i32;
    let (iov, iovlen) = match (&s.raw, &s.iov) {
        (None, _) => (FAULT, 1),
        (Some(_), Some(_)) => {
            s.host_iov = libc::iovec {
                iov_base: s.data.as_mut_ptr().cast(),
                iov_len: s.data.len(),
            };
            (&raw mut s.host_iov as usize, 1)
        }
        // A bad count is the host's to refuse; an unreadable list faults.
        (Some(_), None) if iovlen <= 0 || iovlen > UIO_MAXIOV => (FAULT, iovlen),
        (Some(_), None) => (FAULT, iovlen),
    };
    HostMsg {
        name: name.unwrap_or(0),
        namelen: if name.is_some() {
            s.name.len() as u32
        } else {
            0
        },
        iov,
        iovlen,
        control: control.unwrap_or(0),
        controllen: if control.is_some() {
            s.ctl.len() as u32
        } else {
            0
        },
        flags: 0,
        datalen: 0,
    }
}

/// `recvmsg_x(s, msgp, cnt, flags)`: after the count (`EINVAL` for 0 or
/// more than `UIO_MAXIOV`) and flags (`EINVAL` beyond `MSG_DONTWAIT` and
/// `MSG_NBIO`) checks, up to `cnt` messages; for each, the data (cut to
/// the message's buffers), the sender's address, and control data, with
/// the header written back (`msg_datalen` the bytes received). A
/// blocking socket sleeps for the first message within `SO_RCVTIMEO`.
pub fn recvmsg_x(ctx: &mut Ctx<'_>, fd: i32, msgp: u64, cnt: u32, flags: i32) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    let array = host_int(h, SO_DONTTRUNC) != 0;
    if !array {
        if cnt == 0 || cnt > UIO_MAXIOV as u32 {
            return Err(Errno::EINVAL);
        }
        if flags & !(msg::DONTWAIT | msg::NBIO) != 0 {
            return Err(Errno::EINVAL);
        }
    }
    let cnt = cnt.min(max_recvmsgx());
    let mut slots: Vec<Slot> = (0..cnt).map(|i| slot(ctx, msgp, i)).collect();
    let mut hosts = Vec::with_capacity(slots.len());
    for s in &mut slots {
        let total: u64 = s.iov.as_ref().map_or(0, |v| v.iter().map(|x| x.1).sum());
        s.data = vec![0u8; total.min(DATA_MAX) as usize];
        let name = (s.u64(0) != 0 && s.u32(8) != 0).then(|| {
            s.name = vec![0u8; 256];
            s.name.as_mut_ptr() as usize
        });
        // Control data always has room, so that the descriptors it
        // carries are installed even for a message without a buffer.
        s.ctl = vec![0u8; CONTROL_MAX];
        let control = Some(s.ctl.as_mut_ptr() as usize);
        hosts.push(host_msg(s, name, control));
    }
    let added = if blocking(h) && flags & (msg::DONTWAIT | msg::NBIO) == 0 {
        msg::NBIO
    } else {
        0
    };
    // SAFETY: every pointer in `hosts` is a live buffer of the size its
    // header states, or FAULT.
    let r = host_result(unsafe {
        sys::recvmsg_x(h, hosts.as_mut_ptr(), hosts.len() as u32, flags | added)
    });
    let n = match r {
        Ok(n) => n,
        Err(Errno::EAGAIN) if added != 0 => {
            if timed_out(ctx) {
                return Err(Errno::EAGAIN);
            }
            return park(
                ctx,
                h,
                Block {
                    read: true,
                    timeo: so::RCVTIMEO,
                    done: 0,
                    moved: false,
                    restart: true,
                },
            );
        }
        Err(e) => return Err(e),
    };
    for (i, (s, hm)) in slots.iter_mut().zip(&hosts).enumerate().take(n) {
        let mut raw = s.raw.ok_or(Errno::EFAULT)?;
        let iov = s.iov.as_ref().ok_or(Errno::EFAULT)?;
        let len = hm.datalen.min(s.data.len());
        let mut at = 0usize;
        for &(base, seg) in iov {
            if at >= len {
                break;
            }
            let k = (seg as usize).min(len - at);
            ctx.write(base, &s.data[at..at + k])?;
            at += k;
        }
        let mut out_flags = 0;
        if s.u64(0) != 0 && s.u32(8) != 0 {
            let sa = &s.name[..(hm.namelen as usize).min(256)];
            if let Some(l) = copyout_sa(ctx, s.u64(0), s.u32(8), sa) {
                raw[8..12].copy_from_slice(&l.to_le_bytes());
            }
        }
        let (caddr, clen) = (s.u64(32), s.u32(40));
        let ctl = &mut s.ctl[..(hm.controllen as usize).min(CONTROL_MAX)];
        control::externalize(ctx, ctl)?;
        if caddr != 0 && clen != 0 {
            let (copied, trunc) = control::copyout(ctx, caddr, clen, ctl)?;
            raw[40..44].copy_from_slice(&copied.to_le_bytes());
            out_flags |= trunc;
        }
        raw[44..48].copy_from_slice(&out_flags.to_le_bytes());
        raw[48..56].copy_from_slice(&(len as u64).to_le_bytes());
        ctx.write(msgp + (i * MSGHDR_X) as u64, &raw)?;
    }
    Ok(Rv::one(n as u64))
}

/// `sendmsg_x(s, msgp, cnt, flags)`: `MSG_SKIPCFIL` (`EPERM`) before the
/// descriptor, then the host's send of the messages (each with its
/// address and control data). A blocking socket waits for room within
/// `SO_SNDTIMEO`, going on from the first message not yet sent.
pub fn sendmsg_x(ctx: &mut Ctx<'_>, fd: i32, msgp: u64, cnt: u32, flags: i32) -> SysResult {
    if flags & msg::SKIPCFIL != 0 {
        return Err(Errno::EPERM);
    }
    let (_, h) = sock(ctx, fd)?;
    let done = moved_before(ctx) as u32;
    let local = super::io::is_local(h);
    let mut keep: Vec<Option<OwnedFd>> = Vec::new();
    let mut slots: Vec<Slot> = (done..cnt).map(|i| slot(ctx, msgp, i)).collect();
    let mut hosts = Vec::with_capacity(slots.len());
    for s in &mut slots {
        if let Some(v) = &s.iov {
            let total: u64 = v.iter().map(|x| x.1).sum();
            match super::io::gather(ctx, v, 0, total.min(DATA_MAX) as usize) {
                Ok(d) => s.data = d,
                Err(_) => s.iov = None,
            }
        }
        let name = match (s.u64(0), s.u32(8)) {
            (0, _) => None,
            // Longer than any address: the host refuses it by length.
            (_, l) if l > 255 => Some(FAULT),
            (a, l) => Some(match ctx.read(a, l as usize) {
                Ok(b) => {
                    s.name = b;
                    s.name.as_ptr() as usize
                }
                Err(_) => FAULT,
            }),
        };
        let control = match (s.u64(32), s.u32(40)) {
            (0, _) => None,
            (a, l) => Some(match ctx.read(a, (l as usize).min(CONTROL_MAX)) {
                Ok(mut b) => {
                    let mut k = None;
                    if local {
                        control::internalize(ctx, &mut b, &mut k);
                    }
                    keep.push(k);
                    s.ctl = b;
                    s.ctl.as_ptr() as usize
                }
                Err(_) => FAULT,
            }),
        };
        let mut hm = host_msg(s, name, control);
        // The lengths are the guest's.
        hm.namelen = s.u32(8);
        hm.controllen = s.u32(40);
        hosts.push(hm);
    }
    let block = blocking(h) && flags & msg::NBIO == 0;
    let host_flags = flags | if block { msg::NBIO } else { 0 };
    // SAFETY: every pointer in `hosts` is a live buffer of the size its
    // header states, or FAULT.
    let r =
        host_result(unsafe { sys::sendmsg_x(h, hosts.as_ptr(), hosts.len() as u32, host_flags) });
    drop(keep);
    let r = match r {
        Ok(n) => Ok(Rv::one(u64::from(done) + n as u64)),
        Err(Errno::EAGAIN) if block => {
            if timed_out(ctx) {
                return if done > 0 {
                    Ok(Rv::one(u64::from(done)))
                } else {
                    Err(Errno::EAGAIN)
                };
            }
            return park(
                ctx,
                h,
                Block {
                    read: false,
                    timeo: so::SNDTIMEO,
                    done: u64::from(done),
                    moved: false,
                    restart: true,
                },
            );
        }
        Err(e) if done > 0 => {
            let _ = e;
            Ok(Rv::one(u64::from(done)))
        }
        Err(e) => Err(e),
    };
    sigpipe(ctx, h, &r, flags);
    r
}

/// `SO_DONTTRUNC`.
const SO_DONTTRUNC: i32 = 0x2000;

/// An `int` socket option of the host socket (0 when unreadable).
fn host_int(h: RawFd, opt: i32) -> i32 {
    super::host_int_opt(h, opt).unwrap_or(0)
}

/// `kern.ipc.maxrecvmsgx`: the most messages one `recvmsg_x` takes (at
/// least 1).
fn max_recvmsgx() -> u32 {
    let mut v: u32 = 0;
    let mut len = 4usize;
    // SAFETY: the name is NUL-terminated; `v` holds the `len` bytes
    // offered.
    let r = unsafe {
        libc::sysctlbyname(
            c"kern.ipc.maxrecvmsgx".as_ptr(),
            (&raw mut v).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r == 0 { v.max(1) } else { 256 }
}
