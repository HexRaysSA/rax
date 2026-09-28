//! `io_uring_register` (`io_uring/register.c`, `io_uring/tctx.c`,
//! `io_uring/eventfd.c`, Linux 6.19); the registered files and buffers are
//! in [`rsrc`](super::rsrc). The operations not modelled yet are refused
//! with `EINVAL`, as an unknown one is.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::anon::Anon;
use super::super::super::fs::fd::FileObject;
use super::super::super::uring::abi::{RINGFD_REG_MAX, op};
use super::super::super::uring::{EventFd, Personality, Ring};
use super::super::{Ctx, SysResult};
use super::rsrc::{self, Kind};
use super::{ops, ring_file};
use std::sync::Arc;

/// `IORING_REGISTER_*` (the ones modelled) and `IORING_REGISTER_LAST`.
mod reg {
    pub const REGISTER_BUFFERS: u32 = 0;
    pub const UNREGISTER_BUFFERS: u32 = 1;
    pub const REGISTER_FILES: u32 = 2;
    pub const UNREGISTER_FILES: u32 = 3;
    pub const REGISTER_EVENTFD: u32 = 4;
    pub const UNREGISTER_EVENTFD: u32 = 5;
    pub const REGISTER_FILES_UPDATE: u32 = 6;
    pub const REGISTER_EVENTFD_ASYNC: u32 = 7;
    pub const REGISTER_PROBE: u32 = 8;
    pub const REGISTER_PERSONALITY: u32 = 9;
    pub const UNREGISTER_PERSONALITY: u32 = 10;
    pub const REGISTER_ENABLE_RINGS: u32 = 12;
    pub const REGISTER_FILES2: u32 = 13;
    pub const REGISTER_FILES_UPDATE2: u32 = 14;
    pub const REGISTER_BUFFERS2: u32 = 15;
    pub const REGISTER_BUFFERS_UPDATE: u32 = 16;
    pub const REGISTER_RING_FDS: u32 = 20;
    pub const UNREGISTER_RING_FDS: u32 = 21;
    pub const REGISTER_PBUF_RING: u32 = 22;
    pub const UNREGISTER_PBUF_RING: u32 = 23;
    pub const REGISTER_SYNC_CANCEL: u32 = 24;
    pub const REGISTER_PBUF_STATUS: u32 = 26;
    pub const REGISTER_FILE_ALLOC_RANGE: u32 = 25;
    pub const REGISTER_CLONE_BUFFERS: u32 = 30;
    pub const LAST: u32 = 37;
    /// `IORING_REGISTER_USE_REGISTERED_RING`.
    pub const USE_REGISTERED_RING: u32 = 1 << 31;
}

/// `sizeof(struct io_uring_probe)` and of each `struct io_uring_probe_op`.
const PROBE_HEADER: usize = 16;
const PROBE_OP: usize = 8;
/// `IO_URING_OP_SUPPORTED`.
const OP_SUPPORTED: u16 = 1;
/// `sizeof(struct io_uring_rsrc_update)`.
const RSRC_UPDATE: u64 = 16;

/// `io_uring_register_get_file`: a ring by descriptor, or by the caller's
/// registered index (`EINVAL` past them); `EBADF` if there is none,
/// `EOPNOTSUPP` if the file is no ring.
pub(super) fn get_ring(c: &Ctx<'_>, fd: u32, registered: bool) -> Result<Arc<Ring>, Errno> {
    if registered {
        if fd >= RINGFD_REG_MAX {
            return Err(Errno(EINVAL));
        }
        return c
            .t
            .uring_rings
            .get(fd as usize)
            .cloned()
            .flatten()
            .ok_or(Errno(EBADF));
    }
    super::ring_of(c, fd as i32)
}

/// `io_uring_register`: the ring by descriptor or registered index; with
/// descriptor -1 the operations that need no ring (none modelled). A
/// single-issuer ring takes registrations from its submitter only. What
/// the operation released is dropped once the ring's lock is let go.
pub fn io_uring_register(
    c: &mut Ctx<'_>,
    fd: u32,
    opcode: u32,
    arg: u64,
    nr_args: u32,
) -> SysResult {
    let registered = opcode & reg::USE_REGISTERED_RING != 0;
    let opcode = opcode & !reg::USE_REGISTERED_RING;
    if opcode >= reg::LAST {
        return Err(Errno(EINVAL));
    }
    if fd == u32::MAX {
        return Err(Errno(EINVAL));
    }
    let ring = get_ring(c, fd, registered)?;
    let r = register(c, &ring, opcode, arg, nr_args);
    ring.reap();
    r
}

/// `__io_uring_register`.
fn register(c: &mut Ctx<'_>, ring: &Arc<Ring>, opcode: u32, arg: u64, nr_args: u32) -> SysResult {
    if ring.state().submitter.is_some_and(|t| t != c.t.tid) {
        return Err(Errno(EEXIST));
    }
    if opcode == reg::REGISTER_CLONE_BUFFERS {
        return clone_buffers(c, ring, arg, nr_args);
    }
    let ring = &**ring;
    match opcode {
        reg::REGISTER_BUFFERS => {
            if arg == 0 {
                return Err(Errno(EFAULT));
            }
            rsrc::buffers_register(c, ring, &mut ring.state(), arg, nr_args, 0)
        }
        reg::UNREGISTER_BUFFERS => {
            if arg != 0 || nr_args != 0 {
                return Err(Errno(EINVAL));
            }
            rsrc::buffers_unregister(ring, &mut ring.state())
        }
        reg::REGISTER_FILES => {
            if arg == 0 {
                return Err(Errno(EFAULT));
            }
            rsrc::files_register(c, ring, &mut ring.state(), arg, nr_args, 0)
        }
        reg::UNREGISTER_FILES => {
            if arg != 0 || nr_args != 0 {
                return Err(Errno(EINVAL));
            }
            rsrc::files_unregister(ring, &mut ring.state())
        }
        reg::REGISTER_FILES_UPDATE => {
            rsrc::register_files_update(c, ring, &mut ring.state(), arg, nr_args)
        }
        reg::REGISTER_FILES2 => {
            rsrc::register_rsrc(c, ring, &mut ring.state(), arg, nr_args, Kind::File)
        }
        reg::REGISTER_FILES_UPDATE2 => {
            rsrc::register_rsrc_update(c, ring, &mut ring.state(), arg, nr_args, Kind::File)
        }
        reg::REGISTER_BUFFERS2 => {
            rsrc::register_rsrc(c, ring, &mut ring.state(), arg, nr_args, Kind::Buffer)
        }
        reg::REGISTER_BUFFERS_UPDATE => {
            rsrc::register_rsrc_update(c, ring, &mut ring.state(), arg, nr_args, Kind::Buffer)
        }
        reg::REGISTER_FILE_ALLOC_RANGE => {
            if arg == 0 || nr_args != 0 {
                return Err(Errno(EINVAL));
            }
            rsrc::file_alloc_range(c, &mut ring.state(), arg)
        }
        reg::REGISTER_EVENTFD | reg::REGISTER_EVENTFD_ASYNC => {
            if nr_args != 1 {
                return Err(Errno(EINVAL));
            }
            eventfd_register(c, ring, arg, opcode == reg::REGISTER_EVENTFD_ASYNC)
        }
        reg::UNREGISTER_EVENTFD => {
            if arg != 0 || nr_args != 0 {
                return Err(Errno(EINVAL));
            }
            // io_eventfd_unregister: ENXIO without one.
            match ring.state().eventfd.take() {
                Some(_) => Ok(0),
                None => Err(Errno(ENXIO)),
            }
        }
        reg::REGISTER_PROBE => {
            if arg == 0 || nr_args > 256 {
                return Err(Errno(EINVAL));
            }
            probe(c, arg, nr_args)
        }
        reg::REGISTER_PERSONALITY => {
            if arg != 0 || nr_args != 0 {
                return Err(Errno(EINVAL));
            }
            register_personality(c, ring)
        }
        reg::UNREGISTER_PERSONALITY => {
            if arg != 0 {
                return Err(Errno(EINVAL));
            }
            let id = u16::try_from(nr_args).map_err(|_| Errno(EINVAL))?;
            match ring.state().personalities.remove(&id) {
                Some(_) => Ok(0),
                None => Err(Errno(EINVAL)),
            }
        }
        reg::REGISTER_ENABLE_RINGS => {
            if arg != 0 || nr_args != 0 {
                return Err(Errno(EINVAL));
            }
            enable_rings(c, ring)
        }
        reg::REGISTER_PBUF_RING | reg::UNREGISTER_PBUF_RING | reg::REGISTER_PBUF_STATUS => {
            if arg == 0 || nr_args != 1 {
                return Err(Errno(EINVAL));
            }
            match opcode {
                reg::REGISTER_PBUF_RING => super::kbuf::register_ring(c, ring, arg),
                reg::UNREGISTER_PBUF_RING => super::kbuf::unregister_ring(c, ring, arg),
                _ => super::kbuf::status(c, ring, arg),
            }
        }
        reg::REGISTER_SYNC_CANCEL => {
            if arg == 0 || nr_args != 1 {
                return Err(Errno(EINVAL));
            }
            super::cancel::sync_cancel(c, ring, arg)
        }
        reg::REGISTER_RING_FDS => ringfd_register(c, arg, nr_args),
        reg::UNREGISTER_RING_FDS => ringfd_unregister(c, arg, nr_args),
        _ => Err(Errno(EINVAL)),
    }
}

/// `IORING_REGISTER_CLONE_BUFFERS`, which names a second ring.
fn clone_buffers(c: &Ctx<'_>, ring: &Arc<Ring>, arg: u64, nr_args: u32) -> SysResult {
    if arg == 0 || nr_args != 1 {
        return Err(Errno(EINVAL));
    }
    rsrc::clone_buffers(c, ring, arg)
}

/// `io_eventfd_register`: one eventfd at a time (`EBUSY`), read from `arg`
/// as an `int`; it counts from the current tail on.
fn eventfd_register(c: &mut Ctx<'_>, ring: &Ring, arg: u64, async_only: bool) -> SysResult {
    let mut st = ring.state();
    if st.eventfd.is_some() {
        return Err(Errno(EBUSY));
    }
    let fd = c.read_u32(arg)? as i32;
    // eventfd_ctx_fdget: EBADF, or EINVAL if it is no eventfd.
    let file = ops::fget(c, fd)?;
    if !matches!(&file.object, FileObject::Anon(Anon::Event(_))) {
        return Err(Errno(EINVAL));
    }
    st.eventfd_tail = st.cached_cq_tail;
    st.eventfd = Some(EventFd { file, async_only });
    Ok(0)
}

/// `io_probe`: the caller's zeroed `struct io_uring_probe` of `nr_args`
/// operations (at most `IORING_OP_LAST`) gets the last opcode, the count,
/// and each operation's number and whether it is supported (here: modelled).
fn probe(c: &mut Ctx<'_>, arg: u64, nr_args: u32) -> SysResult {
    let n = nr_args.min(u32::from(op::LAST)) as usize;
    let size = PROBE_HEADER + PROBE_OP * n;
    let mut p = c.read_mem(arg, size)?;
    if p.iter().any(|&b| b != 0) {
        return Err(Errno(EINVAL));
    }
    p[0] = op::LAST - 1;
    p[1] = n as u8;
    for i in 0..n {
        let at = PROBE_HEADER + PROBE_OP * i;
        p[at] = i as u8;
        if ops::supported(i as u8) {
            p[at + 2..at + 4].copy_from_slice(&OP_SUPPORTED.to_le_bytes());
        }
    }
    c.write_mem(arg, &p)?;
    Ok(0)
}

/// `io_register_personality`: the caller's credentials under the next
/// free identifier from 1 up, wrapping (`xa_alloc_cyclic`,
/// `XA_FLAGS_ALLOC1`).
fn register_personality(c: &mut Ctx<'_>, ring: &Ring) -> SysResult {
    let mut st = ring.state();
    let start = st.next_personality.max(1);
    let id = (start..=u16::MAX)
        .chain(1..start)
        .find(|id| !st.personalities.contains_key(id))
        .ok_or(Errno(EBUSY))?;
    st.next_personality = id.wrapping_add(1);
    st.personalities.insert(
        id,
        Personality {
            creds: c.p.creds,
            groups: c.p.groups.clone(),
        },
    );
    Ok(u64::from(id))
}

/// `io_register_enable_rings`: only a disabled ring (`EBADFD`); a
/// single-issuer ring's submitter becomes the caller.
fn enable_rings(c: &mut Ctx<'_>, ring: &Ring) -> SysResult {
    let mut st = ring.state();
    if !st.disabled {
        return Err(Errno(EBADFD));
    }
    if ring.flags & super::super::super::uring::abi::setup::SINGLE_ISSUER != 0
        && st.submitter.is_none()
    {
        st.submitter = Some(c.t.tid);
    }
    st.disabled = false;
    Ok(0)
}

/// `io_ringfd_register`: `nr_args` `struct io_uring_rsrc_update`s, each a
/// ring descriptor (`data`) for a slot (`offset`, or -1 for the first free
/// one) of the caller's registered rings, the slot written back; the
/// number registered, or the first error if none was.
fn ringfd_register(c: &mut Ctx<'_>, arg: u64, nr_args: u32) -> SysResult {
    if nr_args == 0 || nr_args > RINGFD_REG_MAX {
        return Err(Errno(EINVAL));
    }
    let max = RINGFD_REG_MAX as usize;
    if c.t.uring_rings.len() < max {
        c.t.uring_rings.resize(max, None);
    }
    let mut done = 0u32;
    let mut err = Errno(0);
    for i in 0..nr_args {
        let at = arg + RSRC_UPDATE * u64::from(i);
        let b = match c.read_mem(at, RSRC_UPDATE as usize) {
            Ok(b) => b,
            Err(e) => {
                err = e;
                break;
            }
        };
        let offset = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let resv = u32::from_le_bytes(b[4..8].try_into().unwrap());
        let data = u64::from_le_bytes(b[8..16].try_into().unwrap());
        if resv != 0 {
            err = Errno(EINVAL);
            break;
        }
        let (start, end) = if offset == u32::MAX {
            (0, max)
        } else if offset >= RINGFD_REG_MAX {
            err = Errno(EINVAL);
            break;
        } else {
            (offset as usize, offset as usize + 1)
        };
        // io_ring_add_registered_fd.
        let ring = match ops::fget(c, data as i32) {
            Err(e) => Err(e),
            Ok(f) => ring_file(&f).ok_or(Errno(EOPNOTSUPP)),
        };
        let ring = match ring {
            Ok(r) => r,
            Err(e) => {
                err = e;
                break;
            }
        };
        let Some(slot) = (start..end).find(|&s| c.t.uring_rings[s].is_none()) else {
            err = Errno(EBUSY);
            break;
        };
        c.t.uring_rings[slot] = Some(ring);
        if c.write_u32(at, slot as u32).is_err() {
            c.t.uring_rings[slot] = None;
            err = Errno(EFAULT);
            break;
        }
        done += 1;
    }
    if done != 0 {
        Ok(u64::from(done))
    } else {
        Err(err)
    }
}

/// `io_ringfd_unregister`: empties the slots named (`data` and `resv`
/// zero); the number processed, or the first error if none was.
fn ringfd_unregister(c: &mut Ctx<'_>, arg: u64, nr_args: u32) -> SysResult {
    if nr_args == 0 || nr_args > RINGFD_REG_MAX {
        return Err(Errno(EINVAL));
    }
    let mut done = 0u32;
    let mut err = Errno(0);
    for i in 0..nr_args {
        let b = match c.read_mem(arg + RSRC_UPDATE * u64::from(i), RSRC_UPDATE as usize) {
            Ok(b) => b,
            Err(e) => {
                err = e;
                break;
            }
        };
        let offset = u32::from_le_bytes(b[0..4].try_into().unwrap());
        if b[4..16].iter().any(|&x| x != 0) || offset >= RINGFD_REG_MAX {
            err = Errno(EINVAL);
            break;
        }
        if let Some(slot) = c.t.uring_rings.get_mut(offset as usize) {
            *slot = None;
        }
        done += 1;
    }
    if done != 0 {
        Ok(u64::from(done))
    } else {
        Err(err)
    }
}
