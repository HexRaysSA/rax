//! Provided buffers (`io_uring/kbuf.c`, Linux 6.19):
//! `IORING_OP_PROVIDE_BUFFERS` and `IORING_OP_REMOVE_BUFFERS`, buffer rings
//! (`IORING_REGISTER_PBUF_RING`, `_UNREGISTER_PBUF_RING`,
//! `_REGISTER_PBUF_STATUS`, and their mappings), and the selection of a
//! buffer by a request with `IOSQE_BUFFER_SELECT`.
//!
//! A request selects the first buffer of its group (`buf_group`, in
//! `buf_index`): a provided one, which it then holds, or the one at its
//! ring's head. A ring's head moves on as the request completes, or at
//! once where nothing could hand the buffer back (in an async worker, or
//! for a file without a wait queue); consumed in part (`IOU_PBUF_RING_INC`)
//! a buffer stays at the head, moved on and shortened. The completion
//! reports the buffer (`IORING_CQE_F_BUFFER` and its ID). A request that
//! waits hands back a ring's buffer it has not taken; a provided one a read
//! or send keeps, a receive hands back.
//!
//! A ring in the process's memory is its address range (Linux pins its
//! pages as it is registered).

use std::collections::VecDeque;
use std::sync::Arc;

use super::super::super::abi::PAGE_SIZE;
use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::uring::abi::{cqe_flags, op};
use super::super::super::uring::{Buf, BufList, BufRing, Kbuf, Req, Ring, State, req_flags as rf};
use super::super::events;
use super::super::io::MAX_RW_COUNT;
use super::super::{Ctx, SysResult};
use super::{memlock_pages, rsrc};
use crate::user::mm::SharedObject;

/// `MAX_BIDS_PER_BGID`: buffer IDs are 16 bits.
const MAX_BIDS: u64 = 1 << 16;
/// `IOU_PBUF_RING_MMAP`, `IOU_PBUF_RING_INC`.
const RING_MMAP: u16 = 1;
const RING_INC: u16 = 2;
/// `IORING_CQE_BUFFER_SHIFT`.
const BUFFER_SHIFT: u32 = 16;
/// `sizeof(struct io_uring_buf)`; the ring's tail is the first entry's
/// `resv` (`struct io_uring_buf_ring`).
const BUF_SIZE: u64 = 16;
const TAIL: u64 = 14;
/// `sizeof(struct io_uring_buf_reg)`, `sizeof(struct io_uring_buf_status)`.
const BUF_REG: usize = 40;
const BUF_STATUS: usize = 40;

/// `io_provide_buffers_prep` and `io_remove_buffers_prep`: the count from
/// `fd` (1 to 65536: `E2BIG`, for a removal `EINVAL`); a provision's
/// address and length (none: `EINVAL`), their product and end not wrapping
/// (`EOVERFLOW`) and user memory (`EFAULT`), and its first ID from `off`
/// (past 65535: `E2BIG`; its IDs past 65535: `EINVAL`); the group from
/// `buf_index`.
pub(super) fn prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    // The count is the sign-extended descriptor field.
    let n = i64::from(sqe.fd) as u64;
    if sqe.opcode == op::REMOVE_BUFFERS {
        if sqe.op_flags != 0 || sqe.addr != 0 || sqe.len != 0 || sqe.off != 0 || sqe.file_index != 0
        {
            return Err(Errno(EINVAL));
        }
        if n == 0 || n > MAX_BIDS {
            return Err(Errno(EINVAL));
        }
        req.how = [n, 0, 0, 0];
        return Ok(());
    }
    if sqe.op_flags != 0 || sqe.file_index != 0 {
        return Err(Errno(EINVAL));
    }
    if n == 0 || n > MAX_BIDS {
        return Err(Errno(E2BIG));
    }
    let len = u64::from(sqe.len);
    if len == 0 {
        return Err(Errno(EINVAL));
    }
    let size = len.checked_mul(n).ok_or(Errno(EOVERFLOW))?;
    sqe.addr.checked_add(size).ok_or(Errno(EOVERFLOW))?;
    if !events::access_ok(c, sqe.addr, size) {
        return Err(Errno(EFAULT));
    }
    if sqe.off > 0xffff {
        return Err(Errno(E2BIG));
    }
    if sqe.off + n > MAX_BIDS {
        return Err(Errno(EINVAL));
    }
    req.how = [n, sqe.addr, len, sqe.off];
    Ok(())
}

/// `io_manage_buffers_legacy`: the group (a provision makes it; a removal
/// finds none: `ENOENT`), not a ring (`EINVAL`); a provision adds its
/// buffers (at most 65535 in a group: `EOVERFLOW` for none added), a
/// removal takes up to its count from the front, and reports how many.
pub(super) fn issue(st: &mut State, req: &mut Req) {
    let bgid = req.sqe.buf_index;
    let [n, addr, len, bid] = req.how;
    let provide = req.sqe.opcode == op::PROVIDE_BUFFERS;
    let r = (|| {
        let list = match st.bufs.get_mut(&bgid) {
            Some(l) => l,
            None if provide => st
                .bufs
                .entry(bgid)
                .or_insert(BufList::Legacy(VecDeque::new())),
            None => return Err(Errno(ENOENT)),
        };
        let BufList::Legacy(bufs) = list else {
            return Err(Errno(EINVAL));
        };
        if !provide {
            let k = (n as usize).min(bufs.len());
            bufs.drain(..k);
            return Ok(k as i32);
        }
        let mut at = addr;
        for i in 0..n {
            if bufs.len() == 0xffff {
                return if i == 0 { Err(Errno(EOVERFLOW)) } else { Ok(0) };
            }
            bufs.push_back(Buf {
                addr: at,
                len: len.min(MAX_RW_COUNT) as u32,
                bid: (bid + i) as u16,
            });
            at = at.wrapping_add(len);
        }
        Ok(0)
    })();
    match r {
        Ok(v) => {
            req.res = v;
            req.cflags = 0;
        }
        Err(Errno(e)) => req.fail(-e),
    }
}

/// A ring's bytes at `off`: its region, or the process's memory.
fn ring_read(c: &Ctx<'_>, r: &BufRing, off: u64, buf: &mut [u8]) {
    match &r.object {
        Some(o) => {
            let _ = o.read_at(off, buf);
        }
        None => {
            let _ = c.p.space.read_raw(r.addr + off, buf);
        }
    }
}

fn ring_write(c: &Ctx<'_>, r: &BufRing, off: u64, data: &[u8]) {
    match &r.object {
        Some(o) => {
            let _ = o.write_all_at(off, data);
        }
        None => {
            let _ = c.p.space.write_raw(r.addr + off, data);
        }
    }
}

/// A ring entry (`struct io_uring_buf`): address, length, and ID.
fn entry(c: &Ctx<'_>, r: &BufRing, index: u16) -> (u64, u32, u16) {
    let mut b = [0u8; 16];
    let at = u64::from(index & (r.entries - 1) as u16) * BUF_SIZE;
    ring_read(c, r, at, &mut b);
    (
        u64::from_le_bytes(b[..8].try_into().unwrap()),
        u32::from_le_bytes(b[8..12].try_into().unwrap()),
        u16::from_le_bytes(b[12..14].try_into().unwrap()),
    )
}

fn tail(c: &Ctx<'_>, r: &BufRing) -> u16 {
    let mut b = [0u8; 2];
    ring_read(c, r, TAIL, &mut b);
    u16::from_le_bytes(b)
}

/// `io_buffer_select`: the group's first buffer, its length at most the
/// request's (0: the whole buffer); `None` without one. A provided buffer
/// is the request's now; a ring's is committed at once with `now` (an
/// async worker, a file without a wait queue: `io_should_commit`), and
/// otherwise as the request completes.
pub(super) fn select(
    c: &Ctx<'_>,
    st: &mut State,
    req: &mut Req,
    len: &mut u64,
    bgid: u16,
    now: bool,
) -> Option<u64> {
    let list = st.bufs.get_mut(&bgid)?;
    match list {
        BufList::Legacy(bufs) => {
            let buf = bufs.pop_front()?;
            if *len == 0 || *len > u64::from(buf.len) {
                *len = u64::from(buf.len);
            }
            if bufs.is_empty() {
                req.flags |= rf::BL_EMPTY;
            }
            req.kbuf = Some(Kbuf::Legacy { bgid, buf });
            Some(buf.addr)
        }
        BufList::Ring(r) => {
            let (head, tail) = (r.head, tail(c, r));
            if tail == head {
                return None;
            }
            if head.wrapping_add(1) == tail {
                req.flags |= rf::BL_EMPTY;
            }
            let (addr, blen, bid) = entry(c, r, head);
            if *len == 0 || *len > u64::from(blen) {
                *len = u64::from(blen);
            }
            req.kbuf = Some(Kbuf::Ring {
                bgid,
                bid,
                commit: true,
            });
            if now {
                commit(c, st, req, *len as i64, 1);
            }
            Some(addr)
        }
    }
}

/// `PEEK_MAX_IMPORT`, `UIO_MAXIOV`.
const PEEK_MAX: u64 = 256;
const UIO_MAXIOV: u16 = 1024;

/// `io_buffers_select` (`send`: a provided buffer whole, a ring's taken at
/// once and not handed back) and `io_buffers_peek` (a receive: a provided
/// buffer of at most `max_len`, a ring's taken as the request completes):
/// the group's first buffers, as vectors: one, or for a bundle (`expand`)
/// as many as the vector array of the request's message state holds, or
/// with a length as many as `max_len` bytes need, in an array of its own
/// (which the message state keeps); and whether the last was cut short
/// (`partial_map`). `ENOENT` without the group, `ENOBUFS` without a buffer.
pub(super) fn peek(
    c: &Ctx<'_>,
    st: &mut State,
    req: &mut Req,
    bgid: u16,
    max_len: u64,
    expand: bool,
    send: bool,
) -> Result<(Vec<(u64, u64)>, bool), Errno> {
    let list = st.bufs.get_mut(&bgid).ok_or(Errno(ENOENT))?;
    let r = match list {
        BufList::Legacy(bufs) => {
            // io_provided_buffers_select.
            let buf = bufs.pop_front().ok_or(Errno(ENOBUFS))?;
            let limit = if send { 0 } else { max_len };
            let len = if limit == 0 || limit > u64::from(buf.len) {
                u64::from(buf.len)
            } else {
                limit
            };
            if bufs.is_empty() {
                req.flags |= rf::BL_EMPTY;
            }
            req.kbuf = Some(Kbuf::Legacy { bgid, buf });
            return Ok((vec![(buf.addr, len)], false));
        }
        BufList::Ring(r) => r,
    };
    // io_ring_buffers_peek.
    let (mut head, tail) = (r.head, tail(c, r));
    let mut avail = u64::from(tail.wrapping_sub(head).min(UIO_MAXIOV));
    if avail == 0 {
        return Err(Errno(ENOBUFS));
    }
    let (_, first_len, first_bid) = entry(c, r, head);
    let mut nr = if expand {
        u64::from(req.net.vec_nr.max(1))
    } else {
        1
    };
    let mut grown = false;
    if max_len != 0 {
        if first_len == 0 {
            return Err(Errno(ENOBUFS));
        }
        let needed = max_len.div_ceil(u64::from(first_len)).min(PEEK_MAX);
        let needed = if needed == 0 { PEEK_MAX } else { needed };
        avail = avail.min(needed);
    }
    if expand && avail > nr && max_len != 0 {
        nr = avail;
        grown = true;
    } else if avail < nr {
        nr = avail;
    }
    let mut max = if max_len == 0 {
        i32::MAX as u64
    } else {
        max_len
    };
    let mut out = Vec::new();
    let mut partial = false;
    loop {
        let (addr, blen, _) = entry(c, r, head);
        let mut len = u64::from(blen);
        if len > max {
            len = max;
            if !r.inc {
                partial = true;
                if !out.is_empty() {
                    break;
                }
                let at = u64::from(head & (r.entries - 1) as u16) * BUF_SIZE;
                ring_write(c, r, at + 8, &(len as u32).to_le_bytes());
            }
        }
        out.push((addr, len));
        max -= len;
        if max == 0 {
            break;
        }
        head = head.wrapping_add(1);
        nr -= 1;
        if nr == 0 {
            break;
        }
    }
    if head == tail {
        req.flags |= rf::BL_EMPTY;
    }
    req.kbuf = Some(Kbuf::Ring {
        bgid,
        bid: first_bid,
        commit: true,
    });
    if send {
        req.flags |= rf::BL_NO_RECYCLE;
        let total: u64 = out.iter().map(|&(_, l)| l).sum();
        commit(c, st, req, total as i64, out.len() as u16);
    }
    if grown {
        req.net.vec_nr = out.len() as u32;
    }
    Ok((out, partial))
}

/// `io_kbuf_commit`: a ring buffer's taking, once: the head moves on by
/// `nr`, or for a ring consumed in part by the `len` bytes used (whether
/// the head buffer was used up: `IORING_CQE_F_BUF_MORE` otherwise).
pub(super) fn commit(c: &Ctx<'_>, st: &mut State, req: &mut Req, len: i64, nr: u16) -> bool {
    let Some(Kbuf::Ring {
        bgid,
        bid,
        commit: true,
    }) = req.kbuf
    else {
        return true;
    };
    req.kbuf = Some(Kbuf::Ring {
        bgid,
        bid,
        commit: false,
    });
    if len < 0 {
        return true;
    }
    let Some(BufList::Ring(r)) = st.bufs.get_mut(&bgid) else {
        return true;
    };
    if !r.inc {
        r.head = r.head.wrapping_add(nr);
        return true;
    }
    // io_kbuf_inc_commit.
    let mut len = len as u64;
    while len != 0 {
        let (addr, blen, _) = entry(c, r, r.head);
        let at = u64::from(r.head & (r.entries - 1) as u16) * BUF_SIZE;
        let this = len.min(u64::from(blen));
        let left = u64::from(blen) - this;
        if left != 0 || this == 0 {
            ring_write(c, r, at, &(addr + this).to_le_bytes());
            ring_write(c, r, at + 8, &(left as u32).to_le_bytes());
            return false;
        }
        ring_write(c, r, at + 8, &0u32.to_le_bytes());
        r.head = r.head.wrapping_add(1);
        len -= this;
    }
    true
}

/// `io_put_kbuf` as the request completes with `len`: the buffer reported
/// (`IORING_CQE_F_BUFFER` with its ID), a provided one consumed, a ring's
/// committed if it was not (`IORING_CQE_F_BUF_MORE` if its head buffer is
/// only part used).
pub(super) fn put(c: &Ctx<'_>, st: &mut State, req: &mut Req, len: i64, nr: u16) -> u32 {
    let Some(k) = req.kbuf else {
        return 0;
    };
    let bid = match k {
        Kbuf::Legacy { buf, .. } => buf.bid,
        Kbuf::Ring { bid, .. } => bid,
    };
    let mut flags = cqe_flags::BUFFER | u32::from(bid) << BUFFER_SHIFT;
    if matches!(k, Kbuf::Ring { .. }) && !commit(c, st, req, len, nr) {
        flags |= cqe_flags::BUF_MORE;
    }
    req.kbuf = None;
    flags
}

/// `io_kbuf_recycle` as the request waits or fails without data: a ring's
/// buffer not taken yet stays at its head for the next selection (one
/// taken already stays the request's); a provided one goes back to the
/// front of its group.
pub(super) fn recycle(st: &mut State, req: &mut Req) {
    if req.flags & rf::BL_NO_RECYCLE != 0 {
        return;
    }
    match req.kbuf {
        Some(Kbuf::Ring { commit: true, .. }) => req.kbuf = None,
        Some(Kbuf::Legacy { bgid, buf }) => {
            req.kbuf = None;
            if let Some(BufList::Legacy(bufs)) = st.bufs.get_mut(&bgid) {
                bufs.push_front(buf);
            }
        }
        _ => {}
    }
}

/// `io_read`'s hand-back (`REQ_F_BUFFERS_COMMIT`): only a ring's buffer
/// not taken yet; a provided one stays the request's, across a wait, and
/// is reported as it fails.
pub(super) fn recycle_ring(st: &mut State, req: &mut Req) {
    if matches!(req.kbuf, Some(Kbuf::Ring { commit: true, .. })) {
        recycle(st, req);
    }
}

/// `io_register_pbuf_ring`: the `struct io_uring_buf_reg` (`EFAULT`),
/// reserved words zero and known flags (`EINVAL`), a power-of-two count
/// below 65536 (`EINVAL`); no ring or provided buffers in the group already
/// (`EEXIST`; an empty group is replaced); the region (`io_create_region`:
/// the process's page-aligned memory, `EINVAL`, pinned, `EFAULT`, or
/// pages of its own to map), charged to the user (`ENOMEM`).
pub(super) fn register_ring(c: &Ctx<'_>, ring: &Ring, arg: u64) -> SysResult {
    let b = c.read_mem(arg, BUF_REG)?;
    let ring_addr = u64::from_le_bytes(b[..8].try_into().unwrap());
    let entries = u32::from_le_bytes(b[8..12].try_into().unwrap());
    let bgid = u16::from_le_bytes(b[12..14].try_into().unwrap());
    let flags = u16::from_le_bytes(b[14..16].try_into().unwrap());
    if b[16..40] != [0; 24] || flags & !(RING_MMAP | RING_INC) != 0 {
        return Err(Errno(EINVAL));
    }
    if !entries.is_power_of_two() || entries >= 65536 {
        return Err(Errno(EINVAL));
    }
    let mut st = ring.state();
    match st.bufs.get(&bgid) {
        Some(BufList::Ring(_)) => return Err(Errno(EEXIST)),
        Some(BufList::Legacy(l)) if !l.is_empty() => return Err(Errno(EEXIST)),
        Some(BufList::Legacy(_)) => {
            st.bufs.remove(&bgid);
        }
        None => {}
    }
    let size = (u64::from(entries) * BUF_SIZE).next_multiple_of(PAGE_SIZE);
    // io_create_region: a user region needs its address (EFAULT), page
    // aligned (EINVAL); a region of the ring's own takes none.
    let user = flags & RING_MMAP == 0;
    let ring_addr = if user { ring_addr } else { 0 };
    if user && ring_addr == 0 {
        return Err(Errno(EFAULT));
    }
    if ring_addr % PAGE_SIZE != 0 {
        return Err(Errno(EINVAL));
    }
    ring_addr.checked_add(size).ok_or(Errno(EOVERFLOW))?;
    let pages = size / PAGE_SIZE;
    ring.account.charge_user(pages, memlock_pages(c))?;
    let object = if user {
        if let Err(e) = rsrc::pin_pages(c, ring_addr, size) {
            ring.account.uncharge_user(pages);
            return Err(e);
        }
        None
    } else {
        match SharedObject::anonymous(size) {
            Ok(o) => Some(Arc::new(o)),
            Err(_) => {
                ring.account.uncharge_user(pages);
                return Err(Errno(ENOMEM));
            }
        }
    };
    st.bufs.insert(
        bgid,
        BufList::Ring(BufRing {
            object,
            addr: ring_addr,
            entries,
            head: 0,
            inc: flags & RING_INC != 0,
            pages,
        }),
    );
    Ok(0)
}

/// `io_unregister_pbuf_ring`: the `struct io_uring_buf_reg` (`EFAULT`),
/// reserved words and flags zero (`EINVAL`); the group's ring (`ENOENT`
/// without a group, `EINVAL` if it is no ring) goes, its pages uncharged.
pub(super) fn unregister_ring(c: &Ctx<'_>, ring: &Ring, arg: u64) -> SysResult {
    let b = c.read_mem(arg, BUF_REG)?;
    let bgid = u16::from_le_bytes(b[12..14].try_into().unwrap());
    if b[14..16] != [0; 2] || b[16..40] != [0; 24] {
        return Err(Errno(EINVAL));
    }
    let mut st = ring.state();
    match st.bufs.get(&bgid) {
        None => Err(Errno(ENOENT)),
        Some(BufList::Legacy(_)) => Err(Errno(EINVAL)),
        Some(BufList::Ring(r)) => {
            ring.account.uncharge_user(r.pages);
            st.bufs.remove(&bgid);
            Ok(0)
        }
    }
}

/// `io_register_pbuf_status`: the `struct io_uring_buf_status` (`EFAULT`),
/// reserved words zero (`EINVAL`), a ring's group (`ENOENT`, `EINVAL`);
/// its head written back.
pub(super) fn status(c: &Ctx<'_>, ring: &Ring, arg: u64) -> SysResult {
    let mut b = c.read_mem(arg, BUF_STATUS)?;
    if b[8..40] != [0; 32] {
        return Err(Errno(EINVAL));
    }
    let bgid = u32::from_le_bytes(b[..4].try_into().unwrap());
    let st = ring.state();
    let head = match u16::try_from(bgid).ok().and_then(|g| st.bufs.get(&g)) {
        None => return Err(Errno(ENOENT)),
        Some(BufList::Legacy(_)) => return Err(Errno(EINVAL)),
        Some(BufList::Ring(r)) => r.head,
    };
    drop(st);
    b[4..8].copy_from_slice(&u32::from(head).to_le_bytes());
    c.write_mem(arg, &b)?;
    Ok(0)
}

/// `io_pbuf_get_region` for a mapping: the group's ring region, if it has
/// one of its own (a ring in the process's memory maps nothing).
pub(super) fn region(ring: &Ring, bgid: u16) -> Option<Arc<SharedObject>> {
    match ring.state().bufs.get(&bgid) {
        Some(BufList::Ring(r)) => r.object.clone(),
        _ => None,
    }
}
