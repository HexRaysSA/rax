//! Sockets (`io_uring/net.c`, Linux 6.19): `IORING_OP_SEND`, `_RECV`,
//! `_SENDMSG`, `_RECVMSG`, `_ACCEPT` (one-shot and multishot, into a
//! descriptor or a registered slot), `_CONNECT`, `_SOCKET`, `_BIND`,
//! `_LISTEN`, and `_SHUTDOWN`.
//!
//! Preparation reads what `IORING_FEAT_SUBMIT_STABLE` promises: a send's
//! destination, a message header with its name (for a send) and vectors,
//! an address to connect or bind to. Every issue asks the socket not to
//! wait (`MSG_DONTWAIT`, `O_NONBLOCK`): a socket that cannot go on now
//! parks the request for its readiness (`io_arm_poll_handler`), unless it
//! may not wait (`MSG_DONTWAIT` of its own, `IORING_ACCEPT_DONTWAIT`:
//! `-EAGAIN`). `IORING_RECVSEND_POLL_FIRST` parks it before the first try.
//! A send or receive with `MSG_WAITALL` on a stream moves on by what it
//! moved and parks for the rest, counting it (`done_io`). A receive reports
//! `IORING_CQE_F_SOCK_NONEMPTY` when its socket says data is left
//! (`msg_inq`); an accept, when TCP says connections are. A multishot
//! accept posts each connection with `IORING_CQE_F_MORE` and waits for the
//! next.
//!
//! A send or receive with `IOSQE_BUFFER_SELECT` takes a provided buffer
//! ([`kbuf`](super::kbuf)); a bundle takes several. A multishot receive
//! goes on into buffer after buffer, posting each with
//! `IORING_CQE_F_MORE`, until the buffers, the socket, or its limit end
//! it.

use std::sync::Arc;

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::fd::OpenFile;
use super::super::super::net::lx;
use super::super::super::uring::abi::{cqe_flags, op};
use super::super::super::uring::{Req, Ring, State, req_flags as rf};
use super::super::super::wait::SockWait;
use super::super::Ctx;
use super::super::iov::import_iovec_as;
use super::super::net::io::{self as sockio, MsgHdr};
use super::super::net::{self as sock, read_addr, sock_of};
use super::super::ready::ev;
use super::ops::{Done, assign_file};
use super::rw::import_ubuf;
use super::{kbuf, poll, rsrc, submit};

/// `IORING_RECVSEND_*`, `IORING_SEND_VECTORIZED`.
const POLL_FIRST: u32 = 1 << 0;
const RECV_MULTISHOT: u32 = 1 << 1;
const BUNDLE: u32 = 1 << 4;
const SEND_VECTORIZED: u32 = 1 << 5;
/// `SENDMSG_FLAGS`, `RECVMSG_FLAGS`.
const SENDMSG_FLAGS: u32 = POLL_FIRST | BUNDLE | SEND_VECTORIZED;
const RECVMSG_FLAGS: u32 = POLL_FIRST | RECV_MULTISHOT | BUNDLE;
/// `IORING_ACCEPT_*`.
const ACCEPT_MULTISHOT: u32 = 1 << 0;
const ACCEPT_DONTWAIT: u32 = 1 << 1;
const ACCEPT_POLL_FIRST: u32 = 1 << 2;
/// `IORING_FILE_INDEX_ALLOC`.
const FILE_INDEX_ALLOC: u32 = u32::MAX;
/// `RLIMIT_NOFILE`.
const RLIMIT_NOFILE: usize = 7;

/// A receive's readiness, and a send's (with `EPOLLERR` and `EPOLLPRI`,
/// which the retry adds).
const POLL_IN: u32 = ev::IN | ev::RDNORM;
const POLL_OUT: u32 = ev::OUT | ev::WRNORM;

fn is_send(opcode: u8) -> bool {
    matches!(opcode, op::SEND | op::SENDMSG)
}

/// The kernel's own `IORING_RECV_*` flags, above the ones from `ioprio`.
const RECV_RETRY: u32 = 1 << 15;
const RECV_PARTIAL_MAP: u32 = 1 << 14;
const RECV_MSHOT_CAP: u32 = 1 << 13;
const RECV_MSHOT_LIM: u32 = 1 << 12;
const RECV_MSHOT_DONE: u32 = 1 << 11;
const RECV_RETRY_CLEAR: u32 = RECV_RETRY | RECV_PARTIAL_MAP;
const RECV_NO_RETRY: u32 = RECV_RETRY | RECV_PARTIAL_MAP | RECV_MSHOT_CAP | RECV_MSHOT_DONE;
/// `MULTISHOT_MAX_RETRY`.
const MULTISHOT_MAX_RETRY: u32 = 32;
/// `CQE_F_MASK`: a bundle's flags a retry inherits.
const CQE_F_MASK: u32 = cqe_flags::SOCK_NONEMPTY | cqe_flags::MORE;
/// `sizeof(struct io_uring_recvmsg_out)`.
const RECVMSG_OUT: u64 = 16;
/// `MSG_CMSG_COMPAT`, which a header's flags never show.
const MSG_CMSG_COMPAT: u32 = 0x8000_0000;
/// `IO_ALLOC_CACHE_MAX`, `IO_VEC_CACHE_SOFT_CAP`.
const ALLOC_CACHE_MAX: usize = 128;
const VEC_CACHE_SOFT_CAP: u32 = 256;

/// `io_msg_alloc_async`: the request's message state, the one the ring
/// cached last (with the vector array it kept) if any.
fn msg_alloc(st: &mut State, req: &mut Req) {
    req.net.msg = true;
    req.net.vec_nr = st.netmsg.pop().unwrap_or(0);
}

/// `io_req_msg_cleanup` (`io_netmsg_recycle`) as a request completes in
/// its issue: its message state back to the ring's cache while that has
/// room, keeping a vector array of at most 256 entries; an async worker's
/// is freed.
fn msg_recycle(st: &mut State, req: &mut Req) {
    if !std::mem::take(&mut req.net.msg) || st.in_worker {
        return;
    }
    if st.netmsg.len() < ALLOC_CACHE_MAX {
        let nr = if req.net.vec_nr > VEC_CACHE_SOFT_CAP {
            0
        } else {
            req.net.vec_nr
        };
        st.netmsg.push(nr);
    }
}

/// `io_net_import_vec`: more vectors than its array (or the one inline)
/// holds take an array of their own.
fn import_vec_nr(req: &mut Req, n: u64) {
    if n > u64::from(req.net.vec_nr.max(1)) {
        req.net.vec_nr = n as u32;
    }
}

/// `io_sendmsg_prep` and `io_recvmsg_prep`: the length, the flags from
/// `ioprio` (known ones: `EINVAL`), the message flags (`MSG_NOSIGNAL` added
/// to a send's; `MSG_DONTWAIT` meaning no waiting), a bundle (not a
/// message's; a send's waits for all of it); a receive's multishot needs a
/// provided buffer and no `MSG_WAITALL` (`EINVAL`), a multishot `RECV`
/// takes a limit on the whole from `optlen`, and nothing else takes one.
/// Then [`send_setup`], [`msg_setup`], or a receive's buffer.
pub(super) fn sr_prep(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    req: &mut Req,
) -> Result<(), Errno> {
    let sqe = req.sqe;
    let opcode = sqe.opcode;
    req.net.len = u64::from(sqe.len);
    req.net.flags = u32::from(sqe.ioprio);
    let send = is_send(opcode);
    if !send && sqe.off != 0 {
        // io_recvmsg_prep: no addr2.
        return Err(Errno(EINVAL));
    }
    let known = if send { SENDMSG_FLAGS } else { RECVMSG_FLAGS };
    if req.net.flags & !known != 0 {
        return Err(Errno(EINVAL));
    }
    req.net.msg_flags = sqe.op_flags | if send { lx::MSG_NOSIGNAL } else { 0 };
    if req.net.msg_flags & lx::MSG_DONTWAIT != 0 {
        req.flags |= rf::NOWAIT;
    }
    if send {
        if req.net.flags & BUNDLE != 0 {
            if opcode == op::SENDMSG {
                return Err(Errno(EINVAL));
            }
            req.net.msg_flags |= lx::MSG_WAITALL;
            req.flags |= rf::MULTISHOT;
        }
    } else {
        let optlen = sqe.file_index;
        if req.net.flags & RECV_MULTISHOT != 0 {
            if req.flags & rf::BUFFER_SELECT == 0 || req.net.msg_flags & lx::MSG_WAITALL != 0 {
                return Err(Errno(EINVAL));
            }
            if opcode == op::RECV {
                req.net.mshot_len = req.net.len;
                req.net.mshot_total = u64::from(optlen);
                if optlen != 0 {
                    req.net.flags |= RECV_MSHOT_LIM;
                }
            } else if optlen != 0 {
                return Err(Errno(EINVAL));
            }
            req.flags |= rf::APOLL_MULTISHOT;
        } else if optlen != 0 {
            return Err(Errno(EINVAL));
        }
        if req.net.flags & BUNDLE != 0 && opcode == op::RECVMSG {
            return Err(Errno(EINVAL));
        }
    }
    msg_alloc(st, req);
    match opcode {
        op::SEND => send_setup(c, ring, req),
        op::SENDMSG => {
            if sqe.off != 0 || sqe.file_index != 0 {
                return Err(Errno(EINVAL));
            }
            msg_setup(c, ring, req, true)
        }
        op::RECV => {
            // io_recvmsg_prep_setup: msg_inq 0, the buffer unless selected.
            req.net.inq = 0;
            req.net.buf = sqe.addr;
            if req.flags & rf::BUFFER_SELECT == 0 {
                req.vecs = vec![import_ubuf(c, sqe.addr, req.net.len)?];
            }
            Ok(())
        }
        _ => msg_setup(c, ring, req, false),
    }
}

/// `io_send_setup`: the buffer, a destination at `addr2` of `addr_len`
/// bytes (the low half of `file_index`, whose high half is zero:
/// `EINVAL`) read now (`move_addr_to_kernel`), and the buffer (or with
/// `IORING_SEND_VECTORIZED` the vectors) checked.
fn send_setup(c: &Ctx<'_>, ring: &Ring, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    req.net.buf = sqe.addr;
    if sqe.file_index >> 16 != 0 {
        return Err(Errno(EINVAL));
    }
    if sqe.off != 0 {
        req.data = read_addr(c, sqe.off, (sqe.file_index & 0xffff) as i32)?;
        req.names.push((sqe.off, Vec::new()));
    }
    if req.flags & rf::BUFFER_SELECT != 0 {
        return Ok(());
    }
    if req.net.flags & SEND_VECTORIZED != 0 {
        req.vecs = import_iovec_as(c, sqe.addr, req.net.len, ring.compat)?;
        import_vec_nr(req, req.net.len);
        return Ok(());
    }
    import_ubuf(c, sqe.addr, req.net.len)?;
    Ok(())
}

/// `io_msg_copy_hdr` and `io_net_import_vec`: the header at `addr` (the
/// ring's layout), a send's name read now, and the vectors imported (a
/// receive with a provided buffer takes at most one vector, whose length
/// it keeps: `EINVAL` for more); a multishot receive's header, name, and
/// control data fit an `int` (`io_recvmsg_mshot_prep`: `EOVERFLOW`).
fn msg_setup(c: &Ctx<'_>, ring: &Ring, req: &mut Req, send: bool) -> Result<(), Errno> {
    let at = req.sqe.addr;
    req.net.buf = at;
    let m = sockio::read_msghdr(c, at)?;
    if send && let Some(name) = sockio::msg_name(c, &m)? {
        req.data = name;
        req.names.push((m.name, Vec::new()));
    }
    req.net.name = m.name;
    req.net.namelen = m.namelen;
    req.net.control = m.control;
    req.net.controllen = m.controllen;
    if req.flags & rf::BUFFER_SELECT != 0 {
        match m.iovlen {
            0 => req.net.len = 0,
            1 => req.net.len = import_iovec_as(c, m.iov, 1, ring.compat)?[0].1,
            _ => return Err(Errno(EINVAL)),
        }
    } else {
        req.vecs = import_iovec_as(c, m.iov, m.iovlen, ring.compat)?;
        import_vec_nr(req, m.iovlen);
    }
    if req.flags & rf::APOLL_MULTISHOT != 0 {
        // The header's raw msg_namelen, not the one capped for a name.
        let off = if ring.compat { 4 } else { 8 };
        let raw = i32::from_le_bytes(c.read_mem(at + off, 4)?.try_into().unwrap());
        if raw < 0 {
            return Err(Errno(EOVERFLOW));
        }
        let hdr = RECVMSG_OUT + raw as u64;
        if hdr + m.controllen > i32::MAX as u64 {
            return Err(Errno(EOVERFLOW));
        }
        req.net.namelen = raw;
    }
    Ok(())
}

/// The header as read at preparation.
fn header(req: &Req) -> MsgHdr {
    MsgHdr {
        name: req.net.name,
        namelen: req.net.namelen,
        iov: 0,
        iovlen: req.vecs.len() as u64,
        control: req.net.control,
        controllen: req.net.controllen,
        flags: 0,
    }
}

/// `io_net_retry`: a stream (or sequenced packets) waiting for all of it.
fn net_retry(file: &OpenFile, flags: u32) -> bool {
    flags & lx::MSG_WAITALL != 0
        && sock_of(file).is_ok_and(|s| matches!(s.stype, lx::SOCK_STREAM | lx::SOCK_SEQPACKET))
}

/// The vectors less their first `n` bytes.
fn advance(vecs: &mut Vec<(u64, u64)>, mut n: u64) {
    let mut out = Vec::with_capacity(vecs.len());
    for &(base, len) in vecs.iter() {
        if n >= len {
            n -= len;
        } else {
            out.push((base + n, len - n));
            n = 0;
        }
    }
    *vecs = out;
}

fn vec_len(vecs: &[(u64, u64)]) -> u64 {
    vecs.iter().map(|&(_, l)| l).sum()
}

/// `io_bundle_nbufs`: the buffers `ret` bytes used of `vecs`.
fn bundle_nbufs(vecs: &[(u64, u64)], ret: i64) -> u16 {
    if ret <= 0 {
        return 0;
    }
    let mut left = ret as u64;
    let mut n = 0u16;
    for &(_, len) in vecs {
        n += 1;
        left -= len.min(left);
        if left == 0 {
            break;
        }
    }
    n
}

/// `io_net_kbuf_recyle` after part of a `MSG_WAITALL` transfer: the buffer
/// is not handed back, a ring's taken for what moved.
fn keep_buffer(c: &Ctx<'_>, st: &mut State, req: &mut Req, n: i64, vecs: &[(u64, u64)]) {
    req.flags |= rf::BL_NO_RECYCLE;
    kbuf::commit(c, st, req, n, bundle_nbufs(vecs, n));
}

/// `io_mshot_prep_retry`: a multishot or bundle transfer starts over.
fn mshot_prep_retry(req: &mut Req) {
    req.flags &= !rf::BL_EMPTY;
    req.net.done = 0;
    req.net.flags &= !RECV_RETRY_CLEAR;
    req.net.len = req.net.mshot_len;
}

/// The issue of a send or receive; one that cannot go on now (or goes on
/// as a multishot receive) waits for its socket (`io_queue_async`) unless
/// it may not (`-EAGAIN`); an error fails it (`io_req_defer_failed`).
pub(super) fn sr(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Done {
    let send = is_send(req.sqe.opcode);
    let r = match req.sqe.opcode {
        op::SEND => send_issue(c, ring, st, req),
        op::SENDMSG => sendmsg_issue(c, st, req),
        op::RECV => recv_issue(c, ring, st, req),
        _ => recvmsg_issue(c, ring, st, req),
    };
    match r {
        Ok(done) => done,
        Err(Errno(EAGAIN)) if req.flags & rf::NOWAIT == 0 => match assign_file(c, st, req) {
            Ok(f) => Done::Park(f, if send { POLL_OUT } else { POLL_IN }),
            Err(Errno(e)) => {
                req.defer_failed(-e);
                Done::Inline
            }
        },
        Err(Errno(e)) => {
            req.defer_failed(-e);
            Done::Inline
        }
    }
}

/// The socket, `ENOTSOCK` if it is none, and `IORING_RECVSEND_POLL_FIRST`
/// before the first wait (`-EAGAIN`).
fn socket_of(c: &Ctx<'_>, st: &mut State, req: &mut Req) -> Result<Arc<OpenFile>, Errno> {
    let file = assign_file(c, st, req)?;
    sock_of(&file)?;
    if req.flags & rf::POLLED == 0 && req.net.flags & POLL_FIRST != 0 {
        return Err(Errno(EAGAIN));
    }
    Ok(file)
}

/// A transfer's result short of `min`: `-EAGAIN` waits; part of a stream
/// with `MSG_WAITALL` counts and waits for the rest; otherwise the
/// request fails.
fn short(
    c: &Ctx<'_>,
    st: &mut State,
    req: &mut Req,
    file: &OpenFile,
    flags: u32,
    ret: i64,
    vecs: &[(u64, u64)],
) -> Result<(), Errno> {
    if ret == -i64::from(EAGAIN) {
        // A receive hands its buffer back; io_send keeps a provided one (a
        // ring's it took at once).
        if !is_send(req.sqe.opcode) {
            kbuf::recycle(st, req);
        }
        return Err(Errno(EAGAIN));
    }
    if ret > 0 && net_retry(file, flags) {
        req.net.done += ret as u64;
        keep_buffer(c, st, req, ret, vecs);
        advance(&mut req.vecs, ret as u64);
        if !req.vecs.is_empty() || req.sqe.opcode != op::SENDMSG {
            // SEND and RECV move on in their buffer.
            req.net.buf += ret as u64;
            req.net.len = req.net.len.saturating_sub(ret as u64);
        }
        if req.sqe.opcode == op::SENDMSG {
            // io_sendmsg: the control data went with the first part.
            req.net.control = 0;
            req.net.controllen = 0;
        }
        return Err(Errno(EAGAIN));
    }
    req.set_fail();
    Ok(())
}

/// `io_send`: the socket, a provided buffer (or a bundle of them: all
/// taken at once), then the send without waiting; short of all with
/// `MSG_WAITALL` or a bundle, see [`short`]. A bundle posts what it sent
/// with `IORING_CQE_F_MORE` and goes on with the next buffers until they
/// or the sending run out.
fn send_issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Result<Done, Errno> {
    let file = socket_of(c, st, req)?;
    let s = sock_of(&file)?;
    let flags = req.net.msg_flags | lx::MSG_DONTWAIT;
    let bundle = req.net.flags & BUNDLE != 0;
    let name = (!req.names.is_empty()).then(|| req.data.clone());
    loop {
        if req.flags & rf::BUFFER_SELECT != 0 && req.kbuf.is_none() {
            // io_send_select_buffer.
            let max = if req.net.len == 0 {
                i32::MAX as u64
            } else {
                req.net.len.min(i32::MAX as u64)
            };
            let (iov, _) = kbuf::peek(c, st, req, req.sqe.buf_index, max, bundle, true)?;
            req.net.len = vec_len(&iov);
            if iov.len() == 1 {
                req.net.buf = iov[0].0;
                import_ubuf(c, req.net.buf, req.net.len)?;
                req.vecs.clear();
            } else {
                req.vecs = iov;
            }
        }
        let vectored = !req.vecs.is_empty();
        let want = if vectored {
            vec_len(&req.vecs)
        } else {
            req.net.len
        };
        let min = if flags & lx::MSG_WAITALL != 0 || bundle {
            want
        } else {
            0
        };
        let w = SockWait::default();
        let r = if vectored {
            let m = header(req);
            sockio::send_msg(
                c,
                &file,
                s,
                &m,
                name.as_deref(),
                &req.vecs.clone(),
                flags,
                w,
            )
            .map(|(n, _)| n)
        } else {
            sockio::send_buf(
                c,
                &file,
                req.net.buf,
                req.net.len,
                flags,
                name.as_deref(),
                w,
            )
        };
        let mut ret = match r {
            Ok(n) => n as i64,
            Err(Errno(e)) => -i64::from(e),
        };
        if ret < min as i64 {
            let vecs = if vectored {
                req.vecs.clone()
            } else {
                vec![(req.net.buf, req.net.len)]
            };
            short(c, st, req, &file, flags, ret, &vecs)?;
        }
        if ret >= 0 {
            ret += req.net.done as i64;
        } else if req.net.done != 0 {
            ret = req.net.done as i64;
        }
        // io_send_finish.
        let cflags = kbuf::put(c, st, req, ret, 1);
        if bundle
            && ret > 0
            && req.flags & rf::BL_EMPTY == 0
            && submit::post_cqe(
                ring,
                st,
                req.sqe.user_data,
                ret as i32,
                cflags | cqe_flags::MORE,
            )
        {
            mshot_prep_retry(req);
            req.vecs.clear();
            continue;
        }
        req.res = ret as i32;
        req.cflags = cflags;
        msg_recycle(st, req);
        return Ok(Done::Inline);
    }
}

/// `io_sendmsg`: the socket, then the message without waiting; short of
/// all with `MSG_WAITALL`, see [`short`].
fn sendmsg_issue(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) -> Result<Done, Errno> {
    let file = socket_of(c, st, req)?;
    let s = sock_of(&file)?;
    let flags = req.net.msg_flags | lx::MSG_DONTWAIT;
    let want = vec_len(&req.vecs);
    let min = if flags & lx::MSG_WAITALL != 0 {
        want
    } else {
        0
    };
    let m = header(req);
    let name = (!req.names.is_empty()).then(|| req.data.clone());
    let vecs = req.vecs.clone();
    let r = sockio::send_msg(
        c,
        &file,
        s,
        &m,
        name.as_deref(),
        &vecs,
        flags,
        SockWait::default(),
    );
    let mut ret = match r {
        Ok((n, _)) => n as i64,
        Err(Errno(e)) => -i64::from(e),
    };
    if ret < min as i64 {
        short(c, st, req, &file, flags, ret, &vecs)?;
    }
    if ret >= 0 {
        ret += req.net.done as i64;
    } else if req.net.done != 0 {
        ret = req.net.done as i64;
    }
    req.res = ret as i32;
    req.cflags = 0;
    msg_recycle(st, req);
    Ok(Done::Inline)
}

/// `io_recv_buf_select`: a bundle's buffers (as many as the length asked
/// for, or the data the socket had left, need; a provided one alone),
/// or one buffer; `ENOBUFS` (or for a bundle `ENOENT`) without.
fn recv_select(c: &Ctx<'_>, st: &mut State, req: &mut Req, file: &OpenFile) -> Result<(), Errno> {
    let group = req.sqe.buf_index;
    if req.net.flags & BUNDLE != 0 && !st.in_worker {
        let mut max = if req.net.len != 0 {
            req.net.len
        } else if req.net.inq > 1 {
            req.net.inq as u64
        } else {
            0
        };
        if req.net.flags & RECV_MSHOT_LIM != 0 {
            max = if max == 0 {
                req.net.mshot_total
            } else {
                max.min(req.net.mshot_total.max(1))
            };
        }
        let (iov, partial) = kbuf::peek(c, st, req, group, max, true, false)?;
        if partial {
            req.net.flags |= RECV_PARTIAL_MAP;
        }
        req.vecs = iov;
        return Ok(());
    }
    let mut len = req.net.len;
    let now = st.in_worker || !poll::pollable(file);
    let addr = kbuf::select(c, st, req, &mut len, group, now).ok_or(Errno(ENOBUFS))?;
    req.vecs = vec![import_ubuf(c, addr, len)?];
    Ok(())
}

/// What a receive's finish decided.
enum Finish {
    /// Complete with the result.
    Done,
    /// Receive again at once (a bundle with more left, a multishot receive
    /// with data left).
    Again,
    /// Wait for more (a multishot receive, having posted).
    Wait,
}

/// `io_recv_finish`: `IORING_CQE_F_SOCK_NONEMPTY` for data left; a
/// multishot limit counted down; a bundle's buffers (with more left and all
/// of them used, a receive into more, its flags kept), or the buffer;
/// then a multishot receive posts with `IORING_CQE_F_MORE` and goes on
/// (at once while data is left, 32 times, then from its task work).
fn recv_finish(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    req: &mut Req,
    ret: i64,
    finished: bool,
    used: &[(u64, u64)],
) -> Finish {
    let mut finished = finished;
    let mut cflags = if req.net.inq > 0 {
        cqe_flags::SOCK_NONEMPTY
    } else {
        0
    };
    if ret > 0 && req.net.flags & RECV_MSHOT_LIM != 0 {
        req.net.mshot_total -= (ret as u64).min(req.net.mshot_total);
        if req.net.mshot_total == 0 {
            req.net.flags |= RECV_MSHOT_DONE;
            finished = true;
        }
    }
    if req.net.flags & BUNDLE != 0 {
        let this = ret - req.net.done as i64;
        cflags |= kbuf::put(c, st, req, this, bundle_nbufs(used, this));
        if req.net.flags & RECV_RETRY != 0 {
            cflags = req.net.cflags | (cflags & CQE_F_MASK);
        }
        if req.net.mshot_len != 0 && ret as u64 >= req.net.mshot_len {
            req.net.flags |= RECV_MSHOT_CAP;
        }
        let empty = req.flags & rf::BL_EMPTY != 0;
        let whole = this > 0 && this as u64 == vec_len(used);
        if !empty && req.net.flags & RECV_NO_RETRY == 0 && req.net.inq > 1 && whole {
            req.net.cflags = cflags & !CQE_F_MASK;
            req.net.len = req.net.inq as u64;
            req.net.done += this as u64;
            req.net.flags |= RECV_RETRY;
            return Finish::Again;
        }
        if empty {
            return complete_recv(st, req, ret, cflags);
        }
    } else {
        cflags |= kbuf::put(c, st, req, ret, 1);
    }
    let posted = req.flags & rf::APOLL_MULTISHOT != 0
        && !finished
        && submit::post_cqe(
            ring,
            st,
            req.sqe.user_data,
            ret as i32,
            cflags | cqe_flags::MORE,
        );
    if posted {
        mshot_prep_retry(req);
        if cflags & cqe_flags::SOCK_NONEMPTY != 0 || req.net.inq < 0 {
            let loops = req.net.loops;
            req.net.loops += 1;
            if loops < MULTISHOT_MAX_RETRY && req.net.flags & RECV_MSHOT_CAP == 0 {
                return Finish::Again;
            }
            req.net.loops = 0;
            req.net.flags &= !RECV_MSHOT_CAP;
            if st.reissuing {
                req.flags |= rf::REQUEUE;
            }
        }
        return Finish::Wait;
    }
    complete_recv(st, req, ret, cflags)
}

fn complete_recv(st: &mut State, req: &mut Req, ret: i64, cflags: u32) -> Finish {
    req.res = ret as i32;
    req.cflags = cflags;
    msg_recycle(st, req);
    Finish::Done
}

/// `io_recv`: `IORING_RECVSEND_POLL_FIRST` before the socket is looked at;
/// a provided buffer (or bundle), then the receive without waiting; short
/// of all with `MSG_WAITALL`, see [`short`]; a truncated message with it
/// fails the request; then [`recv_finish`].
fn recv_issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Result<Done, Errno> {
    let file = assign_file(c, st, req)?;
    if req.flags & rf::POLLED == 0 && req.net.flags & POLL_FIRST != 0 {
        return Err(Errno(EAGAIN));
    }
    let s = sock_of(&file)?;
    let flags = req.net.msg_flags | lx::MSG_DONTWAIT;
    loop {
        let mut ret: i64;
        let mut oflags = 0;
        let used;
        let mut fail = false;
        let selected = if req.flags & rf::BUFFER_SELECT != 0 && req.kbuf.is_none() {
            recv_select(c, st, req, &file)
        } else {
            Ok(())
        };
        if let Err(Errno(e)) = selected {
            // out_free.
            req.net.inq = -1;
            ret = -i64::from(e);
            used = Vec::new();
            fail = true;
        } else {
            req.net.inq = -1;
            used = req.vecs.clone();
            let want = vec_len(&used);
            let min = if flags & lx::MSG_WAITALL != 0 {
                want
            } else {
                0
            };
            let r = sockio::recv(c, &file, s, &used, flags, SockWait::default());
            ret = match r {
                Ok(got) => {
                    super::super::net::scm::discard(got.fds);
                    oflags = got.flags;
                    got.len as i64
                }
                Err(Errno(e)) => -i64::from(e),
            };
            if ret >= 0 {
                req.net.inq = sockio::inq(s).map_or(-1, |n| n as i64);
            }
            if ret < min as i64 {
                short(c, st, req, &file, flags, ret, &used)?;
            } else if flags & lx::MSG_WAITALL != 0 && oflags & (lx::MSG_TRUNC | lx::MSG_CTRUNC) != 0
            {
                fail = true;
            }
        }
        if fail {
            req.set_fail();
        }
        let finished = ret <= 0;
        if ret > 0 {
            ret += req.net.done as i64;
        } else if req.net.done != 0 {
            ret = req.net.done as i64;
        } else {
            kbuf::recycle(st, req);
        }
        match recv_finish(c, ring, st, req, ret, finished, &used) {
            Finish::Done => return Ok(Done::Inline),
            Finish::Wait => return Err(Errno(EAGAIN)),
            Finish::Again => continue,
        }
    }
}

/// `io_recvmsg`: the socket, `IORING_RECVSEND_POLL_FIRST`, a provided
/// buffer (`ENOBUFS`), laid out for a multishot receive (`struct
/// io_uring_recvmsg_out`, the name, the control data, then the payload:
/// `EFAULT` if the header does not fit), then the receive without waiting;
/// short of all with `MSG_WAITALL` and no control data, see [`short`]; a
/// truncated message with it fails the request; then [`recv_finish`].
fn recvmsg_issue(
    c: &mut Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    req: &mut Req,
) -> Result<Done, Errno> {
    let file = socket_of(c, st, req)?;
    let s = sock_of(&file)?;
    let flags = req.net.msg_flags | lx::MSG_DONTWAIT;
    let multishot = req.flags & rf::APOLL_MULTISHOT != 0;
    loop {
        let mut buf = 0;
        if req.flags & rf::BUFFER_SELECT != 0 && req.kbuf.is_none() {
            let mut len = req.net.len;
            let now = st.in_worker || !poll::pollable(&file);
            let addr =
                kbuf::select(c, st, req, &mut len, req.sqe.buf_index, now).ok_or(Errno(ENOBUFS))?;
            if multishot {
                // io_recvmsg_prep_multishot.
                let hdr = RECVMSG_OUT + req.net.namelen as u64 + req.net.controllen;
                if len < hdr {
                    kbuf::recycle(st, req);
                    return Err(Errno(EFAULT));
                }
                buf = addr;
                req.vecs = vec![(addr + hdr, len - hdr)];
            } else {
                req.vecs = vec![(addr, len)];
            }
        } else if multishot {
            buf = req.net.buf;
        }
        req.net.inq = -1;
        let used = req.vecs.clone();
        let mut finished = true;
        let mut oflags = 0;
        let mut min = 0;
        let mut ret: i64 = if multishot {
            let namelen = req.net.namelen as u64;
            let control = buf + RECVMSG_OUT + namelen;
            let payload = vec_len(&used);
            let r = sockio::recv_parts(
                c,
                &file,
                s,
                &used,
                flags,
                control,
                req.net.controllen,
                SockWait::default(),
            );
            match r {
                Ok((n, from, of, ctl)) => {
                    finished = n == 0;
                    oflags = of;
                    // struct io_uring_recvmsg_out, then as much of the name
                    // as there is room for.
                    let actual = if namelen == 0 { 0 } else { from.len() as u64 };
                    let mut hdr = Vec::with_capacity(16 + from.len());
                    hdr.extend_from_slice(&(actual as u32).to_le_bytes());
                    hdr.extend_from_slice(&(ctl as u32).to_le_bytes());
                    hdr.extend_from_slice(&(n as u32).to_le_bytes());
                    hdr.extend_from_slice(&(of & !MSG_CMSG_COMPAT).to_le_bytes());
                    hdr.extend_from_slice(&from[..actual.min(namelen) as usize]);
                    match c.write_mem(buf, &hdr) {
                        Ok(()) => {
                            (RECVMSG_OUT + namelen + req.net.controllen + (n as u64).min(payload))
                                as i64
                        }
                        Err(_) => -i64::from(EFAULT),
                    }
                }
                Err(Errno(e)) => -i64::from(e),
            }
        } else {
            let want = vec_len(&used);
            if flags & lx::MSG_WAITALL != 0 && req.net.controllen == 0 {
                min = want;
            }
            let m = header(req);
            match sockio::recv_msg(
                c,
                &file,
                s,
                req.net.buf,
                &m,
                &used,
                flags,
                SockWait::default(),
            ) {
                Ok((n, of)) => {
                    oflags = of;
                    n as i64
                }
                Err(Errno(e)) => -i64::from(e),
            }
        };
        if ret >= 0 {
            req.net.inq = sockio::inq(s).map_or(-1, |n| n as i64);
        }
        if !multishot {
            finished = true;
        }
        if ret < min as i64 {
            short(c, st, req, &file, flags, ret, &used)?;
        } else if flags & lx::MSG_WAITALL != 0 && oflags & (lx::MSG_TRUNC | lx::MSG_CTRUNC) != 0 {
            req.set_fail();
        }
        if ret > 0 {
            ret += req.net.done as i64;
        } else if req.net.done != 0 {
            ret = req.net.done as i64;
        } else {
            kbuf::recycle(st, req);
        }
        match recv_finish(c, ring, st, req, ret, finished || ret <= 0, &used) {
            Finish::Done => return Ok(Done::Inline),
            Finish::Wait => return Err(Errno(EAGAIN)),
            Finish::Again => continue,
        }
    }
}

/// `io_accept_prep`: no length or buffer (`EINVAL`); the address and its
/// length's address, the flags (`SOCK_CLOEXEC`, `SOCK_NONBLOCK`), the
/// descriptor limit now, the `IORING_ACCEPT_*` flags from `ioprio`; a slot
/// takes no `SOCK_CLOEXEC` and, multishot, only `IORING_FILE_INDEX_ALLOC`.
pub(super) fn accept_prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.len != 0 || sqe.buf_index != 0 {
        return Err(Errno(EINVAL));
    }
    let flags = sqe.op_flags as i32;
    let iou = u32::from(sqe.ioprio);
    if iou & !(ACCEPT_MULTISHOT | ACCEPT_DONTWAIT | ACCEPT_POLL_FIRST) != 0 {
        return Err(Errno(EINVAL));
    }
    let slot = sqe.file_index;
    if slot != 0
        && (flags & lx::SOCK_CLOEXEC != 0
            || (iou & ACCEPT_MULTISHOT != 0 && slot != FILE_INDEX_ALLOC))
    {
        return Err(Errno(EINVAL));
    }
    if flags & !(lx::SOCK_CLOEXEC | lx::SOCK_NONBLOCK) != 0 {
        return Err(Errno(EINVAL));
    }
    req.net.flags = iou;
    req.how = [sqe.addr, sqe.off, flags as u32 as u64, nofile(c)];
    if iou & ACCEPT_MULTISHOT != 0 {
        req.flags |= rf::APOLL_MULTISHOT;
    }
    if iou & ACCEPT_DONTWAIT != 0 {
        req.flags |= rf::NOWAIT;
    }
    Ok(())
}

fn nofile(c: &Ctx<'_>) -> u64 {
    c.p.rlimits[RLIMIT_NOFILE].0
}

/// `io_accept`: a descriptor first (`EMFILE`: no connection is taken) or
/// the slot, then a connection without waiting; the descriptor or slot,
/// with `IORING_CQE_F_SOCK_NONEMPTY` when TCP has more queued. With none
/// queued the request waits for one (with `IORING_ACCEPT_DONTWAIT`,
/// `-EAGAIN`). Multishot, each connection is posted with
/// `IORING_CQE_F_MORE`, and the next taken at once while more are (or
/// may be) queued; an error ends it.
pub(super) fn accept(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Done {
    let multishot = req.flags & rf::APOLL_MULTISHOT != 0;
    let file = match assign_file(c, st, req) {
        Ok(f) => f,
        Err(Errno(e)) => {
            req.defer_failed(-e);
            return Done::Inline;
        }
    };
    if req.flags & rf::POLLED == 0 && req.net.flags & ACCEPT_POLL_FIRST != 0 {
        return Done::Park(file, POLL_IN);
    }
    loop {
        let (ret, empty) = match accept_one(c, ring, st, req, &file) {
            Ok(r) => r,
            Err(Errno(EAGAIN)) if req.net.flags & ACCEPT_DONTWAIT == 0 => {
                return Done::Park(file, POLL_IN);
            }
            Err(Errno(e)) => (-e, None),
        };
        let cflags = if empty == Some(false) {
            cqe_flags::SOCK_NONEMPTY
        } else {
            0
        };
        if ret >= 0
            && multishot
            && submit::post_cqe(ring, st, req.sqe.user_data, ret, cflags | cqe_flags::MORE)
        {
            // With more queued, or not knowing, the next one at once.
            if empty == Some(true) {
                return Done::Park(file, POLL_IN);
            }
            continue;
        }
        req.res = ret;
        req.cflags = cflags;
        if ret < 0 {
            req.set_fail();
        }
        return Done::Inline;
    }
}

/// One connection: the descriptor reserved (not for a slot), `do_accept`,
/// then installed; the result, and whether TCP has no more queued.
fn accept_one(
    c: &mut Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    req: &Req,
    file: &Arc<OpenFile>,
) -> Result<(i32, Option<bool>), Errno> {
    let [addr, alen, flags, limit] = req.how;
    let flags = flags as u32 as i32;
    let slot = req.sqe.file_index;
    let fd = if slot == 0 {
        Some(c.p.fds.free_fds(1, limit)?[0])
    } else {
        None
    };
    let (new, empty) = sock::accept_file(c, file, addr, alen, flags, true)?;
    let ret = match fd {
        Some(fd) => {
            c.p.fds
                .install_at(fd, new, flags & lx::SOCK_CLOEXEC != 0, limit)?;
            fd
        }
        None => rsrc::fixed_fd_install(ring, st, new, slot)? as i32,
    };
    Ok((ret, empty))
}

/// `io_socket_prep`: no address, flags, or buffer (`EINVAL`); the family
/// from `fd`, the type from `off`, the protocol from `len`, the slot, and
/// the descriptor limit now; the type's flags only `SOCK_CLOEXEC` (not for
/// a slot) and `SOCK_NONBLOCK`.
pub(super) fn socket_prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.addr != 0 || sqe.op_flags != 0 || sqe.buf_index != 0 {
        return Err(Errno(EINVAL));
    }
    let flags = (sqe.off as i32) & !lx::SOCK_TYPE_MASK;
    if sqe.file_index != 0 && flags & lx::SOCK_CLOEXEC != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & !(lx::SOCK_CLOEXEC | lx::SOCK_NONBLOCK) != 0 {
        return Err(Errno(EINVAL));
    }
    req.how[0] = nofile(c);
    Ok(())
}

/// `io_socket`: a descriptor first (`EMFILE`), then the socket
/// (`__sys_socket_file`), installed there or in the slot.
pub(super) fn socket(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Done {
    let sqe = req.sqe;
    let limit = req.how[0];
    let r = (|| {
        let fd = if sqe.file_index == 0 {
            Some(c.p.fds.free_fds(1, limit)?[0])
        } else {
            None
        };
        let (file, cloexec) = sock::new_socket(c, sqe.fd, sqe.off as i32, sqe.len as i32)?;
        Ok(match fd {
            Some(fd) => {
                c.p.fds.install_at(fd, file, cloexec, limit)?;
                fd
            }
            None => rsrc::fixed_fd_install(ring, st, file, sqe.file_index)? as i32,
        })
    })();
    complete(req, r, true)
}

/// Completes with a result, failing the request with an error when `fail`.
fn complete(req: &mut Req, r: Result<i32, Errno>, fail: bool) -> Done {
    match r {
        Ok(v) => {
            req.res = v;
            req.cflags = 0;
        }
        Err(Errno(e)) if fail => req.fail(-e),
        Err(Errno(e)) => {
            req.res = -e;
            req.cflags = 0;
        }
    }
    Done::Inline
}

/// `io_connect_prep` and `io_bind_prep`: no length, buffer, flags, or file
/// slot (`EINVAL`); the address at `addr` of `addr2` bytes read now
/// (`move_addr_to_kernel`). `io_listen_prep`: no address, buffer, flags,
/// file slot, or `addr2`; the backlog from `len`.
pub(super) fn addr_prep(c: &Ctx<'_>, st: &mut State, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.buf_index != 0 || sqe.op_flags != 0 || sqe.file_index != 0 {
        return Err(Errno(EINVAL));
    }
    if sqe.opcode == op::LISTEN {
        if sqe.addr != 0 || sqe.off != 0 {
            return Err(Errno(EINVAL));
        }
        return Ok(());
    }
    if sqe.len != 0 {
        return Err(Errno(EINVAL));
    }
    msg_alloc(st, req);
    req.data = read_addr(c, sqe.addr, sqe.off as i32)?;
    Ok(())
}

/// `io_connect`: without waiting; one under way (or aborted once) waits
/// for the socket to be writable, and the connection's error (`SO_ERROR`)
/// is then its result.
pub(super) fn connect(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) -> Done {
    let file = match assign_file(c, st, req) {
        Ok(f) => f,
        Err(Errno(e)) => {
            req.defer_failed(-e);
            return Done::Inline;
        }
    };
    // A connection under way that failed: its error.
    if req.net.in_progress && sock::has_error(&file) {
        msg_recycle(st, req);
        return complete(req, sock::sock_error(&file).map(|()| 0), true);
    }
    let r = sock::connect_file(c, &file, &req.data, true);
    let r = match r {
        Err(Errno(e @ (EAGAIN | EINPROGRESS | ECONNABORTED))) => {
            if e == EINPROGRESS {
                req.net.in_progress = true;
            } else if e == ECONNABORTED {
                if req.net.aborted {
                    msg_recycle(st, req);
                    return complete(req, Err(Errno(e)), true);
                }
                req.net.aborted = true;
            }
            return Done::Park(file, POLL_OUT);
        }
        Err(Errno(EBADFD | EISCONN)) if req.net.in_progress => sock::sock_error(&file).map(|()| 0),
        r => r.map(|v| v as i32),
    };
    msg_recycle(st, req);
    complete(req, r, true)
}

/// `io_bind`, `io_listen`: the call on the socket (`ENOTSOCK`); an error
/// fails the request.
pub(super) fn bind_listen(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) -> Done {
    let file = match assign_file(c, st, req) {
        Ok(f) => f,
        Err(Errno(e)) => {
            req.defer_failed(-e);
            return Done::Inline;
        }
    };
    let r = if req.sqe.opcode == op::BIND {
        sock::bind_file(c, &file, &req.data)
    } else {
        sock::listen_file(&file, req.sqe.len as i32)
    };
    complete(req, r.map(|v| v as i32), true)
}

/// `io_shutdown_prep`: no offset, address, flags, buffer, or file slot
/// (`EINVAL`); `how` from `len`; for the async workers.
pub(super) fn shutdown_prep(req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.off != 0
        || sqe.addr != 0
        || sqe.op_flags != 0
        || sqe.buf_index != 0
        || sqe.file_index != 0
    {
        return Err(Errno(EINVAL));
    }
    req.flags |= rf::FORCE_ASYNC;
    Ok(())
}

/// `io_shutdown`: the call on the socket (`ENOTSOCK`); its error does not
/// fail the request.
pub(super) fn shutdown(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) -> Done {
    let file = match assign_file(c, st, req) {
        Ok(f) => f,
        Err(Errno(e)) => {
            req.defer_failed(-e);
            return Done::Inline;
        }
    };
    let r = sock::shutdown_file(&file, req.sqe.len as i32);
    complete(req, r.map(|v| v as i32), false)
}
