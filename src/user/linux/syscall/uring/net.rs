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
//! Buffer selection finds no provided buffers (none can be provided yet):
//! a send or receive that asks for one fails (`ENOBUFS`, or `ENOENT` for a
//! send or a bundle, which look for the buffer group first), and a
//! multishot receive, which needs one, is refused at preparation (`EINVAL`).

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
use super::rsrc;
use super::rw::import_ubuf;

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

/// `io_sendmsg_prep` and `io_recvmsg_prep`: the length, the flags from
/// `ioprio` (known ones: `EINVAL`), the message flags (`MSG_NOSIGNAL` added
/// to a send's; `MSG_DONTWAIT` meaning no waiting), a bundle (not a
/// message's; a send's waits for all of it); a receive's multishot needs a
/// provided buffer and no `MSG_WAITALL` (`EINVAL`), and `optlen` only a
/// multishot `RECV` takes. Then [`send_setup`], [`sendmsg_setup`], or
/// [`recv_setup`].
pub(super) fn sr_prep(c: &Ctx<'_>, ring: &Ring, req: &mut Req) -> Result<(), Errno> {
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
        }
    } else {
        let optlen = sqe.file_index;
        if req.net.flags & RECV_MULTISHOT != 0 {
            if req.flags & rf::BUFFER_SELECT == 0 || req.net.msg_flags & lx::MSG_WAITALL != 0 {
                return Err(Errno(EINVAL));
            }
            if opcode == op::RECVMSG && optlen != 0 {
                return Err(Errno(EINVAL));
            }
        } else if optlen != 0 {
            return Err(Errno(EINVAL));
        }
        if req.net.flags & BUNDLE != 0 && opcode == op::RECVMSG {
            return Err(Errno(EINVAL));
        }
    }
    match opcode {
        op::SEND => send_setup(c, ring, req),
        op::SENDMSG => {
            if sqe.off != 0 || sqe.file_index != 0 {
                return Err(Errno(EINVAL));
            }
            msg_setup(c, ring, req, true)
        }
        op::RECV => {
            req.net.buf = sqe.addr;
            if req.flags & rf::BUFFER_SELECT == 0 {
                import_ubuf(c, sqe.addr, req.net.len)?;
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
        return Ok(());
    }
    import_ubuf(c, sqe.addr, req.net.len)?;
    Ok(())
}

/// `io_msg_copy_hdr` and `io_net_import_vec`: the header at `addr` (the
/// ring's layout), a send's name read now, and the vectors imported (a
/// receive with a provided buffer takes at most one vector, whose length
/// it keeps: `EINVAL` for more).
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
        return Ok(());
    }
    req.vecs = import_iovec_as(c, m.iov, m.iovlen, ring.compat)?;
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

/// The issue of a send or receive: [`sr_issue`]'s result; one that cannot
/// go on now waits for its socket (`io_queue_async`) unless it may not
/// (`-EAGAIN`); an error fails it (`io_req_defer_failed`).
pub(super) fn sr(c: &mut Ctx<'_>, st: &mut State, req: &mut Req) -> Done {
    let send = is_send(req.sqe.opcode);
    match sr_issue(c, st, req, send) {
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

/// `io_send`, `io_sendmsg`, `io_recv`, `io_recvmsg`: the socket
/// (`ENOTSOCK`; a receive checks `IORING_RECVSEND_POLL_FIRST` first, a
/// send after), a provided buffer (`ENOBUFS`: none can be), then the
/// transfer without waiting. Short of all with `MSG_WAITALL` on a stream,
/// what moved is counted and the request waits for the rest; a truncated
/// message with it fails the request. The result counts what moved
/// before; a receive reports data left.
fn sr_issue(c: &mut Ctx<'_>, st: &mut State, req: &mut Req, send: bool) -> Result<Done, Errno> {
    let opcode = req.sqe.opcode;
    let poll_first = req.flags & rf::POLLED == 0 && req.net.flags & POLL_FIRST != 0;
    if opcode == op::RECV && poll_first {
        return Err(Errno(EAGAIN));
    }
    let file = assign_file(c, st, req)?;
    let s = sock_of(&file)?;
    if poll_first {
        return Err(Errno(EAGAIN));
    }
    // No buffer group exists: io_buffer_select finds no buffer
    // (ENOBUFS); io_buffers_select (a send) and io_buffers_peek (a
    // receive's bundle) find no list (ENOENT).
    if req.flags & rf::BUFFER_SELECT != 0 {
        let bundle = req.net.flags & BUNDLE != 0;
        let e = if opcode == op::SEND || (opcode == op::RECV && bundle) {
            ENOENT
        } else {
            ENOBUFS
        };
        if opcode == op::RECV {
            // io_recv's out_free: the request fails with it.
            req.fail(-e);
            return Ok(Done::Inline);
        }
        return Err(Errno(e));
    }
    let flags = req.net.msg_flags | lx::MSG_DONTWAIT;
    let w = SockWait::default();
    let (r, want, oflags) = match opcode {
        op::SEND => {
            let name = (!req.names.is_empty()).then_some(req.data.as_slice());
            if req.net.flags & SEND_VECTORIZED != 0 {
                let m = header(req);
                let r = sockio::send_msg(c, &file, s, &m, name, &req.vecs, flags, w);
                (r.map(|(n, _)| n), vec_len(&req.vecs), 0)
            } else {
                let r = sockio::send_buf(c, &file, req.net.buf, req.net.len, flags, name, w);
                (r, req.net.len, 0)
            }
        }
        op::SENDMSG => {
            let m = header(req);
            let name = (!req.names.is_empty()).then_some(req.data.as_slice());
            let r = sockio::send_msg(c, &file, s, &m, name, &req.vecs, flags, w);
            (r.map(|(n, _)| n), vec_len(&req.vecs), 0)
        }
        op::RECV => {
            let iov = [(req.net.buf, req.net.len)];
            match sockio::recv(c, &file, s, &iov, flags, w) {
                Ok(got) => {
                    super::super::net::scm::discard(got.fds);
                    (Ok(got.len), req.net.len, got.flags)
                }
                Err(e) => (Err(e), req.net.len, 0),
            }
        }
        _ => {
            let m = header(req);
            let r = sockio::recv_msg(c, &file, s, req.net.buf, &m, &req.vecs, flags, w);
            match r {
                Ok((n, oflags)) => (Ok(n), vec_len(&req.vecs), oflags),
                Err(e) => (Err(e), vec_len(&req.vecs), 0),
            }
        }
    };
    let waitall = flags & lx::MSG_WAITALL != 0;
    // A message with control data does not retry in part (io_recvmsg).
    let min = if waitall && (opcode != op::RECVMSG || req.net.controllen == 0) {
        want
    } else {
        0
    };
    let mut ret: i64 = match r {
        Ok(n) => n as i64,
        Err(Errno(e)) => -i64::from(e),
    };
    if ret < min as i64 {
        if ret == -i64::from(EAGAIN) {
            return Err(Errno(EAGAIN));
        }
        if ret > 0 && net_retry(&file, flags) {
            let n = ret as u64;
            req.net.done += n;
            match opcode {
                op::SEND | op::RECV if req.vecs.is_empty() => {
                    req.net.buf += n;
                    req.net.len -= n;
                }
                _ => advance(&mut req.vecs, n),
            }
            if opcode == op::SENDMSG {
                // io_sendmsg: the control data went with the first part.
                req.net.control = 0;
                req.net.controllen = 0;
            }
            return Err(Errno(EAGAIN));
        }
        req.set_fail();
    } else if !send && waitall && oflags & (lx::MSG_TRUNC | lx::MSG_CTRUNC) != 0 {
        req.set_fail();
    }
    if ret > 0 {
        ret += req.net.done as i64;
    } else if req.net.done != 0 {
        ret = req.net.done as i64;
    }
    req.res = ret as i32;
    req.cflags = 0;
    if !send && ret >= 0 && sockio::inq(s).is_some_and(|n| n > 0) {
        req.cflags = cqe_flags::SOCK_NONEMPTY;
    }
    Ok(Done::Inline)
}

fn vec_len(vecs: &[(u64, u64)]) -> u64 {
    vecs.iter().map(|&(_, l)| l).sum()
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
        if ret >= 0 && multishot {
            req.posts.push((ret, cflags | cqe_flags::MORE));
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
pub(super) fn addr_prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
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
        return complete(req, sock::sock_error(&file).map(|()| 0), true);
    }
    let r = sock::connect_file(c, &file, &req.data, true);
    let r = match r {
        Err(Errno(e @ (EAGAIN | EINPROGRESS | ECONNABORTED))) => {
            if e == EINPROGRESS {
                req.net.in_progress = true;
            } else if e == ECONNABORTED {
                if req.net.aborted {
                    return complete(req, Err(Errno(e)), true);
                }
                req.net.aborted = true;
            }
            return Done::Park(file, POLL_OUT);
        }
        Err(Errno(EBADFD | EISCONN)) if req.net.in_progress => sock::sock_error(&file).map(|()| 0),
        r => r.map(|v| v as i32),
    };
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
