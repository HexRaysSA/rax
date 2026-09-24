//! A socket's readiness as Linux's `sock_poll` reports it (`unix_poll`,
//! `unix_dgram_poll`, `tcp_poll`, `datagram_poll`).
//!
//! On a Linux host the host's mask is Linux's, `EPOLLRDHUP` included. A
//! Darwin host reports other masks for the same states (probed on Darwin
//! 25): nothing for a new stream socket (Linux: `EPOLLOUT | EPOLLHUP`,
//! state `TCP_CLOSE`), `POLLHUP` once either direction is shut down (Linux:
//! only both, `SHUTDOWN_MASK`), no `POLLOUT` after a shutdown (Linux keeps
//! a Unix or TCP socket writable, to report the error), and `POLLPRI` at
//! end of file. There the mask is derived from the Linux rules:
//!
//! | Bit | Linux condition | Darwin facts used |
//! |---|---|---|
//! | `EPOLLIN` | data queued, `RCV_SHUTDOWN`, or a connection to accept | `FIONREAD`, a peek at end of file, the listener's host readiness |
//! | `EPOLLRDHUP` | `RCV_SHUTDOWN` | the socket's own `SHUT_RD`, or end of file |
//! | `EPOLLOUT` | room to send; a Unix or TCP socket also once shut down or unconnected, not while listening or (TCP) connecting | the host's `POLLOUT`, the shutdown state |
//! | `EPOLLHUP` | `SHUTDOWN_MASK`; a stream socket in `TCP_CLOSE` | both directions shut; not connected, listening, or connecting |
//! | `EPOLLERR` | `sk_err` | the host's `POLLERR` |
//!
//! The peer's `SHUT_RD`, which Darwin does not report, is not seen.

use std::os::fd::AsRawFd;

use super::{Socket, lx};

/// `EPOLL*` bits.
pub mod ev {
    pub const IN: u32 = 0x001;
    pub const PRI: u32 = 0x002;
    pub const OUT: u32 = 0x004;
    pub const ERR: u32 = 0x008;
    pub const HUP: u32 = 0x010;
    pub const RDNORM: u32 = 0x040;
    pub const RDBAND: u32 = 0x080;
    pub const WRNORM: u32 = 0x100;
    pub const WRBAND: u32 = 0x200;
    pub const RDHUP: u32 = 0x2000;
}

/// `sk_shutdown` bits the socket's own `shutdown` set (`RCV_SHUTDOWN`,
/// `SEND_SHUTDOWN`).
pub const RCV_SHUTDOWN: u8 = 1;
pub const SEND_SHUTDOWN: u8 = 2;

/// The socket's poll mask.
pub fn mask(s: &Socket) -> u32 {
    #[cfg(target_os = "linux")]
    {
        linux_host(s)
    }
    #[cfg(not(target_os = "linux"))]
    {
        derived(s)
    }
}

/// Polls the host descriptor for every event, returning `revents`.
fn host_revents(s: &Socket, events: libc::c_short) -> libc::c_short {
    let mut p = libc::pollfd {
        fd: s.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: one valid pollfd for the duration of the call.
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    if rc > 0 { p.revents } else { 0 }
}

#[cfg(target_os = "linux")]
fn linux_host(s: &Socket) -> u32 {
    // The host's bits are Linux's.
    let all = libc::POLLIN
        | libc::POLLPRI
        | libc::POLLOUT
        | libc::POLLRDNORM
        | libc::POLLRDBAND
        | libc::POLLWRNORM
        | libc::POLLWRBAND
        | libc::POLLRDHUP;
    host_revents(s, all) as u16 as u32 & !0x20
}

/// Peeks one byte: `Some(0)` at end of file (or a zero-length datagram),
/// `Some(1)` with data, `None` with nothing to read.
#[cfg(not(target_os = "linux"))]
fn peek(s: &Socket) -> Option<usize> {
    let mut b = [0u8; 1];
    // SAFETY: a one-byte writable buffer.
    let n = unsafe {
        libc::recv(
            s.as_raw_fd(),
            b.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    (n >= 0).then_some(n as usize)
}

#[cfg(not(target_os = "linux"))]
fn derived(s: &Socket) -> u32 {
    use ev::*;
    let r = host_revents(s, libc::POLLIN | libc::POLLOUT);
    let (host_in, host_out, host_err) = (
        r & libc::POLLIN != 0,
        r & libc::POLLOUT != 0,
        r & libc::POLLERR != 0,
    );
    let (own, listening, connecting) = {
        let st = s.state.lock().unwrap();
        (st.shut, st.listening, st.connecting)
    };
    let mut m = if host_err { ERR } else { 0 };
    if !s.connected_type() {
        // datagram_poll, unix_dgram_poll: a datagram (possibly empty)
        // queued; the socket's own shutdown.
        if host_in && peek(s).is_some() {
            m |= IN | RDNORM;
        }
        if own & RCV_SHUTDOWN != 0 {
            m |= RDHUP | IN | RDNORM;
        }
        if own == RCV_SHUTDOWN | SEND_SHUTDOWN {
            m |= HUP;
        }
        if host_out {
            m |= OUT | WRNORM | WRBAND;
        }
        return m;
    }
    if listening {
        if host_in {
            m |= IN | RDNORM;
        }
        return m;
    }
    let connected = super::sys::peername(&s.file).is_ok();
    let queued = super::sys::inq(&s.file, true).unwrap_or(0) > 0;
    let eof = host_in && !queued && peek(s) == Some(0);
    // Darwin dissolves a connection shut down both ways, from either end.
    let rcv = own & RCV_SHUTDOWN != 0 || eof || (!connected && host_in);
    let snd = own & SEND_SHUTDOWN != 0;
    // A TCP connection under way (TCP_SYN_SENT) reports nothing yet.
    if s.tcp() && connecting && !connected && !host_err && r & libc::POLLHUP == 0 {
        return m;
    }
    let closed = !connected;
    if queued {
        m |= IN | RDNORM;
    }
    if rcv {
        m |= RDHUP | IN | RDNORM;
    }
    if (rcv && snd) || closed {
        m |= HUP;
    }
    // unix_writable, and tcp_poll's writable-once-shut-down.
    if host_out || snd || rcv || closed {
        m |= OUT | WRNORM;
        if s.domain == lx::AF_UNIX {
            m |= WRBAND;
        }
    }
    m
}
