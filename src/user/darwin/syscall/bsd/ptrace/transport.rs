//! Nonblocking framed connections between Darwin guest processes.
//!
//! Each endpoint has one reader and one writer. A frame is a little-endian
//! 32-bit byte count followed by its payload. The owner polls `fd()` for
//! readability and, while output is pending, writability; it never waits on
//! the connection while holding guest state. Request identity, authentication,
//! and the meaning of payloads belong to the tracing protocol above this
//! transport.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};

/// Local ownership identity. It never crosses the wire and is never reused
/// during this host process's lifetime. Process-instance discovery uses its
/// separate 128-bit publication generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ConnectionId(u64);

impl ConnectionId {
    fn allocate(counter: &AtomicU64) -> io::Result<Self> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                (next != 0 && next != u64::MAX).then(|| next + 1)
            })
            .map(Self)
            .map_err(|_| io::Error::other("tracing connection identity exhausted"))
    }
}

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

/// A bounded frame; operations with more data must transfer it in chunks.
pub(super) const MAX_FRAME: usize = 1 << 20;
/// Bound memory retained for a peer that has stopped reading.
const MAX_QUEUED: usize = 4 << 20;
/// Limit one receive pass so a busy peer cannot starve guest threads.
const READ_BUDGET: usize = 256 << 10;
/// Bound host descriptors retained for a peer that has stopped reading.
const MAX_QUEUED_FDS: usize = 128;
/// The frame's first byte carries an SCM_RIGHTS descriptor when this bit is set.
const HAS_FD: u32 = 1 << 31;

/// Sends the first bytes of a frame and its descriptor in one stream record.
/// On a partial write the descriptor has already been transferred and must
/// not be sent again with the rest of the frame.
fn send_descriptor(stream: &UnixStream, bytes: &[u8], fd: &OwnedFd) -> io::Result<usize> {
    let mut control = [0usize; 16];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: an all-zero msghdr is valid before its fields are initialized.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE only computes a size for one integer descriptor.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) } as _;
    // SAFETY: the aligned control buffer is large enough for the header and
    // one descriptor, and all pointers remain valid throughout sendmsg.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
        libc::CMSG_DATA(cmsg).cast::<RawFd>().write(fd.as_raw_fd());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let flags = libc::MSG_NOSIGNAL;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let flags = 0;
    // SAFETY: `msg` describes initialized buffers and a live socket.
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, flags) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Reads at most one frame segment and adopts every descriptor the kernel
/// delivered, including those accompanying malformed ancillary data.
fn receive_segment(stream: &UnixStream, bytes: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    // XNU accepts up to 512 descriptors in one SCM_RIGHTS record. Keep
    // enough room to adopt and close an oversized record even though this
    // protocol accepts only one descriptor per frame.
    let mut control = [0usize; 1024];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: an all-zero msghdr is valid before its fields are initialized.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let flags = 0;
    // SAFETY: the iovec and aligned control storage are writable for their
    // stated lengths and remain live for the call.
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, flags) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fds = Vec::new();
    let mut invalid = msg.msg_flags & libc::MSG_CTRUNC != 0;
    // SAFETY: recvmsg populated the control buffer. Bound each payload to
    // the returned control length before reading it: on truncation, the
    // header's cmsg_len can be larger than the bytes actually copied out.
    // Each SCM_RIGHTS integer is a newly owned descriptor and is adopted
    // exactly once.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let len = (*cmsg).cmsg_len as usize;
            let header = libc::CMSG_LEN(0) as usize;
            let base = msg.msg_control as usize;
            let offset = (cmsg as usize).saturating_sub(base);
            let available = (msg.msg_controllen as usize).saturating_sub(offset);
            if len < header || available < header {
                invalid = true;
                break;
            }
            let bounded_len = len.min(available);
            invalid |= len > available;
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_len = bounded_len - header;
                invalid |= data_len % std::mem::size_of::<RawFd>() != 0;
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                for i in 0..data_len / std::mem::size_of::<RawFd>() {
                    let fd = data.add(i).read();
                    if fd < 0 {
                        invalid = true;
                    } else {
                        fds.push(OwnedFd::from_raw_fd(fd));
                    }
                }
            } else {
                invalid = true;
            }
            if len > available {
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    for fd in &fds {
        // Darwin has no MSG_CMSG_CLOEXEC; retain other descriptor flags.
        // SAFETY: each fd is live and fcntl takes no pointer arguments.
        let current = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if current < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, current | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    if invalid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ancillary data",
        ));
    }
    Ok((n as usize, fds))
}

struct Outgoing {
    bytes: Vec<u8>,
    offset: usize,
    fd: Option<OwnedFd>,
}

/// One received frame. A transferred descriptor is owned by this value.
#[derive(Debug)]
pub(super) struct Frame {
    pub(super) payload: Vec<u8>,
    pub(super) fd: Option<OwnedFd>,
}

/// One independently owned end of a tracing connection.
pub(super) struct Link {
    identity: ConnectionId,
    stream: UnixStream,
    input: Vec<u8>,
    input_fd: Option<OwnedFd>,
    output: VecDeque<Outgoing>,
    queued: usize,
    queued_fds: usize,
    eof: bool,
    failure: Option<io::ErrorKind>,
}

impl AsFd for Link {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("identity", &self.identity)
            .field("fd", &self.fd())
            .field("input_bytes", &self.input.len())
            .field("output_frames", &self.output.len())
            .field("queued_bytes", &self.queued)
            .field("eof", &self.eof)
            .field("failure", &self.failure)
            .finish()
    }
}

impl Link {
    /// A connected pair suitable for a parent and child at fork.
    pub(super) fn pair() -> io::Result<(Self, Self)> {
        let (a, b) = UnixStream::pair()?;
        Ok((Self::new(a)?, Self::new(b)?))
    }

    /// Adopts a connected stream. On platforms with `SO_NOSIGPIPE`, setting
    /// it here also covers socket pairs and accepted sockets: a vanished peer
    /// must not deliver a host signal to the emulator.
    pub(super) fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        #[cfg(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        {
            let enabled: libc::c_int = 1;
            // SAFETY: the stream owns a live socket; `enabled` is initialized
            // and the length is exactly the size of the integer option.
            let result = unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&raw const enabled).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            identity: ConnectionId::allocate(&NEXT_CONNECTION)?,
            stream,
            input: Vec::new(),
            input_fd: None,
            output: VecDeque::new(),
            queued: 0,
            queued_fds: 0,
            eof: false,
            failure: None,
        })
    }

    pub(super) fn fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    pub(super) fn identity(&self) -> ConnectionId {
        self.identity
    }

    /// Duplicates an unused endpoint as a host fork does for the ownership
    /// tests; buffered protocol state must not be duplicated in production.
    #[cfg(test)]
    pub(super) fn duplicate_empty(&self) -> io::Result<Self> {
        assert!(
            self.input.is_empty()
                && self.input_fd.is_none()
                && self.output.is_empty()
                && !self.eof
                && self.failure.is_none()
        );
        let mut duplicate = Self::new(self.stream.try_clone()?)?;
        duplicate.identity = self.identity;
        Ok(duplicate)
    }

    pub(super) fn wants_write(&self) -> bool {
        !self.output.is_empty()
    }

    /// Queues one complete frame or leaves the queue unchanged on failure.
    pub(super) fn queue(&mut self, payload: &[u8]) -> io::Result<()> {
        self.queue_inner(payload, None)
    }

    /// Queues a duplicate of `fd` with a frame. The caller retains its own
    /// descriptor whether queuing succeeds or fails.
    ///
    /// On macOS 27.2, a native socket-transfer probe observed a transferred
    /// socket returning EOF when the last sender reference was closed before
    /// receipt while unrelated sockets were opened and closed. Keeping the
    /// sender reference through receipt avoided that outcome in
    /// `tools/darwin/ptrace_scm_socket_probe.c`;
    /// this protocol has no receipt acknowledgment and does not establish
    /// that guarantee. Production callers currently transfer regular files.
    pub(super) fn queue_with_fd(&mut self, payload: &[u8], fd: impl AsFd) -> io::Result<()> {
        if self.queued_fds == MAX_QUEUED_FDS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "descriptor queue full",
            ));
        }
        let duplicate = fd.as_fd().try_clone_to_owned()?;
        self.queue_inner(payload, Some(duplicate))
    }

    fn queue_inner(&mut self, payload: &[u8], fd: Option<OwnedFd>) -> io::Result<()> {
        if payload.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame too large",
            ));
        }
        let length = payload.len() + 4;
        if length > MAX_QUEUED - self.queued {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "output queue full",
            ));
        }
        let mut bytes = Vec::with_capacity(length);
        let header = payload.len() as u32 | if fd.is_some() { HAS_FD } else { 0 };
        bytes.extend_from_slice(&header.to_le_bytes());
        bytes.extend_from_slice(payload);
        self.queued_fds += usize::from(fd.is_some());
        self.output.push_back(Outgoing {
            bytes,
            offset: 0,
            fd,
        });
        self.queued += length;
        Ok(())
    }

    /// Writes as much queued data as the peer accepts without blocking.
    pub(super) fn flush(&mut self) -> io::Result<()> {
        while let Some(frame) = self.output.front_mut() {
            let result = if let Some(fd) = &frame.fd {
                send_descriptor(&self.stream, &frame.bytes[frame.offset..], fd)
            } else {
                self.stream.write(&frame.bytes[frame.offset..])
            };
            match result {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    if frame.fd.take().is_some() {
                        self.queued_fds -= 1;
                    }
                    frame.offset += n;
                    if frame.offset == frame.bytes.len() {
                        self.queued -= frame.bytes.len();
                        self.output.pop_front();
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // XNU can report EAGAIN for a full socket even after its
                    // peer closed; POLLHUP still reports the disconnect.
                    // Do not coalesce essential output against a dead link.
                    let mut pfd = libc::pollfd {
                        fd: self.fd(),
                        // macOS 27.2 ignores an events == 0 pollfd even
                        // when its socket has a pending hangup.
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    loop {
                        // SAFETY: pfd names this owned socket; timeout zero
                        // checks terminal readiness without blocking.
                        let result = unsafe { libc::poll(&mut pfd, 1, 0) };
                        if result >= 0 {
                            if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                                return Err(io::ErrorKind::BrokenPipe.into());
                            }
                            return Ok(());
                        }
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Returns complete received frames and whether the peer closed its end.
    /// A malformed frame, partial EOF, or I/O error is terminal and is
    /// reported after complete frames preceding it have been returned. After
    /// a nonempty batch with `closed == false`, call again without waiting so
    /// a deferred error does not depend on another readiness notification.
    pub(super) fn receive_frames(&mut self) -> io::Result<(Vec<Frame>, bool)> {
        self.receive_frames_limited(usize::MAX, MAX_FRAME)
    }

    pub(super) fn receive_one_frame(&mut self) -> io::Result<(Vec<Frame>, bool)> {
        self.receive_frames_limited(1, MAX_FRAME)
    }

    /// A setup protocol can reject an oversized payload from its header,
    /// before buffering a complete ordinary-operation-sized frame.
    pub(super) fn receive_setup_frame(
        &mut self,
        max_payload: usize,
    ) -> io::Result<(Vec<Frame>, bool)> {
        self.receive_frames_limited(1, max_payload.min(MAX_FRAME))
    }

    fn receive_frames_limited(
        &mut self,
        limit: usize,
        max_payload: usize,
    ) -> io::Result<(Vec<Frame>, bool)> {
        if let Some(kind) = self.failure {
            return Err(kind.into());
        }
        let mut frames = Vec::new();
        let mut read = 0;
        let mut buffer = [0u8; 4096];
        while !self.eof {
            let remaining = if self.input.is_empty() {
                // The descriptor must accompany the first byte, not a
                // later byte of the header combined in the same read.
                1
            } else if self.input.len() < 4 {
                4 - self.input.len()
            } else {
                let header = u32::from_le_bytes(self.input[..4].try_into().unwrap());
                let length = (header & !HAS_FD) as usize;
                if length > max_payload || ((header & HAS_FD != 0) != self.input_fd.is_some()) {
                    self.failure = Some(io::ErrorKind::InvalidData);
                    break;
                }
                if self.input.len() == 4 + length {
                    frames.push(Frame {
                        payload: self.input.split_off(4),
                        fd: self.input_fd.take(),
                    });
                    self.input.clear();
                    if frames.len() == limit {
                        break;
                    }
                    continue;
                }
                4 + length - self.input.len()
            };
            if read == READ_BUDGET {
                break;
            }
            // Never cross a frame boundary in recvmsg: an SCM_RIGHTS record
            // belongs to the first byte of exactly one frame.
            let room = remaining.min(buffer.len()).min(READ_BUDGET - read);
            match receive_segment(&self.stream, &mut buffer[..room]) {
                Ok((0, fds)) => {
                    if !fds.is_empty() {
                        self.failure = Some(io::ErrorKind::InvalidData);
                    }
                    self.eof = true;
                }
                Ok((n, mut fds)) => {
                    if !fds.is_empty() {
                        if !self.input.is_empty() || fds.len() != 1 || self.input_fd.is_some() {
                            self.failure = Some(io::ErrorKind::InvalidData);
                            break;
                        }
                        self.input_fd = fds.pop();
                    }
                    read += n;
                    self.input.extend_from_slice(&buffer[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    self.failure = Some(e.kind());
                    break;
                }
            }
        }
        if self.eof && !self.input.is_empty() {
            self.failure = Some(io::ErrorKind::UnexpectedEof);
        }
        if self.failure.is_some() {
            self.input_fd = None;
        }
        if let Some(kind) = self.failure
            && frames.is_empty()
        {
            return Err(kind.into());
        }
        Ok((
            frames,
            self.eof && self.input.is_empty() && self.failure.is_none(),
        ))
    }

    /// Receives byte-only protocol frames, rejecting unexpected descriptors.
    pub(super) fn receive(&mut self) -> io::Result<(Vec<Vec<u8>>, bool)> {
        self.receive_limited(usize::MAX)
    }

    /// Receives at most one frame so a server can reserve reply capacity.
    pub(super) fn receive_one(&mut self) -> io::Result<(Vec<Vec<u8>>, bool)> {
        self.receive_limited(1)
    }

    fn receive_limited(&mut self, limit: usize) -> io::Result<(Vec<Vec<u8>>, bool)> {
        let (frames, closed) = self.receive_frames_limited(limit, MAX_FRAME)?;
        let mut plain = Vec::with_capacity(frames.len());
        for frame in frames {
            if frame.fd.is_some() {
                self.failure = Some(io::ErrorKind::InvalidData);
                if plain.is_empty() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                return Ok((plain, false));
            }
            plain.push(frame.payload);
        }
        Ok((plain, closed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::Shutdown;

    #[test]
    fn connection_identities_are_never_reused_and_exhaustion_does_not_wrap() {
        let (a, b) = Link::pair().unwrap();
        assert_ne!(a.identity(), b.identity());
        let old = a.identity();
        drop(a);
        let (c, _) = Link::pair().unwrap();
        assert_ne!(old, c.identity());
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            ConnectionId::allocate(&counter).unwrap(),
            ConnectionId(u64::MAX - 1)
        );
        assert!(ConnectionId::allocate(&counter).is_err());
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        assert!(ConnectionId::allocate(&AtomicU64::new(0)).is_err());
    }

    #[test]
    fn descriptors_stay_with_their_frames_and_are_close_on_exec() {
        let (mut a, mut b) = Link::pair().unwrap();
        let (offered, mut peer) = UnixStream::pair().unwrap();
        let offered: OwnedFd = offered.into();
        a.queue(b"before").unwrap();
        a.queue_with_fd(b"with fd", &offered).unwrap();
        a.queue(b"").unwrap();
        drop(offered);
        a.flush().unwrap();
        let (mut frames, closed) = b.receive_frames().unwrap();
        assert!(!closed);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].payload, b"before");
        assert!(frames[0].fd.is_none());
        assert_eq!(frames[1].payload, b"with fd");
        assert_eq!(frames[2].payload, b"");
        assert!(frames[2].fd.is_none());
        let fd = frames[1].fd.take().unwrap();
        // SAFETY: `fd` is owned and live; F_GETFD has no pointer argument.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let mut received = UnixStream::from(fd);
        peer.write_all(b"x").unwrap();
        let mut byte = [0];
        received.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
    }

    #[test]
    fn consecutive_descriptor_frames_keep_each_endpoint() {
        let (mut a, mut b) = Link::pair().unwrap();
        let mut peers = Vec::new();
        for index in 0..16u8 {
            let (fd, peer) = UnixStream::pair().unwrap();
            a.queue_with_fd(&[index], &fd).unwrap();
            peers.push(peer);
        }
        let mut frames = Vec::new();
        for _ in 0..10_000 {
            a.flush().unwrap();
            frames.extend(b.receive_frames().unwrap().0);
            if frames.len() == peers.len() {
                break;
            }
        }
        assert_eq!(frames.len(), peers.len());
        for (index, (frame, peer)) in frames.into_iter().zip(peers.iter_mut()).enumerate() {
            assert_eq!(frame.payload, [index as u8]);
            let mut endpoint = UnixStream::from(frame.fd.unwrap());
            peer.write_all(&[index as u8]).unwrap();
            let mut byte = [0];
            endpoint.read_exact(&mut byte).unwrap();
            assert_eq!(byte[0], index as u8);
        }
    }

    #[test]
    fn transferred_connection_survives_the_intermediate_endpoint() {
        let (mut ancestor, mut intermediate) = Link::pair().unwrap();
        let (offered, mut child) = Link::pair().unwrap();
        intermediate.queue_with_fd(b"descendant", &offered).unwrap();
        intermediate.flush().unwrap();
        assert!(!intermediate.wants_write());
        drop(offered);
        drop(intermediate);
        let (mut frames, closed) = ancestor.receive_frames().unwrap();
        assert!(closed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"descendant");
        let fd = frames[0].fd.take().unwrap();
        let mut adopted = Link::new(UnixStream::from(fd)).unwrap();
        child.queue(b"direct").unwrap();
        child.flush().unwrap();
        assert_eq!(
            adopted.receive().unwrap(),
            (vec![b"direct".to_vec()], false)
        );
    }

    #[test]
    fn descriptor_header_must_match_the_first_byte() {
        let (mut a, mut b) = Link::pair().unwrap();
        a.stream.write_all(&HAS_FD.to_le_bytes()).unwrap();
        assert_eq!(
            b.receive_frames().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let (a, mut b) = Link::pair().unwrap();
        let (fd, _peer) = UnixStream::pair().unwrap();
        let fd: OwnedFd = fd.into();
        assert_eq!(
            send_descriptor(&a.stream, &0u32.to_le_bytes(), &fd).unwrap(),
            4
        );
        assert_eq!(
            b.receive_frames().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let (mut a, mut b) = Link::pair().unwrap();
        let header = HAS_FD.to_le_bytes();
        a.stream.write_all(&header[..1]).unwrap();
        assert!(b.receive_frames().unwrap().0.is_empty());
        assert_eq!(send_descriptor(&a.stream, &header[1..], &fd).unwrap(), 3);
        assert_eq!(
            b.receive_frames().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn byte_only_protocol_returns_prior_frames_before_rejecting_a_descriptor() {
        let (mut a, mut b) = Link::pair().unwrap();
        let (fd, _peer) = UnixStream::pair().unwrap();
        let fd: OwnedFd = fd.into();
        a.queue(b"before").unwrap();
        a.queue_with_fd(b"unexpected", &fd).unwrap();
        a.flush().unwrap();
        assert_eq!(b.receive().unwrap(), (vec![b"before".to_vec()], false));
        assert_eq!(b.receive().unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_frame_closes_its_received_descriptor() {
        let (a, mut b) = Link::pair().unwrap();
        let (fd, mut peer) = UnixStream::pair().unwrap();
        let fd: OwnedFd = fd.into();
        assert_eq!(send_descriptor(&a.stream, &[0], &fd).unwrap(), 1);
        drop(fd);
        drop(a);
        assert_eq!(
            b.receive_frames().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        peer.set_nonblocking(true).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn rejects_and_closes_many_descriptors_in_one_frame() {
        const COUNT: usize = 200;
        let (a, mut b) = Link::pair().unwrap();
        let (fd, mut peer) = UnixStream::pair().unwrap();
        let bytes = HAS_FD.to_le_bytes();
        let mut control = [0u64; 128];
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: an all-zero msghdr is valid before initialization.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        // SAFETY: the aligned buffer holds the header and COUNT integers.
        unsafe {
            msg.msg_controllen = libc::CMSG_SPACE((COUNT * std::mem::size_of::<RawFd>()) as _) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN((COUNT * std::mem::size_of::<RawFd>()) as _) as _;
            let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
            for i in 0..COUNT {
                data.add(i).write(fd.as_raw_fd());
            }
            assert_eq!(libc::sendmsg(a.fd(), &msg, 0), bytes.len() as libc::ssize_t);
        }
        drop(fd);
        assert_eq!(
            b.receive_frames().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap(),
            0,
            "received descriptors leaked"
        );
    }

    #[test]
    fn descriptor_queue_is_bounded_and_releases_unsent_rights() {
        let (mut a, _b) = Link::pair().unwrap();
        let (fd, mut peer) = UnixStream::pair().unwrap();
        let fd: OwnedFd = fd.into();
        for _ in 0..MAX_QUEUED_FDS {
            a.queue_with_fd(b"", &fd).unwrap();
        }
        assert_eq!(
            a.queue_with_fd(b"", &fd).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(fd);
        drop(a);
        peer.set_nonblocking(true).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn a_closed_peer_rejects_a_descriptor_without_a_host_sigpipe() {
        let (mut a, b) = Link::pair().unwrap();
        let (fd, _peer) = UnixStream::pair().unwrap();
        a.queue_with_fd(b"descriptor", &fd).unwrap();
        b.stream.shutdown(Shutdown::Both).unwrap();
        drop(b);
        assert!(a.flush().is_err());
    }

    #[test]
    fn descriptor_is_sent_once_across_partial_writes() {
        let (mut a, mut b) = Link::pair().unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: `a` owns a socket and `size` is a live option value.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    a.fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&raw const size).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        let (fd, _peer) = UnixStream::pair().unwrap();
        let fd: OwnedFd = fd.into();
        a.queue_with_fd(&vec![0xa5; MAX_FRAME], &fd).unwrap();
        a.flush().unwrap();
        assert!(a.wants_write());
        let mut frames = Vec::new();
        for _ in 0..10_000 {
            frames.extend(b.receive_frames().unwrap().0);
            a.flush().unwrap();
            if !frames.is_empty() {
                break;
            }
        }
        assert!(!a.wants_write());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, vec![0xa5; MAX_FRAME]);
        assert!(frames[0].fd.is_some());
    }

    #[test]
    fn frames_survive_partial_writes_and_peer_close() {
        let (mut a, mut b) = Link::pair().unwrap();
        assert_ne!(a.fd(), b.fd());
        a.stream.write_all(&[3, 0]).unwrap();
        assert_eq!(b.receive().unwrap(), (vec![], false));
        a.stream.write_all(&[0, 0, b'a']).unwrap();
        assert_eq!(b.receive().unwrap(), (vec![], false));
        a.stream.write_all(b"bc").unwrap();
        a.queue(b"next").unwrap();
        a.queue(b"").unwrap();
        assert!(a.wants_write());
        a.flush().unwrap();
        assert!(!a.wants_write());
        a.stream.shutdown(Shutdown::Write).unwrap();
        drop(a);
        assert_eq!(
            b.receive().unwrap(),
            (vec![b"abc".to_vec(), b"next".to_vec(), vec![]], true)
        );
    }

    #[test]
    fn rejects_invalid_and_truncated_frames() {
        let (mut a, mut b) = Link::pair().unwrap();
        a.stream
            .write_all(&((MAX_FRAME as u32) + 1).to_le_bytes())
            .unwrap();
        assert_eq!(b.receive().unwrap_err().kind(), io::ErrorKind::InvalidData);

        let (mut a, mut b) = Link::pair().unwrap();
        a.stream.write_all(&[3, 0, 0, 0, b'a']).unwrap();
        a.stream.shutdown(Shutdown::Write).unwrap();
        drop(a);
        assert_eq!(
            b.receive().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let (mut a, mut b) = Link::pair().unwrap();
        a.stream.write_all(&[1, 0, 0, 0, b'x', 3, 0]).unwrap();
        a.stream.shutdown(Shutdown::Write).unwrap();
        drop(a);
        assert_eq!(b.receive().unwrap(), (vec![b"x".to_vec()], false));
        assert_eq!(
            b.receive().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let (mut a, mut b) = Link::pair().unwrap();
        a.stream.write_all(&[1, 0, 0, 0, b'x']).unwrap();
        a.stream
            .write_all(&((MAX_FRAME as u32) + 1).to_le_bytes())
            .unwrap();
        assert_eq!(b.receive().unwrap(), (vec![b"x".to_vec()], false));
        assert_eq!(b.receive().unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn output_is_bounded_and_peer_close_is_an_error() {
        let (mut a, b) = Link::pair().unwrap();
        assert_eq!(
            a.queue(&vec![0; MAX_FRAME + 1]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        for _ in 0..3 {
            a.queue(&vec![0; MAX_FRAME]).unwrap();
        }
        assert_eq!(
            a.queue(&vec![0; MAX_FRAME]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        b.stream.shutdown(Shutdown::Both).unwrap();
        drop(b);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if a.flush().is_err() {
                break;
            }
            if !a.wants_write() {
                a.queue(b"probe").unwrap();
            }
            assert!(std::time::Instant::now() < deadline, "peer did not close");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn backpressure_keeps_every_byte_in_order() {
        let (mut a, mut b) = Link::pair().unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: `a` owns the socket and `size` is a live integer option.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    a.fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&raw const size).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        for byte in 1..=3 {
            a.queue(&vec![byte; MAX_FRAME]).unwrap();
        }
        a.flush().unwrap();
        assert!(a.wants_write());
        let mut frames = Vec::new();
        for _ in 0..10_000 {
            frames.extend(b.receive().unwrap().0);
            a.flush().unwrap();
            if frames.len() == 3 {
                break;
            }
        }
        assert!(!a.wants_write());
        assert_eq!(frames.len(), 3);
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.len(), MAX_FRAME);
            assert!(frame.iter().all(|&byte| byte == index as u8 + 1));
        }
    }
}
