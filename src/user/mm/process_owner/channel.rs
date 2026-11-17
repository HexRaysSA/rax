//! Bounded, descriptor-carrying frames on private Unix stream pairs.
//!
//! No listener or filesystem endpoint is exposed. One owner controls each
//! channel; it is not cloned. After an I/O or framing failure, the stream is
//! shut down and cannot be reused: a lost reply cannot be retried as though
//! the associated mutation had not happened.

use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

const MAGIC: &[u8; 8] = b"RAXMM001";
const HEADER: usize = 16;
pub(super) const MAX_BYTES: usize = 1 << 20;
pub(super) const MAX_FDS: usize = 16;

#[derive(Debug)]
pub(crate) struct Frame {
    pub(crate) bytes: Vec<u8>,
    pub(crate) files: Vec<OwnedFd>,
}

#[derive(Debug)]
pub(crate) struct Channel {
    stream: Option<UnixStream>,
}

impl Channel {
    pub(crate) fn pair() -> io::Result<(Self, Self)> {
        let (a, b) = UnixStream::pair()?;
        Ok((Self::new(a)?, Self::new(b)?))
    }

    /// Take an exclusively owned socket. The caller closes inherited copies
    /// of the opposite endpoint before using the channel after host fork.
    pub(crate) fn new(stream: UnixStream) -> io::Result<Self> {
        close_on_exec(stream.as_raw_fd())?;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let value: libc::c_int = 1;
            // SAFETY: stream owns a live socket; value is initialized and
            // remains readable for the synchronous setsockopt call.
            if unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&value as *const libc::c_int).cast(),
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            stream: Some(stream),
        })
    }

    /// Send one frame. Invalid local sizes are rejected before any bytes or
    /// descriptors move. A stream failure poisons the channel permanently.
    pub(crate) fn send(&mut self, bytes: &[u8], files: &[BorrowedFd<'_>]) -> io::Result<()> {
        self.check()?;
        if bytes.len() > MAX_BYTES || files.len() > MAX_FDS {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        header[12..14].copy_from_slice(&(files.len() as u16).to_le_bytes());
        let result = self.send_header(&header, files).and_then(|sent| {
            let mut stream = self.socket()?;
            stream.write_all(&header[sent..])?;
            stream.write_all(bytes)
        });
        self.finish(result)
    }

    fn send_header(&self, header: &[u8; HEADER], files: &[BorrowedFd<'_>]) -> io::Result<usize> {
        let mut control = control_buffer();
        let mut iov = libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast(),
            iov_len: HEADER,
        };
        // SAFETY: an all-zero native msghdr has null optional pointers and
        // zero lengths. Every active buffer is installed below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !files.is_empty() {
            let bytes = files.len() * std::mem::size_of::<libc::c_int>();
            // SAFETY: control is cmsghdr-aligned and large enough for MAX_FDS.
            // Each descriptor remains borrowed and live through sendmsg.
            unsafe {
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = libc::CMSG_SPACE(bytes as u32) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(bytes as u32) as _;
                let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                for (index, file) in files.iter().enumerate() {
                    data.add(index).write_unaligned(file.as_raw_fd());
                }
            }
        }
        loop {
            #[cfg(target_os = "linux")]
            let flags = libc::MSG_NOSIGNAL;
            #[cfg(not(target_os = "linux"))]
            let flags = 0;
            // SAFETY: initialized msg describes live header/control buffers;
            // sendmsg retains neither pointer. A successful short send carries
            // the descriptors exactly once, with the first header bytes.
            let result = unsafe { libc::sendmsg(self.socket()?.as_raw_fd(), &msg, flags) };
            if result > 0 {
                return Ok(result as usize);
            }
            if result == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    pub(crate) fn receive(&mut self) -> io::Result<Frame> {
        self.check()?;
        let result = self.receive_frame();
        self.finish(result)
    }

    fn receive_frame(&self) -> io::Result<Frame> {
        let mut frame = Frame {
            bytes: Vec::new(),
            files: Vec::new(),
        };
        let mut header = [0; HEADER];
        self.read_exact(&mut header, &mut frame.files, true)?;
        let len = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(header[12..14].try_into().unwrap()) as usize;
        if &header[..8] != MAGIC
            || header[14..] != [0, 0]
            || len > MAX_BYTES
            || count > MAX_FDS
            || frame.files.len() != count
        {
            return Err(invalid());
        }
        frame.bytes.resize(len, 0);
        self.read_exact(&mut frame.bytes, &mut frame.files, false)?;
        Ok(frame)
    }

    /// Receive exactly this part of a frame. recvmsg is also used for payload
    /// bytes so unexpected ancillary descriptors are rejected and closed.
    fn read_exact(
        &self,
        mut bytes: &mut [u8],
        files: &mut Vec<OwnedFd>,
        mut allow_files: bool,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut control = control_buffer();
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: zeroed optional fields, then live, aligned receive
            // buffers with exactly their writable capacities.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = (control.len() * std::mem::size_of::<usize>()) as _;
            #[cfg(target_os = "linux")]
            let flags = libc::MSG_CMSG_CLOEXEC;
            #[cfg(not(target_os = "linux"))]
            let flags = 0;
            // SAFETY: buffers remain live through synchronous recvmsg and
            // the kernel writes at most their specified capacities.
            let received = unsafe { libc::recvmsg(self.socket()?.as_raw_fd(), &mut msg, flags) };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let incoming = receive_files(&msg)?;
            if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
                || !allow_files && !incoming.is_empty()
                || files.len() + incoming.len() > MAX_FDS
            {
                return Err(invalid());
            }
            files.extend(incoming);
            if received == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            allow_files = false;
            bytes = &mut bytes[received as usize..];
        }
        Ok(())
    }

    fn check(&self) -> io::Result<()> {
        self.socket().map(|_| ())
    }

    fn socket(&self) -> io::Result<&UnixStream> {
        self.stream
            .as_ref()
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }

    pub(super) fn poll_fd(&self) -> io::Result<libc::c_int> {
        Ok(self.socket()?.as_raw_fd())
    }

    pub(super) fn into_stream(mut self) -> io::Result<UnixStream> {
        self.stream
            .take()
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }

    pub(super) fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn finish<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            // Close the descriptor as well as shutting down both directions.
            // A retained shutdown socket can still accept peer writes on
            // Darwin. It must not survive a rejected or incomplete frame.
            self.close();
        }
        result
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid memory-owner frame")
}

fn control_buffer() -> Vec<usize> {
    let bytes = MAX_FDS * std::mem::size_of::<libc::c_int>();
    // SAFETY: bounded descriptor byte count fits the native CMSG size type.
    let size = unsafe { libc::CMSG_SPACE(bytes as u32) as usize };
    vec![0; size.div_ceil(std::mem::size_of::<usize>())]
}

fn receive_files(msg: &libc::msghdr) -> io::Result<Vec<OwnedFd>> {
    let mut files = Vec::new();
    let mut valid = true;
    // SAFETY: msg and its control buffer were produced by successful recvmsg.
    // Native CMSG traversal operates only within that initialized buffer.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let base = libc::CMSG_LEN(0) as usize;
            let len = (*cmsg).cmsg_len as usize;
            let offset = (cmsg as usize).checked_sub(msg.msg_control as usize);
            if len < base
                || offset
                    .and_then(|offset| offset.checked_add(len))
                    .is_none_or(|end| end > msg.msg_controllen as usize)
            {
                return Err(invalid());
            }
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let bytes = len - base;
                valid &= bytes.is_multiple_of(std::mem::size_of::<libc::c_int>());
                let count = bytes / std::mem::size_of::<libc::c_int>();
                let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                for index in 0..count {
                    // Kernel-installed descriptors are distinct, owned by us,
                    // and must be closed even if another header is rejected.
                    files.push(OwnedFd::from_raw_fd(data.add(index).read_unaligned()));
                }
            } else {
                valid = false;
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    for file in &files {
        close_on_exec(file.as_raw_fd())?;
    }
    if !valid {
        return Err(invalid());
    }
    Ok(files)
}

fn close_on_exec(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: caller owns a live descriptor for both synchronous calls.
    // Preserve existing descriptor flags and add close-on-exec.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
