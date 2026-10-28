//! Nonblocking connect and kernel-authenticated completion.

use super::{Record, identity};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

#[derive(Debug)]
pub(in super::super) struct Dial {
    stream: Option<UnixStream>,
    pub expected: Record,
    connected: bool,
}

impl Dial {
    pub(super) fn start(path: &Path, expected: Record) -> io::Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: a zero sockaddr_un is initialized before it is passed to
        // connect; its family, path, and platform length are set below.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry socket path too long or contains NUL",
            ));
        }
        address.sun_family = libc::AF_UNIX as _;
        for (dst, src) in address.sun_path.iter_mut().zip(bytes) {
            *dst = *src as _;
        }
        let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
        #[cfg(target_vendor = "apple")]
        {
            address.sun_len = length as _;
        }
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned a newly owned descriptor, adopted once.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        stream.set_nonblocking(true)?;
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { libc::connect(fd, (&raw const address).cast(), length as _) };
        let connected = result == 0;
        if !connected {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error);
            }
        }
        Ok(Self {
            stream: Some(stream),
            expected,
            connected,
        })
    }

    pub fn fd(&self) -> Option<i32> {
        self.stream.as_ref().map(AsRawFd::as_raw_fd)
    }

    pub fn finish(&mut self) -> io::Result<Option<UnixStream>> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| io::Error::other("registry dial already consumed"))?;
        if !self.connected {
            let mut poll = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if poll.revents == 0 {
                return Ok(None);
            }
            if let Some(error) = stream.take_error()? {
                return Err(error);
            }
        }
        identity::require(stream, self.expected.pid, self.expected.uid)?;
        Ok(self.stream.take())
    }
}
