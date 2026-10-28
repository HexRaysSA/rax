//! Host credentials are read from the connected socket, never from a claim
//! in a guest tracing request. Guest cantrace credentials remain separate.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Peer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub(super) fn option<T: Copy>(fd: RawFd, level: i32, name: i32) -> io::Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let mut size = std::mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: the output is writable for exactly size_of::<T>() bytes; only
    // a complete successful kernel output is assumed initialized below.
    if unsafe { libc::getsockopt(fd, level, name, value.as_mut_ptr().cast(), &mut size) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<T>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short peer credentials",
        ));
    }
    Ok(unsafe { value.assume_init() })
}

pub(super) fn peer(stream: &UnixStream) -> io::Result<Peer> {
    let fd = stream.as_raw_fd();
    #[cfg(target_vendor = "apple")]
    let result = {
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: fd is live and both credential outputs are initialized.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Peer {
            pid: option(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID)?,
            uid,
            gid,
        }
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = {
        let cred: libc::ucred = option(fd, libc::SOL_SOCKET, libc::SO_PEERCRED)?;
        Peer {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
        }
    };
    #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
    let result: Peer = return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "authenticated registry peers unavailable",
    ));
    if result.pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "missing peer process identity",
        ));
    }
    Ok(result)
}

pub(super) fn require(stream: &UnixStream, pid: i32, uid: u32) -> io::Result<Peer> {
    let identity = peer(stream)?;
    if identity.pid != pid || identity.uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registry peer identity mismatch",
        ));
    }
    Ok(identity)
}
