//! Host-to-Linux `errno` translation.
//!
//! Host system calls report the host's `errno` numbering, which differs from
//! Linux's everywhere except on a Linux host (for example `EAGAIN` is 35 on
//! macOS and 11 on Linux). Translation is by symbolic name, so each value is
//! correct for whichever host the emulator was built for.

use super::errno_table as linux;

/// A Linux `errno` value (positive).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Errno(pub i32);

impl Errno {
    /// The negated value a system call returns in its result register.
    pub fn as_return(self) -> u64 {
        (-(self.0 as i64)) as u64
    }

    /// The kernel's symbolic name.
    pub fn name(self) -> &'static str {
        linux::errno_name(self.0).unwrap_or("E?")
    }
}

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), self.0)
    }
}

impl std::error::Error for Errno {}

impl From<crate::user::supplied_fs::Error> for Errno {
    fn from(error: crate::user::supplied_fs::Error) -> Self {
        use crate::user::supplied_fs::Error as E;
        Self(match error {
            E::InvalidPath => linux::EINVAL,
            E::TooLong => linux::ENAMETOOLONG,
            E::Exists => linux::EEXIST,
            E::NotFound => linux::ENOENT,
            E::NotDirectory => linux::ENOTDIR,
            E::IsDirectory => linux::EISDIR,
        })
    }
}

impl From<std::io::Error> for Errno {
    fn from(e: std::io::Error) -> Self {
        Errno(from_io_error(&e))
    }
}

/// Linux errno for a host `std::io::Error`.
pub fn from_io_error(e: &std::io::Error) -> i32 {
    if let Some(error) = e
        .get_ref()
        .and_then(|e| e.downcast_ref::<crate::user::supplied_fs::Error>())
    {
        return Errno::from(*error).0;
    }
    if let Some(error) = e.get_ref().and_then(|e| e.downcast_ref::<Errno>()) {
        return error.0;
    }
    // Windows raw values are Win32 errors, not Unix errno numbers. Let std's
    // platform adapter classify them before translating to the guest ABI.
    #[cfg(unix)]
    if let Some(raw) = e.raw_os_error() {
        return from_host(raw);
    }
    use std::io::ErrorKind as K;
    match e.kind() {
        K::NotFound => linux::ENOENT,
        K::PermissionDenied => linux::EACCES,
        K::AlreadyExists => linux::EEXIST,
        K::WouldBlock => linux::EAGAIN,
        K::InvalidInput | K::InvalidData => linux::EINVAL,
        K::Interrupted => linux::EINTR,
        K::Unsupported => linux::ENOSYS,
        K::OutOfMemory => linux::ENOMEM,
        K::BrokenPipe => linux::EPIPE,
        K::TimedOut => linux::ETIMEDOUT,
        _ => linux::EIO,
    }
}

/// Linux errno for a host `errno` value.
#[cfg(unix)]
pub fn from_host(err: i32) -> i32 {
    macro_rules! same_name {
        ($($name:ident),* $(,)?) => {
            $(if err == libc::$name { return linux::$name; })*
        };
    }
    // Names defined by both Linux and every supported Unix host.
    same_name!(
        EPERM,
        ENOENT,
        ESRCH,
        EINTR,
        EIO,
        ENXIO,
        E2BIG,
        ENOEXEC,
        EBADF,
        ECHILD,
        EAGAIN,
        ENOMEM,
        EACCES,
        EFAULT,
        ENOTBLK,
        EBUSY,
        EEXIST,
        EXDEV,
        ENODEV,
        ENOTDIR,
        EISDIR,
        EINVAL,
        ENFILE,
        EMFILE,
        ENOTTY,
        ETXTBSY,
        EFBIG,
        ENOSPC,
        ESPIPE,
        EROFS,
        EMLINK,
        EPIPE,
        EDOM,
        ERANGE,
        EDEADLK,
        ENAMETOOLONG,
        ENOLCK,
        ENOSYS,
        ENOTEMPTY,
        ELOOP,
        ENOMSG,
        EIDRM,
        ENOSTR,
        ENODATA,
        ETIME,
        ENOSR,
        EREMOTE,
        ENOLINK,
        EPROTO,
        EMULTIHOP,
        EBADMSG,
        EOVERFLOW,
        EILSEQ,
        EUSERS,
        ENOTSOCK,
        EDESTADDRREQ,
        EMSGSIZE,
        EPROTOTYPE,
        ENOPROTOOPT,
        EPROTONOSUPPORT,
        ESOCKTNOSUPPORT,
        EOPNOTSUPP,
        EPFNOSUPPORT,
        EAFNOSUPPORT,
        EADDRINUSE,
        EADDRNOTAVAIL,
        ENETDOWN,
        ENETUNREACH,
        ENETRESET,
        ECONNABORTED,
        ECONNRESET,
        ENOBUFS,
        EISCONN,
        ENOTCONN,
        ESHUTDOWN,
        ETOOMANYREFS,
        ETIMEDOUT,
        ECONNREFUSED,
        EHOSTDOWN,
        EHOSTUNREACH,
        EALREADY,
        EINPROGRESS,
        ESTALE,
        EDQUOT,
        ECANCELED,
        EOWNERDEAD,
        ENOTRECOVERABLE,
    );
    // Linux defines ENOTSUP as EOPNOTSUPP; some hosts keep them distinct.
    if err == libc::ENOTSUP {
        return linux::EOPNOTSUPP;
    }
    #[cfg(target_vendor = "apple")]
    {
        // Darwin's "attribute not found" is Linux's ENODATA (xattr calls).
        if err == libc::ENOATTR {
            return linux::ENODATA;
        }
        if err == libc::EPROCLIM {
            return linux::EAGAIN;
        }
    }
    linux::EIO
}

/// Linux errno for a host `errno` value (non-Unix hosts report no raw
/// numbering that RAX translates).
#[cfg(not(unix))]
pub fn from_host(_err: i32) -> i32 {
    linux::EIO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translation_uses_linux_numbering() {
        #[cfg(unix)]
        {
            assert_eq!(from_host(libc::EAGAIN), 11);
            assert_eq!(from_host(libc::ENOENT), 2);
            assert_eq!(from_host(libc::ENOTEMPTY), 39);
            assert_eq!(from_host(libc::ELOOP), 40);
            assert_eq!(from_host(libc::ENOSYS), 38);
            assert_eq!(from_host(libc::ETIMEDOUT), 110);
            assert_eq!(from_host(libc::ENOTSUP), 95);
            assert_eq!(from_host(-12345), linux::EIO);
        }
        let e = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(from_io_error(&e), 2);
        assert_eq!(Errno(linux::ENOENT).as_return(), (-2i64) as u64);
        assert_eq!(Errno(linux::EAGAIN).name(), "EAGAIN");
    }

    #[test]
    fn missing_file_maps_through_the_os_error() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rax-user-missing-{}-{nonce}", std::process::id()));
        let err = std::fs::metadata(path).unwrap_err();
        assert_eq!(Errno::from(err), Errno(linux::ENOENT));
    }

    #[cfg(windows)]
    #[test]
    fn win32_errors_are_not_interpreted_as_unix_errno_numbers() {
        for (host, guest) in [(2, linux::ENOENT), (3, linux::ENOENT), (5, linux::EACCES)] {
            assert_eq!(
                from_io_error(&std::io::Error::from_raw_os_error(host)),
                guest
            );
        }
    }
}
