//! Darwin error numbers and their translation from the host's.
//!
//! The numbers are those of `bsd/sys/errno.h` (XNU 12377.121.6); a unit test
//! checks every constant here against the generated
//! [`ERRNO_TABLE`](super::tables::ERRNO_TABLE). A host error reaches the
//! guest through [`Errno::from_host`]: on a macOS host the numbering is the
//! guest's own; elsewhere each error is translated by name.

use std::fmt;

/// A Darwin `errno` value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Errno(pub i32);

macro_rules! errnos {
    ($($name:ident = $n:expr),* $(,)?) => {
        impl Errno {
            $(
                #[doc = concat!("`", stringify!($name), "`.")]
                pub const $name: Errno = Errno($n);
            )*

            /// The symbolic name, if the number is defined.
            pub fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($n => Some(stringify!($name)),)*
                    _ => None,
                }
            }
        }

        /// Every constant this module defines, for table checks.
        #[cfg(test)]
        pub(crate) const ALL: &[(&str, i32)] = &[$((stringify!($name), $n)),*];
    };
}

errnos! {
    EPERM = 1, ENOENT = 2, ESRCH = 3, EINTR = 4, EIO = 5, ENXIO = 6, E2BIG = 7,
    ENOEXEC = 8, EBADF = 9, ECHILD = 10, EDEADLK = 11, ENOMEM = 12, EACCES = 13,
    EFAULT = 14, ENOTBLK = 15, EBUSY = 16, EEXIST = 17, EXDEV = 18, ENODEV = 19,
    ENOTDIR = 20, EISDIR = 21, EINVAL = 22, ENFILE = 23, EMFILE = 24, ENOTTY = 25,
    ETXTBSY = 26, EFBIG = 27, ENOSPC = 28, ESPIPE = 29, EROFS = 30, EMLINK = 31,
    EPIPE = 32, EDOM = 33, ERANGE = 34, EAGAIN = 35, EINPROGRESS = 36,
    EALREADY = 37, ENOTSOCK = 38, EDESTADDRREQ = 39, EMSGSIZE = 40,
    EPROTOTYPE = 41, ENOPROTOOPT = 42, EPROTONOSUPPORT = 43,
    ESOCKTNOSUPPORT = 44, ENOTSUP = 45, EPFNOSUPPORT = 46, EAFNOSUPPORT = 47,
    EADDRINUSE = 48, EADDRNOTAVAIL = 49, ENETDOWN = 50, ENETUNREACH = 51,
    ENETRESET = 52, ECONNABORTED = 53, ECONNRESET = 54, ENOBUFS = 55,
    EISCONN = 56, ENOTCONN = 57, ESHUTDOWN = 58, ETOOMANYREFS = 59,
    ETIMEDOUT = 60, ECONNREFUSED = 61, ELOOP = 62, ENAMETOOLONG = 63,
    EHOSTDOWN = 64, EHOSTUNREACH = 65, ENOTEMPTY = 66, EPROCLIM = 67,
    EUSERS = 68, EDQUOT = 69, ESTALE = 70, EREMOTE = 71, EBADRPC = 72,
    ERPCMISMATCH = 73, EPROGUNAVAIL = 74, EPROGMISMATCH = 75, EPROCUNAVAIL = 76,
    ENOLCK = 77, ENOSYS = 78, EFTYPE = 79, EAUTH = 80, ENEEDAUTH = 81,
    EPWROFF = 82, EDEVERR = 83, EOVERFLOW = 84, EBADEXEC = 85, EBADARCH = 86,
    ESHLIBVERS = 87, EBADMACHO = 88, ECANCELED = 89, EIDRM = 90, ENOMSG = 91,
    EILSEQ = 92, ENOATTR = 93, EBADMSG = 94, EMULTIHOP = 95, ENODATA = 96,
    ENOLINK = 97, ENOSR = 98, ENOSTR = 99, EPROTO = 100, ETIME = 101,
    EOPNOTSUPP = 102, ENOPOLICY = 103, ENOTRECOVERABLE = 104, EOWNERDEAD = 105,
    EQFULL = 106,
}

impl Errno {
    /// `EWOULDBLOCK`, an alias of `EAGAIN`.
    pub const EWOULDBLOCK: Errno = Errno::EAGAIN;
    /// `ERESTART`: restart the call (kernel-internal, never returned).
    pub const ERESTART: Errno = Errno(-1);
    /// `EJUSTRETURN`: the registers are already set (kernel-internal).
    pub const EJUSTRETURN: Errno = Errno(-2);

    /// The guest error for a host `errno` value.
    pub fn from_host(host: i32) -> Errno {
        #[cfg(target_os = "macos")]
        {
            Errno(host)
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            from_foreign_host(host)
        }
        #[cfg(not(unix))]
        {
            let _ = host;
            Errno::EIO
        }
    }

    /// Translate supplied-file errors, Unix errno values, or platform-neutral
    /// I/O categories. Unknown categories become `EIO`.
    pub fn from_io(e: &std::io::Error) -> Errno {
        if let Some(error) = e
            .get_ref()
            .and_then(|e| e.downcast_ref::<crate::user::supplied_fs::Error>())
        {
            return Self::from(*error);
        }
        if let Some(error) = e.get_ref().and_then(|e| e.downcast_ref::<Self>()) {
            return *error;
        }
        #[cfg(unix)]
        if let Some(raw) = e.raw_os_error() {
            return Self::from_host(raw);
        }
        use std::io::ErrorKind as K;
        match e.kind() {
            K::NotFound => Self::ENOENT,
            K::PermissionDenied => Self::EACCES,
            K::AlreadyExists => Self::EEXIST,
            K::WouldBlock => Self::EAGAIN,
            K::InvalidInput | K::InvalidData => Self::EINVAL,
            K::Interrupted => Self::EINTR,
            K::Unsupported => Self::ENOSYS,
            K::OutOfMemory => Self::ENOMEM,
            K::BrokenPipe => Self::EPIPE,
            K::TimedOut => Self::ETIMEDOUT,
            _ => Self::EIO,
        }
    }

    /// The error of the host's last failed call.
    pub fn last() -> Errno {
        Errno::from_io(&std::io::Error::last_os_error())
    }
}

impl std::error::Error for Errno {}

impl From<crate::user::supplied_fs::Error> for Errno {
    fn from(error: crate::user::supplied_fs::Error) -> Self {
        use crate::user::supplied_fs::Error as E;
        match error {
            E::InvalidPath => Self::EINVAL,
            E::TooLong => Self::ENAMETOOLONG,
            E::Exists => Self::EEXIST,
            E::NotFound => Self::ENOENT,
            E::NotDirectory => Self::ENOTDIR,
            E::IsDirectory => Self::EISDIR,
        }
    }
}

impl From<std::io::Error> for Errno {
    fn from(e: std::io::Error) -> Self {
        Errno::from_io(&e)
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "Errno({})", self.0),
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Translates a non-Darwin host's error by name; an error Darwin lacks
/// becomes the nearest Darwin error.
#[cfg(all(unix, not(target_os = "macos")))]
fn from_foreign_host(host: i32) -> Errno {
    macro_rules! same {
        ($($name:ident),*) => {
            $(if host == libc::$name { return Errno::$name; })*
        };
    }
    same!(
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
        EDEADLK,
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
        EAGAIN,
        EINPROGRESS,
        EALREADY,
        ENOTSOCK,
        EDESTADDRREQ,
        EMSGSIZE,
        EPROTOTYPE,
        ENOPROTOOPT,
        EPROTONOSUPPORT,
        ESOCKTNOSUPPORT,
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
        ELOOP,
        ENAMETOOLONG,
        EHOSTDOWN,
        EHOSTUNREACH,
        ENOTEMPTY,
        EUSERS,
        EDQUOT,
        ESTALE,
        EREMOTE,
        ENOLCK,
        ENOSYS,
        EOVERFLOW,
        ECANCELED,
        EIDRM,
        ENOMSG,
        EILSEQ,
        EBADMSG,
        EMULTIHOP,
        ENODATA,
        ENOLINK,
        ENOSR,
        ENOSTR,
        EPROTO,
        ETIME,
        EOPNOTSUPP,
        ENOTRECOVERABLE,
        EOWNERDEAD
    );
    // Linux has no separate ENOTSUP, and names ENOATTR ENODATA.
    Errno::EIO
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::darwin::abi::tables::ERRNO_TABLE;

    #[test]
    fn constants_match_the_generated_table() {
        for (name, n) in ALL {
            let row = ERRNO_TABLE
                .iter()
                .find(|(t, _, _)| t == name)
                .unwrap_or_else(|| panic!("{name} is not in errno.h"));
            assert_eq!(row.1, *n, "{name}");
        }
        // Every numbered error of errno.h up to ELAST has a constant.
        for (name, n, _) in ERRNO_TABLE {
            if (1..=106).contains(n) && *name != "EWOULDBLOCK" && *name != "ELAST" {
                assert!(
                    ALL.iter().any(|(_, m)| m == n),
                    "{name} = {n} has no constant"
                );
            }
        }
        assert_eq!(Errno::ENOSYS.name(), Some("ENOSYS"));
        assert_eq!(format!("{:?}", Errno(999)), "Errno(999)");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_host_errors_are_the_guest_errors() {
        assert_eq!(Errno::from_host(libc::ENOENT), Errno::ENOENT);
        assert_eq!(Errno::from_host(libc::EAGAIN), Errno::EAGAIN);
        assert_eq!(Errno::from_host(libc::ENOTSUP), Errno::ENOTSUP);
    }
}
