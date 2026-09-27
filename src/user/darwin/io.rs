//! Darwin open-file flags and their host equivalents.
//!
//! The values are `bsd/sys/fcntl.h`'s. On a macOS host they are the host's
//! own; elsewhere each flag is translated by name, and a Darwin-only flag
//! (`O_SHLOCK`, `O_EXLOCK`, `O_EVTONLY`, `O_SYMLINK`, ...) is handled by
//! the caller or dropped.

/// `O_RDONLY`.
pub const O_RDONLY: u32 = 0x0000;
/// `O_WRONLY`.
pub const O_WRONLY: u32 = 0x0001;
/// `O_RDWR`.
pub const O_RDWR: u32 = 0x0002;
/// `O_ACCMODE`.
pub const O_ACCMODE: u32 = 0x0003;
/// `O_NONBLOCK`.
pub const O_NONBLOCK: u32 = 0x0004;
/// `O_APPEND`.
pub const O_APPEND: u32 = 0x0008;
/// `O_SHLOCK`.
pub const O_SHLOCK: u32 = 0x0010;
/// `O_EXLOCK`.
pub const O_EXLOCK: u32 = 0x0020;
/// `O_ASYNC`.
pub const O_ASYNC: u32 = 0x0040;
/// `O_SYNC` (`O_FSYNC`).
pub const O_SYNC: u32 = 0x0080;
/// `O_NOFOLLOW`.
pub const O_NOFOLLOW: u32 = 0x0100;
/// `O_CREAT`.
pub const O_CREAT: u32 = 0x0200;
/// `O_TRUNC`.
pub const O_TRUNC: u32 = 0x0400;
/// `O_EXCL`.
pub const O_EXCL: u32 = 0x0800;
/// `O_EVTONLY`.
pub const O_EVTONLY: u32 = 0x8000;
/// `O_NOCTTY`.
pub const O_NOCTTY: u32 = 0x2_0000;
/// `O_DIRECTORY`.
pub const O_DIRECTORY: u32 = 0x10_0000;
/// `O_SYMLINK`.
pub const O_SYMLINK: u32 = 0x20_0000;
/// `O_DSYNC`.
pub const O_DSYNC: u32 = 0x40_0000;
/// `O_CLOEXEC`.
pub const O_CLOEXEC: u32 = 0x100_0000;
/// `O_NOFOLLOW_ANY`.
pub const O_NOFOLLOW_ANY: u32 = 0x2000_0000;
/// `O_EXEC`.
pub const O_EXEC: u32 = 0x4000_0000;

/// The flags `F_GETFL` reports and `F_SETFL` may change.
pub const O_STATUS_FLAGS: u32 = O_NONBLOCK | O_APPEND | O_ASYNC | O_SYNC | O_DSYNC;

/// Host `open` flags for Darwin `flags` (access mode and the flags the host
/// understands).
pub fn guest_to_host_oflags(flags: u32) -> i32 {
    #[cfg(target_os = "macos")]
    {
        flags as i32
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut h = match flags & O_ACCMODE {
            O_WRONLY => libc::O_WRONLY,
            O_RDWR => libc::O_RDWR,
            _ => libc::O_RDONLY,
        };
        let map = [
            (O_NONBLOCK, libc::O_NONBLOCK),
            (O_APPEND, libc::O_APPEND),
            (O_ASYNC, libc::O_ASYNC),
            (O_SYNC, libc::O_SYNC),
            (O_NOFOLLOW, libc::O_NOFOLLOW),
            (O_CREAT, libc::O_CREAT),
            (O_TRUNC, libc::O_TRUNC),
            (O_EXCL, libc::O_EXCL),
            (O_NOCTTY, libc::O_NOCTTY),
            (O_DIRECTORY, libc::O_DIRECTORY),
            (O_DSYNC, libc::O_DSYNC),
            (O_CLOEXEC, libc::O_CLOEXEC),
        ];
        for (g, hf) in map {
            if flags & g != 0 {
                h |= hf;
            }
        }
        h
    }
}

/// Darwin flags for host `F_GETFL` flags.
pub fn host_to_guest_oflags(host: i32) -> u32 {
    #[cfg(target_os = "macos")]
    {
        host as u32
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut g = match host & libc::O_ACCMODE {
            libc::O_WRONLY => O_WRONLY,
            libc::O_RDWR => O_RDWR,
            _ => O_RDONLY,
        };
        let map = [
            (O_NONBLOCK, libc::O_NONBLOCK),
            (O_APPEND, libc::O_APPEND),
            (O_ASYNC, libc::O_ASYNC),
            (O_SYNC, libc::O_SYNC),
            (O_DSYNC, libc::O_DSYNC),
        ];
        for (gf, h) in map {
            if host & h == h && h != 0 {
                g |= gf;
            }
        }
        g
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_the_hosts_on_macos() {
        #[cfg(target_os = "macos")]
        {
            assert_eq!(O_CREAT as i32, libc::O_CREAT);
            assert_eq!(O_CLOEXEC as i32, libc::O_CLOEXEC);
            assert_eq!(O_DIRECTORY as i32, libc::O_DIRECTORY);
            assert_eq!(O_NOFOLLOW as i32, libc::O_NOFOLLOW);
            assert_eq!(O_NONBLOCK as i32, libc::O_NONBLOCK);
            assert_eq!(O_EXCL as i32, libc::O_EXCL);
        }
        let h = guest_to_host_oflags(O_RDWR | O_CREAT | O_APPEND);
        assert_eq!(
            host_to_guest_oflags(h) & (O_ACCMODE | O_APPEND),
            O_RDWR | O_APPEND
        );
    }
}
