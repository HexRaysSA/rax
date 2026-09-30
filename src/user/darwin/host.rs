//! The host side of file and descriptor calls.
//!
//! On a macOS host a guest call becomes the host's own call with the
//! guest's buffers copied in and out, so the host kernel decides every
//! error and edge case as it would for a native process. On other hosts the
//! Darwin constants are translated by name first.
//!
//! The host process's working directory is kept equal to the guest's
//! (`chdir` and `fchdir` change both), so relative paths and `AT_FDCWD`
//! resolve on the host as they would in the guest.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

/// Darwin `AT_FDCWD`.
pub const AT_FDCWD: i32 = -2;
/// `AT_EACCESS`.
pub const AT_EACCESS: u32 = 0x0010;
/// `AT_SYMLINK_NOFOLLOW`.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x0020;
/// `AT_SYMLINK_FOLLOW`.
pub const AT_SYMLINK_FOLLOW: u32 = 0x0040;
/// `AT_REMOVEDIR`.
pub const AT_REMOVEDIR: u32 = 0x0080;
/// `AT_REALDEV`.
pub const AT_REALDEV: u32 = 0x0200;
/// `AT_FDONLY`.
pub const AT_FDONLY: u32 = 0x0400;
/// `AT_SYMLINK_NOFOLLOW_ANY`.
pub const AT_SYMLINK_NOFOLLOW_ANY: u32 = 0x0800;
/// `AT_RESOLVE_BENEATH`.
pub const AT_RESOLVE_BENEATH: u32 = 0x2000;
