//! POSIX shared memory (`shm_open`, `shm_unlink` in
//! `bsd/kern/posix_shm.c`).
//!
//! The objects are the host's, so a guest shares them by name with every
//! other process on the host, emulated or native, and the host checks the
//! name, flags, and permissions and keeps the object's size. What the
//! host cannot know is the guest program's own: whether its SDK is new
//! enough for undocumented flags to be refused. A guest descriptor for an
//! object is always close-on-exec; its mappings are
//! [`mmap`](super::super::mem::mmap)'s shared-memory kind.

use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{FileKind, OpenFile};
use crate::user::darwin::host::check;
use crate::user::darwin::io::{O_ACCMODE, O_CREAT, O_EXCL, O_RDWR, O_TRUNC};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;

/// `SHM_OPEN_MASK`: the flags `shm_open(2)` documents.
const SHM_OPEN_MASK: u32 = O_RDWR | O_CREAT | O_EXCL | O_TRUNC;

/// Names are copied with room for more than `PSHMNAMLEN`, so that the
/// host sees a long name and refuses it as XNU does.
const NAME_MAX_COPY: usize = 1024;

/// `PLATFORM_*` values (`mach-o/loader.h`).
mod platform {
    pub const MACOS: u32 = 1;
    pub const IOS: u32 = 2;
    pub const TVOS: u32 = 3;
    pub const WATCHOS: u32 = 4;
    pub const BRIDGEOS: u32 = 5;
    pub const MACCATALYST: u32 = 6;
    pub const IOSSIMULATOR: u32 = 7;
    pub const TVOSSIMULATOR: u32 = 8;
    pub const WATCHOSSIMULATOR: u32 = 9;
    pub const DRIVERKIT: u32 = 10;
    pub const XROS: u32 = 11;
    pub const XROSSIMULATOR: u32 = 12;
}

/// `shm_open_should_restrict_flags`: whether the program's SDK is new
/// enough that undocumented flags are refused.
fn restricts_flags(proc: &Proc) -> bool {
    let version = |major: u32, minor: u32| (major << 16) | (minor << 8);
    let Some(build) = proc.program.main.build.as_ref() else {
        return true;
    };
    match build.platform {
        platform::MACOS
        | platform::MACCATALYST
        | platform::IOSSIMULATOR
        | platform::IOS
        | platform::TVOSSIMULATOR
        | platform::TVOS
        | platform::WATCHOSSIMULATOR
        | platform::WATCHOS
        | platform::XROSSIMULATOR
        | platform::XROS => build.sdk >= version(26, 4),
        platform::BRIDGEOS => build.sdk >= version(10, 4),
        platform::DRIVERKIT => build.sdk >= version(25, 4),
        _ => true,
    }
}

/// `shm_open(name, oflag, mode)`.
pub fn shm_open(ctx: &mut Ctx<'_>, name: u64, oflag: u32, mode: u32) -> SysResult {
    let name = ctx.cstr(name, NAME_MAX_COPY)?;
    let cname = CString::new(name).map_err(|_| Errno::EINVAL)?;
    // falloc precedes the flag checks.
    let limit = ctx.proc.rlimits[8].0;
    ctx.proc.fds.lowest_free(0, limit)?;
    let mut oflag = oflag;
    if oflag & !SHM_OPEN_MASK != 0 {
        if restricts_flags(ctx.proc) {
            return Err(Errno::EINVAL);
        }
        // An older program's extra flags have no effect.
        oflag &= SHM_OPEN_MASK;
    }
    // SAFETY: `cname` is NUL-terminated for the call's duration.
    let fd = check(unsafe {
        libc::shm_open(
            cname.as_ptr(),
            crate::user::darwin::host::open_flags(oflag),
            mode as libc::c_uint,
        )
    })?;
    // SAFETY: `fd` was just returned by the host and is owned here; the
    // host descriptor is close-on-exec, as every one the emulator holds.
    let owned = unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        OwnedFd::from_raw_fd(fd)
    };
    let file = Arc::new(OpenFile {
        kind: FileKind::Shm(owned),
        path: None,
        // f_flag keeps the access mode (FMASK), not the open-time flags.
        flags: Mutex::new(oflag & O_ACCMODE),
    });
    let n = ctx.proc.fds.install(file, true, 0, limit)?;
    Ok(Rv::one(n as u64))
}

/// `shm_unlink(name)`.
pub fn shm_unlink(ctx: &mut Ctx<'_>, name: u64) -> SysResult {
    let name = ctx.cstr(name, NAME_MAX_COPY)?;
    let cname = CString::new(name).map_err(|_| Errno::EINVAL)?;
    // SAFETY: `cname` is NUL-terminated for the call's duration.
    check(unsafe { libc::shm_unlink(cname.as_ptr()) })?;
    Ok(Rv::one(0))
}
