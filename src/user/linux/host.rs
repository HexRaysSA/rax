//! Host operating-system services the Linux personality needs beyond `std`.
//!
//! Every `unsafe` foreign call of the personality lives here behind a safe
//! wrapper, so the rest of the subsystem is safe Rust. Each wrapper passes
//! only valid, initialized, properly sized objects and NUL-terminated
//! strings owned for the duration of the call; none of the called functions
//! retain pointers, call back into Rust, or unwind.

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::path::Path;

use super::abi::errno::{Errno, from_host};

fn last_errno() -> Errno {
    Errno(from_host(
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    ))
}

fn cpath(p: &Path) -> Result<CString, Errno> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes()).map_err(|_| Errno(super::abi::errno_table::EINVAL))
}

/// Host clock identifiers `clock_gettime` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostClock {
    /// Wall-clock time.
    Realtime,
    /// Monotonic time since an unspecified point (host boot).
    Monotonic,
    /// CPU time consumed by the emulator process.
    ProcessCpu,
    /// CPU time consumed by the calling host thread.
    ThreadCpu,
}

/// `clock_gettime` on the host, as `(seconds, nanoseconds)`.
pub fn clock_gettime(clock: HostClock) -> (i64, i64) {
    let id = match clock {
        HostClock::Realtime => libc::CLOCK_REALTIME,
        HostClock::Monotonic => libc::CLOCK_MONOTONIC,
        HostClock::ProcessCpu => libc::CLOCK_PROCESS_CPUTIME_ID,
        HostClock::ThreadCpu => libc::CLOCK_THREAD_CPUTIME_ID,
    };
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable `timespec`; the clock IDs are ones
    // every supported host defines, so the call cannot fail.
    let rc = unsafe { libc::clock_gettime(id, &mut ts) };
    debug_assert_eq!(rc, 0);
    (ts.tv_sec as i64, ts.tv_nsec as i64)
}

/// Host clock resolution in nanoseconds.
pub fn clock_getres(clock: HostClock) -> i64 {
    let id = match clock {
        HostClock::Realtime => libc::CLOCK_REALTIME,
        HostClock::Monotonic => libc::CLOCK_MONOTONIC,
        HostClock::ProcessCpu => libc::CLOCK_PROCESS_CPUTIME_ID,
        HostClock::ThreadCpu => libc::CLOCK_THREAD_CPUTIME_ID,
    };
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: as for `clock_gettime`.
    unsafe { libc::clock_getres(id, &mut ts) };
    ts.tv_nsec as i64 + ts.tv_sec as i64 * 1_000_000_000
}

/// Real and effective user and group IDs of the emulator process.
pub fn credentials() -> (u32, u32, u32, u32) {
    // SAFETY: these calls take no arguments and always succeed.
    unsafe {
        (
            libc::getuid() as u32,
            libc::geteuid() as u32,
            libc::getgid() as u32,
            libc::getegid() as u32,
        )
    }
}

/// The emulator process ID.
pub fn pid() -> i32 {
    std::process::id() as i32
}

/// The parent process ID.
pub fn ppid() -> i32 {
    // SAFETY: takes no arguments and always succeeds.
    unsafe { libc::getppid() as i32 }
}

/// The host name (`uname -n`).
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its full length; the host NUL-terminates
    // within `len` or truncates, and we search for the NUL below.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return "localhost".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// `access(2)` on a host path with Linux `mode` bits (which equal the POSIX
/// ones on every supported host). `effective` selects `AT_EACCESS`.
pub fn access(path: &Path, mode: u32, effective: bool, follow: bool) -> Result<(), Errno> {
    let c = cpath(path)?;
    let mut flags = 0;
    if effective {
        flags |= libc::AT_EACCESS;
    }
    if !follow {
        flags |= libc::AT_SYMLINK_NOFOLLOW;
    }
    // SAFETY: `c` is a NUL-terminated path that outlives the call; the mode
    // is limited to R_OK|W_OK|X_OK|F_OK by the caller.
    let rc = unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), mode as libc::c_int, flags) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

/// File-system statistics for `statfs`.
#[derive(Clone, Copy, Debug, Default)]
pub struct FsStats {
    /// Block size.
    pub bsize: u64,
    /// Fragment size.
    pub frsize: u64,
    /// Total blocks.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Blocks available to unprivileged users.
    pub bavail: u64,
    /// Total inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// Maximum name length.
    pub namemax: u64,
    /// Mount flags (`ST_RDONLY`, `ST_NOSUID`).
    pub flags: u64,
}

/// `statvfs(3)` of a host path.
pub fn statvfs(path: &Path) -> Result<FsStats, Errno> {
    let c = cpath(path)?;
    // SAFETY: `statvfs` is plain data; all-zero is a valid initial value.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is NUL-terminated and `st` is a valid, writable struct.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(last_errno());
    }
    Ok(FsStats {
        bsize: st.f_bsize as u64,
        frsize: st.f_frsize as u64,
        blocks: st.f_blocks as u64,
        bfree: st.f_bfree as u64,
        bavail: st.f_bavail as u64,
        files: st.f_files as u64,
        ffree: st.f_ffree as u64,
        namemax: st.f_namemax as u64,
        flags: st.f_flag as u64,
    })
}

/// Terminal window size `(rows, cols, xpixel, ypixel)` of a host terminal.
pub fn window_size(file: &std::fs::File) -> Result<[u16; 4], Errno> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the descriptor is owned by `file` and open for the call;
    // TIOCGWINSZ writes exactly one `winsize` to the valid pointer.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
    if rc != 0 {
        return Err(last_errno());
    }
    Ok([ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel])
}

/// Sets or clears the host `O_NONBLOCK` status flag of an open descriptor.
pub fn set_nonblocking(fd: &impl AsRawFd, on: bool) -> Result<(), Errno> {
    let raw = fd.as_raw_fd();
    // SAFETY: `raw` belongs to an object borrowed for the call; F_GETFL and
    // F_SETFL take and return integer flags only.
    unsafe {
        let flags = libc::fcntl(raw, libc::F_GETFL);
        if flags < 0 {
            return Err(last_errno());
        }
        let new = if on {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if new != flags && libc::fcntl(raw, libc::F_SETFL, new) < 0 {
            return Err(last_errno());
        }
    }
    Ok(())
}

/// The POSIX access mode (`O_RDONLY`/`O_WRONLY`/`O_RDWR`, identical on
/// every supported host and Linux) of an open host descriptor.
pub fn access_mode(fd: &impl AsRawFd) -> Result<u32, Errno> {
    // SAFETY: F_GETFL takes no pointer arguments; the descriptor is borrowed.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(last_errno());
    }
    Ok((flags & libc::O_ACCMODE) as u32)
}

/// Bytes immediately readable from a host descriptor (`FIONREAD`).
pub fn bytes_readable(fd: &impl AsRawFd) -> Result<i32, Errno> {
    let mut n: libc::c_int = 0;
    // SAFETY: FIONREAD writes one `int` to the valid pointer; the descriptor
    // is borrowed for the call.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONREAD, &mut n) };
    if rc != 0 { Err(last_errno()) } else { Ok(n) }
}

/// Readiness of one descriptor, as `poll(2)` reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Readiness {
    /// `POLLIN`.
    pub readable: bool,
    /// `POLLOUT`.
    pub writable: bool,
    /// `POLLHUP`.
    pub hangup: bool,
    /// `POLLERR`.
    pub error: bool,
}

/// Polls host descriptors for readiness, waiting at most `timeout_ms`
/// milliseconds (negative waits indefinitely).
pub fn poll(fds: &[(i32, bool, bool)], timeout_ms: i32) -> Result<Vec<Readiness>, Errno> {
    let mut pfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&(fd, r, w)| libc::pollfd {
            fd,
            events: (if r { libc::POLLIN } else { 0 }) | (if w { libc::POLLOUT } else { 0 }),
            revents: 0,
        })
        .collect();
    // SAFETY: `pfds` is a valid array of `pollfd` of the given length; the
    // descriptors are host descriptors owned by open files the caller holds.
    let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout_ms) };
    if rc < 0 {
        return Err(last_errno());
    }
    Ok(pfds
        .iter()
        .map(|p| Readiness {
            readable: p.revents & libc::POLLIN != 0,
            writable: p.revents & libc::POLLOUT != 0,
            hangup: p.revents & libc::POLLHUP != 0,
            error: p.revents & (libc::POLLERR | libc::POLLNVAL) != 0,
        })
        .collect())
}

/// Resident-set and CPU usage of the emulator process (`getrusage`):
/// `(user_us, system_us, maxrss_kib)`.
pub fn rusage_self() -> (u64, u64, u64) {
    // SAFETY: `rusage` is plain data; zero is a valid initial value.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `ru` is valid and writable; RUSAGE_SELF is always valid.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
    // ru_maxrss is KiB on Linux and bytes on macOS.
    let maxrss = if cfg!(target_os = "macos") {
        ru.ru_maxrss as u64 / 1024
    } else {
        ru.ru_maxrss as u64
    };
    (us(ru.ru_utime), us(ru.ru_stime), maxrss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clocks_advance_and_credentials_resolve() {
        let (a, an) = clock_gettime(HostClock::Monotonic);
        let (b, bn) = clock_gettime(HostClock::Monotonic);
        assert!((b, bn) >= (a, an));
        assert!(clock_gettime(HostClock::Realtime).0 > 1_600_000_000);
        assert!(clock_getres(HostClock::Monotonic) > 0);
        let _ = credentials();
        assert!(!hostname().is_empty());
        assert_eq!(pid(), std::process::id() as i32);
    }

    #[test]
    fn access_and_statvfs_report_host_errors() {
        access(Path::new("/"), 0, false, true).unwrap();
        let e = access(Path::new("/nonexistent/rax"), 0, false, true).unwrap_err();
        assert_eq!(e.0, super::super::abi::errno_table::ENOENT);
        let st = statvfs(Path::new("/")).unwrap();
        assert!(st.bsize > 0 && st.namemax > 0);
    }

    #[test]
    fn poll_reports_pipe_readiness() {
        use std::io::Write;
        let (r, mut w) = std::io::pipe().unwrap();
        let ready = poll(&[(r.as_raw_fd(), true, false)], 0).unwrap();
        assert!(!ready[0].readable);
        w.write_all(b"x").unwrap();
        let ready = poll(&[(r.as_raw_fd(), true, false)], 0).unwrap();
        assert!(ready[0].readable);
        assert_eq!(bytes_readable(&r).unwrap(), 1);
        set_nonblocking(&r, true).unwrap();
    }
}
