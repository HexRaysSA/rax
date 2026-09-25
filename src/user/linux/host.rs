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

/// The emulator's supplementary group IDs, sorted as `setgroups` leaves
/// them.
pub fn groups() -> Vec<u32> {
    // SAFETY: a null buffer of size 0 asks for the count.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n <= 0 {
        return Vec::new();
    }
    let mut v = vec![0 as libc::gid_t; n as usize];
    // SAFETY: `v` is writable for `n` group IDs.
    let m = unsafe { libc::getgroups(n, v.as_mut_ptr()) };
    v.truncate(m.max(0) as usize);
    let mut g: Vec<u32> = v.into_iter().map(|x| x as u32).collect();
    g.sort_unstable();
    g
}

/// The emulator process ID.
pub fn pid() -> i32 {
    std::process::id() as i32
}

/// Stops the emulator process as a group stop stops a Linux process
/// (`raise(SIGSTOP)`); it resumes when the host continues it.
pub fn stop_self() {
    // SAFETY: raise has no memory-safety preconditions; SIGSTOP cannot be
    // caught, so no handler runs and the call returns once the process is
    // continued.
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
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

/// `tee(2)` between two host pipes, never sleeping
/// (`SPLICE_F_NONBLOCK`): the bytes copied.
#[cfg(target_os = "linux")]
pub fn tee(fd_in: i32, fd_out: i32, len: usize) -> Result<usize, Errno> {
    // SAFETY: tee takes two descriptors, a length, and flags; no memory.
    let n = unsafe { libc::tee(fd_in, fd_out, len, libc::SPLICE_F_NONBLOCK) };
    if n < 0 {
        Err(last_errno())
    } else {
        Ok(n as usize)
    }
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

impl Readiness {
    /// Whether any condition is reported.
    pub fn any(&self) -> bool {
        self.readable || self.writable || self.hangup || self.error
    }
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

// ---------------------------------------------------------------------
// Host signals
// ---------------------------------------------------------------------

/// Linux signal numbers and the host's numbers for the same signals. The
/// numbering differs between Linux and other Unix hosts (for example
/// `SIGUSR1` is 10 on Linux and 30 on macOS).
const SIGNAL_MAP: &[(i32, libc::c_int)] = &[
    (1, libc::SIGHUP),
    (2, libc::SIGINT),
    (3, libc::SIGQUIT),
    (4, libc::SIGILL),
    (5, libc::SIGTRAP),
    (6, libc::SIGABRT),
    (7, libc::SIGBUS),
    (8, libc::SIGFPE),
    (9, libc::SIGKILL),
    (10, libc::SIGUSR1),
    (11, libc::SIGSEGV),
    (12, libc::SIGUSR2),
    (13, libc::SIGPIPE),
    (14, libc::SIGALRM),
    (15, libc::SIGTERM),
    (17, libc::SIGCHLD),
    (18, libc::SIGCONT),
    (19, libc::SIGSTOP),
    (20, libc::SIGTSTP),
    (21, libc::SIGTTIN),
    (22, libc::SIGTTOU),
    (23, libc::SIGURG),
    (24, libc::SIGXCPU),
    (25, libc::SIGXFSZ),
    (26, libc::SIGVTALRM),
    (27, libc::SIGPROF),
    (28, libc::SIGWINCH),
    (29, libc::SIGIO),
    (31, libc::SIGSYS),
];

/// The host signals forwarded to the guest: the asynchronous signals other
/// processes, the terminal, and host resource limits send. Fault signals
/// (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`, `SIGTRAP`) and `SIGABRT` keep
/// their host dispositions: on the host they mean the emulator itself
/// failed. `SIGPIPE` stays ignored (the personality raises the guest's
/// `SIGPIPE` itself) and `SIGCHLD` has no guest children to report.
const FORWARDED: &[i32] = &[
    1, 2, 3, 10, 12, 14, 15, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
];

/// The host `si_code` values of a signal another process sent with `kill`.
/// XNU's header defines `SI_USER` as 0x10001, but its `kill(2)` delivers
/// `si_code` 0 (observed on Darwin 27.0.0); both are accepted.
#[cfg(target_vendor = "apple")]
const HOST_SI_USER: [libc::c_int; 2] = [0, 0x10001];
#[cfg(not(target_vendor = "apple"))]
const HOST_SI_USER: [libc::c_int; 1] = [libc::SI_USER];

/// The host signal number of Linux signal `sig`.
pub fn host_signal(sig: i32) -> Option<libc::c_int> {
    SIGNAL_MAP.iter().find(|&&(l, _)| l == sig).map(|&(_, h)| h)
}

/// The Linux signal number of host signal `host`.
pub fn linux_signal(host: libc::c_int) -> Option<i32> {
    SIGNAL_MAP
        .iter()
        .find(|&&(_, h)| h == host)
        .map(|&(l, _)| l)
}

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// Linux-numbered bits of forwarded signals received and not yet taken.
static HOST_PENDING: AtomicU64 = AtomicU64::new(0);
/// Per signal, the sender as `pid << 32 | uid` and a flag in bit 63's
/// place: whether the host reported a `kill` from a process.
static HOST_SENDER: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
/// Per signal, the `si_code` and `si_value` a `rax-user` sender posted
/// (0 for `SI_USER`).
static HOST_CODE: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static HOST_VALUE: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
/// The write end of the wake pipe (-1 before installation).
static WAKE_WRITE: AtomicI32 = AtomicI32::new(-1);
/// The read end of the wake pipe.
static WAKE_READ: AtomicI32 = AtomicI32::new(-1);

#[cfg(target_vendor = "apple")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: returns the calling thread's errno slot; always valid.
    unsafe { libc::__error() }
}

#[cfg(not(target_vendor = "apple"))]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: returns the calling thread's errno slot; always valid.
    unsafe { libc::__errno_location() }
}

/// The handler of forwarded host signals. It is async-signal-safe: it
/// only touches lock-free atomics and calls `write(2)`, and it preserves
/// `errno` for the interrupted code.
extern "C" fn on_host_signal(host: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    let Some(sig) = linux_signal(host) else {
        return;
    };
    let errno = errno_location();
    // SAFETY: the kernel passes a valid siginfo_t for SA_SIGINFO handlers;
    // errno_location is the thread's errno slot.
    let (saved, code, pid, uid) =
        unsafe { (*errno, (*info).si_code, (*info).si_pid(), (*info).si_uid()) };
    // A rax-user sender's own record first (see `sigmail`), then the
    // host's report of a process's kill.
    let sent = super::sigmail::claim(sig);
    let (sent_code, value) = sent.map_or((0, 0), |s| (s.code, s.value));
    let sender = sent
        .map(|s| s.sender)
        .or_else(|| (HOST_SI_USER.contains(&code) && pid > 0).then_some((pid, uid)));
    let packed = match sender {
        Some((pid, uid)) => (1 << 63) | ((pid as u64 & 0x7fff_ffff) << 32) | u64::from(uid),
        None => 0,
    };
    HOST_SENDER[(sig - 1) as usize].store(packed, Ordering::Relaxed);
    HOST_CODE[(sig - 1) as usize].store(u64::from(sent_code as u32), Ordering::Relaxed);
    HOST_VALUE[(sig - 1) as usize].store(value, Ordering::Relaxed);
    HOST_PENDING.fetch_or(1 << (sig - 1), Ordering::SeqCst);
    wake();
    // SAFETY: as above.
    unsafe {
        *errno = saved;
    }
}

/// A non-blocking, close-on-exec host pipe as `(read, write)`.
fn nonblocking_pipe() -> Result<(libc::c_int, libc::c_int), Errno> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid two-element array; F_SETFL/F_SETFD take
    // integer flags on the descriptors pipe(2) just returned.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(last_errno());
        }
        for fd in fds {
            libc::fcntl(
                fd,
                libc::F_SETFL,
                libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
            );
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    Ok((fds[0], fds[1]))
}

/// Creates the wake pipe unless it exists.
fn ensure_wake_pipe() -> Result<(), Errno> {
    if WAKE_READ.load(Ordering::SeqCst) >= 0 {
        return Ok(());
    }
    let (r, w) = nonblocking_pipe()?;
    WAKE_READ.store(r, Ordering::SeqCst);
    WAKE_WRITE.store(w, Ordering::SeqCst);
    Ok(())
}

/// Writes a byte to the wake pipe (async-signal-safe).
fn wake() {
    let fd = WAKE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: write(2) is async-signal-safe; `byte` is valid for one
        // byte. A full pipe (EAGAIN) already wakes its reader.
        unsafe {
            libc::write(fd, (&raw const byte).cast(), 1);
        }
    }
}

/// Whether [`forward_host_signals`] installed its handlers.
static FORWARDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether forwarded host signals are installed.
pub fn forwarding() -> bool {
    FORWARDING.load(Ordering::SeqCst)
}

/// Installs the forwarding handler for [`FORWARDED`] signals and creates the
/// wake pipe. Handlers are installed without `SA_RESTART`, so a blocking
/// host call returns `EINTR` and a wait on the wake pipe ends. Calling it
/// again has no effect.
pub fn forward_host_signals() -> Result<(), Errno> {
    if FORWARDING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    super::sigmail::init()?;
    ensure_wake_pipe()?;
    for &sig in FORWARDED {
        let Some(host) = host_signal(sig) else {
            continue;
        };
        // SAFETY: `sa` is fully initialized (zeroed, then handler, flags,
        // and an empty mask set); the handler has the SA_SIGINFO signature.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_host_signal as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(host, &sa, std::ptr::null_mut()) != 0 {
                return Err(last_errno());
            }
        }
    }
    Ok(())
}

/// The read end of the wake pipe, once [`forward_host_signals`] ran.
pub fn wake_fd() -> Option<i32> {
    let fd = WAKE_READ.load(Ordering::SeqCst);
    (fd >= 0).then_some(fd)
}

/// Empties the wake pipe.
pub fn drain_wake() {
    let Some(fd) = wake_fd() else {
        return;
    };
    let mut buf = [0u8; 64];
    // SAFETY: `buf` is writable for its length; the descriptor is the
    // non-blocking wake pipe this module owns.
    while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
}

/// A forwarded host signal: the Linux number and, when another process
/// sent it with `kill`, that process's PID and real UID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSignal {
    /// Linux signal number.
    pub sig: i32,
    /// `(pid, uid)` of a sending process.
    pub sender: Option<(i32, u32)>,
    /// The `si_code` a `rax-user` sender gave it (0: `SI_USER`).
    pub code: i32,
    /// Its `si_value`.
    pub value: u64,
}

/// Takes the forwarded signals received since the last call, lowest number
/// first.
pub fn take_host_signals() -> Vec<HostSignal> {
    let pending = HOST_PENDING.swap(0, Ordering::SeqCst);
    (0..64)
        .filter(|i| pending & (1 << i) != 0)
        .map(|i| {
            let packed = HOST_SENDER[i].load(Ordering::Relaxed);
            let sender =
                (packed >> 63 != 0).then(|| (((packed >> 32) & 0x7fff_ffff) as i32, packed as u32));
            HostSignal {
                sig: i as i32 + 1,
                sender,
                code: HOST_CODE[i].load(Ordering::Relaxed) as u32 as i32,
                value: HOST_VALUE[i].load(Ordering::Relaxed),
            }
        })
        .collect()
}

/// Ends the emulator process by Linux signal `sig` as the guest was ended,
/// so the parent observes a signal death: the host disposition is reset,
/// the signal unblocked, and the signal raised. Returns only if the host
/// has no equivalent signal or the process survived it. Callers use it for
/// signals whose default action does not dump core: a core-dumping death of
/// the emulator would make the host record a crash report or core of the
/// emulator itself (macOS ReportCrash, a piped `core_pattern`).
pub fn die_by_signal(sig: i32) {
    let Some(host) = host_signal(sig) else {
        return;
    };
    // SAFETY: plain integer and fully initialized sigset arguments; the
    // process is about to terminate.
    unsafe {
        libc::signal(host, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, host);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(host);
    }
}

// ------------------------------------------------------ child processes

/// Set by the host `SIGCHLD` handler: a child process changed state.
static CHILD_EVENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The host `SIGCHLD` handler: records the event and wakes a sleeping
/// scheduler (async-signal-safe; preserves `errno`).
extern "C" fn on_child_signal(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    let errno = errno_location();
    // SAFETY: errno_location is the thread's errno slot.
    let saved = unsafe { *errno };
    CHILD_EVENT.store(true, Ordering::SeqCst);
    wake();
    // SAFETY: as above.
    unsafe {
        *errno = saved;
    }
}

/// Watches the emulator's child processes: installs the host `SIGCHLD`
/// handler (without `SA_RESTART` or `SA_NOCLDSTOP`, so stops and
/// continuations are reported too) and the wake pipe. Idempotent.
pub fn watch_children() -> Result<(), Errno> {
    static WATCHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if WATCHING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    ensure_wake_pipe()?;
    // SAFETY: `sa` is fully initialized; the handler has the SA_SIGINFO
    // signature.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_child_signal as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) != 0 {
            return Err(last_errno());
        }
    }
    Ok(())
}

/// Takes the child-event flag.
pub fn take_child_event() -> bool {
    CHILD_EVENT.swap(false, Ordering::SeqCst)
}

/// A host pipe carrying a forked child's status records to its parent:
/// `(read end, non-blocking; write end)`, both close-on-exec.
pub fn status_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), Errno> {
    use std::os::fd::FromRawFd;
    let (r, w) = nonblocking_pipe()?;
    // SAFETY: pipe(2) just returned these descriptors, owned by nobody else.
    unsafe {
        let w = std::os::fd::OwnedFd::from_raw_fd(w);
        set_nonblocking(&w, false)?;
        Ok((std::os::fd::OwnedFd::from_raw_fd(r), w))
    }
}

/// A tracing link's two ends: a connected pair of non-blocking,
/// close-on-exec `AF_UNIX` stream sockets that raise no `SIGPIPE`.
pub fn link_pair() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), Errno> {
    use std::os::fd::FromRawFd;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: socketpair writes two descriptors into `fds`, which outlives
    // the call.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: socketpair just returned these descriptors, owned by nobody
    // else.
    let (a, b) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    };
    for f in [&a, &b] {
        set_nonblocking(f, true)?;
        // SAFETY: F_SETFD takes an integer flag; the descriptor is borrowed.
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        #[cfg(target_vendor = "apple")]
        {
            let one: libc::c_int = 1;
            // SAFETY: the option value is a valid int for the call.
            unsafe {
                libc::setsockopt(
                    f.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&one as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
        }
    }
    Ok((a, b))
}

/// Writes all of `data` to a non-blocking socket, waiting for room.
pub fn write_all_waiting(fd: &impl AsRawFd, data: &[u8]) -> Result<(), Errno> {
    #[cfg(target_os = "linux")]
    let quiet = libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let quiet = 0;
    let mut at = 0;
    while at < data.len() {
        let rest = &data[at..];
        // SAFETY: `rest` is readable for its length; the descriptor is
        // borrowed for the call.
        let n = unsafe { libc::send(fd.as_raw_fd(), rest.as_ptr().cast(), rest.len(), quiet) };
        if n > 0 {
            at += n as usize;
            continue;
        }
        match last_errno() {
            Errno(EINTR) => {}
            Errno(EAGAIN) => {
                poll(&[(fd.as_raw_fd(), false, true)], -1)?;
            }
            e => return Err(e),
        }
    }
    Ok(())
}

/// One `read(2)` of a non-blocking descriptor.
pub fn read_nonblocking(fd: &impl AsRawFd, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: `buf` is writable for its length; the descriptor is borrowed.
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(last_errno())
    } else {
        Ok(n as usize)
    }
}

/// Forks the emulator: `Some(pid)` in the parent, `None` in the child. The
/// child gets its own wake pipe (the inherited one is the parent's) and no
/// pending host events. The emulator runs one host thread, so the child is
/// a complete copy.
///
/// The forwarded host signals and `SIGCHLD` stay blocked from before the
/// fork until each process is ready: a signal sent to the child as soon as
/// it exists (the parent may `kill` it at once) stays pending in the host
/// kernel until the child has discarded the parent's records, instead of
/// being recorded and then discarded with them.
pub fn fork_process() -> Result<Option<i32>, Errno> {
    // SAFETY: the sets are fully initialized by sigemptyset before use;
    // pthread_sigmask only reads `block` and writes `old`.
    let old = unsafe {
        let mut block: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut block);
        for &sig in FORWARDED {
            if let Some(host) = host_signal(sig) {
                libc::sigaddset(&mut block, host);
            }
        }
        libc::sigaddset(&mut block, libc::SIGCHLD);
        libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut old);
        old
    };
    let restore = || {
        // SAFETY: `old` is the mask pthread_sigmask returned above.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        }
    };
    // Records posted from now on may be for the child.
    let stamp = super::sigmail::stamp();
    // SAFETY: fork(2) in a single-threaded process; the child only uses
    // async-signal-safe calls until it has reinitialized the state below,
    // and then continues the same single-threaded program.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let e = last_errno();
        restore();
        return Err(e);
    }
    if pid > 0 {
        restore();
        return Ok(Some(pid));
    }
    // The child: its own wake pipe, no inherited events.
    let (old_r, old_w) = (
        WAKE_READ.swap(-1, Ordering::SeqCst),
        WAKE_WRITE.swap(-1, Ordering::SeqCst),
    );
    // SAFETY: the inherited descriptors belong to this module; the child
    // closes its copies.
    unsafe {
        if old_r >= 0 {
            libc::close(old_r);
        }
        if old_w >= 0 {
            libc::close(old_w);
        }
    }
    HOST_PENDING.store(0, Ordering::SeqCst);
    CHILD_EVENT.store(false, Ordering::SeqCst);
    super::sigmail::set_floor(stamp);
    let pipe = if old_r >= 0 {
        ensure_wake_pipe()
    } else {
        Ok(())
    };
    restore();
    pipe.map(|()| None)
}

/// A child process's state change, as `waitpid` reports it, in Linux
/// signal numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostWait {
    /// Exited with this code.
    Exited(i32),
    /// Killed by this signal; whether it dumped core.
    Signaled(i32, bool),
    /// Stopped by this signal.
    Stopped(i32),
    /// Continued.
    Continued,
}

/// Resource use of a reaped child: user and system microseconds, maximum
/// resident size in KiB.
pub type ChildRusage = (u64, u64, u64);

/// `wait4(pid, WNOHANG | WUNTRACED | WCONTINUED)`: the child's next state
/// change, if any, and its resource use once it ended.
pub fn wait_child(pid: i32) -> Result<Option<(HostWait, ChildRusage)>, Errno> {
    let mut status = 0;
    // SAFETY: `rusage` is plain data.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers to `status` and `ru`.
    let r = unsafe {
        libc::wait4(
            pid,
            &mut status,
            libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED,
            &mut ru,
        )
    };
    if r < 0 {
        return Err(last_errno());
    }
    if r == 0 {
        return Ok(None);
    }
    let map = |host: i32| linux_signal(host).unwrap_or(host);
    let w = if libc::WIFEXITED(status) {
        HostWait::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        HostWait::Signaled(map(libc::WTERMSIG(status)), libc::WCOREDUMP(status))
    } else if libc::WIFSTOPPED(status) {
        HostWait::Stopped(map(libc::WSTOPSIG(status)))
    } else {
        HostWait::Continued
    };
    let us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
    let maxrss = if cfg!(target_os = "macos") {
        ru.ru_maxrss as u64 / 1024
    } else {
        ru.ru_maxrss as u64
    };
    Ok(Some((w, (us(ru.ru_utime), us(ru.ru_stime), maxrss))))
}

/// Linux signal `sig` from process `sender` (`(pid, real UID)`) to process
/// `pid` through the host, its sender posted for a `rax-user` target (see
/// [`sigmail`](super::sigmail)).
pub fn send(pid: i32, sig: i32, sender: (i32, u32)) -> Result<(), Errno> {
    send_sent(
        pid,
        sig,
        super::sigmail::Sent {
            sender,
            code: 0,
            value: 0,
        },
    )
}

/// Linux signal `sig` to process `pid` through the host, with the sender,
/// `si_code`, and `si_value` of `sent` posted for a `rax-user` target.
pub fn send_sent(pid: i32, sig: i32, sent: super::sigmail::Sent) -> Result<(), Errno> {
    let post = super::sigmail::post_sent(pid, sig, sent);
    let r = kill(pid, sig);
    if r.is_err()
        && let Some(p) = post
    {
        super::sigmail::withdraw(p);
    }
    r
}

/// `kill(pid, sig)` on the host with Linux signal `sig` (0 probes). A
/// signal the host lacks is `EINVAL`.
pub fn kill(pid: i32, sig: i32) -> Result<(), Errno> {
    let host = if sig == 0 {
        0
    } else {
        host_signal(sig).ok_or(Errno(super::abi::errno_table::EINVAL))?
    };
    // SAFETY: plain integer arguments.
    if unsafe { libc::kill(pid, host) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `setpgid`.
pub fn setpgid(pid: i32, pgid: i32) -> Result<(), Errno> {
    // SAFETY: plain integer arguments.
    if unsafe { libc::setpgid(pid, pgid) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `getpgid`.
pub fn getpgid(pid: i32) -> Result<i32, Errno> {
    // SAFETY: plain integer argument.
    let r = unsafe { libc::getpgid(pid) };
    if r < 0 {
        return Err(last_errno());
    }
    Ok(r)
}

/// `setsid`.
pub fn setsid() -> Result<i32, Errno> {
    // SAFETY: no arguments.
    let r = unsafe { libc::setsid() };
    if r < 0 {
        return Err(last_errno());
    }
    Ok(r)
}

/// `getsid`.
pub fn getsid(pid: i32) -> Result<i32, Errno> {
    // SAFETY: plain integer argument.
    let r = unsafe { libc::getsid(pid) };
    if r < 0 {
        return Err(last_errno());
    }
    Ok(r)
}

/// Ends the emulator process at once with `code`, without running exit
/// handlers or destructors (a forked child must not run its parent's
/// cleanup).
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit(2) never returns.
    unsafe { libc::_exit(code) }
}

/// Sends Linux signal `sig` (0 probes) to process group `pgid`, which
/// contains the emulator, except the emulator itself: its copy of the host
/// signal is blocked and consumed. `SIGKILL` and `SIGSTOP` cannot be
/// blocked and act on the emulator as on the group.
pub fn kill_group_but_self(pgid: i32, sig: i32) -> Result<(), Errno> {
    if sig == 0 {
        // SAFETY: plain integer arguments.
        return if unsafe { libc::kill(-pgid, 0) } != 0 {
            Err(last_errno())
        } else {
            Ok(())
        };
    }
    let host = host_signal(sig).ok_or(Errno(super::abi::errno_table::EINVAL))?;
    if host == libc::SIGKILL || host == libc::SIGSTOP {
        // SAFETY: plain integer arguments.
        return if unsafe { libc::kill(-pgid, host) } != 0 {
            Err(last_errno())
        } else {
            Ok(())
        };
    }
    // SAFETY: fully initialized signal sets; the blocked copy the kernel
    // queues for this process before kill returns is consumed by sigwait,
    // then the previous mask comes back.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, host);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        let r = libc::kill(-pgid, host);
        let err = (r != 0).then(last_errno);
        if r == 0 {
            let mut pending: libc::sigset_t = std::mem::zeroed();
            libc::sigpending(&mut pending);
            if libc::sigismember(&pending, host) == 1 {
                let mut got = 0;
                libc::sigwait(&set, &mut got);
            }
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        err.map_or(Ok(()), Err)
    }
}

/// Anonymous memory shared with every process forked from this one
/// (`MAP_SHARED | MAP_ANONYMOUS`), as 64-bit atomic words: the state of an
/// object that stays one object across `fork`, as a Linux open file
/// description does.
pub struct SharedWords {
    ptr: std::ptr::NonNull<std::sync::atomic::AtomicU64>,
    len: usize,
}

// SAFETY: the words are only ever accessed through atomic operations, from
// any thread or process.
unsafe impl Send for SharedWords {}
// SAFETY: as above.
unsafe impl Sync for SharedWords {}

impl SharedWords {
    /// Maps `len` zeroed words.
    pub fn new(len: usize) -> Result<Self, Errno> {
        let bytes = len.max(1) * 8;
        // SAFETY: an anonymous mapping with no address hint and no file;
        // the result is checked before use.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(last_errno());
        }
        let ptr = std::ptr::NonNull::new(p.cast()).ok_or(Errno(super::abi::errno_table::ENOMEM))?;
        Ok(SharedWords { ptr, len })
    }

    /// The words.
    pub fn words(&self) -> &[std::sync::atomic::AtomicU64] {
        // SAFETY: the mapping is page-aligned (so aligned for `AtomicU64`,
        // which has `u64`'s size and alignment), `len` words long,
        // zero-filled when created (a valid value), and unmapped only when
        // `self` drops. Other processes change it only atomically.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for SharedWords {
    fn drop(&mut self) {
        // SAFETY: the mapping `new` created, unmapped once; no reference
        // from `words` outlives `self`.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len.max(1) * 8);
        }
    }
}

impl std::fmt::Debug for SharedWords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedWords")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// A connected pair of non-blocking, close-on-exec host stream sockets. A
/// byte written to one end makes the other readable, so each direction can
/// serve as a level other threads and forked processes wait for in `poll`
/// without consuming it.
pub fn level_pair() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), Errno> {
    use std::os::fd::FromRawFd;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid two-element array; F_SETFL/F_SETFD take
    // integer flags on the descriptors socketpair(2) just returned, which
    // are then owned exactly once.
    unsafe {
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) != 0 {
            return Err(last_errno());
        }
        for fd in fds {
            libc::fcntl(
                fd,
                libc::F_SETFL,
                libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
            );
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        Ok((
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        ))
    }
}

/// Writes one byte to a non-blocking descriptor.
pub fn put_byte(fd: i32) {
    // SAFETY: a one-byte buffer that outlives the call.
    unsafe {
        libc::write(fd, [1u8].as_ptr().cast(), 1);
    }
}

/// Reads one byte from a non-blocking descriptor, if there is one.
pub fn take_byte(fd: i32) {
    let mut b = [0u8];
    // SAFETY: a one-byte writable buffer that outlives the call.
    unsafe {
        libc::read(fd, b.as_mut_ptr().cast(), 1);
    }
}

/// Makes descriptor number `target` refer to `with`'s open file (closing
/// what it referred to), close-on-exec, and closes `with`.
pub fn replace_fd(target: i32, with: std::os::fd::OwnedFd) -> Result<(), Errno> {
    // SAFETY: dup2 and F_SETFD take integer descriptors; `with` stays open
    // across both calls and is closed once, when dropped.
    unsafe {
        if libc::dup2(with.as_raw_fd(), target) < 0 {
            return Err(last_errno());
        }
        libc::fcntl(target, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok(())
}

/// A watch for the end of a host process: a descriptor that becomes
/// readable, and stays so, once the process has exited — a pidfd on Linux,
/// a kqueue holding an `EVFILT_PROC`/`NOTE_EXIT` filter on macOS.
///
/// A macOS kqueue does not survive `fork` (the child's copy of the
/// descriptor is closed, and its number may be reused), so a watch is only
/// used and closed by the process that made it there.
#[derive(Debug)]
pub struct ExitWatch {
    fd: libc::c_int,
    owner: i32,
}

impl ExitWatch {
    /// Watches process `target`; `Ok(None)` when it no longer exists (or
    /// has already exited).
    pub fn new(target: i32) -> Result<Option<Self>, Errno> {
        use super::abi::errno_table::ESRCH;
        let gone = |e: Errno| if e.0 == ESRCH { Ok(None) } else { Err(e) };
        #[cfg(target_os = "linux")]
        let fd = {
            // SAFETY: pidfd_open takes two integers and returns a new
            // close-on-exec descriptor or -1.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_open,
                    target as libc::c_long,
                    0 as libc::c_long,
                )
            };
            if fd < 0 {
                return gone(last_errno());
            }
            fd as libc::c_int
        };
        #[cfg(not(target_os = "linux"))]
        let fd = {
            // SAFETY: kqueue takes no arguments.
            let kq = unsafe { libc::kqueue() };
            if kq < 0 {
                return Err(last_errno());
            }
            // SAFETY: kevent is plain data.
            let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
            ev.ident = target as libc::uintptr_t;
            ev.filter = libc::EVFILT_PROC;
            ev.flags = libc::EV_ADD;
            ev.fflags = libc::NOTE_EXIT;
            // SAFETY: one fully initialized change record is read; no
            // events are written (count 0).
            let r = unsafe { libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            if r != 0 {
                let e = last_errno();
                // SAFETY: the descriptor kqueue just returned, owned here.
                unsafe { libc::close(kq) };
                return gone(e);
            }
            // SAFETY: integer arguments on the descriptor owned here.
            unsafe { libc::fcntl(kq, libc::F_SETFD, libc::FD_CLOEXEC) };
            kq
        };
        Ok(Some(ExitWatch { fd, owner: pid() }))
    }

    /// Whether this process may use the descriptor.
    fn usable(&self) -> bool {
        cfg!(target_os = "linux") || self.owner == pid()
    }

    /// The descriptor, readable once the process has exited; `None` in a
    /// process that cannot use it.
    pub fn fd(&self) -> Option<i32> {
        self.usable().then_some(self.fd)
    }

    /// Whether the process has exited; `None` in a process that cannot use
    /// the watch.
    pub fn exited(&self) -> Option<bool> {
        let fd = self.fd()?;
        Some(poll(&[(fd, true, false)], 0).is_ok_and(|r| r.first().is_some_and(|x| x.readable)))
    }
}

impl Drop for ExitWatch {
    fn drop(&mut self) {
        if self.usable() {
            // SAFETY: the descriptor `new` made, closed once by its owner.
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// What the host reports of another process: its parent and its real,
/// effective, and saved user and group IDs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcIds {
    /// Parent process ID.
    pub ppid: i32,
    /// Real, effective, and saved user IDs.
    pub uids: (u32, u32, u32),
    /// Real, effective, and saved group IDs.
    pub gids: (u32, u32, u32),
}

/// The parent and credentials of host process `pid`.
#[cfg(target_os = "linux")]
pub fn proc_ids(pid: i32) -> Result<ProcIds, Errno> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let mut ids = ProcIds::default();
    let field = |line: &str, i: usize| -> u32 {
        line.split_whitespace()
            .nth(i)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    for line in text.lines() {
        if line.starts_with("PPid:") {
            ids.ppid = field(line, 1) as i32;
        } else if line.starts_with("Uid:") {
            ids.uids = (field(line, 1), field(line, 2), field(line, 3));
        } else if line.starts_with("Gid:") {
            ids.gids = (field(line, 1), field(line, 2), field(line, 3));
        }
    }
    Ok(ids)
}

/// The parent and credentials of host process `pid`.
#[cfg(not(target_os = "linux"))]
pub fn proc_ids(pid: i32) -> Result<ProcIds, Errno> {
    // SAFETY: proc_bsdinfo is plain data.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is writable for `size` bytes, which proc_pidinfo fills
    // at most.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if n != size {
        let e = last_errno();
        return Err(if e.0 == 0 {
            Errno(super::abi::errno_table::ESRCH)
        } else {
            e
        });
    }
    Ok(ProcIds {
        ppid: info.pbi_ppid as i32,
        uids: (info.pbi_ruid, info.pbi_uid, info.pbi_svuid),
        gids: (info.pbi_rgid, info.pbi_gid, info.pbi_svgid),
    })
}

/// The emulator's host umask, read once. The host applies it to every
/// object the emulator creates, beneath the guest's own.
pub fn umask() -> u32 {
    static MASK: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *MASK.get_or_init(|| {
        // SAFETY: umask only swaps the process's mask; the old one comes
        // back at once.
        unsafe {
            let m = libc::umask(0o022);
            libc::umask(m);
            u32::from(m)
        }
    })
}

/// `mknod(path, mode, makedev(major, minor))` on the host.
pub fn mknod(path: &Path, mode: u32, major: u32, minor: u32) -> Result<(), Errno> {
    let c = cpath(path)?;
    #[cfg(target_os = "linux")]
    let dev = libc::makedev(major, minor);
    #[cfg(not(target_os = "linux"))]
    let dev = libc::makedev(major as i32, minor as i32);
    // SAFETY: a NUL-terminated path owned for the call and integer
    // arguments.
    if unsafe { libc::mknod(c.as_ptr(), mode as libc::mode_t, dev) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// One time `utimensat` sets: the current time, none, or seconds and
/// nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetTime {
    /// `UTIME_NOW`.
    Now,
    /// `UTIME_OMIT`.
    Omit,
    /// A time.
    At(i64, i64),
}

fn host_times(t: [SetTime; 2]) -> [libc::timespec; 2] {
    t.map(|t| {
        let (sec, nsec) = match t {
            SetTime::Now => (0, libc::UTIME_NOW),
            SetTime::Omit => (0, libc::UTIME_OMIT),
            SetTime::At(s, n) => (s, n as libc::c_long),
        };
        libc::timespec {
            tv_sec: sec as libc::time_t,
            tv_nsec: nsec,
        }
    })
}

/// `utimensat(AT_FDCWD, path, times)` on the host, following a final
/// symbolic link when `follow`.
pub fn set_times(path: &Path, t: [SetTime; 2], follow: bool) -> Result<(), Errno> {
    let c = cpath(path)?;
    let ts = host_times(t);
    let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    // SAFETY: a NUL-terminated path and a two-element timespec array, both
    // owned for the call.
    if unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), ts.as_ptr(), flags) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `futimens(fd, times)` on the host.
pub fn set_fd_times(fd: &impl AsRawFd, t: [SetTime; 2]) -> Result<(), Errno> {
    let ts = host_times(t);
    // SAFETY: a two-element timespec array owned for the call.
    if unsafe { libc::futimens(fd.as_raw_fd(), ts.as_ptr()) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}
