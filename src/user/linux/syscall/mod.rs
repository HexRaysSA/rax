//! Linux system-call dispatch.
//!
//! [`dispatch`] resolves an ABI system-call number to its [`Sysno`], runs
//! the handler, and produces the [`Outcome`] the process applies to the
//! calling thread. Handlers are grouped by subsystem:
//!
//! | Module | Calls |
//! |---|---|
//! | [`io`] | descriptors, `read`/`write` families, pipes, `fcntl`, `ioctl`, polling |
//! | [`path`] | `open`, `stat`, directory and name operations, working directory |
//! | [`mem`] | `brk`, `mmap` family, `madvise` |
//! | [`process`] | identity, limits, `uname`, `prctl`, `arch_prctl`, thread setup, exit |
//! | [`time`] | clocks and sleeping |
//! | [`signal`] | signal dispositions and masks |
//!
//! Unknown numbers, and calls RAX does not implement, return `-ENOSYS`, which
//! is what a kernel built without the call returns; C libraries treat it as
//! "unsupported" and fall back.

pub mod io;
pub mod mem;
pub mod path;
pub mod process;
pub mod signal;
pub mod time;

use super::abi::Sysno;
use super::abi::errno::Errno;
use super::abi::errno_table::*;
use super::process::{ProcState, Thread};
use super::signal::SigInfo;

/// What a system call did to its thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Store this value in the result register.
    Return(u64),
    /// The handler already set the registers (for example `rt_sigreturn`).
    Unchanged,
    /// The thread exits with this code (`exit`).
    ExitThread(i32),
    /// The process exits with this code (`exit_group`).
    ExitGroup(i32),
    /// Deliver this synchronous signal to the thread (the call itself
    /// faulted); it cannot be blocked or ignored.
    Signal(SigInfo),
    /// Send this signal to the process (`kill`, `tgkill`); dispositions and
    /// the signal mask apply.
    Kill(SigInfo),
    /// The process cannot continue (for example every thread would block
    /// forever); the process ends with an emulator diagnostic.
    Fatal(String),
}

/// The value or error of an ordinary call.
pub type SysResult = Result<u64, Errno>;

/// Handler context: the process and the calling thread.
pub struct Ctx<'a> {
    /// Process-wide state.
    pub p: &'a mut ProcState,
    /// The calling thread.
    pub t: &'a mut Thread,
}

impl Ctx<'_> {
    /// Reads `len` bytes of guest memory (`copy_from_user`).
    pub fn read_mem(&self, addr: u64, len: usize) -> Result<Vec<u8>, Errno> {
        let mut buf = vec![0u8; len];
        self.p
            .space
            .read(addr, &mut buf)
            .map_err(|_| Errno(EFAULT))?;
        Ok(buf)
    }

    /// Writes guest memory (`copy_to_user`).
    pub fn write_mem(&self, addr: u64, data: &[u8]) -> Result<(), Errno> {
        self.p.space.write(addr, data).map_err(|_| Errno(EFAULT))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64(&self, addr: u64) -> Result<u64, Errno> {
        let b = self.read_mem(addr, 8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32(&self, addr: u64) -> Result<u32, Errno> {
        let b = self.read_mem(addr, 4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// Writes a little-endian `u64`.
    pub fn write_u64(&self, addr: u64, v: u64) -> Result<(), Errno> {
        self.write_mem(addr, &v.to_le_bytes())
    }

    /// Writes a little-endian `u32`.
    pub fn write_u32(&self, addr: u64, v: u32) -> Result<(), Errno> {
        self.write_mem(addr, &v.to_le_bytes())
    }

    /// Reads a path argument (`getname`): `EFAULT` on a bad pointer,
    /// `ENAMETOOLONG` beyond `PATH_MAX`, `ENOENT` for an empty string.
    pub fn read_path(&self, addr: u64) -> Result<String, Errno> {
        let bytes = self.read_cstr_raw(addr, super::fs::PATH_MAX - 1)?;
        super::fs::Vfs::path_str(&bytes)
    }

    /// Reads a NUL-terminated string of at most `max` bytes.
    pub fn read_cstr_raw(&self, addr: u64, max: usize) -> Result<Vec<u8>, Errno> {
        match self.p.space.read_cstr(addr, max) {
            Ok(Some(s)) => Ok(s),
            Ok(None) => Err(Errno(ENAMETOOLONG)),
            Err(_) => Err(Errno(EFAULT)),
        }
    }
}

/// `struct iovec` array reader shared by the vector I/O calls.
pub fn read_iovecs(c: &Ctx<'_>, iov: u64, count: u64) -> Result<Vec<(u64, u64)>, Errno> {
    // UIO_MAXIOV.
    if count > 1024 {
        return Err(Errno(EINVAL));
    }
    let raw = c.read_mem(iov, count as usize * 16)?;
    let mut out = Vec::with_capacity(count as usize);
    let mut total: u64 = 0;
    for chunk in raw.chunks_exact(16) {
        let base = u64::from_le_bytes(chunk[..8].try_into().unwrap());
        let len = u64::from_le_bytes(chunk[8..].try_into().unwrap());
        // rw_copy_check_uvector: the total must fit in ssize_t.
        total = total.checked_add(len).ok_or(Errno(EINVAL))?;
        if total > i64::MAX as u64 {
            return Err(Errno(EINVAL));
        }
        out.push((base, len));
    }
    Ok(out)
}

fn call(c: &mut Ctx<'_>, s: Sysno, a: [u64; 6]) -> Result<Outcome, Errno> {
    use Sysno as S;
    let r = |v: SysResult| v.map(Outcome::Return);
    let fd = |x: u64| x as i32;
    match s {
        // ---------------------------------------------------------- exit
        S::Exit => Ok(Outcome::ExitThread(a[0] as i32)),
        S::ExitGroup => Ok(Outcome::ExitGroup(a[0] as i32)),

        // ------------------------------------------------------------ io
        S::Read => r(io::read(c, fd(a[0]), a[1], a[2])),
        S::Write => r(io::write(c, fd(a[0]), a[1], a[2])),
        S::Readv => r(io::readv(c, fd(a[0]), a[1], a[2])),
        S::Writev => r(io::writev(c, fd(a[0]), a[1], a[2])),
        S::Pread64 => r(io::pread(c, fd(a[0]), a[1], a[2], a[3] as i64)),
        S::Pwrite64 => r(io::pwrite(c, fd(a[0]), a[1], a[2], a[3] as i64)),
        S::Preadv => r(io::preadv(c, fd(a[0]), a[1], a[2], a[3] as i64, 0)),
        S::Pwritev => r(io::pwritev(c, fd(a[0]), a[1], a[2], a[3] as i64, 0)),
        S::Preadv2 => r(io::preadv(c, fd(a[0]), a[1], a[2], a[3] as i64, a[5])),
        S::Pwritev2 => r(io::pwritev(c, fd(a[0]), a[1], a[2], a[3] as i64, a[5])),
        S::Close => r(io::close(c, fd(a[0]))),
        S::CloseRange => r(io::close_range(c, a[0] as u32, a[1] as u32, a[2] as u32)),
        S::Lseek => r(io::lseek(c, fd(a[0]), a[1] as i64, a[2] as u32)),
        S::Dup => r(io::dup(c, fd(a[0]))),
        S::Dup2 => r(io::dup2(c, fd(a[0]), fd(a[1]))),
        S::Dup3 => r(io::dup3(c, fd(a[0]), fd(a[1]), a[2] as u32)),
        S::Fcntl => r(io::fcntl(c, fd(a[0]), a[1] as u32, a[2])),
        S::Ioctl => r(io::ioctl(c, fd(a[0]), a[1] as u32, a[2])),
        S::Pipe => r(io::pipe2(c, a[0], 0)),
        S::Pipe2 => r(io::pipe2(c, a[0], a[1] as u32)),
        S::Poll => r(io::poll(c, a[0], a[1], a[2] as i32 as i64)),
        S::Ppoll => r(io::ppoll(c, a[0], a[1], a[2])),
        S::Select => r(io::select(c, a[0] as i32, a[1], a[2], a[3], a[4], false)),
        S::Pselect6 => r(io::select(c, a[0] as i32, a[1], a[2], a[3], a[4], true)),
        S::Sendfile => r(io::sendfile(c, fd(a[0]), fd(a[1]), a[2], a[3])),
        S::CopyFileRange => r(io::copy_file_range(c, fd(a[0]), a[1], fd(a[2]), a[3], a[4])),
        S::Fsync | S::Fdatasync => r(io::fsync(c, fd(a[0]))),
        S::Sync => r(Ok(0)),
        S::Syncfs => r(io::fsync(c, fd(a[0])).map(|_| 0)),
        S::Fadvise64 => r(io::fadvise(c, fd(a[0]), a[3] as u32)),
        S::Flock => r(io::flock(c, fd(a[0]), a[1] as u32)),
        S::Getdents64 => r(io::getdents(c, fd(a[0]), a[1], a[2], true)),
        S::Getdents => r(io::getdents(c, fd(a[0]), a[1], a[2], false)),
        S::Ftruncate => r(io::ftruncate(c, fd(a[0]), a[1] as i64)),
        S::Fallocate => r(io::fallocate(
            c,
            fd(a[0]),
            a[1] as u32,
            a[2] as i64,
            a[3] as i64,
        )),

        // ---------------------------------------------------------- path
        S::Open => r(path::openat(
            c,
            path::AT_FDCWD,
            a[0],
            a[1] as u32,
            a[2] as u32,
        )),
        S::Creat => r(path::openat(
            c,
            path::AT_FDCWD,
            a[0],
            super::abi::open::O_CREAT | super::abi::open::O_WRONLY | super::abi::open::O_TRUNC,
            a[1] as u32,
        )),
        S::Openat => r(path::openat(c, fd(a[0]), a[1], a[2] as u32, a[3] as u32)),
        S::Openat2 => r(path::openat2(c, fd(a[0]), a[1], a[2], a[3])),
        S::Stat => r(path::fstatat(c, path::AT_FDCWD, a[0], a[1], 0)),
        S::Lstat => r(path::fstatat(
            c,
            path::AT_FDCWD,
            a[0],
            a[1],
            path::AT_SYMLINK_NOFOLLOW,
        )),
        S::Fstat => r(path::fstat(c, fd(a[0]), a[1])),
        S::Newfstatat => r(path::fstatat(c, fd(a[0]), a[1], a[2], a[3] as u32)),
        S::Statx => r(path::statx(
            c,
            fd(a[0]),
            a[1],
            a[2] as u32,
            a[3] as u32,
            a[4],
        )),
        S::Access => r(path::faccessat(c, path::AT_FDCWD, a[0], a[1] as u32, 0)),
        S::Faccessat => r(path::faccessat(c, fd(a[0]), a[1], a[2] as u32, 0)),
        S::Faccessat2 => r(path::faccessat(c, fd(a[0]), a[1], a[2] as u32, a[3] as u32)),
        S::Readlink => r(path::readlinkat(c, path::AT_FDCWD, a[0], a[1], a[2])),
        S::Readlinkat => r(path::readlinkat(c, fd(a[0]), a[1], a[2], a[3])),
        S::Getcwd => r(path::getcwd(c, a[0], a[1])),
        S::Chdir => r(path::chdir(c, a[0])),
        S::Fchdir => r(path::fchdir(c, fd(a[0]))),
        S::Mkdir => r(path::mkdirat(c, path::AT_FDCWD, a[0], a[1] as u32)),
        S::Mkdirat => r(path::mkdirat(c, fd(a[0]), a[1], a[2] as u32)),
        S::Rmdir => r(path::unlinkat(c, path::AT_FDCWD, a[0], path::AT_REMOVEDIR)),
        S::Unlink => r(path::unlinkat(c, path::AT_FDCWD, a[0], 0)),
        S::Unlinkat => r(path::unlinkat(c, fd(a[0]), a[1], a[2] as u32)),
        S::Rename => r(path::renameat2(
            c,
            path::AT_FDCWD,
            a[0],
            path::AT_FDCWD,
            a[1],
            0,
        )),
        S::Renameat => r(path::renameat2(c, fd(a[0]), a[1], fd(a[2]), a[3], 0)),
        S::Renameat2 => r(path::renameat2(
            c,
            fd(a[0]),
            a[1],
            fd(a[2]),
            a[3],
            a[4] as u32,
        )),
        S::Link => r(path::linkat(
            c,
            path::AT_FDCWD,
            a[0],
            path::AT_FDCWD,
            a[1],
            0,
        )),
        S::Linkat => r(path::linkat(c, fd(a[0]), a[1], fd(a[2]), a[3], a[4] as u32)),
        S::Symlink => r(path::symlinkat(c, a[0], path::AT_FDCWD, a[1])),
        S::Symlinkat => r(path::symlinkat(c, a[0], fd(a[1]), a[2])),
        S::Chmod => r(path::fchmodat(c, path::AT_FDCWD, a[0], a[1] as u32, 0)),
        S::Fchmod => r(path::fchmod(c, fd(a[0]), a[1] as u32)),
        S::Fchmodat => r(path::fchmodat(c, fd(a[0]), a[1], a[2] as u32, 0)),
        S::Fchmodat2 => r(path::fchmodat(c, fd(a[0]), a[1], a[2] as u32, a[3] as u32)),
        S::Chown => r(path::fchownat(
            c,
            path::AT_FDCWD,
            a[0],
            a[1] as u32,
            a[2] as u32,
            0,
        )),
        S::Lchown => r(path::fchownat(
            c,
            path::AT_FDCWD,
            a[0],
            a[1] as u32,
            a[2] as u32,
            path::AT_SYMLINK_NOFOLLOW,
        )),
        S::Fchown => r(path::fchown(c, fd(a[0]), a[1] as u32, a[2] as u32)),
        S::Fchownat => r(path::fchownat(
            c,
            fd(a[0]),
            a[1],
            a[2] as u32,
            a[3] as u32,
            a[4] as u32,
        )),
        S::Truncate => r(path::truncate(c, a[0], a[1] as i64)),
        S::Utimensat => r(path::utimensat(c, fd(a[0]), a[1], a[2], a[3] as u32)),
        S::Statfs => r(path::statfs(c, a[0], a[1])),
        S::Fstatfs => r(path::fstatfs(c, fd(a[0]), a[1])),
        S::Umask => r(path::umask(c, a[0] as u32)),

        // ----------------------------------------------------------- mem
        S::Brk => r(mem::brk(c, a[0])),
        S::Mmap => r(mem::mmap(
            c,
            a[0],
            a[1],
            a[2] as u32,
            a[3] as u32,
            fd(a[4]),
            a[5],
        )),
        S::Munmap => r(mem::munmap(c, a[0], a[1])),
        S::Mprotect => r(mem::mprotect(c, a[0], a[1], a[2] as u32)),
        S::Mremap => r(mem::mremap(c, a[0], a[1], a[2], a[3] as u32, a[4])),
        S::Madvise => r(mem::madvise(c, a[0], a[1], a[2] as u32)),
        S::Msync => r(mem::msync(c, a[0], a[1], a[2] as u32)),
        S::Mlock | S::Munlock | S::Mlock2 => r(mem::mlock(c, a[0], a[1])),
        S::Mlockall | S::Munlockall => r(Ok(0)),
        S::Mincore => r(mem::mincore(c, a[0], a[1], a[2])),
        S::RiscvFlushIcache => r(Ok(0)),

        // ------------------------------------------------------- process
        S::Getpid => r(Ok(c.p.pid as u64)),
        S::Getppid => r(Ok(c.p.ppid as u64)),
        S::Gettid => r(Ok(c.t.tid as u64)),
        S::Getuid => r(Ok(u64::from(c.p.creds.0))),
        S::Geteuid => r(Ok(u64::from(c.p.creds.1))),
        S::Getgid => r(Ok(u64::from(c.p.creds.2))),
        S::Getegid => r(Ok(u64::from(c.p.creds.3))),
        S::Getresuid => r(process::getres(c, a[0], a[1], a[2], true)),
        S::Getresgid => r(process::getres(c, a[0], a[1], a[2], false)),
        S::Getgroups => r(process::getgroups(c, a[0] as i32, a[1])),
        S::Setuid | S::Setgid | S::Setreuid | S::Setregid | S::Setresuid | S::Setresgid => {
            r(process::setid(c, s, a))
        }
        S::Setfsuid | S::Setfsgid => r(Ok(u64::from(c.p.creds.1))),
        S::Getpgid => r(process::getpgid(c, a[0] as i32)),
        S::Getpgrp => r(Ok(c.p.pid as u64)),
        S::Getsid => r(process::getpgid(c, a[0] as i32)),
        S::Setpgid => r(process::setpgid(c, a[0] as i32, a[1] as i32)),
        S::Setsid => r(Err(Errno(EPERM))),
        S::SetTidAddress => r(process::set_tid_address(c, a[0])),
        S::SetRobustList => r(process::set_robust_list(c, a[0], a[1])),
        S::GetRobustList => r(process::get_robust_list(c, a[0] as i32, a[1], a[2])),
        S::Uname => r(process::uname(c, a[0])),
        S::Sysinfo => r(process::sysinfo(c, a[0])),
        S::Getrlimit => r(process::prlimit(c, 0, a[0] as u32, 0, a[1])),
        S::Setrlimit => r(process::prlimit(c, 0, a[0] as u32, a[1], 0)),
        S::Prlimit64 => r(process::prlimit(c, a[0] as i32, a[1] as u32, a[2], a[3])),
        S::Getrusage => r(process::getrusage(c, a[0] as i32, a[1])),
        S::Times => r(process::times(c, a[0])),
        S::Prctl => r(process::prctl(c, a[0] as i32, a[1], a[2], a[3], a[4])),
        S::ArchPrctl => r(process::arch_prctl(c, a[0] as u32, a[1])),
        S::Personality => r(process::personality(c, a[0] as u32)),
        S::Getrandom => r(process::getrandom(c, a[0], a[1], a[2] as u32)),
        S::SchedGetaffinity => r(process::sched_getaffinity(c, a[0] as i32, a[1], a[2])),
        S::SchedSetaffinity => r(process::sched_setaffinity(c, a[0] as i32, a[1], a[2])),
        S::SchedYield => r(Ok(0)),
        S::Getcpu => r(process::getcpu(c, a[0], a[1])),
        S::SchedGetscheduler => r(process::for_self(c, a[0] as i32, 0)),
        S::SchedGetparam => r(process::sched_getparam(c, a[0] as i32, a[1])),
        S::SchedSetscheduler | S::SchedSetparam => r(process::for_self(c, a[0] as i32, 0)),
        S::SchedGetPriorityMax | S::SchedGetPriorityMin => r(process::sched_priority(a[0] as i32)),
        S::Getpriority => r(process::for_self(c, a[1] as i32, 20)),
        S::Setpriority => r(process::for_self(c, a[1] as i32, 0)),
        S::Capget => r(process::capget(c, a[0], a[1])),
        S::Capset => r(Err(Errno(EPERM))),
        S::RiscvHwprobe => r(process::riscv_hwprobe(
            c,
            a[0],
            a[1],
            a[2],
            a[3],
            a[4] as u32,
        )),
        S::Membarrier => r(process::membarrier(a[0] as i32, a[1] as u32)),

        // ---------------------------------------------------------- time
        S::ClockGettime => r(time::clock_gettime(c, a[0] as i32, a[1])),
        S::ClockGetres => r(time::clock_getres(c, a[0] as i32, a[1])),
        S::Gettimeofday => r(time::gettimeofday(c, a[0], a[1])),
        S::Time => r(time::time(c, a[0])),
        S::Nanosleep => r(time::nanosleep(c, a[0], a[1])),
        S::ClockNanosleep => r(time::clock_nanosleep(
            c,
            a[0] as i32,
            a[1] as u32,
            a[2],
            a[3],
        )),

        // -------------------------------------------------------- signal
        S::RtSigaction => r(signal::rt_sigaction(c, a[0] as i32, a[1], a[2], a[3])),
        S::RtSigprocmask => r(signal::rt_sigprocmask(c, a[0] as i32, a[1], a[2], a[3])),
        S::Sigaltstack => r(signal::sigaltstack(c, a[0], a[1])),
        S::RtSigpending => r(signal::rt_sigpending(c, a[0], a[1])),
        S::Kill => signal::kill(c, a[0] as i32, a[1] as i32),
        S::Tkill => signal::tgkill(c, c.p.pid, a[0] as i32, a[1] as i32),
        S::Tgkill => signal::tgkill(c, a[0] as i32, a[1] as i32, a[2] as i32),

        // A single-threaded process has nothing to wait for; the caller's
        // futex word is re-checked on wake anyway.
        S::Futex => process::futex(c, a[0], a[1] as u32, a[2] as u32, a[3], a[4], a[5] as u32),

        // Calls intentionally reported as unsupported.
        _ => Err(Errno(ENOSYS)),
    }
}

/// Dispatches the native-ABI system call `nr` for thread `t`.
pub fn dispatch(p: &mut ProcState, t: &mut Thread, nr: u64, args: [u64; 6]) -> Outcome {
    let abi = p.abi;
    let strace = p.config.strace;
    let sysno = abi.sysno(nr);
    let tid = t.tid;
    let mut c = Ctx { p, t };
    let result = match sysno {
        Some(s) => call(&mut c, s, args),
        None => Err(Errno(ENOSYS)),
    };
    let outcome = match result {
        Ok(o) => o,
        Err(e) => Outcome::Return(e.as_return()),
    };
    if strace {
        trace(tid, sysno, nr, &args, &outcome);
    }
    outcome
}

/// Dispatches an x86-64 `INT 0x80` (i386 ABI) system call. The 32-bit
/// table is not provided; `-ENOSYS` is what a kernel built without
/// `CONFIG_IA32_EMULATION` returns.
pub fn dispatch_compat(p: &mut ProcState, t: &mut Thread, nr: u64, args: [u64; 6]) -> Outcome {
    let outcome = Outcome::Return(Errno(ENOSYS).as_return());
    if p.config.strace {
        eprintln!(
            "[{}] int80 syscall {nr}({:#x}, {:#x}, {:#x}) = -1 ENOSYS",
            t.tid, args[0], args[1], args[2]
        );
    }
    outcome
}

/// Writes one `strace`-style line.
fn trace(tid: i32, sysno: Option<Sysno>, nr: u64, args: &[u64; 6], outcome: &Outcome) {
    let name = sysno.map_or_else(|| format!("syscall_{nr}"), |s| s.name().to_string());
    let args = args
        .iter()
        .map(|a| format!("{a:#x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let result = match outcome {
        Outcome::Return(v) if (*v as i64) < 0 && (*v as i64) >= -4095 => {
            let e = Errno(-(*v as i64) as i32);
            format!("-1 {}", e.name())
        }
        Outcome::Return(v) => format!("{v:#x}"),
        Outcome::Unchanged => "?".into(),
        Outcome::ExitThread(code) | Outcome::ExitGroup(code) => format!("? (exit {code})"),
        Outcome::Signal(info) | Outcome::Kill(info) => {
            format!("? ({})", super::signal::signal_name(info.signo))
        }
        Outcome::Fatal(why) => format!("? ({why})"),
    };
    eprintln!("[{tid}] {name}({args}) = {result}");
}
