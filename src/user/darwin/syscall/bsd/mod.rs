//! BSD system calls.
//!
//! [`call`] routes a call by number to its handler; the handlers live in
//! submodules by subject. The `_nocancel` variants behave as their
//! cancellable counterparts (thread cancellation is delivered only at
//! explicit cancellation points in libpthread).

pub mod file;
pub mod misc;
pub mod path;
pub mod proc;
pub mod region;
pub mod sig;
pub mod sysctl;
pub mod thread;

use super::Ctx;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::tables::nr;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::host::AT_FDCWD;

/// Runs BSD call `number` with `a` (its arguments in 64-bit words).
pub fn call(ctx: &mut Ctx<'_>, number: u32, a: &[u64; 8]) -> SysResult {
    let i = |n: usize| a[n] as i32;
    let u = |n: usize| a[n] as u32;
    match number {
        nr::EXIT => proc::exit(ctx, i(0)),
        nr::READ | nr::READ_NOCANCEL => file::read(ctx, i(0), a[1], a[2], None),
        nr::WRITE | nr::WRITE_NOCANCEL => file::write(ctx, i(0), a[1], a[2], None),
        nr::PREAD | nr::PREAD_NOCANCEL => file::read(ctx, i(0), a[1], a[2], Some(a[3] as i64)),
        nr::PWRITE | nr::PWRITE_NOCANCEL => file::write(ctx, i(0), a[1], a[2], Some(a[3] as i64)),
        nr::READV | nr::READV_NOCANCEL => file::readv(ctx, i(0), a[1], i(2), None),
        nr::WRITEV | nr::WRITEV_NOCANCEL => file::writev(ctx, i(0), a[1], i(2), None),
        nr::PREADV | nr::PREADV_NOCANCEL => file::readv(ctx, i(0), a[1], i(2), Some(a[3] as i64)),
        nr::PWRITEV | nr::PWRITEV_NOCANCEL => {
            file::writev(ctx, i(0), a[1], i(2), Some(a[3] as i64))
        }
        nr::OPEN | nr::OPEN_NOCANCEL => path::openat(ctx, AT_FDCWD, a[0], u(1), u(2)),
        nr::OPENAT | nr::OPENAT_NOCANCEL => path::openat(ctx, i(0), a[1], u(2), u(3)),
        nr::CLOSE | nr::CLOSE_NOCANCEL => file::close(ctx, i(0)),
        nr::LSEEK => file::lseek(ctx, i(0), a[1] as i64, i(2)),
        nr::DUP => file::dup(ctx, i(0)),
        nr::DUP2 => file::dup2(ctx, i(0), i(1)),
        nr::PIPE => file::pipe(ctx),
        nr::FCNTL | nr::FCNTL_NOCANCEL => file::fcntl(ctx, i(0), i(1), a[2]),
        nr::IOCTL => file::ioctl(ctx, i(0), a[1], a[2]),
        nr::FSTAT64 => file::fstat64(ctx, i(0), a[1]),
        nr::STAT64 => path::stat64(ctx, a[0], a[1]),
        nr::LSTAT64 => path::lstat64(ctx, a[0], a[1]),
        nr::FSTATAT64 => path::fstatat64(ctx, i(0), a[1], a[2], u(3)),
        nr::ACCESS => path::faccessat(ctx, AT_FDCWD, a[0], i(1), 0),
        nr::FACCESSAT => path::faccessat(ctx, i(0), a[1], i(2), u(3)),
        nr::READLINK => path::readlinkat(ctx, AT_FDCWD, a[0], a[1], a[2]),
        nr::READLINKAT => path::readlinkat(ctx, i(0), a[1], a[2], a[3]),
        nr::UNLINK => path::unlinkat(ctx, AT_FDCWD, a[0], 0),
        nr::UNLINKAT => path::unlinkat(ctx, i(0), a[1], u(2)),
        nr::RMDIR => path::rmdir(ctx, a[0]),
        nr::MKDIR => path::mkdirat(ctx, AT_FDCWD, a[0], u(1)),
        nr::MKDIRAT => path::mkdirat(ctx, i(0), a[1], u(2)),
        nr::RENAME => path::renameat(ctx, AT_FDCWD, a[0], AT_FDCWD, a[1]),
        nr::RENAMEAT => path::renameat(ctx, i(0), a[1], i(2), a[3]),
        nr::RENAMEATX_NP => path::renameatx_np(ctx, i(0), a[1], i(2), a[3], u(4)),
        nr::LINK => path::linkat(ctx, AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        nr::LINKAT => path::linkat(ctx, i(0), a[1], i(2), a[3], u(4)),
        nr::SYMLINK => path::symlinkat(ctx, a[0], AT_FDCWD, a[1]),
        nr::SYMLINKAT => path::symlinkat(ctx, a[0], i(1), a[2]),
        nr::CHMOD => path::fchmodat(ctx, AT_FDCWD, a[0], u(1), 0),
        nr::FCHMODAT => path::fchmodat(ctx, i(0), a[1], u(2), u(3)),
        nr::FCHMOD => file::fchmod(ctx, i(0), u(1)),
        nr::CHOWN => path::fchownat(ctx, AT_FDCWD, a[0], u(1), u(2), 0),
        nr::LCHOWN => path::fchownat(
            ctx,
            AT_FDCWD,
            a[0],
            u(1),
            u(2),
            crate::user::darwin::host::AT_SYMLINK_NOFOLLOW,
        ),
        nr::FCHOWNAT => path::fchownat(ctx, i(0), a[1], u(2), u(3), u(4)),
        nr::FCHOWN => file::fchown(ctx, i(0), u(1), u(2)),
        nr::CHDIR => path::chdir(ctx, a[0]),
        nr::FCHDIR => path::fchdir(ctx, i(0)),
        nr::TRUNCATE => path::truncate(ctx, a[0], a[1] as i64),
        nr::FTRUNCATE => file::ftruncate(ctx, i(0), a[1] as i64),
        nr::MKFIFO => path::mkfifoat(ctx, AT_FDCWD, a[0], u(1)),
        nr::MKFIFOAT => path::mkfifoat(ctx, i(0), a[1], u(2)),
        nr::UTIMES => path::utimes(ctx, a[0], a[1]),
        nr::FUTIMES => file::futimes(ctx, i(0), a[1]),
        nr::PATHCONF => path::pathconf(ctx, a[0], i(1)),
        nr::FPATHCONF => file::fpathconf(ctx, i(0), i(1)),
        nr::FSYNC | nr::FSYNC_NOCANCEL | nr::FDATASYNC => file::fsync(ctx, i(0)),
        nr::FLOCK => file::flock(ctx, i(0), i(1)),
        nr::GETDIRENTRIES64 => file::getdirentries64(ctx, i(0), a[1], a[2], a[3]),
        nr::FSTATFS64 => file::fstatfs64(ctx, i(0), a[1]),
        nr::POLL | nr::POLL_NOCANCEL => file::poll(ctx, a[0], u(1), i(2)),
        nr::SELECT | nr::SELECT_NOCANCEL => file::select(ctx, i(0), a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::GETATTRLIST => path::getattrlistat(ctx, None, Some(a[0]), a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::FGETATTRLIST => path::getattrlistat(ctx, Some(i(0)), None, a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::GETATTRLISTAT => {
            path::getattrlistat(ctx, Some(i(0)), Some(a[1]), a[2], a[3], a[4], a[5])
        }
        nr::GETDTABLESIZE => Ok(Rv::one(ctx.proc.rlimits[8].0)),

        nr::MMAP => super::mem::mmap(ctx, a[0], a[1], u(2), u(3), i(4), a[5]),
        nr::MUNMAP => super::mem::munmap(ctx, a[0], a[1]),
        nr::MPROTECT => super::mem::mprotect(ctx, a[0], a[1], u(2)),
        nr::MADVISE => super::mem::madvise(ctx, a[0], a[1], i(2)),
        nr::MINHERIT => super::mem::minherit(ctx, a[0], a[1], i(2)),
        nr::MSYNC | nr::MSYNC_NOCANCEL => super::mem::msync(ctx, a[0], a[1], i(2)),
        nr::MINCORE => super::mem::mincore(ctx, a[0], a[1], a[2]),
        nr::MLOCK | nr::MUNLOCK => super::mem::mlock(ctx, a[0], a[1]),
        nr::SHARED_REGION_CHECK_NP => region::check_np(ctx, a[0]),
        nr::SHARED_REGION_MAP_AND_SLIDE_2_NP => {
            region::map_and_slide_2(ctx, u(0), a[1], u(2), a[3])
        }

        nr::GETPID => Ok(Rv::one(ctx.proc.pid as u64)),
        nr::GETPPID => Ok(Rv::one(ctx.proc.ppid as u64)),
        nr::GETUID => Ok(Rv::one(u64::from(ctx.proc.creds.0))),
        nr::GETEUID => Ok(Rv::one(u64::from(ctx.proc.creds.1))),
        nr::GETGID => Ok(Rv::one(u64::from(ctx.proc.creds.2))),
        nr::GETEGID => Ok(Rv::one(u64::from(ctx.proc.creds.3))),
        nr::ISSETUGID => Ok(Rv::one(0)),
        nr::GETPGRP => proc::host_id(|| unsafe { libc::getpgrp() }),
        nr::GETPGID => proc::host_id(|| unsafe { libc::getpgid(a[0] as i32) }),
        nr::GETSID => proc::host_id(|| unsafe { libc::getsid(a[0] as i32) }),
        nr::SETPGID => proc::host_id(|| unsafe { libc::setpgid(a[0] as i32, a[1] as i32) }),
        nr::SETSID => proc::host_id(|| unsafe { libc::setsid() }),
        nr::GETGROUPS => proc::getgroups(ctx, u(0), a[1]),
        nr::GETLOGIN => proc::getlogin(ctx, a[0], u(1)),
        nr::UMASK => misc::umask(ctx, u(0)),
        nr::GETRLIMIT => misc::getrlimit(ctx, u(0), a[1]),
        nr::SETRLIMIT => misc::setrlimit(ctx, u(0), a[1]),
        nr::GETRUSAGE => misc::getrusage(ctx, i(0), a[1]),
        nr::GETPRIORITY => proc::getpriority(ctx, i(0), a[1]),
        nr::SETPRIORITY => Ok(Rv::one(0)),
        nr::GETENTROPY => misc::getentropy(ctx, a[0], a[1]),
        nr::GETTIMEOFDAY => misc::gettimeofday(ctx, a[0], a[1], a[2]),
        nr::CSOPS | nr::CSOPS_AUDITTOKEN => misc::csops(ctx, i(0), u(1), a[2], a[3]),
        nr::MAC_SYSCALL => misc::mac_syscall(ctx, a[0], i(1), a[2]),
        nr::KDEBUG_TRACE64 | nr::KDEBUG_TRACE | nr::KDEBUG_TRACE_STRING | nr::KDEBUG_TYPEFILTER => {
            misc::kdebug(ctx)
        }
        nr::SYSCTL => sysctl::sysctl(ctx, a),
        nr::SYSCTLBYNAME => sysctl::sysctlbyname(ctx, a),

        nr::THREAD_SELFID => thread::thread_selfid(ctx),
        nr::BSDTHREAD_REGISTER => thread::bsdthread_register(ctx, a),
        nr::ULOCK_WAIT => thread::ulock_wait(ctx, u(0), a[1], a[2], (a[3] as u32 as u64) * 1000),
        nr::ULOCK_WAIT2 => thread::ulock_wait(ctx, u(0), a[1], a[2], a[3]),
        nr::ULOCK_WAKE => thread::ulock_wake(ctx, u(0), a[1], a[2]),
        nr::SEMWAIT_SIGNAL | nr::SEMWAIT_SIGNAL_NOCANCEL => thread::semwait_signal(ctx, a),

        nr::SIGACTION => sig::sigaction(ctx, i(0), a[1], a[2]),
        nr::SIGPROCMASK | nr::PTHREAD_SIGMASK => sig::sigprocmask(ctx, i(0), a[1], a[2]),
        nr::SIGPENDING => sig::sigpending(ctx, a[0]),
        nr::SIGALTSTACK => sig::sigaltstack(ctx, a[0], a[1]),
        nr::KILL => sig::kill(ctx, i(0), i(1), i(2)),
        nr::PTHREAD_KILL => sig::pthread_kill(ctx, u(0), i(1)),
        nr::DISABLE_THREADSIGNAL => Ok(Rv::one(0)),
        _ => {
            if ctx.proc.config.strace || std::env::var_os("RAX_DARWIN_WARN").is_some() {
                eprintln!(
                    "rax-user: unimplemented BSD system call {number} ({})",
                    crate::user::darwin::abi::bsd_syscall(number).name
                );
            }
            Err(Errno::ENOSYS)
        }
    }
}
