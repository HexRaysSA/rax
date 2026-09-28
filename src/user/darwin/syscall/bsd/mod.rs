//! BSD system calls.
//!
//! [`call`] routes a call by number to its handler; the handlers live in
//! submodules by subject. The `_nocancel` variants behave as their
//! cancellable counterparts (thread cancellation is delivered only at
//! explicit cancellation points in libpthread).

#[cfg(target_os = "macos")]
pub mod acl;
#[cfg(target_os = "macos")]
pub mod attr;
#[cfg(target_os = "macos")]
pub mod audit;
pub mod event;
pub mod file;
pub mod mac;
pub mod misc;
pub mod path;
#[cfg(target_os = "macos")]
pub mod persona;
pub mod proc;
#[cfg(target_os = "macos")]
pub mod procinfo;
pub mod pthread;
pub mod region;
pub mod shm;
pub mod sig;
#[cfg(target_os = "macos")]
pub mod socket;
pub mod sysctl;
pub mod thread;
pub mod wait;
pub mod workq;
#[cfg(target_os = "macos")]
pub mod xattr;

use super::Ctx;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::tables::nr;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::host::AT_FDCWD;
use crate::user::darwin::kevent;
use crate::user::darwin::psynch;

/// The calls that are cancellation points (`__pthread_testcancel(1)`
/// before their work): a pending, enabled cancellation fails them with
/// `EINTR`. Their `_nocancel` variants are not.
const CANCELLATION_POINTS: &[u32] = &[
    nr::READ,
    nr::WRITE,
    nr::OPEN,
    nr::CLOSE,
    nr::WAIT4,
    nr::RECVMSG,
    nr::SENDMSG,
    nr::RECVFROM,
    nr::ACCEPT,
    nr::MSYNC,
    nr::CONNECT,
    nr::SELECT,
    nr::FSYNC,
    nr::SENDTO,
    nr::READV,
    nr::WRITEV,
    nr::FCNTL,
    nr::SIGSUSPEND,
    nr::WAITID,
    nr::FDATASYNC,
    nr::PREAD,
    nr::PWRITE,
    nr::MSGSND,
    nr::MSGRCV,
    nr::SEM_WAIT,
    nr::AIO_SUSPEND,
    nr::SIGWAIT,
    nr::POLL,
    nr::PSELECT,
    nr::PREADV,
    nr::PWRITEV,
    nr::OPENAT,
    nr::CONNECTX,
    nr::DISCONNECTX,
    nr::PEELOFF,
];

/// Runs BSD call `number` with `a` (its arguments in 64-bit words).
pub fn call(ctx: &mut Ctx<'_>, number: u32, a: &[u64; 8]) -> SysResult {
    let i = |n: usize| a[n] as i32;
    let u = |n: usize| a[n] as u32;
    if CANCELLATION_POINTS.contains(&number) {
        pthread::testcancel(ctx)?;
    }
    match number {
        nr::EXIT => proc::exit(ctx, i(0)),
        nr::FORK => crate::user::darwin::fork::fork(ctx),
        nr::WAIT4 | nr::WAIT4_NOCANCEL => wait::wait4(ctx, i(0), a[1], i(2), a[3]),
        nr::WAITID | nr::WAITID_NOCANCEL => wait::waitid(ctx, i(0), u(1), a[2], i(3)),
        nr::EXECVE => crate::user::darwin::exec::execve(ctx, a[0], a[1], a[2]),
        nr::POSIX_SPAWN => {
            crate::user::darwin::exec::spawn::posix_spawn(ctx, a[0], a[1], a[2], a[3], a[4])
        }
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
        nr::OPEN_DPROTECTED_NP => {
            path::openat_dprotected(ctx, AT_FDCWD, a[0], u(1), i(2), i(3), u(4), None)
        }
        nr::OPENAT_DPROTECTED_NP => {
            path::openat_dprotected(ctx, i(0), a[1], u(2), i(3), i(4), u(5), Some(i(6)))
        }
        nr::CLOSE | nr::CLOSE_NOCANCEL => file::close(ctx, i(0)),
        nr::LSEEK => file::lseek(ctx, i(0), a[1] as i64, i(2)),
        nr::DUP => file::dup(ctx, i(0)),
        nr::DUP2 => file::dup2(ctx, i(0), i(1)),
        nr::DUP3 => file::dup3(ctx, i(0), i(1), u(2)),
        nr::PIPE => file::pipe(ctx),
        nr::PIPE2 => file::pipe2(ctx, u(1)),
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
        nr::FSGETPATH => path::fsgetpath(ctx, a[0], a[1], a[2], a[3], 0),
        nr::FSGETPATH_EXT => path::fsgetpath(ctx, a[0], a[1], a[2], a[3], u(4)),
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
        nr::STATFS64 => path::statfs64(ctx, a[0], a[1]),
        nr::SHM_OPEN => shm::shm_open(ctx, a[0], u(1), u(2)),
        nr::SHM_UNLINK => shm::shm_unlink(ctx, a[0]),
        nr::GETFSSTAT64 => file::getfsstat64(ctx, a[0], i(1), i(2)),
        nr::POLL | nr::POLL_NOCANCEL => file::poll(ctx, a[0], u(1), i(2)),
        nr::SELECT | nr::SELECT_NOCANCEL => file::select(ctx, i(0), a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::GETATTRLIST => path::getattrlistat(ctx, None, Some(a[0]), a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::FGETATTRLIST => path::getattrlistat(ctx, Some(i(0)), None, a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        #[cfg(target_os = "macos")]
        nr::GETATTRLISTBULK => attr::getattrlistbulk(ctx, i(0), a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::SETATTRLIST => attr::setattrlist(ctx, a[0], a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::FSETATTRLIST => attr::fsetattrlist(ctx, i(0), a[1], a[2], a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::SETATTRLISTAT => attr::setattrlistat(ctx, i(0), a[1], a[2], a[3], a[4], u(5)),
        #[cfg(target_os = "macos")]
        nr::CLONEFILEAT => attr::clonefileat(ctx, i(0), a[1], i(2), a[3], u(4)),
        #[cfg(target_os = "macos")]
        nr::FCLONEFILEAT => attr::fclonefileat(ctx, i(0), i(1), a[2], u(3)),
        #[cfg(target_os = "macos")]
        nr::EXCHANGEDATA => attr::exchangedata(ctx, a[0], a[1], u(2)),
        #[cfg(target_os = "macos")]
        nr::ACCESS_EXTENDED => attr::access_extended(ctx, a[0], a[1], a[2], u(3)),
        nr::GETATTRLISTAT => {
            path::getattrlistat(ctx, Some(i(0)), Some(a[1]), a[2], a[3], a[4], a[5])
        }
        #[cfg(target_os = "macos")]
        nr::STAT64_EXTENDED => acl::stat64_extended(ctx, true, a[0], a[1], a[2], a[3]),
        #[cfg(target_os = "macos")]
        nr::LSTAT64_EXTENDED => acl::stat64_extended(ctx, false, a[0], a[1], a[2], a[3]),
        #[cfg(target_os = "macos")]
        nr::FSTAT64_EXTENDED => acl::fstat64_extended(ctx, i(0), a[1], a[2], a[3]),
        #[cfg(target_os = "macos")]
        nr::CHMOD_EXTENDED => acl::chmod_extended(ctx, a[0], u(1), u(2), i(3), a[4]),
        #[cfg(target_os = "macos")]
        nr::FCHMOD_EXTENDED => acl::fchmod_extended(ctx, i(0), u(1), u(2), i(3), a[4]),
        #[cfg(target_os = "macos")]
        nr::MKDIR_EXTENDED => acl::mknode_extended(ctx, false, a[0], u(1), u(2), i(3), a[4]),
        #[cfg(target_os = "macos")]
        nr::MKFIFO_EXTENDED => acl::mknode_extended(ctx, true, a[0], u(1), u(2), i(3), a[4]),
        #[cfg(target_os = "macos")]
        nr::OPEN_EXTENDED => acl::open_extended(ctx, a[0], u(1), u(2), u(3), i(4), a[5]),
        nr::UMASK_EXTENDED => misc::umask(ctx, u(0)),
        #[cfg(target_os = "macos")]
        nr::GETXATTR => xattr::getxattr(ctx, a[0], a[1], a[2], a[3], u(4), u(5)),
        #[cfg(target_os = "macos")]
        nr::FGETXATTR => xattr::fgetxattr(ctx, i(0), a[1], a[2], a[3], u(4), u(5)),
        #[cfg(target_os = "macos")]
        nr::SETXATTR => xattr::setxattr(ctx, a[0], a[1], a[2], a[3], u(4), u(5)),
        #[cfg(target_os = "macos")]
        nr::FSETXATTR => xattr::fsetxattr(ctx, i(0), a[1], a[2], a[3], u(4), u(5)),
        #[cfg(target_os = "macos")]
        nr::REMOVEXATTR => xattr::removexattr(ctx, a[0], a[1], u(2)),
        #[cfg(target_os = "macos")]
        nr::FREMOVEXATTR => xattr::fremovexattr(ctx, i(0), a[1], u(2)),
        #[cfg(target_os = "macos")]
        nr::LISTXATTR => xattr::listxattr(ctx, a[0], a[1], a[2], u(3)),
        #[cfg(target_os = "macos")]
        nr::FLISTXATTR => xattr::flistxattr(ctx, i(0), a[1], a[2], u(3)),
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
        nr::TASK_READ_FOR_PID => proc::task_flavor_for_pid(ctx, a[0] as u32, i(1), a[2], true),
        nr::TASK_INSPECT_FOR_PID => proc::task_flavor_for_pid(ctx, a[0] as u32, i(1), a[2], false),
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
        nr::GETTID => proc::gettid(ctx, a[0], a[1]),
        nr::SETTID => proc::settid(ctx, u(0), u(1)),
        nr::SETTID_WITH_PID => proc::settid_with_pid(ctx, i(0), i(1)),
        nr::UMASK => misc::umask(ctx, u(0)),
        #[cfg(target_os = "macos")]
        nr::PROC_INFO => procinfo::proc_info(ctx, i(0), i(1), u(2), a[3], a[4], i(5)),
        #[cfg(target_os = "macos")]
        nr::PROC_INFO_EXTENDED_ID => {
            procinfo::proc_info_extended_id(ctx, i(0), i(1), u(2), u(3), a[4], a[5], a[6], i(7))
        }
        nr::GETRLIMIT => misc::getrlimit(ctx, u(0), a[1]),
        nr::SETRLIMIT => misc::setrlimit(ctx, u(0), a[1]),
        nr::GETRUSAGE => misc::getrusage(ctx, i(0), a[1]),
        nr::GETPRIORITY => proc::getpriority(ctx, i(0), a[1]),
        nr::SETPRIORITY => Ok(Rv::one(0)),
        nr::GETENTROPY => misc::getentropy(ctx, a[0], a[1]),
        nr::GETTIMEOFDAY => misc::gettimeofday(ctx, a[0], a[1], a[2]),
        nr::CSOPS | nr::CSOPS_AUDITTOKEN => misc::csops(ctx, i(0), u(1), a[2], a[3]),
        nr::MAC_SYSCALL => mac::mac_syscall(ctx, a[0], i(1), a[2]),
        nr::GETHOSTUUID => misc::gethostuuid(ctx, a[0], a[1]),
        #[cfg(target_os = "macos")]
        nr::PERSONA => persona::persona(ctx, u(0), u(1), a[2], a[3], a[4], a[5]),
        nr::CSRCTL => misc::csrctl(ctx, u(0), a[1], a[2]),
        nr::CROSSARCH_TRAP => misc::crossarch_trap(u(0)),
        nr::KDEBUG_TRACE64 | nr::KDEBUG_TRACE | nr::KDEBUG_TRACE_STRING | nr::KDEBUG_TYPEFILTER => {
            misc::kdebug(ctx)
        }
        nr::SYSCTL => sysctl::sysctl(ctx, a),
        nr::SYSCTLBYNAME => sysctl::sysctlbyname(ctx, a),
        #[cfg(target_os = "macos")]
        nr::AUDIT => audit::submit(ctx, a[0], u(1)),
        #[cfg(target_os = "macos")]
        nr::AUDITON => audit::control(ctx, i(0), a[1], u(2)),
        #[cfg(target_os = "macos")]
        nr::GETAUID => audit::get_auid(ctx, a[0]),
        #[cfg(target_os = "macos")]
        nr::SETAUID => audit::set_auid(ctx, a[0]),
        #[cfg(target_os = "macos")]
        nr::GETAUDIT_ADDR => audit::get_audit_addr(ctx, a[0], u(1)),
        #[cfg(target_os = "macos")]
        nr::SETAUDIT_ADDR => audit::set_audit_addr(ctx, a[0], u(1)),
        #[cfg(target_os = "macos")]
        nr::AUDITCTL => audit::control_file(ctx, a[0]),

        #[cfg(target_os = "macos")]
        nr::SOCKET => socket::socket(ctx, i(0), i(1), i(2)),
        #[cfg(target_os = "macos")]
        nr::SOCKETPAIR => socket::socketpair(ctx, i(0), i(1), i(2), a[3]),
        #[cfg(target_os = "macos")]
        nr::BIND => socket::bind(ctx, i(0), a[1], u(2)),
        #[cfg(target_os = "macos")]
        nr::LISTEN => socket::listen(ctx, i(0), i(1)),
        #[cfg(target_os = "macos")]
        nr::ACCEPT | nr::ACCEPT_NOCANCEL => socket::accept(ctx, i(0), a[1], a[2]),
        #[cfg(target_os = "macos")]
        nr::CONNECT | nr::CONNECT_NOCANCEL => socket::connect(ctx, i(0), a[1], u(2)),
        #[cfg(target_os = "macos")]
        nr::SHUTDOWN => socket::shutdown(ctx, i(0), i(1)),
        #[cfg(target_os = "macos")]
        nr::GETSOCKNAME => socket::getsockname(ctx, i(0), a[1], a[2]),
        #[cfg(target_os = "macos")]
        nr::GETPEERNAME => socket::getpeername(ctx, i(0), a[1], a[2]),
        #[cfg(target_os = "macos")]
        nr::SETSOCKOPT => socket::setsockopt(ctx, i(0), i(1), i(2), a[3], u(4)),
        #[cfg(target_os = "macos")]
        nr::GETSOCKOPT => socket::getsockopt(ctx, i(0), i(1), i(2), a[3], a[4]),
        #[cfg(target_os = "macos")]
        nr::SENDTO | nr::SENDTO_NOCANCEL => socket::sendto(ctx, i(0), a[1], a[2], i(3), a[4], u(5)),
        #[cfg(target_os = "macos")]
        nr::SENDMSG | nr::SENDMSG_NOCANCEL => socket::sendmsg(ctx, i(0), a[1], i(2)),
        #[cfg(target_os = "macos")]
        nr::RECVFROM | nr::RECVFROM_NOCANCEL => {
            socket::recvfrom(ctx, i(0), a[1], a[2], i(3), a[4], a[5])
        }
        #[cfg(target_os = "macos")]
        nr::RECVMSG | nr::RECVMSG_NOCANCEL => socket::recvmsg(ctx, i(0), a[1], i(2)),
        #[cfg(target_os = "macos")]
        nr::RECVMSG_X => socket::recvmsg_x(ctx, i(0), a[1], u(2), i(3)),
        #[cfg(target_os = "macos")]
        nr::SENDMSG_X => socket::sendmsg_x(ctx, i(0), a[1], u(2), i(3)),
        #[cfg(target_os = "macos")]
        nr::CONNECTX => socket::connectx(ctx, i(0), a[1], u(2), u(3), a[4], u(5), a[6], a[7]),
        #[cfg(target_os = "macos")]
        nr::DISCONNECTX => socket::disconnectx(ctx, i(0), u(1), u(2)),
        #[cfg(target_os = "macos")]
        nr::PEELOFF => socket::peeloff(),
        #[cfg(target_os = "macos")]
        nr::SOCKET_DELEGATE => socket::socket_delegate(ctx, i(0), i(1), i(2), i(3)),

        nr::KQUEUE => kevent::kqueue(ctx),
        nr::KEVENT => event::kevent(ctx, a, event::Api::Kevent),
        nr::KEVENT64 => event::kevent(ctx, a, event::Api::Kevent64),
        nr::KEVENT_QOS => event::kevent(ctx, a, event::Api::Qos),
        nr::KEVENT_ID => kevent::kevent_id(ctx, a),
        nr::WORKQ_OPEN => crate::user::darwin::workq::workq_open(ctx),
        nr::WORKQ_KERNRETURN => crate::user::darwin::workq::workq_kernreturn(ctx, a),
        nr::BSDTHREAD_CTL => workq::bsdthread_ctl(ctx, a),
        nr::THREAD_SELFID => thread::thread_selfid(ctx),
        nr::BSDTHREAD_CREATE => pthread::bsdthread_create(ctx, a[0], a[1], a[2], a[3], u(4)),
        nr::BSDTHREAD_TERMINATE => pthread::bsdthread_terminate(ctx, a[0], a[1], u(2), a[3]),
        nr::PTHREAD_MARKCANCEL => pthread::markcancel(ctx, u(0)),
        nr::PTHREAD_CANCELED => pthread::canceled(ctx, i(0)),
        nr::PSYNCH_MUTEXWAIT => psynch::mutex::mutexwait(ctx, a[0], u(1), u(2), a[3], u(4)),
        nr::PSYNCH_MUTEXDROP => psynch::mutex::mutexdrop(ctx, a[0], u(1), u(2), u(4)),
        nr::PSYNCH_CVBROAD => psynch::cond::cvbroad(ctx, a[0], a[1], a[2], u(3)),
        nr::PSYNCH_CVSIGNAL => psynch::cond::cvsignal_call(ctx, a[0], a[1], u(2), u(3), u(7)),
        nr::PSYNCH_CVWAIT => {
            psynch::cond::cvwait(ctx, a[0], a[1], u(2), a[3], a[4], u(5), a[6] as i64, u(7))
        }
        nr::PSYNCH_CVCLRPREPOST => {
            psynch::cond::cvclrprepost(ctx, a[0], u(1), u(2), u(3), u(5), u(6))
        }
        nr::PSYNCH_RW_RDLOCK => psynch::rwlock::lock(ctx, false, a[0], u(1), u(2), u(3)),
        nr::PSYNCH_RW_WRLOCK => psynch::rwlock::lock(ctx, true, a[0], u(1), u(2), u(3)),
        nr::PSYNCH_RW_UNLOCK => psynch::rwlock::unlock_call(ctx, a[0], u(1), u(2), u(3)),
        nr::PSYNCH_RW_LONGRDLOCK | nr::PSYNCH_RW_YIELDWRLOCK => Err(Errno::ESRCH),
        nr::PSYNCH_RW_UNLOCK2 => Err(Errno::ENOTSUP),
        nr::PSYNCH_RW_UPGRADE | nr::PSYNCH_RW_DOWNGRADE => Ok(Rv::one(0)),
        nr::BSDTHREAD_REGISTER => thread::bsdthread_register(ctx, a),
        nr::ULOCK_WAIT => thread::ulock_wait(ctx, u(0), a[1], a[2], (a[3] as u32 as u64) * 1000),
        nr::ULOCK_WAIT2 => thread::ulock_wait(ctx, u(0), a[1], a[2], a[3]),
        nr::ULOCK_WAKE => thread::ulock_wake(ctx, u(0), a[1], a[2]),
        nr::SEMWAIT_SIGNAL | nr::SEMWAIT_SIGNAL_NOCANCEL => thread::semwait_signal(ctx, a),

        nr::SIGACTION => sig::sigaction(ctx, i(0), a[1], a[2]),
        nr::SIGPROCMASK => sig::sigprocmask(ctx, i(0), a[1], a[2]),
        nr::PTHREAD_SIGMASK => sig::pthread_sigmask(ctx, i(0), a[1], a[2]),
        nr::SIGPENDING => sig::sigpending(ctx, a[0]),
        nr::SIGSUSPEND | nr::SIGSUSPEND_NOCANCEL => sig::sigsuspend(ctx, u(0)),
        nr::SIGWAIT | nr::SIGWAIT_NOCANCEL => sig::sigwait(ctx, a[0], a[1]),
        nr::SIGALTSTACK => sig::sigaltstack(ctx, a[0], a[1]),
        nr::SIGRETURN => sig::sigreturn(ctx, a[0], u(1), a[2]),
        nr::KILL => sig::kill(ctx, i(0), i(1), i(2)),
        nr::PTHREAD_KILL => sig::pthread_kill(ctx, u(0), i(1)),
        nr::SETITIMER => sig::setitimer(ctx, u(0), a[1], a[2]),
        nr::GETITIMER => sig::getitimer(ctx, u(0), a[1]),
        nr::DISABLE_THREADSIGNAL => pthread::disable_threadsignal(ctx),
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
