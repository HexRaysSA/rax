//! The system calls of a compatibility task: an i386 one
//! (`arch/x86/entry/syscalls/syscall_32.tbl` on an x86-64 kernel with
//! `CONFIG_IA32_EMULATION`), and an ARM EABI one on arm64, whose calls
//! [`arm`] converts where they differ from i386's.
//!
//! A call the table gives a native entry point whose arguments and memory
//! layouts are the same for a 32-bit caller goes to the native handler with
//! the registers as `do_int80_emulation` zero-extends them; handlers that
//! read structures with pointers or `long`s in them (`struct iovec`,
//! `execve`'s vectors) read the compatibility layouts when
//! [`Ctx::compat`] is set, as the kernel's do under `in_compat_syscall`. A
//! call with a compatibility entry point (`compat_sys_*`, `sys_ia32_*`) or
//! a 32-bit-only one goes through its conversion here. Every other call is
//! `ENOSYS`, so none runs with 64-bit layouts on 32-bit memory.
//!
//! | Module | Contents |
//! |---|---|
//! | this one | the table and the calls without a module of their own |
//! | [`arm`] | ARM EABI's calls that differ from i386's, and those past the table |
//! | [`file`] | split and 32-bit offsets, `_llseek`, `fcntl`'s locks |
//! | [`ipc`] | the `ipc` multiplexer and System V IPC's 32-bit structures |
//! | [`net`] | the `socketcall` multiplexer |
//! | [`resource`] | resource limits and CPU masks |
//! | [`signal`] | `struct compat_sigaction`, the old one-word signal calls, `compat_stack_t` |
//! | [`stat`] | `stat`, `stat64`, the old `stat`, `statfs`, `statfs64` |
//! | [`tls`] | `set_thread_area`, `get_thread_area` |
//! | [`uid16`] | the 16-bit user- and group-ID calls |

pub mod arm;
pub mod file;
pub mod ipc;
pub mod net;
pub mod resource;
pub mod signal;
pub mod stat;
pub mod tls;
pub mod uid16;

use super::super::abi::Sysno as S;
use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::copy::SendfileOffset;
use super::dirents::{self, Dirent};
use super::io;
use super::path::{self, AT_FDCWD};
use super::time;
use super::{Ctx, Outcome, call_handler};
use super::{priority, process};
use file::{dual, sext};
use stat::{FsOf, Of};

/// `PAGE_SHIFT`: `mmap2`'s offset unit.
const PAGE_SHIFT: u32 = 12;

/// Terminal `ioctl`s whose argument (an `int`, `struct termios`, or
/// `struct winsize`) has the same layout for a 32-bit caller
/// (`compat_sys_ioctl` passes them to the driver as they are).
const SAME_LAYOUT_IOCTLS: &[u32] = &[
    0x5401, // TCGETS
    0x5402, // TCSETS
    0x5403, // TCSETSW
    0x5404, // TCSETSF
    0x540F, // TIOCGPGRP
    0x5410, // TIOCSPGRP
    0x5413, // TIOCGWINSZ
    0x5414, // TIOCSWINSZ
    0x541B, // FIONREAD
    0x5421, // FIONBIO
    0x5450, // FIONCLEX
    0x5451, // FIOCLEX
];

/// Runs system call `s` of a compatibility task.
pub(super) fn call(c: &mut Ctx<'_>, s: S, a: [u64; 6]) -> Result<Outcome, Errno> {
    if c.p.abi == super::super::abi::LinuxAbi::Arm
        && let Some(outcome) = arm::call(c, s, a)
    {
        return outcome;
    }
    let r = |v: Result<u64, Errno>| v.map(Outcome::Return);
    let fd = |x: u64| x as i32;
    match s {
        // The native entry points, the same for a 32-bit caller.
        S::RestartSyscall
        | S::Exit
        | S::ExitGroup
        | S::Fork
        | S::Vfork
        | S::Read
        | S::Write
        | S::Close
        | S::Creat
        | S::Link
        | S::Unlink
        | S::Chdir
        | S::Fchdir
        | S::Mknod
        | S::Chmod
        | S::Fchmod
        | S::Access
        | S::Sync
        | S::Syncfs
        | S::Fsync
        | S::Fdatasync
        | S::Rename
        | S::Mkdir
        | S::Rmdir
        | S::Symlink
        | S::Readlink
        | S::Umask
        | S::Chroot
        | S::PivotRoot
        | S::Getcwd
        | S::Flock
        | S::Getdents64
        | S::Statx
        | S::Openat2
        | S::Mkdirat
        | S::Mknodat
        | S::Fchownat
        | S::Unlinkat
        | S::Renameat
        | S::Renameat2
        | S::Linkat
        | S::Symlinkat
        | S::Readlinkat
        | S::Fchmodat
        | S::Fchmodat2
        | S::Faccessat
        | S::Faccessat2
        | S::Setxattr
        | S::Lsetxattr
        | S::Fsetxattr
        | S::Getxattr
        | S::Lgetxattr
        | S::Fgetxattr
        | S::Listxattr
        | S::Llistxattr
        | S::Flistxattr
        | S::Removexattr
        | S::Lremovexattr
        | S::Fremovexattr
        | S::Setxattrat
        | S::Getxattrat
        | S::Listxattrat
        | S::Removexattrat
        | S::Splice
        | S::Tee
        | S::Vmsplice
        | S::CopyFileRange
        | S::CloseRange
        | S::Getpid
        | S::Gettid
        | S::Getppid
        | S::Getpgid
        | S::Getpgrp
        | S::Setpgid
        | S::Getsid
        | S::Setsid
        | S::Brk
        | S::Munmap
        | S::Mprotect
        | S::Madvise
        | S::Mremap
        | S::Mincore
        | S::Msync
        | S::Mlock
        | S::Mlock2
        | S::Munlock
        | S::Mlockall
        | S::Munlockall
        | S::Mseal
        | S::SetTidAddress
        | S::Dup
        | S::Dup2
        | S::Dup3
        | S::Pipe
        | S::Pipe2
        | S::Poll
        | S::Kill
        | S::Tkill
        | S::Tgkill
        // compat_sigset_t is sigset_t's bytes on a little-endian machine,
        // and both are 8 bytes.
        | S::RtSigprocmask
        | S::RtSigpending
        | S::RtSigsuspend
        // Sockets: struct compat_msghdr and its control messages, and the
        // old timeouts' struct old_timeval32, are read where Ctx::compat is.
        | S::Socket
        | S::Socketpair
        | S::Bind
        | S::Connect
        | S::Listen
        | S::Accept4
        | S::Getsockopt
        | S::Setsockopt
        | S::Getsockname
        | S::Getpeername
        | S::Sendto
        | S::Recvfrom
        | S::Shutdown
        | S::Sendmsg
        | S::Recvmsg
        | S::Sendmmsg
        // Threads: clone's CLONE_SETTLS reads a struct user_desc
        // (`thread::NewTls`), the robust-list calls keep the 32-bit list,
        // and struct futex_waitv has one layout.
        | S::Clone
        | S::Clone3
        | S::SetRobustList
        | S::GetRobustList
        | S::FutexWaitv
        | S::FutexWake
        | S::FutexWait
        | S::FutexRequeue
        // struct compat_siginfo in and out (`read_user_siginfo`,
        // rt_sigtimedwait), and the i386 frames of the sigreturns.
        | S::RtSigqueueinfo
        | S::RtTgsigqueueinfo
        | S::PidfdSendSignal
        | S::RtSigreturn
        | S::Pause
        | S::Alarm
        | S::Uname
        | S::Personality
        | S::SchedYield
        | S::SchedSetparam
        | S::SchedGetparam
        | S::SchedSetscheduler
        | S::SchedGetscheduler
        | S::SchedGetPriorityMax
        | S::SchedGetPriorityMin
        | S::SchedSetattr
        | S::SchedGetattr
        | S::Getpriority
        | S::Setpriority
        | S::IoprioGet
        | S::IoprioSet
        | S::Getcpu
        | S::Capget
        | S::Capset
        | S::Prlimit64
        | S::Getrandom
        | S::MemfdCreate
        | S::Membarrier
        | S::Rseq
        | S::Kcmp
        | S::Unshare
        | S::EpollCreate
        | S::EpollCreate1
        // struct epoll_event is packed on x86-64 to match i386's.
        | S::EpollCtl
        | S::EpollWait
        | S::EpollPwait
        // struct __kernel_timespec, its padding cleared (`timeabi`).
        | S::EpollPwait2
        | S::Eventfd
        | S::Eventfd2
        | S::TimerfdCreate
        | S::Signalfd
        | S::Signalfd4
        | S::InotifyInit
        | S::InotifyInit1
        | S::InotifyAddWatch
        | S::InotifyRmWatch
        | S::PidfdOpen
        | S::PidfdGetfd
        | S::Mount
        | S::Umount2
        | S::Fsopen
        | S::Fsconfig
        | S::Fsmount
        | S::Fspick
        | S::MoveMount
        | S::Sethostname
        | S::Setdomainname
        | S::Swapon
        | S::Swapoff
        | S::Reboot
        | S::Acct
        | S::Vhangup
        | S::Iopl
        | S::Ioperm
        | S::Syslog
        | S::InitModule
        | S::FinitModule
        | S::DeleteModule
        // The vectors are read as struct compat_iovec (`iov`).
        | S::Readv
        | S::Writev
        | S::ProcessVmReadv
        | S::ProcessVmWritev
        | S::ProcessMadvise
        // The argument and environment vectors hold compat_uptr_ts.
        | S::Execve
        | S::Execveat => call_handler(c, s, a),
        // struct compat_rusage, struct compat_tms, struct compat_sysinfo,
        // struct compat_siginfo's waitid fields, and arch_prctl's common
        // options: each native handler's 32-bit form.
        | S::Getrusage
        | S::Wait4
        | S::Waitid
        | S::Times
        | S::Sysinfo
        | S::ArchPrctl => call_handler(c, s, a),
        // sys_waitpid: wait4 without a usage record.
        S::Waitpid => call_handler(c, S::Wait4, [a[0], a[1], a[2], 0, 0, 0]),
        // prctl and seccomp: a filter's struct compat_sock_fprog is read
        // where Ctx::compat is.
        S::Prctl | S::Seccomp => call_handler(c, s, a),
        // The 32-bit ID calls are the native ones.
        S::Getuid32 => call_handler(c, S::Getuid, a),
        S::Geteuid32 => call_handler(c, S::Geteuid, a),
        S::Getgid32 => call_handler(c, S::Getgid, a),
        S::Getegid32 => call_handler(c, S::Getegid, a),
        S::Setuid32 => call_handler(c, S::Setuid, a),
        S::Setgid32 => call_handler(c, S::Setgid, a),
        S::Setreuid32 => call_handler(c, S::Setreuid, a),
        S::Setregid32 => call_handler(c, S::Setregid, a),
        S::Setresuid32 => call_handler(c, S::Setresuid, a),
        S::Setresgid32 => call_handler(c, S::Setresgid, a),
        S::Getresuid32 => call_handler(c, S::Getresuid, a),
        S::Getresgid32 => call_handler(c, S::Getresgid, a),
        S::Setfsuid32 => call_handler(c, S::Setfsuid, a),
        S::Setfsgid32 => call_handler(c, S::Setfsgid, a),
        S::Getgroups32 => call_handler(c, S::Getgroups, a),
        S::Setgroups32 => call_handler(c, S::Setgroups, a),
        S::Chown32 => call_handler(c, S::Chown, a),
        S::Lchown32 => call_handler(c, S::Lchown, a),
        S::Fchown32 => call_handler(c, S::Fchown, a),
        // The 16-bit ID calls (kernel/uid16.c).
        S::Getuid => r(uid16::get(c.p.creds.0)),
        S::Geteuid => r(uid16::get(c.p.creds.1)),
        S::Getgid => r(uid16::get(c.p.creds.2)),
        S::Getegid => r(uid16::get(c.p.creds.3)),
        S::Setuid | S::Setgid | S::Setfsuid | S::Setfsgid => uid16::widened(c, s, a, &[0]),
        S::Setreuid | S::Setregid => uid16::widened(c, s, a, &[0, 1]),
        S::Setresuid | S::Setresgid => uid16::widened(c, s, a, &[0, 1, 2]),
        S::Chown | S::Lchown | S::Fchown => uid16::widened(c, s, a, &[1, 2]),
        S::Getresuid => r(uid16::getres(c, a, true)),
        S::Getresgid => r(uid16::getres(c, a, false)),
        S::Getgroups => r(uid16::getgroups(c, a[0] as i32, a[1])),
        S::Setgroups => r(uid16::setgroups(c, a[0] as i32, a[1])),
        // Limits, CPU masks, the old unames, and nice.
        S::Getrlimit => r(resource::old_getrlimit(c, a[0] as u32, a[1])),
        S::Ugetrlimit => r(resource::getrlimit(c, a[0] as u32, a[1])),
        S::Setrlimit => r(resource::setrlimit(c, a[0] as u32, a[1])),
        S::SchedGetaffinity => r(resource::sched_getaffinity(c, fd(a[0]), a[1] as u32, a[2])),
        S::SchedSetaffinity => r(resource::sched_setaffinity(c, fd(a[0]), a[1] as u32, a[2])),
        S::Olduname => r(process::old_uname(c, a[0], 65)),
        S::Oldolduname => r(process::old_uname(c, a[0], 9)),
        S::Nice => r(priority::nice(c, a[0] as i32)),
        S::SetThreadArea => r(tls::set_thread_area(c, a[0])),
        // Signals.
        S::RtSigaction => r(signal::rt_sigaction(c, a[0] as i32, a[1], a[2], a[3])),
        S::Sigaction => r(signal::sigaction(c, a[0] as i32, a[1], a[2])),
        S::Signal => r(signal::signal(c, a[0] as i32, a[1])),
        S::Sgetmask => Ok(Outcome::Return(signal::sgetmask(c))),
        S::Ssetmask => Ok(Outcome::Return(signal::ssetmask(c, a[0]))),
        S::Sigprocmask => r(signal::sigprocmask(c, a[0] as i32, a[1], a[2])),
        S::Sigpending => r(signal::sigpending(c, a[0])),
        S::Sigsuspend => signal::sigsuspend_old(c, a[2]),
        S::Sigaltstack => r(signal::sigaltstack(c, a[0], a[1])),
        S::Sigreturn => super::signal::sigreturn(c),
        S::RtSigtimedwait => time32(c, S::RtSigtimedwait, a),
        S::Socketcall => net::socketcall(c, a[0], a[1]),
        // System V IPC: the calls whose layouts are the same, the ipc
        // multiplexer, and the compatibility entry points.
        S::Semget | S::Shmget | S::Shmat | S::Shmdt | S::Msgget => call_handler(c, s, a),
        S::SemtimedopTime64 => call_handler(c, S::Semtimedop, a),
        S::Ipc => r(ipc::ipc(c, a)),
        S::Semctl => r(ipc::semctl(c, fd(a[0]), fd(a[1]), fd(a[2]), a[3], true)),
        S::Msgctl => r(ipc::msgctl(c, fd(a[0]), fd(a[1]), a[2], true)),
        S::Shmctl => r(ipc::shmctl(c, fd(a[0]), fd(a[1]), a[2], true)),
        // compat_ssize_t sizes and a compat_long_t type, sign-extended.
        S::Msgsnd => call_handler(c, S::Msgsnd, [a[0], a[1], sext(a[2]) as u64, a[3], 0, 0]),
        S::Msgrcv => call_handler(
            c,
            S::Msgrcv,
            [a[0], a[1], sext(a[2]) as u64, sext(a[3]) as u64, a[4], 0],
        ),
        // POSIX message queues: struct compat_mq_attr and struct
        // compat_sigevent are read where Ctx::compat is; mq_timedsend and
        // mq_timedreceive are the *_time32 calls.
        S::MqOpen | S::MqUnlink | S::MqNotify | S::MqGetsetattr => call_handler(c, s, a),
        S::MqTimedsend | S::MqTimedreceive => time32(c, s, a),
        S::MqTimedsendTime64 => call_handler(c, S::MqTimedsend, a),
        S::MqTimedreceiveTime64 => call_handler(c, S::MqTimedreceive, a),
        // Asynchronous I/O: a 32-bit context and iocb pointers
        // (compat_sys_io_setup, compat_sys_io_submit's int count), the
        // *_time32 io_getevents with __s32 counts, and io_pgetevents with
        // struct __compat_aio_sigset and compat_long_t counts.
        S::IoSetup | S::IoDestroy | S::IoCancel => call_handler(c, s, a),
        S::IoSubmit => call_handler(c, s, [a[0], sext(a[1]) as u64, a[2], 0, 0, 0]),
        S::IoGetevents | S::IoPgetevents => {
            c.time32 = true;
            call_handler(c, s, aio_counts(a))
        }
        S::IoPgeteventsTime64 => call_handler(c, S::IoPgetevents, aio_counts(a)),
        // select, pselect6, and ppoll: fd sets of 32-bit words, struct
        // old_timeval32, struct compat_sigset_argpack, and the *_time32
        // timeouts beside the *_time64 ones. The old select takes its
        // arguments in a struct compat_sel_arg_struct.
        S::Select => {
            let b = c.read_mem(a[0], 20)?;
            let w = |i: usize| u64::from(u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap()));
            call_handler(c, S::Select, [w(0), w(1), w(2), w(3), w(4), 0])
        }
        S::Newselect => call_handler(c, S::Select, a),
        S::Pselect6 | S::Ppoll => time32(c, s, a),
        S::Pselect6Time64 => call_handler(c, S::Pselect6, a),
        S::PpollTime64 => call_handler(c, S::Ppoll, a),
        // struct mount_attr has one layout.
        S::OpenTree | S::OpenTreeAttr | S::MountSetattr => call_handler(c, s, a),
        // ptrace: compat_arch_ptrace's words, structures, and i386 register
        // view, where Ctx::compat is.
        S::Ptrace => call_handler(c, s, a),
        // recvmmsg_time32 and recvmmsg_time64.
        S::Recvmmsg => time32(c, S::Recvmmsg, a),
        S::RecvmmsgTime64 => call_handler(c, S::Recvmmsg, a),
        // futex_time32 and futex_time64.
        S::Futex => time32(c, S::Futex, a),
        S::FutexTime64 => call_handler(c, S::Futex, a),
        S::RtSigtimedwaitTime64 => call_handler(c, S::RtSigtimedwait, a),
        S::GetThreadArea => r(tls::get_thread_area(c, a[0])),
        // sys_mmap_pgoff: the offset in pages.
        S::Mmap2 => {
            let mut native = a;
            native[5] = u64::from(a[5] as u32) << PAGE_SHIFT;
            call_handler(c, S::Mmap, native)
        }
        // compat_sys_ia32_mmap: the arguments in a struct mmap_arg_struct32.
        S::Mmap => {
            let b = c.read_mem(a[0], 24)?;
            let word = |i: usize| u64::from(u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap()));
            if word(5) & ((1 << PAGE_SHIFT) - 1) != 0 {
                return Err(Errno(EINVAL));
            }
            call_handler(c, S::Mmap, [word(0), word(1), word(2), word(3), word(4), word(5)])
        }
        S::Ioctl => ioctl(c, a),

        // compat_sys_open and compat_sys_openat: no forced O_LARGEFILE.
        S::Open => r(path::compat_openat(c, AT_FDCWD, a[0], a[1] as u32, a[2] as u32)),
        S::Openat => r(path::compat_openat(c, fd(a[0]), a[1], a[2] as u32, a[3] as u32)),
        // sys_oldumount: umount without flags.
        S::Umount => call_handler(c, S::Umount2, [a[0], 0, 0, 0, 0, 0]),

        // Offsets.
        S::Lseek => r(file::lseek(c, fd(a[0]), a[1], a[2] as u32)),
        S::Llseek => r(file::llseek(c, fd(a[0]), a[1], a[2], a[3], a[4] as u32)),
        S::Pread64 => r(io::pread(c, fd(a[0]), a[1], a[2], dual(a[3], a[4]))),
        S::Pwrite64 => r(io::pwrite(c, fd(a[0]), a[1], a[2], dual(a[3], a[4]))),
        S::Preadv => r(io::preadv(c, fd(a[0]), a[1], a[2], Some(dual(a[3], a[4])), 0)),
        S::Pwritev => r(io::pwritev(c, fd(a[0]), a[1], a[2], Some(dual(a[3], a[4])), 0)),
        S::Preadv2 => {
            let pos = dual(a[3], a[4]);
            r(io::preadv(c, fd(a[0]), a[1], a[2], (pos != -1).then_some(pos), a[5]))
        }
        S::Pwritev2 => {
            let pos = dual(a[3], a[4]);
            r(io::pwritev(c, fd(a[0]), a[1], a[2], (pos != -1).then_some(pos), a[5]))
        }
        S::Truncate => r(path::truncate(c, a[0], sext(a[1]))),
        S::Truncate64 => r(path::truncate(c, a[0], dual(a[1], a[2]))),
        S::Ftruncate => r(file::ftruncate(c, fd(a[0]), sext(a[1]))),
        S::Ftruncate64 => r(file::ftruncate(c, fd(a[0]), dual(a[1], a[2]))),
        // sys_ia32_fadvise64: a size_t length.
        S::Fadvise64 => r(io::fadvise(c, fd(a[0]), a[3] as i64, a[4] as u32)),
        S::Fadvise6464 => r(io::fadvise(c, fd(a[0]), dual(a[3], a[4]), a[5] as u32)),
        S::Readahead => r(io::readahead(c, fd(a[0]))),
        S::SyncFileRange => r(io::sync_file_range(
            c,
            fd(a[0]),
            dual(a[1], a[2]),
            dual(a[3], a[4]),
            a[5] as u32,
        )),
        S::Fallocate => r(io::fallocate(
            c,
            fd(a[0]),
            a[1] as u32,
            dual(a[2], a[3]),
            dual(a[4], a[5]),
        )),
        S::Sendfile => r(file::sendfile(c, a, SendfileOffset::Compat)),
        S::Sendfile64 => r(file::sendfile(c, a, SendfileOffset::Loff)),
        S::Fcntl => r(file::fcntl(c, fd(a[0]), a[1] as u32, a[2], false)),
        S::Fcntl64 => r(file::fcntl(c, fd(a[0]), a[1] as u32, a[2], true)),

        // Status.
        S::Stat => r(stat::stat(c, Of::followed(a[0]), a[1])),
        S::Lstat => r(stat::stat(c, Of::link(a[0]), a[1])),
        S::Fstat => r(stat::stat(c, Of::Fd(fd(a[0])), a[1])),
        S::Stat64 => r(stat::stat64(c, Of::followed(a[0]), a[1])),
        S::Lstat64 => r(stat::stat64(c, Of::link(a[0]), a[1])),
        S::Fstat64 => r(stat::stat64(c, Of::Fd(fd(a[0])), a[1])),
        S::Fstatat64 => {
            let of = Of::Path {
                dirfd: fd(a[0]),
                path: a[1],
                flags: a[3] as u32,
            };
            r(stat::stat64(c, of, a[2]))
        }
        S::Oldstat => r(stat::old_stat(c, Of::followed(a[0]), a[1])),
        S::Oldlstat => r(stat::old_stat(c, Of::link(a[0]), a[1])),
        S::Oldfstat => r(stat::old_stat(c, Of::Fd(fd(a[0])), a[1])),
        S::Statfs => r(stat::statfs(c, FsOf::Path(a[0]), a[1])),
        S::Fstatfs => r(stat::statfs(c, FsOf::Fd(fd(a[0])), a[1])),
        S::Statfs64 => r(stat::statfs64(c, FsOf::Path(a[0]), a[1], a[2])),
        S::Fstatfs64 => r(stat::statfs64(c, FsOf::Fd(fd(a[0])), a[1], a[2])),
        S::Getdents => r(dirents::getdents(c, fd(a[0]), a[1], a[2], Dirent::Compat)),
        S::Readdir => r(dirents::old_readdir(c, fd(a[0]), a[1])),

        // The *_time32 calls: struct old_timespec32, old_time32_t, and
        // struct old_timex32.
        S::Time => time32(c, S::Time, a),
        S::Stime => r(time::stime(c, a[0])),
        S::ClockGettime => time32(c, S::ClockGettime, a),
        S::ClockSettime => time32(c, S::ClockSettime, a),
        S::ClockGetres => time32(c, S::ClockGetres, a),
        S::ClockNanosleep => time32(c, S::ClockNanosleep, a),
        S::Nanosleep => time32(c, S::Nanosleep, a),
        S::SchedRrGetInterval => time32(c, S::SchedRrGetInterval, a),
        S::Utimensat => time32(c, S::Utimensat, a),
        S::TimerSettime => time32(c, S::TimerSettime, a),
        S::TimerGettime => time32(c, S::TimerGettime, a),
        S::TimerfdSettime => time32(c, S::TimerfdSettime, a),
        S::TimerfdGettime => time32(c, S::TimerfdGettime, a),
        S::Adjtimex => time32(c, S::Adjtimex, a),
        S::ClockAdjtime => time32(c, S::ClockAdjtime, a),
        // Their *_time64 forms: struct __kernel_timespec, the padding
        // above the nanoseconds cleared (`timeabi`).
        S::ClockGettime64 => call_handler(c, S::ClockGettime, a),
        S::ClockSettime64 => call_handler(c, S::ClockSettime, a),
        S::ClockGetresTime64 => call_handler(c, S::ClockGetres, a),
        S::ClockNanosleepTime64 => call_handler(c, S::ClockNanosleep, a),
        S::ClockAdjtime64 => call_handler(c, S::ClockAdjtime, a),
        S::SchedRrGetIntervalTime64 => call_handler(c, S::SchedRrGetInterval, a),
        S::UtimensatTime64 => call_handler(c, S::Utimensat, a),
        S::TimerSettime64 => call_handler(c, S::TimerSettime, a),
        S::TimerGettime64 => call_handler(c, S::TimerGettime, a),
        S::TimerfdSettime64 => call_handler(c, S::TimerfdSettime, a),
        S::TimerfdGettime64 => call_handler(c, S::TimerfdGettime, a),
        // struct old_timeval32, struct old_itimerval32, struct
        // old_utimbuf32, and struct compat_sigevent: every 32-bit call's.
        S::Gettimeofday
        | S::Settimeofday
        | S::Getitimer
        | S::Setitimer
        | S::Utimes
        | S::Futimesat
        | S::Utime
        | S::TimerCreate
        | S::TimerGetoverrun
        | S::TimerDelete => call_handler(c, s, a),
        _ => Err(Errno(ENOSYS)),
    }
}

/// `compat_sys_ioctl`: the descriptor first (`EBADF`); the commands
/// `do_vfs_ioctl` handles and the terminal ones with one layout, and every
/// command of the files whose `compat_ioctl` is the native handler
/// (`compat_ptr_ioctl`: pidfds and `epoll`; `inotify_ioctl`) or converts
/// in it (`compat_sock_ioctl`: a socket's interface requests read the
/// 32-bit structures where [`Ctx::compat`] is), run natively. Any other
/// command has no 32-bit conversion here (`ENOTTY`, as for a file without
/// `compat_ioctl`, such as a `timerfd`).
fn ioctl(c: &mut Ctx<'_>, a: [u64; 6]) -> Result<Outcome, Errno> {
    use super::super::fs::anon::Anon;
    use super::super::fs::fd::FileObject;
    let file = c.p.fds.file(a[0] as i32)?;
    let cmd = a[1] as u32;
    let native = SAME_LAYOUT_IOCTLS.contains(&cmd)
        || match &file.object {
            FileObject::Anon(Anon::Pid(_) | Anon::Epoll(_) | Anon::Inotify(_)) => true,
            FileObject::Socket(_) => net::sock_ioctl_known(cmd),
            _ => false,
        };
    if native {
        call_handler(c, S::Ioctl, a)
    } else {
        Err(Errno(ENOTTY))
    }
}

/// A `*_time32` call: the native one with the 32-bit time layouts.
/// The `io_getevents` family's `min_nr` and `nr`, 32-bit and sign-extended.
fn aio_counts(a: [u64; 6]) -> [u64; 6] {
    [a[0], sext(a[1]) as u64, sext(a[2]) as u64, a[3], a[4], a[5]]
}

fn time32(c: &mut Ctx<'_>, s: S, a: [u64; 6]) -> Result<Outcome, Errno> {
    c.time32 = true;
    call_handler(c, s, a)
}
