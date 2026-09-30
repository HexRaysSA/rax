//! Closed Linux embedding policy. Only reviewed, guest-local operations enter
//! the shared handlers. New syscall identities are denied until reviewed here.
use super::abi::Sysno;
use super::process::{LinuxConfig, SpawnError};

/// Virtual process identity; independent processes have independent namespaces.
pub const PID: i32 = 100;

/// Runtime host capability checks are distinct from the guest syscall policy.
/// In particular, old Windows keeps private PE execution while refusing an ELF
/// personality that promises shared mappings.
pub(super) fn validate_host(
    c: &LinuxConfig,
    host_services: bool,
    shared_mappings: bool,
) -> Result<(), SpawnError> {
    if c.host_services && !host_services {
        return Err(SpawnError::Unsupported("this host supports the closed Linux embedding profile; Unix host services are unavailable".into()));
    }
    if !shared_mappings {
        return Err(SpawnError::Unsupported("Linux embedding requires fixed-address shared memory; Windows hosts require VirtualAlloc2, MapViewOfFile3 and UnmapViewOfFile2 placeholder support".into()));
    }
    Ok(())
}

pub fn validate(c: &LinuxConfig) -> Result<(), SpawnError> {
    if c.supplied_files.is_none()
        || c.sysroot.is_some()
        || c.processes
        || c.ipc_dir.is_some()
        || c.fsnotify != super::fsnotify::Backend::Disabled
        || c.strace
        || c.seed.is_none()
        || !matches!(c.console, crate::user::console::Console::Captured(_))
    {
        return Err(SpawnError::Unsupported(
            "closed Linux embedding requires supplied files, captured console, seeded entropy, disabled notifications and no host process/IPC/sysroot/trace services".into()));
    }
    Ok(())
}

/// Constant-time dispatch over the ABI-independent syscall identity. Known
/// calls outside this set return EPERM; unknown numbers retain ENOSYS. Read,
/// map and descriptor handlers can reach only supplied or emulated objects.
pub fn permits(s: Sysno) -> bool {
    use Sysno as S;
    matches!(
        s,
        S::Exit
            | S::ExitGroup
            | S::Clone
            | S::Clone3
            | S::SchedYield
            | S::Execve
            | S::Execveat
            | S::Read
            | S::Write
            | S::Readv
            | S::Writev
            | S::Pread64
            | S::Pwrite64
            | S::Preadv
            | S::Pwritev
            | S::Preadv2
            | S::Pwritev2
            | S::Close
            | S::CloseRange
            | S::Lseek
            | S::Llseek
            | S::Dup
            | S::Dup2
            | S::Dup3
            | S::Fcntl
            | S::Fcntl64
            | S::Ioctl
            | S::Poll
            | S::Ppoll
            | S::PpollTime64
            | S::Select
            | S::Newselect
            | S::Pselect6
            | S::Pselect6Time64
            | S::Getdents
            | S::Getdents64
            | S::Readdir
            | S::Open
            | S::Openat
            | S::Openat2
            | S::Creat
            | S::Access
            | S::Faccessat
            | S::Faccessat2
            | S::Readlink
            | S::Readlinkat
            | S::Getcwd
            | S::Chdir
            | S::Fchdir
            | S::Stat
            | S::Lstat
            | S::Fstat
            | S::Stat64
            | S::Lstat64
            | S::Fstat64
            | S::Oldstat
            | S::Oldlstat
            | S::Oldfstat
            | S::Newfstatat
            | S::Fstatat64
            | S::Statx
            | S::Statfs
            | S::Fstatfs
            | S::Statfs64
            | S::Fstatfs64
            | S::Umask
            | S::Getxattr
            | S::Lgetxattr
            | S::Fgetxattr
            | S::Listxattr
            | S::Llistxattr
            | S::Flistxattr
            | S::Getxattrat
            | S::Listxattrat
            | S::Brk
            | S::Mmap
            | S::Mmap2
            | S::Munmap
            | S::Mprotect
            | S::Mremap
            | S::Madvise
            | S::Mincore
            | S::Msync
            | S::Mseal
            | S::Getpid
            | S::Getppid
            | S::Gettid
            | S::Getuid
            | S::Geteuid
            | S::Getgid
            | S::Getegid
            | S::Getresuid
            | S::Getresgid
            | S::Getgroups
            | S::Getuid32
            | S::Geteuid32
            | S::Getgid32
            | S::Getegid32
            | S::Getresuid32
            | S::Getresgid32
            | S::Getgroups32
            | S::Setuid
            | S::Setgid
            | S::Setreuid
            | S::Setregid
            | S::Setresuid
            | S::Setresgid
            | S::Setgroups
            | S::Setfsuid
            | S::Setfsgid
            | S::Setuid32
            | S::Setgid32
            | S::Setreuid32
            | S::Setregid32
            | S::Setresuid32
            | S::Setresgid32
            | S::Setgroups32
            | S::Setfsuid32
            | S::Setfsgid32
            | S::Getpgid
            | S::Getpgrp
            | S::Getsid
            | S::SetTidAddress
            | S::SetRobustList
            | S::GetRobustList
            | S::Uname
            | S::Olduname
            | S::Oldolduname
            | S::Sysinfo
            | S::Getrlimit
            | S::Ugetrlimit
            | S::Setrlimit
            | S::Prlimit64
            | S::ArchPrctl
            | S::Prctl
            | S::Personality
            | S::Getrandom
            | S::SchedGetaffinity
            | S::SchedSetaffinity
            | S::Getcpu
            | S::Capget
            | S::Membarrier
            | S::SetThreadArea
            | S::GetThreadArea
            | S::Rseq
            | S::RiscvHwprobe
            | S::RiscvFlushIcache
            | S::Futex
            | S::FutexTime64
            | S::FutexWaitv
            | S::FutexWait
            | S::FutexWake
            | S::FutexRequeue
            | S::ClockGettime
            | S::ClockGettime64
            | S::ClockGetres
            | S::ClockGetresTime64
            | S::Gettimeofday
            | S::Time
            | S::Nanosleep
            | S::ClockNanosleep
            | S::ClockNanosleepTime64
            | S::Alarm
            | S::Getitimer
            | S::Setitimer
            | S::TimerCreate
            | S::TimerSettime
            | S::TimerGettime
            | S::TimerGetoverrun
            | S::TimerDelete
            | S::TimerGettime64
            | S::TimerSettime64
            | S::RtSigaction
            | S::RtSigprocmask
            | S::RtSigreturn
            | S::RtSigpending
            | S::RtSigtimedwait
            | S::RtSigtimedwaitTime64
            | S::RtSigsuspend
            | S::RtSigqueueinfo
            | S::RtTgsigqueueinfo
            | S::Sigaction
            | S::Sigprocmask
            | S::Sigreturn
            | S::Sigpending
            | S::Sigsuspend
            | S::Signal
            | S::Sgetmask
            | S::Ssetmask
            | S::Sigaltstack
            | S::Pause
            | S::Kill
            | S::Tkill
            | S::Tgkill
            | S::RestartSyscall
            | S::Eventfd
            | S::Eventfd2
            | S::Signalfd
            | S::Signalfd4
            | S::TimerfdCreate
            | S::TimerfdSettime
            | S::TimerfdGettime
            | S::TimerfdSettime64
            | S::TimerfdGettime64
            | S::EpollCreate
            | S::EpollCreate1
            | S::EpollCtl
            | S::EpollWait
            | S::EpollPwait
            | S::EpollPwait2
    )
}
