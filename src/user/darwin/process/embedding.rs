//! Closed process configuration and BSD syscall admission.

use super::{DarwinConfig, ImageFile, SpawnError, Vfs};
use crate::user::console::Console;

pub(super) fn prepare(config: &DarwinConfig, image: &mut ImageFile) -> Result<Vfs, SpawnError> {
    if config.host_services {
        if !crate::user::darwin::HOST_SERVICES_AVAILABLE {
            return Err(SpawnError::Configuration(
                "the host-backed Darwin profile requires Unix host services",
            ));
        }
        if config.supplied_files.is_some() {
            return Err(SpawnError::Configuration(
                "supplied files require disabled host services",
            ));
        }
        return Ok(Vfs::new(config.root.clone()));
    }
    if config.root.is_some()
        || config.host_job_control
        || config.inherited.is_some()
        || config.strace
    {
        return Err(SpawnError::Configuration(
            "embedded processes cannot use host roots, job control, inherited signals, or stderr tracing",
        ));
    }
    if !matches!(config.console, Console::Captured(_)) || config.seed.is_none() {
        return Err(SpawnError::Configuration(
            "embedded processes require captured streams and an explicit entropy seed",
        ));
    }
    if !config.cwd.starts_with('/') {
        return Err(SpawnError::Configuration(
            "guest working directory must be absolute",
        ));
    }
    let files = config
        .supplied_files
        .as_ref()
        .ok_or(SpawnError::Configuration(
            "embedded processes require a supplied namespace",
        ))?;
    let files = files
        .with_file(config.exec_path.clone(), image.bytes.clone())
        .map_err(|e| SpawnError::Io(config.exec_path.clone(), std::io::Error::other(e)))?;
    let vfs = Vfs::supplied(files);
    let (_, cwd) = vfs
        .lookup(config.cwd.as_bytes(), b"/")
        .map_err(|e| SpawnError::Io(config.cwd.clone(), e))?;
    if !cwd.is_dir() {
        return Err(SpawnError::Configuration(
            "guest working directory is not a directory",
        ));
    }
    let slice = image.slice;
    *image = ImageFile::from_supplied(&config.exec_path, &vfs)
        .map_err(|e| SpawnError::Io(config.exec_path.clone(), e))?;
    image.slice = slice;
    Ok(vfs)
}

/// Admission requires auditing that a handler only uses guest-owned state.
/// Unadmitted handlers fail before argument handling or host operations.
pub(crate) fn bsd_allowed(number: u32) -> bool {
    use crate::user::darwin::abi::tables::nr;
    matches!(
        number,
        nr::EXIT
            | nr::READ
            | nr::READ_NOCANCEL
            | nr::WRITE
            | nr::WRITE_NOCANCEL
            | nr::PREAD
            | nr::PREAD_NOCANCEL
            | nr::PWRITE
            | nr::PWRITE_NOCANCEL
            | nr::READV
            | nr::READV_NOCANCEL
            | nr::WRITEV
            | nr::WRITEV_NOCANCEL
            | nr::PREADV
            | nr::PREADV_NOCANCEL
            | nr::PWRITEV
            | nr::PWRITEV_NOCANCEL
            | nr::OPEN
            | nr::OPEN_NOCANCEL
            | nr::OPENAT
            | nr::OPENAT_NOCANCEL
            | nr::CLOSE
            | nr::CLOSE_NOCANCEL
            | nr::LSEEK
            | nr::DUP
            | nr::DUP2
            | nr::DUP3
            | nr::FCNTL
            | nr::FCNTL_NOCANCEL
            | nr::IOCTL
            | nr::FSTAT64
            | nr::STAT64
            | nr::LSTAT64
            | nr::FSTATAT64
            | nr::ACCESS
            | nr::FACCESSAT
            | nr::READLINK
            | nr::READLINKAT
            | nr::CHDIR
            | nr::FCHDIR
            | nr::GETPID
            | nr::GETPPID
            | nr::GETUID
            | nr::GETEUID
            | nr::GETGID
            | nr::GETEGID
            | nr::GETENTROPY
            | nr::GETRLIMIT
            | nr::SETRLIMIT
            | nr::GETTIMEOFDAY
            | nr::MMAP
            | nr::MUNMAP
            | nr::MPROTECT
            | nr::MADVISE
            | nr::MINHERIT
            | nr::MSYNC
            | nr::MSYNC_NOCANCEL
            | nr::MINCORE
            | nr::MLOCK
            | nr::MUNLOCK
            | nr::SHARED_REGION_CHECK_NP
            | nr::SHARED_REGION_MAP_AND_SLIDE_2_NP
            | nr::UMASK
            | nr::UMASK_EXTENDED
            | nr::GETDTABLESIZE
            | nr::ISSETUGID
            | nr::SYSCTL
            | nr::SYSCTLBYNAME
            | nr::SIGACTION
            | nr::SIGPROCMASK
            | nr::PTHREAD_SIGMASK
            | nr::SIGPENDING
            | nr::SIGSUSPEND
            | nr::SIGSUSPEND_NOCANCEL
            | nr::SIGWAIT
            | nr::SIGWAIT_NOCANCEL
            | nr::SIGALTSTACK
            | nr::SIGRETURN
            | nr::KILL
            | nr::PTHREAD_KILL
            | nr::SETITIMER
            | nr::GETITIMER
            | nr::DISABLE_THREADSIGNAL
            | nr::THREAD_SELFID
            | nr::BSDTHREAD_REGISTER
            | nr::BSDTHREAD_CREATE
            | nr::BSDTHREAD_TERMINATE
            | nr::PTHREAD_MARKCANCEL
            | nr::PTHREAD_CANCELED
            | nr::ULOCK_WAIT
            | nr::ULOCK_WAIT2
            | nr::ULOCK_WAKE
            | nr::SEMWAIT_SIGNAL
            | nr::SEMWAIT_SIGNAL_NOCANCEL
    )
}
