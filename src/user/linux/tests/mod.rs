//! Linux personality unit tests.
//!
//! Host-service fixtures require the Unix host profile. The closed embedding,
//! scheduler, syscall-entry, resource limits, sealing, restartable sequences,
//! ELF-loader, and stack contracts run on every host.

#[cfg(unix)]
mod admin;
#[cfg(unix)]
mod aio;
#[cfg(unix)]
mod arm;
mod bounded;
#[cfg(unix)]
mod console;
mod entry;
#[cfg(unix)]
mod epoll;
#[cfg(unix)]
mod events;
#[cfg(unix)]
mod exclusive;
#[cfg(unix)]
mod exec;
#[cfg(unix)]
mod fdinfo;
#[cfg(unix)]
mod files;
mod harness;
#[cfg(unix)]
mod i386;
#[cfg(unix)]
mod ifreq;
#[cfg(unix)]
mod inotify;
#[cfg(unix)]
mod kcmp;
mod limits;
mod loader;
#[cfg(unix)]
mod locks;
#[cfg(unix)]
mod misc;
#[cfg(unix)]
mod mlock;
#[cfg(unix)]
mod mounts;
#[cfg(unix)]
mod mqueue;
mod mseal;
#[cfg(unix)]
mod netlink;
#[cfg(unix)]
mod nodes;
#[cfg(unix)]
mod pidfd;
#[cfg(unix)]
mod posix_timers;
#[cfg(unix)]
mod priority;
#[cfg(unix)]
mod procfs;
#[cfg(unix)]
mod procmem;
#[cfg(unix)]
mod ptrace;
#[cfg(unix)]
mod ptrace_events;
#[cfg(unix)]
mod ptrace_fork;
#[cfg(unix)]
mod ptrace_jobctl;
#[cfg(unix)]
mod ptrace_regsets;
#[cfg(unix)]
mod ptrace_seccomp;
#[cfg(unix)]
mod ptrace_stops;
mod rseq;
#[cfg(unix)]
mod seccomp;
#[cfg(unix)]
mod signals;
#[cfg(unix)]
mod sockets;
#[cfg(unix)]
mod splice;
mod stack;
#[cfg(unix)]
mod supplied;
#[cfg(unix)]
mod syscall_mm;
#[cfg(unix)]
mod sysvmsg;
#[cfg(unix)]
mod sysvsem;
#[cfg(unix)]
mod sysvshm;
#[cfg(unix)]
mod threads;
#[cfg(unix)]
mod uring;
#[cfg(unix)]
mod vectored;
#[cfg(unix)]
mod waits;
#[cfg(unix)]
mod xattr;

mod embedded;
mod embedded_files;
