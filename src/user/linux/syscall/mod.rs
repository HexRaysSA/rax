//! Linux system-call dispatch.
//!
//! [`dispatch`] resolves an ABI system-call number to its [`Sysno`], runs
//! the handler, and produces the [`Outcome`] the process applies to the
//! calling thread. Handlers are grouped by subsystem:
//!
//! | Module | Calls |
//! |---|---|
//! | [`io`] | descriptors, `read`/`write` families, pipes, polling |
//! | [`fcntl`] | `fcntl`, `ioctl` |
//! | [`path`] | `open`, `stat`, directory and name operations, working directory |
//! | [`mem`] | `brk`, `mmap` family, `madvise` |
//! | [`procmem`] | `process_vm_readv`, `process_vm_writev`, `process_madvise` |
//! | [`kcmp`] | `kcmp` |
//! | [`process`] | identity, limits, `uname`, `prctl`, `arch_prctl` |
//! | [`thread`] | `clone`/`clone3`, thread exit, `set_tid_address`, `sched_yield` |
//! | [`futex`] | `futex`, `futex_waitv`, the `futex2` calls, robust lists |
//! | [`time`] | clocks and sleeping |
//! | [`signal`] | signal dispositions and masks |
//! | [`net`] | sockets |
//!
//! Shared by handlers: [`iov`] imports `struct iovec` arrays as the kernel
//! does, and [`task`] names another task and decides whether it may be
//! inspected.
//!
//! A handler that must sleep records what it waits for with
//! [`Ctx::block`]; the thread is parked and the call dispatched again,
//! with its [`Resume`] record in [`Ctx::resume`], when the wait can end
//! (see [`wait`](super::wait)).
//!
//! Unknown numbers, and calls RAX does not implement, return `-ENOSYS`, which
//! is what a kernel built without the call returns; C libraries treat it as
//! "unsupported" and fall back.

pub mod admin;
pub mod child;
pub mod epoll;
pub mod events;
pub mod exec;
pub mod fcntl;
pub mod futex;
pub mod inotify;
pub mod io;
pub mod iov;
pub mod ipc;
pub mod kcmp;
pub mod locks;
pub mod mem;
pub mod memfd;
pub mod mount;
pub mod mqueue;
pub mod net;
pub mod notify;
pub mod path;
pub mod pidfd;
pub mod priority;
pub mod process;
pub mod procmem;
pub mod ready;
pub mod seccomp;
pub mod signal;
pub mod task;
pub mod thread;
pub mod time;
pub mod timer;
pub mod utimes;
pub mod xattr;

use super::abi::Sysno;
use super::abi::errno::Errno;
use super::abi::errno_table::*;
use super::process::{Peers, ProcState, Thread, Threads};
use super::wait::{Resume, Wait};

/// A program image `execve` installs. Opaque: images never compare equal.
pub struct NewImage(pub Box<super::exec::ProgramImage>);

impl std::fmt::Debug for NewImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NewImage({})", self.0.exe_path)
    }
}

impl PartialEq for NewImage {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl Eq for NewImage {}

/// What a system call did to its thread.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Store this value in the result register.
    Return(u64),
    /// The handler already set the registers (for example `rt_sigreturn`).
    Unchanged,
    /// The thread exits with this code (`exit`).
    ExitThread(i32),
    /// The thread dies of this signal, alone (`do_exit` with a signal:
    /// seccomp's strict mode and `SECCOMP_RET_KILL_THREAD`).
    KillThread(i32),
    /// The process exits with this code (`exit_group`).
    ExitGroup(i32),
    /// The process cannot continue; the process ends with an emulator
    /// diagnostic.
    Fatal(String),
    /// The thread sleeps until the wait can end; the call is then
    /// dispatched again with the record.
    Block(Wait, Resume),
    /// Store this value and let the next thread run (`sched_yield`).
    Yield(u64),
    /// The process runs a new program (`execve`).
    Exec(NewImage),
    /// In a new process (`fork`): the caller continues alone with the
    /// result 0, reporting to its parent through the status pipe.
    Forked(super::children::ForkedSelf),
}

/// How `restart_syscall` continues a call a signal interrupted
/// (`struct restart_block`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartBlock {
    /// `hrtimer_nanosleep_restart`: sleep until `deadline`, reporting the
    /// remaining time through `rmtp` (when nonzero) on another interruption.
    Nanosleep {
        /// Absolute end of the sleep.
        deadline: std::time::Instant,
        /// `rmtp`.
        rmtp: u64,
    },
    /// `do_restart_poll`: poll `fds` again until `deadline`.
    Poll {
        /// `struct pollfd` array.
        fds: u64,
        /// Entries.
        nfds: u64,
        /// Absolute timeout, if any.
        deadline: Option<std::time::Instant>,
    },
    /// `futex_wait_restart`: wait on `uaddr` for value `val` until
    /// `deadline`.
    Futex {
        /// The futex word.
        uaddr: u64,
        /// The expected value.
        val: u32,
        /// The wait mask.
        bitset: u32,
        /// A shared key.
        shared: bool,
        /// Absolute timeout.
        deadline: std::time::Instant,
    },
}

/// Internal errno a handler returns after [`Ctx::block`]; never reaches the
/// guest.
const BLOCKED: i32 = i32::MIN;

/// Whether a handler's result says the thread sleeps.
pub fn is_blocked<T>(r: &Result<T, Errno>) -> bool {
    matches!(r, Err(Errno(BLOCKED)))
}

/// The value or error of an ordinary call.
pub type SysResult = Result<u64, Errno>;

/// Handler context: the process, the calling thread, and the others.
pub struct Ctx<'a> {
    /// Process-wide state.
    pub p: &'a mut ProcState,
    /// The calling thread.
    pub t: &'a mut Thread,
    /// The other threads.
    pub peers: Peers<'a>,
    /// Threads the call created, appended to the list after it returns.
    pub spawned: &'a mut Vec<Thread>,
    /// The record the call left when it last slept, if it is running again
    /// after a wake.
    pub resume: Option<Resume>,
    /// Another thread reported the event the call slept for.
    pub woken: bool,
    /// The call decided itself whether its `EPIPE` raises `SIGPIPE` (the
    /// socket protocols do).
    pub sigpipe_decided: bool,
    block: Option<(Wait, Resume)>,
}

impl<'a> Ctx<'a> {
    /// A context for thread `t` of `p`.
    pub fn new(
        p: &'a mut ProcState,
        t: &'a mut Thread,
        peers: Peers<'a>,
        spawned: &'a mut Vec<Thread>,
    ) -> Self {
        Ctx {
            p,
            t,
            peers,
            spawned,
            resume: None,
            woken: false,
            sigpipe_decided: false,
            block: None,
        }
    }
}

impl Ctx<'_> {
    /// Parks the thread until `wait` can end; returns the internal errno the
    /// handler passes up. The call runs again with `resume` in
    /// [`Ctx::resume`].
    pub fn block(&mut self, wait: Wait, resume: Resume) -> Errno {
        self.block = Some((wait, resume));
        Errno(BLOCKED)
    }

    /// `send_sig(SIGPIPE, current, 0)`: `SIGPIPE` to the calling thread,
    /// as sent by the kernel (`SEND_SIG_NOINFO`: `SI_USER` from the caller
    /// itself).
    pub fn send_sigpipe(&mut self) {
        let info = super::signal::SigInfo::kill(
            super::signal::SIGPIPE,
            super::signal::code::SI_USER,
            self.p.pid,
            self.p.creds.0,
        );
        let tid = self.t.tid;
        let (p, mut th) = self.split();
        super::signal::deliver::send_signal(
            p,
            &mut th,
            info,
            super::signal::deliver::Dest::Thread(tid),
            false,
        );
    }

    /// `signal_pending(current)`: the thread's `TIF_SIGPENDING`.
    pub fn signal_pending(&self) -> bool {
        self.t.sigpending
    }

    /// The process state and every thread, the caller current.
    pub fn split(&mut self) -> (&mut ProcState, Threads<'_>) {
        (
            &mut *self.p,
            Threads::with_current(
                &mut *self.t,
                Peers {
                    lo: &mut *self.peers.lo,
                    hi: &mut *self.peers.hi,
                },
            ),
        )
    }

    /// Generates signals of events outside the process and reports whether
    /// the caller now has a signal to take (after a host call ended with
    /// `EINTR`).
    pub fn check_async(&mut self) -> bool {
        let (p, mut th) = self.split();
        super::signal::deliver::collect_async(p, &mut th);
        self.t.sigpending
    }

    /// Every thread, the caller among them, in list order.
    pub fn thread_refs(&self) -> Vec<&Thread> {
        self.peers
            .lo
            .iter()
            .chain(std::iter::once(&*self.t))
            .chain(self.peers.hi.iter())
            .collect()
    }

    /// Whether `tid` is a thread of this process.
    pub fn is_own_tid(&self, tid: i32) -> bool {
        tid == self.t.tid
            || self
                .peers
                .lo
                .iter()
                .chain(self.peers.hi.iter())
                .any(|t| t.tid == tid)
    }

    /// `set_current_blocked` for the caller.
    pub fn set_blocked(&mut self, mask: u64) {
        let (p, mut th) = self.split();
        super::signal::deliver::set_blocked(p, &mut th, mask);
    }

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

fn call_handler(c: &mut Ctx<'_>, s: Sysno, a: [u64; 6]) -> Result<Outcome, Errno> {
    use Sysno as S;
    let r = |v: SysResult| v.map(Outcome::Return);
    let fd = |x: u64| x as i32;
    match s {
        // ---------------------------------------------------------- exit
        S::Exit => Ok(Outcome::ExitThread(a[0] as i32)),
        S::ExitGroup => Ok(Outcome::ExitGroup(a[0] as i32)),

        // ------------------------------------------------------- threads
        S::Clone => thread::clone(c, a),
        S::Clone3 => thread::clone3(c, a[0], a[1]),
        S::SchedYield => Ok(Outcome::Yield(0)),
        S::Execve => exec::execve(c, a[0], a[1], a[2]),
        S::Fork => child::sys_fork(c),
        S::Vfork => child::sys_vfork(c),
        S::Wait4 => child::wait4(c, a[0] as i32, a[1], a[2] as u32, a[3]),
        S::Waitid => child::waitid(c, a[0] as i32, a[1] as i32, a[2], a[3] as u32, a[4]),
        S::Execveat => exec::execveat(c, fd(a[0]), a[1], a[2], a[3], a[4] as u32),

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
        S::Fcntl => r(fcntl::fcntl(c, fd(a[0]), a[1] as u32, a[2])),
        S::Ioctl => r(fcntl::ioctl(c, fd(a[0]), a[1] as u32, a[2])),
        S::Pipe => r(io::pipe2(c, a[0], 0)),
        S::Pipe2 => r(io::pipe2(c, a[0], a[1] as u32)),
        S::Poll => io::poll(c, a[0], a[1], a[2] as i32 as i64),
        S::Ppoll => io::ppoll(c, a[0], a[1], a[2], a[3], a[4]),
        S::Select => io::select(c, a[0] as i32, a[1], a[2], a[3], a[4]),
        S::Pselect6 => io::pselect6(c, a[0] as i32, a[1], a[2], a[3], a[4], a[5]),
        S::Sendfile => r(io::sendfile(c, fd(a[0]), fd(a[1]), a[2], a[3])),
        S::CopyFileRange => r(io::copy_file_range(c, fd(a[0]), a[1], fd(a[2]), a[3], a[4])),
        S::Fsync | S::Fdatasync => r(io::fsync(c, fd(a[0]))),
        S::Sync => r(Ok(0)),
        S::Syncfs => r(io::syncfs(c, fd(a[0]))),
        S::Fadvise64 => r(io::fadvise(c, fd(a[0]), a[3] as u32)),
        S::Readahead => r(io::readahead(c, fd(a[0]))),
        S::SyncFileRange => r(io::sync_file_range(
            c,
            fd(a[0]),
            a[1] as i64,
            a[2] as i64,
            a[3] as u32,
        )),
        S::Flock => r(locks::flock(c, fd(a[0]), a[1] as u32)),
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
        S::Utimensat => r(utimes::utimensat(c, fd(a[0]), a[1], a[2], a[3] as u32)),
        S::Futimesat => r(utimes::futimesat(c, fd(a[0]), a[1], a[2])),
        S::Utimes => r(utimes::futimesat(c, path::AT_FDCWD, a[0], a[1])),
        S::Utime => r(utimes::utime(c, a[0], a[1])),
        S::Mknod => r(path::mknodat(
            c,
            path::AT_FDCWD,
            a[0],
            a[1] as u32,
            a[2] as u32,
        )),
        S::Mknodat => r(path::mknodat(c, fd(a[0]), a[1], a[2] as u32, a[3] as u32)),
        S::Setxattr => r(xattr::setxattr(c, a[0], 0, a)),
        S::Lsetxattr => r(xattr::setxattr(c, a[0], path::AT_SYMLINK_NOFOLLOW, a)),
        S::Fsetxattr => r(xattr::fsetxattr(c, a)),
        S::Getxattr => r(xattr::getxattr(c, a[0], 0, a)),
        S::Lgetxattr => r(xattr::getxattr(c, a[0], path::AT_SYMLINK_NOFOLLOW, a)),
        S::Fgetxattr => r(xattr::fgetxattr(c, a)),
        S::Listxattr => r(xattr::listxattr(c, a[0], 0, a[1], a[2])),
        S::Llistxattr => r(xattr::listxattr(
            c,
            a[0],
            path::AT_SYMLINK_NOFOLLOW,
            a[1],
            a[2],
        )),
        S::Flistxattr => r(xattr::flistxattr(c, fd(a[0]), a[1], a[2])),
        S::Removexattr => r(xattr::removexattr(c, a[0], 0, a[1])),
        S::Lremovexattr => r(xattr::removexattr(c, a[0], path::AT_SYMLINK_NOFOLLOW, a[1])),
        S::Fremovexattr => r(xattr::fremovexattr(c, fd(a[0]), a[1])),
        S::Setxattrat => r(xattr::setxattrat(c, a)),
        S::Getxattrat => r(xattr::getxattrat(c, a)),
        S::Listxattrat => r(xattr::listxattrat(c, a)),
        S::Removexattrat => r(xattr::removexattrat(c, a)),
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
        S::Shmget => r(ipc::shmget(c, a[0] as i32, a[1], a[2] as i32)),
        S::Shmat => r(ipc::shmat(c, a[0] as i32, a[1], a[2] as i32)),
        S::Shmdt => r(ipc::shmdt(c, a[0])),
        S::Shmctl => r(ipc::shmctl(c, a[0] as i32, a[1] as i32, a[2])),
        S::Semget => r(ipc::semget(c, a[0] as i32, a[1] as i32, a[2] as i32)),
        S::Semop => r(ipc::semtimedop(c, a[0] as i32, a[1], a[2] as u32, 0)),
        S::Semtimedop => r(ipc::semtimedop(c, a[0] as i32, a[1], a[2] as u32, a[3])),
        S::Semctl => r(ipc::semctl(c, a[0] as i32, a[1] as i32, a[2] as i32, a[3])),
        S::Msgget => r(ipc::msgget(c, a[0] as i32, a[1] as i32)),
        S::Msgsnd => r(ipc::msgsnd(c, a[0] as i32, a[1], a[2], a[3] as i32)),
        S::Msgrcv => r(ipc::msgrcv(
            c,
            a[0] as i32,
            a[1],
            a[2],
            a[3] as i64,
            a[4] as i32,
        )),
        S::Msgctl => r(ipc::msgctl(c, a[0] as i32, a[1] as i32, a[2])),
        S::Madvise => r(mem::madvise(c, a[0], a[1], a[2] as u32)),
        S::Msync => r(mem::msync(c, a[0], a[1], a[2] as u32)),
        S::Mlock | S::Munlock | S::Mlock2 => r(mem::mlock(c, a[0], a[1])),
        S::Mlockall | S::Munlockall => r(Ok(0)),
        S::Mincore => r(mem::mincore(c, a[0], a[1], a[2])),
        S::RiscvFlushIcache => r(Ok(0)),
        S::MemfdCreate => r(memfd::memfd_create(c, a[0], a[1] as u32)),
        S::ProcessVmReadv => r(procmem::process_vm_readv(
            c,
            a[0] as i32,
            a[1],
            a[2],
            a[3],
            a[4],
            a[5],
        )),
        S::ProcessVmWritev => r(procmem::process_vm_writev(
            c,
            a[0] as i32,
            a[1],
            a[2],
            a[3],
            a[4],
            a[5],
        )),
        S::ProcessMadvise => r(procmem::process_madvise(
            c,
            a[0] as i32,
            a[1],
            a[2],
            a[3] as i32,
            a[4] as u32,
        )),
        S::Kcmp => r(kcmp::kcmp(
            c,
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
            a[3],
            a[4],
        )),

        // ------------------------------------------------------- process
        S::Getpid => r(Ok(c.p.pid as u64)),
        S::Getppid => r(Ok(super::host::ppid() as u64)),
        S::Gettid => r(Ok(c.t.tid as u64)),
        S::Getuid => r(Ok(u64::from(c.p.creds.0))),
        S::Geteuid => r(Ok(u64::from(c.p.creds.1))),
        S::Getgid => r(Ok(u64::from(c.p.creds.2))),
        S::Getegid => r(Ok(u64::from(c.p.creds.3))),
        S::Getresuid => r(process::getres(c, a[0], a[1], a[2], true)),
        S::Getresgid => r(process::getres(c, a[0], a[1], a[2], false)),
        S::Getgroups => r(process::getgroups(c, a[0] as i32, a[1])),
        S::Setgroups => r(process::setgroups(c, a[0] as i32, a[1])),
        S::Setuid | S::Setgid | S::Setreuid | S::Setregid | S::Setresuid | S::Setresgid => {
            r(process::setid(c, s, a))
        }
        S::Setfsuid | S::Setfsgid => r(Ok(u64::from(c.p.creds.1))),
        S::Getpgid => r(process::getpgid(c, a[0] as i32)),
        S::Getpgrp => r(process::getpgid(c, 0)),
        S::Getsid => r(process::getsid(c, a[0] as i32)),
        S::Setpgid => r(process::setpgid(c, a[0] as i32, a[1] as i32)),
        S::Setsid => r(super::host::setsid().map(|s| s as u64)),
        S::SetTidAddress => r(thread::set_tid_address(c, a[0])),
        S::Unshare => r(thread::unshare(c, a[0])),
        S::SetRobustList => r(futex::set_robust_list(c, a[0], a[1])),
        S::GetRobustList => r(futex::get_robust_list(c, a[0] as i32, a[1], a[2])),
        S::Uname => r(process::uname(c, a[0])),
        S::Sysinfo => r(process::sysinfo(c, a[0])),
        S::Getrlimit => r(process::prlimit(c, 0, a[0] as u32, 0, a[1])),
        S::Setrlimit => r(process::prlimit(c, 0, a[0] as u32, a[1], 0)),
        S::Prlimit64 => r(process::prlimit(c, a[0] as i32, a[1] as u32, a[2], a[3])),
        S::Getrusage => r(process::getrusage(c, a[0] as i32, a[1])),
        S::Times => r(process::times(c, a[0])),
        S::Prctl => r(process::prctl(c, a[0] as i32, a[1], a[2], a[3], a[4])),
        S::Seccomp => r(seccomp::seccomp(c, a[0] as u32, a[1] as u32, a[2])),
        S::ArchPrctl => r(process::arch_prctl(c, a[0] as u32, a[1])),
        S::Personality => r(process::personality(c, a[0] as u32)),
        S::Getrandom => r(process::getrandom(c, a[0], a[1], a[2] as u32)),
        S::SchedGetaffinity => r(process::sched_getaffinity(c, a[0] as i32, a[1], a[2])),
        S::SchedSetaffinity => r(process::sched_setaffinity(c, a[0] as i32, a[1], a[2])),
        S::Getcpu => r(process::getcpu(c, a[0], a[1])),
        S::SchedGetscheduler => r(priority::sched_getscheduler(c, a[0] as i32)),
        S::SchedGetparam => r(priority::sched_getparam(c, a[0] as i32, a[1])),
        S::SchedSetscheduler => r(priority::sched_setscheduler(
            c,
            a[0] as i32,
            a[1] as i32,
            a[2],
        )),
        S::SchedSetparam => r(priority::sched_setparam(c, a[0] as i32, a[1])),
        S::SchedSetattr => r(priority::sched_setattr(c, a[0] as i32, a[1], a[2] as u32)),
        S::SchedGetattr => r(priority::sched_getattr(
            c,
            a[0] as i32,
            a[1],
            a[2] as u32,
            a[3] as u32,
        )),
        S::SchedGetPriorityMax => r(priority::sched_priority(a[0] as i32, true)),
        S::SchedGetPriorityMin => r(priority::sched_priority(a[0] as i32, false)),
        S::SchedRrGetInterval => r(priority::sched_rr_get_interval(c, a[0] as i32, a[1])),
        S::Getpriority => r(priority::getpriority(c, a[0] as i32, a[1] as i32)),
        S::Setpriority => r(priority::setpriority(
            c,
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
        )),
        S::IoprioGet => r(priority::ioprio_get(c, a[0] as i32, a[1] as i32)),
        S::IoprioSet => r(priority::ioprio_set(
            c,
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
        )),
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
        S::Nanosleep => time::nanosleep(c, a[0], a[1]),
        S::Alarm => r(time::alarm(c, a[0] as u32)),
        S::Getitimer => r(time::getitimer(c, a[0] as i32, a[1])),
        S::Setitimer => r(time::setitimer(c, a[0] as i32, a[1], a[2])),
        S::ClockNanosleep => time::clock_nanosleep(c, a[0] as i32, a[1] as u32, a[2], a[3]),
        S::TimerCreate => r(timer::timer_create(c, a[0] as i32, a[1], a[2])),
        S::TimerSettime => r(timer::timer_settime(c, a[0], a[1] as u32, a[2], a[3])),
        S::TimerGettime => r(timer::timer_gettime(c, a[0], a[1])),
        S::TimerGetoverrun => r(timer::timer_getoverrun(c, a[0])),
        S::TimerDelete => r(timer::timer_delete(c, a[0])),
        S::Settimeofday => r(time::settimeofday(c, a[0], a[1])),
        S::ClockSettime => r(time::clock_settime(c, a[0] as i32, a[1])),
        S::Adjtimex => r(time::adjtimex(c, a[0])),
        S::ClockAdjtime => r(time::clock_adjtime(c, a[0] as i32, a[1])),

        // ----------------------------------- event, timer, signal files
        S::Eventfd => r(events::eventfd2(c, a[0] as u32, 0)),
        S::Eventfd2 => r(events::eventfd2(c, a[0] as u32, a[1] as u32)),
        S::InotifyInit => r(inotify::init1(c, 0)),
        S::InotifyInit1 => r(inotify::init1(c, a[0] as u32)),
        S::InotifyAddWatch => r(inotify::add_watch(c, fd(a[0]), a[1], a[2] as u32)),
        S::InotifyRmWatch => r(inotify::rm_watch(c, fd(a[0]), a[1] as i32)),
        S::TimerfdCreate => r(events::timerfd_create(c, a[0] as i32, a[1] as u32)),
        S::TimerfdSettime => r(events::timerfd_settime(
            c,
            fd(a[0]),
            a[1] as u32,
            a[2],
            a[3],
        )),
        S::TimerfdGettime => r(events::timerfd_gettime(c, fd(a[0]), a[1])),
        S::Signalfd => r(events::signalfd4(c, fd(a[0]), a[1], a[2], 0)),
        S::Signalfd4 => r(events::signalfd4(c, fd(a[0]), a[1], a[2], a[3] as u32)),
        S::EpollCreate => r(epoll::epoll_create(c, a[0] as i32)),
        S::EpollCreate1 => r(epoll::epoll_create1(c, a[0] as u32)),
        S::EpollCtl => r(epoll::epoll_ctl(c, fd(a[0]), a[1] as i32, fd(a[2]), a[3])),
        S::EpollWait => epoll::epoll_wait(c, fd(a[0]), a[1], a[2] as i32, a[3] as i32),
        S::EpollPwait => {
            epoll::epoll_pwait(c, fd(a[0]), a[1], a[2] as i32, a[3] as i32, a[4], a[5])
        }
        S::EpollPwait2 => epoll::epoll_pwait2(c, fd(a[0]), a[1], a[2] as i32, a[3], a[4], a[5]),

        // -------------------------------------------------------- signal
        S::RtSigaction => r(signal::rt_sigaction(c, a[0] as i32, a[1], a[2], a[3])),
        S::RtSigprocmask => r(signal::rt_sigprocmask(c, a[0] as i32, a[1], a[2], a[3])),
        S::Sigaltstack => r(signal::sigaltstack(c, a[0], a[1])),
        S::RtSigpending => r(signal::rt_sigpending(c, a[0], a[1])),
        S::Kill => r(signal::kill(c, a[0] as i32, a[1] as i32)),
        S::Tkill => r(signal::tkill(c, a[0] as i32, a[1] as i32)),
        S::Tgkill => r(signal::tgkill(c, a[0] as i32, a[1] as i32, a[2] as i32)),
        S::RtSigqueueinfo => r(signal::rt_sigqueueinfo(c, a[0] as i32, a[1] as i32, a[2])),
        S::RtTgsigqueueinfo => r(signal::rt_tgsigqueueinfo(
            c,
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
            a[3],
        )),
        S::RtSigsuspend => signal::rt_sigsuspend(c, a[0], a[1]),
        S::Pause => signal::pause(c),
        S::RtSigtimedwait => signal::rt_sigtimedwait(c, a[0], a[1], a[2], a[3]),
        S::RtSigreturn => signal::rt_sigreturn(c),
        S::RestartSyscall => signal::restart_syscall(c),
        S::PidfdOpen => r(pidfd::pidfd_open(c, a[0] as i32, a[1] as u32)),
        S::PidfdSendSignal => r(pidfd::pidfd_send_signal(
            c,
            a[0] as i32,
            a[1] as i32,
            a[2],
            a[3] as u32,
        )),
        S::PidfdGetfd => r(pidfd::pidfd_getfd(c, a[0] as i32, a[1] as i32, a[2] as u32)),

        // --------------------------------------------------------- futex
        S::Futex => futex::futex(c, a[0], a[1] as u32, a[2] as u32, a[3], a[4], a[5] as u32),
        S::FutexWaitv => futex::futex_waitv(c, a[0], a[1] as u32, a[2] as u32, a[3], a[4] as i32),
        S::FutexWake => futex::futex_wake(c, a[0], a[1], a[2] as i32, a[3] as u32),
        S::FutexWait => futex::futex_wait(c, a[0], a[1], a[2], a[3] as u32, a[4], a[5] as i32),
        S::FutexRequeue => futex::futex_requeue(c, a[0], a[1] as u32, a[2] as i32, a[3] as i32),

        // ------------------------------------------------------- sockets
        S::Socket => r(net::socket(c, a[0] as i32, a[1] as i32, a[2] as i32)),
        S::Socketpair => r(net::socketpair(
            c,
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
            a[3],
        )),
        S::Bind => r(net::bind(c, fd(a[0]), a[1], a[2] as i32)),
        S::Listen => r(net::listen(c, fd(a[0]), a[1] as i32)),
        S::Accept => r(net::accept4(c, fd(a[0]), a[1], a[2], 0)),
        S::Accept4 => r(net::accept4(c, fd(a[0]), a[1], a[2], a[3] as i32)),
        S::Connect => r(net::connect(c, fd(a[0]), a[1], a[2] as i32)),
        S::Getsockname => r(net::getname(c, fd(a[0]), a[1], a[2], false)),
        S::Getpeername => r(net::getname(c, fd(a[0]), a[1], a[2], true)),
        S::Sendto => r(net::io::sendto(
            c,
            fd(a[0]),
            a[1],
            a[2],
            a[3] as u32,
            a[4],
            a[5] as i32,
        )),
        S::Recvfrom => r(net::io::recvfrom(
            c,
            fd(a[0]),
            a[1],
            a[2],
            a[3] as u32,
            a[4],
            a[5],
        )),
        S::Sendmsg => r(net::io::sendmsg(c, fd(a[0]), a[1], a[2] as u32)),
        S::Recvmsg => r(net::io::recvmsg(c, fd(a[0]), a[1], a[2] as u32)),
        S::Sendmmsg => r(net::io::sendmmsg(
            c,
            fd(a[0]),
            a[1],
            a[2] as u32,
            a[3] as u32,
        )),
        S::Recvmmsg => r(net::io::recvmmsg(
            c,
            fd(a[0]),
            a[1],
            a[2] as u32,
            a[3] as u32,
            a[4],
        )),
        S::Shutdown => r(net::shutdown(c, fd(a[0]), a[1] as i32)),
        S::Setsockopt => r(net::setsockopt(
            c,
            fd(a[0]),
            a[1] as i32,
            a[2] as i32,
            a[3],
            a[4] as i32,
        )),
        S::Getsockopt => r(net::getsockopt(
            c,
            fd(a[0]),
            a[1] as i32,
            a[2] as i32,
            a[3],
            a[4],
        )),

        // ------------------------------------------ machine administration
        S::Swapon => r(admin::swapon(c, a[1] as i32)),
        S::Swapoff => r(admin::swapoff(c)),
        S::Reboot => r(admin::reboot(
            c,
            a[0] as i32,
            a[1] as i32,
            a[2] as u32,
            a[3],
        )),
        S::Acct => r(admin::acct(c, a[0])),
        S::Sethostname | S::Setdomainname => r(admin::setname(c, a[0], a[1] as i32)),
        S::Vhangup => r(admin::vhangup(c)),
        S::Iopl => r(admin::iopl(c, a[0] as u32)),
        S::Ioperm => r(admin::ioperm(c, a[0], a[1], a[2] as i32)),
        S::InitModule => r(admin::init_module(c, a[0], a[1])),
        S::FinitModule => r(admin::finit_module(c, fd(a[0]), a[2] as i32)),
        S::DeleteModule => r(admin::delete_module(c, a[0])),
        S::Syslog => admin::syslog(c, a[0] as i32, a[1], a[2] as i32),
        S::Chroot => r(admin::chroot(c, a[0])),

        // ------------------------------------------- POSIX message queues
        S::MqOpen => r(mqueue::mq_open(
            c,
            a[0],
            a[1] as i32,
            u32::from(a[2] as u16),
            a[3],
        )),
        S::MqUnlink => r(mqueue::mq_unlink(c, a[0])),
        S::MqTimedsend => r(mqueue::mq_timedsend(
            c,
            fd(a[0]),
            a[1],
            a[2],
            a[3] as u32,
            a[4],
        )),
        S::MqTimedreceive => r(mqueue::mq_timedreceive(c, fd(a[0]), a[1], a[2], a[3], a[4])),
        S::MqNotify => r(mqueue::mq_notify(c, fd(a[0]), a[1])),
        S::MqGetsetattr => r(mqueue::mq_getsetattr(c, fd(a[0]), a[1], a[2])),

        // -------------------------------------------------------- mounts
        S::Mount => r(mount::mount(c, a[0], a[1], a[2], a[3], a[4])),
        S::Umount2 => r(mount::umount2(c, a[0], a[1] as i32)),
        S::PivotRoot => r(mount::pivot_root(c)),
        S::MoveMount => r(mount::move_mount(c, a[4] as u32)),
        S::Fsopen => r(mount::fsopen(c, a[0], a[1] as u32)),
        S::Fspick => r(mount::fspick(c, fd(a[0]), a[1], a[2] as u32)),
        S::Fsmount => r(mount::fsmount(c, fd(a[0]), a[1] as u32, a[2] as u32)),
        S::Fsconfig => r(mount::fsconfig(
            c,
            fd(a[0]),
            a[1] as u32,
            a[2],
            a[3],
            a[4] as i32,
        )),
        S::OpenTree => r(mount::open_tree(c, fd(a[0]), a[1], a[2] as u32)),
        S::OpenTreeAttr => r(mount::open_tree_attr(
            c,
            fd(a[0]),
            a[1],
            a[2] as u32,
            a[3],
            a[4],
        )),
        S::MountSetattr => r(mount::mount_setattr(
            c,
            fd(a[0]),
            a[1],
            a[2] as u32,
            a[3],
            a[4],
        )),

        // Calls intentionally reported as unsupported. kexec among them:
        // the kernel is built without CONFIG_KEXEC and CONFIG_KEXEC_FILE,
        // as the reference kernel is.
        _ => Err(Errno(ENOSYS)),
    }
}

/// A system call to run: its number and arguments, and when it runs again
/// after sleeping, its record.
#[derive(Clone, Debug)]
pub struct Call {
    /// The number.
    pub nr: u64,
    /// The arguments.
    pub args: [u64; 6],
    /// The record left when it slept.
    pub resume: Option<Resume>,
    /// Another thread reported the event it slept for.
    pub woken: bool,
}

impl Call {
    /// A new call.
    pub fn new(nr: u64, args: [u64; 6]) -> Self {
        Call {
            nr,
            args,
            resume: None,
            woken: false,
        }
    }
}

/// Dispatches the native-ABI system call for thread `t`; `peers` are the
/// other threads, and threads the call creates are appended to `spawned`.
pub fn dispatch(
    p: &mut ProcState,
    t: &mut Thread,
    peers: Peers<'_>,
    spawned: &mut Vec<Thread>,
    call: Call,
) -> Outcome {
    let (nr, args) = (call.nr, call.args);
    let resumed = call.resume.is_some();
    let abi = p.abi;
    let strace = p.config.strace;
    let sysno = abi.sysno(nr);
    let tid = t.tid;
    let mut c = Ctx::new(p, t, peers, spawned);
    // __secure_computing: once, as the call enters.
    if !resumed && let Some(outcome) = seccomp::entry(&mut c, nr, args, seccomp::Entry::Native) {
        if strace {
            trace(tid, sysno, nr, &args, &outcome, false);
        }
        return outcome;
    }
    c.resume = call.resume;
    c.woken = call.woken;
    let result = match sysno {
        Some(s) => call_handler(&mut c, s, args),
        None => Err(Errno(ENOSYS)),
    };
    // shm_open, shm_close: the calls that change System V segment
    // mappings publish them.
    if let Some(s) = sysno
        && (s == Sysno::Shmat || !c.p.ipc.shm_published.is_empty())
        && matches!(
            s,
            Sysno::Shmat
                | Sysno::Shmdt
                | Sysno::Mmap
                | Sysno::Munmap
                | Sysno::Mremap
                | Sysno::Mprotect
                | Sysno::Brk
        )
    {
        ipc::sync_shm(c.p);
    }
    if let Some((wait, resume)) = c.block.take() {
        debug_assert_eq!(result, Err(Errno(BLOCKED)));
        if strace && !resumed {
            trace_unfinished(tid, sysno, nr, &args);
        }
        return Outcome::Block(wait, resume);
    }
    debug_assert_ne!(
        result,
        Err(Errno(BLOCKED)),
        "a handler blocked without a wait"
    );
    // pipe_write: EPIPE comes with SIGPIPE (the socket protocols decide
    // for themselves).
    if matches!(result, Err(Errno(EPIPE)))
        && !c.sigpipe_decided
        && matches!(
            sysno,
            Some(
                Sysno::Write
                    | Sysno::Writev
                    | Sysno::Pwritev2
                    | Sysno::Sendfile
                    | Sysno::Splice
                    | Sysno::Tee
                    | Sysno::Vmsplice
            )
        )
    {
        c.send_sigpipe();
    }
    let outcome = match result {
        Ok(o) => o,
        Err(e) => Outcome::Return(e.as_return()),
    };
    if strace {
        trace(tid, sysno, nr, &args, &outcome, resumed);
    }
    outcome
}

/// Dispatches an x86-64 `INT 0x80` (i386 ABI) system call. Seccomp checks
/// it as `do_int80_emulation` has it checked, as an `AUDIT_ARCH_I386`
/// call (`TS_COMPAT`); the 32-bit table is not provided, so it then
/// returns `-ENOSYS`.
pub fn dispatch_compat(
    p: &mut ProcState,
    t: &mut Thread,
    peers: Peers<'_>,
    nr: u64,
    args: [u64; 6],
) -> Outcome {
    let mut spawned = Vec::new();
    let mut c = Ctx::new(p, t, peers, &mut spawned);
    if let Some(outcome) = seccomp::entry(&mut c, nr, args, seccomp::Entry::Compat) {
        return outcome;
    }
    let outcome = Outcome::Return(Errno(ENOSYS).as_return());
    if p.config.strace {
        eprintln!(
            "[{}] int80 syscall {nr}({:#x}, {:#x}, {:#x}) = -1 ENOSYS",
            t.tid, args[0], args[1], args[2]
        );
    }
    outcome
}

fn trace_name(sysno: Option<Sysno>, nr: u64) -> String {
    sysno.map_or_else(|| format!("syscall_{nr}"), |s| s.name().to_string())
}

fn trace_args(args: &[u64; 6]) -> String {
    args.iter()
        .map(|a| format!("{a:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Writes the `strace` line of a call that went to sleep.
fn trace_unfinished(tid: i32, sysno: Option<Sysno>, nr: u64, args: &[u64; 6]) {
    let name = trace_name(sysno, nr);
    eprintln!("[{tid}] {name}({}) <unfinished ...>", trace_args(args));
}

/// Writes one `strace`-style line; a call that slept is shown as resumed.
fn trace(
    tid: i32,
    sysno: Option<Sysno>,
    nr: u64,
    args: &[u64; 6],
    outcome: &Outcome,
    resumed: bool,
) {
    let name = trace_name(sysno, nr);
    let args = trace_args(args);
    let result = match outcome {
        // Kernel-internal restart codes, as strace shows them.
        Outcome::Return(v) if super::signal::deliver::restart::is_restart(*v) => {
            match -(*v as i64) {
                512 => "? ERESTARTSYS (To be restarted if SA_RESTART is set)".into(),
                513 => "? ERESTARTNOINTR (To be restarted)".into(),
                514 => "? ERESTARTNOHAND (To be restarted if no handler)".into(),
                _ => "? ERESTART_RESTARTBLOCK (Interrupted by signal)".into(),
            }
        }
        Outcome::Return(v) if (*v as i64) < 0 && (*v as i64) >= -4095 => {
            let e = Errno(-(*v as i64) as i32);
            format!("-1 {}", e.name())
        }
        Outcome::Return(v) | Outcome::Yield(v) => format!("{v:#x}"),
        Outcome::Unchanged | Outcome::Block(..) | Outcome::Exec(_) | Outcome::Forked(_) => {
            "0".into()
        }
        Outcome::ExitThread(code) | Outcome::ExitGroup(code) => format!("? (exit {code})"),
        Outcome::KillThread(sig) => format!("? (killed by signal {sig})"),
        Outcome::Fatal(why) => format!("? ({why})"),
    };
    if resumed {
        eprintln!("[{tid}] <... {name} resumed> = {result}");
    } else {
        eprintln!("[{tid}] {name}({args}) = {result}");
    }
}
