//! `/proc/<pid>/fdinfo/<fd>` (`fs/proc/fd.c`): what a descriptor refers
//! to, as `seq_show` prints it.
//!
//! Every file shows its position, status flags (with `O_CLOEXEC` for a
//! close-on-exec descriptor), mount ID, and inode number; then what its
//! `show_fdinfo` operation adds: a pidfd's task ID (`pidfd_show_fdinfo`),
//! an `eventfd`'s counter (`eventfd_show_fdinfo`), a `timerfd`'s clock,
//! ticks, and times (`timerfd_show`), a `signalfd`'s mask
//! (`signalfd_show_fdinfo`), and an `epoll` instance's items
//! (`ep_show_fdinfo`). `/proc/<pid>/mountinfo` is not provided, so mount
//! IDs only tell the file systems apart. File locks (`show_fd_locks`) and
//! the socket lines (`scm_fds`) are not shown.

use std::fmt::Write as _;

use super::abi::open::O_CLOEXEC;
use super::fs::anon::Anon;
use super::fs::fd::{FileObject, FileType, OpenFile};
use super::posix_timers::clock_now;
use super::process::ProcState;

/// Mount IDs by file system.
mod mnt {
    /// The host file system, as the guest's root mount.
    pub const ROOT: i32 = 1;
    /// `proc`.
    pub const PROC: i32 = 2;
    /// `pidfs`.
    pub const PIDFS: i32 = 3;
    /// `sockfs`.
    pub const SOCKFS: i32 = 4;
    /// `pipefs`.
    pub const PIPEFS: i32 = 5;
    /// `anon_inodefs`.
    pub const ANON: i32 = 6;
    /// The internal `tmpfs` of `memfd`s.
    pub const SHM: i32 = 7;
    /// `mqueue`.
    pub const MQUEUE: i32 = 8;
}

/// The mount ID of the file system `file` lives on.
fn mount_id(file: &OpenFile) -> i32 {
    match &file.object {
        FileObject::Host(_) if file.memfd.is_some() => mnt::SHM,
        FileObject::Host(_) | FileObject::PathOnly => mnt::ROOT,
        FileObject::Synthetic(_) => mnt::PROC,
        FileObject::PipeRead(_) | FileObject::PipeWrite(_) => mnt::PIPEFS,
        FileObject::Socket(_) => mnt::SOCKFS,
        FileObject::Anon(Anon::Pid(_)) => mnt::PIDFS,
        FileObject::Anon(_) => mnt::ANON,
        FileObject::Mqueue(_) => mnt::MQUEUE,
    }
}

/// `file->f_pos`, read without moving it: what `lseek(fd, 0, SEEK_CUR)`
/// returns, or 0 for a file without a position.
fn position(file: &OpenFile) -> i64 {
    let dir = file.state.lock().unwrap().dir.as_ref().map(|d| d.1);
    match &file.object {
        _ if file.ftype == FileType::Directory => dir.unwrap_or(0) as i64,
        FileObject::Synthetic(_) | FileObject::Mqueue(_) => {
            file.state.lock().unwrap().synth_pos as i64
        }
        FileObject::Host(_) if matches!(file.ftype, FileType::Regular | FileType::BlockDevice) => {
            file.seek(0, 1).map_or(0, |p| p as i64)
        }
        _ => 0,
    }
}

/// The kernel's internal encoding of a device number (`MKDEV`), as
/// `ep_show_fdinfo` prints `s_dev`.
fn kdev(major: u32, minor: u32) -> u32 {
    (major << 20) | (minor & 0xf_ffff)
}

/// The content of `/proc/<pid>/fdinfo/<fd>` for process `p`, whose thread
/// IDs `own` recognizes; `None` when `fd` is not open.
pub fn fdinfo(p: &ProcState, own: &dyn Fn(i32) -> bool, fd: i32) -> Option<Vec<u8>> {
    let entry = p.fds.get(fd).ok()?;
    let file = &entry.file;
    let ids = (p.creds.1, p.creds.3);
    let ino = super::syscall::path::stat_open(file, ids).map_or(0, |st| st.ino);
    let flags = file.flags() | if entry.cloexec { O_CLOEXEC } else { 0 };
    let mut s = format!(
        "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{}\nino:\t{}\n",
        position(file),
        flags,
        mount_id(file),
        ino
    );
    let FileObject::Anon(anon) = &file.object else {
        return Some(s.into_bytes());
    };
    match anon {
        Anon::Pid(t) => s.push_str(&super::syscall::pidfd::fdinfo(p, own, t)),
        Anon::Inotify(i) => s.push_str(&super::syscall::inotify::fdinfo(i)),
        Anon::Event(ev) => {
            let _ = write!(
                s,
                "eventfd-count: {:16x}\neventfd-id: {}\neventfd-semaphore: {}\n",
                ev.count(),
                ev.id,
                u8::from(ev.semaphore())
            );
        }
        Anon::Timer(t) => {
            let (ticks, value, interval) = t.shown(&clock_now);
            let split = |ns: i64| (ns / 1_000_000_000, ns % 1_000_000_000);
            let (v, i) = (split(value), split(interval));
            let _ = write!(
                s,
                "clockid: {}\nticks: {}\nsettime flags: 0{:o}\nit_value: ({}, {})\n\
                 it_interval: ({}, {})\n",
                t.clockid,
                ticks,
                t.settime_flags(),
                v.0,
                v.1,
                i.0,
                i.1
            );
        }
        // render_sigset_t: signals 64 down to 1, four to a digit.
        Anon::Signal(sf) => {
            let _ = writeln!(s, "sigmask:\t{:016x}", sf.mask());
        }
        Anon::Epoll(ep) => {
            for (tfd, events, data, target) in ep.listing() {
                let st = super::syscall::path::stat_open(&target, ids).unwrap_or_default();
                let _ = writeln!(
                    s,
                    "tfd: {tfd:8} events: {events:8x} data: {data:16x}  pos:{} ino:{:x} sdev:{:x}",
                    position(&target),
                    st.ino,
                    kdev(st.dev_major, st.dev_minor)
                );
            }
        }
    }
    Some(s.into_bytes())
}
