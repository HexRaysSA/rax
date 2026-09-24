//! What open files report when polled (`vfs_poll`), for `poll`, `select`,
//! and `epoll`.
//!
//! Each file kind reports the mask its `f_op->poll` computes:
//!
//! | File | Mask |
//! |---|---|
//! | Without a `poll` operation (regular files, directories, synthesized files) | `DEFAULT_POLLMASK`: readable and writable |
//! | Pipes and FIFOs (`pipe_poll`) | reading: `EPOLLIN` while bytes are queued, `EPOLLHUP` once no writer is left; writing: `EPOLLOUT` while there is room, `EPOLLERR` once no reader is left |
//! | Other host descriptors (terminals, devices) | the host's readiness |
//! | Anonymous-inode files | their own ([`events::poll`](super::events::poll)) |
//!
//! Host `poll` alone does not give the pipe rules (macOS reports an empty
//! pipe whose writers are gone as readable, and a pipe whose readers are
//! gone as hung up), so a pipe's queued bytes are read with `FIONREAD`.
//!
//! Besides the mask, each file reports a *level* (bytes queued, a counter,
//! pending ticks or signals) whose growth stands for the wake-up an
//! edge-triggered `epoll` item reports, and what a sleeper waits on until
//! the file changes.

use std::os::fd::AsRawFd;

use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::host;
use super::super::wait::Wait;
use super::Ctx;

/// `EPOLL*` event bits; the low sixteen are the `POLL*` bits.
pub mod ev {
    pub const IN: u32 = 0x001;
    pub const PRI: u32 = 0x002;
    pub const OUT: u32 = 0x004;
    pub const ERR: u32 = 0x008;
    pub const HUP: u32 = 0x010;
    pub const NVAL: u32 = 0x020;
    pub const RDNORM: u32 = 0x040;
    pub const RDBAND: u32 = 0x080;
    pub const WRNORM: u32 = 0x100;
    pub const WRBAND: u32 = 0x200;
    pub const MSG: u32 = 0x400;
    pub const RDHUP: u32 = 0x2000;
    /// Events that ask about reading.
    pub const READS: u32 = IN | PRI | RDNORM | RDBAND | RDHUP;
    /// Events that ask about writing.
    pub const WRITES: u32 = OUT | WRNORM | WRBAND;
    /// `DEFAULT_POLLMASK`.
    pub const DEFAULT: u32 = IN | OUT | RDNORM | WRNORM;
}

/// What a polled file reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Polled {
    /// The file's poll mask (every event it reports now).
    pub mask: u32,
    /// How much it holds for a reader.
    pub level: u64,
}

/// The host descriptor of a host-backed description.
pub fn raw_fd(file: &OpenFile) -> Option<i32> {
    match &file.object {
        FileObject::Host(f) => Some(f.as_raw_fd()),
        FileObject::PipeRead(p) => Some(p.as_raw_fd()),
        FileObject::PipeWrite(p) => Some(p.as_raw_fd()),
        _ => None,
    }
}

/// Whether the description refers to a pipe or FIFO.
fn is_fifo(file: &OpenFile) -> bool {
    matches!(
        file.object,
        FileObject::PipeRead(_) | FileObject::PipeWrite(_)
    ) || file.ftype == FileType::Fifo
}

/// The mask of a host-backed file from the host's readiness `r` and its
/// queued bytes.
fn host_mask(file: &OpenFile, r: host::Readiness, queued: u64) -> u32 {
    use ev::*;
    if !is_fifo(file) {
        let mut m = 0;
        if r.readable {
            m |= IN | RDNORM;
        }
        if r.writable {
            m |= OUT | WRNORM;
        }
        if r.hangup {
            m |= HUP;
        }
        if r.error {
            m |= ERR;
        }
        return m;
    }
    // pipe_poll, by the description's access mode. The host reports its
    // hang-up as the other side's absence.
    let (reads, writes) = (file.readable(), file.writable());
    let mut m = 0;
    if reads {
        if queued > 0 {
            m |= IN | RDNORM;
        }
        if r.hangup && !writes {
            m |= HUP;
        }
    }
    if writes {
        // A pipe without readers takes no data but is not full.
        if r.writable || r.hangup {
            m |= OUT | WRNORM;
        }
        if r.hangup && !reads {
            m |= ERR;
        }
    }
    m
}

/// Polls `files`, each with the events a caller asks about, returning
/// every file's report and what a sleeper would wait on until one of them
/// changes. Host descriptors are polled together.
pub fn poll_files(c: &Ctx<'_>, files: &[(&OpenFile, u32)]) -> (Vec<Polled>, Wait) {
    let mut out = vec![Polled::default(); files.len()];
    let mut wait = Wait::event();
    let mut host_at = Vec::new();
    let mut host_req = Vec::new();
    for (i, &(file, events)) in files.iter().enumerate() {
        match &file.object {
            FileObject::Anon(anon) => {
                let (polled, w) = super::events::poll(c, anon, events);
                out[i] = polled;
                wait.fds.extend(w.fds);
                wait.signals |= w.signals;
                wait.deadline = earlier(wait.deadline, w.deadline);
            }
            FileObject::PathOnly => out[i].mask = ev::NVAL,
            _ => match raw_fd(file) {
                Some(raw) if !matches!(file.ftype, FileType::Regular | FileType::Directory) => {
                    host_at.push(i);
                    host_req.push((raw, true, true));
                    wait.fds.push((
                        raw,
                        events & (ev::READS | ev::ERR | ev::HUP) != 0,
                        events & ev::WRITES != 0,
                    ));
                }
                _ => out[i].mask = ev::DEFAULT,
            },
        }
    }
    if !host_req.is_empty() {
        let rs = host::poll(&host_req, 0).unwrap_or_default();
        for (k, &i) in host_at.iter().enumerate() {
            let file = files[i].0;
            let r = rs.get(k).copied().unwrap_or_default();
            let queued = if file.readable() {
                match &file.object {
                    FileObject::Host(f) => host::bytes_readable(f).unwrap_or(0),
                    FileObject::PipeRead(p) => host::bytes_readable(p).unwrap_or(0),
                    _ => 0,
                }
                .max(0) as u64
            } else {
                0
            };
            out[i] = Polled {
                mask: host_mask(file, r, queued),
                level: queued,
            };
        }
    }
    (out, wait)
}

/// The earlier of two optional instants.
pub fn earlier(
    a: Option<std::time::Instant>,
    b: Option<std::time::Instant>,
) -> Option<std::time::Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
