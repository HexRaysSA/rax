//! Knotes the host kernel carries: the descriptor filters (`EVFILT_READ`,
//! `EVFILT_WRITE`, `EVFILT_VNODE`, `EVFILT_EXCEPT`, `EVFILT_SOCK`, ...) and
//! `EVFILT_PROC`.
//!
//! On a macOS host each guest kqueue with such knotes has a host kqueue:
//! the knote is registered there on the guest descriptor's host
//! descriptor (or the process ID), and the host's events — with their
//! data, filter flags, and `EV_EOF` — are the filter's results. The guest
//! kqueue applies its own delivery protocol, so the host knote is only
//! ever added (level- or edge-triggered as the guest's `EV_CLEAR` says),
//! enabled, disabled, and deleted. Elsewhere `EVFILT_READ` and
//! `EVFILT_WRITE` are emulated with `poll` and `FIONREAD`, and the other
//! host filters are not supported.

use super::filters::State;
use super::{Kev, ev, evfilt, fr};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::process::Proc;

/// What the host reported for a knote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostEvent {
    /// `EV_EOF` and `EV_OOBAND` as the host set them.
    pub flags: u16,
    /// The fired filter flags.
    pub fflags: u32,
    /// The filter data.
    pub data: i64,
}

/// A host-carried knote: its host ident and the host's last event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostKnote {
    /// The host descriptor or process ID.
    pub ident: u64,
    /// The last event the host reported and the guest has not taken.
    pub event: Option<HostEvent>,
}

/// A guest kqueue's host side.
#[derive(Debug)]
pub struct HostKq {
    /// The host kqueue (macOS).
    #[cfg(target_os = "macos")]
    fd: std::os::fd::OwnedFd,
    /// Knote identity to host descriptor, for `poll` emulation elsewhere.
    #[cfg(not(target_os = "macos"))]
    fds: Vec<(u64, i32, bool)>,
}

fn knote<'a>(proc: &'a mut Proc, kq: u64, id: u64) -> Option<&'a mut super::Knote> {
    proc.kq
        .kqueues
        .get_mut(&kq)
        .and_then(|q| q.knotes.get_mut(&id))
}

#[cfg(target_os = "macos")]
mod imp {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    /// One host `kevent64` call.
    fn kevent64(kq: i32, changes: &[libc::kevent64_s], out: &mut [libc::kevent64_s]) -> i32 {
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: the change and event arrays are valid for their lengths;
        // a zero timeout never blocks.
        unsafe {
            libc::kevent64(
                kq,
                changes.as_ptr(),
                changes.len() as i32,
                out.as_mut_ptr(),
                out.len() as i32,
                0,
                &zero,
            )
        }
    }

    fn change(
        ident: u64,
        filter: i16,
        flags: u16,
        fflags: u32,
        data: i64,
        udata: u64,
    ) -> libc::kevent64_s {
        libc::kevent64_s {
            ident,
            filter,
            flags,
            fflags,
            data,
            udata,
            ext: [0, 0],
        }
    }

    /// Applies one change with `EV_RECEIPT`; the host's error, if any.
    fn apply(hkq: i32, c: libc::kevent64_s) -> Result<(), Errno> {
        let mut c = c;
        c.flags |= ev::RECEIPT;
        let mut out = [change(0, 0, 0, 0, 0, 0)];
        let n = kevent64(hkq, &[c], &mut out);
        if n < 0 {
            return Err(Errno::last());
        }
        if n == 1 && out[0].flags & ev::ERROR != 0 && out[0].data != 0 {
            return Err(Errno(out[0].data as i32));
        }
        Ok(())
    }

    fn host_kq(proc: &mut Proc, kq: u64) -> Result<i32, Errno> {
        let q = proc.kq.kqueues.get_mut(&kq).ok_or(Errno::EBADF)?;
        if q.host.is_none() {
            // SAFETY: kqueue(2) takes no arguments.
            let fd = unsafe { libc::kqueue() };
            if fd < 0 {
                return Err(Errno::last());
            }
            // SAFETY: fcntl on the descriptor just created.
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            // SAFETY: `fd` is a new descriptor this process owns.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            q.host = Some(HostKq { fd });
        }
        Ok(q.host.as_ref().expect("created").fd.as_raw_fd())
    }

    /// The host ident of a knote: its descriptor's host descriptor, or the
    /// process ID.
    fn host_ident(k: &super::super::Knote, host_fd: Option<i32>) -> u64 {
        match host_fd {
            Some(fd) => fd as u64,
            None => k.ident,
        }
    }

    pub fn register(
        proc: &mut Proc,
        kq: u64,
        id: u64,
        host_fd: Option<i32>,
        add: bool,
    ) -> Result<(), Errno> {
        let hkq = host_kq(proc, kq)?;
        let k = knote(proc, kq, id).ok_or(Errno::ENOENT)?;
        let ident = host_ident(k, host_fd);
        let mut flags = ev::ADD | (k.flags & ev::CLEAR);
        if k.status & super::super::kn::DISABLED != 0 {
            flags |= ev::DISABLE;
        }
        let _ = add;
        apply(hkq, change(ident, k.filter, flags, k.sfflags, k.sdata, id))?;
        if let Some(k) = knote(proc, kq, id)
            && let State::Host(h) = &mut k.state
        {
            h.ident = ident;
        }
        Ok(())
    }

    pub fn control(proc: &mut Proc, kq: u64, id: u64, flags: u16) {
        let Some(hkq) = proc
            .kq
            .kqueues
            .get(&kq)
            .and_then(|q| q.host.as_ref())
            .map(|h| h.fd.as_raw_fd())
        else {
            return;
        };
        let Some(k) = knote(proc, kq, id) else {
            return;
        };
        let State::Host(h) = k.state else {
            return;
        };
        let _ = apply(
            hkq,
            change(h.ident, k.filter, flags, k.sfflags, k.sdata, id),
        );
    }

    /// Collects the host's events for `kq`'s knotes.
    pub fn collect(proc: &mut Proc, kq: u64) -> Vec<(u64, HostEvent)> {
        let Some(hkq) = proc
            .kq
            .kqueues
            .get(&kq)
            .and_then(|q| q.host.as_ref())
            .map(|h| h.fd.as_raw_fd())
        else {
            return Vec::new();
        };
        let mut all = Vec::new();
        loop {
            let mut out = [change(0, 0, 0, 0, 0, 0); 64];
            let n = kevent64(hkq, &[], &mut out);
            if n <= 0 {
                break;
            }
            for e in &out[..n as usize] {
                all.push((
                    e.udata,
                    HostEvent {
                        flags: e.flags & (ev::EOF | ev::FLAG1),
                        fflags: e.fflags,
                        data: e.data,
                    },
                ));
            }
            if (n as usize) < out.len() {
                break;
            }
        }
        all
    }

    pub fn wait_fd(proc: &Proc, kq: u64) -> Option<i32> {
        proc.kq
            .kqueues
            .get(&kq)
            .and_then(|q| q.host.as_ref())
            .map(|h| h.fd.as_raw_fd())
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;

    pub fn register(
        proc: &mut Proc,
        kq: u64,
        id: u64,
        host_fd: Option<i32>,
        _add: bool,
    ) -> Result<(), Errno> {
        let k = knote(proc, kq, id).ok_or(Errno::ENOENT)?;
        let read = match k.filter {
            evfilt::READ => true,
            evfilt::WRITE => false,
            _ => return Err(Errno::ENOTSUP),
        };
        let fd = host_fd.ok_or(Errno::EBADF)?;
        let q = proc.kq.kqueues.get_mut(&kq).ok_or(Errno::EBADF)?;
        let h = q.host.get_or_insert_with(|| HostKq { fds: Vec::new() });
        h.fds.retain(|e| e.0 != id);
        h.fds.push((id, fd, read));
        Ok(())
    }

    pub fn control(proc: &mut Proc, kq: u64, id: u64, flags: u16) {
        if flags & ev::DELETE != 0
            && let Some(h) = proc.kq.kqueues.get_mut(&kq).and_then(|q| q.host.as_mut())
        {
            h.fds.retain(|e| e.0 != id);
        }
    }

    pub fn collect(proc: &mut Proc, kq: u64) -> Vec<(u64, HostEvent)> {
        let Some(h) = proc.kq.kqueues.get(&kq).and_then(|q| q.host.as_ref()) else {
            return Vec::new();
        };
        let fds: Vec<(i32, bool, bool)> = h.fds.iter().map(|e| (e.1, e.2, !e.2)).collect();
        let ready = crate::user::darwin::wait::ready_now(&fds);
        h.fds
            .iter()
            .zip(ready)
            .filter(|(_, r)| *r)
            .map(|(e, _)| {
                let mut n: libc::c_int = 0;
                if e.2 {
                    // SAFETY: FIONREAD writes an int.
                    unsafe {
                        libc::ioctl(e.1, libc::FIONREAD, &mut n);
                    }
                }
                (
                    e.0,
                    HostEvent {
                        flags: 0,
                        fflags: 0,
                        data: i64::from(n),
                    },
                )
            })
            .collect()
    }

    pub fn wait_fd(_proc: &Proc, _kq: u64) -> Option<i32> {
        None
    }
}

/// Attaches a host-carried knote (`host_fd`: the descriptor's host
/// descriptor; `None` for `EVFILT_PROC`).
pub fn attach(proc: &mut Proc, kq: u64, id: u64, host_fd: Option<i32>) -> i32 {
    let is_proc = knote(proc, kq, id).is_some_and(|k| k.filter == evfilt::PROC);
    if host_fd.is_none() && !is_proc {
        if let Some(k) = knote(proc, kq, id) {
            k.set_error(Errno::EBADF);
        }
        return 0;
    }
    if let Some(k) = knote(proc, kq, id) {
        k.state = State::Host(HostKnote::default());
    }
    if let Err(e) = imp::register(proc, kq, id, host_fd, true) {
        if let Some(k) = knote(proc, kq, id) {
            k.set_error(e);
        }
        return 0;
    }
    harvest_one(proc, kq, id)
}

/// `f_touch` of a host knote: the new filter flags and data go to the
/// host.
pub fn touch(proc: &mut Proc, kq: u64, id: u64, kev: &mut Kev) -> i32 {
    if let Some(k) = knote(proc, kq, id) {
        k.sfflags = kev.fflags;
        k.sdata = kev.data;
    }
    let ident = match knote(proc, kq, id).map(|k| k.state.clone()) {
        Some(State::Host(h)) => h.ident,
        _ => 0,
    };
    #[cfg(target_os = "macos")]
    let host_fd = Some(ident as i32)
        .filter(|_| knote(proc, kq, id).is_some_and(|k| k.filter != evfilt::PROC));
    #[cfg(not(target_os = "macos"))]
    let host_fd = {
        let _ = ident;
        proc.kq
            .kqueues
            .get(&kq)
            .and_then(|q| q.host.as_ref())
            .and_then(|h| h.fds.iter().find(|e| e.0 == id).map(|e| e.1))
    };
    if let Err(e) = imp::register(proc, kq, id, host_fd, false) {
        kev.flags |= ev::ERROR;
        kev.data = i64::from(e.0);
        return 0;
    }
    harvest_one(proc, kq, id)
}

/// Collects the host's events and activates their knotes. Level-triggered
/// knotes the host no longer reports lose their last result.
pub fn harvest(proc: &mut Proc, kq: u64) {
    if proc.kq.kqueues.get(&kq).is_none_or(|q| q.host.is_none()) {
        return;
    }
    if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
        for k in q.knotes.values_mut() {
            if k.flags & ev::CLEAR == 0
                && let State::Host(h) = &mut k.state
            {
                h.event = None;
            }
        }
    }
    for (id, e) in imp::collect(proc, kq) {
        let Some(k) = knote(proc, kq, id) else {
            continue;
        };
        if let State::Host(h) = &mut k.state {
            h.event = Some(e);
            super::activate(proc, kq, id);
        }
    }
}

/// Harvests and reports whether knote `id` is active.
fn harvest_one(proc: &mut Proc, kq: u64, id: u64) -> i32 {
    harvest(proc, kq);
    match knote(proc, kq, id).map(|k| &k.state) {
        Some(State::Host(h)) if h.event.is_some() => fr::ACTIVE,
        _ => 0,
    }
}

/// `f_process` of a host knote: the host's last event, `EV_EOF` and
/// `EV_OOBAND` kept on the knote as the kernel's filters keep them.
pub fn process(proc: &mut Proc, kq: u64, id: u64) -> (Kev, i32) {
    let Some(k) = knote(proc, kq, id) else {
        return (Kev::default(), 0);
    };
    let State::Host(h) = k.state else {
        return (Kev::default(), 0);
    };
    let Some(e) = h.event else {
        return (Kev::default(), 0);
    };
    k.flags |= e.flags;
    let mut kev = k.fill(e.data);
    kev.fflags = e.fflags;
    if k.flags & ev::CLEAR != 0 {
        k.state = State::Host(HostKnote { event: None, ..h });
    }
    (kev, fr::ACTIVE)
}

/// `f_detach` of a host knote.
pub fn detach(proc: &mut Proc, kq: u64, id: u64) {
    imp::control(proc, kq, id, ev::DELETE);
}

/// Enables or disables the host knote with the guest's.
pub fn enable(proc: &mut Proc, kq: u64, id: u64, on: bool) {
    imp::control(proc, kq, id, if on { ev::ENABLE } else { ev::DISABLE });
}

/// Host descriptors whose readiness wakes a thread waiting on `kq`.
pub fn wait_fds(proc: &Proc, kq: u64) -> Vec<(i32, bool, bool)> {
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(h) = proc.kq.kqueues.get(&kq).and_then(|q| q.host.as_ref()) {
            return h.fds.iter().map(|e| (e.1, e.2, !e.2)).collect();
        }
    }
    imp::wait_fd(proc, kq)
        .map(|fd| vec![(fd, true, false)])
        .unwrap_or_default()
}
