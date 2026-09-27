//! kqueues and kevents (`bsd/kern/kern_event.c`, `bsd/sys/event.h`,
//! `bsd/sys/event_private.h`).
//!
//! A kqueue holds knotes: registrations of interest in an event source,
//! each identified by (ident, filter) and, with `EV_UDATA_SPECIFIC`, its
//! udata. A knote becomes active when its source fires and is queued on
//! its kqueue in activation order; `kevent` hands queued knotes to their
//! filter's process routine, which snapshots the event, and applies the
//! delivery protocol (`EV_ONESHOT`, `EV_CLEAR`, `EV_DISPATCH`, deferred
//! deletes). Filters ([`filters`]) are emulated for the process's own
//! sources — Mach ports, signals, timers, user events, other kqueues — and
//! passed to the host kernel for descriptors and other processes
//! ([`host`]).

pub mod filters;
pub mod host;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::abi::Errno;
use super::arch::{Rv, SysResult};
use super::process::Proc;
use super::syscall::Ctx;
use super::wait::{Resume, Wait, WaitKey};

/// Filters (`EVFILT_*`).
pub mod evfilt {
    pub const READ: i16 = -1;
    pub const WRITE: i16 = -2;
    pub const AIO: i16 = -3;
    pub const VNODE: i16 = -4;
    pub const PROC: i16 = -5;
    pub const SIGNAL: i16 = -6;
    pub const TIMER: i16 = -7;
    pub const MACHPORT: i16 = -8;
    pub const FS: i16 = -9;
    pub const USER: i16 = -10;
    pub const VM: i16 = -12;
    pub const SOCK: i16 = -13;
    pub const MEMORYSTATUS: i16 = -14;
    pub const EXCEPT: i16 = -15;
    pub const NW_CHANNEL: i16 = -16;
    pub const WORKLOOP: i16 = -17;
    /// `EVFILT_SYSCOUNT`.
    pub const SYSCOUNT: i16 = 18;
}

/// `EV_*` flags.
pub mod ev {
    pub const ADD: u16 = 0x0001;
    pub const DELETE: u16 = 0x0002;
    pub const ENABLE: u16 = 0x0004;
    pub const DISABLE: u16 = 0x0008;
    pub const ONESHOT: u16 = 0x0010;
    pub const CLEAR: u16 = 0x0020;
    pub const RECEIPT: u16 = 0x0040;
    pub const DISPATCH: u16 = 0x0080;
    pub const UDATA_SPECIFIC: u16 = 0x0100;
    pub const DISPATCH2: u16 = DISPATCH | UDATA_SPECIFIC;
    pub const VANISHED: u16 = 0x0200;
    pub const SYSFLAGS: u16 = 0xF000;
    pub const FLAG0: u16 = 0x1000;
    pub const FLAG1: u16 = 0x2000;
    pub const ERROR: u16 = 0x4000;
    pub const EOF: u16 = 0x8000;
}

/// `KEVENT_FLAG_*`.
pub mod kflag {
    pub const IMMEDIATE: u32 = 0x000001;
    pub const ERROR_EVENTS: u32 = 0x000002;
    pub const STACK_DATA: u32 = 0x000008;
    pub const WORKQ: u32 = 0x000020;
    pub const WORKLOOP: u32 = 0x000400;
    pub const PARKING: u32 = 0x000800;
    pub const DYNAMIC_KQ_MUST_EXIST: u32 = 0x020000;
    pub const DYNAMIC_KQ_MUST_NOT_EXIST: u32 = 0x040000;
    pub const LEGACY32: u32 = 0x0040;
    pub const LEGACY64: u32 = 0x0080;
    /// `KEVENT_FLAG_USER`: the flags user space may pass.
    pub const USER: u32 = IMMEDIATE
        | ERROR_EVENTS
        | STACK_DATA
        | WORKQ
        | WORKLOOP
        | DYNAMIC_KQ_MUST_EXIST
        | DYNAMIC_KQ_MUST_NOT_EXIST;
    /// `KEVENT_ID_FLAG_USER`.
    pub const ID_USER: u32 = WORKLOOP | DYNAMIC_KQ_MUST_EXIST | DYNAMIC_KQ_MUST_NOT_EXIST;
}

/// Knote status (`KN_*`).
pub mod kn {
    pub const ACTIVE: u16 = 0x001;
    pub const QUEUED: u16 = 0x002;
    pub const DISABLED: u16 = 0x004;
    pub const DROPPING: u16 = 0x008;
    pub const DEFERDELETE: u16 = 0x080;
    pub const REQVANISH: u16 = 0x200;
    pub const VANISHED: u16 = 0x400;
    pub const SUPPRESSED: u16 = 0x800;
}

/// Filter results (`FILTER_*`).
pub mod fr {
    pub const ACTIVE: i32 = 0x01;
    pub const UPDATE_REQ_QOS: i32 = 0x04;
    pub const RESET_EVENT_QOS: i32 = 0x08;
}

/// The kernel's form of an event (`struct kevent_qos_s`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kev {
    pub ident: u64,
    pub filter: i16,
    pub flags: u16,
    pub qos: i32,
    pub udata: u64,
    pub fflags: u32,
    pub xflags: u32,
    pub data: i64,
    pub ext: [u64; 4],
}

/// Event record layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `struct kevent` of a 64-bit process (32 bytes).
    Kevent,
    /// `struct kevent64_s` (48 bytes).
    Kevent64,
    /// `struct kevent_qos_s` (72 bytes).
    Qos,
}

impl Layout {
    /// The record size.
    pub fn size(self) -> u64 {
        match self {
            Layout::Kevent => 32,
            Layout::Kevent64 => 48,
            Layout::Qos => 72,
        }
    }
}

fn get64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"))
}

fn get32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"))
}

fn get16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().expect("2 bytes"))
}

impl Kev {
    /// Decodes a record (`kevent_legacy_copyin`, `kevent_modern_copyin`);
    /// user space cannot pass the system flags.
    pub fn decode(b: &[u8], layout: Layout) -> Kev {
        let mut k = match layout {
            Layout::Kevent => Kev {
                ident: get64(b, 0),
                filter: get16(b, 8) as i16,
                flags: get16(b, 10),
                fflags: get32(b, 12),
                data: get64(b, 16) as i64,
                udata: get64(b, 24),
                ..Default::default()
            },
            Layout::Kevent64 => Kev {
                ident: get64(b, 0),
                filter: get16(b, 8) as i16,
                flags: get16(b, 10),
                fflags: get32(b, 12),
                data: get64(b, 16) as i64,
                udata: get64(b, 24),
                ext: [get64(b, 32), get64(b, 40), 0, 0],
                ..Default::default()
            },
            Layout::Qos => Kev {
                ident: get64(b, 0),
                filter: get16(b, 8) as i16,
                flags: get16(b, 10),
                qos: get32(b, 12) as i32,
                udata: get64(b, 16),
                fflags: get32(b, 24),
                xflags: get32(b, 28),
                data: get64(b, 32) as i64,
                ext: [get64(b, 40), get64(b, 48), get64(b, 56), get64(b, 64)],
            },
        };
        k.flags &= !ev::SYSFLAGS;
        k
    }

    /// Encodes a record (`kevent_legacy_copyout`, `kevent_modern_copyout`).
    pub fn encode(&self, layout: Layout) -> Vec<u8> {
        let mut b = vec![0u8; layout.size() as usize];
        b[0..8].copy_from_slice(&self.ident.to_le_bytes());
        b[8..10].copy_from_slice(&self.filter.to_le_bytes());
        b[10..12].copy_from_slice(&self.flags.to_le_bytes());
        match layout {
            Layout::Kevent | Layout::Kevent64 => {
                b[12..16].copy_from_slice(&self.fflags.to_le_bytes());
                b[16..24].copy_from_slice(&self.data.to_le_bytes());
                b[24..32].copy_from_slice(&self.udata.to_le_bytes());
                if layout == Layout::Kevent64 {
                    b[32..40].copy_from_slice(&self.ext[0].to_le_bytes());
                    b[40..48].copy_from_slice(&self.ext[1].to_le_bytes());
                }
            }
            Layout::Qos => {
                b[12..16].copy_from_slice(&self.qos.to_le_bytes());
                b[16..24].copy_from_slice(&self.udata.to_le_bytes());
                b[24..28].copy_from_slice(&self.fflags.to_le_bytes());
                b[28..32].copy_from_slice(&self.xflags.to_le_bytes());
                b[32..40].copy_from_slice(&self.data.to_le_bytes());
                for i in 0..4 {
                    b[40 + i * 8..48 + i * 8].copy_from_slice(&self.ext[i].to_le_bytes());
                }
            }
        }
        b
    }
}

/// A knote (`struct knote`): the registration as `kn_kevent` stores it
/// and the delivery state.
#[derive(Debug)]
pub struct Knote {
    /// Process-unique identity.
    pub id: u64,
    /// `kn_id` (the ident).
    pub ident: u64,
    /// `kn_filter`.
    pub filter: i16,
    /// `kn_flags`: the registration's flags (returned with events).
    pub flags: u16,
    /// `kn_qos`.
    pub qos: i32,
    /// `kn_udata`.
    pub udata: u64,
    /// `kn_fflags`: fired filter flags.
    pub fflags: u32,
    /// `kn_sfflags`: the registration's filter flags.
    pub sfflags: u32,
    /// `kn_sdata`: the registration's data.
    pub sdata: i64,
    /// `kn_ext`.
    pub ext: [u64; 4],
    /// `kn_status`.
    pub status: u16,
    /// Whether the knote hangs off a descriptor (`kn_is_fd`).
    pub is_fd: bool,
    /// The filter's state.
    pub state: filters::State,
}

impl Knote {
    /// `knote_fill_kevent_with_sdata`: the registration as an event (the
    /// fired flags are cleared for `EV_CLEAR` knotes).
    pub fn fill_with_sdata(&mut self) -> Kev {
        let k = Kev {
            ident: self.ident,
            filter: self.filter,
            flags: self.flags,
            qos: self.qos,
            udata: self.udata,
            fflags: self.fflags,
            xflags: 0,
            data: self.sdata,
            ext: self.ext,
        };
        if self.flags & ev::CLEAR != 0 {
            self.fflags = 0;
        }
        k
    }

    /// `knote_fill_kevent` with `data`.
    pub fn fill(&mut self, data: i64) -> Kev {
        let mut k = self.fill_with_sdata();
        k.data = data;
        k
    }

    /// `knote_set_error`.
    pub fn set_error(&mut self, e: Errno) {
        self.flags |= ev::ERROR;
        self.sdata = i64::from(e.0);
    }
}

/// The kinds of kqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KqKind {
    /// A `kqueue()` descriptor's kqueue (`struct kqfile`).
    File,
}

/// `KQ_KEV32`, `KQ_KEV64`, `KQ_KEV_QOS`: the interface a file kqueue was
/// first used through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KevApi {
    /// `kevent`.
    Kev32,
    /// `kevent64`.
    Kev64,
    /// `kevent_qos`.
    Qos,
}

/// A kqueue.
#[derive(Debug)]
pub struct Kqueue {
    /// Process-unique identity.
    pub id: u64,
    /// What kind it is.
    pub kind: KqKind,
    /// The interface it is bound to.
    pub api: Option<KevApi>,
    /// Knotes by identity.
    pub knotes: BTreeMap<u64, Knote>,
    /// Queued (active) knotes in activation order.
    pub queue: VecDeque<u64>,
    /// Knotes suppressed during a delivery pass.
    pub suppressed: Vec<u64>,
    /// Knotes on other kqueues watching this one (`EVFILT_READ` on its
    /// descriptor).
    pub watchers: Vec<(u64, u64)>,
    /// The host kqueue carrying the descriptor and process knotes.
    pub host: Option<host::HostKq>,
}

/// A process's kqueues and the event sources' knote lists.
#[derive(Debug, Default)]
pub struct State {
    /// Kqueues by identity.
    pub kqueues: BTreeMap<u64, Kqueue>,
    next_kq: u64,
    next_knote: u64,
    /// Knotes on Mach ports and port sets, by port or set identity
    /// (`ip_klist`, `ips_klist`).
    pub port_klists: HashMap<u64, Vec<(u64, u64)>>,
    /// `EVFILT_SIGNAL` knotes (`p_klist`).
    pub signal_knotes: Vec<(u64, u64)>,
    /// Armed timer knotes and their deadlines (Mach absolute time).
    pub timers: Vec<(u64, u64, u64)>,
}

impl State {
    /// A new kqueue.
    pub fn create(&mut self, kind: KqKind) -> u64 {
        self.next_kq += 1;
        let id = self.next_kq;
        self.kqueues.insert(
            id,
            Kqueue {
                id,
                kind,
                api: None,
                knotes: BTreeMap::new(),
                queue: VecDeque::new(),
                suppressed: Vec::new(),
                watchers: Vec::new(),
                host: None,
            },
        );
        id
    }

    fn knote_id(&mut self) -> u64 {
        self.next_knote += 1;
        self.next_knote
    }

    /// `kq_count`.
    pub fn count(&self, kq: u64) -> usize {
        self.kqueues.get(&kq).map_or(0, |k| k.queue.len())
    }
}

/// `knote_enqueue`: an active knote that is not disabled, suppressed,
/// dropping, or queued goes to the back of its kqueue's queue; a queue
/// that becomes non-empty wakes its waiters and watchers.
pub fn enqueue(proc: &mut Proc, kq: u64, knote: u64) {
    let Some(q) = proc.kq.kqueues.get_mut(&kq) else {
        return;
    };
    let Some(k) = q.knotes.get_mut(&knote) else {
        return;
    };
    if k.status & kn::ACTIVE == 0
        || k.status & (kn::DISABLED | kn::SUPPRESSED | kn::DROPPING | kn::QUEUED) != 0
    {
        return;
    }
    k.status |= kn::QUEUED;
    let wakeup = q.queue.is_empty();
    q.queue.push_back(knote);
    if wakeup {
        wake(proc, kq);
    }
}

/// `kqfile_wakeup`: threads sleeping in `kevent` on `kq` and knotes
/// watching it.
fn wake(proc: &mut Proc, kq: u64) {
    proc.post(WaitKey::Kqueue(kq));
    let watchers = proc
        .kq
        .kqueues
        .get(&kq)
        .map(|q| q.watchers.clone())
        .unwrap_or_default();
    for (wkq, wkn) in watchers {
        activate(proc, wkq, wkn);
    }
}

/// `knote_dequeue`.
fn dequeue(q: &mut Kqueue, knote: u64) {
    if let Some(k) = q.knotes.get_mut(&knote)
        && k.status & kn::QUEUED != 0
    {
        k.status &= !kn::QUEUED;
        if let Some(i) = q.queue.iter().position(|&n| n == knote) {
            q.queue.remove(i);
        }
    }
}

/// `knote_activate`: marks the knote active and queues it.
pub fn activate(proc: &mut Proc, kq: u64, knote: u64) {
    if let Some(k) = proc
        .kq
        .kqueues
        .get_mut(&kq)
        .and_then(|q| q.knotes.get_mut(&knote))
    {
        k.status |= kn::ACTIVE;
    } else {
        return;
    }
    enqueue(proc, kq, knote);
}

/// `knote_suppress`: off the queue and inactive until the pass ends.
fn suppress(q: &mut Kqueue, knote: u64) {
    dequeue(q, knote);
    if let Some(k) = q.knotes.get_mut(&knote) {
        k.status &= !kn::ACTIVE;
        k.status |= kn::SUPPRESSED;
    }
    q.suppressed.push(knote);
}

/// `knote_unsuppress_noqueue`.
fn unsuppress_noqueue(q: &mut Kqueue, knote: u64) {
    if let Some(k) = q.knotes.get_mut(&knote) {
        k.status &= !kn::SUPPRESSED;
    }
    if let Some(i) = q.suppressed.iter().position(|&n| n == knote) {
        q.suppressed.remove(i);
    }
}

/// `knote_unsuppress`.
fn unsuppress(proc: &mut Proc, kq: u64, knote: u64) {
    if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
        unsuppress_noqueue(q, knote);
    }
    enqueue(proc, kq, knote);
}

/// `knote_drop`: detaches the knote from its source and frees it.
fn drop_knote(proc: &mut Proc, kq: u64, knote: u64) {
    let Some(q) = proc.kq.kqueues.get_mut(&kq) else {
        return;
    };
    let Some(k) = q.knotes.get_mut(&knote) else {
        return;
    };
    k.status |= kn::DROPPING;
    if k.status & kn::SUPPRESSED != 0 {
        unsuppress_noqueue(q, knote);
    } else {
        dequeue(q, knote);
    }
    filters::detach(proc, kq, knote);
    if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
        q.knotes.remove(&knote);
    }
}

/// `knote_apply_touch`: enables, then activates or requeues.
fn apply_touch(proc: &mut Proc, kq: u64, knote: u64, kev: &Kev, result: i32) {
    if let Some(q) = proc.kq.kqueues.get_mut(&kq)
        && let Some(k) = q.knotes.get_mut(&knote)
    {
        if kev.flags & ev::ENABLE != 0 && k.status & kn::DISABLED != 0 {
            k.status &= !kn::DISABLED;
            filters::enabled(proc, kq, knote, true);
            if let Some(q) = proc.kq.kqueues.get_mut(&kq)
                && q.knotes
                    .get(&knote)
                    .is_some_and(|k| k.status & kn::SUPPRESSED != 0)
            {
                unsuppress_noqueue(q, knote);
            }
        }
        if result & fr::UPDATE_REQ_QOS != 0 && kev.qos != 0 {
            if let Some(k) = proc
                .kq
                .kqueues
                .get_mut(&kq)
                .and_then(|q| q.knotes.get_mut(&knote))
            {
                k.qos = kev.qos;
            }
        }
    }
    if result & fr::ACTIVE != 0 {
        activate(proc, kq, knote);
    } else {
        enqueue(proc, kq, knote);
    }
}

/// Whether a filter's knotes hang off descriptors (`f_isfd`).
fn is_fd_filter(filter: i16) -> bool {
    matches!(
        filter,
        evfilt::READ
            | evfilt::WRITE
            | evfilt::VNODE
            | evfilt::SOCK
            | evfilt::EXCEPT
            | evfilt::NW_CHANNEL
    )
}

/// `knote_fdfind`: the knote of `kq` matching the event's ident and
/// filter, and its udata when either side is `EV_UDATA_SPECIFIC`.
fn find(q: &Kqueue, kev: &Kev) -> Option<u64> {
    q.knotes
        .values()
        .find(|k| {
            k.ident == kev.ident
                && k.filter == kev.filter
                && if kev.flags & ev::UDATA_SPECIFIC != 0 {
                    k.flags & ev::UDATA_SPECIFIC != 0 && k.udata == kev.udata
                } else {
                    k.flags & ev::UDATA_SPECIFIC == 0
                }
        })
        .map(|k| k.id)
}

/// `kevent_register`: applies one change to `kq`. Errors come back in
/// `kev` (`EV_ERROR` with the errno in `data`).
pub fn register(ctx: &mut Ctx<'_>, kq: u64, kev: &mut Kev) {
    let error = register_inner(ctx, kq, kev);
    if let Err(e) = error {
        kev.flags |= ev::ERROR;
        kev.data = i64::from(e.0);
    }
}

fn register_inner(ctx: &mut Ctx<'_>, kq: u64, kev: &mut Kev) -> Result<(), Errno> {
    if !(kev.filter < 0 && kev.filter + evfilt::SYSCOUNT >= 0) {
        return Err(Errno::EINVAL);
    }
    // EV_VANISHED only when adding udata-specific dispatch knotes.
    if kev.flags & ev::VANISHED != 0
        && kev.flags & (ev::ADD | ev::DISPATCH2) != ev::ADD | ev::DISPATCH2
    {
        return Err(Errno::EINVAL);
    }
    if kev.flags & ev::DELETE != 0 {
        kev.flags &= !ev::ADD;
    }
    if kev.flags & ev::DISABLE != 0 {
        kev.flags &= !ev::ENABLE;
    }
    let found = find(&ctx.proc.kq.kqueues[&kq], kev);
    let Some(id) = found else {
        if kev.flags & ev::ADD == 0 {
            return Err(Errno::ENOENT);
        }
        return add(ctx, kq, kev);
    };
    let proc = &mut *ctx.proc;
    if kev.flags & ev::DELETE != 0 {
        let k = &proc.kq.kqueues[&kq].knotes[&id];
        if kev.flags & ev::ENABLE == 0
            && k.flags & ev::DISPATCH2 == ev::DISPATCH2
            && k.status & kn::DISABLED != 0
        {
            let k = proc
                .kq
                .kqueues
                .get_mut(&kq)
                .and_then(|q| q.knotes.get_mut(&id))
                .expect("found knote");
            k.status |= kn::DEFERDELETE;
            return Err(Errno::EINPROGRESS);
        }
        drop_knote(proc, kq, id);
        return Ok(());
    }
    let status = proc.kq.kqueues[&kq].knotes[&id].status;
    let result = if status & (kn::DEFERDELETE | kn::VANISHED) != 0 {
        if kev.flags & ev::ENABLE != 0 {
            fr::ACTIVE
        } else {
            0
        }
    } else {
        filters::touch(ctx, kq, id, kev)
    };
    if kev.flags & ev::ERROR != 0 {
        return Ok(());
    }
    let proc = &mut *ctx.proc;
    if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
        let k = q.knotes.get_mut(&id).expect("found knote");
        if k.flags & ev::UDATA_SPECIFIC == 0 {
            k.udata = kev.udata;
        }
        if kev.flags & ev::DISABLE != 0 && k.status & kn::DISABLED == 0 {
            k.status |= kn::DISABLED;
            dequeue(q, id);
            filters::enabled(proc, kq, id, false);
        }
    }
    apply_touch(proc, kq, id, kev, result);
    Ok(())
}

/// A new knote (the `kn == NULL` branch of `kevent_register`).
fn add(ctx: &mut Ctx<'_>, kq: u64, kev: &mut Kev) -> Result<(), Errno> {
    let is_fd = is_fd_filter(kev.filter);
    if is_fd {
        // fp_lookup.
        ctx.proc.fds.file(kev.ident as i32)?;
        if kev.ident >= ctx.proc.rlimits[8].0 {
            return Err(Errno::EINVAL);
        }
    }
    let mut status = 0;
    if kev.flags & ev::VANISHED != 0 {
        kev.flags &= !ev::VANISHED;
        status |= kn::REQVANISH;
    }
    if kev.flags & ev::DISABLE != 0 {
        status |= kn::DISABLED;
    }
    let id = ctx.proc.kq.knote_id();
    let k = Knote {
        id,
        ident: kev.ident,
        filter: kev.filter,
        flags: kev.flags,
        qos: kev.qos,
        udata: kev.udata,
        fflags: 0,
        sfflags: kev.fflags,
        sdata: kev.data,
        ext: kev.ext,
        status,
        is_fd,
        state: filters::State::None,
    };
    ctx.proc
        .kq
        .kqueues
        .get_mut(&kq)
        .expect("live kqueue")
        .knotes
        .insert(id, k);
    let result = filters::attach(ctx, kq, id, kev);
    let proc = &mut *ctx.proc;
    let k = &proc.kq.kqueues[&kq].knotes[&id];
    if k.flags & ev::ERROR != 0 {
        let e = Errno(k.sdata as i32);
        if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
            q.knotes.remove(&id);
        }
        return Err(e);
    }
    apply_touch(proc, kq, id, kev, result);
    Ok(())
}

/// `knote_process`: hands one queued knote to its filter and applies the
/// delivery protocol. Returns the event to deliver, if any.
fn process(ctx: &mut Ctx<'_>, kq: u64, knote: u64, data: &mut DataArea) -> Option<Kev> {
    let q = ctx.proc.kq.kqueues.get_mut(&kq)?;
    let status = q.knotes.get(&knote)?.status;
    if status & kn::QUEUED == 0 {
        return None;
    }
    suppress(q, knote);
    let k = q.knotes.get_mut(&knote).expect("queued knote");
    let (kev, result) = if k.status & (kn::DEFERDELETE | kn::VANISHED) != 0 {
        let mut flags = ev::DISPATCH2 | ev::ONESHOT;
        flags |= if k.status & kn::DEFERDELETE != 0 {
            ev::DELETE
        } else {
            ev::VANISHED
        };
        (
            Kev {
                filter: k.filter,
                ident: k.ident,
                flags,
                udata: k.udata,
                ..Default::default()
            },
            fr::ACTIVE,
        )
    } else {
        filters::process(ctx, kq, knote, data)
    };
    let proc = &mut *ctx.proc;
    let q = proc.kq.kqueues.get_mut(&kq)?;
    let Some(k) = q.knotes.get_mut(&knote) else {
        return None;
    };
    if result & fr::ACTIVE == 0 {
        if k.status & kn::ACTIVE == 0 {
            unsuppress(proc, kq, knote);
        }
        return None;
    }
    let mut drop = false;
    if kev.flags & ev::ONESHOT != 0 {
        if k.flags & ev::DISPATCH2 == ev::DISPATCH2 && k.status & kn::DEFERDELETE == 0 {
            // Defer dropping a oneshot dispatch2 knote until re-enabled.
            k.status |= kn::DEFERDELETE | kn::DISABLED;
            filters::enabled(proc, kq, knote, false);
        } else {
            drop = true;
        }
    } else if k.flags & ev::DISPATCH != 0 {
        k.status |= kn::DISABLED;
        filters::enabled(proc, kq, knote, false);
    } else if k.flags & ev::CLEAR == 0 {
        // Re-activate in case there are more events.
        activate(proc, kq, knote);
    }
    if drop {
        drop_knote(proc, kq, knote);
    }
    Some(kev)
}

/// `kqfile_end_processing`: suppressed knotes return to their queue.
fn end_processing(proc: &mut Proc, kq: u64) {
    loop {
        let Some(&first) = proc.kq.kqueues.get(&kq).and_then(|q| q.suppressed.first()) else {
            break;
        };
        unsuppress(proc, kq, first);
    }
}

/// The out-of-line data area of `kevent_qos` (`data_out`,
/// `data_available`), which Mach-port knotes receive messages into.
#[derive(Clone, Copy, Debug, Default)]
pub struct DataArea {
    /// Where the next message goes (the area's top for stack data).
    pub out: u64,
    /// Bytes left.
    pub resid: u64,
    /// The area's size on entry.
    pub size: u64,
    /// `KEVENT_FLAG_STACK_DATA`: the area is consumed from the top down.
    pub stack: bool,
}

/// `kqueue_process`: delivers up to `nevents` events of `kq`.
fn scan_once(ctx: &mut Ctx<'_>, kq: u64, nevents: usize, data: &mut DataArea) -> Vec<Kev> {
    filters::fire_timers(ctx.proc);
    host::harvest(ctx.proc, kq);
    let mut out = Vec::new();
    while out.len() < nevents {
        let Some(&first) = ctx.proc.kq.kqueues.get(&kq).and_then(|q| q.queue.front()) else {
            break;
        };
        if let Some(kev) = process(ctx, kq, first, data) {
            out.push(kev);
        }
    }
    end_processing(ctx.proc, kq);
    out
}

/// The earliest armed timer deadline of `kq`, as an instant.
fn next_timer(proc: &Proc, kq: u64) -> Option<Instant> {
    let now = super::syscall::mach::absolute_time(proc.abi);
    proc.kq
        .timers
        .iter()
        .filter(|t| t.0 == kq)
        .map(|t| t.2)
        .min()
        .map(|d| Instant::now() + filters::abs_to_duration(proc.abi, d.saturating_sub(now)))
}

/// The arguments of a `kevent` family call.
#[derive(Clone, Copy, Debug)]
pub struct Call {
    pub fd: i32,
    pub changelist: u64,
    pub nchanges: i32,
    pub eventlist: u64,
    pub nevents: i32,
    pub flags: u32,
    pub layout: Layout,
    /// The relative timeout (`None`: forever).
    pub timeout: Option<Duration>,
    pub data_out: u64,
    pub data_available: u64,
}

/// `kevent_internal` for a file kqueue: registers the changes, then scans
/// and waits for events. Returns the number of records written.
pub fn kevent(ctx: &mut Ctx<'_>, c: Call) -> SysResult {
    let file = ctx.proc.fds.file(c.fd)?;
    let super::fd::FileKind::Kqueue(kq) = file.kind else {
        return Err(Errno::EBADF);
    };
    // kqfiles cannot be used through kevent() and the others at once.
    let api = match c.layout {
        Layout::Kevent => KevApi::Kev32,
        Layout::Kevent64 => KevApi::Kev64,
        Layout::Qos => KevApi::Qos,
    };
    let q = ctx.proc.kq.kqueues.get_mut(&kq).ok_or(Errno::EBADF)?;
    let bound = *q.api.get_or_insert(api);
    if (bound == KevApi::Kev32) != (api == KevApi::Kev32) {
        return Err(Errno::EINVAL);
    }
    let mut data = DataArea::default();
    if c.data_out != 0 && c.data_available != 0 {
        let avail = ctx.read_u64(c.data_available)?;
        data = DataArea {
            out: c.data_out,
            resid: avail,
            size: avail,
            stack: c.flags & kflag::STACK_DATA != 0,
        };
    }
    let resumed = ctx.thread.resume.is_some_and(|r| r.step == 1);
    let mut noutputs = 0usize;
    let mut out_addr = c.eventlist;
    let rec = c.layout.size();
    if !resumed {
        let mut changes = c.changelist;
        for _ in 0..c.nchanges.max(0) {
            let b = ctx.read(changes, rec as usize)?;
            changes += rec;
            let mut kev = Kev::decode(&b, c.layout);
            register(ctx, kq, &mut kev);
            if (noutputs as i32) < c.nevents && kev.flags & (ev::ERROR | ev::RECEIPT) != 0 {
                if kev.flags & ev::ERROR == 0 {
                    kev.flags |= ev::ERROR;
                    kev.data = 0;
                }
                ctx.write(out_addr, &kev.encode(c.layout))?;
                out_addr += rec;
                noutputs += 1;
            } else if kev.flags & ev::ERROR != 0 {
                return Err(Errno(kev.data as i32));
            }
        }
    }
    if c.flags & kflag::ERROR_EVENTS != 0 || c.nevents <= 0 || noutputs != 0 {
        return Ok(Rv::one(noutputs as u64));
    }
    let events = scan_once(ctx, kq, c.nevents as usize, &mut data);
    if !events.is_empty() {
        for e in &events {
            ctx.write(out_addr, &e.encode(c.layout))?;
            out_addr += rec;
        }
        if data.resid != data.size {
            let _ = ctx.write_u64(c.data_available, data.resid);
        }
        return Ok(Rv::one(events.len() as u64));
    }
    if c.flags & kflag::IMMEDIATE != 0 {
        return Ok(Rv::one(0));
    }
    // Wait for an event (THREAD_ABORTSAFE), the timeout, or a signal.
    let deadline = match ctx.thread.resume.filter(|_| resumed) {
        Some(r) => r.deadline,
        None => c.timeout.map(|d| Instant::now() + d),
    };
    if deadline.is_some_and(|d| d <= Instant::now()) {
        return Ok(Rv::one(0));
    }
    if let Some(e) = super::signal::sleep_interruption(ctx.proc, ctx.thread) {
        // kevent is not restarted after signals.
        let _ = e;
        ctx.thread.resume = None;
        return Err(Errno::EINTR);
    }
    let timer = next_timer(ctx.proc, kq);
    let wake_at = match (deadline, timer) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let fds = host::wait_fds(ctx.proc, kq);
    ctx.thread.resume = Some(Resume {
        pc: ctx.pc,
        call: ctx.nr,
        deadline,
        step: 1,
    });
    ctx.thread.wait = Some(Wait {
        keys: vec![WaitKey::Kqueue(kq)],
        fds,
        deadline: wake_at,
        interruptible: true,
        seq: super::wait::next_seq(),
    });
    Err(Errno::ERESTART)
}

/// `kqueue()`: a new kqueue descriptor.
pub fn kqueue(ctx: &mut Ctx<'_>) -> SysResult {
    let kq = ctx.proc.kq.create(KqKind::File);
    let file = std::sync::Arc::new(super::fd::OpenFile {
        kind: super::fd::FileKind::Kqueue(kq),
        path: None,
        flags: std::sync::Mutex::new(super::io::O_RDWR),
    });
    let limit = ctx.proc.rlimits[8].0;
    match ctx.proc.fds.install(file, false, 0, limit) {
        Ok(fd) => Ok(Rv::one(fd as u64)),
        Err(e) => {
            ctx.proc.kq.kqueues.remove(&kq);
            Err(e)
        }
    }
}

/// A descriptor slot was closed or replaced (`knote_fdclose`, and
/// `kqueue_close` when the last reference to a kqueue goes).
pub fn fd_closed(proc: &mut Proc, fd: i32, file: Option<super::fd::FileRef>) {
    let hits: Vec<(u64, u64, bool)> = proc
        .kq
        .kqueues
        .values()
        .flat_map(|q| {
            q.knotes
                .values()
                .filter(|k| k.is_fd && k.ident == fd as u64 && k.status & kn::VANISHED == 0)
                .map(|k| (q.id, k.id, k.status & kn::REQVANISH != 0))
        })
        .collect();
    for (kq, knote, vanish) in hits {
        if vanish {
            // EV_VANISHED delivery: detached now, reported once.
            filters::detach(proc, kq, knote);
            if let Some(k) = proc
                .kq
                .kqueues
                .get_mut(&kq)
                .and_then(|q| q.knotes.get_mut(&knote))
            {
                k.status |= kn::VANISHED;
                k.state = filters::State::Detached;
            }
            activate(proc, kq, knote);
        } else {
            drop_knote(proc, kq, knote);
        }
    }
    if let Some(f) = file
        && let super::fd::FileKind::Kqueue(kq) = f.kind
        && std::sync::Arc::strong_count(&f) == 1
    {
        destroy(proc, kq);
    }
}

/// `kqueue_dealloc`: drops every knote of a closed kqueue.
pub fn destroy(proc: &mut Proc, kq: u64) {
    let ids: Vec<u64> = proc
        .kq
        .kqueues
        .get(&kq)
        .map(|q| q.knotes.keys().copied().collect())
        .unwrap_or_default();
    for id in ids {
        drop_knote(proc, kq, id);
    }
    proc.kq.kqueues.remove(&kq);
    proc.post(WaitKey::Kqueue(kq));
}

#[cfg(test)]
mod tests;
