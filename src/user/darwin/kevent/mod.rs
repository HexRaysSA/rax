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
//!
//! Besides the kqueues of `kqueue()` descriptors, which a thread scans in
//! `kevent`, a process has a workqueue kqueue and workloops whose events
//! workqueue threads are started to service ([`workq`], [`workloop`]).
//! Their timers and host events are watched by the scheduler
//! ([`pump`], [`autonomous_wait`]).

mod call;
pub mod filters;
pub mod host;
pub mod workloop;
pub mod workq;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Instant;

use super::abi::Errno;
use super::arch::{Rv, SysResult};
use super::process::Proc;
use super::syscall::Ctx;
use super::wait::WaitKey;
use super::workq::priority;

pub use call::{Call, kevent, kevent_id, kevent_workq_internal};

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
    pub const PROC64: u32 = 0x0100;
    pub const KERNEL: u32 = 0x1000;
    pub const DYNAMIC_KQUEUE: u32 = 0x2000;
    pub const NEEDS_END_PROCESSING: u32 = 0x4000;
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
    pub const REGISTER_WAIT: i32 = 0x02;
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
    /// `kn_qos`: the normalized pthread priority.
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
    /// `kn_qos_index`: the bucket it queues in.
    pub qos_index: u8,
    /// `kn_qos_override`.
    pub qos_override: u8,
    /// `kn_thread`: the thread sleeping on a workloop waiter knote.
    pub thread: Option<u64>,
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
    /// The process's workqueue kqueue (`struct kqworkq`).
    Workq,
    /// A workloop (`struct kqworkloop`).
    Workloop,
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
    /// Queued (active) knotes in activation order, by QoS bucket (one
    /// bucket for a file kqueue).
    pub queues: Vec<VecDeque<u64>>,
    /// Knotes suppressed during a delivery pass, by bucket (the
    /// workqueue kqueue's per bucket, the others' in one).
    pub suppressed: Vec<Vec<u64>>,
    /// `KQ_PROCESSING`: a servicer is delivering its events.
    pub processing: bool,
    /// Knotes on other kqueues watching this one (`EVFILT_READ` on its
    /// descriptor).
    pub watchers: Vec<(u64, u64)>,
    /// The host kqueue carrying the descriptor and process knotes.
    pub host: Option<host::HostKq>,
    /// The workqueue kqueue's or workloop's state.
    pub ext: workq::Ext,
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
    /// The workqueue kqueue (`fd_wqkqueue`).
    pub workq: Option<u64>,
    /// Workloops by ID (`fd_kqhash`).
    pub workloops: HashMap<u64, u64>,
    /// Threads sleeping in a workloop registration, by thread ID.
    pub register_waits: HashMap<u64, workloop::RegisterWait>,
}

impl State {
    /// A new kqueue.
    pub fn create(&mut self, kind: KqKind) -> u64 {
        self.next_kq += 1;
        let id = self.next_kq;
        let (nq, ns) = match kind {
            KqKind::File => (1, 1),
            KqKind::Workq => (workq::KQWQ_NBUCKETS, workq::KQWQ_NBUCKETS),
            KqKind::Workloop => (workq::KQWL_NBUCKETS, 1),
        };
        self.kqueues.insert(
            id,
            Kqueue {
                id,
                kind,
                api: None,
                knotes: BTreeMap::new(),
                queues: vec![VecDeque::new(); nq],
                suppressed: vec![Vec::new(); ns],
                processing: false,
                watchers: Vec::new(),
                host: None,
                ext: workq::Ext::File,
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
        self.kqueues
            .get(&kq)
            .map_or(0, |k| k.queues.iter().map(VecDeque::len).sum())
    }
}

/// `knote_get_tailq`: the queue a knote belongs in.
fn queue_index(q: &Kqueue, k: &Knote) -> usize {
    match q.kind {
        KqKind::File => 0,
        _ => (usize::from(k.qos_index).max(1) - 1).min(q.queues.len() - 1),
    }
}

/// The suppression list a knote belongs in (`kqueue_get_suppressed_queue`).
fn suppressed_index(q: &Kqueue, k: &Knote) -> usize {
    match q.kind {
        KqKind::Workq => queue_index(q, k),
        _ => 0,
    }
}

/// `knote_enqueue`: an active knote that is not disabled, suppressed,
/// dropping, or queued goes to the back of its queue; a queue that
/// becomes non-empty wakes the kqueue.
pub fn enqueue(proc: &mut Proc, kq: u64, knote: u64) {
    let Some(q) = proc.kq.kqueues.get_mut(&kq) else {
        return;
    };
    let Some(k) = q.knotes.get(&knote) else {
        return;
    };
    if k.status & kn::ACTIVE == 0
        || k.status & (kn::DISABLED | kn::SUPPRESSED | kn::DROPPING | kn::QUEUED) != 0
    {
        return;
    }
    let (i, qos_index) = (queue_index(q, k), k.qos_index);
    let wakeup = q.queues[i].is_empty();
    q.queues[i].push_back(knote);
    let kind = q.kind;
    if let Some(k) = q.knotes.get_mut(&knote) {
        k.status |= kn::QUEUED;
    }
    if wakeup {
        match kind {
            KqKind::File => wake(proc, kq),
            KqKind::Workq => workq::kqworkq_wakeup(proc, kq, qos_index),
            KqKind::Workloop => workq::kqworkloop_wakeup(proc, kq, qos_index.max(1)),
        }
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
    let Some(k) = q.knotes.get(&knote) else {
        return;
    };
    if k.status & kn::QUEUED == 0 {
        return;
    }
    let i = queue_index(q, k);
    if let Some(p) = q.queues[i].iter().position(|&n| n == knote) {
        q.queues[i].remove(p);
    } else {
        // Its bucket changed while queued: find it.
        for queue in &mut q.queues {
            queue.retain(|&n| n != knote);
        }
    }
    if let Some(k) = q.knotes.get_mut(&knote) {
        k.status &= !kn::QUEUED;
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
    let Some(k) = q.knotes.get_mut(&knote) else {
        return;
    };
    k.status &= !kn::ACTIVE;
    k.status |= kn::SUPPRESSED;
    let k = &q.knotes[&knote];
    let s = suppressed_index(q, k);
    q.suppressed[s].push(knote);
}

/// `knote_unsuppress_noqueue`: an inactive knote's QoS resynchronizes.
fn unsuppress_noqueue(q: &mut Kqueue, knote: u64) {
    let Some(k) = q.knotes.get(&knote) else {
        return;
    };
    let s = suppressed_index(q, k);
    if let Some(i) = q.suppressed[s].iter().position(|&n| n == knote) {
        q.suppressed[s].remove(i);
    } else {
        for list in &mut q.suppressed {
            list.retain(|&n| n != knote);
        }
    }
    let kind = q.kind;
    let k = q.knotes.get_mut(&knote).expect("listed knote");
    k.status &= !kn::SUPPRESSED;
    if k.status & kn::ACTIVE == 0 && kind != KqKind::File {
        let qos = priority::thread_qos_fast(k.qos as u32);
        if qos != 0 {
            k.qos_override = qos;
        }
    }
    k.qos_index = k.qos_override;
}

/// `knote_unsuppress`.
fn unsuppress(proc: &mut Proc, kq: u64, knote: u64) {
    if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
        unsuppress_noqueue(q, knote);
    }
    enqueue(proc, kq, knote);
}

/// `knote_drop`: detaches the knote from its source and frees it; a
/// workloop's knote gives back its reference (`kq_remove_knote`).
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
    let kind = q.kind;
    filters::detach(proc, kq, knote);
    if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
        q.knotes.remove(&knote);
    }
    if kind == KqKind::Workloop {
        workq::release(proc, kq);
    }
}

/// `knote_reset_priority`: the knote's priority as its kqueue keeps it
/// (none on a file kqueue; the manager for no QoS on the workqueue
/// kqueue), and its bucket.
fn reset_priority(q: &mut Kqueue, knote: u64, pp: u32) {
    let kind = q.kind;
    let Some(k) = q.knotes.get(&knote) else {
        return;
    };
    let mut qos = priority::thread_qos(pp);
    let pp = match kind {
        KqKind::Workloop => priority::normalize(pp),
        KqKind::Workq => {
            if qos == 0 {
                qos = workq::KQWQ_QOS_MANAGER;
                priority::EVENT_MANAGER_FLAG
            } else {
                priority::normalize(pp)
            }
        }
        KqKind::File => {
            qos = 0;
            0
        }
    };
    let suppressed = k.status & kn::SUPPRESSED != 0;
    let changed = k.qos_index != qos;
    if !suppressed && changed {
        dequeue(q, knote);
    }
    let k = q.knotes.get_mut(&knote).expect("live knote");
    k.qos = pp as i32;
    k.qos_override = qos;
    if !suppressed {
        k.qos_index = qos;
    }
}

/// `knote_apply_touch`: enables, then activates or requeues.
fn apply_touch(proc: &mut Proc, kq: u64, knote: u64, kev: &Kev, result: i32) {
    if let Some(q) = proc.kq.kqueues.get_mut(&kq)
        && let Some(k) = q.knotes.get_mut(&knote)
        && kev.flags & ev::ENABLE != 0
        && k.status & kn::DISABLED != 0
    {
        k.status &= !kn::DISABLED;
        filters::enabled(proc, kq, knote, true);
        if let Some(q) = proc.kq.kqueues.get_mut(&kq)
            && q.knotes
                .get(&knote)
                .is_some_and(|k| k.status & kn::SUPPRESSED != 0)
            && !q.processing
        {
            unsuppress_noqueue(q, knote);
        }
    }
    if result & fr::UPDATE_REQ_QOS != 0
        && kev.qos != 0
        && let Some(q) = proc.kq.kqueues.get_mut(&kq)
        && q.knotes.get(&knote).is_some_and(|k| k.qos != kev.qos)
    {
        reset_priority(q, knote, kev.qos as u32);
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
/// `kev` (`EV_ERROR` with the errno in `data`). Returns the filter
/// result, with the knote when the caller must sleep on it
/// (`FILTER_REGISTER_WAIT`).
pub fn register(ctx: &mut Ctx<'_>, kq: u64, kev: &mut Kev) -> (i32, Option<u64>) {
    match register_inner(ctx, kq, kev) {
        Ok(r) => r,
        Err(e) => {
            kev.flags |= ev::ERROR;
            kev.data = i64::from(e.0);
            (0, None)
        }
    }
}

fn register_inner(ctx: &mut Ctx<'_>, kq: u64, kev: &mut Kev) -> Result<(i32, Option<u64>), Errno> {
    if !(kev.filter < 0 && kev.filter + evfilt::SYSCOUNT >= 0) {
        return Err(Errno::EINVAL);
    }
    // EV_VANISHED only when adding udata-specific dispatch knotes.
    if kev.flags & ev::VANISHED != 0
        && kev.flags & (ev::ADD | ev::DISPATCH2) != ev::ADD | ev::DISPATCH2
    {
        return Err(Errno::EINVAL);
    }
    let requested = kev.flags;
    if kev.flags & ev::DELETE != 0 {
        kev.flags &= !ev::ADD;
    }
    if kev.flags & ev::DISABLE != 0 {
        kev.flags &= !ev::ENABLE;
    }
    let q = &ctx.proc.kq.kqueues[&kq];
    let kind = q.kind;
    let found = find(q, kev);
    // kevent_register_validate_priority: enabled workloop knotes need a
    // QoS.
    if kind == KqKind::Workloop && kev.flags & (ev::DISABLE | ev::DELETE) == 0 {
        let pp = found.map_or(kev.qos, |id| q.knotes[&id].qos);
        if priority::thread_qos(pp as u32) == 0 {
            return Err(Errno::ERANGE);
        }
    }
    let Some(id) = found else {
        if kev.flags & ev::ADD == 0 {
            // A workloop takes EV_ADD | EV_DELETE as a delete that does
            // not care whether the knote exists.
            if kind == KqKind::Workloop
                && requested & (ev::ADD | ev::DELETE) == ev::ADD | ev::DELETE
            {
                return Ok((0, None));
            }
            return Err(Errno::ENOENT);
        }
        return add(ctx, kq, kev);
    };
    if kev.flags & ev::DELETE != 0 {
        if kev.filter == evfilt::WORKLOOP && !workloop::allow_drop(ctx, kq, id, kev) {
            return Ok((0, None));
        }
        let proc = &mut *ctx.proc;
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
        return Ok((0, None));
    }
    let status = ctx.proc.kq.kqueues[&kq].knotes[&id].status;
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
        return Ok((0, None));
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
    let wait = (result & fr::REGISTER_WAIT != 0).then_some(id);
    Ok((result, wait))
}

/// A new knote (the `kn == NULL` branch of `kevent_register`).
fn add(ctx: &mut Ctx<'_>, kq: u64, kev: &mut Kev) -> Result<(i32, Option<u64>), Errno> {
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
        qos: 0,
        udata: kev.udata,
        fflags: 0,
        sfflags: kev.fflags,
        sdata: kev.data,
        ext: kev.ext,
        status,
        is_fd,
        qos_index: 0,
        qos_override: 0,
        thread: None,
        state: filters::State::None,
    };
    let q = ctx.proc.kq.kqueues.get_mut(&kq).expect("live kqueue");
    let kind = q.kind;
    q.knotes.insert(id, k);
    reset_priority(q, id, kev.qos as u32);
    if kind == KqKind::Workloop {
        // kq_add_knote: a reference on the workloop.
        workq::retain(ctx.proc, kq);
    }
    let result = filters::attach(ctx, kq, id, kev);
    let proc = &mut *ctx.proc;
    let k = &proc.kq.kqueues[&kq].knotes[&id];
    if k.flags & ev::ERROR != 0 {
        // Failed to attach: drop it (an error of 0 is silent).
        let e = Errno(k.sdata as i32);
        if let Some(k) = proc
            .kq
            .kqueues
            .get_mut(&kq)
            .and_then(|q| q.knotes.get_mut(&id))
        {
            k.state = filters::State::Detached;
        }
        drop_knote(proc, kq, id);
        return if e.0 == 0 { Ok((0, None)) } else { Err(e) };
    }
    if kind == KqKind::Workloop && k.qos as u32 & priority::OVERCOMMIT_FLAG != 0 {
        workq::set_overcommit(proc, kq);
    }
    apply_touch(proc, kq, id, kev, result);
    let wait = (result & fr::REGISTER_WAIT != 0).then_some(id);
    Ok((result, wait))
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
    let (mut kev, result) = if k.status & (kn::DEFERDELETE | kn::VANISHED) != 0 {
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
    kev.qos = priority::combine(k.qos as u32, k.qos_override) as i32;
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
fn file_end_processing(proc: &mut Proc, kq: u64) {
    loop {
        let Some(&first) = proc
            .kq
            .kqueues
            .get(&kq)
            .and_then(|q| q.suppressed[0].first())
        else {
            break;
        };
        unsuppress(proc, kq, first);
    }
    if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
        q.processing = false;
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

/// `kqueue_process`: delivers up to `nevents` events of `kq` — a file
/// kqueue's, the calling servicer's workqueue bucket, or its workloop's
/// buckets from the highest. A parking servicer with nothing to deliver
/// unbinds.
fn kqueue_process(
    ctx: &mut Ctx<'_>,
    kq: u64,
    flags: u32,
    nevents: usize,
    data: &mut DataArea,
) -> Vec<Kev> {
    filters::fire_timers(ctx.proc);
    host::harvest(ctx.proc, kq);
    let kind = match ctx.proc.kq.kqueues.get(&kq) {
        Some(q) => q.kind,
        None => return Vec::new(),
    };
    let tid = ctx.thread.tid;
    let bound = ctx.proc.wq.threads.get(&tid).and_then(|w| w.bound);
    let mut flags = flags;
    let rc = match kind {
        KqKind::File => {
            if ctx.proc.kq.count(kq) == 0 {
                -1
            } else {
                if let Some(q) = ctx.proc.kq.kqueues.get_mut(&kq) {
                    q.processing = true;
                }
                0
            }
        }
        KqKind::Workq => match bound {
            Some(r) if r.kq == kq => {
                workq::kqworkq_acknowledge(ctx.proc, r, flags, workq::Ack::BeginProcessing)
            }
            _ => -1,
        },
        KqKind::Workloop => workq::workloop_begin_processing(ctx.proc, kq, flags),
    };
    let mut out = Vec::new();
    if rc == -1 {
        return out;
    }
    loop {
        let buckets: Vec<usize> = match kind {
            KqKind::File => vec![0],
            KqKind::Workq => bound.map_or(Vec::new(), |r| vec![usize::from(r.idx) - 1]),
            KqKind::Workloop => (0..workq::KQWL_NBUCKETS).rev().collect(),
        };
        'fill: for b in buckets {
            while out.len() < nevents {
                let Some(&first) = ctx
                    .proc
                    .kq
                    .kqueues
                    .get(&kq)
                    .and_then(|q| q.queues[b].front())
                else {
                    continue 'fill;
                };
                if let Some(kev) = process(ctx, kq, first, data) {
                    out.push(kev);
                }
            }
            break;
        }
        if !out.is_empty() {
            // Events returned: end processing does not fail.
            flags &= !kflag::PARKING;
        }
        let rc = match kind {
            KqKind::File => {
                file_end_processing(ctx.proc, kq);
                0
            }
            KqKind::Workq => match bound {
                Some(r) => workq::kqworkq_end_processing(ctx.proc, r, flags),
                None => 0,
            },
            KqKind::Workloop => workq::workloop_end_processing(ctx.proc, kq, flags),
        };
        if rc == 0 || !out.is_empty() {
            return out;
        }
        // Events came in while parking: process again.
    }
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

/// `kqueue_dealloc`: drops every knote of a kqueue that goes away.
pub fn destroy(proc: &mut Proc, kq: u64) {
    let Some(q) = proc.kq.kqueues.get_mut(&kq) else {
        return;
    };
    // The knotes' workloop references go with the workloop.
    q.kind = match q.kind {
        KqKind::Workloop => KqKind::File,
        k => k,
    };
    let ids: Vec<u64> = q.knotes.keys().copied().collect();
    for id in ids {
        drop_knote(proc, kq, id);
    }
    proc.kq.kqueues.remove(&kq);
    proc.post(WaitKey::Kqueue(kq));
}

/// The kqueues no thread scans: the workqueue kqueue and the workloops.
fn autonomous(proc: &Proc) -> Vec<u64> {
    proc.kq
        .kqueues
        .values()
        .filter(|q| q.kind != KqKind::File)
        .map(|q| q.id)
        .collect()
}

/// The kernel's event sources for kqueues serviced by workqueue threads:
/// fires due timers and takes the host's events, activating their knotes
/// (which may request threads).
pub fn pump(proc: &mut Proc) {
    filters::fire_timers(proc);
    for kq in autonomous(proc) {
        if proc.kq.kqueues.get(&kq).is_some_and(|q| q.host.is_some()) {
            host::harvest(proc, kq);
        }
    }
}

/// What the scheduler waits for on behalf of those kqueues when every
/// thread sleeps: their host descriptors and the earliest armed timer.
pub fn autonomous_wait(proc: &Proc) -> (Vec<(i32, bool, bool)>, Option<Instant>) {
    let mut fds = Vec::new();
    let mut deadline = None;
    for kq in autonomous(proc) {
        fds.extend(host::wait_fds(proc, kq));
        if let Some(t) = next_timer(proc, kq) {
            deadline = Some(deadline.map_or(t, |d: Instant| d.min(t)));
        }
    }
    (fds, deadline)
}

#[cfg(test)]
mod tests;
