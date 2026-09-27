//! The process's workqueue kqueue and its workloops: kqueues whose events
//! are serviced by workqueue threads rather than by a thread calling
//! `kevent` (the `kqworkq_*`, `kqworkloop_*`, and `kqueue_threadreq_*`
//! parts of `bsd/kern/kern_event.c`).
//!
//! The workqueue kqueue (`KEVENT_FLAG_WORKQ`) queues its knotes by QoS in
//! seven buckets, the last the event manager's; a bucket that gains an
//! event makes a thread request at its QoS, and the thread bound to it
//! receives that bucket's events. A workloop (`kevent_id`) is a kqueue
//! named by a 64-bit ID with one thread request, made when it gains an
//! event while it has neither a servicer nor an owner (a thread holding
//! the workloop's drain lock in user space, see
//! [`super::workloop`]); its servicer receives all its events.

use super::{KqKind, ev, kflag, kn};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::process::Proc;
use crate::user::darwin::workq::{self, QOS_ABOVEUI, QOS_MANAGER, priority, trflag};

/// `KQWQ_QOS_MANAGER`: the workqueue kqueue's manager bucket.
pub const KQWQ_QOS_MANAGER: u8 = 7;
/// `KQWQ_NBUCKETS`.
pub const KQWQ_NBUCKETS: usize = 7;
/// `KQWL_NBUCKETS`.
pub const KQWL_NBUCKETS: usize = 6;

/// A kqueue's thread request: the workqueue kqueue's bucket `idx` (1 to
/// 7), or a workloop's (`idx` 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KqrRef {
    /// The kqueue.
    pub kq: u64,
    /// The bucket.
    pub idx: u8,
}

/// `workq_tr_state_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrState {
    /// `WORKQ_TR_STATE_IDLE`: not requested.
    Idle,
    /// `WORKQ_TR_STATE_QUEUED`: waiting for a thread.
    Queued,
    /// `WORKQ_TR_STATE_BOUND`: a thread services it.
    Bound,
}

/// A kqueue's request (`struct workq_threadreq_s` in a kqueue).
#[derive(Clone, Copy, Debug)]
pub struct Kqr {
    /// `tr_state`.
    pub state: TrState,
    /// `tr_thread`: the servicer.
    pub thread: Option<u64>,
    /// `tr_flags`.
    pub flags: u8,
    /// `tr_qos`: the QoS asked of the work queue.
    pub qos: u8,
    /// `tr_kq_qos_index`: the bucket's QoS, or a workloop's
    /// thread-request knote's.
    pub qos_index: u8,
    /// `tr_kq_override_index`.
    pub override_index: u8,
}

impl Kqr {
    fn new(flags: u8, qos_index: u8) -> Self {
        Kqr {
            state: TrState::Idle,
            thread: None,
            flags,
            qos: 0,
            qos_index,
            override_index: 0,
        }
    }
}

/// A workloop's state (`struct kqworkloop`).
#[derive(Clone, Debug)]
pub struct Kqwl {
    /// `kqwl_dynamicid`.
    pub dynamic_id: u64,
    /// `kqwl_owner`: the thread owning the workloop in user space.
    pub owner: Option<u64>,
    /// `kqwl_wakeup_qos`: the highest bucket with events.
    pub wakeup_qos: u8,
    /// `kqwl_params`: the `workq_threadreq_param_t` it was created with.
    pub params: u64,
    /// `kqwl_retains`.
    pub retains: u32,
    /// `kqwl_request`.
    pub request: Kqr,
}

/// What distinguishes the kinds of kqueue.
#[derive(Clone, Debug)]
pub enum Ext {
    /// A `kqueue()` descriptor's.
    File,
    /// The workqueue kqueue's per-bucket requests.
    Workq([Kqr; KQWQ_NBUCKETS]),
    /// A workloop's.
    Workloop(Box<Kqwl>),
}

/// `workq_threadreq_param_t` flags (`TRP_*`).
pub mod trp {
    pub const PRIORITY: u16 = 0x1;
    pub const POLICY: u16 = 0x2;
    pub const CPUPERCENT: u16 = 0x4;
    pub const BOUND_THREAD: u16 = 0x8;
    pub const RELEASED: u16 = 0x8000;
}

/// `kqworkloop_update_threads_qos` operations (`KQWL_UTQ_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Utq {
    UpdateWakeupQos,
    UpdateWakeupOverride,
    RecomputeWakeupQos,
    ResetWakeupOverride,
    Parking,
    Unbinding,
    RedriveEvents,
    SetQosIndex,
}

/// The request `r` names.
pub fn kqr(proc: &Proc, r: KqrRef) -> Option<&Kqr> {
    match &proc.kq.kqueues.get(&r.kq)?.ext {
        Ext::Workq(reqs) => reqs.get(usize::from(r.idx).checked_sub(1)?),
        Ext::Workloop(wl) => Some(&wl.request),
        Ext::File => None,
    }
}

fn kqr_mut(proc: &mut Proc, r: KqrRef) -> Option<&mut Kqr> {
    match &mut proc.kq.kqueues.get_mut(&r.kq)?.ext {
        Ext::Workq(reqs) => reqs.get_mut(usize::from(r.idx).checked_sub(1)?),
        Ext::Workloop(wl) => Some(&mut wl.request),
        Ext::File => None,
    }
}

/// A workloop's state.
pub fn kqwl(proc: &Proc, kq: u64) -> Option<&Kqwl> {
    match &proc.kq.kqueues.get(&kq)?.ext {
        Ext::Workloop(wl) => Some(wl),
        _ => None,
    }
}

fn kqwl_mut(proc: &mut Proc, kq: u64) -> Option<&mut Kqwl> {
    match &mut proc.kq.kqueues.get_mut(&kq)?.ext {
        Ext::Workloop(wl) => Some(wl),
        _ => None,
    }
}

/// Whether `r` is a workloop's request.
pub fn is_workloop(proc: &Proc, r: KqrRef) -> bool {
    kqwl(proc, r.kq).is_some()
}

/// `kevent_get_kqwq`: the process's workqueue kqueue, made on first use
/// (`kqworkq_alloc`) for the interface of the call that made it.
pub fn get_kqwq(proc: &mut Proc, flags: u32) -> u64 {
    if let Some(kq) = proc.kq.workq {
        return kq;
    }
    let kq = proc.kq.create(KqKind::Workq);
    let q = proc.kq.kqueues.get_mut(&kq).expect("new kqueue");
    q.api = Some(if flags & kflag::LEGACY64 != 0 {
        super::KevApi::Kev64
    } else {
        super::KevApi::Qos
    });
    let reqs = std::array::from_fn(|i| {
        // Event delivery through the workqueue kqueue behaves like the
        // original manager-based kqueue's: overcommit, but the manager.
        let mut f = trflag::KEVENT;
        if i + 1 != usize::from(KQWQ_QOS_MANAGER) {
            f |= trflag::OVERCOMMIT;
        }
        Kqr::new(f, i as u8 + 1)
    });
    q.ext = Ext::Workq(reqs);
    proc.kq.workq = Some(kq);
    kq
}

/// `kqworkloop_get_or_create`: the workloop `id` with a reference for
/// the caller.
pub fn workloop_get_or_create(
    proc: &mut Proc,
    id: u64,
    params: Option<u64>,
    flags: u32,
) -> Result<u64, Errno> {
    if id == 0 || id == u64::MAX {
        return Err(Errno::EINVAL);
    }
    if let Some(&kq) = proc.kq.workloops.get(&id) {
        if flags & kflag::DYNAMIC_KQ_MUST_NOT_EXIST != 0 {
            return Err(Errno::EEXIST);
        }
        retain(proc, kq);
        return Ok(kq);
    }
    if flags & kflag::DYNAMIC_KQ_MUST_EXIST != 0 {
        return Err(Errno::ENOENT);
    }
    let kq = proc.kq.create(KqKind::Workloop);
    let mut tr = trflag::WORKLOOP;
    let p = params.unwrap_or(0);
    let trp_flags = p as u16;
    if trp_flags & trp::PRIORITY != 0 {
        tr |= trflag::WL_OUTSIDE_QOS;
    }
    if trp_flags & trp::BOUND_THREAD != 0 {
        tr |= trflag::PERMANENT_BIND;
    }
    if trp_flags != 0 {
        tr |= trflag::WL_PARAMS;
    }
    let q = proc.kq.kqueues.get_mut(&kq).expect("new kqueue");
    q.api = Some(super::KevApi::Qos);
    q.ext = Ext::Workloop(Box::new(Kqwl {
        dynamic_id: id,
        owner: None,
        wakeup_qos: 0,
        params: p,
        retains: 1,
        request: Kqr::new(tr, 0),
    }));
    proc.kq.workloops.insert(id, kq);
    Ok(kq)
}

/// `kqueue_retain` of a workloop.
pub fn retain(proc: &mut Proc, kq: u64) {
    if let Some(wl) = kqwl_mut(proc, kq) {
        wl.retains += 1;
    }
}

/// `kqueue_release` of a workloop: the last reference frees it
/// (`kqworkloop_dealloc`).
pub fn release(proc: &mut Proc, kq: u64) {
    let Some(wl) = kqwl_mut(proc, kq) else {
        return;
    };
    wl.retains -= 1;
    if wl.retains == 0 {
        let id = wl.dynamic_id;
        proc.kq.workloops.remove(&id);
        super::destroy(proc, kq);
    }
}

/// `thread_workq_qos_for_pri`: the QoS band a scheduler priority maps
/// up to (the bands' base priorities are 46, 37, 31, 20, and 4); above
/// user-interactive is none.
fn qos_for_pri(pri: u8) -> u8 {
    use priority::thread_qos::*;
    match pri {
        47.. => 0,
        38..=46 => USER_INTERACTIVE,
        32..=37 => USER_INITIATED,
        21..=31 => LEGACY,
        5..=20 => UTILITY,
        _ => MAINTENANCE,
    }
}

/// `kqueue_threadreq_initiate`: asks the work queue for a thread for `r`
/// at `qos`. With `rebind`, the calling thread `cur` (unbinding from
/// `r`) keeps it if admission allows.
pub fn threadreq_initiate(proc: &mut Proc, r: KqrRef, qos: u8, rebind: Option<u64>) {
    let wl = is_workloop(proc, r);
    if wl {
        // A thread request reference on the workloop.
        retain(proc, r.kq);
    }
    let mut qos = if !wl && qos == KQWQ_QOS_MANAGER {
        QOS_MANAGER
    } else {
        qos
    };
    let Some(q) = kqr(proc, r).copied() else {
        return;
    };
    if q.flags & trflag::WL_OUTSIDE_QOS != 0 {
        let params = kqwl(proc, r.kq).map_or(0, |w| w.params);
        qos = qos_for_pri((params >> 16) as u8);
        if qos == 0 {
            qos = QOS_ABOVEUI;
        }
    }
    if let Some(q) = kqr_mut(proc, r) {
        q.state = TrState::Queued;
        q.qos = qos;
    }
    if let Some(cur) = rebind
        && workq::kern_threadreq_rebind(proc, r, cur)
    {
        threadreq_bind(proc, r, cur);
        return;
    }
    workq::enqueue_kq(proc, r);
}

/// `kqueue_threadreq_modify`: a queued request's QoS changes.
fn threadreq_modify(proc: &mut Proc, r: KqrRef, qos: u8, make_overcommit: bool) {
    if let Some(q) = kqr_mut(proc, r) {
        if q.flags & trflag::WL_OUTSIDE_QOS != 0 {
            return;
        }
        q.qos = qos;
        if make_overcommit {
            q.flags |= trflag::OVERCOMMIT;
        }
    }
}

/// `kqueue_threadreq_bind`: thread `tid` services `r`.
pub fn threadreq_bind(proc: &mut Proc, r: KqrRef, tid: u64) {
    workq::cancel_kq(proc, r);
    if let Some(q) = kqr_mut(proc, r) {
        q.state = TrState::Bound;
        q.thread = Some(tid);
    }
    if let Some(w) = proc.wq.threads.get_mut(&tid) {
        w.bound = Some(r);
    }
    if let Some(wl) = kqwl_mut(proc, r.kq)
        && wl.owner == Some(tid)
    {
        // A servicer is never the owner.
        wl.owner = None;
    }
}

/// `kqueue_threadreq_unbind`: the servicer `tid` stops servicing `r`
/// (a thread ending, or `WORKQ_SET_SELF_WQ_KEVENT_UNBIND`).
pub fn threadreq_unbind(proc: &mut Proc, r: KqrRef, tid: u64) {
    if is_workloop(proc, r) {
        workloop_unbind(proc, r.kq, tid);
    } else {
        kqworkq_acknowledge(proc, r, 0, Ack::Unbind);
    }
}

fn unbind_locked(proc: &mut Proc, r: KqrRef) {
    let Some(q) = kqr_mut(proc, r) else {
        return;
    };
    let thread = q.thread.take();
    q.state = TrState::Idle;
    if let Some(t) = thread
        && let Some(w) = proc.wq.threads.get_mut(&t)
        && w.bound == Some(r)
    {
        w.bound = None;
    }
}

/// `kqworkq_wakeup`: a bucket of the workqueue kqueue gained an event.
pub fn kqworkq_wakeup(proc: &mut Proc, kq: u64, qos_index: u8) {
    let r = KqrRef {
        kq,
        idx: qos_index.clamp(1, KQWQ_NBUCKETS as u8),
    };
    if kqr(proc, r).is_some_and(|q| q.state == TrState::Idle) {
        threadreq_initiate(proc, r, r.idx, None);
    }
}

/// `kqworkq_acknowledge_events` operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    BeginProcessing,
    EndProcessing,
    Unbind,
}

/// `kqworkq_acknowledge_events`: suppressed knotes of the bucket return;
/// the request unbinds when asked or when parking finds nothing (a new
/// request is made if events remain). Returns -1 when unbound.
pub fn kqworkq_acknowledge(proc: &mut Proc, r: KqrRef, kevent_flags: u32, op: Ack) -> i32 {
    let b = usize::from(r.idx) - 1;
    loop {
        let Some(&first) = proc
            .kq
            .kqueues
            .get(&r.kq)
            .and_then(|q| q.suppressed.get(b))
            .and_then(|s| s.first())
        else {
            break;
        };
        super::unsuppress(proc, r.kq, first);
    }
    let empty = proc
        .kq
        .kqueues
        .get(&r.kq)
        .is_none_or(|q| q.queues[b].is_empty());
    let unbind = match op {
        Ack::Unbind => true,
        _ if kevent_flags & kflag::PARKING == 0 => false,
        _ => empty,
    };
    if !unbind {
        return 0;
    }
    unbind_locked(proc, r);
    if !empty {
        // Ask for a new thread for what was not processed.
        threadreq_initiate(proc, r, r.idx, None);
    }
    -1
}

/// `kqworkq_end_processing`: when parking, -1 if events remain (process
/// again).
pub fn kqworkq_end_processing(proc: &mut Proc, r: KqrRef, kevent_flags: u32) -> i32 {
    if kevent_flags & kflag::PARKING != 0
        && kqworkq_acknowledge(proc, r, kevent_flags, Ack::EndProcessing) == 0
    {
        return -1;
    }
    0
}

/// `kqworkloop_override`: the asynchronous QoS the workloop contributes.
fn override_of(q: &Kqr) -> u8 {
    q.qos_index.max(q.override_index)
}

/// `kqworkloop_acknowledge_events`: suppressed knotes return, but a
/// QoS-adjusting knote disabled by its own `EV_DISPATCH` keeps pushing.
/// Returns that push.
fn workloop_acknowledge(proc: &mut Proc, kq: u64) -> u8 {
    let mut qos = 0;
    let Some(q) = proc.kq.kqueues.get(&kq) else {
        return 0;
    };
    let supp = q.suppressed[0].clone();
    for id in supp {
        let Some(k) = proc.kq.kqueues.get(&kq).and_then(|q| q.knotes.get(&id)) else {
            continue;
        };
        if k.filter == super::evfilt::MACHPORT
            && k.status & kn::DISABLED != 0
            && k.status & kn::DROPPING == 0
            && k.flags & (ev::DISPATCH | ev::DISABLE) == ev::DISPATCH
        {
            qos = qos.max(k.qos_override);
            continue;
        }
        super::unsuppress(proc, kq, id);
    }
    qos
}

/// `kqworkloop_update_threads_qos`: recomputes the workloop's wakeup QoS
/// and override, then makes, adjusts, or leaves its thread request.
pub fn update_threads_qos(proc: &mut Proc, kq: u64, op: Utq, qos: u8, rebind: Option<u64>) {
    let (queues_top, suppressed_empty) = match proc.kq.kqueues.get(&kq) {
        Some(q) => (
            (1..=KQWL_NBUCKETS as u8)
                .rev()
                .find(|&i| !q.queues[usize::from(i) - 1].is_empty())
                .unwrap_or(0),
            q.suppressed[0].is_empty(),
        ),
        None => return,
    };
    let Some(wl) = kqwl_mut(proc, kq) else {
        return;
    };
    let old_override = override_of(&wl.request);
    let mut qos = qos;
    let recompute = match op {
        Utq::UpdateWakeupQos => {
            wl.wakeup_qos = qos;
            true
        }
        Utq::ResetWakeupOverride => {
            wl.request.override_index = qos;
            true
        }
        Utq::Parking | Utq::Unbinding | Utq::RecomputeWakeupQos => {
            if op != Utq::RecomputeWakeupQos {
                wl.request.override_index = qos;
            }
            if suppressed_empty {
                wl.request.override_index = 0;
            }
            wl.wakeup_qos = queues_top;
            true
        }
        Utq::UpdateWakeupOverride => true,
        Utq::RedriveEvents => false,
        Utq::SetQosIndex => {
            wl.request.qos_index = qos;
            false
        }
    };
    if recompute {
        // The override is at least the highest QoS with an event.
        qos = qos.max(wl.wakeup_qos);
        wl.request.override_index = wl.request.override_index.max(qos);
    }
    let owner = wl.owner;
    let wakeup = wl.wakeup_qos;
    let req = wl.request;
    let new_override = override_of(&req);
    let r = KqrRef { kq, idx: 0 };
    if req.state == TrState::Idle && req.flags & trflag::PERMANENT_BIND == 0 {
        // No servicer nor request: ask for one if there is asynchronous
        // work and no owner.
        if owner.is_none() && wakeup != 0 {
            let rebind = if op == Utq::Unbinding { rebind } else { None };
            threadreq_initiate(proc, r, new_override, rebind);
        }
    } else if req.thread.is_some() || new_override == 0 {
        // A servicer takes the difference as an override; a request
        // without events is left for its servicer to discover.
    } else if old_override != new_override {
        threadreq_modify(proc, r, new_override, false);
    }
}

/// `kqworkloop_wakeup`: a bucket of the workloop gained an event.
pub fn kqworkloop_wakeup(proc: &mut Proc, kq: u64, qos: u8) {
    let Some(wl) = kqwl(proc, kq) else {
        return;
    };
    if qos <= wl.wakeup_qos {
        return;
    }
    if proc.kq.kqueues.get(&kq).is_some_and(|q| q.processing) {
        // The servicer processing it recomputes at the end.
        return;
    }
    update_threads_qos(proc, kq, Utq::UpdateWakeupQos, qos, None);
}

/// `kqworkloop_set_overcommit`: an overcommit knote makes the workloop's
/// request overcommit.
pub fn set_overcommit(proc: &mut Proc, kq: u64) {
    let r = KqrRef { kq, idx: 0 };
    let Some(q) = kqr(proc, r).copied() else {
        return;
    };
    if q.flags & trflag::OVERCOMMIT != 0 {
        return;
    }
    if q.state == TrState::Queued {
        threadreq_modify(proc, r, q.qos, true);
    } else if let Some(q) = kqr_mut(proc, r) {
        q.flags |= trflag::OVERCOMMIT;
    }
}

/// `kqworkloop_begin_processing`: returns -1 when there is nothing to
/// process (a parking servicer may have unbound).
pub fn workloop_begin_processing(proc: &mut Proc, kq: u64, kevent_flags: u32) -> i32 {
    let r = KqrRef { kq, idx: 0 };
    let Some(req) = kqr(proc, r).copied() else {
        return -1;
    };
    if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
        q.processing = true;
    }
    let suppressed = proc
        .kq
        .kqueues
        .get(&kq)
        .is_some_and(|q| !q.suppressed[0].is_empty());
    let op = if kevent_flags & kflag::PARKING != 0 {
        if req.flags & (trflag::OVERCOMMIT | trflag::PERMANENT_BIND) != 0 {
            Some(Utq::Parking)
        } else {
            Some(Utq::Unbinding)
        }
    } else if suppressed {
        Some(Utq::ResetWakeupOverride)
    } else {
        None
    };
    let Some(op) = op else {
        return 0;
    };
    let thread = req.thread;
    let qos_override = workloop_acknowledge(proc, kq);
    if op == Utq::Unbinding {
        unbind_locked(proc, r);
        release_live(proc, kq);
    }
    update_threads_qos(proc, kq, op, qos_override, thread);
    let (count, owner) = (proc.kq.count(kq), kqwl(proc, kq).and_then(|w| w.owner));
    let now = kqr(proc, r).and_then(|q| q.thread);
    let mut rc = 0;
    if op == Utq::Parking && (count == 0 || owner.is_some()) {
        if req.flags & trflag::OVERCOMMIT != 0 && req.flags & trflag::PERMANENT_BIND == 0 {
            unbind_locked(proc, r);
            release_live(proc, kq);
        }
        rc = -1;
    } else if op == Utq::Unbinding && now != thread {
        rc = -1;
    }
    if rc == -1
        && let Some(q) = proc.kq.kqueues.get_mut(&kq)
    {
        q.processing = false;
    }
    rc
}

/// `kqworkloop_end_processing`: with `KEVENT_FLAG_PARKING`, -1 if events
/// came in meanwhile (process again), else the servicer unbinds.
pub fn workloop_end_processing(proc: &mut Proc, kq: u64, kevent_flags: u32) -> i32 {
    let r = KqrRef { kq, idx: 0 };
    if kevent_flags & kflag::PARKING != 0 {
        let qos_override = workloop_acknowledge(proc, kq);
        update_threads_qos(proc, kq, Utq::Parking, qos_override, None);
        let (wakeup, owner) = kqwl(proc, kq).map_or((0, None), |w| (w.wakeup_qos, w.owner));
        if wakeup != 0 && owner.is_none() {
            return -1;
        }
        unbind_locked(proc, r);
        release_live(proc, kq);
        if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
            q.processing = false;
        }
    } else {
        if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
            q.processing = false;
        }
        update_threads_qos(proc, kq, Utq::RecomputeWakeupQos, 0, None);
    }
    0
}

/// `kqworkloop_release_live`: drops a reference that is not the last.
fn release_live(proc: &mut Proc, kq: u64) {
    if let Some(wl) = kqwl_mut(proc, kq)
        && wl.retains > 1
    {
        wl.retains -= 1;
    }
}

/// `kqworkloop_unbind`: the servicer leaves outside of event processing;
/// a new request is made for remaining events.
fn workloop_unbind(proc: &mut Proc, kq: u64, _tid: u64) {
    let mut qos_override = 0;
    if proc
        .kq
        .kqueues
        .get(&kq)
        .is_some_and(|q| !q.suppressed[0].is_empty())
    {
        if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
            q.processing = true;
        }
        qos_override = workloop_acknowledge(proc, kq);
        if let Some(q) = proc.kq.kqueues.get_mut(&kq) {
            q.processing = false;
        }
    }
    unbind_locked(proc, KqrRef { kq, idx: 0 });
    update_threads_qos(proc, kq, Utq::Parking, qos_override, None);
    release(proc, kq);
}

/// The workloop's owner changed (`filt_wlupdate` phase 2): a new owner
/// defers a pending request's thread; losing the owner makes a request
/// for pending events.
pub fn set_owner(proc: &mut Proc, kq: u64, new_owner: Option<u64>, action: Option<(Utq, u8)>) {
    let Some(wl) = kqwl_mut(proc, kq) else {
        return;
    };
    let mut new_owner = new_owner;
    if new_owner.is_some() && new_owner == wl.request.thread {
        // Already tracked as the servicer.
        new_owner = None;
    }
    let mut action = action;
    if wl.owner != new_owner {
        wl.owner = new_owner;
        let requested = wl.request.state != TrState::Idle;
        let pending = wl.request.state == TrState::Queued;
        if new_owner.is_some() {
            if pending && action.is_none() {
                action = Some((Utq::RedriveEvents, 0));
            }
        } else if action.is_none() && !requested && wl.wakeup_qos != 0 {
            action = Some((Utq::RedriveEvents, 0));
        }
    }
    if let Some((op, qos)) = action {
        update_threads_qos(proc, kq, op, qos, None);
    }
}
