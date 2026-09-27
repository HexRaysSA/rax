//! Work queues: the kernel side of libpthread's workqueue threads
//! (`bsd/pthread/pthread_workqueue.c`, `bsd/pthread/workqueue_internal.h`,
//! `bsd/pthread/workqueue_syscalls.h`, and libpthread's
//! `kern/kern_support.c`).
//!
//! User space asks for threads — anonymously at a QoS
//! (`WQOPS_QUEUE_REQTHREADS`), or through a kqueue whose events need
//! servicing: the process's workqueue kqueue and its workloops
//! ([`super::kevent::workq`]). Queued thread requests are admitted by
//! pool (overcommit always, the event manager one at a time, constrained
//! requests while fewer active threads than CPUs run at or above their
//! QoS, cooperative requests while the pool has room), and each admitted
//! request runs on an idle workqueue thread or a new one. A thread starts
//! in libpthread's `_pthread_wqthread(self, kport, stacklowaddr,
//! keventlist, flags, nkevents)` on its kernel-allocated stack, with the
//! events of its kqueue request already on that stack, and comes back
//! with `WQOPS_THREAD_RETURN` (or the kevent and workloop forms, which
//! first hand the kqueue its pending changes) to take the next request or
//! park.
//!
//! One host thread runs every guest thread, so the kernel's creator
//! thread, thread calls, turnstiles, and scheduler callbacks are replaced
//! by [`redrive`], which the scheduler calls between slices: a
//! workqueue thread counts as active unless it sleeps, and requests are
//! bound to threads while admission allows. A bound thread performs its
//! setup — the kernel's unpark continuation — in its own context when it
//! is next scheduled ([`run_pending`]).

pub mod priority;

use std::collections::BTreeMap;

use self::priority::thread_qos;
use super::abi::{DarwinAbi, Errno};
use super::arch::{DarwinCpu, Rv, SysResult};
use super::kevent::workq::KqrRef;
use super::mach::ipc::{KObject, Port};
use super::mach::task::ThreadMach;
use super::process::{Proc, Thread};
use super::signal::{self, ThreadSig};
use super::syscall::Ctx;
use super::syscall::bsd::pthread::{set_start_state, tag};
use super::wait::{Wait, WaitKey};

/// `workq_kernreturn` operations (`WQOPS_*`).
pub mod wqops {
    pub const THREAD_RETURN: i32 = 0x004;
    pub const QUEUE_NEWSPISUPP: i32 = 0x010;
    pub const QUEUE_REQTHREADS: i32 = 0x020;
    pub const QUEUE_REQTHREADS2: i32 = 0x030;
    pub const THREAD_KEVENT_RETURN: i32 = 0x040;
    pub const SET_EVENT_MANAGER_PRIORITY: i32 = 0x080;
    pub const THREAD_WORKLOOP_RETURN: i32 = 0x100;
    pub const SHOULD_NARROW: i32 = 0x200;
    pub const SETUP_DISPATCH: i32 = 0x400;
}

/// Upcall flags (`WQ_FLAG_THREAD_*`), the fifth argument of
/// `_pthread_wqthread`.
pub mod upcall {
    pub const PRIO_SCHED: u32 = 0x0000_8000;
    pub const PRIO_QOS: u32 = 0x0000_4000;
    pub const PRIO_MASK: u32 = 0x0000_0fff;
    pub const OVERCOMMIT: u32 = 0x0001_0000;
    pub const REUSE: u32 = 0x0002_0000;
    pub const NEWSPI: u32 = 0x0004_0000;
    pub const KEVENT: u32 = 0x0008_0000;
    pub const EVENT_MANAGER: u32 = 0x0010_0000;
    pub const TSD_BASE_SET: u32 = 0x0020_0000;
    pub const WORKLOOP: u32 = 0x0040_0000;
    pub const OUTSIDEQOS: u32 = 0x0080_0000;
    pub const COOPERATIVE: u32 = 0x0100_0000;
}

/// Setup flags (`WQ_SETUP_*`).
pub mod setup {
    pub const FIRST_USE: u32 = 1;
    pub const CLEAR_VOUCHER: u32 = 2;
    pub const EXIT_THREAD: u32 = 8;
}

/// Thread request flags (`WORKQ_TR_FLAG_*`).
pub mod trflag {
    pub const KEVENT: u8 = 0x01;
    pub const WORKLOOP: u8 = 0x02;
    pub const OVERCOMMIT: u8 = 0x04;
    pub const WL_PARAMS: u8 = 0x08;
    pub const WL_OUTSIDE_QOS: u8 = 0x10;
    pub const COOPERATIVE: u8 = 0x20;
    pub const PERMANENT_BIND: u8 = 0x40;
}

/// `WORKQ_THREAD_QOS_ABOVEUI`.
pub const QOS_ABOVEUI: u8 = thread_qos::LAST;
/// `WORKQ_THREAD_QOS_MANAGER`: the event manager's bucket, outside the
/// QoS range.
pub const QOS_MANAGER: u8 = thread_qos::LAST + 1;
/// `WORKQUEUE_MAXTHREADS`.
pub const MAX_THREADS: usize = 512;
/// `wq_max_constrained_threads`: `WORKQUEUE_MAXTHREADS / 8`, above the
/// `ncpus * WORKQUEUE_CONSTRAINED_FACTOR` floor.
const MAX_CONSTRAINED: usize = MAX_THREADS / 8;
/// `WQ_KEVENT_LIST_LEN`.
pub const KEVENT_LIST_LEN: u64 = 16;
/// `WQ_KEVENT_DATA_SIZE`.
pub const KEVENT_DATA_SIZE: u64 = 32 * 1024;
/// `WORKQ_EXIT_THREAD_NKEVENT`.
pub const EXIT_THREAD_NKEVENT: i32 = -1;
/// `PTH_DEFAULT_STACKSIZE`.
const DEFAULT_STACKSIZE: u64 = 512 * 1024;
/// `sizeof(struct kevent_qos_s)`.
const KEVENT_QOS_SIZE: u64 = 72;
/// `VM_MEMORY_STACK`.
const VM_MEMORY_STACK: u32 = 30;
/// `WORKQ_DISPATCH_SUPPORTED_FLAGS` and
/// `WORKQ_DISPATCH_MIN_SUPPORTED_VERSION`.
const DISPATCH_SUPPORTED_FLAGS: u32 = 0;
const DISPATCH_MIN_SUPPORTED_VERSION: u32 = 1;

/// `workq_threadmask`: the signals a workqueue thread leaves unblocked.
pub const WORKQ_THREADMASK: u32 =
    (signal::THREADMASK | signal::CANTMASK | signal::bit(signal::SIGPROF))
        & !signal::bit(signal::SIGABRT);

/// `PTHREAD_T_OFFSET`: the `pthread_t` sits this far into the top of a
/// workqueue thread's allocation (on the stack's last page on arm64).
fn pthread_t_offset(abi: DarwinAbi) -> u64 {
    match abi {
        DarwinAbi::Arm64 => 12 * 1024,
        DarwinAbi::X86_64 => 0,
    }
}

/// `_wq_bucket`: maintenance and background share a bucket; the manager
/// has the last.
fn bucket(qos: u8) -> usize {
    match qos {
        thread_qos::MAINTENANCE => 0,
        q => usize::from(q.max(2)) - 2,
    }
}

/// `WORKQ_NUM_QOS_BUCKETS`.
const NUM_QOS_BUCKETS: usize = 6;

/// The pools a running thread counts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    /// Admitted against the CPU count (`!overcommit && !cooperative`).
    Constrained,
    /// Always admitted.
    Overcommit,
    /// The cooperative pool.
    Cooperative,
}

/// A running thread's priority and pool (`uu_workq_pri` and the
/// `UT_WORKQ_OVERCOMMIT`/`UT_WORKQ_COOPERATIVE` type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sched {
    /// `qos_req`.
    pub qos_req: u8,
    /// `qos_bucket`: the requested QoS or the manager's.
    pub qos_bucket: u8,
    /// The pool.
    pub pool: Pool,
}

/// A workqueue thread's kernel state (the `uu_workq_*` fields of its
/// uthread and `uu_kqr_bound`).
#[derive(Clone, Debug, Default)]
pub struct ThreadWorkq {
    /// `uu_workq_stackaddr`: the stack allocation (guard page first).
    pub stackaddr: u64,
    /// `uu_workq_thport`: its port name, made on first use.
    pub thport: u32,
    /// `UT_WORKQ_NEW`: never returned to user space.
    pub new: bool,
    /// Set while the thread is logically running a request (counted in
    /// `wq_thscheduled_count`); `None` while it is parked.
    pub sched: Option<Sched>,
    /// `uus_workq_park_data.qos`: the QoS reported to user space.
    pub park_qos: u8,
    /// `uus_workq_park_data.upcall_flags`.
    pub upcall_flags: u32,
    /// `UT_WORKQ_OUTSIDE_QOS`.
    pub outside_qos: bool,
    /// `uu_kqr_bound`: the kqueue request the thread services.
    pub bound: Option<KqrRef>,
    /// Setup flags of an unpark the thread performs when it next runs.
    pub pending: Option<u32>,
    /// `uu_workq_pthread_kill_allowed`.
    pub kill_allowed: bool,
    /// `uu_workq_pri.qos_override`: a dispatch override.
    pub qos_override: u8,
}

/// A queued thread request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReqRef {
    /// A `WQOPS_QUEUE_REQTHREADS` request.
    Anon(u64),
    /// A kqueue's request.
    Kq(KqrRef),
}

/// An anonymous request (`workq_reqthreads`).
#[derive(Clone, Copy, Debug)]
struct Anon {
    id: u64,
    qos: u8,
    flags: u8,
    count: u16,
}

/// A process's work queue (`struct workqueue`).
#[derive(Debug)]
pub struct Workqueue {
    /// `workq_open` ran (`proc_get_wqptr`).
    pub opened: bool,
    /// `p_dispatchqueue_serialno_offset`.
    pub serialno_offset: u64,
    /// `p_dispatchqueue_label_offset`.
    pub label_offset: u64,
    /// `wq_event_manager_priority`.
    pub manager_priority: u32,
    /// `p_workq_allow_sigmask`.
    pub allow_sigmask: u32,
    anon: Vec<Anon>,
    /// Queued requests in enqueue order.
    queue: Vec<ReqRef>,
    next_anon: u64,
    /// Workqueue threads by thread ID.
    pub threads: BTreeMap<u64, ThreadWorkq>,
    /// Parked threads, most recently parked first (`wq_thidlelist`).
    idle: Vec<u64>,
    /// Threads marked as heavy users of shared cluster resources.
    pub shared_rsrc: std::collections::BTreeSet<u64>,
}

impl Default for Workqueue {
    fn default() -> Self {
        Workqueue {
            opened: false,
            serialno_offset: 0,
            label_offset: 0,
            // task_get_default_manager_qos: USER_INITIATED for an app.
            manager_priority: priority::make_from_thread_qos(thread_qos::USER_INITIATED, 0, 0),
            allow_sigmask: 0,
            anon: Vec::new(),
            queue: Vec::new(),
            next_anon: 0,
            threads: BTreeMap::new(),
            idle: Vec::new(),
            shared_rsrc: Default::default(),
        }
    }
}

/// The CPUs the emulated machine has (`qos_max_parallelism`).
pub fn parallelism() -> usize {
    usize::from(super::commpage::NCPUS)
}

/// A request's QoS, flags, and remaining count.
fn req_info(proc: &Proc, r: ReqRef) -> Option<(u8, u8, u16)> {
    match r {
        ReqRef::Anon(id) => proc
            .wq
            .anon
            .iter()
            .find(|a| a.id == id)
            .map(|a| (a.qos, a.flags, a.count)),
        ReqRef::Kq(k) => super::kevent::workq::kqr(proc, k).map(|q| (q.qos, q.flags, 1)),
    }
}

fn is_overcommit(flags: u8) -> bool {
    flags & trflag::OVERCOMMIT != 0
}

fn is_cooperative(flags: u8) -> bool {
    flags & trflag::COOPERATIVE != 0
}

fn is_constrained(flags: u8) -> bool {
    flags & (trflag::OVERCOMMIT | trflag::COOPERATIVE | trflag::PERMANENT_BIND) == 0
}

/// Whether workqueue thread `tid` is active: scheduled and not blocked
/// (the scheduler callback's view). The calling thread runs.
fn active(proc: &Proc, tid: u64, cur: Option<u64>) -> bool {
    if cur == Some(tid) {
        return true;
    }
    proc.threads
        .get(&tid)
        .is_some_and(|t| !t.exited && t.mach.suspend_count == 0 && (t.wait.is_none() || t.woken))
}

/// A queued request as selection sees it: its QoS and flags.
type Candidate = (ReqRef, u8, u8);

impl Workqueue {
    fn sched_of(&self, tid: Option<u64>) -> Option<Sched> {
        tid.and_then(|t| self.threads.get(&t)).and_then(|w| w.sched)
    }

    /// `workq_constrained_allowance`: how many more constrained threads
    /// may run at `at_qos` on `ncpus` CPUs, not counting `uth` itself;
    /// `active` tells whether a scheduled thread is running.
    fn constrained_allowance(
        &self,
        at_qos: u8,
        uth: Option<u64>,
        ncpus: usize,
        active: &dyn Fn(u64) -> bool,
    ) -> usize {
        let mut scheduled = self
            .threads
            .values()
            .filter(|w| w.sched.is_some_and(|s| s.pool == Pool::Constrained))
            .count();
        let me = self.sched_of(uth);
        if me.is_some_and(|s| s.pool == Pool::Constrained) {
            scheduled -= 1;
        }
        if scheduled >= MAX_CONSTRAINED {
            // Constrained threads must return before more may run.
            return 0;
        }
        // Active threads in this bucket and above (not the manager).
        let b = bucket(at_qos);
        let mut thactive = self
            .threads
            .iter()
            .filter(|(tid, w)| {
                w.sched.is_some_and(|s| {
                    s.qos_bucket != QOS_MANAGER
                        && bucket(s.qos_bucket) >= b
                        && bucket(s.qos_bucket) < NUM_QOS_BUCKETS
                }) && active(**tid)
            })
            .count();
        if let Some(s) = me
            && s.qos_bucket != QOS_MANAGER
            && at_qos <= s.qos_bucket
        {
            thactive = thactive.saturating_sub(1);
        }
        ncpus.saturating_sub(thactive)
    }

    /// `workq_cooperative_allowance`: the pool is not full, nothing
    /// serves the request's bucket, or fewer threads than CPUs serve its
    /// QoS and above.
    fn cooperative_allowance(&self, qos: u8, uth: Option<u64>, ncpus: usize) -> bool {
        let coop: Vec<Sched> = self
            .threads
            .iter()
            .filter(|(tid, _)| Some(**tid) != uth)
            .filter_map(|(_, w)| w.sched.filter(|s| s.pool == Pool::Cooperative))
            .collect();
        if coop.len() < ncpus {
            return true;
        }
        let b = bucket(qos);
        if !coop.iter().any(|s| bucket(s.qos_req) == b) {
            return true;
        }
        coop.iter().filter(|s| s.qos_req >= qos).count() < ncpus
    }

    /// `workq_may_start_event_mgr_thread`: no manager runs, or `uth` is
    /// it.
    fn may_start_manager(&self, uth: Option<u64>) -> bool {
        let running = self
            .threads
            .values()
            .any(|w| w.sched.is_some_and(|s| s.qos_bucket == QOS_MANAGER));
        !running
            || self
                .sched_of(uth)
                .is_some_and(|s| s.qos_bucket == QOS_MANAGER)
    }

    /// `workq_threadreq_select`: the request `uth` (or a new thread)
    /// should run: the manager's first, then the best of the overcommit
    /// and cooperative pools, unless a constrained request of a higher
    /// QoS is admitted. Within a pool the highest QoS wins, the first
    /// queued among equals.
    fn select(
        &self,
        reqs: &[Candidate],
        uth: Option<u64>,
        ncpus: usize,
        active: &dyn Fn(u64) -> bool,
    ) -> Option<ReqRef> {
        if let Some(&(r, ..)) = reqs.iter().find(|(_, q, _)| *q == QOS_MANAGER)
            && self.may_start_manager(uth)
        {
            return Some(r);
        }
        let best = |pred: &dyn Fn(u8) -> bool| {
            reqs.iter()
                .filter(|(_, q, f)| *q != QOS_MANAGER && pred(*f))
                .fold(None::<(ReqRef, u8)>, |acc, &(r, q, _)| match acc {
                    Some((_, bq)) if bq >= q => acc,
                    _ => Some((r, q)),
                })
        };
        let mut pick = best(&is_overcommit);
        let mut qos = pick.map_or(0, |p| p.1);
        if let Some((r, q)) = best(&is_cooperative)
            && qos <= q
            && self.cooperative_allowance(q, uth, ncpus)
        {
            pick = Some((r, q));
            qos = q;
        }
        if let Some((r, q)) = best(&is_constrained)
            && qos < q
            && self.constrained_allowance(q, uth, ncpus, active) > 0
        {
            return Some(r);
        }
        pick.map(|p| p.0)
    }
}

fn constrained_allowance(proc: &Proc, at_qos: u8, uth: Option<u64>, cur: Option<u64>) -> usize {
    proc.wq
        .constrained_allowance(at_qos, uth, parallelism(), &|t| active(proc, t, cur))
}

fn cooperative_allowance(proc: &Proc, qos: u8, uth: Option<u64>) -> bool {
    proc.wq.cooperative_allowance(qos, uth, parallelism())
}

fn may_start_manager(proc: &Proc, uth: Option<u64>) -> bool {
    proc.wq.may_start_manager(uth)
}

/// The request `uth` (or a new thread) should run.
fn select(proc: &Proc, uth: Option<u64>, cur: Option<u64>) -> Option<ReqRef> {
    let reqs: Vec<Candidate> = proc
        .wq
        .queue
        .iter()
        .filter_map(|&r| req_info(proc, r).map(|(q, f, _)| (r, q, f)))
        .collect();
    proc.wq
        .select(&reqs, uth, parallelism(), &|t| active(proc, t, cur))
}

/// `workq_threadreq_dequeue`: one thread of the request is served.
fn dequeue(proc: &mut Proc, r: ReqRef) {
    let wq = &mut proc.wq;
    match r {
        ReqRef::Anon(id) => {
            if let Some(i) = wq.anon.iter().position(|a| a.id == id) {
                wq.anon[i].count -= 1;
                if wq.anon[i].count == 0 {
                    wq.anon.remove(i);
                    wq.queue.retain(|&q| q != r);
                }
            }
        }
        ReqRef::Kq(_) => wq.queue.retain(|&q| q != r),
    }
}

/// Queues a kqueue's request (`workq_kern_threadreq_initiate` without the
/// rebind case, which [`kern_threadreq_rebind`] handles).
pub fn enqueue_kq(proc: &mut Proc, r: KqrRef) {
    let rr = ReqRef::Kq(r);
    if !proc.wq.queue.contains(&rr) {
        proc.wq.queue.push(rr);
    }
}

/// Removes a kqueue's queued request (`workq_threadreq_destroy`, or a
/// request that was bound another way).
pub fn cancel_kq(proc: &mut Proc, r: KqrRef) {
    proc.wq.queue.retain(|&q| q != ReqRef::Kq(r));
}

/// `workq_kern_threadreq_initiate` with `WORKQ_THREADREQ_ATTEMPT_REBIND`:
/// whether the calling thread `cur`, about to park, may take the request
/// itself (the request is then not queued).
pub fn kern_threadreq_rebind(proc: &mut Proc, r: KqrRef, cur: u64) -> bool {
    let Some((qos, flags, _)) = req_info(proc, ReqRef::Kq(r)) else {
        return false;
    };
    let admissible = if qos == QOS_MANAGER {
        may_start_manager(proc, Some(cur))
    } else if is_cooperative(flags) {
        cooperative_allowance(proc, qos, Some(cur))
    } else if is_constrained(flags) {
        constrained_allowance(proc, qos, Some(cur), Some(cur)) > 0
    } else {
        true
    };
    if !admissible {
        return false;
    }
    if let Some(w) = proc.wq.threads.get_mut(&cur)
        && let Some(s) = &mut w.sched
        && s.qos_bucket != qos
    {
        s.qos_req = qos;
        s.qos_bucket = qos;
    }
    true
}

/// Binds request `r` to thread `tid` and computes its upcall flags
/// (the run half of `workq_select_threadreq_or_park_and_unlock`).
fn run_request(proc: &mut Proc, tid: u64, r: ReqRef) {
    let Some((qos, flags, _)) = req_info(proc, r) else {
        return;
    };
    dequeue(proc, r);
    let pool = if is_overcommit(flags) {
        Pool::Overcommit
    } else if is_cooperative(flags) {
        Pool::Cooperative
    } else {
        Pool::Constrained
    };
    let mut up = upcall::NEWSPI;
    if qos == QOS_MANAGER {
        up |= upcall::EVENT_MANAGER;
    } else if is_overcommit(flags) {
        up |= upcall::OVERCOMMIT;
    } else if is_cooperative(flags) {
        up |= upcall::COOPERATIVE;
    }
    if flags & trflag::KEVENT != 0 {
        up |= upcall::KEVENT;
    }
    if flags & trflag::WORKLOOP != 0 {
        up |= upcall::WORKLOOP | upcall::KEVENT;
    }
    if let Some(w) = proc.wq.threads.get_mut(&tid) {
        w.sched = Some(Sched {
            qos_req: qos,
            qos_bucket: qos,
            pool,
        });
        w.park_qos = qos;
        w.outside_qos = false;
        w.upcall_flags = up;
    }
    if let ReqRef::Kq(k) = r {
        // kqueue_threadreq_bind_prepost and _commit.
        super::kevent::workq::threadreq_bind(proc, k, tid);
    }
}

/// `workq_add_new_idle_thread`: a new workqueue thread with its stack
/// (`workq_create_threadstack`); it is not runnable until a request is
/// bound to it.
fn create_thread(proc: &mut Proc) -> Option<u64> {
    if proc.wq.threads.len() >= MAX_THREADS || !proc.pthread.registered {
        return None;
    }
    let abi = proc.abi;
    let page = proc.vm.page;
    let pthsize = u64::from(proc.pthread.pthread_size) + pthread_t_offset(abi);
    let pthsize = (pthsize + page - 1) & !(page - 1);
    let size = page + DEFAULT_STACKSIZE + pthsize;
    let hint = proc.pthread.stack_addr_hint;
    let stackaddr =
        super::syscall::mach::vm::map_anywhere(proc, hint, size, page - 1, VM_MEMORY_STACK).ok()?;
    // The guard page is at the lowest address.
    let _ = proc.space.protect(stackaddr, page, super::vm::perms(0));
    let tid = proc.next_tid;
    proc.next_tid += 1;
    let kport = Port::new(KObject::Thread(tid));
    let cpu = DarwinCpu::new(abi, &proc.space);
    let thread = Thread {
        tid,
        port: 0,
        kport,
        cpu,
        // Workqueue threads do not inherit masks.
        sig: ThreadSig {
            mask: !WORKQ_THREADMASK,
            ..Default::default()
        },
        wait: Some(park_wait(tid)),
        resume: None,
        pthread: 0,
        exited: false,
        woken: false,
        wake_event: false,
        mach: ThreadMach {
            tag: tag::WORKQUEUE,
            ..Default::default()
        },
        name: Vec::new(),
        pw: Default::default(),
    };
    proc.threads.insert(tid, thread);
    proc.wq.threads.insert(
        tid,
        ThreadWorkq {
            stackaddr,
            new: true,
            ..Default::default()
        },
    );
    Some(tid)
}

/// The wait of a parked workqueue thread (`workq_parked_wait_event`).
fn park_wait(tid: u64) -> Wait {
    Wait {
        keys: vec![WaitKey::WorkqPark(tid)],
        interruptible: false,
        seq: super::wait::next_seq(),
        ..Default::default()
    }
}

/// `workq_schedule_creator`: binds admissible requests to idle or new
/// threads. The scheduler calls this between slices; bound threads set
/// themselves up when they run ([`run_pending`]).
pub fn redrive(proc: &mut Proc) {
    if proc.wq.queue.is_empty() || proc.exit.is_some() {
        return;
    }
    while let Some(r) = select(proc, None, None) {
        let tid = match proc.wq.idle.first().copied() {
            Some(t) => {
                proc.wq.idle.remove(0);
                t
            }
            None => match create_thread(proc) {
                Some(t) => t,
                None => break,
            },
        };
        run_request(proc, tid, r);
        let new = proc.wq.threads.get(&tid).is_some_and(|w| w.new);
        if let Some(w) = proc.wq.threads.get_mut(&tid) {
            w.new = false;
            w.pending = Some(if new {
                setup::FIRST_USE
            } else {
                setup::CLEAR_VOUCHER
            });
        }
        if let Some(t) = proc.threads.get_mut(&tid) {
            t.wait = None;
            t.woken = true;
        }
    }
}

/// The unpark continuation of a bound thread (`workq_unpark_continue` →
/// `workq_setup_and_run`), in its own context before it runs.
pub fn run_pending(proc: &mut Proc, thread: &mut Thread) {
    let Some(flags) = proc
        .wq
        .threads
        .get_mut(&thread.tid)
        .and_then(|w| w.pending.take())
    else {
        return;
    };
    let mut ctx = Ctx {
        proc,
        thread,
        nr: 0,
        pc: 0,
    };
    setup_and_run(&mut ctx, flags);
}

/// `workq_setup_and_run`.
fn setup_and_run(ctx: &mut Ctx<'_>, setup_flags: u32) {
    let tid = ctx.thread.tid;
    let Some(w) = ctx.proc.wq.threads.get(&tid).cloned() else {
        return;
    };
    let mut up = w.upcall_flags;
    if setup_flags & setup::FIRST_USE == 0 {
        up |= upcall::REUSE;
    }
    if w.outside_qos {
        up |= upcall::OUTSIDEQOS;
    } else {
        up |= u32::from(w.park_qos) | upcall::PRIO_QOS;
    }
    let mut thport = w.thport;
    if thport == 0 {
        // The immovable, pinned thread port.
        let kport = ctx.thread.kport.clone();
        thport = ctx.proc.insert_send(&kport);
        ctx.thread.port = thport;
        if let Some(w) = ctx.proc.wq.threads.get_mut(&tid) {
            w.thport = thport;
        }
    }
    setup_thread(ctx, w.stackaddr, thport, setup_flags, up);
}

/// A workqueue thread's addresses (`struct workq_thread_addrs`).
#[derive(Clone, Copy, Debug)]
struct Addrs {
    /// The `pthread_t`.
    this: u64,
    /// The stack's lowest usable address.
    bottom: u64,
    /// The initial stack pointer.
    top: u64,
}

/// `workq_thread_get_addrs`.
fn addrs(proc: &Proc, stackaddr: u64) -> Addrs {
    let guard = proc.vm.page;
    let this = stackaddr + DEFAULT_STACKSIZE + guard + pthread_t_offset(proc.abi);
    Addrs {
        this,
        bottom: stackaddr + guard,
        top: this & !15,
    }
}

/// `workq_kevent`: services the thread's kqueue request into its stack —
/// `WQ_KEVENT_LIST_LEN` events below the `pthread_t`, their out-of-line
/// data below those — and lowers the stack top under what was used.
/// Returns the event list and count (none on error).
fn workq_kevent(
    ctx: &mut Ctx<'_>,
    a: &mut Addrs,
    changes: u64,
    nchanges: i32,
    flags: u32,
) -> Result<(u64, i32), Errno> {
    let list = a.this - KEVENT_LIST_LEN * KEVENT_QOS_SIZE;
    let data = list - KEVENT_DATA_SIZE;
    let r = super::kevent::kevent_workq_internal(
        ctx,
        changes,
        nchanges,
        list,
        KEVENT_LIST_LEN as i32,
        data,
        KEVENT_DATA_SIZE,
        flags,
    );
    match r {
        Ok((n, resid)) if n != -1 => {
            a.top = (data + resid) & !15;
            Ok((list, n))
        }
        Ok(_) => Ok((0, 0)),
        Err(e) => Err(e),
    }
}

/// `workq_setup_thread`: points the thread at `_pthread_wqthread` with
/// its arguments.
fn setup_thread(ctx: &mut Ctx<'_>, stackaddr: u64, thport: u32, setup_flags: u32, up: u32) {
    let mut up = up;
    let mut a = addrs(ctx.proc, stackaddr);
    if setup_flags & setup::FIRST_USE != 0 {
        let tsd = ctx.proc.pthread.tsd_offset;
        if tsd != 0 {
            ctx.thread.cpu.set_tsd_base(a.this + u64::from(tsd));
            up |= upcall::TSD_BASE_SET;
        }
        ctx.thread.pthread = a.this;
    }
    let (mut list, mut count) = (0u64, 0i32);
    if setup_flags & setup::EXIT_THREAD != 0 {
        count = EXIT_THREAD_NKEVENT;
    } else if up & upcall::KEVENT != 0 {
        let flags = super::kevent::kflag::STACK_DATA | super::kevent::kflag::IMMEDIATE;
        // Errors leave no events.
        (list, count) = workq_kevent(ctx, &mut a, 0, 0, flags).unwrap_or((0, 0));
    }
    set_register_state(ctx, &a, thport, list, up, count);
}

/// `workq_set_register_state`.
fn set_register_state(ctx: &mut Ctx<'_>, a: &Addrs, kport: u32, list: u64, up: u32, count: i32) {
    let start = ctx.proc.pthread.wqthread_start;
    let args = [
        a.this,
        u64::from(kport),
        a.bottom,
        list,
        u64::from(up),
        count as i64 as u64,
    ];
    set_start_state(&mut ctx.thread.cpu, start, a.top, &args);
}

/// `workq_open`.
pub fn workq_open(ctx: &mut Ctx<'_>) -> SysResult {
    if !ctx.proc.pthread.registered {
        return Err(Errno::EINVAL);
    }
    ctx.proc.wq.opened = true;
    Ok(Rv::one(0))
}

/// `workq_kernreturn(options, item, affinity, prio)`.
pub fn workq_kernreturn(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let (options, item, arg2, arg3) = (a[0] as i32, a[1], a[2] as i32, a[3] as i32);
    if !ctx.proc.pthread.registered {
        return Err(Errno::EINVAL);
    }
    match options {
        wqops::QUEUE_NEWSPISUPP => {
            ctx.proc.wq.serialno_offset = arg2 as u64;
            Ok(Rv::one(0))
        }
        wqops::QUEUE_REQTHREADS => reqthreads(ctx, arg2, arg3 as u32, false),
        wqops::QUEUE_REQTHREADS2 => reqthreads(ctx, arg2, arg3 as u32, true),
        wqops::SET_EVENT_MANAGER_PRIORITY => {
            if !ctx.proc.wq.opened {
                return Err(Errno::EINVAL);
            }
            let mut pri = arg2 as u32;
            if priority::has_sched_pri(pri) {
                pri &= priority::SCHED_PRI_MASK | priority::SCHED_PRI_FLAG;
            } else {
                let qos = priority::thread_qos(pri);
                let r = priority::relpri(pri);
                if r > 0 || r < priority::MIN_TIER_IMPORTANCE || qos == 0 {
                    return Err(Errno::EINVAL);
                }
                pri &= !priority::FLAGS_MASK;
            }
            if ctx.proc.wq.manager_priority < pri {
                ctx.proc.wq.manager_priority = pri;
            }
            Ok(Rv::one(0))
        }
        wqops::THREAD_RETURN | wqops::THREAD_KEVENT_RETURN | wqops::THREAD_WORKLOOP_RETURN => {
            thread_return(ctx, item, arg2)
        }
        wqops::SHOULD_NARROW => {
            let tid = ctx.thread.tid;
            let s = match ctx.proc.wq.threads.get(&tid) {
                Some(w) if ctx.thread.mach.tag & tag::WORKQUEUE != 0 => w.sched,
                _ => return Err(Errno::EINVAL),
            };
            if s.is_some_and(|s| s.pool == Pool::Overcommit) {
                return Err(Errno::EINVAL);
            }
            let qos = priority::thread_qos(arg2 as u32);
            if qos == 0 {
                return Err(Errno::EINVAL);
            }
            let narrow = constrained_allowance(ctx.proc, qos, Some(tid), Some(tid)) == 0;
            Ok(Rv::one(u64::from(narrow)))
        }
        wqops::SETUP_DISPATCH => {
            // struct workq_dispatch_config: version, flags, serialno
            // offset, label offset (24 bytes).
            let mut cfg = [0u8; 24];
            let n = (arg2 as u32 as usize).min(24);
            cfg[..n].copy_from_slice(&ctx.read(item, n)?);
            let u32_at = |o: usize| u32::from_le_bytes(cfg[o..o + 4].try_into().expect("4"));
            let u64_at = |o: usize| u64::from_le_bytes(cfg[o..o + 8].try_into().expect("8"));
            let (version, flags) = (u32_at(0), u32_at(4));
            if flags & !DISPATCH_SUPPORTED_FLAGS != 0 || version < DISPATCH_MIN_SUPPORTED_VERSION {
                return Err(Errno::ENOTSUP);
            }
            ctx.proc.wq.serialno_offset = u64_at(8);
            if version >= 2 {
                ctx.proc.wq.label_offset = u64_at(16);
            }
            Ok(Rv::one(0))
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `workq_reqthreads`: queues a request for `count` threads at the
/// priority `pp`.
fn reqthreads(ctx: &mut Ctx<'_>, count: i32, pp: u32, cooperative: bool) -> SysResult {
    let qos = priority::thread_qos(pp);
    if !ctx.proc.wq.opened || count <= 0 || count > i32::from(u16::MAX) || qos == 0 {
        return Err(Errno::EINVAL);
    }
    let mut flags = 0;
    if priority::is_overcommit(pp) {
        flags |= trflag::OVERCOMMIT;
    }
    if cooperative {
        flags |= trflag::COOPERATIVE;
        if count > 1 {
            return Err(Errno::ENOTSUP);
        }
    }
    if is_cooperative(flags) && is_overcommit(flags) {
        return Err(Errno::EINVAL);
    }
    let wq = &mut ctx.proc.wq;
    wq.next_anon += 1;
    let id = wq.next_anon;
    wq.anon.push(Anon {
        id,
        qos,
        flags,
        count: count as u16,
    });
    // The scheduler binds threads to it between slices (`redrive`).
    wq.queue.push(ReqRef::Anon(id));
    Ok(Rv::one(0))
}

/// `workq_thread_return`: a workqueue thread is done with its request.
/// A kqueue servicer first hands its kqueue the pending changes and
/// takes any events that came in meanwhile; otherwise the thread takes
/// the next request it may run, or parks.
fn thread_return(ctx: &mut Ctx<'_>, eventlist: u64, nevents: i32) -> SysResult {
    let tid = ctx.thread.tid;
    let Some(w) = ctx.proc.wq.threads.get(&tid).cloned() else {
        return Err(Errno::EINVAL);
    };
    if ctx.thread.mach.tag & tag::WORKQUEUE == 0 {
        return Err(Errno::EINVAL);
    }
    if eventlist != 0 && nevents != 0 && w.bound.is_none() {
        return Err(Errno::EINVAL);
    }
    // Reset the signal mask, keeping the signals the process preserves.
    let allow = ctx.proc.wq.allow_sigmask;
    ctx.thread.sig.mask |= !WORKQ_THREADMASK & !allow;
    if let Some(r) = w.bound {
        let mut up = upcall::NEWSPI | upcall::REUSE | upcall::KEVENT;
        if super::kevent::workq::is_workloop(ctx.proc, r) {
            up |= upcall::WORKLOOP;
        }
        match w.sched {
            Some(s) if s.qos_bucket == QOS_MANAGER => up |= upcall::EVENT_MANAGER,
            s => {
                if s.is_some_and(|s| s.pool == Pool::Overcommit) {
                    up |= upcall::OVERCOMMIT;
                }
                if w.outside_qos {
                    up |= upcall::OUTSIDEQOS;
                } else {
                    up |= u32::from(s.map_or(0, |s| s.qos_req)) | upcall::PRIO_QOS;
                }
            }
        }
        // workq_handle_stack_events.
        let mut a = addrs(ctx.proc, w.stackaddr);
        let flags = super::kevent::kflag::STACK_DATA
            | super::kevent::kflag::IMMEDIATE
            | super::kevent::kflag::PARKING;
        let (list, count) = workq_kevent(ctx, &mut a, eventlist, nevents, flags)?;
        if count != 0 {
            set_register_state(ctx, &a, w.thport, list, up, count);
            return Err(Errno::EJUSTRETURN);
        }
        // No events: the request was unbound.
    }
    select_or_park(ctx);
    Err(Errno::EJUSTRETURN)
}

/// `workq_select_threadreq_or_park_and_unlock` for the calling thread.
fn select_or_park(ctx: &mut Ctx<'_>) {
    let tid = ctx.thread.tid;
    if let Some(r) = select(ctx.proc, Some(tid), Some(tid)) {
        run_request(ctx.proc, tid, r);
        setup_and_run(ctx, setup::CLEAR_VOUCHER);
        return;
    }
    // workq_park_and_unlock.
    if let Some(w) = ctx.proc.wq.threads.get_mut(&tid) {
        w.sched = None;
        w.bound = None;
    }
    ctx.proc.wq.idle.insert(0, tid);
    ctx.thread.wait = Some(park_wait(tid));
}

/// A workqueue thread ended (`workq_thread_terminate`): it leaves the
/// pool.
pub fn thread_terminated(proc: &mut Proc, tid: u64) {
    if let Some(w) = proc.wq.threads.remove(&tid) {
        if let Some(r) = w.bound {
            super::kevent::workq::threadreq_unbind(proc, r, tid);
        }
        proc.wq.idle.retain(|&t| t != tid);
    }
}

/// Whether `tid` is a workqueue thread `pthread_kill` may not signal:
/// neither it (`BSDTHREAD_CTL_WORKQ_ALLOW_KILL`) nor the process
/// (`BSDTHREAD_CTL_WORKQ_ALLOW_SIGMASK`) allowed it.
pub fn kill_denied(proc: &Proc, tid: u64) -> bool {
    proc.wq.allow_sigmask == 0 && proc.wq.threads.get(&tid).is_some_and(|w| !w.kill_allowed)
}

#[cfg(test)]
mod tests;
