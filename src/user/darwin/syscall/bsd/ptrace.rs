//! Process tracing (`bsd/kern/mach_process.c`, XNU 12377.121.6).
//!
//! Parent-child tracing uses private guest-process connections. Attachment
//! and remote task/thread operations cover limited observed policy cases;
//! remote rights and authorization remain incomplete.

#[cfg(unix)]
mod incoming;
#[cfg(unix)]
mod job_control;
#[cfg(unix)]
mod pump;
#[cfg(unix)]
pub(crate) use pump::pump;
#[cfg(unix)]
mod protocol;
#[cfg(unix)]
mod remote_mach;
#[cfg(unix)]
mod sigwait;
#[cfg(unix)]
pub(crate) use remote_mach::callback_inherit::InheritedHandlers;
#[cfg(unix)]
pub(crate) use remote_mach::callback_runtime::{
    callback_port_died, deliver_callback, release_callback_reply,
};
#[cfg(unix)]
pub(crate) use sigwait::{
    end_sigwait, enter_signal_ast, needs_signal_ast, resume_before_verdict, signal_wait_blocked,
    signal_waiting, thread_suspended,
};

#[cfg(not(unix))]
pub(crate) fn signal_waiting(_: &State, _: u64) -> bool {
    false
}
#[cfg(unix)]
mod channels;
#[cfg(all(unix, test))]
mod job_tests;
#[cfg(unix)]
mod lifecycle;
#[cfg(unix)]
mod lifecycle_rpc;
#[cfg(unix)]
mod observation;
#[cfg(unix)]
mod peers;
#[cfg(unix)]
mod reap;
#[cfg(unix)]
mod registered_pump;
#[cfg(unix)]
mod registry;
#[cfg(all(unix, test))]
mod sigwait_tests;
#[cfg(unix)]
mod trace_control;
#[cfg(unix)]
mod transport;
#[cfg(unix)]
pub(crate) use job_control::{
    consume_continue, consume_stop, continue_job, duplicate_host_stop, flush_exit_output,
    is_signal_peer, is_traced_child, job_stopped, note_host_stop, peek_continue, peek_stop,
    send_traced_signal, stop_job, wait_continue, wait_stop,
};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::process::ExitStatus;
#[cfg(unix)]
use crate::user::darwin::process::{Proc, Thread};
use crate::user::darwin::signal::{self, Origin, SIGSEGV};
use crate::user::darwin::syscall::Ctx;
#[cfg(unix)]
use crate::user::darwin::wait::{Wait, WaitKey};

const PT_TRACE_ME: i32 = 0;
#[cfg(unix)]
const PT_CONTINUE: i32 = 7;
#[cfg(unix)]
const PT_KILL: i32 = 8;
#[cfg(unix)]
const PT_STEP: i32 = 9;
#[cfg(unix)]
const PT_DETACH: i32 = 11;
const PT_ATTACH: i32 = 10;
const PT_SIGEXC: i32 = 12;
const PT_ATTACHEXC: i32 = 14;
#[cfg(unix)]
const PT_THUPDATE: i32 = 13;
const PT_FORCEQUOTA: i32 = 30;
const PT_DENY_ATTACH: i32 = 31;

/// The trace relationship and per-process ptrace flags.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub tracer: Option<i32>,
    #[cfg(unix)]
    tracer_route: Option<channels::ServerRoute>,
    #[cfg(unix)]
    registered_exit: lifecycle::Target,
    #[cfg(unix)]
    reaps: reap::State,
    original_parent: Option<i32>,
    xstatus: Option<i32>,
    pub deny_attach: bool,
    pub signal_exceptions: bool,
    pub force_quota: bool,
    #[cfg(unix)]
    stopped: Option<TraceStop>,
    /// The active kern_sig.c wait, independent of retained stop metadata.
    #[cfg(unix)]
    sigwait: Option<sigwait::SignalWait>,
    #[cfg(unix)]
    sigwaiters: std::collections::BTreeSet<u64>,
    #[cfg(unix)]
    job_stopped: Option<TraceStop>,
    #[cfg(unix)]
    native_host_stop: bool,
    #[cfg(unix)]
    host_parking: bool,
    #[cfg(unix)]
    attached_job_stop: bool,
    /// PT_THUPDATE's p_xstat while p_stat is SRUN and the task is suspended.
    #[cfg(unix)]
    trace_update: Option<i32>,
    #[cfg(unix)]
    reserved_update: Option<ReservedUpdate>,
    #[cfg(unix)]
    verdict: Option<Verdict>,
    #[cfg(unix)]
    soft_override: Option<Verdict>,
    #[cfg(unix)]
    pending_kill: bool,
    /// Finish a fatal tracing request only after its reply leaves the link.
    #[cfg(unix)]
    exit_after_reply: Option<ExitStatus>,
    /// Essential tracing output has not yet left the parent connection.
    #[cfg(unix)]
    output_barrier: bool,
    #[cfg(unix)]
    stepping: Option<u64>,
    #[cfg(unix)]
    pending: std::collections::BTreeMap<u64, PendingCall>,
    #[cfg(unix)]
    next_request: u64,
    /// Connections to the parent and children are independent of tracing
    /// flags: an untraced process can be attached later.
    #[cfg(unix)]
    family: Family,
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct Family {
    parent: Option<transport::Link>,
    parent_pid: Option<i32>,
    parent_status: Option<std::sync::Arc<SharedStatus>>,
    children: std::collections::BTreeMap<i32, Child>,
    mach: remote_mach::State,
    peers: peers::State,
}

#[cfg(unix)]
#[derive(Debug)]
struct Child {
    /// Process which owns this link's ptrace requests, distinct from p_oppid.
    owner_pid: i32,
    /// Present for a separately registered target, rather than a host child.
    registry_instance: Option<[u8; 16]>,
    registry_epoch: u64,
    registry_codesign: Option<u32>,
    registered_exit: Option<lifecycle::Report>,
    link: Option<transport::Link>,
    traced: bool,
    original_parent: Option<i32>,
    stop: Option<ChildStop>,
    /// The new attach SIGSTOP may replace retained job-stop metadata.
    attach_stop_pending: bool,
    continued: bool,
    job_stop_requested: bool,
    host_stopped: bool,
    shared_status: Option<std::sync::Arc<SharedStatus>>,
    /// An observed successful attach or trace-me relationship. This does
    /// not represent taskgated authorization in the general case.
    mach_attached: bool,
}

#[cfg(unix)]
impl Child {
    fn new(link: transport::Link, owner_pid: i32) -> Self {
        Self {
            owner_pid,
            registry_instance: None,
            registry_epoch: 0,
            registry_codesign: None,
            registered_exit: None,
            link: Some(link),
            traced: false,
            original_parent: None,
            stop: None,
            attach_stop_pending: false,
            continued: false,
            job_stop_requested: false,
            host_stopped: false,
            shared_status: None,
            mach_attached: false,
        }
    }

    fn waitable(&self) -> bool {
        self.shared_status.as_ref().is_none_or(|shared| {
            let parent = shared.snapshot().2;
            parent == 0 || parent == self.owner_pid
        })
    }

    fn is_traced(&self) -> bool {
        self.shared_status.as_ref().map_or(self.traced, |shared| {
            let (tracer, _) = shared.trace_owner();
            tracer == Some(self.owner_pid)
        })
    }
}

/// Process status shared by the two host processes created at fork. It is
/// independent of the tracing stream and remains readable until reaping.
#[cfg(unix)]
#[repr(C)]
#[derive(Debug)]
struct SharedWords {
    exit: std::sync::atomic::AtomicI32,
    // Bits 0..30: current parent PID; bit 31: traced; bits 32..63: p_oppid.
    trace: std::sync::atomic::AtomicU64,
    // Bit 63 marks a guest zombie; low 16 bits hold its wait status.
    guest_exit: std::sync::atomic::AtomicU64,
    // Bit 63 marks a known status, bit 32 a stop, and bits 0..31 p_xstat.
    signal: std::sync::atomic::AtomicU64,
    // Bit 63 marks known guest code-signing flags in bits 0..31.
    codesign: std::sync::atomic::AtomicU64,
    // Parent real and effective UIDs, published as one atomic pair.
    parent_creds: std::sync::atomic::AtomicU64,
    parent_creds_known: std::sync::atomic::AtomicBool,
    // Target real and effective UIDs captured at a trace stop.
    target_creds: std::sync::atomic::AtomicU64,
    target_creds_known: std::sync::atomic::AtomicBool,
    // Zero means the image identity counter is exhausted.
    image_epoch: std::sync::atomic::AtomicU64,
}

#[cfg(unix)]
#[derive(Debug)]
struct SharedStatus(std::ptr::NonNull<SharedWords>);

// SAFETY: the mapping remains live for the lifetime of each owning Arc and
// the only shared access is through atomics. After fork each process owns
// its own virtual mapping and its own copy of the Arc's reference count.
#[cfg(unix)]
unsafe impl Send for SharedStatus {}
#[cfg(unix)]
unsafe impl Sync for SharedStatus {}

#[cfg(unix)]
impl SharedStatus {
    fn new() -> std::io::Result<Self> {
        use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64};
        let len = std::mem::size_of::<SharedWords>();
        // SAFETY: anonymous shared memory needs no descriptor or offset;
        // the returned mapping is checked before it is accessed.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let Some(ptr) = std::ptr::NonNull::new(raw.cast::<SharedWords>()) else {
            // SAFETY: raw is a successful mapping of len bytes.
            unsafe { libc::munmap(raw, len) };
            return Err(std::io::Error::other("null shared status mapping"));
        };
        // SAFETY: mmap returns suitably aligned, writable storage of len
        // bytes and no other process can access it before the host fork.
        unsafe {
            ptr.as_ptr().write(SharedWords {
                exit: AtomicI32::new(0),
                trace: AtomicU64::new(0),
                guest_exit: AtomicU64::new(0),
                signal: AtomicU64::new(0),
                codesign: AtomicU64::new(0),
                parent_creds: AtomicU64::new(0),
                parent_creds_known: AtomicBool::new(false),
                target_creds: AtomicU64::new(0),
                target_creds_known: AtomicBool::new(false),
                image_epoch: AtomicU64::new(1),
            })
        };
        Ok(Self(ptr))
    }

    fn store(&self, status: i32) {
        // SAFETY: self owns a live initialized mapping.
        unsafe { self.0.as_ref() }
            .exit
            .store(status, std::sync::atomic::Ordering::Release);
    }

    fn load(&self) -> i32 {
        // SAFETY: self owns a live initialized mapping.
        unsafe { self.0.as_ref() }
            .exit
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn set_trace(&self, original_parent: i32, traced: bool) {
        self.set_tracer(original_parent, traced.then_some(original_parent));
    }

    /// Publish owner and p_oppid in one atomic snapshot. The original parent
    /// may observe an external tracer without gaining that tracer's controls.
    fn set_tracer(&self, original_parent: i32, tracer: Option<i32>) {
        self.set_parent(
            original_parent,
            tracer.unwrap_or(original_parent),
            tracer.is_some(),
        );
    }

    fn set_parent(&self, original_parent: i32, parent: i32, traced: bool) {
        debug_assert!(parent >= 0);
        let value = (u64::from(original_parent as u32) << 32)
            | (u64::from(traced) << 31)
            | u64::from(parent as u32 & 0x7fff_ffff);
        // SAFETY: self owns a live initialized mapping.
        unsafe { self.0.as_ref() }
            .trace
            .store(value, std::sync::atomic::Ordering::Release);
    }

    fn initialize_parent(&self, parent: i32) {
        // The child may already have published PT_TRACE_ME, an attach, or
        // its exit before the parent completes the host fork handoff.
        // SAFETY: self owns a live initialized mapping.
        let _ = unsafe { self.0.as_ref() }.trace.compare_exchange(
            0,
            u64::from(parent as u32 & 0x7fff_ffff),
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
    }

    fn snapshot(&self) -> (bool, i32, i32) {
        // SAFETY: self owns a live initialized mapping.
        let value = unsafe { self.0.as_ref() }
            .trace
            .load(std::sync::atomic::Ordering::Acquire);
        (
            value & (1 << 31) != 0,
            (value >> 32) as u32 as i32,
            (value as u32 & 0x7fff_ffff) as i32,
        )
    }

    fn trace(&self) -> (bool, i32) {
        let (traced, original, _) = self.snapshot();
        (traced, original)
    }

    fn trace_owner(&self) -> (Option<i32>, i32) {
        let (traced, original, parent) = self.snapshot();
        (traced.then_some(parent), original)
    }

    fn clear_traced(&self) {
        // Preserve current parent and p_oppid while the guest is a zombie.
        // SAFETY: self owns a live initialized mapping.
        unsafe { self.0.as_ref() }
            .trace
            .fetch_and(!(1u64 << 31), std::sync::atomic::Ordering::AcqRel);
    }

    fn set_guest_exit(&self, status: i32) {
        // SAFETY: self owns a live initialized mapping.
        unsafe { self.0.as_ref() }.guest_exit.store(
            (1 << 63) | status as u64,
            std::sync::atomic::Ordering::Release,
        );
    }

    fn guest_exit(&self) -> Option<i32> {
        // SAFETY: self owns a live initialized mapping.
        let value = unsafe { self.0.as_ref() }
            .guest_exit
            .load(std::sync::atomic::Ordering::Acquire);
        (value >> 63 != 0).then_some((value & 0xffff) as i32)
    }

    fn set_signal(&self, stopped: bool, status: i32) {
        let value = (1u64 << 63) | (u64::from(stopped) << 32) | u64::from(status as u32);
        // SAFETY: self owns a live initialized mapping.
        unsafe { self.0.as_ref() }
            .signal
            .store(value, std::sync::atomic::Ordering::Release);
    }

    fn signal(&self) -> Option<(bool, i32)> {
        // SAFETY: self owns a live initialized mapping.
        let value = unsafe { self.0.as_ref() }
            .signal
            .load(std::sync::atomic::Ordering::Acquire);
        (value & (1u64 << 63) != 0).then_some((value & (1u64 << 32) != 0, value as u32 as i32))
    }

    fn set_codesign(&self, flags: Option<u32>) {
        let value = flags.map_or(0, |flags| (1u64 << 63) | u64::from(flags));
        // SAFETY: self owns a live initialized mapping.
        unsafe { self.0.as_ref() }
            .codesign
            .store(value, std::sync::atomic::Ordering::Release);
    }

    fn codesign(&self) -> Option<u32> {
        // SAFETY: self owns a live initialized mapping.
        let value = unsafe { self.0.as_ref() }
            .codesign
            .load(std::sync::atomic::Ordering::Acquire);
        (value & (1u64 << 63) != 0).then_some(value as u32)
    }

    fn set_parent_credentials(&self, (ruid, euid): (u32, u32)) {
        // SAFETY: self owns a live initialized mapping.
        let words = unsafe { self.0.as_ref() };
        words.parent_creds.store(
            (u64::from(ruid) << 32) | u64::from(euid),
            std::sync::atomic::Ordering::Release,
        );
        words
            .parent_creds_known
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn parent_credentials(&self) -> Option<(u32, u32)> {
        // SAFETY: self owns a live initialized mapping.
        let words = unsafe { self.0.as_ref() };
        if !words
            .parent_creds_known
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
        let value = words
            .parent_creds
            .load(std::sync::atomic::Ordering::Acquire);
        Some(((value >> 32) as u32, value as u32))
    }

    fn set_target_credentials(&self, (ruid, euid): (u32, u32)) {
        // SAFETY: self owns a live initialized mapping.
        let words = unsafe { self.0.as_ref() };
        words.target_creds.store(
            (u64::from(ruid) << 32) | u64::from(euid),
            std::sync::atomic::Ordering::Release,
        );
        words
            .target_creds_known
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn target_credentials(&self) -> Option<(u32, u32)> {
        // SAFETY: self owns a live initialized mapping.
        let words = unsafe { self.0.as_ref() };
        if !words
            .target_creds_known
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
        let value = words
            .target_creds
            .load(std::sync::atomic::Ordering::Acquire);
        Some(((value >> 32) as u32, value as u32))
    }

    fn image_epoch(&self) -> u64 {
        // SAFETY: self owns a live initialized mapping.
        unsafe { self.0.as_ref() }
            .image_epoch
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn advance_image_epoch(&self) {
        // SAFETY: self owns a live initialized mapping. Zero is a permanent
        // fail-closed marker if the counter exhausts.
        let epoch = &unsafe { self.0.as_ref() }.image_epoch;
        let _ = epoch.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |value| {
                Some(if value == 0 {
                    0
                } else {
                    value.checked_add(1).unwrap_or(0)
                })
            },
        );
    }
}

#[cfg(unix)]
impl Drop for SharedStatus {
    fn drop(&mut self) {
        // SAFETY: this process's last owner releases its live mapping.
        unsafe {
            libc::munmap(self.0.as_ptr().cast(), std::mem::size_of::<SharedWords>());
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct TraceStop {
    thread: u64,
    signal: i32,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct ReservedUpdate {
    id: u64,
    signal: i32,
    stop: TraceStop,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct ChildStop {
    thread: u64,
    signal: i32,
    waited: bool,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct Verdict {
    thread: u64,
    signal: i32,
    original: i32,
}

#[cfg(unix)]
#[derive(Debug)]
struct PendingCall {
    id: u64,
    pid: i32,
    errno: Option<i32>,
    kind: CallKind,
    resume_effect: bool,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallKind {
    Attach,
    Resume {
        detach: bool,
    },
    ThreadUpdate {
        thread: u64,
        remote_instance: Option<u64>,
        signal: i32,
        phase: UpdatePhase,
    },
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdatePhase {
    Preparing,
    Prepared,
    Committing,
}

impl State {
    /// Publishes this process's credentials to its connected children.
    #[cfg(unix)]
    pub(crate) fn update_children_parent_credentials(&self, creds: (u32, u32)) {
        for child in self.family.children.values() {
            if let Some(shared) = &child.shared_status {
                shared.set_parent_credentials(creds);
            }
        }
    }

    /// `proc_exec_switch_task` transfers the local tracing flags. The new
    /// proc's `p_flag` is created by `forkproc`, whose inherited flag mask
    /// does not contain `P_FORCEQUOTA`.
    pub(crate) fn for_exec(&self) -> Self {
        Self {
            tracer: self.tracer,
            #[cfg(unix)]
            tracer_route: self.tracer_route,
            #[cfg(unix)]
            registered_exit: Default::default(),
            #[cfg(unix)]
            reaps: Default::default(),
            original_parent: self.original_parent,
            xstatus: None,
            deny_attach: self.deny_attach,
            signal_exceptions: self.signal_exceptions,
            force_quota: false,
            #[cfg(unix)]
            stopped: None,
            #[cfg(unix)]
            sigwait: None,
            #[cfg(unix)]
            sigwaiters: Default::default(),
            #[cfg(unix)]
            job_stopped: None,
            #[cfg(unix)]
            native_host_stop: false,
            #[cfg(unix)]
            host_parking: false,
            #[cfg(unix)]
            attached_job_stop: false,
            #[cfg(unix)]
            trace_update: None,
            #[cfg(unix)]
            reserved_update: None,
            #[cfg(unix)]
            verdict: None,
            #[cfg(unix)]
            soft_override: None,
            #[cfg(unix)]
            pending_kill: false,
            #[cfg(unix)]
            exit_after_reply: None,
            #[cfg(unix)]
            output_barrier: false,
            #[cfg(unix)]
            stepping: None,
            #[cfg(unix)]
            pending: Default::default(),
            #[cfg(unix)]
            next_request: self.next_request,
            #[cfg(unix)]
            family: Family::default(),
        }
    }

    /// An exec replaces the image in the same process; its live tracing
    /// connections must move exactly once, not be duplicated or dropped.
    #[cfg(unix)]
    pub(crate) fn take_connections(&mut self, old: &mut Self) {
        self.family = std::mem::take(&mut old.family);
        self.output_barrier = std::mem::take(&mut old.output_barrier);
        if let Some(shared) = &self.family.parent_status {
            shared.set_signal(false, 0);
            shared.set_codesign(None);
        }
    }
}

/// Endpoints prepared before a host fork, with one retained by each side.
#[cfg(unix)]
pub(crate) struct ForkPair {
    parent: transport::Link,
    child: transport::Link,
    shared: std::sync::Arc<SharedStatus>,
}

#[cfg(unix)]
impl ForkPair {
    pub(crate) fn prepare() -> Result<Self, Errno> {
        let (parent, child) = transport::Link::pair().map_err(|e| Errno::from_io(&e))?;
        let shared = std::sync::Arc::new(SharedStatus::new().map_err(|e| Errno::from_io(&e))?);
        Ok(Self {
            parent,
            child,
            shared,
        })
    }

    /// Sets the parent's credentials before either endpoint is handed off.
    pub(crate) fn set_parent_credentials(&self, creds: (u32, u32)) {
        self.shared.set_parent_credentials(creds);
    }

    pub(crate) fn parent(self, state: &mut State, child: i32, parent: i32) {
        drop(self.child);
        let mut entry = Child::new(self.parent, parent);
        self.shared.initialize_parent(parent);
        entry.shared_status = Some(self.shared);
        state.family.children.insert(child, entry);
    }

    pub(crate) fn child(self, state: &mut State, parent: i32) {
        drop(self.parent);
        state.family.parent = Some(self.child);
        state.family.parent_pid = Some(parent);
        state.family.parent_status = Some(self.shared);
    }
}

/// Releases the parent's connection once the child has been reaped.
#[cfg(unix)]
pub(crate) fn child_reaped(state: &mut State, pid: i32) {
    state.family.children.remove(&pid);
}

/// Publishes the guest's exit state before the host process exits.
#[cfg(unix)]
pub(crate) fn record_exit(state: &State, status: &ExitStatus) {
    if let Some(shared) = &state.family.parent_status {
        shared.set_guest_exit(lifecycle::wait_status(status));
        shared.clear_traced();
        if let ExitStatus::Signaled { signo, .. } = status {
            shared.store(*signo & 0x7f);
        }
    }
}

/// Substitutes a guest signal-death status only when the host had to fall
/// back to the corresponding `128 + signal` exit code.
#[cfg(unix)]
pub(crate) fn exit_status(state: &State, pid: i32, host_status: i32) -> i32 {
    let Some(status) = state
        .family
        .children
        .get(&pid)
        .and_then(|child| child.shared_status.as_ref())
        .map(|status| status.load())
        .filter(|status| (1..signal::NSIG).contains(status))
    else {
        return host_status;
    };
    if host_status & 0xff == 0 && (host_status >> 8) & 0xff == (128 + status) & 0xff {
        status
    } else {
        host_status
    }
}

#[cfg(unix)]
fn set_signal_status(state: &mut State, stopped: bool, status: i32) {
    state.xstatus = Some(status);
    if let Some(shared) = &state.family.parent_status {
        shared.set_signal(stopped, status);
    }
}

#[cfg(unix)]
fn commit_update(
    proc: &mut Proc,
    running: Option<&mut Thread>,
    id: u64,
    remote: Option<(u64, u64)>,
) -> i32 {
    commit_update_on(proc, running, channels::ServerRoute::Parent, id, remote)
}

#[cfg(unix)]
fn commit_update_on(
    proc: &mut Proc,
    running: Option<&mut Thread>,
    route: channels::ServerRoute,
    id: u64,
    remote: Option<(u64, u64)>,
) -> i32 {
    let Some(reserved) = proc
        .tracing
        .reserved_update
        .filter(|update| update.id == id)
    else {
        return Errno::EBUSY.0;
    };
    proc.tracing.reserved_update = None;
    let same_stop = proc.tracing.stopped.is_some_and(|stop| {
        stop.thread == reserved.stop.thread && stop.signal == reserved.stop.signal
    });
    if proc.tracing.tracer != Some(proc.ppid) || !same_stop || proc.tracing.trace_update.is_some() {
        return Errno::EBUSY.0;
    }
    if let Some((instance, tid)) = remote {
        if !remote_mach::target::has_thread_export(proc, route, instance, tid) {
            return Errno::ESRCH.0;
        }
        let target = running
            .filter(|thread| thread.tid == tid && !thread.exited)
            .or_else(|| proc.threads.get_mut(&tid).filter(|thread| !thread.exited));
        let Some(target) = target else {
            return Errno::ESRCH.0;
        };
        if reserved.signal != 0 {
            target.sig.pending |= signal::bit(reserved.signal);
        }
    }
    proc.tracing.attached_job_stop = false;
    if proc.tracing.signal_exceptions {
        let stop = proc.tracing.stopped.take().expect("validated stop");
        let in_exception = proc.threads.get(&stop.thread).is_some_and(|thread| {
            thread.mach.exception.as_ref().is_some_and(|exception| {
                exception.raised.exception == signal::exc::SOFTWARE
                    && exception.raised.codes[0] == 0x10003
            })
        });
        if in_exception {
            proc.tracing.soft_override = Some(Verdict {
                thread: stop.thread,
                original: stop.signal,
                signal: reserved.signal,
            });
        }
    } else {
        // XNU sets p_xstat and SRUN without waking sigwait or releasing
        // the task suspension in this request.
        proc.tracing.trace_update = Some(reserved.signal);
    }
    set_signal_status(&mut proc.tracing, false, reserved.signal);
    0
}

/// Acquires a connected child's task independently of BSD attach state.
#[cfg(unix)]
pub(crate) fn remote_task_for_pid(ctx: &mut Ctx<'_>, pid: i32, output: u64) -> i32 {
    remote_mach::grant::task_for_pid(ctx, pid, output)
}

#[cfg(unix)]
pub(crate) fn remote_pid_for_task(
    proc: &Proc,
    port: &crate::user::darwin::mach::ipc::Port,
) -> Option<i32> {
    remote_mach::pid_for_task(proc, port)
}

#[cfg(unix)]
pub(crate) fn is_remote_mach_port(
    proc: &Proc,
    port: &crate::user::darwin::mach::ipc::Port,
) -> bool {
    remote_mach::is_remote(proc, port)
}

#[cfg(unix)]
pub(crate) fn deliver_remote_mach(
    ctx: &mut Ctx<'_>,
    message: crate::user::darwin::mach::msg::Message,
) {
    remote_mach::deliver(ctx, message);
}

#[cfg(unix)]
pub(crate) fn remote_child_reaped(proc: &mut Proc, pid: i32) {
    remote_mach::peer_died(proc, pid);
}

#[cfg(unix)]
pub(crate) fn remote_last_send(proc: &mut Proc, port: &crate::user::darwin::mach::ipc::Port) {
    remote_mach::local_last_send(proc, port);
}

#[cfg(unix)]
pub(crate) fn remote_thread_died(proc: &mut Proc, tid: u64) {
    remote_mach::local_thread_died(proc, tid);
}

#[cfg(unix)]
pub(crate) fn remote_before_exec(proc: &mut Proc) {
    peers::before_exec(&mut proc.tracing);
    remote_mach::before_exec(proc);
    remote_mach::target_will_exec(proc);
}

#[cfg(unix)]
pub(crate) fn is_remote_resume_port(
    proc: &Proc,
    port: &crate::user::darwin::mach::ipc::Port,
) -> bool {
    remote_mach::token::is_proxy(proc, port)
}

#[cfg(unix)]
pub(crate) fn deliver_resume_port(
    proc: &mut Proc,
    message: crate::user::darwin::mach::msg::Message,
) {
    remote_mach::token::deliver(proc, message);
}

#[cfg(unix)]
pub(crate) fn release_task_token(
    proc: &mut Proc,
    port: &crate::user::darwin::mach::ipc::Port,
) -> bool {
    remote_mach::token::release(proc, port)
}

#[cfg(unix)]
pub(crate) fn wait_fds(state: &State) -> Vec<(i32, bool, bool)> {
    let mut fds = peers::wait_fds(state);
    if let Some(link) = &state.family.parent {
        fds.push((
            link.fd(),
            state.exit_after_reply.is_none()
                && remote_mach::can_receive_request(&state.family.mach),
            link.wants_write() || !remote_mach::output_empty(&state.family.mach),
        ));
    }
    fds.extend(state.family.children.iter().filter_map(|(&pid, child)| {
        child.link.as_ref().map(|link| {
            (
                link.fd(),
                true,
                link.wants_write()
                    || remote_mach::callback_runtime::wants_write(&state.family.mach, pid),
            )
        })
    }));
    fds
}

#[cfg(unix)]
pub(crate) fn connection_deadline(state: &State) -> Option<std::time::Instant> {
    peers::deadline(state)
        .into_iter()
        .chain(reap::deadline(state))
        .min()
}

#[cfg(unix)]
pub(crate) use lifecycle::{consume_exit, exit_wait, has_registered_wait, peek_exit};
#[cfg(unix)]
pub(crate) use observation::{
    foreign_child, host_child_event, known_process_info, reaping_child, sync_codesign,
};
#[cfg(unix)]
pub(crate) use peers::{consume_host_wake, finalize as finalize_registry, poll as poll_discovery};
#[cfg(unix)]
pub(crate) use reap::{begin_reap, pending_reap};

#[cfg(not(unix))]
pub(crate) fn known_process_info(
    state: &State,
    self_pid: i32,
    parent: i32,
    pid: i32,
) -> Option<(bool, i32, Option<i32>, Option<i32>)> {
    (pid == self_pid).then_some((
        state.tracer.is_some(),
        state.original_parent.unwrap_or(0),
        Some(parent),
        None,
    ))
}

/// Tracing state and `p_oppid` known to this guest. The saved parent can
/// survive exit after the traced flag has been cleared.
pub(crate) fn known_trace_info(state: &State, self_pid: i32, pid: i32) -> Option<(bool, i32)> {
    if pid == self_pid {
        return Some((state.tracer.is_some(), state.original_parent.unwrap_or(0)));
    }
    #[cfg(unix)]
    if let Some(child) = state.family.children.get(&pid) {
        return Some(child.shared_status.as_ref().map_or_else(
            || (child.traced, child.original_parent.unwrap_or(0)),
            |shared| shared.trace(),
        ));
    }
    None
}

pub(crate) fn known_trace_status(state: &State, self_pid: i32, pid: i32) -> Option<bool> {
    known_trace_info(state, self_pid, pid).map(|(traced, _)| traced)
}

/// Publishes the process's guest signing flags to its connected parent.
#[cfg(unix)]
pub(crate) fn publish_codesign(state: &State, flags: u32) {
    if let Some(shared) = &state.family.parent_status {
        shared.set_codesign(Some(flags));
    }
}

/// Guest signing flags available for a connected child.
#[cfg(unix)]
pub(crate) fn known_child_codesign(state: &State, pid: i32) -> Option<u32> {
    let child = state.family.children.get(&pid)?;
    child
        .shared_status
        .as_ref()
        .and_then(|shared| shared.codesign())
        .or(child.registry_codesign)
}

/// Trace-related stop state and p_xstat, when they have been observed.
pub(crate) fn known_signal_status(state: &State, self_pid: i32, pid: i32) -> Option<(bool, i32)> {
    if pid == self_pid {
        #[cfg(unix)]
        let stopped = state.job_stopped.is_some()
            || (state.stopped.is_some() && state.trace_update.is_none());
        #[cfg(not(unix))]
        let stopped = false;
        return state.xstatus.map(|status| (stopped, status));
    }
    #[cfg(unix)]
    if let Some(child) = state.family.children.get(&pid) {
        return child
            .shared_status
            .as_ref()
            .and_then(|shared| shared.signal())
            .or_else(|| child.stop.map(|stop| (true, stop.signal)));
    }
    None
}

#[cfg(all(unix, test))]
pub(crate) fn suspended(state: &State) -> bool {
    state.exit_after_reply.is_some()
        || state.job_stopped.is_some()
        || (state.stopped.is_some() && (state.attached_job_stop || !state.signal_exceptions))
}

#[cfg(unix)]
pub(crate) fn is_stopped(state: &State) -> bool {
    state.stopped.is_some() && state.trace_update.is_none()
}

#[cfg(unix)]
pub(crate) fn stop_for_signal(proc: &mut Proc, thread: u64, signal: i32, pc: u64) -> bool {
    if proc.tracing.tracer != Some(proc.ppid) {
        return false;
    }
    if !proc.tracing.signal_exceptions && proc.tracing.sigwait.is_none() {
        // kern_sig.c takes a normal task user hold for a hard sigwait.
        // Capacity exhaustion is an engine bound, before stop mutation.
        if proc
            .task
            .suspension
            .place(crate::user::darwin::mach::suspend::Hold::Normal)
            .is_err()
        {
            proc.exit_with(ExitStatus::Signaled {
                signo: signal::SIGKILL,
                core: false,
                pc,
            });
            return true;
        }
    }
    let hard = !proc.tracing.signal_exceptions;
    sigwait::begin(&mut proc.tracing, thread, hard);
    proc.tracing.stopped = Some(TraceStop { thread, signal });
    proc.tracing.attached_job_stop = false;
    proc.tracing.trace_update = None;
    if let Some(shared) = &proc.tracing.family.parent_status {
        shared.set_target_credentials((proc.creds.0, proc.creds.1));
    }
    set_signal_status(&mut proc.tracing, true, signal);
    let message = protocol::Message::Stop {
        thread,
        signal,
        uid: proc.creds.0,
        notify: !proc.tracing.signal_exceptions,
    };
    let sent = channels::tracer(proc)
        .is_some_and(|route| remote_mach::queue_control_on(proc, route, message.encode()));
    if !sent {
        proc.exit_with(ExitStatus::Signaled {
            signo: signal::SIGKILL,
            core: false,
            pc,
        });
        return true;
    }
    if signal == signal::SIGKILL {
        // issignal_locked delivers an original SIGKILL after the tracer
        // releases the stop, even if p_xstat is changed to zero.
        proc.tracing.pending_kill = true;
    }
    true
}

#[cfg(unix)]
pub(crate) fn take_verdict(state: &mut State, thread: u64) -> Option<(i32, i32)> {
    if state.verdict.is_some_and(|v| v.thread == thread) {
        end_sigwait(state, thread);
        state.verdict.take().map(|v| (v.signal, v.original))
    } else {
        None
    }
}

#[cfg(unix)]
pub(crate) fn bsd_signal_returned(state: &mut State, thread: u64, signal: i32) {
    let override_signal = if state.soft_override.is_some_and(|v| v.thread == thread) {
        state.soft_override.take().map(|v| v.signal)
    } else {
        None
    };
    state.verdict = Some(Verdict {
        thread,
        original: signal,
        signal: if std::mem::take(&mut state.pending_kill) {
            signal::SIGKILL
        } else {
            override_signal.unwrap_or(signal)
        },
    });
}

#[cfg(unix)]
pub(crate) fn has_verdict(state: &State, thread: u64) -> bool {
    state
        .verdict
        .is_some_and(|verdict| verdict.thread == thread)
}

#[cfg(unix)]
pub(crate) fn stepped(state: &mut State, thread: &mut Thread) {
    if state.stepping == Some(thread.tid) {
        state.stepping = None;
    }
}

/// `thread_setsinglestep` changes the architectural debug state of the
/// target thread; arm64 clears MDSCR.SS on the resulting debug exception.
#[cfg(unix)]
pub(crate) fn set_step_state(thread: &mut Thread, enabled: bool) {
    use crate::user::darwin::arch::DarwinCpu;
    match &mut thread.cpu {
        DarwinCpu::X86_64(cpu) => {
            let flags = cpu.vcpu().user_rflags();
            let tf = crate::isa::x86_64::flags::bits::TF;
            cpu.vcpu_mut()
                .set_user_rflags(if enabled { flags | tf } else { flags & !tf });
        }
        DarwinCpu::Arm64(cpu) => {
            if enabled {
                cpu.core_mut().clear_exclusive_monitor();
            }
            crate::user::darwin::thread_status::set_arm_step(&mut thread.mach.debug_state, enabled);
        }
    }
}

/// `ptrace(req, pid, addr, data)` for local flags and connected guest children.
pub fn ptrace(ctx: &mut Ctx<'_>, request: i32, pid: i32, addr: u64, data: i32) -> SysResult {
    #[cfg(unix)]
    let observed_signing = if request == PT_TRACE_ME && channels::trace_me_route(ctx.proc).is_some()
    {
        crate::user::darwin::codesign::prepare_trace_me(ctx.proc)
    } else {
        None
    };
    // The observed MAC policy rejects a restricted process without
    // get-task-allow when its parent has the same non-root credentials.
    #[cfg(unix)]
    let restricted_trace = request == PT_TRACE_ME
        && ctx.proc.creds.1 != 0
        && ctx
            .proc
            .tracing
            .family
            .parent_status
            .as_ref()
            .and_then(|shared| shared.parent_credentials())
            == Some((ctx.proc.creds.0, ctx.proc.creds.1))
        && ctx.proc.codesign.as_ref().is_some_and(|signing| {
            signing.flags & crate::user::darwin::codesign::cs::RESTRICT != 0
                && signing.flags & crate::user::darwin::codesign::cs::GET_TASK_ALLOW == 0
        });
    #[cfg(unix)]
    if matches!(request, PT_ATTACH | PT_ATTACHEXC)
        && pid >= 2
        && pid != ctx.proc.pid
        && !ctx.proc.tracing.family.children.contains_key(&pid)
    {
        peers::ensure(ctx, pid)?;
    }
    #[cfg(unix)]
    let trace_me_route = channels::trace_me_route(ctx.proc);
    let state = &mut ctx.proc.tracing;
    match request {
        PT_DENY_ATTACH => {
            if state.tracer.is_some() {
                ctx.proc.exit_with(ExitStatus::Exited(Errno::ENOTSUP.0));
                ctx.thread.exited = true;
                return Err(Errno::EJUSTRETURN);
            }
            state.deny_attach = true;
            return Ok(Rv::one(0));
        }
        PT_FORCEQUOTA => {
            let effective_uid = ctx.thread.assumed.map_or(ctx.proc.creds.1, |ids| ids.0);
            if effective_uid != 0 {
                return Err(Errno::EPERM);
            }
            state.force_quota = true;
            return Ok(Rv::one(0));
        }
        PT_SIGEXC => {
            if state.tracer.is_none() {
                return Err(Errno::EINVAL);
            }
            state.signal_exceptions = true;
            return Ok(Rv::one(0));
        }
        PT_TRACE_ME => {
            #[cfg(unix)]
            if let Some(route) = trace_me_route {
                if restricted_trace {
                    return Err(Errno::EPERM);
                }
                let shared = state.family.parent_status.clone();
                let previous = shared.as_ref().map(|shared| shared.trace_owner());
                if let Some(shared) = &shared {
                    shared.set_trace(ctx.proc.ppid, true);
                }
                if let Err(error) = job_control::queue_trace_me(ctx.proc) {
                    if let (Some(shared), Some((tracer, parent))) = (&shared, previous) {
                        shared.set_tracer(parent, tracer);
                    }
                    channels::disconnect(ctx.proc, route);
                    return Err(Errno::from_io(&error));
                }
                let state = &mut ctx.proc.tracing;
                state.tracer = Some(ctx.proc.ppid);
                state.original_parent = Some(ctx.proc.ppid);
                state.tracer_route = Some(route);
                route.server_mut(ctx.proc).expect("trace-me route").allowed = true;
                crate::user::darwin::codesign::trace_me_allow_invalid(ctx.proc, observed_signing);
                return Ok(Rv::one(0));
            }
            return Err(Errno::ENOSYS);
        }
        _ => {}
    }

    if pid < 2 {
        return Err(Errno::EPERM);
    }
    if pid == ctx.proc.pid {
        if matches!(request, PT_ATTACH | PT_ATTACHEXC) {
            // cantrace refuses self-attachment first; ptrace still posts
            // SIGSEGV to the caller when the target has P_LNOATTACH.
            if state.deny_attach {
                let origin = Origin::own(ctx.proc);
                signal::psignal(ctx.proc, Some(ctx.thread), SIGSEGV, origin);
            }
            return Err(Errno::EINVAL);
        }
        return Err(if state.tracer.is_none() {
            Errno::EPERM
        } else {
            Errno::EBUSY
        });
    }
    #[cfg(unix)]
    {
        if let Some(call) = state.pending.get(&ctx.thread.tid) {
            if let Some(errno) = call.errno {
                state.pending.remove(&ctx.thread.tid);
                return if errno == 0 {
                    Ok(Rv::one(0))
                } else {
                    Err(Errno(errno))
                };
            }
            return crate::user::darwin::syscall::sleep(
                ctx,
                Wait {
                    keys: vec![WaitKey::Child],
                    interruptible: false,
                    ..Default::default()
                },
            );
        }
        let callbacks_pending = remote_mach::callback_runtime::wants_write(&state.family.mach, pid);
        if let Some(child) = state.family.children.get_mut(&pid) {
            if request == PT_ATTACH || request == PT_ATTACHEXC {
                if callbacks_pending {
                    return Err(Errno::EAGAIN);
                }
                let link = child.link.as_mut().ok_or(Errno::ESRCH)?;
                let id = state.next_request;
                state.next_request = state.next_request.wrapping_add(1);
                let euid = ctx.thread.assumed.map_or(ctx.proc.creds.1, |ids| ids.0);
                link.queue(
                    &protocol::Message::Attach {
                        id,
                        ruid: ctx.proc.creds.0,
                        euid,
                        sigexc: request == PT_ATTACHEXC,
                    }
                    .encode(),
                )
                .map_err(|e| Errno::from_io(&e))?;
                link.flush().map_err(|e| Errno::from_io(&e))?;
                state.pending.insert(
                    ctx.thread.tid,
                    PendingCall {
                        id,
                        pid,
                        errno: None,
                        kind: CallKind::Attach,
                        resume_effect: false,
                    },
                );
                return crate::user::darwin::syscall::sleep(
                    ctx,
                    Wait {
                        keys: vec![WaitKey::Child],
                        interruptible: false,
                        ..Default::default()
                    },
                );
            } else if !child.is_traced() {
                return Err(Errno::EPERM);
            } else if child.stop.is_none() {
                return Err(Errno::EBUSY);
            } else if matches!(request, PT_CONTINUE | PT_KILL | PT_STEP | PT_DETACH) {
                if matches!(request, PT_CONTINUE | PT_STEP) && addr != 1 {
                    return Err(Errno::ENOTSUP);
                }
                if matches!(request, PT_CONTINUE | PT_STEP) && !(0..signal::NSIG).contains(&data) {
                    return Err(Errno::EINVAL);
                }
                if callbacks_pending {
                    return Err(Errno::EAGAIN);
                }
                let link = child.link.as_mut().ok_or(Errno::ESRCH)?;
                let id = state.next_request;
                state.next_request = state.next_request.wrapping_add(1);
                link.queue(
                    &protocol::Message::Resume {
                        id,
                        signal: data,
                        uid: ctx.proc.creds.0,
                        mode: match request {
                            PT_KILL => protocol::ResumeMode::Kill,
                            PT_STEP => protocol::ResumeMode::Step,
                            PT_DETACH => protocol::ResumeMode::Detach,
                            _ => protocol::ResumeMode::Continue,
                        },
                    }
                    .encode(),
                )
                .map_err(|e| Errno::from_io(&e))?;
                link.flush().map_err(|e| Errno::from_io(&e))?;
                state.pending.insert(
                    ctx.thread.tid,
                    PendingCall {
                        id,
                        pid,
                        errno: None,
                        kind: CallKind::Resume {
                            detach: request == PT_DETACH,
                        },
                        resume_effect: false,
                    },
                );
                return crate::user::darwin::syscall::sleep(
                    ctx,
                    Wait {
                        keys: vec![WaitKey::Child],
                        interruptible: false,
                        ..Default::default()
                    },
                );
            } else if request == PT_THUPDATE {
                if !(0..signal::NSIG).contains(&data) {
                    return Err(Errno::EINVAL);
                }
                // `port_name_to_thread` looks up a send right in the
                // caller's IPC space; a nonzero name is not necessarily a
                // live thread right. The kernel truncates addr to a name.
                let target = ctx
                    .proc
                    .ipc
                    .lookup(addr as u32)
                    .ok()
                    .filter(|entry| entry.send > 0)
                    .and_then(|entry| entry.port())
                    .filter(|port| !port.is_dead())
                    .filter(|port| {
                        !remote_mach::is_proxy(&state.family.mach, port)
                            || matches!(port.kobject, crate::user::darwin::mach::ipc::KObject::Thread(tid)
                                if remote_mach::thread_instance(&state.family.mach, port, pid, tid).is_some())
                    })
                    .and_then(|port| match port.kobject {
                        crate::user::darwin::mach::ipc::KObject::Thread(tid) => Some((
                            tid,
                            remote_mach::thread_instance(&state.family.mach, port, pid, tid),
                        )),
                        _ => None,
                    });
                let live = target.is_some_and(|(tid, remote)| {
                    remote.is_some()
                        || (tid == ctx.thread.tid && !ctx.thread.exited)
                        || ctx
                            .proc
                            .threads
                            .get(&tid)
                            .is_some_and(|thread| !thread.exited)
                });
                if !live {
                    return Err(Errno::ESRCH);
                }
                if callbacks_pending {
                    return Err(Errno::EAGAIN);
                }
                let link = child.link.as_mut().ok_or(Errno::ESRCH)?;
                let id = state.next_request;
                state.next_request = state.next_request.wrapping_add(1);
                link.queue(
                    &protocol::Message::Resume {
                        id,
                        signal: data,
                        mode: protocol::ResumeMode::ThreadUpdate,
                        uid: ctx.proc.creds.0,
                    }
                    .encode(),
                )
                .map_err(|e| Errno::from_io(&e))?;
                link.flush().map_err(|e| Errno::from_io(&e))?;
                let (tid, remote_instance) = target.expect("validated live thread");
                state.pending.insert(
                    ctx.thread.tid,
                    PendingCall {
                        id,
                        pid,
                        errno: None,
                        kind: CallKind::ThreadUpdate {
                            thread: tid,
                            remote_instance,
                            signal: data,
                            phase: UpdatePhase::Preparing,
                        },
                        resume_effect: false,
                    },
                );
                return crate::user::darwin::syscall::sleep(
                    ctx,
                    Wait {
                        keys: vec![WaitKey::Child],
                        interruptible: false,
                        ..Default::default()
                    },
                );
            } else if request != PT_ATTACH && request != PT_ATTACHEXC {
                return Err(Errno::EINVAL);
            }
        }
        // SAFETY: signal 0 checks existence and permissions without delivery.
        if unsafe { libc::kill(pid, 0) } < 0 && Errno::last() == Errno::ESRCH {
            return Err(Errno::ESRCH);
        }
    }
    Err(Errno::ENOSYS)
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(all(test, unix))]
mod step_tests;
