//! Finite KVM entry without installing a process-global signal handler.
//!
//! A private worker blocks signals in userspace and gives KVM an entry-only
//! mask that unmasks its thread-directed monotonic timer. A stopped KVM_RUN
//! can associate a fresh worker with the vCPU before starting its timed entry.
//! KVM returns EINTR before delivering the signal. A retained worker never
//! unmasks a signal that an earlier deadline may have queued. It uses a
//! bounded sequence of thread-directed realtime signals, then exits with
//! its remaining private notifications. Caller masks and dispositions are
//! untouched.
use super::{MemoryOwner, NativeCore};
use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;
use kvm_ioctls::VcpuFd;
use std::os::fd::{AsRawFd, RawFd};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

/// Linux x86-64's kernel sigset is eight bytes, unlike libc's sigset_t.
/// KVM_SET_SIGNAL_MASK encodes the four-byte flexible-array header's size.
#[repr(C)]
struct EntrySignalMask {
    len: u32,
    signals: [u8; 8],
}

fn checked(result: libc::c_int) -> Result<()> {
    if result < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

fn interval(limit: Duration) -> Result<libc::timespec> {
    if limit.is_zero() {
        return Err(Error::InvalidConfig(
            "KVM host interval must be positive".into(),
        ));
    }
    // Linux's monotonic hrtimer deadline uses signed64-bit nanoseconds.
    // Reject intervals that would otherwise be silently saturated by ktime.
    i64::try_from(limit.as_nanos())
        .map_err(|_| Error::InvalidConfig("KVM host interval exceeds native ktime_t".into()))?;
    let seconds = libc::time_t::try_from(limit.as_secs())
        .map_err(|_| Error::InvalidConfig("KVM host interval exceeds native time_t".into()))?;
    Ok(libc::timespec {
        tv_sec: seconds,
        tv_nsec: limit.subsec_nanos().into(),
    })
}

fn monotonic_nanos() -> Result<i128> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: initialized, exclusive output for a synchronous clock query.
    checked(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) })?;
    if now.tv_sec < 0 || !(0..1_000_000_000).contains(&now.tv_nsec) {
        return Err(Error::Emulator(
            "invalid native monotonic clock sample".into(),
        ));
    }
    Ok(i128::from(now.tv_sec) * 1_000_000_000 + i128::from(now.tv_nsec))
}

fn native_deadline(value_ns: i128) -> Result<i64> {
    let deadline_ns = i64::try_from(monotonic_nanos()? + value_ns)
        .map_err(|_| Error::InvalidConfig("KVM host deadline exceeds native ktime_t".into()))?;
    // Linux v6.8 timespec64_to_ktime saturates at the last whole-second
    // quotient, even when the original nanosecond sum fits in i64.
    if deadline_ns / 1_000_000_000 >= i64::MAX / 1_000_000_000 {
        return Err(Error::InvalidConfig(
            "KVM host deadline reaches the native saturation boundary".into(),
        ));
    }
    Ok(deadline_ns)
}

fn bounded_nanos(value: libc::timespec) -> Result<i128> {
    let requested = i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec);
    // Validate the requested interval before any stopped kernel operation.
    native_deadline(requested)?;
    // Bound the timed entry for VM writer exclusion even when an SDK caller
    // requests a longer host slice.
    Ok(requested.min(10_000_000))
}

fn block_worker_signals() -> Result<()> {
    // SAFETY: sigset_t permits a zeroed representation; libc initializes
    // this exclusive local before use and retains no pointer. This private
    // worker never restores an unblocked mask before it terminates.
    let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    checked(unsafe { libc::sigfillset(&mut blocked) })?;
    // SAFETY: the initialized set remains live for this synchronous call;
    // null oldset requests no output. No process disposition is changed.
    let status =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &blocked, std::ptr::null_mut()) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status).into());
    }
    Ok(())
}

struct Deadline {
    fd: RawFd,
    mask_installed: bool,
    timer: Option<libc::timer_t>,
}

impl Deadline {
    fn install_mask(&mut self, signal: libc::c_int) -> Result<()> {
        block_worker_signals()?;
        if !(1..=64).contains(&signal) {
            return Err(Error::InvalidConfig(
                "KVM timer signal exceeds the kernel signal mask".into(),
            ));
        }
        let bit = signal as usize - 1;
        let mut mask = EntrySignalMask {
            len: 8,
            signals: [0xff; 8],
        };
        mask.signals[bit / 8] &= !(1 << (bit % 8));
        // SAFETY: the x86 KVM UAPI header and eight-byte kernel sigset match
        // this initialized repr(C) input. The stopped CPU owns the live FD;
        // its exclusive Rust borrow excludes another managed entry. The
        // kernel copies the mask and retains no reference to this local.
        checked(unsafe {
            libc::ioctl(
                self.fd,
                libc::_IOW::<kvm_bindings::kvm_signal_mask>(kvm_bindings::KVMIO, 0x8b),
                &mask,
            )
        })?;
        self.mask_installed = true;
        Ok(())
    }

    fn prepare(&mut self, signal: libc::c_int) -> Result<()> {
        self.install_mask(signal)?;
        // SAFETY: all-zero sigevent is a valid initialized starting value.
        // SIGEV_THREAD_ID selects the documented Linux union member. gettid
        // identifies this live worker, which keeps the signal blocked outside
        // KVM_RUN; the timer never targets the caller or another CPU's worker.
        let mut event = unsafe { std::mem::zeroed::<libc::sigevent>() };
        event.sigev_notify = libc::SIGEV_THREAD_ID;
        event.sigev_signo = signal;
        event.sigev_notify_thread_id = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        let mut timer = std::ptr::null_mut();
        // SAFETY: initialized input and exclusive output stay live throughout
        // libc's synchronous call. The kernel retains the numeric worker ID,
        // not a pointer into Rust storage. CLOCK_MONOTONIC excludes wall jumps.
        checked(unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut event, &mut timer) })?;
        self.timer = Some(timer);
        Ok(())
    }

    fn arm(&self, value_ns: i128) -> Result<i64> {
        let timer = self.timer.expect("private entry timer was prepared");
        let deadline_ns = native_deadline(value_ns)?;
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: deadline_ns / 1_000_000_000,
                tv_nsec: deadline_ns % 1_000_000_000,
            },
        };
        // SAFETY: this live timer belongs exclusively to this worker. The
        // validated, initialized timespec is copied synchronously. A one-shot
        // expiration remains pending even if it occurs before KVM_RUN starts.
        checked(unsafe {
            libc::timer_settime(timer, libc::TIMER_ABSTIME, &spec, std::ptr::null_mut())
        })?;
        Ok(deadline_ns)
    }

    fn finish(&mut self) -> Result<()> {
        let mut failure = None;
        if let Some(timer) = self.timer {
            // SAFETY: this worker owns the timer returned by timer_create.
            // No other operation deletes it; a failed deletion remains tracked
            // so Drop can attempt cleanup again before this worker exits.
            match checked(unsafe { libc::timer_delete(timer) }) {
                Ok(()) => self.timer = None,
                Err(error) => failure = Some(error),
            }
        }
        if self.mask_installed {
            // SAFETY: the CPU's live FD is exclusively borrowed until worker
            // completion. Null restores its backend-owned default entry mask;
            // userspace remains blocked until this private worker terminates.
            match checked(unsafe {
                libc::ioctl(
                    self.fd,
                    libc::_IOW::<kvm_bindings::kvm_signal_mask>(kvm_bindings::KVMIO, 0x8b),
                    0usize,
                )
            }) {
                Ok(()) => self.mask_installed = false,
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        // Normal entry checks finish's result and poisons on failure. This
        // final attempt also covers unwinding during preparation. The worker
        // still blocks its timer signal and cannot deliver it in userspace.
        let _ = self.finish();
    }
}

/// KVM can associate the worker and finish an earlier I/O transaction at
/// an immediate-exit entry, before starting the native slice's timer.
fn associate_worker(cpu: &mut NativeCore) -> Result<Option<VcpuExit>> {
    cpu.vcpu_fd.set_kvm_immediate_exit(1);
    let result = catch_unwind(AssertUnwindSafe(|| cpu.run_native()));
    cpu.vcpu_fd.set_kvm_immediate_exit(0);
    match result {
        Ok(Err(Error::Kvm(error))) if error.errno() == libc::EINTR => Ok(None),
        Ok(result) => result.map(Some),
        Err(panic) => resume_unwind(panic),
    }
}

fn worker(
    cpu: &mut NativeCore,
    value: libc::timespec,
    activate_resume: bool,
    next_signal: &mut Option<libc::c_int>,
) -> Result<Option<VcpuExit>> {
    let signal = next_signal.expect("active worker has a free signal");
    let mut expiry = None;
    let mut deadline = Deadline {
        fd: cpu.vcpu_fd.as_raw_fd(),
        mask_installed: false,
        timer: None,
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let limit_ns = bounded_nanos(value)?;
        if let Err(error) = deadline.prepare(signal) {
            *next_signal = None;
            return Err(error);
        }
        if !activate_resume
            && cpu.vcpu_fd.get_kvm_run().immediate_exit == 0
            && cpu
                .memory_owner
                .vm_fd
                .check_extension_raw(kvm_bindings::KVM_CAP_IMMEDIATE_EXIT.into())
                > 0
            && let Some(exit) = associate_worker(cpu)?
        {
            return Ok(exit);
        }
        expiry = Some(deadline.arm(limit_ns)?);
        if activate_resume {
            // The parent retains VM write exclusion through this worker.
            // Start clocks after signal setup for the first native attempt.
            cpu.activate_resume_clock()?;
        }
        cpu.run_native()
    }));
    if let Err(cleanup) = deadline.finish() {
        *next_signal = None;
        if activate_resume {
            cpu.memory_owner.poisoned.store(true, Ordering::Release);
        }
        let failure = format!("KVM host deadline cleanup failed: {cleanup}; guest entry disabled");
        cpu.state_failure = Some(failure.clone());
        return Err(Error::Emulator(failure));
    }
    // A sample strictly before the deadline, taken after timer deletion,
    // proves this timer never signalled the thread. Otherwise reserve a
    // different signal. The previous number stays blocked until thread exit.
    let may_have_expired =
        expiry.is_some_and(|end| !monotonic_nanos().is_ok_and(|now| now < i128::from(end)));
    let interrupted = matches!(&result, Ok(Err(Error::Kvm(error))) if error.errno() == libc::EINTR);
    if next_signal.is_some() && (may_have_expired || interrupted) {
        *next_signal = next_worker_signal(signal);
    }
    match result {
        Ok(Err(Error::Kvm(error))) if error.errno() == libc::EINTR => Ok(None),
        Ok(result) => result.map(Some),
        Err(_) => {
            *next_signal = None;
            if activate_resume {
                cpu.memory_owner.poisoned.store(true, Ordering::Release);
            }
            let failure = "KVM host entry worker panicked; guest entry disabled".to_string();
            cpu.state_failure = Some(failure.clone());
            Err(Error::Emulator(failure))
        }
    }
}

fn next_worker_signal(signal: libc::c_int) -> Option<libc::c_int> {
    const SIGNALS_PER_WORKER: libc::c_int = 8;
    let lowest = libc::SIGRTMIN().max(libc::SIGRTMAX() - (SIGNALS_PER_WORKER - 1));
    (signal > lowest).then_some(signal - 1)
}

/// Let KVM process a queued event with a thread-directed signal already
/// pending at its guest-entry check. The caller owns a stopped, unused CPU.
pub(super) fn service_queued_event(cpu: &mut VcpuFd) -> Result<()> {
    let result = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("rax-kvm-stopped-event".into())
            .spawn_scoped(scope, || {
                let mut deadline = Deadline {
                    fd: cpu.as_raw_fd(),
                    mask_installed: false,
                    timer: None,
                };
                let signal = libc::SIGRTMAX();
                deadline.install_mask(signal)?;
                // SAFETY: the private thread blocks this signal in userspace.
                // pthread_kill directs it to this thread only.
                let status = unsafe { libc::pthread_kill(libc::pthread_self(), signal) };
                if status != 0 {
                    return Err(std::io::Error::from_raw_os_error(status).into());
                }
                // SAFETY: the initialized local is valid for both calls. An
                // ignored signal that did not become pending cannot fence entry.
                let mut pending = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                checked(unsafe { libc::sigpending(&mut pending) })?;
                if unsafe { libc::sigismember(&pending, signal) } != 1 {
                    return Err(Error::Emulator(
                        "KVM stopped event signal is not pending".into(),
                    ));
                }
                let header = cpu.get_kvm_run();
                let immediate = header.immediate_exit;
                header.immediate_exit = 0;
                let result = cpu.run().map(|_| ());
                cpu.set_kvm_immediate_exit(immediate);
                deadline.finish()?;
                match result {
                    Err(error) if error.errno() == libc::EINTR => Ok(()),
                    result => Err(Error::Emulator(format!(
                        "KVM stopped event entered the guest: {result:?}"
                    ))),
                }
            })
            .map(|thread| thread.join())
    })?;
    result.map_err(|_| Error::Emulator("KVM stopped event worker panicked".into()))?
}

/// A disposable worker for callers that already hold a native CPU guard.
/// A private timer per entry uses O(1) work and storage outside execution.
/// Kernel scheduling may delay the yield beyond the requested interval.
/// No host timer or worker identity belongs to the guest checkpoint record.
pub(super) fn run(cpu: &mut NativeCore, limit: Duration) -> Result<Option<VcpuExit>> {
    run_mode(cpu, limit)
}

fn run_mode(cpu: &mut NativeCore, limit: Duration) -> Result<Option<VcpuExit>> {
    let result = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("rax-kvm-entry".into())
            .spawn_scoped(scope, || {
                let mut signal = Some(libc::SIGRTMAX());
                run_on_entry_thread(cpu, limit, false, &mut signal)
            })
            .map(|thread| thread.join())
    });
    match result {
        Err(error) => Err(error.into()),
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            let failure =
                "KVM host worker initialization panicked; guest entry disabled".to_string();
            cpu.state_failure = Some(failure.clone());
            Err(Error::Emulator(failure))
        }
    }
}

/// Called on a private thread while its caller retains native CPU exclusion.
pub(super) fn run_on_entry_thread(
    cpu: &mut NativeCore,
    limit: Duration,
    activate_resume: bool,
    next_signal: &mut Option<libc::c_int>,
) -> Result<Option<VcpuExit>> {
    cpu.memory_owner.ready()?;
    if cpu.memory_owner.powered_off.load(Ordering::Acquire) {
        return Ok(Some(VcpuExit::Shutdown));
    }
    cpu.state_ready()?;
    let value = interval(limit)?;
    if matches!(
        cpu.io.event().map_err(Error::Emulator)?,
        Some(super::io::Event::Input(_))
    ) {
        return Err(Error::InvalidConfig(
            "KVM host entry requires completion of the pending input".into(),
        ));
    }
    worker(cpu, value, activate_resume, next_signal)
}

struct EntryRequest {
    limit: Duration,
    reply: mpsc::SyncSender<(Result<Option<VcpuExit>>, bool)>,
}

/// One private thread at most per managed CPU. It leaves any prior timer's
/// pending signal blocked and eventually retires. The VM and core guards
/// live on this thread for the duration of each request.
pub(super) struct EntryWorker {
    requests: Option<mpsc::Sender<EntryRequest>>,
    thread: Option<JoinHandle<()>>,
}

impl EntryWorker {
    pub(super) fn new(owner: Arc<MemoryOwner>, core: Arc<Mutex<NativeCore>>) -> Result<Self> {
        let (requests, receive) = mpsc::channel::<EntryRequest>();
        let (ready, started) = mpsc::sync_channel(0);
        let thread = std::thread::Builder::new()
            .name("rax-kvm-entry".into())
            .spawn(move || {
                let prepared = block_worker_signals();
                let is_ready = prepared.is_ok();
                if ready.send(prepared).is_err() || !is_ready {
                    return;
                }
                let mut next_signal = Some(libc::SIGRTMAX());
                while let Ok(request) = receive.recv() {
                    let result = super::clock_gate::enter_managed(
                        &owner,
                        &core,
                        request.limit,
                        &mut next_signal,
                    );
                    let reusable = next_signal.is_some();
                    if request.reply.send((result, reusable)).is_err() || !reusable {
                        break;
                    }
                }
            })?;
        let prepared = started.recv().unwrap_or_else(|_| {
            Err(Error::Emulator(
                "KVM host worker stopped during initialization".into(),
            ))
        });
        if let Err(error) = prepared {
            let _ = thread.join();
            return Err(error);
        }
        Ok(Self {
            requests: Some(requests),
            thread: Some(thread),
        })
    }

    pub(super) fn run(
        &self,
        owner: &MemoryOwner,
        limit: Duration,
    ) -> (Result<Option<VcpuExit>>, bool) {
        let (reply, receive) = mpsc::sync_channel(0);
        if self
            .requests
            .as_ref()
            .expect("entry worker is live")
            .send(EntryRequest { limit, reply })
            .is_ok()
            && let Ok(result) = receive.recv()
        {
            return result;
        }
        owner.poisoned.store(true, Ordering::Release);
        (
            Err(Error::Emulator(
                "KVM host worker stopped during native entry; guest entry disabled".into(),
            )),
            false,
        )
    }
}

impl Drop for EntryWorker {
    fn drop(&mut self) {
        self.requests.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
