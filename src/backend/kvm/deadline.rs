//! Finite KVM entry without installing a process-global signal handler.
//!
//! A private worker blocks signals in userspace and gives KVM an entry-only
//! mask that unmasks its thread-directed monotonic timer. KVM returns EINTR
//! before delivering that signal. The pending timer notification expires with
//! the worker; the caller's mask and process dispositions remain untouched.
use super::KvmVcpu;
use crate::error::{Error, Result};
use crate::vm::vcpu::{VCpu, VcpuExit};
use std::os::fd::{AsRawFd, RawFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
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

struct Deadline {
    fd: RawFd,
    mask_installed: bool,
    timer: Option<libc::timer_t>,
}

impl Deadline {
    fn arm(&mut self, value: libc::timespec) -> Result<()> {
        // SAFETY: sigset_t permits a zeroed representation; libc initializes
        // this exclusive local before use and retains no pointer. Only this
        // private worker's signal mask is changed, and it exits after entry.
        let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        checked(unsafe { libc::sigfillset(&mut blocked) })?;
        // SAFETY: the initialized set remains live for this synchronous call;
        // null oldset requests no output. No process disposition is changed.
        let status =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &blocked, std::ptr::null_mut()) };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status).into());
        }
        let signal = libc::SIGRTMAX();
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
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: this initialized, exclusive output remains live for the
        // synchronous monotonic clock query; libc retains no reference.
        checked(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) })?;
        if now.tv_sec < 0 || !(0..1_000_000_000).contains(&now.tv_nsec) {
            return Err(Error::Emulator(
                "invalid native monotonic clock sample".into(),
            ));
        }
        let deadline_ns = i128::from(now.tv_sec) * 1_000_000_000
            + i128::from(now.tv_nsec)
            + i128::from(value.tv_sec) * 1_000_000_000
            + i128::from(value.tv_nsec);
        let deadline_ns = i64::try_from(deadline_ns)
            .map_err(|_| Error::InvalidConfig("KVM host deadline exceeds native ktime_t".into()))?;
        // Linux v6.8 ktime_set/timespec64_to_ktime saturate even at the
        // final whole-second quotient. Reject that boundary explicitly.
        if deadline_ns / 1_000_000_000 >= i64::MAX / 1_000_000_000 {
            return Err(Error::InvalidConfig(
                "KVM host deadline reaches the native saturation boundary".into(),
            ));
        }
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
        })
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

fn worker(cpu: &mut KvmVcpu, value: libc::timespec) -> Result<Option<VcpuExit>> {
    let mut deadline = Deadline {
        fd: cpu.vcpu_fd.as_raw_fd(),
        mask_installed: false,
        timer: None,
    };
    let result = match deadline.arm(value) {
        Ok(()) => catch_unwind(AssertUnwindSafe(|| cpu.run())),
        Err(error) => Ok(Err(error)),
    };
    if let Err(cleanup) = deadline.finish() {
        let failure = format!("KVM host deadline cleanup failed: {cleanup}; guest entry disabled");
        cpu.state_failure = Some(failure.clone());
        return Err(Error::Emulator(failure));
    }
    match result {
        Ok(Err(Error::Kvm(error))) if error.errno() == libc::EINTR => Ok(None),
        Ok(result) => result.map(Some),
        Err(_) => {
            let failure = "KVM host entry worker panicked; guest entry disabled".to_string();
            cpu.state_failure = Some(failure.clone());
            Err(Error::Emulator(failure))
        }
    }
}

/// One worker/timer per entry; O(1) work/storage outside native execution.
/// Kernel scheduling may delay the yield beyond the requested interval.
/// No host timer or worker identity belongs to the guest checkpoint record.
pub(super) fn run(cpu: &mut KvmVcpu, limit: Duration) -> Result<Option<VcpuExit>> {
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
    let result = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("rax-kvm-entry".into())
            .spawn_scoped(scope, || worker(cpu, value))
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
