//! Actual KVM host slices. Missing /dev/kvm is a failure when selected.
#![cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
use rax::backend::{
    Backend,
    kvm::{KvmBackend, KvmVm},
};
use rax::vm::memory::{
    GuestMemoryWrapper,
    vm::{Bytes, GuestAddress},
};
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static HANDLED: AtomicUsize = AtomicUsize::new(0);
const CHILD: &str = "RAX_KVM_HOST_SLICE_TEST_CHILD";

fn in_child(name: &str, test: impl FnOnce()) {
    if std::env::var(CHILD).as_deref() == Ok(name) {
        test();
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            name,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fixture(code: &[u8]) -> (GuestMemoryWrapper, Box<dyn VCpu>) {
    let backend = KvmBackend::new().expect("native KVM host-slice tests require /dev/kvm");
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    vm.as_any()
        .downcast_ref::<KvmVm>()
        .unwrap()
        .register_memory(&memory)
        .unwrap();
    memory
        .memory()
        .write_slice(code, GuestAddress(0x1000))
        .unwrap();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    assert!(
        cpu.supports_host_slices(),
        "KVM does not implement bounded native entry"
    );
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.rip = 0x1000;
    state.regs.rflags = 2;
    state.sregs.cs.selector = 0;
    state.sregs.cs.base = 0;
    state.sregs.ds.selector = 0;
    state.sregs.ds.base = 0;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    (memory, cpu)
}

fn next_exit(cpu: &mut dyn VCpu) -> VcpuExit {
    for _ in 0..100 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(100)).unwrap() {
            return exit;
        }
    }
    panic!("guest did not reach its next exit after100 bounded entries");
}

fn signal_mask() -> libc::sigset_t {
    // SAFETY: the output is valid initialized libc signal storage. Null input
    // queries only this calling thread's mask and retains no reference.
    let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) },
        0
    );
    mask
}

fn action() -> libc::sigaction {
    // SAFETY: initialized, exclusive output lives for the synchronous query.
    // Null input leaves the process disposition unchanged.
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGRTMAX(), std::ptr::null(), &mut action) },
        0
    );
    action
}

extern "C" fn foreign_handler(_: i32) {
    // This native x86-64 atomic increment is lock-free and signal-safe.
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn finite_turns_preserve_caller_mask_handlers_and_timer_ownership() {
    in_child(
        "finite_turns_preserve_caller_mask_handlers_and_timer_ownership",
        || {
            let (_memory, mut cpu) = fixture(&[0xeb, 0xfe]); // Infinite guest JMP.
            let original_mask = signal_mask();
            let timers = std::fs::read_to_string("/proc/self/timers").unwrap();
            let mut minimum = Duration::MAX;
            let mut maximum = Duration::ZERO;
            for mode in 0..2 {
                if mode == 1 {
                    // Isolated child only: verify an existing handler is neither
                    // invoked by the worker timer nor replaced by the backend.
                    let mut selected = action();
                    selected.sa_sigaction = foreign_handler as *const () as usize;
                    selected.sa_flags = 0;
                    assert_eq!(unsafe { libc::sigemptyset(&mut selected.sa_mask) }, 0);
                    assert_eq!(
                        unsafe {
                            libc::sigaction(libc::SIGRTMAX(), &selected, std::ptr::null_mut())
                        },
                        0
                    );
                }
                let disposition = action();
                for _ in 0..20 {
                    let start = Instant::now();
                    assert!(
                        cpu.run_host_slice(Duration::from_millis(2))
                            .unwrap()
                            .is_none()
                    );
                    let elapsed = start.elapsed();
                    minimum = minimum.min(elapsed);
                    maximum = maximum.max(elapsed);
                    assert!(elapsed >= Duration::from_millis(2));
                    assert_eq!(cpu.current_pc(), 0x1000);
                    assert_eq!(HANDLED.load(Ordering::Relaxed), 0);
                }
                let after = action();
                assert_eq!(after.sa_sigaction, disposition.sa_sigaction);
                assert_eq!(after.sa_flags, disposition.sa_flags);
            }
            let after_mask = signal_mask();
            for signal in 1..=64 {
                // SAFETY: both initialized sets are live, read-only locals.
                assert_eq!(
                    unsafe { libc::sigismember(&original_mask, signal) },
                    unsafe { libc::sigismember(&after_mask, signal) }
                );
            }
            assert_eq!(
                std::fs::read_to_string("/proc/self/timers").unwrap(),
                timers
            );
            // SAFETY: send the selected signal to this live caller to establish
            // the retained foreign handler is operative after all workers exit.
            assert_eq!(
                unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGRTMAX()) },
                0
            );
            assert_eq!(HANDLED.load(Ordering::Relaxed), 1);
            eprintln!(
                "40 requested2ms slices: minimum_ns={} maximum_ns={}",
                minimum.as_nanos(),
                maximum.as_nanos()
            );
        },
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn input_output_and_halt_survive_worker_returns_and_rejected_reentry() {
    in_child(
        "input_output_and_halt_survive_worker_returns_and_rejected_reentry",
        || {
            let (_memory, mut cpu) = fixture(&[0xe4, 0x70, 0xe6, 0x71, 0xf4]);
            let pc = cpu.current_pc();
            for interval in [
                Duration::ZERO,
                Duration::MAX,
                Duration::from_nanos(i64::MAX as u64 + 1),
                Duration::from_nanos(i64::MAX as u64),
            ] {
                assert!(cpu.run_host_slice(interval).is_err());
                assert_eq!(cpu.current_pc(), pc);
            }
            let mut now = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: initialized, exclusive local output for a clock query.
            assert_eq!(
                unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) },
                0
            );
            let horizon = u64::try_from(i64::MAX / 1_000_000_000 - now.tv_sec).unwrap();
            let timers = std::fs::read_to_string("/proc/self/timers").unwrap();
            assert!(cpu.run_host_slice(Duration::from_secs(horizon)).is_err());
            assert_eq!(cpu.current_pc(), pc);
            assert_eq!(
                std::fs::read_to_string("/proc/self/timers").unwrap(),
                timers
            );
            assert!(matches!(
                next_exit(&mut *cpu),
                VcpuExit::IoIn {
                    port: 0x70,
                    size: 1
                }
            ));
            let pc = cpu.current_pc();
            assert!(cpu.run_host_slice(Duration::from_millis(2)).is_err());
            assert_eq!(cpu.current_pc(), pc);
            cpu.complete_io_in(&[0x5a]);
            assert!(
                matches!(next_exit(&mut *cpu), VcpuExit::IoOut { port: 0x71, data } if data == [0x5a])
            );
            cpu.complete_io_out().unwrap();
            assert!(matches!(next_exit(&mut *cpu), VcpuExit::Hlt));
        },
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn mmio_input_and_output_retain_the_exact_native_frontier() {
    in_child(
        "mmio_input_and_output_retain_the_exact_native_frontier",
        || {
            // Real-mode address-size override: MOV AL,[0xfee00000], then store
            // AL to the next byte. No kernel IRQchip is installed in this fixture.
            let code = [
                0x67, 0xa0, 0x00, 0x00, 0xe0, 0xfe, 0x67, 0xa2, 0x01, 0x00, 0xe0, 0xfe, 0xf4,
            ];
            let (_memory, mut cpu) = fixture(&code);
            let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            // Retain a full32-bit cached data-segment limit (unreal mode).
            // The reset64KiB limit faults before reaching the intended MMIO.
            state.sregs.ds.limit = u32::MAX;
            state.sregs.ds.g = true;
            cpu.set_state(&CpuState::X86_64(state)).unwrap();
            let read = next_exit(&mut *cpu);
            assert!(
                matches!(
                    read,
                    VcpuExit::MmioRead {
                        addr: 0xfee00000,
                        size: 1
                    }
                ),
                "unexpected native read exit: {read:?}"
            );
            assert!(cpu.run_host_slice(Duration::from_millis(2)).is_err());
            cpu.complete_io_in(&[0xa5]);
            assert!(
                matches!(next_exit(&mut *cpu), VcpuExit::MmioWrite { addr: 0xfee00001, data } if data == [0xa5])
            );
            cpu.complete_io_out().unwrap();
            assert!(matches!(next_exit(&mut *cpu), VcpuExit::Hlt));
        },
    );
}

#[path = "raw_owner.rs"]
mod raw_owner;

#[path = "io_completion.rs"]
mod io_completion;
