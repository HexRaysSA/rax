//! Bounded scheduling uses real guest entry/syscall paths on every Linux ABI.
use super::harness::{CODE, Harness};
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::syscall::thread::cf::*;
use crate::user::linux::{ExitStatus, RunStatus};
use std::sync::atomic::{AtomicBool, Ordering};

const ENTRY: u64 = CODE + 0x1000;

fn exit_image(abi: LinuxAbi) -> Harness {
    let h = Harness::new(abi);
    let code = match abi {
        LinuxAbi::X86_64 => vec![0xb8, 60, 0, 0, 0, 0xbf, 37, 0, 0, 0, 0x0f, 0x05],
        LinuxAbi::I386 => vec![0xb8, 1, 0, 0, 0, 0xbb, 37, 0, 0, 0, 0xcd, 0x80],
        LinuxAbi::Aarch64 => words(&[0xd280_0ba8, 0xd280_04a0, 0xd400_0001]),
        LinuxAbi::Arm => words(&[0xe3a0_7001, 0xe3a0_0025, 0xef00_0000]),
        LinuxAbi::Riscv64 => words(&[0x05d0_0893, 0x0250_0513, 0x0000_0073]),
    };
    h.proc.state.space.write_raw(ENTRY, &code).unwrap();
    h
}
fn words(code: &[u32]) -> Vec<u8> {
    code.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn finish(h: &mut Harness) {
    let cancelled = AtomicBool::new(false);
    for _ in 0..100 {
        match h.proc.run_slice(1, &cancelled) {
            RunStatus::BudgetExhausted => {}
            RunStatus::Complete(status) => {
                assert_eq!(status, ExitStatus::Exited(37));
                return;
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
    panic!("exit did not complete within 100 turns");
}

#[test]
fn bounded_zero_cancel_resume_and_cached_exit_all_linux_abis() {
    for abi in [
        LinuxAbi::X86_64,
        LinuxAbi::I386,
        LinuxAbi::Aarch64,
        LinuxAbi::Arm,
        LinuxAbi::Riscv64,
    ] {
        let mut h = exit_image(abi);
        let cancelled = AtomicBool::new(true);
        assert_eq!(h.proc.run_slice(0, &cancelled), RunStatus::BudgetExhausted);
        assert_eq!(h.proc.run_slice(10, &cancelled), RunStatus::Cancelled);
        assert_eq!(h.proc.threads[0].cpu.pc(), ENTRY);
        cancelled.store(false, Ordering::Release);
        finish(&mut h);
        assert_eq!(
            h.proc.run_slice(0, &cancelled),
            RunStatus::Complete(ExitStatus::Exited(37))
        );
        // Cached completion must not re-enter exit teardown, even if a caller
        // modifies the public diagnostic state after observing completion.
        h.proc.state.exit = None;
        assert_eq!(h.proc.run(), ExitStatus::Exited(37));
    }
}

#[test]
fn bounded_indefinite_wait_is_resumable_and_cancellation_keeps_continuation() {
    for abi in [
        LinuxAbi::X86_64,
        LinuxAbi::I386,
        LinuxAbi::Aarch64,
        LinuxAbi::Arm,
        LinuxAbi::Riscv64,
    ] {
        let mut h = exit_image(abi);
        let addr = h.scratch;
        h.proc.state.space.write(addr, &0u32.to_le_bytes()).unwrap();
        assert_eq!(h.start(0, Sysno::Futex, &[addr, 0, 0, 0, 0, 0]), None);
        let cancelled = AtomicBool::new(false);
        assert_eq!(h.proc.run_slice(u64::MAX, &cancelled), RunStatus::Blocked);
        assert!(h.proc.threads[0].blocked.is_some());
        cancelled.store(true, Ordering::Release);
        assert_eq!(h.proc.run_slice(10, &cancelled), RunStatus::Cancelled);
        assert!(h.proc.threads[0].blocked.is_some());
        h.proc.threads[0].blocked.as_mut().unwrap().woken = true;
        cancelled.store(false, Ordering::Release);
        assert_eq!(h.proc.run_slice(1, &cancelled), RunStatus::BudgetExhausted);
        assert!(h.proc.threads[0].blocked.is_none());
        assert_eq!(h.proc.threads[0].cpu.pc(), ENTRY);
        finish(&mut h);
    }
}

#[test]
fn bounded_round_robin_survives_separate_calls() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    h.proc.state.config.slice_insns = 1;
    h.proc
        .state
        .space
        .write_raw(ENTRY, &words(&[0xd503_201f; 8]))
        .unwrap();
    let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    h.ok(Sysno::Clone, &[flags, 0, 0, 0, 0]);
    for thread in &mut h.proc.threads {
        thread.cpu.set_pc(ENTRY);
    }
    for (first, second) in [(1, 0), (1, 1), (2, 1), (2, 2)] {
        assert_eq!(
            h.proc.run_slice(1, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
        assert_eq!(h.proc.threads[0].cpu.pc(), ENTRY + 4 * first);
        assert_eq!(h.proc.threads[1].cpu.pc(), ENTRY + 4 * second);
    }
}

#[test]
fn bounded_reservation_survives_same_thread_yield_but_not_switch() {
    use crate::isa::arm::common::cpu::ArmCpu;
    for peers in [false, true] {
        let mut h = Harness::new(LinuxAbi::Aarch64);
        h.proc.state.config.slice_insns = 1;
        h.proc
            .state
            .space
            .write_raw(ENTRY, &words(&[0xc85f_7c20, 0xc802_7c20]))
            .unwrap();
        if peers {
            let flags =
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
            h.ok(Sysno::Clone, &[flags, 0, 0, 0, 0]);
            h.proc
                .state
                .space
                .write_raw(ENTRY + 0x100, &words(&[0x1400_0000]))
                .unwrap();
            h.proc.threads[1].cpu.set_pc(ENTRY + 0x100);
        }
        let GuestCpu::Aarch64(cpu) = &mut h.proc.threads[0].cpu else {
            unreachable!()
        };
        cpu.core_mut().set_x(1, h.scratch);
        let cancelled = AtomicBool::new(false);
        assert_eq!(h.proc.run_slice(1, &cancelled), RunStatus::BudgetExhausted);
        if peers {
            assert_eq!(h.proc.run_slice(1, &cancelled), RunStatus::BudgetExhausted);
        }
        assert_eq!(h.proc.run_slice(1, &cancelled), RunStatus::BudgetExhausted);
        let GuestCpu::Aarch64(cpu) = &h.proc.threads[0].cpu else {
            unreachable!()
        };
        assert_eq!(cpu.core().get_x(2), u64::from(peers));
    }
}
