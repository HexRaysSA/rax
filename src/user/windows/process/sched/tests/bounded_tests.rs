//! Scheduling boundaries are independent of the guest ISA and host OS.
use super::*;
use crate::user::windows::process::WindowsProcess;

fn runnable(arch: WinArch, peers: bool) -> (WindowsProcess, u64, u64) {
    let mut p = process(arch);
    Arc::make_mut(&mut p.cfg).slice_insns = 1;
    let (code, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let width = if arch == WinArch::Arm64 {
        for i in 0..16 {
            p.space.w32(code + i * 4, 0xD503_201F).unwrap();
        }
        4
    } else {
        p.space.write(code, &[0x90; 16]).unwrap();
        1
    };
    p.vm.protect(code, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
    let mut first = thread(&mut p, 8);
    first.cpu.set_pc(code);
    p.threads.insert(8, first);
    if peers {
        let mut second = thread(&mut p, 12);
        second.cpu.set_pc(code);
        p.threads.insert(12, second);
    }
    (
        WindowsProcess {
            proc: p,
            scheduler: Default::default(),
        },
        code,
        width,
    )
}

#[test]
fn zero_and_cancel_preserve_state_and_resume_all_abis() {
    for arch in WinArch::ALL {
        let (mut p, code, width) = runnable(arch, false);
        let cancelled = AtomicBool::new(true);
        assert_eq!(p.run_slice(0, &cancelled), RunStatus::BudgetExhausted);
        assert_eq!(p.run_slice(5, &cancelled), RunStatus::Cancelled);
        assert_eq!(p.state().threads[&8].cpu.pc(), code);
        assert_eq!(p.scheduler.previous, 0);
        cancelled.store(false, Ordering::Release);
        assert_eq!(p.run_slice(3, &cancelled), RunStatus::BudgetExhausted);
        assert_eq!(p.state().threads[&8].cpu.pc(), code + 3 * width);
    }
}

#[test]
fn separate_calls_preserve_round_robin_all_abis() {
    for arch in WinArch::ALL {
        let (mut p, code, width) = runnable(arch, true);
        let cancelled = AtomicBool::new(false);
        for (a, b) in [(1, 0), (1, 1), (2, 1), (2, 2)] {
            assert_eq!(p.run_slice(1, &cancelled), RunStatus::BudgetExhausted);
            assert_eq!(p.state().threads[&8].cpu.pc(), code + a * width);
            assert_eq!(p.state().threads[&12].cpu.pc(), code + b * width);
        }
    }
}

#[test]
fn blocked_is_resumable_without_sleep_or_thread_loss_all_abis() {
    for arch in WinArch::ALL {
        let (mut p, code, width) = runnable(arch, false);
        let cancelled = AtomicBool::new(false);
        p.state_mut().threads.get_mut(&8).unwrap().suspend = 1;
        assert_eq!(p.run_slice(u64::MAX, &cancelled), RunStatus::Blocked);
        assert_eq!(p.state().threads[&8].cpu.pc(), code);
        p.state_mut().threads.get_mut(&8).unwrap().suspend = 0;
        assert_eq!(p.run_slice(1, &cancelled), RunStatus::BudgetExhausted);
        assert_eq!(p.state().threads[&8].cpu.pc(), code + width);
    }
}

#[test]
fn last_thread_exit_completes_and_terminal_calls_do_not_repeat_teardown_all_abis() {
    for arch in WinArch::ALL {
        let (mut p, _, _) = runnable(arch, false);
        let cancelled = AtomicBool::new(false);
        p.state_mut().threads.get_mut(&8).unwrap().terminate = Some(73);
        assert_eq!(
            p.run_slice(1, &cancelled),
            RunStatus::Complete(ExitStatus::Exited(73))
        );
        assert!(p.state().threads.is_empty());
        // A cached terminal process does not consume newly inserted host state.
        let marker = p.state_mut().objects.create(Object::Process {
            pid: 999,
            exit_code: None,
        });
        assert_eq!(p.run(), ExitStatus::Exited(73));
        assert_eq!(
            p.run_slice(0, &cancelled),
            RunStatus::Complete(ExitStatus::Exited(73))
        );
        assert!(p.state().objects.obj(marker).is_some());
    }
}

#[test]
fn failure_is_terminal_and_cached_all_abis() {
    for arch in WinArch::ALL {
        let (mut p, code, _) = runnable(arch, false);
        p.state_mut().fail("fixture failure");
        let status = ExitStatus::Internal("fixture failure".into());
        assert_eq!(
            p.run_slice(1, &AtomicBool::new(false)),
            RunStatus::Complete(status.clone())
        );
        p.state_mut().failure = None;
        assert_eq!(p.run(), status);
        assert_eq!(p.state().threads[&8].cpu.pc(), code);
    }
}

#[test]
fn indefinite_guest_wait_returns_blocked_and_cancellation_preserves_wait_all_abis() {
    for arch in WinArch::ALL {
        let (mut p, code, _) = runnable(arch, false);
        p.state_mut().threads.get_mut(&8).unwrap().state =
            ThreadState::Waiting(sync::Wait::Sleep {
                deadline: None,
                alertable: false,
            });
        let cancelled = AtomicBool::new(false);
        assert_eq!(p.run_slice(10, &cancelled), RunStatus::Blocked);
        cancelled.store(true, Ordering::Release);
        assert_eq!(p.run_slice(10, &cancelled), RunStatus::Cancelled);
        assert!(matches!(
            p.state().threads[&8].state,
            ThreadState::Waiting(_)
        ));
        assert_eq!(p.state().threads[&8].cpu.pc(), code);
    }
}
