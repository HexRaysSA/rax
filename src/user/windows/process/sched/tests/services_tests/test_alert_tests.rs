//! Native no-argument alert query and owned queued-APC behavior.
use super::*;
use crate::user::windows::process::thread::UserApc;

const SERVICE: u32 = 0x78;

fn call(p: &mut Proc, t: &mut Thread) -> Outcome {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            for (index, value) in [0x1234_0004u32, 0x1234_0000, u32::MAX, u32::MAX]
                .into_iter()
                .enumerate()
            {
                p.space.w32(sp + index as u64 * 4, value).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for index in [10, 2, 8, 9] {
                t.cpu.set_gpr(index, u64::MAX);
            }
        }
        WinArch::Arm64 => {
            for index in 0..8 {
                t.cpu.set_gpr(index, u64::MAX);
            }
        }
    }
    if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    }
}

#[test]
fn native_test_alert_empty_call_ignores_argument_slots_and_returns_native_status_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtTestAlert", SERVICE);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        assert_eq!(call(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.apcs.is_empty());
        assert!(t.frames.is_empty());
    }
}

#[test]
fn native_test_alert_pending_callbacks_enter_owned_scheduler_delivery_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtTestAlert", SERVICE);
        let p = process.state_mut();
        t.apcs.extend(
            [(0x50000, 0x1111), (0x50100, 0x2222)]
                .into_iter()
                .map(UserApc::from),
        );
        assert_eq!(call(p, &mut t), Outcome::Park);
        assert_eq!(
            t.apcs.len(),
            2,
            "delivery starts on the next scheduler poll"
        );
        assert!(matches!(
            t.state,
            ThreadState::Waiting(sync::Wait::Sleep {
                alertable: true,
                ..
            })
        ));
        assert_eq!(t.frames.len(), 1);
    }
}

#[test]
fn native_test_alert_cancellation_retains_queue_and_forced_thread_exit_discards_continuation_all_abis()
 {
    use super::super::super::{RunStatus, Scheduler};
    use std::sync::atomic::AtomicBool;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtTestAlert", SERVICE);
        let p = process.state_mut();
        t.apcs.push_back((0x50000, 0x1111).into());
        assert_eq!(call(p, &mut t), Outcome::Park);
        let tid = t.tid;
        let sp = t.cpu.sp();
        let teb = t.teb;
        let stack = t.thread_stack_alloc;
        assert!(p.threads.is_empty());
        p.threads.insert(tid, t);
        let mut scheduler = Scheduler::default();
        assert_eq!(
            scheduler.run_slice(p, 1, &AtomicBool::new(true)),
            RunStatus::Cancelled
        );
        let t = &p.threads[&tid];
        assert_eq!(
            t.apcs.iter().copied().collect::<Vec<_>>(),
            [(0x50000, 0x1111)].map(UserApc::from)
        );
        assert_eq!(t.frames.len(), 1);
        assert_eq!(t.cpu.sp(), sp);
        assert!(matches!(t.state, ThreadState::Waiting(_)));
        p.threads.get_mut(&tid).unwrap().terminate = Some(37);
        assert_eq!(
            scheduler.run_slice(p, 2, &AtomicBool::new(false)),
            RunStatus::Complete(ExitStatus::Exited(37))
        );
        assert!(p.threads.is_empty());
        assert!(p.failure.is_none(), "{:?}", p.failure);
        assert_eq!(p.vm.query(stack).unwrap().state, mem::FREE);
        assert_eq!(p.vm.query(teb).unwrap().state, mem::RESERVE);
    }
}

#[test]
fn native_test_alert_consumes_alert_before_pending_callbacks_all_abis() {
    use crate::user::windows::nt::status::STATUS_ALERTED;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtTestAlert", SERVICE);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        t.user_alerted = true;
        t.apcs.push_back((0x50000, 0x1111).into());
        assert_eq!(call(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ALERTED));
        assert!(!t.user_alerted);
        assert_eq!(
            t.apcs.iter().copied().collect::<Vec<_>>(),
            [(0x50000, 0x1111)].map(UserApc::from)
        );
        assert!(t.frames.is_empty());
        t.cpu.set_sp(sp);
        assert_eq!(call(p, &mut t), Outcome::Park);
        assert_eq!(t.apcs.len(), 1);
    }
}

#[test]
fn native_test_alert_delivery_restores_context_and_preserves_callback_teb_writes_all_abis() {
    use crate::user::windows::layout;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtTestAlert", SERVICE);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        let error = t.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(error, 0xC0DE).unwrap();
        t.cpu.set_gpr(3, 0xCC55);
        t.apcs.extend(
            [(0x50000, 0x1111), (0x50100, 0x2222)]
                .into_iter()
                .map(UserApc::from),
        );
        assert_eq!(call(p, &mut t), Outcome::Park);
        let interrupted_gpr3 = t.cpu.gpr(3);
        let ThreadState::Waiting(wait) = t.state.clone() else {
            panic!("alert check did not retain its continuation")
        };
        let status = sync::poll(p, t.tid, &wait, Instant::now(), true)
            .unwrap()
            .unwrap();
        assert_eq!(status, sync::WAIT_IO_COMPLETION);
        sync::on_cancel(p, t.tid, &wait).unwrap();
        t.state = ThreadState::Ready;
        assert_eq!(begin_apcs(p, &mut t, Some(status)), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50000);
        t.apcs.push_back((0x50200, 0x3333).into());
        t.cpu.set_gpr(3, 0xBAD);
        p.space.w32(error, 0xABCD).unwrap();
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50100);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50200);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert!(t.apcs.is_empty());
        assert_eq!(t.cpu.gpr(3), interrupted_gpr3);
        assert_eq!(p.space.u32(error).unwrap(), 0xABCD);
        assert_eq!(t.frames.len(), 1, "the interrupted native frame survives");
        let wake = t.wait_status.take().unwrap();
        assert_eq!(dispatch::wait_complete(p, &mut t, wake), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
}

fn deliver_pending(p: &mut Proc, t: &mut Thread) {
    let ThreadState::Waiting(wait) = t.state.clone() else {
        panic!("no suspended native alert frame")
    };
    let status = sync::poll(p, t.tid, &wait, Instant::now(), !t.apcs.is_empty())
        .unwrap()
        .unwrap();
    assert_eq!(status, sync::WAIT_IO_COMPLETION);
    sync::on_cancel(p, t.tid, &wait).unwrap();
    t.state = ThreadState::Ready;
    assert_eq!(begin_apcs(p, t, Some(status)), Outcome::Continue);
}

#[test]
fn native_test_alert_nested_check_drains_remaining_queue_and_keeps_both_continuations_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtTestAlert", SERVICE);
        let p = process.state_mut();
        let caller_sp = t.cpu.sp();
        t.apcs.extend(
            [(0x50000, 0x1111), (0x50100, 0x2222)]
                .into_iter()
                .map(UserApc::from),
        );
        assert_eq!(call(p, &mut t), Outcome::Park);
        deliver_pending(p, &mut t);
        assert_eq!(t.cpu.pc(), 0x50000);
        assert_eq!(t.frames.len(), 2);
        let callback_sp = t.cpu.sp();
        assert_eq!(call(p, &mut t), Outcome::Park);
        deliver_pending(p, &mut t);
        assert_eq!(t.cpu.pc(), 0x50100);
        assert_eq!(t.frames.len(), 4);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert!(t.apcs.is_empty());
        assert_eq!(t.frames.len(), 3);
        let nested = t.wait_status.take().unwrap();
        assert_eq!(
            dispatch::wait_complete(p, &mut t, nested),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(t.frames.len(), 2);
        assert_eq!(
            t.cpu.sp(),
            callback_sp + if arch == WinArch::X86 { 4 } else { 0 }
        );
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.frames.len(), 1);
        let outer = t.wait_status.take().unwrap();
        assert_eq!(dispatch::wait_complete(p, &mut t, outer), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(
            t.cpu.sp(),
            caller_sp + if arch == WinArch::X86 { 4 } else { 0 }
        );
        assert!(t.frames.is_empty());
    }
}

fn callback_argument(p: &Proc, t: &Thread) -> u64 {
    match p.arch {
        WinArch::Arm64 => t.cpu.gpr(0),
        WinArch::X64 => t.cpu.gpr(1),
        WinArch::X86 => u64::from(p.space.u32(t.cpu.sp() + 4).unwrap()),
    }
}

fn finish_delivery(
    p: &mut Proc,
    t: &mut Thread,
    case: u64,
    phase: u64,
    seen: &mut Vec<(u64, u64, u32)>,
) {
    let error = t.teb + crate::user::windows::layout::offsets(p.arch).teb_last_error;
    deliver_pending(p, t);
    loop {
        let argument = callback_argument(p, t);
        seen.push((argument, phase, p.space.u32(error).unwrap()));
        if case == 5 && argument == 0x1111 {
            t.apcs.push_back((0x50200, 0x3333).into());
        }
        if case == 6 && argument == 0x1111 {
            assert_eq!(call(p, t), Outcome::Park);
            finish_delivery(p, t, 0, 6, seen);
            assert_eq!(t.cpu.gpr(0), 0);
        }
        if argument == 0x4444 {
            p.space.w32(error, 0xABCD).unwrap();
        }
        assert_eq!(dispatch::callback_return(p, t), Outcome::Continue);
        if let Some(wake) = t.wait_status.take() {
            assert_eq!(dispatch::wait_complete(p, t, wake), Outcome::Continue);
            break;
        }
    }
}

#[test]
fn native_test_alert_replays_152_native_checks_and_80_single_argument_callbacks_all_profiles() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-test-alert/modeled-cases.json"
    ))
    .unwrap();
    let mut checks = 0;
    let mut callbacks = 0;
    for group in corpus["groups"].as_array().unwrap() {
        let profile = group["profile"].as_str().unwrap();
        let arch = match profile {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" | "x86-laa" => WinArch::X86,
            _ => panic!("unknown captured ABI profile"),
        };
        for case in [0u64, 1, 2, 3, 4, 5, 6, 11, 12] {
            let (mut process, mut t) = fixture(arch, "NtTestAlert", SERVICE);
            let p = process.state_mut();
            let sp = t.cpu.sp();
            let error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
            t.user_alerted = matches!(case, 1 | 2 | 11);
            if matches!(case, 3 | 4 | 5 | 6 | 11) {
                t.apcs.push_back((0x50000, 0x1111).into());
            }
            if matches!(case, 4 | 5 | 6) {
                t.apcs.push_back((0x50100, 0x2222).into());
            }
            if case == 12 {
                t.apcs.push_back((0x50000, 0x4444).into());
            }
            let mut seen = Vec::new();
            for row in group["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["case"].as_str().unwrap().parse::<u64>().unwrap() == case)
            {
                let decimal = |name: &str| row[name].as_str().unwrap().parse::<usize>().unwrap();
                let hex =
                    |name: &str| u64::from_str_radix(row[name].as_str().unwrap(), 16).unwrap();
                assert_eq!(seen.len(), decimal("before"));
                t.cpu.set_sp(sp);
                p.space.w32(error, 0xC0DE).unwrap();
                match call(p, &mut t) {
                    Outcome::Continue => {}
                    Outcome::Park => {
                        finish_delivery(p, &mut t, case, 4 + decimal("call") as u64, &mut seen);
                    }
                    value => panic!("captured alert check failed: {value:?}"),
                }
                assert_eq!(t.cpu.gpr(0), hex("status"), "{profile}/{case}/{row}");
                assert_eq!(u64::from(p.space.u32(error).unwrap()), hex("last"));
                assert_eq!(seen.len(), decimal("after"));
                assert!(t.frames.is_empty());
                checks += 1;
            }
            let expected: Vec<_> = group["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["case"].as_str().unwrap().parse::<u64>().unwrap() == case)
                .map(|row| {
                    (
                        u64::from_str_radix(row["a"].as_str().unwrap(), 16).unwrap(),
                        row["phase"].as_str().unwrap().parse::<u64>().unwrap(),
                        u32::from_str_radix(row["last"].as_str().unwrap(), 16).unwrap(),
                    )
                })
                .collect();
            assert_eq!(seen, expected, "{profile}/{case}");
            callbacks += seen.len();
        }
    }
    assert_eq!(checks, 152);
    assert_eq!(callbacks, 80);
}
