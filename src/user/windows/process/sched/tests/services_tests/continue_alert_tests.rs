//! Alertable context replacement uses the supplied target before APC delivery.
use super::*;
use crate::user::windows::process::thread::UserApc;
use crate::user::windows::{context::RegContext, layout};

const SERVICE: u32 = 0x78;

fn target(p: &mut Proc, t: &mut Thread) -> (u64, RegContext) {
    let address =
        p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let mut context = RegContext::capture(&t.cpu);
    context.set_pc(0x4567_0000);
    context.set_sp((t.cpu.sp() - 512) & !15);
    context.set_gpr(0, 0x1234_5678);
    context.set_gpr(3, 0xCC55);
    assert_eq!(context.validate(&t.cpu), Ok(()));
    context.write(&p.space, address).unwrap();
    (address, context)
}

fn call(p: &mut Proc, t: &mut Thread, address: u64, test: u32) -> Outcome {
    service_call(p, t, SERVICE, address, test)
}

fn service_call(p: &mut Proc, t: &mut Thread, number: u32, address: u64, test: u32) -> Outcome {
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            let sp = t.cpu.sp();
            for (index, value) in [0x1234_0004, 0x1234_0000, address as u32, test]
                .into_iter()
                .enumerate()
            {
                p.space.w32(sp + index as u64 * 4, value).unwrap();
            }
            t.cpu.set_gpr(0, number.into());
            super::super::super::super::services::wow64(p, t, 0x1234_0000)
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, number.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            t.cpu.set_gpr(10, address);
            t.cpu.set_gpr(2, test.into());
            handle_stop(p, t, stop(p.arch, number))
        }
        WinArch::Arm64 => {
            t.cpu.set_gpr(0, address);
            t.cpu.set_gpr(1, test.into());
            handle_stop(p, t, stop(p.arch, number))
        }
    }
}

#[test]
fn native_continue_alert_empty_resume_restores_target_without_fabricated_status_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
        let p = process.state_mut();
        let (address, expected) = target(p, &mut t);
        assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
        assert_eq!(t.cpu.pc(), expected.pc());
        assert_eq!(t.cpu.sp(), expected.sp());
        assert_eq!(t.cpu.gpr(0), 0x1234_5678);
        assert_eq!(t.cpu.gpr(3), 0xCC55);
        assert!(t.frames.is_empty());
        assert!(t.wait_status.is_none());
    }
}

#[test]
fn native_continue_alert_pending_apcs_capture_replaced_context_and_resume_it_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
        let p = process.state_mut();
        let (address, expected) = target(p, &mut t);
        let error = t.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(error, 0xC0DE).unwrap();
        t.apcs.extend(
            [(0x50000, 0x1111), (0x50100, 0x2222)]
                .into_iter()
                .map(UserApc::from),
        );
        assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50000);
        assert_eq!(t.frames.len(), 1);
        assert_eq!(t.apcs.len(), 1);
        assert!(t.cpu.sp() < expected.sp());
        t.cpu.set_gpr(3, 0xBAD);
        p.space.w32(error, 0xABCD).unwrap();
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50100);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.pc(), expected.pc());
        assert_eq!(t.cpu.sp(), expected.sp());
        assert_eq!(t.cpu.gpr(0), 0x1234_5678);
        assert_eq!(t.cpu.gpr(3), 0xCC55);
        assert_eq!(p.space.u32(error).unwrap(), 0xABCD);
        assert!(t.apcs.is_empty());
        assert!(t.frames.is_empty());
        assert!(t.wait_status.is_none());
    }
}

#[test]
fn native_continue_alert_consumes_existing_alert_before_callbacks_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
        let p = process.state_mut();
        let (address, expected) = target(p, &mut t);
        t.user_alerted = true;
        t.apcs.push_back((0x50000, 0x1111).into());
        assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
        assert_eq!(t.cpu.pc(), expected.pc());
        assert_eq!(t.cpu.sp(), expected.sp());
        assert_eq!(t.cpu.gpr(0), 0x1234_5678);
        assert!(!t.user_alerted);
        assert_eq!(
            t.apcs.iter().copied().collect::<Vec<_>>(),
            [(0x50000, 0x1111)].map(UserApc::from)
        );
        assert!(t.frames.is_empty());
    }
}

#[test]
fn native_continue_alert_uses_boolean_byte_and_preserves_false_pending_state_all_abis() {
    for arch in WinArch::ALL {
        for value in [0, 0x100, 0x1_0000, 1, 2, 255, 0x101, u32::MAX] {
            let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
            let p = process.state_mut();
            let (address, expected) = target(p, &mut t);
            t.user_alerted = true;
            t.apcs.push_back((0x50000, 0x1111).into());
            assert_eq!(call(p, &mut t, address, value), Outcome::Continue);
            assert_eq!(t.cpu.pc(), expected.pc());
            assert_eq!(t.cpu.sp(), expected.sp());
            assert_eq!(t.cpu.gpr(0), 0x1234_5678);
            assert_eq!(t.user_alerted, value as u8 == 0);
            assert_eq!(t.apcs.len(), 1);
            assert!(t.frames.is_empty());
            assert!(t.wait_status.is_none());
        }
    }
}

#[test]
fn native_continue_alert_invalid_context_preserves_alert_queue_and_teb_all_abis() {
    for arch in WinArch::ALL {
        for mode in 0..3 {
            let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
            let p = process.state_mut();
            let (mut address, mut context) = target(p, &mut t);
            let expected = if mode == 0 {
                address += 1;
                STATUS_INVALID_PARAMETER
            } else if mode == 1 {
                context.set_flags(RegContext::arch_flag(arch) | 0x8000);
                assert_eq!(context.validate(&t.cpu), Err(STATUS_INVALID_PARAMETER));
                context.write(&p.space, address).unwrap();
                STATUS_INVALID_PARAMETER
            } else {
                address = 0xDEAD_0000;
                STATUS_ACCESS_VIOLATION
            };
            let error = t.teb + layout::offsets(arch).teb_last_error;
            p.space.w32(error, 0xC0DE).unwrap();
            t.user_alerted = true;
            t.apcs.push_back((0x50000, 0x1111).into());
            assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(expected));
            assert_eq!(t.cpu.pc(), 0x1234_0004);
            assert!(t.user_alerted);
            assert_eq!(
                t.apcs.iter().copied().collect::<Vec<_>>(),
                [(0x50000, 0x1111)].map(UserApc::from)
            );
            assert_eq!(p.space.u32(error).unwrap(), 0xC0DE);
            assert!(t.frames.is_empty());
            assert!(t.wait_status.is_none());
        }
    }
}

fn finish_callbacks(
    p: &mut Proc,
    t: &mut Thread,
    number: u64,
    phase: u64,
    seen: &mut Vec<(u64, u64, u32)>,
) {
    let error = t.teb + layout::offsets(p.arch).teb_last_error;
    while matches!(t.cpu.pc(), 0x50000 | 0x50100 | 0x50200) {
        assert!(seen.len() < 8);
        let value = match p.arch {
            WinArch::Arm64 => t.cpu.gpr(0),
            WinArch::X64 => t.cpu.gpr(1),
            WinArch::X86 => u64::from(p.space.u32(t.cpu.sp() + 4).unwrap()),
        };
        seen.push((value, phase, p.space.u32(error).unwrap()));
        if number == 5 && value == 0x1111 {
            t.apcs.push_back((0x50200, 0x3333).into());
        }
        if value == 0x4444 {
            p.space.w32(error, 0xABCD).unwrap();
        }
        t.cpu.set_gpr(3, 0xBAD);
        assert_eq!(dispatch::callback_return(p, t), Outcome::Continue);
    }
    if let Some(status) = t.wait_status.take() {
        assert_eq!(dispatch::wait_complete(p, t, status), Outcome::Continue);
    }
}

#[test]
fn native_continue_alert_replays_52_resumes_104_post_checks_and_48_callbacks_all_profiles() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-continue/cases.json"
    ))
    .unwrap();
    let (mut resumes, mut checks, mut callbacks) = (0, 0, 0);
    for group in corpus["groups"].as_array().unwrap() {
        let profile = group["profile"].as_str().unwrap();
        let arch = match profile {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" | "x86-laa" => WinArch::X86,
            _ => panic!("unknown captured profile"),
        };
        for resume in group["resumes"].as_array().unwrap() {
            let number = resume["case"].as_str().unwrap().parse::<u64>().unwrap();
            let test = resume["test"].as_str().unwrap().parse::<u32>().unwrap();
            let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
            let p = process.state_mut();
            let (address, expected) = target(p, &mut t);
            let error = t.teb + layout::offsets(arch).teb_last_error;
            p.space.w32(error, 0xC0DE).unwrap();
            t.user_alerted = matches!(number, 6 | 7 | 8 | 12);
            if matches!(number, 2 | 3 | 4 | 5 | 6 | 8 | 9 | 10 | 11) {
                t.apcs
                    .push_back((0x50000, if number == 9 { 0x4444 } else { 0x1111 }).into());
            }
            if matches!(number, 4 | 5) {
                t.apcs.push_back((0x50100, 0x2222).into());
            }
            let mut seen = Vec::new();
            assert_eq!(call(p, &mut t, address, test), Outcome::Continue);
            finish_callbacks(p, &mut t, number, 1, &mut seen);
            assert_eq!(t.cpu.pc(), expected.pc());
            assert_eq!(t.cpu.sp(), expected.sp());
            assert_eq!(t.cpu.gpr(0), 0x1234_5678);
            assert_eq!(t.cpu.gpr(3), 0xCC55);
            assert_eq!(
                seen.len(),
                resume["seen"].as_str().unwrap().parse::<usize>().unwrap()
            );
            assert_eq!(
                p.space.u32(error).unwrap(),
                u32::from_str_radix(resume["last"].as_str().unwrap(), 16).unwrap()
            );
            assert!(t.frames.is_empty());
            resumes += 1;
            let index = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((index, table(arch, "NtTestAlert", SERVICE + 1)));
            for row in group["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["case"] == resume["case"])
            {
                let decimal = |name: &str| row[name].as_str().unwrap().parse::<usize>().unwrap();
                assert_eq!(seen.len(), decimal("before"));
                t.cpu.set_sp(expected.sp());
                p.space.w32(error, 0xC0DE).unwrap();
                match service_call(p, &mut t, SERVICE + 1, 0, 0) {
                    Outcome::Continue => (),
                    Outcome::Park => {
                        let ThreadState::Waiting(wait) = t.state.clone() else {
                            panic!("missing alert frame")
                        };
                        let status =
                            sync::poll(p, t.tid, &wait, Instant::now(), !t.apcs.is_empty())
                                .unwrap()
                                .unwrap();
                        sync::on_cancel(p, t.tid, &wait).unwrap();
                        t.state = ThreadState::Ready;
                        assert_eq!(begin_apcs(p, &mut t, Some(status)), Outcome::Continue);
                        finish_callbacks(p, &mut t, number, 3 + decimal("index") as u64, &mut seen);
                    }
                    other => panic!("post-continuation alert: {other:?}"),
                }
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from_str_radix(row["status"].as_str().unwrap(), 16).unwrap()
                );
                assert_eq!(seen.len(), decimal("after"));
                assert_eq!(
                    p.space.u32(error).unwrap(),
                    u32::from_str_radix(row["last"].as_str().unwrap(), 16).unwrap()
                );
                assert!(t.frames.is_empty());
                checks += 1;
            }
            let events: Vec<_> = group["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["case"] == resume["case"])
                .map(|r| {
                    (
                        u64::from_str_radix(r["value"].as_str().unwrap(), 16).unwrap(),
                        r["phase"].as_str().unwrap().parse::<u64>().unwrap(),
                        u32::from_str_radix(r["last"].as_str().unwrap(), 16).unwrap(),
                    )
                })
                .collect();
            assert_eq!(seen, events, "{profile}/{number}");
            callbacks += seen.len();
        }
    }
    assert_eq!((resumes, checks, callbacks), (52, 104, 48));
}

#[test]
fn native_continue_alert_hle_export_matches_native_replacement_and_queue_order_all_abis() {
    for arch in WinArch::ALL {
        for alerted in [false, true] {
            let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
            let p = process.state_mut();
            let (address, expected) = target(p, &mut t);
            let sp = expected.sp() - 128;
            t.cpu.set_sp(sp);
            t.cpu.set_pc(0x1234_0000);
            match arch {
                WinArch::X86 => {
                    for (index, value) in [0xDEAD_0000, address, 1].into_iter().enumerate() {
                        p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
                    }
                }
                WinArch::X64 => {
                    p.space.w64(sp, 0xDEAD_0000).unwrap();
                    t.cpu.set_gpr(1, address);
                    t.cpu.set_gpr(2, 1);
                }
                WinArch::Arm64 => {
                    t.cpu.set_gpr(0, address);
                    t.cpu.set_gpr(1, 1);
                    t.cpu.set_gpr(30, 0xDEAD_0000);
                }
            }
            t.apcs.push_back((0x50000, 0x1111).into());
            t.user_alerted = alerted;
            let api = crate::user::windows::dll::nt_service("NtContinue", arch).unwrap();
            assert_eq!(
                dispatch::enter(p, &mut t, api, 0x1234_0000),
                Outcome::Continue
            );
            let mut seen = Vec::new();
            finish_callbacks(p, &mut t, 0, 1, &mut seen);
            assert_eq!(seen.len(), usize::from(!alerted));
            assert!(!t.user_alerted);
            assert_eq!(t.apcs.len(), usize::from(alerted));
            assert_eq!(t.cpu.pc(), expected.pc());
            assert_eq!(t.cpu.sp(), expected.sp());
            assert_eq!(t.cpu.gpr(0), 0x1234_5678);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_continue_alert_from_callback_discards_replaced_same_height_continuation_all_abis() {
    for arch in WinArch::ALL {
        for test in [0, 1] {
            let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
            let p = process.state_mut();
            let (address, mut expected) = target(p, &mut t);
            t.apcs.extend(
                [(0x50000, 0x1111), (0x50100, 0x2222)]
                    .into_iter()
                    .map(UserApc::from),
            );
            assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
            assert_eq!(t.cpu.pc(), 0x50000);
            assert_eq!(t.frames.len(), 1);
            expected.set_pc(expected.pc() + 0x100);
            expected.set_gpr(0, 0x1234_5678);
            expected.write(&p.space, address).unwrap();
            assert_eq!(call(p, &mut t, address, test), Outcome::Continue);
            let mut seen = Vec::new();
            finish_callbacks(p, &mut t, 0, 1, &mut seen);
            assert_eq!(t.cpu.pc(), expected.pc());
            assert_eq!(t.cpu.sp(), expected.sp());
            assert_eq!(t.cpu.gpr(0), 0x1234_5678);
            assert_eq!(t.apcs.len(), usize::from(test == 0));
            assert_eq!(seen.len(), usize::from(test != 0));
            assert!(
                t.frames.is_empty(),
                "replaced APC continuation must not survive {arch}/{test}"
            );
            assert!(t.wait_status.is_none());
        }
    }
}

#[test]
fn native_continue_alert_exact_interrupted_target_discards_abandoned_apc_frame_all_abis() {
    for arch in WinArch::ALL {
        for test in [0, 1] {
            let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
            let p = process.state_mut();
            let (address, expected) = target(p, &mut t);
            t.apcs.push_back((0x50000, 0x1111).into());
            assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
            assert_eq!(t.cpu.pc(), 0x50000);
            assert_eq!(t.frames.len(), 1);
            assert_eq!(call(p, &mut t, address, test), Outcome::Continue);
            assert_eq!(t.cpu.pc(), expected.pc());
            assert_eq!(t.cpu.sp(), expected.sp());
            assert_eq!(t.cpu.gpr(0), 0x1234_5678);
            assert!(t.apcs.is_empty());
            assert!(
                t.frames.is_empty(),
                "exact interrupted PC/SP must abandon the APC owner {arch}/{test}"
            );
            assert!(t.wait_status.is_none());
        }
    }
}

#[test]
fn native_continue_alert_exact_interrupted_hle_target_discards_apc_owner_all_abis() {
    for arch in WinArch::ALL {
        for test in [0u64, 1] {
            let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
            let p = process.state_mut();
            let (address, expected) = target(p, &mut t);
            t.apcs.push_back((0x50000, 0x1111).into());
            assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
            let sp = t.cpu.sp();
            match arch {
                WinArch::X86 => {
                    for (index, value) in [0xDEAD_0000, address, test].into_iter().enumerate() {
                        p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
                    }
                }
                WinArch::X64 => {
                    p.space.w64(sp, 0xDEAD_0000).unwrap();
                    t.cpu.set_gpr(1, address);
                    t.cpu.set_gpr(2, test);
                }
                WinArch::Arm64 => {
                    t.cpu.set_gpr(0, address);
                    t.cpu.set_gpr(1, test);
                    t.cpu.set_gpr(30, 0xDEAD_0000);
                }
            }
            let api = crate::user::windows::dll::nt_service("NtContinue", arch).unwrap();
            assert_eq!(
                dispatch::enter(p, &mut t, api, 0x1234_0000),
                Outcome::Continue
            );
            assert_eq!(t.cpu.pc(), expected.pc());
            assert_eq!(t.cpu.sp(), expected.sp());
            assert_eq!(t.cpu.gpr(0), 0x1234_5678);
            assert!(
                t.frames.is_empty(),
                "HLE exact target must discard APC owner {arch}/{test}"
            );
            assert!(t.apcs.is_empty());
            assert!(t.wait_status.is_none());
        }
    }
}

#[test]
fn native_continue_alert_replays_16_exact_target_resumes_32_checks_and_28_callbacks_all_profiles() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-continue/supplement-cases.json"
    ))
    .unwrap();
    let (mut resumes, mut checks, mut callbacks) = (0, 0, 0);
    for group in corpus["groups"].as_array().unwrap() {
        let profile = group["profile"].as_str().unwrap();
        let arch = match profile {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" | "x86-laa" => WinArch::X86,
            _ => panic!("unknown native profile"),
        };
        for resume in group["resumes"].as_array().unwrap() {
            let number = resume["case"].as_str().unwrap().parse::<u64>().unwrap();
            let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
            let p = process.state_mut();
            let (address, expected) = target(p, &mut t);
            let error = t.teb + layout::offsets(arch).teb_last_error;
            p.space.w32(error, 0xC0DE).unwrap();
            t.apcs.push_back((0x50000, 0x1111).into());
            if number != 15 {
                t.apcs.push_back((0x50100, 0x2222).into());
            }
            assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
            assert_eq!(t.cpu.pc(), 0x50000);
            let mut seen = vec![(0x1111, 1, 0xC0DE)];
            if number == 16 {
                t.user_alerted = true;
            }
            let jump = group["jumps"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["case"] == resume["case"])
                .unwrap();
            let test = jump["test"].as_str().unwrap().parse::<u32>().unwrap();
            assert_eq!(call(p, &mut t, address, test), Outcome::Continue);
            finish_callbacks(p, &mut t, number, 1, &mut seen);
            assert_eq!(t.cpu.pc(), expected.pc());
            assert_eq!(t.cpu.sp(), expected.sp());
            assert_eq!(t.cpu.gpr(0), 0x1234_5678);
            assert_eq!(t.cpu.gpr(3), 0xCC55);
            assert!(t.frames.is_empty(), "{profile}/{number}");
            assert!(t.wait_status.is_none());
            assert!(!t.user_alerted);
            assert_eq!(
                seen.len(),
                resume["seen"].as_str().unwrap().parse::<usize>().unwrap()
            );
            resumes += 1;
            let index = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((index, table(arch, "NtTestAlert", SERVICE + 1)));
            for row in group["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|x| x["case"] == resume["case"])
            {
                let decimal = |name: &str| row[name].as_str().unwrap().parse::<usize>().unwrap();
                assert_eq!(seen.len(), decimal("before"));
                t.cpu.set_sp(expected.sp());
                p.space.w32(error, 0xC0DE).unwrap();
                match service_call(p, &mut t, SERVICE + 1, 0, 0) {
                    Outcome::Continue => (),
                    Outcome::Park => {
                        let ThreadState::Waiting(wait) = t.state.clone() else {
                            panic!("missing post-abandonment alert frame")
                        };
                        let status =
                            sync::poll(p, t.tid, &wait, Instant::now(), !t.apcs.is_empty())
                                .unwrap()
                                .unwrap();
                        sync::on_cancel(p, t.tid, &wait).unwrap();
                        t.state = ThreadState::Ready;
                        assert_eq!(begin_apcs(p, &mut t, Some(status)), Outcome::Continue);
                        finish_callbacks(p, &mut t, number, 3 + decimal("index") as u64, &mut seen);
                    }
                    other => panic!("post-abandonment check {other:?}"),
                }
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from_str_radix(row["status"].as_str().unwrap(), 16).unwrap()
                );
                assert_eq!(seen.len(), decimal("after"));
                assert_eq!(p.space.u32(error).unwrap(), 0xC0DE);
                assert!(t.frames.is_empty());
                checks += 1;
            }
            let events: Vec<_> = group["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|x| x["case"] == resume["case"])
                .map(|x| {
                    (
                        u64::from_str_radix(x["value"].as_str().unwrap(), 16).unwrap(),
                        x["phase"].as_str().unwrap().parse::<u64>().unwrap(),
                        u32::from_str_radix(x["last"].as_str().unwrap(), 16).unwrap(),
                    )
                })
                .collect();
            assert_eq!(seen, events, "{profile}/{number}");
            callbacks += seen.len();
        }
    }
    assert_eq!((resumes, checks, callbacks), (16, 32, 28));
}

#[test]
fn native_continue_alert_active_callback_cancellation_and_forced_exit_keep_owned_lifetimes_all_abis()
 {
    use super::super::super::{RunStatus, Scheduler};
    use std::sync::atomic::AtomicBool;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtContinue", SERVICE);
        let p = process.state_mut();
        let (address, _) = target(p, &mut t);
        t.apcs.extend(
            [(0x50000, 0x1111), (0x50100, 0x2222)]
                .into_iter()
                .map(UserApc::from),
        );
        assert_eq!(call(p, &mut t, address, 1), Outcome::Continue);
        let (tid, sp, teb, stack) = (t.tid, t.cpu.sp(), t.teb, t.thread_stack_alloc);
        assert_eq!(t.cpu.pc(), 0x50000);
        assert_eq!(t.frames.len(), 1);
        p.threads.insert(tid, t);
        let mut scheduler = Scheduler::default();
        assert_eq!(
            scheduler.run_slice(p, 1, &AtomicBool::new(true)),
            RunStatus::Cancelled
        );
        let t = &p.threads[&tid];
        assert_eq!(t.cpu.pc(), 0x50000);
        assert_eq!(t.cpu.sp(), sp);
        assert_eq!(t.frames.len(), 1);
        assert_eq!(
            t.apcs.iter().copied().collect::<Vec<_>>(),
            [(0x50100, 0x2222)].map(UserApc::from)
        );
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
