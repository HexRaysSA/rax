use super::super::super::super::super::services::dispatch;
use super::*;

fn select(p: &mut Proc, arch: WinArch) {
    let index = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.win32u_services = Some((index, named_table(arch, "NtUserRegisterLPK", 0x1513)));
}

#[test]
fn lpk_registration_commits_full_dword_only_after_successful_cold_conversion() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        for value in [0, 0xf, u32::MAX] {
            for status in [0, 0x103, 0x8000_0001, 0xc000_0001] {
                let (mut process, mut t, entry) = setup(arch);
                let p = process.state_mut();
                select(p, arch);
                let resume = entry + 0x4000;
                t.cpu.set_pc(resume);
                let sp = t.cpu.sp();
                let offset = crate::user::windows::layout::offsets(arch);
                p.space
                    .w32(t.teb + offset.teb_last_error, 0x1234_5678)
                    .unwrap();
                p.space
                    .w32(t.teb + offset.teb_last_status, 0xc123_abcd)
                    .unwrap();
                arguments(p, &mut t, [0x1234_5678_0000_0000 | u64::from(value), 0, 0]);
                assert_eq!(
                    dispatch(p, &mut t, 0x1513, resume - 4),
                    Some(Outcome::Continue)
                );
                assert_eq!(p.gui.lpk_registration, None);
                assert_eq!(
                    p.gui.threads[&t.tid].callbacks[0].completion,
                    Completion::RegisterLpk(value)
                );
                arguments(p, &mut t, [1, u64::from(u32::MAX), status]);
                assert_eq!(
                    dispatch(p, &mut t, 5, entry + 0x100),
                    Some(Outcome::Continue)
                );
                let success = status as u32 as i32 >= 0;
                assert_eq!(t.cpu.gpr(0), u64::from(success));
                assert_eq!(p.gui.lpk_registration, success.then_some(value));
                assert_eq!(t.cpu.pc(), resume);
                assert_eq!(t.cpu.sp(), sp);
                assert_eq!(
                    p.space.u32(t.teb + offset.teb_last_error).unwrap(),
                    0x1234_5678
                );
                assert_eq!(
                    p.space.u32(t.teb + offset.teb_last_status).unwrap(),
                    0xc123_abcd
                );
            }
        }
    }
}

#[test]
fn lpk_registration_in_pending_callback_preserves_outer_operation_and_commit_order() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        for outer_lpk in [false, true] {
            for status in [0, 0xc000_0001] {
                let (mut process, mut t, entry) = setup(arch);
                let p = process.state_mut();
                let resume = entry + 0x4000;
                t.cpu.set_pc(resume);
                if outer_lpk {
                    select(p, arch);
                }
                arguments(p, &mut t, [0x1357_2468, 0, 0]);
                assert_eq!(
                    dispatch(
                        p,
                        &mut t,
                        if outer_lpk { 0x1513 } else { 0x12fd },
                        resume - 4
                    ),
                    Some(Outcome::Continue)
                );
                let original = p.gui.threads[&t.tid].callbacks[0].completion;
                let sp = t.cpu.sp();
                let rng = p.rng;
                let handles = p.objects.handle_count();
                let committed = p.vm.committed_bytes();
                select(p, arch);
                for value in [u32::MAX, 0xf, 0] {
                    arguments(p, &mut t, [u64::from(value), 0, 0]);
                    assert_eq!(
                        dispatch(p, &mut t, 0x1513, entry + 0x200),
                        Some(Outcome::Continue)
                    );
                    assert_eq!(t.cpu.gpr(0), 1);
                    assert_eq!(p.gui.lpk_registration, Some(value));
                    assert_eq!(p.gui.threads[&t.tid].callbacks.len(), 1);
                    assert_eq!(p.gui.threads[&t.tid].callbacks[0].completion, original);
                    assert_eq!(t.cpu.sp(), sp);
                    assert_eq!(p.rng, rng);
                    assert_eq!(p.objects.handle_count(), handles);
                    assert_eq!(p.vm.committed_bytes(), committed);
                }
                arguments(p, &mut t, [1, u64::from(u32::MAX), status]);
                assert_eq!(
                    dispatch(p, &mut t, 5, entry + 0x100),
                    Some(Outcome::Continue)
                );
                let success = status as u32 as i32 >= 0;
                assert_eq!(
                    p.gui.lpk_registration,
                    Some(if outer_lpk && success { 0x1357_2468 } else { 0 })
                );
                let expected = match original {
                    Completion::Value(value) => value,
                    Completion::RegisterLpk(_) => 1,
                    _ => unreachable!("selected outer operation"),
                };
                assert_eq!(t.cpu.gpr(0), if success { expected } else { 0 });
                assert_eq!(t.cpu.pc(), resume);
                assert!(p.gui.threads[&t.tid].callbacks.is_empty());
            }
        }
    }
}

#[test]
fn lpk_unavailable_inputs_and_overflowing_x86_argument_do_not_register() {
    for arch in WinArch::ALL {
        let (mut process, mut t, entry) = setup(arch);
        let p = process.state_mut();
        select(p, arch);
        p.native.as_mut().unwrap().gui = Availability::Unavailable("controlled absence".into());
        arguments(p, &mut t, [0xf, 0, 0]);
        let rng = p.rng;
        let committed = p.vm.committed_bytes();
        let handles = p.objects.handle_count();
        assert!(
            matches!(dispatch(p, &mut t, 0x1513, entry + 4), Some(Outcome::Fail(reason)) if reason.contains("controlled absence"))
        );
        assert_eq!(p.gui.lpk_registration, None);
        assert!(p.gui.threads.is_empty());
        assert_eq!(p.rng, rng);
        assert_eq!(p.vm.committed_bytes(), committed);
        assert_eq!(p.objects.handle_count(), handles);
        if arch == WinArch::X86 {
            t.cpu.set_sp(u64::MAX);
            assert!(
                matches!(dispatch(p, &mut t, 0x1513, entry + 4), Some(Outcome::Fail(reason)) if reason.contains("argument capture is unreadable"))
            );
            assert_eq!(p.gui.lpk_registration, None);
        }
    }
}
