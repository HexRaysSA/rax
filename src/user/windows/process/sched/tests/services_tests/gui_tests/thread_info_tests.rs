use super::super::super::super::super::services::dispatch;
use super::*;

#[test]
fn keyboard_layout_query_uses_converted_threads_and_preserves_teb_status() {
    use super::super::super::super::super::thread;

    const LAYOUT: u64 = 0x0000_0000_e002_0404;
    const ERROR: u32 = 0x5aa5;
    const STATUS: u32 = 0xc000_0034;

    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut caller, entry) = setup(arch);
        let p = process.state_mut();
        let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
            unreachable!("fixture selects GUI inputs");
        };
        std::sync::Arc::get_mut(inputs).unwrap().keyboard_layout =
            std::num::NonZeroU64::new(LAYOUT);
        let peer_tid = thread::create(p, entry + 0x2500, 0, 0x10000, false).unwrap();
        let number = 0x106b;
        let index = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.win32u_services =
            Some((index, named_table(arch, "NtUserGetKeyboardLayout", number)));
        let resume = entry + 0x4000;
        let offsets = crate::user::windows::layout::offsets(arch);

        let invoke = |p: &mut Proc, t: &mut Thread, tid: u32| {
            let error = t.teb + offsets.teb_last_error;
            let status = t.teb + offsets.teb_last_status;
            p.space.w32(error, ERROR).unwrap();
            p.space.w32(status, STATUS).unwrap();
            t.cpu.set_pc(resume);
            let sp = t.cpu.sp();
            arguments(p, t, [u64::from(tid), 0, 0]);
            assert_eq!(dispatch(p, t, number, resume - 4), Some(Outcome::Continue));
            if t.cpu.pc() != resume {
                assert_eq!(t.cpu.pc(), entry);
                assert_eq!(
                    p.gui.threads[&t.tid].callbacks[0].completion,
                    Completion::GetKeyboardLayout([u64::from(tid)])
                );
                arguments(p, t, [0, 0, 0]);
                assert_eq!(dispatch(p, t, 5, entry + 0x100), Some(Outcome::Continue));
            }
            assert_eq!(t.cpu.pc(), resume);
            assert_eq!(t.cpu.sp(), sp);
            assert_eq!(p.space.u32(error).unwrap(), ERROR);
            assert_eq!(p.space.u32(status).unwrap(), STATUS);
            t.cpu.gpr(0)
        };

        let own = caller.tid;
        for (target, expected) in [
            (0, LAYOUT),
            (own, LAYOUT),
            (own | 1, 0),
            (peer_tid, 0),
            (u32::MAX, 0),
        ] {
            assert_eq!(invoke(p, &mut caller, target), expected);
        }
        let mut peer = p.threads.remove(&peer_tid).unwrap();
        assert_eq!(invoke(p, &mut peer, 0), LAYOUT);
        p.threads.insert(peer_tid, peer);
        assert_eq!(invoke(p, &mut caller, peer_tid), LAYOUT);
        assert_eq!(invoke(p, &mut caller, peer_tid | 1), 0);
        p.gui.retire_thread(peer_tid);
        assert_eq!(invoke(p, &mut caller, peer_tid), 0);
    }
}

#[test]
fn gui_thread_information_preserves_native_precedence_and_output() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut t, entry) = setup(arch);
        let p = process.state_mut();
        let pc = entry + 0x4000;
        let number = 0x10eb;
        let index = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.win32u_services =
            Some((index, named_table(arch, "NtUserGetGUIThreadInfo", number)));
        let output = entry + 0x5000;
        let own = u64::from(t.tid);
        let layout = crate::user::windows::layout::offsets(arch);
        let error = t.teb + layout.teb_last_error;
        let status = t.teb + layout.teb_last_status;
        let sp = t.cpu.sp();
        t.cpu.set_pc(pc);
        p.space.wr(output, &[0xa5; 80]).unwrap();
        p.space.w32(output, 72).unwrap();
        arguments(p, &mut t, [own, output, 0]);
        assert_eq!(dispatch(p, &mut t, number, pc - 4), Some(Outcome::Continue));
        assert_eq!(t.cpu.pc(), entry);
        assert_eq!(
            p.gui.threads[&t.tid].callbacks[0].completion,
            Completion::QueryGuiThread([own, output])
        );
        arguments(p, &mut t, [0, 0, 0]);
        assert_eq!(
            dispatch(p, &mut t, 5, entry + 0x100),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), 1);
        assert_eq!(t.cpu.pc(), pc);
        assert_eq!(t.cpu.sp(), sp);
        assert_eq!(p.space.u32(output).unwrap(), 72);
        assert_eq!(p.space.bytes(output + 4, 68).unwrap(), [0; 68]);
        assert_eq!(p.space.u64(output + 72).unwrap(), 0xa5a5_a5a5_a5a5_a5a5);
        assert!(p.gui.threads[&t.tid].initialized);

        for (target, addr, size, expected_error, expected_status) in [
            (own, output, 64, 87, 0xc000_0034),
            (own, output + 2, 72, 998, 0x8000_0002),
            (own, 0, 72, 998, 0xc000_0005),
            (own | 1, 0, 72, 87, 0xc000_0034),
            (0, output, 72, 5, 0xc000_0034),
            (0, output, 64, 87, 0xc000_0034),
        ] {
            p.space.w32(error, 0x5aa5).unwrap();
            p.space.w32(status, 0xc000_0034).unwrap();
            p.space.wr(output, &[0xa5; 80]).unwrap();
            if addr != 0 {
                p.space.w32(addr, size).unwrap();
            }
            let before = p.space.bytes(output, 80).unwrap();
            arguments(p, &mut t, [target, addr, 0]);
            assert_eq!(dispatch(p, &mut t, number, pc - 4), Some(Outcome::Continue));
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(error).unwrap(), expected_error);
            assert_eq!(p.space.u32(status).unwrap(), expected_status);
            assert_eq!(p.space.bytes(output, 80).unwrap(), before);
        }
    }
}
