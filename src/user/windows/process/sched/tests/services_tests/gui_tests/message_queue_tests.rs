use super::super::super::super::super::{services, thread};
use super::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::process::ThreadState;
use crate::user::windows::sync::{self, Wait};

const RETURN: u64 = 0x5000_4000;
const FIRST: u64 = 0x813b;
const SECOND: u64 = 0x813c;
const WORD: u64 = 0x0123_4567_89ab_cdef;
const DATA: u64 = 0xfedc_ba98_7654_3210;

fn invoke<const N: usize>(p: &mut Proc, t: &mut Thread, name: &str, args: [u64; N]) -> Outcome {
    let index = p.modules.nt_services.as_ref().unwrap().0;
    let number = 0x1090;
    p.modules.win32u_services = Some((index, named_table(p.arch, name, number)));
    let sp = t.cpu.sp();
    for (slot, value) in args.into_iter().enumerate() {
        if p.arch == WinArch::Arm64 {
            t.cpu.set_gpr(slot, value);
        } else if let Some(&register) = [10, 2, 8, 9].get(slot) {
            t.cpu.set_gpr(register, value);
        } else {
            p.space
                .w64(sp + 0x28 + 8 * (slot as u64 - 4), value)
                .unwrap();
        }
    }
    t.cpu.set_pc(RETURN);
    let mut result = services::dispatch(p, t, number, RETURN - 4).unwrap();
    if p.gui
        .threads
        .get(&t.tid)
        .is_some_and(|thread| !thread.callbacks.is_empty())
    {
        arguments(p, t, [0, 0, 0]);
        result = services::dispatch(p, t, 5, RETURN - 0x100).unwrap();
    }
    assert_eq!(t.cpu.pc(), RETURN, "{name}");
    assert_eq!(t.cpu.sp(), sp, "{name}");
    result
}

fn value<const N: usize>(p: &mut Proc, t: &mut Thread, name: &str, args: [u64; N]) -> u64 {
    assert_eq!(invoke(p, t, name, args), Outcome::Continue, "{name}");
    t.cpu.gpr(0)
}

#[test]
fn posted_message_selects_removal_sources_and_native_fault_order() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        t.cpu.set_sp(base + 0xe000);
        let tid = u64::from(t.tid);
        let output = base + 0x5000;
        let error = t.teb + offsets(arch).teb_last_error;
        let status = t.teb + offsets(arch).teb_last_status;
        p.space.wr(output, &[0xa5; 48]).unwrap();
        p.space.w32(error, 0x5aa5).unwrap();
        p.space.w32(status, 0xc000_0034).unwrap();
        let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
            unreachable!();
        };
        std::sync::Arc::get_mut(inputs).unwrap().message_cursor = [-11, 141];
        assert_eq!(value(p, &mut t, "NtUserPeekMessage", [0, 0, 0, 0, 1]), 0);
        assert_eq!(p.space.u32(error).unwrap(), 0x5aa5);
        assert_eq!(
            value(
                p,
                &mut t,
                "NtUserPostThreadMessage",
                [tid | 1, FIRST, WORD, DATA]
            ),
            0
        );
        assert_eq!(p.space.u32(error).unwrap(), 1444);
        assert_eq!(p.space.u32(status).unwrap(), 0xc000_0034);
        assert_eq!(
            value(
                p,
                &mut t,
                "NtUserPostThreadMessage",
                [tid, FIRST, WORD, DATA]
            ),
            1
        );
        assert_eq!(
            value(
                p,
                &mut t,
                "NtUserPostThreadMessage",
                [tid, SECOND, DATA, WORD]
            ),
            1
        );
        assert_eq!(
            value(
                p,
                &mut t,
                "NtUserPostQuitMessage",
                [u64::from(u32::MAX - 1)]
            ),
            0
        );
        assert_eq!(
            value(
                p,
                &mut t,
                "NtUserPeekMessage",
                [output, 0, 0x813d, 0x813d, 1]
            ),
            0
        );
        assert_eq!(p.space.bytes(output, 48).unwrap(), [0xa5; 48]);
        assert_eq!(
            value(
                p,
                &mut t,
                "NtUserPeekMessage",
                [output, 0, SECOND, SECOND, 0x10001]
            ),
            0
        );
        assert_eq!(
            value(
                p,
                &mut t,
                "NtUserPeekMessage",
                [output, u64::MAX, SECOND, SECOND, 0]
            ),
            1
        );
        assert_eq!(p.space.u64(output).unwrap(), 0);
        assert_eq!(p.space.u64(output + 8).unwrap(), SECOND);
        assert_eq!(p.space.u64(output + 16).unwrap(), DATA);
        assert_eq!(p.space.u64(output + 24).unwrap(), WORD);
        assert_eq!(p.space.u32(output + 36).unwrap() as i32, -11);
        assert_eq!(p.space.u32(output + 40).unwrap(), 141);
        assert_eq!(p.space.u32(output + 44).unwrap(), 0);
        assert_eq!(
            value(p, &mut t, "NtUserPeekMessage", [0, 0, SECOND, SECOND, 1]),
            0
        );
        assert_eq!(p.space.u32(error).unwrap(), 998);
        assert_eq!(p.space.u32(status).unwrap(), 0xc000_0005);
        assert_eq!(
            value(
                p,
                &mut t,
                "NtUserPeekMessage",
                [output, 0, SECOND, SECOND, 1]
            ),
            0
        );
        assert_eq!(
            value(p, &mut t, "NtUserGetMessage", [output, 0, FIRST, FIRST]),
            1
        );
        assert_eq!(p.space.u32(output + 8).unwrap(), FIRST as u32);
        assert_eq!(
            value(p, &mut t, "NtUserGetMessage", [output, 0, SECOND, SECOND]),
            0
        );
        assert_eq!(p.space.u32(output + 8).unwrap(), 0x12);
        assert_eq!(p.space.u64(output + 16).unwrap(), 0xffff_fffe);
        assert_eq!(
            value(p, &mut t, "NtUserPeekMessage", [output, 0, 0, 0, 1]),
            0
        );
    }
}

#[test]
fn native_get_message_waits_for_selected_peer_post_and_copies_on_resume() {
    let (mut process, mut receiver, base) = setup(WinArch::Arm64);
    let p = process.state_mut();
    let output = base + 0x5000;
    let tid = receiver.tid;
    let peer_tid = thread::create(p, base + 0x2500, 0, 0x10000, false).unwrap();
    let mut peer = p.threads.remove(&peer_tid).unwrap();
    p.space.wr(output, &[0xa5; 48]).unwrap();
    assert_eq!(
        invoke(
            p,
            &mut receiver,
            "NtUserGetMessage",
            [output, 0, SECOND, SECOND]
        ),
        Outcome::Park
    );
    let ThreadState::Waiting(wait) = &receiver.state else {
        panic!("native receiver is not parked");
    };
    let wait = wait.clone();
    let Wait::PostedMessage {
        output,
        minimum,
        maximum,
    } = wait
    else {
        panic!("native receiver lost its message filter");
    };
    assert_eq!(p.space.bytes(output, 48).unwrap(), [0xa5; 48]);
    assert_eq!(sync::poll(p, tid, &wait, Instant::now(), false), Ok(None));
    assert_eq!(
        value(
            p,
            &mut peer,
            "NtUserPostThreadMessage",
            [u64::from(tid), FIRST, WORD, DATA]
        ),
        1
    );
    assert_eq!(sync::poll(p, tid, &wait, Instant::now(), false), Ok(None));
    assert_eq!(
        value(
            p,
            &mut peer,
            "NtUserPostThreadMessage",
            [u64::from(tid), SECOND, DATA, WORD]
        ),
        1
    );
    assert_eq!(
        sync::poll(p, tid, &wait, Instant::now(), false),
        Ok(Some(0))
    );
    sync::on_cancel(p, tid, &wait).unwrap();
    receiver.state = ThreadState::Ready;
    assert_eq!(
        services::resume_posted_message(p, &mut receiver, output, minimum, maximum),
        Outcome::Continue
    );
    assert_eq!(receiver.cpu.pc(), RETURN);
    assert_eq!(receiver.cpu.gpr(0), 1);
    assert_eq!(p.space.u32(output + 8).unwrap(), SECOND as u32);
    assert_eq!(p.space.u64(output + 16).unwrap(), DATA);
    assert_eq!(
        value(p, &mut receiver, "NtUserPeekMessage", [output, 0, 0, 0, 1]),
        1
    );
    assert_eq!(p.space.u32(output + 8).unwrap(), FIRST as u32);
}
