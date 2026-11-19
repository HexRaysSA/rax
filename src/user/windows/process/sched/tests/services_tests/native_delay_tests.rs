//! Native delay capture, scheduler eligibility and alertable completion.
use super::event_tests::setup;
use super::*;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_ALERTED, STATUS_DATATYPE_MISALIGNMENT,
    STATUS_NO_YIELD_PERFORMED, STATUS_SUCCESS, STATUS_USER_APC,
};

const SERVICE: u32 = 0x34;
const RETURN_PC: u64 = 0x1234_0004;

fn call(p: &mut Proc, t: &mut Thread, alertable: u32, interval: u64) -> Outcome {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, "NtDelayExecution", SERVICE)));
    t.cpu.set_pc(RETURN_PC);
    let sp = t.cpu.sp();
    match p.arch {
        WinArch::X86 => {
            for (slot, value) in [RETURN_PC as u32, 0x1234_0000, alertable, interval as u32]
                .into_iter()
                .enumerate()
            {
                p.space.w32(sp + slot as u64 * 4, value).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
            super::super::super::super::services::wow64(p, t, RETURN_PC - 4)
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, RETURN_PC);
            t.cpu.set_gpr(10, alertable.into());
            t.cpu.set_gpr(2, interval);
            handle_stop(p, t, stop(p.arch, SERVICE))
        }
        WinArch::Arm64 => {
            t.cpu.set_gpr(0, alertable.into());
            t.cpu.set_gpr(1, interval);
            handle_stop(p, t, stop(p.arch, SERVICE))
        }
    }
}

#[test]
fn native_delay_validates_before_consuming_alert_and_yields_only_to_eligible_peers() {
    for arch in WinArch::ALL {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        t.attached = true;
        let last_error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0x5aa5).unwrap();
        p.space.w64(data + 4, 0).unwrap();
        t.user_alerted = true;
        for (alertable, interval, status, alert_pending) in [
            (1, 1, STATUS_DATATYPE_MISALIGNMENT, true),
            (1, 0, STATUS_ACCESS_VIOLATION, true),
            (0x100, data + 4, STATUS_NO_YIELD_PERFORMED, true),
            (0xff, data + 4, STATUS_ALERTED, false),
            (1, data + 4, STATUS_NO_YIELD_PERFORMED, false),
        ] {
            let sp = t.cpu.sp();
            assert_eq!(call(p, &mut t, alertable, interval), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(status));
            assert_eq!(t.cpu.pc(), RETURN_PC);
            assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
            assert_eq!(p.space.u32(last_error).unwrap(), 0x5aa5);
            assert_eq!(t.user_alerted, alert_pending);
        }
        let peer = thread::create(p, data + 0x200, 0, 0x10000, false).unwrap();
        assert_eq!(call(p, &mut t, 0, data + 4), Outcome::Yield);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_SUCCESS));
        p.threads.get_mut(&peer).unwrap().suspend = 1;
        assert_eq!(call(p, &mut t, 0, data + 4), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_NO_YIELD_PERFORMED));
    }
}

#[test]
fn native_delay_retains_both_clock_domains_and_resumes_with_apc_status() {
    for arch in WinArch::ALL {
        for ticks in [0, 1, i64::MIN, i64::MAX] {
            let (mut process, mut t, data) = setup(arch);
            let p = process.state_mut();
            p.space.w64(data, ticks as u64).unwrap();
            assert_eq!(
                call(p, &mut t, 1, data),
                if ticks == 0 || ticks == 1 {
                    Outcome::Continue
                } else {
                    Outcome::Park
                }
            );
            if ticks == 0 {
                assert_eq!(t.cpu.gpr(0), u64::from(STATUS_NO_YIELD_PERFORMED));
            } else if ticks == 1 {
                assert_eq!(t.cpu.gpr(0), u64::from(STATUS_SUCCESS));
            } else {
                let ThreadState::Waiting(
                    wait @ sync::Wait::NativeDelay {
                        alertable: true, ..
                    },
                ) = t.state.clone()
                else {
                    panic!("native delay did not capture its deadline");
                };
                // Changing the input after entry must not end the wait.
                p.space.w64(data, 0).unwrap();
                assert_eq!(sync::poll(p, t.tid, &wait, Instant::now(), false), Ok(None));
                sync::on_cancel(p, t.tid, &wait).unwrap();
            }
        }

        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        p.space.w64(data, 0).unwrap();
        t.apcs.push_back((0x50000, 0x1111).into());
        assert_eq!(call(p, &mut t, 1, data), Outcome::Park);
        let ThreadState::Waiting(wait) = t.state.clone() else {
            panic!("missing alertable native delay");
        };
        let status = sync::poll(p, t.tid, &wait, Instant::now(), true)
            .unwrap()
            .unwrap();
        assert_eq!(status, u64::from(STATUS_USER_APC));
        sync::on_cancel(p, t.tid, &wait).unwrap();
        t.state = ThreadState::Ready;
        assert_eq!(begin_apcs(p, &mut t, Some(status)), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50000);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        let wake = t.wait_status.take().unwrap();
        assert_eq!(dispatch::wait_complete(p, &mut t, wake), Outcome::Continue);
        assert_eq!(t.cpu.pc(), RETURN_PC);
        assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_USER_APC));
    }
}
