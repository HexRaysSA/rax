use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::gui::system_parameters::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::prot;
use crate::user::windows::nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOACCESS};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_INVALID_HANDLE,
};

const QUERY: u32 = 0x103d;
const CALLBACK_RETURN: u32 = 5;
const LAST_ERROR: u32 = 0x0abc_1234;
const LAST_STATUS: u32 = STATUS_INVALID_HANDLE;

fn query(
    p: &mut Proc,
    t: &mut Thread,
    action: u32,
    parameter: u32,
    output: u64,
    resume: u64,
) -> Option<Outcome> {
    arguments(p, t, [u64::from(action), u64::from(parameter), output]);
    t.cpu.set_pc(resume);
    super::super::super::super::super::services::dispatch(p, t, QUERY, resume - 4)
}

#[test]
fn selected_gui_system_parameters_replay_cold_metrics_and_warm_outputs() {
    let dispatch = super::super::super::super::super::services::dispatch;
    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut t, entry) = setup(arch);
        let p = process.state_mut();
        let index = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.win32u_services = Some((
            index,
            named_table(arch, "NtUserSystemParametersInfo", QUERY),
        ));
        let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
            unreachable!();
        };
        let mut scheme_name = [0; HIGH_CONTRAST_SCHEME_UNITS];
        scheme_name[0] = 0x41;
        std::sync::Arc::get_mut(inputs).unwrap().system_parameters = Ok(Snapshot {
            wheel_scroll_lines: 3,
            mouse_hover_time: 400,
            nonclient_metrics: [0x57; NONCLIENT_METRICS_SIZE - 4],
            high_contrast_flags: 0x7e,
            high_contrast_scheme: scheme_name,
        });
        let resume = entry + 0x4000;
        let output = entry + 0x5000;
        let scheme = entry + 0x6000;
        let error = t.teb + offsets(arch).teb_last_error;
        let status = t.teb + offsets(arch).teb_last_status;
        p.space.w32(error, LAST_ERROR).unwrap();
        p.space.w32(status, LAST_STATUS).unwrap();
        p.space
            .wr(output, &[0xa5; NONCLIENT_METRICS_SIZE + 4])
            .unwrap();
        p.space.w32(output, 496).unwrap();

        assert_eq!(
            query(p, &mut t, GET_NONCLIENT_METRICS, 500, output, resume),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.pc(), entry);
        assert_eq!(
            p.gui.threads[&t.tid].callbacks[0].completion,
            Completion::SystemParameter {
                action: GET_NONCLIENT_METRICS,
                parameter: 500,
                output,
            }
        );
        assert_eq!(p.space.u32(output + 4).unwrap(), 0xa5a5_a5a5);
        arguments(p, &mut t, [0, 0, 0]);
        assert_eq!(
            dispatch(p, &mut t, CALLBACK_RETURN, entry + 0x100),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), 1);
        assert_eq!(t.cpu.pc(), resume);
        assert_eq!(p.space.u32(output).unwrap(), 496);
        assert_eq!(
            p.space
                .bytes(output + 4, NONCLIENT_METRICS_SIZE - 4)
                .unwrap(),
            [0x57; NONCLIENT_METRICS_SIZE - 4]
        );
        assert_eq!(
            p.space.u32(output + NONCLIENT_METRICS_SIZE as u64).unwrap(),
            0xa5a5_a5a5
        );

        for (action, value) in [(GET_WHEEL_SCROLL_LINES, 3), (GET_MOUSE_HOVER_TIME, 400)] {
            assert_eq!(
                query(p, &mut t, action, 13, output + 1, resume),
                Some(Outcome::Continue)
            );
            assert_eq!(t.cpu.gpr(0), 1);
            assert_eq!(p.space.u32(output + 1).unwrap(), value);
        }
        let output = output + 4;
        let scheme = scheme + 2;
        p.space.w32(output, 7).unwrap();
        p.space.w64(output + 8, scheme).unwrap();
        p.space
            .wr(scheme, &[0xa5; HIGH_CONTRAST_SCHEME_UNITS * 2 + 4])
            .unwrap();
        assert_eq!(
            query(p, &mut t, GET_HIGH_CONTRAST, 0, output, resume),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), 1);
        assert_eq!(p.space.u32(output).unwrap(), 7);
        assert_eq!(p.space.u32(output + 4).unwrap(), 0x7e);
        assert_eq!(p.space.u64(output + 8).unwrap(), scheme);
        assert_eq!(
            p.space.wunits(scheme, HIGH_CONTRAST_SCHEME_UNITS).unwrap(),
            scheme_name
        );
        assert_eq!(
            p.space
                .u32(scheme + (HIGH_CONTRAST_SCHEME_UNITS * 2) as u64)
                .unwrap(),
            0xa5a5_a5a5
        );
        assert_eq!(p.space.u32(error).unwrap(), LAST_ERROR);
        assert_eq!(p.space.u32(status).unwrap(), LAST_STATUS);

        for (action, parameter, address, expected_error, expected_status) in [
            (
                GET_NONCLIENT_METRICS,
                496,
                output,
                ERROR_INVALID_PARAMETER,
                LAST_STATUS,
            ),
            (
                GET_NONCLIENT_METRICS,
                500,
                output + 1,
                ERROR_NOACCESS,
                STATUS_DATATYPE_MISALIGNMENT,
            ),
            (
                GET_HIGH_CONTRAST,
                0,
                output + 1,
                ERROR_NOACCESS,
                STATUS_DATATYPE_MISALIGNMENT,
            ),
            (
                GET_MOUSE_HOVER_TIME,
                0,
                0,
                ERROR_NOACCESS,
                STATUS_ACCESS_VIOLATION,
            ),
        ] {
            p.space.w32(error, LAST_ERROR).unwrap();
            p.space.w32(status, LAST_STATUS).unwrap();
            assert_eq!(
                query(p, &mut t, action, parameter, address, resume),
                Some(Outcome::Continue)
            );
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(error).unwrap(), expected_error);
            assert_eq!(p.space.u32(status).unwrap(), expected_status);
        }

        let size_page = entry + 7 * PAGE_SIZE;
        let body_page = size_page + PAGE_SIZE;
        let metrics = body_page - 4;
        let parameter = NONCLIENT_METRICS_SIZE as u32;
        let untouched = [0xa5; NONCLIENT_METRICS_SIZE - 4];
        p.space.w32(metrics, parameter).unwrap();
        p.space.wr(body_page, &untouched).unwrap();
        p.vm.protect(size_page, PAGE_SIZE, prot::READONLY).unwrap();
        assert_eq!(
            query(p, &mut t, GET_NONCLIENT_METRICS, parameter, metrics, resume),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(p.space.u32(error).unwrap(), ERROR_NOACCESS);
        assert_eq!(p.space.u32(status).unwrap(), STATUS_ACCESS_VIOLATION);
        assert_eq!(p.space.u32(metrics).unwrap(), parameter);
        assert_eq!(
            p.space.bytes(body_page, untouched.len()).unwrap(),
            untouched
        );

        p.vm.protect(size_page, PAGE_SIZE, prot::READWRITE).unwrap();
        p.vm.protect(body_page, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        assert_eq!(
            query(p, &mut t, GET_NONCLIENT_METRICS, parameter, metrics, resume),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(p.space.u32(error).unwrap(), STATUS_GUARD_PAGE_VIOLATION);
        assert_eq!(p.space.u32(status).unwrap(), STATUS_GUARD_PAGE_VIOLATION);
        assert_eq!(p.space.u32(metrics).unwrap(), parameter);
        assert_eq!(
            p.space.bytes(body_page, untouched.len()).unwrap(),
            untouched
        );
        assert_eq!(
            query(p, &mut t, GET_NONCLIENT_METRICS, parameter, metrics, resume),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), 1);
        assert_eq!(p.space.u32(metrics).unwrap(), parameter);
        assert_eq!(
            p.space.bytes(body_page, untouched.len()).unwrap(),
            [0x57; NONCLIENT_METRICS_SIZE - 4]
        );

        p.space.w64(output + 8, 0).unwrap();
        p.space.w32(output + 4, 0xa5a5_a5a5).unwrap();
        assert_eq!(
            query(p, &mut t, GET_HIGH_CONTRAST, 16, output, resume),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(p.space.u32(error).unwrap(), ERROR_NOACCESS);
        assert_eq!(p.space.u32(status).unwrap(), STATUS_ACCESS_VIOLATION);
        assert_eq!(p.space.u32(output + 4).unwrap(), 0xa5a5_a5a5);
        assert!(matches!(
            query(p, &mut t, 0x69, 0, output, resume),
            Some(Outcome::Fail(reason)) if reason.contains("action 0x69")
        ));
        assert!(p.gui.threads[&t.tid].callbacks.is_empty());
    }
}
