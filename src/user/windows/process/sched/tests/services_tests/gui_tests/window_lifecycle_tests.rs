use super::super::super::super::super::services::dispatch;
use super::super::secure_connect_tests::{csr, selected_namespace};
use super::*;
use crate::user::windows::gui::window_classes::{Definition, Name, RECORD_BYTES};
use crate::user::windows::gui::windows::{OVERLAPPED_STYLE, Phase};
use crate::user::windows::object_namespace::csr::{CsrServer, client_data};
use crate::user::windows::registry::Registry;
use std::sync::Arc;

const RETURN: u64 = 0x5000_4000;

fn service<const N: usize>(p: &mut Proc, t: &mut Thread, name: &str, values: [u64; N]) {
    let index = p.modules.nt_services.as_ref().unwrap().0;
    let number = 0x1090;
    p.modules.win32u_services = Some((index, named_table(WinArch::Arm64, name, number)));
    for (slot, value) in values.into_iter().enumerate() {
        if slot < 8 {
            t.cpu.set_gpr(slot, value);
        } else {
            p.space
                .w64(t.cpu.sp() + (slot as u64 - 8) * 8, value)
                .unwrap();
        }
    }
    t.cpu.set_pc(RETURN);
    assert_eq!(
        dispatch(p, t, number, RETURN - 4),
        Some(Outcome::Continue),
        "{name}",
    );
}

fn assert_top_level(p: &mut Proc, t: &mut Thread, handle: u64, result: u64, last_error: u32) {
    let offsets = crate::user::windows::layout::offsets(p.arch);
    let error = t.teb + offsets.teb_last_error;
    let status = t.teb + offsets.teb_last_status;
    p.space.w32(error, 0x4567).unwrap();
    p.space.w32(status, 0xc0000034).unwrap();
    service(p, t, "NtUserIsTopLevelWindow", [handle]);
    assert_eq!(t.cpu.gpr(0), result);
    assert_eq!(p.space.u32(error).unwrap(), last_error);
    assert_eq!(p.space.u32(status).unwrap(), 0xc0000034);
}

fn callback_return(p: &mut Proc, t: &mut Thread, output: [u64; 3]) {
    arguments(p, t, output);
    assert_eq!(dispatch(p, t, 5, RETURN + 0x100), Some(Outcome::Continue));
}

fn expect_callback(p: &Proc, t: &Thread, phase: Phase, index: u32) -> (u32, u64) {
    let callback = p.gui.threads[&t.tid].callbacks.last().unwrap();
    let Completion::ResumeWindow(continuation) = callback.completion else {
        panic!("expected a window operation callback");
    };
    assert_eq!(continuation.phase, phase);
    assert_eq!(t.cpu.sp(), callback.callback_sp);
    assert_eq!(p.space.u32(callback.callback_sp + 12).unwrap(), index);
    let view = t.teb + 0x840;
    if phase == Phase::LoadTheme {
        assert_eq!(p.space.bytes(view, 16).unwrap(), [0; 16]);
    } else {
        let window = p.gui.window(u64::from(continuation.handle)).unwrap();
        assert_eq!(p.space.u64(view).unwrap(), u64::from(continuation.handle));
        assert_eq!(p.space.u64(view + 8).unwrap(), window.client_address);
    }
    (
        continuation.handle,
        p.space.u64(callback.callback_sp).unwrap(),
    )
}

fn setup_window(
    p: &mut Proc,
    t: &mut Thread,
    base: u64,
) -> (Arc<client_data::CsrClientData>, Vec<u16>, u16) {
    t.cpu.set_sp(base + 0xe000);
    let index = p
        .modules
        .by_name("ntdll.dll")
        .unwrap_or(p.modules.nt_services.as_ref().unwrap().0);
    let bridge = base + 0x3000;
    let ntdll = &mut p.modules.list[index];
    ntdll.name = "ntdll.dll".into();
    ntdll.base = bridge - 0x31e500;
    for (word, instruction) in [0xb0ff_f310, 0x9133_4210, 0xd61f_0200]
        .into_iter()
        .enumerate()
    {
        p.space.w32(bridge + word as u64 * 4, instruction).unwrap();
    }
    for index in [2, 3, 10, 18, 21, 75] {
        p.space
            .w64(base + 0x1000 + index * 8, base + 0x2000)
            .unwrap();
    }
    let upcase: Vec<_> = (0..=u16::MAX).collect();
    p.registry = Registry::selected(upcase.clone(), vec![]).unwrap();
    let csr_data = client_data::native_fixture(0);
    let (section, server) = csr::server_for_kernel(29708);
    p.object_namespace = selected_namespace();
    p.object_namespace
        .select_data_section(section.clone())
        .unwrap();
    let server = CsrServer::selected_with_client_data(
        section,
        server.metadata.clone(),
        Some(csr_data.clone()),
    )
    .unwrap();
    p.object_namespace.select_csr_server(server).unwrap();
    assert_eq!(csr_data.map(&mut p.vm).unwrap().len(), 2);
    let module = p.modules.exe().base;
    let procedure = base + 0x2100;
    let mut class = [0; RECORD_BYTES];
    class[8..16].copy_from_slice(&procedure.to_le_bytes());
    class[24..32].copy_from_slice(&module.to_le_bytes());
    let name = Name::Counted("Window".encode_utf16().collect());
    let atom = p
        .gui
        .register_class(
            &upcase,
            &name,
            &name,
            Definition {
                record: class,
                menu: [0; 2],
                ansi_procedure: false,
            },
        )
        .unwrap();
    (csr_data, upcase, atom)
}

#[test]
fn message_only_window_callbacks_retain_class_and_release_destroyed_window() {
    let (mut process, mut t, base) = setup(WinArch::Arm64);
    let p = process.state_mut();
    let (csr_data, upcase, atom) = setup_window(p, &mut t, base);
    let sp = t.cpu.sp();
    let module = p.modules.exe().base;
    let name = Name::Ordinal(atom);
    let atom = u64::from(atom);

    service(
        p,
        &mut t,
        "NtUserCreateWindowEx",
        [
            0,
            atom,
            atom,
            0,
            0,
            3,
            4,
            5,
            6,
            u64::MAX - 2,
            0,
            module,
            0x1234,
            0,
            0x4000_0a00,
            0,
            0,
            1,
        ],
    );
    callback_return(p, &mut t, [0, 0, 0]);
    let (handle, theme) = expect_callback(p, &t, Phase::LoadTheme, 75);
    let client = p.gui.window(u64::from(handle)).unwrap().client_address;
    let slot = csr_data.views[0].base + u64::from(handle as u16) * 32;
    let desktop_base = p.space.u64(t.teb + 0x828).unwrap();
    let desktop_identity = p.space.u64(t.teb + 0x820).unwrap();
    assert_eq!(p.space.u32(client).unwrap(), handle);
    assert_eq!(p.space.u32(client + 0x120).unwrap(), 0x6010);
    assert_eq!(p.space.u32(client + 0x148).unwrap(), t.tid);
    assert_eq!(p.space.u32(client + 0x14c).unwrap(), p.pid);
    assert_eq!(p.space.u64(slot).unwrap(), client - desktop_base);
    assert_eq!(p.space.u64(slot + 8).unwrap(), u64::from(t.tid));
    assert_eq!(
        p.space.u64(slot + 16).unwrap(),
        p.space.u64(desktop_identity).unwrap()
    );
    assert_eq!(p.space.u32(slot + 24).unwrap(), handle & 0xffff_0000 | 1);
    assert!(p.space.wr(slot, &[0; 32]).is_err());
    assert!(csr_data.map(&mut p.vm).unwrap().is_empty());
    assert_eq!(p.space.u32(theme + 4).unwrap(), 112);
    let reply = base + 0x8000;
    let rectangle = reply + 0x40;
    p.space.wr(reply, &[0; 24]).unwrap();
    p.space.wr(rectangle, &[1; 16]).unwrap();
    p.space.w64(reply + 16, rectangle).unwrap();
    for (phase, index, message, result) in [
        (Phase::Measure, 18, 0x24, 0u64),
        (Phase::NonClientCreate, 10, 0x81, 1),
        (Phase::NonClientRectangle, 21, 0x83, 1),
        (Phase::Create, 10, 1, 0),
    ] {
        callback_return(p, &mut t, [reply, 24, 0]);
        let (actual, payload) = expect_callback(p, &t, phase, index);
        let offset = if index == 10 { 0x30 } else { 8 };
        assert_eq!(actual, handle);
        assert_eq!(p.space.u32(payload + offset).unwrap(), message);
        p.space.w64(reply, result).unwrap();
    }
    callback_return(p, &mut t, [reply, 24, 0]);
    assert_eq!(t.cpu.gpr(0), u64::from(handle));
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (RETURN, sp));
    assert_eq!(p.space.bytes(client + 0x68, 16).unwrap(), [1; 16]);
    assert!(matches!(
        p.gui.unregister_class(&upcase, &name, module, None),
        Err(1412)
    ));

    let hwnd = u64::from(handle);
    let tagged = hwnd | (1u64 << 32);
    assert_top_level(p, &mut t, hwnd, 0, 0x4567);
    assert_top_level(p, &mut t, tagged, 0, 0x4567);
    assert_top_level(p, &mut t, hwnd | 0xffff_0000, 0, 0x4567);
    let view = t.teb + 0x840;
    assert_eq!(p.space.bytes(view, 16).unwrap(), [0; 16]);
    let error = t.teb + crate::user::windows::layout::offsets(WinArch::Arm64).teb_last_error;
    p.space.w32(error, 0x5aa5).unwrap();
    let status = t.teb + crate::user::windows::layout::offsets(WinArch::Arm64).teb_last_status;
    p.space.w32(status, 0xc0000034).unwrap();
    let theme_value = 0x1234_0000_0000_5678;
    let index = u64::from((-2i32) as u32);
    service(
        p,
        &mut t,
        "NtUserSetWindowLongPtr",
        [hwnd, index, theme_value, 0],
    );
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(p.space.u64(client + 0xf0).unwrap(), theme_value);
    service(p, &mut t, "NtUserSetWindowLongPtr", [tagged, index, 0, 0]);
    assert_eq!(t.cpu.gpr(0), theme_value);
    assert_eq!(p.space.u64(client + 0xf0).unwrap(), 0);
    assert_eq!(p.space.u32(error).unwrap(), 0x5aa5);
    assert_eq!(p.space.u32(status).unwrap(), 0xc0000034);
    service(
        p,
        &mut t,
        "NtUserSetProp",
        [tagged, 0x1234, 0x1234_0000_0000_5678],
    );
    assert_eq!(t.cpu.gpr(0), 1);
    service(p, &mut t, "NtUserGetProp", [hwnd, 0x1_1234]);
    assert_eq!(t.cpu.gpr(0), 0x1234_0000_0000_5678);
    service(p, &mut t, "NtUserRemoveProp", [tagged, 0x1234]);
    assert_eq!(t.cpu.gpr(0), 0x1234_0000_0000_5678);
    service(p, &mut t, "NtUserRemoveProp", [hwnd, 0x1234]);
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(p.space.u32(error).unwrap(), 0x5aa5);
    service(p, &mut t, "NtUserSetProp", [hwnd, 0, 1]);
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(p.space.u32(error).unwrap(), 87);
    service(p, &mut t, "NtUserSetProp", [hwnd, 1, 0xbeef]);
    assert_eq!(t.cpu.gpr(0), 1);

    p.space.wr(view, &[0x2a; 24]).unwrap();
    service(p, &mut t, "NtUserDestroyWindow", [hwnd]);
    for (phase, index, message) in [
        (Phase::BeginDestroy, 2, 0x90),
        (Phase::Destroy, 2, 2),
        (Phase::NonClientDestroy, 3, 0x82),
    ] {
        let (actual, payload) = expect_callback(p, &t, phase, index);
        assert_eq!(actual, handle);
        assert_eq!(p.space.u32(payload + 8).unwrap(), message);
        callback_return(p, &mut t, [reply, 24, 0]);
    }
    assert_eq!(t.cpu.gpr(0), 1);
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (RETURN, sp));
    assert!(p.gui.window(hwnd).is_none());
    assert_eq!(p.space.bytes(view, 24).unwrap(), [0x2a; 24]);
    service(p, &mut t, "NtUserGetProp", [hwnd, 1]);
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(p.space.u32(error).unwrap(), 1400);
    p.space.w32(error, 0x5aa5).unwrap();
    service(
        p,
        &mut t,
        "NtUserSetWindowLongPtr",
        [hwnd, index, theme_value, 0],
    );
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(p.space.u32(error).unwrap(), 1400);
    assert_eq!(p.space.u32(status).unwrap(), 0xc0000034);
    assert_eq!(p.space.bytes(client, 0x160).unwrap(), [0; 0x160]);
    let mut vacant = [0; 32];
    vacant[26..28].copy_from_slice(&((handle >> 16) as u16 + 1).to_le_bytes());
    assert_eq!(p.space.bytes(slot, 32).unwrap(), vacant);
    assert!(p.gui.unregister_class(&upcase, &name, module, None).is_ok());
    assert_top_level(p, &mut t, hwnd, 0, 1400);
    assert_top_level(p, &mut t, hwnd | 0xffff_0000, 0, 1400);
}

#[test]
fn ime_disabled_overlapped_window_applies_callback_tracking_limits() {
    let (mut process, mut t, base) = setup(WinArch::Arm64);
    let p = process.state_mut();
    let (_, _, atom) = setup_window(p, &mut t, base);
    let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
        panic!("expected selected GUI inputs");
    };
    let limits = [314, 50, 1520, 862, -8, -8, 136, 39, 1524, 866];
    Arc::get_mut(inputs).unwrap().overlapped_window_limits = Ok(limits);
    service(p, &mut t, "NtUserDisableThreadIme", [0]);
    callback_return(p, &mut t, [0, 0, 0]);
    assert_eq!(t.cpu.gpr(0), 1);
    assert!(p.gui.threads[&t.tid].ime_disabled);

    let atom = u64::from(atom);
    let module = p.modules.exe().base;
    service(
        p,
        &mut t,
        "NtUserCreateWindowEx",
        [
            0,
            atom,
            atom,
            0,
            u64::from(OVERLAPPED_STYLE),
            17,
            31,
            197,
            103,
            0,
            0,
            module,
            0x1234,
            0,
            0x4000_0600,
            0,
            0,
            0,
        ],
    );
    let (handle, _) = expect_callback(p, &t, Phase::LoadTheme, 75);
    let reply = base + 0x8000;
    let data = reply + 0x40;
    p.space.wr(reply, &[0; 24]).unwrap();
    callback_return(p, &mut t, [reply, 24, 0]);
    let (_, payload) = expect_callback(p, &t, Phase::Measure, 18);
    for (index, limit) in limits.into_iter().enumerate() {
        assert_eq!(
            p.space.u32(payload + 0x18 + index as u64 * 4).unwrap(),
            limit as u32
        );
        p.space.w32(data + index as u64 * 4, limit as u32).unwrap();
    }
    p.space.w32(data + 24, 220).unwrap();
    p.space.w32(data + 28, 120).unwrap();
    p.space.w64(reply + 8, 40).unwrap();
    p.space.w64(reply + 16, data).unwrap();
    callback_return(p, &mut t, [reply, 24, 0]);
    let (_, payload) = expect_callback(p, &t, Phase::NonClientCreate, 10);
    assert_eq!(p.space.u64(payload + 0x60).unwrap(), 0);
    assert_eq!(p.space.u32(payload + 0x6c).unwrap(), 197);
    assert_eq!(p.space.u32(payload + 0x78).unwrap(), OVERLAPPED_STYLE);
    assert_eq!(p.space.u32(payload + 0x90).unwrap(), 0x100);
    p.space.w64(reply, 1).unwrap();
    callback_return(p, &mut t, [reply, 24, 0]);

    let (_, payload) = expect_callback(p, &t, Phase::NonClientRectangle, 21);
    for (index, coordinate) in [17, 31, 237, 151].into_iter().enumerate() {
        assert_eq!(
            p.space.u32(payload + 0x28 + index as u64 * 4).unwrap(),
            coordinate
        );
    }
    p.space.wr(data, &[3; 16]).unwrap();
    callback_return(p, &mut t, [reply, 24, 0]);
    let (_, payload) = expect_callback(p, &t, Phase::Create, 10);
    assert_eq!(p.space.u32(payload + 0x6c).unwrap(), 197);
    let window = p.gui.window(u64::from(handle)).unwrap().client_address;
    assert_eq!(p.space.u32(window + 0x60).unwrap(), 237);
    assert_eq!(p.space.u32(window + 0x64).unwrap(), 151);
    assert_eq!(p.space.bytes(window + 0x68, 16).unwrap(), [3; 16]);
    p.space.w64(reply, 0).unwrap();
    callback_return(p, &mut t, [reply, 24, 0]);
    assert_eq!(t.cpu.gpr(0), u64::from(handle));
    let hwnd = u64::from(handle);
    for alias in [hwnd, hwnd | 0x5a00_0000_0000_0000, hwnd | 0xffff_0000] {
        assert_top_level(p, &mut t, alias, 1, 0x4567);
    }
    for invalid in [0, 0x1234, u64::MAX - 2, hwnd & 0xffff, hwnd ^ 0x66_0000] {
        assert_top_level(p, &mut t, invalid, 0, 1400);
    }
    service(p, &mut t, "NtUserQueryWindow", [hwnd, 8]);
    assert_eq!(t.cpu.gpr(0), 0);
    service(p, &mut t, "NtUserGetThreadState", [3]);
    assert_eq!(t.cpu.gpr(0), 0);
}
