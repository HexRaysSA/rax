use super::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::nt::error::ERROR_INVALID_PARAMETER;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};
use crate::user::windows::registry::Registry;

const REGISTER: u32 = 0x1032;
const CALLBACK_RETURN: u32 = 5;
const LAST_ERROR: u32 = 0x0abc_1234;
const LAST_STATUS: u32 = STATUS_INVALID_HANDLE;

fn upcase() -> Vec<u16> {
    (0..=u16::MAX)
        .map(|u| match u {
            0x61..=0x7a | 0xe4 => u - 0x20,
            _ => u,
        })
        .collect()
}

fn present(p: &Proc, descriptor: u64, name: &str) -> u16 {
    let units = name.encode_utf16().chain([0]).collect::<Vec<_>>();
    let length = (units.len() as u16 - 1) * 2;
    let buffer = descriptor + 32;
    p.space.w16(descriptor, length).unwrap();
    p.space.w16(descriptor + 2, length + 2).unwrap();
    let width = p.arch.ptr_size();
    p.space.wptr(descriptor + width, width, buffer).unwrap();
    p.space.put_wunits(buffer, &units).unwrap();
    length
}

fn register(p: &mut Proc, t: &mut Thread, descriptor: u64, resume: u64) {
    arguments(p, t, [descriptor, 0, 0]);
    t.cpu.set_pc(resume);
    assert_eq!(
        super::super::super::super::super::services::dispatch(p, t, REGISTER, resume - 4),
        Some(Outcome::Continue)
    );
}

#[test]
fn registered_window_message_resumes_cold_then_preserves_case_and_counted_input() {
    let dispatch = super::super::super::super::super::services::dispatch;
    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut t, entry) = setup(arch);
        let p = process.state_mut();
        let index = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.win32u_services = Some((
            index,
            named_table(arch, "NtUserRegisterWindowMessage", REGISTER),
        ));
        p.registry = Registry::selected(upcase(), vec![]).unwrap();
        let resume = entry + 0x4000;
        let descriptor = entry + 0x5000;
        let error = t.teb + offsets(arch).teb_last_error;
        let status = t.teb + offsets(arch).teb_last_status;
        let stack = t.cpu.sp();
        p.space.w32(error, LAST_ERROR).unwrap();
        p.space.w32(status, LAST_STATUS).unwrap();
        let length = present(p, descriptor, "RAX-Ä");

        for callback_status in [u64::from(STATUS_ACCESS_VIOLATION), 0] {
            register(p, &mut t, descriptor, resume);
            assert_eq!(t.cpu.pc(), entry);
            assert_eq!(
                p.gui.threads[&t.tid].callbacks[0].completion,
                Completion::RegisterWindowMessage(descriptor)
            );
            arguments(p, &mut t, [0, 0, callback_status]);
            assert_eq!(
                dispatch(p, &mut t, CALLBACK_RETURN, entry + 0x100),
                Some(Outcome::Continue)
            );
            assert_eq!(t.cpu.gpr(0), if callback_status == 0 { 0xc000 } else { 0 });
            assert_eq!(t.cpu.pc(), resume);
            assert_eq!(t.cpu.sp(), stack);
        }

        for (name, count, expected) in [
            ("rax-ä", None, 0xc000),
            ("rax-ä-Suffix", Some(length), 0xc000),
            ("rax-ä\0Suffix", None, 0xc000),
            ("another", None, 0xc001),
            ("", None, 0),
            ("#00016", None, 16),
            ("#16x", None, 0xc002),
            (&"x".repeat(255), None, 0xc003),
        ] {
            present(p, descriptor, name);
            if let Some(count) = count {
                p.space.w16(descriptor, count).unwrap();
            }
            register(p, &mut t, descriptor, resume);
            assert_eq!(t.cpu.gpr(0), expected, "{name}");
            assert_eq!(t.cpu.sp(), stack);
            assert!(p.gui.threads[&t.tid].callbacks.is_empty());
            assert_eq!(p.space.u32(error).unwrap(), LAST_ERROR);
            assert_eq!(p.space.u32(status).unwrap(), LAST_STATUS);
        }

        for (name, length, maximum, bad_pointer, expected_status) in [
            ("test", Some(7), None, false, STATUS_ACCESS_VIOLATION),
            ("test", None, Some(2), false, STATUS_ACCESS_VIOLATION),
            ("test", None, None, true, STATUS_INVALID_PARAMETER),
            ("#49152", None, None, false, STATUS_INVALID_PARAMETER),
            (&"x".repeat(256), None, None, false, LAST_STATUS),
        ] {
            p.space.w32(error, LAST_ERROR).unwrap();
            p.space.w32(status, LAST_STATUS).unwrap();
            present(p, descriptor, name);
            if let Some(length) = length {
                p.space.w16(descriptor, length).unwrap();
            }
            if let Some(maximum) = maximum {
                p.space.w16(descriptor + 2, maximum).unwrap();
            }
            register(p, &mut t, if bad_pointer { 0 } else { descriptor }, resume);
            assert_eq!(t.cpu.gpr(0), 0, "{name}");
            assert_eq!(p.space.u32(error).unwrap(), ERROR_INVALID_PARAMETER);
            assert_eq!(p.space.u32(status).unwrap(), expected_status);
        }
        present(p, descriptor, "after invalid input");
        register(p, &mut t, descriptor, resume);
        assert_eq!(t.cpu.gpr(0), 0xc004);
    }
}

#[test]
fn wow64_window_message_uses_the_ready_companion_and_preserves_last_status() {
    use crate::user::windows::object_namespace::csr::client_data::native_fixture;
    use crate::user::windows::process::{services, thread, wow64};

    let (mut process, _, entry) = setup(WinArch::X86);
    let p = process.state_mut();
    let version = &mut std::sync::Arc::make_mut(&mut p.cfg).version;
    version.major = 10;
    version.minor = 0;
    version.build = 29708;
    wow64::initialize_test_profile(p, WinArch::Arm64.machine()).unwrap();
    let inputs = crate::user::windows::gui::tests::wow64_companion_fixture(WinArch::Arm64, 0x34000);
    p.native.as_mut().unwrap().gui = Availability::Wow64Companion(inputs, Wow64Gdi::Insider);
    p.registry = Registry::selected(upcase(), vec![]).unwrap();
    let id = thread::create(p, p.modules.exe().entry, 0, 0x10000, false).unwrap();
    let mut t = p.threads.remove(&id).unwrap();
    let stack = t.cpu.sp();
    let resume = entry + 0x4000;
    let descriptor = entry + 0x5000;
    let offsets = offsets(WinArch::X86);
    let error = t.teb + offsets.teb_last_error;
    let status = t.teb + offsets.teb_last_status;
    let module = p.modules.win32u_services.as_ref().unwrap().0;
    let call = |p: &mut Proc, t: &mut Thread, name, number, argument| {
        p.modules.win32u_services = Some((module, named_table(WinArch::X86, name, number)));
        t.cpu.set_sp(stack);
        p.space.w32(stack, resume as u32).unwrap();
        p.space.w32(stack + 4, (resume + 4) as u32).unwrap();
        p.space.w32(stack + 8, argument as u32).unwrap();
        t.cpu.set_gpr(0, u64::from(number));
        services::wow64(p, t, entry)
    };
    let register = |p: &mut Proc, t: &mut Thread, address| {
        call(p, t, "NtUserRegisterWindowMessage", REGISTER, address)
    };
    let views = native_fixture(0).map_wow64(&mut p.vm).unwrap();
    p.wow64.as_mut().unwrap().user_data = Some(views);
    present(p, descriptor, "RAX-Ä");
    assert!(matches!(
        register(p, &mut t, descriptor),
        Outcome::Fail(reason) if reason.contains("requires an initialized USER companion")
    ));
    assert!(p.gui.threads.is_empty());
    assert_eq!(call(p, &mut t, "NtGdiInit2", 0x1308, 0), Outcome::Continue);

    let valid = [
        ("RAX-Ä", None, false, false, 0xc000),
        ("rax-ä-extra", Some(10), false, false, 0xc000),
        ("#49151", None, false, false, 0xbfff),
        ("", None, false, false, 0),
    ];
    let long_name = "w".repeat(256);
    let invalid = [
        ("x", Some(3), false, false, 0),
        ("x", Some(6), false, false, 0),
        ("x", None, true, false, 0),
        ("", None, true, false, 0),
        ("x", None, false, true, 0),
        ("#49152", None, false, false, 0),
        (&long_name, None, false, false, 0),
    ];
    for (cases, expected_error) in [
        (valid.as_slice(), LAST_ERROR),
        (&invalid, ERROR_INVALID_PARAMETER),
    ] {
        for &(name, length, null_buffer, null_descriptor, expected) in cases {
            p.space.w32(error, LAST_ERROR).unwrap();
            p.space.w32(status, LAST_STATUS).unwrap();
            present(p, descriptor, name);
            if let Some(length) = length {
                p.space.w16(descriptor, length).unwrap();
            }
            if null_buffer {
                p.space.w32(descriptor + 4, 0).unwrap();
            }
            let address = if null_descriptor { 0 } else { descriptor };
            assert_eq!(register(p, &mut t, address), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), expected, "{name}");
            assert_eq!(t.cpu.sp(), stack + 4);
            assert_eq!(t.cpu.pc(), resume);
            assert_eq!(p.space.u32(error).unwrap(), expected_error, "{name}");
            assert_eq!(p.space.u32(status).unwrap(), LAST_STATUS, "{name}");
            assert!(p.gui.threads[&id].callbacks.is_empty());
        }
    }
    p.wow64.as_mut().unwrap().user_data = None;
    assert!(matches!(
        register(p, &mut t, descriptor),
        Outcome::Fail(reason) if reason.contains("requires an initialized USER companion")
    ));
}

#[test]
fn registered_window_message_atoms_are_shared_by_family_and_retained_until_session_end() {
    let upcase = upcase();
    let set = |gui: &State, name: &str| {
        gui.register_message(&upcase, &name.encode_utf16().collect::<Vec<_>>())
    };
    let parent = State::default();
    assert_eq!(set(&parent, "name"), Ok(0xc000));
    let mut child = State::default();
    child.inherit_message_atoms(&parent);
    assert_eq!(set(&child, "NAME"), Ok(0xc000));
    assert_eq!(set(&child, "Another"), Ok(0xc001));
    let other = State::default();
    assert_eq!(set(&other, "Another"), Ok(0xc000));
    drop(child);
    assert_eq!(set(&parent, "another"), Ok(0xc001));
    assert_eq!(set(&parent, "third"), Ok(0xc002));
}
