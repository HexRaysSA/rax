use super::super::super::super::super::services::dispatch;
use super::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::prot;
use crate::user::windows::registry::Registry;
use serde_json::Value;

const REGISTRATION: [&str; 3] = [
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-window-classes/registration-29708-v3.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-window-classes/registration-29708-v5.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-window-classes/function-id-precedence-29708.json"
    )),
];
const LAST_ERROR: u32 = 0x5aa5;
const LAST_STATUS: u32 = 0xc000_0034;
const DENIED: u64 = 0x10000;

fn describe(p: &Proc, descriptor: u64, name: &str) {
    let units = name.encode_utf16().collect::<Vec<_>>();
    let length = (units.len() * 2) as u16;
    p.space.w16(descriptor, length).unwrap();
    p.space.w16(descriptor + 2, length + 2).unwrap();
    p.space.w64(descriptor + 8, descriptor + 16).unwrap();
    p.space.put_wstr(descriptor + 16, &units).unwrap();
}

fn call<const N: usize>(p: &mut Proc, t: &mut Thread, service: &str, values: [u64; N]) -> u64 {
    let arch = p.arch;
    let index = p.modules.nt_services.as_ref().unwrap().0;
    let number = 0x10a2;
    p.modules.win32u_services = Some((index, named_table(arch, service, number)));
    let sp = t.cpu.sp();
    for (slot, value) in values.into_iter().enumerate() {
        if arch == WinArch::Arm64 {
            t.cpu.set_gpr(slot, value);
        } else if let Some(&register) = [10, 2, 8, 9].get(slot) {
            t.cpu.set_gpr(register, value);
        } else {
            p.space
                .w64(sp + 0x28 + 8 * (slot as u64 - 4), value)
                .unwrap();
        }
    }
    let resume = 0x5000_4000;
    t.cpu.set_pc(resume);
    assert_eq!(
        dispatch(p, t, number, resume - 4),
        Some(Outcome::Continue),
        "{arch} {service}"
    );
    if let Some(callback) = p.gui.threads[&t.tid].callbacks.last() {
        if N == 7 {
            let Completion::RegisterWindowClass(captured) = callback.completion else {
                panic!("expected suspended class registration");
            };
            assert_eq!(captured.as_slice(), values.as_slice());
        }
        arguments(p, t, [0, 0, 0]);
        assert_eq!(dispatch(p, t, 5, resume - 0x100), Some(Outcome::Continue));
    }
    assert_eq!(t.cpu.pc(), resume);
    assert_eq!(t.cpu.sp(), sp);
    t.cpu.gpr(0)
}

fn setup_state(
    arch: WinArch,
) -> (
    super::super::super::super::super::WindowsProcess,
    Thread,
    u64,
) {
    let (mut process, mut thread, base) = setup(arch);
    let p = process.state_mut();
    thread.cpu.set_sp(base + 0xe000);
    p.vm.protect(base + 0xf000, 4096, prot::NOACCESS).unwrap();
    p.registry = Registry::selected(
        (0..=u16::MAX)
            .map(|unit| {
                if (0x61..=0x7a).contains(&unit) {
                    unit - 0x20
                } else {
                    unit
                }
            })
            .collect(),
        vec![],
    )
    .unwrap();
    (process, thread, base)
}

fn error_addresses(thread: &Thread, arch: WinArch) -> [u64; 2] {
    [
        thread.teb + offsets(arch).teb_last_error,
        thread.teb + offsets(arch).teb_last_status,
    ]
}

#[test]
fn window_classes_replay_native_registration_controls() {
    let cases: Vec<Value> = REGISTRATION
        .iter()
        .flat_map(|source| serde_json::from_str::<Vec<Value>>(source).unwrap())
        .collect();
    assert_eq!(cases.len(), 135);
    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut t, base) = setup_state(arch);
        let p = process.state_mut();
        let bad = base + 0xf000;
        let [record, primary, version, menu, menu_name] =
            [0x5000, 0x5200, 0x5400, 0x5600, 0x5800].map(|offset| base + offset);
        let [error, status] = error_addresses(&t, arch);
        let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
            unreachable!();
        };
        std::sync::Arc::get_mut(inputs).unwrap().cursor_icons = Ok(
            crate::user::windows::gui::cursor_icons::Catalog::new(vec![]),
        );
        for case in &cases {
            let label = case["label"].as_str().unwrap();
            let options = &case["options"];
            let option = |name: &str, default| options[name].as_u64().unwrap_or(default);
            let extra = |name: &str| options[name].as_i64().unwrap_or(0) as u32;
            describe(p, primary, label);
            if options["alias"] == true {
                describe(p, version, &format!("{label}-version"));
            } else {
                describe(p, version, label);
            }
            for (slot, length, buffer) in [
                (primary, "primary_length", "primary_buffer"),
                (version, "version_length", "version_buffer"),
            ] {
                if let Some(length) = options[length].as_u64() {
                    p.space.w16(slot, length as u16).unwrap();
                }
                if let Some(buffer) = options[buffer].as_u64() {
                    p.space.w64(slot + 8, buffer).unwrap();
                }
            }
            p.space.wr(record, &[0; 80]).unwrap();
            p.space.wr(menu, &[0; 32]).unwrap();
            p.space.wr(menu_name, &[0; 16]).unwrap();
            p.space
                .w64(
                    menu + 16,
                    match option("menu3", menu_name) {
                        DENIED => bad,
                        other => other,
                    },
                )
                .unwrap();
            for (offset, value) in [
                (0, option("size", 80) as u32),
                (4, option("style", 0) as u32),
                (16, extra("class_extra")),
                (20, extra("window_extra")),
            ] {
                p.space.w32(record + offset, value).unwrap();
            }
            for (offset, value) in [
                (8, option("window_proc", base + 0x700)),
                (24, option("instance", base)),
                (32, option("icon", 0)),
                (40, option("cursor", 0)),
                (48, option("background", 0)),
            ] {
                p.space.w64(record + offset, value).unwrap();
            }

            p.space.w32(error, LAST_ERROR).unwrap();
            p.space.w32(status, LAST_STATUS).unwrap();
            let argument = |name, default| match option(name, default) {
                DENIED => bad,
                value => value,
            };
            let result = call(
                p,
                &mut t,
                "NtUserRegisterClassExWOW",
                [
                    argument("p0", record),
                    argument("p1", primary),
                    argument("p2", version),
                    argument("p3", menu),
                    option("fnid", 0),
                    option("flags", 0xc0),
                    option("wow", 0),
                ],
            );
            assert_eq!(
                result != 0,
                case["success"].as_bool().unwrap(),
                "{arch} {label}"
            );
            assert_eq!(
                p.space.u32(error).unwrap() as u64,
                case["error"].as_u64().unwrap(),
                "{arch} {label}"
            );
            assert_eq!(
                p.space.u32(status).unwrap() as u64,
                case["status"].as_u64().unwrap(),
                "{arch} {label}"
            );
        }
    }
}

#[test]
fn window_classes_preserve_versions_outputs_and_atom_lifetime() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut t, base) = setup_state(arch);
        let p = process.state_mut();
        let [record, primary, version, menu, empty, result, menu_out] =
            [0x5000, 0x5200, 0x5400, 0x5600, 0x5800, 0x5a00, 0x5c00].map(|offset| base + offset);
        let module = base + 0x9000;
        let other = base + 0xa000;
        let [error, status] = error_addresses(&t, arch);
        p.space.w32(error, LAST_ERROR).unwrap();
        p.space.w32(status, LAST_STATUS).unwrap();
        describe(p, primary, "Class");
        describe(p, version, "Class.versioned");
        p.space.w64(record + 8, base + 0x600).unwrap();
        p.space.w32(record + 16, 5).unwrap();
        p.space.w32(record + 20, (-7i32) as u32).unwrap();
        p.space.w64(record + 24, module).unwrap();
        p.space.w64(menu, 42).unwrap();
        p.space.w64(menu + 8, 42).unwrap();
        p.space.w64(menu + 16, empty).unwrap();
        let register = [record, primary, version, menu, 0, 0xc0, 0];
        let atom = call(p, &mut t, "NtUserRegisterClassExWOW", register);
        assert!(atom >= 0xc000);
        assert_eq!(call(p, &mut t, "NtUserRegisterClassExWOW", register), 0);
        assert_eq!(p.space.u32(error).unwrap(), 1410);
        assert_eq!(
            call(p, &mut t, "NtUserRegisterWindowMessage", [primary]),
            atom
        );
        p.space.wr(result, &[0xa5; 80]).unwrap();
        p.space.wr(menu_out, &[0xa5; 32]).unwrap();
        for (instance, name) in [(module, primary), (other, version)] {
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtUserGetClassInfoEx",
                    [instance, name, result, menu_out, 0]
                ),
                0
            );
            assert_eq!(p.space.u32(error).unwrap(), 1411);
            assert_eq!(p.space.bytes(result, 80).unwrap(), [0xa5; 80]);
            assert_eq!(p.space.bytes(menu_out, 32).unwrap(), [0xa5; 32]);
        }
        describe(p, version, "cLaSs.veRsIoNeD");
        assert_eq!(
            call(
                p,
                &mut t,
                "NtUserGetClassInfoEx",
                [module, version, result, base + 0xf000, 0]
            ),
            0
        );
        assert_eq!(p.space.u32(error).unwrap(), 998);
        assert_eq!(p.space.u32(status).unwrap(), 0xc000_0005);
        assert_eq!(p.space.bytes(result, 80).unwrap(), [0xa5; 80]);

        p.space.w32(error, LAST_ERROR).unwrap();
        p.space.w32(status, LAST_STATUS).unwrap();
        assert_eq!(
            call(
                p,
                &mut t,
                "NtUserGetClassInfoEx",
                [module, version, result, menu_out, 0]
            ),
            atom
        );
        assert_eq!(p.space.u32(result).unwrap(), 0xa5a5_a5a5);
        assert_eq!(
            p.space.bytes(result + 4, 52).unwrap(),
            p.space.bytes(record + 4, 52).unwrap()
        );
        assert_eq!(p.space.bytes(result + 56, 24).unwrap(), [0; 24]);
        assert_eq!(p.space.u64(menu_out).unwrap(), 42);
        assert_eq!(p.space.bytes(menu_out + 8, 24).unwrap(), [0xa5; 24]);
        assert_eq!(p.space.u32(error).unwrap(), LAST_ERROR);
        assert_eq!(p.space.u32(status).unwrap(), LAST_STATUS);

        assert_eq!(
            call(
                p,
                &mut t,
                "NtUserUnregisterClass",
                [version, module, menu_out]
            ),
            1
        );
        assert_eq!(p.space.u64(menu_out).unwrap(), 42);
        assert_eq!(p.space.u64(menu_out + 8).unwrap(), 42);
        assert_eq!(p.space.u64(menu_out + 16).unwrap(), 0);
        assert_eq!(p.space.u64(menu_out + 24).unwrap(), 0xa5a5_a5a5_a5a5_a5a5);
        assert_eq!(
            call(p, &mut t, "NtUserUnregisterClass", [version, module, 0]),
            0
        );
        assert_eq!(p.space.u32(error).unwrap(), 1411);
        assert_eq!(
            call(p, &mut t, "NtUserRegisterWindowMessage", [primary]),
            atom
        );
        // A child shares USER atoms. Retiring the parent's classes releases
        // its class-only entries there even while both process states remain live.
        let second = call(p, &mut t, "NtUserRegisterClassExWOW", register);
        assert_eq!(second, atom);
        let mut child = State::default();
        child.inherit_message_atoms(&p.gui);
        let upcase = p.registry.upcase_table();
        let next_name = "next class".encode_utf16().collect::<Vec<_>>();
        p.gui.retire_classes();
        assert_eq!(
            child.register_message(&upcase, &next_name).unwrap(),
            atom as u16 + 1
        );
    }
}

#[test]
fn installed_ime_class_is_registered_lazily_with_paired_procedures() {
    use crate::user::windows::gui::cursor_icons::{CURSOR, Catalog, Resource};

    let arch = WinArch::Arm64;
    let (mut process, mut t, base) = setup_state(arch);
    let p = process.state_mut();
    p.modules.list[0].name = "user32.dll".into();
    let user = p.modules.exe().base;
    let [record, name, ordinal, menu, empty, result, menu_out] =
        [0x5000, 0x5200, 0x5400, 0x5600, 0x5800, 0x5a00, 0x5c00].map(|offset| base + offset);
    let [error, status] = error_addresses(&t, arch);
    let wide = base + 0x30c0;
    let ansi = base + 0x30d0;
    let ntdll_index = p
        .modules
        .by_name("ntdll.dll")
        .unwrap_or(p.modules.nt_services.as_ref().unwrap().0);
    let ntdll = &mut p.modules.list[ntdll_index];
    ntdll.name = "ntdll.dll".into();
    ntdll.base = wide - 0x31e5c0;
    for (address, add) in [(wide, 0x9130_4210), (ansi, 0x9130_0210)] {
        for (offset, word) in [0xb0ff_f310, add, 0xd61f_0200].into_iter().enumerate() {
            p.space.w32(address + offset as u64 * 4, word).unwrap();
        }
    }
    let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
        unreachable!();
    };
    std::sync::Arc::get_mut(inputs).unwrap().cursor_icons = Ok(Catalog::new(vec![Resource {
        ordinal: 32512,
        selector: CURSOR,
        depths: 0,
        any_format: false,
    }]));

    describe(p, name, "iMe");
    p.space.w64(ordinal + 8, 0xc027).unwrap();
    p.space.wr(result, &[0xa5; 80]).unwrap();
    p.space.wr(menu_out, &[0xa5; 32]).unwrap();
    p.space.w32(status, LAST_STATUS).unwrap();
    assert_eq!(
        call(p, &mut t, "NtUserRegisterWindowMessage", [name]),
        0xc027
    );
    assert_eq!(
        call(
            p,
            &mut t,
            "NtUserGetClassInfoEx",
            [0, ordinal, result, menu_out, 0]
        ),
        0
    );
    assert_eq!(p.space.u32(error).unwrap(), 1411);
    assert_eq!(p.space.u32(status).unwrap(), LAST_STATUS);
    assert_eq!(p.space.bytes(result, 80).unwrap(), [0xa5; 80]);
    assert_eq!(p.space.bytes(menu_out, 32).unwrap(), [0xa5; 32]);

    p.space.w32(record, 80).unwrap();
    p.space.w32(record + 4, 0x4000).unwrap();
    p.space.w64(record + 8, wide).unwrap();
    p.space.w32(record + 20, 8).unwrap();
    p.space.w64(record + 24, user).unwrap();
    p.space.w64(record + 40, 0x1601_0003).unwrap();
    p.space.w64(menu + 16, empty).unwrap();
    let registration = [record, name, name, menu, 0x2a9, 0x40, 0];
    assert_eq!(
        call(p, &mut t, "NtUserRegisterClassExWOW", registration),
        0xc027
    );

    for (module, query_name, is_ansi, procedure, output_module) in [
        (0, name, 0, wide, 0),
        (user, ordinal, 1, ansi, 0),
        (base + 0x9000, name, 1, ansi, base + 0x9000),
    ] {
        p.space.w32(error, LAST_ERROR).unwrap();
        assert_eq!(
            call(
                p,
                &mut t,
                "NtUserGetClassInfoEx",
                [module, query_name, result, menu_out, is_ansi]
            ),
            0xc027
        );
        assert_eq!(p.space.u32(result).unwrap(), 0xa5a5_a5a5);
        assert_eq!(p.space.u32(result + 4).unwrap(), 0);
        assert_eq!(p.space.u64(result + 8).unwrap(), procedure);
        assert_eq!(p.space.u32(result + 20).unwrap(), 8);
        assert_eq!(p.space.u64(result + 24).unwrap(), output_module);
        assert_eq!(p.space.u64(result + 40).unwrap(), 0x10003);
        assert_eq!(p.space.u64(menu_out).unwrap(), 0);
        assert_eq!(p.space.bytes(menu_out + 8, 24).unwrap(), [0xa5; 24]);
        assert_eq!(p.space.u32(error).unwrap(), LAST_ERROR);
        assert_eq!(p.space.u32(status).unwrap(), LAST_STATUS);
    }
    assert_eq!(call(p, &mut t, "NtUserUnregisterClass", [name, 0, 0]), 1);
    assert_eq!(
        call(
            p,
            &mut t,
            "NtUserGetClassInfoEx",
            [0, ordinal, result, menu_out, 0]
        ),
        0
    );
    assert_eq!(
        call(p, &mut t, "NtUserRegisterWindowMessage", [name]),
        0xc027
    );

    let upcase = p.registry.upcase_table();
    let allocated: Vec<_> = (0..40)
        .map(|i| {
            p.gui
                .register_message(
                    &upcase,
                    &format!("dynamic{i}").encode_utf16().collect::<Vec<_>>(),
                )
                .unwrap()
        })
        .collect();
    assert_eq!(
        allocated,
        (0xc000..0xc029)
            .filter(|&atom| atom != 0xc027)
            .collect::<Vec<_>>()
    );
}
