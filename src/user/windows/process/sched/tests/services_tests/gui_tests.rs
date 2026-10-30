use super::*;
use crate::user::windows::gui::{Availability, Completion, State};
use crate::user::windows::loader::services::tests::named_table;

fn arguments(p: &mut Proc, t: &mut Thread, values: [u64; 3]) {
    match p.arch {
        WinArch::Arm64 => {
            for (index, value) in values.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
        WinArch::X64 => {
            t.cpu.set_gpr(10, values[0]);
            t.cpu.set_gpr(2, values[1]);
            t.cpu.set_gpr(8, values[2]);
        }
        WinArch::X86 => {
            for (index, value) in values.into_iter().enumerate() {
                p.space
                    .w32(t.cpu.sp() + 4 + index as u64 * 4, value as u32)
                    .unwrap();
            }
        }
    }
}

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    use crate::user::windows::loader::apiset_schema::ApiSetSchema;
    use crate::user::windows::memory::{AllocKind, prot};
    use crate::user::windows::native::NativeRuntime;
    use crate::user::windows::process::native_start::EntryPoints;
    let (mut process, t) = fixture(arch, "NtClose", 0x37);
    let p = process.state_mut();
    let idx = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((idx, named_table(arch, "NtCallbackReturn", 5)));
    p.modules.win32u_services = Some((idx, named_table(arch, "NtGdiInit2", 0x12fd)));
    let base =
        p.vm.reserve(
            Some(0x5000_0000),
            65536,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    p.vm.commit(base, 65536, prot::EXECUTE_READWRITE).unwrap();
    p.space.w64(p.peb + 0x58, base + 0x1000).unwrap();
    p.space.w64(base + 0x1000 + 84 * 8, base + 0x2000).unwrap();
    let schema: Vec<_> = [6u32, 28, 0, 0, 28, 28, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    p.native = Some(NativeRuntime {
        directory: Default::default(),
        guest_root: "C:\\Windows".into(),
        guest_directory: "C:\\Windows\\System32".into(),
        version: p.cfg.version.clone(),
        apisets: ApiSetSchema::parse(&schema).unwrap(),
        registry: Default::default(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: Some(EntryPoints {
            loader: base,
            thread: base,
            module: base,
            callback: Some(base),
        }),
        code_integrity: Err("controlled absent code integrity metadata".into()),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
        code_integrity_policies: Err("code integrity policies not captured in this fixture".into()),
        gui: if arch == WinArch::X86 {
            Availability::Unavailable("controlled unpaired WoW64 inputs".into())
        } else {
            Availability::Available(crate::user::windows::gui::tests::fixture(arch))
        },
    });
    if let Availability::Available(inputs) = &p.native.as_ref().unwrap().gui {
        p.objects
            .assign_desktop(inputs.assigned_desktop.clone())
            .unwrap();
    }
    p.gui = State::new((6, 2));
    (process, t, base)
}

#[test]
fn no_active_kernel_callback_rejects_without_probing_output_or_changing_last_error() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtClose", 5);
        let p = process.state_mut();
        let idx = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.nt_services = Some((idx, named_table(arch, "NtCallbackReturn", 5)));
        let error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        p.space.w32(error, 0x1234_5678).unwrap();
        let rng = p.rng;
        for buffer in [0, 1, u64::from(u32::MAX)] {
            for length in [0, 1, u64::from(u32::MAX)] {
                for status in [0, 0x103, 0x8000_0001, 0xc000_0001] {
                    arguments(p, &mut t, [buffer, length, status]);
                    assert_eq!(
                        super::super::super::super::services::dispatch(p, &mut t, 5, 0x1234_0000),
                        Some(Outcome::Continue)
                    );
                    assert_eq!(t.cpu.gpr(0), 0xc000_0258);
                    assert_eq!(p.space.u32(error).unwrap(), 0x1234_5678);
                    assert_eq!(p.rng, rng);
                    assert!(p.gui.threads.is_empty());
                }
            }
        }
    }
}

#[test]
fn gui_client_version_matches_native_subsystem_minor_byte_boundary_controls() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        for (version, expected) in [
            ((6, 255), 0x06ff),
            ((7, 256), 0x0700),
            ((8, 256), 0x0800),
            ((7, 65535), 0x07ff),
        ] {
            let (mut process, mut thread, _) = setup(arch);
            let p = process.state_mut();
            p.gui.executable_version = version;
            assert_eq!(
                super::super::super::super::services::dispatch(p, &mut thread, 0x12fd, 0x1234_0000,),
                Some(Outcome::Continue)
            );
            assert_eq!(
                p.space.u64(thread.teb + 0x810).unwrap(),
                expected,
                "{arch}: {version:?}"
            );
        }
    }
}

#[test]
fn gui_callback_restores_interrupted_service_and_uses_guest_version_and_thread_state() {
    use crate::user::windows::context::RegContext;
    for arch in [WinArch::Arm64, WinArch::X64] {
        for status in [0, 0x103, 0x8000_0001, 0xc000_0001] {
            let (mut process, mut t, entry) = setup(arch);
            let p = process.state_mut();
            let resume = entry + 0x4000;
            t.cpu.set_pc(resume);
            let before = RegContext::capture(&t.cpu);
            assert_eq!(
                super::super::super::super::services::dispatch(p, &mut t, 0x12fd, resume - 4),
                Some(Outcome::Continue)
            );
            assert_eq!(t.cpu.pc(), entry);
            assert_eq!(p.space.u64(t.teb + 0x810).unwrap(), 0x602);
            assert_eq!(p.space.u64(t.teb + 0x78).unwrap(), u64::from(t.tid));
            assert_eq!(p.space.u64(t.teb + 0x800).unwrap(), 0x2000_0000);
            let value = p.gui.value.unwrap();
            assert_ne!(value, 0);
            assert_eq!(p.space.u32(p.peb + 0x108).unwrap(), value as u32);
            let buffer_offset = if arch == WinArch::Arm64 { 0 } else { 32 };
            let index_offset = if arch == WinArch::Arm64 { 12 } else { 44 };
            assert_eq!(p.space.u32(t.cpu.sp() + index_offset).unwrap(), 84);
            assert_ne!(p.space.u64(t.cpu.sp() + buffer_offset).unwrap(), 0);
            arguments(p, &mut t, [1, u64::from(u32::MAX), status]);
            assert_eq!(
                super::super::super::super::services::dispatch(p, &mut t, 5, entry + 0x100),
                Some(Outcome::Continue)
            );
            assert_eq!(t.cpu.pc(), resume);
            assert_eq!(t.cpu.sp(), before.sp());
            let success = status as u32 as i32 >= 0;
            assert_eq!(t.cpu.gpr(0), if success { value } else { 0 });
            assert_eq!(p.gui.threads[&t.tid].initialized, success);
            assert!(p.gui.threads[&t.tid].callbacks.is_empty());
            assert_eq!(
                p.space.u64(t.teb + 0x78).unwrap(),
                if success { u64::from(t.tid) } else { 0 }
            );
        }
    }
}

#[test]
fn guest_callback_dispatcher_reads_kernel_frame_and_returns_through_native_service() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        for (name, number) in [
            ("NtGdiInit2", 0x12fdu32),
            ("NtUserRemoteConnectState", 0x1528),
            ("NtUserGetThreadDesktop", 0x107b),
            ("NtUserRegisterLPK", 0x1513),
            ("NtUserGetProcessUIContextInformation", 0x147f),
        ] {
            let (mut process, mut t, entry) = setup(arch);
            let p = process.state_mut();
            let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
                unreachable!();
            };
            let inputs = std::sync::Arc::get_mut(inputs).unwrap();
            inputs.remote_connect_state = 3;
            inputs.process_ui_context = Ok([2, 3]);
            let index = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.win32u_services = Some((index, named_table(arch, name, number)));
            let marker = entry + 0x3000;
            let service = entry + 0x4000;
            let output = entry + 0x5000;
            p.space.wr(output, &[0xa5; 16]).unwrap();
            let (dispatcher, callback, syscall, marker_register) = match arch {
                WinArch::Arm64 => {
                    // Frame loads, TEB->PEB->KernelCallbackTable, BLR selected slot.
                    let dispatcher = [
                        0xf940_03e0u32,
                        0xb940_0be1,
                        0xb940_0fe2,
                        0xf940_3250,
                        0xf940_2e10,
                        0xf862_7a10,
                        0xd63f_0200,
                        0xd420_0020,
                    ]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>();
                    // Save delivered arguments; NtCallbackReturn(1, UINT32_MAX, 0).
                    let callback = [
                        0xa900_0660u32,
                        0xf900_0a62,
                        0xd280_0020,
                        0x1280_0001,
                        0x5280_0002,
                        0xd400_00a1,
                        0xd420_0040,
                    ]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                    (
                        dispatcher,
                        callback,
                        (0xd400_0001u32 | (number << 5)).to_le_bytes().to_vec(),
                        19,
                    )
                }
                WinArch::X64 => (
                    // RCX/RDX/R8 frame loads; GS:TEB->PEB->table; CALL selected slot.
                    vec![
                        0x48, 0x8b, 0x4c, 0x24, 0x20, 0x8b, 0x54, 0x24, 0x28, 0x44, 0x8b, 0x44,
                        0x24, 0x2c, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x48,
                        0x8b, 0x40, 0x60, 0x48, 0x8b, 0x40, 0x58, 0x42, 0xff, 0x14, 0xc0, 0xcc,
                    ],
                    // Store arguments through R12, then the native syscall ABI.
                    vec![
                        0x49, 0x89, 0x0c, 0x24, 0x49, 0x89, 0x54, 0x24, 0x08, 0x4d, 0x89, 0x44,
                        0x24, 0x10, 0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, 0xba, 0xff, 0xff,
                        0xff, 0xff, 0x45, 0x31, 0xc0, 0x49, 0x89, 0xca, 0xb8, 0x05, 0x00, 0x00,
                        0x00, 0x0f, 0x05, 0xcc,
                    ],
                    [vec![0xb8], number.to_le_bytes().to_vec(), vec![0x0f, 0x05]].concat(),
                    12,
                ),
                WinArch::X86 => unreachable!("paired WoW64 contexts are outside this fixture"),
            };
            p.space.wr(entry, &dispatcher).unwrap();
            p.space.wr(entry + 0x2000, &callback).unwrap();
            p.space.wr(service, &syscall).unwrap();
            p.space.wr(marker, &[0xa5; 24]).unwrap();
            assert_eq!(p.space.u64(t.teb + 0x60).unwrap(), p.peb);
            t.cpu.set_gpr(marker_register, marker);
            t.cpu.set_gpr(3, 0x1122_3344_5566_7788);
            t.cpu.set_pc(service);
            let original_sp = t.cpu.sp();
            let tid = t.tid;
            arguments(
                p,
                &mut t,
                [
                    if name == "NtUserGetProcessUIContextInformation" {
                        u64::MAX
                    } else if name == "NtUserRegisterLPK" {
                        0xf
                    } else {
                        u64::from(tid)
                    },
                    output,
                    0,
                ],
            );
            let expected = match name {
                "NtUserRemoteConnectState" => 3,
                "NtUserGetThreadDesktop" => {
                    let Availability::Available(inputs) = &p.native.as_ref().unwrap().gui else {
                        unreachable!()
                    };
                    u64::from(p.objects.desktop_handle(&inputs.assigned_desktop).unwrap())
                }
                "NtUserRegisterLPK" | "NtUserGetProcessUIContextInformation" => 1,
                _ => 0,
            };
            let boundary = t.cpu.run(64);
            assert_eq!(handle_stop(p, &mut t, boundary), Outcome::Continue);
            assert_eq!(t.cpu.pc(), entry);
            let callback_sp = t.cpu.sp();
            let value = p.gui.value.unwrap();
            let boundary = t.cpu.run(64);
            assert_eq!(handle_stop(p, &mut t, boundary), Outcome::Continue);
            assert_eq!(t.cpu.pc(), service + syscall.len() as u64);
            assert_eq!(t.cpu.sp(), original_sp);
            assert_eq!(
                t.cpu.gpr(0),
                if name == "NtGdiInit2" {
                    value
                } else {
                    expected
                }
            );
            assert_eq!(t.cpu.gpr(3), 0x1122_3344_5566_7788);
            assert_eq!(t.cpu.gpr(marker_register), marker);
            assert_eq!(
                p.space.u64(marker).unwrap(),
                callback_sp + if arch == WinArch::Arm64 { 48 } else { 88 }
            );
            assert_eq!(p.space.u64(marker + 8).unwrap(), 0);
            assert_eq!(p.space.u64(marker + 16).unwrap(), 84);
            assert!(p.gui.threads[&t.tid].initialized);
            assert!(p.gui.threads[&t.tid].callbacks.is_empty());
            if name == "NtUserGetProcessUIContextInformation" {
                assert_eq!(p.space.u32(output).unwrap(), 2);
                assert_eq!(p.space.u32(output + 4).unwrap(), 3);
                assert_eq!(p.space.u64(output + 8).unwrap(), 0xa5a5_a5a5_a5a5_a5a5);
            }
        }
    }
}

#[test]
fn remote_connect_state_cold_conversion_restores_the_query_result_and_failure_marker() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        for value in 0..=4 {
            for status in [0, 0x103, 0x8000_0001, 0xc000_0001] {
                let (mut process, mut t, entry) = setup(arch);
                let p = process.state_mut();
                let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
                    unreachable!();
                };
                std::sync::Arc::get_mut(inputs)
                    .unwrap()
                    .remote_connect_state = value;
                let index = p.modules.nt_services.as_ref().unwrap().0;
                p.modules.win32u_services =
                    Some((index, named_table(arch, "NtUserRemoteConnectState", 0x1528)));
                let resume = entry + 0x4000;
                t.cpu.set_pc(resume);
                t.cpu.set_gpr(3, 0x1122_3344_5566_7788);
                let sp = t.cpu.sp();
                let error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
                p.space.w32(error, 0x1234_5678).unwrap();
                assert_eq!(
                    super::super::super::super::services::dispatch(p, &mut t, 0x1528, resume - 4),
                    Some(Outcome::Continue)
                );
                assert_eq!(t.cpu.pc(), entry);
                assert_eq!(p.gui.threads[&t.tid].callbacks.len(), 1);
                assert_eq!(
                    p.gui.threads[&t.tid].callbacks[0].completion,
                    Completion::Value(u64::from(value))
                );
                arguments(p, &mut t, [1, u64::from(u32::MAX), status]);
                assert_eq!(
                    super::super::super::super::services::dispatch(p, &mut t, 5, entry + 0x100),
                    Some(Outcome::Continue)
                );
                let success = status as u32 as i32 >= 0;
                assert_eq!(t.cpu.gpr(0), if success { u64::from(value) } else { 0 });
                assert_eq!(t.cpu.gpr(3), 0x1122_3344_5566_7788);
                assert_eq!(t.cpu.pc(), resume);
                assert_eq!(t.cpu.sp(), sp);
                assert_eq!(p.gui.threads[&t.tid].initialized, success);
                assert!(p.gui.threads[&t.tid].callbacks.is_empty());
                assert_eq!(
                    p.space.u64(t.teb + 0x78).unwrap(),
                    if success { u64::from(t.tid) } else { 0 }
                );
                assert_eq!(p.space.u32(error).unwrap(), 0x1234_5678);
            }
        }
    }
}

#[test]
fn remote_connect_state_nested_query_preserves_the_outer_conversion_continuation() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut t, entry) = setup(arch);
        let p = process.state_mut();
        let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
            unreachable!();
        };
        std::sync::Arc::get_mut(inputs)
            .unwrap()
            .remote_connect_state = 4;
        let resume = entry + 0x4000;
        t.cpu.set_pc(resume);
        assert_eq!(
            super::super::super::super::services::dispatch(p, &mut t, 0x12fd, resume - 4),
            Some(Outcome::Continue)
        );
        let original = p.gui.value.unwrap();
        let callback_sp = t.cpu.sp();
        let index = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.win32u_services =
            Some((index, named_table(arch, "NtUserRemoteConnectState", 0x1528)));
        let rng = p.rng;
        let handles = p.objects.handle_count();
        let committed = p.vm.committed_bytes();
        for _ in 0..4 {
            assert_eq!(
                super::super::super::super::services::dispatch(p, &mut t, 0x1528, entry + 0x200),
                Some(Outcome::Continue)
            );
            assert_eq!(t.cpu.gpr(0), 4);
            assert_eq!(t.cpu.sp(), callback_sp);
            assert_eq!(p.gui.threads[&t.tid].callbacks.len(), 1);
            assert_eq!(
                p.gui.threads[&t.tid].callbacks[0].completion,
                Completion::Value(original)
            );
            assert_eq!(p.rng, rng);
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.vm.committed_bytes(), committed);
        }
        arguments(p, &mut t, [0, 0, 0]);
        assert_eq!(
            super::super::super::super::services::dispatch(p, &mut t, 5, entry + 0x100),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), original);
        assert_eq!(t.cpu.pc(), resume);
        assert!(p.gui.threads[&t.tid].callbacks.is_empty());
        assert_eq!(
            super::super::super::super::services::dispatch(p, &mut t, 0x1528, entry + 0x200),
            Some(Outcome::Continue)
        );
        assert_eq!(t.cpu.gpr(0), 4);
        assert!(p.gui.threads[&t.tid].callbacks.is_empty());
    }
}

#[path = "gui_tests/desktop_tests.rs"]
mod desktop_tests;

#[path = "gui_tests/lpk_tests.rs"]
mod lpk_tests;

#[path = "gui_tests/context_tests.rs"]
mod context_tests;
