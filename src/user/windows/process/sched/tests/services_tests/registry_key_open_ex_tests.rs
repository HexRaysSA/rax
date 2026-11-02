//! Extended-key dispatch and independently measured output/failure ordering.
use super::*;

#[path = "registry_key_open_ex_replay_tests.rs"]
mod replay;

#[test]
fn native_open_key_ex_four_slot_family_preserves_prior_symbols_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::{hle::Arg, loader::builtin};
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtOpenKeyEx"))
        .unwrap();
    assert_eq!(current.exports[family - 1][0].name, "NtQueryKey");
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    let appended = BuiltinDll {
        exports: &current.exports[..=family],
        ..previous
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(&appended, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(
            &after.symbols[..before.symbols.len()],
            before.symbols.as_slice()
        );
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert_eq!(
            dll::nt_service("NtOpenKeyEx", arch).unwrap().args,
            &[Arg::Ptr, Arg::I32, Arg::Ptr, Arg::I32]
        );
    }
}

#[test]
fn native_open_key_ex_odd_name_uses_captured_kernel_and_preserves_value_queries() {
    for arch in WinArch::ALL {
        for (build, machine, expected) in [
            (20348, 0x8664, STATUS_OBJECT_NAME_INVALID),
            (26100, 0x8664, STATUS_OBJECT_NAME_INVALID),
            (29683, 0xAA64, STATUS_INVALID_PARAMETER),
            (29695, 0xAA64, STATUS_INVALID_PARAMETER),
        ] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            super::super::native_profile::kernel_profile(p, build, machine);
            let attrs = base + 2 * PAGE_SIZE;
            let descriptor = attrs + 64;
            unicode(p, descriptor, attrs + 128, NLS_KEY);
            attributes(p, attrs, descriptor, 0, 0x40);
            assert_eq!(
                call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
                STATUS_SUCCESS
            );
            let key = p.space.ptr(base, arch.ptr_size()).unwrap();
            p.space.w16(descriptor, 1).unwrap();
            let before = p.objects.handle_count();
            for service in ["NtOpenKey", "NtOpenKeyEx"] {
                let args = [base, 1, attrs, 0];
                assert_eq!(
                    call(
                        p,
                        &mut t,
                        service,
                        &args[..if service == "NtOpenKey" { 3 } else { 4 }]
                    ),
                    expected,
                    "{arch}/{build}/{machine:x}/{service}"
                );
                assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
                assert_eq!(p.objects.handle_count(), before);
            }
            // Query-value's existing descriptor validation is a separate contract.
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtQueryValueKey",
                    &[key, descriptor, 2, base + 128, 64, base + 64]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(call(p, &mut t, "NtClose", &[key]), STATUS_SUCCESS);
        }
    }
}

#[test]
fn native_open_key_ex_unknown_odd_name_profile_is_explicit() {
    for arch in WinArch::ALL {
        for (build, machine) in [(12345, 0x8664), (29695, 0x8664), (20348, 0xAA64)] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            super::super::native_profile::kernel_profile(p, build, machine);
            let attrs = base + 2 * PAGE_SIZE;
            unicode(p, attrs + 64, attrs + 128, NLS_KEY);
            attributes(p, attrs, attrs + 64, 0, 0x40);
            p.space.w16(attrs + 64, 1).unwrap();
            let module = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((module, table(arch, "NtOpenKeyEx", 0x12)));
            arguments(p, &mut t, &[base, 1, attrs, 0]);
            let outcome = dispatch(p, &mut t);
            assert!(
                matches!(outcome, Outcome::Fail(ref text) if text.contains("registry odd key-name kernel profile is not captured")),
                "{arch}/{build}/{machine:x}/{outcome:?}"
            );
            assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
        }
    }
}

#[test]
fn native_open_key_ex_invalid_options_keep_native_and_wow64_probe_order() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let attrs = base + PAGE_SIZE * 2;
        unicode(p, attrs + 64, attrs + 128, NLS_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x40);
        for option in [1, 2, 0x20, 0x8000_0000, 0xFFFF_FFFF] {
            for out in [0, 1, base + PAGE_SIZE] {
                p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                let before = p.objects.handle_count();
                let actual = call(p, &mut t, "NtOpenKeyEx", &[out, 0x20019, attrs, option]);
                let expected = if arch != WinArch::X86 || out == 0 {
                    STATUS_INVALID_PARAMETER_4
                } else if out == 1 {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_GUARD_PAGE_VIOLATION
                };
                assert_eq!(actual, expected, "{arch}/{option:x}/{out:x}");
                assert_eq!(p.objects.handle_count(), before);
                assert_eq!(
                    p.vm.query(base + PAGE_SIZE).unwrap().protect,
                    if arch == WinArch::X86 && out == base + PAGE_SIZE {
                        prot::READWRITE
                    } else {
                        prot::READWRITE | prot::GUARD
                    }
                );
            }
        }
    }
}

#[test]
fn native_open_key_ex_null_output_preserves_failure_and_observed_success_leak() {
    use crate::user::windows::registry::{HiveHeader, UserPolicyRoot};
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let attrs = base + PAGE_SIZE * 2;
        for service in ["NtOpenKey", "NtOpenKeyEx"] {
            unicode(p, attrs + 64, attrs + 128, NLS_KEY);
            attributes(p, attrs, attrs + 64, 0, 0x40);
            let before = p.objects.handle_count();
            let args = [0, 0x20019, attrs, 0];
            assert_eq!(
                call(
                    p,
                    &mut t,
                    service,
                    &args[..if service == "NtOpenKey" { 3 } else { 4 }]
                ),
                STATUS_ACCESS_VIOLATION
            );
            assert_eq!(
                p.objects.handle_count(),
                before + usize::from(arch == WinArch::X86)
            );
        }
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        p.registry = p
            .registry
            .clone()
            .with_primary_hive(
                &sid,
                Some(HiveHeader {
                    canonical: "\\REGISTRY\\USER\\.DEFAULT".encode_utf16().collect(),
                    children: 9,
                    values: vec![],
                }),
            )
            .unwrap()
            .with_user_policy_root(UserPolicyRoot::System, &sid, None)
            .unwrap();
        unicode(p, attrs + 64, attrs + 128, "\\Registry\\User\\S-1-5-18");
        attributes(p, attrs, attrs + 64, 0, 0x40);
        assert_eq!(
            call(p, &mut t, "NtOpenKeyEx", &[base, 0x20019, attrs, 0]),
            STATUS_SUCCESS
        );
        let root = p.space.ptr(base, arch.ptr_size()).unwrap();
        for name in [
            "Software\\Policies\\Microsoft\\Windows\\System",
            "Software\\\\Policies\\\\Microsoft\\\\Windows\\\\System",
        ] {
            unicode(p, attrs + 64, attrs + 128, name);
            attributes(p, attrs, attrs + 64, root, 0x40);
            let before = p.objects.handle_count();
            assert_eq!(
                call(p, &mut t, "NtOpenKeyEx", &[0, 0x20019, attrs, 0]),
                if arch == WinArch::X86 {
                    STATUS_OBJECT_NAME_NOT_FOUND
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            );
            assert_eq!(p.objects.handle_count(), before);
            assert_eq!(
                call(p, &mut t, "NtOpenKeyEx", &[base, 0x20019, attrs, 0]),
                STATUS_OBJECT_NAME_NOT_FOUND
            );
            assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
        }
    }
}

#[test]
fn native_open_key_ex_backup_restore_uses_captured_privileges_and_native_grants() {
    use crate::user::windows::{
        security::{Privilege, Subject},
        wnf::Catalog,
    };
    for arch in WinArch::ALL {
        for (profile, expected) in [(0, 0), (1, 0x0102_0019), (2, 0x010F_0006), (3, 0x010F_001F)] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let subject = Subject {
                statistics: None,
                user_attributes: 0,
                user: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                groups: vec![],
                restricted: vec![],
                app_container: false,
                privileges: [17, 18]
                    .into_iter()
                    .enumerate()
                    .map(|(index, luid)| Privilege {
                        luid,
                        attributes: if profile & (1 << index) != 0 { 2 } else { 0 },
                    })
                    .collect(),
                attributes: None,
            };
            p.objects
                .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());
            let attrs = base + PAGE_SIZE * 2;
            unicode(p, attrs + 64, attrs + 128, NLS_KEY);
            attributes(p, attrs, attrs + 64, 0, 0x40);
            for desired in [
                0,
                1,
                2,
                8,
                0x10,
                0x20000,
                0x20019,
                0x8000_0000,
                0x0200_0000,
                0xF003F,
            ] {
                for view in [0, 0x100, 0x200, 0x300] {
                    let actual = call(p, &mut t, "NtOpenKeyEx", &[base, desired | view, attrs, 4]);
                    let status = if arch == WinArch::X86 && view == 0x300 {
                        STATUS_INVALID_PARAMETER
                    } else if expected == 0 {
                        STATUS_ACCESS_DENIED
                    } else {
                        STATUS_SUCCESS
                    };
                    assert_eq!(
                        actual, status,
                        "{arch}/profile{profile}/{desired:x}/{view:x}"
                    );
                    if status == STATUS_SUCCESS {
                        let h = p.space.ptr(base, arch.ptr_size()).unwrap();
                        assert_eq!(p.objects.access(h), Some(expected));
                        assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
#[test]
fn native_open_key_ex_installed_leaf_uses_four_slots_and_ret16() {
    use crate::user::windows::{WindowsConfig, WindowsProcess, loader};
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else {
        WinArch::X64
    };
    for arch in [host, WinArch::X86] {
        let image: &[u8] = match arch {
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-open-key-ex.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let base =
            p.vm.allocate(
                None,
                PAGE_SIZE * 2,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let attrs = base + 128;
        unicode(p, attrs + 64, base + 256, NLS_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x40);
        let before = (p.objects.handle_count(), p.objects.iter().count());
        for options in [0, 8, 16, 24] {
            for view in [0, 0x100, 0x200] {
                assert_eq!(
                    super::installed::invoke(
                        p,
                        &mut t,
                        module,
                        "NtOpenKeyEx",
                        &[base, 0x20019 | view, attrs, options]
                    ),
                    STATUS_SUCCESS
                );
                let h = p.space.ptr(base, arch.ptr_size()).unwrap();
                assert_eq!(p.objects.access(h), Some(0x20019));
                assert_eq!(
                    super::installed::invoke(p, &mut t, module, "NtClose", &[h]),
                    STATUS_SUCCESS
                );
            }
        }
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}
