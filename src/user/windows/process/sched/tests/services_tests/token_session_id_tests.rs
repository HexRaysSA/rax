//! TokenSessionId uses captured DWORDs and the independently measured probes.
use super::*;
use crate::user::windows::{layout, security::Subject};

fn captured(p: &mut Proc, value: u32) {
    p.objects.select_wnf_catalog(
        crate::user::windows::wnf::tests::empty_subject_catalog(false)
            .with_primary_token_session_id(value),
    );
}

fn replay(native: bool) {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-session-id/cases.json"
    ))
    .unwrap();
    assert_eq!(corpus["class"], 12);
    let rows = corpus["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 1830);
    let profiles = if native {
        let host = if cfg!(target_arch = "aarch64") {
            WinArch::Arm64
        } else if cfg!(target_arch = "x86_64") {
            WinArch::X64
        } else {
            WinArch::X86
        };
        let mut profiles = vec![(host, false)];
        if host != WinArch::X86 {
            profiles.push((WinArch::X86, false));
        }
        profiles.push((WinArch::X86, true));
        profiles
    } else {
        vec![
            (WinArch::Arm64, false),
            (WinArch::X64, false),
            (WinArch::X86, false),
            (WinArch::X86, true),
        ]
    };
    for (arch, laa) in profiles {
        let (mut process, mut thread, base, handles) = setup_runtime(arch, laa, native);
        let p = process.state_mut();
        if native {
            #[cfg(windows)]
            assert_eq!(
                p.objects.primary_token_session_id(),
                Some(native_host_profile::primary_token_session_id()),
                "captured primary-token session must match the independent host query"
            );
            let process_session = p.objects.wnf_queries().unwrap().session;
            assert_eq!(
                p.space
                    .u32(p.peb + layout::offsets(arch).peb_session_id)
                    .unwrap(),
                process_session
            );
        }
        // Exact corpus outputs encode session zero. Exercise the installed
        // leaf against that explicit replay input, after checking live capture.
        captured(p, 0);
        let module =
            native.then(|| crate::user::windows::loader::load_dll(p, "ntdll.dll").unwrap());
        for (index, row) in rows.iter().enumerate() {
            let value = |name: &str| row[name].as_str().unwrap();
            let (output, returned) = destinations(p, base, value("role").parse().unwrap());
            let token = handle(p, value("kind"), handles);
            let length = u32::from_str_radix(value("length"), 16).unwrap();
            let expected = u32::from_str_radix(value("status"), 16).unwrap();
            let last_error = thread.teb + layout::offsets(arch).teb_last_error;
            p.space.w32(last_error, 0x7E11_ABCD).unwrap();
            let (sp, rng, count, objects) = (
                thread.cpu.sp(),
                p.rng,
                p.objects.handle_count(),
                p.objects.iter().count(),
            );
            let args = [token, 12, output, u64::from(length), returned];
            let actual = if let Some(module) = module {
                #[cfg(windows)]
                {
                    super::super::virtual_memory_tests::installed::invoke(
                        p,
                        &mut thread,
                        module,
                        "NtQueryInformationToken",
                        &args,
                    )
                }
                #[cfg(not(windows))]
                {
                    let _ = module;
                    panic!("installed Windows leaf requires a native Windows host")
                }
            } else {
                assert_eq!(invoke(p, &mut thread, &args), Outcome::Continue);
                thread.cpu.gpr(0) as u32
            };
            assert_eq!(actual, expected, "{arch}/{laa}/{index}/{row}");
            if !native {
                assert_eq!(
                    thread.cpu.sp(),
                    sp + if arch == WinArch::X86 { 4 } else { 0 }
                );
            }
            thread.cpu.set_sp(sp);
            assert!(thread.frames.is_empty());
            assert_eq!(p.rng, rng);
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                (count, objects)
            );
            assert_eq!(p.space.u32(last_error).unwrap(), 0x7E11_ABCD);
            for (address, name) in [(output, "output-protect"), (returned, "returned-protect")] {
                if (base..base + PAGE_SIZE * 8).contains(&address) {
                    assert_eq!(
                        p.vm.query(address).unwrap().protect,
                        u32::from_str_radix(value(name), 16).unwrap()
                    );
                }
            }
            cells(p, output, value("output-bytes-cells"));
            cells(p, returned, value("return-bytes-cells"));
        }
    }
}

#[test]
fn native_token_session_id_replays_all_7320_native_rows() {
    replay(false);
}

#[cfg(windows)]
#[test]
fn native_token_session_id_installed_leaves_replay_native_profiles() {
    replay(true);
}

#[test]
fn native_token_session_id_preserves_nonzero_values_and_rejects_missing_identity() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        for value in [0, 1, 7, 0x1234_5678, 0x8000_0000, u32::MAX] {
            captured(p, value);
            for kind in ["primary", "effective", "real"] {
                let (output, returned) = destinations(p, base, 0);
                let token = handle(p, kind, handles);
                let sp = thread.cpu.sp();
                assert_eq!(
                    invoke(p, &mut thread, &[token, 12, output, 8, returned]),
                    Outcome::Continue
                );
                thread.cpu.set_sp(sp);
                assert_eq!(thread.cpu.gpr(0), 0);
                assert_eq!(p.space.u32(output).unwrap(), value);
                assert_eq!(p.space.u32(returned).unwrap(), 4);
                assert_eq!(p.space.bytes(output + 4, 4).unwrap(), [0xA5; 4]);
            }
        }
        for catalog in [
            crate::user::windows::wnf::tests::empty_subject_catalog(false),
            crate::user::windows::wnf::Catalog::default().with_primary_token_session_id(7),
        ] {
            p.objects.select_wnf_catalog(catalog);
            let (output, returned) = destinations(p, base, 0);
            assert_ne!(
                invoke(
                    p,
                    &mut thread,
                    &[arch.ptr(u64::MAX - 3), 12, output, 4, returned]
                ),
                Outcome::Continue
            );
            assert_eq!(p.space.u32(output).unwrap(), 0xA5A5_A5A5);
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
        }
        captured(p, 7);
        let id = p
            .objects
            .create(Object::ImpersonationToken(std::sync::Arc::new(Subject {
                statistics: None,
                attributes: None,
                user_attributes: 0,
                user: vec![],
                groups: vec![],
                restricted: vec![],
                app_container: true,
                privileges: vec![],
            })));
        let impersonation = u64::from(p.objects.open_access(id, false, 8).unwrap());
        let (output, returned) = destinations(p, base, 0);
        assert_ne!(
            invoke(p, &mut thread, &[impersonation, 12, output, 4, returned]),
            Outcome::Continue
        );
        assert_eq!(p.space.u32(output).unwrap(), 0xA5A5_A5A5);
        assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
        let sp = thread.cpu.sp();
        assert_eq!(
            invoke(p, &mut thread, &[impersonation, 29, output, 4, returned]),
            Outcome::Continue
        );
        thread.cpu.set_sp(sp);
        assert_eq!(thread.cpu.gpr(0), 0);
        assert_eq!(
            p.space.u32(output).unwrap(),
            1,
            "AppContainer keeps its impersonation subject"
        );
    }
}
