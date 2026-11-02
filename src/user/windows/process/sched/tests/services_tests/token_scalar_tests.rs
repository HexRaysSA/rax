//! Captured scalar properties retain each measured native caller contract.
use super::*;
use crate::user::windows::security::token::scalars::{self, CapturedScalar, Scalars};
use std::collections::BTreeMap;

fn profile(arch: WinArch, laa: bool) -> &'static str {
    match (arch, laa) {
        (WinArch::Arm64, _) => "arm64",
        (WinArch::X64, _) => "x64",
        (WinArch::X86, false) => "x86",
        (WinArch::X86, true) => "x86-laa",
    }
}

fn recorded(corpus: &serde_json::Value, profile: &str) -> BTreeMap<u32, CapturedScalar> {
    scalars::CLASSES
        .into_iter()
        .map(|class| {
            let reference = &corpus["references"][profile][class.to_string()];
            let value = if reference["status"].as_u64().unwrap() == 0 {
                CapturedScalar::Value(reference["value"].as_u64().unwrap() as u32)
            } else {
                CapturedScalar::InvalidClass
            };
            (class, value)
        })
        .collect()
}

fn select(p: &mut Proc, values: &BTreeMap<u32, CapturedScalar>) {
    p.objects.select_wnf_catalog(
        crate::user::windows::wnf::tests::empty_subject_catalog(false).with_primary_token_scalars(
            Scalars::selected(values.iter().map(|(&c, &v)| (c, v))).unwrap(),
        ),
    );
}

/// Only successful scalar value bytes adapt to the independently queried host
/// value. Fault/status, required-size and alias behavior remain native goldens.
fn value_cells(p: &Proc, at: u64, output: u64, expected: &str, value: Option<u32>, width: u32) {
    let mut text = String::new();
    for (index, pair) in expected.as_bytes().chunks_exact(2).enumerate() {
        let address = at.wrapping_add(index as u64);
        if let Some(value) = value
            && address >= output
            && address - output < u64::from(width)
        {
            text.push_str(&format!(
                "{:02X}",
                value.to_le_bytes()[(address - output) as usize]
            ));
        } else {
            text.push_str(std::str::from_utf8(pair).unwrap());
        }
    }
    cells(p, at, &text);
}

#[cfg(windows)]
fn native_reference() -> BTreeMap<u32, CapturedScalar> {
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtOpenProcessToken(process: Handle, access: u32, output: *mut Handle) -> i32;
        fn NtQueryInformationToken(
            token: Handle,
            class: u32,
            output: *mut c_void,
            bytes: u32,
            returned: *mut u32,
        ) -> i32;
    }
    struct Owned(Handle);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: one private token handle, never exposed to a guest.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let mut raw = std::ptr::null_mut();
    // SAFETY: current process, TOKEN_QUERY, exclusive initialized HANDLE.
    assert_eq!(
        unsafe { NtOpenProcessToken(GetCurrentProcess(), 8, &mut raw) },
        0
    );
    assert!(!raw.is_null());
    let owned = Owned(raw);
    scalars::CLASSES
        .into_iter()
        .map(|class| {
            // Match the native caller alignment independently of stack layout.
            let mut native_data = 0xA5A5_A5A5u32;
            let mut returned = 0;
            // SAFETY: private token and exclusively owned scalar/length buffers.
            let status = unsafe {
                NtQueryInformationToken(
                    owned.0,
                    class,
                    (&mut native_data as *mut u32).cast(),
                    4,
                    &mut returned,
                )
            } as u32;
            let data = native_data.to_ne_bytes();
            let value = if status == STATUS_INVALID_INFO_CLASS {
                assert_eq!((returned, data), (0, [0xA5; 4]));
                CapturedScalar::InvalidClass
            } else {
                assert_eq!(status, STATUS_SUCCESS);
                assert_eq!(returned, scalars::width(class).unwrap());
                if returned == 1 {
                    assert_eq!(data[1..], [0xA5; 3]);
                    CapturedScalar::Value(u32::from(data[0]))
                } else {
                    CapturedScalar::Value(u32::from_ne_bytes(data))
                }
            };
            (class, value)
        })
        .collect()
}

fn replay(native: bool) {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-scalars/cases.json"
    ))
    .unwrap();
    assert_eq!(corpus["matrix-queries"], 109800);
    let values = if native {
        #[cfg(windows)]
        {
            native_reference()
        }
        #[cfg(not(windows))]
        {
            panic!("native scalar reference requires Windows")
        }
    } else {
        recorded(&corpus, "arm64")
    };
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
            for (&class, &value) in &values {
                assert_eq!(
                    p.objects.primary_token_scalar(class),
                    Some(value),
                    "independent native capture {class}"
                );
            }
        } else {
            select(p, &values);
        }
        let module =
            native.then(|| crate::user::windows::loader::load_dll(p, "ntdll.dll").unwrap());
        for class in scalars::CLASSES {
            let mut index = corpus["mapping"][profile(arch, laa)][class.to_string()]
                .as_u64()
                .unwrap();
            if native
                && values[&class] == CapturedScalar::InvalidClass
                && !(arch == WinArch::X86 && matches!(class, 40 | 45))
            {
                index = corpus["mapping"]["arm64"]["45"].as_u64().unwrap();
            }
            let rows = corpus["groups"][index as usize]["cases"]
                .as_array()
                .unwrap();
            assert_eq!(rows.len(), 1830);
            for (ordinal, row) in rows.iter().enumerate() {
                let field = |name: &str| row[name].as_str().unwrap();
                let (output, returned) = destinations(p, base, field("role").parse().unwrap());
                let token = handle(p, field("kind"), handles);
                let length = u32::from_str_radix(field("length"), 16).unwrap();
                let expected = u32::from_str_radix(field("status"), 16).unwrap();
                let last_error =
                    thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
                p.space.w32(last_error, 0x7E11_ABCD).unwrap();
                let (sp, rng, count, objects) = (
                    thread.cpu.sp(),
                    p.rng,
                    p.objects.handle_count(),
                    p.objects.iter().count(),
                );
                let args = [token, u64::from(class), output, u64::from(length), returned];
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
                        panic!("native Windows leaf requires Windows")
                    }
                } else {
                    assert_eq!(invoke(p, &mut thread, &args), Outcome::Continue);
                    thread.cpu.gpr(0) as u32
                };
                assert_eq!(actual, expected, "{arch}/{laa}/{class}/{ordinal}/{row}");
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
                for (address, name) in [(output, "output-protect"), (returned, "returned-protect")]
                {
                    if (base..base + PAGE_SIZE * 8).contains(&address) {
                        assert_eq!(
                            p.vm.query(address).unwrap().protect,
                            u32::from_str_radix(field(name), 16).unwrap()
                        );
                    }
                }
                let value = if expected == STATUS_SUCCESS {
                    match values[&class] {
                        CapturedScalar::Value(value) => Some(value),
                        _ => None,
                    }
                } else {
                    None
                };
                let width = scalars::width(class).unwrap_or(0);
                value_cells(p, output, output, field("output-bytes-cells"), value, width);
                value_cells(
                    p,
                    returned,
                    output,
                    field("return-bytes-cells"),
                    value,
                    width,
                );
            }
        }
    }
}

#[test]
fn native_token_scalars_replay_all_109800_native_matrix_queries() {
    replay(false);
}

#[cfg(windows)]
#[test]
fn native_token_scalars_installed_leaves_match_independent_host_capture() {
    replay(true);
}

#[test]
fn native_token_scalars_preserve_nonzero_values_and_refuse_uncaptured_identity() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        for class in scalars::CLASSES
            .into_iter()
            .filter(|c| !matches!(c, 45 | 46))
        {
            let examples: &[u32] = match class {
                21 => &[0, 1, 7, 255],
                _ => &[0, 1, 7, 0x1234_5678, 0x8000_0000, u32::MAX],
            };
            for &value in examples {
                let values = BTreeMap::from([(class, CapturedScalar::Value(value))]);
                select(p, &values);
                for kind in ["primary", "effective", "real"] {
                    let (output, returned) = destinations(p, base, 0);
                    let token = handle(p, kind, handles);
                    let sp = thread.cpu.sp();
                    assert_eq!(
                        invoke(
                            p,
                            &mut thread,
                            &[token, u64::from(class), output, 4, returned]
                        ),
                        Outcome::Continue
                    );
                    thread.cpu.set_sp(sp);
                    if arch == WinArch::X86 && class == 40 {
                        assert_eq!(thread.cpu.gpr(0) as u32, STATUS_INVALID_INFO_CLASS);
                        assert_eq!(p.space.u32(output).unwrap(), 0xA5A5_A5A5);
                        assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
                    } else {
                        assert_eq!(thread.cpu.gpr(0), 0);
                        let width = scalars::width(class).unwrap();
                        assert_eq!(p.space.u32(returned).unwrap(), width);
                        let mut expected = [0xA5; 4];
                        expected[..width as usize]
                            .copy_from_slice(&value.to_le_bytes()[..width as usize]);
                        assert_eq!(p.space.bytes(output, 4).unwrap(), expected);
                    }
                }
            }
        }
    }
    for arch in WinArch::ALL {
        for no_subject in [false, true] {
            let (mut process, mut thread, base, _) = setup(arch, false);
            let p = process.state_mut();
            let values = Scalars::selected([(42, CapturedScalar::Value(1))]).unwrap();
            let catalog = if no_subject {
                crate::user::windows::wnf::Catalog::default().with_primary_token_scalars(values)
            } else {
                crate::user::windows::wnf::tests::empty_subject_catalog(false)
            };
            p.objects.select_wnf_catalog(catalog);
            let (output, returned) = destinations(p, base, 0);
            assert_ne!(
                invoke(
                    p,
                    &mut thread,
                    &[arch.ptr(u64::MAX - 3), 42, output, 4, returned]
                ),
                Outcome::Continue
            );
            assert_eq!(p.space.u32(output).unwrap(), 0xA5A5_A5A5);
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
        }
        let (mut process, mut thread, base, _) = setup(arch, false);
        let p = process.state_mut();
        select(p, &BTreeMap::from([(42, CapturedScalar::Value(0))]));
        let subject = crate::user::windows::security::Subject {
            statistics: None,
            attributes: None,
            user_attributes: 0,
            user: vec![],
            groups: vec![],
            restricted: vec![],
            app_container: true,
            privileges: vec![],
        };
        let id = p
            .objects
            .create(Object::ImpersonationToken(std::sync::Arc::new(subject)));
        let token = u64::from(p.objects.open_access(id, false, 8).unwrap());
        let (output, returned) = destinations(p, base, 0);
        let sp = thread.cpu.sp();
        assert_ne!(
            invoke(p, &mut thread, &[token, 42, output, 4, returned]),
            Outcome::Continue
        );
        thread.cpu.set_sp(sp);
        assert_eq!(p.space.u32(output).unwrap(), 0xA5A5_A5A5);
        assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
        assert_eq!(
            invoke(p, &mut thread, &[token, 29, output, 4, returned]),
            Outcome::Continue
        );
        assert_eq!(
            p.space.u32(output).unwrap(),
            1,
            "AppContainer retains the impersonation subject"
        );
    }
}
