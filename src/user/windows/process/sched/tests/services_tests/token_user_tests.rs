//! Native TokenUser data, fault order and copy progress, independent of HLE code.
use super::*;
use crate::user::windows::layout;

fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-user/cases.json"
    ))
    .unwrap()
}

fn profiles() -> [(WinArch, bool, &'static str); 4] {
    [
        (WinArch::Arm64, false, "arm64"),
        (WinArch::X64, false, "x64"),
        (WinArch::X86, false, "x86"),
        (WinArch::X86, true, "x86-laa"),
    ]
}

fn number(row: &serde_json::Value, name: &str) -> u32 {
    u32::from_str_radix(row[name].as_str().unwrap(), 16).unwrap()
}

fn observed_cells(p: &Proc, at: u64, output: u64, expected: &str) {
    assert!(expected.len().is_multiple_of(2));
    let pointer = (output + 2 * p.arch.ptr_size()).to_le_bytes();
    for (i, pair) in expected.as_bytes().chunks_exact(2).enumerate() {
        let byte = match pair {
            b"??" => continue,
            [b'@', digit @ b'0'..=b'7'] => pointer[usize::from(digit - b'0')],
            _ => u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap(),
        };
        assert_eq!(
            p.space.u8(at + i as u64).unwrap(),
            byte,
            "cell{i} at{at:#x}"
        );
    }
}

fn impersonation(p: &mut Proc) -> u64 {
    let subject = p.objects.primary_token_subject().unwrap();
    assert_eq!(
        subject.user,
        crate::user::windows::wnf::tests::hex("010100000000000512000000")
    );
    let id = p.objects.create(Object::ImpersonationToken(subject));
    u64::from(p.objects.open_access(id, false, 8).unwrap())
}

fn query(
    p: &mut Proc,
    thread: &mut Thread,
    token: u64,
    output: u64,
    length: u32,
    returned: u64,
) -> u32 {
    let (sp, rng, handles, objects, committed) = (
        thread.cpu.sp(),
        p.rng,
        p.objects.handle_count(),
        p.objects.iter().count(),
        p.vm.committed_bytes(),
    );
    assert_eq!(
        invoke(p, thread, &[token, 1, output, u64::from(length), returned]),
        Outcome::Continue
    );
    assert_eq!(
        thread.cpu.sp(),
        sp + if p.arch == WinArch::X86 { 4 } else { 0 }
    );
    thread.cpu.set_sp(sp);
    assert!(thread.frames.is_empty());
    assert_eq!(
        (
            p.rng,
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes()
        ),
        (rng, handles, objects, committed)
    );
    thread.cpu.gpr(0) as u32
}

#[test]
fn native_token_user_replays_all_20064_native_matrix_cases() {
    let corpus = corpus();
    let mut calls = 0;
    for (arch, laa, profile) in profiles() {
        let (mut process, mut thread, base, handles) = setup(arch, laa);
        let p = process.state_mut();
        let impersonation = impersonation(p);
        let rows = corpus["groups"][corpus["mapping"][profile].as_u64().unwrap() as usize]["cases"]
            .as_array()
            .unwrap();
        assert_eq!(rows.len(), 5016);
        for (index, row) in rows.iter().enumerate() {
            let (output, returned) =
                destinations(p, base, row["role"].as_str().unwrap().parse().unwrap());
            let kind = row["kind"].as_str().unwrap();
            let token = if kind == "impersonation" {
                impersonation
            } else {
                handle(p, kind, handles)
            };
            let last_error = thread.teb + layout::offsets(arch).teb_last_error;
            p.space.w32(last_error, 0x7E11_ABCD).unwrap();
            assert_eq!(
                query(
                    p,
                    &mut thread,
                    token,
                    output,
                    number(row, "length"),
                    returned
                ),
                number(row, "status"),
                "{profile}/{index}/{row}"
            );
            assert_eq!(
                p.space.u32(last_error).unwrap(),
                number(row, "last-error"),
                "last-error{profile}/{index}"
            );
            for (at, name) in [(output, "output-protect"), (returned, "returned-protect")] {
                if (base..base + PAGE_SIZE * 8).contains(&at) {
                    assert_eq!(
                        p.vm.query(at).unwrap().protect,
                        number(row, name),
                        "{profile}/{index}/{name}"
                    );
                }
            }
            observed_cells(p, output, output, row["output-cells"].as_str().unwrap());
            observed_cells(p, returned, output, row["return-cells"].as_str().unwrap());
            observed_cells(p, output, output, row["payload"].as_str().unwrap());
            calls += 1;
        }
    }
    assert_eq!(calls, 20064);
}

#[test]
fn native_token_user_replays_all_2624_native_page_boundary_copies() {
    let corpus = corpus();
    let mut calls = 0;
    for (arch, laa, profile) in profiles() {
        let (mut process, mut thread, base, handles) = setup(arch, laa);
        let p = process.state_mut();
        let impersonation = impersonation(p);
        let rows =
            corpus["groups"][corpus["mapping"][profile].as_u64().unwrap() as usize]["boundaries"]
                .as_array()
                .unwrap();
        assert_eq!(rows.len(), 656);
        for (index, row) in rows.iter().enumerate() {
            let (_, returned) = destinations(p, base, 0);
            let side: u64 = row["side"].as_str().unwrap().parse().unwrap();
            let remaining: u64 = row["remaining"].as_str().unwrap().parse().unwrap();
            p.vm.protect(
                base + PAGE_SIZE * (1 + side),
                PAGE_SIZE,
                number(row, "protection"),
            )
            .unwrap();
            let output = base + PAGE_SIZE * 2 - remaining;
            let token = if row["subject"] == "0" {
                handles[1]
            } else {
                impersonation
            };
            assert_eq!(
                query(p, &mut thread, token, output, 64, returned),
                number(row, "status"),
                "{profile}/{index}/{row}"
            );
            assert_eq!(p.space.u32(returned).unwrap(), number(row, "returned"));
            for (page, name) in [(1, "first-after"), (2, "second-after")] {
                assert_eq!(
                    p.vm.query(base + PAGE_SIZE * page).unwrap().protect,
                    number(row, name),
                    "{profile}/{index}/{name}"
                );
            }
            observed_cells(p, output, output, row["cells"].as_str().unwrap());
            calls += 1;
        }
    }
    assert_eq!(calls, 2624);
}

fn subject(user: Vec<u8>) -> crate::user::windows::security::Subject {
    crate::user::windows::security::Subject {
        statistics: None,
        attributes: None,
        user_attributes: 0,
        user,
        groups: vec![],
        restricted: vec![],
        privileges: vec![],
        app_container: false,
    }
}

#[test]
fn native_token_user_retains_variable_sid_bytes_and_native64_padding_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        for count in 0..=15 {
            let mut sid = vec![1, count, 0, 0, 0, 0, 0, 5];
            for i in 0..count {
                sid.extend((0xA1B2_C300 + u32::from(i)).to_le_bytes());
            }
            let attributes = 0xA1B2_C300 + u32::from(count);
            let mut selected = subject(sid.clone());
            selected.user_attributes = attributes;
            p.objects.select_wnf_catalog(
                crate::user::windows::wnf::Catalog::selected(vec![], selected).unwrap(),
            );
            let header = 2 * arch.ptr_size();
            let required = header as u32 + sid.len() as u32;
            for length in [required - 1, required, required + 8] {
                let (output, returned) = destinations(p, base, 0);
                assert_eq!(
                    query(p, &mut thread, handles[1], output, length, returned),
                    if length < required {
                        STATUS_BUFFER_TOO_SMALL
                    } else {
                        STATUS_SUCCESS
                    }
                );
                assert_eq!(p.space.u32(returned).unwrap(), required);
                if length < required {
                    assert_eq!(
                        p.space.bytes(output, required as usize).unwrap(),
                        vec![0xA5; required as usize]
                    );
                } else {
                    assert_eq!(
                        p.space.ptr(output, arch.ptr_size()).unwrap(),
                        output + header
                    );
                    assert_eq!(p.space.u32(output + arch.ptr_size()).unwrap(), attributes);
                    if arch.ptr_size() == 8 {
                        assert_eq!(p.space.u32(output + 12).unwrap(), 0xA5A5_A5A5);
                    }
                    assert_eq!(p.space.bytes(output + header, sid.len()).unwrap(), sid);
                    assert_eq!(
                        p.space.u32(output + u64::from(required)).unwrap(),
                        0xA5A5_A5A5
                    );
                }
            }
        }
    }
}

#[test]
fn native_token_user_uses_impersonation_identity_without_primary_catalog_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, _) = setup(arch, false);
        let p = process.state_mut();
        let sid = crate::user::windows::wnf::tests::hex("01020000000000050700000009000000");
        let id = p
            .objects
            .create(Object::ImpersonationToken(std::sync::Arc::new(subject(
                sid.clone(),
            ))));
        let token = u64::from(p.objects.open_access(id, false, 8).unwrap());
        p.objects
            .select_wnf_catalog(crate::user::windows::wnf::Catalog::default());
        let (output, returned) = destinations(p, base, 0);
        assert_eq!(
            query(p, &mut thread, token, output, 64, returned),
            STATUS_SUCCESS
        );
        assert_eq!(
            p.space.u32(returned).unwrap(),
            (2 * arch.ptr_size()) as u32 + sid.len() as u32
        );
        assert_eq!(
            p.space
                .bytes(output + 2 * arch.ptr_size(), sid.len())
                .unwrap(),
            sid
        );
    }
}

#[test]
fn native_token_user_refuses_uncaptured_primary_identity_without_fabricating_output() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        p.objects
            .select_wnf_catalog(crate::user::windows::wnf::Catalog::default());
        let (output, returned) = destinations(p, base, 0);
        assert!(
            matches!(invoke(p, &mut thread, &[handles[1], 1, output, 64, returned]), Outcome::Fail(reason) if reason.contains("user SID is not captured"))
        );
        assert_eq!(p.space.bytes(output, 64).unwrap(), vec![0xA5; 64]);
        assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
    }
}

#[cfg(windows)]
fn native_user() -> (Vec<u8>, u32) {
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(value: Handle) -> i32;
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtOpenProcessToken(process: Handle, access: u32, output: *mut Handle) -> i32;
        fn NtQueryInformationToken(
            token: Handle,
            class: u32,
            output: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    struct Owned(Handle);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: exclusively owned query token; never exposed to a guest.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let mut token = std::ptr::null_mut();
    // SAFETY: current process, TOKEN_QUERY and initialized exclusive output.
    assert_eq!(
        unsafe { NtOpenProcessToken(GetCurrentProcess(), 8, &mut token) },
        0
    );
    assert!(!token.is_null());
    let token = Owned(token);
    let mut data = [0usize; 512];
    let mut required = 0;
    // SAFETY: aligned owned 2048/4096-byte output and exclusive length DWORD.
    assert_eq!(
        unsafe {
            NtQueryInformationToken(
                token.0,
                1,
                data.as_mut_ptr().cast(),
                std::mem::size_of_val(&data) as u32,
                &mut required,
            )
        },
        0
    );
    let width = std::mem::size_of::<usize>();
    assert!((2 * width + 8..=2 * width + 68).contains(&(required as usize)));
    let offset = data[0].checked_sub(data.as_ptr() as usize).unwrap();
    assert_eq!(offset, 2 * width);
    // SAFETY: initialized contiguous allocation; native extent is bounded above.
    let bytes = unsafe {
        std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), std::mem::size_of_val(&data))
    };
    let attributes = u32::from_ne_bytes(bytes[width..width + 4].try_into().unwrap());
    let sid = crate::user::windows::security::sid(&bytes[offset..required as usize]).unwrap();
    assert_eq!(sid.len() + offset, required as usize);
    (sid.to_vec(), attributes)
}

#[cfg(windows)]
#[test]
fn native_token_user_installed_leaves_match_independent_host_sid_and_cleanup() {
    let (sid, attributes) = native_user();
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
    for (arch, laa) in profiles {
        let (mut process, mut thread, base, handles) = setup_runtime(arch, laa, true);
        let p = process.state_mut();
        assert_eq!(p.objects.primary_token_subject().unwrap().user, sid);
        assert_eq!(
            p.objects.primary_token_subject().unwrap().user_attributes,
            attributes
        );
        let module = crate::user::windows::loader::load_dll(p, "ntdll.dll").unwrap();
        let required = (2 * arch.ptr_size()) as u32 + sid.len() as u32;
        for length in [0, required - 1, required, required + 8] {
            let (output, returned) = destinations(p, base, 0);
            let before = (p.rng, p.objects.handle_count(), p.objects.iter().count());
            let actual = super::super::virtual_memory_tests::installed::invoke(
                p,
                &mut thread,
                module,
                "NtQueryInformationToken",
                &[handles[1], 1, output, u64::from(length), returned],
            );
            assert_eq!(
                actual,
                if length < required {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    STATUS_SUCCESS
                }
            );
            assert_eq!(p.space.u32(returned).unwrap(), required);
            assert_eq!(
                (p.rng, p.objects.handle_count(), p.objects.iter().count()),
                before
            );
            assert!(thread.frames.is_empty());
            if length >= required {
                assert_eq!(
                    p.space.ptr(output, arch.ptr_size()).unwrap(),
                    output + 2 * arch.ptr_size()
                );
                assert_eq!(p.space.u32(output + arch.ptr_size()).unwrap(), attributes);
                assert_eq!(
                    p.space
                        .bytes(output + 2 * arch.ptr_size(), sid.len())
                        .unwrap(),
                    sid
                );
            } else {
                assert_eq!(
                    p.space.bytes(output, required as usize).unwrap(),
                    vec![0xA5; required as usize]
                );
            }
        }
    }
}
