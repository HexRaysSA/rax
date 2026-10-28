//! Actual installed NTDLL section entries and native/WoW64 caller cleanup.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};
fn run_leaf(p: &mut Proc, t: &mut Thread, name: &str, args: [u64; 3], expected: u32) {
    let module = loader::load_dll(p, "ntdll.dll").unwrap();
    let entry = loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let sp = t.cpu.sp() - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    for (i, value) in args.into_iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
            WinArch::X64 => {
                if i < 4 {
                    t.cpu.set_gpr([1, 2, 8, 9][i], value);
                } else {
                    p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap();
                }
            }
            WinArch::Arm64 => t.cpu.set_gpr(i, value),
        }
    }
    match p.arch {
        WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
        WinArch::X64 => p.space.w64(sp, resume).unwrap(),
        WinArch::Arm64 => t.cpu.set_gpr(30, resume),
    }
    let mut returned = false;
    for _ in 0..32 {
        let boundary = t.cpu.run(64);
        if t.cpu.pc() == resume {
            returned = true;
            break;
        }
        assert!(
            matches!(
                handle_stop(p, t, boundary),
                Outcome::Continue | Outcome::Yield
            ),
            "{}: {}",
            p.arch,
            name
        );
    }
    assert!(returned);
    assert_eq!(t.cpu.gpr(0), u64::from(expected));
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 16,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(sp + 128);
}
#[test]
fn native_section_open_installed_leaves_return_typed_image_handles_and_ret12() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    for arch in if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    } {
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
        let mut cfg =
            WindowsConfig::embedded("C:\\native-section-open.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        cfg.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let b =
            p.vm.allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let before = (p.objects.handle_count(), p.objects.iter().count());
        for (root_path, name) in [
            ("", "\\KnownDlls\\kernel32.dll"),
            ("\\KnownDlls", "KERNEL32.DLL"),
            ("\\KnownDlls32", "kernel32.dll"),
        ] {
            let root = if root_path.is_empty() {
                None
            } else {
                Some(
                    p.object_namespace
                        .lookup(None, &root_path.encode_utf16().collect::<Vec<_>>(), 0x40)
                        .unwrap(),
                )
            };
            let expected = p
                .object_namespace
                .lookup_section(
                    root.clone(),
                    &name.encode_utf16().collect::<Vec<_>>(),
                    0x40,
                    arch == WinArch::X86,
                )
                .unwrap();
            if arch == WinArch::X86 && root_path == "\\KnownDlls32" {
                assert_eq!(
                    String::from_utf16(&expected.path).unwrap(),
                    "\\KnownDlls32\\kernel32.dll"
                );
            }
            let rh = root.map(|r| p.objects.open_directory(r, false, 0x20000).unwrap());
            let width = arch.ptr_size();
            let size = if arch.is64() { 48 } else { 24 };
            let mut a = vec![0; size];
            a[..4].copy_from_slice(&(size as u32).to_le_bytes());
            let root = u64::from(rh.unwrap_or(0));
            let np = b + 128;
            for (at, v) in [(width, root), (width * 2, np)] {
                a[at as usize..(at + width) as usize]
                    .copy_from_slice(&v.to_le_bytes()[..width as usize]);
            }
            a[(width * 3) as usize..(width * 3 + 4) as usize]
                .copy_from_slice(&0x40u32.to_le_bytes());
            p.space.wr(b + 64, &a).unwrap();
            let mut u = vec![0; if arch.is64() { 16 } else { 8 }];
            let text: Vec<_> = name.encode_utf16().collect();
            u[..2].copy_from_slice(&((text.len() * 2) as u16).to_le_bytes());
            u[2..4].copy_from_slice(&((text.len() * 2 + 2) as u16).to_le_bytes());
            let at = if arch.is64() { 8 } else { 4 };
            u[at..at + width as usize].copy_from_slice(&(b + 256).to_le_bytes()[..width as usize]);
            p.space.wr(np, &u).unwrap();
            p.space.put_wunits(b + 256, &text).unwrap();
            run_leaf(p, &mut t, "NtOpenSection", [b, 0xD, b + 64], 0);
            let h = p.space.ptr(b, width).unwrap();
            assert_eq!(p.objects.access(h), Some(0xD));
            assert_eq!(p.objects.get(h).unwrap().type_name(), "Section");
            let Some(Object::ImageSection(actual)) = p.objects.get(h) else {
                panic!("image section")
            };
            assert!(Arc::ptr_eq(actual, &expected));
            assert_eq!(actual.attributes, 0x0180_0000);
            assert!(actual.size > 0);
            p.objects.close(h).unwrap();
            if let Some(h) = rh {
                p.objects.close(u64::from(h)).unwrap();
            }
            run_leaf(
                p,
                &mut t,
                "NtOpenSection",
                [0, 0xD, b + 64],
                crate::user::windows::nt::status::STATUS_ACCESS_VIOLATION,
            );
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        }
        p.threads.insert(tid, t);
    }
}

#[test]
fn native_section_open_session_windows_leaves_keep_global_and_current_owners() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    for arch in if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    } {
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
        let mut cfg =
            WindowsConfig::embedded("C:\\native-session-section.exe", vec![], vec![], 4096)
                .unwrap();
        cfg.native_libraries = true;
        cfg.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let session = p
            .objects
            .primary_token_session_id()
            .expect("selected primary-token session");
        // Guest PEB fields cannot choose a different host capture or resource.
        p.space
            .w32(
                p.peb + crate::user::windows::layout::offsets(arch).peb_session_id,
                session ^ 0x8000_0000,
            )
            .unwrap();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let b =
            p.vm.allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let width = arch.ptr_size();
        let mut handles = Vec::new();
        for (name, path, access) in [
            ("NtOpenDirectoryObject", "\\Windows".to_owned(), 0x20000),
            (
                "NtOpenDirectoryObject",
                format!("\\Sessions\\{session}\\Windows"),
                0x20000,
            ),
            ("NtOpenSection", "\\Windows\\SharedSection".to_owned(), 4),
            (
                "NtOpenSection",
                format!("\\Sessions\\{session}\\Windows\\SharedSection"),
                4,
            ),
        ] {
            let mut attributes = vec![0; if arch.is64() { 48 } else { 24 }];
            let size = attributes.len() as u32;
            attributes[..4].copy_from_slice(&size.to_le_bytes());
            attributes[(width * 2) as usize..(width * 3) as usize]
                .copy_from_slice(&(b + 128).to_le_bytes()[..width as usize]);
            attributes[(width * 3) as usize..(width * 3 + 4) as usize]
                .copy_from_slice(&0x40u32.to_le_bytes());
            let text: Vec<_> = path.encode_utf16().collect();
            let mut unicode = vec![0; if arch.is64() { 16 } else { 8 }];
            unicode[..2].copy_from_slice(&((text.len() * 2) as u16).to_le_bytes());
            unicode[2..4].copy_from_slice(&((text.len() * 2 + 2) as u16).to_le_bytes());
            let at = if arch.is64() { 8 } else { 4 };
            unicode[at..at + width as usize]
                .copy_from_slice(&(b + 256).to_le_bytes()[..width as usize]);
            p.space.wr(b + 64, &attributes).unwrap();
            p.space.wr(b + 128, &unicode).unwrap();
            p.space.put_wunits(b + 256, &text).unwrap();
            run_leaf(p, &mut t, name, [b, access, b + 64], 0);
            let handle = p.space.ptr(b, width).unwrap();
            assert_eq!(p.objects.access(handle), Some(access as u32));
            handles.push(handle);
            if name == "NtOpenSection" {
                let Some(Object::DataSection(section)) = p.objects.get(handle) else {
                    panic!("data section expected")
                };
                assert_eq!(
                    section.path,
                    crate::user::windows::object_namespace::DataSection::path_for_session(
                        if path.starts_with("\\Sessions\\") && session != 0 {
                            Some(session)
                        } else {
                            None
                        }
                    )
                );
            }
        }
        assert_eq!(
            p.objects.id(handles[0]) == p.objects.id(handles[1]),
            session == 0
        );
        assert_eq!(
            p.objects.id(handles[2]) == p.objects.id(handles[3]),
            session == 0
        );
        for handle in handles {
            p.objects.close(handle).unwrap();
        }
        p.threads.insert(tid, t);
    }
}
