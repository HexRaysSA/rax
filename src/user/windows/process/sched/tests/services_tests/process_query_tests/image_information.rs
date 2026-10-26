//! ProcessImageInformation service dispatch and admitted-image state.

use super::*;

#[test]
fn native_process_image_information_uses_admitted_executable_for_all_guest_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, scratch) = setup(arch);
        let p = process.state_mut();
        let entry = p.modules.exe().entry;
        let bytes = if arch == WinArch::X86 { 48 } else { 64 };
        arguments(
            p,
            &mut thread,
            arch.ptr(u64::MAX),
            37,
            scratch,
            bytes,
            scratch + 96,
        );
        assert_eq!(dispatch(p, &mut thread), Outcome::Continue, "{arch}");
        assert_eq!(thread.cpu.gpr(0), 0, "{arch}");
        assert_eq!(p.space.ptr(scratch, arch.ptr_size()).unwrap(), entry);
        assert_eq!(p.space.u32(scratch + 96).unwrap(), bytes);
        assert_eq!(thread.cpu.pc(), 0x1234_0004);
        assert!(thread.frames.is_empty());
    }
}

#[path = "image_information/replay.rs"]
mod replay;

#[test]
fn native_process_image_information_survives_guest_header_rewrites() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, scratch) = setup(arch);
        let p = process.state_mut();
        let sp = thread.cpu.sp();
        let size = if arch == WinArch::X86 { 48 } else { 64 };
        arguments(
            p,
            &mut thread,
            arch.ptr(u64::MAX),
            37,
            scratch,
            size,
            scratch + 96,
        );
        assert_eq!(dispatch(p, &mut thread), Outcome::Continue);
        let expected = p.space.bytes(scratch, size as usize).unwrap();
        let image_base = p.modules.exe().base;
        p.vm.protect(image_base, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        p.space.wr(image_base, &[0; 512]).unwrap();
        p.random();
        std::sync::Arc::make_mut(&mut p.cfg).version.build = 1;
        p.space.wr(scratch, &[0xa5; 128]).unwrap();
        thread.cpu.set_sp(sp);
        arguments(
            p,
            &mut thread,
            arch.ptr(u64::MAX),
            37,
            scratch,
            size,
            scratch + 96,
        );
        assert_eq!(dispatch(p, &mut thread), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), 0);
        assert_eq!(p.space.bytes(scratch, size as usize).unwrap(), expected);
    }
}

#[test]
fn native_process_image_information_uses_granted_rights_and_refuses_peer_state() {
    for arch in WinArch::ALL {
        for grant in [0, 8, 0x20, 0x400, 0x1000, 0x1400] {
            let (mut process, mut thread, scratch) = setup(arch);
            let p = process.state_mut();
            let object = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            let handle = p.objects.open_access(object, false, grant).unwrap();
            let size = if arch == WinArch::X86 { 48 } else { 64 };
            arguments(
                p,
                &mut thread,
                u64::from(handle | 1),
                37,
                scratch,
                size,
                scratch + 96,
            );
            assert_eq!(dispatch(p, &mut thread), Outcome::Continue);
            if grant & 0x1000 == 0 {
                assert_eq!(thread.cpu.gpr(0), u64::from(STATUS_ACCESS_DENIED));
                assert_eq!(p.space.bytes(scratch, 80).unwrap(), [0xa5; 80]);
                assert_eq!(
                    p.space.u32(scratch + 96).unwrap(),
                    if arch == WinArch::X86 {
                        0xfffffff0
                    } else {
                        0xa5a5a5a5
                    }
                );
            } else {
                assert_eq!(thread.cpu.gpr(0), 0);
            }
        }
        let (mut process, mut thread, scratch) = setup(arch);
        let p = process.state_mut();
        let peer = p.objects.create(Object::Process {
            pid: p.pid + 4,
            exit_code: None,
        });
        let handle = p.objects.open_access(peer, false, 0x1000).unwrap();
        arguments(
            p,
            &mut thread,
            u64::from(handle),
            37,
            scratch,
            if arch == WinArch::X86 { 48 } else { 64 },
            scratch + 96,
        );
        assert!(
            matches!(dispatch(p, &mut thread), Outcome::Fail(reason) if reason.contains("ProcessImageInformation for a process outside this personality"))
        );
        assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xa5; 128]);
    }
}

#[test]
fn native_process_image_information_refuses_unqualified_image_and_kernel_profiles() {
    for arch in WinArch::ALL {
        for missing_image in [false, true] {
            let (mut process, mut thread, scratch) = setup(arch);
            let p = process.state_mut();
            if missing_image {
                p.image_information = Err("unqualified controlled image");
            } else {
                replay::kernel_profile(p, 12345, 0x9999);
            }
            arguments(
                p,
                &mut thread,
                arch.ptr(u64::MAX),
                37,
                scratch,
                if arch == WinArch::X86 { 48 } else { 64 },
                scratch + 96,
            );
            assert!(
                matches!(dispatch(p, &mut thread), Outcome::Fail(reason) if reason.contains("ProcessImageInformation") && reason.contains("unqualified"))
            );
            assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xa5; 128]);
        }
    }
}

#[test]
fn native_process_image_information_capture_rejects_unqualified_image_states() {
    use crate::user::image::pe::PeImage;
    use crate::user::windows::process::image_information::ImageInformation;
    for arch in WinArch::ALL {
        for variant in ["dll", "subsystem", "managed", "no-execute", "no-entry"] {
            let mut bytes = replay::fixture_bytes(arch);
            let pe = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
            let optional = pe + 24;
            match variant {
                "dll" => {
                    let flags = u16::from_le_bytes(bytes[pe + 22..pe + 24].try_into().unwrap());
                    bytes[pe + 22..pe + 24].copy_from_slice(&(flags | 0x2000).to_le_bytes());
                }
                "subsystem" => {
                    bytes[optional + 68..optional + 70].copy_from_slice(&9u16.to_le_bytes())
                }
                "managed" => {
                    let at = optional + if arch == WinArch::X86 { 96 } else { 112 } + 14 * 8;
                    bytes[at..at + 4].copy_from_slice(&0x1000u32.to_le_bytes());
                    bytes[at + 4..at + 8].copy_from_slice(&72u32.to_le_bytes());
                }
                "no-entry" => bytes[optional + 16..optional + 20].fill(0),
                "no-execute" => {
                    let count =
                        u16::from_le_bytes(bytes[pe + 6..pe + 8].try_into().unwrap()) as usize;
                    let size =
                        u16::from_le_bytes(bytes[pe + 20..pe + 22].try_into().unwrap()) as usize;
                    for index in 0..count {
                        let at = optional + size + index * 40 + 36;
                        let flags = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                        bytes[at..at + 4].copy_from_slice(&(flags & !0x20000000).to_le_bytes());
                    }
                }
                _ => unreachable!(),
            }
            let image = PeImage::parse(bytes).unwrap();
            assert!(
                ImageInformation::capture(&image, 0x11223344).is_err(),
                "{arch} {variant}"
            );
        }
        if arch == WinArch::X86 {
            let image = PeImage::parse(replay::fixture_bytes(arch)).unwrap();
            assert!(ImageInformation::capture(&image, 0x100000000).is_err());
        }
    }
}

#[cfg(windows)]
#[test]
fn installed_native_image_information_query_leaf_uses_admitted_image() {
    use crate::user::windows::loader::{self, SymRef};

    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in arches {
        let image: &[u8] = match arch {
            WinArch::X86 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x86/smoke.exe"
            )),
            WinArch::X64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x64/smoke.exe"
            )),
            WinArch::Arm64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
            )),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-image-information.exe", vec![], vec![], 4096)
                .unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process =
            super::super::super::super::super::WindowsProcess::spawn_image(config, image.to_vec())
                .unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtQueryInformationProcess".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let expected_entry = p.modules.exe().entry;
        let output =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(output, &[0xa5; 104]).unwrap();
        let returned = output + 96;
        let width = if arch == WinArch::X86 { 48u32 } else { 64u32 };
        let resume = p.traps.callback_return();
        let sp = t.cpu.sp();
        match arch {
            WinArch::X86 => {
                for (i, value) in [
                    resume,
                    arch.ptr(u64::MAX),
                    37,
                    output,
                    u64::from(width),
                    returned,
                ]
                .into_iter()
                .enumerate()
                {
                    p.space.w32(sp + i as u64 * 4, value as u32).unwrap();
                }
            }
            WinArch::X64 => {
                p.space.w64(sp, resume).unwrap();
                p.space.w64(sp + 40, returned).unwrap();
                for (register, value) in
                    [(1, u64::MAX), (2, 37), (8, output), (9, u64::from(width))]
                {
                    t.cpu.set_gpr(register, value);
                }
            }
            WinArch::Arm64 => {
                for (register, value) in [
                    (0, u64::MAX),
                    (1, 37),
                    (2, output),
                    (3, u64::from(width)),
                    (4, returned),
                    (30, resume),
                ] {
                    t.cpu.set_gpr(register, value);
                }
            }
        }
        t.cpu.set_pc(entry);
        assert_eq!(
            run_to_return(
                p,
                &mut t,
                resume,
                "NtQueryInformationProcess ImageInformation"
            ),
            0
        );
        assert_eq!(
            p.space.ptr(output, arch.ptr_size()).unwrap(),
            expected_entry
        );
        assert_eq!(p.space.u32(returned).unwrap(), width);
        assert_eq!(
            p.space
                .bytes(output + u64::from(width), 96 - width as usize)
                .unwrap(),
            vec![0xa5; 96 - width as usize]
        );
        assert_eq!(p.space.u32(returned + 4).unwrap(), 0xa5a5_a5a5);
        assert_eq!(
            t.cpu.sp(),
            sp + match arch {
                WinArch::X86 => 24,
                WinArch::X64 => 8,
                WinArch::Arm64 => 0,
            }
        );
        assert!(t.frames.is_empty());
    }
}
