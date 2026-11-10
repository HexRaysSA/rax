//! Actual installed NTDLL NtMapViewOfSection and x86 RET 40-byte cleanup.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

fn leaf(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
    let m = loader::load_dll(p, "ntdll.dll").unwrap();
    let entry = loader::lookup(p, m, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let saved_sp = t.cpu.sp();
    let sp = saved_sp - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    for (i, &value) in args.iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
            WinArch::X64 if i < 4 => t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::X64 => p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap(),
            WinArch::Arm64 if i < 8 => t.cpu.set_gpr(i, value),
            WinArch::Arm64 => p.space.w32(sp + (i - 8) as u64 * 8, value as u32).unwrap(),
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
            "{name} {}",
            p.arch
        );
    }
    assert!(returned, "{name} {}", p.arch);
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 4 + args.len() as u64 * 4,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(saved_sp);
    t.cpu.gpr(0) as u32
}
#[test]
fn native_section_map_installed_leaves_copy_pinned_image_and_unmap_after_close() {
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
        let bytes: &[u8] = match arch {
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
            WindowsConfig::embedded("C:\\native-section-map.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let b = scratch(p);
        let selected = p
            .object_namespace
            .lookup_section(
                None,
                &"\\KnownDlls\\kernel32.dll"
                    .encode_utf16()
                    .collect::<Vec<_>>(),
                0x40,
                arch == WinArch::X86,
            )
            .unwrap();
        let image = selected.image_for(arch).unwrap();
        assert_eq!(image.bytes.len() as u64, selected.size);
        if arch == WinArch::Arm64 {
            // Exercise the owning Rust adapter's distinct ARM64X AMD64 cache.
            // Complete independent byte equivalence is in the native corpus.
            let projected = selected.image_for(WinArch::X64).unwrap();
            assert_eq!(image.machine, 0xAA64);
            assert_eq!(projected.machine, 0x8664);
            assert_eq!(projected.bytes.len() as u64, selected.size);
            assert!(!std::sync::Arc::ptr_eq(&image, &projected));
            assert!(std::sync::Arc::ptr_eq(
                &projected,
                &selected.image_for(WinArch::X64).unwrap()
            ));
            assert!(std::sync::Arc::ptr_eq(&image, &selected.image().unwrap()));
        }
        let h = u64::from(p.objects.open_image_section(selected, false, 0xD).unwrap());
        ptr(p, b, 0x5000_0000);
        ptr(p, b + 16, 0);
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtMapViewOfSection",
                &[h, arch.ptr(u64::MAX), b, 0, 0, 0, b + 16, 1, 0x800000, 0x80]
            ),
            STATUS_IMAGE_AT_DIFFERENT_BASE
        );
        assert_eq!(
            (get(p, b), get(p, b + 16)),
            (0x5000_0000, image.bytes.len() as u64)
        );
        let expected = image.view_bytes(0x5000_0000, true).unwrap();
        let mut header = [0u8; 512];
        p.space.rd(0x5000_0000, &mut header).unwrap();
        assert_eq!(header.as_slice(), &expected[..512]);
        assert_eq!(p.vm.query(0x5000_0000).unwrap().kind, mem::IMAGE);
        assert_eq!(leaf(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        assert!(p.vm.section_view(0x5000_0000).is_some());
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtUnmapViewOfSection",
                &[arch.ptr(u64::MAX), 0x5000_1000]
            ),
            STATUS_SUCCESS
        );
        assert!(p.vm.section_view(0x5000_0000).is_none());
    }
}

#[path = "data_section_leaf_tests.rs"]
mod data;

#[path = "section_map_pagefile_leaf_tests.rs"]
mod pagefile;
