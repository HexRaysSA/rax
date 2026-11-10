//! Installed native/WoW64 leaves, retaining the actual calling-convention checks.
use super::*;

#[test]
fn native_pagefile_map_installed_top_commit_aliases_keep_owned_lifetime() {
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
            WindowsConfig::embedded("C:\\pagefile-leaf.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let b = scratch(p);
        let handles = p.objects.handle_count();
        let (handle, weak) = super::super::pagefile::backed_section(p);
        let mut addresses = Vec::new();
        for (commit, flags, protection) in [
            (16384, mem::TOP_DOWN, prot::READWRITE),
            (0, 0, prot::READONLY),
        ] {
            ptr(p, b, 0);
            ptr(p, b + 16, 0);
            assert_eq!(
                leaf(
                    p,
                    &mut t,
                    "NtMapViewOfSection",
                    &[
                        handle,
                        arch.ptr(u64::MAX),
                        b,
                        0,
                        commit,
                        0,
                        b + 16,
                        2,
                        flags.into(),
                        protection.into(),
                    ]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(get(p, b + 16), 65536);
            addresses.push(get(p, b));
        }
        assert!(addresses[0] > addresses[1]);
        p.space.w32(addresses[0], 0x5a17c0de).unwrap();
        assert_eq!(p.space.u32(addresses[1]).unwrap(), 0x5a17c0de);
        assert!(p.space.w32(addresses[1], 1).is_err());
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtUnmapViewOfSection",
                &[arch.ptr(u64::MAX), addresses[0]]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(leaf(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
        assert_eq!(p.space.u32(addresses[1]).unwrap(), 0x5a17c0de);
        assert!(weak.upgrade().is_some());
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtUnmapViewOfSection",
                &[arch.ptr(u64::MAX), addresses[1]]
            ),
            STATUS_SUCCESS
        );
        assert!(weak.upgrade().is_none());
        assert_eq!(p.objects.handle_count(), handles);
    }
}
