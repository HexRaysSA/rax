//! Actual installed leaves exercise the retained native file-to-image adapter.
use super::super::installed::leaf;
use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn native_mapped_file_identity_compares_retained_installed_views() {
    let arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let directory = Directory::new();
    let mut config =
        WindowsConfig::embedded("C:\\mapped-identity.exe", vec![], vec![], 4096).unwrap();
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    let mut process = WindowsProcess::spawn_image(config, image(arch).to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let out = scratch(p);
    let module = &p.modules.list[p.modules.by_name("ntdll.dll").unwrap()];
    let (loaded, original) = (module.base, module.host_path.clone().unwrap());
    let copy = directory.0.join("copy.dll");
    std::fs::copy(&original, &copy).unwrap();
    let current = arch.ptr(u64::MAX);
    let data = 0x5000_0000;
    let copy_data = 0x5100_0000;
    for (path, address) in [(&original, data), (&copy, copy_data)] {
        let file = insert_file(p, path, 0x100021);
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "NtCreateSection",
                &[out, 5, 0, 0, 2, 0x0800_0000, file]
            ),
            0
        );
        let section = get(p, out);
        assert_eq!(leaf(p, &mut thread, "NtClose", &[file]), 0);
        ptr(p, out, address);
        ptr(p, out + 16, 0);
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "NtMapViewOfSection",
                &[section, current, out, 0, 0, 0, out + 16, 2, 0, 2]
            ),
            0
        );
        assert_eq!(get(p, out), address);
        assert_eq!(leaf(p, &mut thread, "NtClose", &[section]), 0);
    }

    let pinned = p
        .object_namespace
        .lookup_section(
            None,
            &"\\KnownDlls\\ntdll.dll".encode_utf16().collect::<Vec<_>>(),
            0x40,
            arch == WinArch::X86,
        )
        .unwrap();
    let image = pinned.image_for(arch).unwrap();
    let size = image.bytes.len() as u64;
    let selected = 0x5200_0000;
    p.vm.map_section_image(
        pinned,
        &image,
        selected,
        selected,
        image.allocation_size(),
        0,
        size,
        false,
        false,
    )
    .unwrap();

    for (first, second, status) in [
        (loaded, selected, STATUS_SUCCESS),
        (selected, loaded, STATUS_SUCCESS),
        (loaded, data, STATUS_SUCCESS),
        (selected, data, STATUS_SUCCESS),
        (loaded, copy_data, STATUS_NOT_SAME_DEVICE),
        (selected, copy_data, STATUS_NOT_SAME_DEVICE),
        (data, loaded, STATUS_CONFLICTING_ADDRESSES),
    ] {
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "NtAreMappedFilesTheSame",
                &[first + 0x40, second + 0x40]
            ),
            status
        );
    }
}

#[test]
fn native_section_file_installed_host_and_wow_leaves_preserve_full_image_metadata() {
    let arches: &[WinArch] = if cfg!(target_arch = "aarch64") {
        &[WinArch::Arm64, WinArch::X86]
    } else if cfg!(target_arch = "x86_64") {
        &[WinArch::X64, WinArch::X86]
    } else {
        &[WinArch::X86]
    };
    for &arch in arches {
        let directory = Directory::new();
        let path = directory.0.join("version.dll");
        let system = std::path::Path::new("C:\\Windows").join(if arch == WinArch::X86 {
            "SysWOW64"
        } else {
            "System32"
        });
        std::fs::copy(system.join("version.dll"), &path).unwrap();
        let mut config =
            WindowsConfig::embedded("C:\\file-image.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image(arch).to_vec())
            .unwrap_or_else(|error| panic!("{arch} installed runtime: {error}"));
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let b = scratch(p);
        for (requested, protection, attributes, image_flags) in [
            (0, 0x10, 0x0100_0000, 0),
            (1, 0x10, 0x0100_0000, 1),
            (4096, 0x10, 0x0100_0000, 1),
            (0, 2, 0x1100_0000, 2),
        ] {
            let file = insert_file(p, &path, 0x100021);
            p.space.w64(b + 64, requested).unwrap();
            assert_eq!(
                leaf(
                    p,
                    &mut thread,
                    "NtCreateSection",
                    &[b, 0xD, 0, b + 64, protection, attributes, file]
                ),
                0,
                "{arch} maximum={requested}"
            );
            let section = get(p, b);
            let Object::ImageSection(created) = p.objects.get(section).unwrap() else {
                panic!("native image section")
            };
            let full = created.image_size;
            if image_flags == 2 {
                let template = created.image_for(arch).unwrap();
                assert!(
                    template
                        .regions
                        .iter()
                        .all(|region| region.protection == prot::READONLY)
                );
                assert!(template.extensions.iter().all(Option::is_none));
            }
            let weak = Arc::downgrade(created);
            assert_eq!(created.size, if requested == 0 { full } else { requested });
            if arch == WinArch::Arm64 {
                // The ARM64X file backing also supplies the distinct AMD64
                // image projection. Full AMD64 process spawning on ARM64 is a
                // separate runtime-directory selection boundary, not a leaf
                // execution result from this test.
                let projected = created.image_for(WinArch::X64).unwrap();
                assert_eq!(projected.machine, 0x8664);
                assert_eq!(projected.bytes.len() as u64, full);
                assert!(Arc::ptr_eq(
                    &projected,
                    &created.image_for(WinArch::X64).unwrap()
                ));
            }
            assert_eq!(leaf(p, &mut thread, "NtClose", &[file]), 0);
            ptr(p, b, 0x50000000);
            ptr(p, b + 16, 0);
            assert_eq!(
                leaf(
                    p,
                    &mut thread,
                    "NtMapViewOfSection",
                    &[section, arch.ptr(u64::MAX), b, 0, 0, 0, b + 16, 1, 0, 2]
                ),
                STATUS_IMAGE_NOT_AT_BASE,
                "{arch} maximum={requested}"
            );
            let extent = if requested == 0 {
                full
            } else {
                (requested + 4095) & !4095
            };
            assert_eq!((get(p, b), get(p, b + 16)), (0x50000000, extent));
            assert_eq!(
                p.vm.section_image_information(0x50000000).unwrap().0,
                0x50000000
            );
            let (_, image_size, flags) = p.vm.section_image_information(0x50000000).unwrap();
            assert_eq!(image_size, full);
            assert_eq!(flags & 3, image_flags);
            if extent != full {
                assert_eq!(p.vm.allocation(0x50000000).unwrap().size, extent);
                assert_eq!(flags, 1);
            }
            assert_eq!(leaf(p, &mut thread, "NtClose", &[section]), 0);
            assert!(weak.upgrade().is_some());
            assert_eq!(p.space.bytes(0x50000000, 2).unwrap(), b"MZ");
            if image_flags == 2 {
                assert_eq!(
                    p.vm.query(0x50000000).unwrap().allocation_protect,
                    prot::READONLY
                );
            }
            assert_eq!(
                leaf(
                    p,
                    &mut thread,
                    "NtUnmapViewOfSection",
                    &[arch.ptr(u64::MAX), 0x50000000]
                ),
                0
            );
            assert!(weak.upgrade().is_none());
        }
    }
}
