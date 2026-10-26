//! Process CHPE policy is independent of the native kernel machine.
use super::*;

#[test]
fn native_section_pure_x86_profile_keeps_host_identity_and_explicit_image_roots() {
    let mut captured = namespace();
    captured.native_machine = Some(0xaa64);
    let mut pure = captured.clone();
    pure.select_wow_section_root(false).unwrap();
    assert_eq!(pure.native_machine, Some(0xaa64));
    let direct = pure
        .lookup(
            None,
            &"\\KnownDlls32".encode_utf16().collect::<Vec<_>>(),
            0x40,
        )
        .unwrap();

    for name in ["ntdll.dll", "kernel32.dll"] {
        let units: Vec<_> = name.encode_utf16().collect();
        let original = captured
            .lookup_section(Some(direct.clone()), &units, 0x40, true)
            .unwrap();
        let selected = pure
            .lookup_section(Some(direct.clone()), &units, 0x40, true)
            .unwrap();
        assert_eq!(
            String::from_utf16(&original.path).unwrap(),
            format!("\\KnownDllsChpe32\\{name}")
        );
        assert_eq!(
            String::from_utf16(&selected.path).unwrap(),
            format!("\\KnownDlls32\\{name}")
        );
        assert!(!Arc::ptr_eq(&original, &selected));

        // A changed process selector cannot rewrite or hide absolute resources.
        for root in ["\\KnownDlls32", "\\KnownDllsChpe32"] {
            let absolute: Vec<_> = format!("{root}\\{name}").encode_utf16().collect();
            assert!(Arc::ptr_eq(
                &captured
                    .lookup_section(None, &absolute, 0x40, true)
                    .unwrap(),
                &pure.lookup_section(None, &absolute, 0x40, true).unwrap()
            ));
        }
        assert!(Arc::ptr_eq(
            &selected,
            &captured
                .lookup_section(Some(direct.clone()), &units, 0x40, false)
                .unwrap()
        ));
    }

    // Selecting another process profile preserves the previously captured view.
    pure.select_wow_section_root(true).unwrap();
    assert_eq!(pure.native_machine, Some(0xaa64));
    let name: Vec<_> = "kernel32.dll".encode_utf16().collect();
    assert!(Arc::ptr_eq(
        &captured
            .lookup_section(Some(direct.clone()), &name, 0x40, true)
            .unwrap(),
        &pure
            .lookup_section(Some(direct), &name, 0x40, true)
            .unwrap()
    ));
}

#[test]
fn native_section_pure_x86_profile_runs_native_and_wow64_open_copyback() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtOpenSection", SERVICE);
        let p = process.state_mut();
        p.object_namespace = namespace();
        p.object_namespace.native_machine = Some(0xaa64);
        let b =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let width = arch.ptr_size();
        let attributes_size = if arch.is64() { 48 } else { 24 };

        for chpe in [false, true, false] {
            p.object_namespace.select_wow_section_root(chpe).unwrap();
            for (root, name, redirected) in [
                ("\\KnownDlls32", "kernel32.dll", true),
                ("\\KnownDlls32", "NTDLL.DLL", true),
                ("", "\\KnownDlls32\\kernel32.dll", false),
                ("\\", "KnownDlls32\\kernel32.dll", false),
                ("", "\\KnownDllsChpe32\\kernel32.dll", false),
            ] {
                for tag in [0u64, 3] {
                    let handle = if root.is_empty() {
                        None
                    } else {
                        let directory = p
                            .object_namespace
                            .lookup(None, &root.encode_utf16().collect::<Vec<_>>(), 0x40)
                            .unwrap();
                        Some(p.objects.open_directory(directory, false, 0x20000).unwrap())
                    };
                    let root_handle = handle.map_or(0, |h| u64::from(h) | tag);
                    let text: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
                    let mut attributes = vec![0; attributes_size];
                    attributes[..4].copy_from_slice(&(attributes_size as u32).to_le_bytes());
                    for (at, value) in [(width, root_handle), (width * 2, b + 128)] {
                        attributes[at as usize..(at + width) as usize]
                            .copy_from_slice(&value.to_le_bytes()[..width as usize]);
                    }
                    attributes[(width * 3) as usize..(width * 3 + 4) as usize]
                        .copy_from_slice(&0x40u32.to_le_bytes());
                    let mut unicode = vec![0; if arch.is64() { 16 } else { 8 }];
                    unicode[..2].copy_from_slice(&(text.len() as u16).to_le_bytes());
                    unicode[2..4].copy_from_slice(&(text.len() as u16).to_le_bytes());
                    let pointer_at = if arch.is64() { 8 } else { 4 };
                    unicode[pointer_at..pointer_at + width as usize]
                        .copy_from_slice(&(b + 256).to_le_bytes()[..width as usize]);
                    p.space.wr(b + 64, &attributes).unwrap();
                    p.space.wr(b + 128, &unicode).unwrap();
                    p.space.wr(b + 256, &text).unwrap();
                    p.space.wr(b, &[0xa5; 8]).unwrap();
                    assert_eq!(call(p, &mut thread, [b, 0xd, b + 64]), STATUS_SUCCESS);
                    let output = p.space.ptr(b, width).unwrap();
                    let Some(Object::ImageSection(section)) = p.objects.get(output) else {
                        panic!("typed image handle");
                    };
                    let expected_root = if name.contains("Chpe32")
                        || (redirected && chpe && arch == WinArch::X86)
                    {
                        "\\KnownDllsChpe32"
                    } else {
                        "\\KnownDlls32"
                    };
                    let expected_name = if name.ends_with("NTDLL.DLL") {
                        "ntdll.dll"
                    } else {
                        "kernel32.dll"
                    };
                    assert_eq!(
                        String::from_utf16(&section.path).unwrap(),
                        format!("{expected_root}\\{expected_name}"),
                        "arch={arch} chpe={chpe} root={root} name={name} tag={tag}"
                    );
                    assert_eq!(p.objects.access(output), Some(0xd));
                    p.objects.close(output).unwrap();
                    if let Some(handle) = handle {
                        p.objects.close(u64::from(handle)).unwrap();
                    }
                    assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
                }
            }
            assert_eq!(p.object_namespace.native_machine, Some(0xaa64));
        }
    }
}
