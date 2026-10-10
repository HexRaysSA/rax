//! Installed NTDLL kernel leaves, separate from native loader/CRT startup.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

fn invoke(p: &mut Proc, t: &mut Thread, module: usize, service: &str, args: &[u64]) -> u32 {
    let entry = loader::lookup(p, module, &SymRef::Name(service.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let arch = p.arch;
    let sp = t.cpu.sp();
    let resume = p.traps.callback_return();
    for (index, &value) in args.iter().enumerate() {
        match arch {
            WinArch::X86 => p
                .space
                .w32(sp + 4 + index as u64 * 4, value as u32)
                .unwrap(),
            WinArch::X64 if index < 4 => t.cpu.set_gpr([1, 2, 8, 9][index], value),
            WinArch::X64 => p.space.w64(sp + 8 + index as u64 * 8, value).unwrap(),
            WinArch::Arm64 => t.cpu.set_gpr(index, value),
        }
    }
    match arch {
        WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
        WinArch::X64 => p.space.w64(sp, resume).unwrap(),
        WinArch::Arm64 => t.cpu.set_gpr(30, resume),
    }
    t.cpu.set_pc(entry);
    let mut completed = false;
    for _ in 0..64 {
        let boundary = t.cpu.run(64);
        if t.cpu.pc() == resume {
            completed = true;
            break;
        }
        let description = format!("{arch}/{service} PC={:#x} {boundary:?}", t.cpu.pc());
        assert!(
            matches!(
                handle_stop(p, t, boundary),
                Outcome::Continue | Outcome::Yield
            ),
            "{description}"
        );
    }
    assert!(completed, "{arch}/{service} did not return");
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match arch {
            WinArch::X86 => 4 * (args.len() as u64 + 1),
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}
fn unicode_units(p: &Proc, descriptor: u64, buffer: u64, units: &[u16]) {
    assert!(units.len() <= 255);
    let bytes: Vec<_> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    p.space.wr(buffer, &bytes).unwrap();
    p.space.w16(descriptor, bytes.len() as u16).unwrap();
    p.space.w16(descriptor + 2, bytes.len() as u16).unwrap();
    p.space
        .wptr(
            descriptor + if p.arch.is64() { 8 } else { 4 },
            p.arch.ptr_size(),
            buffer,
        )
        .unwrap();
}
#[test]
fn installed_ntdll_registry_leaves_open_query_close_selected_snapshot() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let archs = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in archs {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-registry.exe", vec![], vec![], 4096).unwrap();
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
        let vn = base + 192;
        unicode(p, vn, base + 256, NLS_KEY);
        attributes(p, attrs, vn, 0, 0x240);
        let before = (p.objects.handle_count(), p.objects.iter().count());
        assert_eq!(
            invoke(p, &mut t, module, "NtOpenKey", &[base, 0x80000000, attrs]),
            STATUS_SUCCESS
        );
        let h = p.space.ptr(base, arch.ptr_size()).unwrap();
        let key = p
            .registry
            .key(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        for name in ["ACP", "OEMCP", "MACCP"] {
            let value = key.value(&name.encode_utf16().collect::<Vec<_>>()).unwrap();
            unicode(p, vn, base + 256, name);
            assert_eq!(
                invoke(
                    p,
                    &mut t,
                    module,
                    "NtQueryValueKey",
                    &[h, vn, 2, base + 512, PAGE_SIZE, base + 16]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(
                p.space.u32(base + 16).unwrap(),
                value.data.len() as u32 + 12
            );
            assert_eq!(p.space.u32(base + 516).unwrap(), value.kind);
            assert_eq!(p.space.u32(base + 520).unwrap(), value.data.len() as u32);
            assert_eq!(
                p.space.bytes(base + 524, value.data.len()).unwrap(),
                value.data
            );
        }
        assert_eq!(invoke(p, &mut t, module, "NtClose", &[h]), STATUS_SUCCESS);
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        let path = crate::user::windows::registry::IFEO_KEY;
        unicode(p, vn, base + 256, path);
        attributes(p, attrs, vn, 0, 0x240);
        let root = p.registry.key(&path.encode_utf16().collect::<Vec<_>>());
        assert_eq!(
            invoke(p, &mut t, module, "NtOpenKey", &[base + 8, 9, attrs]),
            if root.is_some() {
                STATUS_SUCCESS
            } else {
                STATUS_OBJECT_NAME_NOT_FOUND
            }
        );
        if let Some(root) = root {
            let root_handle = p.space.ptr(base + 8, arch.ptr_size()).unwrap();

            for name in ["probe.exe", "missing-rax-image.exe\\child", "\\probe.exe"] {
                unicode(p, vn, base + 256, name);
                attributes(p, attrs, vn, root_handle, 0x240);
                let expected = if name.starts_with('\\') {
                    STATUS_OBJECT_PATH_SYNTAX_BAD
                } else if matches!(
                    root.relative(&name.encode_utf16().collect::<Vec<_>>()),
                    crate::user::windows::registry::Lookup::Present(_)
                ) {
                    STATUS_SUCCESS
                } else {
                    STATUS_OBJECT_NAME_NOT_FOUND
                };
                assert_eq!(
                    invoke(p, &mut t, module, "NtOpenKey", &[base, 1, attrs]),
                    expected
                );
                if expected == STATUS_SUCCESS {
                    let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
                    assert_eq!(
                        invoke(p, &mut t, module, "NtClose", &[handle]),
                        STATUS_SUCCESS
                    );
                }
            }
            if let Some(child) = root.captured_children().unwrap().next() {
                let name = child.path.rsplit(|u| *u == 92).next().unwrap();
                unicode_units(p, vn, base + 256, name);
                attributes(p, attrs, vn, root_handle, 0x240);
                assert_eq!(
                    invoke(p, &mut t, module, "NtOpenKey", &[base, 1, attrs]),
                    STATUS_SUCCESS
                );
                let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
                let name: Vec<_> = "UseFilter".encode_utf16().collect();
                let value = child.value(&name);
                unicode(p, vn, base + 256, "UseFilter");
                let expected = match value {
                    None => STATUS_OBJECT_NAME_NOT_FOUND,
                    Some(v) if v.data.len() + 12 > PAGE_SIZE as usize => STATUS_BUFFER_OVERFLOW,
                    Some(_) => STATUS_SUCCESS,
                };
                assert_eq!(
                    invoke(
                        p,
                        &mut t,
                        module,
                        "NtQueryValueKey",
                        &[handle, vn, 2, base + 512, PAGE_SIZE, base + 16]
                    ),
                    expected
                );
                if let Some(v) = value {
                    assert_eq!(p.space.u32(base + 516).unwrap(), v.kind);
                    assert_eq!(p.space.u32(base + 520).unwrap(), v.data.len() as u32);
                    let length = v.data.len().min(PAGE_SIZE as usize - 12);
                    assert_eq!(p.space.bytes(base + 524, length).unwrap(), v.data[..length]);
                }
                assert_eq!(
                    invoke(p, &mut t, module, "NtClose", &[handle]),
                    STATUS_SUCCESS
                );
            } else {
                assert_eq!(root.children, 0);
            }
            assert_eq!(
                invoke(p, &mut t, module, "NtClose", &[root_handle]),
                STATUS_SUCCESS
            );
        } else {
            assert!(matches!(
                p.registry.lookup(&path.encode_utf16().collect::<Vec<_>>()),
                crate::user::windows::registry::Lookup::Missing
            ));
        }
        let path = crate::user::windows::registry::SEGMENT_HEAP_KEY;
        let present = p
            .registry
            .key(&path.encode_utf16().collect::<Vec<_>>())
            .is_some();
        unicode(p, vn, base + 256, path);
        attributes(p, attrs, vn, 0, 0x240);
        assert_eq!(
            invoke(p, &mut t, module, "NtOpenKey", &[base + 8, 1, attrs]),
            if present {
                STATUS_SUCCESS
            } else {
                STATUS_OBJECT_NAME_NOT_FOUND
            }
        );
        if present {
            let handle = p.space.ptr(base + 8, arch.ptr_size()).unwrap();
            assert_eq!(
                invoke(p, &mut t, module, "NtClose", &[handle]),
                STATUS_SUCCESS
            );
        } else {
            assert_eq!(p.space.ptr(base + 8, arch.ptr_size()).unwrap(), 0);
        }
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        assert_eq!(
            invoke(p, &mut t, module, "NtQueryValueKey", &[h, vn, 2, 0, 64, 0]),
            STATUS_INVALID_HANDLE
        );
        let path = crate::user::windows::registry::SESSION_MANAGER_KEY;
        unicode(p, vn, base + 256, path);
        attributes(p, attrs, vn, 0, 0x240);
        assert_eq!(
            invoke(p, &mut t, module, "NtOpenKey", &[base + 8, 1, attrs]),
            STATUS_SUCCESS
        );
        let handle = p.space.ptr(base + 8, arch.ptr_size()).unwrap();
        let key = p
            .registry
            .key(&path.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        for name in ["GlobalFlag", "CriticalSectionTimeout", "missing-rax-value"] {
            let value = key.value(&name.encode_utf16().collect::<Vec<_>>());
            unicode(p, vn, base + 256, name);
            assert_eq!(
                invoke(
                    p,
                    &mut t,
                    module,
                    "NtQueryValueKey",
                    &[handle, vn, 2, base + 512, PAGE_SIZE, base + 16]
                ),
                if value.is_some() {
                    STATUS_SUCCESS
                } else {
                    STATUS_OBJECT_NAME_NOT_FOUND
                }
            );
            if let Some(value) = value {
                assert_eq!(p.space.u32(base + 516).unwrap(), value.kind);
                assert_eq!(p.space.u32(base + 520).unwrap(), value.data.len() as u32);
                assert_eq!(
                    p.space.bytes(base + 524, value.data.len()).unwrap(),
                    value.data
                );
            }
        }
        assert_eq!(
            invoke(p, &mut t, module, "NtClose", &[handle]),
            STATUS_SUCCESS
        );
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}
