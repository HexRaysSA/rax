//! Installed NTDLL NLS map/unmap leaves, separate from loader/CRT startup.
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
#[test]
fn installed_ntdll_nls_leaves_map_actual_tables_and_unmap_all_selected_abis() {
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
            WindowsConfig::embedded("C:\\native-nls.exe", vec![], vec![], 4096).unwrap();
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
        for (kind, data) in [
            (11, 1252),
            (11, 437),
            (12, 1),
            (12, 2),
            (12, 5),
            (12, 6),
            (12, 13),
            (14, 0),
            (14, u32::MAX),
        ] {
            let expected = p
                .nls
                .as_ref()
                .unwrap()
                .section(kind, data)
                .expect("installed oracle table");
            assert_eq!(
                invoke(
                    p,
                    &mut t,
                    module,
                    "NtGetNlsSectionPtr",
                    &[u64::from(kind), u64::from(data), 0, base + 1, base + 17]
                ),
                STATUS_SUCCESS
            );
            let view = ptr(p, base + 1);
            assert_eq!(p.space.u32(base + 17).unwrap() as usize, expected.len());
            assert_eq!(
                p.space.bytes(view, expected.len()).unwrap(),
                expected.as_ref()
            );
            assert_eq!(p.vm.query(view).unwrap().protect, prot::READONLY);
            assert_eq!(
                invoke(
                    p,
                    &mut t,
                    module,
                    "NtUnmapViewOfSection",
                    &[arch.ptr(u64::MAX), view + 1]
                ),
                STATUS_SUCCESS
            );
            assert!(p.space.u8(view).is_err());
        }
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtGetNlsSectionPtr",
                &[11, 1252, 0, base, 0]
            ),
            STATUS_SUCCESS
        );
        let view = ptr(p, base);
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtUnmapViewOfSection",
                &[arch.ptr(u64::MAX), view]
            ),
            STATUS_SUCCESS
        );
        assert!(p.vm.nls_view_count() == 0);
    }
}
