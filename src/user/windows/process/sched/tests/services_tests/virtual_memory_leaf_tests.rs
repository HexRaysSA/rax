//! Actual installed NtQueryVirtualMemory leaf execution, separate from startup.
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
fn installed_ntdll_virtual_memory_leaves_query_guest_images_and_nls_all_selected_abis() {
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
            WindowsConfig::embedded("C:\\native-query.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let ntdll_base = p.modules.list[module].base;
        let ntdll_size = p.modules.list[module].size;
        let base =
            p.vm.allocate(
                None,
                PAGE_SIZE * 2,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtQueryVirtualMemory",
                &[
                    arch.ptr(u64::MAX),
                    ntdll_base + 1,
                    6,
                    base + 128,
                    64,
                    base + 257
                ]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(read_ptr(p, base + 128), ntdll_base);
        assert_eq!(
            read_ptr(p, base + 128 + if arch.is64() { 8 } else { 4 }),
            ntdll_size
        );
        assert_eq!(
            p.space
                .u32(base + 128 + if arch.is64() { 16 } else { 8 })
                .unwrap(),
            0
        );
        assert_eq!(read_ptr(p, base + 257), required(arch, 6));
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtGetNlsSectionPtr",
                &[11, 1252, 0, base + 64, 0]
            ),
            STATUS_SUCCESS
        );
        let view = read_ptr(p, base + 64);
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtQueryVirtualMemory",
                &[arch.ptr(u64::MAX), view + 1, 6, base + 128, 64, 0]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            p.space
                .bytes(base + 128, required(arch, 6) as usize)
                .unwrap(),
            vec![0; required(arch, 6) as usize]
        );
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtQueryVirtualMemory",
                &[arch.ptr(u64::MAX), view, 0, base + 128, 64, base + 257]
            ),
            STATUS_SUCCESS
        );
        let protect_at = if arch.is64() { 36 } else { 20 };
        assert_eq!(
            p.space.u32(base + 128 + protect_at).unwrap(),
            prot::READONLY
        );
        assert_eq!(
            p.space.u32(base + 128 + protect_at + 4).unwrap(),
            mem::MAPPED
        );
        assert_eq!(read_ptr(p, base + 257), required(arch, 0));
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtQueryVirtualMemory",
                &[arch.ptr(u64::MAX), ntdll_base, 6, 0, 64, 0]
            ),
            if arch == WinArch::X86 {
                STATUS_SUCCESS
            } else {
                STATUS_ACCESS_VIOLATION
            }
        );
        for alias in [0, 64] {
            let out = base + PAGE_SIZE;
            p.space.wr(out, &vec![0xA5; PAGE_SIZE as usize]).unwrap();
            p.vm.protect(out, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            assert_eq!(
                invoke(
                    p,
                    &mut t,
                    module,
                    "NtQueryVirtualMemory",
                    &[arch.ptr(u64::MAX), ntdll_base, 6, out, 64, out + alias]
                ),
                if arch == WinArch::X86 {
                    STATUS_SUCCESS
                } else {
                    STATUS_GUARD_PAGE_VIOLATION
                }
            );
            assert_eq!(p.vm.query(out).unwrap().protect & prot::GUARD, 0);
            if arch == WinArch::X86 {
                assert_eq!(read_ptr(p, out), ntdll_base);
                if alias != 0 {
                    assert_eq!(p.space.u32(out + alias).unwrap(), 0xA5A5_A5A5);
                }
            } else {
                assert_eq!(p.space.u8(out).unwrap(), 0xA5);
            }
        }
    }
}
