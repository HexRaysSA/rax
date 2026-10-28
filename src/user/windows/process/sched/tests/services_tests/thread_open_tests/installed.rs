//! Real installed NTDLL instructions, including WoW64 RET16 and guard effects.
use super::*;
use crate::user::windows::{
    loader,
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn native_thread_open_installed_leaves_keep_guest_identity_grants_and_ret16() {
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
            WinArch::Arm64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
            )),
            WinArch::X64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x64/smoke.exe"
            )),
            WinArch::X86 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x86/smoke.exe"
            )),
        };
        let mut cfg =
            WindowsConfig::embedded("C:\\native-thread-open.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert!(p.thread_access.is_ok(), "{:?}", p.thread_access);
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let base = scratch(p);
        let (oa, cid) = inputs(p, &t, base);
        p.space.wptr(cid, arch.ptr_size(), 0).unwrap();
        let last_error = t.teb + layout::offsets(arch).teb_last_error;
        let invoke = |p: &mut Proc, t: &mut Thread, args: &[u64]| {
            p.space.w32(last_error, LAST_ERROR).unwrap();
            let status = super::super::virtual_memory_tests::installed::invoke(
                p,
                t,
                module,
                "NtOpenThread",
                args,
            );
            assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
            status
        };
        assert_eq!(invoke(p, &mut t, &[base, 0x800, oa, cid]), 0);
        let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
        assert_eq!(p.objects.id(handle), Some(t.obj));
        assert_eq!(p.objects.access(handle), Some(0x800));
        p.objects.close(handle).unwrap();
        let count = p.objects.handle_count();
        for output in [0, 1, arch.ptr(u64::MAX) - 3] {
            assert_eq!(
                invoke(p, &mut t, &[output, 0x800, oa, cid]),
                STATUS_ACCESS_VIOLATION
            );
            assert_eq!(p.objects.handle_count(), count);
        }
        p.vm.protect(base, 4096, prot::READONLY | prot::GUARD)
            .unwrap();
        assert_eq!(
            invoke(p, &mut t, &[base, 0x800, oa, cid]),
            if arch == WinArch::X86 {
                STATUS_ACCESS_VIOLATION
            } else {
                STATUS_GUARD_PAGE_VIOLATION
            }
        );
        assert_eq!(
            p.vm.query(base).unwrap().protect,
            prot::READONLY | if arch == WinArch::X86 { prot::GUARD } else { 0 }
        );
        assert_eq!(p.objects.handle_count(), count);
        p.vm.protect(base, 4096, prot::READWRITE).unwrap();
        p.space
            .wptr(cid + arch.ptr_size(), arch.ptr_size(), 0)
            .unwrap();
        assert_eq!(
            invoke(p, &mut t, &[base, 0x800, oa, cid]),
            STATUS_INVALID_CID
        );
        assert_eq!(p.objects.handle_count(), count);
    }
}
