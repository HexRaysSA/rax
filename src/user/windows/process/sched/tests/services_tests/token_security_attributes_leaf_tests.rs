//! Execute installed NTDLL leaves, native capture and x86 RET24 cleanup.
use super::{Outcome, Proc, Thread, WinArch, handle_stop, mem, prot};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{STATUS_BUFFER_TOO_SMALL, STATUS_DATATYPE_MISALIGNMENT};
use crate::user::windows::process::sched::run_cpu;
use crate::user::windows::security::token::attributes::Attributes;
use crate::user::windows::{
    layout,
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};
use std::ffi::c_void;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySecurityAttributesToken(
        token: *mut c_void,
        names: *const c_void,
        count: u32,
        output: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

fn native_reference() -> (u32, Attributes) {
    let mut needed = 0;
    let token = (usize::MAX - 3) as *mut c_void;
    // SAFETY: current-process pseudo token is query-only; names/output are
    // NULL with zero counts, and the ULONG output is exclusive and initialized.
    let status = unsafe {
        NtQuerySecurityAttributesToken(
            token,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    } as u32;
    assert_eq!(status, STATUS_BUFFER_TOO_SMALL);
    assert!((16..=1048576).contains(&needed));
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    let mut returned = 0;
    // SAFETY: initialized eight-byte aligned storage covers `needed` bytes;
    // native pointers are decoded before this exclusive allocation drops.
    assert_eq!(
        unsafe {
            NtQuerySecurityAttributesToken(
                token,
                std::ptr::null(),
                0,
                storage.as_mut_ptr().cast(),
                needed,
                &mut returned,
            )
        },
        0
    );
    assert!(returned <= needed);
    // SAFETY: the successful native byte count fits the initialized allocation.
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned as usize) };
    (
        needed,
        Attributes::from_native(bytes, storage.as_ptr() as u64, std::mem::size_of::<usize>())
            .unwrap(),
    )
}

fn leaf(p: &mut Proc, t: &mut Thread, entry: u64, args: [u64; 6]) -> u32 {
    let saved = t.cpu.sp();
    let sp = saved - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    for (i, value) in args.into_iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
            WinArch::X64 if i < 4 => t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::X64 => p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap(),
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
        let stop = run_cpu(p, &mut t.cpu, 64);
        if t.cpu.pc() == resume {
            returned = true;
            break;
        }
        assert!(matches!(
            handle_stop(p, t, stop),
            Outcome::Continue | Outcome::Yield
        ));
    }
    assert!(returned);
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 28,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    assert!(t.frames.is_empty());
    t.cpu.set_sp(saved);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_token_security_attributes_installed_leaves_match_independent_capture_and_ret24() {
    let (needed, expected) = native_reference();
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
            WindowsConfig::embedded("C:\\attribute-leaf.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert_eq!(
            p.objects
                .primary_token_subject()
                .unwrap()
                .attributes
                .as_ref(),
            Some(&expected)
        );
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtQuerySecurityAttributesToken".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let base =
            p.vm.allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let returned = base + 4096;
        let token = arch.ptr(u64::MAX - 3);
        let last_error = t.teb + layout::offsets(arch).teb_last_error;
        let before = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        p.space.w32(last_error, 0xC0DE).unwrap();
        assert_eq!(
            leaf(p, &mut t, entry, [token, 0, 0, 0, 0, returned]),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(p.space.u32(returned).unwrap(), needed);
        for offset in if arch == WinArch::X86 {
            vec![0, 1, 2, 4, 8]
        } else {
            vec![0, 4, 8]
        } {
            let output = base + offset;
            assert_eq!(
                leaf(
                    p,
                    &mut t,
                    entry,
                    [token, 0, 0, output, 4096 - offset, returned]
                ),
                0
            );
            let count = p.space.u32(returned).unwrap() as usize;
            // Native logical ReturnLength excludes absolute alignment bias.
            // The caller capacity bounds the complete pointer-bearing result.
            assert!(count <= (4096 - offset) as usize);
            let bytes = p.space.bytes(output, (4096 - offset) as usize).unwrap();
            assert_eq!(
                Attributes::from_native(&bytes, output, arch.ptr_size() as usize),
                Some(expected.clone()),
                "{arch}/{offset}/required{count}"
            );
        }
        assert_eq!(
            leaf(p, &mut t, entry, [0x13572468, 0, 0, 0, 0, 1]),
            STATUS_DATATYPE_MISALIGNMENT
        );
        assert_eq!(p.space.u32(last_error).unwrap(), 0xC0DE);
        assert_eq!(
            (
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes()
            ),
            before
        );
    }
}
