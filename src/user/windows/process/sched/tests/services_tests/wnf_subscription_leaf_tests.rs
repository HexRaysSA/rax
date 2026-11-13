//! Installed syscall leaves with a captured catalog, ULONG64 output, and x86 RET16.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};
fn run_leaf(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64], expected: u32) {
    let module = loader::load_dll(p, "ntdll.dll").unwrap();
    let entry = loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let sp = t.cpu.sp() - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    for (i, &value) in args.iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
            WinArch::X64 => t.cpu.set_gpr([1, 2, 8, 9][i], value),
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
        let boundary = run_cpu(p, &mut t.cpu, 64);
        if t.cpu.pc() == resume {
            returned = true;
            break;
        }
        assert!(
            matches!(
                handle_stop(p, t, boundary),
                Outcome::Continue | Outcome::Yield
            ),
            "{}: {name}",
            p.arch
        );
    }
    assert!(returned);
    assert_eq!(
        t.cpu.gpr(0),
        u64::from(expected),
        "{}: {name} args={args:X?}",
        p.arch
    );
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 4 + args.len() as u64 * 4,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(sp + 128);
}
#[test]
fn installed_wnf_subscription_leaves_publish_update_and_remove_fixed_64_bit_identity() {
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
            WindowsConfig::embedded("C:\\wnf-subscription.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        // Installed NTDLL supplies the ABI leaves, while these fixed names and
        // expected permissions come from the captured catalog/security subject.
        // A CI host's installed WNF catalog need not contain the captured name.
        p.objects.select_wnf_catalog(catalog());
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let input =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let output = input + 32;
        p.space.w64(input, KNOWN).unwrap();
        p.space.w64(output + 8, POISON).unwrap();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        run_leaf(
            p,
            &mut t,
            "NtSubscribeWnfStateChange",
            &[0, 0, 0x11, output],
            STATUS_ACCESS_VIOLATION,
        );
        assert_eq!(p.space.u64(output).unwrap(), 0);
        run_leaf(
            p,
            &mut t,
            "NtSubscribeWnfStateChange",
            &[input, 0, 0x11, output],
            0,
        );
        let id = p.space.u64(output).unwrap();
        assert_ne!(id, 0);
        run_leaf(
            p,
            &mut t,
            "NtSubscribeWnfStateChange",
            &[input, 1, 0x11, output],
            0,
        );
        assert_eq!(p.space.u64(output).unwrap(), id);
        assert_eq!(p.objects.wnf_subscription(KNOWN).unwrap().change_stamp, 1);
        run_leaf(
            p,
            &mut t,
            "NtSubscribeWnfStateChange",
            &[input, 0, 0x20, output],
            STATUS_INVALID_PARAMETER,
        );
        assert_eq!(p.space.u64(output).unwrap(), 0);
        assert_eq!(p.objects.wnf_subscription(KNOWN).unwrap().id, id);
        assert_eq!(p.space.u64(output + 8).unwrap(), POISON);
        run_leaf(p, &mut t, "NtUnsubscribeWnfStateChange", &[input], 0);
        assert!(p.objects.wnf_subscription(KNOWN).is_none());
        run_leaf(
            p,
            &mut t,
            "NtUnsubscribeWnfStateChange",
            &[input],
            STATUS_OBJECT_NAME_NOT_FOUND,
        );
        run_leaf(
            p,
            &mut t,
            "NtUnsubscribeWnfStateChange",
            &[0],
            STATUS_ACCESS_VIOLATION,
        );
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}
