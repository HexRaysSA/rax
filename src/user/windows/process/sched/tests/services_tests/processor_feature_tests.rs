//! Class 250's native bitmap and WoW64 rejection, measured on build 29683.

use super::*;
use crate::user::windows::nt::status::STATUS_INVALID_INFO_CLASS;

#[test]
fn native_processor_feature_bitmap_lengths_and_suffix_preservation_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 1, 8, 15, 16, 17, 20, 24, 31, 32, 33, 48, 64] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            let sp = t.cpu.sp();
            query_arguments(p, &mut t, 250, scratch, length, scratch + 128);
            p.space.w32(scratch + 128, 0xA5A5_A5A5).unwrap();
            assert_eq!(
                dispatch_query(p, &mut t),
                Outcome::Continue,
                "{arch}/{length}"
            );
            let success = arch != WinArch::X86 && length >= 16 && length % 8 == 0;
            let expected = if arch == WinArch::X86 {
                STATUS_INVALID_INFO_CLASS
            } else if success {
                STATUS_SUCCESS
            } else {
                STATUS_INFO_LENGTH_MISMATCH
            };
            assert_eq!(t.cpu.gpr(0), u64::from(expected), "{arch}/{length}");
            assert_eq!(
                p.space.bytes(scratch, 16).unwrap(),
                if success { [0; 16] } else { [0xA5; 16] }
            );
            assert_eq!(p.space.bytes(scratch + 16, 112).unwrap(), [0xA5; 112]);
            assert_eq!(
                p.space.u32(scratch + 128).unwrap(),
                if arch == WinArch::X86 {
                    0xA5A5_A5A5
                } else {
                    16
                }
            );
            assert_eq!(t.cpu.pc(), 0x1234_0004);
            assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_processor_feature_bitmap_fault_order_guards_and_aliases_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..8 {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            let returned =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.w32(returned, 0xA5A5_A5A5).unwrap();
            let (mut output, mut length, mut ret) = (scratch, 16, returned);
            let expected64 = match role {
                0 => {
                    output += 1;
                    ret = 1;
                    STATUS_DATATYPE_MISALIGNMENT
                }
                1 => {
                    output = 0;
                    STATUS_ACCESS_VIOLATION
                }
                2 => {
                    ret = 0;
                    STATUS_SUCCESS
                }
                3 => {
                    ret += 1;
                    STATUS_SUCCESS
                }
                4 => {
                    length = 15;
                    p.vm.protect(scratch, PAGE_SIZE, prot::READONLY).unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                5 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    p.vm.protect(returned, PAGE_SIZE, prot::READONLY).unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                6 => {
                    length = 15;
                    p.vm.protect(returned, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                7 => {
                    ret = scratch;
                    STATUS_SUCCESS
                }
                _ => unreachable!(),
            };
            query_arguments(p, &mut t, 250, output, length, ret);
            assert_eq!(
                dispatch_query(p, &mut t),
                Outcome::Continue,
                "{arch}/{role}"
            );
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if arch == WinArch::X86 {
                    STATUS_INVALID_INFO_CLASS
                } else {
                    expected64
                }),
                "{arch}/{role}"
            );
            if role == 5 || role == 6 {
                let guarded = if role == 5 { scratch } else { returned };
                assert_eq!(
                    p.vm.query(guarded).unwrap().protect & prot::GUARD,
                    if arch == WinArch::X86 { prot::GUARD } else { 0 },
                    "{arch}/{role}"
                );
            }
            p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE).unwrap();
            p.vm.protect(returned, PAGE_SIZE, prot::READWRITE).unwrap();
            let success = arch != WinArch::X86 && expected64 == STATUS_SUCCESS;
            let mut expected = if success { [0; 16] } else { [0xA5; 16] };
            if success && role == 7 {
                expected[..4].copy_from_slice(&16u32.to_le_bytes());
            }
            assert_eq!(
                p.space.bytes(scratch, 16).unwrap(),
                expected,
                "{arch}/{role}"
            );
            if success && role == 3 {
                assert_eq!(p.space.u32(returned + 1).unwrap(), 16);
                assert_eq!(p.space.u8(returned).unwrap(), 0xA5);
            } else {
                assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5, "{arch}/{role}");
            }
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_processor_feature_bitmap_probes_unused_supplied_tail_all_abis() {
    for arch in WinArch::ALL {
        for protection in [prot::READONLY, prot::READWRITE | prot::GUARD] {
            let (mut process, mut t, _) = query_fixture(arch);
            let p = process.state_mut();
            let pages =
                p.vm.allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
            let output = pages + PAGE_SIZE - 16;
            p.space.wr(output, &[0xA5; 32]).unwrap();
            p.vm.protect(pages + PAGE_SIZE, PAGE_SIZE, protection)
                .unwrap();
            query_arguments(p, &mut t, 250, output, 24, 0);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            let status = if arch == WinArch::X86 {
                STATUS_INVALID_INFO_CLASS
            } else if protection & prot::GUARD != 0 {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            };
            assert_eq!(t.cpu.gpr(0), u64::from(status), "{arch}/{protection:#x}");
            assert_eq!(p.space.bytes(output, 16).unwrap(), [0xA5; 16]);
            assert_eq!(
                p.vm.query(pages + PAGE_SIZE).unwrap().protect & prot::GUARD,
                if arch == WinArch::X86 {
                    protection & prot::GUARD
                } else {
                    0
                }
            );
            assert!(t.frames.is_empty());
        }
    }
}

#[cfg(windows)]
#[test]
fn installed_processor_feature_query_leaf_and_rtl_read_guest_policy() {
    use crate::user::windows::{
        dll::processor_feature_present,
        loader::{self, SymRef},
        process::{WindowsConfig, WindowsProcess},
    };
    let host_arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let architectures = if host_arch == WinArch::X86 {
        vec![host_arch]
    } else {
        vec![host_arch, WinArch::X86]
    };
    for arch in architectures {
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
            WindowsConfig::embedded("C:\\native-features.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtQuerySystemInformation".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let sp = t.cpu.sp();
        let output = sp - 128;
        let returned = output + 32;
        let resume = p.traps.callback_return();
        p.space.wr(output, &[0xA5; 40]).unwrap();
        query_arguments(p, &mut t, 250, output, 16, returned);
        match arch {
            WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
            WinArch::X64 => {
                p.space.w64(sp, resume).unwrap();
                t.cpu.set_gpr(1, 250);
            }
            WinArch::Arm64 => t.cpu.set_gpr(30, resume),
        }
        // The test's ordinary entry ABI differs from the direct WoW64 kernel
        // helper, which includes the transition's own return-address slot.
        if arch == WinArch::X86 {
            for (index, value) in [250, output, 16, returned].into_iter().enumerate() {
                p.space
                    .w32(sp + 4 + index as u64 * 4, value as u32)
                    .unwrap();
            }
        }
        t.cpu.set_pc(entry);
        assert_eq!(
            execute_to_return(p, &mut t, resume),
            if arch == WinArch::X86 {
                u64::from(STATUS_INVALID_INFO_CLASS)
            } else {
                0
            }
        );
        assert_eq!(
            p.space.bytes(output, 16).unwrap(),
            if arch == WinArch::X86 {
                [0xA5; 16]
            } else {
                [0; 16]
            }
        );
        assert_eq!(
            p.space.u32(returned).unwrap(),
            if arch == WinArch::X86 {
                0xA5A5_A5A5
            } else {
                16
            }
        );
        assert_eq!(
            t.cpu.sp(),
            sp + if arch == WinArch::X86 {
                20
            } else if arch == WinArch::X64 {
                8
            } else {
                0
            }
        );
        assert!(t.frames.is_empty());
        // Baseline native RTL queries read KUSER_SHARED_DATA directly. Extended
        // entries remain false before native bitmap initialization as in our
        // guest's conservative feature policy. Do not infer full Ldr startup.
        if arch == host_arch && arch != WinArch::X86 {
            let rtl = loader::lookup(
                p,
                module,
                &SymRef::Name(b"RtlIsProcessorFeaturePresent".to_vec(), None),
            )
            .unwrap()
            .unwrap();
            for feature in [2, 6, 10, 19, 23, 34, 63, 64, 65, 191, 192, u32::MAX] {
                let expected = u64::from(processor_feature_present(&t.cpu, feature));
                t.cpu.set_sp(sp);
                t.cpu.set_pc(rtl);
                if arch == WinArch::X64 {
                    p.space.w64(sp, resume).unwrap();
                    t.cpu.set_gpr(1, u64::from(feature));
                } else {
                    t.cpu.set_gpr(0, u64::from(feature));
                    t.cpu.set_gpr(30, resume);
                }
                assert_eq!(
                    execute_to_return(p, &mut t, resume),
                    expected,
                    "{arch}/{feature}"
                );
                assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X64 { 8 } else { 0 });
                assert!(t.frames.is_empty());
            }
        }
    }
}

#[cfg(windows)]
fn execute_to_return(p: &mut Proc, t: &mut Thread, resume: u64) -> u64 {
    for _ in 0..32 {
        let boundary = t.cpu.run(64);
        if t.cpu.pc() == resume {
            return t.cpu.gpr(0);
        }
        let description = format!(
            "{} PC={:#x}, SP={:#x}, boundary={boundary:?}",
            p.arch,
            t.cpu.pc(),
            t.cpu.sp()
        );
        assert!(
            matches!(
                handle_stop(p, t, boundary),
                Outcome::Continue | Outcome::Yield
            ),
            "{description}"
        );
    }
    panic!("installed NTDLL feature query did not return within 2048 instructions");
}
