//! Class62 behavior from original native length/pointer/guard/alias oracles.
use super::*;

#[test]
fn native_emulation_basic_query_reports_guest_memory_bounds_cpu_and_preserves_wow64_padding_all_abis()
 {
    use crate::user::windows::layout::{self, kuser, offsets};
    for arch in WinArch::ALL {
        for output_offset in [0, 1, 4] {
            for returned_offset in [None, Some(96), Some(97)] {
                let (mut process, mut t, scratch) = query_fixture(arch);
                let p = process.state_mut();
                let output = scratch + output_offset;
                let required = if arch == WinArch::X86 { 44 } else { 64 };
                let returned = returned_offset.map_or(0, |offset| scratch + offset);
                query_arguments(p, &mut t, 62, output, required, returned);
                assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
                if arch != WinArch::X86 && output_offset == 1 {
                    assert_eq!(t.cpu.gpr(0), u64::from(STATUS_DATATYPE_MISALIGNMENT));
                    assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
                    continue;
                }
                assert_eq!(t.cpu.gpr(0), 0);
                assert!(t.frames.is_empty());
                assert_eq!(p.space.u32(output).unwrap(), 0);
                assert_eq!(p.space.u32(output + 4).unwrap(), 10_000); // 100 ns units.
                assert_eq!(p.space.u32(output + 8).unwrap(), 4096);
                assert_eq!(p.space.u32(output + 12).unwrap(), 16_384); // 64 MiB guest.
                assert_eq!(p.space.u32(output + 16).unwrap(), 0);
                assert_eq!(p.space.u32(output + 20).unwrap(), 16_383);
                assert_eq!(p.space.u32(output + 24).unwrap(), 65_536);
                let first = if arch == WinArch::X86 { 28 } else { 32 };
                let width = arch.ptr_size();
                assert_eq!(p.space.ptr(output + first, width).unwrap(), 0x1_0000);
                assert_eq!(
                    p.space.ptr(output + first + width, width).unwrap(),
                    p.vm.high() - 1
                );
                assert_eq!(p.space.ptr(output + first + 2 * width, width).unwrap(), 1);
                assert_eq!(p.space.u8(output + first + 3 * width).unwrap(), 1);
                if arch == WinArch::X86 {
                    assert_eq!(p.space.bytes(output + 41, 3).unwrap(), [0xA5; 3]);
                } else {
                    assert_eq!(p.space.u32(output + 28).unwrap(), 0);
                    assert_eq!(p.space.bytes(output + 57, 7).unwrap(), [0; 7]);
                }
                assert_eq!(p.space.u8(output + u64::from(required)).unwrap(), 0xA5);
                if returned != 0 {
                    assert_eq!(p.space.u32(returned).unwrap(), required);
                    assert_eq!(p.space.u8(returned + 4).unwrap(), 0xA5);
                }
                assert_eq!(
                    p.space
                        .u32(layout::KUSER_SHARED_DATA + kuser::NUMBER_OF_PHYSICAL_PAGES)
                        .unwrap(),
                    16_384
                );
                assert_eq!(
                    p.space
                        .u32(layout::KUSER_SHARED_DATA + kuser::ACTIVE_PROCESSOR_COUNT)
                        .unwrap(),
                    1
                );
                assert_eq!(
                    p.space
                        .u32(p.peb + offsets(arch).peb_number_of_processors)
                        .unwrap(),
                    1
                );
            }
        }
    }
}

#[test]
fn native_emulation_basic_query_length_null_and_return_faults_are_class_specific_all_abis() {
    for arch in WinArch::ALL {
        let required = if arch == WinArch::X86 { 44 } else { 64 };
        for length in [0, required - 1, required + 1] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            query_arguments(p, &mut t, 62, scratch, length, scratch + 96);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INFO_LENGTH_MISMATCH));
            assert_eq!(p.space.bytes(scratch, 80).unwrap(), [0xA5; 80]);
            assert_eq!(p.space.u32(scratch + 96).unwrap(), required);
        }
        for (output_bad, returned_bad) in [(true, false), (false, true)] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            query_arguments(
                p,
                &mut t,
                62,
                if output_bad { 0 } else { scratch },
                required,
                if returned_bad {
                    0xDEAD_0000
                } else {
                    scratch + 96
                },
            );
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
            if arch == WinArch::X86 && returned_bad {
                assert_eq!(p.space.u32(scratch + 8).unwrap(), 4096);
                assert_eq!(p.space.bytes(scratch + 41, 3).unwrap(), [0xA5; 3]);
            } else {
                assert_eq!(p.space.bytes(scratch, 80).unwrap(), [0xA5; 80]);
            }
            assert_eq!(
                p.space.u32(scratch + 96).unwrap(),
                if arch == WinArch::X86 && output_bad {
                    0xFFFF_FFEC
                } else {
                    0xA5A5_A5A5
                }
            );
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_emulation_basic_query_probes_fields_before_writing_and_does_not_probe_wow64_padding_all_abis()
 {
    for arch in WinArch::ALL {
        for prefix in [0, 1, 4, 20, 40, 41, 43, 44, 60, 63, 64] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            let base =
                p.vm.allocate(
                    None,
                    PAGE_SIZE * 2,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
            p.space.wr(base + PAGE_SIZE - 80, &[0xA5; 80]).unwrap();
            p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            let output = base + PAGE_SIZE - prefix;
            let required = if arch == WinArch::X86 { 44 } else { 64 };
            query_arguments(p, &mut t, 62, output, required, scratch + 96);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            let success = prefix >= if arch == WinArch::X86 { 41 } else { 64 };
            let status = if success {
                STATUS_SUCCESS
            } else if arch != WinArch::X86 && output % 4 != 0 {
                STATUS_DATATYPE_MISALIGNMENT
            } else {
                STATUS_ACCESS_VIOLATION
            };
            assert_eq!(t.cpu.gpr(0), u64::from(status), "{arch}/{prefix}");
            if success {
                assert_eq!(p.space.u32(output + 8).unwrap(), 4096);
                assert_eq!(p.space.u32(scratch + 96).unwrap(), required);
            } else {
                assert_eq!(
                    p.space.bytes(output, prefix as usize).unwrap(),
                    vec![0xA5; prefix as usize]
                );
                assert_eq!(p.space.u32(scratch + 96).unwrap(), 0xA5A5_A5A5);
            }
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_emulation_basic_query_output_and_return_guards_are_one_shot_all_abis() {
    for arch in WinArch::ALL {
        for return_guard in [false, true] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            let returned =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.w32(returned, 0xA5A5_A5A5).unwrap();
            let guarded = if return_guard { returned } else { scratch };
            p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            let required = if arch == WinArch::X86 { 44 } else { 64 };
            query_arguments(p, &mut t, 62, scratch, required, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_GUARD_PAGE_VIOLATION));
            assert_eq!(p.vm.query(guarded).unwrap().protect, prot::READWRITE);
            assert_eq!(
                p.space.u32(scratch + 8).unwrap(),
                if arch == WinArch::X86 && return_guard {
                    4096
                } else {
                    0xA5A5_A5A5
                }
            );
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
            query_arguments(p, &mut t, 62, scratch, required, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(returned).unwrap(), required);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_emulation_basic_query_readonly_destinations_and_output_aliases_preserve_write_order_all_abis()
 {
    for arch in WinArch::ALL {
        let required = if arch == WinArch::X86 { 44 } else { 64 };
        for readonly_output in [false, true] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            let returned =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.w32(returned, 0xA5A5_A5A5).unwrap();
            p.vm.protect(
                if readonly_output { scratch } else { returned },
                PAGE_SIZE,
                prot::READONLY,
            )
            .unwrap();
            query_arguments(p, &mut t, 62, scratch, required, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
            assert_eq!(
                p.space.u32(scratch + 8).unwrap(),
                if arch == WinArch::X86 && !readonly_output {
                    4096
                } else {
                    0xA5A5_A5A5
                }
            );
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
            assert!(t.frames.is_empty());
        }
        let (mut process, mut t, scratch) = query_fixture(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        query_arguments(p, &mut t, 62, scratch, required, 0);
        assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        let original = p.space.bytes(scratch, 80).unwrap();
        for offset in [0, 1, 8, 24, 40, 60] {
            p.space.wr(scratch, &[0xA5; 80]).unwrap();
            t.cpu.set_sp(sp);
            query_arguments(p, &mut t, 62, scratch, required, scratch + offset);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            let mut expected = original.clone();
            expected[offset as usize..offset as usize + 4].copy_from_slice(&required.to_le_bytes());
            assert_eq!(
                p.space.bytes(scratch, 80).unwrap(),
                expected,
                "{arch}/{offset}"
            );
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn wow64_emulation_basic_query_tracks_the_executable_large_address_aware_flag() {
    use crate::user::image::pe::IMAGE_FILE_LARGE_ADDRESS_AWARE;
    for large in [false, true] {
        let mut image =
            include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
                .to_vec();
        let pe = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
        let mut flags = u16::from_le_bytes(image[pe + 22..pe + 24].try_into().unwrap());
        if large {
            flags |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
        } else {
            flags &= !IMAGE_FILE_LARGE_ADDRESS_AWARE;
        }
        image[pe + 22..pe + 24].copy_from_slice(&flags.to_le_bytes());
        let mut config = WindowsConfig::embedded("C:\\app\\range.exe", vec![], vec![], 0).unwrap();
        config.arena_bytes = (128 << 20) + 123; // Backing rounds down to 4 KiB.
        let mut process =
            crate::user::windows::process::WindowsProcess::spawn_image(config, image).unwrap();
        let p = process.state_mut();
        let module = p.modules.by_name("ntdll.dll").unwrap();
        p.modules.nt_services = Some((
            module,
            table(WinArch::X86, "NtQuerySystemInformation", 0x36),
        ));
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let sp = t.cpu.sp();
        let output = sp - 128;
        query_arguments(p, &mut t, 50, output, 4, output + 16);
        assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        let expected = if large { 0xFFFF_0000 } else { 0x7FFF_0000 };
        assert_eq!(p.vm.high(), expected);
        assert_eq!(p.space.u32(output).unwrap(), expected as u32);
        assert_eq!(p.space.u32(output + 16).unwrap(), 4);
        t.cpu.set_sp(sp);
        query_arguments(p, &mut t, 62, output, 44, output + 96);
        assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(p.space.u32(output + 12).unwrap(), 32_768);
        assert_eq!(p.space.u32(output + 20).unwrap(), 32_767);
        assert_eq!(p.space.u32(output + 32).unwrap(), expected as u32 - 1);
        assert_eq!(p.space.u32(output + 96).unwrap(), 44);
    }
}

#[cfg(windows)]
#[test]
fn installed_emulation_basic_query_leaf_reports_guest_metadata() {
    use crate::user::windows::{
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
        let returned = output + 96;
        let resume = p.traps.callback_return();
        p.space.wr(output, &[0xA5; 128]).unwrap();
        let required = if arch == WinArch::X86 { 44 } else { 64 };
        query_arguments(p, &mut t, 62, output, required, returned);
        match arch {
            WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
            WinArch::X64 => {
                p.space.w64(sp, resume).unwrap();
                t.cpu.set_gpr(1, 62);
            }
            WinArch::Arm64 => t.cpu.set_gpr(30, resume),
        }
        // The test's ordinary entry ABI differs from the direct WoW64 kernel
        // helper, which includes the transition's own return-address slot.
        if arch == WinArch::X86 {
            for (index, value) in [62, output, u64::from(required), returned]
                .into_iter()
                .enumerate()
            {
                p.space
                    .w32(sp + 4 + index as u64 * 4, value as u32)
                    .unwrap();
            }
        }
        t.cpu.set_pc(entry);
        assert_eq!(execute_to_return(p, &mut t, resume), 0);
        assert_eq!(p.space.u32(output + 8).unwrap(), PAGE_SIZE as u32);
        assert_eq!(p.space.u32(output + 12).unwrap(), 65_536);
        let first = if arch == WinArch::X86 { 28 } else { 32 };
        assert_eq!(
            p.space.ptr(output + first, arch.ptr_size()).unwrap(),
            p.vm.low()
        );
        assert_eq!(
            p.space
                .ptr(output + first + arch.ptr_size(), arch.ptr_size())
                .unwrap(),
            p.vm.high() - 1
        );
        assert_eq!(p.space.u32(returned).unwrap(), required);
        if arch == WinArch::X86 {
            assert_eq!(p.space.bytes(output + 41, 3).unwrap(), [0xA5; 3]);
        }
        assert_eq!(p.space.u8(output + u64::from(required)).unwrap(), 0xA5);
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
    panic!("installed NTDLL emulation basic query did not return within 2048 instructions");
}
