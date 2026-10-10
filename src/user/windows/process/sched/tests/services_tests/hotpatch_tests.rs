//! Installed NT hotpatch availability query with explicit unavailable capability.
use super::*;

fn arguments(p: &mut Proc, t: &mut Thread, args: &[u64]) {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (index, value) in args.iter().enumerate() {
                p.space
                    .w32(sp + 8 + index as u64 * 4, *value as u32)
                    .unwrap();
            }
            t.cpu.set_gpr(0, 0x119);
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, 0x119);
            t.cpu.set_gpr(1, 0x1234_0004);
            for (index, value) in args.iter().enumerate() {
                if index < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][index], *value);
                } else {
                    p.space.w64(sp + 8 + index as u64 * 8, *value).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (index, value) in args.iter().enumerate() {
                t.cpu.set_gpr(index, *value);
            }
        }
    }
}
fn dispatch(p: &mut Proc, t: &mut Thread) -> Outcome {
    if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x119))
    }
}

#[test]
fn native_hotpatch_check_reports_unavailable_and_zero_return_length_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtManageHotPatch", 0x119);
        let p = process.state_mut();
        let scratch =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(scratch, &[0xA5; 32]).unwrap();
        arguments(p, &mut t, &[9, scratch, 8, scratch + 16]);
        assert_eq!(dispatch(p, &mut t), Outcome::Continue);
        assert_eq!(
            t.cpu.gpr(0),
            u64::from(crate::user::windows::nt::status::STATUS_NOT_SUPPORTED)
        );
        assert_eq!(p.space.u32(scratch + 16).unwrap(), 0);
        assert_eq!(p.space.bytes(scratch, 8).unwrap(), [0xA5; 8]);
        assert!(t.frames.is_empty());
    }
}

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtManageHotPatch", 0x119);
    let p = process.state_mut();
    let scratch =
        p.vm.allocate(
            None,
            PAGE_SIZE * 2,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.space
        .wr(scratch, &vec![0xA5; PAGE_SIZE as usize * 2])
        .unwrap();
    (process, t, scratch)
}
fn call(
    p: &mut Proc,
    t: &mut Thread,
    class: u32,
    info: u64,
    length: u32,
    returned: u64,
) -> Outcome {
    let sp = t.cpu.sp();
    arguments(p, t, &[u64::from(class), info, u64::from(length), returned]);
    let result = dispatch(p, t);
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    result
}
#[test]
fn native_hotpatch_disabled_lengths_and_opaque_version_flags_all_abis() {
    use crate::user::windows::nt::status::*;
    for arch in WinArch::ALL {
        for length in [0, 1, 4, 7, 8, 9, 12, 16, u32::MAX] {
            for (version, flags) in [(0, 0), (1, 0), (2, 0x12345678), (u32::MAX, u32::MAX)] {
                let (mut process, mut t, scratch) = setup(arch);
                let p = process.state_mut();
                p.space.w32(scratch, version).unwrap();
                p.space.w32(scratch + 4, flags).unwrap();
                let before = p.space.bytes(scratch, 8).unwrap();
                let rng = p.rng;
                let handles = p.objects.handle_count();
                assert_eq!(
                    call(p, &mut t, 9, scratch, length, scratch + 32),
                    Outcome::Continue
                );
                let bad = arch == WinArch::X86 && length != 8;
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if bad {
                        STATUS_INVALID_PARAMETER
                    } else {
                        STATUS_NOT_SUPPORTED
                    })
                );
                assert_eq!(
                    p.space.u32(scratch + 32).unwrap(),
                    if bad { 0xA5A5A5A5 } else { 0 }
                );
                assert_eq!(p.space.bytes(scratch, 8).unwrap(), before);
                assert_eq!(p.rng, rng);
                assert_eq!(p.objects.handle_count(), handles);
            }
        }
    }
}
#[test]
fn native_hotpatch_disabled_fault_priority_aliases_and_partial_return_length_all_abis() {
    use crate::user::windows::nt::status::*;
    for arch in WinArch::ALL {
        for role in 0..21 {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let ret = scratch + PAGE_SIZE;
            p.space.w32(scratch, 1).unwrap();
            p.space.w32(scratch + 4, 0x12345678).unwrap();
            let (mut out, mut returned, mut length) = (scratch, ret, 8);
            let mut expected = STATUS_NOT_SUPPORTED;
            let mut length_written = true;
            match role {
                0 => {
                    out = 0;
                    if arch == WinArch::X86 {
                        expected = STATUS_ACCESS_VIOLATION;
                        length_written = false;
                    }
                }
                1 => out = scratch + 1,
                2 => {
                    returned = 0;
                    expected = STATUS_ACCESS_VIOLATION;
                    length_written = false;
                }
                3 => returned = ret + 1,
                4 => {
                    returned = 1;
                    expected = STATUS_ACCESS_VIOLATION;
                    length_written = false;
                }
                5 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READONLY).unwrap();
                    if arch == WinArch::X86 {
                        expected = STATUS_ACCESS_VIOLATION;
                    }
                }
                6 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    if arch == WinArch::X86 {
                        expected = STATUS_GUARD_PAGE_VIOLATION;
                        length_written = false;
                    }
                }
                7 => {
                    p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = STATUS_GUARD_PAGE_VIOLATION;
                    length_written = false;
                }
                8 => {
                    length = 7;
                    p.vm.protect(scratch, PAGE_SIZE, prot::NOACCESS).unwrap();
                    if arch == WinArch::X86 {
                        expected = STATUS_INVALID_PARAMETER;
                        length_written = false;
                    }
                }
                9 => {
                    returned = scratch;
                }
                10 => {
                    returned = scratch + 4;
                }
                11 => {
                    returned = scratch + 1;
                }
                12 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    p.vm.protect(ret, PAGE_SIZE, prot::NOACCESS).unwrap();
                    expected = if arch.is64() {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_GUARD_PAGE_VIOLATION
                    };
                    length_written = false;
                }
                13 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::NOACCESS).unwrap();
                    p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = if arch.is64() {
                        STATUS_GUARD_PAGE_VIOLATION
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                    length_written = false;
                }
                14 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READONLY).unwrap();
                    p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = if arch == WinArch::X86 {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_GUARD_PAGE_VIOLATION
                    };
                    length_written = false;
                }
                15 => {
                    out = ret - 4;
                    returned = scratch + 128;
                    p.vm.protect(ret, PAGE_SIZE, prot::NOACCESS).unwrap();
                    if arch == WinArch::X86 {
                        expected = STATUS_ACCESS_VIOLATION;
                        length_written = false;
                    }
                }
                16 => {
                    out = ret - 8;
                    returned = scratch + 128;
                    p.vm.protect(ret, PAGE_SIZE, prot::NOACCESS).unwrap();
                }
                17 => {
                    length = 7;
                    returned = 1;
                    expected = if arch == WinArch::X86 {
                        STATUS_INVALID_PARAMETER
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                    length_written = false;
                }
                18 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READONLY | prot::GUARD)
                        .unwrap();
                    returned = 0;
                    expected = if arch == WinArch::X86 {
                        STATUS_GUARD_PAGE_VIOLATION
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                    length_written = false;
                }
                19 => {
                    p.vm.protect(ret, PAGE_SIZE, prot::READONLY | prot::GUARD)
                        .unwrap();
                    expected = STATUS_GUARD_PAGE_VIOLATION;
                    length_written = false;
                }
                20 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READONLY).unwrap();
                    returned = 0;
                    expected = STATUS_ACCESS_VIOLATION;
                    length_written = false;
                }
                _ => unreachable!(),
            }
            let before = p.objects.handle_count();
            assert_eq!(call(p, &mut t, 9, out, length, returned), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(expected), "{arch}/role{role}");
            assert_eq!(p.objects.handle_count(), before);
            if matches!(role, 6 | 12 | 18) {
                assert_eq!(
                    p.vm.query(scratch).unwrap().protect & prot::GUARD != 0,
                    arch.is64()
                );
            }
            if role == 13 {
                assert_eq!(
                    p.vm.query(ret).unwrap().protect & prot::GUARD != 0,
                    arch == WinArch::X86
                );
            }
            if matches!(role, 7 | 14 | 19) {
                assert_eq!(p.vm.query(ret).unwrap().protect & prot::GUARD, 0);
            }
            if !length_written && p.vm.query(ret).unwrap().protect == prot::READWRITE {
                assert_eq!(p.space.u32(ret).unwrap(), 0xA5A5A5A5, "{arch}/role{role}");
            }
            // Read-only/guard failures leave the captured input intact. Aliases
            // expose the native ReturnLength write and WoW64's later copy-back.
            if matches!(role, 9..=11) {
                let mut expected = [1, 0, 0, 0, 0x78, 0x56, 0x34, 0x12];
                if arch.is64() {
                    let at = if role == 9 {
                        0
                    } else if role == 10 {
                        4
                    } else {
                        1
                    };
                    expected[at..at + 4].fill(0);
                }
                assert_eq!(p.space.bytes(scratch, 8).unwrap(), expected);
            } else if length_written {
                assert_eq!(p.space.u32(returned).unwrap(), 0, "{arch}/role{role}");
            }
        }
    }
}
#[test]
fn native_hotpatch_mutating_and_unknown_operations_remain_explicitly_unsupported() {
    for arch in WinArch::ALL {
        for class in [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, u32::MAX] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            p.vm.protect(scratch, PAGE_SIZE * 2, prot::READWRITE | prot::GUARD)
                .unwrap();
            let before = p.objects.handle_count();
            assert!(
                matches!(call(p,&mut t,class,scratch,8,scratch+PAGE_SIZE),Outcome::Fail(reason)if reason.contains(&format!("hotpatch operation class {class}")))
            );
            assert_eq!(p.objects.handle_count(), before);
            assert_ne!(p.vm.query(scratch).unwrap().protect & prot::GUARD, 0);
            assert_ne!(
                p.vm.query(scratch + PAGE_SIZE).unwrap().protect & prot::GUARD,
                0
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn installed_ntdll_hotpatch_query_leaf_reports_disabled_capability() {
    use crate::user::windows::{
        loader::{self, SymRef},
        nt::status::STATUS_NOT_SUPPORTED,
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
            WindowsConfig::embedded("C:\\native-hotpatch.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(p, module, &SymRef::Name(b"NtManageHotPatch".to_vec(), None))
            .unwrap()
            .unwrap();
        let sp = t.cpu.sp();
        let out = sp - 128;
        let returned = out + 16;
        let resume = p.traps.callback_return();
        let handles = p.objects.handle_count();
        p.space.wr(out, &[0xA5; 32]).unwrap();
        for (index, value) in [9, out, 8, returned].into_iter().enumerate() {
            match arch {
                WinArch::X86 => p
                    .space
                    .w32(sp + 4 + index as u64 * 4, value as u32)
                    .unwrap(),
                WinArch::X64 => t.cpu.set_gpr([1, 2, 8, 9][index], value),
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
        for _ in 0..32 {
            let boundary = t.cpu.run(64);
            if t.cpu.pc() == resume {
                completed = true;
                break;
            }
            let description = format!("{arch} NtManageHotPatch PC={:#x} {boundary:?}", t.cpu.pc());
            assert!(
                matches!(
                    handle_stop(p, &mut t, boundary),
                    Outcome::Continue | Outcome::Yield
                ),
                "{description}"
            );
        }
        assert!(
            completed,
            "{arch} installed NtManageHotPatch did not return"
        );
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_NOT_SUPPORTED));
        assert_eq!(p.space.u32(returned).unwrap(), 0);
        assert_eq!(p.space.bytes(out, 8).unwrap(), [0xA5; 8]);
        assert_eq!(p.objects.handle_count(), handles);
        assert!(t.frames.is_empty());
        assert_eq!(
            t.cpu.sp(),
            sp + match arch {
                WinArch::X86 => 20,
                WinArch::X64 => 8,
                WinArch::Arm64 => 0,
            }
        );
    }
}

#[test]
fn builtin_hotpatch_query_returns_nt_fault_status_without_guest_exception_all_abis() {
    use crate::user::windows::{dll, hle::dispatch, nt::status::*};
    for arch in WinArch::ALL {
        for role in 0..5 {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let returned = scratch + PAGE_SIZE;
            let mut args = [9, scratch, 8, returned];
            let expected = match role {
                0 => {
                    args[3] = 0;
                    STATUS_ACCESS_VIOLATION
                }
                1 => {
                    args[3] = 1;
                    STATUS_ACCESS_VIOLATION
                }
                2 => {
                    p.vm.protect(returned, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                3 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READONLY).unwrap();
                    if arch == WinArch::X86 {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_NOT_SUPPORTED
                    }
                }
                4 => STATUS_NOT_SUPPORTED,
                _ => unreachable!(),
            };
            let sp = t.cpu.sp();
            let resume = 0x1234_5000;
            for (index, value) in args.into_iter().enumerate() {
                match arch {
                    WinArch::X86 => p
                        .space
                        .w32(sp + 4 + index as u64 * 4, value as u32)
                        .unwrap(),
                    WinArch::X64 => t.cpu.set_gpr([1, 2, 8, 9][index], value),
                    WinArch::Arm64 => t.cpu.set_gpr(index, value),
                }
            }
            match arch {
                WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
                WinArch::X64 => p.space.w64(sp, resume).unwrap(),
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            let api = dll::nt_service("NtManageHotPatch", arch).unwrap();
            assert_eq!(
                dispatch::enter(p, &mut t, api, 0x1234_1000),
                Outcome::Continue,
                "{arch}/role{role}"
            );
            assert_eq!(t.cpu.pc(), resume, "{arch}/role{role}");
            assert_eq!(t.cpu.gpr(0), u64::from(expected), "{arch}/role{role}");
            assert!(t.frames.is_empty(), "{arch}/role{role}");
            assert_eq!(
                t.cpu.sp(),
                sp + match arch {
                    WinArch::X86 => 20,
                    WinArch::X64 => 8,
                    WinArch::Arm64 => 0,
                }
            );
        }
    }
}
