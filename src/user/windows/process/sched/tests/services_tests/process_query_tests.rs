//! Installed process-cookie query, independently probed handle and fault order.

use super::*;
use crate::user::windows::nt::status::{STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE};

fn arguments(p: &mut Proc, t: &mut Thread, handle: u64, class: u32, out: u64, len: u32, ret: u64) {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            for (index, value) in [
                0x1234_0004,
                0x1234_0000,
                handle,
                u64::from(class),
                out,
                u64::from(len),
                ret,
            ]
            .into_iter()
            .enumerate()
            {
                p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, 0x19);
        }
        WinArch::X64 => {
            for (register, value) in [
                (0, 0x19),
                (1, 0x1234_0004),
                (10, handle),
                (2, u64::from(class)),
                (8, out),
                (9, u64::from(len)),
            ] {
                t.cpu.set_gpr(register, value);
            }
            p.space.w64(sp + 40, ret).unwrap();
        }
        WinArch::Arm64 => {
            for (index, value) in [handle, u64::from(class), out, u64::from(len), ret]
                .into_iter()
                .enumerate()
            {
                t.cpu.set_gpr(index, value);
            }
        }
    }
}

fn dispatch(p: &mut Proc, t: &mut Thread) -> Outcome {
    if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x19))
    }
}

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtQueryInformationProcess", 0x19);
    let p = process.state_mut();
    let scratch =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space.wr(scratch, &[0xA5; 128]).unwrap();
    (process, t, scratch)
}

#[test]
fn native_process_cookie_is_stable_across_queries_prng_changes_and_guest_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let cookie = p.process_cookie;
        let sp = t.cpu.sp();
        for returned_offset in [None, Some(64), Some(65)] {
            let rng = p.rng;
            t.cpu.set_sp(sp);
            arguments(
                p,
                &mut t,
                arch.ptr(u64::MAX),
                36,
                scratch,
                4,
                returned_offset.map_or(0, |n| scratch + n),
            );
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(
                p.rng, rng,
                "query must not consume the existing PRNG stream"
            );
            assert_eq!(p.space.u32(scratch).unwrap(), cookie);
            assert_eq!(p.space.u32(scratch + 4).unwrap(), 0xA5A5_A5A5);
            if let Some(offset) = returned_offset {
                assert_eq!(p.space.u32(scratch + offset).unwrap(), 4);
            }
            assert_eq!(t.cpu.pc(), 0x1234_0004);
            assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
            assert!(t.frames.is_empty());
            p.random();
        }
        let (other, _, _) = setup(arch);
        assert_eq!(
            other.state().process_cookie,
            cookie,
            "identical seeds reproduce the modeled value"
        );
    }
}

#[test]
fn native_process_cookie_checks_exact_length_alignment_and_handle_write_grants_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, 3, 5, u32::MAX] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            arguments(p, &mut t, 0, 36, scratch, length, scratch + 64);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INFO_LENGTH_MISMATCH));
            assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
        }
        for access in [0, 0x10, 0x40, 0x400, 0x1000, 0x1400, 0x20, 0x420, u32::MAX] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let object = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            let handle = p.objects.open_access(object, false, access).unwrap();
            arguments(
                p,
                &mut t,
                u64::from(handle | 1),
                36,
                scratch,
                4,
                scratch + 64,
            );
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            if access & 0x20 == 0 {
                assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_DENIED));
                assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
            } else {
                assert_eq!(t.cpu.gpr(0), 0);
                assert_eq!(p.space.u32(scratch).unwrap(), p.process_cookie);
                assert_eq!(p.space.u32(scratch + 64).unwrap(), 4);
            }
        }
        for handle in [0, 1, arch.ptr(u64::MAX - 1)] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            arguments(p, &mut t, handle, 36, scratch, 4, scratch + 64);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_HANDLE));
            assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
        }
        for class in [0, 1, u32::MAX] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            arguments(
                p,
                &mut t,
                arch.ptr(u64::MAX),
                class,
                scratch,
                4,
                scratch + 64,
            );
            assert!(
                matches!(dispatch(p, &mut t), Outcome::Fail(reason) if reason.contains(&format!("NtQueryInformationProcess class {class}")))
            );
            assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
        }
    }
}

#[test]
fn native_process_cookie_fault_priority_differs_from_system_queries_all_abis() {
    for arch in WinArch::ALL {
        for (out, returned, length, handle, status) in [
            (1, 1, 4, 0, STATUS_DATATYPE_MISALIGNMENT),
            (0, 1, 0, 0, STATUS_ACCESS_VIOLATION),
            (0, 0, 4, 0, STATUS_INVALID_HANDLE),
            (0, 0, 4, arch.ptr(u64::MAX), STATUS_ACCESS_VIOLATION),
        ] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            arguments(p, &mut t, handle, 36, out, length, returned);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(status));
            assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
            assert!(t.frames.is_empty());
        }
        for output_guard in [false, true] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let returned =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.w32(returned, 0xA5A5_A5A5).unwrap();
            p.vm.protect(
                if output_guard { scratch } else { returned },
                PAGE_SIZE,
                prot::READWRITE | prot::GUARD,
            )
            .unwrap();
            if output_guard {
                p.vm.protect(returned, PAGE_SIZE, prot::READONLY).unwrap();
            }
            arguments(p, &mut t, arch.ptr(u64::MAX), 36, scratch, 4, returned);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if output_guard {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_GUARD_PAGE_VIOLATION
                })
            );
            if output_guard {
                assert_eq!(
                    p.vm.query(scratch).unwrap().protect,
                    prot::READWRITE | prot::GUARD
                );
                p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE).unwrap();
            }
            assert_eq!(p.space.u32(scratch).unwrap(), 0xA5A5_A5A5);
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_process_cookie_aliases_and_each_guard_preserve_probe_write_and_retry_order_all_abis() {
    for arch in WinArch::ALL {
        for offset in 0..=4 {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            arguments(
                p,
                &mut t,
                arch.ptr(u64::MAX),
                36,
                scratch,
                4,
                scratch + offset,
            );
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            let mut expected = [0xA5; 12];
            expected[..4].copy_from_slice(&p.process_cookie.to_le_bytes());
            expected[offset as usize..offset as usize + 4].copy_from_slice(&4u32.to_le_bytes());
            assert_eq!(p.space.bytes(scratch, 12).unwrap(), expected);
        }
        for output_guard in [false, true] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let returned =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.w32(returned, 0xA5A5_A5A5).unwrap();
            let guarded = if output_guard { scratch } else { returned };
            p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            let sp = t.cpu.sp();
            arguments(p, &mut t, arch.ptr(u64::MAX), 36, scratch, 4, returned);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_GUARD_PAGE_VIOLATION));
            assert_eq!(p.vm.query(guarded).unwrap().protect, prot::READWRITE);
            assert_eq!(p.space.u32(scratch).unwrap(), 0xA5A5_A5A5);
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
            t.cpu.set_sp(sp);
            arguments(p, &mut t, arch.ptr(u64::MAX), 36, scratch, 4, returned);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(scratch).unwrap(), p.process_cookie);
            assert_eq!(p.space.u32(returned).unwrap(), 4);
        }
    }
}

#[test]
fn native_process_cookie_for_an_unmodeled_peer_is_explicitly_unsupported() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let peer = p.objects.create(Object::Process {
            pid: p.pid + 4,
            exit_code: None,
        });
        let handle = p.objects.open_access(peer, false, 0x20).unwrap();
        arguments(p, &mut t, u64::from(handle), 36, scratch, 4, scratch + 64);
        assert!(matches!(dispatch(p, &mut t), Outcome::Fail(reason)
            if reason.contains("ProcessCookie for a process outside this personality")));
        assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
    }
}

#[cfg(windows)]
#[test]
fn installed_native_cookie_leaf_and_pointer_encoding_execute_actual_ntdll_and_returns() {
    use crate::user::windows::loader::{self, SymRef};
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let mut arches = vec![host];
    if host != WinArch::X86 {
        arches.push(WinArch::X86);
    }
    for arch in arches {
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
            WindowsConfig::embedded("C:\\native-cookie.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process =
            super::super::super::super::WindowsProcess::spawn_image(config, image.to_vec())
                .unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        if arch == WinArch::X86 {
            assert_eq!(
                p.space
                    .u32(t.teb + crate::user::windows::layout::WOW64_TEB_TRANSITION)
                    .unwrap(),
                p.traps.wow64_transition() as u32
            );
        }
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtQueryInformationProcess".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let sp = t.cpu.sp();
        let output = sp - 128;
        let returned = output + 32;
        let resume = p.traps.callback_return();
        p.space.wr(output, &[0xA5; 40]).unwrap();
        match arch {
            WinArch::X86 => {
                for (index, value) in [resume, arch.ptr(u64::MAX), 36, output, 4, returned]
                    .into_iter()
                    .enumerate()
                {
                    p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
                }
            }
            WinArch::X64 => {
                p.space.w64(sp, resume).unwrap();
                p.space.w64(sp + 40, returned).unwrap();
                for (register, value) in [(1, u64::MAX), (2, 36), (8, output), (9, 4)] {
                    t.cpu.set_gpr(register, value);
                }
            }
            WinArch::Arm64 => {
                for (register, value) in [
                    (0, u64::MAX),
                    (1, 36),
                    (2, output),
                    (3, 4),
                    (4, returned),
                    (30, resume),
                ] {
                    t.cpu.set_gpr(register, value);
                }
            }
        }
        t.cpu.set_pc(entry);
        assert_eq!(
            run_to_return(p, &mut t, resume, "NtQueryInformationProcess"),
            0
        );
        assert_eq!(p.space.u32(output).unwrap(), p.process_cookie);
        assert_eq!(p.space.u32(returned).unwrap(), 4);
        assert_eq!(
            t.cpu.sp(),
            sp + match arch {
                WinArch::X86 => 24,
                WinArch::X64 => 8,
                WinArch::Arm64 => 0,
            }
        );
        assert!(t.frames.is_empty());
        // Actual userland encoding executes around the same native kernel query.
        // Check its inverse, not host-cookie-dependent encoded constants.
        for value in [0, 1, 0x1234_5678, arch.ptr(u64::MAX)] {
            let mut pointer = value;
            for name in ["RtlEncodePointer", "RtlDecodePointer"] {
                let entry =
                    loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap()
                        .unwrap();
                t.cpu.set_sp(sp);
                match arch {
                    WinArch::X86 => {
                        p.space.w32(sp, resume as u32).unwrap();
                        p.space.w32(sp + 4, pointer as u32).unwrap();
                    }
                    WinArch::X64 => {
                        p.space.w64(sp, resume).unwrap();
                        t.cpu.set_gpr(1, pointer);
                    }
                    WinArch::Arm64 => {
                        t.cpu.set_gpr(0, pointer);
                        t.cpu.set_gpr(30, resume);
                    }
                }
                t.cpu.set_pc(entry);
                pointer = arch.ptr(run_to_return(p, &mut t, resume, name));
                assert_eq!(t.cpu.sp(), sp + if arch == WinArch::Arm64 { 0 } else { 8 });
                assert!(t.frames.is_empty());
            }
            assert_eq!(pointer, value, "{arch}");
        }
    }
}

#[cfg(windows)]
fn run_to_return(p: &mut Proc, t: &mut Thread, resume: u64, name: &str) -> u64 {
    for _ in 0..32 {
        let boundary = t.cpu.run(64);
        if t.cpu.pc() == resume {
            return t.cpu.gpr(0);
        }
        let description = format!(
            "{} {name}: PC={:#x}, SP={:#x}, boundary={boundary:?}",
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
    panic!("installed NTDLL did not return within 2048 instructions");
}
