use super::*;
use crate::user::windows::loader::services::tests::table;

#[path = "services_tests/process_query_tests.rs"]
mod process_query_tests;

fn fixture(
    arch: WinArch,
    name: &str,
    number: u32,
) -> (super::super::super::WindowsProcess, Thread) {
    let (mut process, thread, module) = terminal_fixture(arch);
    process.state_mut().modules.nt_services = Some((module, table(arch, name, number)));
    (process, thread)
}

fn stop(arch: WinArch, number: u32) -> CpuStop {
    match arch {
        WinArch::Arm64 => CpuStop::Svc {
            imm: number as u16,
            pc: 0x1234_0000,
        },
        _ => CpuStop::X86Syscall {
            insn: crate::isa::x86_64::X86SyscallInsn::Syscall,
            insn_rip: 0x1234_0000,
        },
    }
}

#[test]
fn native_close_preserves_kernel_resume_stack_and_arch_argument_transport() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        let (mut process, mut t) = fixture(arch, "NtClose", 0x37);
        let p = process.state_mut();
        let object = p.objects.create(Object::Event {
            manual: true,
            signaled: false,
        });
        let handle = p.objects.open(object, false);
        let sp = t.cpu.sp();
        t.cpu.set_pc(0x1234_0004);
        t.cpu.set_gpr(8, 0xBAD); // ARM64 must select the SVC immediate.
        if arch == WinArch::X64 {
            t.cpu.set_gpr(0, 0x37);
            t.cpu.set_gpr(10, u64::from(handle));
            t.cpu.set_gpr(1, 0x1234_0004); // Architectural SYSCALL clobber.
        } else {
            t.cpu.set_gpr(0, u64::from(handle));
        }
        assert_eq!(handle_stop(p, &mut t, stop(arch, 0x37)), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_SUCCESS));
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp);
        assert!(p.objects.get(u64::from(handle)).is_none());
        if arch == WinArch::X64 {
            assert_eq!(t.cpu.gpr(1), 0x1234_0004);
        }
        assert!(t.frames.is_empty());
    }
}

#[test]
fn native_alloc_invalid_pointer_returns_status_without_dispatching_guest_exception() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        let (mut process, mut t) = fixture(arch, "NtAllocateVirtualMemory", 0x18);
        if arch == WinArch::X64 {
            t.cpu.set_gpr(0, 0x18);
            t.cpu.set_gpr(10, u64::MAX);
            t.cpu.set_gpr(2, 0xDEAD_0000);
            t.cpu.set_gpr(8, 0);
            t.cpu.set_gpr(9, 0xDEAD_1000);
        } else {
            t.cpu.set_gpr(0, u64::MAX);
            t.cpu.set_gpr(1, 0xDEAD_0000);
            t.cpu.set_gpr(2, 0);
            t.cpu.set_gpr(3, 0xDEAD_1000);
        }
        assert_eq!(
            handle_stop(process.state_mut(), &mut t, stop(arch, 0x18)),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
        assert!(t.frames.is_empty());
    }
}

#[test]
fn native_termination_is_forced_and_unknown_services_are_diagnosed() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        let (mut process, mut t) = fixture(arch, "NtTerminateProcess", 0x2C);
        if arch == WinArch::X64 {
            t.cpu.set_gpr(0, 0x2C);
            t.cpu.set_gpr(10, u64::MAX);
            t.cpu.set_gpr(2, 73);
        } else {
            t.cpu.set_gpr(0, u64::MAX);
            t.cpu.set_gpr(1, 73);
        }
        assert_eq!(
            handle_stop(process.state_mut(), &mut t, stop(arch, 0x2C)),
            Outcome::ProcessTerminate(73)
        );
        t.cpu.set_gpr(0, 0x55);
        assert!(
            matches!(handle_stop(process.state_mut(), &mut t, stop(arch, 0x55)), Outcome::Fail(reason) if reason.contains("no admitted stub"))
        );
    }
}

#[test]
fn wow64_close_consumes_only_its_internal_return_and_keeps_callee_cleanup_in_guest_code() {
    let (mut process, mut t) = fixture(WinArch::X86, "NtClose", 0x3000f);
    let p = process.state_mut();
    let object = p.objects.create(Object::Event {
        manual: true,
        signaled: false,
    });
    let handle = p.objects.open(object, false);
    let sp = t.cpu.sp();
    p.space.w32(sp, 0x1234000c).unwrap();
    p.space.w32(sp + 4, 0x12340000).unwrap();
    p.space.w32(sp + 8, handle).unwrap();
    t.cpu.set_pc(0x10010000);
    t.cpu.set_gpr(0, 0x3000f);
    assert_eq!(
        super::super::super::services::wow64(p, &mut t, 0x10010000),
        Outcome::Continue
    );
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(t.cpu.pc(), 0x1234000c);
    assert_eq!(t.cpu.sp(), sp + 4);
    assert!(p.objects.get(u64::from(handle)).is_none());
    assert!(t.frames.is_empty());
}

#[test]
fn wow64_stack_arguments_faults_and_unknown_numbers_have_distinct_results() {
    let (mut process, mut t) = fixture(WinArch::X86, "NtAllocateVirtualMemory", 0x18);
    let p = process.state_mut();
    let sp = t.cpu.sp() - 0x100;
    t.cpu.set_sp(sp);
    t.cpu.set_pc(0x10010000);
    t.cpu.set_gpr(0, 0x18);
    for (i, arg) in [
        0x1234000c,
        0x12340000,
        u32::MAX,
        (sp + 0x80) as u32,
        0,
        (sp + 0x84) as u32,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    ]
    .into_iter()
    .enumerate()
    {
        p.space.w32(sp + 4 * i as u64, arg).unwrap();
    }
    p.space.w32(sp + 0x80, 0).unwrap();
    p.space.w32(sp + 0x84, 4096).unwrap();
    assert_eq!(
        super::super::super::services::wow64(p, &mut t, 0x10010000),
        Outcome::Continue
    );
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(p.space.u32(sp + 0x84).unwrap(), 4096);
    let allocation = u64::from(p.space.u32(sp + 0x80).unwrap());
    assert!(allocation >= 0x10000);
    assert_eq!(p.vm.query(allocation).unwrap().state, mem::COMMIT);
    t.cpu.set_sp(sp);
    t.cpu.set_pc(0x10010000);
    p.space.w32(sp + 12, 0xDEAD0000).unwrap();
    t.cpu.set_gpr(0, 0x18);
    assert_eq!(
        super::super::super::services::wow64(p, &mut t, 0x10010000),
        Outcome::Continue
    );
    assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
    t.cpu.set_sp(sp);
    t.cpu.set_pc(0x10010000);
    t.cpu.set_gpr(0, 0x12345678);
    assert!(
        matches!(super::super::super::services::wow64(p,&mut t,0x10010000),Outcome::Fail(reason) if reason.contains("no admitted stub"))
    );
    assert_eq!(t.cpu.sp(), sp);
    assert_eq!(t.cpu.pc(), 0x10010000);
    t.cpu.set_sp(0xDEAD0000);
    assert!(
        matches!(super::super::super::services::wow64(p,&mut t,0x10010000),Outcome::Fail(reason) if reason.contains("return address"))
    );
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn installed_wow64_close_executes_the_selected_leaf_thunk_and_actual_ret_cleanup() {
    use crate::user::windows::{
        loader::{self, SymRef},
        native::NativeRuntime,
    };
    let runtime = NativeRuntime::select(WinArch::X86).unwrap();
    let bytes = std::fs::read(runtime.dll("ntdll.dll").unwrap().unwrap()).unwrap();
    let (mut process, mut t, _) = terminal_fixture(WinArch::X86);
    let p = process.state_mut();
    let mut config = (*p.cfg).clone();
    config.host_filesystem = false;
    config
        .supplied_dlls
        .insert("c:\\selected\\ntdll.dll".into(), bytes.into());
    p.cfg = Arc::new(config);
    let module = loader::load_dll(p, "C:\\selected\\ntdll.dll").unwrap();
    let entry = loader::lookup(p, module, &SymRef::Name(b"NtClose".to_vec(), None))
        .unwrap()
        .unwrap();
    let object = p.objects.create(Object::Event {
        manual: true,
        signaled: false,
    });
    let handle = p.objects.open(object, false);
    let sp = t.cpu.sp();
    let return_pc = p.traps.callback_return();
    p.space.w32(sp, return_pc as u32).unwrap();
    p.space.w32(sp + 4, handle).unwrap();
    t.cpu.set_pc(entry);
    let stop = t.cpu.run(64);
    assert!(matches!(stop, CpuStop::Fault(_)));
    assert_eq!(t.cpu.pc(), p.traps.wow64_transition());
    assert_eq!(t.cpu.sp(), sp - 4);
    assert_eq!(handle_stop(p, &mut t, stop), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(t.cpu.pc(), entry + 12);
    assert_eq!(t.cpu.sp(), sp);
    assert!(p.objects.get(u64::from(handle)).is_none());
    t.cpu.run(1);
    assert_eq!(t.cpu.pc(), return_pc);
    assert_eq!(t.cpu.sp(), sp + 8);
}

#[cfg(windows)]
#[test]
fn installed_ntdll_close_executes_its_guest_stub_and_resumes_at_ret() {
    use crate::user::windows::loader::{self, SymRef};
    let root =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("Windows SystemRoot"));
    let bytes = std::fs::read(root.join("System32").join("ntdll.dll")).unwrap();
    let image = crate::user::image::pe::PeImage::parse(bytes.clone()).unwrap();
    let arch = WinArch::from_machine(image.headers().machine).unwrap();
    let (mut process, mut t, _) = terminal_fixture(arch);
    let p = process.state_mut();
    let mut config = (*p.cfg).clone();
    config.host_filesystem = false;
    config
        .supplied_dlls
        .insert("c:\\selected\\ntdll.dll".into(), bytes.into());
    p.cfg = Arc::new(config);
    let module = loader::load_dll(p, "C:\\selected\\ntdll.dll").unwrap();
    let entry = loader::lookup(p, module, &SymRef::Name(b"NtClose".to_vec(), None))
        .unwrap()
        .unwrap();
    let object = p.objects.create(Object::Event {
        manual: true,
        signaled: false,
    });
    let handle = p.objects.open(object, false);
    t.cpu.set_pc(entry);
    if arch == WinArch::X64 {
        t.cpu.set_gpr(1, u64::from(handle));
    } else {
        t.cpu.set_gpr(0, u64::from(handle));
        t.cpu.set_gpr(8, 0xBAD);
    }
    let sp = t.cpu.sp();
    let stop = t.cpu.run(64);
    assert!(matches!(
        stop,
        CpuStop::Svc { .. } | CpuStop::X86Syscall { .. }
    ));
    let resume = t.cpu.pc();
    assert!(resume > entry);
    assert_eq!(handle_stop(p, &mut t, stop), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(t.cpu.pc(), resume);
    assert_eq!(t.cpu.sp(), sp);
    assert!(p.objects.get(u64::from(handle)).is_none());
    assert!(t.frames.is_empty());
    // Execute the real installed RET; kernel dispatch did not consume it.
    let return_pc = if arch == WinArch::Arm64 {
        t.cpu.gpr(30)
    } else {
        p.space.u64(sp).unwrap()
    };
    t.cpu.run(1);
    assert_eq!(t.cpu.pc(), return_pc);
}

#[cfg(windows)]
#[test]
fn native_closed_spawn_selects_installed_ntdll_and_guest_api_set_map() {
    use crate::user::windows::loader::{self, ModuleKind, SymRef, builtin};
    let arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let base = if arch.is64() { 0x140000000 } else { 0x400000 };
    let mut image = builtin::build(
        crate::user::windows::dll::find("ntdll.dll").unwrap(),
        arch,
        base,
        &[],
    )
    .bytes;
    let pe = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    let characteristics = u16::from_le_bytes(image[pe + 22..pe + 24].try_into().unwrap())
        & !crate::user::image::pe::IMAGE_FILE_DLL;
    image[pe + 22..pe + 24].copy_from_slice(&characteristics.to_le_bytes());
    image[pe + 24 + 68..pe + 24 + 70].copy_from_slice(&1u16.to_le_bytes()); // IMAGE_SUBSYSTEM_NATIVE
    let mut config =
        WindowsConfig::embedded("C:\\app\\native-probe.exe", vec![], vec![], 0).unwrap();
    config.native_libraries = true;
    let mut process = super::super::super::WindowsProcess::spawn_image(config, image).unwrap();
    let p = process.state_mut();
    assert!(!p.cfg.host_filesystem);
    assert!(
        p.modules
            .list
            .iter()
            .all(|module| !matches!(module.kind, ModuleKind::Builtin(_)))
    );
    let module = p.modules.by_name("ntdll.dll").unwrap();
    assert!(
        p.modules.list[module]
            .host_path
            .as_ref()
            .unwrap()
            .starts_with(&p.native.as_ref().unwrap().directory)
    );
    let o = *crate::user::windows::layout::offsets(arch);
    let schema = p.space.ptr(p.peb + o.peb_api_set_map, o.ptr).unwrap();
    assert_eq!(p.space.u32(schema).unwrap(), 6);
    assert_eq!(
        p.space.u32(schema + 12).unwrap(),
        p.native.as_ref().unwrap().apisets.bytes[12..16]
            .try_into()
            .map(u32::from_le_bytes)
            .unwrap()
    );
    assert!(loader::load_dll(p, "api-ms-win-core-nonexistent-l65535-65535-0.dll").is_err());
    let terminate = loader::lookup(
        p,
        module,
        &SymRef::Name(b"NtTerminateProcess".to_vec(), None),
    )
    .unwrap()
    .unwrap();
    let thread = p.threads.values_mut().next().unwrap();
    thread.cpu.set_pc(terminate);
    if arch == WinArch::X64 {
        thread.cpu.set_gpr(1, u64::MAX);
        thread.cpu.set_gpr(2, 73);
    } else {
        thread.cpu.set_gpr(0, u64::MAX);
        thread.cpu.set_gpr(1, 73);
    }
    let cancellation = AtomicBool::new(false);
    assert_eq!(
        process.run_slice(4, &cancellation),
        RunStatus::Complete(super::super::super::ExitStatus::Exited(73))
    );
}

fn query_arguments(p: &mut Proc, t: &mut Thread, class: u32, out: u64, len: u32, ret: u64) {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            for (index, value) in [
                0x1234_0004,
                0x1234_0000,
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
            t.cpu.set_gpr(0, 0x36);
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, 0x36);
            t.cpu.set_gpr(10, u64::from(class));
            t.cpu.set_gpr(1, 0x1234_0004);
            t.cpu.set_gpr(2, out);
            t.cpu.set_gpr(8, u64::from(len));
            t.cpu.set_gpr(9, ret);
        }
        WinArch::Arm64 => {
            for (index, value) in [u64::from(class), out, u64::from(len), ret]
                .into_iter()
                .enumerate()
            {
                t.cpu.set_gpr(index, value);
            }
        }
    }
}

fn dispatch_query(p: &mut Proc, t: &mut Thread) -> Outcome {
    if p.arch == WinArch::X86 {
        super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x36))
    }
}

fn query_fixture(arch: WinArch) -> (super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtQuerySystemInformation", 0x36);
    let p = process.state_mut();
    let scratch =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space.wr(scratch, &[0xA5; 128]).unwrap();
    (process, t, scratch)
}

#[test]
fn native_range_query_preserves_width_alignment_optional_length_and_kernel_resume_all_abis() {
    for arch in WinArch::ALL {
        for offset in [0, 1, 4] {
            for returned_offset in [None, Some(32), Some(33)] {
                let (mut process, mut t, scratch) = query_fixture(arch);
                let p = process.state_mut();
                let sp = t.cpu.sp();
                let output = scratch + offset;
                let returned = returned_offset.map_or(0, |offset| scratch + offset);
                query_arguments(p, &mut t, 50, output, arch.ptr_size() as u32, returned);
                assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
                let misaligned = arch != WinArch::X86 && offset == 1;
                let expected_status = if misaligned {
                    STATUS_DATATYPE_MISALIGNMENT
                } else {
                    STATUS_SUCCESS
                };
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(expected_status),
                    "{arch}/{offset}/{returned_offset:?}"
                );
                assert_eq!(t.cpu.pc(), 0x1234_0004);
                assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
                assert!(t.frames.is_empty());
                let mut expected = [0xA5; 64];
                if !misaligned {
                    let range: u64 = if arch == WinArch::X86 {
                        0x7FFF_0000
                    } else {
                        0xFFFF_8000_0000_0000
                    };
                    expected[offset as usize..(offset + arch.ptr_size()) as usize]
                        .copy_from_slice(&range.to_le_bytes()[..arch.ptr_size() as usize]);
                    if let Some(offset) = returned_offset {
                        expected[offset as usize..offset as usize + 4]
                            .copy_from_slice(&(arch.ptr_size() as u32).to_le_bytes());
                    }
                }
                assert_eq!(p.space.bytes(scratch, 64).unwrap(), expected);
            }
        }
    }
}

#[test]
fn native_range_query_length_errors_and_unknown_classes_do_not_publish_output_all_abis() {
    for arch in WinArch::ALL {
        for length in [0, arch.ptr_size() as u32 - 1, arch.ptr_size() as u32 + 1] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            query_arguments(p, &mut t, 50, scratch, length, scratch + 32);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INFO_LENGTH_MISMATCH));
            assert_eq!(p.space.bytes(scratch, 16).unwrap(), [0xA5; 16]);
            assert_eq!(
                p.space.u32(scratch + 32).unwrap(),
                if arch == WinArch::X86 { 0xFFFF_FFFC } else { 8 }
            );
            assert_eq!(p.space.bytes(scratch + 36, 28).unwrap(), [0xA5; 28]);
        }
        for class in [1, u32::MAX] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            query_arguments(
                p,
                &mut t,
                class,
                scratch,
                arch.ptr_size() as u32,
                scratch + 32,
            );
            assert!(matches!(dispatch_query(p, &mut t), Outcome::Fail(reason)
                if reason.contains(&format!("NtQuerySystemInformation class {class}"))));
            assert_eq!(p.space.bytes(scratch, 64).unwrap(), [0xA5; 64]);
        }
    }
}

#[test]
fn native_basic_query_reports_guest_memory_bounds_cpu_and_preserves_wow64_padding_all_abis() {
    use crate::user::windows::layout::{self, kuser, offsets};
    for arch in WinArch::ALL {
        for output_offset in [0, 1, 4] {
            for returned_offset in [None, Some(96), Some(97)] {
                let (mut process, mut t, scratch) = query_fixture(arch);
                let p = process.state_mut();
                let output = scratch + output_offset;
                let required = if arch == WinArch::X86 { 44 } else { 64 };
                let returned = returned_offset.map_or(0, |offset| scratch + offset);
                query_arguments(p, &mut t, 0, output, required, returned);
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
fn native_basic_query_length_null_and_return_faults_are_class_specific_all_abis() {
    for arch in WinArch::ALL {
        let required = if arch == WinArch::X86 { 44 } else { 64 };
        for length in [0, required - 1, required + 1] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            query_arguments(p, &mut t, 0, scratch, length, scratch + 96);
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
                0,
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
fn native_basic_query_probes_fields_before_writing_and_does_not_probe_wow64_padding_all_abis() {
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
            query_arguments(p, &mut t, 0, output, required, scratch + 96);
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
fn native_basic_query_output_and_return_guards_are_one_shot_all_abis() {
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
            query_arguments(p, &mut t, 0, scratch, required, returned);
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
            query_arguments(p, &mut t, 0, scratch, required, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(returned).unwrap(), required);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_basic_query_readonly_destinations_and_output_aliases_preserve_write_order_all_abis() {
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
            query_arguments(p, &mut t, 0, scratch, required, returned);
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
        query_arguments(p, &mut t, 0, scratch, required, 0);
        assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        let original = p.space.bytes(scratch, 80).unwrap();
        for offset in [0, 1, 8, 24, 40, 60] {
            p.space.wr(scratch, &[0xA5; 80]).unwrap();
            t.cpu.set_sp(sp);
            query_arguments(p, &mut t, 0, scratch, required, scratch + offset);
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
fn native_system_query_combined_faults_probe_output_before_returned_all_abis() {
    for arch in WinArch::ALL {
        for class in [0, 50] {
            let required = if class == 0 {
                if arch == WinArch::X86 { 44 } else { 64 }
            } else {
                arch.ptr_size() as u32
            };
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            query_arguments(p, &mut t, class, scratch + 1, required, 1);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if arch == WinArch::X86 {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_DATATYPE_MISALIGNMENT
                })
            );

            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            let returned =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.w32(returned, 0xA5A5_A5A5).unwrap();
            p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            p.vm.protect(returned, PAGE_SIZE, prot::READONLY).unwrap();
            query_arguments(p, &mut t, class, scratch, required, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_GUARD_PAGE_VIOLATION));
            assert_eq!(p.vm.query(scratch).unwrap().protect, prot::READWRITE);
            assert_eq!(p.space.bytes(scratch, 80).unwrap(), [0xA5; 80]);
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_range_query_fault_order_and_wow64_partial_publication_match_observed_abi() {
    for arch in WinArch::ALL {
        for (out_bad, ret_bad) in [(true, false), (false, true)] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            let output = if out_bad { 0xDEAD_0000 } else { scratch };
            let returned = if ret_bad { 0xDEAD_0000 } else { scratch + 32 };
            query_arguments(p, &mut t, 50, output, arch.ptr_size() as u32, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
            let mut expected = [0xA5; 64];
            if arch == WinArch::X86 && ret_bad {
                expected[..4].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
            }
            assert_eq!(p.space.bytes(scratch, 64).unwrap(), expected);
        }
        let (mut process, mut t, scratch) = query_fixture(arch);
        let p = process.state_mut();
        query_arguments(p, &mut t, 50, 0, arch.ptr_size() as u32, scratch + 32);
        assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
        assert_eq!(
            t.cpu.gpr(0),
            u64::from(if arch == WinArch::X86 {
                STATUS_INVALID_PARAMETER
            } else {
                STATUS_ACCESS_VIOLATION
            })
        );
        assert_eq!(
            p.space.u32(scratch + 32).unwrap(),
            if arch == WinArch::X86 {
                0xFFFF_FFFC
            } else {
                0xA5A5_A5A5
            }
        );

        let (mut process, mut t, scratch) = query_fixture(arch);
        let p = process.state_mut();
        query_arguments(p, &mut t, 50, scratch, u32::MAX, scratch + 32);
        assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
        assert_eq!(
            t.cpu.gpr(0),
            u64::from(if arch == WinArch::X86 {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                STATUS_ACCESS_VIOLATION
            })
        );
        assert_eq!(p.space.bytes(scratch, 16).unwrap(), [0xA5; 16]);
    }
}

#[test]
fn native_range_query_checks_write_permissions_and_orders_overlapping_outputs_all_abis() {
    for arch in WinArch::ALL {
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
            query_arguments(p, &mut t, 50, scratch, arch.ptr_size() as u32, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
            let mut expected = [0xA5; 16];
            if arch == WinArch::X86 && !readonly_output {
                expected[..4].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
            }
            assert_eq!(p.space.bytes(scratch, 16).unwrap(), expected);
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
        }
        for offset in [0, 4] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            query_arguments(
                p,
                &mut t,
                50,
                scratch,
                arch.ptr_size() as u32,
                scratch + offset,
            );
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            let mut expected = [0xA5; 16];
            let range: u64 = if arch == WinArch::X86 {
                0x7FFF_0000
            } else {
                0xFFFF_8000_0000_0000
            };
            expected[..arch.ptr_size() as usize]
                .copy_from_slice(&range.to_le_bytes()[..arch.ptr_size() as usize]);
            expected[offset as usize..offset as usize + 4]
                .copy_from_slice(&(arch.ptr_size() as u32).to_le_bytes());
            assert_eq!(p.space.bytes(scratch, 16).unwrap(), expected);
        }
    }
}

#[test]
fn native_range_query_guard_destinations_are_disarmed_once_without_guest_exception_all_abis() {
    for arch in WinArch::ALL {
        for guard_output in [false, true] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            let returned =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.w32(returned, 0xA5A5_A5A5).unwrap();
            let guarded = if guard_output { scratch } else { returned };
            p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            let sp = t.cpu.sp();
            query_arguments(p, &mut t, 50, scratch, arch.ptr_size() as u32, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_GUARD_PAGE_VIOLATION));
            assert_eq!(p.vm.query(guarded).unwrap().protect, prot::READWRITE);
            assert!(!p.vm.take_guard(guarded));
            assert!(t.frames.is_empty());
            let mut expected = [0xA5; 16];
            if arch == WinArch::X86 && !guard_output {
                expected[..4].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
            }
            assert_eq!(p.space.bytes(scratch, 16).unwrap(), expected);
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
            t.cpu.set_sp(sp);
            query_arguments(p, &mut t, 50, scratch, arch.ptr_size() as u32, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(returned).unwrap(), arch.ptr_size() as u32);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn wow64_range_query_tracks_the_executable_large_address_aware_flag() {
    use crate::user::image::pe::IMAGE_FILE_LARGE_ADDRESS_AWARE;
    for large in [false, true] {
        let mut image =
            include_bytes!("../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
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
        let mut process = super::super::super::WindowsProcess::spawn_image(config, image).unwrap();
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
        query_arguments(p, &mut t, 0, output, 44, output + 96);
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
fn installed_native_range_query_executes_the_selected_leaf_and_actual_return() {
    use crate::user::windows::{
        loader::{self, SymRef},
        native::NativeRuntime,
    };
    let host_arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let mut arches = vec![host_arch];
    if host_arch != WinArch::X86 {
        arches.push(WinArch::X86);
    }
    for (arch, class) in arches
        .into_iter()
        .flat_map(|arch| [50u32, 0].map(|class| (arch, class)))
    {
        let runtime = NativeRuntime::select(arch).unwrap();
        let bytes = std::fs::read(runtime.dll("ntdll.dll").unwrap().unwrap()).unwrap();
        let (mut process, mut t, _) = terminal_fixture(arch);
        let p = process.state_mut();
        let mut config = (*p.cfg).clone();
        config.host_filesystem = false;
        config
            .supplied_dlls
            .insert("c:\\selected\\ntdll.dll".into(), bytes.into());
        p.cfg = Arc::new(config);
        let module = loader::load_dll(p, "C:\\selected\\ntdll.dll").unwrap();
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
        let length = if class == 0 {
            if arch == WinArch::X86 { 44 } else { 64 }
        } else {
            arch.ptr_size()
        };
        let resume = p.traps.callback_return();
        match arch {
            WinArch::X86 => {
                for (index, value) in [resume, u64::from(class), output, length, returned]
                    .into_iter()
                    .enumerate()
                {
                    p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
                }
            }
            WinArch::X64 => {
                p.space.w64(sp, resume).unwrap();
                for (register, value) in [
                    (1, u64::from(class)),
                    (2, output),
                    (8, length),
                    (9, returned),
                ] {
                    t.cpu.set_gpr(register, value);
                }
            }
            WinArch::Arm64 => {
                for (register, value) in [
                    (0, u64::from(class)),
                    (1, output),
                    (2, length),
                    (3, returned),
                    (30, resume),
                ] {
                    t.cpu.set_gpr(register, value);
                }
            }
        }
        p.space.wr(output, &[0xA5; 104]).unwrap();
        t.cpu.set_pc(entry);
        let boundary = t.cpu.run(64);
        let outcome = handle_stop(p, &mut t, boundary);
        assert_eq!(outcome, Outcome::Continue, "{arch}");
        assert_eq!(t.cpu.gpr(0), 0);
        if class == 50 {
            assert_eq!(
                p.space.ptr(output, arch.ptr_size()).unwrap(),
                if arch == WinArch::X86 {
                    0x7FFF_0000
                } else {
                    0xFFFF_8000_0000_0000
                }
            );
        } else {
            assert_eq!(p.space.u32(output + 8).unwrap(), 4096);
            assert_eq!(p.space.u32(output + 12).unwrap(), 16_384);
            assert_eq!(
                p.space
                    .u8(output + if arch == WinArch::X86 { 40 } else { 56 })
                    .unwrap(),
                1
            );
            if arch == WinArch::X86 {
                assert_eq!(p.space.bytes(output + 41, 3).unwrap(), [0xA5; 3]);
            }
        }
        assert_eq!(p.space.u32(returned).unwrap(), length as u32);
        // Kernel dispatch resumes the installed DLL's own RET/RET imm16.
        t.cpu.run(8);
        assert_eq!(t.cpu.pc(), resume);
        assert_eq!(
            t.cpu.sp(),
            sp + match arch {
                WinArch::X86 => 20,
                WinArch::X64 => 8,
                WinArch::Arm64 => 0,
            }
        );
        assert!(t.frames.is_empty());
    }
}
