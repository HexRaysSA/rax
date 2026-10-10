use super::*;
use crate::user::windows::loader::services::tests::table;

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
