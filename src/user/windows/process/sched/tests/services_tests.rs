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
