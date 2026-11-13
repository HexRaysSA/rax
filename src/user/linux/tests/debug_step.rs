//! Architectural TF, Linux debug causes, and the syscall IRET frontier.
//! Linux v6.19: traps.c exc_debug_user, syscall_64.c do_syscall_64, and
//! ptrace.c's native/i386 user debug-register views.

use super::harness::{CODE, Harness};
use crate::isa::x86_64::flags::bits::TF;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::{CpuEvent, GuestCpu};
use crate::user::linux::ptrace::debug_x86::Registers;
use crate::user::linux::signal::{SIGTRAP, code};

#[test]
fn architectural_tf_reports_trace_status_without_contaminating_a_later_icebp() {
    for abi in [LinuxAbi::X86_64, LinuxAbi::I386] {
        let mut h = Harness::embedded(abi);
        let pc = CODE + 0x1000;
        h.proc.state.space.write_raw(pc, &[0x90, 0xf1]).unwrap();
        let cpu = &mut h.proc.threads[0].cpu;
        cpu.set_pc(pc);
        let GuestCpu::X86_64(x) = cpu else {
            unreachable!()
        };
        x.vcpu_mut().set_user_rflags(0x202 | TF);
        let CpuEvent::Signal(info, _) = cpu.step() else {
            panic!("TF trace")
        };
        assert_eq!(
            (info.signo, info.code, info.addr()),
            (SIGTRAP, code::TRAP_TRACE, pc + 1)
        );
        assert_eq!(
            match cpu {
                GuestCpu::X86_64(x) => x.vcpu().last_user_debug_status(),
                _ => unreachable!(),
            },
            1 << 14
        );
        let GuestCpu::X86_64(x) = cpu else {
            unreachable!()
        };
        assert_eq!(Registers::default().read(x, 6), 0xffff_4ff0);
        x.vcpu_mut().set_user_rflags(0x202);
        let CpuEvent::Signal(info, _) = cpu.step() else {
            panic!("ICEBP")
        };
        assert_eq!(
            (info.signo, info.code, info.addr()),
            (SIGTRAP, code::TRAP_BRKPT, pc + 2)
        );
        assert_eq!(
            match cpu {
                GuestCpu::X86_64(x) => x.vcpu().last_user_debug_status(),
                _ => unreachable!(),
            },
            0
        );
    }
}

#[test]
fn a_virtual_ptrace_status_write_leaves_live_hardware_status_unchanged() {
    let mut h = Harness::embedded(LinuxAbi::X86_64);
    let GuestCpu::X86_64(x) = &mut h.proc.threads[0].cpu else {
        unreachable!()
    };
    let live = x.vcpu().user_debug_registers()[4];
    let mut debug = Registers::default();
    for value in [0, 0x4001, u64::MAX] {
        debug.write(x, 6, value).unwrap();
        assert_eq!(debug.read(x, 6), value);
        assert_eq!(x.vcpu().user_debug_registers()[4], live);
    }
}

#[test]
fn guest_tf_survives_a_linux_syscall_and_traces_the_first_user_instruction() {
    let mut h = Harness::embedded(LinuxAbi::X86_64);
    let pc = CODE + 0x1000;
    h.proc
        .state
        .space
        .write_raw(pc, &[0x0f, 0x05, 0x90, 0x90])
        .unwrap();
    let nr = h.abi().number(Sysno::Getpid).unwrap();
    let cpu = &mut h.proc.threads[0].cpu;
    cpu.set_pc(pc);
    cpu.set_syscall_number(nr);
    let GuestCpu::X86_64(x) = cpu else {
        unreachable!()
    };
    x.vcpu_mut().set_user_rflags(0x202 | TF);
    let CpuEvent::Syscall { nr, args } = cpu.step() else {
        panic!("SYSCALL")
    };
    h.proc.enter_syscall(0, nr, args);
    assert!(h.proc.threads[0].pending.dequeue(0).is_none());
    let cpu = &mut h.proc.threads[0].cpu;
    assert_eq!(cpu.pc(), pc + 2);
    let CpuEvent::Signal(info, _) = cpu.step() else {
        panic!("first user instruction")
    };
    assert_eq!(
        (info.signo, info.code, info.addr()),
        (SIGTRAP, code::TRAP_TRACE, pc + 3)
    );
}
