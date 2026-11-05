use super::*;
use crate::user::mm::{Mapping, PAGE_SIZE, Perms, SpaceConfig};
use crate::user::windows::memory::Mem;

fn space() -> AddressSpace {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 64 * PAGE_SIZE,
        reserved_phys: crate::user::cpu::x86_64::RESERVED_PHYS.to_vec(),
    })
    .unwrap();
    space
        .map(
            0x10000,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::EXEC),
        )
        .unwrap();
    space
        .map(
            0x20000,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    space
}

#[test]
fn sdk_overlay_keeps_all_integer_x87_and_vector_carriers_for_every_top() {
    let space = space();
    for top in 0..8u16 {
        let mut cpu = WinCpu::new(WinArch::X64, &space);
        for n in 0..16 {
            cpu.set_gpr(n, 0x1122_3344_5566_0000 | n as u64);
        }
        cpu.set_pc(0x10000);
        cpu.set_teb(0x1234_5678);
        let core = cpu.x86_mut().unwrap().vcpu_mut();
        let mut fx = core.xsave_image(3).bytes;
        fx.truncate(512);
        fx[2..4].copy_from_slice(&(top << 11).to_le_bytes());
        fx[4] = 0xff;
        for n in 0..8 {
            let at = 32 + n * 16;
            fx[at..at + 8].copy_from_slice(&(0x1234_5678_0000_0000 | n as u64).to_le_bytes());
            fx[at + 8..at + 10].copy_from_slice(&(0x1000 | n as u16).to_le_bytes());
        }
        for n in 0..16 {
            let at = 160 + n * 16;
            fx[at..at + 16].copy_from_slice(
                &(0x1122_3344_5566_7788_9900_aabb_ccdd_0000 | n as u128).to_le_bytes(),
            );
        }
        core.fxrstor_image(&fx).unwrap();
        let original_fx = core.xsave_image(3).bytes;
        let original = registers(cpu.x86().unwrap());
        cpu.enable_arm64ec().unwrap();
        let WinCpu::Arm64Ec(ec) = &mut cpu else {
            unreachable!()
        };
        ec.from_context();
        assert_eq!(ec.arm64.core().get_x(0), original[1]);
        assert_eq!(ec.arm64.core().get_x(8), original[0]);
        assert_eq!(ec.arm64.core().get_x(30), 0x1234_5678_0000_0000);
        assert_eq!(ec.arm64.core().get_x(16), 0x1003_1002_1001_1000);
        assert_eq!(ec.arm64.core().get_x(17), 0x1007_1006_1005_1004);
        assert_eq!(ec.arm64.core().get_x(18), 0x1234_5678);
        ec.to_context().unwrap();
        assert_eq!(registers(ec.x64()), original, "TOP={top}");
        assert_eq!(
            ec.x64().vcpu().xsave_image(3).bytes,
            original_fx,
            "TOP={top}"
        );
    }
}

#[test]
fn entry_pops_x64_link_aligns_stack_and_runs_the_real_arm64_thunk() {
    let space = space();
    // MOVZ X8,#0x1234 in a compiler-entry-thunk position; the target body
    // remains distinct so decoder selection cannot accidentally run it first.
    space
        .write_raw(0x10100, &0xd282_4688u32.to_le_bytes())
        .unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_sp(0x20fd3);
    cpu.set_pc(0x10200);
    cpu.set_gpr(1, 0x55aa);
    space.w64(0x20fd3, 0x10040).unwrap();
    let stop = cpu.run_routed(1, |pc, active, _| {
        assert_eq!(pc, 0x10200);
        assert_eq!(active, WinArch::X64);
        Ok(InstructionRoute::Enter {
            target: pc,
            thunk: 0x10100,
        })
    });
    assert!(matches!(stop, CpuStop::Yield));
    assert_eq!(cpu.arch(), WinArch::X64);
    assert_eq!(cpu.instruction_arch(), WinArch::Arm64);
    assert_eq!(cpu.pc(), 0x10104);
    assert_eq!(cpu.sp(), 0x20fd0);
    assert_eq!(cpu.call_gpr(0), 0x55aa);
    assert_eq!(cpu.call_gpr(4), 0x20fdb);
    assert_eq!(cpu.call_gpr(9), 0x10200);
    assert_eq!(cpu.call_gpr(30), 0x10040);
    assert_eq!(cpu.gpr(0), 0x1234);
    crate::user::windows::hle::dispatch::write_value(
        &mut cpu,
        crate::user::windows::hle::Value::Int(0xc000_0022),
    );
    assert_eq!(cpu.call_gpr(0), 0xc000_0022);
    assert_eq!(cpu.gpr(1), 0xc000_0022); // X0 occupies the RCX context field.
    assert_eq!(cpu.gpr(0), 0x1234); // X8/RAX is the thunk's separate return carrier.
    cpu.ec_return().unwrap();
    assert_eq!(cpu.instruction_arch(), WinArch::X64);
    assert_eq!(cpu.pc(), 0x10040);
    assert_eq!(cpu.sp(), 0x20fdb);
}

#[test]
fn zero_budget_and_unreadable_return_leave_the_x64_boundary_intact() {
    let space = space();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_pc(0x10200);
    cpu.set_sp(0x30000);
    assert!(matches!(
        cpu.run_routed(0, |_, _, _| panic!("zero budget routed")),
        CpuStop::Yield
    ));
    let result = cpu.run_routed(1, |pc, _, _| {
        Ok(InstructionRoute::Enter {
            target: pc,
            thunk: 0x10100,
        })
    });
    assert!(matches!(result, CpuStop::Internal(_)));
    assert_eq!(cpu.pc(), 0x10200);
    assert_eq!(cpu.sp(), 0x30000);
    assert!(!cpu.is_arm64ec());
}

#[test]
fn native_service_arguments_keep_eight_arm64_registers_and_the_ninth_stack_slot() {
    use crate::user::windows::hle::{Arg, Conv};
    let space = space();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_sp(0x20f00);
    cpu.enable_arm64ec().unwrap();
    let WinCpu::Arm64Ec(ec) = &mut cpu else {
        unreachable!()
    };
    ec.from_context();
    for n in 0..8 {
        ec.arm64.core_mut().set_x(n, 0x100 + u64::from(n));
    }
    ec.active = true;
    ec.to_context().unwrap();
    space.w64(0x20f00, 0x108).unwrap();
    let args = [Arg::I64; 9];
    for n in 0..9 {
        assert_eq!(
            crate::user::windows::hle::args::read_arg(
                &cpu,
                &space,
                cpu.sp(),
                &args,
                Conv::Stdcall,
                n
            )
            .unwrap(),
            0x100 + n as u64
        );
    }
}
