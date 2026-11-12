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
fn native_context_x18_exclusion_keeps_thread_teb_on_pairing_and_clone() {
    fn native_teb(cpu: &WinCpu) -> u64 {
        let WinCpu::Arm64Ec(cpu) = cpu else {
            panic!("paired native CPU")
        };
        cpu.arm64.core().get_x(18)
    }
    let space = space();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_sp(0x20f00);
    cpu.set_pc(0x10000);
    cpu.set_teb(0x20000);
    cpu.enable_arm64ec().unwrap();
    assert_eq!(native_teb(&cpu), 0x20000);
    for teb in [0x20080, 0x20100] {
        let mut child = cpu.new_thread();
        child.set_teb(teb);
        assert_eq!(native_teb(&child), teb);
        let mut context = child.arm64_kernel_context().unwrap();
        context.set_flags(0x0040_0007);
        context.set_gpr(18, 0xbad);
        child.apply_kernel_context(&context).unwrap();
        assert_eq!(native_teb(&child), teb);
        assert_eq!(child.teb(), teb);
        let cloned = child.new_thread();
        assert_eq!(native_teb(&cloned), teb);
        assert_eq!(cloned.teb(), teb);
    }
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
fn native_kernel_context_commits_selected_groups_and_keeps_native_only_registers() {
    use crate::user::windows::context::{CONTEXT_ARM64, CONTROL};
    let space = space();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_sp(0x20f00);
    cpu.set_pc(0x10000);
    cpu.set_gpr(1, 0x1234);
    cpu.set_teb(0x77770000);
    cpu.enable_arm64ec().unwrap();
    let WinCpu::Arm64Ec(pair) = &mut cpu else {
        unreachable!()
    };
    pair.arm64.core_mut().set_x(13, 0x1313);
    pair.arm64.core_mut().set_x(28, 0x2828);
    pair.arm64.core_mut().set_simd(31, 0x3131);
    let mut context = cpu.arm64_kernel_context().unwrap();
    context.set_flags(CONTEXT_ARM64 | CONTROL);
    context.set_pc(0x10100);
    context.set_sp(0x20e00);
    context.set_gpr(18, 0xdead);
    context.set_gpr(0, 0xbad);
    context.set_gpr(29, 0x2929);
    context.set_gpr(30, 0x3030);
    cpu.apply_kernel_context(&context).unwrap();
    assert_eq!(cpu.arch(), WinArch::X64);
    assert_eq!(cpu.instruction_arch(), WinArch::Arm64);
    assert_eq!(cpu.pc(), 0x10100);
    assert_eq!(cpu.sp(), 0x20e00);
    assert_eq!(cpu.gpr(1), 0x1234);
    assert_eq!(cpu.teb(), 0x77770000);
    let native = cpu.arm64_kernel_context().unwrap();
    assert_eq!(native.gpr(13), 0x1313);
    assert_eq!(native.gpr(28), 0x2828);
    assert_eq!(native.v(31), 0x3131);
    assert_eq!(native.gpr(29), 0x2929);
    assert_eq!(native.gpr(30), 0x3030);
}

#[test]
fn rejected_native_context_keeps_both_views_mode_and_unpaired_cpu_unchanged() {
    use crate::user::windows::context::CONTEXT_ARM64;
    use crate::user::windows::nt::status::STATUS_INVALID_PARAMETER;
    let space = space();
    for paired in [false, true] {
        let mut cpu = WinCpu::new(WinArch::X64, &space);
        cpu.set_sp(0x20f00);
        cpu.set_pc(0x10000);
        if paired {
            cpu.enable_arm64ec().unwrap();
        }
        let before = RegContext::capture(&cpu);
        let native_before = cpu.arm64_kernel_context().unwrap();
        let mut invalid = native_before.clone();
        invalid.set_flags(CONTEXT_ARM64 | 8); // Native debug registers are not modeled.
        invalid.set_pc(0x10100);
        invalid.set_sp(0);
        assert_eq!(
            cpu.apply_kernel_context(&invalid),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(RegContext::capture(&cpu), before);
        assert_eq!(cpu.arm64_kernel_context().unwrap(), native_before);
        assert_eq!(cpu.is_arm64ec(), paired);
        assert_eq!(cpu.instruction_arch(), WinArch::X64);
        // Public logical restoration must still reject a native buffer.
        assert_eq!(native_before.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
    }
}

#[test]
fn native_capture_and_logical_projection_do_not_change_live_views() {
    use crate::user::windows::context::{CONTEXT_ARM64, CONTEXT_UNWOUND_TO_CALL, CONTROL};
    let space = space();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_sp(0x20f00);
    cpu.set_pc(0x10000);
    cpu.enable_arm64ec().unwrap();
    cpu.set_gpr(1, 0x5151);
    let before = RegContext::capture(&cpu);
    let mut native = cpu.arm64_kernel_context().unwrap();
    assert_eq!(native.gpr(0), 0x5151);
    native.set_flags(CONTEXT_ARM64 | CONTROL | CONTEXT_UNWOUND_TO_CALL);
    native.set_pc(0x10100);
    native.set_sp(0x20e00);
    let projected = cpu.project_kernel_context(&native).unwrap();
    assert_eq!(projected.arch(), WinArch::X64);
    assert_eq!(projected.pc(), 0x10100);
    assert_eq!(projected.sp(), 0x20e00);
    assert_eq!(projected.gpr(1), 0x5151);
    assert_ne!(projected.flags() & CONTEXT_UNWOUND_TO_CALL, 0);
    assert_eq!(RegContext::capture(&cpu), before);
    assert_eq!(cpu.instruction_arch(), WinArch::X64);
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
