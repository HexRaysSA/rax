use super::*;

fn native_cpu(vm: &mut VirtualMemory, code: u64) -> (WinCpu, Area) {
    vm.allocate(
        Some(code),
        PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    let area = Area::allocate(vm).unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, vm.space());
    cpu.set_pc(code);
    cpu.set_sp(area.base + 7 * PAGE_SIZE - 64);
    (cpu, area)
}

fn arm64(_: u64, active: WinArch, _: bool) -> Result<InstructionRoute, String> {
    Ok(if active == WinArch::X64 {
        InstructionRoute::ResumeArm64
    } else {
        InstructionRoute::Stay
    })
}

#[test]
fn native_owner_retains_saved_rsp_and_simulation_flag_without_clobbering_live_stack() {
    for quantum in [1, 2] {
        for flag in [0, 1] {
            let mut vm = memory();
            let code = 0x4000_0000;
            let (mut cpu, area) = native_cpu(&mut vm, code);
            vm.space().w32(code, 0x9100_005f).unwrap(); // MOV SP,X2
            vm.space().w32(code + 4, 0xf900_0020).unwrap(); // STR X0,[X1]
            vm.protect(code, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
            cpu.set_sp(0x25_e100);
            cpu.set_gpr(1, 0x25_e0d8);
            cpu.set_gpr(2, area.context + (x64::RAX + 4 * 8) as u64);
            cpu.set_gpr(8, 0x7ffc_f5e8_a000);
            cpu.bind_chpe_area_with_owner(area.clone(), ContextOwner::NativeRtl)
                .unwrap();
            vm.space().w8(area.base, flag).unwrap();
            for _ in 0..2 / quantum {
                let stop = cpu.run_routed(quantum, arm64);
                assert!(matches!(stop, CpuStop::Yield), "{stop:?}");
            }
            assert_eq!(cpu.sp(), 0x7ffc_f5e8_a000, "quantum={quantum}");
            assert_eq!(cpu.pc(), code + 8);
            assert_eq!(
                vm.space()
                    .u64(area.context + (x64::RAX + 4 * 8) as u64)
                    .unwrap(),
                0x25_e0d8
            );
            assert_eq!(vm.space().u8(area.base).unwrap(), flag);
        }
    }
}

#[test]
fn native_owner_preserves_partial_save_bytes_at_instruction_and_run_boundaries() {
    for quantum in [1, 2] {
        let mut vm = memory();
        let code = 0x4000_0000;
        let (mut cpu, area) = native_cpu(&mut vm, code);
        vm.space().w32(code, 0xd28a_cf08).unwrap(); // MOVZ X8,#0x5678
        vm.space().w32(code + 4, 0xd503_201f).unwrap(); // NOP
        vm.protect(code, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
        cpu.set_gpr(0, 0x1234);
        cpu.bind_chpe_area_with_owner(area.clone(), ContextOwner::NativeRtl)
            .unwrap();
        // A save under construction is not yet a valid CONTEXT command.
        vm.space()
            .w32(area.context + x64::FLAGS as u64, 0xdead_0000)
            .unwrap();
        let saved = vm.space().bytes(area.context, x64::SIZE).unwrap();
        for publish in [false, true] {
            cpu.sync_chpe_area(publish).unwrap();
            assert_eq!(cpu.gpr(0), 0x1234);
            assert_eq!(vm.space().bytes(area.context, x64::SIZE).unwrap(), saved);
        }
        for _ in 0..2 / quantum {
            let stop = cpu.run_routed(quantum, arm64);
            assert!(matches!(stop, CpuStop::Yield), "{stop:?}");
        }
        assert_eq!(cpu.gpr(0), 0x5678);
        assert_eq!(vm.space().bytes(area.context, x64::SIZE).unwrap(), saved);
    }
}

#[test]
fn native_owner_explicit_kernel_context_restore_keeps_validation_and_resume_semantics() {
    let mut vm = memory();
    let code = 0x4000_0000;
    let (mut cpu, area) = native_cpu(&mut vm, code);
    for offset in [0, 4, 8, 12] {
        vm.space().w32(code + offset, 0xd503_201f).unwrap();
    }
    vm.protect(code, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
    cpu.bind_chpe_area_with_owner(area.clone(), ContextOwner::NativeRtl)
        .unwrap();
    assert!(matches!(cpu.run_routed(1, arm64), CpuStop::Yield));
    let saved = vm.space().bytes(area.context, x64::SIZE).unwrap();
    let before = cpu.arm64_kernel_context().unwrap();
    let mut invalid = before.clone();
    invalid.set_flags(0xdead_0000);
    assert_eq!(
        cpu.apply_kernel_context(&invalid),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(cpu.arm64_kernel_context().unwrap(), before);
    let mut next = before;
    next.set_pc(code + 8);
    next.set_sp(cpu.sp() - 128);
    next.set_gpr(8, 0x8765_4321);
    cpu.apply_kernel_context(&next).unwrap();
    assert_eq!(cpu.pc(), next.pc());
    assert_eq!(cpu.sp(), next.sp());
    assert_eq!(cpu.gpr(0), 0x8765_4321);
    let mut resumed = false;
    let stop = cpu.run_routed(1, |pc, active, context| {
        assert_eq!(pc, code + 8);
        assert_eq!(active, WinArch::Arm64);
        assert!(context);
        resumed = true;
        Ok(InstructionRoute::Stay)
    });
    assert!(resumed && matches!(stop, CpuStop::Yield));
    assert_eq!(cpu.pc(), code + 12);
    assert_eq!(vm.space().bytes(area.context, x64::SIZE).unwrap(), saved);
}

#[test]
fn native_owner_rejects_replaced_area_without_mutating_new_owner_or_cpu() {
    let mut vm = memory();
    let area = Area::allocate(&mut vm).unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, vm.space());
    cpu.set_gpr(0, 0x5a);
    cpu.bind_chpe_area_with_owner(area.clone(), ContextOwner::NativeRtl)
        .unwrap();
    let before = RegContext::capture(&cpu);
    vm.release(area.base).unwrap();
    vm.reserve(
        Some(area.base),
        65536,
        prot::READWRITE,
        AllocKind::Private,
        false,
        Some(Arc::from("[CHPE thread context]")),
    )
    .unwrap();
    vm.commit(area.base, PAGE_SIZE, prot::READWRITE).unwrap();
    vm.space()
        .wr(area.base, &[0x7b; PAGE_SIZE as usize])
        .unwrap();
    for publish in [false, true] {
        assert!(cpu.sync_chpe_area(publish).is_err());
        assert_eq!(RegContext::capture(&cpu), before);
        assert_eq!(
            vm.space().bytes(area.base, PAGE_SIZE as usize).unwrap(),
            vec![0x7b; PAGE_SIZE as usize]
        );
    }
}

#[test]
fn native_owner_clone_and_rebind_preserve_owner_without_republishing_parent_storage() {
    let mut vm = memory();
    let first = Area::allocate(&mut vm).unwrap();
    let second = Area::allocate(&mut vm).unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, vm.space());
    cpu.set_gpr(0, 0x1234);
    cpu.bind_chpe_area_with_owner(first.clone(), ContextOwner::NativeRtl)
        .unwrap();
    vm.space()
        .w64(first.context + x64::RAX as u64, 0x9876)
        .unwrap();
    let saved = vm.space().bytes(first.context, x64::SIZE).unwrap();
    let mut child = cpu.new_thread();
    let WinCpu::Arm64Ec(ec) = &child else {
        panic!("missing EC carrier")
    };
    assert_eq!(ec.area.as_ref().unwrap().owner, ContextOwner::NativeRtl);
    child.set_gpr(0, 0x5678);
    child.sync_chpe_area(true).unwrap();
    assert_eq!(vm.space().bytes(first.context, x64::SIZE).unwrap(), saved);
    child
        .bind_chpe_area_with_owner(second.clone(), ContextOwner::NativeRtl)
        .unwrap();
    assert_eq!(
        vm.space().u64(second.context + x64::RAX as u64).unwrap(),
        0x5678
    );
    assert_eq!(vm.space().bytes(first.context, x64::SIZE).unwrap(), saved);
    let WinCpu::Arm64Ec(ec) = &child else {
        unreachable!()
    };
    assert_eq!(ec.area.as_ref().unwrap().owner, ContextOwner::NativeRtl);
    assert_eq!(ec.area.as_ref().unwrap().area.context, second.context);
}
