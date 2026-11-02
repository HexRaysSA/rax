//! Guest PSCI startup, SPI discovery/routing, and source-free VM continuation.
use super::*;
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::vcpu::Aarch64CpuState;

fn state(vm: &Vmm, id: usize) -> Aarch64CpuState {
    let CpuState::Aarch64(state) = vm.vcpus[id].get_state().unwrap() else {
        panic!()
    };
    state
}

fn same(source: &Vmm, target: &Vmm) {
    assert_eq!(source.coordinator, target.coordinator);
    assert_eq!(
        source.timing_context.checkpoint_state(),
        target.timing_context.checkpoint_state()
    );
    let graph = |vm: &Vmm| {
        crate::codec::serialize(
            &vm.vm
                .as_any()
                .downcast_ref::<EmulatorVm>()
                .unwrap()
                .arm_cluster()
                .unwrap()
                .checkpoint()
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(graph(source), graph(target));
    for id in 0..source.vcpus.len() {
        assert_eq!(state(source, id), state(target, id));
        assert_eq!(
            source.vcpus[id].instruction_count(),
            target.vcpus[id].instruction_count()
        );
    }
}

fn write_program(vm: &Vmm, address: u64, words: &[u32]) {
    let bytes = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    vm.guest_mem
        .memory()
        .write_slice(&bytes, GuestAddress(address))
        .unwrap();
}

fn start_through_guest_psci(source: &mut Fixture, count: u8) -> Vec<u64> {
    // PE0 executes CPU_ON64 for each secondary; neither request_on nor the
    // coordinator's request-drain helper is called by this fixture.
    let mut boot = Vec::new();
    for id in 1..count {
        let entry = CODE + u64::from(id) * 0x1000;
        boot.extend_from_slice(&[
            0xd280_0060,                        // MOV X0,#3.
            0xf2b8_8000,                        // MOVK X0,#0xc400,LSL#16: PSCI CPU_ON64.
            0xd280_0001 | (u32::from(id) << 5), // MOV X1,#target affinity.
            0xd280_0002 | (((entry as u32) & 0xffff) << 5),
            0xf2a0_0002 | ((((entry >> 16) as u32) & 0xffff) << 5),
            0xd280_0003 | (u32::from(id) << 5), // X3: secondary context.
            0xd400_0002,                        // HVC#0.
        ]);
        write_program(&source.vm, entry, &[0xd503_207f]);
    }
    boot.push(0xd503_207f);
    write_program(&source.vm, CODE, &boot);
    for id in 0..usize::from(count) {
        let turn = source.vm.execute_turn().unwrap().unwrap();
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(turn.exit, VcpuExit::Hlt));
        assert_eq!(
            state(&source.vm, id).regs.x[0],
            if id == 0 { 0 } else { id as u64 }
        );
        assert_eq!(
            source.vm.vcpus[id].instruction_count(),
            if id == 0 { boot.len() as u64 } else { 1 }
        );
    }
    assert_eq!(source.vm.coordinator.online, vec![true; usize::from(count)]);
    (0..usize::from(count))
        .map(|id| source.vm.vcpus[id].instruction_count())
        .collect()
}

#[test]
fn guest_started_pes_discover_and_restore_top_spi_routes_with_both_access_widths() {
    for count in [1, 2, 4] {
        for split in [false, true] {
            eprintln!("GIC discovery case: PEs={count}, split_words={split}");
            let mut source = Fixture::with_clock(count, ClockMode::Retired);
            let startup_counts = start_through_guest_psci(&mut source, count);
            let mut program = vec![
                0xb940_0545, // LDR W5,[X10,#4]: GICD_TYPER.
                0x5300_10a6, // UBFX W6,W5,#0,#5: ITLinesNumber.
                0x531b_68c6, // LSL W6,W6,#5.
                0x1100_7cc6, // ADD W6,W6,#31: maximum discovered INTID.
                0x4b07_00c6, // SUB W6,W6,W7: distinct top-bank SPI per PE.
                0xb900_029f, // STR WZR,[X20]: wake Redistributor.
                0xb900_014b, // STR W11,[X10]: enable distributor Group1.
                0xb900_01ee, // STR W14,[X15]: enable this SPI.
            ];
            if split {
                program.extend_from_slice(&[0xb900_0207, 0xb900_061f]); // IROUTER low/high.
            } else {
                program.push(0xf900_0207); // STR X7,[X16]: full64-bit IROUTER.
            }
            program.extend_from_slice(&[
                0xb900_022e, // STR W14,[X17]: software-pend SPI.
                0xd518_4612, // MSR ICC_PMR_EL1,X18.
                0xd518_ccf3, // MSR ICC_IGRPEN1_EL1,X19.
                0xd503_207f, // WFI with IRQ masked.
                0x9100_0484, // ADD X4,X4,#1 after handler return.
                0xd503_207f,
            ]);
            let prefix = program.len() as u64 - 2;
            let handler = [
                0xd538_cc00, // MRS X0,ICC_IAR1_EL1.
                0xf940_0201, // LDR X1,[X16]: full64-bit route readback.
                // This implementation retains level software-pending state
                // until ICPENDR. Withdraw this source before deactivation.
                0xb900_02ce, // STR W14,[X22]: GICD_ICPENDR8.
                0xd518_cc20, // MSR ICC_EOIR1_EL1,X0.
                0xd538_cb62, // MRS X2,ICC_RPR_EL1.
                0xd69f_03e0,
            ];
            for id in 0..usize::from(count) {
                let base = CODE + id as u64 * 0x1000;
                write_program(&source.vm, base, &program);
                write_program(&source.vm, base + 0x280, &handler);
                let mut cpu = state(&source.vm, id);
                cpu.regs.pc = base;
                cpu.regs.x[4] = 0;
                cpu.regs.x[7] = id as u64;
                cpu.regs.x[10] = 0x0800_0000;
                cpu.regs.x[11] = 2;
                cpu.regs.x[14] = 1 << (31 - id);
                cpu.regs.x[15] = 0x0800_0120;
                cpu.regs.x[16] = 0x0800_6000 + 8 * (287 - id as u64);
                cpu.regs.x[17] = 0x0800_0220;
                cpu.regs.x[18] = 0xff;
                cpu.regs.x[19] = 1;
                cpu.regs.x[20] = 0x080a_0014 + id as u64 * 0x20000;
                cpu.regs.x[22] = 0x0800_02a0;
                cpu.sregs.vbar_el1 = base;
                source.vm.vcpus[id]
                    .set_state(&CpuState::Aarch64(cpu))
                    .unwrap();
                source.vm.vcpus[id].wake();
            }
            for (id, startup) in startup_counts.iter().enumerate() {
                let turn = source.vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                assert_eq!(state(&source.vm, id).regs.x[6], 287 - id as u64);
                assert_eq!((state(&source.vm, id).regs.x[5] >> 5) & 7, 0);
                assert_eq!(source.vm.vcpus[id].instruction_count(), startup + prefix);
            }
            let bundle = source
                .vm
                .take_snapshot_bundle(source.vm.coordinator.retired)
                .unwrap();
            let path = source.kernel.with_extension("gic-discovery.rxc");
            bundle.save(&path).unwrap();
            let loaded = SnapshotBundle::load(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            std::fs::remove_file(&source.kernel).unwrap();
            let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
            assert!(!config.kernel.exists() && !path.exists());
            let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
            same(&source.vm, &target);
            let cluster = target
                .vm
                .as_any()
                .downcast_ref::<EmulatorVm>()
                .unwrap()
                .arm_cluster()
                .unwrap();
            let handles = (0..usize::from(count))
                .map(|id| cluster.irq_line_for_test(id))
                .collect::<Vec<_>>();
            target.restore_snapshot_bundle(&loaded).unwrap();
            for (id, line) in handles.iter().enumerate() {
                assert!(Arc::ptr_eq(line, &cluster.irq_line_for_test(id)));
                assert!(line.load(Ordering::Acquire));
            }
            same(&source.vm, &target);
            for vm in [&mut source.vm, &mut target] {
                for id in 0..usize::from(count) {
                    let mut cpu = state(vm, id);
                    cpu.regs.pstate &= !(1 << 7);
                    vm.vcpus[id].set_state(&CpuState::Aarch64(cpu)).unwrap();
                    vm.vcpus[id].wake();
                }
                for (id, startup) in startup_counts.iter().enumerate() {
                    assert!(vm.execute_turn().unwrap().is_none());
                    assert_eq!(state(vm, id).regs.pc, CODE + id as u64 * 0x1000 + 0x280);
                    assert_eq!(vm.vcpus[id].instruction_count(), startup + prefix);
                }
            }
            same(&source.vm, &target);
            for vm in [&mut source.vm, &mut target] {
                for (id, startup) in startup_counts.iter().enumerate() {
                    let turn = vm.execute_turn().unwrap().unwrap();
                    assert_eq!(turn.cpu_index, id);
                    assert!(matches!(turn.exit, VcpuExit::Hlt));
                    let cpu = state(vm, id);
                    assert_eq!(&cpu.regs.x[..3], &[287 - id as u64, id as u64, 0xff]);
                    assert_eq!(cpu.regs.x[4], 1);
                    assert_eq!(
                        vm.vcpus[id].instruction_count(),
                        startup + prefix + handler.len() as u64 + 2
                    );
                }
                assert_eq!(
                    vm.coordinator.retired,
                    startup_counts.iter().sum::<u64>()
                        + u64::from(count) * (program.len() + handler.len()) as u64
                );
            }
            same(&source.vm, &target);
            for id in 0..usize::from(count) {
                assert!(
                    !source
                        .cluster()
                        .irq_line_for_test(id)
                        .load(Ordering::Acquire)
                );
                assert!(!cluster.irq_line_for_test(id).load(Ordering::Acquire));
            }
            eprintln!("GIC discovery continuation passed: PEs={count}, split_words={split}");
        }
    }
}
