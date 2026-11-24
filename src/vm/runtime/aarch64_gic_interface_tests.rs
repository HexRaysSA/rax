//! IRQ/FIQ guest handlers resumed from source-free prepared 1/2/4-PE files.
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

#[test]
fn irq_and_fiq_handlers_preserve_bank_semantics_across_source_free_vm_files() {
    for count in [1, 2, 4] {
        for group in [0, 1] {
            let mut source = Fixture::with_clock(count, ClockMode::Retired);
            for id in 1..count {
                assert_eq!(
                    source
                        .cluster()
                        .request_on(u64::from(id), CODE + u64::from(id) * 0x1000, 0, 0x3c5)
                        .unwrap(),
                    0
                );
            }
            source.vm.route_interprocessor_requests().unwrap();
            let program = [
                0xb900_029f, // STR WZR,[X20]: wake this Redistributor.
                0xb900_014b, // STR W11,[X10]: enable both distributor groups.
                0xb900_01ac, // STR W12,[X13]: configure SGI7's group.
                0xb900_01ee, // STR W14,[X15]: enable SGI7.
                0xb900_020e, // STR W14,[X16]: software-pend SGI7.
                0xd518_4611, // MSR ICC_PMR_EL1,X17.
                0xd518_ccd2, // MSR ICC_IGRPEN0_EL1,X18.
                0xd518_ccf2, // MSR ICC_IGRPEN1_EL1,X18.
                0xd503_207f, // WFI with both PSTATE masks set.
                0x9100_0484, // ADD X4,X4,#1 after exception return.
                0xd503_207f, // WFI: end of continuation.
            ];
            let handler = [
                if group == 0 { 0xd538_c800 } else { 0xd538_cc00 }, // correct IAR -> X0
                if group == 0 { 0xd518_cc20 } else { 0xd518_c820 }, // wrong EOIR
                0xd538_cb61, // RPR -> X1: priority must still be active.
                0xb940_02a5, // LDR W5,[X21]: SGI remains active after wrong EOI.
                if group == 0 { 0xd538_cc02 } else { 0xd538_c802 }, // wrong IAR -> X2
                if group == 0 { 0xd518_c820 } else { 0xd518_cc20 }, // correct EOIR
                0xd538_cb63, // RPR -> X3: idle priority.
                0xb940_02a6, // LDR W6,[X21]: correct EOI deactivated the SGI.
                0xd69f_03e0, // ERET to the instruction after WFI.
            ];
            let bytes = |words: &[u32]| {
                words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>()
            };
            for id in 0..usize::from(count) {
                let base = CODE + id as u64 * 0x1000;
                source
                    .vm
                    .guest_mem
                    .memory()
                    .write_slice(&bytes(&program), GuestAddress(base))
                    .unwrap();
                let vector = if group == 0 { 0x300 } else { 0x280 };
                source
                    .vm
                    .guest_mem
                    .memory()
                    .write_slice(&bytes(&handler), GuestAddress(base + vector))
                    .unwrap();
                let mut cpu = state(&source.vm, id);
                let bank = 0x080a_0000 + id as u64 * 0x20000;
                cpu.regs.x[10] = 0x0800_0000;
                cpu.regs.x[11] = 3;
                cpu.regs.x[12] = if group == 0 { 0 } else { 1 << 7 };
                cpu.regs.x[13] = bank + 0x10080;
                cpu.regs.x[14] = 1 << 7;
                cpu.regs.x[15] = bank + 0x10100;
                cpu.regs.x[16] = bank + 0x10200;
                cpu.regs.x[17] = 0xff;
                cpu.regs.x[18] = 1;
                cpu.regs.x[20] = bank + 0x14;
                cpu.regs.x[21] = bank + 0x10300;
                cpu.sregs.vbar_el1 = base;
                source.vm.vcpus[id]
                    .set_state(&CpuState::Aarch64(cpu))
                    .unwrap();
            }
            for id in 0..usize::from(count) {
                let turn = source.vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                assert_eq!(source.vm.vcpus[id].instruction_count(), 9);
            }
            let bundle = source
                .vm
                .take_snapshot_bundle(source.vm.coordinator.retired)
                .unwrap();
            let path = source.kernel.with_extension("gic-interface.rxc");
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
                    cpu.regs.pstate &= !(if group == 0 { 1 << 6 } else { 1 << 7 });
                    vm.vcpus[id].set_state(&CpuState::Aarch64(cpu)).unwrap();
                    vm.vcpus[id].wake();
                }
                for id in 0..usize::from(count) {
                    // Exception entry changes state without retiring a guest
                    // instruction; every PE receives its own coordinator turn.
                    assert!(vm.execute_turn().unwrap().is_none());
                    let cpu = state(vm, id);
                    assert_eq!(
                        cpu.regs.pc,
                        CODE + id as u64 * 0x1000 + if group == 0 { 0x300 } else { 0x280 }
                    );
                    assert_eq!(cpu.sregs.elr_el1, CODE + id as u64 * 0x1000 + 36);
                    assert_eq!(vm.vcpus[id].instruction_count(), 9);
                }
                assert_eq!(vm.coordinator.retired, 9 * u64::from(count));
            }
            same(&source.vm, &target);
            for vm in [&mut source.vm, &mut target] {
                for id in 0..usize::from(count) {
                    let turn = vm.execute_turn().unwrap().unwrap();
                    assert_eq!(turn.cpu_index, id);
                    assert!(matches!(turn.exit, VcpuExit::Hlt));
                    let cpu = state(vm, id);
                    assert_eq!(&cpu.regs.x[..5], &[7, 0xa0, 1023, 0xff, 1]);
                    assert_eq!(&cpu.regs.x[5..7], &[1 << 7, 0]);
                    assert_eq!(cpu.regs.pc, CODE + id as u64 * 0x1000 + 44);
                    assert_eq!(vm.vcpus[id].instruction_count(), 20);
                }
                assert_eq!(vm.coordinator.retired, 20 * u64::from(count));
            }
            same(&source.vm, &target);
        }
    }
}

#[test]
fn detached_gic_binary_points_and_active_priority_registers_continue_on_each_guest_pe() {
    let program: [u32; 31] = [
        0xd518_cc8d, // MSR ICC_CTLR_EL1,X13: select common or separate BPRs.
        0xd518_4609, // MSR ICC_PMR_EL1,X9.
        0xd518_ccea, // MSR ICC_IGRPEN1_EL1,X10.
        0xd518_c86b, // MSR ICC_BPR0_EL1,X11.
        0xd518_cc6c, // MSR ICC_BPR1_EL1,X12: ignored in common mode.
        0xd538_cc60, // MRS X0,ICC_BPR1_EL1.
        0xd538_cc81, // MRS X1,ICC_CTLR_EL1.
        0x9240_0021, // AND X1,X1,#1: read CBPR.
        0xb900_0293, // STR W19,[X20]: enable distributor Group 1.
        0xb900_02bf, // STR WZR,[X21]: wake the local redistributor.
        0xb901_02ce, // STR W14,[X22,#0x100]: enable SGI7 and SGI8.
        0x3910_1ecf, // STRB W15,[X22,#0x407]: SGI7 priority.
        0x3910_22d0, // STRB W16,[X22,#0x408]: SGI8 priority.
        0xb902_02d1, // STR W17,[X22,#0x200]: pend SGI7.
        0xd538_cc02, // MRS X2,ICC_IAR1_EL1: acknowledge SGI7.
        0xb902_02d2, // STR W18,[X22,#0x200]: pend SGI8.
        0xd538_cb63, // MRS X3,ICC_RPR_EL1: running group priority.
        0xd538_c928, // MRS X8,ICC_AP1R1_EL1: rank from SGI7 acknowledgement.
        0xd518_c8f7, // MSR ICC_AP0R3_EL1,X23: a rank with no acknowledged INTID.
        0xd503_207f, // WFI: checkpoint boundary with SGI7 still active.
        0xd538_c8f8, // MRS X24,ICC_AP0R3_EL1.
        0xd538_c939, // MRS X25,ICC_AP1R1_EL1.
        0xd538_cc44, // MRS X4,ICC_HPPIR1_EL1: SGI8 remains visible.
        0xd538_cc05, // MRS X5,ICC_IAR1_EL1: blocked by the active group priority.
        0xd518_cc22, // MSR ICC_EOIR1_EL1,X2: drop SGI7's priority.
        0xd538_cc06, // MRS X6,ICC_IAR1_EL1: SGI8 can now run.
        0xd518_cc26, // MSR ICC_EOIR1_EL1,X6.
        0xd538_cb67, // MRS X7,ICC_RPR_EL1: the software-written Group 0 rank.
        0xd518_c8ff, // MSR ICC_AP0R3_EL1,XZR.
        0xd538_cb7a, // MRS X26,ICC_RPR_EL1: idle.
        0xd503_207f, // WFI: end of continuation.
    ];
    let bytes = program
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    for count in [2, 4] {
        let mut source = Fixture::with_clock(count, ClockMode::Retired);
        for id in 1..count {
            assert_eq!(
                source
                    .cluster()
                    .request_on(u64::from(id), CODE, 0, 0x3c5)
                    .unwrap(),
                0
            );
        }
        source.vm.route_interprocessor_requests().unwrap();
        source
            .vm
            .guest_mem
            .memory()
            .write_slice(&bytes, GuestAddress(CODE))
            .unwrap();
        let cluster = source.cluster();
        for id in 0..usize::from(count) {
            let mut cpu = state(&source.vm, id);
            let redist = 0x080a_0000 + id as u64 * 0x20000;
            let common = id % 2 != 0;
            cpu.regs.x[9..23].copy_from_slice(&[
                0xff,
                1,
                4,
                if common { 2 } else { 5 },
                u64::from(common),
                (1 << 7) | (1 << 8),
                0x70,
                0x68,
                1 << 7,
                1 << 8,
                2,
                0x0800_0000,
                redist + 0x14,
                redist + 0x10000,
            ]);
            cpu.regs.x[23] = 1 << id;
            source.vm.vcpus[id]
                .set_state(&CpuState::Aarch64(cpu))
                .unwrap();
        }
        for id in 0..usize::from(count) {
            let turn = source.vm.execute_turn().unwrap().unwrap();
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            assert_eq!(
                &state(&source.vm, id).regs.x[..4],
                &[5, (id % 2) as u64, 7, 0x60]
            );
            assert_eq!(state(&source.vm, id).regs.x[8], 1 << 16);
            assert_eq!(source.vm.vcpus[id].instruction_count(), 20);
            assert!(!cluster.irq_line_for_test(id).load(Ordering::Acquire));
        }

        let path = source.kernel.with_extension("gic-binary-point.rxc");
        source
            .vm
            .take_snapshot_bundle(20 * u64::from(count))
            .unwrap()
            .save(&path)
            .unwrap();
        drop(cluster);
        drop(source);
        let bundle = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        assert!(!config.kernel.exists());
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        let cluster = target
            .vm
            .as_any()
            .downcast_ref::<EmulatorVm>()
            .unwrap()
            .arm_cluster()
            .unwrap();
        for id in 0..usize::from(count) {
            assert!(!cluster.irq_line_for_test(id).load(Ordering::Acquire));
            target.vcpus[id].wake();
        }
        for id in 0..usize::from(count) {
            let turn = target.execute_turn().unwrap().unwrap();
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            let regs = state(&target, id).regs;
            let residual_priority = 0xc0 + 2 * id as u64;
            assert_eq!(
                &regs.x[..9],
                &[
                    5,
                    (id % 2) as u64,
                    7,
                    0x60,
                    8,
                    1023,
                    8,
                    residual_priority,
                    1 << 16
                ]
            );
            assert_eq!(&regs.x[24..27], &[1 << id, 1 << 16, 0xff]);
            assert_eq!(target.vcpus[id].instruction_count(), 31);
            assert!(!cluster.irq_line_for_test(id).load(Ordering::Acquire));
        }
    }
}

#[test]
fn detached_gic_dir_uses_the_eoi_mode_of_each_guest_pe() {
    let program = [
        0xd518_cc81u32, // MSR ICC_CTLR_EL1,X1: set EOImode.
        0xd518_4603,    // MSR ICC_PMR_EL1,X3.
        0xd518_cce4,    // MSR ICC_IGRPEN1_EL1,X4.
        0xb900_00c4,    // STR W4,[X6]: enable distributor Group 1 (X4 contains 3).
        0xb900_00ff,    // STR WZR,[X7]: wake this redistributor.
        0xb901_0110,    // STR W16,[X8,#0x100]: enable SGI7.
        0xb902_0110,    // STR W16,[X8,#0x200]: pend SGI7.
        0xd538_cc00,    // MRS X0,ICC_IAR1_EL1: acknowledge SGI7.
        0xd503_207f,    // WFI: save while the interrupt is still active.
        0xd518_cb20,    // MSR ICC_DIR_EL1,X0: attempt deactivation before EOI.
        0xb943_0111,    // LDR W17,[X8,#0x300]: active bit after DIR.
        0xd538_cb72,    // MRS X18,ICC_RPR_EL1: priority remains active.
        0xd518_cc20,    // MSR ICC_EOIR1_EL1,X0.
        0xb943_0113,    // LDR W19,[X8,#0x300]: active bit after EOIR.
        0xd538_cb74,    // MRS X20,ICC_RPR_EL1: idle priority.
        0xd503_207f,    // WFI: end of continuation.
    ];
    let bytes = program
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    for count in [2, 4] {
        let mut source = Fixture::with_clock(count, ClockMode::Retired);
        for id in 1..count {
            assert_eq!(
                source
                    .cluster()
                    .request_on(u64::from(id), CODE, 0, 0x3c5)
                    .unwrap(),
                0
            );
        }
        source.vm.route_interprocessor_requests().unwrap();
        source
            .vm
            .guest_mem
            .memory()
            .write_slice(&bytes, GuestAddress(CODE))
            .unwrap();
        for id in 0..usize::from(count) {
            let mut cpu = state(&source.vm, id);
            let redist = 0x080a_0000 + id as u64 * 0x20000;
            cpu.regs.x[1] = ((id % 2) * 2) as u64;
            cpu.regs.x[3..9].copy_from_slice(&[
                0xff,
                3,
                0,
                0x0800_0000,
                redist + 0x14,
                redist + 0x10000,
            ]);
            cpu.regs.x[16] = 1 << 7;
            source.vm.vcpus[id]
                .set_state(&CpuState::Aarch64(cpu))
                .unwrap();
        }
        for id in 0..usize::from(count) {
            let turn = source.vm.execute_turn().unwrap().unwrap();
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            assert_eq!(state(&source.vm, id).regs.x[0], 7);
            assert_eq!(source.vm.vcpus[id].instruction_count(), 9);
        }
        let path = source.kernel.with_extension("gic-dir.rxc");
        source
            .vm
            .take_snapshot_bundle(9 * u64::from(count))
            .unwrap()
            .save(&path)
            .unwrap();
        drop(source);
        let bundle = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        assert!(!config.kernel.exists());
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        for id in 0..usize::from(count) {
            target.vcpus[id].wake();
            let turn = target.execute_turn().unwrap().unwrap();
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            let active_after_dir = if id % 2 == 0 { 1 << 7 } else { 0 };
            assert_eq!(
                &state(&target, id).regs.x[17..21],
                &[active_after_dir, 0xa0, 0, 0xff],
                "PE {id} of {count}"
            );
            assert_eq!(target.vcpus[id].instruction_count(), 16);
        }
    }
}
