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
