//! Scalable access faults and handlers across real multi-CPU file restoration.
use super::{CODE, Fixture};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::runtime::Vmm;
use crate::vm::timing::ClockMode;
use crate::vm::vcpu::{CpuState, VcpuExit};
use vm_memory::{Bytes, GuestAddress};

fn entry(id: usize) -> u64 {
    CODE + id as u64 * 0x1_0000
}
fn target(id: usize) -> u8 {
    match id {
        1 => 2,
        2 => 3,
        _ => 1,
    }
}
fn handler(id: usize) -> u64 {
    entry(id) + 0x1000 + if target(id) == 1 { 0x200 } else { 0x400 }
}

fn source(count: u8) -> Fixture {
    let mut source = Fixture::with_clock(count, ClockMode::Retired);
    for id in 1..count {
        source
            .cluster()
            .request_on(u64::from(id), entry(usize::from(id)), 0, 0x3c5)
            .unwrap();
    }
    source.vm.route_interprocessor_requests().unwrap();
    for id in 0..usize::from(count) {
        for (address, word) in [
            (entry(id), 0x2518_e3e0u32),
            (handler(id), 0x9100_0529),
            (handler(id) + 4, 0xd503_207f),
        ] {
            source
                .vm
                .guest_mem
                .memory()
                .write_slice(&word.to_le_bytes(), GuestAddress(address))
                .unwrap();
        }
        let cpu = &mut source.vm.vcpus[id];
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = entry(id);
        state.regs.pstate = 0x3c5;
        state.regs.x[9] = 100 + id as u64;
        state.sregs.vbar_el1 = entry(id) + 0x1000;
        let execution = state.sregs.execution.as_mut().unwrap();
        let mut features = ArmFeatures::from_bits_retain(execution.features);
        features.set(ArmFeatures::SVE, id != 3);
        features.set(ArmFeatures::SME, id == 3);
        execution.features = features.bits();
        let system = &mut execution.sysregs;
        system.scr_el3 = 1 | (1 << 10);
        system.hcr_el2 = 1 << 31;
        system.el1.vbar = entry(id) + 0x1000;
        system.el2.vbar = system.el1.vbar;
        system.el3.vbar = system.el1.vbar;
        system.el1.cpacr = (3 << 20)
            | if id == 0 {
                0
            } else if id == 3 {
                3 << 24
            } else {
                3 << 16
            };
        for (op1, value) in [
            (4, if id == 1 { 1 << 8 } else { 0 }),
            (
                6,
                if id == 2 {
                    0
                } else if id == 3 {
                    1 << 12
                } else {
                    1 << 8
                },
            ),
        ] {
            system
                .impl_defined
                .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), value);
        }
        cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    }
    source
}

fn deliver(vm: &mut Vmm, count: u8) {
    for _ in 0..count {
        assert!(vm.execute_turn().unwrap().is_none());
    }
    assert_eq!(vm.coordinator.retired, 0);
    assert_eq!(vm.coordinator.cursor, 0);
    for (id, cpu) in vm.vcpus.iter().enumerate() {
        assert_eq!(cpu.instruction_count(), 0);
        let state = cpu.get_state().unwrap();
        let state = state.as_aarch64().unwrap();
        assert_eq!(state.regs.pc, handler(id));
        assert_eq!(state.regs.x[9], 100 + id as u64);
        let system = &state.sregs.execution.as_ref().unwrap().sysregs;
        let bank = system.bank(target(id));
        assert_eq!(bank.elr, entry(id));
        assert_eq!(bank.esr >> 26, if id == 3 { 0x1d } else { 0x19 });
        assert_eq!(bank.esr & 7, if id == 3 { 2 } else { 0 });
    }
}

fn continue_handlers(vm: &mut Vmm, count: u8) {
    for id in 0..usize::from(count) {
        let turn = vm.execute_turn().unwrap().expect("handler WFI yields");
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(turn.exit, VcpuExit::Hlt));
    }
    assert_eq!(vm.coordinator.retired, 2 * u64::from(count));
    assert_eq!(vm.coordinator.cursor, 0);
    for (id, cpu) in vm.vcpus.iter().enumerate() {
        assert_eq!(cpu.instruction_count(), 2);
        let state = cpu.get_state().unwrap();
        let state = state.as_aarch64().unwrap();
        assert_eq!(state.regs.x[9], 101 + id as u64);
        assert_eq!(state.regs.pc, handler(id) + 8);
    }
}

fn assert_same_cpus(left: &mut Vmm, right: &mut Vmm) {
    let left = left.capture_cpu_states().unwrap();
    let right = right.capture_cpu_states().unwrap();
    assert_eq!(left.len(), right.len());
    for (id, (left, right)) in left.iter().zip(&right).enumerate() {
        // Debug text also exposes hash-map iteration order; compare the full
        // typed AArch64 state and exact base-private wire representation.
        assert_eq!(
            left.state.as_aarch64().unwrap(),
            right.state.as_aarch64().unwrap(),
            "CPU{id}"
        );
        assert_eq!(
            crate::codec::serialize_limited(&left.emulator, 16 * 1024 * 1024).unwrap(),
            crate::codec::serialize_limited(&right.emulator, 16 * 1024 * 1024).unwrap(),
            "CPU{id} base-private state"
        );
    }
}

#[test]
fn two_and_four_cpu_files_preserve_scalable_controls_fault_frames_and_handler_continuation() {
    for count in [2, 4] {
        let mut original = source(count);
        let path = original.kernel.with_extension("sve-before.rxc");
        original
            .vm
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&path)
            .unwrap();
        let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
        let mut restored = Fixture::with_clock(count, ClockMode::Retired);
        restored.vm.restore_snapshot_bundle(&loaded).unwrap();
        deliver(&mut original.vm, count);
        deliver(&mut restored.vm, count);
        assert_same_cpus(&mut original.vm, &mut restored.vm);
        let after = original.kernel.with_extension("sve-delivered.rxc");
        restored
            .vm
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&after)
            .unwrap();
        let loaded = crate::vm::snapshot::SnapshotBundle::load(&after).unwrap();
        let mut resumed = Fixture::with_clock(count, ClockMode::Retired);
        resumed.vm.restore_snapshot_bundle(&loaded).unwrap();
        continue_handlers(&mut original.vm, count);
        continue_handlers(&mut resumed.vm, count);
        assert_same_cpus(&mut original.vm, &mut resumed.vm);
        assert_eq!(original.vm.coordinator, resumed.vm.coordinator);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(after).unwrap();
    }
}

fn selected_profile_source(count: u8, scalar: bool) -> Fixture {
    let mut fixture = source(count);
    for id in 0..usize::from(count) {
        let words = if scalar {
            vec![
                0x04bf_5800 | (((id + 1) as u32) << 5), // RDSVL X0,#1..4
                0x9100_0529,                            // ADD X9,X9,#1
                0xd503_207f,                            // WFI
            ]
        } else {
            vec![0x4502_6820] // PMULLB Z0.Q,Z1.D,Z2.D; requires the AES/PMULL feature.
        };
        for (offset, word) in words.into_iter().enumerate() {
            fixture
                .vm
                .guest_mem
                .memory()
                .write_slice(
                    &word.to_le_bytes(),
                    GuestAddress(entry(id) + offset as u64 * 4),
                )
                .unwrap();
        }
        for (offset, word) in [0x9100_0529u32, 0xd503_207f].into_iter().enumerate() {
            fixture
                .vm
                .guest_mem
                .memory()
                .write_slice(
                    &word.to_le_bytes(),
                    GuestAddress(entry(id) + 0x1200 + offset as u64 * 4),
                )
                .unwrap();
        }
        let cpu = &mut fixture.vm.vcpus[id];
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = entry(id);
        state.regs.pstate = 0x3c5;
        state.sregs.vbar_el1 = entry(id) + 0x1000;
        let execution = state.sregs.execution.as_mut().unwrap();
        let mut features = ArmFeatures::from_bits_retain(execution.features);
        features.set(ArmFeatures::SVE2, !scalar || id % 2 == 1);
        features.set(ArmFeatures::SVE, !scalar || id % 2 == 1);
        features.set(ArmFeatures::SME, scalar);
        features.remove(ArmFeatures::SME2);
        features.set(ArmFeatures::SVE2_AES, !scalar && id % 2 == 1);
        execution.features = features.bits();
        let system = &mut execution.sysregs;
        system.el1.vbar = entry(id) + 0x1000;
        system.scr_el3 = 1 | (1 << 10);
        system.hcr_el2 = 1 << 31;
        system.el1.cpacr = (3 << 20) | if scalar { 3 << 24 } else { 0 };
        for (op1, value) in [(4, 0), (6, (1 << 8) | (1 << 12))] {
            system
                .impl_defined
                .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), value);
        }
        cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    }
    fixture
}

fn deliver_selected_profile_faults(vm: &mut Vmm, count: u8) {
    for _ in 0..count {
        assert!(vm.execute_turn().unwrap().is_none());
    }
    assert_eq!((vm.coordinator.retired, vm.coordinator.cursor), (0, 0));
    for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
        let state = cpu.get_state().unwrap();
        let state = state.as_aarch64().unwrap();
        let bank = state.sregs.execution.as_ref().unwrap().sysregs.bank(1);
        assert_eq!(bank.elr, entry(id));
        // A missing capability precedes denied ZEN. The same instruction on
        // the next CPU has its capability selected and takes SVEAccessTrap.
        assert_eq!(bank.esr >> 26, if id % 2 == 0 { 0 } else { 0x19 });
        assert_eq!(bank.esr & 0x1ff_ffff, 0);
        assert_eq!(state.regs.pc, entry(id) + 0x1200);
        assert_eq!(state.regs.x[9], 100 + id as u64);
        assert_eq!(cpu.instruction_count(), 0);
    }
}

#[test]
fn two_and_four_cpu_files_preserve_selected_capabilities_before_access_checks() {
    for count in [2, 4] {
        let mut original = selected_profile_source(count, false);
        let before = original.kernel.with_extension("selected-before.rxc");
        original
            .vm
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&before)
            .unwrap();
        let loaded = crate::vm::snapshot::SnapshotBundle::load(&before).unwrap();
        let mut restored = Fixture::with_clock(count, ClockMode::Retired);
        restored.vm.restore_snapshot_bundle(&loaded).unwrap();
        deliver_selected_profile_faults(&mut original.vm, count);
        deliver_selected_profile_faults(&mut restored.vm, count);
        assert_same_cpus(&mut original.vm, &mut restored.vm);
        let after = original.kernel.with_extension("selected-delivered.rxc");
        restored
            .vm
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&after)
            .unwrap();
        let loaded = crate::vm::snapshot::SnapshotBundle::load(&after).unwrap();
        let mut resumed = Fixture::with_clock(count, ClockMode::Retired);
        resumed.vm.restore_snapshot_bundle(&loaded).unwrap();
        for vm in [&mut original.vm, &mut resumed.vm] {
            for id in 0..usize::from(count) {
                let turn = vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                let state = vm.vcpus[id].get_state().unwrap();
                let state = state.as_aarch64().unwrap();
                assert_eq!(state.regs.x[9], 101 + id as u64);
                assert_eq!(vm.vcpus[id].instruction_count(), 2);
            }
            assert_eq!(vm.coordinator.retired, 2 * u64::from(count));
        }
        assert_same_cpus(&mut original.vm, &mut resumed.vm);
        assert_eq!(original.vm.coordinator, resumed.vm.coordinator);
        std::fs::remove_file(before).unwrap();
        std::fs::remove_file(after).unwrap();
    }
}

#[test]
fn two_and_four_cpu_files_preserve_scalar_sme_execution_with_sve_present_or_absent() {
    for count in [2, 4] {
        let mut original = selected_profile_source(count, true);
        let path = original.kernel.with_extension("scalar-sme-before.rxc");
        original
            .vm
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&path)
            .unwrap();
        let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
        let mut restored = Fixture::with_clock(count, ClockMode::Retired);
        restored.vm.restore_snapshot_bundle(&loaded).unwrap();
        for vm in [&mut original.vm, &mut restored.vm] {
            for id in 0..usize::from(count) {
                let turn = vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                let state = vm.vcpus[id].get_state().unwrap();
                let state = state.as_aarch64().unwrap();
                assert_eq!(state.regs.x[0], 16 * (id as u64 + 1));
                assert_eq!(state.regs.x[9], 101 + id as u64);
                assert_eq!(state.regs.pc, entry(id) + 12);
                assert_eq!(vm.vcpus[id].instruction_count(), 3);
            }
            assert_eq!(vm.coordinator.retired, 3 * u64::from(count));
        }
        assert_same_cpus(&mut original.vm, &mut restored.vm);
        assert_eq!(original.vm.coordinator, restored.vm.coordinator);
        std::fs::remove_file(path).unwrap();
    }
}
