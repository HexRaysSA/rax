//! Canonical FPEXC aliases and precise faults across actual source-free files.
use super::*;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::vcpu::{Aarch64CpuState, RetirementStop};

const READ: u32 = 0xd53c_5301;
const WRITE: u32 = 0xd51c_5300;
const WFI: u32 = 0xd503_207f;
const ERET: u32 = 0xd69f_03e0;

fn entry(id: usize) -> u64 {
    CODE + id as u64 * 0x1_0000
}

fn image(vm: &Vmm, id: usize) -> Aarch64CpuState {
    let CpuState::Aarch64(state) = vm.vcpus[id].get_state().unwrap() else {
        panic!("AArch64 fixture")
    };
    state
}

fn write(vm: &Vmm, address: u64, words: &[u32]) {
    vm.guest_mem
        .memory()
        .write_slice(
            &words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>(),
            GuestAddress(address),
        )
        .unwrap();
}

fn source(count: u8, trapping: bool, program: &[u32], aarch32: bool) -> Fixture {
    let mut source = Fixture::with_clock(count, ClockMode::Retired);
    for id in 1..count {
        assert_eq!(
            source
                .cluster()
                .request_on(u64::from(id), entry(usize::from(id)), 0, 0x3c9)
                .unwrap(),
            0
        );
    }
    source.vm.route_interprocessor_requests().unwrap(); // Prepared platform peers, not guest PSCI.
    for id in 0..usize::from(count) {
        write(&source.vm, entry(id), program);
        let mut state = image(&source.vm, id);
        state.regs.pc = entry(id);
        state.regs.pstate = 0x3c9;
        state.regs.x[0] = u64::MAX;
        state.regs.x[1] = 0xfeed_face;
        state.regs.x[3] = 0x33ff; // Handler clears CPTR_EL2.TFP.
        let system = &mut state.sregs.execution.as_mut().unwrap().sysregs;
        system.scr_el3 = 0x501;
        system.hcr_el2 = if aarch32 { 0 } else { 1 << 31 };
        system.el1.cpacr = 3 << 20;
        system.el2.vbar = entry(id) + 0x1000;
        system.el2.elr = entry(id) + 0x100;
        system.el2.spsr = 0x1d3;
        for op1 in [4, 6] {
            system
                .impl_defined
                .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), 0);
        }
        if trapping {
            let mvfr = system.aarch32_fp_ids()[0] | (1 << 12);
            system.impl_defined.insert(
                Aarch64SysRegEncoding::new(3, 0, 0, 3, 0).encode(),
                u64::from(mvfr),
            );
        }
        source.vm.vcpus[id]
            .set_state(&CpuState::Aarch64(state))
            .unwrap();
    }
    source
}

fn restored(source: &Fixture, suffix: &str) -> Vmm {
    let saved = source
        .vm
        .take_snapshot_bundle(source.vm.coordinator.retired)
        .unwrap();
    let path = source.kernel.with_extension(suffix);
    saved.save(&path).unwrap();
    let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(&source.kernel).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    assert!(
        !config.kernel.exists(),
        "restore must not reopen source kernel"
    );
    let target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    assert_eq!(target.coordinator, source.vm.coordinator);
    assert_eq!(
        target.timing_context.checkpoint_state(),
        source.vm.timing_context.checkpoint_state()
    );
    for id in 0..source.vm.vcpus.len() {
        assert_eq!(image(&target, id), image(&source.vm, id));
        assert_eq!(
            target.vcpus[id].instruction_count(),
            source.vm.vcpus[id].instruction_count()
        );
    }
    target
}

fn agree(source: &Vmm, target: &Vmm) {
    assert_eq!(source.coordinator, target.coordinator);
    assert_eq!(
        source.timing_context.checkpoint_state(),
        target.timing_context.checkpoint_state()
    );
    for id in 0..source.vcpus.len() {
        assert_eq!(image(source, id), image(target, id));
        assert_eq!(
            source.vcpus[id].instruction_count(),
            target.vcpus[id].instruction_count()
        );
    }
}

#[test]
fn source_free_one_two_four_pe_files_keep_the_written_bank_through_a32_entry() {
    for count in [1, 2, 4] {
        for trapping in [false, true] {
            let mut source = source(count, trapping, &[WRITE, READ, ERET], true);
            for id in 0..usize::from(count) {
                write(
                    &source.vm,
                    entry(id) + 0x100,
                    &[
                        0xeef8_4a10, // VMRS R4,FPEXC.
                        0xeef0_5a10, // VMRS R5,FPSID.
                        0xe320_f003, // A32 WFI.
                    ],
                );
                let _binding = source.vm.timing_context.enter();
                let run = source.vm.vcpus[id].run_retirement_budget(1).unwrap();
                assert_eq!(run.retired, 1);
                assert!(matches!(run.stop, RetirementStop::BudgetExhausted));
                source.vm.coordinator.retired += 1;
            }
            // Capture after the write, before its read and real mixed-state ERET.
            let mut target = restored(&source, "fpexc-bank.rxc");
            for machine in [&mut source.vm, &mut target] {
                for id in 0..usize::from(count) {
                    let turn = machine.execute_turn().unwrap().unwrap();
                    assert_eq!(turn.cpu_index, id);
                    assert!(matches!(turn.exit, VcpuExit::Hlt));
                    let state = image(machine, id);
                    let wanted = if trapping { 0x6400_079f } else { 0x4000_0700 };
                    assert_eq!((state.regs.x[1], state.regs.x[4]), (wanted, wanted));
                    assert_eq!(
                        state.regs.x[5],
                        if trapping { 0x4141_3070 } else { 0x4103_3070 }
                    );
                    assert_eq!(state.regs.pstate & 31, 0x13); // A32 SVC.
                    assert_eq!(state.regs.pc, entry(id) + 0x10c);
                    assert_eq!(machine.vcpus[id].instruction_count(), 6);
                }
                assert_eq!(machine.coordinator.retired, 6 * u64::from(count));
            }
            agree(&source.vm, &target);
        }
    }
}

#[test]
fn source_free_files_preserve_delivered_fp_traps_and_handler_retry_on_every_pe() {
    for count in [1, 2, 4] {
        let mut source = source(count, false, &[WRITE, READ, WFI], false);
        for id in 0..usize::from(count) {
            write(&source.vm, entry(id) + 0x1200, &[0xd51c_1143, ERET]); // MSR CPTR_EL2,X3.
            let mut state = image(&source.vm, id);
            state
                .sregs
                .execution
                .as_mut()
                .unwrap()
                .sysregs
                .impl_defined
                .insert(Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(), 1 << 10);
            source.vm.vcpus[id]
                .update_state(&CpuState::Aarch64(state))
                .unwrap();
        }
        let clock = source.vm.timing_context.checkpoint_state();
        for id in 0..usize::from(count) {
            assert!(source.vm.execute_turn().unwrap().is_none());
            let state = image(&source.vm, id);
            let bank = &state.sregs.execution.as_ref().unwrap().sysregs.el2;
            assert_eq!(
                (bank.elr, bank.esr, bank.spsr),
                (entry(id), (7 << 26) | (1 << 25), 0x3c9)
            );
            assert_eq!(
                (state.regs.pc, state.regs.x[1]),
                (entry(id) + 0x1200, 0xfeed_face)
            );
            assert_eq!(source.vm.vcpus[id].instruction_count(), 0);
        }
        assert_eq!(source.vm.coordinator.retired, 0);
        assert_eq!(source.vm.timing_context.checkpoint_state(), clock);
        let mut target = restored(&source, "fpexc-fault.rxc");
        for machine in [&mut source.vm, &mut target] {
            for id in 0..usize::from(count) {
                let turn = machine.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                let state = image(machine, id);
                assert_eq!(
                    (state.regs.x[1], state.regs.pc),
                    (0x4000_0700, entry(id) + 12)
                );
                assert_eq!(machine.vcpus[id].instruction_count(), 5);
            }
            assert_eq!(machine.coordinator.retired, 5 * u64::from(count));
        }
        agree(&source.vm, &target);
    }
}

#[test]
fn source_free_files_reject_unimplemented_alias_before_conflicting_fp_traps() {
    for count in [1, 2, 4] {
        for instruction in [WRITE, READ] {
            let mut source = source(count, false, &[instruction], false);
            for id in 0..usize::from(count) {
                let mut state = image(&source.vm, id);
                let system = &mut state.sregs.execution.as_mut().unwrap().sysregs;
                system.id_aa64pfr0_el1 = (system.id_aa64pfr0_el1 & !(15 << 4)) | (1 << 4);
                for op1 in [4, 6] {
                    system.impl_defined.insert(
                        Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(),
                        1 << 10,
                    );
                }
                source.vm.vcpus[id]
                    .update_state(&CpuState::Aarch64(state))
                    .unwrap();
            }
            let mut target = restored(&source, "fpexc-absent.rxc");
            for machine in [&mut source.vm, &mut target] {
                let clock = machine.timing_context.checkpoint_state();
                for id in 0..usize::from(count) {
                    assert!(machine.execute_turn().unwrap().is_none());
                    let state = image(machine, id);
                    let system = &state.sregs.execution.as_ref().unwrap().sysregs;
                    assert_eq!((system.el2.elr, system.el2.esr), (entry(id), 1 << 25));
                    assert_eq!(
                        (state.regs.pc, state.regs.x[0], state.regs.x[1]),
                        (entry(id) + 0x1200, u64::MAX, 0xfeed_face)
                    );
                    assert!(
                        !system
                            .impl_defined
                            .contains_key(&Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode())
                    );
                    assert_eq!(machine.vcpus[id].instruction_count(), 0);
                }
                assert_eq!(machine.coordinator.retired, 0);
                assert_eq!(machine.timing_context.checkpoint_state(), clock);
            }
            agree(&source.vm, &target);
        }
    }
}
