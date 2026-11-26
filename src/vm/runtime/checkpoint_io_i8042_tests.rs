//! Native IRQ line admission against the saved PC output latch.
use super::*;
use crate::devices::i8042::{AUX_IRQ, DATA_PORT, KEYBOARD_IRQ, STATUS_PORT};
use crate::vm::vcpu::CheckpointIoReply;

fn native_pc() -> Fixture {
    let mut fixture = Fixture::with_construction(
        1,
        128 << 20,
        ConstructionMode::Checkpoint {
            initialize_kvm_irqchip: true,
        },
    );
    fixture.prepare(0, &[0xf4]);
    fixture
}

fn fill_latch(vm: &Vmm, irq: u8) {
    let write = |port, value| {
        assert!(matches!(
            vm.checkpoint_io_service(
                0,
                VcpuExit::IoOut {
                    port,
                    data: vec![value],
                }
            )
            .unwrap(),
            CheckpointIoReply::Output
        ));
    };
    write(STATUS_PORT, 0x60);
    if irq == AUX_IRQ {
        write(DATA_PORT, 2);
        write(STATUS_PORT, 0xd3);
        write(DATA_PORT, 0x69);
    } else {
        write(DATA_PORT, 1);
        write(DATA_PORT, 0xf4);
    }
}

#[test]
#[ignore = "requires the managed native KVM irqchip"]
fn capture_rejects_i8042_irq_lines_that_disagree_with_the_latch() {
    for irq in [KEYBOARD_IRQ, AUX_IRQ] {
        let source = native_pc();
        let vm = &source.vm;
        let drive = |asserted| vm.vm.set_irq_line(u32::from(irq), asserted).unwrap();
        let expect_rejection = || {
            let error = vm.take_snapshot_bundle(0).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("native i8042 IRQ{irq}")),
                "{error}"
            );
        };

        drive(true);
        expect_rejection();
        drive(false);
        vm.take_snapshot_bundle(0).unwrap();

        fill_latch(vm, irq);
        vm.take_snapshot_bundle(0).unwrap();
        drive(false);
        expect_rejection();
    }
}

#[test]
#[ignore = "requires the managed native KVM irqchip"]
fn restore_rejects_i8042_irq_disagreement_before_publication() {
    for irq in [KEYBOARD_IRQ, AUX_IRQ] {
        let source = native_pc();
        let idle = source.vm.take_snapshot_bundle(0).unwrap();
        fill_latch(&source.vm, irq);
        let asserted = source.vm.take_snapshot_bundle(0).unwrap();
        let idle_pc = idle.execution().unwrap().pc.clone();
        let asserted_pc = asserted.execution().unwrap().pc.clone();
        drop(source);

        let mut target = native_pc();
        let CpuState::X86_64(mut state) = target.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rip = 0x1140;
        target.vm.vcpus[0]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
        let address = GuestAddress(0x2000);
        let sentinel = 0x5a_u8;
        target
            .vm
            .guest_mem
            .memory()
            .write_obj(sentinel, address)
            .unwrap();
        let pc = target.vm.vcpus[0].current_pc();
        assert_eq!(pc, 0x1140);
        for (mut bundle, other_device) in [(idle, asserted_pc), (asserted, idle_pc)] {
            let mut execution = bundle.take_execution().unwrap();
            execution.pc = other_device;
            // Each bank and the public CPU projection still belong to their
            // original capture. Only the corresponding i8042 device changes.
            let mixed = bundle.with_execution(execution).unwrap();
            let error = target.vm.restore_snapshot_bundle(&mixed).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("native i8042 IRQ{irq}")),
                "{error}"
            );
            assert_eq!(target.vm.vcpus[0].current_pc(), pc);
            assert_eq!(
                target
                    .vm
                    .guest_mem
                    .memory()
                    .read_obj::<u8>(address)
                    .unwrap(),
                sentinel
            );
            let controller = &target.vm.pc_devices.as_ref().unwrap().i8042;
            assert_eq!(controller.lock().unwrap().output_irq(), None);
        }
    }
}
