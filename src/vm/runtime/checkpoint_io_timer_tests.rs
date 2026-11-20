//! An armed software LAPIC timer can wake a VM restored with every CPU halted.
use super::Fixture;
use crate::config::{CliConfig, VmConfig};
use crate::devices::lapic::LAPIC_BASE;
use crate::vm::runtime::Vmm;
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::vcpu::{CheckpointIoState, CpuState, VcpuExit};
use std::time::{Duration, Instant};
use vm_memory::{Bytes, GuestAddress};

const VECTOR: u8 = 0x41;
const HANDLER: u16 = 0x1800;
const MARKERS: u16 = 0x2000;
const COUNT: u32 = 1_000_000_000; // 1 s at divisor 1 and modeled 1 GHz.

fn write_lapic(code: &mut Vec<u8>, offset: u32, value: u32) {
    // MOV DWORD [absolute disp32], imm32 in a 16-bit code segment.
    code.extend_from_slice(&[0x67, 0x66, 0xc7, 0x05]);
    code.extend_from_slice(&(LAPIC_BASE as u32 + offset).to_le_bytes());
    code.extend_from_slice(&value.to_le_bytes());
}

#[test]
#[ignore = "requires native Linux KVM with userspace interrupt ownership"]
fn software_lapic_timer_wakes_an_all_halted_vmm_after_detached_restore() {
    for cpus in [1, 2, 4] {
        let mut source = Fixture::with_memory(cpus, 128 << 20);
        // The fixture sets up each real-mode context in place of guest SIPI.
        source.vm.coordinator.online.fill(true);
        let timer_cpu = usize::from(cpus - 1);
        for id in 0..timer_cpu {
            source.prepare(id, &[0xfa, 0xf4]); // CLI; HLT.
            assert!(matches!(source.exit(id), VcpuExit::Hlt));
        }
        let mut guest = Vec::new();
        write_lapic(&mut guest, 0x3e0, 0xb); // Divide by 1.
        write_lapic(&mut guest, 0x320, u32::from(VECTOR));
        write_lapic(&mut guest, 0x380, COUNT);
        guest.extend_from_slice(&[0xfb, 0xf4]); // STI; HLT.
        let halted_pc = 0x1000 + timer_cpu as u64 * 0x100 + guest.len() as u64;
        // After IRET, record the continuation and halt with interrupts masked.
        guest.extend_from_slice(&[0xc6, 0x06, 0x01, 0x20, 0x5a, 0xfa, 0xf4]);
        source.prepare(timer_cpu, &guest);

        let mut handler = vec![0xfe, 0x06, 0x00, 0x20]; // INC BYTE [2000h].
        write_lapic(&mut handler, 0xb0, 0); // EOI.
        handler.push(0xcf); // IRET.
        let memory = source.vm.guest_mem.memory();
        memory
            .write_slice(&handler, GuestAddress(u64::from(HANDLER)))
            .unwrap();
        // Real-mode IVT entry with segment 0.
        memory
            .write_obj(u32::from(HANDLER), GuestAddress(u64::from(VECTOR) * 4))
            .unwrap();
        let CpuState::X86_64(mut state) = source.vm.vcpus[timer_cpu].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rsp = 0x9000;
        state.sregs.ss.base = 0;
        state.sregs.ss.selector = 0;
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 0x3ff;
        source.vm.vcpus[timer_cpu]
            .set_state(&CpuState::X86_64(state))
            .unwrap();

        for offset in [0x3e0, 0x320, 0x380] {
            assert!(matches!(
                source.exit(timer_cpu),
                VcpuExit::MmioWrite { addr, .. } if addr == LAPIC_BASE + offset
            ));
            assert_eq!(source.settle(timer_cpu), CheckpointIoState::Complete);
        }
        assert!(matches!(source.exit(timer_cpu), VcpuExit::Hlt));
        assert_eq!(source.vm.vcpus[timer_cpu].current_pc(), halted_pc);

        let image = source.vm.take_snapshot_bundle(0).unwrap();
        assert_eq!(image.saved_kvm_irqchip(), Some(false));
        let age = image.execution().unwrap().local_apics[timer_cpu]
            .timer_age_nanos
            .expect("the software LAPIC timer must be armed at capture");
        assert!(age < u128::from(COUNT));
        let path = source.kernel.with_extension("rxc");
        image.save(&path).unwrap();
        drop(image);
        drop(source);
        let image = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&image, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &image).unwrap();
        let phase = target.timing_context.elapsed_nanos();
        std::thread::sleep(Duration::from_millis(25));
        assert!(target.timing_context.is_stopped_at(phase));
        let republished = target.take_snapshot_bundle(0).unwrap();
        assert_eq!(
            republished.execution().unwrap().local_apics[timer_cpu].timer_age_nanos,
            Some(age)
        );
        drop(republished);
        let turn = target.execute_turn().unwrap().unwrap();
        assert!(matches!(turn.exit, VcpuExit::Hlt));
        assert_eq!(target.vcpus[timer_cpu].current_pc(), halted_pc);
        assert!(
            !target.timing_context.is_stopped_at(phase),
            "the first scheduled idle turn must resume the device clock"
        );

        let stop = Instant::now() + Duration::from_secs(4);
        let mut eoi_seen = false;
        loop {
            let turn = target.execute_turn().unwrap();
            match turn.map(|turn| (turn.cpu_index, turn.exit)) {
                Some((id, VcpuExit::Hlt)) if eoi_seen && id == timer_cpu => break,
                Some((_, VcpuExit::Hlt)) | None => {}
                Some((id, VcpuExit::MmioWrite { addr, .. })) => {
                    assert_eq!(addr, LAPIC_BASE + 0xb0);
                    assert_eq!(id, timer_cpu);
                    assert!(!eoi_seen);
                    assert_eq!(
                        target.vcpus[timer_cpu]
                            .settle_checkpoint_io(&mut |event| {
                                target.checkpoint_io_service(timer_cpu, event)
                            })
                            .unwrap(),
                        CheckpointIoState::Complete
                    );
                    eoi_seen = true;
                }
                Some((id, exit)) => panic!("unexpected exit from CPU {id}: {exit:?}"),
            }
            assert!(
                Instant::now() < stop,
                "software timer did not wake CPU {timer_cpu}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut markers = [0; 2];
        target
            .guest_mem
            .memory()
            .read_slice(&mut markers, GuestAddress(u64::from(MARKERS)))
            .unwrap();
        assert_eq!(markers, [1, 0x5a]);
        assert_eq!(target.vcpus[timer_cpu].current_pc(), halted_pc + 7);
        for id in 0..timer_cpu {
            assert_eq!(target.vcpus[id].current_pc(), 0x1002 + id as u64 * 0x100);
        }
    }
}
