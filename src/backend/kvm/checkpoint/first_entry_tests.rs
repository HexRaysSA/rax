//! First-entry activation through the real managed wrapper and native RDTSC.
use super::{Image, exit, graph, native, offsets};
use crate::vm::memory::vm::{Bytes, GuestAddress};
use crate::vm::vcpu::{CpuState, VcpuExit};
use std::time::Duration;

const CODE: &[u8] = &[0xf4, 0x0f, 0x31, 0xe6, 0xe9, 0xf4]; // HLT; RDTSC; OUT e9,AL; HLT.

pub(super) fn host_tsc() -> u64 {
    // SAFETY: these native KVM tests require x86-64, whose SSE2/RDTSC baseline
    // is also required by the admitted unscaled clock profile. LFENCE orders
    // this independent observation around the managed call. No pointer or
    // optional vector state is accessed and no host policy is changed.
    unsafe {
        std::arch::x86_64::_mm_lfence();
        let value = std::arch::x86_64::_rdtsc();
        std::arch::x86_64::_mm_lfence();
        value
    }
}

pub(super) fn anchor(image: &Image) -> u64 {
    serde_json::to_value(&image.clock).unwrap()["anchor"]
        .as_u64()
        .unwrap()
}

pub(super) fn acknowledge(cpu: &mut dyn crate::vm::vcpu::VCpu) {
    cpu.complete_io_out().unwrap();
    assert_eq!(
        cpu.settle_checkpoint_io(&mut |exit| panic!("already acknowledged output: {exit:?}"))
            .unwrap(),
        crate::vm::vcpu::CheckpointIoState::Complete
    );
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn source_free_first_entry_excludes_publication_and_parked_poll_time_for_every_cpu() {
    for count in [1, 2, 4] {
        let (source, memory, mut cpus) = graph(count, false);
        memory
            .memory()
            .write_slice(CODE, GuestAddress(0x1000))
            .unwrap();
        for cpu in &mut cpus {
            assert!(matches!(exit(&mut **cpu), VcpuExit::Hlt));
            assert_eq!(cpu.current_pc(), 0x1001);
        }
        let boundary = source.checkpoint_boundary().unwrap();
        let image = native(&*source).capture_native_banks(&boundary).unwrap();
        let json = serde_json::to_vec(&image).unwrap();
        let binary = crate::codec::serialize(&image).unwrap();
        drop(boundary);
        drop(cpus);
        drop(source);
        drop(memory);
        for image in [
            serde_json::from_slice::<Image>(&json).unwrap(),
            crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
        ] {
            for first in [0, count - 1] {
                let (target, memory, mut cpus) = graph(count, false);
                memory
                    .memory()
                    .write_slice(CODE, GuestAddress(0x1000))
                    .unwrap();
                let boundary = target.checkpoint_boundary().unwrap();
                let vm = native(&*target);
                image.restore_stored(vm, &boundary).unwrap();
                image.stage_resume_clock(vm, &boundary).unwrap();
                // Simulate substantial stopped RAM/device publication. This
                // time must not be charged to the restored native epoch.
                std::thread::sleep(Duration::from_millis(150));
                let pending = vm.capture_native_banks(&boundary).unwrap();
                assert_eq!(pending.clock, image.clock);
                drop(boundary);

                let first = usize::from(first);
                for invalid in [Duration::ZERO, Duration::MAX] {
                    assert!(cpus[first].run_host_slice(invalid).is_err());
                }
                let CpuState::X86_64(mut overlay) = cpus[first].get_state().unwrap() else {
                    unreachable!()
                };
                overlay.regs.rflags |= 1 << 9;
                cpus[first].set_state(&CpuState::X86_64(overlay)).unwrap();
                // This samples readiness with immediate-exit KVM_RUN, but it
                // does not authorize execution or consume the queued epoch.
                assert!(cpus[first].can_inject_interrupt());
                for _ in 0..3 {
                    assert!(matches!(exit(&mut *cpus[first]), VcpuExit::Hlt));
                    assert_eq!(cpus[first].current_pc(), 0x1001);
                }
                let boundary = target.checkpoint_boundary().unwrap();
                assert_eq!(
                    vm.capture_native_banks(&boundary).unwrap().clock,
                    image.clock
                );
                drop(boundary);
                cpus[first].wake();

                let before = host_tsc();
                let event = exit(&mut *cpus[first]);
                let after = host_tsc();
                assert!(matches!(event, VcpuExit::IoOut { port: 0xe9, .. }));
                let CpuState::X86_64(state) = cpus[first].get_state().unwrap() else {
                    unreachable!()
                };
                let observed = (state.regs.rdx as u32 as u64) << 32 | state.regs.rax as u32 as u64;
                let expected = anchor(&image).wrapping_add(offsets(&image)[first]);
                // The guest may advance during its authorized entry window;
                // the deliberately earlier publication delay is excluded.
                assert!(observed.wrapping_sub(expected) <= after.wrapping_sub(before));
                acknowledge(&mut *cpus[first]);

                let boundary = target.checkpoint_boundary().unwrap();
                let activated = vm.capture_native_banks(&boundary).unwrap();
                let saved_offsets = offsets(&image);
                let active_offsets = offsets(&activated);
                let delta = active_offsets[0].wrapping_sub(saved_offsets[0]);
                assert!(
                    active_offsets
                        .iter()
                        .zip(&saved_offsets)
                        .all(|(active, saved)| active.wrapping_sub(*saved) == delta)
                );
                // Infer the actual native rebase anchor from the installed
                // offsets, independently of the gate's pending-state flag.
                let resumed_at = anchor(&image).wrapping_sub(delta);
                assert!(resumed_at.wrapping_sub(before) <= after.wrapping_sub(before));
                drop(boundary);
                for (id, cpu) in cpus.iter_mut().enumerate() {
                    if id != first {
                        cpu.wake();
                        assert!(matches!(
                            exit(&mut **cpu),
                            VcpuExit::IoOut { port: 0xe9, .. }
                        ));
                        acknowledge(&mut **cpu);
                    }
                }
                let boundary = target.checkpoint_boundary().unwrap();
                let later = vm.capture_native_banks(&boundary).unwrap();
                assert_eq!(
                    offsets(&later),
                    active_offsets,
                    "a later CPU rebased the epoch again"
                );
            }
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn powered_off_host_calls_do_not_consume_a_staged_native_epoch() {
    let (vm, _memory, mut cpus) = graph(1, false);
    let boundary = vm.checkpoint_boundary().unwrap();
    let source = native(&*vm).capture_native_banks(&boundary).unwrap();
    source.stage_resume_clock(native(&*vm), &boundary).unwrap();
    assert!(cpus[0].capture_checkpoint_record(&boundary, None).is_err());
    drop(boundary);
    native(&*vm).memory.power_off().unwrap();
    assert!(matches!(
        cpus[0].run_host_slice(Duration::from_millis(10)).unwrap(),
        Some(VcpuExit::Shutdown)
    ));
    let boundary = vm.checkpoint_boundary().unwrap();
    assert_eq!(
        native(&*vm).capture_native_banks(&boundary).unwrap().clock,
        source.clock
    );
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn losing_a_peer_after_staging_fences_the_common_epoch_before_guest_execution() {
    let (vm, memory, mut cpus) = graph(2, false);
    memory
        .memory()
        .write_slice(
            &[0xc6, 0x06, 0x00, 0x50, 0xa5, 0xe6, 0xe9, 0xf4],
            GuestAddress(0x1000),
        )
        .unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let image = native(&*vm).capture_native_banks(&boundary).unwrap();
    image.stage_resume_clock(native(&*vm), &boundary).unwrap();
    drop(boundary);
    drop(cpus.pop().unwrap());
    assert!(cpus[0].run_host_slice(Duration::from_millis(10)).is_err());
    assert_eq!(
        memory
            .memory()
            .read_obj::<u8>(GuestAddress(0x5000))
            .unwrap(),
        0
    );
    assert!(cpus[0].get_state().is_err());
    assert!(vm.checkpoint_boundary().is_err());
    assert!(cpus[0].run_host_slice(Duration::from_millis(10)).is_err());
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn staged_resume_retains_native_vm_and_ram_after_outer_handles_are_dropped() {
    let (vm, memory, mut cpus) = graph(1, false);
    memory
        .memory()
        .write_slice(&CODE[1..], GuestAddress(0x1000))
        .unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let image = native(&*vm).capture_native_banks(&boundary).unwrap();
    image.stage_resume_clock(native(&*vm), &boundary).unwrap();
    let expected = anchor(&image).wrapping_add(offsets(&image)[0]);
    drop(boundary);
    drop(vm);
    drop(memory);
    std::thread::sleep(Duration::from_millis(150));
    let before = host_tsc();
    assert!(matches!(
        exit(&mut *cpus[0]),
        VcpuExit::IoOut { port: 0xe9, .. }
    ));
    let after = host_tsc();
    let CpuState::X86_64(state) = cpus[0].get_state().unwrap() else {
        unreachable!()
    };
    let observed = (state.regs.rdx as u32 as u64) << 32 | state.regs.rax as u32 as u64;
    assert!(observed.wrapping_sub(expected) <= after.wrapping_sub(before));
}
