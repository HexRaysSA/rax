//! Native entry, retained software timer phase and source-free clock ownership.
use super::first_entry::{acknowledge, anchor, host_tsc};
use super::{Image, exit, graph, native, offsets};
use crate::devices::lapic::LocalApic;
use crate::vm::memory::vm::{Bytes, GuestAddress};
use crate::vm::timing::{ClockMode, ClockState, TimingContext};
use crate::vm::vcpu::{CpuState, VcpuExit};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CODE: &[u8] = &[0xf4, 0x0f, 0x31, 0xe6, 0xe9, 0xf4];
const TIMER_COUNT: u32 = 1_000_000_000;
const LAPIC_LVT_TIMER: u64 = 0x320;
const LAPIC_TIMER_ICR: u64 = 0x380;
const LAPIC_TIMER_CCR: u64 = 0x390;
const LAPIC_TIMER_DCR: u64 = 0x3e0;

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn source_free_software_timer_and_native_epoch_wait_for_the_same_managed_entry() {
    for count in [1, 2, 4] {
        let (source, memory, mut cpus) = graph(count, false);
        memory
            .memory()
            .write_slice(CODE, GuestAddress(0x1000))
            .unwrap();
        for cpu in &mut cpus {
            assert!(matches!(exit(&mut **cpu), VcpuExit::Hlt));
        }
        let timing = Arc::new(TimingContext::new());
        let weak = Arc::downgrade(&timing);
        let scope = timing.enter();
        let initial = timing.checkpoint_state();
        timing
            .prepare_stopped_checkpoint_state(&initial)
            .unwrap()
            .commit();
        let mut apic = LocalApic::new(0);
        apic.write_register(LAPIC_LVT_TIMER, 0x41);
        apic.write_register(LAPIC_TIMER_DCR, 11);
        apic.write_register(LAPIC_TIMER_ICR, TIMER_COUNT);
        timing.set_resume_base(initial.elapsed_nanos.wrapping_add(1234));
        let state = timing.checkpoint_state();
        let saved_timer = apic.checkpoint_at(Instant::now());
        assert_eq!(saved_timer.timer_age_nanos, Some(1234));
        let boundary = source.checkpoint_boundary().unwrap();
        let image = native(&*source).capture_native_banks(&boundary).unwrap();
        let json = serde_json::to_vec(&(&image, state)).unwrap();
        let binary = crate::codec::serialize(&(&image, state)).unwrap();
        drop(boundary);
        drop(cpus);
        drop(source);
        drop(memory);
        drop(apic);
        drop(scope);
        drop(timing);
        assert!(weak.upgrade().is_none(), "image retained the source clock");
        for (image, state) in [
            serde_json::from_slice::<(Image, ClockState)>(&json).unwrap(),
            crate::codec::deserialize_strict::<(Image, ClockState)>(&binary).unwrap(),
        ] {
            for first in [0, count - 1] {
                let (target, memory, mut cpus) = graph(count, false);
                memory
                    .memory()
                    .write_slice(CODE, GuestAddress(0x1000))
                    .unwrap();
                let timing = Arc::new(TimingContext::new());
                let mut apic =
                    saved_timer.prepare_for_clock(Instant::now(), &timing, state.elapsed_nanos);
                let boundary = target.checkpoint_boundary().unwrap();
                let vm = native(&*target);
                image.restore_stored(vm, &boundary).unwrap();
                image
                    .stage_resume_clock_with_timing(vm, &boundary, timing.clone(), state)
                    .unwrap();
                std::thread::sleep(Duration::from_millis(30));
                assert_eq!(timing.checkpoint_state(), state);
                assert_eq!(apic.read_register(LAPIC_TIMER_CCR), TIMER_COUNT - 1234);
                assert_eq!(apic.tick(), None);
                assert_eq!(
                    vm.capture_native_banks(&boundary).unwrap().clock,
                    image.clock
                );
                drop(boundary);
                let first = usize::from(first);
                assert!(cpus[first].run_host_slice(Duration::ZERO).is_err());
                for _ in 0..3 {
                    assert!(matches!(exit(&mut *cpus[first]), VcpuExit::Hlt));
                    assert_eq!(timing.checkpoint_state(), state);
                }
                cpus[first].wake();
                let wall_before = Instant::now();
                let before = host_tsc();
                assert!(matches!(
                    exit(&mut *cpus[first]),
                    VcpuExit::IoOut { port: 0xe9, .. }
                ));
                let after = host_tsc();
                let elapsed = timing.elapsed_nanos().wrapping_sub(state.elapsed_nanos);
                assert!(u128::from(elapsed) <= wall_before.elapsed().as_nanos());
                let CpuState::X86_64(cpu) = cpus[first].get_state().unwrap() else {
                    unreachable!()
                };
                let tsc = (cpu.regs.rdx as u32 as u64) << 32 | cpu.regs.rax as u32 as u64;
                let expected = anchor(&image).wrapping_add(offsets(&image)[first]);
                assert!(tsc.wrapping_sub(expected) <= after.wrapping_sub(before));
                acknowledge(&mut *cpus[first]);
                std::thread::sleep(Duration::from_millis(2));
                let age_before = timing.elapsed_nanos().wrapping_sub(state.elapsed_nanos) + 1234;
                let observed_age = u64::from(TIMER_COUNT - apic.read_register(LAPIC_TIMER_CCR));
                let age_after = timing.elapsed_nanos().wrapping_sub(state.elapsed_nanos) + 1234;
                assert!((age_before..=age_after).contains(&observed_age));
                assert!(!timing.is_stopped_at(state.elapsed_nanos));
                let boundary = target.checkpoint_boundary().unwrap();
                let active_offsets = offsets(&vm.capture_native_banks(&boundary).unwrap());
                let delta = active_offsets[0].wrapping_sub(offsets(&image)[0]);
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
                assert_eq!(
                    offsets(&vm.capture_native_banks(&boundary).unwrap()),
                    active_offsets
                );
            }
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn staged_device_owner_cannot_be_detached_or_replaced_by_a_foreign_clock() {
    let (vm, _memory, mut cpus) = graph(1, false);
    let boundary = vm.checkpoint_boundary().unwrap();
    let native = native(&*vm);
    let image = native.capture_native_banks(&boundary).unwrap();
    let timing = Arc::new(TimingContext::new());
    let state = timing.checkpoint_state();
    image
        .stage_resume_clock_with_timing(native, &boundary, timing.clone(), state)
        .unwrap();
    let foreign = Arc::new(TimingContext::new());
    let foreign_state = foreign.checkpoint_state();
    assert!(
        image
            .stage_resume_clock_with_timing(native, &boundary, foreign.clone(), foreign_state)
            .is_err()
    );
    assert!(!foreign.is_stopped_at(foreign_state.elapsed_nanos));
    assert!(image.stage_resume_clock(native, &boundary).is_err());
    let retired = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    assert!(
        image
            .stage_resume_clock_with_timing(
                native,
                &boundary,
                retired.clone(),
                retired.checkpoint_state(),
            )
            .is_err()
    );
    assert_eq!(timing.checkpoint_state(), state);
    drop(boundary);
    assert!(matches!(
        exit(&mut *cpus[0]),
        VcpuExit::IoOut { port: 0xe9, .. }
    ));
    assert!(!timing.is_stopped_at(state.elapsed_nanos));
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn independently_changed_device_phase_fences_every_cpu_before_native_execution() {
    let (vm, memory, mut cpus) = graph(2, false);
    memory
        .memory()
        .write_slice(
            &[0xc6, 0x06, 0x00, 0x50, 0xa5, 0xe6, 0xe9, 0xf4],
            GuestAddress(0x1000),
        )
        .unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let native = native(&*vm);
    let image = native.capture_native_banks(&boundary).unwrap();
    let timing = Arc::new(TimingContext::new());
    let state = timing.checkpoint_state();
    image
        .stage_resume_clock_with_timing(native, &boundary, timing.clone(), state)
        .unwrap();
    drop(boundary);
    timing.set_resume_base(state.elapsed_nanos.wrapping_add(1));
    let boundary = vm.checkpoint_boundary().unwrap();
    assert!(native.capture_native_banks(&boundary).is_err());
    drop(boundary);
    assert!(cpus[0].run_host_slice(Duration::from_millis(10)).is_err());
    assert_eq!(
        memory
            .memory()
            .read_obj::<u8>(GuestAddress(0x5000))
            .unwrap(),
        0
    );
    assert!(cpus[1].get_state().is_err());
    assert!(vm.checkpoint_boundary().is_err());
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn staged_native_owner_retains_the_software_clock_after_outer_handles_are_dropped() {
    let (vm, memory, mut cpus) = graph(1, false);
    let boundary = vm.checkpoint_boundary().unwrap();
    let native = native(&*vm);
    let image = native.capture_native_banks(&boundary).unwrap();
    let timing = Arc::new(TimingContext::new());
    let weak = Arc::downgrade(&timing);
    let state = timing.checkpoint_state();
    image
        .stage_resume_clock_with_timing(native, &boundary, timing.clone(), state)
        .unwrap();
    drop(boundary);
    drop(timing);
    drop(vm);
    drop(memory);
    assert!(weak.upgrade().unwrap().is_stopped_at(state.elapsed_nanos));
    std::thread::sleep(Duration::from_millis(30));
    assert!(matches!(
        exit(&mut *cpus[0]),
        VcpuExit::IoOut { port: 0xe9, .. }
    ));
    assert!(weak.upgrade().is_none());
}
