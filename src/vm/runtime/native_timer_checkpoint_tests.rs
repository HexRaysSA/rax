//! Guest observations of the virtual counter across native file restoration.
use super::*;
use crate::backend::intel_hvf_deadline::mach;
use std::time::Duration;

fn read_guest_counter(cpu: &mut dyn crate::vm::vcpu::VCpu) -> (u64, u64) {
    for _ in 0..50 {
        match cpu.run_host_slice(Duration::from_millis(10)).unwrap() {
            Some(VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            }) => {
                let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
                    unreachable!();
                };
                cpu.complete_io_in(&0u64.to_le_bytes());
                cpu.io_completion_result().unwrap();
                return (state.regs.x[20], state.regs.x[21]);
            }
            None => (),
            exit => panic!("unexpected clock probe exit: {exit:?}"),
        }
    }
    panic!("clock probe did not reach MMIO");
}

fn capture_shared_clock(vm: &Vmm) -> crate::backend::arm64_hvf_context::VtimerSnapshot {
    let boundary = vm.vm.checkpoint_boundary().unwrap();
    let shared = vm
        .vm
        .capture_checkpoint_vm_context(&boundary)
        .unwrap()
        .unwrap();
    GlobalContext::decode(&shared.data).unwrap().vtimer.unwrap()
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_virtual_counter_file_excludes_detached_and_first_entry_delay() {
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(2)).unwrap();
    psci::boot_native_secondaries(&mut source);
    // MRS X20,CNTVCT_EL0; MRS X21,CNTFRQ_EL0; LDR X0,[X7]; B back.
    let program = [0xd53b_e054u32, 0xd53b_e015, 0xf940_00e0, 0x17ff_fffd];
    for (index, word) in program.into_iter().enumerate() {
        source
            .guest_mem
            .memory()
            .write_slice(&word.to_le_bytes(), GuestAddress(CODE + index as u64 * 4))
            .unwrap();
    }
    publish_native_code(&source.guest_mem, CODE, program.len() * 4);
    let rates: Vec<_> = source
        .vcpus
        .iter_mut()
        .map(|cpu| {
            let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
                unreachable!();
            };
            state.regs.pc = CODE;
            state.regs.pstate = 0x3c5;
            state.regs.x[7] = UART;
            cpu.set_state(&CpuState::Aarch64(state)).unwrap();
            read_guest_counter(&mut **cpu).1
        })
        .collect();
    assert!(rates[0] > 0);
    assert_eq!(rates[0], rates[1]);

    let capture_start = mach::now();
    let saved = source.take_snapshot_bundle(0).unwrap();
    let capture_end = mach::now();
    let offsets: Vec<_> = saved
        .backend_contexts()
        .unwrap()
        .entries()
        .iter()
        .map(|record| {
            Context::decode(&record.as_ref().unwrap().data)
                .unwrap()
                .controls
                .vtimer_offset
        })
        .collect();
    saved.save(&fixture.checkpoint).unwrap();
    drop(saved);
    drop(source);
    std::thread::sleep(Duration::from_millis(250));

    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    let clock = GlobalContext::decode(&loaded.vm_context().unwrap().data)
        .unwrap()
        .vtimer
        .unwrap();
    assert!(!clock.waiting_for_entry);
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    std::thread::sleep(Duration::from_millis(250));
    let waiting = capture_shared_clock(&target);
    assert!(waiting.waiting_for_entry);
    assert_eq!(waiting.tick, clock.tick);
    assert_eq!(waiting.timebase, clock.timebase);

    let first_start = mach::now();
    let first = read_guest_counter(&mut *target.vcpus[0]);
    let first_end = mach::now();
    // A late peer still shares the first owner's resume anchor.
    std::thread::sleep(Duration::from_millis(100));
    let second_start = mach::now();
    let second = read_guest_counter(&mut *target.vcpus[1]);
    let second_end = mach::now();
    let normalized_first = first.0.wrapping_add(offsets[0]);
    let normalized_second = second.0.wrapping_add(offsets[1]);
    let peer_elapsed = normalized_second.wrapping_sub(normalized_first);
    assert!((second_start - first_end..=second_end - first_start).contains(&peer_elapsed));
    let resumed = capture_shared_clock(&target);
    assert!(!resumed.waiting_for_entry);
    assert!(resumed.tick >= normalized_second);
    for (id, ((count, rate), entry_start, entry_end)) in [
        (first, first_start, first_end),
        (second, second_start, second_end),
    ]
    .into_iter()
    .enumerate()
    {
        let earliest = capture_start
            .wrapping_sub(offsets[id])
            .wrapping_add(entry_start.saturating_sub(first_end));
        let latest = capture_end
            .wrapping_sub(offsets[id])
            .wrapping_add(entry_end - first_start);
        assert_eq!(rate, rates[id]);
        assert!(
            count.wrapping_sub(earliest) <= latest.wrapping_sub(earliest),
            "CPU {id} counter {count} outside resumed interval {earliest}..={latest} ticks"
        );
        eprintln!("CPU {id} counter {count} within {earliest}..={latest} ticks at {rate} Hz");
    }
}
