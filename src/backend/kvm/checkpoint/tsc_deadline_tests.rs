//! Restore an armed LAPIC TSC deadline at the managed first-entry gate.
use super::{Image, exit, first_entry, graph, lock_cpus, native, stored_cpu_banks};
use crate::vm::memory::GuestMemoryWrapper;
use crate::vm::vcpu::{VCpu, VcpuExit};
use kvm_bindings::{Msrs, kvm_msr_entry};
use kvm_ioctls::VcpuFd;
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};

const TSC: u32 = 0x10;
const TSC_DEADLINE: u32 = 0x6e0;
const TIMER_VECTOR: u8 = 0x41;
const TIMER_MARKER: u8 = 0xa1;
const TIMER_DELAY_MS: u64 = 600;

fn write_msr(cpu: &VcpuFd, index: u32, data: u64) {
    let entry = kvm_msr_entry {
        index,
        data,
        ..Default::default()
    };
    assert_eq!(
        cpu.set_msrs(&Msrs::from_entries(&[entry]).unwrap())
            .unwrap(),
        1
    );
}

fn read_msr(cpu: &VcpuFd, index: u32) -> u64 {
    let entry = kvm_msr_entry {
        index,
        ..Default::default()
    };
    let mut values = Msrs::from_entries(&[entry]).unwrap();
    assert_eq!(cpu.get_msrs(&mut values).unwrap(), 1);
    values.as_slice()[0].data
}

fn recorded_deadline(image: &Image, index: usize) -> u64 {
    stored_cpu_banks(image)[index]["msrs"]["registers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["index"].as_u64() == Some(u64::from(TSC_DEADLINE)))
        .and_then(|entry| entry["value"].as_u64())
        .expect("native checkpoint omitted its LAPIC deadline MSR")
}

fn install_guest_timer(memory: &GuestMemoryWrapper) {
    memory
        .memory()
        .write_slice(
            &0x2000_u32.to_le_bytes(),
            GuestAddress(u64::from(TIMER_VECTOR) * 4),
        )
        .unwrap();
    memory
        .memory()
        .write_slice(
            &[0xb0, TIMER_MARKER, 0xe6, 0xe9, 0xf4],
            GuestAddress(0x2000),
        )
        .unwrap();
}

fn assert_output(cpu: &mut dyn VCpu, expected: u8) {
    let event = exit(cpu);
    assert!(
        matches!(&event, VcpuExit::IoOut { port: 0xe9, data } if data == &[expected]),
        "unexpected guest frontier {event:?}"
    );
    first_entry::acknowledge(cpu);
}

#[test]
#[ignore = "requires physical Linux KVM"]
fn armed_deadline_keeps_its_vcpu_and_waits_for_the_restored_clock() {
    for count in [1, 2, 4] {
        let index = usize::from(count - 1);
        let (source, memory, cpus) = graph(count, true);
        let native_source = native(&*source);
        let boundary = source.checkpoint_boundary().unwrap();
        let handles = native_source.checkpoint_cpu_handles(&boundary).unwrap();
        let deadline = {
            let mut cores = lock_cpus(native_source, &handles).unwrap();
            let cpu = &mut cores[index].vcpu_fd;
            let mut regs = cpu.get_regs().unwrap();
            regs.rflags |= 1 << 9;
            regs.rsp = 0x9000;
            cpu.set_regs(&regs).unwrap();
            let mut lapic = cpu.get_lapic().unwrap();
            lapic.regs[0xf0..0xf4].copy_from_slice(&0x1ff_u32.to_le_bytes().map(|byte| byte as i8));
            let lvtt = (2 << 17) | u32::from(TIMER_VECTOR);
            lapic.regs[0x320..0x324].copy_from_slice(&lvtt.to_le_bytes().map(|byte| byte as i8));
            cpu.set_lapic(&lapic).unwrap();
            let cycles_per_ms = u64::from(cpu.get_tsc_khz().unwrap());
            let deadline = read_msr(cpu, TSC) + cycles_per_ms * TIMER_DELAY_MS;
            write_msr(cpu, TSC_DEADLINE, deadline);
            assert_eq!(read_msr(cpu, TSC_DEADLINE), deadline);
            deadline
        };
        let image = native_source.capture_native_banks(&boundary).unwrap();
        assert_eq!(recorded_deadline(&image, index), deadline);
        let encoded = crate::codec::serialize(&image).unwrap();
        drop(boundary);
        drop(handles);
        drop(cpus);
        drop(source);
        drop(memory);
        let image: Image = crate::codec::deserialize_strict(&encoded).unwrap();

        let (target, memory, mut cpus) = graph(count, true);
        install_guest_timer(&memory);
        let native_target = native(&*target);
        let boundary = target.checkpoint_boundary().unwrap();
        let handles = native_target.checkpoint_cpu_handles(&boundary).unwrap();
        {
            // The destination's old clock would treat the saved deadline as expired.
            let core = handles[index].lock().unwrap();
            write_msr(&core.vcpu_fd, TSC, deadline + (1 << 34));
            assert!(read_msr(&core.vcpu_fd, TSC) > deadline);
        }
        image.restore_stored(native_target, &boundary).unwrap();
        image.stage_resume_clock(native_target, &boundary).unwrap();
        std::thread::sleep(Duration::from_millis(TIMER_DELAY_MS + 100));
        assert_eq!(
            recorded_deadline(
                &native_target.capture_native_banks(&boundary).unwrap(),
                index
            ),
            deadline,
        );
        assert_eq!(
            read_msr(&handles[index].lock().unwrap().vcpu_fd, TSC_DEADLINE),
            0
        );
        drop(boundary);

        // The last CPU consumes the common clock. Its ordinary output must
        // precede the IRQ, even after waiting beyond the saved timer interval.
        assert_output(&mut *cpus[index], 0x21 + index as u8);
        for (peer, cpu) in cpus.iter_mut().enumerate().take(index) {
            assert_output(&mut **cpu, 0x21 + peer as u8);
        }
        assert_output(&mut *cpus[index], TIMER_MARKER);
    }
}
