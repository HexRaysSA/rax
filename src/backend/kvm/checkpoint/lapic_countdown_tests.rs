//! A restored local APIC countdown must start at managed first entry.
use super::{Image, exit, first_entry, graph, lock_cpus, native, stored_cpu_banks};
use crate::vm::vcpu::{VCpu, VcpuExit};
use kvm_bindings::kvm_lapic_state;
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};

const INITIAL_COUNT: u32 = 600_000_000;
const TIMER_VECTOR: u8 = 0x41;
const TIMER_MARKER: u8 = 0xa1;

fn put_register(lapic: &mut kvm_lapic_state, offset: usize, value: u32) {
    lapic.regs[offset..offset + 4].copy_from_slice(&value.to_le_bytes().map(|byte| byte as i8));
}

fn captured_count(image: &Image, index: usize) -> u32 {
    let cpus = stored_cpu_banks(image);
    let bytes = cpus[index]["lapic"]["bytes"].as_array().unwrap();
    u32::from_le_bytes(std::array::from_fn(|i| {
        u8::try_from(bytes[0x390 + i].as_u64().unwrap()).unwrap()
    }))
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
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn restored_countdown_excludes_stopped_time_for_one_shot_and_periodic_vcpus() {
    for (periodic, x2apic) in [(false, false), (true, true)] {
        for count in [1, 2, 4] {
            let index = usize::from(count - 1);
            let (source, memory, cpus) = graph(count, true);
            let source_vm = native(&*source);
            let boundary = source.checkpoint_boundary().unwrap();
            let handles = source_vm.checkpoint_cpu_handles(&boundary).unwrap();
            {
                let cores = lock_cpus(source_vm, &handles).unwrap();
                let cpu = &cores[index].vcpu_fd;
                let mut regs = cpu.get_regs().unwrap();
                let mut special = cpu.get_sregs().unwrap();
                regs.rflags |= 1 << 9;
                regs.rsp = 0x9000;
                if x2apic {
                    special.apic_base |= 1 << 10;
                }
                cpu.set_sregs(&special).unwrap();
                cpu.set_regs(&regs).unwrap();
                let mut lapic = cpu.get_lapic().unwrap();
                put_register(&mut lapic, 0xf0, 0x1ff);
                put_register(
                    &mut lapic,
                    0x320,
                    (u32::from(periodic) << 17) | u32::from(TIMER_VECTOR),
                );
                put_register(&mut lapic, 0x380, INITIAL_COUNT);
                put_register(&mut lapic, 0x390, INITIAL_COUNT);
                put_register(&mut lapic, 0x3e0, 0xb); // Divide by one.
                cpu.set_lapic(&lapic).unwrap();
            }
            let image = source_vm.capture_native_banks(&boundary).unwrap();
            let expected = captured_count(&image, index);
            assert!((INITIAL_COUNT / 2..INITIAL_COUNT).contains(&expected));
            let encoded = crate::codec::serialize(&image).unwrap();
            drop(boundary);
            drop(handles);
            drop(cpus);
            drop(source);
            drop(memory);
            let image: Image = crate::codec::deserialize_strict(&encoded).unwrap();

            let (target, memory, mut cpus) = graph(count, true);
            if periodic {
                // Wake from HLT and return to the same wait after every IRQ.
                memory
                    .memory()
                    .write_slice(&[0xf4, 0xeb, 0xfd], GuestAddress(0x1002))
                    .unwrap();
            }
            memory
                .memory()
                .write_obj(0x2000_u32, GuestAddress(u64::from(TIMER_VECTOR) * 4))
                .unwrap();
            // OUT marker; for the periodic profile, issue x2APIC EOI and IRET.
            let handler = if periodic {
                &[
                    0xb0,
                    TIMER_MARKER,
                    0xe6,
                    0xe9,
                    0x66,
                    0xb9,
                    0x0b,
                    0x08,
                    0,
                    0,
                    0x66,
                    0x31,
                    0xc0,
                    0x66,
                    0x31,
                    0xd2,
                    0x0f,
                    0x30,
                    0xcf,
                ][..]
            } else {
                &[0xb0, TIMER_MARKER, 0xe6, 0xe9, 0xf4]
            };
            memory
                .memory()
                .write_slice(handler, GuestAddress(0x2000))
                .unwrap();
            let target_vm = native(&*target);
            let boundary = target.checkpoint_boundary().unwrap();
            image.restore_stored(target_vm, &boundary).unwrap();
            // Include a delay before the explicit clock stage, as RAM and
            // device publication can take place between these two operations.
            std::thread::sleep(Duration::from_millis(700));
            image.stage_resume_clock(target_vm, &boundary).unwrap();
            let recapture = target_vm.capture_native_banks(&boundary).unwrap();
            assert_eq!(
                captured_count(&recapture, index),
                expected,
                "stopped countdown changed before entry"
            );
            drop(boundary);

            assert_output(&mut *cpus[index], 0x21 + index as u8);
            for (peer, cpu) in cpus.iter_mut().enumerate().take(index) {
                assert_output(&mut **cpu, 0x21 + peer as u8);
            }
            assert_output(&mut *cpus[index], TIMER_MARKER);
            if periodic {
                assert_output(&mut *cpus[index], TIMER_MARKER);
            }
        }
    }
}
