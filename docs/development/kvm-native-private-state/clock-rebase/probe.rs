mod bank;
mod clock;
mod codec;

use kvm_bindings::kvm_device_attr;
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

struct Graph {
    cpus: Vec<VcpuFd>,
    vm: VmFd,
    _kvm: Kvm,
}

impl Graph {
    fn new(count: u32, irqchip: bool) -> Self {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        if irqchip {
            vm.create_irq_chip().unwrap();
        }
        let cpus = (0..count)
            .map(|id| vm.create_vcpu(u64::from(id)).unwrap())
            .collect();
        Self {
            cpus,
            vm,
            _kvm: kvm,
        }
    }

    fn references(&self) -> Vec<(u32, &VcpuFd)> {
        self.cpus
            .iter()
            .enumerate()
            .map(|(id, cpu)| (id as u32, cpu))
            .collect()
    }

    fn offsets(&self) -> Vec<u64> {
        self.cpus.iter().map(|cpu| offset(cpu, None)).collect()
    }
}

fn host_tsc() -> u64 {
    // SAFETY: this probe runs on native x86-64 with permitted user TSC reads.
    // SSE2/RDTSC are baseline; fences order the sample without touching memory.
    unsafe {
        std::arch::x86_64::_mm_lfence();
        let value = std::arch::x86_64::_rdtsc();
        std::arch::x86_64::_mm_lfence();
        value
    }
}

fn offset(cpu: &VcpuFd, desired: Option<u64>) -> u64 {
    let mut value = desired.unwrap_or(0);
    let attr = kvm_device_attr {
        group: kvm_bindings::KVM_VCPU_TSC_CTRL,
        attr: u64::from(kvm_bindings::KVM_VCPU_TSC_OFFSET),
        addr: (&mut value as *mut u64) as u64,
        flags: 0,
    };
    let request = if desired.is_some() {
        libc::_IOW::<kvm_device_attr>(kvm_bindings::KVMIO, 0xe1)
    } else {
        libc::_IOW::<kvm_device_attr>(kvm_bindings::KVMIO, 0xe2)
    };
    // SAFETY: the retained native UAPI selects the initialized u64 attribute.
    // Descriptor, attribute and aligned exclusive value remain live for the
    // synchronous copy; no guest runs and the kernel retains no pointer.
    assert_eq!(unsafe { libc::ioctl(cpu.as_raw_fd(), request, &attr) }, 0);
    value
}

fn altered(value: &serde_json::Value, case: usize) -> serde_json::Value {
    let mut value = value.clone();
    match case {
        0 => value["version"] = serde_json::json!(2),
        1 => {
            value["clock_before"] = serde_json::json!(u64::MAX);
            value["anchor"] = serde_json::json!(0);
        }
        2 => value["cpus"] = serde_json::json!([]),
        3 => value["cpus"] = serde_json::json!(vec![value["cpus"][0].clone(); 256]),
        4 => {
            value["cpus"] = serde_json::json!([value["cpus"][0], value["cpus"][0]]);
        }
        5 => value["cpus"][0]["id"] = serde_json::json!(1000),
        6 => value["cpus"][0]["khz"] = serde_json::json!(0),
        7 => {
            let khz = value["cpus"][0]["khz"].as_u64().unwrap();
            value["cpus"][0]["khz"] = serde_json::json!(khz + 1);
        }
        8 => value["clock"]["kind"] = serde_json::json!(1),
        9 => {
            value["clock"]["bytes"].as_array_mut().unwrap().pop();
        }
        10 => value["unrecognized"] = serde_json::json!(0),
        11 => value["clock"]["bytes"][8] = serde_json::json!(128),
        _ => unreachable!(),
    }
    value
}

fn main() {
    for irqchip in [false, true] {
        for count in [1u32, 2, 4] {
            let (image, original_offsets, khz) = {
                let source = Graph::new(count, irqchip);
                let khz = source.cpus[0].get_tsc_khz().unwrap();
                let anchor = host_tsc();
                for (id, cpu) in &source.references() {
                    let phase = 0x1_2345_6789u64 + u64::from(*id) * 0x4_0000_0000;
                    offset(cpu, Some(phase.wrapping_sub(anchor)));
                }
                source
                    .vm
                    .set_clock(&kvm_bindings::kvm_clock_data {
                        clock: 10_000_000_000,
                        ..Default::default()
                    })
                    .unwrap();
                let image = clock::Image::capture(&source.vm, &source.references(), khz).unwrap();
                let offsets = source.offsets();
                drop(source);
                (image, offsets, khz)
            };
            let value = serde_json::to_value(&image).unwrap();
            let binary = codec::serialize(&image).unwrap();
            let mut restored = 0;
            let mut rejected = 0;
            for decoded in [
                serde_json::from_value::<clock::Image>(value.clone()).unwrap(),
                codec::deserialize_limited::<clock::Image, 8192>(&binary).unwrap(),
            ] {
                assert_eq!(decoded, image);
                let target = Graph::new(count, irqchip);
                let references = target.references();
                let before = target.offsets();
                for case in 0..12 {
                    match serde_json::from_value::<clock::Image>(altered(&value, case)) {
                        Err(_) => {}
                        Ok(bad) => assert!(
                            bad.restore_at_resume(&target.vm, &references, khz).is_err(),
                            "malformed case {case}"
                        ),
                    }
                    assert_eq!(target.offsets(), before);
                    rejected += 1;
                }
                assert!(
                    decoded
                        .restore_at_resume(&target.vm, &references[..references.len() - 1], khz)
                        .is_err()
                );
                assert!(
                    decoded
                        .restore_at_resume(&target.vm, &references, khz + 1)
                        .is_err()
                );
                assert_eq!(target.offsets(), before);
                rejected += 2;

                // The bank's 12-byte header and fixed payload precede two
                // u64 samples and the CPU sequence's u64 length. Exercise the
                // actual legacy codec's size hint before it allocates CPUs.
                let count_at = 30 + std::mem::size_of::<kvm_bindings::kvm_clock_data>();
                assert_eq!(binary.len(), count_at + 8 + count as usize * 16);
                for case in 0..5 {
                    let mut bad = binary.clone();
                    match case {
                        0 => bad[count_at..count_at + 8].copy_from_slice(&u64::MAX.to_le_bytes()),
                        1 => bad[count_at..count_at + 8].copy_from_slice(&256u64.to_le_bytes()),
                        2 => {
                            bad[count_at..count_at + 8].copy_from_slice(&0u64.to_le_bytes());
                            bad.truncate(count_at + 8);
                        }
                        3 => bad[..2].copy_from_slice(&2u16.to_le_bytes()),
                        4 => bad.push(0),
                        _ => unreachable!(),
                    }
                    match codec::deserialize_limited::<clock::Image, 8192>(&bad) {
                        Err(_) => {}
                        Ok(bad) => {
                            assert!(bad.restore_at_resume(&target.vm, &references, khz).is_err())
                        }
                    }
                    assert_eq!(target.offsets(), before);
                    rejected += 1;
                }

                // Deliberate offline time must not be added to the VM clock.
                std::thread::sleep(Duration::from_millis(20));
                let started = Instant::now();
                let applied = decoded
                    .restore_at_resume(&target.vm, &references, khz)
                    .unwrap();
                let observed_clock = target.vm.get_clock().unwrap();
                let elapsed_ns = started.elapsed().as_nanos() as u64;
                let saved_clock = decoded.captured_clock_ns().unwrap();
                assert!(observed_clock.clock >= saved_clock);
                assert!(observed_clock.clock - saved_clock <= elapsed_ns + 1_000_000);
                assert!(applied.resume_tsc > 0);
                assert!(
                    applied.clock_publication_interval.1 >= applied.clock_publication_interval.0
                );
                assert!(applied.elapsed_while_rebasing_ns <= elapsed_ns + 1_000_000);
                let actual = target.offsets();
                for (id, (_, desired)) in applied.offsets.iter().enumerate() {
                    assert_eq!(actual[id], *desired);
                    assert_eq!(
                        actual[id].wrapping_sub(actual[0]),
                        original_offsets[id].wrapping_sub(original_offsets[0])
                    );
                    restored += 1;
                }
            }
            println!(
                "{}",
                serde_json::json!({
                    "cpu_count":count,"irqchip":irqchip,"source_graph_destroyed":true,
                    "source_free_exact_cpu_phases":restored,"malformed_or_target_controls":rejected,
                    "offsets_unchanged_after_rejection":true,"json_and_production_codec":true,
                    "offline_delay_ms_per_target":20,"clock_tolerance_ns":1000000,
                    "guest_entered":false,"complete_checkpoint_producer":false
                })
            );
        }
    }
}
