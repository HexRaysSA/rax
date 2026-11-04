mod error {
    pub use rax::error::{Error, Result};
}
#[path = "identity.rs"]
pub(crate) mod actual_identity;
mod isa {
    pub(crate) mod x86_64 {
        pub(crate) use crate::actual_identity as identity;
    }
}
mod cpuid;
mod cpuid_apic;

mod checkpoint {
    mod msrs;
    use kvm_bindings::{CpuId, Msrs, kvm_msr_entry};
    use msrs::{Image, Plan};
    use rax::backend::{
        Backend, Vm,
        kvm::{KvmBackend, KvmVm, OwnedVcpuFd},
    };
    use rax::vm::memory::GuestMemoryWrapper;

    struct Graph {
        cpus: Vec<OwnedVcpuFd>,
        plans: Vec<Plan>,
        _memory: GuestMemoryWrapper,
        _vm: Box<dyn Vm>,
    }

    fn graph(count: u8, irqchip: bool) -> Graph {
        let backend = KvmBackend::new().unwrap();
        let vm = backend.create_vm().unwrap();
        vm.configure_cpu_topology(count, 2 * 1024 * 1024).unwrap();
        let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
        if irqchip {
            native.create_irq_chip().unwrap();
        }
        let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
        native.register_memory(&memory).unwrap();
        let supported = native
            .kvm()
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let topology = crate::cpuid::Topology::new(count).unwrap();
        let mut cpus = Vec::new();
        let mut plans = Vec::new();
        for id in 0..count {
            let mut guest: CpuId = topology.project(&supported, u32::from(id)).unwrap();
            crate::cpuid_apic::admit(
                &mut guest,
                irqchip,
                native
                    .kvm()
                    .check_extension(kvm_ioctls::Cap::TscDeadlineTimer),
            );
            let cpu = native.create_vcpu_fd(u64::from(id)).unwrap();
            cpu.set_cpuid2(&guest).unwrap();
            let plan = Plan::capture(native.kvm(), &guest, irqchip).unwrap();
            assert!(!plan.indices().contains(&0x10));
            assert!(!plan.indices().contains(&0x4000_0020));
            let async_feature = guest
                .as_slice()
                .iter()
                .any(|e| e.function == 0x4000_0001 && e.eax & (1 << 14) != 0);
            assert_eq!(
                plan.indices().contains(&0x4b56_4d06),
                irqchip && async_feature
            );
            cpus.push(cpu);
            plans.push(plan);
        }
        Graph {
            cpus,
            plans,
            _memory: memory,
            _vm: vm,
        }
    }

    fn write(cpu: &kvm_ioctls::VcpuFd, index: u32, value: u64) {
        let table = Msrs::from_entries(&[kvm_msr_entry {
            index,
            data: value,
            ..Default::default()
        }])
        .unwrap();
        assert_eq!(cpu.set_msrs(&table).unwrap(), 1, "index={index:#x}");
    }

    fn seed(graph: &Graph) {
        for (id, (cpu, plan)) in graph.cpus.iter().zip(&graph.plans).enumerate() {
            let id = id as u64;
            for (index, value) in [
                (0xc000_0102, 0x1122_3344_5000 + id * 0x100),
                (0xc000_0103, 0x1234_0000 + id),
                (0xc000_0081, 0x0033_0023_0000_0000),
                (0xc000_0082, 0x1234_5678_9000 + id * 0x10),
                (0xc000_0083, 0x2345_6789_a000 + id * 0x10),
                (0xc000_0084, 0x0044_7700),
                (0x174, 0x10 + id * 8),
                (0x175, 0x2345_6000 + id * 0x100),
                (0x176, 0x1234_5000 + id * 0x100),
            ] {
                assert!(
                    plan.indices().contains(&index),
                    "missing seed index={index:#x}"
                );
                write(cpu, index, value);
            }
            if plan.indices().contains(&0x4b56_4d06) {
                write(cpu, 0x4b56_4d06, 0x40 + id);
            }
            // Real registered guest pages back the paravirtual MSR caches.
            if plan.indices().contains(&0x4b56_4d02) {
                write(cpu, 0x4b56_4d02, 0x2001);
            }
            assert!(plan.indices().contains(&0x4b56_4d04));
            write(cpu, 0x4b56_4d04, 0x3001);
        }
    }

    pub(super) fn exercise() {
        for irqchip in [false, true] {
            for count in [1, 2, 4] {
                // Only owned integer records and plans leave this block.
                // Every source CPU, VM, run mapping and backing owner closes
                // before the fresh destination graph is constructed.
                let (images, plans) = {
                    let source = graph(count, irqchip);
                    seed(&source);
                    let mut images = Vec::new();
                    for (cpu, plan) in source.cpus.iter().zip(&source.plans) {
                        let image = Image::capture(cpu, plan).unwrap();
                        let wire = rax::codec::serialize(&image).unwrap();
                        let decoded: Image = rax::codec::deserialize(&wire).unwrap();
                        assert_eq!(image, decoded);
                        assert_eq!(
                            Image::from_parts(
                                image.registers().to_vec(),
                                image.counters().to_vec(),
                                plan
                            )
                            .unwrap(),
                            image
                        );
                        images.push(decoded);
                    }
                    (images, source.plans.clone())
                };
                let destination = graph(count, irqchip);
                assert_eq!(plans, destination.plans);
                for ((cpu, plan), image) in
                    destination.cpus.iter().zip(&destination.plans).zip(&images)
                {
                    image.restore_stored_registers(cpu, plan).unwrap();
                    assert_eq!(
                        Image::capture(cpu, plan).unwrap().registers(),
                        image.registers()
                    );
                }
                let mut rejected = 0;
                for ((cpu, plan), image) in
                    destination.cpus.iter().zip(&destination.plans).zip(&images)
                {
                    let original = serde_json::to_value(image).unwrap();
                    for case in 0..8 {
                        let mut bad = original.clone();
                        let field = if case < 4 { "registers" } else { "counters" };
                        let entries = bad[field].as_array_mut().unwrap();
                        assert!(entries.len() > 2);
                        match case % 4 {
                            0 => {
                                entries.pop();
                            }
                            1 => {
                                entries.push(entries[0].clone());
                            }
                            2 => {
                                entries.swap(0, 1);
                            }
                            3 => {
                                entries[0]["index"] = serde_json::json!(0xffff_ffffu32);
                            }
                            _ => unreachable!(),
                        }
                        let bad: Image = serde_json::from_value(bad).unwrap();
                        assert!(bad.restore_stored_registers(cpu, plan).is_err());
                        assert_eq!(
                            Image::capture(cpu, plan).unwrap().registers(),
                            image.registers()
                        );
                        rejected += 1;
                    }
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "count":count,"irqchip":irqchip,"source_destroyed_before_destination":true,
                        "entries_per_cpu":plans[0].indices().len(),"restored_cpu_banks":images.len(),
                        "stored_bank_exact_readback":true,"clock_counters_retained_per_cpu":images[0].counters().len(),"clock_restore_complete":false,"nonzero_seed_indices":10 + 2 * u32::from(irqchip),
                        "malformed_records_rejected_without_bank_changes":rejected,
                        "images":images,
                        "scope":"Actual RAX-owned native SDK CPU graphs and actual profile/admission source; Selected migration-MSR capture, stored-register restoration, and raw clock counter retention only. No guest entered. Coordinated clock restoration, other CPU banks, shared controllers, in-flight completion and the full producer remain required."
                    })
                );
            }
        }
    }
}

fn main() {
    checkpoint::exercise();
}
