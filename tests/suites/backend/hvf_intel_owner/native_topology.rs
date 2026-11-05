//! Real owner CPUID dispatch with modeled SDK exits; no guest instruction runs.
use super::*;
use rax::vm::vcpu::{VCpu, VcpuExit};
use std::time::Duration;

fn query(cpu: &mut dyn VCpu, native_id: u32, leaf: u32, subleaf: u32) -> [u32; 4] {
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&native_id).unwrap();
        native.registers.insert(0, 0x1000);
        native.registers.insert(2, u64::from(leaf));
        native.registers.insert(3, u64::from(subleaf));
        native.vmcs.insert(0x440c, 2);
        native.exits = [10, 0x8000_0021].into_iter().collect();
    }
    assert!(matches!(
        cpu.run_host_slice(Duration::from_secs(1)).unwrap(),
        Some(VcpuExit::FailEntry {
            reason: 0x8000_0021
        })
    ));
    let sdk = SDK.lock().unwrap();
    let registers = &sdk.cpus[&native_id].registers;
    assert_eq!(registers[&0], 0x1002);
    [2, 5, 3, 4].map(|id| registers[&id] as u32)
}

#[test]
fn configured_topology_matches_cpu_count_and_apic_domains() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SDM CPUID.4 has six bits for package cores minus one. Above64 CPUs,
    // use additional packages; the last package may be partly populated.
    for (count, cores, shift) in [
        (1u8, 1, 0),
        (2, 2, 1),
        (3, 3, 2),
        (4, 4, 2),
        (31, 31, 5),
        (32, 32, 5),
        (33, 33, 6),
        (63, 63, 6),
        (64, 64, 6),
        (65, 64, 6),
        (127, 64, 6),
        (128, 64, 6),
        (129, 64, 6),
        (254, 64, 6),
        (255, 64, 6),
    ] {
        let (vm, memory) = fixture();
        vm.configure_cpu_topology(count, 0x4000).unwrap();
        let mut ids = vec![0, u32::from(count) - 1];
        ids.sort_unstable();
        ids.dedup();
        for (native_id, id) in ids.into_iter().enumerate() {
            let mut cpu = vm
                .create_vcpu(id, Arc::new(memory.memory().clone()))
                .unwrap();
            let native_id = native_id as u32;
            let legacy = query(cpu.as_mut(), native_id, 1, 0);
            assert_eq!((legacy[1] >> 16) & 255, cores, "count={count} id={id}");
            assert_eq!(legacy[1] >> 24, id);
            assert_eq!((legacy[3] >> 28) & 1, u32::from(cores > 1));
            assert_eq!(query(cpu.as_mut(), native_id, 0xb, 0), [0, 1, 0x100, id]);
            assert_eq!(
                query(cpu.as_mut(), native_id, 0xb, 1),
                [shift, cores, 0x201, id]
            );
            for subleaf in [2, 3, 255, 256, u32::MAX] {
                assert_eq!(
                    query(cpu.as_mut(), native_id, 0xb, subleaf),
                    [0, 0, subleaf & 255, id]
                );
            }
            for subleaf in 0..4 {
                let cache = query(cpu.as_mut(), native_id, 4, subleaf);
                assert_eq!((cache[0] >> 26) + 1, cores);
                assert_eq!(
                    ((cache[0] >> 14) & 0xfff) + 1,
                    if subleaf == 3 { cores } else { 1 }
                );
            }
            assert_eq!(query(cpu.as_mut(), native_id, 4, 4), [0; 4]);
            // The existing profile advertises max_basic=0x16, so leaf1f
            // remains unavailable rather than introducing a new feature.
            assert_eq!(query(cpu.as_mut(), native_id, 0x1f, 0), [0; 4]);
        }
        assert_eq!(SDK.lock().unwrap().wrong_owner, 0);
    }
}

#[test]
fn unconfigured_sdk_consumers_keep_their_existing_cpuid_geometry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(117, Arc::new(memory.memory().clone()))
        .unwrap();
    let legacy = query(cpu.as_mut(), 0, 1, 0);
    assert_eq!(legacy[1], (117 << 24) | 0x0001_0800);
    assert_ne!(legacy[3] & (1 << 28), 0);
    assert_eq!(query(cpu.as_mut(), 0, 0xb, 0), [1, 1, 0x100, 117]);
    assert_eq!(query(cpu.as_mut(), 0, 0xb, 1), [4, 1, 0x201, 117]);
    assert_eq!(query(cpu.as_mut(), 0, 4, 0)[0], 0x1c00_4121);
}

#[test]
fn shared_restore_and_rollback_preserve_the_captured_cpuid_policy() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    vm.configure_cpu_topology(2, 0x4000).unwrap();
    let cpu0 = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let mut cpu1 = vm
        .create_vcpu(1, Arc::new(memory.memory().clone()))
        .unwrap();
    assert_eq!(query(cpu1.as_mut(), 1, 0xb, 1), [1, 2, 0x201, 1]);
    let configured = {
        let boundary = vm.checkpoint_boundary().unwrap();
        vm.capture_checkpoint_vm_context(&boundary)
            .unwrap()
            .unwrap()
    };
    assert_eq!(&configured.data[..8], b"RAXHVG03");
    let mut legacy = configured.clone();
    legacy.data[..8].copy_from_slice(b"RAXHVG02");
    for tag in [b"RAXHVG01", b"RAXHVG02"] {
        legacy.data[..8].copy_from_slice(tag);
        {
            let boundary = vm.checkpoint_boundary().unwrap();
            vm.restore_checkpoint_vm_context(&boundary, Some(&legacy))
                .unwrap();
            let captured = vm
                .capture_checkpoint_vm_context(&boundary)
                .unwrap()
                .unwrap();
            assert_eq!(&captured.data[..8], b"RAXHVG02");
            assert_eq!(&captured.data[8..], &legacy.data[8..]);
        }
        assert_eq!(query(cpu1.as_mut(), 1, 0xb, 1), [4, 1, 0x201, 1]);
        {
            let boundary = vm.checkpoint_boundary().unwrap();
            vm.rollback_checkpoint_vm_context(&boundary, Some(&configured))
                .unwrap();
        }
        assert_eq!(query(cpu1.as_mut(), 1, 0xb, 1), [1, 2, 0x201, 1]);
    }
    // Rollback must also restore legacy geometry when it is the destination's
    // original policy, rather than treating rollback as a cold-boot default.
    {
        let boundary = vm.checkpoint_boundary().unwrap();
        vm.restore_checkpoint_vm_context(&boundary, Some(&configured))
            .unwrap();
        vm.rollback_checkpoint_vm_context(&boundary, Some(&legacy))
            .unwrap();
    }
    assert_eq!(query(cpu1.as_mut(), 1, 0xb, 1), [4, 1, 0x201, 1]);
    drop(cpu1);
    drop(cpu0);
    assert_eq!(SDK.lock().unwrap().wrong_owner, 0);
}

#[test]
fn configured_policy_cannot_restore_to_an_unconfigured_sdk_vm() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    {
        let boundary = vm.checkpoint_boundary().unwrap();
        let mut record = vm
            .capture_checkpoint_vm_context(&boundary)
            .unwrap()
            .unwrap();
        assert_eq!(&record.data[..8], b"RAXHVG02");
        record.data[..8].copy_from_slice(b"RAXHVG03");
        assert!(
            vm.restore_checkpoint_vm_context(&boundary, Some(&record))
                .is_err()
        );
        assert_eq!(
            &vm.capture_checkpoint_vm_context(&boundary)
                .unwrap()
                .unwrap()
                .data[..8],
            b"RAXHVG02"
        );
    }
    assert_eq!(query(cpu.as_mut(), 0, 0xb, 0), [1, 1, 0x100, 0]);
}
