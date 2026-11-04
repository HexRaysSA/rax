mod bank;
mod codec;

use bank::{Bank, NativeType};
use kvm_bindings::{kvm_cpuid_entry2, kvm_pit_config};
use kvm_ioctls::Kvm;
use std::fmt::Debug;

trait Check {
    fn verify(&self) -> usize;
}

struct Fixture<T> {
    native: T,
    bank: Bank<T>,
}

fn reject<T: NativeType>(value: &serde_json::Value) -> bool {
    match serde_json::from_value::<Bank<T>>(value.clone()) {
        Err(_) => true,
        Ok(value) => value.decode().is_err(),
    }
}

fn reject_binary<T: NativeType>(value: &[u8]) -> bool {
    match codec::deserialize_limited::<Bank<T>, 8192>(value) {
        Err(_) => true,
        Ok(value) => value.decode().is_err(),
    }
}

impl<T: NativeType + PartialEq + Debug> Check for Fixture<T> {
    fn verify(&self) -> usize {
        let value = serde_json::to_value(&self.bank).unwrap();
        let decoded: Bank<T> = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded.decode().unwrap(), self.native);
        let encoded = codec::serialize(&self.bank).unwrap();
        assert_eq!(encoded.len(), 12 + std::mem::size_of::<T>());
        assert_eq!(&encoded[12..], self.native.as_bytes());
        let binary: Bank<T> = codec::deserialize_limited::<_, 8192>(&encoded).unwrap();
        assert_eq!(binary.decode().unwrap(), self.native);
        let mut rejected = 0;
        for case in 0..7 {
            let mut bad = value.clone();
            match case {
                0 => bad["version"] = serde_json::json!(2),
                1 => bad["kind"] = serde_json::json!(65535),
                2 => {
                    bad["bytes"].as_array_mut().unwrap().pop();
                }
                3 => bad["bytes"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!(0)),
                4 => bad["bytes"] = serde_json::json!([]),
                5 => bad["unknown"] = serde_json::json!(0),
                6 => bad["bytes"] = serde_json::json!(vec![0u8; 4097]),
                _ => unreachable!(),
            }
            assert!(reject::<T>(&bad), "JSON case={case}, kind={}", T::KIND);
            rejected += 1;
        }
        for case in 0..9 {
            let mut bad = encoded.clone();
            let size = std::mem::size_of::<T>();
            match case {
                0 => {
                    bad.pop();
                }
                1 => {
                    bad[4..12].copy_from_slice(&((size + 1) as u64).to_le_bytes());
                    bad.push(0);
                }
                2 => {
                    bad[4..12].copy_from_slice(&((size - 1) as u64).to_le_bytes());
                    bad.pop();
                }
                3 => bad[..2].copy_from_slice(&2u16.to_le_bytes()),
                4 => bad[2..4].copy_from_slice(&65535u16.to_le_bytes()),
                5 => bad[4..12].copy_from_slice(&u64::MAX.to_le_bytes()),
                6 => {
                    bad[4..12].copy_from_slice(&4097u64.to_le_bytes());
                    bad.resize(12 + 4097, 0);
                }
                7 => bad.push(0),
                8 => {
                    bad[4..12].copy_from_slice(&0u64.to_le_bytes());
                    bad.truncate(12);
                }
                _ => unreachable!(),
            }
            assert!(
                reject_binary::<T>(&bad),
                "binary case={case}, kind={}",
                T::KIND
            );
            rejected += 1;
        }
        rejected
    }
}

fn fixture<T: NativeType + PartialEq + Debug + 'static>(value: T) -> Box<dyn Check> {
    Box::new(Fixture {
        bank: Bank::capture(&value).unwrap(),
        native: value,
    })
}

fn main() {
    // This is the SDK's documented compatibility normalization, without any
    // native setter. The checkpoint bank must reject these lengths instead.
    let empty = codec::serialize(&Vec::<u8>::new()).unwrap();
    let sdk_empty: kvm_bindings::kvm_regs = codec::deserialize_limited::<_, 4096>(&empty).unwrap();
    assert_eq!(sdk_empty, kvm_bindings::kvm_regs::default());
    let overlong = codec::serialize(&vec![0u8; 145]).unwrap();
    let sdk_overlong: kvm_bindings::kvm_regs =
        codec::deserialize_limited::<_, 4096>(&overlong).unwrap();
    assert_eq!(sdk_overlong, kvm_bindings::kvm_regs::default());
    for irqchip in [false, true] {
        for count in [1u32, 2, 4] {
            let checks = {
                let kvm = Kvm::new().unwrap();
                let vm = kvm.create_vm().unwrap();
                if irqchip {
                    vm.create_irq_chip().unwrap();
                    vm.create_pit2(kvm_pit_config::default()).unwrap();
                }
                let supported = kvm
                    .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
                    .unwrap();
                let mut cpus = Vec::new();
                let mut checks: Vec<Box<dyn Check>> = vec![fixture(vm.get_clock().unwrap())];
                if irqchip {
                    checks.push(fixture(vm.get_pit2().unwrap()));
                }
                for id in 0..count {
                    let cpu = vm.create_vcpu(u64::from(id)).unwrap();
                    cpu.set_cpuid2(&supported).unwrap();
                    let mut regs = cpu.get_regs().unwrap();
                    regs.rax = 0x1122_3344_5566_7700 | u64::from(id);
                    regs.r15 = !regs.rax;
                    regs.rip = 0x1000 + u64::from(id) * 4;
                    cpu.set_regs(&regs).unwrap();
                    let special = cpu.get_sregs().unwrap();
                    checks.push(fixture(cpu.get_regs().unwrap()));
                    checks.push(fixture(special));
                    checks.push(fixture(cpu.get_debug_regs().unwrap()));
                    checks.push(fixture(cpu.get_vcpu_events().unwrap()));
                    checks.push(fixture(cpu.get_mp_state().unwrap()));
                    checks.push(fixture(cpu.get_xcrs().unwrap()));
                    checks.push(fixture(special.cs));
                    checks.push(fixture(special.idt));
                    let cpuid = cpu.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
                    let entry: kvm_cpuid_entry2 = cpuid.as_slice()[0];
                    checks.push(fixture(entry));
                    if irqchip {
                        checks.push(fixture(cpu.get_lapic().unwrap()));
                    }
                    cpus.push(cpu);
                }
                drop(cpus);
                drop(vm);
                drop(kvm);
                checks
            };
            // Only owned records and fixed pointer-free SDK values survive.
            // No native VM or vCPU exists while malformed packets are decoded.
            let rejected: usize = checks.iter().map(|check| check.verify()).sum();
            println!(
                "{}",
                serde_json::json!({
                    "irqchip":irqchip,"cpu_count":count,"captured_banks":checks.len(),
                    "malformed_packets_rejected":rejected,"json_and_actual_legacy_codec":true,
                    "source_graph_destroyed_before_decode":true,"native_setters_during_decode":false,
                    "complete_private_producer":false
                })
            );
        }
    }
}
