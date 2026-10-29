//! CPU0 coherence is independent of serialized hash-map iteration order.
use super::*;
use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::FlatMemory;
use crate::vm::vcpu::Aarch64Registers;

fn state() -> CpuState {
    let cpu = AArch64Cpu::new(
        AArch64Config {
            gic_config: None,
            ..Default::default()
        },
        Box::new(FlatMemory::new(0, 0x1000)),
    );
    let mut system = cpu.export_sregs();
    let saved = system.execution.as_mut().unwrap();
    for key in 0..64u16 {
        saved.sysregs.impl_defined.insert(key, u64::from(key) + 100);
    }
    CpuState::aarch64(
        Aarch64Registers {
            pc: 0x100,
            ..Default::default()
        },
        system,
    )
}

#[test]
fn independently_decoded_register_maps_preserve_cpu0_coherence() {
    let original = state();
    let raw = encode(&original).unwrap();
    let base: CpuState = decode(&raw).unwrap();
    let entry: CpuState = decode(&raw).unwrap();
    assert_eq!(base.as_aarch64().unwrap(), entry.as_aarch64().unwrap());
    // Make the actual counterexample observable rather than assuming that two
    // randomized maps necessarily serialize in the same order.
    assert_ne!(encode(&base).unwrap(), encode(&entry).unwrap());
    let emulator = EmulatorState::default();
    CpuSnapshots::validate_entries(
        &[CpuSnapshot {
            state: entry,
            emulator: emulator.clone(),
        }],
        &base,
        &emulator,
    )
    .unwrap();
}

#[test]
fn cpu0_coherence_rejects_real_public_and_private_differences() {
    let base = state();
    let emulator = EmulatorState::default();
    for kind in 0..9 {
        let mut entry = CpuSnapshot {
            state: base.clone(),
            emulator: emulator.clone(),
        };
        let CpuState::Aarch64(saved) = &mut entry.state else {
            unreachable!()
        };
        let execution = saved.sregs.execution.as_mut().unwrap();
        match kind {
            0 => saved.regs.x[17] ^= 1,
            1 => saved.regs.v[7][0] = 0x7ff8_0000_0000_0001,
            2 => execution.features ^= ArmFeatures::SVE.bits(),
            3 => execution.sysregs.el1.cpacr ^= 1 << 16,
            4 => *execution.sysregs.impl_defined.get_mut(&17).unwrap() ^= 1,
            5 => {
                execution.sysregs.impl_defined.remove(&17);
            }
            6 => {
                execution.sysregs.impl_defined.insert(100, 117);
            }
            7 => entry.emulator.halted = true,
            8 => entry.emulator.mxcsr ^= 1,
            _ => unreachable!(),
        }
        let error = CpuSnapshots::validate_entries(&[entry], &base, &emulator).unwrap_err();
        assert!(
            error.to_string().contains("CPU0 disagrees"),
            "case {kind}: {error}"
        );
    }
}
