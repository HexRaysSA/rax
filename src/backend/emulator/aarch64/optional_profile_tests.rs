//! Actual pre-fix RAXA6402 exports and transactional profile migration.
use super::Aarch64Vcpu;
use crate::isa::arm::common::features::ArmFeatures;
use crate::vm::snapshot::{AARCH64_CONTEXT, BackendContext, EmulatorState};
use crate::vm::vcpu::{CpuState, VCpu};
use std::path::Path;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn features() -> [ArmFeatures; 6] {
    [
        ArmFeatures::JSCVT,
        ArmFeatures::FCMA,
        ArmFeatures::FRINTTS,
        ArmFeatures::BF16,
        ArmFeatures::I8MM,
        ArmFeatures::DOTPROD,
    ]
}

fn fixture(name: &str) -> (CpuState, BackendContext) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/development/a64-optional-fp-profile/fixtures");
    let state = std::fs::read(root.join(format!("{name}.state.bin"))).unwrap();
    let private = std::fs::read(root.join(format!("{name}.backend.bin"))).unwrap();
    assert!(private.starts_with(b"RAXA6402"));
    (
        crate::codec::deserialize_limited::<_, { 4 * 1024 * 1024 }>(&state).unwrap(),
        BackendContext {
            kind: AARCH64_CONTEXT,
            data: private,
        },
    )
}

fn target() -> (Aarch64Vcpu, Arc<GuestMemoryMmap>) {
    let memory: Arc<GuestMemoryMmap> =
        Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    memory
        .write_slice(
            &[0x20, 0, 0x7e, 0x1e, 0, 0, 0x20, 0xd4],
            GuestAddress(0x1000),
        )
        .unwrap();
    memory
        .write_slice(&0x9100_0694u32.to_le_bytes(), GuestAddress(0x1100))
        .unwrap();
    let mut cpu = Aarch64Vcpu::new(0, memory.clone());
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = 0x1100;
    state.regs.x[20] = 0xbeef;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    (cpu, memory)
}

#[test]
fn optional_profile_actual_v2_records_preserve_advertised_caps_and_continue() {
    for (name, ids) in [
        ("parent-default", 0x37),
        ("none", 0),
        ("flags-all-ids-none", 0),
        ("ids-all-flags-none", 63),
        ("all-enabled", 63),
        ("flags-all-parent-ids", 0x37),
        ("alternating", 0x2a),
    ] {
        let (public, private) = fixture(name);
        let CpuState::Aarch64(original) = &public else {
            panic!()
        };
        let original_system = &original.sregs.execution.as_ref().unwrap().sysregs;
        let (mut cpu, _) = target();
        cpu.restore_checkpoint_context(&public, &EmulatorState::default(), Some(&private))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let CpuState::Aarch64(after) = cpu.get_state().unwrap() else {
            panic!()
        };
        let execution = after.sregs.execution.as_ref().unwrap();
        let actual = ArmFeatures::from_bits_retain(execution.features);
        for (i, feature) in features().into_iter().enumerate() {
            assert_eq!(
                actual.contains(feature),
                ids & (1 << i) != 0,
                "{name}: {feature:?}"
            );
        }
        assert_eq!(
            execution.sysregs.id_aa64isar0_el1, original_system.id_aa64isar0_el1,
            "{name}"
        );
        assert_eq!(
            execution.sysregs.id_aa64isar1_el1, original_system.id_aa64isar1_el1,
            "{name}"
        );
        assert_eq!(after.regs, original.regs, "{name}");
        let current = cpu.capture_backend_context().unwrap().unwrap();
        assert!(current.data.starts_with(b"RAXA6407"));
        let (mut roundtrip, _) = target();
        roundtrip
            .restore_checkpoint_context(
                &CpuState::Aarch64(after.clone()),
                &EmulatorState::default(),
                Some(&current),
            )
            .unwrap();
        let CpuState::Aarch64(roundtrip_state) = roundtrip.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(roundtrip_state, after, "{name}");
        cpu.step_insn().unwrap();
        roundtrip.step_insn().unwrap();
        let CpuState::Aarch64(roundtrip_result) = roundtrip.get_state().unwrap() else {
            panic!()
        };
        let CpuState::Aarch64(current_result) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(roundtrip_result, current_result, "{name}");
        let CpuState::Aarch64(result) = cpu.get_state().unwrap() else {
            panic!()
        };
        if ids & 1 != 0 {
            assert_eq!(
                (result.regs.pc, result.regs.x[0], cpu.instruction_count()),
                (0x1004, 7, 1),
                "{name}"
            );
        } else {
            let system = &result.sregs.execution.as_ref().unwrap().sysregs;
            assert_eq!(
                (
                    system.el1.esr >> 26,
                    system.el1.elr,
                    result.regs.x[0],
                    cpu.instruction_count()
                ),
                (0, 0x1000, 0x55, 0),
                "{name}"
            );
        }
    }
}

fn rejects_without_target_mutation(public: &CpuState, private: &BackendContext) {
    let (mut cpu, memory) = target();
    let CpuState::Aarch64(before) = cpu.get_state().unwrap() else {
        panic!()
    };
    let mut bytes = vec![0; 0x8000];
    memory.read_slice(&mut bytes, GuestAddress(0)).unwrap();
    assert!(
        cpu.restore_checkpoint_context(public, &EmulatorState::default(), Some(private))
            .is_err()
    );
    let CpuState::Aarch64(after_state) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(after_state, before);
    assert_eq!(cpu.instruction_count(), 0);
    let mut after = vec![0; 0x8000];
    memory.read_slice(&mut after, GuestAddress(0)).unwrap();
    assert_eq!(bytes, after);
    cpu.step_insn().unwrap();
    let CpuState::Aarch64(result) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(
        (result.regs.pc, result.regs.x[20], cpu.instruction_count()),
        (0x1104, 0xbef0, 1)
    );
}

#[test]
fn optional_profile_legacy_unsupported_levels_reject_transactionally() {
    for name in ["bf16-level2", "fcma-reserved15"] {
        let (public, private) = fixture(name);
        rejects_without_target_mutation(&public, &private);
    }
}

#[test]
fn optional_profile_source_conflicts_reject_before_migration_can_hide_them() {
    let (original, private) = fixture("parent-default");
    for feature in features() {
        let CpuState::Aarch64(mut state) = original.clone() else {
            panic!()
        };
        state.sregs.execution.as_mut().unwrap().features ^= feature.bits();
        rejects_without_target_mutation(&CpuState::Aarch64(state), &private);
    }
}

#[test]
fn optional_profile_forged_v3_tag_does_not_get_legacy_normalization() {
    let (public, mut private) = fixture("parent-default");
    // An intentionally forged current record, not a historical producer fixture.
    private.data[..8].copy_from_slice(b"RAXA6403");
    rejects_without_target_mutation(&public, &private);
}

#[test]
fn optional_profile_backend_selection_preserves_count_registers_ram_and_shutdown() {
    let (mut cpu, memory) = target();
    cpu.step_insn().unwrap();
    let CpuState::Aarch64(before) = cpu.get_state().unwrap() else {
        panic!()
    };
    cpu.shutdown = true;
    let mut bytes = vec![0; 0x8000];
    memory.read_slice(&mut bytes, GuestAddress(0)).unwrap();
    let selected = features()
        .into_iter()
        .fold(ArmFeatures::FP16 | ArmFeatures::FHM, |flags, feature| {
            flags | feature
        });
    cpu.set_aarch64_fp_features(selected.bits()).unwrap();
    assert_eq!(cpu.aarch64_fp_features(), Some(selected.bits()));
    let CpuState::Aarch64(after) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(after.regs, before.regs);
    assert_eq!(cpu.instruction_count(), 1);
    assert!(cpu.shutdown);
    assert!(cpu.set_aarch64_fp_features(1 << 63).is_err());
    let CpuState::Aarch64(rejected) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(rejected, after);
    assert_eq!(cpu.instruction_count(), 1);
    assert!(cpu.shutdown);
    let mut unchanged = vec![0; 0x8000];
    memory.read_slice(&mut unchanged, GuestAddress(0)).unwrap();
    assert_eq!(bytes, unchanged);
}
