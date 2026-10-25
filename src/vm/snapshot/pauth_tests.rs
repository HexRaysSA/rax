//! Version-before-layout checks and mandatory keyed system-state persistence.

use super::*;
use crate::isa::arm::aarch64::pauth::{PauthAlgorithm, PauthConfig, PauthProfile};
use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use crate::isa::arm::common::memory::FlatMemory;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TestFile(std::path::PathBuf);

impl TestFile {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "rax-pauth-checkpoint-{}-{}.rxc",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn pauth_checkpoint_roundtrip_retains_keys_profile_banks_and_pstate() {
    let mut snapshot = super::tests::snapshot_with_memory_metadata(0x1000, 0x1000);
    let config = AArch64Config {
        pauth: PauthConfig {
            algorithm: PauthAlgorithm::Qarma3,
            profile: PauthProfile::Fpac,
        },
        ..Default::default()
    };
    let cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x1000)));
    let mut sregs = cpu.export_sregs();
    let execution = sregs.execution.as_mut().unwrap();
    execution.sysregs.apiakeylo_el1 = 0x1234_5678_9abc_def0;
    execution.sysregs.apgakeyhi_el1 = 0xfedc_ba98_7654_3210;
    execution.sysregs.el2.elr = 0x8000;
    execution.sysregs.el3.spsr = 0x3c9;
    execution.sysregs.hcr_el2 = (1 << 40) | (1 << 41);
    execution.sysregs.scr_el3 = 1 | (1 << 16) | (1 << 17);
    execution.sp_el2 = 0x3000;
    execution.sp_el3 = 0x4000;
    let mut regs = crate::vm::vcpu::Aarch64Registers::default();
    regs.pstate |= crate::vm::vcpu::Aarch64Registers::PSTATE_BTYPE_MASK;
    snapshot.cpu_state = CpuState::aarch64(regs, sregs);
    let file = TestFile::new();
    snapshot.save(&file.0).unwrap();
    let saved = std::fs::read(&file.0).unwrap();
    assert_eq!(&saved[8..12], &8u32.to_le_bytes());
    let restored = Snapshot::load(&file.0).unwrap();
    assert_eq!(
        crate::codec::serialize(&restored.cpu_state).unwrap(),
        crate::codec::serialize(&snapshot.cpu_state).unwrap()
    );
}

#[test]
fn pauth_checkpoint_aarch32_state_roundtrip_and_width_validation() {
    let mut snapshot = super::tests::snapshot_with_memory_metadata(0x1000, 0x1000);
    let cpu = AArch64Cpu::new(
        AArch64Config::default(),
        Box::new(FlatMemory::new(0, 0x1000)),
    );
    let mut regs = crate::vm::vcpu::Aarch64Registers::default();
    regs.pstate = 0xa805_0030;
    regs.pc = 0x102;
    regs.x[13] = 0x1234_5678_0000_0800;
    regs.sp = 0x800;
    snapshot.cpu_state = CpuState::aarch64(regs, cpu.export_sregs());
    let file = TestFile::new();
    snapshot.save(&file.0).unwrap();
    let restored = Snapshot::load(&file.0).unwrap();
    assert_eq!(
        crate::codec::serialize(&restored.cpu_state).unwrap(),
        crate::codec::serialize(&snapshot.cpu_state).unwrap()
    );
    let CpuState::Aarch64(state) = &mut snapshot.cpu_state else {
        panic!("architecture");
    };
    state
        .sregs
        .execution
        .as_mut()
        .unwrap()
        .sysregs
        .id_aa64pfr0_el1 = 0x1111;
    assert!(snapshot.save(&file.0).is_err());
}

#[test]
fn pauth_checkpoint_rejects_older_version_before_decoding_the_cpu_layout() {
    let file = TestFile::new();
    for version in [0u32, 1, 7, 9, u32::MAX] {
        let mut bytes = CHECKPOINT_MAGIC.to_vec();
        bytes.extend_from_slice(&version.to_le_bytes());
        // No remaining image is needed to diagnose a version mismatch.
        std::fs::write(&file.0, bytes).unwrap();
        let error = Snapshot::load(&file.0).err().unwrap().to_string();
        assert!(
            error.contains(&format!(
                "Unsupported checkpoint version {} (expected 8)",
                version
            )),
            "{error}"
        );
    }
}

#[test]
fn pauth_checkpoint_rejects_absent_keyed_extension_on_save_and_load() {
    let mut snapshot = super::tests::snapshot_with_memory_metadata(0x1000, 0x1000);
    snapshot.cpu_state = CpuState::aarch64(Default::default(), Default::default());
    let file = TestFile::new();
    assert!(
        snapshot
            .save(&file.0)
            .unwrap_err()
            .to_string()
            .contains("missing keyed system state")
    );
    // Bypass the writer's validation to exercise the reader independently.
    let mut bytes = CHECKPOINT_MAGIC.to_vec();
    bytes.extend_from_slice(&crate::codec::serialize(&snapshot).unwrap());
    std::fs::write(&file.0, bytes).unwrap();
    assert!(
        Snapshot::load(&file.0)
            .err()
            .unwrap()
            .to_string()
            .contains("missing keyed system state")
    );
}
