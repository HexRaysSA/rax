//! Actual S5L factory and production coordinator retirement boundaries.
use super::*;
use crate::config::{CliConfig, MemorySize};
use std::path::PathBuf;
use vm_memory::{Bytes, GuestAddress};
const CODE: u32 = 0x1000;
fn child(label: &str) -> bool {
    if std::env::var("RAX_S5L_BOUNDED_PROBE").as_deref() == Ok(label) {
        return true;
    }
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("RAX_S5L_") || name == "RAX_TRACE_PC" {
            cmd.env_remove(name);
        }
    }
    let out = cmd
        .args([
            &format!("vm::runtime::s5l_bounded_tests::{label}"),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RAX_MACHINE", "s5l8900")
        .env("RAX_S5L_BOUNDED_PROBE", label)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "child {:?}\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed; 0 failed"));
    false
}
struct Fixture {
    path: PathBuf,
    vm: Vmm,
}
impl Fixture {
    fn new(count: u8, words: &[u32]) -> Self {
        let path =
            std::env::temp_dir().join(format!("rax-s5l-quantum-{}-{count}", std::process::id()));
        std::fs::write(&path, [0; 64]).unwrap();
        let cfg = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Armv7a),
                backend: Some(BackendKind::Emulator),
                kernel: Some(path.clone()),
                memory: Some(MemorySize(128 << 20)),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let mut vm = Vmm::new_resume(cfg).unwrap();
        let bytes: Vec<_> = words.iter().flat_map(|v| v.to_le_bytes()).collect();
        vm.guest_mem
            .memory()
            .write_slice(&bytes, GuestAddress(u64::from(CODE)))
            .unwrap();
        for cpu in &mut vm.vcpus {
            let mut state = cpu.get_state().unwrap();
            let CpuState::Aarch32(s) = &mut state else {
                panic!()
            };
            s.regs.pc = CODE;
            cpu.set_state(&state).unwrap();
        }
        Self { path, vm }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
#[test]
fn every_s5l_factory_cpu_contributes_its_completed_wfi_work() {
    if !child("every_s5l_factory_cpu_contributes_its_completed_wfi_work") {
        return;
    }
    for count in [1, 2, 4] {
        let mut f = Fixture::new(count, &[0xe3a0_002a, 0xe320_f003]);
        // Prepared online contexts qualify selection, not unsupported S5L AP startup.
        f.vm.coordinator.online.fill(true);
        for index in 0..usize::from(count) {
            let turn = f.vm.execute_turn().unwrap().unwrap();
            assert_eq!(turn.cpu_index, index);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            assert_eq!(
                f.vm.coordinator.retired,
                2 * (index as u64 + 1),
                "S5L completed work was not accounted by the actual coordinator"
            );
            assert_eq!(f.vm.vcpus[index].instruction_count(), 2);
        }
    }
}
#[test]
fn s5l_tight_loop_yields_after_the_exact_coordinator_quantum() {
    if !child("s5l_tight_loop_yields_after_the_exact_coordinator_quantum") {
        return;
    }
    for count in [1, 2, 4] {
        let mut f = Fixture::new(count, &[0xeaff_fffe]); // B to the same instruction.
        // This board has no secondary-startup protocol; make the test precondition explicit.
        f.vm.coordinator.online.fill(true);
        for index in 0..usize::from(count) {
            assert!(
                f.vm.execute_turn().unwrap().is_none(),
                "a host batch boundary was fabricated as a guest HLT"
            );
            assert_eq!(f.vm.coordinator.retired, 1000 * (index as u64 + 1));
            assert_eq!(f.vm.vcpus[index].instruction_count(), 1000);
        }
    }
}

#[test]
fn cold_s5l_keeps_secondary_contexts_offline_without_a_start_request() {
    if !child("cold_s5l_keeps_secondary_contexts_offline_without_a_start_request") {
        return;
    }
    for count in [1, 2, 4] {
        let mut f = Fixture::new(count, &[0xeaff_fffe]);
        assert_eq!(
            f.vm.coordinator.online,
            (0..count).map(|id| id == 0).collect::<Vec<_>>()
        );
        assert!(f.vm.execute_turn().unwrap().is_none());
        assert_eq!(f.vm.coordinator.retired, 1000);
        assert_eq!(f.vm.vcpus[0].instruction_count(), 1000);
        for cpu in &f.vm.vcpus[1..] {
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}
