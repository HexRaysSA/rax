//! Production GSC factory/coordinator checks, with process-local selectors.
use super::*;
use crate::config::{CliConfig, MemorySize};
use std::path::PathBuf;
use vm_memory::{Bytes, GuestAddress};

const CODE: u64 = 0x1000;
const PREFIX: &str = "vm::runtime::gsc_bounded_tests::";

// Keep this board's environment selector out of every other concurrent fixture.
fn child(label: &str) -> bool {
    if std::env::var("RAX_GSC_PLATFORM_PROBE").as_deref() == Ok(label) {
        assert_eq!(std::env::var("RAX_MACHINE").as_deref(), Ok("gsc"));
        return true;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("RAX_GSC_") {
            command.env_remove(name);
        }
    }
    let output = command
        .args([
            &format!("{PREFIX}{label}"),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RAX_MACHINE", "gsc")
        .env("RAX_GSC_PLATFORM_PROBE", label)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child status {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    false
}

struct Fixture {
    kernel: PathBuf,
    vm: Vmm,
}
impl Fixture {
    fn new(words: &[u32]) -> Self {
        let kernel =
            std::env::temp_dir().join(format!("rax-gsc-coordinator-{}", std::process::id()));
        std::fs::write(&kernel, [0; 64]).unwrap();
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Riscv64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                memory: Some(MemorySize(128 << 20)),
                vcpus: Some(1),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let mut vm = Vmm::new_resume(config).unwrap();
        let code: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        vm.guest_mem
            .memory()
            .write_slice(&code, GuestAddress(CODE))
            .unwrap();
        let mut state = vm.vcpus[0].get_state().unwrap();
        let CpuState::RiscV(s) = &mut state else {
            panic!()
        };
        s.regs.pc = CODE;
        vm.vcpus[0].set_state(&state).unwrap();
        Self { kernel, vm }
    }
    fn run_to_break(&mut self) -> crate::vm::vcpu::RiscVRegisters {
        let turn = self
            .vm
            .execute_turn()
            .unwrap()
            .expect("guest did not reach EBREAK");
        assert_eq!(turn.cpu_index, 0);
        assert!(matches!(turn.exit, VcpuExit::Debug), "{turn:?}");
        let CpuState::RiscV(s) = self.vm.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        s.regs
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
    }
}

#[test]
fn actual_gsc_factory_coordinator_advances_the_guest_timer() {
    if !child("actual_gsc_factory_coordinator_advances_the_guest_timer") {
        return;
    }
    let mut words = vec![0x0000_0013; 24];
    // LUI a1,0x400c0; LW a0,20(a1); EBREAK.
    words.extend([0x400c_05b7, 0x0145_a503, 0x0010_0073]);
    let mut fixture = Fixture::new(&words);
    assert_eq!(
        fixture.run_to_break().x[10],
        1,
        "production GSC timer stayed frozen"
    );
    assert_eq!(fixture.vm.coordinator.retired, 26);
}

#[test]
fn actual_gsc_factory_coordinator_reboots_and_preserves_completed_work() {
    if !child("actual_gsc_factory_coordinator_reboots_and_preserves_completed_work") {
        return;
    }
    // Persist a PMU scratch marker; request one warm reset; then read RSTSRC.
    let mut fixture = Fixture::new(&[
        0x4000_0537, // LUI a0,0x40000
        0x04c5_2603, // LW a2,76(a0)
        0x0006_1c63, // BNE a2,x0,+24
        0x0010_0613, // ADDI a2,x0,1
        0x04c5_2623, // SW a2,76(a0)
        0x0704_15b7, // LUI a1,0x07041
        0x7765_8593, // ADDI a1,a1,0x776
        0x00b5_2423, // SW a1,8(a0)
        0x0005_2683, // LW a3,0(a0)
        0x0010_0073, // EBREAK
    ]);
    assert_eq!(
        fixture.run_to_break().x[13],
        0x22,
        "production GSC skipped the warm reset"
    );
    assert_eq!(fixture.vm.coordinator.retired, 12);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 12);
}
