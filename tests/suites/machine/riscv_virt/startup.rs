//! Public VMM execution, including secondary-hart guest publications.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::runtime::Vmm;
use rax::vm::vcpu::CpuState;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "../../../support/riscv_startup.rs"]
mod program;

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn public_vmm_runs_one_two_and_four_harts_from_an_elf_entry() {
    for count in [1, 2, 4] {
        let path = std::env::temp_dir().join(format!(
            "rax-public-riscv-startup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &path,
            program::elf(&program::program(count, false), 0x1000, 0x1000),
        )
        .unwrap();
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Riscv64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(path.clone()),
                memory: Some(MemorySize(128 << 20)),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let mut vm = Vmm::new(config).unwrap();
        vm.run().unwrap();
        let cpus = vm.capture_cpu_states().unwrap();
        assert_eq!(cpus.len(), usize::from(count));
        let mut stacks = Vec::new();
        for (id, cpu) in cpus.iter().enumerate() {
            let CpuState::RiscV(state) = &cpu.state else {
                panic!()
            };
            assert_eq!(
                state.regs.x[31],
                id as u64 + 1,
                "hart {id} executed its publication"
            );
            assert_eq!(state.regs.x[29], 1, "hart {id} executed new work");
            assert_eq!(state.regs.x[27] & 15, 0);
            assert!(state.regs.x[27] > 0);
            stacks.push(state.regs.x[27]);
        }
        for pair in stacks.windows(2) {
            assert_eq!(pair[0] - pair[1], 4096);
        }
        std::fs::remove_file(&path).unwrap();
    }
}
