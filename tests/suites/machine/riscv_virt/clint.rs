//! An independently linked consumer executes the CLINT guest through Vmm.run.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::runtime::Vmm;
use rax::vm::timing::ClockMode;
use std::sync::atomic::{AtomicU64, Ordering};
#[path = "../../../support/riscv_startup.rs"]
mod image;
#[path = "../../../support/riscv_clint.rs"]
mod program;
static NEXT: AtomicU64 = AtomicU64::new(0);
#[test]
fn public_vmm_delivers_both_clint_interrupts_to_one_two_and_four_harts() {
    for (mode, future) in [
        (ClockMode::Wall, false),
        (ClockMode::Retired, false),
        (ClockMode::Wall, true),
        (ClockMode::Retired, true),
    ] {
        for count in [1, 2, 4] {
            let path = std::env::temp_dir().join(format!(
                "rax-public-clint-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let code = if future {
                program::future_program(count, false)
            } else {
                program::program(count, false)
            };
            println!("public CLINT mode={mode:?} harts={count} future={future}");
            std::fs::write(&path, image::elf(&code, 0x1000, 0x1000)).unwrap();
            let result = (|| -> rax::error::Result<()> {
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
                )?;
                let mut vm = Vmm::new_with_clock(config, mode)?;
                // The BSP's bounded guest loop exits successfully only when
                // every hart has published both software and timer work bits.
                vm.run()?;
                assert_eq!(vm.capture_cpu_states()?.len(), usize::from(count));
                Ok(())
            })();
            std::fs::remove_file(&path).unwrap();
            result.unwrap();
        }
    }
}
