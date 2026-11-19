//! Board UART output through both PLIC contexts and source-free file continuation.
use super::*;
use crate::backend::emulator::riscv::platform::PLIC_BASE;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::timing::ClockMode;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

#[path = "../../../tests/support/riscv_startup.rs"]
mod image;
#[path = "../../../tests/support/riscv_plic_uart.rs"]
mod payload;

const LOAD: u64 = 0x1000;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    kernel: PathBuf,
    vm: Vmm,
}

impl Fixture {
    fn new(count: u8, hold: bool, verify_repend: bool) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-plic-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let bytes = payload::program(count, hold, verify_repend);
        std::fs::write(&kernel, image::elf(&bytes, LOAD, LOAD)).unwrap();
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Riscv64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                memory: Some(MemorySize(128 << 20)),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let vm = Vmm::new_with_clock(config, ClockMode::Retired).unwrap();
        Self { kernel, vm }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
        let _ = std::fs::remove_file(self.kernel.with_extension("rxc"));
    }
}

fn stage(vm: &Vmm, hart: u8) -> u32 {
    let addr = LOAD + payload::RECORDS_OFFSET + u64::from(hart) * 4;
    u32::from_le(vm.guest_mem.memory().read_obj(GuestAddress(addr)).unwrap())
}

fn assert_completed(vm: &Vmm, harts: u8) {
    for hart in 0..harts {
        assert_eq!(stage(vm, hart), 3, "topology {harts}, hart {hart}");
    }
    let platform = platform(vm);
    for hart in 0..harts {
        let signals = platform.signals(u32::from(hart)).unwrap().unwrap();
        assert_eq!(signals.external, Some((false, false)));
    }
}

fn platform(vm: &Vmm) -> Arc<crate::backend::emulator::riscv::platform::Platform> {
    vm.vm
        .as_any()
        .downcast_ref::<crate::backend::emulator::EmulatorVm>()
        .unwrap()
        .riscv_platform()
        .unwrap()
}

fn contexts(vm: &Vmm) -> Vec<Option<crate::vm::snapshot::BackendContext>> {
    vm.vcpus
        .iter()
        .map(|cpu| cpu.capture_backend_context().unwrap())
        .collect()
}

#[test]
fn every_hart_claims_and_completes_actual_uart_in_m_and_s_modes() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count, false, true);
        fixture.vm.run().unwrap();
        assert_completed(&fixture.vm, count);
    }
}

#[test]
fn source_free_file_retains_the_asserted_uart_with_claim_in_service() {
    for count in [1, 2, 4] {
        let mut source = Fixture::new(count, true, true);
        let inactive = platform(&source.vm).checkpoint().unwrap();
        let mut ready = false;
        for _ in 0..48 {
            if let Some(turn) = source.vm.execute_turn().unwrap() {
                match turn.exit {
                    VcpuExit::MmioWrite { addr, data } => {
                        source
                            .vm
                            .dispatch_mmio_write(turn.cpu_index, addr, &data)
                            .unwrap();
                    }
                    other => panic!("unexpected exit before the captured claim: {other:?}"),
                }
            }
            ready =
                stage(&source.vm, 0) == 2 && source.vm.coordinator.cursor == usize::from(count > 1);
            if ready {
                break;
            }
        }
        assert!(
            ready,
            "hart 0 must be in the S-mode handler after its PLIC claim"
        );
        for hart in 1..count {
            assert_eq!(stage(&source.vm, hart), 0);
        }
        let CpuState::RiscV(active) = source.vm.vcpus[0].get_state().unwrap() else {
            panic!("expected a RISC-V hart");
        };
        assert_eq!(active.regs.privilege, Some(1));
        assert_eq!(
            active
                .regs
                .csrs
                .iter()
                .find(|&&(n, _)| n == 0x141)
                .unwrap()
                .1,
            LOAD + payload::SUPERVISOR_RESUME_OFFSET
        );
        assert!(source.vm.serial.lock().unwrap().interrupt_output());
        let mut pending = [0xff; 4];
        platform(&source.vm)
            .read(PLIC_BASE + 0x1000, &mut pending)
            .unwrap();
        assert_eq!(pending, [0; 4]);

        let before = contexts(&source.vm);
        let file = source.kernel.with_extension("rxc");
        source
            .vm
            .take_snapshot_bundle(source.vm.coordinator.retired)
            .unwrap()
            .save(&file)
            .unwrap();
        let bundle = SnapshotBundle::load(&file).unwrap();
        std::fs::remove_file(&source.kernel).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &bundle).unwrap();

        assert_eq!(contexts(&restored), before);
        let before_controller = platform(&restored).checkpoint().unwrap();
        assert_eq!(restored.coordinator, source.vm.coordinator);
        assert_eq!(
            before_controller,
            platform(&source.vm).checkpoint().unwrap()
        );

        let mut mismatched = bundle.execution().unwrap().clone();
        mismatched.riscv_platform = inactive;
        let bad_bundle = bundle.with_execution(mismatched).unwrap();
        let error = restored.restore_snapshot_bundle(&bad_bundle).unwrap_err();
        assert!(error.to_string().contains("saved PLIC UART line disagrees"));
        assert_eq!(contexts(&restored), before);
        assert_eq!(restored.coordinator, source.vm.coordinator);
        assert_eq!(platform(&restored).checkpoint().unwrap(), before_controller);
        assert!(restored.serial.lock().unwrap().interrupt_output());

        for vm in [&mut source.vm, &mut restored] {
            vm.guest_mem
                .memory()
                .write_obj(1u32.to_le(), GuestAddress(LOAD + payload::RELEASE_OFFSET))
                .unwrap();
            vm.run().unwrap();
            assert_completed(vm, count);
        }
        assert_eq!(contexts(&source.vm), contexts(&restored));
        assert_eq!(
            platform(&source.vm).checkpoint().unwrap(),
            platform(&restored).checkpoint().unwrap()
        );
        assert_eq!(source.vm.coordinator, restored.coordinator);
    }
}
