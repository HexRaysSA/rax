//! Device-lock admission must precede changes to any live base checkpoint field.
use super::*;
use crate::config::{CliConfig, MemorySize};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    kernel: std::path::PathBuf,
    vm: Vmm,
}
impl Fixture {
    fn new() -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-admission-lock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&kernel, [0; 64]).unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(4096);
        Self {
            kernel,
            vm: Vmm::new_resume(config).unwrap(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.kernel).unwrap();
    }
}
fn poison<T: Send + 'static>(lock: Arc<std::sync::Mutex<T>>) {
    assert!(
        std::thread::spawn(move || {
            let _guard = lock.lock().unwrap();
            panic!("owned device-lock fixture");
        })
        .join()
        .is_err()
    );
}
fn devices(vm: &Vmm) -> DeviceState {
    DeviceState {
        pic: vm.pic.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        pit: vm.pit.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        serial: vm.serial.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        lapic: vm.lapic.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    }
}
#[test]
fn every_poisoned_legacy_device_lock_rejects_before_any_assignment() {
    for which in 0..4 {
        let mut fixture = Fixture::new();
        let vm = &mut fixture.vm;
        vm.guest_mem.write_all(&[0xa5; 4096]).unwrap();
        let before_cpu = crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap();
        let before_private = crate::codec::serialize(&vm.vcpus[0].get_emulator_state()).unwrap();
        let before_devices = crate::codec::serialize(&devices(vm)).unwrap();
        let mut snapshot = vm.take_snapshot(41).unwrap();
        let CpuState::X86_64(cpu) = &mut snapshot.cpu_state else {
            unreachable!()
        };
        cpu.regs.rax = 0x12345678;
        snapshot.memory_data = zstd::encode_all(&[0x33; 4096][..], 3).unwrap();
        snapshot.devices.pic.set_irq(3, true);
        IoDevice::write(&mut snapshot.devices.serial, 0x3f9, 0x0f);
        match which {
            0 => poison(vm.pic.clone()),
            1 => poison(vm.pit.clone()),
            2 => poison(vm.serial.clone()),
            3 => poison(vm.lapic.clone()),
            _ => unreachable!(),
        }
        assert!(vm.restore_snapshot(&snapshot).is_err());
        assert_eq!(
            crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap(),
            before_cpu
        );
        assert_eq!(
            crate::codec::serialize(&vm.vcpus[0].get_emulator_state()).unwrap(),
            before_private
        );
        assert_eq!(
            crate::codec::serialize(&devices(vm)).unwrap(),
            before_devices
        );
        assert_eq!(vm.guest_mem.try_read_all().unwrap(), vec![0xa5; 4096]);
    }
}

#[cfg(feature = "debug")]
#[test]
fn debugger_cache_failure_prevents_every_checkpoint_capture_before_publication() {
    use crate::vm::vcpu::VCpu;
    struct FailureCpu {
        id: u32,
        state: CpuState,
    }
    impl VCpu for FailureCpu {
        fn id(&self) -> u32 {
            self.id
        }
        fn run(&mut self) -> Result<VcpuExit> {
            panic!("poisoned debugger must exclude guest entry")
        }
        fn get_state(&self) -> Result<CpuState> {
            Ok(self.state.clone())
        }
        fn set_state(&mut self, state: &CpuState) -> Result<()> {
            self.state = state.clone();
            Ok(())
        }
        fn complete_io_in(&mut self, _data: &[u8]) {}
        fn debug_memory_changed(&mut self, _pages: &[u64]) -> Result<()> {
            Err(Error::Emulator("scripted debugger cache failure".into()))
        }
    }
    for failure_index in 0..2 {
        let mut fixture = super::execution_tests::Fixture::new(2);
        let vm = &mut fixture.vm;
        // Valid snapshots establish that poison alone rejects capture and
        // import, independently of an adapter's private-state validation.
        let base = vm.take_snapshot(0).unwrap();
        let bundle = vm.take_snapshot_bundle(0).unwrap();
        assert!(vm.capture_cpu_states().is_ok());
        let before = vm.guest_mem.try_read_all().unwrap();
        let state = vm.vcpus[failure_index].get_state().unwrap();
        let original = std::mem::replace(
            &mut vm.vcpus[failure_index],
            Box::new(FailureCpu {
                id: failure_index as u32,
                state,
            }),
        );
        vm.debugger.physical_memory = true;
        assert!(vm.write_debug_memory(0x8000, b"ABCD").is_err());
        vm.vcpus[failure_index] = original;
        assert!(vm.gdb_stopped);
        let accepted = [
            vm.take_snapshot(0).is_ok(),
            vm.take_snapshot_bundle(0).is_ok(),
            vm.capture_cpu_states().is_ok(),
        ];
        assert_eq!(
            accepted, [false; 3],
            "global failure must fence base, bundle and CPU-set captures at CPU {failure_index}"
        );
        assert!(vm.capture_execution_state().is_err());
        assert!(vm.restore_snapshot(&base).is_err());
        assert!(vm.restore_snapshot_bundle(&bundle).is_err());
        assert!(vm.write_debug_memory(0x8000, b"EFGH").is_err());
        assert!(vm.execute_turn().is_err());
        assert_eq!(vm.guest_mem.try_read_all().unwrap(), before);
    }
}
