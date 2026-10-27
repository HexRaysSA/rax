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
