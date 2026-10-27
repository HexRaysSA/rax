//! Actual VMM device-transaction and completion/checkpoint frontiers.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::devices::bus::{MmioDevice, MmioRmwOp};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ADDRESS: u64 = 0x5000_0000;

#[derive(Default)]
struct Observed {
    calls: Vec<&'static str>,
    captured: usize,
    complete_unlocked: bool,
}

struct Device {
    value: u32,
    observed: Arc<Mutex<Observed>>,
}
impl MmioDevice for Device {
    fn read(&mut self, address: u64, data: &mut [u8]) {
        assert_eq!((address, data.len()), (ADDRESS, 4));
        self.observed.lock().unwrap().calls.push("read");
        data.copy_from_slice(&self.value.to_le_bytes());
    }
    fn write(&mut self, address: u64, data: &[u8]) {
        assert_eq!((address, data.len()), (ADDRESS, 4));
        self.observed.lock().unwrap().calls.push("write");
        self.value = u32::from_le_bytes(data.try_into().unwrap());
    }
}

struct Cpu {
    id: u32,
    state: CpuState,
    device: Arc<Mutex<Device>>,
    observed: Arc<Mutex<Observed>>,
    issued: bool,
    fail: bool,
}
impl VCpu for Cpu {
    fn run(&mut self) -> Result<VcpuExit> {
        if self.issued {
            self.observed.lock().unwrap().calls.push("shutdown");
            return Ok(VcpuExit::Shutdown);
        }
        self.issued = true;
        self.observed.lock().unwrap().calls.push("issue");
        Ok(VcpuExit::MmioRmw {
            addr: ADDRESS,
            size: 4,
            operation: MmioRmwOp::Add {
                value: 1,
                carry: false,
            },
        })
    }
    fn get_state(&self) -> Result<CpuState> {
        self.observed.lock().unwrap().captured += 1;
        Ok(self.state.clone())
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.state = state.clone();
        Ok(())
    }
    fn complete_io_in(&mut self, data: &[u8]) {
        let unlocked = self.device.try_lock().is_ok();
        let mut observed = self.observed.lock().unwrap();
        observed.complete_unlocked = unlocked;
        observed.calls.push("complete");
        let CpuState::X86_64(state) = &mut self.state else {
            panic!()
        };
        state.regs.rax = u64::from(u32::from_le_bytes(data.try_into().unwrap()));
        state.regs.rip = state.regs.rip.wrapping_add(3);
    }
    fn io_completion_result(&self) -> Result<()> {
        self.observed.lock().unwrap().calls.push("status");
        if self.fail {
            Err(Error::Emulator("mock native RMW completion failure".into()))
        } else {
            Ok(())
        }
    }
    fn id(&self) -> u32 {
        self.id
    }
}

struct Fixture {
    vm: Vmm,
    directory: PathBuf,
    device: Arc<Mutex<Device>>,
    observed: Arc<Mutex<Observed>>,
}
impl Fixture {
    fn new(fail: bool) -> Self {
        Self::with_origin(fail, 0)
    }

    fn with_origin(fail: bool, origin: usize) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-rmw-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let kernel = directory.join("kernel");
        std::fs::write(&kernel, [0; 64]).unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                vcpus: Some((origin + 1) as u8),
                kernel: Some(kernel),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(128 * 1024 * 1024);
        let mut vm = Vmm::new_resume(config).unwrap();
        let state = vm.vcpus[origin].get_state().unwrap();
        let observed = Arc::new(Mutex::new(Observed::default()));
        let device = Arc::new(Mutex::new(Device {
            value: 7,
            observed: observed.clone(),
        }));
        vm.mmio_bus
            .register(
                crate::devices::bus::MmioRange {
                    base: ADDRESS,
                    len: 4096,
                },
                Box::new(crate::devices::bus::SharedMmioDevice::new(device.clone())),
            )
            .unwrap();
        vm.vcpus[origin] = Box::new(Cpu {
            id: origin as u32,
            state,
            device: device.clone(),
            observed: observed.clone(),
            issued: false,
            fail,
        });
        vm.coordinator.online.fill(false);
        vm.coordinator.online[origin] = true;
        vm.coordinator.cursor = origin;
        // Force an automatic capture at the completion frontier, including for
        // this mock non-stepping backend whose retirement accounting is separate.
        vm.coordinator.retired = 5;
        vm.snapshot_config = Some(SnapshotConfig {
            interval: 0,
            at_instructions: vec![5],
            output_dir: directory.to_string_lossy().into_owned(),
            prefix: "rmw".into(),
        });
        Self {
            vm,
            directory,
            device,
            observed,
        }
    }
    fn checkpoints(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("rmw"))
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn device_lock_is_released_before_completion_and_checkpoint_sees_the_published_value() {
    let mut fixture = Fixture::new(false);
    fixture.vm.run().unwrap();
    assert_eq!(fixture.device.lock().unwrap().value, 8);
    let observed = fixture.observed.lock().unwrap();
    assert_eq!(
        observed.calls,
        ["issue", "read", "write", "complete", "status", "shutdown"]
    );
    assert!(observed.complete_unlocked);
    assert!(observed.captured > 0);
    let checkpoints = fixture.checkpoints();
    assert_eq!(checkpoints.len(), 1);
    let loaded = crate::vm::snapshot::SnapshotBundle::load(&checkpoints[0]).unwrap();
    let CpuState::X86_64(cpu) = &loaded.base().cpu_state else {
        panic!()
    };
    assert_eq!(cpu.regs.rax, 7);
}

#[test]
fn failed_native_completion_stops_before_checkpoint_or_second_device_transaction() {
    let mut fixture = Fixture::new(true);
    let error = fixture.vm.run().unwrap_err().to_string();
    assert!(
        error.contains("mock native RMW completion failure"),
        "{error}"
    );
    assert_eq!(fixture.device.lock().unwrap().value, 8);
    let observed = fixture.observed.lock().unwrap();
    assert_eq!(
        observed.calls,
        ["issue", "read", "write", "complete", "status"]
    );
    assert!(observed.complete_unlocked);
    assert_eq!(observed.captured, 0);
    assert!(fixture.checkpoints().is_empty());
}

#[test]
fn an_ap_origin_receives_its_own_completion_and_checkpoint_registers() {
    let mut fixture = Fixture::with_origin(false, 1);
    fixture.vm.run().unwrap();
    assert_eq!(fixture.device.lock().unwrap().value, 8);
    let checkpoints = fixture.checkpoints();
    assert_eq!(checkpoints.len(), 1);
    let loaded = crate::vm::snapshot::SnapshotBundle::load(&checkpoints[0]).unwrap();
    let entries = loaded.cpus().unwrap().entries();
    let CpuState::X86_64(bsp) = &entries[0].state else {
        panic!()
    };
    let CpuState::X86_64(ap) = &entries[1].state else {
        panic!()
    };
    assert_eq!(bsp.regs.rax, 0);
    assert_eq!(ap.regs.rax, 7);
    assert!(fixture.observed.lock().unwrap().complete_unlocked);
}
