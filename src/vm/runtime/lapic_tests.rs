//! Guest LAPIC accesses and VMM interrupt/checkpoint ownership must agree.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::devices::bus::MmioDevice;
use crate::vm::vcpu::{DescriptorTable, Segment};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::GuestAddress;

static NEXT: AtomicU64 = AtomicU64::new(0);
const CODE: u64 = 0x8000;
const TPR: u64 = LAPIC_BASE + 0x80;

struct Fixture {
    kernel: PathBuf,
    vm: Vmm,
}

impl Fixture {
    fn new(cpus: u8) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-lapic-owner-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&kernel, [0; 64]).unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                vcpus: Some(cpus),
                kernel: Some(kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(65536);
        Self {
            kernel,
            vm: Vmm::new_resume(config).unwrap(),
        }
    }

    fn execute(&mut self, cpu: usize, code: &[u8]) -> CpuState {
        self.vm
            .guest_mem
            .memory()
            .write_slice(code, GuestAddress(CODE))
            .unwrap();
        let mut state = self.vm.vcpus[cpu].get_state().unwrap();
        let CpuState::X86_64(s) = &mut state else {
            panic!("x86 fixture")
        };
        s.regs.rip = CODE;
        s.regs.rsp = 0xe000;
        s.regs.rflags = 2;
        s.sregs.cr0 = 1 | 16;
        s.sregs.cr3 = 0;
        s.sregs.cr4 = 0;
        s.sregs.efer = 0;
        s.sregs.cs = Segment {
            selector: 8,
            limit: u32::MAX,
            type_: 11,
            present: true,
            s: true,
            db: true,
            g: true,
            ..Default::default()
        };
        s.sregs.ds = Segment {
            selector: 16,
            limit: u32::MAX,
            type_: 3,
            present: true,
            s: true,
            db: true,
            g: true,
            ..Default::default()
        };
        s.sregs.gdt = DescriptorTable { base: 0, limit: 0 };
        self.vm.vcpus[cpu].set_state(&state).unwrap();
        assert!(self.vm.vcpus[cpu].step_insn().unwrap().is_none());
        self.vm.vcpus[cpu].get_state().unwrap()
    }

    fn store(&mut self, cpu: usize, address: u64, value: u32) {
        let mut code = vec![0xc7, 0x05];
        code.extend_from_slice(&(address as u32).to_le_bytes());
        code.extend_from_slice(&value.to_le_bytes());
        self.execute(cpu, &code);
    }

    fn load(&mut self, cpu: usize, address: u64) -> u32 {
        let mut code = vec![0xa1];
        code.extend_from_slice(&(address as u32).to_le_bytes());
        let CpuState::X86_64(state) = self.execute(cpu, &code) else {
            panic!("x86 fixture")
        };
        state.regs.rax as u32
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.kernel).unwrap();
    }
}

#[test]
fn guest_tpr_write_is_visible_to_vmm_bus_and_snapshot() {
    let mut fixture = Fixture::new(1);
    for priority in [0x10u32, 0x5f, 0xa5, 0xff, 0] {
        fixture.store(0, TPR, priority);
        let mut bytes = [0; 4];
        fixture.vm.mmio_bus.read(TPR, &mut bytes).unwrap();
        assert_eq!(u32::from_le_bytes(bytes), priority, "live VMM controller");
        let snapshot = fixture.vm.take_snapshot(0).unwrap();
        let mut device = LapicDevice::new(Arc::new(std::sync::Mutex::new(snapshot.devices.lapic)));
        device.read(TPR, &mut bytes);
        assert_eq!(u32::from_le_bytes(bytes), priority, "captured controller");
    }
}

#[test]
fn vmm_controller_write_is_visible_to_guest_load() {
    let mut fixture = Fixture::new(1);
    for priority in [0x10u32, 0x5f, 0xa5, 0xff, 0] {
        fixture
            .vm
            .mmio_bus
            .write(TPR, &priority.to_le_bytes())
            .unwrap();
        assert_eq!(fixture.load(0, TPR), priority);
    }
}

#[test]
fn guest_self_ipi_reaches_the_controller_polled_by_vmm() {
    let mut fixture = Fixture::new(1);
    fixture.store(0, LAPIC_BASE + 0x300, (1 << 18) | 0x51);
    assert_eq!(
        fixture.vm.lapic.lock().unwrap().get_pending_vector(),
        Some(0x51)
    );
}

#[test]
fn every_constructed_cpu_observes_its_own_lapic_id() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count);
        for index in 0..usize::from(count) {
            assert_eq!(fixture.load(index, LAPIC_BASE + 0x20), (index as u32) << 24);
        }
    }
}

struct CallbackProbe {
    cpu: Box<dyn VCpu>,
    controller: Arc<std::sync::Mutex<LocalApic>>,
    accepted: Arc<std::sync::atomic::AtomicBool>,
    attempts: Arc<AtomicU64>,
}

impl VCpu for CallbackProbe {
    fn id(&self) -> u32 {
        self.cpu.id()
    }

    fn run(&mut self) -> Result<VcpuExit> {
        self.cpu.run()
    }
    fn get_state(&self) -> Result<CpuState> {
        self.cpu.get_state()
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.cpu.set_state(state)
    }
    fn complete_io_in(&mut self, data: &[u8]) {
        self.cpu.complete_io_in(data);
    }
    fn can_inject_interrupt(&self) -> bool {
        true
    }
    fn inject_interrupt(&mut self, _vector: u8) -> Result<bool> {
        // An injection may itself access guest memory/device state. Acquiring
        // this lock must succeed before the VMM acknowledges the interrupt.
        let _controller = self
            .controller
            .try_lock()
            .map_err(|_| Error::Emulator("controller lock held across CPU injection".into()))?;
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Ok(self.accepted.load(Ordering::SeqCst))
    }
}

fn probe(
    fixture: &mut Fixture,
    accept: bool,
) -> (Arc<std::sync::atomic::AtomicBool>, Arc<AtomicU64>) {
    let accepted = Arc::new(std::sync::atomic::AtomicBool::new(accept));
    let attempts = Arc::new(AtomicU64::new(0));
    let cpu = fixture.vm.vcpus.remove(0);
    fixture.vm.vcpus.push(Box::new(CallbackProbe {
        cpu,
        controller: fixture.vm.lapic.clone(),
        accepted: accepted.clone(),
        attempts: attempts.clone(),
    }));
    (accepted, attempts)
}

#[test]
fn delivery_releases_controller_lock_and_preserves_rejected_irq() {
    let mut fixture = Fixture::new(1);
    let (accepted, attempts) = probe(&mut fixture, false);
    fixture.vm.lapic.lock().unwrap().set_irr(0x51);
    fixture.vm.poll_local_apic(0).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.vm.lapic.lock().unwrap().get_pending_vector(),
        Some(0x51)
    );
    accepted.store(true, Ordering::SeqCst);
    fixture.vm.poll_local_apic(0).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    let lapic = fixture.vm.lapic.lock().unwrap();
    assert_eq!(lapic.get_pending_vector(), None);
    assert_eq!(lapic.read_register(0x120), 1 << 17);
}

#[test]
fn tpr_in_service_priority_and_software_disable_keep_irr_pending() {
    let mut fixture = Fixture::new(1);
    let (_, attempts) = probe(&mut fixture, true);
    {
        let mut lapic = fixture.vm.lapic.lock().unwrap();
        lapic.write_register(0x80, 0x50);
        lapic.set_irr(0x51);
    }
    fixture.vm.poll_local_apic(0).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    fixture.vm.lapic.lock().unwrap().write_register(0x80, 0);
    fixture.vm.poll_local_apic(0).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    fixture.vm.lapic.lock().unwrap().set_irr(0x41);
    fixture.vm.poll_local_apic(0).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    fixture.vm.lapic.lock().unwrap().write_register(0xb0, 0);
    fixture.vm.poll_local_apic(0).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    {
        let mut lapic = fixture.vm.lapic.lock().unwrap();
        lapic.write_register(0xf0, 0xff);
        lapic.set_irr(0x61);
    }
    fixture.vm.poll_local_apic(0).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    fixture.vm.lapic.lock().unwrap().write_register(0xf0, 0x1ff);
    fixture.vm.poll_local_apic(0).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.vm.lapic.lock().unwrap().get_pending_vector(), None);
}
