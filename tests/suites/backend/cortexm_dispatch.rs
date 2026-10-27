//! Existing Cortex-M4 core selected through VM/backend construction paths.
use rax::backend::emulator::{EmulatorBackend, EmulatorVm};
use rax::backend::{self, Backend, Vm};
use rax::config::{ArchKind, BackendKind, CliConfig, Endianness, HexagonIsa, MemorySize, VmConfig};
use rax::vm::{
    runtime::Vmm,
    snapshot::Snapshot,
    vcpu::{CortexMRegisters, CpuState, RetirementStop, VCpu, VcpuExit},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;
const PROGRAM: [u8; 10] = [0x2a, 0x20, 0x08, 0x60, 0x01, 0x30, 0x30, 0xbf, 0x07, 0x20];
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    kernel: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-cm-dispatch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let kernel = directory.join("kernel.bin");
        let mut image = Vec::new();
        image.extend_from_slice(&0x20001000u32.to_le_bytes());
        image.extend_from_slice(&9u32.to_le_bytes());
        image.extend_from_slice(&PROGRAM);
        std::fs::write(&kernel, image).unwrap();
        Self { directory, kernel }
    }
    fn config(&self) -> VmConfig {
        VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::CortexM),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "retaining failed CortexM fixture:{}",
                self.directory.display()
            );
        } else {
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }
}
fn memory() -> Arc<GuestMemoryMmap> {
    let m = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    m.write_slice(&PROGRAM, GuestAddress(CODE)).unwrap();
    m
}
fn vm() -> EmulatorVm {
    EmulatorVm::new(
        ArchKind::CortexM,
        HexagonIsa::default(),
        Endianness::Little,
        None,
    )
}
fn prepare(cpu: &mut dyn VCpu) {
    let mut regs = CortexMRegisters::default();
    regs.pc = CODE as u32;
    regs.msp = 0x3f00;
    regs.r[1] = DATA as u32;
    cpu.set_state(&CpuState::cortex_m(regs, Default::default()))
        .unwrap();
}
fn register(cpu: &dyn VCpu) -> CortexMRegisters {
    let CpuState::CortexM(s) = cpu.get_state().unwrap() else {
        panic!("wrong state kind")
    };
    s.regs
}
#[test]
fn configured_backend_creates_a_real_stepping_cortexm_cpu() {
    let f = Fixture::new();
    let backend = backend::create(&f.config()).unwrap();
    assert_eq!(backend.name(), "emulator");
    let vm = backend.create_vm().unwrap();
    let cpu = vm.create_vcpu(7, memory()).unwrap();
    assert_eq!(cpu.id(), 7);
    assert!(cpu.supports_stepping());
    assert!(matches!(cpu.get_state().unwrap(), CpuState::CortexM(_)));
}
#[test]
fn direct_backend_and_vm_factories_select_the_same_adapter() {
    let backend =
        EmulatorBackend::new(ArchKind::CortexM, HexagonIsa::default(), Endianness::Little);
    let vm1 = backend.create_vm().unwrap();
    for vm in [&*vm1 as &dyn Vm, &vm() as &dyn Vm] {
        let cpu = vm.create_vcpu(3, memory()).unwrap();
        assert_eq!(cpu.id(), 3);
        assert!(cpu.supports_stepping());
        assert_eq!(register(&*cpu).xpsr, 0x01000000);
    }
}
#[test]
fn cpu_identifier_domain_is_not_truncated() {
    for id in [0, 1, 255, u32::MAX] {
        let cpu = vm().create_vcpu(id, memory()).unwrap();
        assert_eq!(cpu.id(), id);
    }
}
#[test]
fn factory_cpu_executes_actual_thumb_data_operations() {
    let memory = memory();
    let mut cpu = vm().create_vcpu(0, memory.clone()).unwrap();
    prepare(&mut *cpu);
    let result = cpu.run_retirement_budget(3).unwrap();
    assert_eq!(result.retired, 3);
    assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
    assert_eq!(cpu.current_pc(), CODE + 6);
    assert_eq!(register(&*cpu).r[0], 43);
    let mut word = [0; 4];
    memory.read_slice(&mut word, GuestAddress(DATA)).unwrap();
    assert_eq!(u32::from_le_bytes(word), 42);
}
#[test]
fn factory_wait_and_wake_keep_retirement_boundaries() {
    let mut cpu = vm().create_vcpu(0, memory()).unwrap();
    prepare(&mut *cpu);
    let first = cpu.run_retirement_budget(1000).unwrap();
    assert_eq!(first.retired, 4);
    assert!(matches!(first.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    let wait = cpu.run_retirement_budget(1000).unwrap();
    assert_eq!(wait.retired, 0);
    assert!(matches!(wait.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    cpu.wake();
    let result = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 1);
    assert_eq!(register(&*cpu).r[0], 7);
    assert_eq!(cpu.current_pc(), CODE + 10);
}
#[test]
fn actual_vmm_boot_loads_vector_stack_and_thumb_entry() {
    let f = Fixture::new();
    let vm = Vmm::new(f.config()).unwrap();
    let cpus = vm.capture_cpu_states().unwrap();
    assert_eq!(cpus.len(), 1);
    let CpuState::CortexM(s) = &cpus[0].state else {
        panic!()
    };
    assert_eq!(
        (s.regs.pc, s.regs.msp, s.regs.xpsr, s.sregs.vtor),
        (8, 0x20001000, 0x01000000, 0)
    );
}
#[test]
fn resumed_vmm_can_construct_and_import_the_existing_base_state() {
    let f = Fixture::new();
    let source = Vmm::new(f.config()).unwrap();
    let snapshot = source.take_snapshot(0).unwrap();
    let file = f.directory.join("base.rxc");
    snapshot.save(&file).unwrap();
    let loaded = Snapshot::load(&file).unwrap();
    let mut target = Vmm::new_resume(f.config()).unwrap();
    target.restore_snapshot(&loaded).unwrap();
    let states = target.capture_cpu_states().unwrap();
    let CpuState::CortexM(s) = &states[0].state else {
        panic!()
    };
    assert_eq!((s.regs.pc, s.regs.msp), (8, 0x20001000));
}
#[test]
fn existing_unimplemented_arm_selectors_keep_explicit_errors() {
    for arch in [ArchKind::Armv8a32, ArchKind::CortexR] {
        let vm = EmulatorVm::new(arch, HexagonIsa::default(), Endianness::Little, None);
        assert!(
            vm.create_vcpu(0, memory())
                .err()
                .unwrap()
                .to_string()
                .contains("Unsupported architecture")
        );
    }
}
pub fn emit_reference(path: &std::path::Path) {
    let mut rows = Vec::new();
    for count in [1u32, 2, 4] {
        let vm = vm();
        for id in 0..count {
            let m = memory();
            let mut cpu = vm.create_vcpu(id, m.clone()).unwrap();
            prepare(&mut *cpu);
            let first = cpu.run_retirement_budget(3).unwrap();
            assert!(matches!(first.stop, RetirementStop::BudgetExhausted));
            let mut word = [0; 4];
            m.read_slice(&mut word, GuestAddress(DATA)).unwrap();
            let r = register(&*cpu);
            for value in [
                u64::from(count),
                u64::from(cpu.id()),
                first.retired,
                cpu.current_pc(),
                u64::from(r.r[0]),
                u64::from(u32::from_le_bytes(word)),
            ] {
                rows.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    std::fs::write(path, rows).unwrap();
}
