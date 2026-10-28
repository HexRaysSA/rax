//! Every represented CPU must be admitted before any CPU/RAM/device mutation.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "rax-cpu-live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, [0; 64]).unwrap();
        Self(p)
    }
    fn vm(&self, arch: ArchKind, n: u8) -> Vmm {
        let mut c = VmConfig::from_sources(
            CliConfig {
                arch: Some(arch),
                backend: Some(BackendKind::Emulator),
                vcpus: Some(n),
                kernel: Some(self.0.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        c.memory = MemorySize(4096);
        Vmm::new_resume(c).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}
fn mark(vm: &mut Vmm) {
    for (index, vcpu) in vm.vcpus.iter_mut().enumerate() {
        let mut state = vcpu.get_state().unwrap();
        let value = 0x12340000 + index as u64;
        match &mut state {
            CpuState::X86_64(s) => s.regs.rax = value,
            CpuState::Aarch64(s) => s.regs.x[3] = value,
            CpuState::RiscV(s) => s.regs.x[3] = value,
            _ => unreachable!(),
        };
        vcpu.set_state(&state).unwrap();
    }
}
fn bytes(vm: &Vmm) -> Vec<Vec<u8>> {
    vm.capture_cpu_states()
        .unwrap()
        .into_iter()
        .map(|e| crate::codec::serialize(&(e.state, e.emulator)).unwrap())
        .collect()
}
fn represented(vm: &Vmm) -> SnapshotBundle {
    let base = vm.take_snapshot(53).unwrap();
    let mut b = SnapshotBundle::new(base)
        .with_cpus(vm.capture_cpu_states().unwrap())
        .unwrap();
    // A shared ARM controller/power graph is required even when this fixture
    // checks only represented CPU bytes. Keep the one-CPU legacy case intact.
    if vm.checkpoint_config.arch == ArchKind::Aarch64 && vm.checkpoint_config.vcpus > 1 {
        b = b
            .with_execution(vm.capture_execution_state().unwrap())
            .unwrap();
    }
    if let Some(p) = &vm.pci_devices {
        b = b.with_pci(p.checkpoint().unwrap()).unwrap();
    }
    b
}
#[test]
fn one_two_four_x86_arm_and_riscv_contexts_restore_exact_represented_bytes() {
    let f = Fixture::new();
    for arch in [ArchKind::X86_64, ArchKind::Aarch64, ArchKind::Riscv64] {
        for n in [1, 2, 4] {
            let mut source = f.vm(arch, n);
            mark(&mut source);
            let expected = bytes(&source);
            let b = represented(&source);
            let mut target = f.vm(arch, n);
            target.restore_snapshot_bundle(&b).unwrap();
            assert_eq!(bytes(&target), expected, "{arch:?}/{n}");
        }
    }
}
#[test]
fn default_four_cpu_physical_file_capture_retains_every_context() {
    let f = Fixture::new();
    let mut source = f.vm(ArchKind::X86_64, 4);
    mark(&mut source);
    let expected = bytes(&source);
    let b = source.take_snapshot_bundle(53).unwrap();
    assert_eq!(b.cpus().unwrap().entries().len(), 4);
    let p = f.0.with_extension("rxc");
    b.save(&p).unwrap();
    let b = SnapshotBundle::load(&p).unwrap();
    let mut target = f.vm(ArchKind::X86_64, 4);
    target.restore_snapshot_bundle(&b).unwrap();
    assert_eq!(bytes(&target), expected);
    std::fs::remove_file(p).unwrap();
}
#[test]
fn last_riscv_privilege_failure_preserves_every_earlier_cpu_and_ram() {
    let f = Fixture::new();
    let mut source = f.vm(ArchKind::Riscv64, 4);
    mark(&mut source);
    let base = source.take_snapshot(53).unwrap();
    let mut states = source.capture_cpu_states().unwrap();
    let CpuState::RiscV(s) = &mut states[3].state else {
        unreachable!()
    };
    s.regs.privilege = Some(2);
    let b = SnapshotBundle::new(base).with_cpus(states).unwrap();
    let mut target = f.vm(ArchKind::Riscv64, 4);
    target.guest_mem.write_all(&[0xa5; 4096]).unwrap();
    let before = bytes(&target);
    assert!(target.restore_snapshot_bundle(&b).is_err());
    assert_eq!(bytes(&target), before);
    assert_eq!(target.guest_mem.try_read_all().unwrap(), vec![0xa5; 4096]);
}
