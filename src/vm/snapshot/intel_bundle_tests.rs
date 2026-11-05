//! Portable Intel producer/file admission; SDK images and profiles are synthetic.
use super::*;
use crate::backend::intel_hvf_context::{Context, GlobalContext};
use crate::config::{ArchKind, BackendKind};
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[path = "intel_bundle_tests/file_owners.rs"]
mod file_owners;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct TestPath(std::path::PathBuf);
impl TestPath {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "rax-intel-bundle-{}-{}.rxc",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for TestPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
type Inputs = (
    Snapshot,
    Vec<CpuSnapshot>,
    Vec<Option<BackendContext>>,
    BackendContext,
);
fn inputs(count: u8) -> Inputs {
    let mut base = super::tests::snapshot_with_memory_metadata(4096, 4096);
    base.config.arch = ArchKind::X86_64;
    base.config.backend = BackendKind::Hvf;
    base.config.vcpus = count;
    base.memory_data = zstd::encode_all(&[0x51; 4096][..], 3).unwrap();
    let mut cpus = Vec::new();
    let mut records = Vec::new();
    for id in 0..count {
        let mut context = crate::backend::intel_hvf_context::tests::context();
        context.id = u32::from(id);
        cpus.push(CpuSnapshot {
            state: CpuState::X86_64(context.public.clone()),
            emulator: context.emulator.clone(),
        });
        records.push(Some(BackendContext {
            kind: HVF_INTEL_CONTEXT,
            data: context.encode().unwrap(),
        }));
    }
    base.cpu_state = cpus[0].state.clone();
    base.emulator_state = cpus[0].emulator.clone();
    let shared = BackendContext {
        kind: HVF_INTEL_CONTEXT,
        data: GlobalContext {
            cpus: count,
            ram_size: 4096,
            regions: vec![(0, 4096)],
            fixed_holes: vec![],
            pending_irqs: vec![],
            resume_clock: None,
            anchor: 1000,
        }
        .encode()
        .unwrap(),
    };
    (base, cpus, records, shared)
}
fn complete(count: u8) -> SnapshotBundle {
    let (base, cpus, records, shared) = inputs(count);
    let bundle = SnapshotBundle::new(base)
        .with_checkpoint_records(cpus, records, Some(shared))
        .unwrap();
    let execution = ExecutionSnapshot {
        cursor: 0,
        retired: 0,
        online: (0..count).map(|id| id == 0).collect(),
        local_apics: (0..count)
            .map(|id| {
                let apic = if id == 0 {
                    bundle.base.devices.lapic.clone()
                } else {
                    crate::devices::lapic::LocalApic::new(u32::from(id))
                };
                apic.checkpoint_at(std::time::Instant::now())
            })
            .collect(),
        riscv_platform: None,
        arm_cluster: None,
        pc: None,
        pl011: None,
    };
    let mut clock = crate::vm::timing::TimingContext::default().checkpoint_state();
    clock.elapsed_nanos = bundle.base.elapsed_nanos;
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    memory.write_slice(&[0x51; 4096], GuestAddress(0)).unwrap();
    let bundle = bundle
        .with_execution(execution)
        .unwrap()
        .with_clock(clock)
        .unwrap()
        .with_physical_memory(PhysicalMemorySnapshot::capture(&memory).unwrap())
        .unwrap();
    file_owners::with_owned_devices(bundle)
}

#[test]
fn portable_intel_files_preserve_complete_one_two_four_cpu_graphs() {
    for count in [1, 2, 4] {
        let saved = complete(count);
        let path = TestPath::new();
        saved.save(&path.0).unwrap();
        let loaded = SnapshotBundle::load(&path.0).unwrap();
        assert_eq!(loaded.vm_context(), saved.vm_context());
        assert_eq!(
            loaded.backend_contexts().unwrap().entries(),
            saved.backend_contexts().unwrap().entries()
        );
        assert_eq!(loaded.cpus().unwrap().entries().len(), usize::from(count));
        assert_eq!(loaded.base.decompress_memory().unwrap(), vec![0x51; 4096]);
    }
}

#[test]
fn intel_producer_rejects_missing_foreign_and_inconsistent_graphs() {
    for corruption in 0..9 {
        let (mut base, mut cpus, mut records, mut shared) = inputs(2);
        match corruption {
            0 => {
                cpus.pop();
            }
            1 => records[1] = None,
            2 => records[1].as_mut().unwrap().kind = HVF_AARCH64_CONTEXT,
            3 => records[1].as_mut().unwrap().data[8..12].copy_from_slice(&0u32.to_le_bytes()),
            4 => shared.kind = HVF_AARCH64_CONTEXT,
            5 => base.config.backend = BackendKind::Emulator,
            6 => {
                *shared.data.last_mut().unwrap() ^= 1;
            }
            7 => {
                if let CpuState::X86_64(cpu) = &mut cpus[1].state {
                    cpu.regs.rax ^= 1;
                }
            }
            8 => {
                let mut state = GlobalContext::decode(&shared.data).unwrap();
                state.resume_clock = Some(0);
                shared.data = state.encode().unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            SnapshotBundle::new(base)
                .with_checkpoint_records(cpus, records, Some(shared))
                .is_err(),
            "case {corruption}"
        );
    }
}

#[test]
fn native_intel_files_require_coordinator_clock_and_complete_physical_spans() {
    for missing in 0..3 {
        let mut bundle = complete(1);
        match missing {
            0 => bundle.execution = None,
            1 => bundle.clock = None,
            2 => bundle.physical_memory = None,
            _ => unreachable!(),
        }
        let path = TestPath::new();
        assert!(bundle.save(&path.0).is_err(), "missing component {missing}");
        assert!(!path.0.exists());
    }
    let mut bundle = complete(1);
    let record = bundle.vm_context.as_mut().unwrap();
    let mut shared = GlobalContext::decode(&record.data).unwrap();
    shared.regions.push((0x8000, 4096));
    record.data = shared.encode().unwrap();
    let path = TestPath::new();
    assert!(bundle.save(&path.0).is_err());
    assert!(!path.0.exists());
}

#[test]
fn native_intel_priority_graph_checks_low_tpr_bits_as_well_as_cr8() {
    let mut bundle = complete(1);
    let mut context = Context::decode(
        &bundle.backend_contexts().unwrap().entries()[0]
            .as_ref()
            .unwrap()
            .data,
    )
    .unwrap();
    context.tpr = 0x0b;
    let (public, emulator) = context.projection().unwrap();
    context.public = public;
    context.emulator = emulator;
    // CR8 remains zero while the full TPR differs from the controller record.
    assert_eq!(context.public.sregs.cr8, 0);
    bundle.backend_contexts = Some(
        BackendContexts::capture(
            vec![Some(BackendContext {
                kind: HVF_INTEL_CONTEXT,
                data: context.encode().unwrap(),
            })],
            1,
        )
        .unwrap(),
    );
    assert!(bundle.validate().is_err());
}
