//! Required clock framing, complete typed state and runtime publication order.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::devices::{lapic::LocalApic, pic::DualPic, pit::Pit, serial::Serial16550};
use rax::vm::{
    runtime::Vmm,
    snapshot::{DeviceState, EmulatorState, Snapshot, SnapshotBundle},
    timing::{ClockMode, ClockState, TimingContext},
    vcpu::{CpuState, Registers, SystemRegisters},
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
const RAM: usize = 4096;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    kernel: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-clock-file-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let kernel = directory.join("kernel.bin");
        std::fs::write(&kernel, [0; 64]).unwrap();
        Self { directory, kernel }
    }
    fn config(&self) -> VmConfig {
        let mut c = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        c.memory = MemorySize(RAM as u64);
        c.pci_devices = false;
        c
    }
    fn base(&self, elapsed: u64) -> Snapshot {
        Snapshot::new(
            self.config().to_checkpoint(),
            17,
            elapsed,
            CpuState::x86_64(
                Registers {
                    rip: 0x1000,
                    rflags: 2,
                    ..Default::default()
                },
                SystemRegisters::default(),
            ),
            EmulatorState::default(),
            DeviceState {
                pic: DualPic::new(),
                pit: Pit::new(),
                serial: Serial16550::new(0x3f8),
                lapic: LocalApic::new(0),
            },
            &vec![0x6b; RAM],
        )
        .unwrap()
    }
    fn bundle(&self, state: ClockState) -> SnapshotBundle {
        SnapshotBundle::new(self.base(state.elapsed_nanos))
            .with_clock(state)
            .unwrap()
    }
    fn raw(&self, b: &SnapshotBundle) -> Vec<u8> {
        let path = self.directory.join("input.rxc");
        b.save(&path).unwrap();
        std::fs::read(path).unwrap()
    }
    fn read(&self, raw: &[u8]) -> rax::Result<SnapshotBundle> {
        let p = self.directory.join("mutated.rxc");
        std::fs::write(&p, raw).unwrap();
        SnapshotBundle::load(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "retaining failed clock fixture:{}",
                self.directory.display()
            );
        } else {
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }
}
fn state(mode: ClockMode, phase: u8) -> ClockState {
    ClockState {
        mode,
        elapsed_nanos: 97,
        retired_units: if mode == ClockMode::Retired {
            0x123456789abcdef0
        } else {
            0
        },
        subnanosecond_quanta: phase,
        diagnostic_ticks: 37,
        timer_pending: true,
    }
}
#[cfg(test)]
fn with_bridge(bundle: SnapshotBundle) -> SnapshotBundle {
    let memory = std::sync::Arc::new(
        vm_memory::GuestMemoryMmap::<()>::from_ranges(&[(vm_memory::GuestAddress(0), RAM)])
            .unwrap(),
    );
    let checkpoint =
        rax::vm::runtime::pci_state::PciDevices::new(memory, &Default::default(), false)
            .unwrap()
            .checkpoint()
            .unwrap();
    bundle.with_pci(checkpoint).unwrap()
}
#[derive(Clone)]
struct Section {
    kind: u32,
    schema: u32,
    data: Vec<u8>,
}
fn sections(raw: &[u8]) -> Vec<Section> {
    let count = u32::from_le_bytes(raw[16..20].try_into().unwrap());
    let mut at = 20;
    let mut parts = Vec::new();
    for _ in 0..count {
        let kind = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let schema = u32::from_le_bytes(raw[at + 4..at + 8].try_into().unwrap());
        let n = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap()) as usize;
        parts.push(Section {
            kind,
            schema,
            data: raw[at + 16..at + 16 + n].to_vec(),
        });
        at += 16 + n;
    }
    assert_eq!(at, raw.len());
    parts
}
fn assemble(parts: &[Section]) -> Vec<u8> {
    let mut raw = b"RAXCKPT\0".to_vec();
    raw.extend_from_slice(&8u32.to_le_bytes());
    raw.extend_from_slice(b"RXS8");
    raw.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    for p in parts {
        raw.extend_from_slice(&p.kind.to_le_bytes());
        raw.extend_from_slice(&p.schema.to_le_bytes());
        raw.extend_from_slice(&(p.data.len() as u64).to_le_bytes());
        raw.extend_from_slice(&p.data);
    }
    raw
}
fn clock(parts: &mut [Section]) -> &mut Section {
    parts.iter_mut().find(|p| p.kind == 12).unwrap()
}
#[test]
fn wall_and_all_retired_phases_roundtrip_every_field() {
    let f = Fixture::new();
    for (mode, phases) in [
        (ClockMode::Wall, vec![0]),
        (ClockMode::Retired, vec![0, 1, 2]),
    ] {
        for phase in phases {
            let s = state(mode, phase);
            let b = f.bundle(s);
            let raw = f.raw(&b);
            assert_eq!(f.read(&raw).unwrap().clock(), Some(&s));
        }
    }
}
#[test]
fn full_width_fields_and_final_phase_roundtrip() {
    let f = Fixture::new();
    let mut s = state(ClockMode::Retired, 2);
    s.elapsed_nanos = u64::MAX;
    s.retired_units = u64::MAX;
    s.diagnostic_ticks = u64::MAX;
    assert_eq!(f.read(&f.raw(&f.bundle(s))).unwrap().clock(), Some(&s));
}
#[test]
fn original_base_writer_has_six_sections_and_no_clock() {
    let f = Fixture::new();
    let p = f.directory.join("base.rxc");
    f.base(97).save(&p).unwrap();
    let raw = std::fs::read(&p).unwrap();
    assert_eq!(sections(&raw).len(), 6);
    assert!(SnapshotBundle::load(&p).unwrap().clock().is_none());
    assert_eq!(Snapshot::load(&p).unwrap().elapsed_nanos, 97);
}
#[test]
fn canonical_clock_record_precedes_ram_and_has_fixed_framing() {
    let f = Fixture::new();
    let parts = sections(&f.raw(&f.bundle(state(ClockMode::Retired, 2))));
    assert_eq!(
        parts.iter().map(|s| s.kind).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 12, 6]
    );
    let c = &parts[5];
    assert_eq!(c.schema, 1);
    assert_eq!(c.data.len(), 44);
    assert_eq!(&c.data[..8], b"RAXCLK01");
    assert_eq!(&c.data[8..16], &3_000_000_000u64.to_le_bytes());
    assert_eq!(&c.data[16..20], &[1, 2, 1, 0]);
}
#[test]
fn malformed_clock_fields_are_rejected() {
    let f = Fixture::new();
    let original = sections(&f.raw(&f.bundle(state(ClockMode::Wall, 0))));
    for (offset, value) in [
        (0, b'X'),
        (8, 1),
        (16, 2),
        (17, 3),
        (18, 2),
        (19, 1),
        (20, 98),
        (28, 1),
    ] {
        let mut p = original.clone();
        clock(&mut p).data[offset] = value;
        assert!(f.read(&assemble(&p)).is_err(), "offset{offset}");
    }
}
#[test]
fn record_lengths_are_checked_before_payload_read() {
    let f = Fixture::new();
    let original = f.raw(&f.bundle(state(ClockMode::Retired, 2)));
    let mut at = 20;
    while u32::from_le_bytes(original[at..at + 4].try_into().unwrap()) != 12 {
        let n = u64::from_le_bytes(original[at + 8..at + 16].try_into().unwrap()) as usize;
        at += 16 + n;
    }
    for n in [0u64, 43, 45, u64::MAX] {
        let mut raw = original.clone();
        raw[at + 8..at + 16].copy_from_slice(&n.to_le_bytes());
        assert!(f.read(&raw).err().unwrap().to_string().contains("44 bytes"));
    }
}
#[test]
fn duplicate_alias_schema_and_late_order_are_rejected() {
    let f = Fixture::new();
    let original = sections(&f.raw(&f.bundle(state(ClockMode::Retired, 2))));
    for case in 0..4 {
        let mut p = original.clone();
        match case {
            0 => {
                let c = clock(&mut p).clone();
                p.insert(6, c)
            }
            1 => clock(&mut p).kind |= 1 << 31,
            2 => clock(&mut p).schema = 2,
            3 => {
                let c = p.remove(5);
                p.push(c)
            }
            _ => unreachable!(),
        };
        assert!(f.read(&assemble(&p)).is_err(), "case{case}");
    }
}
#[test]
fn base_reader_rejects_required_clock_header_before_missing_payload() {
    let f = Fixture::new();
    let mut raw = b"RAXCKPT\0".to_vec();
    raw.extend_from_slice(&8u32.to_le_bytes());
    raw.extend_from_slice(b"RXS8");
    raw.extend_from_slice(&1u32.to_le_bytes());
    raw.extend_from_slice(&12u32.to_le_bytes());
    raw.extend_from_slice(&1u32.to_le_bytes());
    raw.extend_from_slice(&44u64.to_le_bytes());
    let p = f.directory.join("header.rxc");
    std::fs::write(&p, &raw).unwrap();
    assert!(
        Snapshot::load(&p)
            .err()
            .unwrap()
            .to_string()
            .contains("required clock state")
    );
    assert!(
        SnapshotBundle::load(&p)
            .err()
            .unwrap()
            .to_string()
            .contains("precedes checkpoint config")
    );
}
#[test]
fn clock_conflicting_with_base_metadata_is_rejected_at_attachment() {
    let f = Fixture::new();
    assert!(
        SnapshotBundle::new(f.base(98))
            .with_clock(state(ClockMode::Wall, 0))
            .is_err()
    );
}
#[test]
fn required_clock_must_be_explicitly_handled_before_extraction() {
    let f = Fixture::new();
    assert!(f.bundle(state(ClockMode::Wall, 0)).into_base().is_err());
    assert!(f.bundle(state(ClockMode::Wall, 0)).into_parts().is_err());
    let mut b = f.bundle(state(ClockMode::Wall, 0));
    let s = b.take_clock().unwrap();
    assert_eq!(s.diagnostic_ticks, 37);
    assert!(b.clock().is_none());
    assert_eq!(b.into_base().unwrap().elapsed_nanos, 97);
}
#[test]
fn runtime_restores_diagnostic_ticks_notification_and_time_anchor() {
    let f = Fixture::new();
    let b = with_bridge(f.bundle(state(ClockMode::Wall, 0)));
    let mut vm = Vmm::new_resume(f.config()).unwrap();
    vm.restore_snapshot_bundle(&b).unwrap();
    let restored = vm.timing_context().checkpoint_state();
    assert_eq!(restored.diagnostic_ticks, 37);
    assert!(restored.timer_pending);
    assert!(restored.elapsed_nanos >= 97);
    assert_eq!(
        vm.take_snapshot(0).unwrap().decompress_memory().unwrap(),
        vec![0x6b; RAM]
    );
}
#[test]
fn retired_mode_is_rejected_before_runtime_or_constructor_mutation() {
    let f = Fixture::new();
    let b = f.bundle(state(ClockMode::Retired, 2));
    let mut vm = Vmm::new_resume(f.config()).unwrap();
    vm.timing_context().tick();
    let before = vm.take_snapshot(0).unwrap();
    assert!(vm.restore_snapshot_bundle(&b).is_err());
    assert_eq!(vm.timing_context().instruction_count(), 1);
    assert!(!vm.timing_context().is_timer_pending());
    assert_eq!(
        vm.take_snapshot(0).unwrap().decompress_memory().unwrap(),
        before.decompress_memory().unwrap()
    );
    assert!(
        f.config()
            .validate_resume_bundle(&b)
            .err()
            .unwrap()
            .to_string()
            .contains("deterministic coordinator")
    );
    assert!(Vmm::new_resume_bundle(f.config(), &b).is_err());
}
#[test]
fn legacy_base_projection_preserves_existing_unrepresented_tick_and_flag_state() {
    let f = Fixture::new();
    let mut vm = Vmm::new_resume(f.config()).unwrap();
    for _ in 0..7 {
        vm.timing_context().tick();
    }
    vm.timing_context().set_timer_pending();
    vm.restore_snapshot_bundle(&SnapshotBundle::new(f.base(97)))
        .unwrap();
    assert_eq!(vm.timing_context().instruction_count(), 7);
    assert!(vm.timing_context().is_timer_pending());
}
#[test]
fn late_cpu_admission_failure_does_not_publish_prepared_clock() {
    let f = Fixture::new();
    let mut s = state(ClockMode::Wall, 0);
    s.elapsed_nanos = 1_000_000_000_000_000;
    let mut base = f.base(s.elapsed_nanos);
    base.emulator_state.mxcsr = 1 << 16;
    let b = with_bridge(SnapshotBundle::new(base).with_clock(s).unwrap());
    let mut vm = Vmm::new_resume(f.config()).unwrap();
    for _ in 0..7 {
        vm.timing_context().tick();
    }
    assert!(
        vm.restore_snapshot_bundle(&b)
            .err()
            .unwrap()
            .to_string()
            .contains("MXCSR")
    );
    assert_eq!(vm.timing_context().instruction_count(), 7);
    assert!(!vm.timing_context().is_timer_pending());
    assert!(vm.timing_context().elapsed_nanos() < s.elapsed_nanos);
    assert_eq!(
        vm.take_snapshot(0).unwrap().decompress_memory().unwrap(),
        vec![0; RAM]
    );
}
pub fn emit_reference(directory: &std::path::Path) {
    std::fs::create_dir_all(directory).unwrap();
    let f = Fixture::new();
    for id in 0..5 {
        let mut s = if id == 0 {
            state(ClockMode::Wall, 0)
        } else {
            state(ClockMode::Retired, if id == 4 { 2 } else { id - 1 })
        };
        if id == 4 {
            s.elapsed_nanos = u64::MAX;
            s.retired_units = u64::MAX;
            s.diagnostic_ticks = u64::MAX;
        }
        let b = f.bundle(s);
        let path = directory.join(format!("clock-{id}.rxc"));
        b.save(&path).unwrap();
        let b = SnapshotBundle::load(path).unwrap();
        let target = TimingContext::with_mode(s.mode);
        target.restore_checkpoint_state(b.clock().unwrap()).unwrap();
        let values = if s.mode == ClockMode::Wall {
            vec![
                target.instruction_count(),
                u64::from(target.is_timer_pending()),
            ]
        } else {
            target.advance_retired(1).unwrap();
            let a = target.checkpoint_state();
            vec![
                a.elapsed_nanos,
                a.retired_units,
                u64::from(a.subnanosecond_quanta),
                a.diagnostic_ticks,
                u64::from(a.timer_pending),
            ]
        };
        let raw: Vec<_> = values.into_iter().flat_map(u64::to_le_bytes).collect();
        std::fs::write(directory.join(format!("clock-{id}.runtime")), raw).unwrap();
    }
}

#[test]
fn default_full_file_capture_and_detached_restore_preserve_clock_fields() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.memory = MemorySize(128 * 1024 * 1024);
    let source = Vmm::new_resume(config.clone()).unwrap();
    for _ in 0..37 {
        source.timing_context().tick();
    }
    source.timing_context().set_timer_pending();
    let bundle = source.take_snapshot_bundle(17).unwrap();
    let captured = *bundle.clock().unwrap();
    assert_eq!(captured.elapsed_nanos, bundle.base().elapsed_nanos);
    assert_eq!(captured.diagnostic_ticks, 37);
    assert!(captured.timer_pending);
    let path = fixture.directory.join("full.rxc");
    bundle.save(&path).unwrap();
    let bundle = SnapshotBundle::load(&path).unwrap();
    assert_eq!(bundle.clock(), Some(&captured));
    let target = Vmm::new_resume_bundle(config, &bundle).unwrap();
    assert_eq!(target.timing_context().instruction_count(), 37);
    assert!(target.timing_context().is_timer_pending());
    assert!(target.timing_context().elapsed_nanos() >= captured.elapsed_nanos);
}

#[test]
fn a_clock_component_cannot_substitute_for_missing_secondary_cpu_state() {
    let fixture = Fixture::new();
    let state = state(ClockMode::Wall, 0);
    let mut base = fixture.base(state.elapsed_nanos);
    base.config.vcpus = 2;
    let bundle = SnapshotBundle::new(base).with_clock(state).unwrap();
    let mut config = fixture.config();
    config.vcpus = 2;
    let mut target = Vmm::new_resume(config).unwrap();
    target.timing_context().tick();
    let before: Vec<_> = target
        .capture_cpu_states()
        .unwrap()
        .iter()
        .map(|c| c.state.pc())
        .collect();
    assert!(
        target
            .restore_snapshot_bundle(&bundle)
            .err()
            .unwrap()
            .to_string()
            .contains("missing additional CPU state")
    );
    let after: Vec<_> = target
        .capture_cpu_states()
        .unwrap()
        .iter()
        .map(|c| c.state.pc())
        .collect();
    assert_eq!(after, before);
    assert_eq!(target.timing_context().instruction_count(), 1);
    assert!(!target.timing_context().is_timer_pending());
    assert_eq!(
        target
            .take_snapshot(0)
            .unwrap()
            .decompress_memory()
            .unwrap(),
        vec![0; RAM]
    );
}
