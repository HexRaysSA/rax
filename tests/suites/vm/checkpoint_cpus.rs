//! Ordered represented CPU contexts, full configured domain and pre-mutation admission.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::devices::{lapic::LocalApic, pic::DualPic, pit::Pit, serial::Serial16550};
use rax::vm::memory::vm::{GuestAddress, GuestMemoryMmap};
use rax::vm::runtime::{Vmm, pci_state::PciDevices};
use rax::vm::snapshot::{CpuSnapshot, DeviceState, EmulatorState, Snapshot, SnapshotBundle};
use rax::vm::vcpu::state::{CpuState, Registers};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
const RAM: usize = 4096;
fn word(id: u8, lane: usize) -> u64 {
    0x0102030405060708 ^ (u64::from(id) << 48) ^ (lane as u64 + 1)
}
fn entry(id: u8) -> CpuSnapshot {
    let mut regs = Registers::default();
    let mut lane = 0;
    macro_rules! mark {($($name:ident),*)=>{$(regs.$name=word(id,lane);lane+=1;)*}}
    mark!(
        rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17,
        r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30, r31
    );
    regs.rip = 0x1000 + u64::from(id) * 4;
    regs.rflags = 2 + u64::from(id & 1);
    for row in &mut regs.xmm {
        for cell in row {
            *cell = word(id, lane);
            lane += 1;
        }
    }
    for row in &mut regs.ymm_high {
        for cell in row {
            *cell = word(id, lane);
            lane += 1;
        }
    }
    for row in &mut regs.zmm_high {
        for cell in row {
            *cell = word(id, lane);
            lane += 1;
        }
    }
    for row in &mut regs.zmm_ext {
        for cell in row {
            *cell = word(id, lane);
            lane += 1;
        }
    }
    for cell in &mut regs.k {
        *cell = word(id, lane);
        lane += 1;
    }
    for cell in &mut regs.mm {
        *cell = word(id, lane);
        lane += 1;
    }
    assert_eq!(lane, 304);
    let mut emulator = EmulatorState::default();
    emulator.fpu.control_word = 0x37f;
    emulator.fpu.status_word = 0;
    emulator.fpu.tag_word = 0;
    emulator.fpu.data_ptr = 0x11110000 + u64::from(id);
    emulator.fpu.instr_ptr = 0x22220000 + u64::from(id);
    emulator.fpu.last_opcode = 0x123;
    emulator.fpu.top = 0;
    for (slot, value) in regs.mm.iter().enumerate() {
        emulator.fpu.st[slot][..8].copy_from_slice(&value.to_le_bytes());
        emulator.fpu.st[slot][8..].copy_from_slice(&[0xff, 0xff]);
    }
    emulator.kernel_gs_base = 0x33000000 + u64::from(id) * 0x1000;
    emulator.tsc_adjust = u64::from(id) * 3;
    emulator.tsc_aux = u32::from(id) * 17;
    emulator.misc_enable = 1;
    emulator.pat = 0x0007040600070406;
    emulator.umwait_control = 0x40;
    emulator.pkru = u32::from(id) * 0x10203;
    emulator.mxcsr = 0x1f80 | u32::from(id & 0x3f);
    emulator.halted = id & 1 != 0;
    emulator.interrupt_inhibit = id & 2 != 0;
    CpuSnapshot {
        state: CpuState::x86_64(regs, Default::default()),
        emulator,
    }
}
struct Fixture {
    dir: PathBuf,
    kernel: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rax-cpu-set-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let kernel = dir.join("kernel");
        std::fs::write(&kernel, [0; 64]).unwrap();
        Self { dir, kernel }
    }
    fn config(&self, n: u8) -> VmConfig {
        let mut c = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                vcpus: Some(n),
                kernel: Some(self.kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        c.memory = MemorySize(RAM as u64);
        c
    }
    fn base(&self, n: u8) -> Snapshot {
        let e = entry(0);
        Snapshot::new(
            self.config(n).to_checkpoint(),
            53,
            97,
            e.state,
            e.emulator,
            DeviceState {
                pic: DualPic::new(),
                pit: Pit::new(),
                serial: Serial16550::new(0x3f8),
                lapic: LocalApic::new(0),
            },
            &vec![0x33; RAM],
        )
        .unwrap()
    }
    fn bundle(&self, n: u8) -> SnapshotBundle {
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM)]).unwrap());
        let pci = PciDevices::new(memory, &Default::default(), false)
            .unwrap()
            .checkpoint()
            .unwrap();
        SnapshotBundle::new(self.base(n))
            .with_cpus((0..n).map(entry).collect())
            .unwrap()
            .with_pci(pci)
            .unwrap()
    }
    fn raw(&self, b: &SnapshotBundle) -> Vec<u8> {
        let p = self.dir.join("input.rxc");
        b.save(&p).unwrap();
        std::fs::read(p).unwrap()
    }
    fn read(&self, parts: &[Section]) -> rax::Result<SnapshotBundle> {
        let p = self.dir.join("mutated.rxc");
        std::fs::write(&p, assemble(parts)).unwrap();
        SnapshotBundle::load(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("retaining failed CPU-set fixture:{}", self.dir.display());
        } else {
            std::fs::remove_dir_all(&self.dir).unwrap();
        }
    }
}
#[cfg(test)]
fn all_bytes(entries: &[CpuSnapshot]) -> Vec<Vec<u8>> {
    entries
        .iter()
        .map(|e| bincode::serialize(&(&e.state, &e.emulator)).unwrap())
        .collect()
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
        let length = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap()) as usize;
        parts.push(Section {
            kind,
            schema,
            data: raw[at + 16..at + 16 + length].to_vec(),
        });
        at += 16 + length;
    }
    assert_eq!(at, raw.len());
    parts
}
fn assemble(parts: &[Section]) -> Vec<u8> {
    let mut r = b"RAXCKPT\0".to_vec();
    r.extend_from_slice(&8u32.to_le_bytes());
    r.extend_from_slice(b"RXS8");
    r.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    for p in parts {
        r.extend_from_slice(&p.kind.to_le_bytes());
        r.extend_from_slice(&p.schema.to_le_bytes());
        r.extend_from_slice(&(p.data.len() as u64).to_le_bytes());
        r.extend_from_slice(&p.data);
    }
    r
}
fn cpu_section(parts: &mut [Section]) -> &mut Vec<u8> {
    &mut parts.iter_mut().find(|p| p.kind == 11).unwrap().data
}
#[test]
fn all_configured_count_boundaries_and_one_two_four_roundtrip() {
    let f = Fixture::new();
    for n in [1, 2, 4, u8::MAX] {
        let b = f.bundle(n);
        let raw = f.raw(&b);
        let loaded = f.read(&sections(&raw)).unwrap();
        assert_eq!(
            all_bytes(loaded.cpus().unwrap().entries()),
            all_bytes(b.cpus().unwrap().entries())
        );
        assert_eq!(loaded.cpus().unwrap().entries().len(), n as usize);
    }
}
#[test]
fn runtime_restores_every_public_and_represented_private_register() {
    let f = Fixture::new();
    for n in [1, 2, 4] {
        let b = f.bundle(n);
        let mut vm = Vmm::new_resume(f.config(n)).unwrap();
        vm.restore_snapshot_bundle(&b).unwrap();
        assert_eq!(
            all_bytes(&vm.capture_cpu_states().unwrap()),
            all_bytes(b.cpus().unwrap().entries())
        );
        assert_eq!(vm.guest_mem().try_read_all().unwrap(), vec![0x33; RAM]);
    }
}
#[test]
fn late_invalid_private_state_precedes_every_cpu_and_ram_assignment() {
    let f = Fixture::new();
    for n in [2, 4] {
        let b = f.bundle(n);
        let mut entries = b.cpus().unwrap().entries().to_vec();
        entries.last_mut().unwrap().emulator.mxcsr = 0x80000000;
        let pci = b.pci().unwrap().to_devices().unwrap();
        let b = SnapshotBundle::new(f.base(n))
            .with_cpus(entries)
            .unwrap()
            .with_pci(pci)
            .unwrap();
        let mut vm = Vmm::new_resume(f.config(n)).unwrap();
        vm.guest_mem().write_all(&vec![0xa5; RAM]).unwrap();
        let before = all_bytes(&vm.capture_cpu_states().unwrap());
        assert!(vm.restore_snapshot_bundle(&b).is_err());
        assert_eq!(all_bytes(&vm.capture_cpu_states().unwrap()), before);
        assert_eq!(vm.guest_mem().try_read_all().unwrap(), vec![0xa5; RAM]);
    }
}
#[test]
fn legacy_multi_cpu_bundle_is_not_silently_treated_as_complete() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base(2));
    let mut vm = Vmm::new_resume(f.config(2)).unwrap();
    let before = all_bytes(&vm.capture_cpu_states().unwrap());
    assert!(
        vm.restore_snapshot_bundle(&b)
            .unwrap_err()
            .to_string()
            .contains("missing additional CPU")
    );
    assert_eq!(all_bytes(&vm.capture_cpu_states().unwrap()), before);
}
#[test]
fn base_api_remains_explicit_cpu_zero_projection() {
    let f = Fixture::new();
    let b = f.base(2);
    let mut vm = Vmm::new_resume(f.config(2)).unwrap();
    let old = all_bytes(&vm.capture_cpu_states().unwrap());
    vm.restore_snapshot(&b).unwrap();
    let new = all_bytes(&vm.capture_cpu_states().unwrap());
    assert_ne!(old[0], new[0]);
    assert_eq!(old[1], new[1]);
}
#[test]
fn count_mismatch_empty_and_overflow_are_rejected() {
    let f = Fixture::new();
    assert!(
        SnapshotBundle::new(f.base(2))
            .with_cpus(vec![entry(0)])
            .is_err()
    );
    assert!(
        SnapshotBundle::new(f.base(1))
            .with_cpus(Vec::new())
            .is_err()
    );
    assert!(
        SnapshotBundle::new(f.base(u8::MAX))
            .with_cpus((0..=u8::MAX).map(entry).collect())
            .is_err()
    );
}
#[test]
fn cpu_zero_base_disagreement_is_rejected() {
    let f = Fixture::new();
    let mut e = entry(0);
    e.emulator.pkru ^= 1;
    assert!(SnapshotBundle::new(f.base(1)).with_cpus(vec![e]).is_err());
    let mut e = entry(0);
    let CpuState::X86_64(c) = &mut e.state else {
        unreachable!()
    };
    c.regs.rax ^= 1;
    assert!(SnapshotBundle::new(f.base(1)).with_cpus(vec![e]).is_err());
}
#[test]
fn mixed_cpu_kind_is_rejected_before_serialization() {
    let f = Fixture::new();
    let e = CpuSnapshot {
        state: CpuState::riscv(Default::default()),
        emulator: Default::default(),
    };
    assert!(
        SnapshotBundle::new(f.base(2))
            .with_cpus(vec![entry(0), e])
            .is_err()
    );
}
#[test]
fn required_cpu_state_cannot_be_dropped_by_extraction() {
    let f = Fixture::new();
    assert!(f.bundle(2).into_base().is_err());
    assert!(f.bundle(2).into_parts().is_err());
    let mut b = f.bundle(2);
    assert!(b.take_cpus().is_some());
    assert!(b.take_pci().is_some());
    assert!(b.into_base().is_ok());
}
#[test]
fn base_reader_rejects_required_cpu_header_before_missing_payload() {
    let f = Fixture::new();
    let mut r = f.raw(&f.bundle(2));
    let mut at = 20;
    while u32::from_le_bytes(r[at..at + 4].try_into().unwrap()) != 11 {
        at += 16 + u64::from_le_bytes(r[at + 8..at + 16].try_into().unwrap()) as usize;
    }
    r.truncate(at + 16);
    let p = f.dir.join("header.rxc");
    std::fs::write(&p, r).unwrap();
    assert!(
        Snapshot::load(p)
            .err()
            .unwrap()
            .to_string()
            .contains("required CPU set")
    );
}
#[test]
fn malformed_count_lengths_tag_and_truncation_reject_before_records() {
    let f = Fixture::new();
    let p = sections(&f.raw(&f.bundle(2)));
    for case in 0..8 {
        let mut p = p.clone();
        let r = cpu_section(&mut p);
        match case {
            0 => r[8..12].copy_from_slice(&0u32.to_le_bytes()),
            1 => r[8..12].copy_from_slice(&256u32.to_le_bytes()),
            2 => r[8..12].copy_from_slice(&1u32.to_le_bytes()),
            3 => r[12..20].copy_from_slice(&0u64.to_le_bytes()),
            4 => r[12..20].copy_from_slice(&u64::MAX.to_le_bytes()),
            5 => r[0] ^= 1,
            6 => {
                r.pop();
            }
            7 => r.push(0),
            _ => unreachable!(),
        };
        assert!(f.read(&p).is_err(), "{case}");
    }
}
#[test]
fn cpu_schema_optional_alias_duplicate_and_order_are_checked() {
    let f = Fixture::new();
    let p = sections(&f.raw(&f.bundle(2)));
    for case in 0..5 {
        let mut p = p.clone();
        let at = p.iter().position(|p| p.kind == 11).unwrap();
        match case {
            0 => p[at].schema = 2,
            1 => p[at].kind |= 1 << 31,
            2 => p.insert(at, p[at].clone()),
            3 => {
                let r = p.remove(at);
                p.push(r);
            }
            4 => {
                let r = p.remove(at);
                p.insert(0, r);
            }
            _ => unreachable!(),
        };
        assert!(f.read(&p).is_err(), "{case}");
    }
}
/// Actual codec/runtime producer; raw register words are independently modeled.
pub fn emit_reference(out: &Path) {
    let f = Fixture::new();
    for n in [1, 2, 4] {
        let b = f.bundle(n);
        b.save(out.join(format!("cpus-{n}.rxc"))).unwrap();
        let mut vm = Vmm::new_resume(f.config(n)).unwrap();
        vm.restore_snapshot_bundle(&b).unwrap();
        let mut actual = Vec::new();
        for e in vm.capture_cpu_states().unwrap() {
            let CpuState::X86_64(c) = e.state else {
                unreachable!()
            };
            for v in [
                c.regs.rax,
                c.regs.rip,
                e.emulator.kernel_gs_base,
                u64::from(e.emulator.pkru),
                u64::from(e.emulator.mxcsr),
            ] {
                actual.extend_from_slice(&v.to_le_bytes());
            }
        }
        std::fs::write(out.join(format!("cpus-{n}.runtime")), actual).unwrap();
        println!("{n}\t{}", b.cpus().unwrap().entries().len());
    }
}
