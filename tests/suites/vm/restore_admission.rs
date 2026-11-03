//! Actual VM restore admission and exact reported-RAM transfer boundaries.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::memory::GuestMemoryWrapper;
use rax::vm::runtime::Vmm;
use rax::vm::snapshot::Snapshot;
use rax::vm::vcpu::state::{CpuState, RiscVVectorState};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
const RAM: usize = 4096;
struct Kernel(PathBuf);
impl Kernel {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "rax-restore-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, [0; 64]).unwrap();
        Self(p)
    }
    fn vm(&self, arch: ArchKind) -> Vmm {
        let mut c = VmConfig::from_sources(
            CliConfig {
                arch: Some(arch),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.0.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        c.memory = MemorySize(RAM as u64);
        let mut vm = Vmm::new_resume(c).unwrap();
        if arch == ArchKind::Riscv64 {
            // These witnesses exercise the historical base-only format.
            // Select its ordinary-RAM profile explicitly before capture;
            // new CLINT files require the complete producer graph.
            let base = copy(vm.take_snapshot_bundle(0).unwrap().base());
            vm.restore_snapshot(&base).unwrap();
        }
        vm
    }
}
impl Drop for Kernel {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}
fn copy(snapshot: &Snapshot) -> Snapshot {
    Snapshot {
        version: snapshot.version,
        config: snapshot.config.clone(),
        instruction_count: snapshot.instruction_count,
        elapsed_nanos: snapshot.elapsed_nanos,
        cpu_state: snapshot.cpu_state.clone(),
        emulator_state: snapshot.emulator_state.clone(),
        devices: snapshot.devices.clone(),
        memory_size: snapshot.memory_size,
        memory_data: snapshot.memory_data.clone(),
    }
}
fn marker(state: &CpuState) -> u64 {
    match state {
        CpuState::X86_64(s) => s.regs.rax,
        CpuState::RiscV(s) => s.regs.x[5],
        _ => unreachable!(),
    }
}
fn alter(state: &mut CpuState) {
    match state {
        CpuState::X86_64(s) => s.regs.rax = 0x12345678,
        CpuState::RiscV(s) => s.regs.x[5] = 0x12345678,
        _ => unreachable!(),
    }
}
fn compressed(snapshot: &Snapshot, bytes: &[u8]) -> Vec<u8> {
    Snapshot::new(
        snapshot.config.clone(),
        snapshot.instruction_count,
        snapshot.elapsed_nanos,
        snapshot.cpu_state.clone(),
        snapshot.emulator_state.clone(),
        snapshot.devices.clone(),
        bytes,
    )
    .unwrap()
    .memory_data
}
fn malformed(index: usize, base: &Snapshot) -> Snapshot {
    let mut s = copy(base);
    alter(&mut s.cpu_state);
    s.memory_data = compressed(&s, &[0x33; RAM]);
    match index {
        0 => s.memory_data = vec![0; 16],
        1 => {
            s.config.memory_bytes = 8192;
            s.memory_size = 8192;
            s.memory_data = compressed(&s, &[0x33; 8192]);
        }
        2 => s.emulator_state.mxcsr |= 1 << 16,
        3 => s.version = 7,
        4 => s.config.arch = ArchKind::Aarch64,
        5 => s.config.vcpus = 2,
        6 => {
            let CpuState::RiscV(r) = &mut s.cpu_state else {
                unreachable!()
            };
            r.regs.privilege = Some(2);
        }
        7 => {
            let CpuState::RiscV(r) = &mut s.cpu_state else {
                unreachable!()
            };
            r.regs.vector = Some(RiscVVectorState {
                vl: 0,
                vtype: 0,
                vstart: 0,
                vxrm: 0,
                vxsat: 0,
                v: vec![0; 1],
            });
        }
        8 => s.emulator_state.fpu.top = 8,
        9 => s.emulator_state.lazy_flags.op = 255,
        10 => {
            s.emulator_state.lazy_flags.op = 1;
            s.emulator_state.lazy_flags.size = 3;
        }
        _ => unreachable!(),
    }
    s
}
#[cfg(test)]
fn rejected_case(index: usize) {
    let k = Kernel::new();
    let mut vm = k.vm(if matches!(index, 6 | 7) {
        ArchKind::Riscv64
    } else {
        ArchKind::X86_64
    });
    vm.guest_mem().write_all(&[0xa5; RAM]).unwrap();
    let before = vm.take_snapshot(17).unwrap();
    let before_cpu = rax::codec::serialize(&before.cpu_state).unwrap();
    let before_private = rax::codec::serialize(&before.emulator_state).unwrap();
    let before_devices = rax::codec::serialize(&before.devices).unwrap();
    let invalid = malformed(index, &before);
    assert!(
        vm.restore_snapshot(&invalid).is_err(),
        "case {index} must reject"
    );
    let after = vm.take_snapshot(17).unwrap();
    assert_eq!(rax::codec::serialize(&after.cpu_state).unwrap(), before_cpu);
    assert_eq!(
        rax::codec::serialize(&after.emulator_state).unwrap(),
        before_private
    );
    assert_eq!(
        rax::codec::serialize(&after.devices).unwrap(),
        before_devices
    );

    assert_eq!(
        marker(&after.cpu_state),
        marker(&before.cpu_state),
        "CPU changed in case {index}"
    );
    assert_eq!(
        vm.guest_mem().read_all(),
        vec![0xa5; RAM],
        "RAM changed in case {index}"
    );
}
#[test]
fn every_nonexact_reported_ram_write_rejects_without_any_mutation() {
    let m = GuestMemoryWrapper::new(RAM as u64).unwrap();
    for size in [0, 1, RAM - 1, RAM + 1, RAM * 2] {
        m.write_all(&[0xa5; RAM]).unwrap();
        assert!(m.write_all(&vec![0x33; size]).is_err(), "size {size}");
        assert_eq!(m.read_all(), vec![0xa5; RAM]);
    }
}
#[test]
fn corrupt_ram_is_rejected_before_cpu_changes() {
    rejected_case(0);
}
#[test]
fn target_ram_geometry_is_rejected_before_cpu_changes() {
    rejected_case(1);
}
#[test]
fn invalid_private_mxcsr_is_rejected_before_cpu_changes() {
    rejected_case(2);
}
#[test]
fn wrong_snapshot_version_is_rejected_before_cpu_changes() {
    rejected_case(3);
}
#[test]
fn wrong_machine_architecture_is_rejected_before_cpu_changes() {
    rejected_case(4);
}
#[test]
fn wrong_cpu_count_metadata_is_rejected_before_cpu_changes() {
    rejected_case(5);
}
#[test]
fn riscv_reserved_privilege_is_rejected_before_register_changes() {
    rejected_case(6);
}
#[test]
fn riscv_vector_geometry_is_rejected_before_register_changes() {
    rejected_case(7);
}
/// Publish all cases without assertions so the exact same client captures the
/// predecessor's failures and the fixed implementation's admission behavior.
pub fn emit_reference() {
    let directory = std::env::args_os().nth(1).map(PathBuf::from);
    if let Some(path) = &directory {
        std::fs::create_dir_all(path).unwrap();
    }
    for size in [0, 1, RAM - 1, RAM + 1, RAM * 2] {
        let m = GuestMemoryWrapper::new(RAM as u64).unwrap();
        m.write_all(&[0xa5; RAM]).unwrap();
        let accepted = m.write_all(&vec![0x33; size]).is_ok();
        let raw = m.read_all();
        if let Some(path) = &directory {
            std::fs::write(path.join(format!("ram-{size}.raw")), &raw).unwrap();
        }
        let changed = raw != vec![0xa5; RAM];
        println!("ram\t{size}\t{}\t{}", u8::from(accepted), u8::from(changed));
    }
    for index in 0..11 {
        let k = Kernel::new();
        let mut vm = k.vm(if matches!(index, 6 | 7) {
            ArchKind::Riscv64
        } else {
            ArchKind::X86_64
        });
        vm.guest_mem().write_all(&[0xa5; RAM]).unwrap();
        let before = vm.take_snapshot(17).unwrap();
        let accepted = vm.restore_snapshot(&malformed(index, &before)).is_ok();
        let after = vm.take_snapshot(17).unwrap();
        let raw = vm.guest_mem().read_all();
        let markers = [marker(&before.cpu_state), marker(&after.cpu_state)];
        if let Some(path) = &directory {
            std::fs::write(path.join(format!("vm-{index}.raw")), &raw).unwrap();
            let mut bytes = Vec::new();
            for marker in markers {
                bytes.extend_from_slice(&marker.to_le_bytes());
            }
            std::fs::write(path.join(format!("vm-{index}.cpu")), bytes).unwrap();
        }
        let changed = markers[0] != markers[1] || raw != vec![0xa5; RAM];
        println!("vm\t{index}\t{}\t{}", u8::from(accepted), u8::from(changed));
    }
}
#[test]
fn invalid_x87_top_is_rejected_before_cpu_changes() {
    rejected_case(8);
}
#[test]
fn unknown_lazy_flag_operation_is_rejected_before_cpu_changes() {
    rejected_case(9);
}
#[test]
fn unsupported_active_lazy_flag_width_is_rejected_before_cpu_changes() {
    rejected_case(10);
}
#[test]
fn unused_lazy_flag_width_preserves_legacy_dont_care_state() {
    let k = Kernel::new();
    let mut vm = k.vm(ArchKind::X86_64);
    let mut s = vm.take_snapshot(19).unwrap();
    s.emulator_state.lazy_flags.op = 0;
    s.emulator_state.lazy_flags.size = 255;
    vm.restore_snapshot(&s).unwrap();
    assert_eq!(
        vm.take_snapshot(19).unwrap().emulator_state.lazy_flags.size,
        255
    );
}
#[test]
fn exact_ram_capture_and_restore_preserve_reserved_padding() {
    use rax::vm::memory::vm::{Bytes, GuestAddress};
    let m = GuestMemoryWrapper::new(RAM as u64).unwrap();
    m.memory()
        .write_slice(&[0x77; 16], GuestAddress(RAM as u64))
        .unwrap();
    m.write_all(&[0x42; RAM]).unwrap();
    assert_eq!(m.try_read_all().unwrap(), vec![0x42; RAM]);
    let mut padding = [0; 16];
    m.memory()
        .read_slice(&mut padding, GuestAddress(RAM as u64))
        .unwrap();
    assert_eq!(padding, [0x77; 16]);
}
#[test]
fn valid_base_restore_installs_cpu_private_state_devices_and_reported_ram() {
    let k = Kernel::new();
    let mut vm = k.vm(ArchKind::X86_64);
    let mut s = vm.take_snapshot(23).unwrap();
    alter(&mut s.cpu_state);
    s.emulator_state.fpu.top = 7;
    s.emulator_state.mxcsr = 0x1f80;
    s.emulator_state.lazy_flags.op = 0;
    s.emulator_state.kernel_gs_base = 0x123456789abcdef0;
    s.memory_data = compressed(&s, &[0x55; RAM]);
    rax::devices::bus::IoDevice::write(&mut s.devices.serial, 0x3f9, 0x0f);
    vm.restore_snapshot(&s).unwrap();
    let after = vm.take_snapshot(23).unwrap();
    assert_eq!(marker(&after.cpu_state), 0x12345678);
    assert_eq!(after.emulator_state.fpu.top, 7);
    assert_eq!(after.emulator_state.kernel_gs_base, 0x123456789abcdef0);
    assert_eq!(vm.guest_mem().try_read_all().unwrap(), vec![0x55; RAM]);
    assert_eq!(
        rax::codec::serialize(&after.devices).unwrap(),
        rax::codec::serialize(&s.devices).unwrap()
    );
}
#[test]
fn all_supported_active_flag_widths_operations_and_x87_tops_remain_admitted() {
    let k = Kernel::new();
    let mut vm = k.vm(ArchKind::X86_64);
    let base = vm.take_snapshot(31).unwrap();
    for op in 1..=5 {
        for size in [1, 2, 4, 8] {
            for top in 0..8 {
                let mut s = copy(&base);
                s.emulator_state.lazy_flags.op = op;
                s.emulator_state.lazy_flags.size = size;
                s.emulator_state.fpu.top = top;
                vm.restore_snapshot(&s).unwrap();
                let actual = vm.take_snapshot(31).unwrap();
                assert_eq!(
                    (
                        actual.emulator_state.lazy_flags.op,
                        actual.emulator_state.lazy_flags.size,
                        actual.emulator_state.fpu.top
                    ),
                    (op, size, top)
                );
            }
        }
    }
}
#[test]
fn cpu_admission_rejects_before_decoding_an_invalid_ram_payload() {
    let k = Kernel::new();
    let mut vm = k.vm(ArchKind::X86_64);
    let mut s = vm.take_snapshot(37).unwrap();
    s.memory_data = vec![0; 16];
    s.emulator_state.mxcsr |= 1 << 16;
    assert!(
        vm.restore_snapshot(&s)
            .unwrap_err()
            .to_string()
            .contains("MXCSR")
    );
    s.emulator_state.mxcsr = 0x1f80;
    s.cpu_state = CpuState::riscv(Default::default());
    assert!(
        vm.restore_snapshot(&s)
            .unwrap_err()
            .to_string()
            .contains("expected x86_64 state")
    );
}
