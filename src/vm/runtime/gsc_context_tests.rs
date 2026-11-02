//! Actual GSC files and cross-process machine/resource reconstruction.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

const CODE: u64 = 0x1000;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rax-gsc-private-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn selected(label: &str) -> bool {
    std::env::var("RAX_GSC_CHECKPOINT_CASE").as_deref() == Ok(label)
}
fn root() -> PathBuf {
    std::env::var_os("RAX_GSC_CHECKPOINT_ROOT").unwrap().into()
}
fn phase() -> String {
    std::env::var("RAX_GSC_CHECKPOINT_PHASE").unwrap()
}
fn child(label: &str, dir: &Path, mode: &str, machine: bool, extras: &[(&str, &str)]) {
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("RAX_GSC_") {
            cmd.env_remove(key);
        }
    }
    cmd.env_remove("RAX_MACHINE");
    if machine {
        cmd.env("RAX_MACHINE", "gsc");
    }
    cmd.args([
        &format!("vm::runtime::gsc_context_tests::{label}"),
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("RAX_GSC_CHECKPOINT_CASE", label)
    .env("RAX_GSC_CHECKPOINT_ROOT", dir)
    .env("RAX_GSC_CHECKPOINT_PHASE", mode);
    for (key, value) in extras {
        cmd.env(key, value);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "GSC child {mode}: {:?}\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed; 0 failed"));
    if mode == "restore" && label == "new_gsc_files_keep_ap_flash_after_the_source_file_is_removed"
    {
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains("failed to read RAX_GSC_AP_FLASH"),
            "checkpoint restore reopened missing AP flash"
        );
    }
}
fn once(label: &str, extras: &[(&str, &str)]) -> bool {
    if selected(label) {
        return true;
    }
    let dir = Directory::new();
    child(label, &dir.0, "once", true, extras);
    false
}
fn config(dir: &Path, count: u8) -> VmConfig {
    VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::Riscv64),
            backend: Some(BackendKind::Emulator),
            kernel: Some(dir.join("kernel")),
            memory: Some(MemorySize(128 << 20)),
            vcpus: Some(count),
            ..Default::default()
        },
        None,
    )
    .unwrap()
}
fn source(dir: &Path, count: u8, words: &[u32]) -> Vmm {
    std::fs::write(dir.join("kernel"), [0; 64]).unwrap();
    let mut vm = Vmm::new_resume(config(dir, count)).unwrap();
    let code: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    vm.guest_mem
        .memory()
        .write_slice(&code, GuestAddress(CODE))
        .unwrap();
    for cpu in &mut vm.vcpus {
        let mut state = cpu.get_state().unwrap();
        let CpuState::RiscV(s) = &mut state else {
            panic!()
        };
        s.regs.pc = CODE;
        cpu.set_state(&state).unwrap();
    }
    vm
}
fn edit(cpu: &mut dyn VCpu, f: impl FnOnce(&mut crate::vm::vcpu::RiscVRegisters)) {
    let mut state = cpu.get_state().unwrap();
    let CpuState::RiscV(s) = &mut state else {
        panic!()
    };
    f(&mut s.regs);
    cpu.set_state(&state).unwrap();
}
fn reg(cpu: &dyn VCpu, index: usize) -> u64 {
    let CpuState::RiscV(s) = cpu.get_state().unwrap() else {
        panic!()
    };
    s.regs.x[index]
}
fn steps(vm: &mut Vmm, n: u64) {
    for cpu in &mut vm.vcpus {
        let result = cpu.run_retirement_budget(n).unwrap();
        assert_eq!(result.retired, n, "{result:?}");
        assert!(matches!(
            result.stop,
            crate::vm::vcpu::RetirementStop::BudgetExhausted
        ));
    }
}
fn save(vm: &Vmm, dir: &Path) {
    let total = vm.vcpus.iter().map(|c| c.instruction_count()).sum();
    vm.take_snapshot_bundle(total)
        .unwrap()
        .save(dir.join("state.rxc"))
        .unwrap();
}
fn restore(dir: &Path, count: u8) -> Vmm {
    let b = SnapshotBundle::load(dir.join("state.rxc")).unwrap();
    let cfg = VmConfig::from_checkpoint_bundle(&b, CliConfig::default()).unwrap();
    assert_eq!(cfg.vcpus, count);
    Vmm::new_resume_bundle(cfg, &b).unwrap()
}

#[test]
fn actual_gsc_file_keeps_each_core_retirement_counter() {
    if !once("actual_gsc_file_keeps_each_core_retirement_counter", &[]) {
        return;
    }
    let dir = root();
    for count in [1, 2, 4] {
        let mut vm = source(&dir, count, &[0x0000_0013, 0x0000_0013]);
        steps(&mut vm, 1);
        save(&vm, &dir);
        let mut target = restore(&dir, count);
        for cpu in &target.vcpus {
            assert_eq!(cpu.instruction_count(), 1, "GSC counter lost in file");
        }
        steps(&mut target, 1);
        for cpu in &target.vcpus {
            assert_eq!(cpu.instruction_count(), 2);
        }
    }
}

#[test]
fn actual_gsc_file_keeps_machine_scratch_csr() {
    if !once("actual_gsc_file_keeps_machine_scratch_csr", &[]) {
        return;
    }
    let dir = root();
    for count in [1, 2, 4] {
        // CSRW mscratch,a0; CSRR a1,mscratch.
        let mut vm = source(&dir, count, &[0x3405_1073, 0x3400_25f3]);
        for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
            edit(cpu.as_mut(), |r| r.x[10] = 0x1234 + id as u64);
        }
        steps(&mut vm, 1);
        save(&vm, &dir);
        let mut target = restore(&dir, count);
        for machine in [&mut vm, &mut target] {
            steps(machine, 1);
            for (id, cpu) in machine.vcpus.iter().enumerate() {
                assert_eq!(
                    reg(cpu.as_ref(), 11),
                    0x1234 + id as u64,
                    "GSC mscratch lost in file"
                );
            }
        }
    }
}

#[test]
fn actual_gsc_file_keeps_persistent_pmu_scratch() {
    if !once("actual_gsc_file_keeps_persistent_pmu_scratch", &[]) {
        return;
    }
    let dir = root();
    for count in [1, 2, 4] {
        // LUI a0,0x40000; ADDI a1,zero,42; SW a1,76(a0); LW a2,76(a0).
        let mut vm = source(
            &dir,
            count,
            &[0x4000_0537, 0x02a0_0593, 0x04b5_2623, 0x04c5_2603],
        );
        steps(&mut vm, 3);
        save(&vm, &dir);
        let mut target = restore(&dir, count);
        for machine in [&mut vm, &mut target] {
            steps(machine, 1);
            for cpu in &machine.vcpus {
                assert_eq!(reg(cpu.as_ref(), 12), 42, "GSC PMU scratch lost in file");
            }
        }
    }
}

#[test]
fn actual_gsc_file_keeps_consumed_uart_input_and_arming() {
    if !once(
        "actual_gsc_file_keeps_consumed_uart_input_and_arming",
        &[("RAX_GSC_UART_RX", "QR")],
    ) {
        return;
    }
    let dir = root();
    for count in [1, 2, 4] {
        let mut vm = source(
            &dir,
            count,
            &[0x404d_05b7, 0x1050_0073, 0x0005_a503, 0x0005_a603],
        );
        steps(&mut vm, 3);
        for cpu in &vm.vcpus {
            assert_eq!(reg(cpu.as_ref(), 10), u64::from(b'Q'));
        }
        save(&vm, &dir);
        let mut target = restore(&dir, count);
        for machine in [&mut vm, &mut target] {
            steps(machine, 1);
            for cpu in &machine.vcpus {
                assert_eq!(
                    reg(cpu.as_ref(), 12),
                    u64::from(b'R'),
                    "GSC UART input lost/reseeded in file"
                );
            }
        }
    }
}

#[test]
fn new_gsc_files_reconstruct_the_machine_without_a_process_selector() {
    let label = "new_gsc_files_reconstruct_the_machine_without_a_process_selector";
    if !selected(label) {
        let dir = Directory::new();
        child(label, &dir.0, "save", true, &[]);
        std::fs::remove_file(dir.0.join("kernel")).unwrap();
        child(label, &dir.0, "restore", false, &[]);
        return;
    }
    let dir = root();
    if phase() == "save" {
        let mut vm = source(&dir, 1, &[0x0000_0013, 0x0006_368b]);
        edit(vm.vcpus[0].as_mut(), |r| r.x[12] = 7);
        steps(&mut vm, 1);
        save(&vm, &dir);
        steps(&mut vm, 1);
        assert_eq!(reg(vm.vcpus[0].as_ref(), 13), 3);
    } else {
        let mut vm = restore(&dir, 1);
        steps(&mut vm, 1);
        assert_eq!(
            reg(vm.vcpus[0].as_ref(), 13),
            3,
            "GSC vendor ISA not reconstructed"
        );
    }
}

#[test]
fn new_gsc_files_restore_the_captured_timer_profile() {
    let label = "new_gsc_files_restore_the_captured_timer_profile";
    if !selected(label) {
        let dir = Directory::new();
        child(label, &dir.0, "save", true, &[("RAX_GSC_TIMER_DIV", "1")]);
        child(label, &dir.0, "restore", true, &[]);
        return;
    }
    let dir = root();
    if phase() == "save" {
        let mut vm = source(&dir, 1, &[0x0000_0013, 0x0005_a503]);
        edit(vm.vcpus[0].as_mut(), |r| r.x[11] = 0x400c_0014);
        steps(&mut vm, 1);
        save(&vm, &dir);
        steps(&mut vm, 1);
        assert_eq!(reg(vm.vcpus[0].as_ref(), 10), 1);
    } else {
        let mut vm = restore(&dir, 1);
        steps(&mut vm, 1);
        assert_eq!(
            reg(vm.vcpus[0].as_ref(), 10),
            1,
            "GSC source timer profile was replaced by environment defaults"
        );
    }
}

#[test]
fn new_gsc_files_keep_ap_flash_after_the_source_file_is_removed() {
    let label = "new_gsc_files_keep_ap_flash_after_the_source_file_is_removed";
    if !selected(label) {
        let dir = Directory::new();
        let flash = dir.0.join("ap.bin");
        let mut bytes = vec![0xff; 0x1244];
        bytes[0x1234] = 0xa0;
        std::fs::write(&flash, bytes).unwrap();
        let path = flash.to_str().unwrap();
        child(label, &dir.0, "save", true, &[("RAX_GSC_AP_FLASH", path)]);
        std::fs::remove_file(&flash).unwrap();
        std::fs::remove_file(dir.0.join("kernel")).unwrap();
        child(
            label,
            &dir.0,
            "restore",
            true,
            &[("RAX_GSC_AP_FLASH", path)],
        );
        return;
    }
    let dir = root();
    let mut vm = if phase() == "save" {
        let mut vm = source(
            &dir,
            1,
            &[
                0x0000_0013,
                0x00b5_2023,
                0x0005_2223,
                0x00d6_2023,
                0x00f7_2023,
                0x00d5_4803,
            ],
        );
        edit(vm.vcpus[0].as_mut(), |r| {
            r.x[10] = 0x4060_1000;
            r.x[11] = 0x3412_000b;
            r.x[12] = 0x4060_0008;
            r.x[13] = 0x0018_1380;
            r.x[14] = 0x4060_0004;
            r.x[15] = 0x0067_0001;
        });
        steps(&mut vm, 1);
        save(&vm, &dir);
        vm
    } else {
        restore(&dir, 1)
    };
    steps(&mut vm, 5);
    assert_eq!(
        reg(vm.vcpus[0].as_ref(), 16),
        0xa0,
        "captured AP flash source was reopened or lost"
    );
}

#[test]
fn generic_riscv_files_ignore_a_gsc_process_selector() {
    let label = "generic_riscv_files_ignore_a_gsc_process_selector";
    if !selected(label) {
        let dir = Directory::new();
        child(label, &dir.0, "save", false, &[]);
        child(label, &dir.0, "restore", true, &[]);
        return;
    }
    let dir = root();
    let mut vm = if phase() == "save" {
        let mut vm = source(&dir, 1, &[0x0000_0013, 0xfff0_0513]);
        steps(&mut vm, 1);
        save(&vm, &dir);
        vm
    } else {
        restore(&dir, 1)
    };
    steps(&mut vm, 1);
    assert_eq!(
        reg(vm.vcpus[0].as_ref(), 10),
        u64::MAX,
        "generic RV64 profile was replaced by the GSC process selector"
    );
}
#[test]
fn absent_gsc_private_sections_retain_legacy_projection_semantics() {
    if !once(
        "absent_gsc_private_sections_retain_legacy_projection_semantics",
        &[],
    ) {
        return;
    }
    let dir = root();
    for count in [1, 2, 4] {
        let mut vm = source(&dir, count, &[0x0000_0013, 0x0000_0013]);
        for cpu in &mut vm.vcpus {
            edit(cpu.as_mut(), |r| r.x[10] = 42);
        }
        steps(&mut vm, 1);
        let mut b = vm.take_snapshot_bundle(u64::from(count)).unwrap();
        b.take_backend_contexts();
        b.take_resources();
        b.save(dir.join("state.rxc")).unwrap();
        let mut target = restore(&dir, count);
        for cpu in &target.vcpus {
            assert_eq!(cpu.instruction_count(), 0);
            assert_eq!(reg(cpu.as_ref(), 10), 42);
        }
        steps(&mut target, 1);
        for cpu in &target.vcpus {
            assert_eq!(cpu.instruction_count(), 1);
        }
    }
}
#[test]
fn final_gsc_record_or_resource_rejects_before_any_cpu_or_ram_change() {
    if !once(
        "final_gsc_record_or_resource_rejects_before_any_cpu_or_ram_change",
        &[],
    ) {
        return;
    }
    let dir = root();
    for count in [2, 4] {
        for missing in [false, true] {
            let mut vm = source(&dir, count, &[0x0000_0013]);
            steps(&mut vm, 1);
            let mut b = vm.take_snapshot_bundle(u64::from(count)).unwrap();
            let mut entries = b.take_backend_contexts().unwrap().entries().to_vec();
            if missing {
                *entries.last_mut().unwrap() = None;
                b = b.with_backend_contexts(entries).unwrap();
            } else {
                let last = entries.last_mut().unwrap().as_mut().unwrap();
                assert_eq!(last.data.len(), 100);
                let old: crate::vm::snapshot::ResourceKey =
                    crate::codec::deserialize_strict(&last.data[12..56]).unwrap();
                let prepared = b.resources().unwrap().prepare().unwrap();
                let mut bytes = prepared.resolve(old).unwrap().as_ref().clone();
                assert_eq!(&bytes[..8], b"RAXGSI01");
                bytes[8..12].copy_from_slice(&u32::from(count).to_le_bytes());
                let bad = crate::vm::snapshot::CheckpointResource::gsc_state(bytes).unwrap();
                last.data[12..56].copy_from_slice(&crate::codec::serialize(&bad.key()).unwrap());
                let mut resources = Vec::new();
                for cpu in &vm.vcpus {
                    resources.extend(
                        cpu.capture_checkpoint_resources()
                            .unwrap()
                            .into_iter()
                            .filter(|r| r.key() != old),
                    );
                }
                resources.push(bad);
                b.take_resources();
                b = b
                    .with_backend_contexts(entries)
                    .unwrap()
                    .with_resources(resources)
                    .unwrap();
            }
            b.save(dir.join("state.rxc")).unwrap();
            let loaded = SnapshotBundle::load(dir.join("state.rxc")).unwrap();
            let mut target = source(&dir, count, &[0x0000_0013]);
            for (id, cpu) in target.vcpus.iter_mut().enumerate() {
                edit(cpu.as_mut(), |r| r.x[10] = 7 + id as u64);
            }
            target
                .guest_mem
                .memory()
                .write_slice(&[0x77], GuestAddress(0x2000))
                .unwrap();
            let before: Vec<_> = target
                .vcpus
                .iter()
                .map(|c| c.capture_backend_context().unwrap())
                .collect();
            let ram = target.guest_mem.try_read_all().unwrap();
            let error = target
                .restore_snapshot_bundle(&loaded)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(if missing {
                    "missing private context"
                } else {
                    "resource CPU identity differs"
                }),
                "{error}"
            );
            assert_eq!(
                before,
                target
                    .vcpus
                    .iter()
                    .map(|c| c.capture_backend_context().unwrap())
                    .collect::<Vec<_>>()
            );
            assert_eq!(ram, target.guest_mem.try_read_all().unwrap());
        }
    }
}
