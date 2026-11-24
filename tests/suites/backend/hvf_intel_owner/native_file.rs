//! Real VMM/file transactions with SDK storage; no guest instruction executes.
use super::*;
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::runtime::Vmm;
use rax::vm::snapshot::SnapshotBundle;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Paths {
    kernel: std::path::PathBuf,
    checkpoint: std::path::PathBuf,
}
impl Paths {
    fn new() -> Self {
        let prefix = std::env::temp_dir().join(format!(
            "rax-intel-context-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let paths = Self {
            kernel: prefix.with_extension("kernel"),
            checkpoint: prefix.with_extension("rxc"),
        };
        std::fs::write(&paths.kernel, [0; 64]).unwrap();
        paths
    }
    fn config(&self, count: u8) -> VmConfig {
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Hvf),
                kernel: Some(self.kernel.clone()),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(4096);
        config
    }
}
impl Drop for Paths {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
        let _ = std::fs::remove_file(&self.checkpoint);
    }
}
fn reset_model() {
    std::hint::black_box(hv_tsc_clock as extern "C" fn() -> u64);
    std::hint::black_box(hv_vcpu_set_tsc_relative as extern "C" fn(u32, i64) -> i32);
    *SDK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Sdk::new();
    SDK.clear_poison();
}
fn set_distinct_native_state() {
    let mut sdk = SDK.lock().unwrap();
    for (&id, cpu) in &mut sdk.cpus {
        // SDK identifiers and offsets are from the retained SDK/Intel XSAVE ABI.
        cpu.registers.insert(0, 0x100 + u64::from(id)); // RIP
        cpu.registers.insert(2, 0xface_0000 + u64::from(id)); // RAX
        cpu.registers.insert(50, 7); // XCR0
        cpu.vmcs.insert(0x4824, 1); // STI blocking
        cpu.vmcs.insert(0x6822, 1 << 14); // pending guest #DB
        cpu.msrs.insert(0xc000_0102, 0xdead_0000 + u64::from(id));
        cpu.msrs.insert(0xc000_0103, u64::from(id) + 17);
        cpu.fpstate[512..520].copy_from_slice(&7u64.to_le_bytes());
        cpu.fpstate[160..168].copy_from_slice(&(0x1234 + u64::from(id)).to_le_bytes());
        cpu.fpstate[824..832].copy_from_slice(&(0x5678 + u64::from(id)).to_le_bytes());
    }
}
fn architectural_bytes(bundle: &SnapshotBundle) -> Vec<u8> {
    rax::codec::serialize(
        &bundle
            .cpus()
            .unwrap()
            .entries()
            .iter()
            .map(|cpu| (&cpu.state, &cpu.emulator))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn actual_vmm_files_restore_one_two_four_native_cpu_records_and_ram() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for count in [1, 2, 4] {
        reset_model();
        let paths = Paths::new();
        let mut vm = Vmm::new_resume(paths.config(count)).unwrap();
        set_distinct_native_state();
        vm.guest_mem().write_all(&[0x51; 4096]).unwrap();
        {
            let mut sdk = SDK.lock().unwrap();
            for (&id, cpu) in &mut sdk.cpus {
                cpu.registers.insert(1, 0x202); // RFLAGS.IF
                if id == 0 {
                    cpu.vmcs.insert(0x4016, 0x8000_0301); // #DB with STI blocking.
                } else {
                    cpu.vmcs.insert(0x4824, 0);
                    cpu.vmcs.insert(0x4016, 0x8000_0040 + u64::from(id));
                }
            }
        }
        let saved = vm.take_snapshot_bundle(0).unwrap();
        saved.save(&paths.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&paths.checkpoint).unwrap();
        assert_eq!(architectural_bytes(&loaded), architectural_bytes(&saved));
        assert_eq!(loaded.vm_context(), saved.vm_context());
        assert_eq!(
            loaded.backend_contexts().unwrap().entries(),
            saved.backend_contexts().unwrap().entries()
        );
        {
            let mut sdk = SDK.lock().unwrap();
            for cpu in sdk.cpus.values_mut() {
                cpu.registers.insert(2, 0);
                cpu.msrs.insert(0xc000_0102, 0);
                cpu.fpstate[160..416].fill(0);
                cpu.fpstate[576..832].fill(0);
                cpu.vmcs.insert(0x4824, 0);
                cpu.vmcs.insert(0x4016, 0);
            }
            sdk.tsc += 50_000;
        }
        vm.guest_mem().write_all(&[0xa5; 4096]).unwrap();
        vm.restore_snapshot_bundle(&loaded).unwrap();
        let restored = vm.take_snapshot_bundle(0).unwrap();
        assert_eq!(architectural_bytes(&restored), architectural_bytes(&saved));
        assert_eq!(vm.guest_mem().try_read_all().unwrap(), vec![0x51; 4096]);
        for (&id, cpu) in &SDK.lock().unwrap().cpus {
            let expected = if id == 0 {
                0x8000_0301
            } else {
                0x8000_0040 + u64::from(id)
            };
            assert_eq!(cpu.vmcs[&0x4016], expected);
        }
        drop(vm);
        let sdk = SDK.lock().unwrap();
        assert!(!sdk.live);
        assert_eq!(sdk.wrong_owner, 0);
    }
}

#[test]
fn vmm_capture_rejects_a_blocked_queued_interrupt_on_the_last_cpu() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset_model();
    let paths = Paths::new();
    let vm = Vmm::new_resume(paths.config(2)).unwrap();
    vm.guest_mem().write_all(&[0x51; 4096]).unwrap();
    {
        let mut sdk = SDK.lock().unwrap();
        let cpu = sdk.cpus.get_mut(&1).unwrap();
        cpu.registers.insert(1, 2); // RFLAGS.IF is clear.
        cpu.vmcs.insert(0x4016, 0x8000_0041);
    }
    let error = vm
        .take_snapshot_bundle(0)
        .err()
        .expect("the final CPU's blocked interrupt must prevent capture");
    assert!(
        error
            .to_string()
            .contains("queued VM-entry event is blocked"),
        "{error}"
    );
    assert_eq!(vm.guest_mem().try_read_all().unwrap(), vec![0x51; 4096]);
    {
        let mut sdk = SDK.lock().unwrap();
        let cpu = sdk.cpus.get_mut(&1).unwrap();
        assert_eq!(cpu.vmcs[&0x4016], 0x8000_0041);
        cpu.registers.insert(1, 0x202);
    }
    vm.take_snapshot_bundle(0)
        .unwrap()
        .save(&paths.checkpoint)
        .unwrap();
    drop(vm);
}

#[test]
fn native_vmm_transaction_rolls_back_before_and_after_ram_publication() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Last-CPU failure before RAM publication and last-CPU failure after it.
    // Raw CPU tests separately cover every SDK setter class.
    for operation in ["fp-write", "invalidate"] {
        reset_model();
        let paths = Paths::new();
        let mut vm = Vmm::new_resume(paths.config(2)).unwrap();
        let source = vm.take_snapshot_bundle(0).unwrap();
        set_distinct_native_state();
        vm.guest_mem().write_all(&[0xa5; 4096]).unwrap();
        let before = vm.take_snapshot_bundle(0).unwrap();
        SDK.lock().unwrap().fault = Some(Fault {
            operation,
            remaining: 2,
            persistent: false,
        });
        let error = vm.restore_snapshot_bundle(&source).unwrap_err();
        assert!(
            !error.to_string().contains("rollback failed"),
            "{operation}: {error}"
        );
        let after = vm.take_snapshot_bundle(0).unwrap();
        assert_eq!(
            architectural_bytes(&before),
            architectural_bytes(&after),
            "{operation}"
        );
        assert_eq!(
            vm.guest_mem().try_read_all().unwrap(),
            vec![0xa5; 4096],
            "{operation}"
        );
        drop(vm);
        assert_eq!(SDK.lock().unwrap().wrong_owner, 0);
    }
}

#[test]
fn failed_native_vmm_rollback_fences_all_further_entry_and_capture() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset_model();
    let paths = Paths::new();
    let mut vm = Vmm::new_resume(paths.config(2)).unwrap();
    let saved = vm.take_snapshot_bundle(0).unwrap();
    SDK.lock().unwrap().fault = Some(Fault {
        operation: "fp-write",
        remaining: 1,
        persistent: true,
    });
    let error = vm.restore_snapshot_bundle(&saved).unwrap_err();
    assert!(error.to_string().contains("rollback failed"), "{error}");
    SDK.lock().unwrap().fault = None;
    let calls = SDK.lock().unwrap().trace.len();
    assert!(vm.take_snapshot_bundle(0).is_err());
    assert!(vm.restore_snapshot_bundle(&saved).is_err());
    assert_eq!(calls, SDK.lock().unwrap().trace.len());
    drop(vm);
}
