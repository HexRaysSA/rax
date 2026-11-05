//! Actual native VMM/file capture; requires a locally signed test executable.
use super::*;
use crate::backend::arm64_hvf_context::{Context, GlobalContext};
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::{HVF_AARCH64_CONTEXT, SnapshotBundle};
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress, GuestMemory};

#[path = "native_checkpoint_uart_tests.rs"]
mod uart;

static NEXT: AtomicU64 = AtomicU64::new(0);
const CODE: u64 = 0x4000_1000;
const UART: u64 = 0x0900_0000;

struct Fixture {
    kernel: std::path::PathBuf,
    checkpoint: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let prefix = std::env::temp_dir().join(format!(
            "rax-native-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let fixture = Self {
            kernel: prefix.with_extension("kernel"),
            checkpoint: prefix.with_extension("rxc"),
        };
        std::fs::write(&fixture.kernel, [0; 64]).unwrap();
        fixture
    }
    fn config(&self, count: u8) -> VmConfig {
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Aarch64),
                backend: Some(BackendKind::Hvf),
                kernel: Some(self.kernel.clone()),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(128 << 20);
        config
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
        let _ = std::fs::remove_file(&self.checkpoint);
    }
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn actual_native_vmm_restores_one_two_four_cpu_files_and_continues_pending_mmio() {
    for count in [1, 2, 4] {
        restore_native_file_fixture(count, false);
    }
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_reversed_cpu_creation_order_preserves_real_file_continuation() {
    restore_native_file_fixture(4, true);
}

fn restore_native_file_fixture(count: u8, reversed_creation: bool) {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(count)).unwrap();
    if reversed_creation {
        assert_eq!(count, 4);
        drop(vm.vcpus.remove(2));
        drop(vm.vcpus.remove(1));
        assert!(vm.take_snapshot_bundle(0).is_err());
        let memory = Arc::new(vm.guest_mem.memory().clone());
        let second = vm.vm.create_vcpu(2, memory.clone()).unwrap();
        let first = vm.vm.create_vcpu(1, memory).unwrap();
        vm.vcpus.insert(1, first);
        vm.vcpus.insert(2, second);
    } else if count > 1 {
        drop(vm.vcpus.remove(1));
        assert!(vm.take_snapshot_bundle(0).is_err());
        let replacement = vm
            .vm
            .create_vcpu(1, Arc::new(vm.guest_mem.memory().clone()))
            .unwrap();
        vm.vcpus.insert(1, replacement);
    }
    psci::boot_native_secondaries(&mut vm);
    for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
        let pc = CODE + id as u64 * 0x20;
        vm.guest_mem
            .memory()
            .write_slice(&0xf940_0020u32.to_le_bytes(), GuestAddress(pc))
            .unwrap(); // LDR X0,[X1]
        vm.guest_mem
            .memory()
            .write_slice(
                &(0xd280_0002u32 | (0xbeef << 5)).to_le_bytes(),
                GuestAddress(pc + 4),
            )
            .unwrap(); // MOV X2,#0xbeef
        vm.guest_mem
            .memory()
            .write_slice(&0xd503_207fu32.to_le_bytes(), GuestAddress(pc + 8))
            .unwrap(); // WFI
        // WFI may complete without an interrupt. Keep continued native entry
        // inside the fixture instead of falling into unmapped exception code.
        vm.guest_mem
            .memory()
            .write_slice(&0x1400_0000u32.to_le_bytes(), GuestAddress(pc + 12))
            .unwrap(); // B .
        publish_native_code(&vm.guest_mem, pc, 16);
        let CpuState::Aarch64(mut public) = cpu.get_state().unwrap() else {
            panic!()
        };
        public.regs.pc = pc;
        public.regs.pstate = 0x3c5;
        public.regs.x[0] = 0x1234_0000 + id as u64;
        public.regs.x[1] = UART;
        public.sregs.esr_el1 = 0x9600_0005 + id as u64;
        public.sregs.far_el1 = 0xfeed_0000 + id as u64;
        public.sregs.cntp_cval_el0 = u64::MAX - 0x100;
        public.sregs.cntv_cval_el0 = u64::MAX - 0x200;
        public.sregs.cntp_ctl_el0 = 3;
        public.sregs.cntv_ctl_el0 = 3;
        for (index, q) in public.regs.v.iter_mut().enumerate() {
            *q = [
                0xface_0000 | (id as u64) << 8 | index as u64,
                !(index as u64),
            ];
        }
        cpu.set_state(&CpuState::Aarch64(public)).unwrap();
        let mut pending = false;
        for _ in 0..16 {
            match cpu.run().unwrap() {
                VcpuExit::MmioRead {
                    addr: UART,
                    size: 8,
                } => {
                    pending = true;
                    break;
                }
                VcpuExit::Hlt => (), // A genuine guest waiting hint.
                exit => panic!("unexpected native exit: {exit:?}"),
            }
        }
        assert!(pending, "native load did not reach its MMIO frontier");
    }
    vm.vm.set_irq_line(33, true).unwrap();
    vm.vm.set_irq_line(33, true).unwrap();
    let saved = vm.take_snapshot_bundle(0).unwrap();
    saved.save(&fixture.checkpoint).unwrap();
    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    assert_eq!(loaded.cpus().unwrap().entries().len(), usize::from(count));
    let shared = loaded.vm_context().unwrap();
    assert_eq!(shared.kind, HVF_AARCH64_CONTEXT);
    let shared = GlobalContext::decode(&shared.data).unwrap();
    assert_eq!(shared.cpus, count);
    assert_eq!(shared.irq_levels, [(33, true)]);
    for (id, record) in loaded
        .backend_contexts()
        .unwrap()
        .entries()
        .iter()
        .enumerate()
    {
        let context = Context::decode(&record.as_ref().unwrap().data).unwrap();
        assert_eq!(context.id, id as u32);
        let pending = context.pending_read.unwrap();
        assert_eq!(
            (pending.address, pending.register, pending.size),
            (UART, 0, 8),
            "CPU{id}: captured PC={:#x}; installed instruction={:#x}",
            context.public.regs.pc,
            vm.guest_mem
                .memory()
                .read_obj::<u32>(GuestAddress(CODE + id as u64 * 0x20))
                .unwrap()
        );
        assert_eq!(context.public.regs.pc, CODE + id as u64 * 0x20);
        assert_eq!(pending.retire_pc, Some(CODE + id as u64 * 0x20 + 4));
        assert_eq!(context.public.regs.x[0], 0x1234_0000 + id as u64);
        for (index, q) in context.public.regs.v.iter().enumerate() {
            assert_eq!(
                *q,
                [
                    0xface_0000 | (id as u64) << 8 | index as u64,
                    !(index as u64)
                ]
            );
        }
        assert!(context.public.sregs.execution.is_none());
        assert_eq!(context.public.sregs.esr_el1, 0x9600_0005 + id as u64);
        assert_eq!(context.public.sregs.far_el1, 0xfeed_0000 + id as u64);
        assert_eq!(context.public.sregs.cntp_cval_el0, u64::MAX - 0x100);
        assert_eq!(context.public.sregs.cntv_cval_el0, u64::MAX - 0x200);
    }
    assert_eq!(loaded.vm_context(), saved.vm_context());
    assert_eq!(
        loaded.backend_contexts().unwrap().entries(),
        saved.backend_contexts().unwrap().entries()
    );
    if let Some(directory) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::copy(
            &fixture.checkpoint,
            directory.join(format!("native-capture-{count}.rxc")),
        )
        .unwrap();
    }
    drop(vm);
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
    let expected: Vec<_> = loaded
        .backend_contexts()
        .unwrap()
        .entries()
        .iter()
        .map(|record| Context::decode(&record.as_ref().unwrap().data).unwrap())
        .collect();
    assert_eq!(private_states(&restored), expected);
    for (id, cpu) in restored.vcpus.iter_mut().enumerate() {
        assert!(matches!(
            cpu.run().unwrap(),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8
            }
        ));
        let reply = 0xface_cafe_0000_0000 | id as u64;
        cpu.complete_io_in(&reply.to_le_bytes());
        cpu.io_completion_result().unwrap();
        let mut continued = false;
        for _ in 0..16 {
            assert!(matches!(
                native_wait_turn(cpu.as_mut()),
                None | Some(VcpuExit::Hlt)
            ));
            let CpuState::Aarch64(public) = cpu.get_state().unwrap() else {
                panic!()
            };
            if public.regs.x[2] == 0xbeef && public.regs.pc == CODE + id as u64 * 0x20 + 12 {
                assert_eq!(public.regs.x[0], reply);
                assert_eq!(public.regs.pc, CODE + id as u64 * 0x20 + 12);
                continued = true;
                break;
            }
        }
        assert!(
            continued,
            "restored native CPU did not execute its continuation"
        );
    }
    println!(
        "native file continuation: {count} CPUs, reversed creation={reversed_creation}, pending MMIO, Q registers, shared GIC/IRQ, real .rxc save/load and Vmm::new_resume_bundle"
    );
}

fn private_states(vm: &Vmm) -> Vec<Context> {
    vm.vcpus
        .iter()
        .map(|cpu| Context::decode(&cpu.capture_backend_context().unwrap().unwrap().data).unwrap())
        .collect()
}

// Fixture writers replace startup instructions through raw RAM aliases while
// every native CPU is stopped. Apple OSCacheControl.h requires host data/code
// synchronization after writing instructions and before executing them.
fn publish_native_code(memory: &GuestMemoryWrapper, address: u64, length: usize) {
    assert!(length != 0);
    assert!(
        address
            .checked_add(length as u64)
            .is_some_and(|end| end <= memory.actual_size())
    );
    let pointer = memory
        .memory()
        .get_host_address(GuestAddress(address))
        .unwrap();
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut std::ffi::c_void, length: usize);
    }
    // SAFETY: GuestMemoryWrapper owns one contiguous backing from address0 to
    // actual_size; the checked nonempty range is live for this call. All guest
    // CPUs are stopped during fixture publication. The host API synchronizes
    // cache visibility and does not replace or release the backing allocation.
    unsafe { sys_icache_invalidate(pointer.cast(), length) };
}

// The SDK may handle WFI without a guest exit. A bounded host turn preserves
// that distinction while the test checks the resulting architectural frontier.
fn native_wait_turn(cpu: &mut dyn VCpu) -> Option<VcpuExit> {
    cpu.run_host_slice(crate::vm::vcpu::DEFAULT_HOST_SLICE)
        .unwrap()
}

#[test]
#[ignore = "requires physical Apple Silicon SME2 and com.apple.security.hypervisor entitlement"]
fn active_sme_modes_restore_all_storage_and_execute_za_after_real_file_resume() {
    for streaming in [false, true] {
        for za_enabled in [false, true] {
            let fixture = Fixture::new();
            let mut source = Vmm::new_resume(fixture.config(1)).unwrap();
            let mut seeded = private_states(&source).remove(0);
            let bytes = usize::from(seeded.profile.maximum_svl);
            assert!(bytes >= 16, "this test requires actual native SME storage");
            assert!(
                seeded
                    .profile
                    .feature_values
                    .iter()
                    .any(|register| { register.id == 0xc025 && (register.value >> 56) & 15 != 0 }),
                "this test requires actual native SME2 ZT0 storage"
            );
            seeded.public.regs.pc = CODE;
            seeded.public.regs.pstate = 0x3c5;
            seeded.public.regs.fpsr = 1;
            for register in &mut seeded.system {
                match register.id {
                    0xc082 => register.value |= (3 << 16) | (3 << 20) | (3 << 24),
                    0xc096 => register.value = (bytes / 16 - 1) as u64,
                    _ => (),
                }
            }
            let pattern = |length: usize, salt: u8| {
                (0..length)
                    .map(|index| (index as u8).wrapping_mul(17).wrapping_add(salt))
                    .collect::<Vec<_>>()
            };
            seeded.sme.streaming = streaming;
            seeded.sme.za_enabled = za_enabled;
            seeded.sme.z = pattern(if streaming { 32 * bytes } else { 0 }, 0x35);
            seeded.sme.p = pattern(if streaming { 2 * bytes } else { 0 }, 0x71);
            seeded.sme.za = pattern(if za_enabled { bytes * bytes } else { 0 }, 0xa3);
            seeded.sme.zt = za_enabled.then(|| pattern(64, 0xd7));
            if streaming {
                for (index, z) in seeded.sme.z.chunks_exact(bytes).enumerate() {
                    seeded.public.regs.v[index] = [
                        u64::from_le_bytes(z[..8].try_into().unwrap()),
                        u64::from_le_bytes(z[8..16].try_into().unwrap()),
                    ];
                }
            } else {
                for (index, q) in seeded.public.regs.v.iter_mut().enumerate() {
                    *q = [0xface_0000 | index as u64, !(index as u64)];
                }
            }
            seeded.project_system().unwrap();
            let record = crate::vm::snapshot::BackendContext {
                kind: HVF_AARCH64_CONTEXT,
                data: seeded.encode().unwrap(),
            };
            {
                let boundary = source.vm.checkpoint_boundary().unwrap();
                source.vcpus[0]
                    .restore_checkpoint_record(
                        &boundary,
                        &CpuState::Aarch64(seeded.public.clone()),
                        &crate::vm::snapshot::EmulatorState::default(),
                        Some(&record),
                    )
                    .unwrap();
            }
            let actual = private_states(&source).remove(0);
            assert_eq!(
                actual.sme, seeded.sme,
                "seed SM={streaming}, ZA={za_enabled}"
            );
            assert_eq!(actual.public.regs.v, seeded.public.regs.v);
            assert_eq!(actual.public.regs.fpsr, 1);
            // Use PSCI SYSTEM_OFF: direct SDK execution can continue past WFI.
            let instruction = if za_enabled { 0xc008_00ff } else { 0xd297_dde2 };
            let words: [u32; 4] = [instruction, 0x5280_0100, 0x72b0_8000, 0xd400_0002];
            for (index, word) in words.into_iter().enumerate() {
                source
                    .guest_mem
                    .memory()
                    .write_slice(&word.to_le_bytes(), GuestAddress(CODE + index as u64 * 4))
                    .unwrap();
            }
            let saved = source.take_snapshot_bundle(0).unwrap();
            saved.save(&fixture.checkpoint).unwrap();
            let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
            if let Some(directory) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
                let directory = std::path::PathBuf::from(directory);
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::copy(
                    &fixture.checkpoint,
                    directory.join(format!("native-sme-sm-{streaming}-za-{za_enabled}.rxc")),
                )
                .unwrap();
                std::fs::write(
                    directory.join(format!("native-sme-sm-{streaming}-za-{za_enabled}.json")),
                    serde_json::to_vec_pretty(&actual).unwrap(),
                )
                .unwrap();
            }
            drop(source);
            let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
            let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
            assert_eq!(private_states(&target), vec![actual.clone()]);
            let mut code = [0; 16];
            target
                .guest_mem
                .memory()
                .read_slice(&mut code, GuestAddress(CODE))
                .unwrap();
            for (word, expected) in code.chunks_exact(4).zip(words) {
                assert_eq!(u32::from_le_bytes(word.try_into().unwrap()), expected);
            }
            let mut continued = false;
            for _ in 0..16 {
                let exit = target.vcpus[0].run().unwrap();
                if matches!(exit, VcpuExit::Hlt) {
                    continue;
                }
                assert!(matches!(exit, VcpuExit::Shutdown), "native exit: {exit:?}");
                let after = private_states(&target).remove(0);
                if after.public.regs.pc == CODE + 16 {
                    assert_eq!(after.sme.streaming, streaming);
                    assert_eq!(after.sme.za_enabled, za_enabled);
                    assert_eq!(after.sme.z, actual.sme.z);
                    assert_eq!(after.sme.p, actual.sme.p);
                    assert_eq!(after.sme.zt, actual.sme.zt);
                    assert_eq!(after.public.regs.fpsr, 1);
                    if za_enabled {
                        assert!(after.sme.za.iter().all(|&byte| byte == 0));
                    } else {
                        assert_eq!(after.public.regs.x[2], 0xbeef);
                    }
                    continued = true;
                    break;
                }
            }
            assert!(
                continued,
                "SM={streaming}, ZA={za_enabled} guest did not continue"
            );
            println!(
                "native SME file continuation: SM={streaming}, ZA={za_enabled}, maximum SVL={bytes} bytes"
            );
        }
    }
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_failed_restore_and_failed_rollback_disable_all_further_entry() {
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(1)).unwrap();
    let saved = source.take_snapshot_bundle(0).unwrap();
    drop(source);
    let mut target = Vmm::new_resume(fixture.config(1)).unwrap();
    target
        .vm
        .as_any()
        .downcast_ref::<crate::backend::hvf::arm64::HvfArm64Vm>()
        .unwrap()
        .fail_next_gpr_writes(0, 0, 2);
    let error = target.restore_snapshot_bundle(&saved).unwrap_err();
    assert!(error.to_string().contains("rollback failed"), "{error}");
    assert!(
        error.to_string().contains("guest entry disabled"),
        "{error}"
    );
    let error = target.vcpus[0].run().unwrap_err();
    assert!(
        error.to_string().contains("failed checkpoint rollback"),
        "{error}"
    );
    assert!(target.vcpus[0].get_state().is_err());
    assert!(target.vm.set_irq_line(33, true).is_err());
    assert!(target.take_snapshot_bundle(0).is_err());
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_psci_shutdown_survives_files_and_register_overlays_until_explicit_restart() {
    for (name, function, call) in [
        ("off-hvc", 8u32, 0xd400_0002u32),
        ("reset-hvc", 9, 0xd400_0002),
        ("off-smc", 8, 0xd400_0003),
        ("reset-smc", 9, 0xd400_0003),
    ] {
        let fixture = Fixture::new();
        let mut source = Vmm::new_resume(fixture.config(1)).unwrap();
        // SYSTEM_OFF/RESET is followed by observable code which must remain
        // unexecuted until the embedder explicitly restarts the stopped CPU.
        let words = [
            0x5280_0000 | (function << 5),
            0x72b0_8000,
            call,
            0xd280_0002 | (0xbad << 5),
            call,
        ];
        for (index, word) in words.into_iter().enumerate() {
            source
                .guest_mem
                .memory()
                .write_slice(&word.to_le_bytes(), GuestAddress(CODE + index as u64 * 4))
                .unwrap();
        }
        let CpuState::Aarch64(mut state) = source.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.pstate = 0x3c5;
        state.regs.x[2] = 0;
        source.vcpus[0]
            .set_state(&CpuState::Aarch64(state))
            .unwrap();
        loop {
            match source.vcpus[0].run().unwrap() {
                VcpuExit::Hlt => (),
                VcpuExit::Shutdown => break,
                exit => panic!("{name}: unexpected initial exit {exit:?}"),
            }
        }
        let stopped = private_states(&source).remove(0);
        assert_eq!(stopped.public.regs.pc, CODE + 12, "{name}");
        assert_eq!(stopped.public.regs.x[2], 0, "{name}");
        let saved = source.take_snapshot_bundle(0).unwrap();
        saved.save(&fixture.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
        if let Some(directory) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::copy(
                &fixture.checkpoint,
                directory.join(format!("native-shutdown-{name}.rxc")),
            )
            .unwrap();
        }
        drop(source);
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(private_states(&target), vec![stopped.clone()], "{name}");
        let exit = target.vcpus[0].run().unwrap();
        let after = private_states(&target);
        assert!(
            matches!(exit, VcpuExit::Shutdown),
            "{name}: expected retained shutdown; exit={exit:?}, PC={:#x}, X2={:#x}",
            after[0].public.regs.pc,
            after[0].public.regs.x[2],
        );
        assert_eq!(
            after,
            vec![stopped],
            "{name}: restoring a terminal CPU must not execute past shutdown"
        );
        let CpuState::Aarch64(mut overlay) = target.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        overlay.regs.x[5] = 0x1234;
        target.vcpus[0]
            .update_state(&CpuState::Aarch64(overlay))
            .unwrap();
        let overlaid = private_states(&target);
        for _ in 0..2 {
            assert!(matches!(target.vcpus[0].run().unwrap(), VcpuExit::Shutdown));
            assert_eq!(
                private_states(&target),
                overlaid,
                "{name}: overlay retained stop"
            );
        }
        target.vcpus[0].wake();
        loop {
            match target.vcpus[0].run().unwrap() {
                VcpuExit::Hlt => (),
                VcpuExit::Shutdown => break,
                exit => panic!("{name}: unexpected restarted exit {exit:?}"),
            }
        }
        let restarted = private_states(&target).remove(0);
        assert_eq!(restarted.public.regs.pc, CODE + 20, "{name}");
        assert_eq!(restarted.public.regs.x[2], 0xbad, "{name}");
        assert!(matches!(target.vcpus[0].run().unwrap(), VcpuExit::Shutdown));
        assert_eq!(private_states(&target), vec![restarted.clone()], "{name}");
        let mut replacement = restarted.public;
        replacement.regs.pc = CODE + 12;
        replacement.regs.x[2] = 0;
        target.vcpus[0]
            .set_state(&CpuState::Aarch64(replacement))
            .unwrap();
        loop {
            match target.vcpus[0].run().unwrap() {
                VcpuExit::Hlt => (),
                VcpuExit::Shutdown => break,
                exit => panic!("{name}: unexpected replacement exit {exit:?}"),
            }
        }
        assert_eq!(private_states(&target)[0].public.regs.x[2], 0xbad, "{name}");
    }
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn active_uart_spi_file_restore_preserves_priority_reassertion_and_deassertion() {
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(1)).unwrap();
    // LLVM MC fixture: configure GICD and the group-1 CPU interface, acknowledge
    // SPI 33, then stop at an unserviced PL011 FR load. On resume, EOI/IAR
    // observes the asserted level again, DR consumes the byte, and a second
    // EOI/IAR must observe no interrupt after the VMM lowers the UART line.
    let words: [u32; 30] = [
        0xd2a1_0009,
        0xb940_012a,
        0x3200_054a,
        0xb900_012a,
        0x5280_004a,
        0xb900_852a,
        0xb901_052a,
        0x5290_100a,
        0x72b0_100a,
        0xb904_212a,
        0xf930_853f,
        0x5280_00ea,
        0xd518_ccaa,
        0x5280_1fea,
        0xd518_460a,
        0x5280_002a,
        0xd518_ccea,
        0xd503_3fdf,
        0xd538_cc03,
        0xb940_18e8,
        0xd518_cc23,
        0xd503_3fdf,
        0xd538_cc04,
        0x3940_00e6,
        0xd518_cc24,
        0xd503_3fdf,
        0xd538_cc05,
        0x5280_0100,
        0x72b0_8000,
        0xd400_0002,
    ];
    for (index, word) in words.into_iter().enumerate() {
        source
            .guest_mem
            .memory()
            .write_slice(&word.to_le_bytes(), GuestAddress(CODE + index as u64 * 4))
            .unwrap();
    }
    source
        .mmio_bus
        .write(UART + 0x30, &0x301u32.to_le_bytes())
        .unwrap();
    source
        .mmio_bus
        .write(UART + 0x38, &16u32.to_le_bytes())
        .unwrap();
    {
        let mut uart = source.pl011.as_ref().unwrap().lock().unwrap();
        uart.queue_input(&[0xab]);
        assert!(uart.irq_pending());
    }
    source.vm.set_irq_line(33, true).unwrap();
    let CpuState::Aarch64(mut public) = source.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    public.regs.pc = CODE;
    public.regs.pstate = 0x3c5;
    public.regs.x[7] = UART;
    public.regs.x[8] = 0xfeed_cafe_1234_5678;
    source.vcpus[0]
        .set_state(&CpuState::Aarch64(public))
        .unwrap();
    let mut pending = false;
    for _ in 0..64 {
        match source.vcpus[0].run().unwrap() {
            VcpuExit::MmioRead { addr, size: 4 } if addr == UART + 0x18 => {
                pending = true;
                break;
            }
            VcpuExit::Hlt => (),
            exit => panic!("native GIC setup did not reach its status read: {exit:?}"),
        }
    }
    assert!(pending);
    let active = private_states(&source).remove(0);
    assert_eq!(active.public.regs.x[3], 33);
    assert_eq!(active.running_priority, 0x80);
    assert_eq!(active.public.regs.pc, CODE + 76);
    assert_eq!(
        active.pending_read.as_ref().unwrap().retire_pc,
        Some(CODE + 80)
    );
    assert_eq!(active.public.regs.x[8], 0xfeed_cafe_1234_5678);
    assert_eq!(active.pending_read.as_ref().unwrap().register, 8);
    let saved = source.take_snapshot_bundle(0).unwrap();
    saved.save(&fixture.checkpoint).unwrap();
    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    if let Some(directory) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::copy(
            &fixture.checkpoint,
            directory.join("native-active-uart-spi.rxc"),
        )
        .unwrap();
    }
    drop(source);
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    assert_eq!(private_states(&target), vec![active]);
    assert!(target.pl011.as_ref().unwrap().lock().unwrap().irq_pending());
    target.run().unwrap();
    let final_state = private_states(&target).remove(0);
    assert_eq!(final_state.public.regs.x[3], 33);
    assert_eq!(final_state.public.regs.x[4], 33);
    assert_eq!(final_state.public.regs.x[5], 1023);
    assert_eq!(final_state.public.regs.x[6], 0xab);
    assert_eq!(final_state.public.regs.x[8] & 16, 0);
    assert_eq!(final_state.public.regs.pc, CODE + 120);
    assert_eq!(final_state.running_priority, 255);
    assert!(final_state.pending_read.is_none());
    assert!(!target.pl011.as_ref().unwrap().lock().unwrap().irq_pending());
    let boundary = target.vm.checkpoint_boundary().unwrap();
    let shared = target
        .vm
        .capture_checkpoint_vm_context(&boundary)
        .unwrap()
        .unwrap();
    assert_eq!(
        GlobalContext::decode(&shared.data).unwrap().irq_levels,
        [(33, false)]
    );
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_register_overlay_preserves_each_pending_io_phase() {
    for phase in ["unserviced read", "consumed reply", "unacknowledged write"] {
        let fixture = Fixture::new();
        let mut vm = Vmm::new_resume(fixture.config(1)).unwrap();
        let write = phase == "unacknowledged write";
        let instruction: u32 = if write { 0xf900_0020 } else { 0xf940_0020 };
        vm.guest_mem
            .memory()
            .write_slice(&instruction.to_le_bytes(), GuestAddress(CODE))
            .unwrap();
        let CpuState::Aarch64(mut public) = vm.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        public.regs.pc = CODE;
        public.regs.pstate = 0x3c5;
        public.regs.x[0] = 0xfedc_ba98_7654_3210;
        public.regs.x[1] = UART;
        vm.vcpus[0].set_state(&CpuState::Aarch64(public)).unwrap();
        let mut pending = false;
        for _ in 0..16 {
            match vm.vcpus[0].run().unwrap() {
                VcpuExit::MmioRead {
                    addr: UART,
                    size: 8,
                } if !write => {
                    pending = true;
                    break;
                }
                VcpuExit::MmioWrite { addr: UART, .. } if write => {
                    pending = true;
                    break;
                }
                VcpuExit::Hlt => (),
                exit => panic!("{phase}: unexpected native exit {exit:?}"),
            }
        }
        assert!(pending, "{phase}: no pending native transaction");
        if phase == "consumed reply" {
            vm.vm
                .as_any()
                .downcast_ref::<crate::backend::hvf::arm64::HvfArm64Vm>()
                .unwrap()
                .fail_next_gpr_writes(0, 0, 1);
            vm.vcpus[0].complete_io_in(&0xface_cafe_1234_5678u64.to_le_bytes());
        }
        let before = private_states(&vm).remove(0);
        let mut invalid = before.public.clone();
        invalid.regs.pstate = 0x3c9; // EL2h is outside the native EL0/EL1 contract.
        assert!(
            vm.vcpus[0]
                .update_state(&CpuState::Aarch64(invalid))
                .is_err()
        );
        assert_eq!(
            private_states(&vm).remove(0),
            before,
            "{phase}: rejected overlay mutated state"
        );
        let mut public = before.public.clone();
        public.regs.x[5] = 0xface_8765_4321_1234;
        vm.vcpus[0]
            .update_state(&CpuState::Aarch64(public.clone()))
            .unwrap();
        let after = private_states(&vm).remove(0);
        assert_eq!(
            after.pending_read, before.pending_read,
            "{phase}: native register overlay must retain the pending read"
        );
        assert_eq!(
            after.pending_write, before.pending_write,
            "{phase}: native register overlay must retain the pending write"
        );
        assert_eq!(after.pending_reply, before.pending_reply, "{phase}");
        assert_eq!(after.completion_error, before.completion_error, "{phase}");
        let mut expected = before;
        expected.public = public;
        assert_eq!(after, expected, "{phase}: unrelated private state changed");
        assert!(vm.vcpus[0].io_completion_result().is_err(), "{phase}");
    }
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_target_rejects_legacy_cpu_projection_before_any_mutation() {
    let fixture = Fixture::new();
    let mut target = Vmm::new_resume(fixture.config(1)).unwrap();
    let before = private_states(&target);
    let cpu = &mut target.vcpus[0];
    let mut public = before[0].public.clone();
    public.regs.x[0] ^= u64::MAX;
    let public = CpuState::Aarch64(public);
    let emulator = crate::vm::snapshot::EmulatorState::default();
    assert!(cpu.validate_checkpoint_state(&public, &emulator).is_err());
    assert!(
        cpu.restore_checkpoint_context(&public, &emulator, None)
            .is_err()
    );
    assert_eq!(private_states(&target), before);
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_pending_mmio_store_survives_real_file_before_device_dispatch() {
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(1)).unwrap();
    for (offset, word) in [
        (0, 0xf900_0020u32), // STR X0,[X1]
        (4, 0xd297_dde2),    // MOV X2,#0xbeef
        (8, 0x5280_0100),    // MOV W0,#8
        (12, 0x72b0_8000),   // MOVK W0,#0x8400,LSL#16
        (16, 0xd400_0002),   // HVC #0: PSCI SYSTEM_OFF
    ] {
        source
            .guest_mem
            .memory()
            .write_slice(&word.to_le_bytes(), GuestAddress(CODE + offset))
            .unwrap();
    }
    let CpuState::Aarch64(mut public) = source.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    let data = 0xfedc_ba98_7654_3210u64.to_le_bytes().to_vec();
    public.regs.pc = CODE;
    public.regs.pstate = 0x3c5;
    public.regs.x[0] = u64::from_le_bytes(data.clone().try_into().unwrap());
    public.regs.x[1] = UART + 0x30; // PL011 control, without console output.
    source.vcpus[0]
        .set_state(&CpuState::Aarch64(public))
        .unwrap();
    let mut pending = false;
    for _ in 0..16 {
        match source.vcpus[0].run().unwrap() {
            VcpuExit::MmioWrite { addr, data: actual } if addr == UART + 0x30 => {
                assert_eq!(actual, data);
                pending = true;
                break;
            }
            VcpuExit::Hlt => (),
            exit => panic!("unexpected native store exit: {exit:?}"),
        }
    }
    assert!(pending, "native store did not reach its MMIO handoff");
    let saved = source.take_snapshot_bundle(0).unwrap();
    saved.save(&fixture.checkpoint).unwrap();
    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    drop(source);
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    for _ in 0..2 {
        let exit = target.vcpus[0].run().unwrap();
        assert!(
            matches!(exit, VcpuExit::MmioWrite { addr, data: actual } if addr == UART + 0x30 && actual == data),
            "the undispatched native store must survive file restoration"
        );
        assert!(target.vcpus[0].io_completion_result().is_err());
        let pending = private_states(&target).remove(0);
        assert_eq!(pending.public.regs.pc, CODE);
        let phase = pending
            .pending_write
            .as_ref()
            .unwrap()
            .retirement
            .as_ref()
            .unwrap();
        assert_eq!(phase.next_pc, CODE + 4);
        assert!(!phase.acknowledged);
    }
    // Exercise the actual coordinator and device-dispatch acknowledgement.
    target.run().unwrap();
    let after = private_states(&target).remove(0);
    assert!(after.pending_write.is_none());
    assert_eq!(after.public.regs.pc, CODE + 20);
    assert_eq!(after.public.regs.x[2], 0xbeef);
    target.vcpus[0].io_completion_result().unwrap();
    assert!(target.vcpus[0].complete_io_out().is_err());
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn late_sdk_gic_rejection_rolls_back_every_native_cpu_ram_and_irq_level() {
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(2)).unwrap();
    for (id, cpu) in source.vcpus.iter_mut().enumerate() {
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.x[0] = 0xface_1000 + id as u64;
        cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    }
    source
        .guest_mem
        .memory()
        .write_slice(&[0xa5; 16], GuestAddress(CODE))
        .unwrap();
    source.vm.set_irq_line(33, true).unwrap();
    let mut bad = source.take_snapshot_bundle(0).unwrap();
    let mut shared = bad.take_vm_context().unwrap();
    let mut state = GlobalContext::decode(&shared.data).unwrap();
    state.gic = vec![0xff]; // Well-framed producer record; invalid SDK device image.
    shared.data = state.encode().unwrap();
    let cpus = bad.cpus().unwrap().entries().to_vec();
    let contexts = bad.backend_contexts().unwrap().entries().to_vec();
    bad = bad
        .with_checkpoint_records(cpus, contexts, Some(shared))
        .unwrap();
    drop(source);
    let mut target = Vmm::new_resume(fixture.config(2)).unwrap();
    target
        .guest_mem
        .memory()
        .write_slice(&[0x5a; 16], GuestAddress(CODE))
        .unwrap();
    let before = private_states(&target);
    let shared_before = {
        let boundary = target.vm.checkpoint_boundary().unwrap();
        target
            .vm
            .capture_checkpoint_vm_context(&boundary)
            .unwrap()
            .unwrap()
    };
    let error = target.restore_snapshot_bundle(&bad).unwrap_err();
    assert!(
        error.to_string().contains("restore shared GIC state"),
        "{error}"
    );
    assert!(!error.to_string().contains("rollback failed"), "{error}");
    assert_eq!(private_states(&target), before);
    let shared_after = {
        let boundary = target.vm.checkpoint_boundary().unwrap();
        target
            .vm
            .capture_checkpoint_vm_context(&boundary)
            .unwrap()
            .unwrap()
    };
    assert_eq!(shared_after, shared_before);
    let mut actual = [0; 16];
    target
        .guest_mem
        .memory()
        .read_slice(&mut actual, GuestAddress(CODE))
        .unwrap();
    assert_eq!(actual, [0x5a; 16]);
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn failed_native_reply_file_retries_saved_data_without_a_second_device_read() {
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(1)).unwrap();
    for (offset, word) in [
        (0, 0x3940_0020u32),
        (4, 0xd280_0002 | (0xbeef << 5)),
        (8, 0xd503_207f),
        (12, 0x1400_0000), // B . after the optional WFI wait.
    ] {
        source
            .guest_mem
            .memory()
            .write_slice(&word.to_le_bytes(), GuestAddress(CODE + offset))
            .unwrap();
    }
    source
        .pl011
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .queue_input(&[0xab, 0xcd]);
    let CpuState::Aarch64(mut state) = source.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = CODE;
    state.regs.pstate = 0x3c5;
    state.regs.x[0] = 0x1234_5678_9abc_def0;
    state.regs.x[1] = UART;
    source.vcpus[0]
        .set_state(&CpuState::Aarch64(state))
        .unwrap();
    let mut pending = false;
    for _ in 0..16 {
        match source.vcpus[0].run().unwrap() {
            VcpuExit::MmioRead {
                addr: UART,
                size: 1,
            } => {
                pending = true;
                break;
            }
            VcpuExit::Hlt => (),
            exit => panic!("unexpected native exit: {exit:?}"),
        }
    }
    assert!(pending);
    let mut data = [0];
    source.mmio_bus.read(UART, &mut data).unwrap();
    assert_eq!(data, [0xab]);
    source
        .vm
        .as_any()
        .downcast_ref::<crate::backend::hvf::arm64::HvfArm64Vm>()
        .unwrap()
        .fail_next_gpr_writes(0, 0, 1);
    source.vcpus[0].complete_io_in(&data);
    assert!(
        source.vcpus[0]
            .io_completion_result()
            .unwrap_err()
            .to_string()
            .contains("injected native GPR write failure")
    );
    let record = private_states(&source).remove(0);
    assert_eq!(record.pending_reply, Some(vec![0xab]));
    assert_eq!(record.public.regs.x[0], 0x1234_5678_9abc_def0);
    let saved = source.take_snapshot_bundle(0).unwrap();
    saved.save(&fixture.checkpoint).unwrap();
    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    drop(source);
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    assert!(
        target.vcpus[0]
            .run()
            .unwrap_err()
            .to_string()
            .contains("injected native GPR write failure")
    );
    let mut finished = false;
    for _ in 0..16 {
        assert!(matches!(
            native_wait_turn(target.vcpus[0].as_mut()),
            None | Some(VcpuExit::Hlt)
        ));
        let CpuState::Aarch64(state) = target.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        if state.regs.pc == CODE + 12 {
            assert_eq!(state.regs.x[0], 0xab);
            assert_eq!(state.regs.x[2], 0xbeef);
            finished = true;
            break;
        }
    }
    assert!(finished);
    target.mmio_bus.read(UART, &mut data).unwrap();
    assert_eq!(data, [0xcd]);
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_short_mmio_reply_reports_pending_before_more_execution() {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(1)).unwrap();
    vm.guest_mem
        .memory()
        .write_slice(&0xf940_0020u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    let cpu = &mut vm.vcpus[0];
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = CODE;
    state.regs.pstate = 0x3c5;
    state.regs.x[0] = 0x1234_5678_9abc_def0;
    state.regs.x[1] = UART;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    let mut pending = false;
    for _ in 0..16 {
        match cpu.run().unwrap() {
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => {
                pending = true;
                break;
            }
            VcpuExit::Hlt => (),
            exit => panic!("unexpected native exit: {exit:?}"),
        }
    }
    assert!(pending);
    cpu.complete_io_in(&[0xaa]);
    assert!(
        cpu.io_completion_result().is_err(),
        "a short native reply is not a completed read"
    );
    let partial = Context::decode(&cpu.capture_backend_context().unwrap().unwrap().data).unwrap();
    assert!(partial.pending_read.is_some());
    assert_eq!(partial.public.regs.pc, CODE);
    assert_eq!(
        partial.pending_read.as_ref().unwrap().retire_pc,
        Some(CODE + 4)
    );
    assert_eq!(partial.public.regs.x[0], 0x1234_5678_9abc_def0);
    let reply = 0xfedc_ba98_7654_3210u64;
    cpu.complete_io_in(&reply.to_le_bytes());
    cpu.io_completion_result().unwrap();
    let completed = Context::decode(&cpu.capture_backend_context().unwrap().unwrap().data).unwrap();
    assert!(completed.pending_read.is_none());
    assert_eq!(completed.public.regs.x[0], reply);
    assert_eq!(completed.public.regs.pc, CODE + 4);
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_cpu_destruction_preserves_peer_entry_but_rejects_incomplete_checkpoint() {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(2)).unwrap();
    psci::boot_native_secondaries(&mut vm);
    let removed = vm.vcpus.remove(0);
    drop(removed);
    vm.guest_mem
        .memory()
        .write_slice(&0xf940_0020u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    let CpuState::Aarch64(mut state) = vm.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = CODE;
    state.regs.pstate = 0x3c5;
    state.regs.x[1] = UART;
    vm.vcpus[0].set_state(&CpuState::Aarch64(state)).unwrap();
    vm.vm.set_irq_line(33, true).unwrap();
    let mut pending = false;
    for _ in 0..100 {
        match vm.vcpus[0].run().unwrap() {
            VcpuExit::Hlt => (),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => {
                pending = true;
                break;
            }
            exit => panic!("surviving CPU did not execute its load: {exit:?}"),
        }
    }
    assert!(pending);
    assert!(vm.take_snapshot_bundle(0).is_err());
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_kick_spawn_failure_unwinds_sdk_owner_and_allows_identity_reuse() {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(2)).unwrap();
    drop(vm.vcpus.pop().unwrap());
    vm.vm
        .as_any()
        .downcast_ref::<crate::backend::hvf::HvfArm64Vm>()
        .unwrap()
        .fail_next_kick_spawn();
    let result = vm
        .vm
        .create_vcpu(1, Arc::new(vm.guest_mem.memory().clone()));
    assert!(
        matches!(result, Err(Error::Emulator(ref message)) if message.contains("injected native kick spawn failure"))
    );
    let CpuState::Aarch64(mut state) = vm.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.x[5] = 0xbeef;
    vm.vcpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
    let CpuState::Aarch64(state) = vm.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    assert_eq!(state.regs.x[5], 0xbeef);
    assert!(vm.take_snapshot_bundle(0).is_err());
    let replacement = vm
        .vm
        .create_vcpu(1, Arc::new(vm.guest_mem.memory().clone()))
        .unwrap();
    vm.vcpus.push(replacement);
    psci::boot_native_secondaries(&mut vm);
    vm.guest_mem
        .memory()
        .write_slice(&0xf940_0020u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    let CpuState::Aarch64(mut state) = vm.vcpus[1].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = CODE;
    state.regs.pstate = 0x3c5;
    state.regs.x[1] = UART;
    vm.vcpus[1].set_state(&CpuState::Aarch64(state)).unwrap();
    let mut pending = false;
    for _ in 0..100 {
        match vm.vcpus[1].run().unwrap() {
            VcpuExit::Hlt => (),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => {
                pending = true;
                break;
            }
            exit => panic!("replacement failed after injected startup error: {exit:?}"),
        }
    }
    assert!(pending);
    vm.take_snapshot_bundle(0).unwrap();
    drop(vm);
    drop(Vmm::new_resume(fixture.config(1)).unwrap());
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_coordinator_runs_online_cpus_and_resumes_the_next_cpu_from_a_real_file() {
    for count in [2, 4] {
        let fixture = Fixture::new();
        let mut vm = Vmm::new_resume(fixture.config(count)).unwrap();
        psci::boot_native_secondaries(&mut vm);
        for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
            let pc = CODE + id as u64 * 0x40;
            // ADD X2,X2,#1; STR X2,[X1]; LDR X0,[X4]; B .-12.
            for (i, word) in [0x91000442u32, 0xf9000022, 0xf9400080, 0x17fffffd]
                .iter()
                .enumerate()
            {
                vm.guest_mem
                    .memory()
                    .write_slice(&word.to_le_bytes(), GuestAddress(pc + 4 * i as u64))
                    .unwrap();
            }
            publish_native_code(&vm.guest_mem, pc, 16);
            let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = pc;
            state.regs.pstate = 0x3c5;
            state.regs.x[1] = 0x40010000 + id as u64 * 8;
            state.regs.x[2] = (id as u64 + 1) * 0x1000;
            state.regs.x[4] = UART;
            cpu.set_state(&CpuState::Aarch64(state)).unwrap();
            // Initial RAM agrees with the per-CPU accumulator, including idle CPUs.
            vm.guest_mem
                .memory()
                .write_obj(
                    (id as u64 + 1) * 0x1000,
                    GuestAddress(0x40010000 + id as u64 * 8),
                )
                .unwrap();
        }
        // Prepared contexts qualify execution/restore, not PSCI startup.
        assert!(vm.coordinator.online.iter().all(|online| *online));
        let mut markers: Vec<u64> = (0..count).map(|id| (u64::from(id) + 1) * 0x1000).collect();
        let mut exits = vec![0u32; usize::from(count)];
        run_native_coordinator_rounds(&mut vm, &mut markers, &mut exits, 2);
        // Stop after CPU 0's next actual I/O frontier, retaining a nonzero cursor.
        while vm.coordinator.cursor != 1 {
            run_native_coordinator_turn(&mut vm, &mut markers, &mut exits);
        }
        let coordinator = vm.coordinator.clone();
        assert_eq!(
            coordinator.retired, 0,
            "host cancellation is not a retirement counter"
        );
        let saved = vm.take_snapshot_bundle(0).unwrap();
        saved.save(&fixture.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
        assert_eq!(loaded.execution().unwrap().cursor(), 1);
        assert_eq!(
            loaded.execution().unwrap().online(),
            vec![true; usize::from(count)]
        );
        if let Some(directory) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::copy(
                &fixture.checkpoint,
                directory.join(format!("native-coordinator-{count}.rxc")),
            )
            .unwrap();
        }
        drop(vm);
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(restored.coordinator, coordinator);
        let before = exits.clone();
        run_native_coordinator_rounds(&mut restored, &mut markers, &mut exits, 4);
        assert!(
            exits
                .iter()
                .zip(before)
                .all(|(after, prior)| *after > prior)
        );
    }
}

fn run_native_coordinator_rounds(
    vm: &mut Vmm,
    markers: &mut [u64],
    exits: &mut [u32],
    minimum: u32,
) {
    for _ in 0..1000 {
        if exits.iter().all(|count| *count >= minimum) {
            return;
        }
        run_native_coordinator_turn(vm, markers, exits);
    }
    panic!("native CPUs did not each reach their I/O frontier: {exits:?}");
}

fn run_native_coordinator_turn(vm: &mut Vmm, markers: &mut [u64], exits: &mut [u32]) {
    let selected = vm.coordinator.cursor;
    let turn = vm.execute_turn().unwrap();
    assert_eq!(vm.coordinator.cursor, (selected + 1) % markers.len());
    if let Some(turn) = turn {
        assert_eq!(turn.cpu_index, selected);
        match turn.exit {
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => {
                exits[selected] += 1;
                vm.vcpus[selected].complete_io_in(&(0xface0000u64 + selected as u64).to_le_bytes());
                vm.vcpus[selected].io_completion_result().unwrap();
            }
            VcpuExit::Hlt => (), // A genuine guest waiting hint.
            exit => panic!("unexpected native coordinator exit: {exit:?}"),
        }
    }
    // A None host turn still advances selection; every peer marker must remain
    // unchanged and the selected CPU may complete at most its pending load.
    for (id, previous) in markers.iter_mut().enumerate() {
        let value: u64 = vm
            .guest_mem
            .memory()
            .read_obj(GuestAddress(0x40010000 + id as u64 * 8))
            .unwrap();
        if id == selected {
            assert!(((*previous)..=(*previous + 1)).contains(&value));
        } else {
            assert_eq!(value, *previous, "unscheduled CPU {id} changed RAM");
        }
        *previous = value;
    }
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_coordinator_yields_from_gic_handled_wfi_without_claiming_retirement() {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(2)).unwrap();
    psci::boot_native_secondaries(&mut vm);
    for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
        let pc = CODE + id as u64 * 0x40;
        for (i, word) in [0xd503207fu32, 0xd297dde2, 0xf9400020].iter().enumerate() {
            vm.guest_mem
                .memory()
                .write_slice(&word.to_le_bytes(), GuestAddress(pc + i as u64 * 4))
                .unwrap();
        }
        publish_native_code(&vm.guest_mem, pc, 12);
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = pc;
        state.regs.pstate = 0x3c5;
        state.regs.x[1] = UART;
        state.regs.x[2] = 0;
        cpu.set_state(&CpuState::Aarch64(state)).unwrap();
        assert!(cpu.run_retirement_budget(1).is_err());
    }
    assert!(vm.coordinator.online.iter().all(|online| *online));
    let start = std::time::Instant::now();
    let mut completed = [false; 2];
    for _ in 0..100 {
        let Some(turn) = vm.execute_turn().unwrap() else {
            continue;
        };
        match turn.exit {
            VcpuExit::Hlt => (),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => {
                let CpuState::Aarch64(state) = vm.vcpus[turn.cpu_index].get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(state.regs.x[2], 0xbeef);
                completed[turn.cpu_index] = true;
            }
            exit => panic!("unexpected WFI continuation: {exit:?}"),
        }
        if completed.iter().all(|done| *done) {
            break;
        }
    }
    assert_eq!(completed, [true, true]);
    assert_eq!(vm.coordinator.retired, 0);
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
}

#[path = "native_psci_tests.rs"]
mod psci;

#[path = "native_standalone_tests.rs"]
mod standalone;

#[path = "native_terminal_io_tests.rs"]
mod terminal_io;

#[path = "native_store_retirement_tests.rs"]
mod store_retirement;
