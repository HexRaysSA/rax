//! Signed Intel HVF integration tests for private CPU and in-flight state.
use super::*;
use crate::backend::intel_hvf_context::{Context, Packet};
use crate::backend::intel_hvf_projection::Read;
use crate::backend::intel_hvf_registers::hv_vmx_vmcs_field_t as Vmcs;
use crate::config::{CliConfig, MemorySize};
use crate::devices::bus::MmioDevice;
use crate::vm::snapshot::{HVF_INTEL_CONTEXT, SnapshotBundle};
use crate::vm::vcpu::{Segment, X86_64CpuState};
use std::path::PathBuf;
use std::sync::Mutex;
use vm_memory::{Bytes, GuestAddress};

const RAM: u64 = 128 << 20;
const CODE: u64 = 0x10_0000;
const MMIO: u64 = 0x4000_0103;
const LANE_INSN_LENGTH: u64 = 6;
const LOW: u64 = 0x1122_3344_5566_7788;
const HIGH: u64 = 0xa1b2_c3d4_e5f6_0718;
const REPLY: u64 = 0x7e2d_b864_11db_feb0;

struct Paths(PathBuf);

impl Paths {
    fn new(count: u8) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-intel-vmm-checkpoint-{}-{count}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let paths = Self(directory);
        std::fs::write(paths.0.join("kernel"), [0; 64]).unwrap();
        paths
    }

    fn config(&self, count: u8) -> VmConfig {
        VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Hvf),
                kernel: Some(self.0.join("kernel")),
                memory: Some(MemorySize(RAM)),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap()
    }
}

impl Drop for Paths {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Access {
    Read(u64, usize),
    Write(u64, Vec<u8>),
}

struct Device(Arc<Mutex<Vec<Access>>>);

impl MmioDevice for Device {
    fn read(&mut self, address: u64, bytes: &mut [u8]) {
        self.0
            .lock()
            .unwrap()
            .push(Access::Read(address, bytes.len()));
        bytes.copy_from_slice(&REPLY.to_le_bytes());
    }

    fn write(&mut self, address: u64, bytes: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push(Access::Write(address, bytes.to_vec()));
    }
}

fn attach(vm: &mut Vmm, accesses: &Arc<Mutex<Vec<Access>>>) {
    vm.mmio_bus
        .register(
            MmioRange { base: MMIO, len: 8 },
            Box::new(Device(accesses.clone())),
        )
        .unwrap();
}

fn protected_long_mode_state() -> X86_64CpuState {
    let data = Segment {
        selector: 16,
        limit: u32::MAX,
        type_: 3,
        present: true,
        s: true,
        db: true,
        g: true,
        ..Default::default()
    };
    let mut state = X86_64CpuState::default();
    state.regs.rip = CODE + 0x100;
    state.regs.rsp = 0x1f_0000;
    state.regs.rflags = 2;
    state.sregs.cs = Segment {
        selector: 8,
        limit: u32::MAX,
        type_: 11,
        present: true,
        s: true,
        l: true,
        g: true,
        ..Default::default()
    };
    state.sregs.ds = data.clone();
    state.sregs.es = data.clone();
    state.sregs.ss = data.clone();
    state.sregs.fs = data.clone();
    state.sregs.gs = data;
    state.sregs.tr = Segment {
        selector: 24,
        base: 0x8000,
        limit: 0x67,
        type_: 11,
        present: true,
        ..Default::default()
    };
    state.sregs.ldt.unusable = true;
    state.sregs.gdt.base = 0x9000;
    state.sregs.gdt.limit = 47;
    state.sregs.cr0 = 0x8001_0033;
    state.sregs.cr3 = 0x1000;
    state.sregs.cr4 = 0x220;
    state.sregs.efer = 0x500;
    state.sregs.dr6 = 0xffff_0ff0;
    state.sregs.dr7 = 0x400;
    state
}

fn install_program(vm: &mut Vmm, ap: usize, read: bool) {
    let memory = vm.guest_mem.memory();
    for (address, word) in [
        (0x1000, 0x2003u64),             // PML4 to PDPT.
        (0x2000, 0x3003),                // PD for RAM.
        (0x2008, 0x4003),                // PD for the device.
        (0x3000, 0x0083),                // Identity-map the first 2 MiB.
        (0x4000, 0x4000_009b),           // Identity-map the MMIO region uncached.
        (0x9008, 0x00af_9b00_0000_ffff), // 64-bit code descriptor.
        (0x9010, 0x00cf_9300_0000_ffff), // Data descriptor.
        (0x9018, 0x0000_8b00_8000_0067), // Busy 64-bit TSS descriptor.
        (0x8004, 0x1f_0000),             // RSP0.
    ] {
        memory
            .write_slice(&word.to_le_bytes(), GuestAddress(address))
            .unwrap();
    }
    memory
        .write_slice(&0x68u16.to_le_bytes(), GuestAddress(0x8066))
        .unwrap();

    // The first instruction is MOVLPD (load) or MOVHPD (store) at [RDI+3].
    // MOV DX,0x604; MOV AX,0x2000; OUT DX,AX shuts down the VMM after retirement.
    let opcode = if read { 0x12 } else { 0x17 };
    let program = [
        0x66, 0x44, 0x0f, opcode, 0x7f, 3, 0x66, 0xba, 4, 6, 0x66, 0xb8, 0, 0x20, 0x66, 0xef, 0xf4,
    ];
    memory.write_slice(&program, GuestAddress(CODE)).unwrap();
    memory
        .write_slice(&[0xf4, 0xeb, 0xfd], GuestAddress(CODE + 0x100))
        .unwrap();

    let mut state = protected_long_mode_state();
    vm.vcpus[0]
        .set_state(&CpuState::X86_64(state.clone()))
        .unwrap();
    state.regs.rip = CODE;
    state.regs.rdi = MMIO - 3;
    state.regs.xmm[15] = [LOW, HIGH];
    vm.vcpus[ap].set_state(&CpuState::X86_64(state)).unwrap();
    vm.coordinator.online[ap] = true;
    vm.coordinator.cursor = ap;
}

#[test]
#[ignore = "requires Intel macOS and com.apple.security.hypervisor entitlement"]
fn legacy_pae_requires_private_paging_bank_and_resumes_from_it() {
    const PDPT: GuestAddress = GuestAddress(0x1000);
    const CACHED: [(Vmcs, u64); 4] = [
        (Vmcs::VMCS_GUEST_PDPTE0, 0x2001),
        (Vmcs::VMCS_GUEST_PDPTE1, 0x3001),
        (Vmcs::VMCS_GUEST_PDPTE2, 0x4001),
        (Vmcs::VMCS_GUEST_PDPTE3, 0x5001),
    ];
    let run_output = |vm: &mut Vmm, expected, phase| {
        let cpu = &mut vm.vcpus[0];
        let exit = (0..100)
            .find_map(|_| {
                cpu.run_host_slice(std::time::Duration::from_millis(10))
                    .unwrap_or_else(|error| panic!("{phase}: {error}"))
            })
            .unwrap_or_else(|| panic!("{phase}: guest did not reach an exit"));
        assert!(
            matches!(&exit, VcpuExit::IoOut { port: 0xe9, data } if data.as_slice() == [expected]),
            "{phase}: expected port byte {expected:#04x}, got {exit:?} at RIP {:#x}",
            cpu.current_pc(),
        );
        cpu.complete_io_out().unwrap();
    };
    let paths = Paths::new(1);
    let mut source = Vmm::new_resume(paths.config(1)).unwrap();
    let mut projected = source.take_snapshot(0).unwrap();
    let memory = source.guest_mem.memory();
    for (address, word) in [
        (0x2000, 0x83u64),               // Identity-map the first 2 MiB.
        (0x9008, 0x00cf_9b00_0000_ffff), // 32-bit code descriptor.
        (0x9010, 0x00cf_9300_0000_ffff), // Data descriptor.
        (0x9018, 0x0000_8b00_8000_0067), // Busy 32-bit TSS descriptor.
    ] {
        memory
            .write_slice(&word.to_le_bytes(), GuestAddress(address))
            .unwrap();
    }
    for (index, (_, value)) in CACHED.iter().enumerate() {
        memory
            .write_slice(
                &value.to_le_bytes(),
                GuestAddress(PDPT.0 + index as u64 * 8),
            )
            .unwrap();
    }
    // Enable paging in the guest so the processor loads PDPTEs from RAM.
    // Use two port writes to distinguish the source and resumed frontiers.
    memory
        .write_slice(
            &[
                0xb8, 0x33, 0x00, 0x01, 0x80, // MOV EAX, 0x80010033
                0x0f, 0x22, 0xc0, // MOV CR0, EAX
                0xb0, 0x5a, 0xe6, 0xe9, // MOV AL, 0x5a; OUT 0xe9, AL
                0xb0, 0xa5, 0xe6, 0xe9, // MOV AL, 0xa5; OUT 0xe9, AL
                0xf4,
            ],
            GuestAddress(CODE),
        )
        .unwrap();

    let mut state = protected_long_mode_state();
    state.regs.rip = CODE;
    state.sregs.cs.l = false;
    state.sregs.cs.db = true;
    state.sregs.gdt.limit = 31;
    state.sregs.efer = 0;
    state.sregs.cr0 &= !(1 << 31);
    source.vcpus[0].set_state(&CpuState::X86_64(state)).unwrap();
    run_output(&mut source, 0x5a, "source PAE entry with valid RAM PDPT");
    let state = source.vcpus[0].get_state().unwrap();
    assert_eq!(state.pc(), CODE + 12);

    source
        .guest_mem
        .memory()
        .write_slice(&[0; 32], PDPT)
        .unwrap();
    let error = source
        .take_snapshot(0)
        .err()
        .expect("legacy PAE capture succeeded");
    assert!(error.to_string().contains("cached PDPTRs"), "{error}");

    // Use a foreign projected producer to exercise the target-side check.
    // Successful RAM publication would erase the program.
    projected.config.backend = BackendKind::Emulator;
    projected.cpu_state = state;
    let error = source.restore_snapshot(&projected).unwrap_err();
    assert!(error.to_string().contains("cached PDPTRs"), "{error}");
    assert_eq!(
        source
            .guest_mem
            .memory()
            .read_obj::<u8>(GuestAddress(CODE))
            .unwrap(),
        0xb8
    );

    // Confirm the source still owns the actual cached entries after removing
    // the RAM table, before checking the fresh owner's admission and entry.
    let bundle = source.take_snapshot_bundle(0).unwrap();
    let captured = bundle.backend_contexts().unwrap();
    let bank = Context::decode(&captured.entries()[0].as_ref().unwrap().data).unwrap();
    for (field, value) in CACHED {
        assert_eq!(bank.vmcs(field as u32).unwrap(), value, "source {field:?}");
    }

    let checkpoint = paths.0.join("legacy-pae.rxc");
    bundle.save(&checkpoint).unwrap();
    drop(bundle);
    drop(source);
    std::fs::remove_file(paths.0.join("kernel")).unwrap();
    let loaded = SnapshotBundle::load(&checkpoint).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    let mut pdpt = [0xff; 32];
    target
        .guest_mem
        .memory()
        .read_slice(&mut pdpt, PDPT)
        .unwrap();
    assert_eq!(pdpt, [0; 32]);
    {
        let boundary = target.vm.checkpoint_boundary().unwrap();
        let (_, record) = target.vcpus[0]
            .capture_checkpoint_record(&boundary, None)
            .unwrap();
        let restored = Context::decode(&record.unwrap().data).unwrap();
        for (field, value) in CACHED {
            assert_eq!(restored.vmcs(field as u32).unwrap(), value);
        }
    }
    run_output(&mut target, 0xa5, "restored PAE entry with zeroed RAM PDPT");
    assert_eq!(target.vcpus[0].get_state().unwrap().pc(), CODE + 16);
}

fn hold_pending(vm: &mut Vmm, ap: usize, read: bool) -> Packet {
    let turn = (0..32)
        .filter_map(|_| vm.execute_turn().unwrap())
        .find(|turn| turn.cpu_index == ap)
        .expect("native AP did not reach its MMIO instruction");
    let expected = if read {
        Packet::Read {
            address: MMIO,
            size: 8,
        }
    } else {
        Packet::Write {
            address: MMIO,
            data: HIGH.to_le_bytes().to_vec(),
        }
    };
    assert_eq!(Packet::from_exit(&turn.exit).unwrap(), expected);
    assert!(vm.vcpus[ap].io_completion_result().is_err());
    expected
}

fn stopped_context(vm: &Vmm, index: usize) -> Context {
    // The public state accessor is fenced until the device request completes.
    let boundary = vm.vm.checkpoint_boundary().unwrap();
    let (public, record) = vm.vcpus[index]
        .capture_checkpoint_record(&boundary, None)
        .unwrap();
    let record = record.unwrap();
    assert_eq!(record.kind, HVF_INTEL_CONTEXT);
    let context = Context::decode(&record.data).unwrap();
    assert_eq!(context.id as usize, index);
    assert_eq!(context.public.regs.rip, public.state.pc());
    context
}

fn assert_pending_lane(context: &Context, expected: &Packet, read: bool) {
    assert_eq!(context.public.regs.rip, CODE);
    if read {
        assert_eq!(context.request.as_ref(), Some(expected));
        assert!(context.output.is_none());
    } else {
        assert!(context.request.is_none());
        assert_eq!(
            context
                .output
                .as_ref()
                .map(|(packet, length)| (packet, *length)),
            Some((expected, LANE_INSN_LENGTH))
        );
    }
}

fn run_pending(vm: &mut Vmm, accesses: &Arc<Mutex<Vec<Access>>>, ap: usize, read: bool) {
    assert!(vm.vcpus[ap].io_completion_result().is_err());
    assert!(accesses.lock().unwrap().is_empty());
    vm.run().unwrap();

    let expected = if read {
        Access::Read(MMIO, 8)
    } else {
        Access::Write(MMIO, HIGH.to_le_bytes().to_vec())
    };
    assert_eq!(*accesses.lock().unwrap(), [expected]);
    let CpuState::X86_64(after) = vm.vcpus[ap].get_state().unwrap() else {
        panic!("expected x86 vCPU")
    };
    assert_eq!(after.regs.rip, CODE + 16);
    assert_eq!(after.regs.xmm[15], [if read { REPLY } else { LOW }, HIGH]);
    vm.vcpus[ap].io_completion_result().unwrap();
    assert!(vm.vcpus[ap].complete_io_out().is_err());
}

#[test]
#[ignore = "requires Intel macOS and com.apple.security.hypervisor entitlement"]
fn pending_xmm_lane_on_secondary_survives_file_and_dispatches_once() {
    for (count, read) in [(2, true), (4, false)] {
        let ap = usize::from(count - 1);
        let paths = Paths::new(count);
        let accesses = Arc::new(Mutex::new(Vec::new()));
        let mut source = Vmm::new_resume(paths.config(count)).unwrap();
        attach(&mut source, &accesses);
        install_program(&mut source, ap, read);
        let legacy = source.take_snapshot(0).unwrap();
        let expected = hold_pending(&mut source, ap, read);
        assert!(accesses.lock().unwrap().is_empty());
        let error = source
            .take_snapshot(0)
            .err()
            .expect("legacy snapshot discarded a pending MMIO transaction on the AP");
        assert!(
            error.to_string().contains(&format!("Intel HVF vCPU {ap}")),
            "{error}"
        );
        assert!(source.vcpus[ap].io_completion_result().is_err());
        assert!(accesses.lock().unwrap().is_empty());

        // Replace the stopped instruction with UD2. A target that discards its
        // pending transaction cannot reproduce the transfer by re-executing it.
        source
            .guest_mem
            .memory()
            .write_slice(&[0x0f, 0x0b], GuestAddress(CODE))
            .unwrap();
        let checkpoint = paths.0.join("pending.rxc");
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&checkpoint)
            .unwrap();
        if let Some(out) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
            let out = PathBuf::from(out);
            std::fs::create_dir_all(&out).unwrap();
            std::fs::copy(
                &checkpoint,
                out.join(format!("pending-xmm-ap{ap}-{count}cpus.rxc")),
            )
            .unwrap();
        }
        let source_coordinator = source.coordinator.clone();
        drop(source);

        let loaded = SnapshotBundle::load(&checkpoint).unwrap();
        assert_eq!(loaded.cpus().unwrap().entries()[ap].state.pc(), CODE);
        let private = loaded.backend_contexts().unwrap().entries();
        assert_eq!(private.len(), usize::from(count));
        assert!(
            private
                .iter()
                .all(|cpu| cpu.as_ref().unwrap().kind == HVF_INTEL_CONTEXT)
        );
        assert!(loaded.execution().unwrap().online()[ap]);

        // Give the existing VM different live work. At four CPUs it is also
        // on a different AP, which the loaded coordinator must take offline.
        let old_ap = if count == 4 { 2 } else { ap };
        let marker = GuestAddress(CODE + 0x200);
        {
            let mut warm = Vmm::new_resume(paths.config(count)).unwrap();
            attach(&mut warm, &accesses);
            install_program(&mut warm, old_ap, !read);
            warm.guest_mem.memory().write_obj(0x5au8, marker).unwrap();
            let old_request = hold_pending(&mut warm, old_ap, !read);
            let old_frontier = warm.coordinator.clone();
            let before = stopped_context(&warm, old_ap);
            assert_pending_lane(&before, &old_request, !read);
            assert_ne!(old_request, expected);

            let check_unchanged = |vm: &Vmm| {
                let after = stopped_context(vm, old_ap);
                assert_eq!(after.request, before.request);
                assert_eq!(after.output, before.output);
                assert_eq!(
                    crate::codec::serialize(&after.public).unwrap(),
                    crate::codec::serialize(&before.public).unwrap(),
                );
                assert_eq!(vm.coordinator, old_frontier);
                assert_eq!(vm.guest_mem.memory().read_obj::<u8>(marker).unwrap(), 0x5a);
                assert!(accesses.lock().unwrap().is_empty());
            };
            let err = warm.restore_snapshot(&legacy).unwrap_err();
            assert!(err.to_string().contains("complete backend record"), "{err}");
            check_unchanged(&warm);
            let err = warm
                .restore_snapshot_bundle(&SnapshotBundle::new(legacy))
                .unwrap_err();
            assert!(err.to_string().contains("complete CPU set"), "{err}");
            check_unchanged(&warm);

            warm.restore_snapshot_bundle(&loaded).unwrap();
            assert_eq!(warm.coordinator, source_coordinator);
            assert_eq!(warm.guest_mem.memory().read_obj::<u8>(marker).unwrap(), 0);
            assert_eq!(
                warm.guest_mem
                    .memory()
                    .read_obj::<u16>(GuestAddress(CODE))
                    .unwrap(),
                u16::from_le_bytes([0x0f, 0x0b]),
            );
            if old_ap != ap {
                assert!(!warm.coordinator.online[old_ap]);
                let offline = stopped_context(&warm, old_ap);
                assert!(offline.request.is_none());
                assert!(offline.output.is_none());
            }
            let resumed = stopped_context(&warm, ap);
            assert_pending_lane(&resumed, &expected, read);
            run_pending(&mut warm, &accesses, ap, read);

            println!(
                "native warm pending XMM passed count={count} ap={ap} replaced_ap={old_ap} read={read}"
            );
        }

        // The archive remains independently usable by a fresh VM without its
        // original loader input or any device calls from the warm target.
        std::fs::remove_file(paths.0.join("kernel")).unwrap();
        let accesses = Arc::new(Mutex::new(Vec::new()));
        let config = VmConfig::from_checkpoint_bundle(
            &loaded,
            CliConfig {
                hvf_parallel_vcpus: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
        attach(&mut target, &accesses);
        let resumed = stopped_context(&target, ap);
        assert_pending_lane(&resumed, &expected, read);
        run_pending(&mut target, &accesses, ap, read);

        println!("native pending XMM passed count={count} ap={ap} read={read}");
    }
}

#[cfg(feature = "debug")]
#[test]
#[ignore = "requires Intel macOS and com.apple.security.hypervisor entitlement"]
fn gdb_resume_keeps_native_mmio_pending_after_a_saved_triple_fault() {
    use super::gdb_lifecycle_tests::{connect, packet, unused_address};
    use crate::debug::gdb::{GdbCommand, protocol::send_packet};
    use std::time::Duration;

    let paths = Paths::new(2);
    let accesses = Arc::new(Mutex::new(Vec::new()));
    let checkpoint = paths.0.join("gdb-terminal.rxc");
    let (pending, retired) = {
        let mut source = Vmm::new_resume(paths.config(2)).unwrap();
        attach(&mut source, &accesses);
        install_program(&mut source, 1, true);
        let pending = hold_pending(&mut source, 1, true);
        // The bootstrap CPU has an empty IDT. UD2 causes a native VMX
        // triple-fault exit while the AP still owns its unserviced read.
        source
            .guest_mem
            .memory()
            .write_slice(&[0x0f, 0x0b], GuestAddress(CODE + 0x100))
            .unwrap();
        // Looking for the AP exit may have let the BSP execute its HLT.
        source.vcpus[0]
            .set_state(&CpuState::X86_64(protected_long_mode_state()))
            .unwrap();
        source.vcpus[0].wake();
        let terminal = (0..32).find_map(|_| {
            source.vcpus[0]
                .run_host_slice(Duration::from_millis(10))
                .unwrap()
        });
        assert!(matches!(terminal, Some(VcpuExit::Shutdown)), "{terminal:?}");
        assert!(stopped_context(&source, 0).shutdown);
        assert_pending_lane(&stopped_context(&source, 1), &pending, true);
        assert!(accesses.lock().unwrap().is_empty());
        let retired = source.coordinator.retired;
        source
            .take_snapshot_bundle(retired)
            .unwrap()
            .save(&checkpoint)
            .unwrap();
        (pending, retired)
    };
    let saved = SnapshotBundle::load(&checkpoint).unwrap();
    let address = unused_address();
    let mut config = paths.config(2);
    config.gdb_port = Some(address.port());
    config.wait_gdb = true;
    let mut target = Vmm::new_resume(config).unwrap();
    attach(&mut target, &accesses);
    let mut stream = connect(address);
    let receive = |vm: &Vmm| {
        vm.gdb_channels
            .as_ref()
            .unwrap()
            .cmd_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
    };
    let attach = receive(&target);
    assert!(matches!(attach, GdbCommand::Attach));
    target.handle_gdb_command(attach).unwrap();
    send_packet(&mut stream, "Hg2").unwrap();
    target.handle_gdb_command(receive(&target)).unwrap();
    assert_eq!(packet(&mut stream), "OK");

    target.restore_snapshot_bundle(&saved).unwrap();
    assert!(target.gdb_stopped);
    assert_eq!(target.coordinator.online, [true, true]);
    assert!(stopped_context(&target, 0).shutdown);
    assert_pending_lane(&stopped_context(&target, 1), &pending, true);
    send_packet(&mut stream, "qC").unwrap();
    target.handle_gdb_command(receive(&target)).unwrap();
    assert_eq!(packet(&mut stream), "QC2");

    // The AP has a valid power-off program after its pending load. If the
    // terminal BSP is ignored, the VM can still exit, but the device and
    // retirement assertions below will detect the extra work.
    send_packet(&mut stream, "vCont;c:2").unwrap();
    target.run().unwrap();
    assert_eq!(packet(&mut stream), "W00");
    assert!(accesses.lock().unwrap().is_empty());
    assert_pending_lane(&stopped_context(&target, 1), &pending, true);
    assert_eq!(target.coordinator.retired, retired);

    if let Some(out) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
        let out = PathBuf::from(out);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::copy(&checkpoint, out.join("gdb-terminal-2cpus.rxc")).unwrap();
        target
            .take_snapshot_bundle(retired)
            .unwrap()
            .save(out.join("gdb-terminal-after-resume-2cpus.rxc"))
            .unwrap();
    }
    println!("native GDB terminal precedence passed count=2 ap=1");
}

#[cfg(feature = "debug")]
#[test]
#[ignore = "requires Intel macOS and com.apple.security.hypervisor entitlement"]
fn saved_init_waits_for_the_native_mmio_owner() {
    use crate::debug::gdb::threads::parse_resume;

    let paths = Paths::new(2);
    let accesses = Arc::new(Mutex::new(Vec::new()));
    let checkpoint = paths.0.join("queued-init.rxc");
    let expected = {
        let mut source = Vmm::new_resume(paths.config(2)).unwrap();
        attach(&mut source, &accesses);
        install_program(&mut source, 1, true);
        let expected = hold_pending(&mut source, 1, true);

        // The BSP powers off the PC after the restored coordinator drains
        // the AP's transaction and applies the queued INIT.
        source
            .guest_mem
            .memory()
            .write_slice(
                &[0x66, 0xba, 4, 6, 0x66, 0xb8, 0, 0x20, 0x66, 0xef, 0xf4],
                GuestAddress(CODE + 0x100),
            )
            .unwrap();
        source.vcpus[0]
            .set_state(&CpuState::X86_64(protected_long_mode_state()))
            .unwrap();
        source.vcpus[0].wake();
        assert_eq!(
            source
                .resume_debugger(&parse_resume("c:1").unwrap())
                .unwrap(),
            Some(true)
        );
        assert!(!source.debugger_allows_cpu(1));
        source.local_apics[0]
            .lock()
            .unwrap()
            .write_register(0x300, 0x000c_4500); // INIT, excluding the sender.

        for _ in 0..2 {
            source.route_interprocessor_requests().unwrap();
            assert_eq!(source.coordinator.online, [true, true]);
            let delivery = source.coordinator.pending_ipi.as_ref().unwrap();
            assert_eq!(delivery.source, 0);
            assert_eq!(delivery.remaining.as_ref().unwrap(), &[1]);
            assert_pending_lane(&stopped_context(&source, 1), &expected, true);
        }
        assert!(accesses.lock().unwrap().is_empty());
        source
            .take_snapshot_bundle(source.coordinator.retired)
            .unwrap()
            .save(&checkpoint)
            .unwrap();
        expected
    };

    std::fs::remove_file(paths.0.join("kernel")).unwrap();
    let saved = SnapshotBundle::load(&checkpoint).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &saved).unwrap();
    attach(&mut target, &accesses);
    assert_eq!(target.coordinator.online, [true, true]);
    let delivery = target.coordinator.pending_ipi.as_ref().unwrap();
    assert_eq!(delivery.remaining.as_ref().unwrap(), &[1]);
    assert_pending_lane(&stopped_context(&target, 1), &expected, true);

    target.run().unwrap();
    assert_eq!(*accesses.lock().unwrap(), [Access::Read(MMIO, 8)]);
    assert_eq!(target.coordinator.online, [true, false]);
    assert!(target.coordinator.pending_ipi.is_none());
    let ap = stopped_context(&target, 1);
    assert!(ap.request.is_none());
    assert!(ap.output.is_none());
    assert_eq!(ap.public.regs.rip, 0xfff0);
    // INIT preserves the SSE image, including the lane just written by the
    // MMIO completion. A reset before completion would leave LOW in that lane.
    assert_eq!(ap.public.regs.xmm[15], [REPLY, HIGH]);

    if let Some(out) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
        let out = PathBuf::from(out);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::copy(&checkpoint, out.join("queued-init-2cpus.rxc")).unwrap();
        target
            .take_snapshot_bundle(target.coordinator.retired)
            .unwrap()
            .save(out.join("queued-init-after-resume-2cpus.rxc"))
            .unwrap();
    }
    println!("native queued INIT followed pending MMIO count=2 ap=1");
}
