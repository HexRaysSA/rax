//! Exercise the actual VMM run loop with an xAPIC INIT/SIPI guest.
#[cfg(feature = "debug")]
use super::coordinator::ExecutionTurn;
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::timing::ClockMode;
use crate::vm::vcpu::Segment;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::GuestAddress;

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) const BSP: u64 = 0x8000;
const AP: u64 = 0x9000;
const FLAGS: u64 = 0x7000;

pub(super) struct Fixture {
    pub(super) kernel: PathBuf,
    pub(super) vm: Vmm,
}

impl Fixture {
    pub(super) fn new(count: u8) -> Self {
        Self::with_memory(count, 65536)
    }

    pub(super) fn with_memory(count: u8, bytes: u64) -> Self {
        Self::with_devices(count, bytes, false, ClockMode::Wall)
    }

    pub(super) fn with_pci(count: u8) -> Self {
        Self::with_devices(count, 65536, true, ClockMode::Wall)
    }

    pub(super) fn with_retired_clock() -> Self {
        Self::with_retired_cpus(1)
    }

    pub(super) fn with_retired_cpus(count: u8) -> Self {
        Self::with_devices(count, 128 << 20, false, ClockMode::Retired)
    }

    fn with_devices(count: u8, bytes: u64, pci_devices: bool, clock_mode: ClockMode) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-coordinator-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&kernel, [0; 64]).unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                vcpus: Some(count),
                kernel: Some(kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(bytes);
        config.pci_devices = pci_devices;
        let mut vm =
            Vmm::build_with_contexts(config, ConstructionMode::RestoreTarget, None, clock_mode)
                .unwrap();
        let mut state = vm.vcpus[0].get_state().unwrap();
        let CpuState::X86_64(s) = &mut state else {
            unreachable!()
        };
        s.regs.rip = BSP;
        s.regs.rsp = 0xe000;
        s.regs.rflags = 2;
        s.sregs.cr0 = 0x11;
        s.sregs.cr3 = 0;
        s.sregs.cr4 = 0;
        s.sregs.efer = 0;
        s.sregs.cs = Segment {
            selector: 8,
            limit: u32::MAX,
            type_: 11,
            present: true,
            s: true,
            db: true,
            g: true,
            ..Default::default()
        };
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
        s.sregs.ds = data.clone();
        s.sregs.es = data.clone();
        s.sregs.ss = data;
        vm.vcpus[0].set_state(&state).unwrap();
        let fixture = Self { kernel, vm };
        fixture.write(0x7200, &[23, 0, 0, 0x73, 0, 0]);
        let gdt: Vec<u8> = [0u64, 0x00cf_9a00_0000_ffff, 0x00cf_9200_0000_ffff]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        fixture.write(0x7300, &gdt);
        fixture
    }

    pub(super) fn write(&self, address: u64, bytes: &[u8]) {
        self.vm
            .guest_mem
            .memory()
            .write_slice(bytes, GuestAddress(address))
            .unwrap();
    }

    fn flag(&self, index: usize) -> u32 {
        let mut value = [0; 4];
        self.vm
            .guest_mem
            .memory()
            .read_slice(&mut value, GuestAddress(FLAGS + 4 * index as u64))
            .unwrap();
        u32::from_le_bytes(value)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_file(&self.kernel).unwrap();
        }
    }
}

fn store32(code: &mut Vec<u8>, address: u32, value: u32) {
    code.extend_from_slice(&[0xc7, 0x05]);
    code.extend_from_slice(&address.to_le_bytes());
    code.extend_from_slice(&value.to_le_bytes());
}

#[test]
fn stopped_checkpoint_io_latches_only_an_accepted_s5() {
    use crate::vm::vcpu::CheckpointIoReply;

    let fixture = Fixture::new(2);
    let write = |value: u16| {
        fixture
            .vm
            .checkpoint_io_service(
                0,
                VcpuExit::IoOut {
                    port: 0x604,
                    data: value.to_le_bytes().to_vec(),
                },
            )
            .unwrap()
    };
    assert!(matches!(write(0), CheckpointIoReply::Output));
    assert!(!fixture.vm.pc_powered_off());
    assert!(matches!(write(0x2000), CheckpointIoReply::PowerOff));
    assert!(fixture.vm.pc_powered_off());
}

#[test]
fn pc_s5_remains_terminal_after_detached_checkpoint_restore() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut fixture = Fixture::with_retired_cpus(2);
    let s5 = [0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef];
    let mut bsp = s5.to_vec();
    store32(&mut bsp, FLAGS as u32, 1);
    bsp.extend_from_slice(&s5); // Bound the predecessor's unexpected reentry.
    fixture.write(BSP, &bsp);
    let mut ap = Vec::new();
    store32(&mut ap, FLAGS as u32 + 4, 1);
    ap.push(0xf4);
    fixture.write(AP, &ap);
    let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
        unreachable!();
    };
    state.regs.rip = AP;
    fixture.vm.vcpus[1]
        .set_state(&CpuState::X86_64(state))
        .unwrap();
    fixture.vm.coordinator.online[1] = true;
    fixture.vm.run().unwrap();
    assert_eq!((fixture.flag(0), fixture.flag(1)), (0, 0));
    let retired = fixture.vm.coordinator.retired;
    assert_eq!(fixture.vm.vcpus[0].current_pc(), BSP + s5.len() as u64);
    let path = fixture.kernel.with_extension("rxc");
    fixture
        .vm
        .take_snapshot_bundle(retired)
        .unwrap()
        .save(&path)
        .unwrap();
    drop(fixture);

    let bundle = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
    target.run().unwrap();
    target.run().unwrap();
    let mut flags = [0; 8];
    target
        .guest_mem
        .memory()
        .read_slice(&mut flags, GuestAddress(FLAGS))
        .unwrap();
    assert_eq!(flags, [0; 8]);
    assert_eq!(target.coordinator.retired, retired);
    assert_eq!(target.vcpus[0].current_pc(), BSP + s5.len() as u64);
    assert_eq!(target.vcpus[1].current_pc(), AP);
    assert!(matches!(
        target.take_snapshot(retired),
        Err(Error::InvalidConfig(message)) if message.contains("PC S5")
    ));
}

#[test]
fn detached_x86_resume_dispatches_issued_s5_without_fetching_an_instruction() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut source = Fixture::with_retired_clock();
    let s5 = [0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef];
    let mut code = s5.to_vec();
    store32(&mut code, FLAGS as u32, 1);
    code.extend_from_slice(&s5); // Bound execution if the saved write is lost.
    source.write(BSP, &code);
    let turn = source.vm.execute_turn().unwrap().unwrap();
    assert!(matches!(turn.exit, VcpuExit::IoOut { port: 0x604, data } if data == [0, 0x20]));
    assert!(!source.vm.pc_powered_off());
    let retired = source.vm.coordinator.retired;
    let path = source.kernel.with_extension("rxc");
    source
        .vm
        .take_snapshot_bundle(retired)
        .unwrap()
        .save(&path)
        .unwrap();
    drop(source);

    let bundle = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
    assert!(!target.pc_powered_off());
    target.run().unwrap();
    target.run().unwrap();
    assert!(target.pc_powered_off());
    let marker: u32 = target
        .guest_mem
        .memory()
        .read_obj(GuestAddress(FLAGS))
        .unwrap();
    assert_eq!(marker, 0);
    assert_eq!(target.vcpus[0].current_pc(), BSP + s5.len() as u64);
    assert_eq!(target.coordinator.retired, retired);
}

fn bsp_program() -> Vec<u8> {
    let mut code = Vec::new();
    store32(&mut code, FLAGS as u32, 1);
    // INIT, level assert, all excluding self; then SIPI vector 9.
    store32(&mut code, (LAPIC_BASE + 0x300) as u32, 0x000c_4500);
    store32(&mut code, (LAPIC_BASE + 0x300) as u32, 0x000c_0609);
    // Bound the guest itself: a CPU0-only VMM reaches shutdown and fails the
    // memory assertions instead of hanging the host test indefinitely.
    code.extend_from_slice(&[0xb9, 0x00, 0x80, 0x00, 0x00]);
    code.extend_from_slice(&[0x49, 0x75, 0xfd]);
    code.extend_from_slice(&[0x66, 0xba, 0x04, 0x06]); // DX = ACPI control port
    code.extend_from_slice(&[0x66, 0xb8, 0x00, 0x20]); // AX = S5 power-off
    code.extend_from_slice(&[0x66, 0xef]);
    code
}

fn ap_program() -> Vec<u8> {
    // Frozen LLVM23/QEMU witness: LGDT, CR0.PE, far jump, flat data
    // segments, then read this AP's xAPIC ID and publish its RAM flag.
    vec![
        0x0f, 0x01, 0x16, 0x00, 0x72, 0x0f, 0x20, 0xc0, 0x66, 0x83, 0xc8, 0x01, 0x0f, 0x22, 0xc0,
        0x66, 0xea, 0x17, 0x90, 0x00, 0x00, 0x08, 0x00, 0x66, 0xb8, 0x10, 0x00, 0x8e, 0xd8, 0x8e,
        0xc0, 0x8e, 0xd0, 0xa1, 0x20, 0x00, 0xe0, 0xfe, 0xc1, 0xe8, 0x18, 0xba, 0x00, 0x70, 0x00,
        0x00, 0xc7, 0x04, 0x82, 0x01, 0x00, 0x00, 0x00, 0xf4, 0xeb, 0xfd,
    ]
}

fn run_startup(count: u8) {
    let mut fixture = Fixture::new(count);
    fixture.write(BSP, &bsp_program());
    fixture.write(AP, &ap_program());
    fixture.vm.run().unwrap();
    for index in 0..usize::from(count) {
        assert_eq!(fixture.flag(index), 1, "CPU {index} of {count} executed");
    }
    for index in usize::from(count)..4 {
        assert_eq!(fixture.flag(index), 0, "no phantom CPU {index}");
    }
}

#[test]
fn actual_vmm_run_executes_one_cpu() {
    run_startup(1);
}

#[test]
fn actual_vmm_run_executes_two_cpus_after_init_sipi() {
    run_startup(2);
}

#[test]
fn actual_vmm_run_executes_four_cpus_after_init_sipi() {
    run_startup(4);
}

#[test]
fn actual_saved_two_and_four_cpu_guests_resume_the_same_interleaving() {
    for count in [2, 4] {
        let mut fixture = Fixture::with_memory(count, 128 * 1024 * 1024);
        fixture.write(BSP, &bsp_program());
        let mut program = ap_program();
        // Replace the final store/halt with a counter loop. APs must execute
        // after resume; retaining an old flag alone cannot satisfy this test.
        program.truncate(46);
        program.extend_from_slice(&[0xff, 0x04, 0x82, 0xeb, 0xfb]);
        fixture.write(AP, &program);
        for _ in 0..usize::from(count) + 1 {
            fixture.vm.execute_turn().unwrap();
        }
        let before: Vec<_> = (1..usize::from(count))
            .map(|index| fixture.flag(index))
            .collect();
        assert!(before.iter().all(|value| *value > 0));
        let saved = fixture.vm.take_snapshot_bundle(53).unwrap();
        assert!(
            saved
                .execution()
                .unwrap()
                .online()
                .iter()
                .all(|online| *online)
        );
        assert_ne!(saved.execution().unwrap().cursor(), 0);
        let path = fixture.kernel.with_extension("rxc");
        saved.save(&path).unwrap();
        let saved = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
        let mut resumed = Vmm::new_resume_bundle(config, &saved).unwrap();
        fixture.vm.run().unwrap();
        resumed.run().unwrap();
        assert_eq!(
            fixture.vm.guest_mem.try_read_all().unwrap(),
            resumed.guest_mem.try_read_all().unwrap(),
            "complete RAM after actual run-loop resume with {count} CPUs"
        );
        assert_eq!(fixture.vm.coordinator, resumed.coordinator);
        for (index, prior) in (1..usize::from(count)).zip(before) {
            assert!(
                fixture.flag(index) > prior,
                "AP {index} continued after checkpoint"
            );
        }
        for (left, right) in fixture.vm.vcpus.iter().zip(&resumed.vcpus) {
            assert_eq!(
                crate::codec::serialize(&(left.get_state().unwrap(), left.get_emulator_state()))
                    .unwrap(),
                crate::codec::serialize(&(right.get_state().unwrap(), right.get_emulator_state()))
                    .unwrap()
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn coordinated_checkpoint_cannot_omit_an_aps_pending_input() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut source = Fixture::with_memory(2, 128 << 20);
    source.write(BSP, &[0xf4]);
    // IN AL,0xe9; OUT 0xe9,AL; HLT, in the AP's SIPI mode.
    source.write(AP, &[0xe4, 0xe9, 0xe6, 0xe9, 0xf4]);
    {
        let mut bsp = source.vm.local_apics[0].lock().unwrap();
        bsp.write_register(0x310, 1 << 24);
        bsp.write_register(0x300, 0x4500);
        bsp.write_register(0x300, 0x0609);
    }
    let bsp = source.vm.execute_turn().unwrap().unwrap();
    assert_eq!(bsp.cpu_index, 0);
    assert!(matches!(bsp.exit, VcpuExit::Hlt));
    let ap = source.vm.execute_turn().unwrap().unwrap();
    assert_eq!(ap.cpu_index, 1);
    assert!(matches!(
        ap.exit,
        VcpuExit::IoIn {
            port: 0xe9,
            size: 1
        }
    ));

    let full = source.vm.take_snapshot_bundle(2).unwrap();
    assert_eq!(full.execution().unwrap().online(), &[true, true]);
    let path = source.kernel.with_extension("rxc");
    full.save(&path).unwrap();
    let mut missing = SnapshotBundle::load(&path).unwrap();
    assert!(missing.take_backend_contexts().is_some());
    let valid_file = std::fs::read(&path).unwrap();
    let error = missing.save(&path).unwrap_err();
    assert!(
        error.to_string().contains("private backend contexts"),
        "{error}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), valid_file);
    std::fs::remove_file(path).unwrap();

    let config = VmConfig::from_checkpoint_bundle(&full, CliConfig::default()).unwrap();
    let error = match Vmm::new_resume_bundle(config, &missing) {
        Ok(mut resumed) => {
            let ap = &mut resumed.vcpus[1];
            ap.complete_io_in(&[0x5a]);
            panic!(
                "restored an AP without its pending input: {:?}",
                ap.step_insn().unwrap()
            );
        }
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("private backend contexts"),
        "{error}"
    );

    let mut target = Fixture::with_memory(2, 128 << 20);
    target.write(FLAGS + 4, &0x5678u32.to_le_bytes());
    let online = target.vm.coordinator.online.clone();
    let error = target.vm.restore_snapshot_bundle(&missing).unwrap_err();
    assert!(
        error.to_string().contains("private backend contexts"),
        "{error}"
    );
    assert_eq!(target.flag(1), 0x5678);
    assert_eq!(target.vm.coordinator.online, online);

    let config = VmConfig::from_checkpoint_bundle(&full, CliConfig::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &full).unwrap();
    let ap = &mut resumed.vcpus[1];
    ap.complete_io_in(&[0x5a]);
    assert!(matches!(
        ap.step_insn().unwrap(),
        Some(VcpuExit::IoOut { port: 0xe9, data }) if data == [0x5a]
    ));
}

#[test]
fn detached_x86_resume_services_pending_ap_input_before_entering_any_cpu() {
    use crate::vm::snapshot::SnapshotBundle;

    for repeat in [false, true] {
        let mut source = Fixture::with_memory(2, 128 << 20);
        source.write(BSP, &[0xf4]);
        let mut ap_code = vec![0xba, 0xf8, 0x03]; // MOV DX,0x3f8
        if repeat {
            ap_code.extend_from_slice(&[0xbf, 0x04, 0x70, 0xb9, 2, 0, 0xf3, 0x6c]);
        } else {
            ap_code.extend_from_slice(&[0xec, 0xa2, 0x04, 0x70]); // IN AL,DX; MOV [0x7004],AL
        }
        ap_code.extend_from_slice(&[0xba, 0x04, 0x06, 0xb8, 0x00, 0x20, 0xef]); // ACPI S5
        source.write(AP, &ap_code);
        {
            let mut bsp = source.vm.local_apics[0].lock().unwrap();
            bsp.write_register(0x310, 1 << 24);
            bsp.write_register(0x300, 0x4500);
            bsp.write_register(0x300, 0x0609);
        }
        let bsp = source.vm.execute_turn().unwrap().unwrap();
        assert_eq!(bsp.cpu_index, 0);
        assert!(matches!(bsp.exit, VcpuExit::Hlt));
        let ap = source.vm.execute_turn().unwrap().unwrap();
        assert_eq!(ap.cpu_index, 1);
        assert!(matches!(
            ap.exit,
            VcpuExit::IoIn {
                port: 0x3f8,
                size: 1
            }
        ));

        // The BSP is next in the saved schedule and reads the same UART.
        // INSB stores the byte as part of I/O completion, before the AP can
        // shut down the machine on the next turn.
        source.write(
            BSP,
            &[0x66, 0xba, 0xf8, 0x03, 0xbf, 0, 0x70, 0, 0, 0x6c, 0xf4],
        );
        let CpuState::X86_64(mut bsp) = source.vm.vcpus[0].get_state().unwrap() else {
            unreachable!();
        };
        bsp.regs.rip = BSP;
        source.vm.vcpus[0]
            .set_state(&CpuState::X86_64(bsp))
            .unwrap();
        source.vm.vcpus[0].wake();
        {
            let mut uart = source.vm.serial.lock().unwrap();
            IoDevice::write(&mut *uart, 0x3fa, 1); // Enable the RX FIFO.
            uart.queue_input(&[0x5a, 0xc3, 0x71, 0x99]);
        }

        let path = source.kernel.with_extension("rxc");
        let retired = source.vm.coordinator.retired;
        let bundle = source.vm.take_snapshot_bundle(retired).unwrap();
        assert_eq!(bundle.execution().unwrap().cursor(), 0);
        assert!(bundle.base().devices.serial.has_input());
        assert!(
            source
                .vm
                .take_snapshot(retired)
                .err()
                .expect("base-only capture lost the issued input")
                .to_string()
                .contains("pending software x86 port I/O")
        );
        assert!(
            source
                .vm
                .restore_snapshot(bundle.base())
                .unwrap_err()
                .to_string()
                .contains("pending software x86 port I/O")
        );
        bundle.save(&path).unwrap();
        drop(source);
        let bundle = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut resumed = Vmm::new_resume_bundle(config, &bundle).unwrap();
        resumed.run().unwrap();
        assert!(resumed.pc_powered_off());

        let mut results = [0; 8];
        resumed
            .guest_mem
            .memory()
            .read_slice(&mut results, GuestAddress(FLAGS))
            .unwrap();
        assert_eq!(
            results,
            [0xc3, 0, 0, 0, 0x5a, if repeat { 0x71 } else { 0 }, 0, 0]
        );
        let remaining = IoDevice::read(&mut *resumed.serial.lock().unwrap(), 0x3f8);
        assert_eq!(remaining, if repeat { 0x99 } else { 0x71 });
    }
}

#[test]
fn detached_x86_resume_dispatches_issued_ap_output_before_bsp_entry() {
    use crate::vm::snapshot::SnapshotBundle;

    const DATA: u64 = 0x7100;
    for repeat in [false, true] {
        let mut source = Fixture::with_memory(2, 128 << 20);
        // Park until the AP has issued its write, then read COM1 into FLAGS.
        source.write(
            BSP,
            &[
                0xf4, 0x66, 0xba, 0xf8, 0x03, 0xbf, 0, 0x70, 0, 0, 0x6c, 0xf4,
            ],
        );
        let mut ap_code = vec![0xba, 0xf8, 0x03]; // MOV DX,0x3f8
        if repeat {
            ap_code.extend_from_slice(&[0xbe, 0x00, 0x71, 0xb9, 2, 0, 0xf3, 0x6e]);
            source.write(DATA, &[0x5a, 0xc3]);
        } else {
            ap_code.extend_from_slice(&[0xb0, 0x5a, 0xee]); // MOV AL,0x5a; OUT DX,AL
        }
        ap_code.extend_from_slice(&[0xba, 0x04, 0x06, 0xb8, 0x00, 0x20, 0xef]); // ACPI S5
        source.write(AP, &ap_code);
        {
            let mut uart = source.vm.serial.lock().unwrap();
            IoDevice::write(&mut *uart, 0x3fa, 1); // Enable the RX FIFO.
            IoDevice::write(&mut *uart, 0x3fc, 0x10); // Enable loopback.
            let mut bsp = source.vm.local_apics[0].lock().unwrap();
            bsp.write_register(0x310, 1 << 24);
            bsp.write_register(0x300, 0x4500);
            bsp.write_register(0x300, 0x0609);
        }
        let bsp = source.vm.execute_turn().unwrap().unwrap();
        assert_eq!(bsp.cpu_index, 0);
        assert!(matches!(bsp.exit, VcpuExit::Hlt));
        let ap = source.vm.execute_turn().unwrap().unwrap();
        assert_eq!(ap.cpu_index, 1);
        assert!(matches!(ap.exit, VcpuExit::IoOut { port: 0x3f8, data } if data == [0x5a]));
        source.vm.vcpus[0].wake();
        if repeat {
            source.write(DATA, &[0xff]); // Distinguish delivery from rereading the operand.
        }

        let path = source.kernel.with_extension("rxc");
        let bundle = source
            .vm
            .take_snapshot_bundle(source.vm.coordinator.retired)
            .unwrap();
        assert_eq!(bundle.execution().unwrap().cursor(), 0);
        assert!(!bundle.base().devices.serial.has_input());
        assert!(matches!(
            source.vm.take_snapshot(source.vm.coordinator.retired),
            Err(Error::InvalidConfig(message)) if message.contains("pending software x86 port I/O")
        ));
        bundle.save(&path).unwrap();
        drop(source);

        let bundle = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        target.run().unwrap();
        assert!(target.pc_powered_off());
        let value: u8 = target
            .guest_mem
            .memory()
            .read_obj(GuestAddress(FLAGS))
            .unwrap();
        assert_eq!(value, 0x5a, "BSP must see the already-issued AP byte");
        let mut uart = target.serial.lock().unwrap();
        if repeat {
            assert_eq!(IoDevice::read(&mut *uart, 0x3f8), 0xc3);
        }
        assert!(!uart.has_input(), "AP output was delivered twice");
    }
}

#[test]
fn detached_x86_resume_keeps_a_consumed_uart_byte_until_the_store_succeeds() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut source = Fixture::with_memory(1, 128 << 20);
    source.write(
        BSP,
        &[
            0x66, 0xba, 0xf8, 0x03, 0xbf, 0, 0x70, 0, 0, 0x6c, // INSB to 0x7000
            0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef, // ACPI S5
        ],
    );
    const DESTINATION_PTE: u64 = 0x401c;
    for (address, entry) in [
        (0x3000, 0x4003u32),
        (DESTINATION_PTE, 0x7003),
        (0x4020, 0x8003),
    ] {
        source.write(address, &entry.to_le_bytes());
    }
    let mut sregs = source.vm.vcpus[0].get_sregs().unwrap();
    sregs.cr0 |= 1 << 31 | 1 << 16; // PG, WP
    sregs.cr3 = 0x3000;
    source.vm.vcpus[0].set_sregs(&sregs).unwrap();
    {
        let mut uart = source.vm.serial.lock().unwrap();
        IoDevice::write(&mut *uart, 0x3fa, 1);
        uart.queue_input(&[0xa5, 0x71]);
    }
    let turn = source.vm.execute_turn().unwrap().unwrap();
    assert!(matches!(
        turn.exit,
        VcpuExit::IoIn {
            port: 0x3f8,
            size: 1
        }
    ));
    source.write(DESTINATION_PTE, &0u32.to_le_bytes());

    let retired = source.vm.coordinator.retired;
    assert!(
        source.vm.run().is_err(),
        "failed destination store was ignored"
    );
    assert!(!source.vm.pc_powered_off());
    assert_eq!(source.vm.coordinator.retired, retired);
    assert!(source.vm.vcpus[0].step_insn().is_err());
    assert!(source.vm.take_snapshot(retired).is_err());
    let path = source.kernel.with_extension("rxc");
    source
        .vm
        .take_snapshot_bundle(retired)
        .unwrap()
        .save(&path)
        .unwrap();
    drop(source);

    let bundle = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &bundle).unwrap();
    assert!(
        resumed.run().is_err(),
        "the restored mapping still denies the store"
    );
    assert_eq!(resumed.coordinator.retired, retired);
    resumed
        .guest_mem
        .memory()
        .write_obj(0x7003u32, GuestAddress(DESTINATION_PTE))
        .unwrap();
    resumed.run().unwrap();
    assert!(resumed.pc_powered_off());
    assert_eq!(
        resumed
            .guest_mem
            .memory()
            .read_obj::<u8>(GuestAddress(FLAGS))
            .unwrap(),
        0xa5
    );
    let mut uart = resumed.serial.lock().unwrap();
    assert_eq!(IoDevice::read(&mut *uart, 0x3f8), 0x71);
    assert!(!uart.has_input(), "each UART byte should be read once");
}

#[test]
fn failing_pio_dispatch_retains_output_without_mutating_the_uart() {
    let mut source = Fixture::new(1);
    source.write(
        BSP,
        &[
            0x66, 0xba, 0xf8, 0x03, 0xb0, 0x5a, 0xee, // OUT DX,AL to COM1
            0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef, // ACPI S5
        ],
    );
    {
        let mut uart = source.vm.serial.lock().unwrap();
        IoDevice::write(&mut *uart, 0x3fa, 1);
        IoDevice::write(&mut *uart, 0x3fc, 0x10);
    }
    assert!(source.vm.serial_irq.is_some());
    let turn = source.vm.execute_turn().unwrap().unwrap();
    assert!(matches!(turn.exit, VcpuExit::IoOut { port: 0x3f8, data } if data == [0x5a]));
    let retired = source.vm.coordinator.retired;
    let pic = source.vm.pic.clone();
    assert!(
        std::panic::catch_unwind(|| {
            let _guard = pic.lock().unwrap();
            panic!("inject a PIC lock failure before UART dispatch");
        })
        .is_err()
    );
    assert!(
        source
            .vm
            .run()
            .unwrap_err()
            .to_string()
            .contains("serial interrupt controller lock poisoned")
    );
    assert!(!source.vm.serial.lock().unwrap().has_input());
    assert_eq!(source.vm.coordinator.retired, retired);

    pic.clear_poison();
    source.vm.run().unwrap();
    assert!(source.vm.pc_powered_off());
    assert!(
        source.vm.vcpus[0]
            .pending_software_port_io()
            .unwrap()
            .is_none()
    );
    let mut uart = source.vm.serial.lock().unwrap();
    assert_eq!(IoDevice::read(&mut *uart, 0x3f8), 0x5a);
    assert!(!uart.has_input());
}

#[test]
fn checkpoint_keeps_an_unprocessed_init_sipi_and_fixed_ipi_fifo() {
    let mut fixture = Fixture::with_memory(2, 128 * 1024 * 1024);
    {
        let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
        bsp.write_register(0x310, 1 << 24);
        for value in [0x4500, 0x0609, 0x41, 0x42] {
            bsp.write_register(0x300, value);
        }
    }
    let saved = fixture.vm.take_snapshot_bundle(53).unwrap();
    let state = saved.execution().unwrap();
    assert_eq!(state.local_apics[0].queued.len(), 4);
    let path = fixture.kernel.with_extension("rxc");
    saved.save(&path).unwrap();
    let saved = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
    assert_eq!(saved.execution().unwrap().local_apics[0].queued.len(), 4);
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &saved).unwrap();
    for vm in [&mut fixture.vm, &mut resumed] {
        vm.route_interprocessor_requests().unwrap();
        assert!(vm.coordinator.online[1]);
        let state = vm.vcpus[1].get_state().unwrap();
        let CpuState::X86_64(state) = state else {
            unreachable!()
        };
        assert_eq!(state.regs.rip, 0);
        assert_eq!(state.sregs.cs.base, AP);
        let apic = vm.local_apics[1].lock().unwrap();
        assert_eq!(apic.read_register(0x220), (1 << 1) | (1 << 2));
    }
    std::fs::remove_file(path).unwrap();
}

fn delay_and_shutdown(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0xb9, 0x00, 0x80, 0x00, 0x00, 0x49, 0x75, 0xfd]);
    code.extend_from_slice(&[0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef]);
}

#[test]
fn actual_vmm_fixed_ipi_wakes_halted_aps_and_eoi_clears_each_controller() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count);
        let mut bsp = bsp_program();
        bsp.truncate(bsp.len() - 10);
        store32(&mut bsp, (LAPIC_BASE + 0x300) as u32, 0x000c_0041);
        delay_and_shutdown(&mut bsp);
        fixture.write(BSP, &bsp);

        let mut ap = ap_program();
        ap.truncate(53); // Flat protected mode, AP ID read, initial flag stored.
        ap.extend_from_slice(&[
            0x89, 0xc4, 0xc1, 0xe4, 0x0a, // ESP = AP ID << 10
            0x81, 0xc4, 0x00, 0xb0, 0x00, 0x00, // distinct stack per AP
        ]);
        store32(&mut ap, (LAPIC_BASE + 0xf0) as u32, 0x1ff);
        ap.extend_from_slice(&[0xfb, 0xf4, 0xeb, 0xfd]); // STI; HLT; repeat HLT
        fixture.write(AP, &ap);
        // 32-bit interrupt gate 0x41 -> 0008:a000; all APs use this IDT.
        fixture.write(0x41 * 8, &[0x00, 0xa0, 0x08, 0x00, 0x00, 0x8e, 0x00, 0x00]);
        let mut handler = vec![0xff, 0x04, 0x82]; // flags[AP ID]++
        store32(&mut handler, (LAPIC_BASE + 0xb0) as u32, 0); // EOI
        handler.push(0xcf); // IRETD
        fixture.write(0xa000, &handler);
        fixture.vm.run().unwrap();
        assert_eq!(fixture.flag(0), 1);
        for index in 1..usize::from(count) {
            assert_eq!(
                fixture.flag(index),
                2,
                "AP {index} woke and handled its IPI"
            );
            let apic = fixture.vm.local_apics[index].lock().unwrap();
            assert_eq!(apic.read_register(0x120), 0, "ISR cleared by guest EOI");
            assert_eq!(apic.read_register(0x220), 0, "IRR transferred exactly once");
            drop(apic);
            assert!(fixture.vm.vcpus[index].get_emulator_state().unwrap().halted);
        }
    }
}

#[test]
fn ap_startup_wait_prevents_execution_before_any_sipi() {
    let mut fixture = Fixture::new(4);
    let mut bsp = Vec::new();
    store32(&mut bsp, FLAGS as u32, 1);
    delay_and_shutdown(&mut bsp);
    fixture.write(BSP, &bsp);
    fixture.vm.run().unwrap();
    for index in 1..4 {
        assert_eq!(fixture.vm.vcpus[index].instruction_count(), 0);
        assert_eq!(fixture.flag(index), 0);
        assert!(!fixture.vm.coordinator.online[index]);
    }
}

#[test]
fn second_sipi_does_not_restart_an_online_application_cpu() {
    let mut fixture = Fixture::new(2);
    fixture.write(BSP, &bsp_program());
    fixture.write(AP, &ap_program());
    fixture.vm.execute_turn().unwrap();
    fixture.vm.execute_turn().unwrap();
    let before = crate::codec::serialize(&fixture.vm.vcpus[1].get_state().unwrap()).unwrap();
    {
        let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
        bsp.write_register(0x310, 1 << 24);
        bsp.write_register(0x300, 0x060a); // different vector while AP is online
    }
    fixture.vm.route_interprocessor_requests().unwrap();
    assert_eq!(
        crate::codec::serialize(&fixture.vm.vcpus[1].get_state().unwrap()).unwrap(),
        before
    );
}

#[test]
fn physical_flat_cluster_and_broadcast_ipis_select_the_expected_controllers() {
    // (destination format, logical IDs, ICR high, ICR low, expected recipients)
    for (format, logical, high, low, expected) in [
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            2 << 24,
            0x41,
            [false, false, true, false],
        ),
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            3 << 24,
            0x0841,
            [true, true, false, false],
        ),
        (
            0x0fff_ffff,
            [0x11, 0x12, 0x21, 0x22],
            0x21 << 24,
            0x0841,
            [false, false, true, false],
        ),
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            0xff << 24,
            0x41,
            [true, true, true, true],
        ),
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            0,
            0x000c_0041,
            [false, true, true, true],
        ),
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            0,
            0x0008_0041,
            [true, true, true, true],
        ),
    ] {
        let mut fixture = Fixture::new(4);
        for (apic, id) in fixture.vm.local_apics.iter().zip(logical) {
            let mut apic = apic.lock().unwrap();
            apic.write_register(0xe0, format);
            apic.write_register(0xd0, id << 24);
        }
        {
            let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
            bsp.write_register(0x310, high);
            bsp.write_register(0x300, low);
        }
        fixture.vm.route_interprocessor_requests().unwrap();
        for (index, wanted) in expected.into_iter().enumerate() {
            let apic = fixture.vm.local_apics[index].lock().unwrap();
            assert_eq!(
                apic.read_register(0x220) & 2 != 0,
                wanted,
                "CPU {index},ICR {high:x}:{low:x}"
            );
        }
    }
}

#[test]
fn lowest_priority_ipi_selects_one_online_enabled_target() {
    let mut fixture = Fixture::new(4);
    fixture.vm.coordinator.online.fill(true);
    for (index, priority) in [0x70, 0x20, 0x20, 0x10].into_iter().enumerate() {
        fixture.vm.local_apics[index]
            .lock()
            .unwrap()
            .write_register(0x80, priority);
    }
    fixture.vm.coordinator.online[3] = false;
    fixture.vm.local_apics[0]
        .lock()
        .unwrap()
        .write_register(0x300, 0x0008_0141);
    fixture.vm.route_interprocessor_requests().unwrap();
    for index in 0..4 {
        assert_eq!(
            fixture.vm.local_apics[index]
                .lock()
                .unwrap()
                .read_register(0x220)
                & 2
                != 0,
            index == 1
        );
    }
}

#[test]
fn illegal_fixed_ipi_vectors_set_sender_error_without_queueing_an_interrupt() {
    for vector in 0..16 {
        let mut fixture = Fixture::new(2);
        {
            let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
            bsp.write_register(0x300, 0x000c_0000 | vector);
        }
        fixture.vm.route_interprocessor_requests().unwrap();
        assert_eq!(
            fixture.vm.local_apics[0]
                .lock()
                .unwrap()
                .read_register(0x280)
                & 0x20,
            0x20,
            "sender rejected vector {vector}"
        );
        for apic in &fixture.vm.local_apics {
            assert_eq!(
                apic.lock().unwrap().read_register(0x200) & 0xffff,
                0,
                "reserved vectors never enter IRR"
            );
        }
    }
}

#[cfg(feature = "debug")]
#[test]
fn gdb_single_step_reports_one_bsp_instruction_with_other_cpus_online() {
    let mut fixture = Fixture::new(4);
    fixture.write(BSP, &[0x90, 0x90, 0xf4]);
    fixture.vm.coordinator.online.fill(true);
    fixture.vm.coordinator.cursor = 2;
    fixture.vm.gdb_single_step = true;
    fixture.vm.vcpus[0].set_single_step(true);
    // GDB all-stop permits other threads to run while the selected thread
    // steps. Require the selected CPU's one-instruction stop within a round.
    let mut stopped = None;
    for _ in 0..4 {
        let turn = fixture.vm.execute_turn().unwrap();
        if matches!(
            turn,
            Some(ExecutionTurn {
                cpu_index: 0,
                exit: VcpuExit::GdbStep,
                ..
            })
        ) {
            stopped = turn;
            break;
        }
    }
    assert!(
        matches!(
            stopped,
            Some(ExecutionTurn {
                cpu_index: 0,
                exit: VcpuExit::GdbStep,
                ..
            })
        ),
        "selected BSP must report its single-instruction stop"
    );
    assert_eq!(fixture.vm.vcpus[0].current_pc(), BSP + 1);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 1);
}

#[cfg(feature = "debug")]
#[test]
fn gdb_breakpoint_stops_before_the_instruction_has_any_effect() {
    let mut fixture = Fixture::new(1);
    fixture.write(BSP, &[0xb8, 0x34, 0x12, 0x00, 0x00, 0xf4]);
    fixture.vm.vcpus[0].set_debug_breakpoint(BSP).unwrap();
    let turn = fixture.vm.execute_turn().unwrap();
    assert!(matches!(
        turn,
        Some(ExecutionTurn {
            cpu_index: 0,
            exit: VcpuExit::GdbBreakpoint { addr: BSP },
            ..
        })
    ));
    assert_eq!(fixture.vm.vcpus[0].current_pc(), BSP);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 0);
    let CpuState::X86_64(state) = fixture.vm.vcpus[0].get_state().unwrap() else {
        unreachable!()
    };
    assert_eq!(state.regs.rax, 0);
}

#[cfg(feature = "debug")]
#[test]
fn gdb_io_single_step_completes_input_and_stops_before_the_next_instruction() {
    use crate::debug::gdb::{GdbCommand, GdbResponse};
    let (client, channels) = crate::debug::gdb::create_channels();
    let worker = std::thread::spawn(move || {
        let mut fixture = Fixture::new(1);
        let mut code = vec![0xe4, 0x80]; // IN AL,80h; an unregistered port readsFF.
        store32(&mut code, FLAGS as u32, 0xdead_beef);
        delay_and_shutdown(&mut code);
        fixture.write(BSP, &code);
        fixture.vm.gdb_channels = Some(channels);
        fixture.vm.gdb_stopped = true;
        let outcome = fixture.vm.run().map_err(|error| error.to_string());
        let CpuState::X86_64(state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        (
            outcome,
            state.regs.rip,
            state.regs.rax & 0xff,
            fixture.flag(0),
            fixture.vm.vcpus[0].instruction_count(),
        )
    });
    client.cmd_tx.send(GdbCommand::Step).unwrap();
    let reply = client
        .resp_rx
        .recv_timeout(std::time::Duration::from_secs(30));
    // Always release the worker, including a failed stop expectation.
    let _ = client.cmd_tx.send(GdbCommand::Kill);
    let (outcome, pc, value, marker, retired) = worker.join().unwrap();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(
        matches!(
            reply,
            Ok(GdbResponse::ThreadStop {
                signal: 5,
                index: 0
            })
        ),
        "{reply:?}"
    );
    assert_eq!(pc, BSP + 2);
    assert_eq!(value, 0xff, "I/O completion precedes the debug stop");
    assert_eq!(marker, 0, "the following store did not execute");
    assert_eq!(retired, 1);
}

#[cfg(feature = "debug")]
#[test]
fn gdb_preserves_and_steps_a_detached_pending_port_read() {
    use crate::debug::gdb::{GdbCommand, GdbResponse};
    use crate::vm::snapshot::SnapshotBundle;

    let mut source = Fixture::with_memory(1, 128 << 20);
    let mut code = vec![0x66, 0xba, 0xf8, 0x03, 0xec]; // MOV DX,COM1; IN AL,DX
    store32(&mut code, FLAGS as u32, 0xdead_beef);
    delay_and_shutdown(&mut code);
    source.write(BSP, &code);
    source.vm.serial.lock().unwrap().queue_input(&[0x5a]);
    let turn = source.vm.execute_turn().unwrap().unwrap();
    assert!(matches!(
        turn.exit,
        VcpuExit::IoIn {
            port: 0x3f8,
            size: 1
        }
    ));
    let retired = source.vm.coordinator.retired;
    let path = source.kernel.with_extension("rxc");
    source
        .vm
        .take_snapshot_bundle(retired)
        .unwrap()
        .save(&path)
        .unwrap();
    drop(source);
    let saved = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();

    for wait_gdb in [false, true] {
        let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
        let mut vm = Vmm::new_resume_bundle(config, &saved).unwrap();
        let (client, channels) = crate::debug::gdb::create_channels();
        vm.gdb_channels = Some(channels);
        vm.gdb_stopped = true;
        vm.wait_gdb = wait_gdb;
        client.cmd_tx.send(GdbCommand::Kill).unwrap();
        vm.run().unwrap();
        assert!(
            vm.serial.lock().unwrap().has_input(),
            "stopped replay consumed the UART byte (wait_gdb={wait_gdb})"
        );
        assert!(vm.vcpus[0].pending_software_port_io().unwrap().is_some());
        assert_eq!(vm.coordinator.retired, retired);
    }

    let (client, channels) = crate::debug::gdb::create_channels();
    let worker = std::thread::spawn(move || {
        let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
        let mut vm = Vmm::new_resume_bundle(config, &saved).unwrap();
        vm.gdb_channels = Some(channels);
        vm.gdb_stopped = true;
        vm.run().unwrap();
        let CpuState::X86_64(state) = vm.vcpus[0].get_state().unwrap() else {
            unreachable!();
        };
        let marker: u32 = vm.guest_mem.memory().read_obj(GuestAddress(FLAGS)).unwrap();
        (
            state.regs.rax & 0xff,
            state.regs.rip,
            vm.coordinator.retired,
            marker,
        )
    });
    client.cmd_tx.send(GdbCommand::Step).unwrap();
    let reply = client
        .resp_rx
        .recv_timeout(std::time::Duration::from_secs(30));
    let _ = client.cmd_tx.send(GdbCommand::Kill);
    let result = worker.join().unwrap();
    assert!(
        matches!(
            reply,
            Ok(GdbResponse::ThreadStop {
                signal: 5,
                index: 0
            })
        ),
        "{reply:?}"
    );
    assert_eq!(result, (0x5a, BSP + 5, retired, 0));
}

#[cfg(feature = "debug")]
#[test]
fn gdb_single_step_stops_after_output_or_halt_before_the_following_store() {
    use crate::debug::gdb::{GdbCommand, GdbResponse};
    for instruction in [vec![0xe6, 0x80], vec![0xf4]] {
        let length = instruction.len() as u64;
        let (client, channels) = crate::debug::gdb::create_channels();
        let worker = std::thread::spawn(move || {
            let mut fixture = Fixture::new(1);
            let mut code = instruction;
            store32(&mut code, FLAGS as u32, 0xdead_beef);
            delay_and_shutdown(&mut code);
            fixture.write(BSP, &code);
            fixture.vm.gdb_channels = Some(channels);
            fixture.vm.gdb_stopped = true;
            let outcome = fixture.vm.run().map_err(|error| error.to_string());
            (
                outcome,
                fixture.vm.vcpus[0].current_pc(),
                fixture.flag(0),
                fixture.vm.vcpus[0].instruction_count(),
            )
        });
        client.cmd_tx.send(GdbCommand::Step).unwrap();
        let reply = client
            .resp_rx
            .recv_timeout(std::time::Duration::from_secs(30));
        let _ = client.cmd_tx.send(GdbCommand::Kill);
        let (outcome, pc, marker, retired) = worker.join().unwrap();
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(
            matches!(
                reply,
                Ok(GdbResponse::ThreadStop {
                    signal: 5,
                    index: 0
                })
            ),
            "{reply:?}"
        );
        assert_eq!(pc, BSP + length);
        assert_eq!(
            marker, 0,
            "the instruction following the step did not execute"
        );
        assert_eq!(retired, 1);
    }
}

#[cfg(feature = "debug")]
#[test]
fn gdb_single_step_waits_for_retirement_after_a_delivered_fault() {
    let mut fixture = Fixture::new(1);
    fixture.write(BSP, &[0x8e, 0xd8]); // MOV DS,AX: selector18h exceeds GDT.
    fixture.write(0xa000, &[0x90, 0xf4]);
    fixture.write(13 * 8, &[0x00, 0xa0, 0x08, 0x00, 0x00, 0x8e, 0x00, 0x00]);
    let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rax = 0x18;
    state.sregs.gdt.base = 0x7300;
    state.sregs.gdt.limit = 23;
    state.sregs.idt.base = 0;
    state.sregs.idt.limit = 2047;
    fixture.vm.vcpus[0]
        .set_state(&CpuState::X86_64(state))
        .unwrap();
    fixture.vm.vcpus[0].set_single_step(true);
    assert!(fixture.vm.execute_turn().unwrap().is_none());
    assert_eq!(fixture.vm.vcpus[0].current_pc(), 0xa000);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 0);
    assert!(matches!(
        fixture.vm.execute_turn().unwrap(),
        Some(ExecutionTurn {
            cpu_index: 0,
            exit: VcpuExit::GdbStep,
            ..
        })
    ));
    assert_eq!(fixture.vm.vcpus[0].current_pc(), 0xa001);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 1);
}

#[test]
fn automatic_checkpoint_after_input_contains_the_completed_value_and_resumes_it() {
    let mut fixture = Fixture::with_memory(1, 128 * 1024 * 1024);
    let directory = fixture.kernel.with_extension("automatic");
    std::fs::create_dir(&directory).unwrap();
    fixture.vm.snapshot_config = Some(SnapshotConfig {
        interval: 0,
        at_instructions: vec![1],
        output_dir: directory.to_string_lossy().into_owned(),
        prefix: "completion".into(),
    });
    let mut code = vec![0xe4, 0x80, 0xa3]; // IN AL,80h; MOV [FLAGS],EAX
    code.extend_from_slice(&(FLAGS as u32).to_le_bytes());
    delay_and_shutdown(&mut code);
    fixture.write(BSP, &code);
    fixture.vm.run().unwrap();
    assert_eq!(fixture.flag(0), 0xff);
    let path = directory.join("completion_000000000001.rxc");
    let saved = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
    let CpuState::X86_64(state) = &saved.base().cpu_state else {
        unreachable!()
    };
    assert_eq!(saved.base().instruction_count, 1);
    assert_eq!(state.regs.rip, BSP + 2);
    assert_eq!(
        state.regs.rax & 0xff,
        0xff,
        "snapshot follows I/O completion"
    );
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &saved).unwrap();
    resumed.run().unwrap();
    assert_eq!(
        resumed.guest_mem.try_read_all().unwrap(),
        fixture.vm.guest_mem.try_read_all().unwrap()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn automatic_checkpoints_publish_exact_and_periodic_counts_inside_a_turn() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut fixture = Fixture::with_memory(1, 128 << 20);
    let directory = fixture.kernel.with_extension("exact-count");
    std::fs::create_dir(&directory).unwrap();
    let schedule = SnapshotConfig {
        interval: 3,
        at_instructions: vec![7, 2, 5, 2],
        output_dir: directory.to_string_lossy().into_owned(),
        prefix: "exact".into(),
    };
    fixture.vm.snapshot_config = Some(schedule.clone());
    let mut guest = vec![0x90; 7];
    guest.extend_from_slice(&[0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef]);
    fixture.write(BSP, &guest);
    fixture.vm.run().unwrap();

    let expected = [(2, 2), (5, 5), (7, 7), (10, guest.len() as u64)];
    assert_eq!(
        std::fs::read_dir(&directory).unwrap().count(),
        expected.len()
    );
    for (retired, offset) in expected {
        let saved = SnapshotBundle::load(schedule.filename(retired)).unwrap();
        let CpuState::X86_64(state) = &saved.base().cpu_state else {
            unreachable!()
        };
        assert_eq!(state.regs.rip, BSP + offset);
        assert_eq!(saved.base().instruction_count, retired);
        assert_eq!(saved.execution().unwrap().retired(), retired);
    }
    assert!(fixture.vm.pc_powered_off());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn exact_checkpoint_records_the_next_hart_and_resumes_its_interleaving() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut fixture = Fixture::with_retired_cpus(2);
    let directory = fixture.kernel.with_extension("exact-smp");
    std::fs::create_dir(&directory).unwrap();
    let schedule = SnapshotConfig {
        at_instructions: vec![2],
        output_dir: directory.to_string_lossy().into_owned(),
        prefix: "exact-smp".into(),
        ..SnapshotConfig::default()
    };
    fixture.vm.snapshot_config = Some(schedule.clone());
    let mut bsp = vec![0x90, 0x90, 0xa1]; // NOP; NOP; MOV EAX,[FLAGS]
    bsp.extend_from_slice(&(FLAGS as u32).to_le_bytes());
    bsp.push(0xa3); // MOV [FLAGS+4],EAX
    bsp.extend_from_slice(&(FLAGS as u32 + 4).to_le_bytes());
    bsp.extend_from_slice(&[0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef]);
    fixture.write(BSP, &bsp);
    let mut ap = Vec::new();
    store32(&mut ap, FLAGS as u32, 0xc0de);
    ap.push(0xf4);
    fixture.write(AP, &ap);
    let CpuState::X86_64(mut secondary) = fixture.vm.vcpus[0].get_state().unwrap() else {
        unreachable!()
    };
    secondary.regs.rip = AP;
    fixture.vm.vcpus[1]
        .set_state(&CpuState::X86_64(secondary))
        .unwrap();
    fixture.vm.coordinator.online[1] = true;

    let blocked = schedule.filename(2);
    std::fs::create_dir(&blocked).unwrap();
    assert!(fixture.vm.run().is_err());
    assert_eq!(fixture.vm.coordinator.retired, 2);
    assert_eq!(fixture.vm.vcpus[0].current_pc(), BSP + 2);
    assert_eq!(fixture.vm.vcpus[1].current_pc(), AP);
    assert_eq!(fixture.vm.last_snapshot_insn, 0);
    assert_eq!(fixture.flag(0), 0);
    std::fs::remove_dir(&blocked).unwrap();

    fixture.vm.run().unwrap();
    assert_eq!(fixture.flag(1), 0xc0de);
    let saved = SnapshotBundle::load(schedule.filename(2)).unwrap();
    assert_eq!(saved.execution().unwrap().cursor(), 1);
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &saved).unwrap();
    resumed.run().unwrap();
    assert!(resumed.pc_powered_off());
    assert_eq!(resumed.coordinator.retired, fixture.vm.coordinator.retired);
    assert_eq!(
        resumed.guest_mem.try_read_all().unwrap(),
        fixture.vm.guest_mem.try_read_all().unwrap()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn failed_terminal_checkpoint_retries_without_entering_the_guest() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut fixture = Fixture::with_retired_clock();
    let directory = fixture.kernel.with_extension("terminal-capture");
    std::fs::create_dir(&directory).unwrap();
    let schedule = SnapshotConfig {
        at_instructions: vec![3],
        output_dir: directory.to_string_lossy().into_owned(),
        prefix: "terminal".into(),
        ..SnapshotConfig::default()
    };
    let path = schedule.filename(3);
    std::fs::create_dir(&path).unwrap();
    fixture.vm.snapshot_config = Some(schedule);
    // MOV DX,604h; MOV AX,2000h; OUT DX,AX; UD2.
    fixture.write(
        BSP,
        &[
            0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef, 0x0f, 0x0b,
        ],
    );
    assert!(fixture.vm.run().is_err());
    assert!(fixture.vm.pc_powered_off());
    assert_eq!(fixture.vm.coordinator.retired, 3);
    assert_eq!(fixture.vm.last_snapshot_insn, 0);
    assert_eq!(fixture.vm.vcpus[0].current_pc(), BSP + 10);

    std::fs::remove_dir(&path).unwrap();
    fixture.vm.run().unwrap();
    assert_eq!(fixture.vm.last_snapshot_insn, 3);
    assert_eq!(fixture.vm.vcpus[0].current_pc(), BSP + 10);
    let saved = SnapshotBundle::load(&path).unwrap();
    assert_eq!(saved.base().instruction_count, 3);
    let config = VmConfig::from_checkpoint_bundle(
        &saved,
        CliConfig {
            snapshot_at: vec![3],
            snapshot_dir: Some(directory.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &saved).unwrap();
    std::fs::remove_file(&path).unwrap();
    fixture.vm.run().unwrap();
    resumed.run().unwrap();
    assert!(resumed.pc_powered_off());
    assert_eq!(resumed.coordinator.retired, 3);
    assert_eq!(resumed.vcpus[0].current_pc(), BSP + 10);
    assert!(std::fs::read_dir(&directory).unwrap().next().is_none());
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn automatic_checkpoint_schedule_rewinds_and_resumes_from_real_files() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut fixture = Fixture::with_memory(1, 128 << 20);
    let directory = fixture.kernel.with_extension("schedule");
    std::fs::create_dir(&directory).unwrap();
    let schedule = SnapshotConfig {
        interval: 20,
        at_instructions: vec![25],
        output_dir: directory.to_string_lossy().into_owned(),
        prefix: "schedule".into(),
    };
    fixture.vm.snapshot_config = Some(schedule.clone());
    fixture.vm.last_snapshot_insn = 10;
    fixture.vm.coordinator.retired = 23;
    let manual = directory.join("manual.rxc");
    fixture
        .vm
        .take_snapshot_bundle(23)
        .unwrap()
        .save(&manual)
        .unwrap();
    let saved = SnapshotBundle::load(&manual).unwrap();

    fixture.vm.coordinator.retired = 58;
    fixture.vm.last_snapshot_insn = 50;
    fixture.vm.restore_snapshot_bundle(&saved).unwrap();
    let config = VmConfig::from_checkpoint_bundle(
        &saved,
        CliConfig {
            snapshot_interval: 20,
            snapshot_at: vec![25],
            snapshot_dir: Some(directory.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let detached = Vmm::new_resume_bundle(config, &saved).unwrap();
    assert_eq!(
        (fixture.vm.coordinator.retired, detached.coordinator.retired),
        (23, 23)
    );
    assert_eq!(
        (fixture.vm.last_snapshot_insn, detached.last_snapshot_insn),
        (10, 10)
    );
    drop(detached);

    // Retirement 23 alone does not fix interval phase or consume the trigger
    // at 25. Only a successful automatic write advances the schedule.
    fixture.vm.coordinator.retired = 24;
    fixture.vm.maybe_snapshot(24).unwrap();
    assert_eq!(fixture.vm.last_snapshot_insn, 10);
    assert!(!std::path::Path::new(&schedule.filename(24)).exists());
    fixture.vm.coordinator.retired = 25;
    let blocked = schedule.filename(25);
    std::fs::create_dir(&blocked).unwrap();
    assert!(fixture.vm.maybe_snapshot(25).is_err());
    assert_eq!(fixture.vm.last_snapshot_insn, 10);
    std::fs::remove_dir(&blocked).unwrap();
    fixture.vm.maybe_snapshot(25).unwrap();
    let scheduled = SnapshotBundle::load(&schedule.filename(25)).unwrap();
    assert_eq!(scheduled.base().instruction_count, 25);
    fixture.vm.last_snapshot_insn = 50;
    fixture.vm.restore_snapshot_bundle(&scheduled).unwrap();
    assert_eq!(fixture.vm.last_snapshot_insn, 25);
    std::fs::remove_file(schedule.filename(25)).unwrap();
    fixture.vm.maybe_snapshot(25).unwrap();
    assert!(!std::path::Path::new(&schedule.filename(25)).exists());

    let mut legacy = saved;
    let mut execution = legacy.take_execution().unwrap();
    execution.last_snapshot_insn = None;
    legacy
        .with_execution(execution)
        .unwrap()
        .save(&manual)
        .unwrap();
    let legacy = SnapshotBundle::load(&manual).unwrap();
    fixture.vm.restore_snapshot_bundle(&legacy).unwrap();
    assert_eq!(fixture.vm.last_snapshot_insn, 23);
    std::fs::remove_file(manual).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn automatic_checkpoint_schedule_cannot_wrap_the_next_interval() {
    let mut fixture = Fixture::new(1);
    fixture.vm.snapshot_config = Some(SnapshotConfig {
        interval: 5,
        // Any attempted save would fail because the parent is a file.
        output_dir: fixture.kernel.to_string_lossy().into_owned(),
        ..SnapshotConfig::default()
    });
    fixture.vm.last_snapshot_insn = u64::MAX - 2;
    fixture.vm.coordinator.retired = u64::MAX - 1;
    fixture.vm.maybe_snapshot(u64::MAX - 1).unwrap();
    assert_eq!(fixture.vm.last_snapshot_insn, u64::MAX - 2);

    fixture.write(BSP, &[0x90, 0xf4]); // NOP; HLT
    fixture.vm.coordinator.retired = u64::MAX;
    assert!(matches!(
        fixture.vm.execute_turn().unwrap().unwrap().exit,
        VcpuExit::Hlt
    ));
    assert_eq!(fixture.vm.coordinator.retired, 1);
    assert_eq!(fixture.vm.last_snapshot_insn, 0);
}

#[test]
fn automatic_checkpoint_schedule_legacy_base_resumes_at_its_recorded_count() {
    let mut fixture = Fixture::new(1);
    let saved = fixture.vm.take_snapshot(23).unwrap();
    fixture.vm.coordinator.retired = 50;
    fixture.vm.last_snapshot_insn = 48;
    fixture.vm.restore_snapshot(&saved).unwrap();
    assert_eq!(fixture.vm.coordinator.retired, 23);
    assert_eq!(fixture.vm.last_snapshot_insn, 23);
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn projected_checkpoints_resume_each_cpu_with_restored_guest_code() {
    const AFTER_HLT: u64 = BSP + 19;
    const WARM_ITERATIONS: u64 = 96;
    const DATA_VA: u64 = 0xa000;
    const SAVED_DATA_PA: u64 = 0xd000;
    const LIVE_DATA_PA: u64 = 0xc000;
    const DATA_PTE: u64 = 0x4000 + (DATA_VA >> 12) * 8;

    fn run_to_hlt(cpu: &mut dyn crate::vm::vcpu::VCpu) -> u64 {
        for _ in 0..16 {
            assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
            if cpu.current_pc() == AFTER_HLT {
                let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                    unreachable!()
                };
                return state.regs.rax;
            }
        }
        panic!("guest loop did not reach HLT");
    }

    for restore_bundle in [false, true] {
        let mut fixture = Fixture::new(2);
        for (address, pointer) in [
            (0x1000, 0x2003u64),
            (0x2000, 0x3003),
            (0x3000, 0x4003),
            (0x4000 + (BSP >> 12) * 8, BSP | 3),
            (DATA_PTE, SAVED_DATA_PA | 3),
        ] {
            fixture.write(address, &pointer.to_le_bytes());
        }
        for cpu in &mut fixture.vm.vcpus {
            let mut config = cpu.x86_configuration().unwrap();
            config.apx = true;
            cpu.set_x86_configuration(config).unwrap();
            let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                unreachable!()
            };
            state.regs.rip = BSP;
            state.regs.rcx = 3;
            state.sregs.cr0 = 0x8000_0011;
            state.sregs.cr3 = 0x1000;
            state.sregs.cr4 = 1 << 5;
            state.sregs.efer = (1 << 8) | (1 << 10);
            state.sregs.cs.l = true;
            state.sregs.cs.db = false;
            state.sregs.cs.base = 0;
            cpu.set_state(&CpuState::X86_64(state)).unwrap();
        }
        // MOV EAX,2; APX NF DEC RCX; BLSI RDX,RCX; JNZ to MOV; HLT.
        // The AP's next instruction resets RCX and branches to the loop.
        fixture.write(
            BSP,
            &[
                0xb8, 2, 0, 0, 0, 0x62, 0xf4, 0xfc, 0x0c, 0xff, 0xc9, 0xc4, 0xe2, 0xe8, 0xf3, 0xd9,
                0x75, 0xee, 0xf4, 0xb9, 3, 0, 0, 0, 0xeb, 0xe6,
            ],
        );
        let base = fixture.vm.take_snapshot(0).unwrap();
        let cpus = fixture.vm.capture_cpu_states().unwrap();
        fixture.write(BSP + 1, &[1]);
        fixture.write(DATA_PTE, &(LIVE_DATA_PA | 3).to_le_bytes());
        for cpu in &mut fixture.vm.vcpus {
            let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                unreachable!()
            };
            state.regs.rcx = WARM_ITERATIONS;
            cpu.set_state(&CpuState::X86_64(state)).unwrap();
            assert_eq!(run_to_hlt(&mut **cpu), 1);
            assert_eq!(
                cpu.translate_addr(DATA_VA, crate::vm::vcpu::MemAccess::Read)
                    .unwrap(),
                LIVE_DATA_PA,
            );
        }

        if restore_bundle {
            let pci = fixture
                .vm
                .pci_devices
                .as_ref()
                .unwrap()
                .checkpoint()
                .unwrap();
            let bundle = crate::vm::snapshot::SnapshotBundle::new(base)
                .with_cpus(cpus)
                .unwrap()
                .with_pci(pci)
                .unwrap();
            fixture.vm.restore_snapshot_bundle(&bundle).unwrap();
        } else {
            fixture.vm.restore_snapshot(&base).unwrap();
            assert_eq!(fixture.vm.vcpus[1].current_pc(), AFTER_HLT);
        }
        for (index, cpu) in fixture.vm.vcpus.iter_mut().enumerate() {
            cpu.wake();
            assert_eq!(
                run_to_hlt(&mut **cpu),
                2,
                "restore_bundle={restore_bundle} CPU {index} executed stale code"
            );
            assert_eq!(
                cpu.translate_addr(DATA_VA, crate::vm::vcpu::MemAccess::Read)
                    .unwrap(),
                SAVED_DATA_PA,
                "restore_bundle={restore_bundle} CPU {index} reused a stale translation"
            );
        }
    }
}

#[cfg(feature = "debug")]
#[test]
fn gdb_boundary_halted_cpu_does_not_hit_the_following_breakpoint_until_woken() {
    let mut fixture = Fixture::new(1);
    fixture.write(BSP, &[0xf4, 0x90]);
    assert!(matches!(
        fixture.vm.execute_turn().unwrap(),
        Some(ExecutionTurn {
            cpu_index: 0,
            exit: VcpuExit::Hlt,
            ..
        })
    ));
    fixture.vm.vcpus[0].set_debug_breakpoint(BSP + 1).unwrap();
    assert!(
        matches!(
            fixture.vm.execute_turn().unwrap(),
            Some(ExecutionTurn {
                cpu_index: 0,
                exit: VcpuExit::Hlt,
                ..
            })
        ),
        "halted CPUs do not attempt the instruction at their next RIP"
    );
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 1);
    fixture.vm.vcpus[0].wake();
    assert!(
        matches!(fixture.vm.execute_turn().unwrap(), Some(ExecutionTurn {
        cpu_index: 0,
        exit: VcpuExit::GdbBreakpoint { addr },
        ..
    }) if addr == BSP + 1)
    );
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 1);
}

#[cfg(feature = "debug")]
#[test]
fn gdb_boundary_stopped_cpu_retains_registers_stack_and_pending_interrupt() {
    use crate::debug::gdb::{GdbCommand, GdbResponse};
    let (client, channels) = crate::debug::gdb::create_channels();
    let worker = std::thread::spawn(move || {
        let mut fixture = Fixture::new(1);
        fixture.write(BSP, &[0x90, 0xf4]);
        fixture.write(0xa000, &[0x90, 0xf4]);
        fixture.write(0x41 * 8, &[0x00, 0xa0, 0x08, 0x00, 0x00, 0x8e, 0x00, 0x00]);
        let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rflags = 0x202;
        state.sregs.gdt.base = 0x7300;
        state.sregs.gdt.limit = 23;
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 2047;
        fixture.vm.vcpus[0]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
        {
            let mut apic = fixture.vm.local_apics[0].lock().unwrap();
            apic.write_register(0xf0, 0x1ff);
            apic.receive_fixed_interrupt(0x41);
        }
        fixture.vm.gdb_channels = Some(channels);
        fixture.vm.gdb_stopped = true;
        let outcome = fixture.vm.run().map_err(|error| error.to_string());
        let CpuState::X86_64(state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        let mut stack = [0; 16];
        fixture
            .vm
            .guest_mem
            .memory()
            .read_slice(&mut stack, GuestAddress(0xdff0))
            .unwrap();
        let apic = fixture.vm.local_apics[0].lock().unwrap();
        (
            outcome,
            state.regs.rip,
            state.regs.rsp,
            stack,
            apic.read_register(0x220),
            apic.read_register(0x120),
        )
    });
    client.cmd_tx.send(GdbCommand::ReadRegisters).unwrap();
    let reply = client
        .resp_rx
        .recv_timeout(std::time::Duration::from_secs(30));
    let _ = client.cmd_tx.send(GdbCommand::Kill);
    let (outcome, pc, sp, stack, irr, isr) = worker.join().unwrap();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(matches!(reply, Ok(GdbResponse::Registers(_))), "{reply:?}");
    assert_eq!(
        pc, BSP,
        "debugger inspection cannot deliver a guest interrupt"
    );
    assert_eq!(sp, 0xe000);
    assert_eq!(stack, [0; 16]);
    assert_eq!(irr & 2, 2);
    assert_eq!(isr & 2, 0);
}

#[test]
fn retirement_distinguishes_inline_faults_debug_traps_and_faulted_software_interrupts() {
    use crate::vm::vcpu::RetirementStop;
    for (name, code, vector, retired, debug_general_detect, nested_software_fault) in [
        ("segment selector GP", vec![0x8e, 0xd8], 13, 0, false, false),
        ("UD2", vec![0x0f, 0x0b], 6, 0, false, false),
        ("unknown RDMSR", vec![0x0f, 0x32], 13, 0, false, false),
        (
            "debug-register GD fault",
            vec![0x0f, 0x21, 0xc0],
            1,
            0,
            true,
            false,
        ),
        ("ICEBP trap", vec![0xf1], 1, 1, false, false),
        ("INT3 trap", vec![0xcc], 3, 1, false, false),
        ("faulted INT80 gate", vec![0xcd, 0x80], 13, 0, false, true),
    ] {
        let mut fixture = Fixture::new(1);
        fixture.write(BSP, &code);
        fixture.write(0xa000, &[0x90, 0xf4]);
        fixture.write(
            vector * 8,
            &[0x00, 0xa0, 0x08, 0x00, 0x00, 0x8e, 0x00, 0x00],
        );
        if nested_software_fault {
            fixture.write(0x80 * 8, &[0x00, 0xa0, 0x18, 0x00, 0x00, 0x8e, 0x00, 0x00]);
        }
        let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rax = 0x18;
        state.regs.rcx = u64::from(u32::MAX);
        state.sregs.gdt.base = 0x7300;
        state.sregs.gdt.limit = 23;
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 2047;
        if debug_general_detect {
            state.sregs.dr7 |= 1 << 13;
        }
        fixture.vm.vcpus[0]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
        let result = fixture.vm.vcpus[0].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, retired, "{name}: {result:?}");
        if retired == 0 {
            assert!(
                matches!(result.stop, RetirementStop::StateChange),
                "{name}: {result:?}"
            );
        } else {
            assert!(
                matches!(result.stop, RetirementStop::BudgetExhausted),
                "{name}: {result:?}"
            );
        }
        assert_eq!(fixture.vm.vcpus[0].current_pc(), 0xa000, "{name}");
        assert_eq!(fixture.vm.vcpus[0].instruction_count(), retired, "{name}");
        // The first handler instruction must retire independently, with no
        // stale event classification inherited from the interrupted attempt.
        let result = fixture.vm.vcpus[0].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 1, "{name}: handler NOP");
        assert_eq!(fixture.vm.vcpus[0].current_pc(), 0xa001, "{name}");
    }
}
