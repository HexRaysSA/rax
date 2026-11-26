//! Checkpoint admission must precede changes to any live base checkpoint field.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    kernel: std::path::PathBuf,
    vm: Vmm,
}
impl Fixture {
    fn new() -> Self {
        Self::with_memory(4096)
    }

    fn with_memory(size: u64) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-admission-lock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&kernel, [0; 64]).unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(size);
        Self {
            kernel,
            vm: Vmm::new_resume(config).unwrap(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let checkpoint = self.kernel.with_extension("rxc");
        if checkpoint.exists() {
            std::fs::remove_file(checkpoint).unwrap();
        }
        std::fs::remove_file(&self.kernel).unwrap();
    }
}

#[test]
fn console_checkpoint_preserves_input_before_the_hotkey_only() {
    let mut fixture = Fixture::new();
    let vm = &mut fixture.vm;
    vm.snapshot_out = fixture.kernel.with_extension("rxc");
    // Enable the FIFO and received-data interrupts on IRQ4.
    {
        let mut serial = vm.serial.lock().unwrap();
        IoDevice::write(&mut *serial, 0x3fa, 1); // FCR: enable FIFO
        IoDevice::write(&mut *serial, 0x3fc, 8); // MCR: OUT2
        IoDevice::write(&mut *serial, 0x3f9, 1); // IER: received data
    }
    vm.io_bus.get_mut().unwrap().write(0x21, &[0xef]).unwrap();
    let mut console = Console::from_bytes(b"A\x01\x01\x01sB");
    assert!(!vm.service_console(&mut console));

    let saved = crate::vm::snapshot::SnapshotBundle::load(&vm.snapshot_out).unwrap();
    let mut saved_pic = saved.base().devices.pic.clone();
    assert_eq!(saved_pic.get_pending_vector(), Some(0x24));
    let mut live = vm.serial.lock().unwrap();
    assert_eq!(IoDevice::read(&mut *live, 0x3f8), b'A');
    assert_eq!(IoDevice::read(&mut *live, 0x3f8), 1);
    assert_eq!(IoDevice::read(&mut *live, 0x3f8), b'B');
    drop(live);

    // Read the restored UART through its real I/O bridge. Only the bytes
    // before the hotkey are available to a resumed guest.
    vm.restore_snapshot_bundle(&saved).unwrap();
    let mut read_port = |port| {
        port_io::read(
            vm.io_bus.get_mut().unwrap(),
            &vm.serial,
            vm.backend_kind,
            None,
            port,
            1,
            1,
        )
        .unwrap()[0]
    };
    assert_eq!(read_port(0x3f8), b'A');
    assert_eq!(read_port(0x3f8), 1);
    assert_eq!(read_port(0x3fd) & 1, 0);
}

#[test]
fn checkpoint_preserves_pic_input_high_after_acknowledgement() {
    let mut source = Fixture::new();
    let vm = &mut source.vm;
    vm.io_bus.get_mut().unwrap().write(0x21, &[0xf7]).unwrap();
    vm.pic.lock().unwrap().set_irq(3, true);
    assert_pic_checkpoint_does_not_create_edge(&mut source, 3, 3);
}

#[test]
fn checkpoint_preserves_pic_cascade_high_after_acknowledgement() {
    use crate::vm::vcpu::CheckpointIoReply;
    let mut source = Fixture::new();
    let vm = &mut source.vm;
    let io = vm.io_bus.get_mut().unwrap();
    io.write(0x21, &[0xfb]).unwrap();
    io.write(0xa1, &[0xee]).unwrap();
    // Enable auxiliary IRQs and put a byte on the i8042 output latch.
    for (port, value) in [(0x64, 0x60), (0x60, 0x22), (0x64, 0xd3), (0x60, 0x5a)] {
        let reply = vm
            .checkpoint_io_service(
                0,
                VcpuExit::IoOut {
                    port,
                    data: vec![value],
                },
            )
            .unwrap();
        assert!(matches!(reply, CheckpointIoReply::Output));
    }
    assert_pic_checkpoint_does_not_create_edge(&mut source, 12, 8);
}

fn assert_pic_checkpoint_does_not_create_edge(source: &mut Fixture, irq: u8, next_irq: u8) {
    let vm = &mut source.vm;
    assert_eq!(
        vm.pic.lock().unwrap().get_pending_vector(),
        Some(0x20 + irq)
    );
    let path = source.kernel.with_extension("rxc");
    vm.take_snapshot_bundle(0).unwrap().save(&path).unwrap();
    let saved = SnapshotBundle::load(&path).unwrap();
    let mut target = Fixture::new();
    target.vm.restore_snapshot_bundle(&saved).unwrap();

    for (name, vm) in [("source", vm), ("restored", &mut target.vm)] {
        // IRQ3 stays high. A higher-priority slave request also leaves an
        // already-high cascade input high. Neither transition is a new edge.
        vm.pic.lock().unwrap().set_irq(next_irq, true);
        vm.io_bus.get_mut().unwrap().write(0x20, &[0x20]).unwrap();
        assert_eq!(
            vm.pic.lock().unwrap().get_pending_vector(),
            None,
            "{name} IRQ{irq}"
        );
    }
}

fn poison<T: Send + 'static>(lock: Arc<std::sync::Mutex<T>>) {
    assert!(
        std::thread::spawn(move || {
            let _guard = lock.lock().unwrap();
            panic!("owned device-lock fixture");
        })
        .join()
        .is_err()
    );
}
fn devices(vm: &Vmm) -> DeviceState {
    DeviceState {
        pic: vm.pic.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        pit: vm.pit.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        serial: vm.serial.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        lapic: vm.lapic.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    }
}
#[test]
fn every_poisoned_legacy_device_lock_rejects_before_any_assignment() {
    for which in 0..4 {
        let mut fixture = Fixture::new();
        let vm = &mut fixture.vm;
        vm.guest_mem.write_all(&[0xa5; 4096]).unwrap();
        let before_cpu = crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap();
        let before_private = crate::codec::serialize(&vm.vcpus[0].get_emulator_state()).unwrap();
        let before_devices = crate::codec::serialize(&devices(vm)).unwrap();
        let mut snapshot = vm.take_snapshot(41).unwrap();
        let CpuState::X86_64(cpu) = &mut snapshot.cpu_state else {
            unreachable!()
        };
        cpu.regs.rax = 0x12345678;
        snapshot.memory_data = zstd::encode_all(&[0x33; 4096][..], 3).unwrap();
        snapshot.devices.pic.set_irq(3, true);
        IoDevice::write(&mut snapshot.devices.serial, 0x3f9, 0x0f);
        match which {
            0 => poison(vm.pic.clone()),
            1 => poison(vm.pit.clone()),
            2 => poison(vm.serial.clone()),
            3 => poison(vm.lapic.clone()),
            _ => unreachable!(),
        }
        assert!(vm.restore_snapshot(&snapshot).is_err());
        assert_eq!(
            crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap(),
            before_cpu
        );
        assert_eq!(
            crate::codec::serialize(&vm.vcpus[0].get_emulator_state()).unwrap(),
            before_private
        );
        assert_eq!(
            crate::codec::serialize(&devices(vm)).unwrap(),
            before_devices
        );
        assert_eq!(vm.guest_mem.try_read_all().unwrap(), vec![0xa5; 4096]);
    }
}

#[cfg(unix)]
#[test]
fn legacy_restore_checks_all_ram_permissions_before_publication() {
    use vm_memory::mmap::MmapRegionBuilder;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, GuestRegionMmap};

    const PAGE: usize = 4096;
    let mut fixture = Fixture::with_memory((2 * PAGE) as u64);
    let vm = &mut fixture.vm;
    let writable = MmapRegionBuilder::new(PAGE)
        .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
        .build()
        .unwrap();
    let readonly = MmapRegionBuilder::new(PAGE)
        .with_mmap_prot(libc::PROT_READ)
        .build()
        .unwrap();
    let backing = GuestMemoryMmap::from_regions(vec![
        GuestRegionMmap::new(writable, GuestAddress(0)).unwrap(),
        GuestRegionMmap::new(readonly, GuestAddress(PAGE as u64)).unwrap(),
    ])
    .unwrap();
    backing.write_slice(&[0xa5; PAGE], GuestAddress(0)).unwrap();
    vm.guest_mem = GuestMemoryWrapper::with_test_backing(backing, (2 * PAGE) as u64);

    let before_ram = vm.guest_mem.try_read_all().unwrap();
    assert_eq!(&before_ram[..PAGE], &[0xa5; PAGE]);
    assert_eq!(&before_ram[PAGE..], &[0; PAGE]);
    let before_cpu = crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap();
    let before_private = crate::codec::serialize(&vm.vcpus[0].get_emulator_state()).unwrap();
    let before_devices = crate::codec::serialize(&devices(vm)).unwrap();
    let before_retired = vm.coordinator.retired;
    let before_last_snapshot = vm.last_snapshot_insn;
    let mut snapshot = vm.take_snapshot(41).unwrap();
    let CpuState::X86_64(cpu) = &mut snapshot.cpu_state else {
        unreachable!()
    };
    cpu.regs.rax = 0x12345678;
    let private = &mut snapshot.emulator_state;
    private.halted = !private.halted;
    snapshot.memory_data = zstd::encode_all(&[0x33; 2 * PAGE][..], 3).unwrap();
    snapshot.devices.pic.set_irq(3, true);
    let bundle = crate::vm::snapshot::SnapshotBundle::new(snapshot);

    for restore_bundle in [false, true] {
        let error = if restore_bundle {
            vm.restore_snapshot_bundle(&bundle).unwrap_err()
        } else {
            vm.restore_snapshot(bundle.base()).unwrap_err()
        };
        assert!(
            crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap() == before_cpu,
            "CPU state changed after rejected restore: {error}"
        );
        assert_eq!(
            crate::codec::serialize(&vm.vcpus[0].get_emulator_state()).unwrap(),
            before_private
        );
        assert_eq!(
            crate::codec::serialize(&devices(vm)).unwrap(),
            before_devices
        );
        assert_eq!(vm.guest_mem.try_read_all().unwrap(), before_ram);
        assert_eq!(vm.coordinator.retired, before_retired);
        assert_eq!(vm.last_snapshot_insn, before_last_snapshot);
        assert!(error.to_string().contains("checkpoint RAM destination"));
    }

    let mut writable = Fixture::with_memory((2 * PAGE) as u64);
    writable.vm.restore_snapshot_bundle(&bundle).unwrap();
    let CpuState::X86_64(cpu) = writable.vm.vcpus[0].get_state().unwrap() else {
        unreachable!()
    };
    assert_eq!(cpu.regs.rax, 0x12345678);
    assert_eq!(
        writable.vm.guest_mem.try_read_all().unwrap(),
        [0x33; 2 * PAGE]
    );
    assert_eq!(writable.vm.coordinator.retired, 41);
}

#[cfg(feature = "debug")]
#[test]
fn debugger_cache_failure_prevents_every_checkpoint_capture_before_publication() {
    use crate::vm::vcpu::VCpu;
    struct FailureCpu {
        id: u32,
        state: CpuState,
    }
    impl VCpu for FailureCpu {
        fn id(&self) -> u32 {
            self.id
        }
        fn run(&mut self) -> Result<VcpuExit> {
            panic!("poisoned debugger must exclude guest entry")
        }
        fn get_state(&self) -> Result<CpuState> {
            Ok(self.state.clone())
        }
        fn set_state(&mut self, state: &CpuState) -> Result<()> {
            self.state = state.clone();
            Ok(())
        }
        fn complete_io_in(&mut self, _data: &[u8]) {}
        fn debug_memory_changed(&mut self, _pages: &[u64]) -> Result<()> {
            Err(Error::Emulator("scripted debugger cache failure".into()))
        }
    }
    for failure_index in 0..2 {
        let mut fixture = super::execution_tests::Fixture::new(2);
        let vm = &mut fixture.vm;
        // Valid snapshots establish that poison alone rejects capture and
        // import, independently of an adapter's private-state validation.
        let base = vm.take_snapshot(0).unwrap();
        let bundle = vm.take_snapshot_bundle(0).unwrap();
        assert!(vm.capture_cpu_states().is_ok());
        let before = vm.guest_mem.try_read_all().unwrap();
        let state = vm.vcpus[failure_index].get_state().unwrap();
        let original = std::mem::replace(
            &mut vm.vcpus[failure_index],
            Box::new(FailureCpu {
                id: failure_index as u32,
                state,
            }),
        );
        vm.debugger.physical_memory = true;
        assert!(vm.write_debug_memory(0x8000, b"ABCD").is_err());
        vm.vcpus[failure_index] = original;
        assert!(vm.gdb_stopped);
        let accepted = [
            vm.take_snapshot(0).is_ok(),
            vm.take_snapshot_bundle(0).is_ok(),
            vm.capture_cpu_states().is_ok(),
        ];
        assert_eq!(
            accepted, [false; 3],
            "global failure must fence base, bundle and CPU-set captures at CPU {failure_index}"
        );
        assert!(vm.capture_execution_state().is_err());
        assert!(vm.restore_snapshot(&base).is_err());
        assert!(vm.restore_snapshot_bundle(&bundle).is_err());
        assert!(vm.write_debug_memory(0x8000, b"EFGH").is_err());
        assert!(vm.execute_turn().is_err());
        assert_eq!(vm.guest_mem.try_read_all().unwrap(), before);
    }
}
