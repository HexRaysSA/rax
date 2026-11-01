//! Component boundaries and source-to-target isolation without a guest backend.
use super::*;
use crate::devices::bus::{IoBus, IoDevice, MmioBus};
use crate::machine::pc::PcMachine;
use std::sync::atomic::{AtomicBool, Ordering};
fn device_set() -> (PcDevices, IoBus, MmioBus) {
    let mut io = IoBus::new();
    let mut mmio = MmioBus::new();
    let devices = PcMachine::new()
        .setup_pc_devices(&mut io, &mut mmio)
        .unwrap();
    (devices, io, mmio)
}
fn capture(devices: &PcDevices) -> (PcCheckpoint, Vec<CheckpointResource>) {
    devices
        .checkpoint_with(|state, resources| Ok((state, resources)))
        .unwrap()
}
#[test]
fn aliases_keep_target_owners_and_partial_dma_keyboard_and_floppy_commands() {
    let (source, mut io, _) = device_set();
    io.write(0x00, &[0x34]).unwrap();
    io.write(0x83, &[0x56]).unwrap();
    io.write(0x64, &[0x60]).unwrap();
    io.write(0x3f2, &[0x0c]).unwrap();
    io.write(0x3f5, &[0x03]).unwrap();
    io.write(0x3f5, &[0xa5]).unwrap();
    // The shared FDC remains mid-SPECIFY across its aliased port windows.
    let (image, resources) = capture(&source);
    let resources = PreparedResources::from_bindings(resources).unwrap();
    let (target, mut ports, _) = device_set();
    let dma = target.dma.clone();
    let keyboard = target.i8042.clone();
    let floppy = target.fdc.clone();
    target
        .restore_with(image.prepare(&resources).unwrap(), || Ok(()))
        .unwrap();
    assert!(Arc::ptr_eq(&dma, &target.dma));
    assert!(Arc::ptr_eq(&keyboard, &target.i8042));
    assert!(Arc::ptr_eq(&floppy, &target.fdc));
    ports.write(0x00, &[0x12]).unwrap();
    assert_eq!(target.dma.lock().unwrap().current_address(0), 0x1234);
    assert_eq!(target.dma.lock().unwrap().channel(1).page, 0x56);
    ports.write(0x60, &[0x47]).unwrap();
    ports.write(0x64, &[0x20]).unwrap();
    let mut byte = [0];
    ports.read(0x60, &mut byte).unwrap();
    assert_eq!(byte[0], 0x47);
    ports.write(0x3f5, &[0x23]).unwrap();
    assert_eq!(
        ports
            .read(0x3f4, &mut byte)
            .map(|_| byte[0] & 0x10)
            .unwrap(),
        0
    );
    // Immutable source was captured before the target continued any command.
    let (again, _) = capture(&source);
    assert_eq!(again.data, image.data);
}
#[test]
fn failed_publication_callback_preserves_the_entire_device_inventory() {
    let (source, mut io, _) = device_set();
    io.write(0x70, &[0xb8]).unwrap();
    io.write(0x71, &[0xa5]).unwrap();
    let (image, resources) = capture(&source);
    let resources = PreparedResources::from_bindings(resources).unwrap();
    let (target, _, _) = device_set();
    let (before, _) = capture(&target);
    assert!(
        target
            .restore_with::<()>(image.prepare(&resources).unwrap(), || Err(invalid(
                "injected CPU admission failure"
            )))
            .is_err()
    );
    let (after, _) = capture(&target);
    assert_eq!(before.data, after.data);
}
#[test]
fn poisoned_last_device_lock_rejects_before_callback_and_prefix_mutation() {
    let (source, _, _) = device_set();
    let (image, resources) = capture(&source);
    let resources = PreparedResources::from_bindings(resources).unwrap();
    let (target, _, _) = device_set();
    let rtc = crate::codec::serialize(&target.rtc.lock().unwrap().checkpoint_state()).unwrap();
    let fdc = target.fdc.clone();
    assert!(
        std::thread::spawn(move || {
            let _held = fdc.lock().unwrap();
            panic!("intentional last-lock poison");
        })
        .join()
        .is_err()
    );
    let called = AtomicBool::new(false);
    assert!(
        target
            .restore_with(image.prepare(&resources).unwrap(), || {
                called.store(true, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
    );
    assert!(!called.load(Ordering::SeqCst));
    assert_eq!(
        rtc,
        crate::codec::serialize(&target.rtc.lock().unwrap().checkpoint_state()).unwrap()
    );
}
#[test]
fn immutable_cd_resources_deduplicate_and_rebind_both_channels() {
    let (source, _, _) = device_set();
    let cd = Arc::new(vec![0x5a; 8192]);
    source.ide_primary.lock().unwrap().attach_cdrom(cd.clone());
    source.ide_secondary.lock().unwrap().attach_cdrom(cd);
    let (image, resources) = capture(&source);
    let resources = PreparedResources::from_bindings(resources).unwrap();
    assert_eq!(
        resources
            .keys()
            .filter(|key| key.kind() == crate::vm::snapshot::BOOT_CDROM_RESOURCE)
            .count(),
        1
    );
    assert_eq!(image.references().unwrap().len(), 9);
    assert!(image.prepare(&PreparedResources::default()).is_err());
    let (target, _, _) = device_set();
    target
        .restore_with(image.prepare(&resources).unwrap(), || Ok(()))
        .unwrap();
    let primary = target
        .ide_primary
        .lock()
        .unwrap()
        .checkpoint_cdrom()
        .unwrap();
    let secondary = target
        .ide_secondary
        .lock()
        .unwrap()
        .checkpoint_cdrom()
        .unwrap();
    assert!(Arc::ptr_eq(&primary, &secondary));
    assert_eq!(&**primary, &[0x5a; 8192]);
}
#[test]
fn absent_and_empty_cd_media_remain_distinct() {
    let (source, _, _) = device_set();
    source
        .ide_primary
        .lock()
        .unwrap()
        .attach_cdrom(Arc::new(Vec::new()));
    let (image, resources) = capture(&source);
    let resources = PreparedResources::from_bindings(resources).unwrap();
    let (target, _, _) = device_set();
    target
        .restore_with(image.prepare(&resources).unwrap(), || Ok(()))
        .unwrap();
    assert_eq!(
        target
            .ide_primary
            .lock()
            .unwrap()
            .checkpoint_cdrom()
            .unwrap()
            .len(),
        0
    );
    assert!(
        target
            .ide_secondary
            .lock()
            .unwrap()
            .checkpoint_cdrom()
            .is_none()
    );
}
#[test]
fn truncated_unknown_tag_and_trailing_pc_images_reject() {
    let (source, _, _) = device_set();
    let (image, _) = capture(&source);
    let raw = image.encoded().unwrap();
    assert_eq!(PcCheckpoint::decode(&raw).unwrap().encoded().unwrap(), raw);
    for end in [0, 7, 8, 9, 129, 130, raw.len() / 2, raw.len() - 1] {
        assert!(PcCheckpoint::decode(&raw[..end]).is_err(), "prefix {end}");
    }
    let mut unknown = raw.clone();
    unknown[7] = b'2';
    assert!(PcCheckpoint::decode(&unknown).is_err());
    let mut trailing = raw;
    trailing.push(0);
    assert!(PcCheckpoint::decode(&trailing).is_err());
}

#[test]
fn atapi_data_cursor_and_mutable_disk_bytes_resume_in_independent_owners() {
    let (source, mut io, _) = device_set();
    let cd = Arc::new(
        (0..131072)
            .map(|i| (i as u8).wrapping_mul(13))
            .collect::<Vec<u8>>(),
    );
    source.ide_primary.lock().unwrap().attach_cdrom(cd);
    for (port, byte) in [(0x1f6, 0xe0), (0x1f4, 1), (0x1f5, 0), (0x1f7, 0xa0)] {
        io.write(port, &[byte]).unwrap();
    }
    // A one-byte requested block takes the model's existing whole-response
    // branch. Preserve that represented state, including its >64KiB buffer.
    for byte in [0x28, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0] {
        io.write(0x1f0, &[byte]).unwrap();
    }
    let mut byte = [0];
    for i in 0..123 {
        io.read(0x1f0, &mut byte).unwrap();
        assert_eq!(byte[0], (i as u8).wrapping_mul(13));
    }
    let (image, resources) = capture(&source);
    assert!(
        image.data.len() < 16384,
        "large data leaked into PC control record"
    );
    let resources = PreparedResources::from_bindings(resources).unwrap();
    let (target, mut ports, _) = device_set();
    target
        .restore_with(image.prepare(&resources).unwrap(), || Ok(()))
        .unwrap();
    for i in 123..131072 {
        ports.read(0x1f0, &mut byte).unwrap();
        assert_eq!(byte[0], (i as u8).wrapping_mul(13), "byte {i}");
    }
    // Mutable ATA backing is copied out of a shared checkpoint resource.
    let (disk_source, _, _) = device_set();
    *disk_source.ide_primary.lock().unwrap() = IdeController::with_sectors(2);
    let (disk_image, bindings) = capture(&disk_source);
    let bindings = PreparedResources::from_bindings(bindings).unwrap();
    let (a, mut a_ports, _) = device_set();
    let (b, _, _) = device_set();
    a.restore_with(disk_image.prepare(&bindings).unwrap(), || Ok(()))
        .unwrap();
    b.restore_with(disk_image.prepare(&bindings).unwrap(), || Ok(()))
        .unwrap();
    for (port, byte) in [
        (0x1f2, 1),
        (0x1f3, 0),
        (0x1f4, 0),
        (0x1f5, 0),
        (0x1f6, 0xe0),
        (0x1f7, 0x30),
    ] {
        a_ports.write(port, &[byte]).unwrap();
    }
    for _ in 0..512 {
        a_ports.write(0x1f0, &[0x5a]).unwrap();
    }
    let (a_image, _) = capture(&a);
    let (b_image, _) = capture(&b);
    assert_ne!(
        a_image.state().unwrap().buffers[0],
        b_image.state().unwrap().buffers[0]
    );
    assert_eq!(
        b_image.state().unwrap().buffers[0],
        disk_image.state().unwrap().buffers[0]
    );
}

#[test]
fn owned_machine_boot_binds_each_iso_to_its_original_device_set() {
    use crate::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
    use crate::machine::Machine;
    use vm_memory::{GuestAddress, GuestMemoryMmap};
    struct Files(Vec<std::path::PathBuf>);
    impl Drop for Files {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let files = Files(
        ["a", "b"]
            .into_iter()
            .map(|name| {
                std::env::temp_dir().join(format!("rax-owned-iso-{}-{name}", std::process::id()))
            })
            .collect(),
    );
    let machine = PcMachine::new();
    let mut ports_a = IoBus::new();
    let mut mmio_a = MmioBus::new();
    let a = machine
        .setup_owned_devices(&mut ports_a, &mut mmio_a)
        .unwrap()
        .unwrap();
    let mut ports_b = IoBus::new();
    let mut mmio_b = MmioBus::new();
    let b = machine
        .setup_owned_devices(&mut ports_b, &mut mmio_b)
        .unwrap()
        .unwrap();
    for (index, (path, devices)) in files.0.iter().zip([&a, &b]).enumerate() {
        let mut iso = vec![0; 22 * 2048];
        iso[16 * 2048 + 1..16 * 2048 + 6].copy_from_slice(b"CD001");
        let record = 17 * 2048;
        iso[record + 1..record + 6].copy_from_slice(b"CD001");
        iso[record + 6] = 1;
        iso[record + 7..record + 30].copy_from_slice(b"EL TORITO SPECIFICATION");
        iso[record + 0x47..record + 0x4b].copy_from_slice(&20u32.to_le_bytes());
        let catalog = 20 * 2048;
        iso[catalog] = 1;
        iso[catalog + 30] = 0x55;
        iso[catalog + 31] = 0xaa;
        iso[catalog + 32] = 0x88;
        iso[catalog + 38..catalog + 40].copy_from_slice(&4u16.to_le_bytes());
        iso[catalog + 40..catalog + 44].copy_from_slice(&21u32.to_le_bytes());
        iso[21 * 2048] = 0xfc;
        iso[21 * 2048 + 1] = index as u8;
        std::fs::write(path, &iso).unwrap();
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                memory: Some(MemorySize(128 << 20)),
                kernel: Some(path.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 128 << 20)]).unwrap();
        let boot = machine
            .load_kernel_with_devices(&memory, &config, Some(devices))
            .unwrap();
        let binding = devices
            .ide_primary
            .lock()
            .unwrap()
            .checkpoint_cdrom()
            .unwrap();
        assert_eq!(&**binding, &iso);
        assert!(Arc::ptr_eq(
            &binding,
            &boot.as_x86_64().unwrap().real_mode.as_ref().unwrap().cdrom
        ));
        if index == 0 {
            assert!(b.ide_primary.lock().unwrap().checkpoint_cdrom().is_none());
        }
    }
    assert_ne!(
        a.ide_primary.lock().unwrap().checkpoint_cdrom().unwrap()[21 * 2048 + 1],
        b.ide_primary.lock().unwrap().checkpoint_cdrom().unwrap()[21 * 2048 + 1]
    );
}
