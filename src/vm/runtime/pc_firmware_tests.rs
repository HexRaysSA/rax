//! Cold PC construction must publish firmware without host-supplied CPU counts.
use super::*;
use crate::config::{CliConfig, MemorySize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::GuestAddress;

#[path = "pc_firmware_program.rs"]
mod guest;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Kernel(PathBuf);
impl Drop for Kernel {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn cold(count: u8) -> (Vmm, Kernel) {
    cold_image(BackendKind::Emulator, count, &[0; 64]).unwrap()
}

fn cold_image(backend: BackendKind, count: u8, image: &[u8]) -> Result<(Vmm, Kernel)> {
    use std::io::Write;
    let path = std::env::temp_dir().join(format!(
        "rax-pc-firmware-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let kernel = Kernel(path);
    file.write_all(image).unwrap();
    drop(file);
    let config = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(backend),
            vcpus: Some(count),
            memory: Some(MemorySize(128 * 1024 * 1024)),
            kernel: Some(kernel.0.clone()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    Ok((Vmm::new(config)?, kernel))
}

fn el_torito(load_segment: u16, image: &[u8]) -> Vec<u8> {
    use crate::machine::pc::bios_boot::CD_SECTOR;
    let sectors = u16::try_from(image.len().div_ceil(512)).unwrap();
    let image_start = 21 * CD_SECTOR;
    let mut iso = vec![0; image_start + usize::from(sectors) * 512];
    iso[16 * CD_SECTOR + 1..][..5].copy_from_slice(b"CD001");
    let record = &mut iso[17 * CD_SECTOR..][..CD_SECTOR];
    record[1..7].copy_from_slice(b"CD001\x01");
    record[7..30].copy_from_slice(b"EL TORITO SPECIFICATION");
    record[0x47..0x4b].copy_from_slice(&20u32.to_le_bytes());
    let catalog = &mut iso[20 * CD_SECTOR..][..64];
    catalog[0] = 1;
    catalog[0x1c..0x20].copy_from_slice(&[0xaa, 0x55, 0x55, 0xaa]);
    catalog[32] = 0x88;
    catalog[34..36].copy_from_slice(&load_segment.to_le_bytes());
    catalog[38..40].copy_from_slice(&sectors.to_le_bytes());
    catalog[40..44].copy_from_slice(&21u32.to_le_bytes());
    iso[image_start..][..image.len()].copy_from_slice(image);
    iso
}

#[test]
fn el_torito_guest_discovers_and_starts_its_secondary_cpus() {
    check_el_torito_smp(BackendKind::Emulator);
}

#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "requires /dev/kvm with in-kernel interrupt controllers"]
fn native_kvm_el_torito_guest_discovers_and_starts_its_secondary_cpus() {
    check_el_torito_smp(BackendKind::Kvm);
}

fn check_el_torito_smp(backend: BackendKind) {
    let mut image = guest::ISO_BSP.to_vec();
    image.resize(0x400, 0);
    image.extend_from_slice(guest::ISO_AP);
    let iso = el_torito(0, &image);
    for count in [2, 4] {
        let (mut vm, _iso) = cold_image(backend, count, &iso).unwrap();
        assert_eq!(vm.vm.uses_native_x86_irqchip(), backend == BackendKind::Kvm);
        assert!(vm.coordinator.online[0]);
        assert!(vm.coordinator.online[1..].iter().all(|online| !online));
        assert_eq!(read(&vm, 0x550), 0);
        vm.run().unwrap();
        assert_eq!(read(&vm, 0x554), 0x600d600d);
        assert_eq!(read(&vm, 0x550), u32::from(count));
        for id in 0..count {
            assert_eq!(read(&vm, 0x580 + u64::from(id) * 4), 0x534d5052);
        }
    }
}

#[test]
fn el_torito_firmware_placement_preserves_the_boot_image_and_fails_on_full_overlap() {
    let image = vec![0xa5; 512];
    let (vm, _iso) = cold_image(BackendKind::Emulator, 2, &el_torito(0xf000, &image)).unwrap();
    let mut readback = vec![0; image.len()];
    vm.guest_mem()
        .memory()
        .read_slice(&mut readback, GuestAddress(0xf0000))
        .unwrap();
    assert_eq!(readback, image);
    assert_eq!(read(&vm, 0xf0200), u32::from_le_bytes(*b"_MP_"));
    assert_eq!(read(&vm, 0xf0204), 0xf0210);
    let full_window = el_torito(0xf000, &vec![0xa5; 0x10000]);
    let Err(error) = cold_image(BackendKind::Emulator, 2, &full_window) else {
        panic!("SMP cannot publish an MP pointer outside its BIOS discovery window");
    };
    assert!(error.to_string().contains("reserved BIOS memory"));
    let (single, _iso) = cold_image(BackendKind::Emulator, 1, &full_window).unwrap();
    assert_eq!(read(&single, 0xf0000), 0xa5a5a5a5);
    assert_eq!(read(&single, 0xffffc), 0xa5a5a5a5);
}

#[test]
fn cold_software_pc_publishes_an_explicit_mp_pointer_for_every_configured_cpu() {
    for count in [1, 2, 4] {
        let (vm, _kernel) = cold(count);
        let mut pointer = [0; 16];
        vm.guest_mem()
            .memory()
            .read_slice(&mut pointer, GuestAddress(0xf0000))
            .unwrap();
        assert_eq!(&pointer[..4], b"_MP_", "{count}-CPU cold PC discovery");
        assert_eq!(
            pointer
                .iter()
                .fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
        assert_eq!(&pointer[8..10], &[1, 4]);
        let address = u64::from(u32::from_le_bytes(pointer[4..8].try_into().unwrap()));
        let mut header = [0; 44];
        vm.guest_mem()
            .memory()
            .read_slice(&mut header, GuestAddress(address))
            .unwrap();
        assert_eq!(&header[..4], b"PCMP");
        let length = u16::from_le_bytes(header[4..6].try_into().unwrap());
        assert_eq!(length, 44 + u16::from(count) * 20 + 19 * 8);
        let mut table = vec![0; usize::from(length)];
        vm.guest_mem()
            .memory()
            .read_slice(&mut table, GuestAddress(address))
            .unwrap();
        assert_eq!(
            table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
        assert_eq!(
            u16::from_le_bytes(table[34..36].try_into().unwrap()),
            u16::from(count) + 19
        );
        for id in 0..count {
            let record = &table[44 + usize::from(id) * 20..][..20];
            assert_eq!(&record[..4], &[0, id, 0x14, if id == 0 { 3 } else { 1 }]);
        }
        let io = &table[44 + usize::from(count) * 20 + 8..][..8];
        assert_eq!(io, &[2, 0, 0x20, 1, 0, 0, 0xc0, 0xfe]);
    }
}

fn install_guest(vm: &Vmm) {
    let mut image = vec![0; 0x200];
    image.extend_from_slice(guest::DISCOVERY);
    assert!(image.len() <= 0x400);
    image.resize(0x400, 0);
    image.extend_from_slice(guest::BSP);
    image.resize(0x1200, 0);
    image.extend_from_slice(guest::AP);
    vm.guest_mem()
        .memory()
        .write_slice(&image, GuestAddress(0x1000000))
        .unwrap();
}

fn read(vm: &Vmm, address: u64) -> u32 {
    vm.guest_mem()
        .memory()
        .read_obj(GuestAddress(address))
        .unwrap()
}

#[test]
fn guest_discovers_one_two_four_cpus_from_firmware_then_starts_and_interrupts_every_ap() {
    for count in [1, 2, 4] {
        let (mut vm, _kernel) = cold(count);
        install_guest(&vm);
        assert_eq!(
            read(&vm, 0x210000),
            0,
            "host must not supply a guest CPU count"
        );
        vm.run().unwrap();
        assert_eq!(
            read(&vm, 0x210000),
            u32::from(count),
            "discovery marker={:#x}; CPU={:#x?}",
            read(&vm, 0x210004),
            vm.vcpus[0].get_state()
        );
        assert_eq!(
            read(&vm, 0x210004),
            0x600d600d,
            "firmware or AP startup failed"
        );
        for id in 0..count {
            assert_eq!(read(&vm, 0x200000 + u64::from(id) * 8), 0xa5a55a5a);
            assert_eq!(
                read(&vm, 0x200004 + u64::from(id) * 8),
                if id == 0 { 0 } else { 2 }
            );
            assert_eq!(read(&vm, 0x220000 + u64::from(id) * 4), u32::from(id));
            assert_eq!(read(&vm, 0x250000 + u64::from(id) * 4), u32::from(id));
        }
    }
}

#[test]
fn guest_rejects_checksum_valid_cpu_and_irq_mismatches_before_starting_any_ap() {
    for (offset, mask) in [
        (44 + 4, 1),
        (44 + 20 + 1, 3),
        (44 + 40 + 8 + 2, 1),
        (44 + 40 + 16 + 7, 2),
    ] {
        let (mut vm, _kernel) = cold(2);
        install_guest(&vm);
        let mut table = vec![0; 44 + 40 + 19 * 8];
        vm.guest_mem()
            .memory()
            .read_slice(&mut table, GuestAddress(0xf0010))
            .unwrap();
        table[offset] ^= mask;
        table[7] = 0;
        table[7] = 0u8.wrapping_sub(table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        vm.guest_mem()
            .memory()
            .write_slice(&table, GuestAddress(0xf0010))
            .unwrap();
        vm.run().unwrap();
        assert_eq!(read(&vm, 0x210004), 0xbad00bad, "corruption at {offset}");
        assert_eq!(read(&vm, 0x200008), 0, "AP must remain unstarted");
        assert_eq!(vm.coordinator.online, [true, false]);
    }
}

#[test]
fn source_free_resume_preserves_guest_modified_firmware_ram_instead_of_republishing() {
    let (vm, kernel) = cold(2);
    let marker = [0xa5; 64];
    vm.guest_mem()
        .memory()
        .write_slice(&marker, GuestAddress(0xf0000))
        .unwrap();
    let saved = vm.take_snapshot_bundle(0).unwrap();
    drop(vm);
    drop(kernel);
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    let restored = Vmm::new_resume_bundle(config, &saved).unwrap();
    let mut actual = [0; 64];
    restored
        .guest_mem()
        .memory()
        .read_slice(&mut actual, GuestAddress(0xf0000))
        .unwrap();
    assert_eq!(actual, marker);
}

#[test]
fn ioapic_private_policy_cannot_restore_without_its_controller_image() {
    let (mut vm, kernel) = cold(1);
    let mut saved = vm.take_snapshot_bundle(0).unwrap();
    assert!(
        saved.backend_contexts().unwrap().entries()[0]
            .as_ref()
            .unwrap()
            .data
            .starts_with(b"RAXX8604")
    );
    let checkpoint = Kernel(kernel.0.with_extension("rxc"));
    saved.save(&checkpoint.0).unwrap();
    let valid_file = std::fs::read(&checkpoint.0).unwrap();
    saved.take_execution();
    let before = crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap();
    vm.guest_mem()
        .memory()
        .write_obj(0xa55au32, GuestAddress(0x210004))
        .unwrap();
    for error in [
        saved.save(&checkpoint.0).unwrap_err(),
        vm.restore_snapshot_bundle(&saved).unwrap_err(),
    ] {
        assert!(
            error
                .to_string()
                .contains("requires the PC controller image"),
            "{error}"
        );
    }
    assert_eq!(std::fs::read(&checkpoint.0).unwrap(), valid_file);
    assert_eq!(read(&vm, 0x210004), 0xa55a);
    assert_eq!(
        crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap(),
        before
    );
}
