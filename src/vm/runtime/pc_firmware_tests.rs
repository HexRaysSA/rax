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
    file.write_all(&[0; 64]).unwrap();
    drop(file);
    let config = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Emulator),
            vcpus: Some(count),
            memory: Some(MemorySize(128 * 1024 * 1024)),
            kernel: Some(kernel.0.clone()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    (Vmm::new(config).unwrap(), kernel)
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
    let (mut vm, _kernel) = cold(1);
    let mut saved = vm.take_snapshot_bundle(0).unwrap();
    assert!(
        saved.backend_contexts().unwrap().entries()[0]
            .as_ref()
            .unwrap()
            .data
            .starts_with(b"RAXX8604")
    );
    saved.take_execution();
    let before = crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap();
    vm.guest_mem()
        .memory()
        .write_obj(0xa55au32, GuestAddress(0x210004))
        .unwrap();
    let error = vm.restore_snapshot_bundle(&saved).unwrap_err().to_string();
    assert!(
        error.contains("requires the PC controller image"),
        "{error}"
    );
    assert_eq!(read(&vm, 0x210004), 0xa55a);
    assert_eq!(
        crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap(),
        before
    );
}
