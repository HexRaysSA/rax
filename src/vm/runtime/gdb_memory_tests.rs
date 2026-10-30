//! Actual RSP access to different per-CPU higher-half address spaces.
use super::*;
const ADDRESS: u64 = 0xffff_8000_0040_0000;
fn listen_mapped(setup: impl FnOnce(&mut Fixture) + Send + 'static) -> Running {
    Running::configured(2, move |f| {
        for (address, value) in [
            (0x1800, 0x4003),
            (0x4000, 0x5003),
            (0x5010, 0x6003),
            (0x6000, 0xa001),
            (0x6008, 0xc001),
            (0x7000, 0x2003),
            (0x7800, 0xd003),
            (0xd000, 0xe003),
            (0xe010, 0xf003),
            (0xf000, 0xb001),
        ] {
            f.write(address, &u64::to_le_bytes(value));
        }
        f.write(0xa000, b"CPU0DATA");
        f.write(0xb000, b"CPU1DATA");
        let CpuState::X86_64(mut state) = f.vm.vcpus[1].get_state().unwrap() else {
            unreachable!()
        };
        state.sregs.cr3 = 0x7000;
        f.vm.vcpus[1].set_state(&CpuState::X86_64(state)).unwrap();
        setup(f);
    })
}
fn mapped() -> Running {
    let mut vm = listen_mapped(|_| {});
    let stream = TcpStream::connect(vm.address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    vm.stream = Some(stream);
    vm
}
#[test]
fn higher_half_reads_use_the_selected_cpus_cr3() {
    let mut vm = mapped();
    assert_eq!(vm.packet("Hg1"), "OK");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553044415441");
    assert_eq!(vm.packet("Hg2"), "OK");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553144415441");
}
#[test]
fn debugger_writes_resolve_the_ap_read_only_mapping_without_touching_the_bsp() {
    let mut vm = mapped();
    assert_eq!(vm.packet("Hg2"), "OK");
    assert_eq!(vm.packet(&format!("M{ADDRESS:x},4:41424344")), "OK");
    assert_eq!(vm.packet("mb000,8"), "4142434444415441");
    assert_eq!(vm.packet("ma000,8"), "4350553044415441");
}
#[test]
fn inspection_does_not_set_accessed_or_dirty_bits() {
    let mut vm = mapped();
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553044415441");
    for (address, expected) in [
        (0x1800, "0340000000000000"),
        (0x4000, "0350000000000000"),
        (0x5010, "0360000000000000"),
        (0x6000, "01a0000000000000"),
    ] {
        assert_eq!(vm.packet(&format!("m{address:x},8")), expected);
    }
}

#[test]
fn crossing_pages_writes_discontiguous_physical_frames() {
    let mut vm = mapped();
    assert_eq!(
        vm.packet(&format!("M{:x},4:11223344", ADDRESS + 0xffe)),
        "OK"
    );
    assert_eq!(vm.packet("maffe,2"), "1122");
    assert_eq!(vm.packet("mc000,2"), "3344");
    assert_eq!(vm.packet("mb000,8"), "4350553144415441");
    assert_eq!(vm.packet(&format!("m{:x},4", ADDRESS + 0xffe)), "11223344");
}
#[test]
fn absent_later_page_rejects_the_whole_write_without_publishing_a_prefix() {
    let mut vm = mapped();
    assert_eq!(vm.packet("Hg2"), "OK");
    assert_eq!(vm.packet("Mbffe,2:7788"), "OK");
    assert_eq!(
        vm.packet(&format!("M{:x},4:11223344", ADDRESS + 0xffe)),
        "E01"
    );
    assert_eq!(vm.packet("mbffe,2"), "7788");
    assert_eq!(vm.packet("mf000,8"), "01b0000000000000");
    assert_eq!(vm.packet(&format!("m{:x},4", ADDRESS + 0xffe)), "E01");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553144415441");
}
#[test]
fn rejected_packet_lengths_and_addresses_preserve_memory_and_registers() {
    let mut vm = mapped();
    let registers = vm.packet("g");
    for packet in [
        format!("M{ADDRESS:x},5:41424344"),
        format!("M{ADDRESS:x},3:41424344"),
        "M800000000000,1:ab".into(),
        "Mffffffffffffffff,2:abcd".into(),
        "m800000000000,1".into(),
        "mffffffffffffffff,2".into(),
        format!("m{ADDRESS:x},4096"),
    ] {
        assert_eq!(vm.packet(&packet), "E01", "{packet}");
    }
    assert_eq!(vm.packet("g"), registers);
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553044415441");
}
#[test]
fn reserved_pte_rejection_is_inspection_only_and_repairable() {
    let mut vm = mapped();
    // Bit 48 exceeds this software CPU's advertised 48-bit physical width.
    assert_eq!(vm.packet("M6000,8:01a0000000000100"), "OK");
    let registers = vm.packet("g");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "E01");
    assert_eq!(vm.packet(&format!("M{ADDRESS:x},4:41424344")), "E01");
    assert_eq!(vm.packet("g"), registers);
    assert_eq!(vm.packet("ma000,8"), "4350553044415441");
    assert_eq!(vm.packet("M6000,8:01a0000000000000"), "OK");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553044415441");
}
#[test]
fn debugger_write_keeps_all_page_walk_status_bits_clear() {
    let mut vm = mapped();
    assert_eq!(vm.packet("Hg2"), "OK");
    assert_eq!(vm.packet(&format!("M{ADDRESS:x},4:41424344")), "OK");
    for (address, expected) in [
        (0x7800, "03d0000000000000"),
        (0xd000, "03e0000000000000"),
        (0xe010, "03f0000000000000"),
        (0xf000, "01b0000000000000"),
    ] {
        assert_eq!(vm.packet(&format!("m{address:x},8")), expected);
    }
}
#[test]
fn explicit_physical_mode_overrides_translation_and_rejects_bad_values() {
    let mut vm = mapped();
    assert_eq!(vm.packet("qqemu.PhyMemMode"), "0");
    assert_eq!(vm.packet("Qqemu.PhyMemMode:1"), "OK");
    assert_eq!(vm.packet("qqemu.PhyMemMode"), "1");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "E01");
    assert_eq!(vm.packet("ma000,8"), "4350553044415441");
    assert_eq!(vm.packet("Qqemu.PhyMemMode:2"), "E01");
    assert_eq!(vm.packet("qqemu.PhyMemMode"), "1");
    assert_eq!(vm.packet("Qqemu.PhyMemMode:0"), "OK");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553044415441");
}
#[test]
fn reconnect_resets_physical_memory_mode() {
    let mut vm = mapped();
    assert_eq!(vm.packet("Qqemu.PhyMemMode:1"), "OK");
    assert_eq!(vm.packet("D"), "OK");
    let _ = vm.stream.take().unwrap().shutdown(Shutdown::Both);
    let stream = TcpStream::connect(vm.address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    vm.stream = Some(stream);
    assert_eq!(vm.packet("qqemu.PhyMemMode"), "0");
    assert_eq!(vm.packet("Hg1"), "OK");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553044415441");
}
#[test]
fn any_cpu_selector_preserves_the_explicit_general_cpu_for_memory() {
    let mut vm = mapped();
    assert_eq!(vm.packet("Hg2"), "OK");
    assert_eq!(vm.packet("Hg0"), "OK");
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553144415441");
}

#[test]
fn debugger_write_invalidates_a_peers_cached_code_through_another_virtual_alias() {
    let mut vm = listen_mapped(|f| {
        f.write(0xf008, &0xa003u64.to_le_bytes());
        f.write(0xa000, &[0x48, 0xff, 0xc0, 0xeb, 0xfb]);
        let CpuState::X86_64(mut state) = f.vm.vcpus[1].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rip = ADDRESS + 0x1000;
        f.vm.vcpus[1].set_state(&CpuState::X86_64(state)).unwrap();
    });
    let stream = TcpStream::connect(vm.address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    vm.stream = Some(stream);
    assert_eq!(vm.packet("Hc2"), "OK");
    assert_eq!(vm.packet("s"), "T05thread:2;core:1;");
    assert_eq!(vm.rax(2), 0x102);
    assert_eq!(vm.packet("s"), "T05thread:2;core:1;");
    assert_eq!(vm.packet("Hg1"), "OK");
    assert_eq!(vm.packet(&format!("M{ADDRESS:x},3:48ffc8")), "OK");
    assert_eq!(vm.packet("s"), "T05thread:2;core:1;");
    assert_eq!(
        vm.rax(2),
        0x101,
        "peer executes DEC rather than its previously cached INC"
    );
    assert_eq!(vm.rax(1), 0x100);
}

#[test]
fn debugger_rejects_device_backing_and_page_tables_without_device_callbacks() {
    use crate::devices::bus::{MmioDevice, MmioRange};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Device(Arc<AtomicUsize>);
    impl MmioDevice for Device {
        fn read(&mut self, _address: u64, data: &mut [u8]) {
            self.0.fetch_add(1, Ordering::SeqCst);
            data.fill(0x55);
        }
        fn write(&mut self, _address: u64, _data: &[u8]) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    for physical in [0xa000, 0x6000] {
        let calls = Arc::new(AtomicUsize::new(0));
        let owned = calls.clone();
        let mut vm = listen_mapped(move |f| {
            f.vm.mmio_bus
                .register(
                    MmioRange {
                        base: physical,
                        len: 0x1000,
                    },
                    Box::new(Device(owned)),
                )
                .unwrap();
        });
        let stream = TcpStream::connect(vm.address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        vm.stream = Some(stream);
        assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "E01");
        assert_eq!(vm.packet(&format!("M{ADDRESS:x},4:41424344")), "E01");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(vm.packet("Hg2"), "OK");
        assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "4350553144415441");
    }
}
#[test]
#[ignore = "Requires RAX_GDB pointing to an installed GDB; explicitly run in the debugger CI lane"]
fn installed_gdb_uses_selected_cpu_virtual_memory_and_read_only_writes() {
    let vm = listen_mapped(|_| {});
    let script = r#"import gdb
inferior = gdb.selected_inferior()
assert len(inferior.threads()) == 2
high = 0xffff800000400000
gdb.execute('thread 1')
assert inferior.read_memory(high,8).tobytes() == b'CPU0DATA'
gdb.execute('thread 2')
assert inferior.read_memory(high,8).tobytes() == b'CPU1DATA'
inferior.write_memory(high,b'ABCD')
assert inferior.read_memory(high,8).tobytes() == b'ABCDDATA'
gdb.execute('thread 1')
assert inferior.read_memory(high,8).tobytes() == b'CPU0DATA'
assert inferior.read_memory(0xf000,8).tobytes() == bytes.fromhex('01b0000000000000')
print('RAX_GDB_MEMORY_OK')"#;
    super::client::run_script(vm, script, "RAX_GDB_MEMORY_OK");
}

#[test]
fn debugger_memory_matches_a_guest_load_from_modeled_backing_above_reported_ram() {
    let mut vm = listen_mapped(|f| {
        f.write(0x6000, &0x18001u64.to_le_bytes());
        f.write(0x18000, b"PADALIAS");
        let mut instruction = vec![0x48, 0xa1];
        instruction.extend_from_slice(&ADDRESS.to_le_bytes());
        instruction.extend_from_slice(&[0xeb, 0xfe]);
        f.write(BSP, &instruction);
    });
    let stream = TcpStream::connect(vm.address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    vm.stream = Some(stream);
    assert_eq!(vm.packet("Hc1"), "OK");
    assert_eq!(vm.packet("s"), "T05thread:1;core:0;");
    assert_eq!(vm.rax(1), u64::from_le_bytes(*b"PADALIAS"));
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "504144414c494153");
    assert_eq!(vm.packet(&format!("M{ADDRESS:x},4:41424344")), "OK");
    assert_eq!(vm.packet("m18000,8"), "414243444c494153");
    assert_eq!(vm.packet("Qqemu.PhyMemMode:1"), "OK");
    assert_eq!(vm.packet("m18000,8"), "414243444c494153");
}

#[test]
fn fixed_controller_and_unassigned_pci_aperture_do_not_expose_shadow_backing() {
    use std::sync::{Arc, Mutex};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    const ADDRESS: u64 = PCI_MMIO_AP_END - 0x10000;
    let backing = Arc::new(Mutex::new(None::<GuestMemoryMmap>));
    let observed = backing.clone();
    let mut vm = Running::with_fixture(
        2,
        || Fixture::with_pci(2),
        move |f| {
            let bridge = f.vm.pci_devices.as_ref().unwrap().bridge();
            assert!(
                bridge
                    .lock()
                    .unwrap()
                    .mmio_ranges()
                    .iter()
                    .all(|range| !range.contains(ADDRESS))
            );
            f.write(ADDRESS, b"SHADOW!!");
            f.write(LAPIC_BASE, b"SHADOW!!");
            f.write(0x2018, &0x10003u64.to_le_bytes());
            let pde = 0x10000 + ((ADDRESS >> 21) & 511) * 8;
            f.write(pde, &((ADDRESS & !0x1f_ffff) | 0x83).to_le_bytes());
            let mut instruction = vec![0x48, 0xa1];
            instruction.extend_from_slice(&ADDRESS.to_le_bytes());
            instruction.extend_from_slice(&[0xeb, 0xfe]);
            f.write(BSP, &instruction);
            *observed.lock().unwrap() = Some(f.vm.guest_mem.memory().clone());
        },
    );
    let stream = TcpStream::connect(vm.address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    vm.stream = Some(stream);
    assert_eq!(vm.packet("Hc1"), "OK");
    assert_eq!(vm.packet("s"), "T05thread:1;core:0;");
    assert_eq!(
        vm.rax(1),
        u64::MAX,
        "the actual guest sees unassigned PCI open bus, not shadow RAM"
    );
    assert_eq!(vm.packet(&format!("m{ADDRESS:x},8")), "E01");
    assert_eq!(vm.packet("Qqemu.PhyMemMode:1"), "OK");
    for address in [ADDRESS, LAPIC_BASE] {
        assert_eq!(vm.packet(&format!("m{address:x},8")), "E01");
        assert_eq!(vm.packet(&format!("M{address:x},4:41424344")), "E01");
        let mut bytes = [0; 8];
        backing
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .read_slice(&mut bytes, GuestAddress(address))
            .unwrap();
        assert_eq!(&bytes, b"SHADOW!!");
    }
}
