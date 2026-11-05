//! Native RAM registration and PC firmware/layout regressions.
use linux_loader::loader::bootparam::{boot_e820_entry, boot_params};
use rax::backend::{
    Backend,
    kvm::{KvmBackend, KvmVm},
};
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::machine::{Machine, pc::PcMachine};
use rax::vm::Vmm;
use rax::vm::memory::GuestMemoryWrapper;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

fn assert_access(name: &str, address: u64, store: bool, ram: bool) {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    let memory = GuestMemoryWrapper::new(0xc000_1000).unwrap();
    native.register_memory(&memory).unwrap();
    native.set_tss_address(0xc000_1000).unwrap();
    native.set_identity_map_address(0xc000_0000).unwrap();
    memory
        .memory()
        .write_obj(0x3001u64, GuestAddress(0x2000))
        .unwrap();
    memory
        .memory()
        .write_obj(0x83u64, GuestAddress(0x3000))
        .unwrap();
    memory
        .memory()
        .write_obj(address & !0x1f_ffff | 0x83, GuestAddress(0x3800))
        .unwrap();
    memory
        .memory()
        .write_obj(0x1234_5678u32, GuestAddress(address))
        .unwrap();
    let displacement = 0x2000_0000u32 + (address & 0x1f_ffff) as u32;
    let mut code = if store { vec![0xc7, 0x05] } else { vec![0xa1] };
    code.extend_from_slice(&displacement.to_le_bytes());
    if store {
        code.extend_from_slice(&0xdead_beefu32.to_le_bytes());
    }
    code.extend_from_slice(&[0xe6, 0x80, 0xf4]);
    memory
        .memory()
        .write_slice(&code, GuestAddress(0x1000))
        .unwrap();
    let mut cpu = native.create_vcpu_fd(0).unwrap();
    cpu.set_cpuid2(
        &native
            .kvm()
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap(),
    )
    .unwrap();
    cpu.set_mp_state(kvm_bindings::kvm_mp_state {
        mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
    })
    .unwrap();
    let mut s = cpu.get_sregs().unwrap();
    let code_segment = kvm_bindings::kvm_segment {
        base: 0,
        limit: u32::MAX,
        selector: 8,
        type_: 11,
        present: 1,
        dpl: 0,
        db: 1,
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    };
    s.cs = code_segment;
    let data_segment = kvm_bindings::kvm_segment {
        selector: 16,
        type_: 3,
        ..code_segment
    };
    s.ds = data_segment;
    s.es = data_segment;
    s.fs = data_segment;
    s.gs = data_segment;
    s.ss = data_segment;
    s.cr0 = 0x8000_0011;
    s.cr3 = 0x2000;
    s.cr4 = 0x20;
    s.efer = 0;
    cpu.set_sregs(&s).unwrap();
    cpu.set_regs(&kvm_bindings::kvm_regs {
        rip: 0x1000,
        rsp: 0x8000,
        rflags: 2,
        ..Default::default()
    })
    .unwrap();
    let event = match cpu.run().unwrap() {
        kvm_ioctls::VcpuExit::IoOut(port, data) => {
            serde_json::json!({"kind":"io","port":port,"data":data})
        }
        kvm_ioctls::VcpuExit::MmioRead(gpa, data) => {
            serde_json::json!({"kind":"mmio-read","gpa":gpa,"bytes":data.len()})
        }
        kvm_ioctls::VcpuExit::MmioWrite(gpa, data) => {
            serde_json::json!({"kind":"mmio-write","gpa":gpa,"bytes":data.len(),"data":data})
        }
        other => serde_json::json!({"kind":"other","exit":format!("{other:?}")}),
    };
    let regs = cpu.get_regs().unwrap();
    let backing: u32 = memory.memory().read_obj(GuestAddress(address)).unwrap();
    println!(
        "native_ram_case={name} address={address:#x} event={event} rax={:#x} backing={backing:#x}",
        regs.rax
    );
    if ram {
        assert_eq!(
            event["kind"], "io",
            "configured RAM must complete before its I/O result"
        );
        assert_eq!(event["port"], 0x80);
        if store {
            assert_eq!(backing, 0xdead_beef);
        } else {
            assert_eq!(regs.rax, 0x1234_5678);
        }
    } else {
        assert_eq!(event["kind"], "mmio-read");
        assert_eq!(event["gpa"], address);
        assert_eq!(backing, 0x1234_5678);
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn high_ram_reads_execute_without_mmio() {
    assert_access(
        "high_ram_reads_execute_without_mmio",
        0x100000000,
        false,
        true,
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn high_ram_writes_reach_the_registered_backing() {
    assert_access(
        "high_ram_writes_reach_the_registered_backing",
        0x100000000,
        true,
        true,
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn pci_window_remains_mmio() {
    assert_access("pci_window_remains_mmio", 0xc2000000, false, false);
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn padding_after_high_ram_remains_mmio() {
    assert_access(
        "padding_after_high_ram_remains_mmio",
        0x100001000,
        false,
        false,
    );
}

static NEXT_INPUT: AtomicU64 = AtomicU64::new(0);
struct Input(PathBuf);
impl Input {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rax-pc-ram-{}-{}",
            std::process::id(),
            NEXT_INPUT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        Self(path)
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn elf(second: Option<(u64, u64, u64, u64)>) -> Vec<u8> {
    let mut image = vec![0; if second.is_some() { 0x2010 } else { 0x1010 }];
    image[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    image[16..18].copy_from_slice(&2u16.to_le_bytes());
    image[18..20].copy_from_slice(&62u16.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[24..32].copy_from_slice(&0x100000u64.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&(if second.is_some() { 2u16 } else { 1 }).to_le_bytes());
    let mut headers = vec![(0x100000u64, 0x1000u64, 16u64, 4096u64)];
    headers.extend(second);
    for (index, (address, offset, file_size, memory_size)) in headers.into_iter().enumerate() {
        let at = 64 + index * 56;
        image[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        image[at + 4..at + 8].copy_from_slice(&5u32.to_le_bytes());
        for (field, value) in [
            (8, offset),
            (16, address),
            (24, address),
            (32, file_size),
            (40, memory_size),
            (48, 4096),
        ] {
            image[at + field..at + field + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    image[0x1000] = 0xf4;
    if second.is_some() {
        image[0x2000..0x2010].fill(0xa5);
    }
    image
}

fn config(bytes: u64, kernel: &Input, initrd: &Input) -> VmConfig {
    let mut config = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Kvm),
            kernel: Some(kernel.0.clone()),
            initrd: Some(initrd.0.clone()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    config.memory = MemorySize(bytes);
    config
}

fn assert_initrd(vm: &Vmm) {
    let memory = vm.guest_mem().memory();
    let address: u32 = memory
        .read_obj(GuestAddress(
            0x7000 + std::mem::offset_of!(boot_params, hdr.ramdisk_image) as u64,
        ))
        .unwrap();
    let size: u32 = memory
        .read_obj(GuestAddress(
            0x7000 + std::mem::offset_of!(boot_params, hdr.ramdisk_size) as u64,
        ))
        .unwrap();
    assert_eq!(size, 64);
    assert!(u64::from(address) + u64::from(size) <= 0xc000_0000 - 0x4000);
    let mut data = [0; 64];
    memory
        .read_slice(&mut data, GuestAddress(u64::from(address)))
        .unwrap();
    assert_eq!(
        data, [0x5a; 64],
        "the published pointer must name the actual payload"
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn cold_elf_e820_and_initrd_match_the_registered_pc_ram_intervals() {
    for bytes in [0xc000_1000u64, 0x1_0000_0000, 0x1_4000_0000] {
        let kernel = Input::new(&elf(None));
        let initrd = Input::new(&[0x5a; 64]);
        let vm = Vmm::new(config(bytes, &kernel, &initrd)).unwrap();
        assert_initrd(&vm);
        let memory = vm.guest_mem().memory();
        let count: u8 = memory
            .read_obj(GuestAddress(
                0x7000 + std::mem::offset_of!(boot_params, e820_entries) as u64,
            ))
            .unwrap();
        assert!(count >= 4);
        let mut rows = Vec::new();
        for index in 0..u64::from(count) {
            let at = 0x7000
                + std::mem::offset_of!(boot_params, e820_table) as u64
                + index * std::mem::size_of::<boot_e820_entry>() as u64;
            let address: u64 = memory.read_obj(GuestAddress(at)).unwrap();
            let size: u64 = memory.read_obj(GuestAddress(at + 8)).unwrap();
            let kind: u32 = memory.read_obj(GuestAddress(at + 16)).unwrap();
            rows.push((address, size, kind));
        }
        println!("native_pc_ram_bytes={bytes} e820={rows:x?}");
        assert!(
            rows.windows(2)
                .all(|pair| pair[0].0 + pair[0].1 <= pair[1].0)
        );
        assert!(
            rows.iter()
                .filter(|row| row.2 == 1)
                .all(|row| row.0 + row.1 <= 0xc000_0000 || row.0 >= 0x1_0000_0000)
        );
        assert!(rows.contains(&(0x1_0000_0000, bytes - 0xc000_0000, 1)));
        let usable: u64 = rows.iter().filter(|row| row.2 == 1).map(|row| row.1).sum();
        assert_eq!(usable, bytes - (0x100000 - 0x9fc00) - 0x4000);
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn high_elf_data_and_bss_preserve_low_initrd_placement() {
    let kernel = Input::new(&elf(Some((0x1_0000_0000, 0x2000, 16, 4096))));
    let initrd = Input::new(&[0x5a; 64]);
    let vm = Vmm::new(config(0xc000_1000, &kernel, &initrd)).unwrap();
    assert_initrd(&vm);
    let mut high = [0; 4096];
    vm.guest_mem()
        .memory()
        .read_slice(&mut high, GuestAddress(0x1_0000_0000))
        .unwrap();
    assert_eq!(&high[..16], &[0xa5; 16]);
    assert!(high[16..].iter().all(|byte| *byte == 0));
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn invalid_elf_extent_does_not_publish_an_earlier_segment() {
    for second in [
        (0xc200_0000, 0x2000, 16, 4096),
        (0x1_0000_0000, 0x4000, 16, 4096),
        (0x1_0000_0000, 0x2000, 16, 8),
    ] {
        let kernel = Input::new(&elf(Some(second)));
        let initrd = Input::new(&[0x5a; 64]);
        let config = config(0xc000_1000, &kernel, &initrd);
        let memory = GuestMemoryWrapper::new(config.memory.bytes()).unwrap();
        memory
            .memory()
            .write_slice(&[0xcc; 64], GuestAddress(0x100000))
            .unwrap();
        assert!(
            PcMachine::new()
                .load_kernel(memory.memory(), &config)
                .is_err()
        );
        let mut first = [0; 64];
        memory
            .memory()
            .read_slice(&mut first, GuestAddress(0x100000))
            .unwrap();
        assert_eq!(first, [0xcc; 64]);
    }
}

fn run_elf_entry_case(virtual_entry: bool, physical: u64, name: &str) {
    const CHILD: &str = "RAX_KVM_ELF_ENTRY_TEST_CHILD";
    if std::env::var(CHILD).as_deref() != Ok(name) {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--include-ignored",
                "--exact",
                name,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() >= Duration::from_secs(40) {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "owned ELF entry guest exceeded40s: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    // This virtual base has no bootstrap alias. The target's physical address
    // is independently covered by the board's initial identity mapping.
    let virtual_base = 0xffff_9200_0000_0000u64;
    let entry = if virtual_entry {
        virtual_base + 8
    } else {
        physical + 8
    };
    let high = physical >= 0x1_0000_0000;
    let header = if high { 120 } else { 64 };
    let offset = if high { 0x2000 } else { 0x1000 };
    let mut image = elf(high.then_some((physical, offset as u64, 64, 4096)));
    image.resize(offset + 64, 0);
    image[24..32].copy_from_slice(&entry.to_le_bytes());
    image[header + 16..header + 24].copy_from_slice(&virtual_base.to_le_bytes());
    image[header + 32..header + 40].copy_from_slice(&64u64.to_le_bytes());
    image[offset + 8..offset + 30].copy_from_slice(&[
        0xc7, 0x04, 0x25, 0x00, 0x00, 0x20, 0x00, 0x79, 0x72, 0x74, 0x6e, // marker
        0x66, 0xba, 0x04, 0x06, // DX = PM1 control
        0x66, 0xb8, 0x00, 0x20, // AX = S5
        0x66, 0xef, 0xf4,
    ]);
    let kernel = Input::new(&image);
    let initrd = Input::new(&[0x5a; 64]);
    let bytes = if high {
        physical - 0x4000_0000 + 4096
    } else {
        64 << 20
    };
    let mut vm = Vmm::new(config(bytes, &kernel, &initrd)).unwrap();
    vm.run().unwrap();
    let marker: u32 = vm
        .guest_mem()
        .memory()
        .read_obj(GuestAddress(0x200000))
        .unwrap();
    assert_eq!(
        marker, 0x6e74_7279,
        "native ELF entry did not execute its payload"
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn virtual_elf_entry_executes_the_matching_physical_load_segment() {
    run_elf_entry_case(
        true,
        0x100000,
        "memory_layout::virtual_elf_entry_executes_the_matching_physical_load_segment",
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn legacy_physical_elf_entry_retains_native_execution() {
    run_elf_entry_case(
        false,
        0x100000,
        "memory_layout::legacy_physical_elf_entry_retains_native_execution",
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn high_virtual_elf_entry_executes_above_four_gib() {
    run_elf_entry_case(
        true,
        0x1_0000_0000,
        "memory_layout::high_virtual_elf_entry_executes_above_four_gib",
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn legacy_physical_elf_entry_executes_at_ram_capacity() {
    run_elf_entry_case(
        false,
        (65 << 30) - 4096,
        "memory_layout::legacy_physical_elf_entry_executes_at_ram_capacity",
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn elf_entry_outside_load_segments_rejects_before_any_segment_write() {
    for entry in [0xfff0u64, u64::MAX] {
        let mut image = elf(None);
        image[24..32].copy_from_slice(&entry.to_le_bytes());
        let kernel = Input::new(&image);
        let initrd = Input::new(&[0x5a; 64]);
        let config = config(64 << 20, &kernel, &initrd);
        let memory = GuestMemoryWrapper::new(config.memory.bytes()).unwrap();
        memory
            .memory()
            .write_slice(&[0xcc; 64], GuestAddress(0x100000))
            .unwrap();
        assert!(
            PcMachine::new()
                .load_kernel(memory.memory(), &config)
                .is_err()
        );
        let mut first = [0; 64];
        memory
            .memory()
            .read_slice(&mut first, GuestAddress(0x100000))
            .unwrap();
        assert_eq!(first, [0xcc; 64]);
    }
}
