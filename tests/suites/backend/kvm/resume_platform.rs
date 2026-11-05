//! Rebuild the native PC profile before restoring source-free checkpoint CPUs.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::runtime::Vmm;
use rax::vm::snapshot::SnapshotBundle;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

static NEXT: AtomicU64 = AtomicU64::new(0);
const CHILD: &str = "RAX_KVM_RESUME_PLATFORM_CHILD";
const NAME: &str = "resume_platform::source_free_pc_checkpoint_keeps_native_profile_and_uart";
const FEATURES: u32 = (1 << 21) | (1 << 24);
const RESULT: u64 = 0x20_0000;
const FIRMWARE: u64 = 0x000f_0000;

struct Files(PathBuf);

impl Files {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rax-native-resume-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        // This directory was created exclusively by this fixture; no host
        // input or shared build directory is placed under it.
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn kernel() -> Vec<u8> {
    let code = [
        0xb8, 1, 0, 0, 0, // MOV EAX,1.
        0x31, 0xc9, // XOR ECX,ECX.
        0x0f, 0xa2, // CPUID.
        0x81, 0xe1, 0, 0, 0x20, 1, // AND ECX,x2APIC|TSC_DEADLINE.
        0x89, 0x0c, 0x25, 0, 0, 0x20, 0, // MOV [0x200000],ECX.
        0x66, 0xba, 0xf8, 3, // MOV DX,0x3f8.
        0xb0, b'S', 0xee, // UART write, including the real backend IRQ path.
        0x66, 0xba, 4, 6, // MOV DX,0x604.
        0x66, 0xb8, 0, 0x20, // MOV AX,0x2000.
        0x66, 0xef, // OUT DX,AX: actual VMM power-off service.
        0xf4,
    ];
    let mut image = vec![0; 0x1000 + code.len()];
    image[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    image[16..18].copy_from_slice(&2u16.to_le_bytes());
    image[18..20].copy_from_slice(&62u16.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[24..32].copy_from_slice(&0x10_0000u64.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&1u16.to_le_bytes());
    image[64..68].copy_from_slice(&1u32.to_le_bytes());
    image[68..72].copy_from_slice(&5u32.to_le_bytes());
    for (offset, value) in [
        (8, 0x1000),
        (16, 0x10_0000),
        (24, 0x10_0000),
        (32, code.len() as u64),
        (40, code.len() as u64),
        (48, 0x1000),
    ] {
        image[64 + offset..72 + offset].copy_from_slice(&value.to_le_bytes());
    }
    image[0x1000..].copy_from_slice(&code);
    image
}

fn features(vm: &Vmm) -> u32 {
    vm.guest_mem()
        .memory()
        .read_obj::<u32>(GuestAddress(RESULT))
        .unwrap()
}

#[test]
fn source_free_pc_checkpoint_keeps_native_profile_and_uart() {
    if std::env::var(CHILD).as_deref() != Ok(NAME) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, NAME)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return;
    }
    for count in [1, 2, 4] {
        let files = Files::new();
        let kernel_path = files.0.join("guest.elf");
        let checkpoint = files.0.join("machine.rxc");
        std::fs::write(&kernel_path, kernel()).unwrap();
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Kvm),
                memory: Some(MemorySize(128 * 1024 * 1024)),
                kernel: Some(kernel_path.clone()),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let mut source = Vmm::new(config).unwrap();
        let canary = [0x5a; 1024];
        source
            .guest_mem()
            .memory()
            .write_slice(&canary, GuestAddress(FIRMWARE))
            .unwrap();
        let image = source.take_snapshot_bundle(0).unwrap();
        image.save(&checkpoint).unwrap();
        drop(image);
        source.run().unwrap();
        let expected = features(&source);
        assert_ne!(
            expected & FEATURES,
            0,
            "native APIC feature control is absent"
        );
        drop(source);
        std::fs::remove_file(&kernel_path).unwrap();
        let image = SnapshotBundle::load(&checkpoint).unwrap();
        std::fs::remove_file(&checkpoint).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&image, CliConfig::default()).unwrap();
        assert!(!config.kernel.exists());
        let mut target = Vmm::new_resume_bundle(config, &image).unwrap();
        assert_eq!(
            target.capture_cpu_states().unwrap().len(),
            usize::from(count)
        );
        let mut restored = [0; 1024];
        target
            .guest_mem()
            .memory()
            .read_slice(&mut restored, GuestAddress(FIRMWARE))
            .unwrap();
        assert_eq!(restored, canary);
        let result = target.run();
        let actual = features(&target);
        eprintln!(
            "native checkpoint CPUs={count}, source_ecx={expected:#x}, restored_ecx={actual:#x}, run={result:?}"
        );
        assert_eq!(actual, expected, "checkpoint changed native LAPIC CPUID");
        result.unwrap();
    }
}
