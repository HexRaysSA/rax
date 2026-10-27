//! Publish deterministic payloads using the product's public checkpoint API.
use rax::config::{ArchKind, BackendKind, CliConfig, VmConfig};
use rax::vm::snapshot::{DeviceState, EmulatorState, Snapshot};
use rax::vm::vcpu::state::CpuState;
fn main() {
    let folder = std::path::PathBuf::from(std::env::args_os().nth(1).expect("outputdirectory"));
    std::fs::create_dir_all(&folder).unwrap();
    let kernel = folder.join("kernel.input");
    std::fs::write(&kernel, [0; 64]).unwrap();
    rax::vm::timing::init();
    for (i, arch) in [ArchKind::X86_64, ArchKind::Aarch64, ArchKind::Riscv64]
        .into_iter()
        .enumerate()
    {
        for pci in [false, true] {
            let config = VmConfig::from_sources(
                CliConfig {
                    arch: Some(arch),
                    backend: Some(BackendKind::Emulator),
                    kernel: Some(kernel.clone()),
                    pci_devices: pci,
                    cmdline: Some("checkpoint-wire-oracle".to_string()),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
            let mut config = config.to_checkpoint();
            config.memory_bytes = 4096;
            let cpu = match arch {
                ArchKind::X86_64 => CpuState::x86_64(Default::default(), Default::default()),
                ArchKind::Aarch64 => {
                    let cpu = rax::isa::arm::aarch64::AArch64Cpu::new(
                        Default::default(),
                        Box::new(rax::isa::arm::common::memory::FlatMemory::new(0, 4096)),
                    );
                    CpuState::aarch64(Default::default(), cpu.export_sregs())
                }
                ArchKind::Riscv64 => CpuState::riscv(Default::default()),
                _ => unreachable!(),
            };
            let data = vec![0x30 + i as u8 + u8::from(pci); 4096];
            let snapshot = Snapshot::new(
                config,
                123456789 + i as u64,
                987654321 + i as u64,
                cpu,
                EmulatorState::default(),
                DeviceState {
                    pic: rax::devices::pic::DualPic::new(),
                    pit: rax::devices::pit::Pit::new(),
                    serial: rax::devices::serial::Serial16550::new(0x3f8),
                    lapic: rax::devices::lapic::LocalApic::new(0),
                },
                &data,
            )
            .unwrap();
            let name = format!("case-{}-{}.rxc", i, u8::from(pci));
            snapshot.save(folder.join(name)).unwrap();
        }
    }
    let nvme = folder.join("nvme.raw");
    let ahci = folder.join("ahci.raw");
    std::fs::write(&nvme, vec![0xa3; 512]).unwrap();
    std::fs::write(&ahci, vec![0xb9; 1024]).unwrap();
    use rax::config::{ImageAccess, MemorySize};
    for (index, nmode, amode) in [
        (0, Some(ImageAccess::ReadOnly), None),
        (1, None, Some(ImageAccess::ReadWrite)),
        (
            2,
            Some(ImageAccess::CopyOnWrite),
            Some(ImageAccess::CopyOnWrite),
        ),
        (3, Some(ImageAccess::ReadWrite), Some(ImageAccess::ReadOnly)),
    ] {
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                cmdline: Some("checkpoint-image-wire-oracle".to_string()),
                nvme_image: nmode.map(|_| nvme.clone()),
                nvme_image_mode: nmode,
                nvme_image_limit: nmode.map(|_| MemorySize(16384)),
                ahci_image: amode.map(|_| ahci.clone()),
                ahci_image_mode: amode,
                ahci_image_limit: amode.map(|_| MemorySize(16384)),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let mut config = config.to_checkpoint();
        config.memory_bytes = 4096;
        let snapshot = Snapshot::new(
            config,
            2000 + index,
            3000 + index,
            CpuState::x86_64(Default::default(), Default::default()),
            EmulatorState::default(),
            DeviceState {
                pic: rax::devices::pic::DualPic::new(),
                pit: rax::devices::pit::Pit::new(),
                serial: rax::devices::serial::Serial16550::new(0x3f8),
                lapic: rax::devices::lapic::LocalApic::new(0),
            },
            &vec![0x70 + index as u8; 4096],
        )
        .unwrap();
        snapshot
            .save(folder.join(format!("image-case-{index}.rxc")))
            .unwrap();
    }
}
