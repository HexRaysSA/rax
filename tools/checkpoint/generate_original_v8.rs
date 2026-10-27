use rax::config::{ArchKind, BackendKind, CliConfig, VmConfig};
use rax::vm::snapshot::{DeviceState, EmulatorState, Snapshot};
use rax::vm::vcpu::state::CpuState;
fn main() {
    let folder = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    let kernel = folder.join("kernel.input");
    std::fs::write(&kernel, [0u8; 64]).unwrap();
    rax::vm::timing::init();
    let mut retained = None;
    for flag in [false, true] {
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                pci_devices: flag,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let mut captured = config.to_checkpoint();
        captured.memory_bytes = 4096;
        let snapshot = retained.get_or_insert_with(|| Snapshot {
            version: 8,
            config: captured.clone(),
            instruction_count: 123456789,
            elapsed_nanos: 987654321,
            cpu_state: CpuState::x86_64(Default::default(), Default::default()),
            emulator_state: EmulatorState::default(),
            devices: DeviceState {
                pic: rax::devices::pic::DualPic::new(),
                pit: rax::devices::pit::Pit::new(),
                serial: rax::devices::serial::Serial16550::new(0x3f8),
                lapic: rax::devices::lapic::LocalApic::new(0),
            },
            memory_size: 4096,
            memory_data: zstd::encode_all(&[0xa5u8; 4096][..], 3).unwrap(),
        });
        snapshot.config = captured;
        let mut bytes = b"RAXCKPT\0".to_vec();
        bytes.extend(bincode::serialize(snapshot).unwrap());
        std::fs::write(folder.join(format!("legacy-v8-pci-{flag}.rxc")), bytes).unwrap();
    }
}
