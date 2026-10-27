//! Same existing public-API observer for predecessor/current VM clock isolation.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::runtime::Vmm;
pub const BASE: u64 = 1_000_000_000_000_000;
pub fn observe(directory: &std::path::Path) -> [u64; 4] {
    std::fs::create_dir_all(directory).unwrap();
    let kernel = directory.join("kernel.bin");
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
    config.memory = MemorySize(4096);
    let mut left = Vmm::new_resume(config.clone()).unwrap();
    let right = Vmm::new_resume(config).unwrap();
    let before = right.take_snapshot(0).unwrap().elapsed_nanos;
    let mut state = left.take_snapshot(0).unwrap();
    state.elapsed_nanos = BASE;
    left.restore_snapshot(&state).unwrap();
    let after = right.take_snapshot(0).unwrap().elapsed_nanos;
    let resumed = left.take_snapshot(0).unwrap().elapsed_nanos;
    std::fs::remove_file(kernel).unwrap();
    [BASE, before, after, resumed]
}
fn main() {
    let directory = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    let rows = observe(&directory);
    let bytes: Vec<_> = rows.into_iter().flat_map(u64::to_le_bytes).collect();
    std::fs::write(directory.join("restore.bin"), bytes).unwrap();
}
