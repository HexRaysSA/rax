//! Existing-API predecessor/current observer for omitted runtime timing fields.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::{runtime::Vmm, snapshot::SnapshotBundle};
fn main() {
    let directory = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    std::fs::create_dir_all(&directory).unwrap();
    let kernel = directory.join("kernel.bin");
    std::fs::write(&kernel, [0; 64]).unwrap();
    let mut c = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Emulator),
            kernel: Some(kernel),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    c.memory = MemorySize(128 * 1024 * 1024);
    c.pci_devices = false;
    let source = Vmm::new_resume(c.clone()).unwrap();
    for _ in 0..37 {
        source.timing_context().tick();
    }
    source.timing_context().set_timer_pending();
    let bundle = source.take_snapshot_bundle(17).unwrap();
    let p = directory.join("full.rxc");
    bundle.save(&p).unwrap();
    let bundle = SnapshotBundle::load(&p).unwrap();
    let target = Vmm::new_resume_bundle(c, &bundle).unwrap();
    let values = [
        target.timing_context().instruction_count(),
        u64::from(target.timing_context().is_timer_pending()),
    ];
    let raw: Vec<_> = values.into_iter().flat_map(u64::to_le_bytes).collect();
    std::fs::write(directory.join("observed.bin"), raw).unwrap();
}
