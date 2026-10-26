//! Replay retained raw PCI/AHCI inputs through the current controller source.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/ahci_dma.rs"]
mod owning;
fn main() {
    let mut args = std::env::args_os().skip(1);
    let folder = std::path::PathBuf::from(args.next().expect("reference directory"));
    assert!(args.next().is_none());
    owning::compare_reference(&folder);
}
