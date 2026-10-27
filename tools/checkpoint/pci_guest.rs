//! Publish actual PCI checkpoint records for an independent wire/routing parser.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/pci_checkpoint.rs"]
mod controls;
fn main() {
    let path = std::env::args_os().nth(1).expect("output directory");
    controls::emit_reference(std::path::Path::new(&path));
}
