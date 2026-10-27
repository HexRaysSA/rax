//! Publish the actual runtime PCI state set for independent model comparison.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/vm/runtime_pci_checkpoint.rs"]
mod controls;
fn main() {
    let directory = std::env::args_os().nth(1).expect("output directory");
    controls::emit_reference(std::path::Path::new(&directory));
}
