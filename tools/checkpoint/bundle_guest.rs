//! Publish deterministic typed PCI/media fixtures with the additive bundle API.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/vm/checkpoint_pci.rs"]
mod controls;
fn main() {
    let directory = std::env::args_os().nth(1).expect("output directory");
    controls::emit_reference(std::path::Path::new(&directory));
}
