//! Publish actual optional endpoint state for independent byte expectations.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/pci_endpoint_checkpoint.rs"]
mod controls;
fn main() {
    let directory = std::env::args_os().nth(1).expect("output directory");
    controls::emit_reference(std::path::Path::new(&directory));
}
