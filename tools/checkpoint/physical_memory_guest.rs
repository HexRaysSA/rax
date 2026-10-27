//! Publish complete mapped-region fixtures through the public checkpoint API.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/vm/checkpoint_physical_memory.rs"]
mod controls;
fn main() {
    let directory = std::env::args_os().nth(1).expect("output directory");
    controls::emit_reference(std::path::Path::new(&directory));
}
