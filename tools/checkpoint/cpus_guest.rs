//! Publish actual ordered CPU files and live runtime markers.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/vm/checkpoint_cpus.rs"]
mod controls;
fn main() {
    let out = std::env::args_os().nth(1).expect("output directory");
    controls::emit_reference(std::path::Path::new(&out));
}
