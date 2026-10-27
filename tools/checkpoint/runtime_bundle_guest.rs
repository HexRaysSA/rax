//! Publish represented VM restore bytes using actual public runtime APIs.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/vm/runtime_checkpoint_bundle.rs"]
mod controls;
fn main() {
    let dir = std::env::args_os().nth(1).expect("output directory");
    controls::emit_reference(std::path::Path::new(&dir));
}
