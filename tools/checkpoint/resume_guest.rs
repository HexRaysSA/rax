//! Publish a console checkpoint from an actual high-address RISC-V ELF load.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/vm/checkpoint_resume.rs"]
mod controls;
fn main() {
    let out = std::env::args_os().nth(1).expect("output directory");
    controls::emit_reference(std::path::Path::new(&out));
}
