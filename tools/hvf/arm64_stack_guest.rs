#[path = "../../tests/suites/backend/hvf_arm64_state.rs"]
mod owner;
fn main() {
    owner::emit_reference(&std::path::PathBuf::from(
        std::env::args_os().nth(1).unwrap(),
    ));
}
