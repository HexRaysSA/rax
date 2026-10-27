#[path = "../../tests/suites/vm/checkpoint_clock.rs"]
mod owner;
fn main() {
    owner::emit_reference(&std::path::PathBuf::from(
        std::env::args_os().nth(1).unwrap(),
    ));
}
