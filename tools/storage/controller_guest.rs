//! Publish real controller checkpoint and continuation states.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/controller_checkpoint.rs"]
mod owning;
fn main() {
    let mut args = std::env::args_os().skip(1);
    let folder = std::path::PathBuf::from(args.next().expect("evidence directory"));
    assert!(args.next().is_none());
    owning::emit_reference(&folder);
}
