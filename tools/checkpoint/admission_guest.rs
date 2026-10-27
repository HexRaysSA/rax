//! Identical actual public-API probe for prior and current restore admission.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/vm/restore_admission.rs"]
mod controls;
fn main() {
    controls::emit_reference();
}
