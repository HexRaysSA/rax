//! Entered pipe reads complete against the closing descriptor's native outcome.
use super::support::{build, comparable, compare};

fn pipe_drain(arch: &str) {
    if !comparable("fd_pipe_drain", arch) {
        return;
    }
    let program = build("fd_pipe_drain", arch);
    compare("fd_pipe_drain", &program, arch, &[], &[], None);
}

#[test]
fn entered_pipe_reads_arm64() {
    pipe_drain("arm64");
}

#[test]
fn entered_pipe_reads_x86_64() {
    pipe_drain("x86_64");
}
