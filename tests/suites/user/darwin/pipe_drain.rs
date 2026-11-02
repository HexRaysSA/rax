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

fn fifo_lifetime(arch: &str) {
    if !comparable("fd_fifo_lifetime", arch) {
        return;
    }
    let program = build("fd_fifo_lifetime", arch);
    compare("fd_fifo_lifetime", &program, arch, &[], &[], None);
}

#[test]
fn entered_fifo_reads_arm64() {
    fifo_lifetime("arm64");
}

#[test]
fn entered_fifo_reads_x86_64() {
    fifo_lifetime("x86_64");
}
