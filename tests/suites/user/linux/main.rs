//! `rax-user` Linux personality integration tests.
//!
//! - `abi_tables`: the generated syscall and errno tables agree with the
//!   Linux 6.19 UAPI headers vendored under `docs/specifications/linux/`.
//! - `fixtures`: static musl programs for x86-64, AArch64, and RV64
//!   (`tests/fixtures/user/linux`) produce, byte for byte, the output and
//!   exit status recorded on a real Linux kernel.
//! - `cli`: command-line contract of the `rax-user` binary.
//!
//! Run with:
//!
//! ```text
//! cargo test --no-default-features --features x86_64-suite,smir-jit --test user_linux
//! ```
#![cfg(unix)]

mod abi_tables;
mod cli;
mod fixtures;
mod sha256;
mod support;
