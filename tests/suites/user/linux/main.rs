//! `rax-user` Linux personality integration tests.
//!
//! - `abi_tables`: the generated syscall and errno tables agree with the
//!   Linux 6.19 UAPI headers vendored under `docs/specifications/linux/`.
//! - `fixtures`: static musl programs for x86-64, AArch64, and RV64
//!   (`tests/fixtures/user/linux`) produce, byte for byte, the output and
//!   exit status recorded on a real Linux kernel.
//! - `programs`: the morok program corpus
//!   (`tests/fixtures/user/linux/programs`), 97 C and C++ programs trimmed to
//!   run in milliseconds, matches its real-kernel recording in every
//!   execution mode, apart from the listed known divergences.
//! - `cli`: command-line contract of the `rax-user` binary.
//! - `host_signals`: signals sent to `rax-user` reach the guest, or act on
//!   `rax-user` itself with `--no-signal-forwarding`.
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
mod host_signals;
mod programs;
mod sha256;
mod support;
