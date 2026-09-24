//! `rax-user` Linux personality integration tests.
//!
//! - `abi_tables`: the generated syscall and errno tables agree with the
//!   Linux 6.19 UAPI headers vendored under `docs/specifications/linux/`.
//!
//! Run with:
//!
//! ```text
//! cargo test --no-default-features --features x86_64-suite,smir-jit --test user_linux
//! ```
#![cfg(unix)]

mod abi_tables;
