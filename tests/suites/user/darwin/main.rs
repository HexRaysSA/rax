//! `rax-user` Darwin personality integration tests.
//!
//! The oracle is the host itself: on a macOS host each fixture
//! (`tests/fixtures/user/darwin/src/*.c`) is compiled for arm64 and x86_64
//! with the SDK's `clang`, run natively (x86_64 through Rosetta), and run
//! under `rax-user` against the host's `dyld` and shared cache; standard
//! output and exit status must match byte for byte. The same holds for a
//! set of system programs. Elsewhere the comparisons have no oracle and
//! report themselves skipped.
//!
//! - `fixtures`: the C fixtures.
//! - `programs`: `/bin` and `/usr/bin` programs.
//! - `generators`: the checked-in generated tables equal what
//!   `tools/darwin/gen_abi.py` and `gen_mig.py` produce from the vendored
//!   sources.
//! - `layouts`: the signal-frame and thread-state layouts the personality
//!   writes equal the SDK's (a probe compiled with the SDK's `clang`).
//!
//! Run with:
//!
//! ```text
//! cargo test --no-default-features --features x86_64-suite,smir-jit --test user_darwin
//! ```
#![cfg(unix)]

mod fixtures;
mod generators;
mod layouts;
mod programs;
mod support;
