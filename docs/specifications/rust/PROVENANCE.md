# Rust file-locking API reference

The original installed standard-library source is archived as
`std-fs-1.98.1.rs` (122615 bytes, SHA-256
`d90d36fa6f8f80a62530e86ff5898cd75e8ed4fc19997e24d7a340a9b97479c6`).
It was retrieved from the installed `rust-src` component on 2026-10-25:
`rustc 1.98.1 (48a229cea 2026-09-01)`,
`library/std/src/fs.rs`. Canonical project source:
https://github.com/rust-lang/rust/blob/1.98.1/library/std/src/fs.rs .
Issuer: The Rust Project Developers.

The `File::try_lock`, `File::try_lock_shared`, `TryLockError`, and synchronization
APIs define the storage backend's nonblocking lock and host-error contracts.
The file is retained unchanged; the relevant locking APIs are marked stable
since Rust 1.89.0. This source reference is not a runtime dependency.

Original upstream licenses were retrieved on 2026-10-25 from:

- https://raw.githubusercontent.com/rust-lang/rust/1.98.1/LICENSE-MIT
- https://raw.githubusercontent.com/rust-lang/rust/1.98.1/LICENSE-APACHE

They are retained alongside the source. Source-level API evidence and host-local
behavioral tests do not prove filesystem power-loss durability or exclusion of
host writers that ignore advisory locks.
