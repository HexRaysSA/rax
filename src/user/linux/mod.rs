//! Linux personality: runs Linux user-space programs.
//!
//! The personality implements the Linux 6.19 system-call ABI for x86-64,
//! AArch64, and RV64 guests on a Unix host.
//!
//! | Module | Owns |
//! |---|---|
//! | [`abi`] | Per-ABI numbering, constants, and structure layouts |

pub mod abi;
