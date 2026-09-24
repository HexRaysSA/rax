//! Linux personality: runs Linux user-space programs.
//!
//! The personality implements the Linux 6.19 system-call ABI for x86-64,
//! AArch64, and RV64 guests on a Unix host. Guest programs are loaded as
//! `binfmt_elf` would load them (with address-space randomization disabled).
//!
//! | Module | Owns |
//! |---|---|
//! | [`abi`] | Per-ABI numbering, constants, and structure layouts |
//! | [`loader`] | `execve` image loading |
//! | [`stack`] | Initial stack and auxiliary vector |

pub mod abi;
pub mod loader;
pub mod stack;

#[cfg(test)]
mod tests;
