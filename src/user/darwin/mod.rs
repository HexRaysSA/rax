//! Darwin personality: runs macOS user-space programs.
//!
//! The personality implements the XNU user-space ABI for x86-64 and arm64
//! programs.
//!
//! | Module | Owns |
//! |---|---|
//! | [`abi`] | Numbering, conventions, error numbers, and machine parameters |
//! | [`mach`] | Ports, messages, and kernel objects |
//! | [`mig`] | The kernel's MIG servers |

pub mod abi;
pub mod mach;
pub mod mig;
