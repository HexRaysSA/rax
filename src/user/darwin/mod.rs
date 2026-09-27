//! Darwin personality: runs macOS user-space programs.
//!
//! The personality implements the XNU user-space ABI for x86-64 and arm64
//! programs: images are loaded as `exec_mach_imgact` loads them (ASLR
//! disabled), and `dyld` and the dyld shared cache come from the host (or a
//! guest root).
//!
//! | Module | Owns |
//! |---|---|
//! | [`abi`] | Numbering, conventions, error numbers, and machine parameters |
//! | [`arch`] | Per-ISA registers, kernel entry, and result conventions |
//! | [`loader`] | `exec`: mapping the image and `dyld`, the stack, the commpage |
//! | [`stack`] | The initial stack (`exec_copyout_strings`) |
//! | [`commpage`] | The commpage |
//! | [`shared_region`] | The dyld shared cache |
//! | [`vm`] | Mach VM attributes and address selection |
//! | [`vfs`] | Guest paths and the root overlay |
//! | [`mach`] | Ports, messages, and kernel objects |
//! | [`mig`] | The kernel's MIG servers |

pub mod abi;
pub mod arch;
pub mod commpage;
pub mod loader;
pub mod mach;
pub mod mig;
pub mod shared_region;
pub mod stack;
pub mod vfs;
pub mod vm;
