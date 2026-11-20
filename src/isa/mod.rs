//! Guest instruction-set implementations.
//!
//! This namespace contains decoding, architectural state, and instruction
//! semantics. Machine construction and execution-backend selection live in
//! their respective top-level modules.

pub mod arm;
pub mod ebpf;
pub mod hexagon;
pub mod riscv;
pub mod x86_64;
pub mod xtensa;
