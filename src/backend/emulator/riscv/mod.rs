//! RISC-V emulator backend: bridges the self-contained [`crate::isa::riscv`]
//! interpreter to the VMM's [`VCpu`](crate::vm::vcpu::VCpu) interface.

mod cpu;
pub(crate) mod platform;
pub(crate) use cpu::context_uses_platform;

pub use cpu::{RiscVVcpu, RvUserTrap};
