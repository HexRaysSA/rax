//! RISC-V emulator backend: bridges the self-contained [`crate::isa::riscv`]
//! interpreter to the VMM's [`VCpu`](crate::vm::vcpu::VCpu) interface.

mod cpu;
pub(crate) mod platform;
pub(crate) use cpu::checkpoint_profiles;

pub use cpu::{RiscVVcpu, RvUserTrap};
