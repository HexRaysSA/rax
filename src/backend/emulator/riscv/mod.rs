//! RISC-V emulator backend: bridges the self-contained [`crate::isa::riscv`]
//! interpreter to the VMM's [`VCpu`](crate::vm::vcpu::VCpu) interface.

mod cpu;
pub(crate) mod platform;
pub(crate) use cpu::{checkpoint_profiles, refresh_checkpoint_signals};

pub use cpu::{RiscVVcpu, RvUserTrap};
