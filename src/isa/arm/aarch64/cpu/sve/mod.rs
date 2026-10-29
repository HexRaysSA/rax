//! SVE (Scalable Vector Extension) instruction execution

use crate::isa::arm::aarch64::cpu::*;
use std::collections::HashSet;
use std::fmt::Debug;

use crate::isa::arm::aarch64::exceptions::{
    ExceptionType, SyndromeRegister, build_spsr, exception_target_el, parse_spsr, vector_offset,
};
use crate::isa::arm::aarch64::gic::{Gic, GicConfig};
use crate::isa::arm::aarch64::mmu::{Mmu, MmuConfig, TranslationFault, TranslationGranule};
use crate::isa::arm::aarch64::sysregs::SystemRegisters;
use crate::isa::arm::aarch64::{NUM_ELS, NUM_GPRS, NUM_SIMD_REGS, sctlr};

use crate::isa::arm::common::cpu::{
    ArmCpu, ArmError, ArmException, ArmProfile, ArmVersion, CpuExit, MemoryFaultInfo,
    MemoryFaultType, ProcessorState, WatchpointKind,
};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::ArmMemory;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::vcpu::Aarch64SystemRegisters;

// ---- module tree (auto-split) ----
pub(super) mod admission;
mod core;
pub(crate) use core::*;
mod fp;
pub(crate) use fp::*;
mod memory;
pub(crate) use memory::*;
mod misc;
pub(crate) use misc::*;
mod permute;
pub(crate) use permute::*;
mod pred;
pub(crate) use pred::*;
mod reduce;
pub(crate) use reduce::*;
mod shift;
pub(crate) use shift::*;
mod sve2;
pub(crate) use sve2::*;
