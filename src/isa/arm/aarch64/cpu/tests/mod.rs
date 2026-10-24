//! tests.rs

use super::*;

// ---- split submodules ----
#[cfg(test)]
mod branch;
#[cfg(test)]
mod data;
#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
mod jit_comparisons;
#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
mod jit_fetch;
#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
mod jit_permissions;
#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
mod jit_resize;
#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
mod jit_saturating;
#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
mod jit_scalar_simd;
#[cfg(test)]
mod memory;
#[cfg(test)]
mod misc;
mod pauth;
mod pauth_aarch32;
mod pauth_descriptors;
mod pauth_entry;
mod pauth_eret;
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
mod pauth_jit;
mod pauth_keyed;
mod pauth_regime;
mod pauth_state;
#[cfg(test)]
mod simd;
#[cfg(test)]
mod sve;
#[cfg(test)]
mod system;
use crate::isa::arm::common::memory::{ArmMemory, FlatMemory, MemResult, MmioHandler};

#[derive(Debug)]
struct WrappingMemory {
    data: Vec<u8>,
}

impl WrappingMemory {
    fn with_pattern(size: usize) -> Self {
        assert!(size > 0);
        Self {
            data: (0..size).map(|i| i as u8).collect(),
        }
    }

    fn offset(&self, addr: u64) -> usize {
        (addr as usize) % self.data.len()
    }
}

impl ArmMemory for WrappingMemory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = self.data[self.offset(addr.wrapping_add(i as u64))];
        }
        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        for (i, byte) in data.iter().enumerate() {
            let offset = self.offset(addr.wrapping_add(i as u64));
            self.data[offset] = *byte;
        }
        Ok(())
    }

    fn mark_exclusive(&mut self, _addr: u64, _size: u8) {}

    fn check_exclusive(&mut self, _addr: u64, _size: u8) -> bool {
        true
    }

    fn clear_exclusive(&mut self) {}

    fn requires_alignment(&self) -> bool {
        false
    }

    fn register_mmio(&mut self, _base: u64, _size: u64, _handler: Box<dyn MmioHandler>) {}

    fn unregister_mmio(&mut self, _base: u64) {}
}

fn create_test_cpu() -> AArch64Cpu {
    let memory = FlatMemory::new(0, 0x1000_0000);
    AArch64Cpu::new(AArch64Config::default(), Box::new(memory))
}

fn create_wrapping_memory_cpu() -> AArch64Cpu {
    AArch64Cpu::new(
        AArch64Config::default(),
        Box::new(WrappingMemory::with_pattern(64)),
    )
}

// =========================================================================
// Instruction Execution Tests
// =========================================================================

/// Helper to create a CPU and write an instruction at PC
fn create_cpu_with_insn(insn: u32) -> AArch64Cpu {
    let mut cpu = create_test_cpu();
    cpu.write_memory(0, &insn.to_le_bytes()).unwrap();
    cpu
}

/// Helper to write instruction at specific address
fn write_insn(cpu: &mut AArch64Cpu, addr: u64, insn: u32) {
    cpu.write_memory(addr, &insn.to_le_bytes()).unwrap();
}

fn encode_casp(sz: u32, rn: u8, rs: u8, rt: u8) -> u32 {
    debug_assert!(sz <= 1);
    (sz << 30)
        | (0b001000 << 24)
        | (1 << 21)
        | ((rs as u32) << 16)
        | (0b11111 << 10)
        | ((rn as u32) << 5)
        | rt as u32
}

fn encode_mrs_rng(op2: u32, rt: u8) -> u32 {
    debug_assert!(op2 <= 1);
    0xd530_0000 | (1 << 19) | (3 << 16) | (2 << 12) | (4 << 8) | (op2 << 5) | rt as u32
}

fn encode_ld1_structure(q: u32, size: u32, rn: u8, rt: u8) -> u32 {
    debug_assert!(q <= 1);
    debug_assert!(size <= 3);
    (q << 30)
        | (0b001100 << 24)
        | (1 << 22)
        | (0b0111 << 12)
        | (size << 10)
        | ((rn as u32) << 5)
        | rt as u32
}

fn encode_simd_two_reg_misc(
    scalar: bool,
    q: u32,
    u: u32,
    size: u32,
    opcode: u32,
    rn: u8,
    rd: u8,
) -> u32 {
    debug_assert!(q <= 1);
    debug_assert!(u <= 1);
    debug_assert!(size <= 3);
    debug_assert!(opcode <= 0x1f);
    let q = if scalar { 1 } else { q };
    let op_bits = if scalar { 0b11110 } else { 0b01110 };
    (q << 30)
        | (u << 29)
        | (op_bits << 24)
        | (size << 22)
        | (0b10000 << 17)
        | (opcode << 12)
        | (0b10 << 10)
        | ((rn as u32) << 5)
        | rd as u32
}

fn pack_h_lanes(lanes: [u16; 8]) -> u128 {
    lanes
        .into_iter()
        .enumerate()
        .fold(0u128, |acc, (i, lane)| acc | ((lane as u128) << (i * 16)))
}

fn h_lane(value: u128, lane: usize) -> u16 {
    ((value >> (lane * 16)) & 0xffff) as u16
}

fn create_issue_39_cpu() -> (AArch64Cpu, u64) {
    let mut cpu = create_test_cpu(); // EL1, flat memory, MMU initially disabled.
    cpu.sysregs.id_aa64mmfr2_el1 |= 1 << 4; // Advertise FEAT_UAO for override checks.

    // Single-level L1-block identity map for the low 1GB, AP=00 (EL1 RW, EL0
    // no-access). Tables/data are written while the MMU is disabled (identity).
    let table = 0x8000u64;
    cpu.mem_write_u64(table, 0x401).unwrap(); // L1[0]: block, AP=00, AF, PA[47:30]=0
    let data_va = 0x1000u64;
    cpu.mem_write_u64(data_va, 0xCAFE_F00D_DEAD_BEEF).unwrap();

    // Enable the MMU: 4KB granule (TG0=0), T0SZ=25 (walk starts at L1).
    cpu.sysregs.el1.ttbr0 = table;
    cpu.sysregs.el1.tcr = 25;
    cpu.sysregs.el1.sctlr |= sctlr::M;
    cpu.update_mmu_config();
    assert_eq!(cpu.current_el(), 1, "test runs at EL1");

    (cpu, data_va)
}

fn ldtr_x0_x1_0() -> u32 {
    (0b11 << 30) | (0b111 << 27) | (0b01 << 22) | (0b10 << 10) | (1 << 5)
}

fn sttr_x0_x1_0() -> u32 {
    (0b11 << 30) | (0b111 << 27) | (0b00 << 22) | (0b10 << 10) | (1 << 5)
}

fn msr_imm_pstate(op1: u8, op2: u8, imm: u8) -> u32 {
    0xD500_401F | ((op1 as u32) << 16) | ((imm as u32) << 8) | ((op2 as u32) << 5)
}

fn ldtp_x0_x2_x1_0() -> u32 {
    (0b11 << 30) | (0b101 << 27) | (0b10 << 23) | (1 << 22) | (2 << 10) | (1 << 5)
}

fn sttp_x0_x2_x1_0() -> u32 {
    (0b11 << 30) | (0b101 << 27) | (0b10 << 23) | (2 << 10) | (1 << 5)
}

fn is_permission_error<T>(result: Result<T, ArmError>) -> bool {
    matches!(
        result,
        Err(ArmError::MemoryError(info)) if info.fault_type == MemoryFaultType::Permission
    )
}
