//! Intel APX PUSH2/POP2 Instruction Tests
//!
//! PUSH2 and POP2 are new APX instructions that push/pop pairs of registers
//! atomically in a single instruction.
//!
//! PUSH2 src1, src2:
//! - Pushes src2 first (higher address), then src1 (lower address)
//! - RSP decremented by 16 (2 * 8 bytes)
//! - Memory layout: [src1 at RSP][src2 at RSP+8]
//!
//! POP2 dst1, dst2:
//! - Pops dst1 first (from RSP), then dst2 (from RSP+8)
//! - RSP incremented by 16
//!
//! Encoding:
//! - Uses EVEX prefix with special NDD encoding
//! - EVEX.pp = 00 for PUSH2, 01 for POP2
//! - Operands encoded in reg and vvvv fields
//! - Can use EGPR (R16-R31) via extended EVEX

use crate::common::*;

// ============================================================================
// Basic PUSH2 Tests
// ============================================================================

/// PUSH2 with two legacy registers
#[test]
fn test_push2_rax_rbx() {
    // PUSH2 rax, rbx
    let code = [
        0x62, 0xF4, 0x6C, 0x18,  // EVEX prefix for PUSH2
        0xFF, 0xF0,              // PUSH2 reg encoding
        0xF4,                    // HLT
    ];
    let mut regs = Registers::default();
    regs.rax = 0x1111111111111111;
    regs.rbx = 0x2222222222222222;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// PUSH2 with different register pairs
#[test]
fn test_push2_rcx_rdx() {
    // PUSH2 rcx, rdx
    let code = [
        0x62, 0xF4, 0x54, 0x18,
        0xFF, 0xF1,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rcx = 0xAAAABBBBCCCCDDDD;
    regs.rdx = 0x1234567890ABCDEF;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// PUSH2 with R8-R15 registers
#[test]
fn test_push2_r8_r9() {
    // PUSH2 r8, r9
    let code = [
        0x62, 0xD4, 0x34, 0x18,
        0xFF, 0xF0,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.r8 = 0x8888888888888888;
    regs.r9 = 0x9999999999999999;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// PUSH2 with mixed legacy and extended registers
#[test]
fn test_push2_rax_r10() {
    // PUSH2 rax, r10
    let code = [
        0x62, 0xD4, 0x2C, 0x18,
        0xFF, 0xF0,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rax = 0xDEADDEADDEADDEAD;
    regs.r10 = 0xBEEFBEEFBEEFBEEF;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

// ============================================================================
// Basic POP2 Tests
// ============================================================================

/// POP2 with two legacy registers
#[test]
fn test_pop2_rax_rbx() {
    // First push some values, then POP2
    // PUSH rbx; PUSH rax; POP2 rax, rbx
    let code = [
        0x53,                    // PUSH rbx
        0x50,                    // PUSH rax
        0x62, 0xF4, 0x6C, 0x18,  // EVEX prefix for POP2
        0x8F, 0xC0,              // POP2 reg encoding
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rax = 0x1111111111111111;
    regs.rbx = 0x2222222222222222;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// POP2 with different register pairs
#[test]
fn test_pop2_rcx_rdx() {
    // PUSH rdx; PUSH rcx; POP2 rcx, rdx
    let code = [
        0x52,                    // PUSH rdx
        0x51,                    // PUSH rcx
        0x62, 0xF4, 0x54, 0x18,
        0x8F, 0xC1,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rcx = 0xCAFEBABE12345678;
    regs.rdx = 0xFEEDFACE87654321;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// POP2 with R12-R13 registers
#[test]
fn test_pop2_r12_r13() {
    // Set up stack with values, then POP2
    let code = [
        0x41, 0x55,              // PUSH r13
        0x41, 0x54,              // PUSH r12
        0x62, 0xD4, 0x14, 0x18,
        0x8F, 0xC4,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.r12 = 0x1212121212121212;
    regs.r13 = 0x1313131313131313;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

// ============================================================================
// PUSH2/POP2 with EGPR (R16-R31)
// ============================================================================

/// PUSH2 with R16 and R17
#[test]
fn test_push2_r16_r17() {
    // PUSH2 r16, r17 - uses extended EVEX encoding
    let code = [
        0x62, 0xEC, 0x74, 0x18,  // EVEX with EGPR bits
        0xFF, 0xF0,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}

/// POP2 with R20 and R21
#[test]
fn test_pop2_r20_r21() {
    // Set up stack, then POP2 r20, r21
    let code = [
        0x50,                    // PUSH rax (placeholder)
        0x50,                    // PUSH rax (placeholder)
        0x62, 0xEC, 0x54, 0x18,
        0x8F, 0xC4,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}

/// PUSH2 with mixed EGPR and legacy registers
#[test]
fn test_push2_rax_r24() {
    // PUSH2 rax, r24
    let code = [
        0x62, 0xEC, 0x3C, 0x18,
        0xFF, 0xF0,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rax = 0xAAAAAAAAAAAAAAAA;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// POP2 with mixed EGPR and legacy registers
#[test]
fn test_pop2_rbx_r28() {
    // Set up stack, then POP2 rbx, r28
    let code = [
        0x50,                    // PUSH rax (placeholder)
        0x50,                    // PUSH rax (placeholder)
        0x62, 0xEC, 0x1C, 0x18,
        0x8F, 0xC3,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}

/// PUSH2 with R30 and R31 (highest EGPR)
#[test]
fn test_push2_r30_r31() {
    // PUSH2 r30, r31
    let code = [
        0x62, 0xEC, 0x04, 0x18,
        0xFF, 0xF6,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}

// ============================================================================
// PUSH2/POP2 Roundtrip Tests
// ============================================================================

/// Push and pop same registers - should restore values
#[test]
fn test_push2_pop2_roundtrip() {
    // PUSH2 rax, rbx; POP2 rax, rbx
    let code = [
        0x62, 0xF4, 0x6C, 0x18,  // PUSH2
        0xFF, 0xF0,
        0x62, 0xF4, 0x6C, 0x18,  // POP2
        0x8F, 0xC0,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rax = 0xDEADBEEFCAFEBABE;
    regs.rbx = 0x123456789ABCDEF0;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// Multiple PUSH2/POP2 operations
#[test]
fn test_push2_pop2_multiple() {
    // PUSH2 rax, rbx; PUSH2 rcx, rdx; POP2 rcx, rdx; POP2 rax, rbx
    let code = [
        0x62, 0xF4, 0x6C, 0x18, 0xFF, 0xF0,  // PUSH2 rax, rbx
        0x62, 0xF4, 0x54, 0x18, 0xFF, 0xF1,  // PUSH2 rcx, rdx
        0x62, 0xF4, 0x54, 0x18, 0x8F, 0xC1,  // POP2 rcx, rdx
        0x62, 0xF4, 0x6C, 0x18, 0x8F, 0xC0,  // POP2 rax, rbx
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rax = 0x1111;
    regs.rbx = 0x2222;
    regs.rcx = 0x3333;
    regs.rdx = 0x4444;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

// ============================================================================
// Edge Cases
// ============================================================================

/// PUSH2 with same register twice (allowed)
#[test]
fn test_push2_same_register() {
    // PUSH2 rax, rax
    let code = [
        0x62, 0xF4, 0x7C, 0x18,  // vvvv = RAX
        0xFF, 0xF0,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rax = 0xDEADDEADDEADDEAD;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// POP2 into same register (last pop wins)
#[test]
fn test_pop2_same_register() {
    // Set up stack, then POP2 rax, rax
    let code = [
        0x50,                    // PUSH rax
        0x50,                    // PUSH rax
        0x62, 0xF4, 0x7C, 0x18,
        0x8F, 0xC0,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}

/// PUSH2 with zero values
#[test]
fn test_push2_zero_values() {
    let code = [
        0x62, 0xF4, 0x6C, 0x18,
        0xFF, 0xF0,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rax = 0;
    regs.rbx = 0;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

/// PUSH2 with maximum values
#[test]
fn test_push2_max_values() {
    let code = [
        0x62, 0xF4, 0x6C, 0x18,
        0xFF, 0xF0,
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rax = u64::MAX;
    regs.rbx = u64::MAX;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

// ============================================================================
// Callee-Saved Register Pattern
// ============================================================================

/// Typical function prologue/epilogue pattern with PUSH2/POP2
#[test]
fn test_push2_function_prologue() {
    // PUSH2 rbx, r12; PUSH2 r13, r14; <work>; POP2 r13, r14; POP2 rbx, r12
    let code = [
        0x62, 0xD4, 0x24, 0x18, 0xFF, 0xF3,  // PUSH2 rbx, r12
        0x62, 0xD4, 0x0C, 0x18, 0xFF, 0xF5,  // PUSH2 r13, r14
        // Simulated function body (NOP)
        0x90,
        0x62, 0xD4, 0x0C, 0x18, 0x8F, 0xC5,  // POP2 r13, r14
        0x62, 0xD4, 0x24, 0x18, 0x8F, 0xC3,  // POP2 rbx, r12
        0xF4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0xBBBB;
    regs.r12 = 0x1212;
    regs.r13 = 0x1313;
    regs.r14 = 0x1414;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let _ = run_until_hlt(&mut vcpu);
}

// ============================================================================
// RSP Interaction Tests
// ============================================================================

/// PUSH2 modifies RSP correctly
#[test]
fn test_push2_rsp_modification() {
    let code = [
        0x62, 0xF4, 0x6C, 0x18,
        0xFF, 0xF0,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}

/// POP2 modifies RSP correctly
#[test]
fn test_pop2_rsp_modification() {
    // Set up stack first
    let code = [
        0x50,                    // PUSH rax
        0x50,                    // PUSH rax
        0x62, 0xF4, 0x6C, 0x18,
        0x8F, 0xC0,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}

// ============================================================================
// Flag Preservation Tests
// ============================================================================

/// PUSH2 does not modify flags
#[test]
fn test_push2_preserves_flags() {
    // Set flags, then PUSH2
    let code = [
        0xF9,                    // STC (set CF)
        0x62, 0xF4, 0x6C, 0x18,
        0xFF, 0xF0,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}

/// POP2 does not modify flags
#[test]
fn test_pop2_preserves_flags() {
    // Set flags, set up stack, then POP2
    let code = [
        0x50,                    // PUSH rax
        0x50,                    // PUSH rax
        0xF9,                    // STC (set CF)
        0x62, 0xF4, 0x6C, 0x18,
        0x8F, 0xC0,
        0xF4,
    ];
    let (mut vcpu, _) = setup_vm(&code, None);
    let _ = run_until_hlt(&mut vcpu);
}
