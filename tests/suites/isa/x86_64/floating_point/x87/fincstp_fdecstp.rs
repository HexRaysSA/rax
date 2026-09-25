//! Tests for the FINCSTP and FDECSTP instructions.
//!
//! FINCSTP - Increment Stack-Top Pointer
//! FDECSTP - Decrement Stack-Top Pointer
//!
//! FINCSTP adds one to the TOP field of the FPU status word (increments the top-of-stack pointer).
//! If the TOP field contains a 7, it is set to 0. The effect is to rotate the stack by one position.
//! The contents of the FPU data registers and tag register are not affected.
//!
//! FDECSTP subtracts one from the TOP field of the FPU status word (decrements the top-of-stack pointer).
//! If the TOP field contains a 0, it is set to 7. The effect is to rotate the stack by one position.
//! The contents of the FPU data registers and tag register are not affected.
//!
//! Opcodes:
//! - FINCSTP: D9 F7
//! - FDECSTP: D9 F6
//!
//! Flags affected:
//! - C1: Set to 0
//! - C0, C2, C3: Undefined
//!
//! References: docs/fincstp.txt, docs/fdecstp.txt

use crate::common::*;
use rax::vm::vcpu::Registers;
use vm_memory::{Bytes, GuestAddress};

// Helper function to write f64 to memory
fn write_f64(mem: &vm_memory::GuestMemoryMmap, addr: u64, val: f64) {
    mem.write_slice(&val.to_le_bytes(), GuestAddress(addr))
        .unwrap();
}

// Helper function to read f64 from memory
fn read_f64(mem: &vm_memory::GuestMemoryMmap, addr: u64) -> f64 {
    let mut buf = [0u8; 8];
    mem.read_slice(&mut buf, GuestAddress(addr)).unwrap();
    f64::from_le_bytes(buf)
}

fn assert_empty_pop(value: f64, message: &str) {
    assert!(value.is_nan(), "{}", message);
}

// ============================================================================
// FINCSTP - Basic Tests
// ============================================================================

#[test]
fn test_fincstp_basic() {
    // FINCSTP increments TOP, making what was ST(1) become ST(0)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xD9, 0xF7, // FINCSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 10.0);
    write_f64(&mem, 0x2008, 20.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, 10.0, "After FINCSTP, old ST(1) becomes ST(0)");
}

#[test]
fn test_fincstp_single_value() {
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF7, // FINCSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 5.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    // After FINCSTP, TOP points at an empty physical register.
    assert_empty_pop(
        result,
        "FINCSTP with a single value should expose empty ST(0)",
    );
}

#[test]
fn test_fincstp_multiple_values() {
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xD9, 0xF7, // FINCSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 1.0);
    write_f64(&mem, 0x2008, 2.0);
    write_f64(&mem, 0x2010, 3.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result0 = read_f64(&mem, 0x3000);
    let result1 = read_f64(&mem, 0x3008);
    assert_eq!(result0, 2.0, "After FINCSTP, ST(1) becomes ST(0)");
    assert_eq!(result1, 1.0, "After FINCSTP, ST(2) becomes ST(1)");
}

// ============================================================================
// FDECSTP - Basic Tests
// ============================================================================

#[test]
fn test_fdecstp_basic() {
    // FDECSTP decrements TOP, making what was ST(0) become ST(1)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xD9, 0xF6, // FDECSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xDD, 0x1C, 0x25, 0x10, 0x30, 0x00, 0x00, // FSTP qword [0x3010]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 10.0);
    write_f64(&mem, 0x2008, 20.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result1 = read_f64(&mem, 0x3008);
    let result2 = read_f64(&mem, 0x3010);
    assert_eq!(result1, 20.0, "After FDECSTP, old ST(0) becomes ST(1)");
    assert_eq!(result2, 10.0, "After FDECSTP, old ST(1) becomes ST(2)");
}

#[test]
fn test_fdecstp_single_value() {
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF6, // FDECSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 7.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result1 = read_f64(&mem, 0x3008);
    assert!(
        result1 == 7.0 || result1 == 0.0,
        "FDECSTP with single value"
    );
}

// ============================================================================
// FINCSTP/FDECSTP - Wrap Around
// ============================================================================

#[test]
fn test_fincstp_wraparound() {
    // Multiple FINCSTP should wrap around (8 increments = back to start)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF7, // FINCSTP (1)
        0xD9, 0xF7, // FINCSTP (2)
        0xD9, 0xF7, // FINCSTP (3)
        0xD9, 0xF7, // FINCSTP (4)
        0xD9, 0xF7, // FINCSTP (5)
        0xD9, 0xF7, // FINCSTP (6)
        0xD9, 0xF7, // FINCSTP (7)
        0xD9, 0xF7, // FINCSTP (8) - wrap to 0
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 42.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(
        result, 42.0,
        "8 FINCSTPs should wrap around to original position"
    );
}

#[test]
fn test_fdecstp_wraparound() {
    // Multiple FDECSTP should wrap around (8 decrements = back to start)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF6, // FDECSTP (1)
        0xD9, 0xF6, // FDECSTP (2)
        0xD9, 0xF6, // FDECSTP (3)
        0xD9, 0xF6, // FDECSTP (4)
        0xD9, 0xF6, // FDECSTP (5)
        0xD9, 0xF6, // FDECSTP (6)
        0xD9, 0xF6, // FDECSTP (7)
        0xD9, 0xF6, // FDECSTP (8) - wrap to 0
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 99.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(
        result, 99.0,
        "8 FDECSTPs should wrap around to original position"
    );
}

// ============================================================================
// FINCSTP/FDECSTP - Combined
// ============================================================================

#[test]
fn test_fincstp_then_fdecstp() {
    // FINCSTP followed by FDECSTP should cancel out
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF6, // FDECSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 100.0);
    write_f64(&mem, 0x2008, 200.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, 200.0, "FINCSTP then FDECSTP should cancel out");
}

#[test]
fn test_fdecstp_then_fincstp() {
    // FDECSTP followed by FINCSTP should cancel out
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xD9, 0xF6, // FDECSTP
        0xD9, 0xF7, // FINCSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 50.0);
    write_f64(&mem, 0x2008, 75.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, 75.0, "FDECSTP then FINCSTP should cancel out");
}

#[test]
fn test_multiple_inc_dec_pairs() {
    // Multiple pairs should still cancel out
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF6, // FDECSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF6, // FDECSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF6, // FDECSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 33.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, 33.0, "Multiple INC/DEC pairs should cancel");
}

// ============================================================================
// FINCSTP/FDECSTP - Stack Rotation
// ============================================================================

#[test]
fn test_fincstp_rotation() {
    // FINCSTP rotates stack upward
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000] ; 1
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008] ; 2
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010] ; 3
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 1.0);
    write_f64(&mem, 0x2008, 2.0);
    write_f64(&mem, 0x2010, 3.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, 1.0, "Two FINCSTPs rotate stack by 2");
}

#[test]
fn test_fdecstp_rotation() {
    // FDECSTP rotates stack downward
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xD9, 0xF6, // FDECSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 10.0);
    write_f64(&mem, 0x2008, 20.0);
    write_f64(&mem, 0x2010, 30.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result1 = read_f64(&mem, 0x3008);
    assert_eq!(result1, 30.0, "FDECSTP rotation");
}

// ============================================================================
// FINCSTP/FDECSTP - Data Preservation
// ============================================================================

#[test]
fn test_fincstp_preserves_data() {
    // FINCSTP should not modify register contents
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF6, // FDECSTP (restore)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    let value = std::f64::consts::PI;
    write_f64(&mem, 0x2000, value);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, value, "FINCSTP should preserve data");
}

#[test]
fn test_fdecstp_preserves_data() {
    // FDECSTP should not modify register contents
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF6, // FDECSTP
        0xD9, 0xF7, // FINCSTP (restore)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    let value = std::f64::consts::E;
    write_f64(&mem, 0x2000, value);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, value, "FDECSTP should preserve data");
}

// ============================================================================
// FINCSTP/FDECSTP - With Operations
// ============================================================================

#[test]
fn test_fincstp_with_operation() {
    // FINCSTP leaves the register it skipped tagged valid, so the next FLD
    // overflows the stack: the masked response loads the x87 indefinite,
    // which FADDP propagates (Intel SDM Vol. 1, 8.5.1.1; confirmed on
    // Rosetta 2: result FFF8000000000000, FSW 0041h).
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xD9, 0xF7, // FINCSTP
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xDE, 0xC1, // FADDP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 5.0);
    write_f64(&mem, 0x2008, 10.0);
    write_f64(&mem, 0x2010, 3.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result.to_bits(), 0xFFF8_0000_0000_0000, "stack overflow");
}

#[test]
fn test_fdecstp_with_operation() {
    // After FDECSTP, FLD, FINCSTP, ST(0) is the empty register FDECSTP
    // exposed, so FADDP underflows: the masked response is the x87
    // indefinite (confirmed on Rosetta 2: result FFF8000000000000, FSW
    // 3841h).
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xD9, 0xF6, // FDECSTP
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xD9, 0xF7, // FINCSTP (restore)
        0xDE, 0xC1, // FADDP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 7.0);
    write_f64(&mem, 0x2008, 11.0);
    write_f64(&mem, 0x2010, 13.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result.to_bits(), 0xFFF8_0000_0000_0000, "stack underflow");
}

// ============================================================================
// FINCSTP/FDECSTP - Edge Cases
// ============================================================================

#[test]
fn test_fincstp_sequence() {
    // Sequence of FINCSTPs
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 123.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(
        result,
        "FINCSTP sequence should expose an empty physical register",
    );
}

#[test]
fn test_fdecstp_sequence() {
    // Sequence of FDECSTPs
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF6, // FDECSTP
        0xD9, 0xF6, // FDECSTP
        0xD9, 0xF6, // FDECSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 456.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(
        result,
        "FDECSTP sequence should expose an empty physical register",
    );
}

#[test]
fn test_alternating_inc_dec() {
    // Alternating INC and DEC
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF6, // FDECSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF6, // FDECSTP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 789.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(
        result, 789.0,
        "Alternating INC/DEC should maintain position"
    );
}

#[test]
fn test_fincstp_full_rotation_with_values() {
    // Full rotation with multiple values
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP
        0xD9, 0xF7, // FINCSTP (full rotation)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 11.0);
    write_f64(&mem, 0x2008, 22.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, 22.0, "Full rotation should return to start");
}
