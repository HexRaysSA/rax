//! Tests for the FFREE instruction.
//!
//! FFREE - Free Floating-Point Register
//!
//! Sets the tag in the FPU tag register associated with register ST(i) to empty (11B).
//! The contents of ST(i) and the FPU stack-top pointer (TOP) are not affected.
//! This instruction is used to mark a register as empty without popping the stack.
//!
//! Opcode: DD C0+i (where i = 0-7)
//!
//! Flags affected:
//! - C0, C1, C2, C3: Undefined
//!
//! Reference: docs/ffree.txt

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
// FFREE - Basic Tests
// ============================================================================

#[test]
fn test_ffree_st0() {
    // FFREE ST(0) marks ST(0) empty. Popping it stores the masked-invalid
    // x87 indefinite value.
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 5.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(result, "FSTP from FFREE'd ST(0) should be indefinite");
}

#[test]
fn test_ffree_st1() {
    // FFREE ST(1)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0xC1, // FFREE ST(1)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000] ; ST(0)
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008] ; ST(1)
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 10.0);
    write_f64(&mem, 0x2008, 20.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result0 = read_f64(&mem, 0x3000);
    let result1 = read_f64(&mem, 0x3008);
    assert_eq!(result0, 20.0, "ST(0) should be unchanged");
    assert_empty_pop(result1, "FFREE ST(1) should make the second pop empty");
}

#[test]
fn test_ffree_st2() {
    // FFREE ST(2)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xDD, 0xC2, // FFREE ST(2)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xDD, 0x1C, 0x25, 0x10, 0x30, 0x00, 0x00, // FSTP qword [0x3010]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 1.0);
    write_f64(&mem, 0x2008, 2.0);
    write_f64(&mem, 0x2010, 3.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result0 = read_f64(&mem, 0x3000);
    let result1 = read_f64(&mem, 0x3008);
    let result2 = read_f64(&mem, 0x3010);
    assert_eq!(result0, 3.0, "ST(0) unchanged");
    assert_eq!(result1, 2.0, "ST(1) unchanged");
    assert_empty_pop(result2, "FFREE ST(2) should make the third pop empty");
}

#[test]
fn test_ffree_st3() {
    // FFREE ST(3)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xDD, 0x04, 0x25, 0x18, 0x20, 0x00, 0x00, // FLD qword [0x2018]
        0xDD, 0xC3, // FFREE ST(3)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xDD, 0x1C, 0x25, 0x10, 0x30, 0x00, 0x00, // FSTP qword [0x3010]
        0xDD, 0x1C, 0x25, 0x18, 0x30, 0x00, 0x00, // FSTP qword [0x3018]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 4.0);
    write_f64(&mem, 0x2008, 3.0);
    write_f64(&mem, 0x2010, 2.0);
    write_f64(&mem, 0x2018, 1.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result3 = read_f64(&mem, 0x3018);
    assert_empty_pop(result3, "FFREE ST(3) should make the fourth pop empty");
}

#[test]
fn test_ffree_st7() {
    // FFREE ST(7) - highest stack register
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0xC7, // FFREE ST(7)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 7.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, 7.0, "FFREE ST(7) should work");
}

// ============================================================================
// FFREE - Stack Pointer Not Affected
// ============================================================================

#[test]
fn test_ffree_does_not_pop() {
    // FFREE should not pop the stack
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 100.0);
    write_f64(&mem, 0x2008, 200.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result0 = read_f64(&mem, 0x3000);
    let result1 = read_f64(&mem, 0x3008);
    assert_empty_pop(result0, "FFREE ST(0) should mark the top item empty");
    assert_eq!(result1, 100.0, "Both items should be accessible");
}

#[test]
fn test_ffree_does_not_push() {
    // FFREE should not push onto the stack
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 42.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(result, "FFREE should not push a replacement value");
}

// ============================================================================
// FFREE - Multiple FFREE
// ============================================================================

#[test]
fn test_ffree_multiple_registers() {
    // Free multiple registers
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0xC1, // FFREE ST(1)
        0xDD, 0xC2, // FFREE ST(2)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xDD, 0x1C, 0x25, 0x10, 0x30, 0x00, 0x00, // FSTP qword [0x3010]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 1.0);
    write_f64(&mem, 0x2008, 2.0);
    write_f64(&mem, 0x2010, 3.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result0 = read_f64(&mem, 0x3000);
    let result1 = read_f64(&mem, 0x3008);
    let result2 = read_f64(&mem, 0x3010);
    assert_empty_pop(result0, "FFREE ST(0) should make first pop empty");
    assert_empty_pop(result1, "FFREE ST(1) should make second pop empty");
    assert_empty_pop(result2, "FFREE ST(2) should make third pop empty");
}

#[test]
fn test_ffree_same_register_twice() {
    // Free the same register twice
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0xC0, // FFREE ST(0) again
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 99.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(result, "Double FFREE keeps the register empty");
}

// ============================================================================
// FFREE - With Operations
// ============================================================================

#[test]
fn test_ffree_before_operation() {
    // FFREE empties the register that FADDP later reads as ST(1): a stack
    // underflow, whose masked response is the x87 indefinite (Intel SDM
    // Vol. 1, 8.5.1.1; confirmed on Rosetta 2: result FFF8000000000000,
    // FSW 0041h)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDE, 0xC1, // FADDP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 5.0);
    write_f64(&mem, 0x2008, 10.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(
        result.to_bits(),
        0xFFF8_0000_0000_0000,
        "an emptied register is a stack underflow"
    );
}

#[test]
fn test_ffree_after_operation() {
    // FFREE after an operation
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xD9, 0xFA, // FSQRT
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 16.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(result, "FFREE after FSQRT marks the result empty");
}

// ============================================================================
// FFREE - Special Values
// ============================================================================

#[test]
fn test_ffree_zero() {
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 0.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(result, "FFREE should mark zero-valued ST(0) empty");
}

#[test]
fn test_ffree_infinity() {
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, f64::INFINITY);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(result, "FFREE should mark infinite ST(0) empty");
}

#[test]
fn test_ffree_nan() {
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, f64::NAN);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert!(result.is_nan(), "FFREE should work with NaN");
}

// ============================================================================
// FFREE - Various Stack Positions
// ============================================================================

#[test]
fn test_ffree_all_positions() {
    // Test FFREE on each stack position
    for i in 0..8 {
        let mut code = vec![
            0xDD,
            0x04,
            0x25,
            0x00,
            0x20,
            0x00,
            0x00, // FLD qword [0x2000]
            0xDD,
            0xC0 + i, // FFREE ST(i)
            0xDD,
            0x1C,
            0x25,
            0x00,
            0x30,
            0x00,
            0x00, // FSTP qword [0x3000]
            0xF4, // HLT
        ];

        let (mut vcpu, mem) = setup_vm(&code, None);
        write_f64(&mem, 0x2000, i as f64);

        run_until_hlt(&mut vcpu).unwrap();

        let result = read_f64(&mem, 0x3000);
        if i == 0 {
            assert_empty_pop(result, "FFREE ST(0) should make ST(0) empty");
        } else {
            assert_eq!(result, i as f64, "FFREE ST({}) should not affect ST(0)", i);
        }
    }
}

#[test]
fn test_ffree_with_full_stack() {
    // FFREE with a full stack
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xDD, 0x04, 0x25, 0x18, 0x20, 0x00, 0x00, // FLD qword [0x2018]
        0xDD, 0xC3, // FFREE ST(3)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 10.0);
    write_f64(&mem, 0x2008, 20.0);
    write_f64(&mem, 0x2010, 30.0);
    write_f64(&mem, 0x2018, 40.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(result, 40.0, "FFREE should work with full stack");
}

#[test]
fn test_ffree_pattern() {
    // Free every other register
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xDD, 0x04, 0x25, 0x18, 0x20, 0x00, 0x00, // FLD qword [0x2018]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0xC2, // FFREE ST(2)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xDD, 0x1C, 0x25, 0x08, 0x30, 0x00, 0x00, // FSTP qword [0x3008]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 1.0);
    write_f64(&mem, 0x2008, 2.0);
    write_f64(&mem, 0x2010, 3.0);
    write_f64(&mem, 0x2018, 4.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result0 = read_f64(&mem, 0x3000);
    let result1 = read_f64(&mem, 0x3008);
    assert_empty_pop(result0, "Pattern FFREE should empty the first pop");
    assert_eq!(result1, 3.0);
}

#[test]
fn test_ffree_reverse_order() {
    // Free registers in reverse order
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0x04, 0x25, 0x10, 0x20, 0x00, 0x00, // FLD qword [0x2010]
        0xDD, 0xC2, // FFREE ST(2)
        0xDD, 0xC1, // FFREE ST(1)
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 11.0);
    write_f64(&mem, 0x2008, 22.0);
    write_f64(&mem, 0x2010, 33.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_empty_pop(result, "Reverse order FFREE should empty ST(0)");
}

#[test]
fn test_ffree_preserves_values() {
    // FFREE keeps the values but tags both registers empty, so FADDP
    // underflows: the masked response is the x87 indefinite (confirmed on
    // Rosetta 2: result FFF8000000000000, FSW 0041h)
    let code = [
        0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // FLD qword [0x2000]
        0xDD, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00, // FLD qword [0x2008]
        0xDD, 0xC0, // FFREE ST(0)
        0xDD, 0xC1, // FFREE ST(1)
        // Use the values after FFREE
        0xDE, 0xC1, // FADDP
        0xDD, 0x1C, 0x25, 0x00, 0x30, 0x00, 0x00, // FSTP qword [0x3000]
        0xF4, // HLT
    ];

    let (mut vcpu, mem) = setup_vm(&code, None);
    write_f64(&mem, 0x2000, 7.0);
    write_f64(&mem, 0x2008, 8.0);

    run_until_hlt(&mut vcpu).unwrap();

    let result = read_f64(&mem, 0x3000);
    assert_eq!(
        result.to_bits(),
        0xFFF8_0000_0000_0000,
        "emptied registers are a stack underflow"
    );
}
