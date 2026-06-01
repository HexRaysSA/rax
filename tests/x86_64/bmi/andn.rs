use crate::common::*;
use rax::cpu::Registers;

// ANDN - Logical AND NOT (BMI1)
// Performs a bitwise AND operation with the first source operand and the bitwise NOT of the second source operand.
// This is equivalent to: dest = src1 & ~src2
// Sets ZF if result is zero, clears CF, OF, SF, AF, PF are undefined.
//
// Opcodes:
// VEX.NDS.LZ.0F38.W0 F2 /r   ANDN r32, r32, r/m32   - AND NOT (32-bit)
// VEX.NDS.LZ.0F38.W1 F2 /r   ANDN r64, r64, r/m64   - AND NOT (64-bit)

#[test]
fn test_andn_eax_ebx_ecx_basic() {
    // ANDN EAX, EBX, ECX - dest = ebx & ~ecx
    // ModRM 0xC1: mod=11, reg=0 (EAX), r/m=1 (ECX)
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0b1111_1111;
    regs.rcx = 0b0000_1111;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // ~0b0000_1111 = 0xFFFFFFF0, 0b1111_1111 & 0xFFFFFFF0 = 0xF0
    assert_eq!(regs.rax & 0xFFFFFFFF, 0xF0, "EAX should contain EBX AND NOT ECX");
    assert!(!zf_set(regs.rflags), "ZF should be clear (result is non-zero)");
    assert!(!cf_set(regs.rflags), "CF should be clear");
}

#[test]
fn test_andn_eax_ebx_ecx_zero_result() {
    // ANDN that results in zero
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0b0000_1111; // First operand
    regs.rcx = 0xFFFFFFFF; // Second operand (all 1s, so ~ecx is 0)
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rax & 0xFFFFFFFF, 0, "EAX should be zero");
    assert!(zf_set(regs.rflags), "ZF should be set (result is zero)");
}

#[test]
fn test_andn_eax_ebx_ecx_all_ones_mask() {
    // ANDN with all 1s in second operand
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0x12345678;
    regs.rcx = 0x00000000; // Zero means ~0 is all 1s
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rax & 0xFFFFFFFF, 0x12345678, "EAX should equal EBX (AND with all 1s)");
}

#[test]
fn test_andn_rax_rbx_rcx_64bit() {
    // ANDN RAX, RBX, RCX - 64-bit version
    let code = [
        0xc4, 0xe2, 0xe0, 0xf2, 0xc1, // ANDN RAX, RBX, RCX (ModRM: r/m=1 RCX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0xFFFFFFFFFFFFFFFF;
    regs.rcx = 0x00000000FFFFFFFF;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // ~0x00000000FFFFFFFF = 0xFFFFFFFF00000000
    // 0xFFFFFFFFFFFFFFFF & 0xFFFFFFFF00000000 = 0xFFFFFFFF00000000
    assert_eq!(regs.rax, 0xFFFFFFFF00000000, "RAX should contain RBX AND NOT RCX");
}

#[test]
fn test_andn_basic_bit_patterns() {
    // Test with basic bit patterns
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];

    let test_cases = [
        (0x0000_0000u32, 0xFFFF_FFFFu32, 0x0000_0000u32), // 0 & ~(all 1s) = 0
        (0xFFFF_FFFFu32, 0x0000_0000u32, 0xFFFF_FFFFu32), // (all 1s) & ~0 = all 1s
        (0xAAAA_AAAAu32, 0x5555_5555u32, 0xAAAA_AAAAu32), // alternating & ~alternating = first
        (0x5555_5555u32, 0xAAAA_AAAAu32, 0x5555_5555u32), // alternating & ~alternating = first
    ];

    for (ebx, ecx, expected) in &test_cases {
        let mut regs = Registers::default();
        regs.rbx = *ebx as u64;
        regs.rcx = *ecx as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax & 0xFFFFFFFF, *expected as u64, "ANDN({:08x}, {:08x}) should be {:08x}", ebx, ecx, expected);
    }
}

#[test]
fn test_andn_single_bit_first_operand() {
    // Test with single bit in first operand
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];

    for bit_pos in 0..32 {
        let mut regs = Registers::default();
        regs.rbx = 1u64 << bit_pos;
        regs.rcx = 0xFFFFFFFF;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax & 0xFFFFFFFF, 0, "Single bit AND with ~(all 1s) should be zero");
    }
}

#[test]
fn test_andn_single_bit_second_operand() {
    // Test with single bit in second operand
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];

    for bit_pos in 0..32 {
        let mut regs = Registers::default();
        regs.rbx = 0xFFFFFFFF;
        regs.rcx = 1u64 << bit_pos;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        let expected = 0xFFFFFFFF ^ (1u64 << bit_pos); // All 1s with one bit cleared
        assert_eq!(regs.rax & 0xFFFFFFFF, expected, "All 1s AND with ~(single bit) should clear that bit");
    }
}

#[test]
fn test_andn_with_extended_registers() {
    // ANDN R8D, R9D, R10D
    // VEX byte1 0x42: R=0(REX.R=1), X=1(REX.X=0), B=0(REX.B=1), m_mmmm=2
    // VEX byte2 0x30: W=0, vvvv=6(~9), L=0, pp=0
    // ModRM 0xC2: mod=11, reg=0(+REX.R=8=R8), r/m=2(+REX.B=10=R10)
    let code = [
        0xc4, 0x42, 0x30, 0xf2, 0xc2, // ANDN R8D, R9D, R10D
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.r9 = 0b1111_0000;
    regs.r10 = 0b0011_1100;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // ~0b0011_1100 = 0xFFFFFFC3, 0b1111_0000 & 0xFFFFFFC3 = 0xC0
    assert_eq!(regs.r8 & 0xFFFFFFFF, 0xC0, "R8D should contain R9D AND NOT R10D");
}

#[test]
fn test_andn_preserves_first_operand() {
    // ANDN should not modify the first source operand
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0x12345678;
    regs.rcx = 0x87654321;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rbx & 0xFFFFFFFF, 0x12345678, "EBX should be unchanged");
    assert_eq!(regs.rcx & 0xFFFFFFFF, 0x87654321, "ECX should be unchanged");
}

#[test]
fn test_andn_mem32() {
    // ANDN EAX, EBX, [mem]
    // ModRM 0x04: mod=00, reg=0 (EAX), r/m=4 (SIB follows)
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // ANDN EAX, EBX, [DATA_ADDR]
        0xf4,
    ];
    let mut initial_regs = Registers::default();
    initial_regs.rbx = 0xFFFFFFFF;
    let (mut vcpu, mem) = setup_vm(&code, Some(initial_regs));
    write_mem_u32(&mem, 0x00000000);
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rax & 0xFFFFFFFF, 0xFFFFFFFF, "EAX should contain EBX AND NOT [mem]");
}

#[test]
fn test_andn_mem64() {
    // ANDN RAX, RBX, [mem]
    // ModRM 0x04: mod=00, reg=0 (RAX), r/m=4 (SIB follows)
    let code = [
        0xc4, 0xe2, 0xe0, 0xf2, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // ANDN RAX, RBX, [DATA_ADDR]
        0xf4,
    ];
    let mut initial_regs = Registers::default();
    initial_regs.rbx = 0xFFFFFFFFFFFFFFFF;
    let (mut vcpu, mem) = setup_vm(&code, Some(initial_regs));
    write_mem_u64(&mem, 0x00000000FFFFFFFF);
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // ~0x00000000FFFFFFFF = 0xFFFFFFFF00000000
    // 0xFFFFFFFFFFFFFFFF & 0xFFFFFFFF00000000 = 0xFFFFFFFF00000000
    assert_eq!(regs.rax, 0xFFFFFFFF00000000, "RAX should contain RBX AND NOT [mem]");
}

#[test]
fn test_andn_mask_extraction() {
    // Practical use: extract bits where mask is zero
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0xDEADBEEF;
    regs.rcx = 0x0000FFFF; // Mask for lower bits
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // ~0x0000FFFF = 0xFFFF0000
    // 0xDEADBEEF & 0xFFFF0000 = 0xDEAD0000
    assert_eq!(regs.rax & 0xFFFFFFFF, 0xDEAD0000, "Should extract high bits where mask is zero");
}

#[test]
fn test_andn_complementary_masks() {
    // Test with complementary bitmasks
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];

    let test_cases = [
        (0xFF00FF00u32, 0x00FF00FFu32, 0xFF00FF00u32), // Complementary masks
        (0xF0F0F0F0u32, 0x0F0F0F0Fu32, 0xF0F0F0F0u32), // Complementary patterns
        (0x12345678u32, 0x12345678u32, 0x00000000u32), // Same value
    ];

    for (ebx, ecx, expected) in &test_cases {
        let mut regs = Registers::default();
        regs.rbx = *ebx as u64;
        regs.rcx = *ecx as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax & 0xFFFFFFFF, *expected as u64, "ANDN({:08x}, {:08x}) should be {:08x}", ebx, ecx, expected);
    }
}

#[test]
fn test_andn_64bit_comprehensive() {
    // Comprehensive 64-bit test
    let code = [
        0xc4, 0xe2, 0xe0, 0xf2, 0xc1, // ANDN RAX, RBX, RCX (ModRM: r/m=1 RCX)
        0xf4,
    ];
    let test_cases = [
        (0x0000000000000000u64, 0xFFFFFFFFFFFFFFFFu64, 0x0000000000000000u64),
        (0xFFFFFFFFFFFFFFFFu64, 0x0000000000000000u64, 0xFFFFFFFFFFFFFFFFu64),
        (0x00000000FFFFFFFFu64, 0xFFFFFFFF00000000u64, 0x00000000FFFFFFFFu64),
        (0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64, 0xAAAAAAAAAAAAAAAAu64),
    ];

    for (rbx, rcx, expected) in &test_cases {
        let mut regs = Registers::default();
        regs.rbx = *rbx;
        regs.rcx = *rcx;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax, *expected, "ANDN({:016x}, {:016x}) should be {:016x}", rbx, rcx, expected);
    }
}

#[test]
fn test_andn_flags_zf_only() {
    // Test that only ZF is affected by ANDN
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];

    // Result is zero
    let mut regs = Registers::default();
    regs.rbx = 0x12345678;
    regs.rcx = 0xFFFFFFFF;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();
    assert!(zf_set(regs.rflags), "ZF should be set for zero result");
    assert!(!cf_set(regs.rflags), "CF should be clear");

    // Result is non-zero
    let mut regs = Registers::default();
    regs.rbx = 0x12345678;
    regs.rcx = 0x00000000;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();
    assert!(!zf_set(regs.rflags), "ZF should be clear for non-zero result");
    assert!(!cf_set(regs.rflags), "CF should be clear");
}

#[test]
fn test_andn_identity_operations() {
    // Test identity-like operations
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];

    // ANDN x, x, 0 = x
    let mut regs = Registers::default();
    regs.rbx = 0x12345678;
    regs.rcx = 0x00000000;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();
    assert_eq!(regs.rax & 0xFFFFFFFF, 0x12345678, "ANDN x, x, 0 should equal x");

    // ANDN x, x, -1 = 0
    let mut regs = Registers::default();
    regs.rbx = 0x12345678;
    regs.rcx = 0xFFFFFFFF;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();
    assert_eq!(regs.rax & 0xFFFFFFFF, 0, "ANDN x, x, -1 should be zero");
}

#[test]
fn test_andn_sequential_operations() {
    // Test sequential ANDN operations
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut value = 0xFFFFFFFFu32;

    let masks = [0xF0F0F0F0u32, 0x0F0F0F0Fu32];

    for mask in &masks {
        let mut regs = Registers::default();
        regs.rbx = value as u64;
        regs.rcx = *mask as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let result_regs = run_until_hlt(&mut vcpu).unwrap();
        value = (result_regs.rax & 0xFFFFFFFF) as u32;
    }

    // Step 1: 0xFFFFFFFF & ~0xF0F0F0F0 = 0x0F0F0F0F
    // Step 2: 0x0F0F0F0F & ~0x0F0F0F0F = 0x00000000
    assert_eq!(value, 0x00000000u32, "Sequential ANDNs should produce correct result");
}

#[test]
fn test_andn_byte_patterns() {
    // Test with various byte-aligned patterns
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];

    let test_cases = [
        (0xFF000000u32, 0x00FFFFFFu32, 0xFF000000u32), // High byte
        (0x00FF0000u32, 0xFF00FFFFu32, 0x00FF0000u32), // Mid-high byte
        (0x0000FF00u32, 0xFFFF00FFu32, 0x0000FF00u32), // Mid-low byte
        (0x000000FFu32, 0xFFFFFF00u32, 0x000000FFu32), // Low byte
    ];

    for (ebx, ecx, expected) in &test_cases {
        let mut regs = Registers::default();
        regs.rbx = *ebx as u64;
        regs.rcx = *ecx as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax & 0xFFFFFFFF, *expected as u64, "ANDN byte pattern test failed");
    }
}

#[test]
fn test_andn_practical_bit_selection() {
    // Practical use: select bits from first operand where mask is zero
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0xFEDCBA98; // Source data
    regs.rcx = 0x00FF00FF; // Mask: zero for bits to keep
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // Keep bits where mask is zero
    // ~0x00FF00FF = 0xFF00FF00
    // 0xFEDCBA98 & 0xFF00FF00 = 0xFE00BA00
    assert_eq!(regs.rax & 0xFFFFFFFF, 0xFE00BA00, "Should keep bits where mask is zero");
}

#[test]
fn test_andn_64bit_high_low_bits() {
    // Test 64-bit with mixed high and low bits
    let code = [
        0xc4, 0xe2, 0xe0, 0xf2, 0xc1, // ANDN RAX, RBX, RCX (ModRM: r/m=1 RCX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0xFF00FF00FF00FF00u64;
    regs.rcx = 0x00FF00FF00FF00FFu64;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rax, 0xFF00FF00FF00FF00u64, "64-bit ANDN with complementary patterns");
}

#[test]
fn test_andn_rotate_pattern() {
    // Test with rotated bit patterns
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0x00FFFF00;
    regs.rcx = 0xFF0000FF;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rax & 0xFFFFFFFF, 0x00FFFF00, "ANDN with rotated patterns");
}

#[test]
fn test_andn_all_zero_patterns() {
    // Test with patterns resulting in zero
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let test_cases = [
        (0x00000000u32, 0x00000000u32, 0x00000000u32),
        (0xFFFFFFFFu32, 0xFFFFFFFFu32, 0x00000000u32),
        (0x12345678u32, 0x12345678u32, 0x00000000u32),
    ];

    for (ebx, ecx, expected) in &test_cases {
        let mut regs = Registers::default();
        regs.rbx = *ebx as u64;
        regs.rcx = *ecx as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax & 0xFFFFFFFF, *expected as u64, "Zero pattern test");
    }
}

#[test]
fn test_andn_high_low_extraction_64bit() {
    // Extract high/low parts using ANDN
    let code = [
        0xc4, 0xe2, 0xe0, 0xf2, 0xc1, // ANDN RAX, RBX, RCX (ModRM: r/m=1 RCX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0x12345678_ABCDEF00u64;
    regs.rcx = 0xFFFFFFFF_00000000u64; // Mask: keep lower 32 bits
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // ~0xFFFFFFFF_00000000 = 0x00000000_FFFFFFFF
    // 0x12345678_ABCDEF00 & 0x00000000_FFFFFFFF = 0x00000000_ABCDEF00
    assert_eq!(regs.rax, 0x00000000ABCDEF00u64, "Extract lower 32 bits");
}

#[test]
fn test_andn_gradient_patterns() {
    // Test with gradient bit patterns
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let test_cases = [
        (0xF0000000u32, 0x0F000000u32, 0xF0000000u32),
        (0x0F000000u32, 0xF0000000u32, 0x0F000000u32),
        // 0x00F00000 & ~0xFF00FF00 = 0x00F00000 & 0x00FF00FF = 0x00F00000
        (0x00F00000u32, 0xFF00FF00u32, 0x00F00000u32),
    ];

    for (ebx, ecx, expected) in &test_cases {
        let mut regs = Registers::default();
        regs.rbx = *ebx as u64;
        regs.rcx = *ecx as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax & 0xFFFFFFFF, *expected as u64, "Gradient pattern test");
    }
}

#[test]
fn test_andn_with_r15() {
    // Test with R15 register
    // VEX byte 0x62: R=0(REX.R=1), X=1(REX.X=0), B=1(REX.B=0), m_mmmm=2
    // ModRM 0xf9: mod=11, reg=111(+REX.R=15=R15), r/m=001(+REX.B=0=RCX)
    let code = [
        0xc4, 0x62, 0x80, 0xf2, 0xf9, // ANDN R15, R15, RCX
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.r15 = 0xDEADBEEFDEADBEEFu64;
    regs.rcx = 0x00000000FFFFFFFFu64;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // ~0x00000000FFFFFFFF = 0xFFFFFFFF00000000
    // 0xDEADBEEFDEADBEEF & 0xFFFFFFFF00000000 = 0xDEADBEEF00000000
    assert_eq!(regs.r15, 0xDEADBEEF00000000u64, "R15 ANDN operation");
}

#[test]
fn test_andn_chained_operations() {
    // Chain multiple ANDN operations
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut value = 0xFFFFFFFFu32;
    let masks = [0xF0F0F0F0u32, 0x00FF00FFu32, 0x0F0F0F0Fu32];

    for &mask in &masks {
        let mut regs = Registers::default();
        regs.rbx = value as u64;
        regs.rcx = mask as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let result = run_until_hlt(&mut vcpu).unwrap();
        value = (result.rax & 0xFFFFFFFF) as u32;
    }

    // After 3 chained ANDN operations:
    // Step 1: 0xFFFFFFFF & ~0xF0F0F0F0 = 0x0F0F0F0F
    // Step 2: 0x0F0F0F0F & ~0x00FF00FF = 0x0F000F00
    // Step 3: 0x0F000F00 & ~0x0F0F0F0F = 0x00000000
    assert_eq!(value, 0x00000000u32, "Chained ANDN operations");
}

#[test]
fn test_andn_nibble_extraction() {
    // Extract individual nibbles using ANDN
    // For 0xABCDEF12: nibble0=2, nibble1=1, nibble2=F, nibble3=E
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0xABCDEF12;

    // (mask, expected_result): result = 0xABCDEF12 & ~mask
    let masks = [
        (0xFFFFFFF0u32, 0x00000002u32), // Extract nibble 0: ~0xFFFFFFF0 = 0x0F, 0x12 & 0x0F = 0x02
        (0xFFFFFF0Fu32, 0x00000010u32), // Extract nibble 1: ~0xFFFFFF0F = 0xF0, 0x12 & 0xF0 = 0x10
        (0xFFFFF0FFu32, 0x00000F00u32), // Extract nibble 2: ~0xFFFFF0FF = 0xF00, 0xEF12 & 0xF00 = 0xF00
        (0xFFFF0FFFu32, 0x0000E000u32), // Extract nibble 3: ~0xFFFF0FFF = 0xF000, 0xEF12 & 0xF000 = 0xE000
    ];

    for (mask, expected) in &masks {
        let mut test_regs = regs.clone();
        test_regs.rcx = *mask as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(test_regs));
        let result = run_until_hlt(&mut vcpu).unwrap();
        assert_eq!(result.rax & 0xFFFFFFFF, *expected as u64, "Nibble extraction for mask {:#x}", mask);
    }
}

#[test]
fn test_andn_boundary_transitions() {
    // Test bit patterns at byte/word boundaries
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let test_cases = [
        (0x000000FFu32, 0xFFFFFF00u32, 0x000000FFu32), // Byte 0
        (0x0000FF00u32, 0xFFFF00FFu32, 0x0000FF00u32), // Byte 1
        (0x00FF0000u32, 0xFF00FFFFu32, 0x00FF0000u32), // Byte 2
        (0xFF000000u32, 0x00FFFFFFu32, 0xFF000000u32), // Byte 3
    ];

    for (ebx, ecx, expected) in &test_cases {
        let mut regs = Registers::default();
        regs.rbx = *ebx as u64;
        regs.rcx = *ecx as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax & 0xFFFFFFFF, *expected as u64, "Boundary transition test");
    }
}

#[test]
fn test_andn_symmetric_patterns() {
    // Test with symmetric bit patterns
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let test_cases = [
        (0x33333333u32, 0xCCCCCCCCu32, 0x33333333u32),
        (0xCCCCCCCCu32, 0x33333333u32, 0xCCCCCCCCu32),
        (0x99999999u32, 0x66666666u32, 0x99999999u32),
    ];

    for (ebx, ecx, expected) in &test_cases {
        let mut regs = Registers::default();
        regs.rbx = *ebx as u64;
        regs.rcx = *ecx as u64;
        let (mut vcpu, _) = setup_vm(&code, Some(regs));
        let regs = run_until_hlt(&mut vcpu).unwrap();

        assert_eq!(regs.rax & 0xFFFFFFFF, *expected as u64, "Symmetric pattern test");
    }
}

#[test]
fn test_andn_inverse_extraction() {
    // Use ANDN to extract inverse mask regions
    let code = [
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (ModRM: r/m=1 ECX)
        0xf4,
    ];
    let mut regs = Registers::default();
    regs.rbx = 0x12345678;
    regs.rcx = 0x0F0F0F0F; // Mask alternating nibbles
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    // ~0x0F0F0F0F = 0xF0F0F0F0
    // 0x12345678 & 0xF0F0F0F0 = 0x10305070
    assert_eq!(regs.rax & 0xFFFFFFFF, 0x10305070, "Inverse mask extraction");
}

// ============================================================================
// Lazy-flags regression tests (BMI flag-writing instructions)
//
// rax uses lazy flags: ALU ops (e.g. OR) store operands and defer flag
// computation until a flag reader (SETcc/Jcc) calls materialize_flags().
// The BMI instructions ANDN/BLSR/BEXTR write defined flags EAGERLY, so they
// must afterward call clear_lazy_flags() to drop any stale pending lazy op.
// Without that, a subsequent SETZ/JZ re-materializes the prior op's flags and
// silently clobbers the BMI instruction's correct ZF. These tests pin that
// behavior: each runs an OR producing ZF=0, then a BMI op producing ZF=1, then
// a flag consumer that must observe ZF=1.
// ============================================================================

#[test]
fn test_andn_clears_stale_lazy_zf_setz() {
    // EDX=1; OR EDX,EDX -> result 1, lazy ZF=0.
    // ANDN EAX,EBX,ECX with EBX=0x0F, ECX=0xFFFFFFFF -> result 0, ZF=1.
    // SETZ DL must observe ANDN's ZF=1, not the stale OR's ZF=0.
    let code = [
        0xba, 0x01, 0x00, 0x00, 0x00, // MOV EDX, 1
        0x09, 0xd2, // OR EDX, EDX  (sets lazy flags, ZF=0)
        0xc4, 0xe2, 0x60, 0xf2, 0xc1, // ANDN EAX, EBX, ECX (result 0 -> ZF=1)
        0x0f, 0x94, 0xc2, // SETZ DL
        0xf4, // HLT
    ];
    let mut regs = Registers::default();
    regs.rbx = 0x0000_000F;
    regs.rcx = 0xFFFF_FFFF;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rax & 0xFFFFFFFF, 0, "ANDN result should be zero");
    assert!(zf_set(regs.rflags), "ZF must reflect ANDN (result zero), not stale OR");
    // MOV EDX,1 zero-extended RDX to 1; SETZ DL then writes ZF into DL.
    assert_eq!(regs.rdx, 1, "SETZ must see ANDN's ZF=1, not the stale OR's ZF=0");
}

#[test]
fn test_blsr_clears_stale_lazy_zf_jz() {
    // EDX=1; OR EDX,EDX -> lazy ZF=0.
    // BLSR EAX,EBX with EBX=1 -> result 0, ZF=1.
    // JZ must jump based on BLSR's ZF=1, not the stale OR's ZF=0.
    let code = [
        0xba, 0x01, 0x00, 0x00, 0x00, // MOV EDX, 1
        0x09, 0xd2, // OR EDX, EDX  (sets lazy flags, ZF=0)
        0xc4, 0xe2, 0x78, 0xf3, 0xcb, // BLSR EAX, EBX (EBX=1 -> result 0 -> ZF=1)
        0x74, 0x09, // JZ +9 (.taken) - skip MOV RBX,0 (7) + JMP (2)
        0x48, 0xc7, 0xc3, 0x00, 0x00, 0x00, 0x00, // MOV RBX, 0 (not taken)
        0xeb, 0x07, // JMP +7 (.done) - skip MOV RBX,1 (7)
        // .taken:
        0x48, 0xc7, 0xc3, 0x01, 0x00, 0x00, 0x00, // MOV RBX, 1
        // .done:
        0xf4, // HLT
    ];
    let mut regs = Registers::default();
    regs.rbx = 0x0000_0001;
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rax & 0xFFFFFFFF, 0, "BLSR result should be zero");
    assert_eq!(regs.rbx, 1, "JZ must jump on BLSR's ZF=1, not the stale OR's ZF=0");
}

#[test]
fn test_bextr_clears_stale_lazy_zf_setz() {
    // EDX=1; OR EDX,EDX -> lazy ZF=0.
    // BEXTR EAX,EBX,ECX with ECX=0 (len=0) -> result 0, ZF=1.
    // SETZ DL must observe BEXTR's ZF=1, not the stale OR's ZF=0.
    let code = [
        0xba, 0x01, 0x00, 0x00, 0x00, // MOV EDX, 1
        0x09, 0xd2, // OR EDX, EDX  (sets lazy flags, ZF=0)
        0xc4, 0xe2, 0x70, 0xf7, 0xc3, // BEXTR EAX, EBX, ECX (ECX=0 -> result 0 -> ZF=1)
        0x0f, 0x94, 0xc2, // SETZ DL
        0xf4, // HLT
    ];
    let mut regs = Registers::default();
    regs.rbx = 0xDEAD_BEEF;
    regs.rcx = 0x0000_0000; // start=0, len=0 -> extracts nothing
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    let regs = run_until_hlt(&mut vcpu).unwrap();

    assert_eq!(regs.rax & 0xFFFFFFFF, 0, "BEXTR with len=0 should be zero");
    assert!(zf_set(regs.rflags), "ZF must reflect BEXTR (result zero), not stale OR");
    assert_eq!(regs.rdx, 1, "SETZ must see BEXTR's ZF=1, not the stale OR's ZF=0");
}
