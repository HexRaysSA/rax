//! tests::memory tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

#[test]
fn neon_ldst_structures_effective_addresses_wrap() {
    let mut cpu = create_wrapping_memory_cpu();

    // LD1 {V0.8B}, [X5]. Starting at u64::MAX makes the inter-element
    // address increment wrap after the first byte.
    cpu.set_x(5, u64::MAX);
    assert_eq!(
        cpu.exec_ldst_structures(encode_ld1_structure(0, 0, 5, 0))
            .unwrap(),
        CpuExit::Continue
    );
    assert_eq!(cpu.get_simd_reg(0), Some((0x0605_0403_0201_003f, 0)));

    // LD1 {V1.2S}, [X5]. Starting near u64::MAX makes the per-element
    // byte address wrap while assembling the first 32-bit element.
    cpu.set_x(5, u64::MAX - 2);
    assert_eq!(
        cpu.exec_ldst_structures(encode_ld1_structure(0, 2, 5, 1))
            .unwrap(),
        CpuExit::Continue
    );
    assert_eq!(cpu.get_simd_reg(1), Some((0x0403_0201_003f_3e3d, 0)));
}
// -------------------------------------------------------------------------
// Load/Store Instructions - LDR Literal
// -------------------------------------------------------------------------

#[test]
fn test_ldr_literal_64() {
    // LDR X0, #0x100 (load from PC+0x100)
    let insn = 0x58000800; // LDR X0, #0x100
    let mut cpu = create_cpu_with_insn(insn);
    // Write test value at offset 0x100
    cpu.write_memory(0x100, &0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes())
        .unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xDEAD_BEEF_CAFE_BABE);
}
#[test]
fn test_ldr_literal_32() {
    // LDR W0, #0x80
    let insn = 0x18000400; // LDR W0, #0x80
    let mut cpu = create_cpu_with_insn(insn);
    cpu.write_memory(0x80, &0x1234_5678u32.to_le_bytes())
        .unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x1234_5678);
}
#[test]
fn test_ldrsw_literal() {
    // LDRSW X0, #0x40 (sign-extended 32-bit load)
    let insn = 0x98000200; // LDRSW X0, #0x40
    let mut cpu = create_cpu_with_insn(insn);
    cpu.write_memory(0x40, &0x8000_0001u32.to_le_bytes())
        .unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xFFFF_FFFF_8000_0001); // Sign-extended
}
// -------------------------------------------------------------------------
// Load/Store Instructions - Load/Store Pair
// -------------------------------------------------------------------------

#[test]
fn test_stp_64() {
    // STP X0, X1, [X2]
    let insn = 0xA9000440; // STP X0, X1, [X2]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0x1111_1111_1111_1111);
    cpu.set_x(1, 0x2222_2222_2222_2222);
    cpu.set_x(2, 0x1000);
    cpu.step().unwrap();

    let data = cpu.read_memory(0x1000, 8).unwrap();
    assert_eq!(
        u64::from_le_bytes(data[..8].try_into().unwrap()),
        0x1111_1111_1111_1111
    );

    let data = cpu.read_memory(0x1008, 8).unwrap();
    assert_eq!(
        u64::from_le_bytes(data[..8].try_into().unwrap()),
        0x2222_2222_2222_2222
    );
}
#[test]
fn test_ldp_64() {
    // LDP X0, X1, [X2]
    let insn = 0xA9400440; // LDP X0, X1, [X2]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(2, 0x1000);
    cpu.write_memory(0x1000, &0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes())
        .unwrap();
    cpu.write_memory(0x1008, &0x1234_5678_9ABC_DEF0u64.to_le_bytes())
        .unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xAAAA_BBBB_CCCC_DDDD);
    assert_eq!(cpu.get_x(1), 0x1234_5678_9ABC_DEF0);
}
#[test]
fn test_ldp_post_index() {
    // LDP X0, X1, [X2], #16
    let insn = 0xA8C10440; // LDP X0, X1, [X2], #16
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(2, 0x1000);
    cpu.write_memory(0x1000, &1u64.to_le_bytes()).unwrap();
    cpu.write_memory(0x1008, &2u64.to_le_bytes()).unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 1);
    assert_eq!(cpu.get_x(1), 2);
    assert_eq!(cpu.get_x(2), 0x1010); // Post-indexed
}
#[test]
fn test_stp_pre_index() {
    // STP X0, X1, [X2, #-16]!
    let insn = 0xA9BF0440; // STP X0, X1, [X2, #-16]!
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0x1111);
    cpu.set_x(1, 0x2222);
    cpu.set_x(2, 0x1010);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(2), 0x1000); // Pre-indexed
}
#[test]
fn test_ldp_32() {
    // LDP W0, W1, [X2]
    let insn = 0x29400440; // LDP W0, W1, [X2]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(2, 0x1000);
    cpu.write_memory(0x1000, &0xDEAD_BEEFu32.to_le_bytes())
        .unwrap();
    cpu.write_memory(0x1004, &0xCAFE_BABEu32.to_le_bytes())
        .unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xDEAD_BEEF);
    assert_eq!(cpu.get_x(1), 0xCAFE_BABE);
}
// -------------------------------------------------------------------------
// Load/Store Instructions - Register Offset
// -------------------------------------------------------------------------

#[test]
fn test_str_imm() {
    // STR X0, [X1, #8]
    let insn = 0xF9000420; // STR X0, [X1, #8]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0xDEAD_BEEF_1234_5678);
    cpu.set_x(1, 0x1000);
    cpu.step().unwrap();

    let data = cpu.read_memory(0x1008, 8).unwrap();
    assert_eq!(
        u64::from_le_bytes(data[..8].try_into().unwrap()),
        0xDEAD_BEEF_1234_5678
    );
}
#[test]
fn test_ldr_imm() {
    // LDR X0, [X1, #16]
    let insn = 0xF9400820; // LDR X0, [X1, #16]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1000);
    cpu.write_memory(0x1010, &0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes())
        .unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xCAFE_BABE_DEAD_BEEF);
}
#[test]
fn test_strb() {
    // STRB W0, [X1]
    let insn = 0x39000020; // STRB W0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0x1234_5678);
    cpu.set_x(1, 0x1000);
    cpu.step().unwrap();

    let data = cpu.read_memory(0x1000, 1).unwrap();
    assert_eq!(data[0], 0x78);
}
#[test]
fn test_ldrb() {
    // LDRB W0, [X1]
    let insn = 0x39400020; // LDRB W0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1000);
    cpu.write_memory(0x1000, &[0xAB]).unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xAB);
}
#[test]
fn test_ldrsb() {
    // LDRSB X0, [X1] (sign-extend byte to 64-bit)
    let insn = 0x39800020; // LDRSB X0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1000);
    cpu.write_memory(0x1000, &[0x80]).unwrap(); // Negative byte
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xFFFF_FFFF_FFFF_FF80);
}
#[test]
fn test_strh() {
    // STRH W0, [X1]
    let insn = 0x79000020; // STRH W0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0x1234_5678);
    cpu.set_x(1, 0x1000);
    cpu.step().unwrap();

    let data = cpu.read_memory(0x1000, 2).unwrap();
    assert_eq!(u16::from_le_bytes(data[..2].try_into().unwrap()), 0x5678);
}
#[test]
fn test_ldrh() {
    // LDRH W0, [X1]
    let insn = 0x79400020; // LDRH W0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1000);
    cpu.write_memory(0x1000, &0xABCDu16.to_le_bytes()).unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xABCD);
}
#[test]
fn test_ldrsh() {
    // LDRSH X0, [X1] (sign-extend halfword to 64-bit)
    let insn = 0x79800020; // LDRSH X0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1000);
    cpu.write_memory(0x1000, &0x8001u16.to_le_bytes()).unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xFFFF_FFFF_FFFF_8001);
}
#[test]
fn test_str_32() {
    // STR W0, [X1]
    let insn = 0xB9000020; // STR W0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0xDEAD_BEEF);
    cpu.set_x(1, 0x1000);
    cpu.step().unwrap();

    let data = cpu.read_memory(0x1000, 4).unwrap();
    assert_eq!(
        u32::from_le_bytes(data[..4].try_into().unwrap()),
        0xDEAD_BEEF
    );
}
#[test]
fn test_ldr_32() {
    // LDR W0, [X1]
    let insn = 0xB9400020; // LDR W0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1000);
    cpu.write_memory(0x1000, &0x1234_5678u32.to_le_bytes())
        .unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x1234_5678);
}
#[test]
fn test_ldrsw() {
    // LDRSW X0, [X1] (sign-extend word to 64-bit)
    let insn = 0xB9800020; // LDRSW X0, [X1]
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1000);
    cpu.write_memory(0x1000, &0x8000_0001u32.to_le_bytes())
        .unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xFFFF_FFFF_8000_0001);
}
#[test]
fn test_ldr_post_index() {
    // LDR X0, [X1], #8
    let insn = 0xF8408420; // LDR X0, [X1], #8
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1000);
    cpu.write_memory(0x1000, &0x1234u64.to_le_bytes()).unwrap();
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x1234);
    assert_eq!(cpu.get_x(1), 0x1008); // Post-indexed
}
#[test]
fn test_str_pre_index() {
    // STR X0, [X1, #8]!
    let insn = 0xF8008C20; // STR X0, [X1, #8]!
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0x5678);
    cpu.set_x(1, 0x1000);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(1), 0x1008); // Pre-indexed

    let data = cpu.read_memory(0x1008, 8).unwrap();
    assert_eq!(u64::from_le_bytes(data[..8].try_into().unwrap()), 0x5678);
}
#[test]
fn test_xpaclri_strips_lr_instruction_pac() {
    for input in [
        0xabcd_0000_1234_5670u64,
        0x5a00_7fff_ffff_fff0u64,
        0xffff_8000_0000_0010u64,
    ] {
        let mut cpu = create_cpu_with_insn(0xD50320FF); // XPACLRI
        cpu.set_x(30, input);

        assert!(matches!(cpu.step(), Ok(CpuExit::Continue)));
        assert_eq!(
            cpu.get_x(30),
            strip_pac(input, false),
            "XPACLRI should strip LR PAC bits"
        );
        assert_eq!(cpu.get_pc(), 4);
    }
}

// -------------------------------------------------------------------------
// LDRAA/LDRAB (encodings from `clang -arch arm64e`).
// -------------------------------------------------------------------------

fn pauth_cpu() -> AArch64Cpu {
    use crate::isa::arm::common::features::ArmFeatures;
    use crate::isa::arm::common::memory::FlatMemory;
    let config = AArch64Config {
        features: ArmFeatures::armv8_3_base(),
        ..AArch64Config::default()
    };
    AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x1000_0000)))
}

#[test]
fn test_ldraa_ldrab_offsets_and_writeback() {
    // (insn, Rt, Rn, base, address loaded, written-back base)
    let cases: [(u32, u8, u8, u64, u64, Option<u64>); 5] = [
        (0xf8200420, 0, 1, 0x2000, 0x2000, None), // ldraa x0, [x1]
        (0xf8600462, 2, 3, 0x3000, 0x2000, None), // ldraa x2, [x3, #-0x1000]
        (0xf8bffca4, 4, 5, 0x3000, 0x3ff8, Some(0x3ff8)), // ldrab x4, [x5, #0xff8]!
        (0xf82017e6, 6, 31, 0x5000, 0x5008, None), // ldraa x6, [sp, #0x8]
        (0xf8fffd07, 7, 8, 0x6008, 0x6000, Some(0x6000)), // ldrab x7, [x8, #-0x8]!
    ];
    for (insn, rt, rn, base, addr, wback) in cases {
        let mut cpu = pauth_cpu();
        cpu.write_memory(0, &insn.to_le_bytes()).unwrap();
        cpu.write_memory(addr, &0x1122_3344_5566_7788u64.to_le_bytes())
            .unwrap();
        if rn == 31 {
            cpu.set_current_sp(base);
        } else {
            cpu.set_x(rn, base);
        }
        cpu.step().unwrap();
        assert_eq!(cpu.get_x(rt), 0x1122_3344_5566_7788, "{insn:#010x}");
        let now = if rn == 31 {
            cpu.current_sp()
        } else {
            cpu.get_x(rn)
        };
        assert_eq!(now, wback.unwrap_or(base), "{insn:#010x} base");
        assert_eq!(cpu.get_pc(), 4);
    }
}

#[test]
fn test_ldraa_needs_feat_pauth_and_an_aligned_sp() {
    let mut cpu = create_test_cpu();
    cpu.write_memory(0, &0xf8200420u32.to_le_bytes()).unwrap();
    cpu.set_x(1, 0x2000);
    assert!(matches!(cpu.step(), Err(ArmError::UndefinedInstruction(_))));
    let mut cpu = pauth_cpu();
    cpu.write_memory(0, &0xf82017e6u32.to_le_bytes()).unwrap(); // ldraa x6, [sp, #8]
    cpu.set_current_sp(0x5004);
    assert!(matches!(cpu.step(), Err(ArmError::MemoryError(_))));
}
