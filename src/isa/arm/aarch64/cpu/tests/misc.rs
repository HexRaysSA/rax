//! tests::misc tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

#[test]
fn test_cpu_creation() {
    let cpu = create_test_cpu();
    assert_eq!(cpu.get_pc(), 0);
    assert_eq!(cpu.current_el(), 1);
}
#[test]
fn test_register_access() {
    let mut cpu = create_test_cpu();

    cpu.set_x(0, 0x1234_5678_9ABC_DEF0);
    assert_eq!(cpu.get_x(0), 0x1234_5678_9ABC_DEF0);

    cpu.set_w(1, 0xDEAD_BEEF);
    assert_eq!(cpu.get_w(1), 0xDEAD_BEEF);
    assert_eq!(cpu.get_x(1), 0xDEAD_BEEF); // Zero-extended

    // XZR always reads 0
    assert_eq!(cpu.get_x(31), 0);
    cpu.set_x(31, 0xFFFF); // Write to XZR is ignored
    assert_eq!(cpu.get_x(31), 0);
}
#[test]
fn test_condition_flags() {
    let mut cpu = create_test_cpu();

    cpu.set_nzcv(true, false, true, false);
    assert!(cpu.get_n());
    assert!(!cpu.get_z());
    assert!(cpu.get_c());
    assert!(!cpu.get_v());

    cpu.update_nz_64(0);
    assert!(!cpu.get_n());
    assert!(cpu.get_z());

    cpu.update_nz_64(0x8000_0000_0000_0000);
    assert!(cpu.get_n());
    assert!(!cpu.get_z());
}
#[test]
fn test_condition_evaluation() {
    let mut cpu = create_test_cpu();

    // Test EQ (Z=1)
    cpu.set_z(true);
    assert!(cpu.condition_holds(0b0000)); // EQ
    assert!(!cpu.condition_holds(0b0001)); // NE

    // Test CS (C=1)
    cpu.set_c(true);
    assert!(cpu.condition_holds(0b0010)); // CS
    assert!(!cpu.condition_holds(0b0011)); // CC

    // Test AL (always)
    assert!(cpu.condition_holds(0b1110)); // AL
}
#[test]
fn test_stack_pointer() {
    let mut cpu = create_test_cpu();

    cpu.set_current_sp(0x8000_0000);
    assert_eq!(cpu.current_sp(), 0x8000_0000);
}
#[test]
fn test_bitmask_decode() {
    // Test 64-bit mode with N=1 (64-bit elements)
    // imms=0 means a single 1 bit, immr=0 means no rotation
    let mask = decode_bitmask(true, 0, 0, true).unwrap();
    assert_eq!(mask, 0x0000_0000_0000_0001);

    // imms=62 means 63 ones (all except MSB), immr=0
    let mask = decode_bitmask(true, 62, 0, true).unwrap();
    assert_eq!(mask, 0x7FFF_FFFF_FFFF_FFFF);

    // Test N=0 (smaller element sizes)
    // ~imms[5:0] = 0x20 = 0b100000, highest bit at position 5, so len=6 (invalid for N=0)
    // Let's use imms=0b011111, so ~imms[5:0]=0b100000, but that's still len=6

    // imms=0b111100, ~imms[5:0]=0b000011, highest bit at position 1, len=1
    // (2-bit elements). s = imms & 0b1 = 0, so element = 0b01.
    let mask = decode_bitmask(false, 0b111100, 0, true).unwrap();
    // 2-bit element 0b01 replicated: 0x5555555555555555
    assert_eq!(mask, 0x5555_5555_5555_5555);

    // 32-bit mode should mask result
    let mask = decode_bitmask(false, 0b111100, 0, false).unwrap();
    assert_eq!(mask, 0x0000_0000_5555_5555);
}
#[test]
fn test_crc32() {
    // Test basic CRC32 functionality
    let crc = crc32(0, 0x12, 8);
    assert_ne!(crc, 0);

    let crc = crc32c(0, 0x12, 8);
    assert_ne!(crc, 0);
}
#[test]
fn test_arm_cpu_trait() {
    let mut cpu = create_test_cpu();

    assert_eq!(cpu.arch_version(), ArmVersion::V8_0A);
    assert_eq!(cpu.profile(), ArmProfile::A);
    assert!(cpu.is_privileged()); // EL1 is privileged

    cpu.reset();
    assert_eq!(cpu.get_pc(), 0);

    // Test PSTATE
    let pstate = cpu.get_pstate();
    assert_eq!(pstate.el, 1);

    // Test register access via trait
    cpu.set_gpr(5, 0xDEAD_BEEF);
    assert_eq!(cpu.get_gpr(5), 0xDEAD_BEEF);

    // Test LR
    cpu.set_lr(0x1234);
    assert_eq!(cpu.get_lr(), 0x1234);
}
#[test]
fn test_breakpoint() {
    let mut cpu = create_test_cpu();

    assert!(cpu.set_breakpoint(0x1000).is_ok());
    // set_breakpoint always succeeds (idempotent)
    assert!(cpu.set_breakpoint(0x1000).is_ok());

    assert!(cpu.clear_breakpoint(0x1000).is_ok());
    // clear_breakpoint is also idempotent
    assert!(cpu.clear_breakpoint(0x1000).is_ok());
}
#[test]
fn sve_ldff1_gather_suppresses_non_first_fault() {
    // #19: an LDFF1 gather lets the first active lane fault normally but
    // suppresses a LATER faulting lane (clearing its FFR bit); a plain LD1
    // gather still propagates the fault as an error.
    let make = |first_fault: bool| {
        let mut cpu = create_test_cpu();
        // Z2: lane0 base = 0 (valid), lane1 base = 0x2000_0000 (faults,
        // beyond the 256 MiB test memory).
        cpu.set_simd_reg(2, 0, 0x2000_0000).unwrap();
        cpu.set_sve_pred(0, (1 << 0) | (1 << 8)); // D lanes 0 and 1 active
        cpu.sve_ffr = 0xFFFF;
        // LD1D gather, vector base + imm (D): 1100010 msz=11 01 imm5=0 1 U=1 ff Pg Zn=2 Zt=0.
        let word =
            (0b1100010u32 << 25) | (0b11 << 23) | (0b01 << 21) | (1 << 15) | (1 << 14) | (2 << 5);
        let insn = if first_fault { word | (1 << 13) } else { word };
        (cpu, insn)
    };
    // LDFF1: lane0 ok, lane1 fault suppressed -> Continue, FFR bit cleared.
    let (mut cpu, ff) = make(true);
    assert_eq!(cpu.exec_sve_ldst(ff).unwrap(), CpuExit::Continue);
    assert_eq!(
        cpu.sve_ffr & (1 << 8),
        0,
        "FFR bit for the faulting lane must clear"
    );
    // Plain LD1 gather: the fault propagates as an error.
    let (mut cpu2, plain) = make(false);
    assert!(
        cpu2.exec_sve_ldst(plain).is_err(),
        "a plain gather must propagate the lane fault"
    );
}
#[test]
fn sve_integer_immediate_arithmetic_rejects_reserved_forms() {
    let cases = [
        0x2520_e020, // ADD Z0.B, Z0.B, #1, LSL #8
        0x2522_c020, // reserved op slot in the ADD/SUB/SUBR immediate space
    ];

    for insn in cases {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_simd(0, 0xdead_beef_dead_beef_dead_beef_dead_beefu128);

        assert_eq!(
            cpu.step().unwrap(),
            CpuExit::Undefined(insn),
            "{insn:#010x}"
        );
        assert_eq!(
            cpu.get_simd(0),
            0xdead_beef_dead_beef_dead_beef_dead_beefu128
        );
    }
}
#[test]
fn sve_fscale_updates_status() {
    // FSCALE Z0.S, P0/M, Z0.S, Z1.S
    let mut cpu = create_cpu_with_insn(0x6589_8020);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, 1.0f32.to_bits() as u128);
    cpu.set_simd(1, 200u32 as u128);
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_OFC | FPSR_IXC), FPSR_OFC | FPSR_IXC);

    let mut cpu = create_cpu_with_insn(0x6589_8020);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, 1.0f32.to_bits() as u128);
    cpu.set_simd(1, (-200i32 as u32) as u128);
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_UFC | FPSR_IXC), FPSR_UFC | FPSR_IXC);
}
#[test]
fn sve_fscale_preserves_half_nan_payloads() {
    // FSCALE Z0.H, P0/M, Z0.H, Z0.H
    let mut cpu = create_cpu_with_insn(0x6549_8000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, u128::MAX);
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_simd(0), u128::MAX);
    assert_eq!(cpu.fpsr, 0);
}
#[test]
fn sve_ftsmul_f64_updates_status() {
    // FTSMUL Z0.D, Z0.D, Z0.D
    let mut cpu = create_cpu_with_insn(0x65c0_0c00);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, (1e155f64).to_bits() as u128);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_OFC | FPSR_IXC), FPSR_OFC | FPSR_IXC);

    let mut cpu = create_cpu_with_insn(0x65c0_0c00);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, (1e-200f64).to_bits() as u128);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_UFC | FPSR_IXC), FPSR_UFC | FPSR_IXC);
}
#[test]
fn sve_clast_no_active_preserves_gpr() {
    // CLASTB X0, P0, Z1.B. Conditional LAST forms preserve the low element
    // of Rdn, zero-extended to the destination X register, when the
    // governing predicate has no active elements.
    let mut cpu = create_cpu_with_insn(0x0531_A020);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    let sentinel = 0xDEAD_BEEF_CAFE_55AA;
    cpu.set_x(0, sentinel);
    cpu.set_simd_reg(1, 0x8877_6655_4433_2211, 0x00ff_eedd_ccbb_aa99)
        .unwrap();
    cpu.set_sve_pred(0, 0);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_x(0), sentinel & 0xff);
}
#[test]
fn sve2_xtn_rejects_reserved_encodings() {
    // SVE2 saturating extract-narrow (SQXTN/UQXTN/SQXTUN) only allocates
    // one-hot tsz (001/010/100) and variants 00/01/10. Non-one-hot tsz and
    // variant 11 are reserved and must trap, not execute as H/S forms.
    let setup = |insn: u32| {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
        cpu
    };
    // tsz=011 (non-one-hot) and variant=11 are both reserved.
    for insn in [0x4538_4020u32, 0x4528_5820] {
        assert_eq!(
            setup(insn).step().unwrap(),
            CpuExit::Undefined(insn),
            "reserved XTN encoding {insn:#x} must trap"
        );
    }
    // Valid SQXTNB (tsz=001,vv=00) and SQXTUNB (tsz=001,vv=10) still execute.
    assert_eq!(setup(0x4528_4020).step().unwrap(), CpuExit::Continue);
    assert_eq!(setup(0x4528_5020).step().unwrap(), CpuExit::Continue);
}
#[test]
fn sve2_int_pairwise_rejects_reserved_encodings() {
    // SVE2 integer pairwise (ADDP/SMAXP/UMAXP/SMINP/UMINP) only allocates
    // (opc,U) in {(00,1),(10,0),(10,1),(11,0),(11,1)}. The reserved (00,0),
    // (01,0) and (01,1) encodings must trap, not execute as ADDP/MINP.
    let setup = |insn: u32| {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
        cpu.set_sve_pred(0, 0xffff);
        cpu
    };
    for insn in [0x4410_a020u32, 0x4412_a020, 0x4413_a020] {
        assert_eq!(
            setup(insn).step().unwrap(),
            CpuExit::Undefined(insn),
            "reserved pairwise encoding {insn:#x} must trap"
        );
    }
    // Valid ADDP (00,1) and UMINP (11,1) still execute.
    assert_eq!(setup(0x4411_a020).step().unwrap(), CpuExit::Continue);
    assert_eq!(setup(0x4417_a020).step().unwrap(), CpuExit::Continue);
}
#[test]
fn sve_ld234_rejects_bit20_set() {
    // SVE LD2/LD3/LD4 (scalar+imm) has a fixed 0 at bit20. 0xa430e020 is
    // unallocated (bit20=1) and must trap, not read guest memory; the valid
    // ld2b (0xa420e020) still executes.
    let mut bad = create_cpu_with_insn(0xA430_E020);
    bad.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16);
    assert_eq!(bad.step().unwrap(), CpuExit::Undefined(0xA430_E020));

    let mut good = create_cpu_with_insn(0xA420_E020);
    good.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16);
    good.set_sve_pred(0, 0); // no active lanes -> no memory access needed
    assert_eq!(good.step().unwrap(), CpuExit::Continue);
}
#[test]
fn sve_gather_scatter_reject_unallocated_combos() {
    // Encoders mirror tests/suites/differential/arm/aarch64.rs:
    // Rn=x1, Zm=z2, Zt=z0, Pg=p0.
    let gather_d = |msz: u32, scaled: bool, u: u32| -> u32 {
        let ig1 = if scaled { 0b11 } else { 0b10 };
        (0b1100010 << 25) | (msz << 23) | (ig1 << 21) | (2 << 16) | (1 << 15) | (u << 14) | (1 << 5)
    };
    let gather_s = |msz: u32, scaled: bool, u: u32| -> u32 {
        // 1000010 msz xs scaled Zm 0 U ff Pg Rn Zt (xs=0 unsigned offset).
        (0b1000010 << 25) | (msz << 23) | ((scaled as u32) << 21) | (2 << 16) | (u << 14) | (1 << 5)
    };
    let scatter_d = |msz: u32, scaled: bool| -> u32 {
        let ig1 = if scaled { 0b01 } else { 0b00 };
        (0b1110010 << 25) | (msz << 23) | (ig1 << 21) | (2 << 16) | (0b101 << 13) | (1 << 5)
    };
    let run = |insn: u32| {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16);
        cpu.set_sve_pred(0, 0); // no active lanes for the valid-form checks
        cpu.step().unwrap()
    };

    // Unallocated: scaled-byte gather/scatter and signed widest-element loads.
    // Scaled-byte *gather* with Zt=0 is the reused gather-prefetch encoding,
    // so use Zt=16 (bit4 set) to land in the genuinely unallocated load space.
    for insn in [
        gather_d(0, true, 1) | 16, // scaled byte (D), Zt=16
        gather_d(3, false, 0),     // LD1SD (signed 64-bit) does not exist
        gather_s(0, true, 1) | 16, // scaled byte (S), Zt=16
        gather_s(2, false, 0),     // signed word->S does not exist
        scatter_d(0, true),        // scaled byte scatter (D)
    ] {
        assert_eq!(
            run(insn),
            CpuExit::Undefined(insn),
            "encoding {insn:#x} should be unallocated"
        );
    }

    // The LDFF1 (first-fault, bit13=1) variant shares these handlers, so the
    // same scaled-byte rejection applies to it too (Zt=16 to avoid prefetch).
    let ldff_scaled_byte = gather_d(0, true, 1) | 16 | (1 << 13);
    assert_eq!(run(ldff_scaled_byte), CpuExit::Undefined(ldff_scaled_byte));

    // x32 ST1 scatter scaled-byte (0xe4228020) is unallocated and must trap.
    assert_eq!(run(0xe422_8020), CpuExit::Undefined(0xe422_8020));

    // A genuine gather prefetch (PRFB, 0xc4220020) remains a no-op hint.
    assert_eq!(run(0xc422_0020), CpuExit::Continue);

    // Allocated forms still decode/execute (no active lanes -> no access).
    for insn in [
        gather_d(3, false, 1),
        gather_d(1, true, 1),
        scatter_d(2, true),
    ] {
        assert_eq!(
            run(insn),
            CpuExit::Continue,
            "encoding {insn:#x} should execute"
        );
    }
}
#[test]
fn simd_modified_imm_rejects_reserved_bits() {
    // SIMD modified-immediate: bit31 is fixed 0 and o2 (bit11) is fixed 0
    // except for the FP16 FMOV form (cmode=1111, op=0). Reserved encodings
    // (o2=1 on a MOVI, or bit31 set) must trap; valid forms still execute.
    let setup = |insn: u32| {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        cpu
    };
    // MOVI v0.4s,#1 with o2=1 (0x4f000c20) -> unallocated.
    assert!(matches!(
        setup(0x4f00_0c20).step(),
        Err(ArmError::UndefinedInstruction(0x4f00_0c20))
    ));
    // bit31 set (0xcf000420) -> unallocated.
    assert!(matches!(
        setup(0xcf00_0420).step(),
        Err(ArmError::UndefinedInstruction(0xcf00_0420))
    ));
    // Valid MOVI v0.4s,#1 (0x4f000420) still executes.
    assert_eq!(setup(0x4f00_0420).step().unwrap(), CpuExit::Continue);
    // Valid FP16 FMOV v0.4h,#1.0 (0x0f03fe00, cmode=1111 op=0 o2=1) executes.
    assert_eq!(setup(0x0f03_fe00).step().unwrap(), CpuExit::Continue);
}
#[test]
fn neon_ldst_single_rejects_nonzero_rm_no_offset() {
    // LD/ST single-structure no-offset form (bit23==0) reserves Rm (bits
    // [20:16]) as 0. A non-zero Rm (e.g. 0x0d410020) is unallocated and must
    // trap; the valid Rm==0 form (0x0d400020) still executes.
    let mut bad = create_cpu_with_insn(0x0d41_0020);
    bad.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    assert!(matches!(
        bad.step(),
        Err(ArmError::UndefinedInstruction(0x0d41_0020))
    ));

    let mut good = create_cpu_with_insn(0x0d40_0020);
    good.sysregs.el1.cpacr |= 0b11 << 20;
    good.set_x(1, 0x1000); // base address in mapped scratch
    assert_eq!(good.step().unwrap(), CpuExit::Continue);
}
#[test]
fn simd_dot_rejects_non_word_size() {
    // Vector SDOT/UDOT/USDOT always dot 8-bit lanes into 32-bit elements.
    // The same opcode with size != 0b10 is unallocated.
    for insn in [
        0x0e00_9400, // SDOT size=0
        0x0e40_9400, // SDOT size=1
        0x0ec0_9400, // SDOT size=3
        0x2e00_9400, // UDOT size=0
        0x0e00_9c00, // USDOT size=0
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        let exit = cpu.step();
        assert!(
            matches!(exit, Ok(CpuExit::Undefined(got)) if got == insn)
                || matches!(exit, Err(ArmError::UndefinedInstruction(got)) if got == insn),
            "expected {insn:#010x} to be undefined, got {exit:?}"
        );
    }

    for insn in [
        0x0e82_9420, // SDOT V0.2S, V1.8B, V2.8B
        0x2e82_9420, // UDOT V0.2S, V1.8B, V2.8B
        0x0e82_9c20, // USDOT V0.2S, V1.8B, V2.8B
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    }
}
#[test]
fn simd_float_fused_sets_underflow_status_for_lost_product() {
    let mut cpu = create_cpu_with_insn(0x0e20_cc20); // FMLA V0.2S, V1.2S, V0.2S
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = 0x0000_0001_0000_0001; // subnormal accumulator and multiplier
    cpu.v[1] = 0x0000_0001_0000_0001; // subnormal multiplicand
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_UFC | FPSR_IXC), FPSR_UFC | FPSR_IXC);
}
#[test]
fn simd_fmlal_rejects_reserved_size() {
    for insn in [
        0x0e60_ec00, // FMLAL with reserved low size bit
        0x0ee0_ec00, // FMLSL with reserved low size bit
        0x2e60_cc00, // FMLAL2 with reserved low size bit
        0x6e60_cc00, // FMLAL2 with reserved low size bit, Q=1
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        let exit = cpu.step();
        assert!(
            matches!(exit, Ok(CpuExit::Undefined(got)) if got == insn)
                || matches!(exit, Err(ArmError::UndefinedInstruction(got)) if got == insn),
            "expected {insn:#010x} to be undefined, got {exit:?}"
        );
    }

    let mut cpu = create_cpu_with_insn(0x0e20_ec00); // FMLAL V0.2S, V0.2H, V0.2H
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);

    let mut cpu = create_cpu_with_insn(0x0ea0_ec00); // FMLSL V0.2S, V0.2H, V0.2H
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
}
#[test]
fn simd_sqrdmlah_sqrdmlsh_set_qc_on_saturation() {
    let mut cpu = create_cpu_with_insn(0x2e40_8400); // SQRDMLAH V0.4H, V0.4H, V0.4H
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = 0x7fff_7fff_7fff_7fff;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_QC, FPSR_QC);

    let mut cpu = create_cpu_with_insn(0x2e42_8c20); // SQRDMLSH V0.4H, V1.4H, V2.4H
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = 0x8000_8000_8000_8000; // accumulator
    cpu.v[1] = 0x7fff_7fff_7fff_7fff;
    cpu.v[2] = 0x7fff_7fff_7fff_7fff;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_QC, FPSR_QC);

    let mut cpu = create_cpu_with_insn(0x7e40_8400); // SQRDMLAH H0, H0, H0
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = 0x7fff;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_QC, FPSR_QC);
}
#[test]
fn simd_rsqrts_sets_inexact_for_lost_product() {
    let mut cpu = create_cpu_with_insn(0x0ea2_fc20); // FRSQRTS V0.2S, V1.2S, V2.2S
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x0000_0001_0000_0001; // smallest positive f32 subnormal
    cpu.v[2] = 0x3f80_0000_3f80_0000; // 1.0
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IXC, FPSR_IXC);

    let mut cpu = create_cpu_with_insn(0x5e22_fc20); // FRSQRTS S0, S1, S2
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x0000_0001; // smallest positive f32 subnormal
    cpu.v[2] = 0x3f80_0000; // 1.0
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IXC, FPSR_IXC);
}
#[test]
fn simd_float_compare_nan_sets_invalid_status() {
    let mut cpu = create_cpu_with_insn(0x0ea0_c820); // FCMGT V0.2S, V1.2S, #0
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x7fc0_0001_7fc0_0001; // quiet NaNs
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);

    let mut cpu = create_cpu_with_insn(0x2e22_ec20); // FACGE V0.2S, V1.2S, V2.2S
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x7fc0_0001_7fc0_0001; // quiet NaNs
    cpu.v[2] = 0x3f80_0000_3f80_0000; // 1.0
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);

    let mut cpu = create_cpu_with_insn(0x7e40_2400); // FCMGE H0, H0, H0
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = 0x7e01; // quiet NaN
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);
}
#[test]
fn rdffr_rejects_0x24_family() {
    // RDFFR requires top byte 0x25. 0x2419f000 is actually CMPLO (a 0x24
    // compare), which must NOT be executed as RDFFR (copying FFR into Pd).
    let mut cpu = create_cpu_with_insn(0x2419_f000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.sve_ffr = 0xFFFF;
    cpu.set_sve_pred(0, 0x0000);
    let _ = cpu.step();
    // RDFFR would have set p0 = FFR = 0xFFFF; the fix must prevent that.
    assert_ne!(cpu.sve_pred(0), 0xFFFF, "0x24 encoding executed as RDFFR");

    // The genuine RDFFR (top byte 0x25) still copies FFR into Pd.
    let mut ok = create_cpu_with_insn(0x2519_f000);
    ok.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16);
    ok.sve_ffr = 0xABCD;
    ok.set_sve_pred(0, 0);
    assert_eq!(ok.step().unwrap(), CpuExit::Continue);
    assert_eq!(ok.sve_pred(0), 0xABCD);
}
#[test]
fn sve_whilels_wraparound_keeps_full_prefix() {
    // WHILELS P0.B, W0, W0. Per ASL, the running operand is a 32-bit value
    // for the W form; incrementing UINT32_MAX wraps to zero and the prefix
    // remains active for every byte lane.
    let mut cpu = create_cpu_with_insn(0x2520_0c10);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_w(0, u32::MAX);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.sve_pred(0), 0xffff);
    assert!(cpu.get_n());
    assert!(!cpu.get_z());
    assert!(!cpu.get_c());
    assert!(!cpu.get_v());
}
#[test]
fn sve_unpredicated_wide_shift_uses_covered_dword_amounts() {
    let value = 0x0404_0404_0404_0404_0404_0404_0404_0404u128;
    let amounts = (2u128 << 64) | 1u128;
    for (insn, expected) in [
        (0x0422_8020, 0x0101_0101_0101_0101_0202_0202_0202_0202), // ASR
        (0x0422_8420, 0x0101_0101_0101_0101_0202_0202_0202_0202), // LSR
        (0x0422_8c20, 0x1010_1010_1010_1010_0808_0808_0808_0808), // LSL
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
        cpu.set_simd(1, value);
        cpu.set_simd(2, amounts);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_simd(0), expected);
    }

    let invalid_d_size = 0x04e2_8020; // ASR Z0.D, Z1.D, Z2.D
    let mut cpu = create_cpu_with_insn(invalid_d_size);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(invalid_d_size));
}
#[test]
fn sve_unpredicated_shift_immediate_decodes_tsize() {
    for (insn, value, expected) in [
        (0x042f_9020, 0x0101_0101_0101_0101_0101_0101_0101_0101, 0), // ASR B #1
        (0x042f_9420, 0x0101_0101_0101_0101_0101_0101_0101_0101, 0), // LSR B #1
        (
            0x042f_9c20,
            0x0101_0101_0101_0101_0101_0101_0101_0101,
            0x8080_8080_8080_8080_8080_8080_8080_8080,
        ), // LSL B #7
        (0x04e0_9020, 0x0000_0000_0000_0001_0000_0000_0000_0001, 0), // ASR D #32
        (0x04e0_9420, 0x0000_0000_0000_0001_0000_0000_0000_0001, 0), // LSR D #32
        (
            0x04e0_9c20,
            0x0000_0000_0000_0001_0000_0000_0000_0001,
            0x0000_0001_0000_0000_0000_0001_0000_0000,
        ), // LSL D #32
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
        cpu.set_simd(1, value);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_simd(0), expected);
    }

    let invalid_tsize = 0x0420_9020; // ASR with tsize == 0
    let mut cpu = create_cpu_with_insn(invalid_tsize);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(invalid_tsize));
}
#[test]
fn sve_saturating_immediate_arithmetic_updates_destructive_operand() {
    for (insn, input, expected) in [
        (
            0x2524_c020,
            0x7f7f_7f7f_7f7f_7f7f_7f7f_7f7f_7f7f_7f7f,
            0x7f7f_7f7f_7f7f_7f7f_7f7f_7f7f_7f7f_7f7f,
        ), // SQADD B #1
        (
            0x2525_c020,
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        ), // UQADD B #1
        (
            0x2526_c020,
            0x8080_8080_8080_8080_8080_8080_8080_8080,
            0x8080_8080_8080_8080_8080_8080_8080_8080,
        ), // SQSUB B #1
        (0x2527_c020, 0, 0), // UQSUB B #1
        (
            0x2564_e020,
            0x7f00_7f00_7f00_7f00_7f00_7f00_7f00_7f00,
            0x7fff_7fff_7fff_7fff_7fff_7fff_7fff_7fff,
        ), // SQADD H #256
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_simd(0, input);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_simd(0), expected);
    }

    let invalid_shifted_byte = 0x2524_e020; // SQADD Z0.B, Z0.B, #1, LSL #8
    let mut cpu = create_cpu_with_insn(invalid_shifted_byte);
    cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    assert_eq!(
        cpu.step().unwrap(),
        CpuExit::Undefined(invalid_shifted_byte)
    );
}
#[test]
fn sve_minmax_immediate_arithmetic_updates_destructive_operand() {
    for (insn, input, expected) in [
        (
            0x2528_c020,
            0x8080_8080_8080_8080_8080_8080_8080_8080,
            0x0101_0101_0101_0101_0101_0101_0101_0101,
        ), // SMAX B #1
        (0x2529_c020, 0, 0x0101_0101_0101_0101_0101_0101_0101_0101), // UMAX B #1
        (
            0x252a_dfe0,
            0x7f7f_7f7f_7f7f_7f7f_7f7f_7f7f_7f7f_7f7f,
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        ), // SMIN B #-1
        (
            0x252b_c020,
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            0x0101_0101_0101_0101_0101_0101_0101_0101,
        ), // UMIN B #1
        (
            0x25e8_dfe0,
            0xffff_fffe_ffff_fffe_ffff_fffe_ffff_fffe,
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        ), // SMAX D #-1
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_simd(0, input);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_simd(0), expected);
    }
}
#[test]
fn sve_prefetch_register_offset_rejects_rm31() {
    let invalid_rm31 = 0x841f_c000; // PRFB PLDL1KEEP, P0, [X0, XZR]
    let mut cpu = create_cpu_with_insn(invalid_rm31);
    cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(invalid_rm31));

    let mut valid = create_cpu_with_insn(0x8400_c000); // PRFB PLDL1KEEP, P0, [X0, X0]
    valid.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    assert_eq!(valid.step().unwrap(), CpuExit::Continue);
}
#[test]
fn sve_fscale_rejects_byte_elements() {
    let insn = 0x6509_8020; // invalid FSCALE Z0.B, P0/M, Z0.B, Z1.B
    let mut cpu = create_cpu_with_insn(insn);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_sve_pred(0, 0xffff);
    let z0 = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff;

    cpu.set_simd(0, z0);
    cpu.set_simd(1, 0x0101_0101_0101_0101_0101_0101_0101_0101);

    assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(insn));
    assert_eq!(cpu.get_simd(0), z0);
}
#[test]
fn rdvl_xzr_does_not_update_sp() {
    let mut cpu = create_cpu_with_insn(0x04bf_503f); // RDVL XZR, #1
    cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    cpu.set_sp(0x1234_5678_9abc_def0);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_sp(), 0x1234_5678_9abc_def0);
}
#[test]
fn addvl_sp_still_updates_sp() {
    let mut cpu = create_cpu_with_insn(0x043f_503f); // ADDVL SP, SP, #1
    cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    cpu.set_sp(0x1000);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_sp(), 0x1010);
}
// -------------------------------------------------------------------------
// Branch Instructions - Register
// -------------------------------------------------------------------------

#[test]
fn test_br() {
    // BR X1
    let insn = 0xD61F0020; // BR X1
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x2000);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x2000);
}
#[test]
fn test_orn() {
    // ORN X0, X1, X2 (X1 OR NOT X2)
    let insn = 0xAA220020; // ORN X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0);
    cpu.set_x(2, 0xFF);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), !0xFFu64);
}
#[test]
fn test_eon() {
    // EON X0, X1, X2 (X1 XOR NOT X2)
    let insn = 0xCA220020; // EON X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0);
    cpu.set_x(2, 0);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), !0u64);
}
#[test]
fn test_tst() {
    // TST X1, X2 (ANDS XZR, X1, X2)
    let insn = 0xEA02003F; // TST X1, X2 (Rd=XZR)
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x8000_0000_0000_0000);
    cpu.set_x(2, 0x8000_0000_0000_0000);
    cpu.step().unwrap();
    assert!(cpu.get_n()); // Negative (bit 63 set)
    assert!(!cpu.get_z()); // Not zero
}
#[test]
fn test_mvn() {
    // MVN X0, X1 (alias for ORN X0, XZR, X1)
    let insn = 0xAA2103E0; // MVN X0, X1
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), !0u64);
}
#[test]
fn test_cmn() {
    // CMN X1, X2 (ADDS XZR, X1, X2)
    let insn = 0xAB02003F; // CMN X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0xFFFF_FFFF_FFFF_FFFF);
    cpu.set_x(2, 1);
    cpu.step().unwrap();
    assert!(cpu.get_z()); // Result is zero
    assert!(cpu.get_c()); // Carry out
}
#[test]
fn test_ngc() {
    // NGC X0, X1 (SBC X0, XZR, X1)
    let insn = 0xDA0103E0; // NGC X0, X1
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0);
    cpu.set_c(true);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0);
}
// -------------------------------------------------------------------------
// Data Processing Register - Conditional Compare
// -------------------------------------------------------------------------

#[test]
fn test_ccmp_true() {
    // CCMP X1, X2, #0, EQ (compare if Z=1)
    // Encoding: sf=1 11 11010010 Rm cond 00 Rn 0 nzcv
    // = 111 11010010 00010 0000 00 00001 0 0000
    // = 0xFA420020
    let insn = 0xFA420020; // CCMP X1, X2, #0, EQ
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 100);
    cpu.set_x(2, 100);
    cpu.set_z(true); // Condition true (EQ)
    cpu.step().unwrap();
    assert!(cpu.get_z()); // Result of comparison (100-100=0)
    assert!(cpu.get_c()); // No borrow
}
#[test]
fn test_ccmp_false() {
    // CCMP X1, X2, #0b0100, EQ (use nzcv if Z=0)
    // Encoding: 111 11010010 00010 0000 00 00001 0 0100
    // = 0xFA420024
    let insn = 0xFA420024; // CCMP X1, X2, #4, EQ (nzcv=0100)
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_z(false); // Condition false
    cpu.step().unwrap();
    assert!(cpu.get_z()); // nzcv bit 2 = Z
    assert!(!cpu.get_c()); // nzcv bit 1 = C (clear)
}
#[test]
fn test_ccmn() {
    // CCMN X1, X2, #0, NE (add comparison if Z=0)
    // Encoding: sf=1 01 11010010 Rm cond 00 Rn 0 nzcv (note: op=0 for CCMN)
    // = 101 11010010 00010 0001 00 00001 0 0000
    // = 0xBA421020
    let insn = 0xBA421020; // CCMN X1, X2, #0, NE
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0xFFFF_FFFF_FFFF_FFFF);
    cpu.set_x(2, 1);
    cpu.set_z(false); // NE is true
    cpu.step().unwrap();
    assert!(cpu.get_z()); // Result is zero
    assert!(cpu.get_c()); // Carry out
}
// -------------------------------------------------------------------------
// Data Processing Register - Conditional Select
// -------------------------------------------------------------------------

#[test]
fn test_csel_true() {
    // CSEL X0, X1, X2, EQ (select X1 if Z=1)
    let insn = 0x9A820020; // CSEL X0, X1, X2, EQ
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1111);
    cpu.set_x(2, 0x2222);
    cpu.set_z(true);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x1111);
}
#[test]
fn test_csel_false() {
    // CSEL X0, X1, X2, EQ (select X2 if Z=0)
    let insn = 0x9A820020; // CSEL X0, X1, X2, EQ
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1111);
    cpu.set_x(2, 0x2222);
    cpu.set_z(false);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x2222);
}
#[test]
fn test_csinc_true() {
    // CSINC X0, X1, X2, NE (select X1 if Z=0)
    let insn = 0x9A821420; // CSINC X0, X1, X2, NE
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 100);
    cpu.set_x(2, 200);
    cpu.set_z(false); // NE is true
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 100);
}
#[test]
fn test_csinc_false() {
    // CSINC X0, X1, X2, NE (select X2+1 if Z=1)
    let insn = 0x9A821420; // CSINC X0, X1, X2, NE
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 100);
    cpu.set_x(2, 200);
    cpu.set_z(true); // NE is false
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 201);
}
#[test]
fn test_csinv() {
    // CSINV X0, X1, X2, EQ (select X1 if Z=1, else ~X2)
    let insn = 0xDA820020; // CSINV X0, X1, X2, EQ
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1111);
    cpu.set_x(2, 0);
    cpu.set_z(false);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), !0u64);
}
#[test]
fn test_csneg() {
    // CSNEG X0, X1, X2, EQ (select X1 if Z=1, else -X2)
    let insn = 0xDA820420; // CSNEG X0, X1, X2, EQ
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0);
    cpu.set_x(2, 5);
    cpu.set_z(false);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0xFFFF_FFFF_FFFF_FFFB); // -5
}
#[test]
fn test_cinc() {
    // CINC X0, X1, NE = CSINC X0, X1, X1, EQ
    // If EQ is true: X0 = X1
    // If EQ is false (NE is true): X0 = X1 + 1
    let insn = 0x9A810420; // CINC X0, X1, NE
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 100);
    cpu.set_z(false); // EQ is false, so NE is true -> X0 = X1 + 1
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 101);
}
#[test]
fn test_cset() {
    // CSET X0, EQ (CSINC X0, XZR, XZR, NE)
    let insn = 0x9A9F17E0; // CSET X0, EQ
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_z(true); // EQ is true
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 1);
}
#[test]
fn test_csetm() {
    // CSETM X0, EQ = CSINV X0, XZR, XZR, NE
    // If NE (Z=0): X0 = XZR = 0
    // If EQ (Z=1): X0 = NOT(XZR) = !0
    // Encoding: sf=1 op=1 S=0 11010100 Rm=11111 cond=0001(NE) op2=00 Rn=11111 Rd=00000
    // = 110 11010100 11111 0001 00 11111 00000 = 0xDA9F13E0
    let insn = 0xDA9F13E0; // CSETM X0, EQ (encoded as CSINV X0, XZR, XZR, NE)
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_z(true); // EQ is true, so NE is false -> X0 = !0
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), !0u64);
}
// -------------------------------------------------------------------------
// Data Processing Register - 2-source
// -------------------------------------------------------------------------

#[test]
fn test_udiv() {
    // UDIV X0, X1, X2
    let insn = 0x9AC20820; // UDIV X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 100);
    cpu.set_x(2, 7);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 14);
}
#[test]
fn test_udiv_by_zero() {
    // UDIV X0, X1, X2 (divide by zero returns 0)
    let insn = 0x9AC20820; // UDIV X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 100);
    cpu.set_x(2, 0);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0);
}
#[test]
fn test_sdiv() {
    // SDIV X0, X1, X2
    let insn = 0x9AC20C20; // SDIV X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, (-100i64) as u64);
    cpu.set_x(2, 7);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0) as i64, -14);
}
#[test]
fn test_sdiv_by_zero() {
    // SDIV X0, X1, X2 (divide by zero returns 0)
    let insn = 0x9AC20C20; // SDIV X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, (-100i64) as u64);
    cpu.set_x(2, 0);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0);
}
#[test]
fn test_mneg() {
    // MNEG X0, X1, X2 (MSUB X0, X1, X2, XZR)
    let insn = 0x9B02FC20; // MNEG X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 10);
    cpu.set_x(2, 20);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0) as i64, -200);
}
#[test]
fn test_smaddl() {
    // SMADDL X0, W1, W2, X3 (signed widening multiply-add)
    let insn = 0x9B220C20; // SMADDL X0, W1, W2, X3
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0xFFFF_FFFF); // -1 as W
    cpu.set_x(2, 10);
    cpu.set_x(3, 100);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0) as i64, 90); // 100 + (-1 * 10)
}
#[test]
fn test_smull() {
    // SMULL X0, W1, W2 (SMADDL X0, W1, W2, XZR)
    let insn = 0x9B227C20; // SMULL X0, W1, W2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0xFFFF_FFFF); // -1 as W
    cpu.set_x(2, 100);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0) as i64, -100);
}
#[test]
fn test_umaddl() {
    // UMADDL X0, W1, W2, X3 (unsigned widening multiply-add)
    let insn = 0x9BA20C20; // UMADDL X0, W1, W2, X3
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0xFFFF_FFFF); // Max u32
    cpu.set_x(2, 2);
    cpu.set_x(3, 1);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x1_FFFF_FFFF); // 2 * 0xFFFF_FFFF + 1
}
#[test]
fn test_umull() {
    // UMULL X0, W1, W2 (UMADDL X0, W1, W2, XZR)
    let insn = 0x9BA27C20; // UMULL X0, W1, W2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1_0000);
    cpu.set_x(2, 0x1_0000);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x1_0000_0000);
}
#[test]
fn test_smulh() {
    // SMULH X0, X1, X2 (signed high multiply)
    let insn = 0x9B427C20; // SMULH X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x8000_0000_0000_0000); // Large negative
    cpu.set_x(2, 2);
    cpu.step().unwrap();
    // Result is high 64 bits of signed 128-bit product
    assert_eq!(cpu.get_x(0), 0xFFFF_FFFF_FFFF_FFFF);
}
#[test]
fn test_umulh() {
    // UMULH X0, X1, X2 (unsigned high multiply)
    let insn = 0x9BC27C20; // UMULH X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x8000_0000_0000_0000);
    cpu.set_x(2, 2);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 1);
}
// -------------------------------------------------------------------------
// System Instructions
// -------------------------------------------------------------------------

#[test]
fn test_nop() {
    // NOP
    let insn = 0xD503201F; // NOP
    let mut cpu = create_cpu_with_insn(insn);
    let old_pc = cpu.get_pc();
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), old_pc + 4);
}
#[test]
fn test_dmb() {
    // DMB SY
    let insn = 0xD5033FBF; // DMB SY
    let mut cpu = create_cpu_with_insn(insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 4);
}
#[test]
fn test_dsb() {
    // DSB SY
    let insn = 0xD5033F9F; // DSB SY
    let mut cpu = create_cpu_with_insn(insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 4);
}
#[test]
fn test_isb() {
    // ISB
    let insn = 0xD5033FDF; // ISB
    let mut cpu = create_cpu_with_insn(insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 4);
}
// -------------------------------------------------------------------------
// Multi-instruction sequences
// -------------------------------------------------------------------------

#[test]
fn test_simple_program() {
    // Simple program: MOV X0, #1; ADD X0, X0, #1; ADD X0, X0, #1
    let mut cpu = create_test_cpu();
    write_insn(&mut cpu, 0, 0xD2800020); // MOV X0, #1
    write_insn(&mut cpu, 4, 0x91000400); // ADD X0, X0, #1
    write_insn(&mut cpu, 8, 0x91000400); // ADD X0, X0, #1

    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 1);

    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 2);

    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 3);
}
#[test]
fn test_loop() {
    // Simple countdown loop
    // 0x0000: MOV X0, #5
    // 0x0004: SUBS X0, X0, #1
    // 0x0008: B.NE #-4
    let mut cpu = create_test_cpu();
    write_insn(&mut cpu, 0, 0xD28000A0); // MOV X0, #5
    write_insn(&mut cpu, 4, 0xF1000400); // SUBS X0, X0, #1
    write_insn(&mut cpu, 8, 0x54FFFFE1); // B.NE #-4

    // Execute MOV
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 5);

    // Execute loop 5 times
    for expected in (0..5).rev() {
        cpu.step().unwrap(); // SUBS
        assert_eq!(cpu.get_x(0), expected);
        cpu.step().unwrap(); // B.NE or fall through
    }

    // After loop, PC should be at 0x0C (fell through)
    assert_eq!(cpu.get_pc(), 0x0C);
}
#[test]
fn test_function_call() {
    // Test function call and return
    // 0x0000: MOV X0, #42
    // 0x0004: BL #0x100
    // 0x0008: ADD X0, X0, #1  (after return)
    // ...
    // 0x0104: ADD X0, X0, X0
    // 0x0108: RET
    let mut cpu = create_test_cpu();
    write_insn(&mut cpu, 0x0000, 0xD2800540); // MOV X0, #42
    write_insn(&mut cpu, 0x0004, 0x94000040); // BL #0x100
    write_insn(&mut cpu, 0x0008, 0x91000400); // ADD X0, X0, #1

    write_insn(&mut cpu, 0x0104, 0x8B000000); // ADD X0, X0, X0
    write_insn(&mut cpu, 0x0108, 0xD65F03C0); // RET

    // MOV X0, #42
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 42);

    // BL #0x100
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x104);
    assert_eq!(cpu.get_x(30), 8); // Return address

    // ADD X0, X0, X0
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 84);

    // RET
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 8);

    // ADD X0, X0, #1
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 85);
}
#[test]
fn test_memory_operations() {
    // Test store and load sequence
    // MOV X0, #0xABCD
    // MOV X1, #0x1000
    // STR X0, [X1]
    // MOV X0, #0
    // LDR X2, [X1]
    let mut cpu = create_test_cpu();
    write_insn(&mut cpu, 0x00, 0xD29579A0); // MOV X0, #0xABCD (imm16=0xABCD, hw=0)
    write_insn(&mut cpu, 0x04, 0xD2820001); // MOV X1, #0x1000
    write_insn(&mut cpu, 0x08, 0xF9000020); // STR X0, [X1]
    write_insn(&mut cpu, 0x0C, 0xD2800000); // MOV X0, #0
    write_insn(&mut cpu, 0x10, 0xF9400022); // LDR X2, [X1]

    for _ in 0..5 {
        cpu.step().unwrap();
    }

    assert_eq!(cpu.get_x(0), 0);
    assert_eq!(cpu.get_x(2), 0xABCD);
}
#[test]
fn issue_39_ldtr_sttr_use_unprivileged_permission_checks() {
    let (mut cpu, data_va) = create_issue_39_cpu();
    cpu.set_x(1, data_va);

    assert!(is_permission_error(cpu.exec_ldst_reg(ldtr_x0_x1_0())));

    cpu.uao = true;
    assert_eq!(
        cpu.exec_ldst_reg(ldtr_x0_x1_0()).unwrap(),
        CpuExit::Continue
    );
    assert_eq!(cpu.get_x(0), 0xCAFE_F00D_DEAD_BEEF);

    cpu.uao = false;
    cpu.set_x(0, 0x1122_3344_5566_7788);
    assert!(is_permission_error(cpu.exec_ldst_reg(sttr_x0_x1_0())));
    assert_eq!(cpu.mem_read_u64(data_va).unwrap(), 0xCAFE_F00D_DEAD_BEEF);

    cpu.uao = true;
    assert_eq!(
        cpu.exec_ldst_reg(sttr_x0_x1_0()).unwrap(),
        CpuExit::Continue
    );
    assert_eq!(cpu.mem_read_u64(data_va).unwrap(), 0x1122_3344_5566_7788);
}
#[test]
fn issue_39_lrcpc3_pair_uses_unprivileged_permission_checks() {
    let (mut cpu, data_va) = create_issue_39_cpu();
    cpu.config.features |= ArmFeatures::RCPC3;
    cpu.set_x(1, data_va);
    cpu.mem_write_u64(data_va + 8, 0x1234_5678_9ABC_DEF0)
        .unwrap();

    assert!(is_permission_error(cpu.exec_ldst_pair(ldtp_x0_x2_x1_0())));

    cpu.uao = true;
    assert_eq!(
        cpu.exec_ldst_pair(ldtp_x0_x2_x1_0()).unwrap(),
        CpuExit::Continue
    );
    assert_eq!(cpu.get_x(0), 0xCAFE_F00D_DEAD_BEEF);
    assert_eq!(cpu.get_x(2), 0x1234_5678_9ABC_DEF0);

    cpu.uao = false;
    cpu.set_x(0, 0x1122_3344_5566_7788);
    cpu.set_x(2, 0x8877_6655_4433_2211);
    assert!(is_permission_error(cpu.exec_ldst_pair(sttp_x0_x2_x1_0())));
    assert_eq!(cpu.mem_read_u64(data_va).unwrap(), 0xCAFE_F00D_DEAD_BEEF);
    assert_eq!(
        cpu.mem_read_u64(data_va + 8).unwrap(),
        0x1234_5678_9ABC_DEF0
    );

    cpu.uao = true;
    assert_eq!(
        cpu.exec_ldst_pair(sttp_x0_x2_x1_0()).unwrap(),
        CpuExit::Continue
    );
    assert_eq!(cpu.mem_read_u64(data_va).unwrap(), 0x1122_3344_5566_7788);
    assert_eq!(
        cpu.mem_read_u64(data_va + 8).unwrap(),
        0x8877_6655_4433_2211
    );
}
#[test]
fn issue_187_unadvertised_uao_does_not_override_permissions() {
    let (mut cpu, data_va) = create_issue_39_cpu();
    cpu.sysregs.id_aa64mmfr2_el1 = 0;
    cpu.uao = true;

    assert!(
        is_permission_error(cpu.mem_read_u64_unprivileged(data_va)),
        "unadvertised UAO state must not make EL1 unprivileged accesses privileged"
    );
}
// Regression for issue #49: checkpoint-imported TCR values are guest
// controlled, so invalid T0SZ/T1SZ fields must be clamped before translation
// arithmetic uses them.
#[test]
fn issue_49_import_sregs_sanitizes_tcr_sizes_for_mmu() {
    let mut cpu = create_test_cpu();
    let mut sregs = Aarch64SystemRegisters {
        sctlr_el1: sctlr::M,
        tcr_el1: 0,
        ..Aarch64SystemRegisters::default()
    };

    cpu.import_sregs(&sregs).unwrap();
    assert_eq!(cpu.mmu.config().t0sz, 16);
    assert_eq!(cpu.mmu.config().t1sz, 16);
    assert!(
        cpu.mem_read_u8(0).is_err(),
        "invalid low TCR sizes should fault, not panic"
    );

    sregs.tcr_el1 = 63 | (63 << 16) | (0b01 << 14) | (0b11 << 30);
    cpu.import_sregs(&sregs).unwrap();
    assert_eq!(cpu.mmu.config().t0sz, 47);
    assert_eq!(cpu.mmu.config().t1sz, 47);
    assert!(
        cpu.mem_read_u8(0).is_err(),
        "invalid high TCR sizes should fault, not panic"
    );
}
#[test]
fn sve_ftmad_preserves_half_nan_payloads() {
    // FTMAD Z0.H, Z0.H, Z0.H, #0. The multiply uses abs(Zm), but NaN
    // propagation follows FPMulAdd operand order and must not canonicalize.
    let mut cpu = create_cpu_with_insn(0x6550_8000);
    cpu.v[0] = u128::MAX;

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.v[0], u128::MAX);
    assert_eq!(cpu.fpsr & FPSR_IOC, 0);
}
// -------------------------------------------------------------------------
// Edge cases and special values
// -------------------------------------------------------------------------

#[test]
fn test_max_values() {
    // ADD with maximum 64-bit value
    let insn = 0x91000400; // ADD X0, X0, #1
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, u64::MAX);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0); // Wraps around
}
#[test]
fn test_signed_overflow() {
    // ADDS with signed overflow
    let insn = 0xAB020020; // ADDS X0, X1, X2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x7FFF_FFFF_FFFF_FFFF); // Max positive
    cpu.set_x(2, 1);
    cpu.step().unwrap();
    assert!(cpu.get_v()); // Overflow flag set
    assert!(cpu.get_n()); // Result is negative
}
#[test]
fn test_zero_register_as_source() {
    // ADD X0, XZR, #100 (XZR as source)
    // imm12 = 100 = 0x64, Rn = 31 (XZR), Rd = 0
    let insn = 0x910193E0; // ADD X0, XZR, #100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 100);
}
#[test]
fn test_zero_register_as_dest() {
    // ADD XZR, X1, #100 (XZR as destination, discards result)
    let insn = 0x9119003F; // ADD XZR, X0, #100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 50);
    cpu.step().unwrap();
    // Result discarded, XZR still reads 0
    assert_eq!(cpu.get_x(31), 0);
}
#[test]
fn test_32bit_operations() {
    // 32-bit operations should zero-extend
    let insn = 0x0B020020; // ADD W0, W1, W2
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0xFFFF_FFFF_0000_0001);
    cpu.set_x(2, 0xFFFF_FFFF_0000_0001);
    cpu.step().unwrap();
    // Result is 32-bit, zero-extended to 64
    assert_eq!(cpu.get_x(0), 2);
}
