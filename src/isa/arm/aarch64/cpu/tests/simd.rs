//! tests::simd tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

fn create_fp16_cpu_with_insn(insn: u32) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config::v8_2(),
        Box::new(FlatMemory::new(0, 0x1000_0000)),
    );
    cpu.write_memory(0, &insn.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn sve_ld1rq_effective_address_wraps_no_panic() {
    // LD1RQ Z0.B, P0/Z, [X5, #0]. With the base register at u64::MAX, the
    // per-lane effective address addr0 + e overflows u64. Effective-address
    // arithmetic must wrap (and fault through translation), not panic in
    // checked builds. Lane 0 is inactive so a later lane drives the wrap.
    let mut cpu = create_cpu_with_insn(0xA400_20A0);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_x(5, u64::MAX); // base = u64::MAX
    cpu.set_sve_pred(0, 0b10); // lane 0 inactive, lane 1 active
    // Must not panic; the wrapped lane addresses resolve normally here.
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
}
#[test]
fn sve_ld1r_address_addition_wraps_no_panic() {
    // #18: LD1R computes `base + imm6*mbytes` BEFORE the predicate-active
    // check; with base near u64::MAX this overflowed and panicked in
    // checked builds. The add must wrap. imm6=1 forces the overflow even
    // with no active lanes (so no memory is touched).
    let mut cpu = create_test_cpu();
    cpu.set_x(5, u64::MAX); // Rn = X5 = base
    cpu.set_sve_pred(0, 0); // no active lanes
    // LD1RB {Z0.B}, P0/Z, [X5, #1]: 1000010 00 1 imm6=1 1 00 Pg=0 Rn=5 Zt=0.
    let insn = (0b1000010u32 << 25) | (1 << 22) | (1 << 16) | (1 << 15) | (5 << 5);
    assert_eq!(cpu.exec_sve_ldst(insn).unwrap(), CpuExit::Continue);
}
#[test]
fn sve_ld1_st1_immediate_offset_scales_by_memory_footprint() {
    // Contiguous SVE scalar+immediate LD1/ST1 scale the immediate by the
    // memory footprint of the vector access. For LD1B/ST1B Zt.H at VL=128
    // that is 8 bytes, not the full 16-byte Z register width.
    let mut cpu = create_test_cpu();
    let base = 0x200u64;
    cpu.set_x(3, base); // Rn = X3
    cpu.write_memory(base + 8, &[0xAA]).unwrap();
    cpu.write_memory(base + 16, &[0xBB]).unwrap();
    cpu.set_sve_pred(0, 0xFFFF); // all lanes active
    // LD1B Zt.H: 1010010 dtype=0001 0 imm4=1 101 Pg=0 Rn=3 Zt=0.
    let ld1b_h = (0b1010010u32 << 25) | (0b0001 << 21) | (1 << 16) | (0b101 << 13) | (3 << 5);
    assert_eq!(cpu.exec_sve_ldst(ld1b_h).unwrap(), CpuExit::Continue);
    // Lane 0 (halfword) = zero-extended byte at base+8 = 0xAA.
    let (lo, _hi) = cpu.get_simd_reg(0).unwrap();
    assert_eq!(
        lo & 0xFFFF,
        0x00AA,
        "LD1 imm offset must scale by memory footprint (got {lo:#x})"
    );

    cpu.write_memory(base + 8, &[0x11]).unwrap();
    cpu.write_memory(base + 16, &[0x22]).unwrap();
    cpu.set_simd_reg(0, 0x00dd_00cc_00bb_00aa, 0x0044_0033_0022_0011)
        .unwrap();
    cpu.set_sve_pred(0, 1); // only lane 0 active
    // ST1B Zt.H: 1110010 msz=00 size=01 imm4=1 111 Pg=0 Rn=3 Zt=0.
    let st1b_h = (0b1110010u32 << 25) | (0b01 << 21) | (1 << 16) | (0b111 << 13) | (3 << 5);
    assert_eq!(cpu.exec_sve_ldst(st1b_h).unwrap(), CpuExit::Continue);
    assert_eq!(cpu.mem_read_u8(base + 8).unwrap(), 0xAA);
    assert_eq!(
        cpu.mem_read_u8(base + 16).unwrap(),
        0x22,
        "ST1 imm offset must not use the full Z-register byte width"
    );
}
#[test]
fn sve_zip_uzp_trn_rejects_reserved_opc() {
    // #167: the SVE unpredicated permute (00000101 size 1 Zm 011 opc Zn Zd)
    // defines only opc 000..101 — ZIP1/ZIP2 (000/001), UZP1/UZP2 (010/011),
    // TRN1/TRN2 (100/101). opc 0b110/0b111 are reserved and must trap
    // UNDEFINED, not silently zero-write Zd and report success.
    let setup = |insn: u32| {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
        cpu
    };
    // Reserved opc 0b110 (0x05227820) and 0b111 (0x05227C20) (size=00, Zm=2,
    // Zn=1, Zd=0) must be UNDEFINED.
    for insn in [0x0522_7820u32, 0x0522_7C20u32] {
        assert_eq!(
            setup(insn).step().unwrap(),
            CpuExit::Undefined(insn),
            "reserved SVE permute opc must be UNDEFINED: {insn:#010x}",
        );
    }
    // Sanity: a valid opc (ZIP1, opc 000) still executes.
    assert_eq!(setup(0x0522_6020).step().unwrap(), CpuExit::Continue);
}
#[test]
fn sve_integer_immediate_arithmetic_updates_destructive_vector() {
    let initial = 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100u128;
    let cases = [
        // ADD Z0.B, Z0.B, #1
        (0x2520_c020, 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128),
        // SUB Z0.B, Z0.B, #1
        (0x2521_c020, 0x0e0d_0c0b_0a09_0807_0605_0403_0201_00ffu128),
        // SUBR Z0.B, Z0.B, #1
        (0x2523_c020, 0xf2f3_f4f5_f6f7_f8f9_fafb_fcfd_feff_0001u128),
        // ADD Z0.H, Z0.H, #1, LSL #8
        (0x2560_e020, 0x100e_0e0c_0c0a_0a08_0806_0604_0402_0200u128),
    ];

    for (insn, expected) in cases {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_simd(0, initial);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{insn:#010x}");
        assert_eq!(cpu.get_simd(0), expected, "{insn:#010x}");
    }
}
#[test]
fn sve_logical_immediate_updates_destructive_vector() {
    let initial = 0xffff_ffff_ffff_ffff_0000_0000_0000_0000u128;
    let cases = [
        // ORR Z0.S, Z0.S, #0x1
        (0x0500_0000, 0xffff_ffff_ffff_ffff_0000_0001_0000_0001u128),
        // EOR Z0.S, Z0.S, #0x1
        (0x0540_0000, 0xffff_fffe_ffff_fffe_0000_0001_0000_0001u128),
        // AND Z0.S, Z0.S, #0x1
        (0x0580_0000, 0x0000_0001_0000_0001_0000_0000_0000_0000u128),
    ];

    for (insn, expected) in cases {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_simd(0, initial);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{insn:#010x}");
        assert_eq!(cpu.get_simd(0), expected, "{insn:#010x}");
    }
}
#[test]
fn sve_fp_compare_zero_ordered_qnan_sets_ioc() {
    // FCMGT P0.H, P0/Z, Z0.H, #0.0
    let mut cpu = create_cpu_with_insn(0x6550_2010);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, 0x7e00); // fp16 qNaN in lane 0
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.sve_pred(0), 0);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);
}
#[test]
fn sve_fp_abs_compare_ordered_qnan_sets_ioc() {
    // FACGE P0.S, P0/Z, Z0.S, Z0.S
    let mut cpu = create_cpu_with_insn(0x6580_c010);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, 0x7fc0_0000); // fp32 qNaN in lane 0
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.sve_pred(0), 0x1110);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);
}
#[test]
fn sve_int_to_fp16_overflow_sets_ofc_ixc() {
    // UCVTF Z0.H, P0/M, Z0.S
    let mut cpu = create_cpu_with_insn(0x6555_a000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, u128::from(u32::MAX));
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_simd(0) & 0xffff, 0x7c00);
    assert_eq!(cpu.fpsr & (FPSR_OFC | FPSR_IXC), FPSR_OFC | FPSR_IXC);
}
#[test]
fn sve_fp_unpredicated_vector_add_executes() {
    // FADD Z0.S, Z0.S, Z0.S
    let mut cpu = create_cpu_with_insn(0x6580_0000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    let one = 1.0f32.to_bits() as u128;
    cpu.set_simd(0, one | (one << 32) | (one << 64) | (one << 96));

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    let two = 2.0f32.to_bits() as u128;
    assert_eq!(
        cpu.get_simd(0),
        two | (two << 32) | (two << 64) | (two << 96)
    );
    assert_eq!(cpu.fpsr, 0);
}
#[test]
fn sve_fp_estimate_updates_status() {
    // FRECPE Z0.S, Z0.S: reciprocal estimate of zero raises DZC.
    let mut cpu = create_cpu_with_insn(0x658e_3000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, 0);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_DZC, FPSR_DZC);

    // FRSQRTE Z0.S, Z0.S: reciprocal-square-root estimate of -1 raises IOC.
    let mut cpu = create_cpu_with_insn(0x658f_3000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, (-1.0f32).to_bits() as u128);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);
}
#[test]
fn sve_fcvt_d2h_preserves_nan_payload() {
    // FCVT Z0.H, P0/M, Z0.D
    let mut cpu = create_cpu_with_insn(0x65c8_a000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_simd(0, 0xffff_ffff_ffff_ffff);
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_simd(0) & 0xffff, 0xffff);
    assert_eq!(cpu.fpsr, 0);
}
#[test]
fn simd_copy_ins_rejects_q0() {
    // INS (element/general) is 128-bit-only (Q=1). The Q=0 encodings are
    // unallocated and must trap; the valid Q=1 forms still execute.
    let setup = |insn: u32| {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        cpu
    };
    // INS element Q=0 (0x2e0c0420) and INS general Q=0 (0x0e0c1c40) -> trap.
    assert!(matches!(
        setup(0x2e0c_0420).step(),
        Err(ArmError::UndefinedInstruction(0x2e0c_0420))
    ));
    assert!(matches!(
        setup(0x0e0c_1c40).step(),
        Err(ArmError::UndefinedInstruction(0x0e0c_1c40))
    ));
    // Valid Q=1 forms still execute.
    assert_eq!(setup(0x6e0c_0420).step().unwrap(), CpuExit::Continue);
    assert_eq!(setup(0x4e0c_1c40).step().unwrap(), CpuExit::Continue);
}
#[test]
fn simd_indexed_sdot_rejects_scalar_form() {
    // SDOT/UDOT by element are vector-only. The scalar indexed-element form
    // (bits[28:24]==11111, e.g. 0x5f82e020) is unallocated and must trap;
    // the vector form (0x4f82e020) still executes.
    let mut bad = create_cpu_with_insn(0x5f82_e020);
    bad.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    assert_eq!(bad.step().unwrap(), CpuExit::Undefined(0x5f82_e020));

    let mut good = create_cpu_with_insn(0x4f82_e020);
    good.sysregs.el1.cpacr |= 0b11 << 20;
    assert_eq!(good.step().unwrap(), CpuExit::Continue);
}
#[test]
fn simd_scalar_cmp_zero_rejects_non_doubleword_size() {
    // Scalar integer compare-with-zero has only the D-sized form. The
    // generated boundary corpus includes B/H/S encodings, which hardware
    // reports as unallocated.
    for insn in [
        0x5e20_8800, // CMGT size=0
        0x5e60_8800, // CMGT size=1
        0x5ea0_8800, // CMGT size=2
        0x7e20_8800, // CMGE size=0
        0x5e20_9800, // CMEQ size=0
        0x5e20_a800, // CMLT size=0
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
        0x5ee0_8800, // CMGT D0, D0, #0
        0x7ee0_8800, // CMGE D0, D0, #0
        0x5ee0_9800, // CMEQ D0, D0, #0
        0x5ee0_a800, // CMLT D0, D0, #0
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    }
}
#[test]
fn simd_scalar_shift_imm_rejects_non_doubleword_size() {
    // Scalar same-size shift-immediate encodings are D-sized only. Vector
    // B/H/S forms exist, but the scalar B/H/S encodings are unallocated.
    for insn in [
        0x5f08_0400, // SSHR size=B
        0x5f18_0400, // SSHR size=H
        0x5f20_0400, // SSHR size=S
        0x7f08_4400, // SRI size=B
        0x7f08_5400, // SLI size=B
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
        0x5f7f_0400, // SSHR D0, D0, #1
        0x7f7f_0400, // USHR D0, D0, #1
        0x7f7f_4400, // SRI D0, D0, #1
        0x7f41_5400, // SLI D0, D0, #1
        0x5f08_7420, // SQSHL B0, B1, #0
        0x7f08_6420, // SQSHLU B0, B1, #0
        0x7f08_7420, // UQSHL B0, B1, #0
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    }
}
#[test]
fn simd_scalar_abs_neg_rejects_non_doubleword_size() {
    for insn in [
        0x5e20_b800, // ABS size=B
        0x5e60_b800, // ABS size=H
        0x5ea0_b800, // ABS size=S
        0x7e20_b800, // NEG size=B
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
        0x5ee0_b800, // ABS D0, D0
        0x7ee0_b800, // NEG D0, D0
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    }
}
#[test]
fn simd_scalar_fp16_pairwise_maxmin_rejects_reserved_size_bit() {
    // FP16 scalar pairwise max/min use size bit[1] for min/max selection.
    // The low size bit is reserved for max/min, though FADDP accepts it.
    for insn in [
        0x5e70_c800, // FMAXNMP with reserved low size bit
        0x5e70_f800, // FMAXP with reserved low size bit
        0x5ef0_c800, // FMINNMP with reserved low size bit
        0x5ef0_f800, // FMINP with reserved low size bit
    ] {
        let mut cpu = create_fp16_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        let exit = cpu.step();
        assert!(
            matches!(exit, Ok(CpuExit::Undefined(got)) if got == insn)
                || matches!(exit, Err(ArmError::UndefinedInstruction(got)) if got == insn),
            "expected {insn:#010x} to be undefined, got {exit:?}"
        );
    }

    for insn in [
        0x5e30_c800, // FMAXNMP H0, V0.2H
        0x5eb0_c800, // FMINNMP H0, V0.2H
        0x5e30_f800, // FMAXP H0, V0.2H
        0x5eb0_f800, // FMINP H0, V0.2H
    ] {
        let mut cpu = create_fp16_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    }

    let mut cpu = create_fp16_cpu_with_insn(0x5e30_f821); // FMAXP H1, V1.2H
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x3c00_7d01; // +1.0 and an FP16 signaling NaN
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);
}
#[test]
fn simd_scalar_fp16_pairwise_add_rejects_reserved_size_bit() {
    for insn in [
        0x5e70_d800, // FADDP with reserved low size bit
        0x5e70_d81f,
        0x5e70_dbe0,
    ] {
        let mut cpu = create_fp16_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        let exit = cpu.step();
        assert!(
            matches!(exit, Ok(CpuExit::Undefined(got)) if got == insn)
                || matches!(exit, Err(ArmError::UndefinedInstruction(got)) if got == insn),
            "expected {insn:#010x} to be undefined, got {exit:?}"
        );
    }

    let mut cpu = create_fp16_cpu_with_insn(0x5e30_d800); // FADDP H0, V0.2H
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = 0x3c00_7d01; // +1.0 and an FP16 signaling NaN
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);
}
#[test]
fn simd_float_narrow_sets_fpsr_status() {
    for insn in [
        0x2e21_6800, // FCVTXN with reserved f32->f16 size
        0x6e21_6800, // FCVTXN2 with reserved f32->f16 size
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

    let mut cpu = create_cpu_with_insn(0x0e21_6820); // FCVTN V0.4H, V1.4S
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x3f80_0000_0080_0000; // +1.0 and tiny f32 -> f16 zero
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_UFC | FPSR_IXC), FPSR_UFC | FPSR_IXC);

    let mut cpu = create_cpu_with_insn(0x0e21_6820); // FCVTN V0.4H, V1.4S
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x7f80_0001; // f32 signaling NaN
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);

    let mut cpu = create_cpu_with_insn(0x2e61_6820); // FCVTXN V0.2S, V1.2D
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = (f64::MAX.to_bits() as u128) | ((1.0f64.to_bits() as u128) << 64);
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_OFC | FPSR_IXC), FPSR_OFC | FPSR_IXC);
}
#[test]
fn simd_frintts_sets_fpsr_status() {
    let mut cpu = create_cpu_with_insn(0x0e21_e820); // FRINT32Z V0.2S, V1.2S
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x3fc0_0000_3fc0_0000; // 1.5 in both f32 lanes
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IXC, FPSR_IXC);

    let mut cpu = create_cpu_with_insn(0x0e21_e820); // FRINT32Z V0.2S, V1.2S
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x7fc0_0001_5280_0000; // quiet NaN and finite out-of-range
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);

    let mut cpu = create_cpu_with_insn(0x1e28_4020); // FRINT32Z S0, S1
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[1] = 0x7fc0_0001; // quiet NaN
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IOC, FPSR_IOC);
}
#[test]
fn simd_fp8fma_by_element_requires_v9_4_profile() {
    for insn in [
        0x0fc0_0000, // FMLALB by element, FP8 source
        0x0fc0_001f, // FP8 source, Rd=31
        0x0fc0_03e0, // FP8 source, Rn=31
        0x4fc0_0000, // FMLALT by element, FP8 source
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

    let mut invalid = create_cpu_with_insn(0x8fc0_0000); // bit31 set
    invalid.config.version = ArmVersion::V9_4A;
    invalid.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    assert!(matches!(
        invalid.step(),
        Err(ArmError::UndefinedInstruction(0x8fc0_0000))
    ));

    let mut valid = create_cpu_with_insn(0x0fc0_0000);
    valid.config.version = ArmVersion::V9_4A;
    valid.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    assert_eq!(valid.step().unwrap(), CpuExit::Continue);
}
#[test]
fn simd_scalar_sqdmlal_sets_qc_on_saturation() {
    let mut cpu = create_cpu_with_insn(0x5ea0_d000); // SQDMULL D0, S0, S0
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = 0x8000_0000; // i32::MIN
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_QC, FPSR_QC);

    let mut cpu = create_cpu_with_insn(0x5ea2_9020); // SQDMLAL D0, S1, S2
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = i64::MAX as u64 as u128;
    cpu.v[1] = 0x7fff_ffff;
    cpu.v[2] = 0x7fff_ffff;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_QC, FPSR_QC);

    let mut cpu = create_cpu_with_insn(0x5ea2_b020); // SQDMLSL D0, S1, S2
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = i64::MIN as u64 as u128;
    cpu.v[1] = 0x7fff_ffff;
    cpu.v[2] = 0x7fff_ffff;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_QC, FPSR_QC);
}
#[test]
fn simd_fp16_fma_lost_product_sets_inexact() {
    let acc = 0x5f11_5f11_5f11_5f11u128;
    let tiny = 0x0001_0001_0001_0001u128;

    let mut cpu = create_fp16_cpu_with_insn(0x0e41_0c20); // FMLA V0.4H, V1.4H, V1.4H
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = acc;
    cpu.v[1] = tiny;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IXC, FPSR_IXC);

    let mut cpu = create_fp16_cpu_with_insn(0x0f01_1020); // FMLA V0.4H, V1.4H, V1.H[0]
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = acc;
    cpu.v[1] = tiny;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IXC, FPSR_IXC);

    let mut cpu = create_fp16_cpu_with_insn(0x5f01_1020); // FMLA H0, H1, V1.H[0]
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = acc;
    cpu.v[1] = tiny;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & FPSR_IXC, FPSR_IXC);
}
#[test]
fn simd_fmulx_sets_underflow_for_tiny_f64_result() {
    let tiny = 0x0000_0000_0000_0001u128;

    let mut cpu = create_cpu_with_insn(0x4e60_dc00); // FMULX V0.2D, V0.2D, V0.2D
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = tiny | (tiny << 64);
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_UFC | FPSR_IXC), FPSR_UFC | FPSR_IXC);

    let mut cpu = create_cpu_with_insn(0x5e60_dc00); // FMULX D0, D0, D0
    cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
    cpu.v[0] = tiny;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpsr & (FPSR_UFC | FPSR_IXC), FPSR_UFC | FPSR_IXC);
}
#[test]
fn simd_two_reg_scalar_narrowing_writes_low_lane() {
    let cases = [
        (
            "sqxtun",
            encode_simd_two_reg_misc(true, 0, 1, 0, 0b10010, 1, 0),
            0xff80u64,
            0x00u64,
        ),
        (
            "sqxtn",
            encode_simd_two_reg_misc(true, 0, 0, 0, 0b10100, 1, 0),
            0xff80u64,
            0x80u64,
        ),
        (
            "uqxtn",
            encode_simd_two_reg_misc(true, 0, 1, 0, 0b10100, 1, 0),
            0x0123u64,
            0xffu64,
        ),
    ];

    for (name, insn, src, expected) in cases {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        cpu.set_simd_reg(0, 0xaaaa_aaaa_aaaa_aaaa, 0xbbbb_bbbb_bbbb_bbbb)
            .unwrap();
        cpu.set_simd_reg(1, src, 0).unwrap();

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{name}");
        assert_eq!(cpu.get_simd_reg(0), Some((expected, 0)), "{name}");
    }
}
#[test]
fn simd_two_reg_scalar_rejects_vector_only_narrow_widen_slots() {
    let bad = [
        encode_simd_two_reg_misc(true, 0, 0, 0, 0b00010, 1, 0), // SADDLP
        encode_simd_two_reg_misc(true, 0, 1, 0, 0b00110, 1, 0), // UADALP
        encode_simd_two_reg_misc(true, 0, 1, 0, 0b10011, 1, 0), // SHLL
        encode_simd_two_reg_misc(true, 0, 0, 0, 0b10010, 1, 0), // XTN
    ];

    for insn in bad {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 20; // FPEN
        assert!(
            matches!(cpu.step(), Err(ArmError::UndefinedInstruction(got)) if got == insn),
            "{insn:#010x} must trap"
        );
    }

    let mut valid_vector_xtn =
        create_cpu_with_insn(encode_simd_two_reg_misc(false, 0, 0, 0, 0b10010, 1, 0));
    valid_vector_xtn.sysregs.el1.cpacr |= 0b11 << 20;
    assert_eq!(valid_vector_xtn.step().unwrap(), CpuExit::Continue);
}
#[test]
fn sve_fp_pairwise_rejects_reserved_encodings() {
    // FP pairwise (FADDP/.../FMINP) is defined only for H/S/D elements and
    // opc in {000,100,101,110,111}. Reserved size==00 and reserved opc
    // values (001/010/011) must trap as UNDEFINED, not execute as FMINP.
    let setup = |insn: u32| {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
        cpu.set_sve_pred(0, 0xffff);
        cpu
    };

    // Reserved size==00 (byte elements): 0x64108040.
    assert_eq!(
        setup(0x6410_8040).step().unwrap(),
        CpuExit::Undefined(0x6410_8040)
    );
    // Reserved opc==001 (S elements): 0x64918040.
    assert_eq!(
        setup(0x6491_8040).step().unwrap(),
        CpuExit::Undefined(0x6491_8040)
    );

    // Valid FADDP z0.s, p0/m, z0.s, z2.s (opc 000, S) still executes.
    assert_eq!(setup(0x6490_8040).step().unwrap(), CpuExit::Continue);
}
#[test]
fn sve_dup_scalar_register_broadcasts_xn_or_sp() {
    let x1 = 0x1122_3344_5566_7788u64;
    for (insn, expected) in [
        (0x0520_3820, 0x8888_8888_8888_8888_8888_8888_8888_8888), // DUP B
        (0x0560_3820, 0x7788_7788_7788_7788_7788_7788_7788_7788), // DUP H
        (0x05a0_3820, 0x5566_7788_5566_7788_5566_7788_5566_7788), // DUP S
        (0x05e0_3820, 0x1122_3344_5566_7788_1122_3344_5566_7788), // DUP D
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_x(1, x1);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_simd(0), expected);
    }

    let mut cpu = create_cpu_with_insn(0x05e0_3be0); // DUP Z0.D, SP
    cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    cpu.set_current_sp(0xfeed_face_cafe_beefu64);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_simd(0), 0xfeed_face_cafe_beef_feed_face_cafe_beef);
}
#[test]
fn sve_last_scalar_selects_active_or_wrapped_element() {
    let bytes = u128::from_le_bytes([
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ]);
    for (insn, pred, expected) in [
        (0x0522_8020, (1 << 1) | (1 << 4), 0x15), // LASTA B: after lane 4
        (0x0523_8020, (1 << 1) | (1 << 4), 0x14), // LASTB B: lane 4
        (0x0522_8020, 0, 0x10),                   // LASTA B: no active -> lane 0
        (0x0523_8020, 0, 0x1f),                   // LASTB B: no active -> final lane
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_sve_pred(0, pred);
        cpu.set_simd(1, bytes);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_simd(0), expected);
    }

    let mut cpu = create_cpu_with_insn(0x05e3_8020); // LASTB D0, P0, Z1.D
    cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    cpu.set_sve_pred(0, 1 << 8);
    cpu.set_simd(1, 0x2222_2222_2222_2222_1111_1111_1111_1111);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_simd(0), 0x2222_2222_2222_2222);
}
#[test]
fn test_f32_to_bf16_with_fpcr_rounding_modes() {
    let positive_low_even_tie = 0x3f80_8000u32;
    let positive_low_odd_tie = 0x3f81_8000u32;
    let negative_low_even_tie = 0xbf80_8000u32;
    let negative_low_odd_tie = 0xbf81_8000u32;

    assert_eq!(
        f32_to_bf16_with_fpcr(positive_low_even_tie, 0 << 22),
        0x3f80
    );
    assert_eq!(f32_to_bf16_with_fpcr(positive_low_odd_tie, 0 << 22), 0x3f82);
    assert_eq!(
        f32_to_bf16_with_fpcr(positive_low_even_tie, 1 << 22),
        0x3f81
    );
    assert_eq!(f32_to_bf16_with_fpcr(positive_low_odd_tie, 2 << 22), 0x3f81);
    assert_eq!(f32_to_bf16_with_fpcr(positive_low_odd_tie, 3 << 22), 0x3f81);

    assert_eq!(
        f32_to_bf16_with_fpcr(negative_low_even_tie, 0 << 22),
        0xbf80
    );
    assert_eq!(f32_to_bf16_with_fpcr(negative_low_odd_tie, 0 << 22), 0xbf82);
    assert_eq!(f32_to_bf16_with_fpcr(negative_low_odd_tie, 1 << 22), 0xbf81);
    assert_eq!(
        f32_to_bf16_with_fpcr(negative_low_even_tie, 2 << 22),
        0xbf81
    );
    assert_eq!(f32_to_bf16_with_fpcr(negative_low_odd_tie, 3 << 22), 0xbf81);
}
// Regression for issue #45: the JIT vector load/store helpers must translate and
// permission-check every byte (like the interpreter), so a vector access that
// straddles a guest page boundary faults on the second page instead of reading/
// writing adjacent physical memory. Here page 0x1000 is mapped but 0x2000 is not.
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn issue_45_vector_helper_translates_each_page() {
    use crate::smir::lower::runtime::Aarch64GuestRegs;

    let mut cpu = create_test_cpu();
    // 4KB-page MMU, single L3 level (T0SZ=43): L3 index = va[20:12]. Map page
    // 0x1000 -> PA frame 1, AP=01 (RW); leave page 0x2000 invalid (unmapped).
    let l3 = 0x8000u64;
    cpu.mem_write_u64(l3 + 8, 0x1443).unwrap(); // L3[1]: page, AF, AP=01, PA frame 1
    cpu.mem_write_u64(0x1000, 0x1122_3344_5566_7788).unwrap();
    cpu.sysregs.el1.ttbr0 = l3;
    cpu.sysregs.el1.tcr = 43; // T0SZ=43, TG0=0 (4KB)
    cpu.sysregs.el1.sctlr |= sctlr::M;
    cpu.update_mmu_config();

    let mut regs = Aarch64GuestRegs::default();
    regs.ctx = &cpu as *const AArch64Cpu as usize as u64;

    // A vector load fully inside the mapped page succeeds.
    let ok = unsafe { rax_a64_vec_load(&mut regs, 0x1000, 0, 8) };
    assert_eq!(ok, 1, "in-page vector load succeeds");
    assert_eq!(regs.v[0], 0x1122_3344_5566_7788);

    // A vector load straddling into the UNMAPPED page 0x2000 must fault.
    let ok = unsafe { rax_a64_vec_load(&mut regs, 0x1FF9, 1, 8) };
    assert_eq!(
        ok, 0,
        "page-straddling vector load must fault on the unmapped page"
    );
}
