//! fp part 2 tests

use super::*;
use crate::smir::interpret::tests::*;
use crate::smir::interpret::*;

#[test]
fn smir_x86_scalar_shifts_apply_the_operand_count_mask() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let initial_flags = 0x2 | 0x8D5;

    for (op, initial) in [
        (
            OpKind::Shl {
                dst: rax,
                src: rax,
                amount: SrcOperand::Imm(32),
                width: OpWidth::W8,
                flags: FlagUpdate::All,
            },
            0xA5A5_A5A5_A5A5_A581,
        ),
        (
            OpKind::Shr {
                dst: rax,
                src: rax,
                amount: SrcOperand::Reg(VReg::Arch(ArchReg::X86(X86Reg::Rcx))),
                width: OpWidth::W16,
                flags: FlagUpdate::All,
            },
            0xA5A5_A5A5_A5A5_8001,
        ),
        (
            OpKind::Sar {
                dst: rax,
                src: rax,
                amount: SrcOperand::Imm(32),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
            0x8000_0000,
        ),
    ] {
        let (value, flags) = exec_x86_rax_op(op, initial, 32, initial_flags);
        assert_eq!(
            value, initial,
            "masked count zero must preserve the operand"
        );
        assert_eq!(
            flags & 0x8D5,
            initial_flags & 0x8D5,
            "masked count zero must preserve every status flag"
        );
    }
}
/// Pins a few known (input -> Rd, Pe) pairs for the reciprocal / inverse-sqrt
/// seed + fixup family. The expected values were derived directly from the
/// reference sem (`src/isa/hexagon/semantics/float_ext.rs`:
/// `sf_recipa`/`sf_invsqrta`/`sf_recip_common`/`sf_invsqrt_common`), which is
/// what the full diff harness (`tests/suites/smir/lift/hexagon.rs`) compares against.
#[test]
fn smir_hex_fp_recip_eval_matches_sem() {
    use HexFpRecipKind::*;

    // ---- sfrecipa normal seed path (no scalbn adjust, Pe = 0) ----
    // recipa(_, 2.0): idx=0, mant=(0xfe<<15)|1, exp=125 -> 0x3eff0001.
    assert_eq!(
        hex_fp_recip_eval(SfRecipa, 0x3f80_0000, 0x4000_0000),
        (0x3eff_0001, 0x00)
    );
    // recipa(_, 4.0): idx=0, exp=124 -> 0x3e7f0001.
    assert_eq!(
        hex_fp_recip_eval(SfRecipa, 0x3f80_0000, 0x4080_0000),
        (0x3e7f_0001, 0x00)
    );
    // ---- sfrecipa special cases (Pe = 0) ----
    // Rt == 0 (divide-by-zero) -> the common sets RdV = float32_one (the seed
    // result for the special cases; the actual inf/zero lands in RsV/RtV for
    // the fixup ops). So sfrecipa's Rd = 1.0, Pe = 0.
    assert_eq!(
        hex_fp_recip_eval(SfRecipa, 0x4040_0000 /*3.0*/, 0x0000_0000),
        (0x3f80_0000, 0x00)
    );
    // Either NaN -> default all-ones NaN.
    assert_eq!(
        hex_fp_recip_eval(SfRecipa, 0x7fc0_0000, 0x3f80_0000),
        (0xffff_ffff, 0x00)
    );

    // ---- sfinvsqrta normal seed path (Rt ignored, Pe = 0) ----
    // invsqrta(4.0): idx=64, mant=0xfe<<15, exp=125 -> 0x3eff0000.
    assert_eq!(
        hex_fp_recip_eval(SfInvSqrtA, 0x4080_0000, 0),
        (0x3eff_0000, 0x00)
    );
    // invsqrta(1.0): idx=64, exp=126 -> 0x3f7f0000.
    assert_eq!(
        hex_fp_recip_eval(SfInvSqrtA, 0x3f80_0000, 0),
        (0x3f7f_0000, 0x00)
    );
    // ---- sfinvsqrta extreme-exponent path: Rs=2^-110 (raw exp 17 <= 24) ----
    // scalbn(+64) -> 0x28800000; idx=64, exp=149 -> 0x4aff0000, Pe = 0xe0.
    assert_eq!(
        hex_fp_recip_eval(SfInvSqrtA, 0x0880_0000, 0),
        (0x4aff_0000, 0xe0)
    );
    // invsqrta(-1.0): negative non-zero -> default NaN, Pe = 0.
    assert_eq!(
        hex_fp_recip_eval(SfInvSqrtA, 0xbf80_0000, 0),
        (0xffff_ffff, 0x00)
    );

    // ---- fixup ops return the (possibly adjusted) operand, no Pe ----
    // sffixupn/d on a no-adjust normal pair returns the operands unchanged.
    assert_eq!(
        hex_fp_recip_eval(SfFixupN, 0x3f80_0000, 0x4000_0000),
        (0x3f80_0000, 0x00)
    );
    assert_eq!(
        hex_fp_recip_eval(SfFixupD, 0x3f80_0000, 0x4000_0000),
        (0x4000_0000, 0x00)
    );
    // sffixupr on Rs=2^-110 returns the scalbn(+64)-adjusted radicand.
    assert_eq!(
        hex_fp_recip_eval(SfFixupR, 0x0880_0000, 0),
        (0x2880_0000, 0x00)
    );
}
#[test]
fn smir_hex_fp_eval_matches_sem() {
    use HexFpOp::*;
    let f32b = |x: f32| x.to_bits() as u64;
    let f64b = |x: f64| x.to_bits();

    // ---- compares -> predicate byte ----
    assert_eq!(hex_fp_eval(SfCmpEq, f32b(1.0), f32b(1.0)), 0xff);
    assert_eq!(hex_fp_eval(SfCmpEq, f32b(1.0), f32b(2.0)), 0x00);
    assert_eq!(hex_fp_eval(SfCmpGt, f32b(2.0), f32b(1.0)), 0xff);
    assert_eq!(hex_fp_eval(SfCmpGe, f32b(1.0), f32b(1.0)), 0xff);
    // NaN -> unordered: eq/gt/ge false, uo true.
    let snan32 = 0x7f80_0001u64; // signaling NaN
    assert_eq!(hex_fp_eval(SfCmpEq, snan32, f32b(1.0)), 0x00);
    assert_eq!(hex_fp_eval(SfCmpUo, snan32, f32b(1.0)), 0xff);
    assert_eq!(hex_fp_eval(DfCmpGt, f64b(3.0), f64b(2.0)), 0xff);
    assert_eq!(hex_fp_eval(DfCmpUo, f64::NAN.to_bits(), f64b(0.0)), 0xff);

    // ---- classify: mask bit by category (0=zero,1=normal,2=sub,3=inf,4=nan) ----
    assert_eq!(hex_fp_eval(SfClass, f32b(0.0), 1 << 0), 0xff); // zero
    assert_eq!(hex_fp_eval(SfClass, f32b(1.5), 1 << 1), 0xff); // normal
    assert_eq!(
        hex_fp_eval(SfClass, f32::INFINITY.to_bits() as u64, 1 << 3),
        0xff
    );
    assert_eq!(hex_fp_eval(SfClass, snan32, 1 << 4), 0xff); // nan
    assert_eq!(hex_fp_eval(SfClass, f32b(1.5), 1 << 0), 0x00); // normal !zero
    assert_eq!(hex_fp_eval(DfClass, f64b(0.0), 1 << 0), 0xff);

    // ---- min / max with signed-zero tie + NaN ----
    assert_eq!(hex_fp_eval(SfMax, f32b(1.0), f32b(2.0)), f32b(2.0));
    assert_eq!(hex_fp_eval(SfMin, f32b(1.0), f32b(2.0)), f32b(1.0));
    // max(+0,-0) = +0 ; min(+0,-0) = -0
    assert_eq!(hex_fp_eval(SfMax, f32b(0.0), f32b(-0.0)), f32b(0.0));
    assert_eq!(hex_fp_eval(SfMin, f32b(0.0), f32b(-0.0)), f32b(-0.0));
    // one quiet NaN -> the number (no canonicalisation).
    let qnan32 = 0x7fc0_0000u64;
    assert_eq!(hex_fp_eval(SfMax, qnan32, f32b(3.0)), f32b(3.0));
    // both NaN -> default all-ones.
    assert_eq!(hex_fp_eval(SfMax, qnan32, qnan32), 0xFFFF_FFFF);
    assert_eq!(hex_fp_eval(DfMax, f64b(1.0), f64b(2.0)), f64b(2.0));

    // ---- arithmetic, native round + default-NaN ----
    assert_eq!(hex_fp_eval(SfAdd, f32b(1.0), f32b(2.0)), f32b(3.0));
    assert_eq!(hex_fp_eval(SfSub, f32b(5.0), f32b(2.0)), f32b(3.0));
    assert_eq!(hex_fp_eval(SfMpy, f32b(3.0), f32b(4.0)), f32b(12.0));
    assert_eq!(hex_fp_eval(DfAdd, f64b(1.0), f64b(2.0)), f64b(3.0));
    assert_eq!(hex_fp_eval(DfSub, f64b(5.0), f64b(2.0)), f64b(3.0));
    // inf - inf -> default NaN
    assert_eq!(
        hex_fp_eval(
            SfSub,
            f32::INFINITY.to_bits() as u64,
            f32::INFINITY.to_bits() as u64
        ),
        0xFFFF_FFFF
    );

    // ---- conversions ----
    assert_eq!(hex_fp_eval(ConvSf2Df, f32b(2.5), 0), f64b(2.5));
    assert_eq!(hex_fp_eval(ConvDf2Sf, f64b(2.5), 0), f32b(2.5));
    assert_eq!(hex_fp_eval(ConvW2Sf, (-3i32) as u32 as u64, 0), f32b(-3.0));
    assert_eq!(hex_fp_eval(ConvUw2Sf, 3u64, 0), f32b(3.0));
    assert_eq!(hex_fp_eval(ConvW2Df, (-3i32) as u32 as u64, 0), f64b(-3.0));
    // sf -> signed int (round-to-nearest-even): 2.5 -> 2 ; 3.5 -> 4
    assert_eq!(hex_fp_eval(ConvSf2W, f32b(2.5), 0), 2);
    assert_eq!(hex_fp_eval(ConvSf2W, f32b(3.5), 0), 4);
    assert_eq!(hex_fp_eval(ConvSf2WChop, f32b(2.9), 0), 2);
    // NaN -> -1 (signed) ; saturate max (unsigned)
    assert_eq!(hex_fp_eval(ConvSf2W, snan32, 0), 0xFFFF_FFFF);
    assert_eq!(hex_fp_eval(ConvSf2Uw, snan32, 0), 0xFFFF_FFFF);
    // negative -> unsigned saturates to 0
    assert_eq!(hex_fp_eval(ConvSf2Uw, f32b(-1.0), 0), 0);
    // out-of-range signed saturates to i32::MAX
    assert_eq!(hex_fp_eval(ConvSf2W, f32b(1e30), 0), i32::MAX as u32 as u64);
    assert_eq!(hex_fp_eval(ConvDf2D, f64b(123.0), 0), 123);

    // ---- fused multiply-add (single rounding) ----
    // 2*3 + 4 = 10 ; 4 - 2*3 = -2
    assert_eq!(
        hex_sf_fma(f32b(2.0) as u32, f32b(3.0) as u32, f32b(4.0) as u32, false),
        f32b(10.0) as u32
    );
    assert_eq!(
        hex_sf_fma(f32b(2.0) as u32, f32b(3.0) as u32, f32b(4.0) as u32, true),
        f32b(-2.0) as u32
    );
    // NaN accumulator -> canonical all-ones.
    assert_eq!(
        hex_sf_fma(f32b(2.0) as u32, f32b(3.0) as u32, snan32 as u32, false),
        0xFFFF_FFFF
    );
    // 0 * inf -> NaN -> canonical.
    assert_eq!(
        hex_sf_fma(
            f32b(0.0) as u32,
            f32::INFINITY.to_bits(),
            f32b(1.0) as u32,
            false
        ),
        0xFFFF_FFFF
    );
}
#[test]
fn lifted_scalar_vector_movq_executes_aliasing_upper_state_memory_and_faults_exactly() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let flags_before = 0xCD7;
    let mut memory = FlatMemory::new(0x400);
    let mut ctx = SmirContext::new_x86_64();
    ctx.flags.materialized = MaterializedFlags::from_rflags(flags_before);
    ctx.flags.lazy = None;

    // Legacy load clears bits 127:64 and preserves backing state above bit
    // 127. A same-register source must be captured before that clear.
    let legacy_dst = [0xAAAA_AAAA_AAAA_AAAAu64; 16];
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = legacy_dst;
        x86.xmm[1][0] = 0x0123_4567_89AB_CDEF;
    }
    execute_lifted_x86(&[0xF3, 0x0F, 0x7E, 0xC1], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0][0], 0x0123_4567_89AB_CDEF);
        assert_eq!(x86.xmm[0][1], 0);
        assert_eq!(&x86.xmm[0][2..], &legacy_dst[2..]);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = legacy_dst;
        x86.xmm[0][0] = 0x8877_6655_4433_2211;
    }
    execute_lifted_x86(&[0xF3, 0x0F, 0x7E, 0xC0], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0][0], 0x8877_6655_4433_2211);
        assert_eq!(x86.xmm[0][1], 0);
        assert_eq!(&x86.xmm[0][2..], &legacy_dst[2..]);
    }

    // Legacy store-to-register has the same destination upper-state rule.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0][0] = 0xDEAD_BEEF_CAFE_BABE;
        x86.xmm[1] = legacy_dst;
    }
    execute_lifted_x86(&[0x66, 0x0F, 0xD6, 0xC1], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(x86.xmm[1][1], 0);
        assert_eq!(&x86.xmm[1][2..], &legacy_dst[2..]);
    }

    // VEX load and store-to-register clear all state above the low qword.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = [u64::MAX; 16];
        x86.xmm[1][0] = 0x1111_2222_3333_4444;
    }
    execute_lifted_x86(&[0xC5, 0xFA, 0x7E, 0xC1], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0][0], 0x1111_2222_3333_4444);
        assert!(x86.xmm[0][1..].iter().all(|word| *word == 0));
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0][0] = 0x5555_6666_7777_8888;
        x86.xmm[1] = [u64::MAX; 16];
    }
    execute_lifted_x86(&[0xC5, 0xF9, 0xD6, 0xC1], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x5555_6666_7777_8888);
        assert!(x86.xmm[1][1..].iter().all(|word| *word == 0));
    }

    // EVEX high-register load and compressed disp8*N store use N=8 bytes.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[17] = [u64::MAX; 16];
        x86.xmm[18][0] = 0x9999_AAAA_BBBB_CCCC;
    }
    execute_lifted_x86(&[0x62, 0xA1, 0xFE, 0x08, 0x7E, 0xCA], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[17][0], 0x9999_AAAA_BBBB_CCCC);
        assert!(x86.xmm[17][1..].iter().all(|word| *word == 0));
    }
    memory.write(0x180, &[0xA5; 16]).unwrap();
    ctx.write_vreg(rax, 0x100);
    execute_lifted_x86(
        &[0x62, 0xF1, 0xFD, 0x08, 0xD6, 0x40, 0x10],
        &mut ctx,
        &mut memory,
    );
    let mut stored = [0u8; 16];
    memory.read(0x180, &mut stored).unwrap();
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(&stored[..8], &x86.xmm[0][0].to_le_bytes());
    }
    assert_eq!(&stored[8..], &[0xA5; 8]);

    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags(), flags_before);

    // A faulting load must not perform any part of its destination write.
    let fault_sentinel = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = fault_sentinel;
    }
    ctx.write_vreg(rax, 0x1000);
    let exit = execute_lifted_x86(&[0xC5, 0xFA, 0x7E, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0], fault_sentinel);
    }
}
#[test]
fn lifted_horizontal_integer_family_executes_ordering_wrapping_saturation_and_faults() {
    fn seeded(bytes: &[u8], fill: u64) -> VecValue {
        let mut value = [fill; 16];
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            value[index] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        value
    }

    fn bytes(value: &VecValue, len: usize) -> Vec<u8> {
        value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(len)
            .collect()
    }

    fn reference(
        first: &[u8],
        second: &[u8],
        elem_bytes: usize,
        subtract: bool,
        saturating: bool,
    ) -> Vec<u8> {
        let bits = elem_bytes * 8;
        let mask = (1u64 << bits) - 1;
        let block_lanes = usize::min(16, first.len()) / elem_bytes;
        let lanes = first.len() / elem_bytes;
        let read = |source: &[u8], lane: usize| -> u64 {
            let at = lane * elem_bytes;
            match elem_bytes {
                2 => u64::from(u16::from_le_bytes(source[at..at + 2].try_into().unwrap())),
                4 => u64::from(u32::from_le_bytes(source[at..at + 4].try_into().unwrap())),
                _ => unreachable!(),
            }
        };
        let calculate = |a: u64, b: u64| -> u64 {
            if saturating {
                let shift = 64 - bits;
                let lhs = ((a << shift) as i64) >> shift;
                let rhs = ((b << shift) as i64) >> shift;
                let value = if subtract { lhs - rhs } else { lhs + rhs };
                value.clamp(-(1i64 << (bits - 1)), (1i64 << (bits - 1)) - 1) as u64 & mask
            } else if subtract {
                a.wrapping_sub(b) & mask
            } else {
                a.wrapping_add(b) & mask
            }
        };
        let mut result = vec![0; first.len()];
        let mut write = |lane: usize, value: u64| {
            let at = lane * elem_bytes;
            result[at..at + elem_bytes].copy_from_slice(&value.to_le_bytes()[..elem_bytes]);
        };
        for block_base in (0..lanes).step_by(block_lanes) {
            let half = block_lanes / 2;
            for pair in 0..half {
                let lhs = block_base + pair * 2;
                write(
                    block_base + pair,
                    calculate(read(first, lhs), read(first, lhs + 1)),
                );
                write(
                    block_base + half + pair,
                    calculate(read(second, lhs), read(second, lhs + 1)),
                );
            }
        }
        result
    }

    let words1 = [
        30_000i16,
        10_000,
        i16::MAX,
        1,
        i16::MIN,
        -1,
        200,
        -300,
        12_000,
        -15_000,
        20_000,
        20_000,
        -20_000,
        -20_000,
        1234,
        4321,
    ];
    let words2 = [
        -30_000i16,
        -10_000,
        i16::MIN,
        1,
        i16::MAX,
        -1,
        -200,
        300,
        -12_000,
        15_000,
        25_000,
        25_000,
        -25_000,
        -25_000,
        -1234,
        -4321,
    ];
    let dwords1 = [
        2_000_000_000i32,
        1_000_000_000,
        i32::MAX,
        1,
        i32::MIN,
        -1,
        123_456,
        -654_321,
    ];
    let dwords2 = [
        -2_000_000_000i32,
        -1_000_000_000,
        i32::MIN,
        1,
        i32::MAX,
        -1,
        -123_456,
        654_321,
    ];
    let words1_bytes = words1
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let words2_bytes = words2
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let dwords1_bytes = dwords1
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let dwords2_bytes = dwords2
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let upper = 0xA5A5_A5A5_A5A5_A5A5;
    let flags_before = 0xCD7;
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x400);
    ctx.flags.materialized = MaterializedFlags::from_rflags(flags_before);
    ctx.flags.lazy = None;

    for (opcode, first, second, elem_bytes, subtract, saturating) in [
        (
            0x01,
            words1_bytes.as_slice(),
            words2_bytes.as_slice(),
            2,
            false,
            false,
        ),
        (
            0x02,
            dwords1_bytes.as_slice(),
            dwords2_bytes.as_slice(),
            4,
            false,
            false,
        ),
        (
            0x03,
            words1_bytes.as_slice(),
            words2_bytes.as_slice(),
            2,
            false,
            true,
        ),
        (
            0x05,
            words1_bytes.as_slice(),
            words2_bytes.as_slice(),
            2,
            true,
            false,
        ),
        (
            0x06,
            dwords1_bytes.as_slice(),
            dwords2_bytes.as_slice(),
            4,
            true,
            false,
        ),
        (
            0x07,
            words1_bytes.as_slice(),
            words2_bytes.as_slice(),
            2,
            true,
            true,
        ),
    ] {
        let mmx_first = u64::from_le_bytes(first[..8].try_into().unwrap());
        let mmx_second = u64::from_le_bytes(second[..8].try_into().unwrap());
        let mmx_expected = u64::from_le_bytes(
            reference(&first[..8], &second[..8], elem_bytes, subtract, saturating)
                .try_into()
                .unwrap(),
        );
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.mm[0] = mmx_first;
            x86.mm[1] = mmx_second;
            x86.x87.tag_word = 0xFFFF;
            x86.x87.status_word = 3 << 11;
        }
        execute_lifted_x86(&[0x0F, 0x38, opcode, 0xC1], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(
                x86.mm[0], mmx_expected,
                "MMX horizontal opcode {opcode:02X}"
            );
            assert_eq!(x86.x87.tag_word, 0);
            assert_eq!(x86.x87.status_word & 0x3800, 3 << 11);
        }

        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[0] = seeded(&first[..16], upper);
            x86.xmm[1] = seeded(&second[..16], 0);
        }
        execute_lifted_x86(&[0x66, 0x0F, 0x38, opcode, 0xC1], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(
                bytes(&x86.xmm[0], 16),
                reference(
                    &first[..16],
                    &second[..16],
                    elem_bytes,
                    subtract,
                    saturating,
                ),
                "legacy horizontal opcode {opcode:02X}",
            );
            assert!(x86.xmm[0][2..].iter().all(|word| *word == upper));
        }

        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[0] = [u64::MAX; 16];
            x86.xmm[1] = seeded(first, 0);
            x86.xmm[2] = seeded(second, 0);
        }
        execute_lifted_x86(&[0xC4, 0xE2, 0x75, opcode, 0xC2], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(
                bytes(&x86.xmm[0], 32),
                reference(first, second, elem_bytes, subtract, saturating),
                "VEX horizontal opcode {opcode:02X}",
            );
            assert!(x86.xmm[0][4..].iter().all(|word| *word == 0));
        }
    }

    // Destructive same-register legacy operands are read before any result
    // lane is merged back into the destination.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = seeded(&words1_bytes[..16], upper);
    }
    execute_lifted_x86(&[0x66, 0x0F, 0x38, 0x01, 0xC0], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[0], 16),
            reference(&words1_bytes[..16], &words1_bytes[..16], 2, false, false,)
        );
    }

    // The destructive MMX alias reads both source operands before the
    // packed result replaces MM0.
    let mmx_alias = u64::from_le_bytes(words1_bytes[..8].try_into().unwrap());
    let mmx_alias_expected = u64::from_le_bytes(
        reference(&words1_bytes[..8], &words1_bytes[..8], 2, false, false)
            .try_into()
            .unwrap(),
    );
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mm[0] = mmx_alias;
    }
    execute_lifted_x86(&[0x0F, 0x38, 0x01, 0xC0], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.mm[0], mmx_alias_expected);
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let sentinel = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    memory.write(0x101, &words2_bytes).unwrap();
    ctx.write_vreg(rax, 0x101);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
    }
    let misaligned = execute_lifted_x86(&[0x66, 0x0F, 0x38, 0x03, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        misaligned,
        BlockResult::Exit(ExitReason::GeneralProtection { error_code: 0, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0], sentinel);
    }

    // The MMX source is an unaligned m64. Its complete load precedes the
    // destructive destination write and the x87-to-MMX state transition.
    memory.write(0x181, &words2_bytes[..8]).unwrap();
    ctx.write_vreg(rax, 0x180);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mm[0] = u64::from_le_bytes(words1_bytes[..8].try_into().unwrap());
        x86.x87.tag_word = 0xFFFF;
    }
    execute_lifted_x86(&[0x0F, 0x38, 0x07, 0x40, 0x01], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            x86.mm[0],
            u64::from_le_bytes(
                reference(&words1_bytes[..8], &words2_bytes[..8], 2, true, true)
                    .try_into()
                    .unwrap()
            )
        );
        assert_eq!(x86.x87.tag_word, 0);
    }

    ctx.write_vreg(rax, 0x3FC);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mm[0] = 0xDEAD_BEEF_CAFE_BABE;
        x86.x87.tag_word = 0xFFFF;
    }
    let mmx_fault = execute_lifted_x86(&[0x0F, 0x38, 0x01, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        mmx_fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.mm[0], 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(x86.x87.tag_word, 0xFFFF);
    }

    // Type-4 alignment applies only to legacy SSE; VEX.256 accepts the
    // same unaligned address and consumes the complete 32-byte operand.
    ctx.write_vreg(rax, 0x101);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
        x86.xmm[1] = seeded(&words1_bytes, 0);
    }
    execute_lifted_x86(&[0xC4, 0xE2, 0x75, 0x01, 0x00], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[0], 32),
            reference(&words1_bytes, &words2_bytes, 2, false, false)
        );
    }

    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags(), flags_before);

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
    }
    ctx.write_vreg(rax, 0x3F0);
    let fault = execute_lifted_x86(&[0xC4, 0xE2, 0x75, 0x06, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0], sentinel);
    }
}
#[test]
fn lifted_psign_family_executes_wrapping_control_aliases_and_faults() {
    fn seeded(bytes: &[u8], fill: u64) -> VecValue {
        let mut value = [fill; 16];
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            value[index] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        value
    }

    fn bytes(value: &VecValue, len: usize) -> Vec<u8> {
        value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(len)
            .collect()
    }

    fn reference(value: &[u8], control: &[u8], elem_bytes: usize) -> Vec<u8> {
        let bits = elem_bytes * 8;
        let mask = (1u64 << bits) - 1;
        value
            .chunks_exact(elem_bytes)
            .zip(control.chunks_exact(elem_bytes))
            .flat_map(|(value, control)| {
                let read = |bytes: &[u8]| -> u64 {
                    match elem_bytes {
                        1 => u64::from(bytes[0]),
                        2 => u64::from(u16::from_le_bytes(bytes.try_into().unwrap())),
                        4 => u64::from(u32::from_le_bytes(bytes.try_into().unwrap())),
                        _ => unreachable!(),
                    }
                };
                let value = read(value);
                let control = read(control);
                let result = if control == 0 {
                    0
                } else if control & (1u64 << (bits - 1)) != 0 {
                    0u64.wrapping_sub(value) & mask
                } else {
                    value
                };
                result.to_le_bytes()[..elem_bytes].to_vec()
            })
            .collect()
    }

    let byte_values = [
        0x80u8, 0x7F, 0x01, 0xFF, 0x55, 0xAA, 0x00, 0x40, 0x81, 0x11, 0x22, 0x33, 0x44, 0x66, 0x77,
        0x88, 0x80, 0x7F, 0x01, 0xFF, 0x55, 0xAA, 0x00, 0x40, 0x81, 0x11, 0x22, 0x33, 0x44, 0x66,
        0x77, 0x88,
    ];
    let byte_controls = [
        0xFFu8, 0x80, 0x00, 0x01, 0x7F, 0xFE, 0x00, 0x02, 0x81, 0x00, 0x01, 0xFF, 0x7F, 0x80, 0x00,
        0x01, 0xFF, 0x80, 0x00, 0x01, 0x7F, 0xFE, 0x00, 0x02, 0x81, 0x00, 0x01, 0xFF, 0x7F, 0x80,
        0x00, 0x01,
    ];
    let word_values = [
        i16::MIN,
        i16::MAX,
        1,
        -1,
        0x1234,
        -0x2345,
        0,
        17,
        i16::MIN,
        i16::MAX,
        1,
        -1,
        0x3456,
        -0x4567,
        0,
        29,
    ];
    let word_controls = [
        -1i16,
        i16::MIN,
        0,
        1,
        i16::MAX,
        -2,
        0,
        2,
        -1,
        i16::MIN,
        0,
        1,
        i16::MAX,
        -2,
        0,
        2,
    ];
    let dword_values = [i32::MIN, i32::MAX, 1, -1, 0x1234_5678, -0x2345_678, 0, 37];
    let dword_controls = [-1i32, i32::MIN, 0, 1, i32::MAX, -2, 0, 2];
    let word_value_bytes = word_values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let word_control_bytes = word_controls
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let dword_value_bytes = dword_values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let dword_control_bytes = dword_controls
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let cases = [
        (
            0x08,
            1usize,
            byte_values.as_slice(),
            byte_controls.as_slice(),
        ),
        (
            0x09,
            2,
            word_value_bytes.as_slice(),
            word_control_bytes.as_slice(),
        ),
        (
            0x0A,
            4,
            dword_value_bytes.as_slice(),
            dword_control_bytes.as_slice(),
        ),
    ];

    let upper = 0xA5A5_A5A5_A5A5_A5A5;
    let sentinel = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    let flags_before = 0xCD7;
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x400);
    ctx.flags.materialized = MaterializedFlags::from_rflags(flags_before);
    ctx.flags.lazy = None;

    for &(opcode, elem_bytes, value, control) in &cases {
        let value = &value[..8];
        let control = &control[..8];
        let expected =
            u64::from_le_bytes(reference(value, control, elem_bytes).try_into().unwrap());
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.mm[0] = u64::from_le_bytes(value.try_into().unwrap());
            x86.mm[1] = u64::from_le_bytes(control.try_into().unwrap());
            x86.x87.tag_word = 0xFFFF;
            x86.x87.status_word = 3 << 11;
        }
        execute_lifted_x86(&[0x0F, 0x38, opcode, 0xC1], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.mm[0], expected, "MMX opcode={opcode:02X}");
            assert_eq!(x86.x87.tag_word, 0);
            assert_eq!(x86.x87.status_word & 0x3800, 3 << 11);
        }
    }

    // The m64 control operand is unaligned and must be read completely
    // before either the destructive destination or x87/MMX state changes.
    let mmx_value = &byte_values[..8];
    let mmx_control = &byte_controls[..8];
    let mmx_expected = u64::from_le_bytes(reference(mmx_value, mmx_control, 1).try_into().unwrap());
    memory.write(0x81, mmx_control).unwrap();
    ctx.write_vreg(rax, 0x80);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mm[0] = u64::from_le_bytes(mmx_value.try_into().unwrap());
        x86.x87.tag_word = 0xFFFF;
    }
    execute_lifted_x86(&[0x0F, 0x38, 0x08, 0x40, 0x01], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.mm[0], mmx_expected);
        assert_eq!(x86.x87.tag_word, 0);
    }

    ctx.write_vreg(rax, 0x3FC);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mm[0] = 0xDEAD_BEEF_CAFE_BABE;
        x86.x87.tag_word = 0xFFFF;
    }
    let mmx_fault = execute_lifted_x86(&[0x0F, 0x38, 0x08, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        mmx_fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.mm[0], 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(x86.x87.tag_word, 0xFFFF);
    }

    for (opcode, elem_bytes, value, control) in cases {
        let expected = reference(value, control, elem_bytes);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[0] = seeded(&value[..16], upper);
            x86.xmm[1] = seeded(&control[..16], 0);
        }
        execute_lifted_x86(&[0x66, 0x0F, 0x38, opcode, 0xC1], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(bytes(&x86.xmm[0], 16), expected[..16]);
            assert!(x86.xmm[0][2..].iter().all(|word| *word == upper));
        }

        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[0] = sentinel;
            x86.xmm[1] = seeded(value, 0);
            x86.xmm[2] = seeded(control, 0);
        }
        execute_lifted_x86(&[0xC4, 0xE2, 0x75, opcode, 0xC2], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(bytes(&x86.xmm[0], 32), expected);
            assert!(x86.xmm[0][4..].iter().all(|word| *word == 0));
        }
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
        x86.xmm[1] = seeded(&byte_values[..16], 0);
        x86.xmm[2] = seeded(&byte_controls[..16], 0);
    }
    execute_lifted_x86(&[0xC4, 0xE2, 0x71, 0x08, 0xC2], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[0], 16),
            reference(&byte_values[..16], &byte_controls[..16], 1)
        );
        assert!(x86.xmm[0][2..].iter().all(|word| *word == 0));
    }

    // Wrapping negation leaves each signed minimum unchanged.
    assert_eq!(
        reference(&dword_value_bytes, &dword_control_bytes, 4)[..4],
        i32::MIN.to_le_bytes()
    );

    // Legacy value/control alias: both roles must be captured before the
    // first result lane is merged into the architectural destination.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = seeded(&byte_values[..16], upper);
    }
    execute_lifted_x86(&[0x66, 0x0F, 0x38, 0x08, 0xC0], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[0], 16),
            reference(&byte_values[..16], &byte_values[..16], 1)
        );
    }

    // VEX destination aliases src1, then src2. Both inputs are reduced to
    // temporaries before the final architectural VAndNot write.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = seeded(&byte_values, 0);
        x86.xmm[2] = seeded(&byte_controls, 0);
    }
    execute_lifted_x86(&[0xC4, 0xE2, 0x7D, 0x08, 0xC2], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[0], 32),
            reference(&byte_values, &byte_controls, 1)
        );
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = seeded(&byte_controls, 0);
        x86.xmm[1] = seeded(&byte_values, 0);
    }
    execute_lifted_x86(&[0xC4, 0xE2, 0x75, 0x08, 0xC0], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[0], 32),
            reference(&byte_values, &byte_controls, 1)
        );
    }

    memory.write(0x101, &byte_controls).unwrap();
    ctx.write_vreg(rax, 0x101);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
    }
    let misaligned = execute_lifted_x86(&[0x66, 0x0F, 0x38, 0x08, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        misaligned,
        BlockResult::Exit(ExitReason::GeneralProtection { error_code: 0, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0], sentinel);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
        x86.xmm[1] = seeded(&byte_values, 0);
    }
    execute_lifted_x86(&[0xC4, 0xE2, 0x75, 0x08, 0x00], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[0], 32),
            reference(&byte_values, &byte_controls, 1)
        );
    }

    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags(), flags_before);

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
    }
    ctx.write_vreg(rax, 0x3F0);
    let fault = execute_lifted_x86(&[0xC4, 0xE2, 0x75, 0x08, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0], sentinel);
    }
}
#[test]
fn lifted_pavgb_pavgw_execute_rounded_unsigned_masks_alignment_and_faults() {
    fn packed_bytes(values: &[u8], fill: u64) -> VecValue {
        let mut out = [fill; 16];
        for (index, byte) in values.iter().copied().enumerate() {
            let shift = (index % 8) * 8;
            out[index / 8] = (out[index / 8] & !(0xFFu64 << shift)) | (u64::from(byte) << shift);
        }
        out
    }

    fn bytes(value: &VecValue, count: usize) -> Vec<u8> {
        value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(count)
            .collect()
    }

    fn packed_words(values: &[u16], fill: u64) -> VecValue {
        let raw = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        packed_bytes(&raw, fill)
    }

    fn words(value: &VecValue, count: usize) -> Vec<u16> {
        bytes(value, count * 2)
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    let a8 = (0..64)
        .map(|lane| (lane * 37 + 0x7F) as u8)
        .collect::<Vec<_>>();
    let b8 = (0..64)
        .map(|lane| 0xFFu8.wrapping_sub((lane * 29) as u8))
        .collect::<Vec<_>>();
    let a16 = (0..32)
        .map(|lane| 0x8001u16.wrapping_add((lane as u16).wrapping_mul(0x1111)))
        .collect::<Vec<_>>();
    let b16 = (0..32)
        .map(|lane| 0xFFF1u16.wrapping_sub((lane as u16).wrapping_mul(0x0101)))
        .collect::<Vec<_>>();
    let upper = 0xA5A5_A5A5_A5A5_A5A5;
    let flags_before = 0xCD7;
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x100);
    ctx.flags.materialized = MaterializedFlags::from_rflags(flags_before);
    ctx.flags.lazy = None;

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[2] = packed_bytes(&a8[..16], upper);
        x86.xmm[1] = packed_bytes(&b8[..16], 0);
    }
    execute_lifted_x86(&[0x66, 0x0F, 0xE0, 0xD1], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[2], 16),
            a8[..16]
                .iter()
                .zip(&b8[..16])
                .map(|(a, b)| ((u16::from(*a) + u16::from(*b) + 1) >> 1) as u8)
                .collect::<Vec<_>>(),
        );
        assert!(x86.xmm[2][2..].iter().all(|word| *word == upper));
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[4] = packed_words(&a16[..8], upper);
        x86.xmm[3] = packed_words(&b16[..8], 0);
    }
    execute_lifted_x86(&[0x66, 0x0F, 0xE3, 0xE3], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            words(&x86.xmm[4], 8),
            a16[..8]
                .iter()
                .zip(&b16[..8])
                .map(|(a, b)| ((u32::from(*a) + u32::from(*b) + 1) >> 1) as u16)
                .collect::<Vec<_>>(),
        );
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[8] = [upper; 16];
        x86.xmm[9] = packed_bytes(&a8[..32], 0);
        x86.xmm[10] = packed_bytes(&b8[..32], 0);
    }
    execute_lifted_x86(&[0xC4, 0x41, 0x35, 0xE0, 0xC2], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            bytes(&x86.xmm[8], 32),
            a8[..32]
                .iter()
                .zip(&b8[..32])
                .map(|(a, b)| ((u16::from(*a) + u16::from(*b) + 1) >> 1) as u8)
                .collect::<Vec<_>>(),
        );
        assert!(x86.xmm[8][4..].iter().all(|word| *word == 0));
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[16] = [upper; 16];
        x86.xmm[17] = packed_words(&a16, 0);
        x86.xmm[18] = packed_words(&b16, 0);
        x86.k[1] = 0xA5A5_5A5A;
    }
    execute_lifted_x86(&[0x62, 0xA1, 0x75, 0x41, 0xE3, 0xC2], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        let actual = words(&x86.xmm[16], 32);
        for lane in 0..32 {
            assert_eq!(
                actual[lane],
                if (0xA5A5_5A5Au64 >> lane) & 1 != 0 {
                    ((u32::from(a16[lane]) + u32::from(b16[lane]) + 1) >> 1) as u16
                } else {
                    0xA5A5
                },
            );
        }
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let k1 = VReg::Arch(ArchReg::X86(X86Reg::K(1)));
    memory.write(0xF0, &b8[..16]).unwrap();
    ctx.write_vreg(rax, 0xF0);
    ctx.write_vreg(k1, 0xFFFF);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = [0; 16];
        x86.xmm[1] = packed_bytes(&a8, 0);
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF1, 0x75, 0x49, 0xE0, 0x00], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    ctx.write_vreg(k1, 1 << 16);
    let sentinel = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
    }
    let fault = execute_lifted_x86(&[0x62, 0xF1, 0x75, 0x49, 0xE0, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0], sentinel);
    }
    ctx.write_vreg(rax, 0xF1);
    let misaligned = execute_lifted_x86(&[0x66, 0x0F, 0xE3, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        misaligned,
        BlockResult::Exit(ExitReason::GeneralProtection { error_code: 0, .. })
    ));
    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags(), flags_before);
}
#[test]
fn lifted_dot_products_execute_masks_rounding_mxcsr_atomicity_and_faults() {
    fn vector_f32(values: &[u32], fill: u64) -> VecValue {
        let mut bytes = Vec::with_capacity(values.len() * 4);
        for value in values {
            bytes.extend(value.to_le_bytes());
        }
        let mut out = [fill; 16];
        for (word, chunk) in bytes.chunks_exact(8).enumerate() {
            out[word] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        out
    }
    fn vector_f64(values: &[u64], fill: u64) -> VecValue {
        let mut out = [fill; 16];
        for (lane, value) in values.iter().copied().enumerate() {
            out[lane] = value;
        }
        out
    }
    fn f32_lanes(value: &VecValue, count: usize) -> Vec<u32> {
        value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(count * 4)
            .collect::<Vec<_>>()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }
    let sentinel = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    let upper = 0xA5A5_A5A5_A5A5_A5A5;
    let flags_before = 0xCD7;
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x400);
    ctx.flags.materialized = MaterializedFlags::from_rflags(flags_before);
    ctx.flags.lazy = None;

    // DPPS performs the documented pairwise tree and broadcasts only to
    // low-mask-selected lanes. Legacy state above bit 127 is preserved.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = vector_f32(
            &[
                1.0f32.to_bits(),
                2.0f32.to_bits(),
                3.0f32.to_bits(),
                4.0f32.to_bits(),
            ],
            upper,
        );
        x86.xmm[10] = vector_f32(
            &[
                10.0f32.to_bits(),
                20.0f32.to_bits(),
                30.0f32.to_bits(),
                40.0f32.to_bits(),
            ],
            0,
        );
    }
    execute_lifted_x86(
        &[0x66, 0x45, 0x0F, 0x3A, 0x40, 0xCA, 0xF1],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(f32_lanes(&x86.xmm[9], 4), vec![300.0f32.to_bits(), 0, 0, 0]);
        assert!(x86.xmm[9][2..].iter().all(|word| *word == upper));
    }

    // DPPD uses imm[5:4] for input selection and imm[1:0] for output.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = vector_f64(&[1.5f64.to_bits(), 2.0f64.to_bits()], upper);
        x86.xmm[10] = vector_f64(&[2.0f64.to_bits(), 3.0f64.to_bits()], 0);
    }
    execute_lifted_x86(
        &[0x66, 0x45, 0x0F, 0x3A, 0x41, 0xCA, 0x33],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(&x86.xmm[9][..2], &[9.0f64.to_bits(), 9.0f64.to_bits()]);
        assert!(x86.xmm[9][2..].iter().all(|word| *word == upper));
    }

    // VDPPS.256 repeats the same primitive independently in each 128-bit
    // half and clears all state above bit 255.
    let first = [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0].map(f32::to_bits);
    let second = [2.0f32, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0].map(f32::to_bits);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
        x86.xmm[10] = vector_f32(&second, 0);
        x86.xmm[11] = vector_f32(&first, 0);
    }
    execute_lifted_x86(&[0xC4, 0x43, 0x25, 0x40, 0xCA, 0xFF], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            f32_lanes(&x86.xmm[9], 8),
            [40.0f32; 4]
                .into_iter()
                .chain([200.0f32; 4])
                .map(f32::to_bits)
                .collect::<Vec<_>>()
        );
        assert!(x86.xmm[9][4..].iter().all(|word| *word == 0));
    }

    // Each multiply is rounded before horizontal addition. This product is
    // just above an exact representable value: RN selects +2 ULP, RU +3 ULP.
    for (rc, expected) in [(0u32, 0x3F80_0002u32), (2, 0x3F80_0003)] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.mxcsr = (0x1F80 & !(3 << 13)) | (rc << 13);
            x86.xmm[9] = sentinel;
            x86.xmm[10] = vector_f32(&[0x3F80_0001, 0, 0, 0], 0);
            x86.xmm[11] = vector_f32(&[0x3F80_0001, 0, 0, 0], 0);
        }
        execute_lifted_x86(&[0xC4, 0x43, 0x21, 0x40, 0xCA, 0x11], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(f32_lanes(&x86.xmm[9], 1), vec![expected]);
            assert_ne!(x86.mxcsr & (1 << 5), 0, "inexact multiplication");
            assert!(x86.xmm[9][2..].iter().all(|word| *word == 0));
        }
    }

    // Input selection occurs before arithmetic and suppresses SNaN and
    // denormal-input exceptions for deselected lanes.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mxcsr = 0x1F80;
        x86.xmm[9] = vector_f32(&[0x7F80_0001, 1, 0, 0], upper);
        x86.xmm[10] = vector_f32(&[1.0f32.to_bits(), 1.0f32.to_bits(), 0, 0], 0);
    }
    execute_lifted_x86(
        &[0x66, 0x45, 0x0F, 0x3A, 0x40, 0xCA, 0x0F],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(f32_lanes(&x86.xmm[9], 4), vec![0; 4]);
        assert_eq!(x86.mxcsr & 0x3F, 0);
    }

    // With invalid masked, a selected SNaN is quieted with its payload and
    // sign preserved. A zero output mask does not suppress computation.
    for (imm, expected) in [(0x11u8, 0x7FC0_0123u32), (0x10, 0)] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.mxcsr = 0x1F80;
            x86.xmm[9] = sentinel;
            x86.xmm[10] = vector_f32(&[1.0f32.to_bits(), 0, 0, 0], 0);
            x86.xmm[11] = vector_f32(&[0x7F80_0123, 0, 0, 0], 0);
        }
        execute_lifted_x86(&[0xC4, 0x43, 0x21, 0x40, 0xCA, imm], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(f32_lanes(&x86.xmm[9], 1), vec![expected]);
            assert_ne!(x86.mxcsr & 1, 0);
        }
    }

    // DAZ converts selected denormals to signed zero without DE. Without
    // DAZ, exact denormal operands/results survive and DE becomes sticky.
    for (daz, expected, expect_de) in [(false, 1u32, true), (true, 0x0000_0000u32, false)] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.mxcsr = 0x1F80 | if daz { 1 << 6 } else { 0 };
            x86.xmm[9] = sentinel;
            x86.xmm[10] = vector_f32(&[1.0f32.to_bits(), 0, 0, 0], 0);
            x86.xmm[11] = vector_f32(&[1, 0, 0, 0], 0);
        }
        execute_lifted_x86(&[0xC4, 0x43, 0x21, 0x40, 0xCA, 0x11], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(f32_lanes(&x86.xmm[9], 1), vec![expected]);
            assert_eq!(x86.mxcsr & (1 << 1) != 0, expect_de);
        }
    }

    // An exact tiny product is retained with masked underflow and FTZ=0;
    // FTZ flushes it and sets UE+PE even though the pre-flush result is exact.
    for (ftz, expected, expected_status) in [
        (false, 0x0040_0000u32, 0u32),
        (true, 0u32, (1 << 4) | (1 << 5)),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.mxcsr = 0x1F80 | if ftz { 1 << 15 } else { 0 };
            x86.xmm[9] = sentinel;
            x86.xmm[10] = vector_f32(&[0.5f32.to_bits(), 0, 0, 0], 0);
            x86.xmm[11] = vector_f32(&[0x0080_0000, 0, 0, 0], 0);
        }
        execute_lifted_x86(&[0xC4, 0x43, 0x21, 0x40, 0xCA, 0x11], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(f32_lanes(&x86.xmm[9], 1), vec![expected]);
            assert_eq!(x86.mxcsr & ((1 << 4) | (1 << 5)), expected_status);
        }
    }

    // Selected SNaN, overflow, and exact tiny results all trap before any
    // architectural write when their corresponding exception is unmasked.
    for (mxcsr, first_lane, second_lane, expected_status) in [
        (0x1F80 & !(1 << 7), 0x7F80_0001, 1.0f32.to_bits(), 1),
        (0x1F80 & !(1 << 10), 0x7F7F_FFFF, 2.0f32.to_bits(), 1 << 3),
        (0x1F80 & !(1 << 11), 0x0080_0000, 0.5f32.to_bits(), 1 << 4),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.mxcsr = mxcsr;
            x86.xmm[9] = sentinel;
            x86.xmm[10] = vector_f32(&[second_lane, 0, 0, 0], 0);
            x86.xmm[11] = vector_f32(&[first_lane, 0, 0, 0], 0);
        }
        let exit = execute_lifted_x86(&[0xC4, 0x43, 0x21, 0x40, 0xCA, 0x11], &mut ctx, &mut memory);
        assert!(matches!(
            exit,
            BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
        ));
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.xmm[9], sentinel);
            assert_ne!(x86.mxcsr & expected_status, 0);
        }
    }

    // VEX memory is unaligned-capable. Legacy alignment and VEX load faults
    // occur before dot-product status or destination writes.
    let memory_operand = [2.0f32, 3.0, 4.0, 5.0]
        .into_iter()
        .flat_map(|value| value.to_bits().to_le_bytes())
        .collect::<Vec<_>>();
    memory.write(0x101, &memory_operand).unwrap();
    ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mxcsr = 0x1F80;
        x86.xmm[9] = sentinel;
        x86.xmm[11] = vector_f32(&first[..4], 0);
    }
    execute_lifted_x86(
        &[0xC4, 0x63, 0x21, 0x40, 0x48, 0x01, 0xF1],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(f32_lanes(&x86.xmm[9], 1), vec![40.0f32.to_bits()]);
    }

    ctx.write_vreg(rax, 0x101);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
    }
    let misaligned = execute_lifted_x86(
        &[0x66, 0x44, 0x0F, 0x3A, 0x40, 0x08, 0xF1],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        misaligned,
        BlockResult::Exit(ExitReason::GeneralProtection { error_code: 0, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[9], sentinel);
    }

    ctx.write_vreg(rax, 0x3F8);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
        x86.mxcsr = 0x1F80;
    }
    let fault = execute_lifted_x86(&[0xC4, 0x63, 0x21, 0x40, 0x08, 0xF1], &mut ctx, &mut memory);
    assert!(matches!(
        fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[9], sentinel);
        assert_eq!(x86.mxcsr & 0x3F, 0);
    }
    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags(), flags_before);
}
#[test]
fn lifted_fp_compare_family_executes_all_predicates_masks_mxcsr_sae_and_faults() {
    fn vector_f32(values: &[u32], fill: u64) -> VecValue {
        let mut bytes = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        let mut out = [fill; 16];
        for (word, chunk) in bytes.chunks_exact(8).enumerate() {
            out[word] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        out
    }
    fn f32_lanes(value: &VecValue, count: usize) -> Vec<u32> {
        value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(count * 4)
            .collect::<Vec<_>>()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }
    fn vector_f16(values: &[u16], fill: u64) -> VecValue {
        let mut bytes = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        let mut out = [fill; 16];
        for (word, chunk) in bytes.chunks_exact(8).enumerate() {
            out[word] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        out
    }

    const TRUTH_TABLES: [u8; 16] = [
        0b0100, 0b0010, 0b0110, 0b1000, 0b1011, 0b1101, 0b1001, 0b0111, 0b1100, 0b1010, 0b1110,
        0b0000, 0b0011, 0b0101, 0b0001, 0b1111,
    ];
    const SIGNALING: [u8; 16] = [1, 2, 5, 6, 9, 10, 13, 14, 16, 19, 20, 23, 24, 27, 28, 31];
    let sentinel = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    let flags_before = 0xCD7;
    let qnan = 0x7FC0_1234u32;
    let snan = 0x7F80_1234u32;
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x200);
    ctx.flags.materialized = MaterializedFlags::from_rflags(flags_before);
    ctx.flags.lazy = None;

    // Lanes encode the four mutually exclusive relations in table order:
    // greater, less, equal, unordered. Both AVX predicate halves share the
    // same truth table; they differ only in QNaN signaling policy.
    for predicate in 0u8..32 {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[1] = sentinel;
            x86.xmm[2] = vector_f32(
                &[2.0f32.to_bits(), 1.0f32.to_bits(), 1.0f32.to_bits(), qnan],
                0,
            );
            x86.xmm[3] = vector_f32(
                &[
                    1.0f32.to_bits(),
                    2.0f32.to_bits(),
                    1.0f32.to_bits(),
                    0.0f32.to_bits(),
                ],
                0,
            );
            x86.mxcsr = 0x1F80;
        }
        execute_lifted_x86(&[0xC5, 0xE8, 0xC2, 0xCB, predicate], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            let table = TRUTH_TABLES[usize::from(predicate & 15)];
            let expected = (0..4)
                .map(|relation| {
                    if table & (1 << relation) != 0 {
                        u32::MAX
                    } else {
                        0
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(f32_lanes(&x86.xmm[1], 4), expected, "predicate {predicate}");
            assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
            assert_eq!(
                x86.mxcsr & 1 != 0,
                SIGNALING.contains(&predicate),
                "predicate {predicate} QNaN invalid status"
            );
        }
    }

    // FP16 comparisons share the complete 32-predicate truth table and
    // additionally cover DAZ-independent denormal, NaN, opmask, and
    // destination-width rules. Lanes encode greater, less, equal, unordered,
    // denormal, signed-zero equality, infinity equality, and SNaN.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[2] = vector_f16(
            &[
                0x4000, 0x3C00, 0x3C00, 0x7E00, 0x0001, 0x8000, 0x7C00, 0x7D00,
            ],
            0,
        );
        x86.xmm[0] = vector_f16(&[0x3C00, 0x4000, 0x3C00, 0, 0, 0, 0x7C00, 0], 0);
        x86.k[2] = 0xFF;
        x86.k[3] = u64::MAX;
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0x6C, 0x0A, 0xC2, 0xD8, 0],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 0x64);
        assert_eq!(x86.mxcsr & 3, 3);
    }

    for daz in [false, true] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[2] = vector_f16(&[1], 0);
            x86.xmm[0] = vector_f16(&[0], 0);
            x86.k[2] = 1;
            x86.k[3] = u64::MAX;
            x86.mxcsr = 0x1F80 | if daz { 1 << 6 } else { 0 };
        }
        execute_lifted_x86(
            &[0x62, 0xF3, 0x6C, 0x0A, 0xC2, 0xD8, 0],
            &mut ctx,
            &mut memory,
        );
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.k[3], 0, "FP16 DAZ changed comparison result");
            assert_ne!(x86.mxcsr & (1 << 1), 0, "FP16 DAZ suppressed DE");
        }
    }

    // Packed FP16 broadcast compares the same m16 value against every
    // active source lane and zeros all inactive destination mask bits.
    memory.write(0x100, &0x3C00u16.to_le_bytes()).unwrap();
    ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[2] = vector_f16(
            &[
                0x3C00, 0x4000, 0x3C00, 0x4000, 0x3C00, 0x4000, 0x3C00, 0x4000,
            ],
            0,
        );
        x86.k[2] = 0x55;
        x86.k[3] = u64::MAX;
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0x6C, 0x1A, 0xC2, 0x18, 0],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 0x55);
        assert_eq!(x86.mxcsr & 0x3F, 0);
    }

    // Scalar FP16 SAE suppresses a signaling-predicate QNaN exception.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[2] = vector_f16(&[0x7E00], 0);
        x86.xmm[0] = vector_f16(&[0], 0);
        x86.k[2] = 1;
        x86.k[3] = u64::MAX;
        x86.mxcsr = 0x1F80 & !(1 << 7);
    }
    let fp16_sae = execute_lifted_x86(
        &[0x62, 0xF3, 0x6E, 0x1A, 0xC2, 0xD8, 5],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(fp16_sae, BlockResult::Exit(ExitReason::Halt)));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 1);
        assert_eq!(x86.mxcsr & 0x3F, 0);
    }

    // An inactive scalar opmask suppresses the m16 load; an active mask
    // exposes the fault without committing the destination opmask.
    ctx.write_vreg(rax, 0x300);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.k[2] = 0;
        x86.k[3] = u64::MAX;
    }
    let fp16_suppressed_fault = execute_lifted_x86(
        &[0x62, 0xF3, 0x6E, 0x0A, 0xC2, 0x18, 1],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        fp16_suppressed_fault,
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 0);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.k[2] = 1;
        x86.k[3] = 0xAA;
    }
    let fp16_fault = execute_lifted_x86(
        &[0x62, 0xF3, 0x6E, 0x0A, 0xC2, 0x18, 1],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        fp16_fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 0xAA);
    }

    // Legacy scalar preserves every bit above its result lane. VEX scalar
    // copies lanes 1..3 from vvvv and clears all state above bit 127.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = vector_f32(
            &[
                1.0f32.to_bits(),
                11.0f32.to_bits(),
                12.0f32.to_bits(),
                13.0f32.to_bits(),
            ],
            sentinel[0],
        );
        x86.xmm[3] = vector_f32(&[1.0f32.to_bits(); 4], 0);
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(&[0xF3, 0x0F, 0xC2, 0xCB, 0], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            f32_lanes(&x86.xmm[1], 4),
            [
                u32::MAX,
                11.0f32.to_bits(),
                12.0f32.to_bits(),
                13.0f32.to_bits()
            ]
        );
        assert!(x86.xmm[1][2..].iter().all(|word| *word == sentinel[0]));
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.xmm[2] = vector_f32(
            &[
                1.0f32.to_bits(),
                21.0f32.to_bits(),
                22.0f32.to_bits(),
                23.0f32.to_bits(),
            ],
            sentinel[0],
        );
        x86.xmm[3] = vector_f32(&[2.0f32.to_bits(); 4], 0);
    }
    execute_lifted_x86(&[0xC5, 0xEA, 0xC2, 0xCB, 4], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            f32_lanes(&x86.xmm[1], 4),
            [
                u32::MAX,
                21.0f32.to_bits(),
                22.0f32.to_bits(),
                23.0f32.to_bits()
            ]
        );
        assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
    }

    // DAZ converts a denormal operand to signed zero without DE; without
    // DAZ the denormal remains unequal to zero and records DE.
    for (daz, expected, denormal_status) in [(false, 0u32, true), (true, u32::MAX, false)] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[2] = vector_f32(&[1, 0, 0, 0], 0);
            x86.xmm[3] = vector_f32(&[0; 4], 0);
            x86.mxcsr = 0x1F80 | if daz { 1 << 6 } else { 0 };
        }
        execute_lifted_x86(&[0xC5, 0xE8, 0xC2, 0xCB, 0], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(f32_lanes(&x86.xmm[1], 1), [expected]);
            assert_eq!(x86.mxcsr & (1 << 1) != 0, denormal_status);
        }
    }

    // Every predicate invalidates SNaN. An unmasked invalid exception sets
    // MXCSR.IE but leaves the architectural destination fully unchanged.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.xmm[2] = vector_f32(&[snan, 0, 0, 0], 0);
        x86.xmm[3] = vector_f32(&[0; 4], 0);
        x86.mxcsr = 0x1F80 & !(1 << 7);
    }
    let invalid = execute_lifted_x86(&[0xC5, 0xE8, 0xC2, 0xCB, 0], &mut ctx, &mut memory);
    assert!(matches!(
        invalid,
        BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], sentinel);
        assert_ne!(x86.mxcsr & 1, 0);
    }

    // Scalar EVEX SAE suppresses MXCSR status and traps while retaining the
    // signaling predicate's unordered truth value in the destination bit.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[18] = vector_f32(&[qnan, 0, 0, 0], 0);
        x86.xmm[19] = vector_f32(&[0; 4], 0);
        x86.k[2] = 1;
        x86.k[3] = u64::MAX;
        x86.mxcsr = 0x1F80 & !(1 << 7);
    }
    let sae = execute_lifted_x86(
        &[0x62, 0xB1, 0x6E, 0x12, 0xC2, 0xDB, 0x05],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(sae, BlockResult::Exit(ExitReason::Halt)));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 1);
        assert_eq!(x86.mxcsr & 0x3F, 0);
    }

    // EVEX broadcast compares one memory scalar against all active lanes;
    // the write mask both zeroes inactive results and suppresses their
    // memory accesses and floating-point exceptions.
    memory.write(0x100, &qnan.to_le_bytes()).unwrap();
    ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[2] = vector_f32(&[0; 16], 0);
        x86.k[2] = 0x5555;
        x86.k[3] = u64::MAX;
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(
        &[0x62, 0xF1, 0x6C, 0x5A, 0xC2, 0x18, 0x03],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 0x5555);
        assert_eq!(x86.mxcsr & 1, 0);
    }

    ctx.write_vreg(rax, 0x300);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.k[2] = 0;
        x86.k[3] = u64::MAX;
        x86.mxcsr = 0x1F80;
    }
    let suppressed_fault = execute_lifted_x86(
        &[0x62, 0xF1, 0x6E, 0x0A, 0xC2, 0x18, 0x01],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        suppressed_fault,
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 0);
        assert_eq!(x86.mxcsr, 0x1F80);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.k[2] = 1;
        x86.k[3] = 0xAA;
    }
    let fault = execute_lifted_x86(
        &[0x62, 0xF1, 0x6E, 0x0A, 0xC2, 0x18, 0x01],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.k[3], 0xAA);
    }

    // Legacy packed operands use Type 2 alignment rules.
    ctx.write_vreg(rax, 0x101);
    let misaligned = execute_lifted_x86(&[0x0F, 0xC2, 0x08, 0], &mut ctx, &mut memory);
    assert!(matches!(
        misaligned,
        BlockResult::Exit(ExitReason::GeneralProtection { error_code: 0, .. })
    ));
    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags(), flags_before);
}
#[test]
fn lifted_round_family_executes_mxcsr_daz_exceptions_merges_and_faults() {
    fn vector_f32(values: &[u32], fill: u64) -> VecValue {
        let mut bytes = Vec::with_capacity(values.len() * 4);
        for value in values {
            bytes.extend(value.to_le_bytes());
        }
        let mut out = [fill; 16];
        for (word, chunk) in bytes.chunks_exact(8).enumerate() {
            out[word] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        out
    }
    fn f32_lanes(value: &VecValue, count: usize) -> Vec<u32> {
        value
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(count * 4)
            .collect::<Vec<_>>()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }
    fn vector_f64(values: &[u64], fill: u64) -> VecValue {
        let mut out = [fill; 16];
        out[..values.len()].copy_from_slice(values);
        out
    }
    fn f64_lanes(value: &VecValue, count: usize) -> Vec<u64> {
        value[..count].to_vec()
    }

    let upper = 0xA5A5_A5A5_A5A5_A5A5;
    let sentinel = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    let flags_before = 0xCD7;
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x400);
    ctx.flags.materialized = MaterializedFlags::from_rflags(flags_before);
    ctx.flags.lazy = None;

    let inputs = [2.5f32, -2.5, 2.1, -2.1].map(f32::to_bits);
    for (mode, expected) in [
        (0u8, [2.0f32, -2.0, 2.0, -2.0]),
        (1, [2.0f32, -3.0, 2.0, -3.0]),
        (2, [3.0f32, -2.0, 3.0, -2.0]),
        (3, [2.0f32, -2.0, 2.0, -2.0]),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[9] = [upper; 16];
            x86.xmm[10] = vector_f32(&inputs, 0);
            x86.mxcsr = 0x1F80;
        }
        execute_lifted_x86(
            &[0x66, 0x45, 0x0F, 0x3A, 0x08, 0xCA, mode],
            &mut ctx,
            &mut memory,
        );
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(
                f32_lanes(&x86.xmm[9], 4),
                expected.map(f32::to_bits),
                "mode {mode}"
            );
            assert!(x86.xmm[9][2..].iter().all(|word| *word == upper));
            assert_ne!(x86.mxcsr & (1 << 5), 0, "mode {mode}: precision");
        }
    }

    // VEX.256 rounds all eight lanes and clears state above bit 255.
    let packed256 = [2.9f32, -2.1, 3.0, -3.0, 4.7, -4.2, 0.5, -0.5];
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
        x86.xmm[10] = vector_f32(&packed256.map(f32::to_bits), upper);
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(&[0xC4, 0x43, 0x7D, 0x08, 0xCA, 0x01], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            f32_lanes(&x86.xmm[9], 8),
            packed256.map(|value| value.floor().to_bits())
        );
        assert!(x86.xmm[9][4..].iter().all(|word| *word == 0));
    }

    // Double-precision packed and scalar forms use the same control fields.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = [upper; 16];
        x86.xmm[10] = vector_f64(&[2.1f64.to_bits(), (-2.9f64).to_bits()], 0);
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(
        &[0x66, 0x45, 0x0F, 0x3A, 0x09, 0xCA, 0x02],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            f64_lanes(&x86.xmm[9], 2),
            [3.0f64.to_bits(), (-2.0f64).to_bits()]
        );
        assert!(x86.xmm[9][2..].iter().all(|word| *word == upper));
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
        x86.xmm[10] = vector_f64(&[(-2.9f64).to_bits(), 99.0f64.to_bits()], 0);
        x86.xmm[11] = vector_f64(&[88.0f64.to_bits(), 17.0f64.to_bits()], upper);
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(&[0xC4, 0x43, 0x21, 0x0B, 0xCA, 0x03], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            f64_lanes(&x86.xmm[9], 2),
            [(-2.0f64).to_bits(), 17.0f64.to_bits()]
        );
        assert!(x86.xmm[9][2..].iter().all(|word| *word == 0));
    }

    // VEX scalar form obtains untouched lanes from vvvv and clears all
    // state above bit 127; its rounding mode is selected dynamically.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
        x86.xmm[10] = vector_f32(&[2.1f32.to_bits(); 4], 0);
        x86.xmm[11] = vector_f32(
            &[
                99.0f32.to_bits(),
                11.0f32.to_bits(),
                12.0f32.to_bits(),
                13.0f32.to_bits(),
            ],
            upper,
        );
        x86.mxcsr = (0x1F80 & !(3 << 13)) | (2 << 13);
    }
    execute_lifted_x86(&[0xC4, 0x43, 0x21, 0x0A, 0xCA, 0x04], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            f32_lanes(&x86.xmm[9], 4),
            [3.0f32, 11.0, 12.0, 13.0].map(f32::to_bits)
        );
        assert!(x86.xmm[9][2..].iter().all(|word| *word == 0));
    }

    // DAZ changes a positive subnormal rounded toward +infinity from 1.0
    // to +0.0, and the DAZ conversion itself does not signal precision.
    for (daz, expected, precision) in [
        (false, 1.0f32.to_bits(), true),
        (true, 0.0f32.to_bits(), false),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[9] = sentinel;
            x86.xmm[10] = vector_f32(&[1, 0, 0, 0], 0);
            x86.mxcsr = 0x1F80 | if daz { 1 << 6 } else { 0 };
        }
        execute_lifted_x86(
            &[0x66, 0x45, 0x0F, 0x3A, 0x0A, 0xCA, 0x02],
            &mut ctx,
            &mut memory,
        );
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(f32_lanes(&x86.xmm[9], 1), [expected]);
            assert_eq!(x86.mxcsr & (1 << 5) != 0, precision);
        }
    }

    // Masked invalid quiets SNaN while preserving its sign/payload. Bit 3
    // suppresses precision only; invalid status is still recorded.
    let snan = 0x7F80_1234u32;
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
        x86.xmm[10] = vector_f32(&[snan, 0, 0, 0], 0);
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(
        &[0x66, 0x45, 0x0F, 0x3A, 0x0A, 0xCA, 0x08],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(f32_lanes(&x86.xmm[9], 1), [snan | 0x0040_0000]);
        assert_ne!(x86.mxcsr & 1, 0);
        assert_eq!(x86.mxcsr & (1 << 5), 0);
    }

    // Unmasked precision and invalid exceptions update MXCSR status but
    // fault before any architectural vector write.
    for (input, imm, mask_bit, status_bit) in
        [(1.5f32.to_bits(), 0x00, 12u32, 5u32), (snan, 0x08, 7, 0)]
    {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[9] = sentinel;
            x86.xmm[10] = vector_f32(&[input, 0, 0, 0], 0);
            x86.mxcsr = 0x1F80 & !(1 << mask_bit);
        }
        let exit = execute_lifted_x86(
            &[0x66, 0x45, 0x0F, 0x3A, 0x0A, 0xCA, imm],
            &mut ctx,
            &mut memory,
        );
        assert!(matches!(
            exit,
            BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
        ));
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.xmm[9], sentinel);
            assert_ne!(x86.mxcsr & (1 << status_bit), 0);
        }
    }

    // Legacy packed memory requires 16-byte alignment; VEX packed memory
    // is unaligned-capable but still faults atomically on a short operand.
    ctx.write_vreg(rax, 0x101);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
        x86.mxcsr = 0x1F80;
    }
    let misaligned = execute_lifted_x86(
        &[0x66, 0x44, 0x0F, 0x3A, 0x08, 0x08, 0x08],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        misaligned,
        BlockResult::Exit(ExitReason::GeneralProtection { error_code: 0, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[9], sentinel);
    }

    ctx.write_vreg(rax, 0x3F0);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[9] = sentinel;
        x86.mxcsr = 0x1F80;
    }
    let fault = execute_lifted_x86(&[0xC4, 0x63, 0x7D, 0x09, 0x08, 0x08], &mut ctx, &mut memory);
    assert!(matches!(
        fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[9], sentinel);
    }
    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags(), flags_before);
}
#[test]
fn x86_exp2_semantics_cover_error_bound_exact_specials_denormals_and_overflow() {
    let one32 = u64::from(1.0f32.to_bits());
    let one64 = 1.0f64.to_bits();
    for (bits, format, expected) in [
        (0u64, X86_SIMD_F32, one32),
        (0x8000_0000, X86_SIMD_F32, one32),
        (1, X86_SIMD_F32, one32),
        (0x8000_0001, X86_SIMD_F32, one32),
        (0, X86_SIMD_F64, one64),
        (0x8000_0000_0000_0000, X86_SIMD_F64, one64),
        (1, X86_SIMD_F64, one64),
        (0x8000_0000_0000_0001, X86_SIMD_F64, one64),
    ] {
        assert_eq!(
            SmirInterpreter::x86_simd_exp2(bits, format),
            X86SimdFpResult {
                bits: expected,
                status: 0
            }
        );
    }

    for (input, expected) in [
        (-126.0f32, 0x0080_0000u64),
        (-1.0, u64::from(0.5f32.to_bits())),
        (0.0, one32),
        (1.0, u64::from(2.0f32.to_bits())),
        (127.0, 0x7F00_0000),
    ] {
        let result = SmirInterpreter::x86_simd_exp2(u64::from(input.to_bits()), X86_SIMD_F32);
        assert_eq!(result.bits, expected, "FP32 integral {input}");
        assert_eq!(result.status, 0);
    }
    assert_eq!(
        SmirInterpreter::x86_simd_exp2(u64::from((-127.0f32).to_bits()), X86_SIMD_F32,),
        X86SimdFpResult { bits: 0, status: 0 },
        "exact subnormal result is architecturally flushed",
    );
    assert_eq!(
        SmirInterpreter::x86_simd_exp2(u64::from(128.0f32.to_bits()), X86_SIMD_F32,),
        X86SimdFpResult {
            bits: 0x7F80_0000,
            status: 1 << 3,
        }
    );

    for input in [-100.25f32, -1.5, -0.125, 0.1, 17.75, 127.25] {
        let result = SmirInterpreter::x86_simd_exp2(u64::from(input.to_bits()), X86_SIMD_F32);
        if result.status == 0 && result.bits != 0 {
            let actual = f64::from(f32::from_bits(result.bits as u32));
            let reference = f64::from(input).exp2();
            let relative_error = ((actual - reference) / reference).abs();
            assert!(
                relative_error < 2.0f64.powi(-23),
                "FP32 {input}: relative error {relative_error:e}"
            );
        }
    }
    for input in [-1000.25f64, -1.5, -0.125, 0.1, 17.75, 1000.25] {
        let result = SmirInterpreter::x86_simd_exp2(input.to_bits(), X86_SIMD_F64);
        if result.status == 0 && result.bits != 0 {
            let actual = f64::from_bits(result.bits);
            let reference = input.exp2();
            let relative_error = ((actual - reference) / reference).abs();
            assert!(
                relative_error < 2.0f64.powi(-23),
                "FP64 {input}: relative error {relative_error:e}"
            );
        }
    }

    for (input, expected) in [
        (f32::INFINITY.to_bits(), 0x7F80_0000u64),
        (f32::NEG_INFINITY.to_bits(), 0),
    ] {
        assert_eq!(
            SmirInterpreter::x86_simd_exp2(u64::from(input), X86_SIMD_F32),
            X86SimdFpResult {
                bits: expected,
                status: 0,
            }
        );
    }
    let qnan = SmirInterpreter::x86_simd_exp2(0xFFC1_2345, X86_SIMD_F32);
    assert_eq!(qnan.bits, 0xFFC1_2345);
    assert_eq!(qnan.status, 0);
    let snan = SmirInterpreter::x86_simd_exp2(0xFF81_2345, X86_SIMD_F32);
    assert_eq!(snan.bits, 0xFFC1_2345);
    assert_eq!(snan.status, 1);
}
#[test]
fn x86_exp2_matches_intel_reference_polynomial_and_segment_error_bound() {
    for (input, expected) in [
        (-100.25f32, 0x0D57_44FDu64),
        (-1.5, 0x3EB5_04F3),
        (-0.125, 0x3F6A_C0C7),
        (0.1, 0x3F89_2FDF),
        (17.75, 0x4857_44FD),
        (127.25, 0x7F18_37F0),
    ] {
        assert_eq!(
            SmirInterpreter::x86_simd_exp2(u64::from(input.to_bits()), X86_SIMD_F32),
            X86SimdFpResult {
                bits: expected,
                status: 0,
            },
            "Intel EXP2S reference vector {input}",
        );
    }
    for (input, expected) in [
        (-1000.25f64, 0x016A_E89F_A000_0000u64),
        (-1.5, 0x3FD6_A09E_6000_0000),
        (-0.125, 0x3FED_5818_E000_0000),
        (0.1, 0x3FF1_25FB_E000_0000),
        (17.75, 0x410A_E89F_A000_0000),
        (1000.25, 0x7E73_06FE_0000_0000),
    ] {
        assert_eq!(
            SmirInterpreter::x86_simd_exp2(input.to_bits(), X86_SIMD_F64),
            X86SimdFpResult {
                bits: expected,
                status: 0,
            },
            "Intel EXP2D reference vector {input}",
        );
    }

    // Exercise both sides and the interior of every one of the 64 table
    // segments at representative output scales, including the finite
    // boundaries. The exact ISA requirement is relative error < 2^-23.
    let limit = 2.0f64.powi(-23);
    for scale in [-126, -100, -1, 0, 17, 126] {
        for segment in 0..64 {
            for offset in [1, 0x1F_FFFF, 0x20_0000, 0x3F_FFFF] {
                let fraction = ((segment << 22) + offset) as f64 / 268_435_456.0;
                let input = scale as f64 + fraction;
                let input32 = input as f32;
                let result =
                    SmirInterpreter::x86_simd_exp2(u64::from(input32.to_bits()), X86_SIMD_F32);
                let actual = f64::from(f32::from_bits(result.bits as u32));
                let reference = f64::from(input32).exp2();
                let relative_error = ((actual - reference) / reference).abs();
                assert!(
                    relative_error < limit,
                    "EXP2S {input32}: relative error {relative_error:e}",
                );
            }
        }
    }
    for scale in [-1022, -1000, -1, 0, 17, 1000, 1022] {
        for segment in 0..64 {
            for offset in [1, 0x1F_FFFF, 0x20_0000, 0x3F_FFFF] {
                let fraction = ((segment << 22) + offset) as f64 / 268_435_456.0;
                let input = scale as f64 + fraction;
                let result = SmirInterpreter::x86_simd_exp2(input.to_bits(), X86_SIMD_F64);
                let actual = f64::from_bits(result.bits);
                let reference = input.exp2();
                let relative_error = ((actual - reference) / reference).abs();
                assert!(
                    relative_error < limit,
                    "EXP2D {input}: relative error {relative_error:e}",
                );
            }
        }
    }
}
#[test]
fn x86_recip14_matches_intel_reference_all_segments_mxcsr_and_special_values() {
    // FNV-1a accumulation over outputs generated by Intel's RECIP14.c
    // RCP14S/RCP14D implementation. The corpus covers every polynomial
    // segment, both signs, four exponent scales, and four segment offsets.
    const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
    let mut hash32 = FNV_OFFSET;
    let mut count32 = 0usize;
    for sign in [0u32, 1] {
        for exponent in [1u32, 127, 253, 254] {
            for segment in 0u32..64 {
                for tail in [0u32, 1, 0xFFFF, 0x1_FFFF] {
                    let bits = (sign << 31) | (exponent << 23) | (segment << 17) | tail;
                    let result =
                        SmirInterpreter::x86_simd_recip14(u64::from(bits), X86_SIMD_F32, 0);
                    hash32 = (hash32 ^ result.bits).wrapping_mul(FNV_PRIME);
                    assert_eq!(result.status, 0);
                    count32 += 1;
                }
            }
        }
    }
    assert_eq!(count32, 2_048);
    assert_eq!(hash32, 0x3458_3FF8_E41E_DD25);

    let mut hash64 = FNV_OFFSET;
    let mut count64 = 0usize;
    for sign in [0u64, 1] {
        for exponent in [1u64, 1023, 2045, 2046] {
            for segment in 0u64..64 {
                for tail in [0u64, 1, (1 << 45) - 1, (1 << 46) - 1] {
                    let bits = (sign << 63) | (exponent << 52) | (segment << 46) | tail;
                    let result = SmirInterpreter::x86_simd_recip14(bits, X86_SIMD_F64, 0);
                    hash64 = (hash64 ^ result.bits).wrapping_mul(FNV_PRIME);
                    assert_eq!(result.status, 0);
                    count64 += 1;
                }
            }
        }
    }
    assert_eq!(count64, 2_048);
    assert_eq!(hash64, 0xD3E9_7608_DF2E_C325);

    for (bits, format, mxcsr, expected) in [
        (0, X86_SIMD_F32, 0, 0x7F80_0000),
        (0x8000_0000, X86_SIMD_F32, 0, 0xFF80_0000),
        (0x7F80_0000, X86_SIMD_F32, 0, 0),
        (0xFF80_0000, X86_SIMD_F32, 0, 0x8000_0000),
        (0x7FC1_2345, X86_SIMD_F32, 0, 0x7FC1_2345),
        (0x7F81_2345, X86_SIMD_F32, 0, 0x7FC1_2345),
        (0x0020_0000, X86_SIMD_F32, 0, 0x7F80_0000),
        (0x0020_0001, X86_SIMD_F32, 0, 0x7F7F_FE00),
        (0x0020_0001, X86_SIMD_F32, 1 << 6, 0x7F80_0000),
        (0x0040_0000, X86_SIMD_F32, 0, 0x7F00_0000),
        (0x7E80_0001, X86_SIMD_F32, 0, 0x007F_FF00),
        (0x7E80_0001, X86_SIMD_F32, 1 << 15, 0),
        (0x7F00_0001, X86_SIMD_F32, 0, 0x003F_FF80),
        (0, X86_SIMD_F64, 0, 0x7FF0_0000_0000_0000),
        (
            0x8000_0000_0000_0000,
            X86_SIMD_F64,
            0,
            0xFFF0_0000_0000_0000,
        ),
        (0x7FF0_0000_0000_0000, X86_SIMD_F64, 0, 0),
        (
            0xFFF0_0000_0000_0000,
            X86_SIMD_F64,
            0,
            0x8000_0000_0000_0000,
        ),
        (
            0x7FF8_1234_5678_9ABC,
            X86_SIMD_F64,
            0,
            0x7FF8_1234_5678_9ABC,
        ),
        (
            0x7FF0_1234_5678_9ABC,
            X86_SIMD_F64,
            0,
            0x7FF8_1234_5678_9ABC,
        ),
        (
            0x0004_0000_0000_0000,
            X86_SIMD_F64,
            0,
            0x7FF0_0000_0000_0000,
        ),
        (
            0x0004_0000_0000_0001,
            X86_SIMD_F64,
            0,
            0x7FEF_FFC0_0000_0000,
        ),
        (
            0x0004_0000_0000_0001,
            X86_SIMD_F64,
            1 << 6,
            0x7FF0_0000_0000_0000,
        ),
        (
            0x7FD0_0000_0000_0001,
            X86_SIMD_F64,
            0,
            0x000F_FFE0_0000_0000,
        ),
        (0x7FD0_0000_0000_0001, X86_SIMD_F64, 1 << 15, 0),
    ] {
        assert_eq!(
            SmirInterpreter::x86_simd_recip14(bits, format, mxcsr),
            X86SimdFpResult {
                bits: expected,
                status: 0,
            }
        );
    }

    let limit = 2.0f64.powi(-14);
    for exponent in [1u64, 256, 1023, 1792, 2046] {
        for segment in 0u64..64 {
            for tail in [1u64, (1 << 45) - 1, (1 << 46) - 1] {
                let bits = (exponent << 52) | (segment << 46) | tail;
                let input = f64::from_bits(bits);
                let actual =
                    f64::from_bits(SmirInterpreter::x86_simd_recip14(bits, X86_SIMD_F64, 0).bits);
                let reference = input.recip();
                let relative_error = ((actual - reference) / reference).abs();
                assert!(
                    relative_error < limit,
                    "VRCP14D {input:e}: relative error {relative_error:e}"
                );
            }
        }
    }
}
#[test]
fn x86_recip28_matches_intel_reference_all_segments_and_special_values() {
    // FNV-1a-style accumulation over outputs and status flags generated by
    // Intel's RECIP28EXP2.c RCP28S/RCP28D implementation. The corpus
    // exercises all 256 polynomial segments, both signs, four in-segment
    // positions, and minimum/central/maximum normal exponent fields.
    const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
    let mut hash32 = FNV_OFFSET;
    let mut count32 = 0usize;
    for sign in [0u32, 1] {
        for exponent in [1u32, 127, 254] {
            for segment in 0u32..256 {
                for tail in [0u32, 1, 0x3FFF, 0x7FFF] {
                    let fraction = (segment << 15) | tail;
                    if fraction == 0 {
                        continue;
                    }
                    let bits = (sign << 31) | (exponent << 23) | fraction;
                    let result = SmirInterpreter::x86_simd_recip28(u64::from(bits), X86_SIMD_F32);
                    hash32 = (hash32 ^ result.bits).wrapping_mul(FNV_PRIME);
                    hash32 = (hash32 ^ u64::from(result.status)).wrapping_mul(FNV_PRIME);
                    count32 += 1;
                }
            }
        }
    }
    assert_eq!(count32, 6_138);
    assert_eq!(hash32, 0x033E_3A71_C458_F825);

    let mut hash64 = FNV_OFFSET;
    let mut count64 = 0usize;
    for sign in [0u64, 1] {
        for exponent in [1u64, 1023, 2046] {
            for segment in 0u64..256 {
                for tail in [0u64, 1, 0x1F_FFFF, 0x3F_FFFF] {
                    let fraction = (segment << 44) | (tail << 22) | (tail & 0x3F_FFFF);
                    if fraction == 0 {
                        continue;
                    }
                    let bits = (sign << 63) | (exponent << 52) | fraction;
                    let result = SmirInterpreter::x86_simd_recip28(bits, X86_SIMD_F64);
                    hash64 = (hash64 ^ result.bits).wrapping_mul(FNV_PRIME);
                    hash64 = (hash64 ^ u64::from(result.status)).wrapping_mul(FNV_PRIME);
                    count64 += 1;
                }
            }
        }
    }
    assert_eq!(count64, 6_138);
    assert_eq!(hash64, 0xC358_27E9_E21A_2AD5);

    for (bits, format, expected, status) in [
        (0, X86_SIMD_F32, 0x7F80_0000, 1 << 2),
        (0x8000_0000, X86_SIMD_F32, 0xFF80_0000, 1 << 2),
        (1, X86_SIMD_F32, 0x7F80_0000, 1 << 2),
        (0x8000_0001, X86_SIMD_F32, 0xFF80_0000, 1 << 2),
        (0x7F80_0000, X86_SIMD_F32, 0, 0),
        (0xFF80_0000, X86_SIMD_F32, 0x8000_0000, 0),
        (0, X86_SIMD_F64, 0x7FF0_0000_0000_0000, 1 << 2),
        (
            0x8000_0000_0000_0000,
            X86_SIMD_F64,
            0xFFF0_0000_0000_0000,
            1 << 2,
        ),
        (1, X86_SIMD_F64, 0x7FF0_0000_0000_0000, 1 << 2),
        (
            0x8000_0000_0000_0001,
            X86_SIMD_F64,
            0xFFF0_0000_0000_0000,
            1 << 2,
        ),
        (0x7FF0_0000_0000_0000, X86_SIMD_F64, 0, 0),
        (
            0xFFF0_0000_0000_0000,
            X86_SIMD_F64,
            0x8000_0000_0000_0000,
            0,
        ),
    ] {
        assert_eq!(
            SmirInterpreter::x86_simd_recip28(bits, format),
            X86SimdFpResult {
                bits: expected,
                status,
            }
        );
    }

    for (input, expected) in [(0.5f64, 2.0f64), (1.0, 1.0), (2.0, 0.5), (-4.0, -0.25)] {
        assert_eq!(
            SmirInterpreter::x86_simd_recip28(input.to_bits(), X86_SIMD_F64),
            X86SimdFpResult {
                bits: expected.to_bits(),
                status: 0,
            }
        );
    }

    let qnan = SmirInterpreter::x86_simd_recip28(0xFFC1_2345, X86_SIMD_F32);
    assert_eq!(
        qnan,
        X86SimdFpResult {
            bits: 0xFFC1_2345,
            status: 0
        }
    );
    let snan = SmirInterpreter::x86_simd_recip28(0xFF81_2345, X86_SIMD_F32);
    assert_eq!(
        snan,
        X86SimdFpResult {
            bits: 0xFFC1_2345,
            status: 1
        }
    );

    let limit = 2.0f64.powi(-28);
    for exponent in [1u64, 256, 1023, 1792, 2046] {
        for segment in 0u64..256 {
            for tail in [1u64, 0x1F_FFFF, 0x3F_FFFF] {
                let bits = (exponent << 52) | (segment << 44) | (tail << 22);
                let input = f64::from_bits(bits);
                let result = SmirInterpreter::x86_simd_recip28(bits, X86_SIMD_F64);
                if result.bits == 0 || result.bits == 0x7FF0_0000_0000_0000 {
                    continue;
                }
                let actual = f64::from_bits(result.bits);
                let reference = input.recip();
                let relative_error = ((actual - reference) / reference).abs();
                assert!(
                    relative_error < limit,
                    "VRCP28D {input:e}: relative error {relative_error:e}"
                );
            }
        }
    }
}
#[test]
fn lifted_x86_recip14_preserves_widths_scalar_merge_masks_mxcsr_and_fault_suppression() {
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [0xAAAA_AAAA_DEAD_BEEF; 16];
        x86.xmm[2] = [
            0x0123_4567_89AB_CDEF,
            0x0FED_CBA9_8765_4321,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        x86.xmm[3][0] = u64::from(3.0f32.to_bits());
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x08, 0x4D, 0xCB], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x0123_4567_3EAA_AA80);
        assert_eq!(x86.xmm[1][1], 0x0FED_CBA9_8765_4321);
        assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1][0] = 0xAAAA_AAAA_DEAD_BEEF;
        x86.k[1] = 0;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0x4D, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x0123_4567_DEAD_BEEF);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1][0] = 0xAAAA_AAAA_DEAD_BEEF;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x89, 0x4D, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x0123_4567_0000_0000);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[3][0] = 0x0020_0001;
        x86.mxcsr = 0;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x08, 0x4D, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0] as u32, 0x7F7F_FE00);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mxcsr = 1 << 6;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x08, 0x4D, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0] as u32, 0x7F80_0000);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[3][0] = 0x7E80_0001;
        x86.mxcsr = 0;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x08, 0x4D, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0] as u32, 0x007F_FF00);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mxcsr = 1 << 15;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x08, 0x4D, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0] as u32, 0);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [0xDEAD_BEEF_CAFE_BABE; 16];
        x86.xmm[3][0] = (u64::from(4.0f32.to_bits()) << 32) | u64::from(2.0f32.to_bits());
        x86.xmm[3][1] = (u64::from(16.0f32.to_bits()) << 32) | u64::from(8.0f32.to_bits());
        x86.mxcsr = 0;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x7D, 0x08, 0x4C, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x3E80_0000_3F00_0000);
        assert_eq!(x86.xmm[1][1], 0x3D80_0000_3E00_0000);
        assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let k1 = VReg::Arch(ArchReg::X86(X86Reg::K(1)));
    ctx.write_vreg(rax, 0x100);
    ctx.write_vreg(k1, 0);
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0x4D, 0x08], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    ctx.write_vreg(k1, 1);
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0x4D, 0x08], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
}
#[test]
fn lifted_x86_recip28_preserves_scalar_merge_masks_sae_and_fault_atomicity() {
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [0xAAAA_AAAA_DEAD_BEEF; 16];
        x86.xmm[2] = [
            0x0123_4567_89AB_CDEF,
            0x0FED_CBA9_8765_4321,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        x86.xmm[3][0] = u64::from(2.0f32.to_bits());
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x08, 0xCB, 0xCB], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x0123_4567_3F00_0000);
        assert_eq!(x86.xmm[1][1], 0x0FED_CBA9_8765_4321);
        assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1][0] = 0xAAAA_AAAA_DEAD_BEEF;
        x86.k[1] = 0;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0xCB, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x0123_4567_DEAD_BEEF);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1][0] = 0xAAAA_AAAA_DEAD_BEEF;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x89, 0xCB, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x0123_4567_0000_0000);
    }

    let sentinel = [0xDEAD_BEEF_CAFE_BABEu64; 16];
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.xmm[3][0] = 0x7F80_1234;
        x86.k[1] = 1;
        x86.mxcsr = 0;
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0xCB, 0xCB], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], sentinel);
        assert_ne!(x86.mxcsr & 1, 0);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.mxcsr = 0;
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x19, 0xCB, 0xCB], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0x0123_4567_7FC0_1234);
        assert_eq!(x86.mxcsr & 0x3F, 0);
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let k1 = VReg::Arch(ArchReg::X86(X86Reg::K(1)));
    ctx.write_vreg(rax, 0x100);
    ctx.write_vreg(k1, 0);
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0xCB, 0x08], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    ctx.write_vreg(k1, 1);
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0xCB, 0x08], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
}
#[test]
fn lifted_x86_exp2_preserves_masks_fault_suppression_sae_and_exception_atomicity() {
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [0xAAAA_AAAA_DEAD_BEEF; 16];
        x86.xmm[3][0] = (u64::from(2.0f32.to_bits()) << 32) | u64::from(1.0f32.to_bits());
        x86.k[1] = 1;
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x7D, 0x49, 0xC8, 0xCB], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0xAAAA_AAAA_4000_0000);
        assert!(
            x86.xmm[1][1..8]
                .iter()
                .all(|word| *word == 0xAAAA_AAAA_DEAD_BEEF)
        );
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [u64::MAX; 16];
        x86.k[1] = 0;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x7D, 0xC9, 0xC8, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert!(x86.xmm[1][..8].iter().all(|word| *word == 0));
    }

    let sentinel = [0xDEAD_BEEF_CAFE_BABEu64; 16];
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.xmm[3][0] = 0x7F80_1234;
        x86.k[1] = 1;
        x86.mxcsr = 0;
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x7D, 0x49, 0xC8, 0xCB], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], sentinel);
        assert_ne!(x86.mxcsr & 1, 0);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.mxcsr = 0;
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x7D, 0x19, 0xC8, 0xCB], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0] & 0xFFFF_FFFF, 0x7FC0_1234);
        assert_eq!(x86.mxcsr & 0x3F, 0);
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let k1 = VReg::Arch(ArchReg::X86(X86Reg::K(1)));
    ctx.write_vreg(rax, 0x100);
    ctx.write_vreg(k1, 0);
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x7D, 0x49, 0xC8, 0x08], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::Halt)
    ));
    ctx.write_vreg(k1, 1);
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x7D, 0x49, 0xC8, 0x08], &mut ctx, &mut memory,),
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
}
#[test]
fn lifted_x86_range_preserves_scalar_merge_fault_suppression_and_exception_atomicity() {
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [0xCCCC_CCCC_4120_0000; 16];
        x86.xmm[2] = [
            0xA5A5_A5A5_C000_0000,
            0x0123_4567_89AB_CDEF,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        x86.xmm[3][0] = u64::from(3.0f32.to_bits());
    }
    assert!(matches!(
        execute_lifted_x86(
            &[0x62, 0xF3, 0x6D, 0x08, 0x51, 0xCB, 0x05],
            &mut ctx,
            &mut memory,
        ),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0xA5A5_A5A5_4040_0000);
        assert_eq!(x86.xmm[1][1], 0x0123_4567_89AB_CDEF);
        assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.k[1] = 0;
        x86.xmm[1][0] = 0xCCCC_CCCC_4120_0000;
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0x6D, 0x09, 0x51, 0xCB, 0x05],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0xA5A5_A5A5_4120_0000);
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0x6D, 0x89, 0x51, 0xCB, 0x05],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0xA5A5_A5A5_0000_0000);
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let k1 = VReg::Arch(ArchReg::X86(X86Reg::K(1)));
    ctx.write_vreg(rax, 0x100);
    ctx.write_vreg(k1, 0);
    assert!(matches!(
        execute_lifted_x86(
            &[0x62, 0xF3, 0x6D, 0x09, 0x51, 0x08, 0x05],
            &mut ctx,
            &mut memory,
        ),
        BlockResult::Exit(ExitReason::Halt)
    ));
    ctx.write_vreg(k1, 1);
    assert!(matches!(
        execute_lifted_x86(
            &[0x62, 0xF3, 0x6D, 0x09, 0x51, 0x08, 0x05],
            &mut ctx,
            &mut memory,
        ),
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));

    let sentinel = [0xDEAD_BEEF_CAFE_BABEu64; 16];
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mxcsr = 0x1F00;
        x86.xmm[1] = sentinel;
        x86.xmm[2][0] = 0x7F80_1234;
        x86.xmm[3][0] = u64::from(1.0f32.to_bits());
    }
    assert!(matches!(
        execute_lifted_x86(
            &[0x62, 0xF3, 0x6D, 0x08, 0x51, 0xCB, 0x0C],
            &mut ctx,
            &mut memory,
        ),
        BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], sentinel);
        assert_ne!(x86.mxcsr & 1, 0);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mxcsr = 0x1F00;
        x86.xmm[1] = sentinel;
    }
    assert!(matches!(
        execute_lifted_x86(
            &[0x62, 0xF3, 0x6D, 0x18, 0x51, 0xCB, 0x0C],
            &mut ctx,
            &mut memory,
        ),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0] & 0xFFFF_FFFF, 0x7FC0_1234);
        assert_eq!(x86.mxcsr, 0x1F00);
    }
}
#[test]
fn x86_scale_f_exact_semantics_cover_floor_specials_daz_ftz_and_rounding() {
    let run32 = |first: f32, second: f32, mxcsr: u32| {
        SmirInterpreter::x86_simd_scale_f(
            u64::from(first.to_bits()),
            u64::from(second.to_bits()),
            X86_SIMD_F32,
            FpRoundMode::RoundNearest,
            mxcsr,
            false,
        )
    };
    assert_eq!(run32(1.5, 2.75, 0x1F80).bits, u64::from(6.0f32.to_bits()));
    assert_eq!(
        run32(1.5, -1.25, 0x1F80).bits,
        u64::from(0.375f32.to_bits())
    );

    let first_qnan = 0x7FC1_2345u64;
    let second_snan = 0x7F81_5678u64;
    let nan = SmirInterpreter::x86_simd_scale_f(
        first_qnan,
        second_snan,
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1F80,
        false,
    );
    assert_eq!(nan.bits, first_qnan);
    assert_eq!(nan.status, 1);

    let qnan_positive_infinity = SmirInterpreter::x86_simd_scale_f(
        first_qnan,
        u64::from(f32::INFINITY.to_bits()),
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1F80,
        false,
    );
    assert_eq!(
        qnan_positive_infinity.bits,
        u64::from(f32::INFINITY.to_bits())
    );
    assert_eq!(qnan_positive_infinity.status, 0);
    let qnan_negative_infinity = SmirInterpreter::x86_simd_scale_f(
        first_qnan,
        u64::from(f32::NEG_INFINITY.to_bits()),
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1F80,
        false,
    );
    assert_eq!(qnan_negative_infinity.bits, 0);
    assert_eq!(qnan_negative_infinity.status, 0);

    let denormal_then_nan = SmirInterpreter::x86_simd_scale_f(
        1,
        second_snan,
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1F80,
        false,
    );
    assert_eq!(denormal_then_nan.status, 1, "src2 NaN suppresses src1 DE");

    for (first, second, expected, status) in [
        (f32::INFINITY, f32::NEG_INFINITY, 0xFFC0_0000u64, 1u32),
        (0.0, f32::INFINITY, 0xFFC0_0000, 1),
        (
            -1.0,
            f32::INFINITY,
            u64::from(f32::NEG_INFINITY.to_bits()),
            0,
        ),
        (-1.0, f32::NEG_INFINITY, u64::from((-0.0f32).to_bits()), 0),
    ] {
        let result = run32(first, second, 0x1F80);
        assert_eq!(result.bits, expected);
        assert_eq!(result.status, status);
    }

    let denormal = SmirInterpreter::x86_simd_scale_f(
        1,
        u64::from(0.0f32.to_bits()),
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1F80,
        false,
    );
    assert_eq!(denormal.bits, 1);
    assert_eq!(denormal.status, 1 << 1);
    let daz = SmirInterpreter::x86_simd_scale_f(
        1,
        u64::from(0.0f32.to_bits()),
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1FC0,
        false,
    );
    assert_eq!(daz.bits, 0);
    assert_eq!(daz.status, 0);

    let negative_denormal_scale = 0x8000_0001u64;
    let no_daz = SmirInterpreter::x86_simd_scale_f(
        u64::from(1.0f32.to_bits()),
        negative_denormal_scale,
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1F80,
        false,
    );
    assert_eq!(no_daz.bits, u64::from(0.5f32.to_bits()));
    assert_eq!(no_daz.status, 0, "src2 denormal never raises DE");
    let with_daz = SmirInterpreter::x86_simd_scale_f(
        u64::from(1.0f32.to_bits()),
        negative_denormal_scale,
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1FC0,
        false,
    );
    assert_eq!(with_daz.bits, u64::from(1.0f32.to_bits()));

    let fp16_gradual = SmirInterpreter::x86_simd_scale_f(
        1,
        0,
        X86_SIMD_F16,
        FpRoundMode::RoundNearest,
        0x9FC0,
        false,
    );
    assert_eq!(fp16_gradual.bits, 1, "packed FP16 ignores DAZ and FTZ");
    assert_eq!(fp16_gradual.status, 1 << 1);
    let fp16_scalar_ftz = SmirInterpreter::x86_simd_scale_f(
        1,
        0,
        X86_SIMD_F16,
        FpRoundMode::RoundNearest,
        0x9FC0,
        true,
    );
    assert_eq!(fp16_scalar_ftz.bits, 0, "scalar FP16 honors FTZ");
    assert_eq!(fp16_scalar_ftz.status, (1 << 1) | (1 << 4) | (1 << 5));

    let max_f32 = 0x7F7F_FFFFu64;
    let overflow_nearest = SmirInterpreter::x86_simd_scale_f(
        max_f32,
        u64::from(1.0f32.to_bits()),
        X86_SIMD_F32,
        FpRoundMode::RoundNearest,
        0x1F80,
        false,
    );
    assert_eq!(overflow_nearest.bits, u64::from(f32::INFINITY.to_bits()));
    assert_eq!(overflow_nearest.status, (1 << 3) | (1 << 5));
    let overflow_zero = SmirInterpreter::x86_simd_scale_f(
        max_f32,
        u64::from(1.0f32.to_bits()),
        X86_SIMD_F32,
        FpRoundMode::RoundTowardZero,
        0x1F80,
        false,
    );
    assert_eq!(overflow_zero.bits, max_f32);
    assert_eq!(overflow_zero.status, (1 << 3) | (1 << 5));
}
#[test]
fn lifted_x86_scale_f_preserves_scalar_merge_and_exception_atomicity() {
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [0xCCCC_CCCC_4120_0000; 16];
        x86.xmm[2] = [
            0xA5A5_A5A5_3FC0_0000,
            0x0123_4567_89AB_CDEF,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        x86.xmm[3][0] = u64::from(2.75f32.to_bits());
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x08, 0x2D, 0xCB], &mut ctx, &mut memory),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0xA5A5_A5A5_40C0_0000);
        assert_eq!(x86.xmm[1][1], 0x0123_4567_89AB_CDEF);
        assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.k[1] = 0;
        x86.xmm[1][0] = 0xCCCC_CCCC_4120_0000;
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0x2D, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0xA5A5_A5A5_4120_0000);
    }
    execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x89, 0x2D, 0xCB], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0], 0xA5A5_A5A5_0000_0000);
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let k1 = VReg::Arch(ArchReg::X86(X86Reg::K(1)));
    ctx.write_vreg(rax, 0x100);
    ctx.write_vreg(k1, 0);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0x2D, 0x08], &mut ctx, &mut memory),
        BlockResult::Exit(ExitReason::Halt)
    ));
    let masked_memory_result = match &ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.xmm[1],
        _ => unreachable!(),
    };
    ctx.write_vreg(k1, 1);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x09, 0x2D, 0x08], &mut ctx, &mut memory),
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], [0xCCCC_CCCC_CCCC_CCCCu64; 16]);
        assert_ne!(masked_memory_result, x86.xmm[1]);
    }

    let sentinel = [0xDEAD_BEEF_CAFE_BABEu64; 16];
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mxcsr = 0x1F00;
        x86.xmm[1] = sentinel;
        x86.xmm[2][0] = u64::from(f32::INFINITY.to_bits());
        x86.xmm[3][0] = u64::from(f32::NEG_INFINITY.to_bits());
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x08, 0x2D, 0xCB], &mut ctx, &mut memory),
        BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], sentinel);
        assert_ne!(x86.mxcsr & 1, 0);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.mxcsr = 0x1F00;
        x86.xmm[1] = sentinel;
    }
    assert!(matches!(
        execute_lifted_x86(&[0x62, 0xF2, 0x6D, 0x18, 0x2D, 0xCB], &mut ctx, &mut memory),
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][0] & 0xFFFF_FFFF, 0xFFC0_0000);
        assert_eq!(x86.mxcsr, 0x1F00);
    }
}
