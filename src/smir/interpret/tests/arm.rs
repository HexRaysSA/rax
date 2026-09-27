//! tests::arm tests

use super::*;
use crate::smir::interpret::*;
use crate::smir::ir::FunctionBuilder;
use crate::smir::ir::flags::{FlagSet, FlagUpdate, MaterializedFlags};
use crate::smir::ir::memory::{FlatMemory, SmirMemory};
use crate::smir::ir::types::ShiftOp;

#[test]
fn interworking_call_targets_use_explicit_pc_and_w32_indirect_masking() {
    let interpreter = SmirInterpreter::new();
    let mut memory = FlatMemory::new(0x1000);
    let mut ctx = SmirContext::new_aarch64();
    let continuation = BlockId(1);

    let mut direct = SmirBlock::new(BlockId(0), 0x1000);
    direct.set_terminator(Terminator::Call {
        target: CallTarget::GuestAddrInterworking {
            addr: 0x2002,
            thumb: true,
        },
        args: Vec::new(),
        continuation,
    });
    assert!(matches!(
        interpreter.execute_block(&mut ctx, &mut memory, &direct),
        BlockResult::Continue(0x2002)
    ));

    let target = VReg::Arch(ArchReg::Arm(ArmReg::X(3)));
    ctx.write_vreg(target, 0xdead_beef_1234_5679);
    let mut indirect = SmirBlock::new(BlockId(0), 0x1000);
    indirect.set_terminator(Terminator::TailCall {
        target: CallTarget::IndirectInterworking(target),
        args: Vec::new(),
    });
    assert!(matches!(
        interpreter.execute_block(&mut ctx, &mut memory, &indirect),
        BlockResult::Continue(0x1234_5678)
    ));
}
#[test]
fn lifted_t16_selective_nzcv_ops_interpret_all_prior_flag_states() {
    let r0 = VReg::Arch(ArchReg::Arm(ArmReg::X(0)));
    let r1 = VReg::Arch(ArchReg::Arm(ArmReg::X(1)));
    for (bytes, expected, updates_c) in [
        (&[0x00, 0x20][..], 0_u32, None),             // MOVS r0,#0
        (&[0x08, 0x40][..], 0x8000_0001, None),       // ANDS r0,r1
        (&[0x48, 0x43][..], 0x7fff_ffff, None),       // MULS r0,r1
        (&[0x48, 0x00][..], 0xffff_fffe, Some(true)), // LSLS r0,r1,#1
        (&[0x08, 0x08][..], 0, Some(true)),           // LSRS r0,r1,#32
        (&[0x08, 0x10][..], u32::MAX, Some(true)),    // ASRS r0,r1,#32
    ] {
        for old_nzcv in 0_u8..16 {
            let mut ctx = SmirContext::new_aarch64();
            ctx.write_vreg(r0, 0x8000_0001);
            ctx.write_vreg(r1, u64::from(u32::MAX));
            ctx.flags.materialized = MaterializedFlags {
                sf: old_nzcv & 0b1000 != 0,
                zf: old_nzcv & 0b0100 != 0,
                cf: old_nzcv & 0b0010 != 0,
                of: old_nzcv & 0b0001 != 0,
                pf: true,
                af: true,
                df: true,
                ac: true,
            };
            ctx.flags.lazy = None;

            assert!(matches!(
                execute_lifted_thumb(bytes, &mut ctx),
                BlockResult::Exit(ExitReason::Halt)
            ));
            ctx.flags.materialize_all();
            assert_eq!(ctx.read_vreg(r0), u64::from(expected), "{bytes:02x?}");
            assert_eq!(ctx.flags.materialized.sf, expected & 0x8000_0000 != 0);
            assert_eq!(ctx.flags.materialized.zf, expected == 0);
            assert_eq!(
                ctx.flags.materialized.cf,
                updates_c.unwrap_or(old_nzcv & 0b0010 != 0),
                "{bytes:02x?} old={old_nzcv:#x}"
            );
            assert_eq!(
                ctx.flags.materialized.of,
                old_nzcv & 0b0001 != 0,
                "{bytes:02x?} old={old_nzcv:#x}"
            );
            assert!(ctx.flags.materialized.pf, "PF is outside T16 NZCV writes");
            assert!(ctx.flags.materialized.af, "AF is outside T16 NZCV writes");
            assert!(ctx.flags.materialized.df, "DF is outside T16 NZCV writes");
            assert!(ctx.flags.materialized.ac, "AC is outside T16 NZCV writes");
        }
    }
}
#[test]
fn lifted_t16_register_shifts_interpret_low_byte_boundaries_and_aliases() {
    fn expected(value: u32, raw_count: u64, shift: ShiftOp, carry_in: bool) -> (u32, bool) {
        let count = (raw_count & 0xff) as u32;
        if count == 0 {
            return (value, carry_in);
        }
        match shift {
            ShiftOp::Lsl if count < 32 => (value << count, (value >> (32 - count)) & 1 != 0),
            ShiftOp::Lsl if count == 32 => (0, value & 1 != 0),
            ShiftOp::Lsl => (0, false),
            ShiftOp::Lsr if count < 32 => (value >> count, (value >> (count - 1)) & 1 != 0),
            ShiftOp::Lsr if count == 32 => (0, value >> 31 != 0),
            ShiftOp::Lsr => (0, false),
            ShiftOp::Asr if count < 32 => (
                ((value as i32) >> count) as u32,
                (value >> (count - 1)) & 1 != 0,
            ),
            ShiftOp::Asr => {
                let sign = value >> 31 != 0;
                (if sign { u32::MAX } else { 0 }, sign)
            }
            ShiftOp::Ror => {
                let result = value.rotate_right(count % 32);
                (result, result >> 31 != 0)
            }
            ShiftOp::Rrx => unreachable!(),
        }
    }

    let r0 = VReg::Arch(ArchReg::Arm(ArmReg::X(0)));
    let r1 = VReg::Arch(ArchReg::Arm(ArmReg::X(1)));
    let values = [0_u32, 1, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, u32::MAX];
    let counts = [
        0_u64,
        1,
        2,
        31,
        32,
        33,
        63,
        64,
        127,
        128,
        255,
        256,
        257,
        u64::MAX,
    ];

    for (op, shift) in [
        (0b0010_u16, ShiftOp::Lsl),
        (0b0011, ShiftOp::Lsr),
        (0b0100, ShiftOp::Asr),
        (0b0111, ShiftOp::Ror),
    ] {
        let raw = 0x4000_u16 | (op << 6) | (1 << 3); // Rdn=r0, Rs=r1
        for &value in &values {
            for &count in &counts {
                for old_nzcv in 0_u8..16 {
                    let carry_in = old_nzcv & 0b0010 != 0;
                    let (result, carry) = expected(value, count, shift, carry_in);
                    let mut ctx = SmirContext::new_aarch64();
                    ctx.write_vreg(r0, u64::from(value));
                    ctx.write_vreg(r1, count);
                    ctx.flags.materialized = MaterializedFlags {
                        sf: old_nzcv & 0b1000 != 0,
                        zf: old_nzcv & 0b0100 != 0,
                        cf: carry_in,
                        of: old_nzcv & 0b0001 != 0,
                        pf: true,
                        af: true,
                        df: true,
                        ac: true,
                    };
                    ctx.flags.lazy = None;

                    assert!(matches!(
                        execute_lifted_thumb(&raw.to_le_bytes(), &mut ctx),
                        BlockResult::Exit(ExitReason::Halt)
                    ));
                    assert_eq!(ctx.read_vreg(r0), u64::from(result));
                    assert_eq!(ctx.flags.materialized.sf, result >> 31 != 0);
                    assert_eq!(ctx.flags.materialized.zf, result == 0);
                    assert_eq!(ctx.flags.materialized.cf, carry);
                    assert_eq!(ctx.flags.materialized.of, old_nzcv & 1 != 0);
                    assert!(ctx.flags.materialized.pf);
                    assert!(ctx.flags.materialized.af);
                    assert!(ctx.flags.materialized.df);
                    assert!(ctx.flags.materialized.ac);
                }
            }
        }

        // Rdn==Rs is legal: both the source value and count must be read
        // before the destination is overwritten.
        let alias_raw = 0x4000_u16 | (op << 6);
        for &value in &values {
            let (result, carry) = expected(value, u64::from(value), shift, true);
            let mut ctx = SmirContext::new_aarch64();
            ctx.write_vreg(r0, u64::from(value));
            ctx.flags.materialized.cf = true;
            assert!(matches!(
                execute_lifted_thumb(&alias_raw.to_le_bytes(), &mut ctx),
                BlockResult::Exit(ExitReason::Halt)
            ));
            assert_eq!(ctx.read_vreg(r0), u64::from(result));
            assert_eq!(ctx.flags.materialized.cf, carry);
        }
    }
}
#[test]
fn lifted_t32_register_shifts_interpret_independent_aliases_and_flag_modes() {
    fn expected(value: u32, raw_count: u64, shift: ShiftOp, carry_in: bool) -> (u32, bool) {
        let count = (raw_count & 0xff) as u32;
        if count == 0 {
            return (value, carry_in);
        }
        match shift {
            ShiftOp::Lsl if count < 32 => (value << count, (value >> (32 - count)) & 1 != 0),
            ShiftOp::Lsl if count == 32 => (0, value & 1 != 0),
            ShiftOp::Lsl => (0, false),
            ShiftOp::Lsr if count < 32 => (value >> count, (value >> (count - 1)) & 1 != 0),
            ShiftOp::Lsr if count == 32 => (0, value >> 31 != 0),
            ShiftOp::Lsr => (0, false),
            ShiftOp::Asr if count < 32 => (
                ((value as i32) >> count) as u32,
                (value >> (count - 1)) & 1 != 0,
            ),
            ShiftOp::Asr => {
                let sign = value >> 31 != 0;
                (if sign { u32::MAX } else { 0 }, sign)
            }
            ShiftOp::Ror => {
                let result = value.rotate_right(count % 32);
                (result, result >> 31 != 0)
            }
            ShiftOp::Rrx => unreachable!(),
        }
    }

    fn encode(kind: u16, setflags: bool, dst: u8, src: u8, amount: u8) -> [u8; 4] {
        let op1 = (kind << 1) | u16::from(setflags);
        let hw1 = 0xfa00_u16 | (op1 << 4) | u16::from(src);
        let hw2 = 0xf000_u16 | (u16::from(dst) << 8) | u16::from(amount);
        let [a, b] = hw1.to_le_bytes();
        let [c, d] = hw2.to_le_bytes();
        [a, b, c, d]
    }

    let regs = [
        VReg::Arch(ArchReg::Arm(ArmReg::X(0))),
        VReg::Arch(ArchReg::Arm(ArmReg::X(1))),
        VReg::Arch(ArchReg::Arm(ArmReg::X(2))),
    ];
    for (kind, shift) in [
        (0_u16, ShiftOp::Lsl),
        (1, ShiftOp::Lsr),
        (2, ShiftOp::Asr),
        (3, ShiftOp::Ror),
    ] {
        for setflags in [false, true] {
            for &(dst, src, amount) in &[
                (0_usize, 1_usize, 2_usize),
                (0, 0, 2),
                (0, 1, 0),
                (0, 1, 1),
                (0, 0, 0),
            ] {
                let bytes = encode(kind, setflags, dst as u8, src as u8, amount as u8);
                for &(value, raw_count) in &[
                    (0x8000_0001_u64, 0_u64),
                    (0x8000_0001, 1),
                    (0x8000_0001, 31),
                    (0x8000_0001, 32),
                    (0x8000_0001, 33),
                    (0x8000_0001, 255),
                    (0x8000_0001, 256),
                    (0x7fff_ffff, 257),
                ] {
                    let mut input = [0xaaaa_aaaa_u64, 0xbbbb_bbbb, 0xcccc_cccc];
                    input[src] = value;
                    input[amount] = raw_count;
                    for old_nzcv in 0_u8..16 {
                        let (result, carry) = expected(
                            input[src] as u32,
                            input[amount],
                            shift,
                            old_nzcv & 0b0010 != 0,
                        );
                        let mut ctx = SmirContext::new_aarch64();
                        for (reg, initial) in regs.into_iter().zip(input) {
                            ctx.write_vreg(reg, initial);
                        }
                        ctx.flags.materialized = MaterializedFlags {
                            sf: old_nzcv & 0b1000 != 0,
                            zf: old_nzcv & 0b0100 != 0,
                            cf: old_nzcv & 0b0010 != 0,
                            of: old_nzcv & 0b0001 != 0,
                            pf: true,
                            af: true,
                            df: true,
                            ac: true,
                        };
                        ctx.flags.lazy = None;

                        assert!(matches!(
                            execute_lifted_thumb(&bytes, &mut ctx),
                            BlockResult::Exit(ExitReason::Halt)
                        ));
                        assert_eq!(ctx.read_vreg(regs[dst]), u64::from(result));
                        for reg in 0..3 {
                            if reg != dst {
                                assert_eq!(ctx.read_vreg(regs[reg]), input[reg]);
                            }
                        }
                        let actual_nzcv = (u8::from(ctx.flags.materialized.sf) << 3)
                            | (u8::from(ctx.flags.materialized.zf) << 2)
                            | (u8::from(ctx.flags.materialized.cf) << 1)
                            | u8::from(ctx.flags.materialized.of);
                        let expected_nzcv = if setflags {
                            ((result >> 31) as u8) << 3
                                | (u8::from(result == 0) << 2)
                                | (u8::from(carry) << 1)
                                | (old_nzcv & 1)
                        } else {
                            old_nzcv
                        };
                        assert_eq!(
                            actual_nzcv, expected_nzcv,
                            "{shift:?} S={setflags} aliases=({dst},{src},{amount}) count={raw_count:#x}"
                        );
                        assert!(ctx.flags.materialized.pf);
                        assert!(ctx.flags.materialized.af);
                        assert!(ctx.flags.materialized.df);
                        assert!(ctx.flags.materialized.ac);
                    }
                }
            }
        }
    }
}
#[test]
fn lifted_a32_data_processing_register_shifts_cover_all_semantics_and_aliases() {
    use crate::smir::ir::ops::ArmDpRegShiftKind as Kind;

    fn encode(kind: Kind, set_flags: bool, rd: u8, rn: u8, rm: u8, rs: u8, shift: u8) -> u32 {
        0xe000_0000
            | ((kind as u32) << 21)
            | (u32::from(set_flags) << 20)
            | (u32::from(rn) << 16)
            | (u32::from(rd) << 12)
            | (u32::from(rs) << 8)
            | (u32::from(shift) << 5)
            | (1 << 4)
            | u32::from(rm)
    }

    fn shift_expected(value: u32, raw_count: u64, shift: ShiftOp, carry: bool) -> (u32, bool) {
        let count = (raw_count & 0xff) as u32;
        if count == 0 {
            return (value, carry);
        }
        match shift {
            ShiftOp::Lsl if count < 32 => (value << count, value >> (32 - count) & 1 != 0),
            ShiftOp::Lsl if count == 32 => (0, value & 1 != 0),
            ShiftOp::Lsl => (0, false),
            ShiftOp::Lsr if count < 32 => (value >> count, value >> (count - 1) & 1 != 0),
            ShiftOp::Lsr if count == 32 => (0, value >> 31 != 0),
            ShiftOp::Lsr => (0, false),
            ShiftOp::Asr if count < 32 => (
                ((value as i32) >> count) as u32,
                value >> (count - 1) & 1 != 0,
            ),
            ShiftOp::Asr => {
                let sign = value >> 31 != 0;
                (if sign { u32::MAX } else { 0 }, sign)
            }
            ShiftOp::Ror => {
                let result = value.rotate_right(count % 32);
                (result, result >> 31 != 0)
            }
            ShiftOp::Rrx => unreachable!(),
        }
    }

    fn add_carry(a: u32, b: u32, carry: bool) -> (u32, bool, bool) {
        let unsigned = u64::from(a) + u64::from(b) + u64::from(carry);
        let signed = i64::from(a as i32) + i64::from(b as i32) + i64::from(carry);
        (
            unsigned as u32,
            unsigned > u64::from(u32::MAX),
            signed < i64::from(i32::MIN) || signed > i64::from(i32::MAX),
        )
    }

    fn expected(kind: Kind, lhs: u32, shifted: u32, carry: bool) -> (u32, Option<(bool, bool)>) {
        match kind {
            Kind::And | Kind::Tst => (lhs & shifted, None),
            Kind::Eor | Kind::Teq => (lhs ^ shifted, None),
            Kind::Sub | Kind::Cmp => {
                let (r, c, v) = add_carry(lhs, !shifted, true);
                (r, Some((c, v)))
            }
            Kind::Rsb => {
                let (r, c, v) = add_carry(shifted, !lhs, true);
                (r, Some((c, v)))
            }
            Kind::Add | Kind::Cmn => {
                let (r, c, v) = add_carry(lhs, shifted, false);
                (r, Some((c, v)))
            }
            Kind::Adc => {
                let (r, c, v) = add_carry(lhs, shifted, carry);
                (r, Some((c, v)))
            }
            Kind::Sbc => {
                let (r, c, v) = add_carry(lhs, !shifted, carry);
                (r, Some((c, v)))
            }
            Kind::Rsc => {
                let (r, c, v) = add_carry(shifted, !lhs, carry);
                (r, Some((c, v)))
            }
            Kind::Orr => (lhs | shifted, None),
            Kind::Mov => (shifted, None),
            Kind::Bic => (lhs & !shifted, None),
            Kind::Mvn => (!shifted, None),
        }
    }

    let kinds = (0_u8..16)
        .map(|opcode| Kind::from_opcode(opcode).unwrap())
        .collect::<Vec<_>>();
    let shifts = [ShiftOp::Lsl, ShiftOp::Lsr, ShiftOp::Asr, ShiftOp::Ror];
    let aliases = [
        (0_u8, 1_u8, 2_u8, 3_u8),
        (0, 0, 2, 3),
        (0, 1, 0, 3),
        (0, 1, 2, 0),
        (0, 1, 1, 3),
        (0, 1, 2, 1),
        (0, 1, 2, 2),
        (0, 0, 0, 0),
    ];
    let inputs = [
        (0x8000_0001_u64, 0_u64),
        (0x8000_0001, 1),
        (0x7fff_ffff, 31),
        (0x8000_0000, 32),
        (0xffff_ffff, 33),
        (0x4000_0001, 255),
        (0x8000_0001, 256),
        (0x7fff_ffff, 257),
    ];
    let regs = [
        VReg::Arch(ArchReg::Arm(ArmReg::X(0))),
        VReg::Arch(ArchReg::Arm(ArmReg::X(1))),
        VReg::Arch(ArchReg::Arm(ArmReg::X(2))),
        VReg::Arch(ArchReg::Arm(ArmReg::X(3))),
    ];

    for kind in kinds {
        let flag_modes: &[bool] = if kind.writes_result() {
            &[false, true]
        } else {
            &[true]
        };
        for (shift_bits, shift) in shifts.into_iter().enumerate() {
            for &(encoded_rd, encoded_rn, rm, rs) in &aliases {
                let rd = if kind.writes_result() { encoded_rd } else { 0 };
                let rn = if kind.uses_rn() { encoded_rn } else { 0 };
                for &set_flags in flag_modes {
                    let raw = encode(kind, set_flags, rd, rn, rm, rs, shift_bits as u8);
                    let block = lifted_a32_block(raw);
                    for &(value, raw_count) in &inputs {
                        let mut initial = [0x1111_1111_u64, 0x2222_2222, 0x3333_3333, 0x4444_4444];
                        initial[usize::from(rm)] = value;
                        initial[usize::from(rs)] = raw_count;
                        for old_nzcv in 0_u8..16 {
                            let carry_in = old_nzcv & 0b0010 != 0;
                            let (shifted, shifter_carry) = shift_expected(
                                initial[usize::from(rm)] as u32,
                                initial[usize::from(rs)],
                                shift,
                                carry_in,
                            );
                            let lhs = if kind.uses_rn() {
                                initial[usize::from(rn)] as u32
                            } else {
                                0
                            };
                            let (result, arithmetic) = expected(kind, lhs, shifted, carry_in);
                            let expected_nzcv = if !set_flags {
                                old_nzcv
                            } else if let Some((carry, overflow)) = arithmetic {
                                ((result >> 31) as u8) << 3
                                    | (u8::from(result == 0) << 2)
                                    | (u8::from(carry) << 1)
                                    | u8::from(overflow)
                            } else {
                                ((result >> 31) as u8) << 3
                                    | (u8::from(result == 0) << 2)
                                    | (u8::from(shifter_carry) << 1)
                                    | (old_nzcv & 1)
                            };

                            let mut ctx = SmirContext::new_aarch64();
                            for (reg, value) in regs.into_iter().zip(initial) {
                                ctx.write_vreg(reg, value);
                            }
                            ctx.flags.materialized = MaterializedFlags {
                                sf: old_nzcv & 0b1000 != 0,
                                zf: old_nzcv & 0b0100 != 0,
                                cf: carry_in,
                                of: old_nzcv & 0b0001 != 0,
                                pf: true,
                                af: true,
                                df: true,
                                ac: true,
                            };
                            ctx.flags.lazy = None;
                            let exit = SmirInterpreter::new().execute_block(
                                &mut ctx,
                                &mut FlatMemory::new(0x1000),
                                &block,
                            );
                            assert!(matches!(exit, BlockResult::Exit(ExitReason::Halt)));
                            if kind.writes_result() {
                                assert_eq!(ctx.read_vreg(regs[usize::from(rd)]), u64::from(result));
                            }
                            for reg in 0_u8..4 {
                                if !kind.writes_result() || reg != rd {
                                    assert_eq!(
                                        ctx.read_vreg(regs[usize::from(reg)]),
                                        initial[usize::from(reg)]
                                    );
                                }
                            }
                            let actual_nzcv = (u8::from(ctx.flags.materialized.sf) << 3)
                                | (u8::from(ctx.flags.materialized.zf) << 2)
                                | (u8::from(ctx.flags.materialized.cf) << 1)
                                | u8::from(ctx.flags.materialized.of);
                            assert_eq!(
                                actual_nzcv, expected_nzcv,
                                "{kind:?} {shift:?} S={set_flags} regs=({rd},{rn},{rm},{rs}) old={old_nzcv:#x}"
                            );
                            assert!(ctx.flags.materialized.pf);
                            assert!(ctx.flags.materialized.af);
                            assert!(ctx.flags.materialized.df);
                            assert!(ctx.flags.materialized.ac);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn lifted_t16_adr_matches_the_direct_executor() {
    // ADR Rd, #imm8:'00' at 0x1000: Align(0x1004, 4) + imm32, the flags
    // and the other registers unchanged.
    use crate::isa::arm::aarch32::cpu::{Armv7Cpu, FlatMemory as ArmMemory};
    use crate::isa::arm::aarch32::instructions::Executor;
    use crate::isa::arm::decoder::ThumbDecoder;
    for rd in [0_u16, 1, 7] {
        for imm8 in [0_u16, 6, 0xff] {
            let hw = 0xa000 | (rd << 8) | imm8;
            let want = 0x1004 + u32::from(imm8) * 4;

            let mut cpu = Armv7Cpu::new();
            cpu.regs[15] = 0x1000;
            cpu.cpsr.t = true;
            cpu.regs[0] = 0x5555_0000;
            let mut mem = ArmMemory::new(0x2000, 0);
            let insn = ThumbDecoder::decode_16bit(hw).unwrap();
            Executor::new(&mut cpu, &mut mem).execute(&insn);
            assert_eq!(cpu.regs[usize::from(rd)], want, "direct {hw:#06x}");

            let mut ctx = SmirContext::new_aarch64();
            ctx.write_vreg(VReg::Arch(ArchReg::Arm(ArmReg::X(0))), 0x5555_0000);
            assert!(matches!(
                execute_lifted_thumb(&hw.to_le_bytes(), &mut ctx),
                BlockResult::Exit(ExitReason::Halt)
            ));
            let got = ctx.read_vreg(VReg::Arch(ArchReg::Arm(ArmReg::X(rd as u8))));
            assert_eq!(got, u64::from(want), "lifted {hw:#06x}");
        }
    }
}
