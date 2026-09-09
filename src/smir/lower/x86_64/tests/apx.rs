//! tests::apx tests

use super::*;
use crate::smir::lower::x86_64::*;

#[test]
fn lower_rex2_mov_egpr_sequence_addresses_apx_slot() {
    // LLVM 20 encodes:
    //   mov r16, 0x1122334455667788  => d5 18 b8 imm64
    //   mov rax, r16                 => d5 48 89 c0
    let (lowered, _) = lower_rex2_block(&[
        0xD5, 0x18, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xD5, 0x48, 0x89, 0xC0,
        0xF4,
    ]);
    let r16_slot = (16u32 * 8).to_le_bytes();
    assert!(
        lowered.windows(4).any(|window| window == r16_slot),
        "state-backed REX2 MOV should address GuestRegs.gpr[16]"
    );
}
#[test]
fn lower_apx_push2_pop2_requires_helper_backed_stack_memory() {
    // LLVM 23:
    //   push2 %rax, %rbx => 62 f4 64 18 ff f0
    //   pop2  %rbx, %rax => 62 f4 7c 18 8f c3
    let code = [
        0x62, 0xF4, 0x64, 0x18, 0xFF, 0xF0, 0x62, 0xF4, 0x7C, 0x18, 0x8F, 0xC3, 0xF4,
    ];

    // Direct lowering must reject the virtual guest-RSP memory rather than
    // addressing the live host stack.
    let err = lower_rex2_block_err(&code);
    assert!(
        matches!(err, LowerError::InvalidRegister(ref reg) if reg.contains("Rsp")),
        "push2/pop2 must reject non-helper guest stack memory, got {err:?}"
    );

    // Helper mode fuses each complete five-op instruction into exactly one
    // paired runtime call, preserving the all-or-neither commit boundary.
    let (lowered, _) = lower_rex2_block_with_mem_helpers(&code, true);
    for offset in [
        X86_GUEST_PAIR_STORE_FN_OFFSET,
        X86_GUEST_PAIR_LOAD_FN_OFFSET,
    ] {
        let mut call = vec![0xFF, 0x90];
        call.extend_from_slice(&(offset as u32).to_le_bytes());
        assert_eq!(
            lowered
                .windows(call.len())
                .filter(|bytes| *bytes == call)
                .count(),
            1,
            "paired helper call at GuestRegs offset {offset:#x}: {lowered:02X?}"
        );
    }
}
#[test]
fn lower_apx_ndd_nf_alu_legacy_gpr_slice_lowers_without_relocs() {
    // LLVM 23 APX MAP4 forms:
    //   add eax, ebx, eax  => NDD destination aliases the second source
    //   {nf} add rax, rbx  => no-flag-update SMIR shape
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xF4, 0x7C, 0x18, 0x03, 0xD8, 0x62, 0xF4, 0xFC, 0x0C, 0x01, 0xD8, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
}
#[test]
fn lower_apx_ndd_adc_sbb_alias_slice_lowers_without_relocs() {
    // LLVM 20 APX MAP4 forms:
    //   adcq %r8, %rax, %r8 => 62 74 bc 18 11 c0
    //   sbbq %r8, %rax, %r8 => 62 74 bc 18 19 c0
    // The destination aliases the carry op's second source, so lifting must
    // preserve that source before the x86 lowerer copies src1 into dst.
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0x74, 0xBC, 0x18, 0x11, 0xC0, 0x62, 0x74, 0xBC, 0x18, 0x19, 0xC0, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(
        lowered.windows(3).any(|bytes| bytes == [0x49, 0x11, 0xC0]),
        "alias ADC must commute its sources instead of overwriting r8: {lowered:02X?}"
    );
    assert!(
        lowered.windows(14).any(|bytes| bytes
            == [
                0x41, 0x50, 0x49, 0x89, 0xC0, 0x4C, 0x1B, 0x04, 0x24, 0x48, 0x8D, 0x64, 0x24, 0x08,
            ]),
        "alias SBB must consume the saved second source and preserve result flags: {lowered:02X?}"
    );
}
#[test]
fn lower_apx_ndd_binary_alu_alias_second_source_is_native_and_flag_safe() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));
    for (name, op, expected) in [
        (
            "add",
            OpKind::Add {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            &[0x49, 0x01, 0xC0][..],
        ),
        (
            "or",
            OpKind::Or {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            &[0x49, 0x09, 0xC0][..],
        ),
        (
            "and",
            OpKind::And {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            &[0x49, 0x21, 0xC0][..],
        ),
        (
            "sub",
            OpKind::Sub {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            &[
                0x41, 0x50, 0x49, 0x89, 0xC0, 0x4C, 0x2B, 0x04, 0x24, 0x48, 0x8D, 0x64, 0x24, 0x08,
            ][..],
        ),
        (
            "xor",
            OpKind::Xor {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            &[0x49, 0x31, 0xC0][..],
        ),
    ] {
        let code = lower_single_op(op);
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "missing alias-safe {name} {expected:02X?}: {code:02X?}"
        );
    }

    for (width, expected) in [
        (
            OpWidth::W8,
            &[
                0x41, 0x50, 0x41, 0x88, 0xC0, 0x44, 0x2A, 0x04, 0x24, 0x48, 0x8D, 0x64, 0x24, 0x08,
            ][..],
        ),
        (
            OpWidth::W16,
            &[
                0x41, 0x50, 0x66, 0x41, 0x89, 0xC0, 0x66, 0x44, 0x2B, 0x04, 0x24, 0x48, 0x8D, 0x64,
                0x24, 0x08,
            ][..],
        ),
        (
            OpWidth::W32,
            &[
                0x41, 0x50, 0x41, 0x89, 0xC0, 0x44, 0x2B, 0x04, 0x24, 0x48, 0x8D, 0x64, 0x24, 0x08,
            ][..],
        ),
        (
            OpWidth::W64,
            &[
                0x41, 0x50, 0x49, 0x89, 0xC0, 0x4C, 0x2B, 0x04, 0x24, 0x48, 0x8D, 0x64, 0x24, 0x08,
            ][..],
        ),
    ] {
        let code = lower_single_op(OpKind::Sub {
            dst: r8,
            src1: rax,
            src2: SrcOperand::Reg(r8),
            width,
            flags: FlagUpdate::All,
        });
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "missing flag-safe alias SUB {width:?} {expected:02X?}: {code:02X?}"
        );
    }
}
#[test]
fn lower_apx_nf_binary_alu_preserves_flags_for_aliases_and_immediates() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));
    for (name, op, expected) in [
        (
            "add",
            OpKind::Add {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            &[0x9C, 0x49, 0x01, 0xC0, 0x9D][..],
        ),
        (
            "or",
            OpKind::Or {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            &[0x9C, 0x49, 0x09, 0xC0, 0x9D][..],
        ),
        (
            "and",
            OpKind::And {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            &[0x9C, 0x49, 0x21, 0xC0, 0x9D][..],
        ),
        (
            "sub",
            OpKind::Sub {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            &[
                0x9C, 0x41, 0x50, 0x49, 0x89, 0xC0, 0x4C, 0x2B, 0x04, 0x24, 0x48, 0x8D, 0x64, 0x24,
                0x08, 0x9D,
            ][..],
        ),
        (
            "xor",
            OpKind::Xor {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Reg(r8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            &[0x9C, 0x49, 0x31, 0xC0, 0x9D][..],
        ),
    ] {
        let code = lower_single_op(op);
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "NF alias {name} must preserve flags: {code:02X?}"
        );
    }

    for (name, op, digit) in [
        (
            "add",
            OpKind::Add {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Imm(7),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            0u8,
        ),
        (
            "or",
            OpKind::Or {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Imm(7),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            1,
        ),
        (
            "adc",
            OpKind::Adc {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Imm(7),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            2,
        ),
        (
            "sbb",
            OpKind::Sbb {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Imm(7),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            3,
        ),
        (
            "and",
            OpKind::And {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Imm(7),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            4,
        ),
        (
            "sub",
            OpKind::Sub {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Imm(7),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            5,
        ),
        (
            "xor",
            OpKind::Xor {
                dst: r8,
                src1: rax,
                src2: SrcOperand::Imm(7),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            6,
        ),
    ] {
        let code = lower_single_op(op);
        // The complete W64 immediate path saves flags before copying src1.
        // MOV is flag-neutral, so ADC/SBB still consume the incoming CF and
        // POPFQ restores every status bit after the ALU instruction.
        let expected = [
            0x9C,
            0x49,
            0x89,
            0xC0,
            0x49,
            0x83,
            0xC0 | digit << 3,
            0x07,
            0x9D,
        ];
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "NF immediate {name} must preserve flags: {code:02X?}"
        );
    }

    for width in [OpWidth::W8, OpWidth::W16, OpWidth::W32, OpWidth::W64] {
        let code = lower_single_op(OpKind::Add {
            dst: r8,
            src1: rax,
            src2: SrcOperand::Reg(r8),
            width,
            flags: FlagUpdate::None,
        });
        let push = code.iter().position(|byte| *byte == 0x9C).unwrap();
        assert!(
            code[push + 1..].contains(&0x9D),
            "NF ADD {width:?} must bracket its ALU instruction"
        );
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_apx_nf_immediates_preserve_the_source_and_every_status_flag() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let src1 = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let mut executions = 0;
    for group in 0..=6 {
        for destination in [X86Reg::Rax, X86Reg::R8] {
            let dst = VReg::Arch(ArchReg::X86(destination));
            for value in [7i64, 0x8000_0000, 0x1234_5678_9ABC_DEF0] {
                for src2 in [SrcOperand::Imm(value), SrcOperand::Imm64(value)] {
                    macro_rules! alu {
                        ($kind:ident) => {
                            OpKind::$kind {
                                dst,
                                src1,
                                src2: src2.clone(),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            }
                        };
                    }
                    let kind = match group {
                        0 => alu!(Add),
                        1 => alu!(Or),
                        2 => alu!(Adc),
                        3 => alu!(Sbb),
                        4 => alu!(And),
                        5 => alu!(Sub),
                        6 => alu!(Xor),
                        _ => unreachable!("seven Group-1 arithmetic operations"),
                    };
                    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
                    builder.push_op(0x1000, kind);
                    builder.set_terminator(Terminator::Return { values: vec![] });
                    let mut lowerer = X86_64Lowerer::new();
                    let lowered = lowerer.lower_function(&builder.finish()).unwrap();
                    let exec = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();

                    // Enumerate all 2^6 arithmetic-status images; retain IF
                    // and DF as non-arithmetic state. Values include unsigned
                    // wrap and the signed overflow boundary.
                    for pattern in 0u64..64 {
                        let mut regs = GuestRegs {
                            gpr: core::array::from_fn(|index| 0x1234_5678_0000_0000 | index as u64),
                            rflags: [0, 2, 4, 6, 7, 11]
                                .into_iter()
                                .enumerate()
                                .fold(0x602, |flags, (index, bit)| {
                                    flags | (((pattern >> index) & 1) << bit)
                                }),
                            ..GuestRegs::default()
                        };
                        let lhs = [0, u64::MAX, i64::MAX as u64, i64::MIN as u64]
                            [(pattern as usize >> 1) & 3];
                        regs.gpr[0] = lhs;
                        let mut expected = regs;
                        let rhs = value as u64;
                        let carry = regs.rflags & 1;
                        // Modulo-2^64 arithmetic is independent of the emitted
                        // instruction and preserves the input flag image.
                        expected.gpr[destination.gpr_index().unwrap() as usize] = match group {
                            0 => lhs.wrapping_add(rhs),
                            1 => lhs | rhs,
                            2 => lhs.wrapping_add(rhs).wrapping_add(carry),
                            3 => lhs.wrapping_sub(rhs).wrapping_sub(carry),
                            4 => lhs & rhs,
                            5 => lhs.wrapping_sub(rhs),
                            6 => lhs ^ rhs,
                            _ => unreachable!(),
                        };
                        exec.run(lowered.entry_offset, &mut regs);
                        expected.host_mxcsr = regs.host_mxcsr;
                        assert_eq!(
                            regs, expected,
                            "group={group} dst={destination:?} value={value:#x} src2={src2:?} flags={pattern:#x}"
                        );
                        executions += 1;
                    }
                }
            }
        }
    }
    assert_eq!(executions, 7 * 2 * 3 * 2 * 64);
    eprintln!("executed {executions} native APX NF immediate differentials");
}

#[test]
fn lower_apx_ndd_imul_alias_second_source_covers_widths_and_nf() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rbx = VReg::Arch(ArchReg::X86(X86Reg::Rbx));
    for (width, expected) in [
        (OpWidth::W16, &[0x66, 0x0F, 0xAF, 0xD8][..]),
        (OpWidth::W32, &[0x0F, 0xAF, 0xD8][..]),
        (OpWidth::W64, &[0x48, 0x0F, 0xAF, 0xD8][..]),
    ] {
        let code = lower_single_op(OpKind::MulS {
            dst_lo: rbx,
            dst_hi: None,
            src1: rax,
            src2: SrcOperand::Reg(rbx),
            width,
            flags: FlagUpdate::All,
        });
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "missing direct alias IMUL {width:?} {expected:02X?}: {code:02X?}"
        );
    }

    let nf = lower_single_op(OpKind::MulS {
        dst_lo: rbx,
        dst_hi: None,
        src1: rax,
        src2: SrcOperand::Reg(rbx),
        width: OpWidth::W64,
        flags: FlagUpdate::None,
    });
    let expected_nf = [0x9C, 0x48, 0x0F, 0xAF, 0xD8, 0x9D];
    assert!(
        nf.windows(expected_nf.len())
            .any(|bytes| bytes == expected_nf),
        "NF alias IMUL must preserve flags around the direct multiply: {nf:02X?}"
    );
}
#[test]
fn lower_apx_ndd_double_shift_covers_direct_alias_cl_partial_width_and_nf_paths() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let rbx = VReg::Arch(ArchReg::X86(X86Reg::Rbx));
    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));

    for (name, op, expected) in [
        (
            "direct shld",
            OpKind::X86NddDoubleShift {
                dst: r8,
                base: rax,
                fill: rbx,
                amount: SrcOperand::Imm(4),
                width: OpWidth::W64,
                left: true,
                flags: FlagUpdate::All,
            },
            &[0x49, 0x89, 0xC0, 0x49, 0x0F, 0xA4, 0xD8, 0x04][..],
        ),
        (
            "fill-alias shld",
            OpKind::X86NddDoubleShift {
                dst: rbx,
                base: rax,
                fill: rbx,
                amount: SrcOperand::Imm(4),
                width: OpWidth::W64,
                left: true,
                flags: FlagUpdate::All,
            },
            &[
                0x53, 0x48, 0x89, 0x04, 0x24, 0x48, 0x0F, 0xA4, 0x1C, 0x24, 0x04, 0x5B,
            ][..],
        ),
        (
            "CL-alias shrd",
            OpKind::X86NddDoubleShift {
                dst: rcx,
                base: rax,
                fill: rbx,
                amount: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
                left: false,
                flags: FlagUpdate::All,
            },
            &[
                0x51, 0x48, 0x89, 0x04, 0x24, 0x48, 0x0F, 0xAD, 0x1C, 0x24, 0x59,
            ][..],
        ),
        (
            "NF fill-alias shld",
            OpKind::X86NddDoubleShift {
                dst: rbx,
                base: rax,
                fill: rbx,
                amount: SrcOperand::Imm(4),
                width: OpWidth::W64,
                left: true,
                flags: FlagUpdate::None,
            },
            &[
                0x9C, 0x53, 0x48, 0x89, 0x04, 0x24, 0x48, 0x0F, 0xA4, 0x1C, 0x24, 0x04, 0x5B, 0x9D,
            ][..],
        ),
        (
            "word fill-alias shld",
            OpKind::X86NddDoubleShift {
                dst: rbx,
                base: rax,
                fill: rbx,
                amount: SrcOperand::Imm(4),
                width: OpWidth::W16,
                left: true,
                flags: FlagUpdate::All,
            },
            &[
                0x53, 0x66, 0x89, 0x04, 0x24, 0x66, 0x0F, 0xA4, 0x1C, 0x24, 0x04, 0x5B,
            ][..],
        ),
        (
            "dword fill-alias shld",
            OpKind::X86NddDoubleShift {
                dst: rbx,
                base: rax,
                fill: rbx,
                amount: SrcOperand::Imm(4),
                width: OpWidth::W32,
                left: true,
                flags: FlagUpdate::All,
            },
            &[
                0x53, 0x89, 0x04, 0x24, 0x0F, 0xA4, 0x1C, 0x24, 0x04, 0x5B, 0x89, 0xDB,
            ][..],
        ),
    ] {
        let code = lower_single_op(op);
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "missing {name} lowering {expected:02X?}: {code:02X?}"
        );
    }

    for invalid in [
        OpKind::X86NddDoubleShift {
            dst: rbx,
            base: rax,
            fill: rbx,
            amount: SrcOperand::Imm(4),
            width: OpWidth::W8,
            left: true,
            flags: FlagUpdate::All,
        },
        OpKind::X86NddDoubleShift {
            dst: rbx,
            base: rax,
            fill: rbx,
            amount: SrcOperand::Reg(VReg::Arch(ArchReg::X86(X86Reg::Rdx))),
            width: OpWidth::W64,
            left: false,
            flags: FlagUpdate::All,
        },
        OpKind::X86NddDoubleShift {
            dst: rbx,
            base: rax,
            fill: r8,
            amount: SrcOperand::Imm(4),
            width: OpWidth::W64,
            left: true,
            flags: FlagUpdate::Specific(FlagSet::ZF),
        },
    ] {
        assert!(
            lower_single_op_err(invalid)
                .to_string()
                .contains("X86NddDoubleShift")
        );
    }
}
#[test]
fn lower_apx_ndd_single_shift_cl_alias_covers_all_groups_widths_and_nf() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    for (name, op, digit) in [
        (
            "rol",
            OpKind::Rol {
                dst: rcx,
                src: rax,
                amount: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            0u8,
        ),
        (
            "ror",
            OpKind::Ror {
                dst: rcx,
                src: rax,
                amount: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            1,
        ),
        (
            "rcl",
            OpKind::Rcl {
                dst: rcx,
                src: rax,
                amount: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            2,
        ),
        (
            "rcr",
            OpKind::Rcr {
                dst: rcx,
                src: rax,
                amount: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            3,
        ),
        (
            "shl",
            OpKind::Shl {
                dst: rcx,
                src: rax,
                amount: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            4,
        ),
        (
            "shr",
            OpKind::Shr {
                dst: rcx,
                src: rax,
                amount: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            5,
        ),
        (
            "sar",
            OpKind::Sar {
                dst: rcx,
                src: rax,
                amount: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            7,
        ),
    ] {
        let code = lower_single_op(op);
        if matches!(digit, 2 | 3) {
            let expected = [0x48, 0xD3, 0xC2 | (digit << 3)];
            assert!(
                code.windows(expected.len()).any(|bytes| bytes == expected),
                "missing deterministic CL-alias {name} {expected:02X?}: {code:02X?}"
            );
            assert_eq!(
                code.iter().filter(|byte| **byte == 0x9C).count(),
                2,
                "CL-alias {name} must save incoming and native RFLAGS: {code:02X?}"
            );
            continue;
        }
        let expected = [
            0x51,
            0x48,
            0x89,
            0x04,
            0x24,
            0x48,
            0xD3,
            digit << 3 | 0x04,
            0x24,
            0x59,
        ];
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "missing direct CL-alias {name} {expected:02X?}: {code:02X?}"
        );
    }

    for (width, expected) in [
        (
            OpWidth::W8,
            &[0x51, 0x40, 0x88, 0x04, 0x24, 0xD2, 0x24, 0x24, 0x59][..],
        ),
        (
            OpWidth::W16,
            &[0x51, 0x66, 0x89, 0x04, 0x24, 0x66, 0xD3, 0x24, 0x24, 0x59][..],
        ),
        (
            OpWidth::W32,
            &[0x51, 0x89, 0x04, 0x24, 0xD3, 0x24, 0x24, 0x59, 0x89, 0xC9][..],
        ),
        (
            OpWidth::W64,
            &[0x51, 0x48, 0x89, 0x04, 0x24, 0x48, 0xD3, 0x24, 0x24, 0x59][..],
        ),
    ] {
        let code = lower_single_op(OpKind::Shl {
            dst: rcx,
            src: rax,
            amount: SrcOperand::Reg(rcx),
            width,
            flags: FlagUpdate::All,
        });
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "missing CL-alias SHL {width:?} {expected:02X?}: {code:02X?}"
        );
    }

    let nf_alias = lower_single_op(OpKind::Shl {
        dst: rcx,
        src: rax,
        amount: SrcOperand::Reg(rcx),
        width: OpWidth::W64,
        flags: FlagUpdate::None,
    });
    let expected_nf_alias = [
        0x9C, 0x51, 0x48, 0x89, 0x04, 0x24, 0x48, 0xD3, 0x24, 0x24, 0x59, 0x9D,
    ];
    assert!(
        nf_alias
            .windows(expected_nf_alias.len())
            .any(|bytes| bytes == expected_nf_alias),
        "NF CL-alias SHL must preserve flags: {nf_alias:02X?}"
    );

    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));
    let nf_imm = lower_single_op(OpKind::Shl {
        dst: r8,
        src: rax,
        amount: SrcOperand::Imm(4),
        width: OpWidth::W64,
        flags: FlagUpdate::None,
    });
    let expected_nf_imm = [0x49, 0x89, 0xC0, 0x9C, 0x49, 0xC1, 0xE0, 0x04, 0x9D];
    assert!(
        nf_imm
            .windows(expected_nf_imm.len())
            .any(|bytes| bytes == expected_nf_imm),
        "NF immediate SHL must preserve flags: {nf_imm:02X?}"
    );
}
#[test]
fn lower_immediate_one_carry_rotates_cover_widths_and_ndd_copy() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));
    let flags = FlagUpdate::Specific(FlagSet::CF.union(FlagSet::OF));

    for (name, op, expected) in [
        (
            "RCL byte",
            OpKind::Rcl {
                dst: rax,
                src: rax,
                amount: SrcOperand::Imm(1),
                width: OpWidth::W8,
                flags,
            },
            &[0xD0, 0xD0][..],
        ),
        (
            "RCR word",
            OpKind::Rcr {
                dst: rcx,
                src: rcx,
                amount: SrcOperand::Imm(1),
                width: OpWidth::W16,
                flags,
            },
            &[0x66, 0xD1, 0xD9][..],
        ),
        (
            "RCL dword NDD",
            OpKind::Rcl {
                dst: r8,
                src: rax,
                amount: SrcOperand::Imm(1),
                width: OpWidth::W32,
                flags,
            },
            &[0x41, 0x89, 0xC0, 0x41, 0xD1, 0xD0][..],
        ),
        (
            "RCR qword NDD",
            OpKind::Rcr {
                dst: r8,
                src: rax,
                amount: SrcOperand::Imm(1),
                width: OpWidth::W64,
                flags,
            },
            &[0x49, 0x89, 0xC0, 0x49, 0xD1, 0xD8][..],
        ),
    ] {
        let code = lower_single_op(op);
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }
}
#[test]
fn lower_apx_ndd_nf_shift_rotate_slice_lowers_without_relocs() {
    // LLVM 20 APX MAP4 forms:
    //   shlq $4,  %rax, %r8        => 62 f4 bc 18 c1 e0 04
    //   {nf} shrq %cl, %rax, %r8   => 62 f4 bc 1c d3 e8
    //   rolq $7,  %rax, %r8        => 62 f4 bc 18 c1 c0 07
    //   rorq %cl, %rax, %r8        => 62 f4 bc 18 d3 c8
    //   rclq      %rax, %r8        => 62 f4 bc 18 d1 d0
    //   rcrq %cl, %rax, %r8        => 62 f4 bc 18 d3 d8
    //   shlq %cl, %rax, %rcx       => 62 f4 f4 18 d3 e0
    //   shldq $4, %rbx, %rax, %r8  => 62 f4 bc 18 24 d8 04
    //   {nf} shldq $4, %rbx, %rax, %r8 => 62 f4 bc 1c 24 d8 04
    //   shrdq %cl, %rbx, %rax, %r8 => 62 f4 bc 18 ad d8
    //   shrdq %cl, %rbx, %rax, %rcx => 62 f4 f4 18 ad d8
    //   shldq $4, %rbx, %rax, %rbx => 62 f4 e4 18 24 d8 04
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xF4, 0xBC, 0x18, 0xC1, 0xE0, 0x04, 0x62, 0xF4, 0xBC, 0x1C, 0xD3, 0xE8, 0x62, 0xF4,
        0xBC, 0x18, 0xC1, 0xC0, 0x07, 0x62, 0xF4, 0xBC, 0x18, 0xD3, 0xC8, 0x62, 0xF4, 0xBC, 0x18,
        0xD1, 0xD0, 0x62, 0xF4, 0xBC, 0x18, 0xD3, 0xD8, 0x62, 0xF4, 0xF4, 0x18, 0xD3, 0xE0, 0x62,
        0xF4, 0xBC, 0x18, 0x24, 0xD8, 0x04, 0x62, 0xF4, 0xBC, 0x1C, 0x24, 0xD8, 0x04, 0x62, 0xF4,
        0xBC, 0x18, 0xAD, 0xD8, 0x62, 0xF4, 0xF4, 0x18, 0xAD, 0xD8, 0x62, 0xF4, 0xE4, 0x18, 0x24,
        0xD8, 0x04, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
}
#[test]
fn lower_apx_ndd_nf_unary_slice_lowers_without_relocs() {
    // LLVM 23 APX MAP4 forms:
    //   notq %rax, %r8       => 62 f4 bc 18 f7 d0
    //   negq %rax, %r8       => 62 f4 bc 18 f7 d8
    //   incq %rax, %r8       => 62 f4 bc 18 ff c0
    //   decq %rax, %r8       => 62 f4 bc 18 ff c8
    //   {nf} negq %rax       => 62 f4 fc 0c f7 d8
    //   {nf} incq %rax       => 62 f4 fc 0c ff c0
    //   {nf} decq %rax       => 62 f4 fc 0c ff c8
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xF4, 0xBC, 0x18, 0xF7, 0xD0, 0x62, 0xF4, 0xBC, 0x18, 0xF7, 0xD8, 0x62, 0xF4, 0xBC,
        0x18, 0xFF, 0xC0, 0x62, 0xF4, 0xBC, 0x18, 0xFF, 0xC8, 0x62, 0xF4, 0xFC, 0x0C, 0xF7, 0xD8,
        0x62, 0xF4, 0xFC, 0x0C, 0xFF, 0xC0, 0x62, 0xF4, 0xFC, 0x0C, 0xFF, 0xC8, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
    assert!(
        lowered.contains(&0x9C),
        "NF unary lowering must preserve flags"
    );
    assert!(
        lowered.contains(&0x9D),
        "NF unary lowering must restore flags"
    );
}
#[test]
fn lower_apx_implicit_group3_slice_lowers_both_nf_states_without_relocs() {
    // LLVM 23 APX MAP4 forms:
    //   mulq       %rbx => 62 f4 fc 08 f7 e3
    //   imulq      %rbx => 62 f4 fc 08 f7 eb
    //   divq       %rbx => 62 f4 fc 08 f7 f3
    //   idivq      %rbx => 62 f4 fc 08 f7 fb
    //   {nf} mulq  %rbx => 62 f4 fc 0c f7 e3
    //   {nf} imulq %rbx => 62 f4 fc 0c f7 eb
    //   {nf} divq  %rbx => 62 f4 fc 0c f7 f3
    //   {nf} idivq %rbx => 62 f4 fc 0c f7 fb
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xF4, 0xFC, 0x08, 0xF7, 0xE3, 0x62, 0xF4, 0xFC, 0x08, 0xF7, 0xEB, 0x62, 0xF4, 0xFC,
        0x08, 0xF7, 0xF3, 0x62, 0xF4, 0xFC, 0x08, 0xF7, 0xFB, 0x62, 0xF4, 0xFC, 0x0C, 0xF7, 0xE3,
        0x62, 0xF4, 0xFC, 0x0C, 0xF7, 0xEB, 0x62, 0xF4, 0xFC, 0x0C, 0xF7, 0xF3, 0x62, 0xF4, 0xFC,
        0x0C, 0xF7, 0xFB, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
    assert!(
        lowered.contains(&0x9C),
        "NF implicit lowering must save flags"
    );
    assert!(
        lowered.contains(&0x9D),
        "NF implicit lowering must restore flags"
    );
}
#[test]
fn lower_apx_ndd_nf_imul_slice_lowers_without_relocs() {
    // LLVM 20 APX MAP4 forms:
    //   imulq %rbx, %rax, %r8       => 62 f4 bc 18 af c3
    //   {nf} imulq %rbx, %rax, %r8  => 62 f4 bc 1c af c3
    //   imulq %rbx, %rax, %rbx      => 62 f4 e4 18 af c3
    //   {nf} imulq $7, %rax, %r8    => 62 74 fc 0c 6b c0 07
    //   {nf} imulq $0x12345678, %rax, %r8
    //                                => 62 74 fc 0c 69 c0 78 56 34 12
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xF4, 0xBC, 0x18, 0xAF, 0xC3, 0x62, 0xF4, 0xBC, 0x1C, 0xAF, 0xC3, 0x62, 0xF4, 0xE4,
        0x18, 0xAF, 0xC3, 0x62, 0x74, 0xFC, 0x0C, 0x6B, 0xC0, 0x07, 0x62, 0x74, 0xFC, 0x0C, 0x69,
        0xC0, 0x78, 0x56, 0x34, 0x12, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
}
#[test]
fn lower_apx_movbe_slice_lowers_without_relocs() {
    // LLVM 20 APX MAP4 forms:
    //   movbeq %rax, %r8  => 62 d4 fc 08 61 c0
    //   movbel %eax, %r8d => 62 d4 7c 08 61 c0
    //   movbew %ax, %r8w  => 62 d4 7d 08 61 c0
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xD4, 0xFC, 0x08, 0x61, 0xC0, 0x62, 0xD4, 0x7C, 0x08, 0x61, 0xC0, 0x62, 0xD4, 0x7D,
        0x08, 0x61, 0xC0, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
}
#[test]
fn lower_apx_setzucc_slice_lowers_without_relocs() {
    // LLVM 20 APX MAP4 forms:
    //   setzuo  %al    => 62 f4 7f 18 40 c0
    //   setzune %bl    => 62 f4 7f 18 45 c3
    //   setzuo  %r8b   => 62 d4 7f 18 40 c0
    //   setzuo  (%rax) => 62 f4 7f 18 40 00
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xF4, 0x7F, 0x18, 0x40, 0xC0, 0x62, 0xF4, 0x7F, 0x18, 0x45, 0xC3, 0x62, 0xD4, 0x7F,
        0x18, 0x40, 0xC0, 0x62, 0xF4, 0x7F, 0x18, 0x40, 0x00, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
}
#[test]
fn lower_apx_cmov_cfcmov_slice_lowers_without_relocs() {
    // LLVM 20 APX MAP4 forms:
    //   cmovbq    %rbx, %rax, %r8  => 62 f4 bc 18 42 c3
    //   cfcmovbq  %rbx, %rax, %r8  => 62 f4 bc 1c 42 c3
    //   cfcmovbq  %rbx, %rax       => 62 f4 fc 0c 42 d8
    //   cfcmovbq  (%rbx), %rax     => 62 f4 fc 08 42 03
    //   cfcmovbq  %rbx, (%rax)     => 62 f4 fc 0c 42 18
    //   cfcmovbq  (%rbx), %rax, %r8
    //                                => 62 f4 bc 1c 42 03
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xF4, 0xBC, 0x18, 0x42, 0xC3, 0x62, 0xF4, 0xBC, 0x1C, 0x42, 0xC3, 0x62, 0xF4, 0xFC,
        0x0C, 0x42, 0xD8, 0x62, 0xF4, 0xFC, 0x08, 0x42, 0x03, 0x62, 0xF4, 0xFC, 0x0C, 0x42, 0x18,
        0x62, 0xF4, 0xBC, 0x1C, 0x42, 0x03, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
    assert!(
        lowered.contains(&0x9C),
        "CFCMOV/Select lowering must preserve flags"
    );
    assert!(
        lowered.contains(&0x9D),
        "CFCMOV/Select lowering must restore flags"
    );
}
#[test]
fn lower_apx_count_flagging_and_nf_slice_lowers_without_relocs() {
    // Intel APX revision 7 MAP4 SCALABLE forms:
    //        popcnt r8, rax   => 62 74 fc 08 88 c0
    //        lzcnt  r8, rax   => 62 74 fc 08 f5 c0
    //        tzcnt  r8, rax   => 62 74 fc 08 f4 c0
    //   {nf} popcnt r8, rax   => 62 74 fc 0c 88 c0
    //   {nf} lzcnt  r8, rax   => 62 74 fc 0c f5 c0
    //   {nf} tzcnt  r8, rax   => 62 74 fc 0c f4 c0
    //   {nf} popcnt r8w, ax   => 62 74 7d 0c 88 c0
    //   {nf} lzcnt  r8, [rbx] => 62 74 fc 0c f5 03
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0x74, 0xFC, 0x08, 0x88, 0xC0, 0x62, 0x74, 0xFC, 0x08, 0xF5, 0xC0, 0x62, 0x74, 0xFC,
        0x08, 0xF4, 0xC0, 0x62, 0x74, 0xFC, 0x0C, 0x88, 0xC0, 0x62, 0x74, 0xFC, 0x0C, 0xF5, 0xC0,
        0x62, 0x74, 0xFC, 0x0C, 0xF4, 0xC0, 0x62, 0x74, 0x7D, 0x0C, 0x88, 0xC0, 0x62, 0x74, 0xFC,
        0x0C, 0xF5, 0x03, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
    assert!(
        lowered.contains(&0x9C),
        "count lowering must preserve flags"
    );
    assert!(lowered.contains(&0x9D), "count lowering must restore flags");
}
#[test]
fn lower_x86_adx_emits_exact_native_encodings_and_preserves_three_operand_aliases() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rbx = VReg::Arch(ArchReg::X86(X86Reg::Rbx));
    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));
    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let rbp = VReg::Arch(ArchReg::X86(X86Reg::Rbp));
    let r16 = VReg::Arch(ArchReg::X86(X86Reg::R16));
    let r31 = VReg::Arch(ArchReg::X86(X86Reg::R31));

    let distinct = lower_single_op(OpKind::X86Adx {
        dst: r8,
        src1: rax,
        src2: rbx,
        width: OpWidth::W64,
        kind: X86AdxKind::Adcx,
        flags: FlagUpdate::Specific(FlagSet::CF),
    });
    let distinct_core = [0x49, 0x89, 0xC0, 0x66, 0x4C, 0x0F, 0x38, 0xF6, 0xC3];
    assert!(
        distinct
            .windows(distinct_core.len())
            .any(|window| window == distinct_core),
        "distinct ADCX lowering: {distinct:02X?}"
    );

    let destructive_alias = lower_single_op(OpKind::X86Adx {
        dst: rbx,
        src1: rax,
        src2: rbx,
        width: OpWidth::W64,
        kind: X86AdxKind::Adox,
        flags: FlagUpdate::Specific(FlagSet::OF),
    });
    let alias_core = [
        0x53, 0x48, 0x89, 0xC3, 0xF3, 0x48, 0x0F, 0x38, 0xF6, 0x1C, 0x24, 0x48, 0x8D, 0x64, 0x24,
        0x08,
    ];
    assert!(
        destructive_alias
            .windows(alias_core.len())
            .any(|window| window == alias_core),
        "dst==src2 ADOX lowering: {destructive_alias:02X?}"
    );

    let self_alias = lower_single_op(OpKind::X86Adx {
        dst: rax,
        src1: rax,
        src2: rax,
        width: OpWidth::W32,
        kind: X86AdxKind::Adcx,
        flags: FlagUpdate::None,
    });
    assert!(
        self_alias
            .windows(5)
            .any(|window| window == [0x66, 0x0F, 0x38, 0xF6, 0xC0]),
        "self-aliased ADCX lowering: {self_alias:02X?}"
    );

    for (name, op, expected) in [
        (
            "state-backed ADCX qword",
            OpKind::X86Adx {
                dst: rsp,
                src1: rsp,
                src2: rbp,
                width: OpWidth::W64,
                kind: X86AdxKind::Adcx,
                flags: FlagUpdate::Specific(FlagSet::CF),
            },
            &[0x66, 0x48, 0x0F, 0x38, 0xF6, 0xD7][..],
        ),
        (
            "state-backed ADOX dword",
            OpKind::X86Adx {
                dst: rbp,
                src1: rsp,
                src2: rbp,
                width: OpWidth::W32,
                kind: X86AdxKind::Adox,
                flags: FlagUpdate::Specific(FlagSet::OF),
            },
            &[0xF3, 0x0F, 0x38, 0xF6, 0xD7][..],
        ),
        (
            "state-backed suppressed ADCX all operands alias",
            OpKind::X86Adx {
                dst: r31,
                src1: r31,
                src2: r31,
                width: OpWidth::W64,
                kind: X86AdxKind::Adcx,
                flags: FlagUpdate::None,
            },
            &[0x66, 0x48, 0x0F, 0x38, 0xF6, 0xD7][..],
        ),
    ] {
        let code = lower_single_op(op);
        assert!(
            code.windows(expected.len()).any(|bytes| bytes == expected),
            "{name}: missing scratch ADX {expected:02X?} in {code:02X?}"
        );
        assert!(
            code.contains(&0x9C) && code.contains(&0x9D),
            "{name}: incoming and preserved flags must be saved and restored or merged"
        );
    }

    for malformed in [
        OpKind::X86Adx {
            dst: rax,
            src1: rax,
            src2: rbx,
            width: OpWidth::W16,
            kind: X86AdxKind::Adcx,
            flags: FlagUpdate::Specific(FlagSet::CF),
        },
        OpKind::X86Adx {
            dst: rax,
            src1: rax,
            src2: rbx,
            width: OpWidth::W64,
            kind: X86AdxKind::Adox,
            flags: FlagUpdate::Specific(FlagSet::CF),
        },
        OpKind::X86Adx {
            dst: r16,
            src1: rsp,
            src2: rbp,
            width: OpWidth::W16,
            kind: X86AdxKind::Adcx,
            flags: FlagUpdate::Specific(FlagSet::CF),
        },
        OpKind::X86Adx {
            dst: r31,
            src1: VReg::Virtual(crate::smir::ir::types::VirtualId(7)),
            src2: rbp,
            width: OpWidth::W64,
            kind: X86AdxKind::Adox,
            flags: FlagUpdate::Specific(FlagSet::OF),
        },
        OpKind::X86Adx {
            dst: rsp,
            src1: rbp,
            src2: r16,
            width: OpWidth::W64,
            kind: X86AdxKind::Adcx,
            flags: FlagUpdate::Specific(FlagSet::OF),
        },
    ] {
        assert!(matches!(
            lower_single_op_err(malformed),
            LowerError::InvalidOperand { .. } | LowerError::InvalidRegister(_)
        ));
    }
    assert!(matches!(
        lower_single_hinted_op_err(
            OpKind::X86Adx {
                dst: r16,
                src1: rsp,
                src2: rbp,
                width: OpWidth::W64,
                kind: X86AdxKind::Adcx,
                flags: FlagUpdate::None,
            },
            X86OpHint::Mulx,
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_adx_consumes_input_and_preserves_non_output_flags() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    if !std::is_x86_feature_detected!("adx") {
        return;
    }
    struct Case {
        name: &'static str,
        kind: X86AdxKind,
        flagful: bool,
        dst: X86Reg,
        src1: X86Reg,
        src2: X86Reg,
        width: OpWidth,
        src1_value: u64,
        src2_value: u64,
        status: u64,
    }
    let cases = [
        Case {
            name: "ADCX RSP,RSP,RBP consumes set CF and carries",
            kind: X86AdxKind::Adcx,
            flagful: true,
            dst: X86Reg::Rsp,
            src1: X86Reg::Rsp,
            src2: X86Reg::Rbp,
            width: OpWidth::W64,
            src1_value: u64::MAX,
            src2_value: 0,
            status: 0x8D5,
        },
        Case {
            name: "ADOX RBP,RSP,RBP destination-second-source alias",
            kind: X86AdxKind::Adox,
            flagful: true,
            dst: X86Reg::Rbp,
            src1: X86Reg::Rsp,
            src2: X86Reg::Rbp,
            width: OpWidth::W64,
            src1_value: u64::MAX,
            src2_value: 0,
            status: 0x8D5,
        },
        Case {
            name: "ADCX R16D,R31D,R31D source alias zero-extends",
            kind: X86AdxKind::Adcx,
            flagful: true,
            dst: X86Reg::R16,
            src1: X86Reg::R31,
            src2: X86Reg::R31,
            width: OpWidth::W32,
            src1_value: 0xAABB_CCDD_FFFF_FFFF,
            src2_value: 0xAABB_CCDD_FFFF_FFFF,
            status: 0x8D4,
        },
        Case {
            name: "suppressed ADOX R31,R31,R31 preserves every status flag",
            kind: X86AdxKind::Adox,
            flagful: false,
            dst: X86Reg::R31,
            src1: X86Reg::R31,
            src2: X86Reg::R31,
            width: OpWidth::W64,
            src1_value: 0x0123_4567_89AB_CDEF,
            src2_value: 0x0123_4567_89AB_CDEF,
            status: 0x8D5,
        },
    ];
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    const STATUS: u64 = 0x8D5;

    for case in cases {
        let output = match case.kind {
            X86AdxKind::Adcx => FlagSet::CF,
            X86AdxKind::Adox => FlagSet::OF,
        };
        let flags = if case.flagful {
            FlagUpdate::Specific(output)
        } else {
            FlagUpdate::None
        };
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(
            0x1000,
            OpKind::X86Adx {
                dst: x86(case.dst),
                src1: x86(case.src1),
                src2: x86(case.src2),
                width: case.width,
                kind: case.kind,
                flags,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let mut lowerer = X86_64Lowerer::new();
        let lowered = lowerer
            .lower_function(&builder.finish())
            .unwrap_or_else(|error| panic!("{} lowering: {error:?}", case.name));
        let code = lowerer
            .finalize()
            .unwrap_or_else(|error| panic!("{} finalize: {error:?}", case.name));
        let exec = ExecMem::new(&code)
            .unwrap_or_else(|error| panic!("{} executable mapping: {error:?}", case.name));

        let mut regs = GuestRegs::default();
        for (index, value) in regs.gpr.iter_mut().enumerate() {
            *value = 0x2468_0000_1357_0000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let src1_idx = case.src1.gpr_index().unwrap() as usize;
        let src2_idx = case.src2.gpr_index().unwrap() as usize;
        regs.gpr[src1_idx] = case.src1_value;
        regs.gpr[src2_idx] = case.src2_value;
        regs.rflags = 0x2 | case.status;

        let mut expected = regs;
        let src1 = regs.gpr[src1_idx] & case.width.mask();
        let src2 = regs.gpr[src2_idx] & case.width.mask();
        let input_mask = match case.kind {
            X86AdxKind::Adcx => 1,
            X86AdxKind::Adox => 1 << 11,
        };
        let carry_in = u128::from((regs.rflags & input_mask) != 0);
        let sum = u128::from(src1) + u128::from(src2) + carry_in;
        let result = (sum as u64) & case.width.mask();
        expected.gpr[dst_idx] = result;
        if case.flagful {
            expected.rflags &= !input_mask;
            expected.rflags |= u64::from(sum > u128::from(case.width.mask())) * input_mask;
        }

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        if case.width == OpWidth::W32 {
            assert_eq!(regs.gpr[dst_idx] >> 32, 0, "{} zero extension", case.name);
        }
        assert_eq!(
            regs.rflags & STATUS,
            expected.rflags & STATUS,
            "{} status flags",
            case.name
        );
    }
}
#[test]
fn lower_apx_nf_bmi_0f38_slice_lowers_without_relocs() {
    // LLVM 20 APX EVEX.0F38 NF BMI forms:
    //   {nf} andn   r8, rax, rbx       => 62 72 fc 0c f2 c3
    //   {nf} bextr  r8, rax, rbx       => 62 72 e4 0c f7 c0
    //   {nf} bzhi   r8, rax, rbx       => 62 72 e4 0c f5 c0
    //   {nf} blsi   r8, rax            => 62 f2 bc 0c f3 d8
    //   {nf} blsmsk r8, rax            => 62 f2 bc 0c f3 d0
    //   {nf} blsr   r8, rax            => 62 f2 bc 0c f3 c8
    //   {nf} bextr  r8, [rbx], rcx     => 62 72 f4 0c f7 03
    //   {nf} bzhi   r8, [rbx], rcx     => 62 72 f4 0c f5 03
    //   {nf} blsr   r8, [rbx]          => 62 f2 bc 0c f3 0b
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0x72, 0xFC, 0x0C, 0xF2, 0xC3, 0x62, 0x72, 0xE4, 0x0C, 0xF7, 0xC0, 0x62, 0x72, 0xE4,
        0x0C, 0xF5, 0xC0, 0x62, 0xF2, 0xBC, 0x0C, 0xF3, 0xD8, 0x62, 0xF2, 0xBC, 0x0C, 0xF3, 0xD0,
        0x62, 0xF2, 0xBC, 0x0C, 0xF3, 0xC8, 0x62, 0x72, 0xF4, 0x0C, 0xF7, 0x03, 0x62, 0x72, 0xF4,
        0x0C, 0xF5, 0x03, 0x62, 0xF2, 0xBC, 0x0C, 0xF3, 0x0B, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
    assert!(
        lowered.contains(&0x9C),
        "BEXTR/BZHI lowering must preserve flags"
    );
    assert!(
        lowered.contains(&0x9D),
        "BEXTR/BZHI lowering must restore flags"
    );
}
#[test]
fn lower_apx_ccmp_ctest_slice_lowers_without_relocs() {
    // LLVM 23 APX MAP4 forms:
    //   ccmpo  {dfv=cf,zf} rax, rbx => 62 f4 9c 00 39 d8
    //   ccmpnb {dfv=cf,zf} rax, 100 => 62 f4 9c 03 83 f8 64
    //   ccmpnz {dfv=of,sf} rax, [rbx] => 62 f4 e4 05 3b 03
    //   ccmpae {dfv=of,sf} qword ptr [rbx], 100
    //                                      => 62 f4 e4 03 83 3b 64
    //   ctesto {dfv=sf,of} rax, rbx => 62 f4 e4 40 85 d8
    //   ctestnz {dfv=sf,of} rax, 0xf => 62 f4 e4 45 f7 c0 0f 00 00 00
    //   ctestb {dfv=of,sf} [rbx], rcx => 62 f4 e4 02 85 0b
    //   ctests {dfv=of,sf} qword ptr [rbx], 0xf0
    //                                      => 62 f4 e4 08 f7 03 f0 00 00 00
    let (lowered, entry) = lower_rex2_block(&[
        0x62, 0xF4, 0x9C, 0x00, 0x39, 0xD8, 0x62, 0xF4, 0x9C, 0x03, 0x83, 0xF8, 0x64, 0x62, 0xF4,
        0xE4, 0x05, 0x3B, 0x03, 0x62, 0xF4, 0xE4, 0x03, 0x83, 0x3B, 0x64, 0x62, 0xF4, 0xE4, 0x40,
        0x85, 0xD8, 0x62, 0xF4, 0xE4, 0x45, 0xF7, 0xC0, 0x0F, 0x00, 0x00, 0x00, 0x62, 0xF4, 0xE4,
        0x02, 0x85, 0x0B, 0x62, 0xF4, 0xE4, 0x08, 0xF7, 0x03, 0xF0, 0x00, 0x00, 0x00, 0xF4,
    ]);
    assert!(entry < lowered.len());
    assert!(!lowered.is_empty());
    assert!(
        lowered.contains(&0x9C),
        "CCMP/CTEST lowering must read/save flags"
    );
    assert!(
        lowered.contains(&0x9D),
        "CCMP/CTEST lowering must write/restore flags"
    );
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn exec_rex2_mov_egpr_roundtrips_through_jit_state() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let imm = 0x1122_3344_5566_7788u64;
    let (lowered, entry_offset) = lower_rex2_block(&[
        0xD5, 0x18, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xD5, 0x48, 0x89, 0xC0,
        0xF4,
    ]);
    let mem = ExecMem::new(&lowered).expect("ExecMem");
    let mut regs = GuestRegs::default();
    let status = 0x8D5u64; // CF/PF/AF/ZF/SF/OF
    regs.rflags = 0x2 | status;
    regs.apx_enabled = 1;

    mem.run(entry_offset, &mut regs);

    assert_eq!(regs.gpr[16], imm, "r16 state slot");
    assert_eq!(regs.gpr[0], imm, "rax copied from r16");
    assert_eq!(
        regs.rflags & status,
        status,
        "MOV must preserve status flags"
    );
}
