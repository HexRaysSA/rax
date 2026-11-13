//! state part 2 tests

use super::*;
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;
use crate::smir::lower::x86_64::tests::*;
use crate::smir::lower::x86_64::*;

#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_scalar_count_consumes_staged_stack_source() {
    // popcnt r8w, word ptr [rbx]; hlt
    let (lowered, entry) =
        lower_rex2_block_with_mem_helpers(&[0xF3, 0x66, 0x44, 0x0F, 0xB8, 0x03, 0xF4], true);
    assert!(entry < lowered.len());
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0xF3, 0x66, 0x44, 0x0F, 0xB8, 0x04, 0x24]),
        "helper-backed POPCNT must consume the caller-owned stack word: {lowered:02X?}"
    );
    let helper_call = host_c_helper_reference(X86_GUEST_LOAD_FN_OFFSET);
    assert_eq!(
        lowered
            .windows(helper_call.len())
            .filter(|bytes| *bytes == helper_call)
            .count(),
        1,
        "memory-source count must issue exactly one load helper call"
    );
}
#[test]
fn lower_guest_rbp_mov_updates_state_and_saved_epilogue_value() {
    // `mov rbp, 0x1234` (48 C7 C5 34 12 00 00) must write GuestRegs.gpr[5]
    // and the prologue's saved guest-RBP word. Hardware RBP remains the
    // trusted frame pointer until the epilogue POP consumes that saved word.
    let (lowered, _) = lower_rex2_block(&[0x48, 0xC7, 0xC5, 0x34, 0x12, 0x00, 0x00, 0xF4]);
    assert!(
        lowered
            .windows(4)
            .any(|bytes| bytes == [0x48, 0x89, 0x50, 0x28]),
        "state-backed guest RBP store missing: {lowered:02X?}"
    );
    assert!(
        lowered
            .windows(4)
            .any(|bytes| bytes == [0x48, 0x89, 0x55, 0x00]),
        "saved guest RBP update missing: {lowered:02X?}"
    );
}
#[test]
fn lower_state_backed_gpr_rotate_emits_count_flag_contracts_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let rotate_flags = FlagSet::CF.union(FlagSet::OF);

    let one = lower_single_op(OpKind::Rol {
        dst: x86(X86Reg::Rsp),
        src: x86(X86Reg::Rbp),
        amount: SrcOperand::Imm(1),
        width: OpWidth::W64,
        flags: FlagUpdate::Specific(rotate_flags),
    });
    assert!(
        one.windows(3).any(|bytes| bytes == [0x48, 0xD1, 0xC2]),
        "state-backed ROL must rotate RDX by its immediate: {one:02X?}"
    );
    assert_eq!(
        one.iter().filter(|byte| **byte == 0x9C).count(),
        2,
        "flagful ROL must save incoming and native RFLAGS: {one:02X?}"
    );
    assert_eq!(one.iter().filter(|byte| **byte == 0x9D).count(), 1);
    assert!(
        one.windows(9)
            .any(|bytes| bytes == [0x48, 0x81, 0x64, 0x24, 0x10, 0xFE, 0xF7, 0xFF, 0xFF]),
        "count-one ROL must replace exactly CF and OF: {one:02X?}"
    );

    let dynamic = lower_single_op(OpKind::Ror {
        dst: x86(X86Reg::R31),
        src: x86(X86Reg::R16),
        amount: SrcOperand::Reg(x86(X86Reg::Rsp)),
        width: OpWidth::W8,
        flags: FlagUpdate::All,
    });
    assert!(
        dynamic.windows(2).any(|bytes| bytes == [0xD2, 0xCA]),
        "state-backed ROR must use staged CL and DL: {dynamic:02X?}"
    );
    assert!(
        dynamic
            .windows(4)
            .any(|bytes| bytes == [0x48, 0x83, 0xE7, 0x1F]),
        "byte ROR must classify the 5-bit masked count: {dynamic:02X?}"
    );
    assert!(
        dynamic
            .windows(2)
            .filter(|bytes| *bytes == [0x0F, 0x84])
            .count()
            >= 2,
        "dynamic ROR must branch on zero and one counts: {dynamic:02X?}"
    );

    let suppressed = lower_single_op(OpKind::Rol {
        dst: x86(X86Reg::Rbp),
        src: x86(X86Reg::R31),
        amount: SrcOperand::Imm(9),
        width: OpWidth::W16,
        flags: FlagUpdate::None,
    });
    assert!(
        suppressed
            .windows(4)
            .any(|bytes| bytes == [0x66, 0xC1, 0xC2, 0x09]),
        "state-backed NF ROL must use staged DX: {suppressed:02X?}"
    );
    assert_eq!(suppressed.iter().filter(|byte| **byte == 0x9C).count(), 1);
    assert_eq!(suppressed.iter().filter(|byte| **byte == 0x9D).count(), 1);
    assert!(
        suppressed
            .windows(4)
            .any(|bytes| bytes == [0x66, 0x89, 0x55, 0x00]),
        "word ROL must partially synchronize guest RBP: {suppressed:02X?}"
    );

    for malformed in [
        OpKind::Rol {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rsp),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W128,
            flags: FlagUpdate::Specific(rotate_flags),
        },
        OpKind::Ror {
            dst: x86(X86Reg::R31),
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W64,
            flags: FlagUpdate::Specific(rotate_flags),
        },
        OpKind::Rol {
            dst: x86(X86Reg::Rsp),
            src: x86(X86Reg::Rbp),
            amount: SrcOperand::Imm64(1),
            width: OpWidth::W64,
            flags: FlagUpdate::Specific(rotate_flags),
        },
        OpKind::Ror {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rbp),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W64,
            flags: FlagUpdate::Specific(FlagSet::CF),
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. } | LowerError::InvalidRegister(_)
            ),
            "malformed state-backed rotate must fail lowering"
        );
    }
    assert!(matches!(
        lower_single_hinted_op_err(
            OpKind::Rol {
                dst: x86(X86Reg::R16),
                src: x86(X86Reg::Rsp),
                amount: SrcOperand::Reg(x86(X86Reg::Rbp)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            X86OpHint::Mulx,
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_rotate_preserves_width_alias_count_and_flag_contracts() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS_MASK: u64 = 0x8D5;
    let rotate_flags = FlagSet::CF.union(FlagSet::OF);

    struct Case {
        name: &'static str,
        right: bool,
        dst: X86Reg,
        src: X86Reg,
        count_reg: Option<X86Reg>,
        immediate: i64,
        width: OpWidth,
        flags: FlagUpdate,
        source: u64,
        count: u64,
        status: u64,
    }

    let cases = [
        Case {
            name: "ROL RSP,RBP,0 preserves every flag",
            right: false,
            dst: X86Reg::Rsp,
            src: X86Reg::Rbp,
            count_reg: None,
            immediate: 0,
            width: OpWidth::W64,
            flags: FlagUpdate::Specific(rotate_flags),
            source: 0x8123_4567_89AB_CDEF,
            count: 0,
            status: 0x8D5,
        },
        Case {
            name: "ROL BPL,SPL,1 partial count-one flags",
            right: false,
            dst: X86Reg::Rbp,
            src: X86Reg::Rsp,
            count_reg: None,
            immediate: 1,
            width: OpWidth::W8,
            flags: FlagUpdate::Specific(rotate_flags),
            source: 0x2233_4455_6677_5681,
            count: 1,
            status: 0x0D4,
        },
        Case {
            name: "ROR R16B,R31B,9 preserves multi-bit OF",
            right: true,
            dst: X86Reg::R16,
            src: X86Reg::R31,
            count_reg: None,
            immediate: 9,
            width: OpWidth::W8,
            flags: FlagUpdate::All,
            source: 0xFFEE_DDCC_BBAA_1302,
            count: 9,
            status: 0x8D4,
        },
        Case {
            name: "ROL R31W,R16W,SP effective-zero updates CF",
            right: false,
            dst: X86Reg::R31,
            src: X86Reg::R16,
            count_reg: Some(X86Reg::Rsp),
            immediate: 0,
            width: OpWidth::W16,
            flags: FlagUpdate::Specific(rotate_flags),
            source: 0xAABB_CCDD_EEFF_8000,
            count: 16,
            status: 0x8D4,
        },
        Case {
            name: "ROR R16D,R16D,R16 all aliases",
            right: true,
            dst: X86Reg::R16,
            src: X86Reg::R16,
            count_reg: Some(X86Reg::R16),
            immediate: 0,
            width: OpWidth::W32,
            flags: FlagUpdate::Specific(rotate_flags),
            source: 0xAABB_CCDD_8000_0011,
            count: 0x8000_0011,
            status: 0x0D5,
        },
        Case {
            name: "NF ROR RSP,R31D,BP zero-extends and preserves flags",
            right: true,
            dst: X86Reg::Rsp,
            src: X86Reg::R31,
            count_reg: Some(X86Reg::Rbp),
            immediate: 0,
            width: OpWidth::W32,
            flags: FlagUpdate::None,
            source: 0xFFEE_DDCC_8000_0001,
            count: 1,
            status: 0x8D5,
        },
    ];

    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    for case in cases {
        let amount = case
            .count_reg
            .map_or(SrcOperand::Imm(case.immediate), |reg| {
                SrcOperand::Reg(x86(reg))
            });
        let kind = if case.right {
            OpKind::Ror {
                dst: x86(case.dst),
                src: x86(case.src),
                amount,
                width: case.width,
                flags: case.flags,
            }
        } else {
            OpKind::Rol {
                dst: x86(case.dst),
                src: x86(case.src),
                amount,
                width: case.width,
                flags: case.flags,
            }
        };
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
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
            *value = 0x1357_0000_2468_0000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let src_idx = case.src.gpr_index().unwrap() as usize;
        regs.gpr[src_idx] = case.source;
        if let Some(count_reg) = case.count_reg {
            let count_idx = count_reg.gpr_index().unwrap() as usize;
            if count_idx != src_idx {
                regs.gpr[count_idx] = case.count;
            }
        }
        regs.rflags = 0x2 | case.status;

        let mut expected = regs;
        let bits = u64::from(case.width.bits());
        let count_mask = if bits == 64 { 0x3f } else { 0x1f };
        let raw_count = case.count_reg.map_or(case.immediate as u64, |reg| {
            regs.gpr[reg.gpr_index().unwrap() as usize]
        });
        let masked = raw_count & count_mask;
        let amount = masked % bits;
        let source = regs.gpr[src_idx] & case.width.mask();
        let result = if amount == 0 {
            source
        } else if case.right {
            ((source >> amount) | (source << (bits - amount))) & case.width.mask()
        } else {
            ((source << amount) | (source >> (bits - amount))) & case.width.mask()
        };
        expected.gpr[dst_idx] = match case.width {
            OpWidth::W8 | OpWidth::W16 => (regs.gpr[dst_idx] & !case.width.mask()) | result,
            OpWidth::W32 | OpWidth::W64 => result,
            OpWidth::W128 => unreachable!(),
        };
        if case.flags.updates_any() && masked != 0 {
            let sign_bit = case.width.sign_bit();
            let cf = if case.right {
                u64::from(result & sign_bit != 0)
            } else {
                result & 1
            };
            expected.rflags = (expected.rflags & !1) | cf;
            if masked == 1 {
                let of = if case.right {
                    u64::from((result & sign_bit != 0) != (result & (sign_bit >> 1) != 0))
                } else {
                    u64::from((result & sign_bit != 0) != (cf != 0))
                };
                expected.rflags = (expected.rflags & !(1 << 11)) | (of << 11);
            }
        }

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS_MASK,
            expected.rflags & STATUS_MASK,
            "{} status flags",
            case.name
        );
    }
}
#[test]
fn lower_state_backed_gpr_shift_emits_count_flag_contracts_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));

    let one = lower_single_op(OpKind::Shl {
        dst: x86(X86Reg::Rsp),
        src: x86(X86Reg::Rbp),
        amount: SrcOperand::Imm(1),
        width: OpWidth::W64,
        flags: FlagUpdate::All,
    });
    assert!(
        one.windows(3).any(|bytes| bytes == [0x48, 0xD1, 0xE2]),
        "state-backed SHL must shift RDX by its immediate: {one:02X?}"
    );
    assert_eq!(
        one.iter().filter(|byte| **byte == 0x9C).count(),
        2,
        "flagful SHL must save incoming and native RFLAGS: {one:02X?}"
    );
    assert_eq!(one.iter().filter(|byte| **byte == 0x9D).count(), 1);
    assert!(
        one.windows(9)
            .any(|bytes| bytes == [0x48, 0x81, 0x64, 0x24, 0x18, 0x3A, 0xF7, 0xFF, 0xFF]),
        "count-one SHL must replace CF/PF/ZF/SF/OF while retaining AF: {one:02X?}"
    );

    let dynamic = lower_single_op(OpKind::Shr {
        dst: x86(X86Reg::R31),
        src: x86(X86Reg::R16),
        amount: SrcOperand::Reg(x86(X86Reg::Rsp)),
        width: OpWidth::W8,
        flags: FlagUpdate::All,
    });
    assert!(
        dynamic.windows(2).any(|bytes| bytes == [0xD2, 0xEA]),
        "state-backed SHR must use staged CL and DL: {dynamic:02X?}"
    );
    assert!(
        dynamic
            .windows(4)
            .any(|bytes| bytes == [0x48, 0x83, 0xE7, 0x1F]),
        "byte SHR must classify the 5-bit masked count: {dynamic:02X?}"
    );
    assert!(
        dynamic
            .windows(4)
            .any(|bytes| bytes == [0x48, 0x83, 0xFF, 0x08]),
        "byte SHR must classify operand-width boundary counts: {dynamic:02X?}"
    );
    assert!(
        dynamic
            .windows(2)
            .filter(|bytes| matches!(*bytes, [0x0F, 0x84] | [0x0F, 0x87]))
            .count()
            >= 4,
        "dynamic subword SHR must branch on zero/one/boundary/oversized counts: {dynamic:02X?}"
    );

    let suppressed = lower_single_op(OpKind::Sar {
        dst: x86(X86Reg::Rbp),
        src: x86(X86Reg::R31),
        amount: SrcOperand::Imm(9),
        width: OpWidth::W16,
        flags: FlagUpdate::None,
    });
    assert!(
        suppressed
            .windows(4)
            .any(|bytes| bytes == [0x66, 0xC1, 0xFA, 0x09]),
        "state-backed NF SAR must use staged DX: {suppressed:02X?}"
    );
    assert_eq!(suppressed.iter().filter(|byte| **byte == 0x9C).count(), 1);
    assert_eq!(suppressed.iter().filter(|byte| **byte == 0x9D).count(), 1);
    assert!(
        suppressed
            .windows(4)
            .any(|bytes| bytes == [0x66, 0x89, 0x55, 0x00]),
        "word SAR must partially synchronize guest RBP: {suppressed:02X?}"
    );

    for malformed in [
        OpKind::Shl {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rsp),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W128,
            flags: FlagUpdate::All,
        },
        OpKind::Shr {
            dst: x86(X86Reg::R31),
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
        OpKind::Sar {
            dst: x86(X86Reg::Rsp),
            src: x86(X86Reg::Rbp),
            amount: SrcOperand::Imm64(1),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
        OpKind::Shl {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rbp),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W64,
            flags: FlagUpdate::Specific(FlagSet::CF),
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. } | LowerError::InvalidRegister(_)
            ),
            "malformed state-backed shift must fail lowering"
        );
    }
    assert!(matches!(
        lower_single_hinted_op_err(
            OpKind::Shr {
                dst: x86(X86Reg::R16),
                src: x86(X86Reg::Rsp),
                amount: SrcOperand::Reg(x86(X86Reg::Rbp)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            X86OpHint::Mulx,
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_shift_preserves_width_alias_count_and_flag_contracts() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS_MASK: u64 = 0x8D5;

    struct Case {
        name: &'static str,
        kind: u8,
        dst: X86Reg,
        src: X86Reg,
        count_reg: Option<X86Reg>,
        immediate: i64,
        width: OpWidth,
        flags: FlagUpdate,
        source: u64,
        count: u64,
        status: u64,
    }

    let cases = [
        Case {
            name: "SHL RSP,RBP,0 preserves every flag",
            kind: 0,
            dst: X86Reg::Rsp,
            src: X86Reg::Rbp,
            count_reg: None,
            immediate: 0,
            width: OpWidth::W64,
            flags: FlagUpdate::All,
            source: 0x8123_4567_89AB_CDEF,
            count: 0,
            status: 0x8D5,
        },
        Case {
            name: "SHR BPL,SPL,1 partial count-one flags",
            kind: 1,
            dst: X86Reg::Rbp,
            src: X86Reg::Rsp,
            count_reg: None,
            immediate: 1,
            width: OpWidth::W8,
            flags: FlagUpdate::All,
            source: 0x2233_4455_6677_5681,
            count: 1,
            status: 0x0D4,
        },
        Case {
            name: "SHL R16B,R31B,8 reconstructs boundary CF",
            kind: 0,
            dst: X86Reg::R16,
            src: X86Reg::R31,
            count_reg: None,
            immediate: 8,
            width: OpWidth::W8,
            flags: FlagUpdate::All,
            source: 0xFFEE_DDCC_BBAA_1381,
            count: 8,
            status: 0x8D4,
        },
        Case {
            name: "SHR R31W,R16W,17 clears oversized CF and OF",
            kind: 1,
            dst: X86Reg::R31,
            src: X86Reg::R16,
            count_reg: None,
            immediate: 17,
            width: OpWidth::W16,
            flags: FlagUpdate::All,
            source: 0xAABB_CCDD_EEFF_8001,
            count: 17,
            status: 0x8D5,
        },
        Case {
            name: "SAR R16B,R31B,9 reconstructs oversized sign CF",
            kind: 2,
            dst: X86Reg::R16,
            src: X86Reg::R31,
            count_reg: None,
            immediate: 9,
            width: OpWidth::W8,
            flags: FlagUpdate::All,
            source: 0xFFEE_DDCC_BBAA_1381,
            count: 9,
            status: 0x0D4,
        },
        Case {
            name: "SAR R31W,R16W,SP dynamic boundary",
            kind: 2,
            dst: X86Reg::R31,
            src: X86Reg::R16,
            count_reg: Some(X86Reg::Rsp),
            immediate: 0,
            width: OpWidth::W16,
            flags: FlagUpdate::All,
            source: 0xAABB_CCDD_EEFF_8001,
            count: 16,
            status: 0x8D4,
        },
        Case {
            name: "SHL R16D,R16D,R16 all aliases",
            kind: 0,
            dst: X86Reg::R16,
            src: X86Reg::R16,
            count_reg: Some(X86Reg::R16),
            immediate: 0,
            width: OpWidth::W32,
            flags: FlagUpdate::All,
            source: 0xAABB_CCDD_8000_0001,
            count: 0x8000_0001,
            status: 0x0D5,
        },
        Case {
            name: "NF SAR RSP,R31D,BP zero-extends and preserves flags",
            kind: 2,
            dst: X86Reg::Rsp,
            src: X86Reg::R31,
            count_reg: Some(X86Reg::Rbp),
            immediate: 0,
            width: OpWidth::W32,
            flags: FlagUpdate::None,
            source: 0xFFEE_DDCC_8000_0001,
            count: 1,
            status: 0x8D5,
        },
    ];

    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    for case in cases {
        let amount = case
            .count_reg
            .map_or(SrcOperand::Imm(case.immediate), |reg| {
                SrcOperand::Reg(x86(reg))
            });
        let kind = match case.kind {
            0 => OpKind::Shl {
                dst: x86(case.dst),
                src: x86(case.src),
                amount,
                width: case.width,
                flags: case.flags,
            },
            1 => OpKind::Shr {
                dst: x86(case.dst),
                src: x86(case.src),
                amount,
                width: case.width,
                flags: case.flags,
            },
            2 => OpKind::Sar {
                dst: x86(case.dst),
                src: x86(case.src),
                amount,
                width: case.width,
                flags: case.flags,
            },
            _ => unreachable!(),
        };
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
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
            *value = 0x1357_0000_2468_0000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let src_idx = case.src.gpr_index().unwrap() as usize;
        regs.gpr[src_idx] = case.source;
        if let Some(count_reg) = case.count_reg {
            let count_idx = count_reg.gpr_index().unwrap() as usize;
            if count_idx != src_idx {
                regs.gpr[count_idx] = case.count;
            }
        }
        regs.rflags = 0x2 | case.status;

        let mut expected = regs;
        let bits = u64::from(case.width.bits());
        let count_mask = if bits == 64 { 0x3f } else { 0x1f };
        let raw_count = case.count_reg.map_or(case.immediate as u64, |reg| {
            regs.gpr[reg.gpr_index().unwrap() as usize]
        });
        let count = raw_count & count_mask;
        let source = regs.gpr[src_idx] & case.width.mask();
        let signed_source = if source & case.width.sign_bit() != 0 {
            source | !case.width.mask()
        } else {
            source
        };
        let result = if count >= bits {
            if case.kind == 2 && (signed_source as i64) < 0 {
                case.width.mask()
            } else {
                0
            }
        } else {
            match case.kind {
                0 => (source << count) & case.width.mask(),
                1 => source >> count,
                2 => ((signed_source as i64 >> count) as u64) & case.width.mask(),
                _ => unreachable!(),
            }
        };
        expected.gpr[dst_idx] = match case.width {
            OpWidth::W8 | OpWidth::W16 => (regs.gpr[dst_idx] & !case.width.mask()) | result,
            OpWidth::W32 | OpWidth::W64 => result,
            OpWidth::W128 => unreachable!(),
        };
        if case.flags.updates_any() && count != 0 {
            let cf = match case.kind {
                0 if count <= bits => (source >> (bits - count)) & 1,
                0 => 0,
                1 => (source >> (count - 1)) & 1,
                2 => (signed_source >> (count - 1)) & 1,
                _ => unreachable!(),
            };
            expected.rflags = (expected.rflags & !1) | cf;
            let pf = u64::from((result as u8).count_ones().is_multiple_of(2));
            expected.rflags = (expected.rflags & !(1 << 2)) | (pf << 2);
            let zf = u64::from(result == 0);
            expected.rflags = (expected.rflags & !(1 << 6)) | (zf << 6);
            let sf = u64::from(result & case.width.sign_bit() != 0);
            expected.rflags = (expected.rflags & !(1 << 7)) | (sf << 7);
            let of = if count == 1 {
                match case.kind {
                    0 => u64::from((cf != 0) != (sf != 0)),
                    1 => u64::from(source & case.width.sign_bit() != 0),
                    2 => 0,
                    _ => unreachable!(),
                }
            } else {
                0
            };
            expected.rflags = (expected.rflags & !(1 << 11)) | (of << 11);
        }

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS_MASK,
            expected.rflags & STATUS_MASK,
            "{} status flags",
            case.name
        );
    }
}

#[test]
fn lower_state_backed_gpr_double_shift_emits_guarded_flag_contracts_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));

    let one = lower_single_op(OpKind::Shld {
        dst: x86(X86Reg::Rsp),
        src: x86(X86Reg::Rbp),
        amount: SrcOperand::Imm(1),
        width: OpWidth::W64,
        flags: FlagUpdate::All,
    });
    assert!(
        one.windows(5)
            .any(|bytes| bytes == [0x48, 0x0F, 0xA4, 0xF2, 0x01]),
        "state-backed SHLD must shift staged RDX with RSI: {one:02X?}"
    );
    assert_eq!(one.iter().filter(|byte| **byte == 0x9C).count(), 2);
    assert_eq!(one.iter().filter(|byte| **byte == 0x9D).count(), 1);

    let dynamic = lower_single_op(OpKind::Shrd {
        dst: x86(X86Reg::R31),
        src: x86(X86Reg::R16),
        amount: SrcOperand::Reg(x86(X86Reg::Rsp)),
        width: OpWidth::W16,
        flags: FlagUpdate::All,
    });
    assert!(
        dynamic
            .windows(4)
            .any(|bytes| bytes == [0x66, 0x0F, 0xAD, 0xF2]),
        "state-backed SHRD must use staged DX, SI, and CL: {dynamic:02X?}"
    );
    assert!(
        dynamic
            .windows(4)
            .any(|bytes| bytes == [0x48, 0x83, 0xFF, 0x10]),
        "word SHRD must guard counts above the defined width: {dynamic:02X?}"
    );
    assert!(
        dynamic.windows(2).any(|bytes| bytes == [0x0F, 0x87]),
        "word SHRD must branch around undefined host counts: {dynamic:02X?}"
    );
    assert!(
        dynamic
            .windows(9)
            .any(|bytes| bytes == [0x48, 0x81, 0x64, 0x24, 0x18, 0xFF, 0xF7, 0xFF, 0xFF]),
        "multi-bit SHRD must clear deterministic OF: {dynamic:02X?}"
    );

    let suppressed = lower_single_op(OpKind::Shld {
        dst: x86(X86Reg::Rbp),
        src: x86(X86Reg::R31),
        amount: SrcOperand::Reg(x86(X86Reg::Rsp)),
        width: OpWidth::W16,
        flags: FlagUpdate::None,
    });
    assert_eq!(suppressed.iter().filter(|byte| **byte == 0x9C).count(), 1);
    assert_eq!(suppressed.iter().filter(|byte| **byte == 0x9D).count(), 2);
    assert!(
        suppressed
            .windows(4)
            .any(|bytes| bytes == [0x66, 0x89, 0x55, 0x00]),
        "word SHLD must partially synchronize guest RBP: {suppressed:02X?}"
    );

    let ndd = lower_single_op(OpKind::X86NddDoubleShift {
        dst: x86(X86Reg::R16),
        base: x86(X86Reg::Rsp),
        fill: x86(X86Reg::R31),
        amount: SrcOperand::Imm(4),
        width: OpWidth::W64,
        left: true,
        flags: FlagUpdate::All,
    });
    assert!(
        ndd.windows(5)
            .any(|bytes| bytes == [0x48, 0x0F, 0xA4, 0xF2, 0x04]),
        "state-backed NDD SHLD must shift staged base RDX with fill RSI: {ndd:02X?}"
    );
    assert!(
        ndd.windows(4)
            .any(|bytes| bytes == [0x48, 0x8B, 0x50, 0x20]),
        "state-backed NDD SHLD must load guest RSP as its independent base: {ndd:02X?}"
    );

    let guarded_ndd = lower_single_op(OpKind::X86NddDoubleShift {
        dst: x86(X86Reg::Rdx),
        base: x86(X86Reg::Rax),
        fill: x86(X86Reg::Rbx),
        amount: SrcOperand::Imm(17),
        width: OpWidth::W16,
        left: true,
        flags: FlagUpdate::All,
    });
    assert!(
        !guarded_ndd
            .windows(5)
            .any(|bytes| bytes == [0x66, 0x0F, 0xA4, 0xF2, 0x11]),
        "W16 NDD count above the width must not execute the host instruction: {guarded_ndd:02X?}"
    );
    assert_eq!(guarded_ndd.iter().filter(|byte| **byte == 0x9C).count(), 1);
    assert_eq!(guarded_ndd.iter().filter(|byte| **byte == 0x9D).count(), 1);

    let guarded_legacy = lower_single_op(OpKind::Shld {
        dst: x86(X86Reg::Rax),
        src: x86(X86Reg::Rbx),
        amount: SrcOperand::Imm(17),
        width: OpWidth::W16,
        flags: FlagUpdate::All,
    });
    assert!(
        !guarded_legacy
            .windows(5)
            .any(|bytes| bytes == [0x66, 0x0F, 0xA4, 0xF2, 0x11]),
        "W16 legacy count above the width must not execute the host instruction: {guarded_legacy:02X?}"
    );

    let dynamic_legacy = lower_single_op(OpKind::Shrd {
        dst: x86(X86Reg::Rax),
        src: x86(X86Reg::Rbx),
        amount: SrcOperand::Reg(x86(X86Reg::Rcx)),
        width: OpWidth::W16,
        flags: FlagUpdate::None,
    });
    assert!(
        dynamic_legacy
            .windows(4)
            .any(|bytes| bytes == [0x66, 0x0F, 0xAD, 0xF2]),
        "dynamic W16 legacy SHRD must use the staged register form: {dynamic_legacy:02X?}"
    );
    assert!(
        dynamic_legacy
            .windows(4)
            .any(|bytes| bytes == [0x48, 0x83, 0xFF, 0x10]),
        "dynamic W16 legacy SHRD must guard counts above the width: {dynamic_legacy:02X?}"
    );

    for malformed in [
        OpKind::Shld {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rsp),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W8,
            flags: FlagUpdate::All,
        },
        OpKind::Shrd {
            dst: x86(X86Reg::R31),
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
        OpKind::Shld {
            dst: x86(X86Reg::Rsp),
            src: x86(X86Reg::Rbp),
            amount: SrcOperand::Imm64(1),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
        OpKind::Shrd {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rbp),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W64,
            flags: FlagUpdate::Specific(FlagSet::ZF),
        },
        OpKind::X86NddDoubleShift {
            dst: x86(X86Reg::R16),
            base: x86(X86Reg::Rsp),
            fill: x86(X86Reg::R31),
            amount: SrcOperand::Reg(x86(X86Reg::Rbp)),
            width: OpWidth::W64,
            left: true,
            flags: FlagUpdate::All,
        },
        OpKind::X86NddDoubleShift {
            dst: x86(X86Reg::R16),
            base: x86(X86Reg::Rsp),
            fill: x86(X86Reg::R31),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W64,
            left: false,
            flags: FlagUpdate::Specific(FlagSet::ZF),
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. } | LowerError::InvalidRegister(_)
            ),
            "malformed state-backed double shift must fail lowering"
        );
    }
    assert!(matches!(
        lower_single_hinted_op_err(
            OpKind::Shld {
                dst: x86(X86Reg::R16),
                src: x86(X86Reg::Rsp),
                amount: SrcOperand::Reg(x86(X86Reg::Rbp)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            X86OpHint::Mulx,
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_double_shift_preserves_alias_count_and_flag_contracts() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS_MASK: u64 = 0x8D5;

    struct Case {
        name: &'static str,
        left: bool,
        dst: X86Reg,
        src: X86Reg,
        count_reg: Option<X86Reg>,
        immediate: i64,
        width: OpWidth,
        flags: FlagUpdate,
        base: u64,
        fill: u64,
        count: u64,
        status: u64,
    }

    let cases = [
        Case {
            name: "SHLD RSP,RBP,0 preserves every flag",
            left: true,
            dst: X86Reg::Rsp,
            src: X86Reg::Rbp,
            count_reg: None,
            immediate: 0,
            width: OpWidth::W64,
            flags: FlagUpdate::All,
            base: 0x8123_4567_89AB_CDEF,
            fill: 0x1020_3040_5060_7080,
            count: 0,
            status: 0x8D5,
        },
        Case {
            name: "SHLD BP,SP,1 partial count-one flags",
            left: true,
            dst: X86Reg::Rbp,
            src: X86Reg::Rsp,
            count_reg: None,
            immediate: 1,
            width: OpWidth::W16,
            flags: FlagUpdate::All,
            base: 0x3344_5566_8765_4000,
            fill: 0x2233_4455_6677_8001,
            count: 1,
            status: 0x8D5,
        },
        Case {
            name: "SHRD R16W,R31W,17 immediate undefined no-op",
            left: false,
            dst: X86Reg::R16,
            src: X86Reg::R31,
            count_reg: None,
            immediate: 17,
            width: OpWidth::W16,
            flags: FlagUpdate::All,
            base: 0xAABB_CCDD_EEFF_1357,
            fill: 0xFFEE_DDCC_BBAA_2468,
            count: 17,
            status: 0x0D5,
        },
        Case {
            name: "SHLD R31W,R16W,SP dynamic undefined no-op",
            left: true,
            dst: X86Reg::R31,
            src: X86Reg::R16,
            count_reg: Some(X86Reg::Rsp),
            immediate: 0,
            width: OpWidth::W16,
            flags: FlagUpdate::All,
            base: 0xFFEE_DDCC_BBAA_1357,
            fill: 0xAABB_CCDD_EEFF_2468,
            count: 17,
            status: 0x8D5,
        },
        Case {
            name: "SHRD R16D all operands alias",
            left: false,
            dst: X86Reg::R16,
            src: X86Reg::R16,
            count_reg: Some(X86Reg::R16),
            immediate: 0,
            width: OpWidth::W32,
            flags: FlagUpdate::All,
            base: 0xAABB_CCDD_8000_0001,
            fill: 0,
            count: 0,
            status: 0x0D5,
        },
        Case {
            name: "NF SHRD RSP,R31D,BP preserves flags and zero-extends",
            left: false,
            dst: X86Reg::Rsp,
            src: X86Reg::R31,
            count_reg: Some(X86Reg::Rbp),
            immediate: 0,
            width: OpWidth::W32,
            flags: FlagUpdate::None,
            base: 0x2233_4455_8000_0001,
            fill: 0xFFEE_DDCC_2468_1357,
            count: 4,
            status: 0x8D5,
        },
        Case {
            name: "SHRD RAX,RDX,BP stages only the count",
            left: false,
            dst: X86Reg::Rax,
            src: X86Reg::Rdx,
            count_reg: Some(X86Reg::Rbp),
            immediate: 0,
            width: OpWidth::W64,
            flags: FlagUpdate::All,
            base: 0x8123_4567_89AB_CDEF,
            fill: 0x1020_3040_5060_7080,
            count: 9,
            status: 0x8D5,
        },
        Case {
            name: "SHLD RBX,R31,7 stages only the fill",
            left: true,
            dst: X86Reg::Rbx,
            src: X86Reg::R31,
            count_reg: None,
            immediate: 7,
            width: OpWidth::W64,
            flags: FlagUpdate::All,
            base: 0x0123_4567_89AB_CDEF,
            fill: 0xFEDC_BA98_7654_3210,
            count: 7,
            status: 0x0D5,
        },
    ];

    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    for case in cases {
        let amount = case
            .count_reg
            .map_or(SrcOperand::Imm(case.immediate), |reg| {
                SrcOperand::Reg(x86(reg))
            });
        let kind = if case.left {
            OpKind::Shld {
                dst: x86(case.dst),
                src: x86(case.src),
                amount,
                width: case.width,
                flags: case.flags,
            }
        } else {
            OpKind::Shrd {
                dst: x86(case.dst),
                src: x86(case.src),
                amount,
                width: case.width,
                flags: case.flags,
            }
        };
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
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
            *value = 0x1357_0000_2468_0000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let src_idx = case.src.gpr_index().unwrap() as usize;
        regs.gpr[dst_idx] = case.base;
        if src_idx != dst_idx {
            regs.gpr[src_idx] = case.fill;
        }
        if let Some(count_reg) = case.count_reg {
            let count_idx = count_reg.gpr_index().unwrap() as usize;
            if count_idx != dst_idx && count_idx != src_idx {
                regs.gpr[count_idx] = case.count;
            }
        }
        regs.rflags = 0x2 | case.status;

        let mut expected = regs;
        let bits = u64::from(case.width.bits());
        let count_mask = if bits == 64 { 0x3f } else { 0x1f };
        let raw_count = case.count_reg.map_or(case.immediate as u64, |reg| {
            regs.gpr[reg.gpr_index().unwrap() as usize]
        });
        let masked = raw_count & count_mask;
        let base = regs.gpr[dst_idx] & case.width.mask();
        let fill = regs.gpr[src_idx] & case.width.mask();
        let defined = masked != 0 && masked <= bits;
        let result = if !defined {
            base
        } else if case.left {
            ((base << masked) | (fill >> (bits - masked))) & case.width.mask()
        } else {
            ((base >> masked) | (fill << (bits - masked))) & case.width.mask()
        };
        expected.gpr[dst_idx] = match case.width {
            OpWidth::W16 => (regs.gpr[dst_idx] & !case.width.mask()) | result,
            OpWidth::W32 | OpWidth::W64 => result,
            OpWidth::W8 | OpWidth::W128 => unreachable!(),
        };
        if case.flags.updates_any() && defined {
            let cf = if case.left {
                (base >> (bits - masked)) & 1
            } else {
                (base >> (masked - 1)) & 1
            };
            expected.rflags = (expected.rflags & !1) | cf;
            let pf = u64::from((result as u8).count_ones().is_multiple_of(2));
            expected.rflags = (expected.rflags & !(1 << 2)) | (pf << 2);
            expected.rflags = (expected.rflags & !(1 << 6)) | (u64::from(result == 0) << 6);
            expected.rflags = (expected.rflags & !(1 << 7))
                | (u64::from(result & case.width.sign_bit() != 0) << 7);
            let of = u64::from(masked == 1 && ((result ^ base) & case.width.sign_bit()) != 0);
            expected.rflags = (expected.rflags & !(1 << 11)) | (of << 11);
        }

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS_MASK,
            expected.rflags & STATUS_MASK,
            "{} status flags",
            case.name
        );
    }
}
#[test]
fn lower_state_backed_gpr_count_emits_flag_contracts_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let flagless = lower_single_op(OpKind::X86Count {
        dst: x86(X86Reg::R31),
        src: x86(X86Reg::Rbp),
        width: OpWidth::W32,
        kind: X86CountKind::Lzcnt,
        flags: FlagUpdate::None,
    });
    assert!(
        flagless.contains(&0x9C) && flagless.contains(&0x9D),
        "APX NF LZCNT must preserve RFLAGS: {flagless:02X?}"
    );
    assert!(
        flagless
            .windows(4)
            .any(|bytes| bytes == [0xF3, 0x0F, 0xBD, 0xD2]),
        "dword LZCNT must count EDX into EDX: {flagless:02X?}"
    );
    assert!(
        flagless
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0xF8, 0x00, 0x00, 0x00]),
        "dword LZCNT must fully commit GuestRegs.gpr[31]: {flagless:02X?}"
    );

    let popcnt_all = lower_single_op(OpKind::X86Count {
        dst: x86(X86Reg::Rbp),
        src: x86(X86Reg::Rsp),
        width: OpWidth::W16,
        kind: X86CountKind::Popcnt,
        flags: FlagUpdate::All,
    });
    assert!(
        !popcnt_all.contains(&0x9C) && !popcnt_all.contains(&0x9D),
        "flag-setting POPCNT must leave native flags live: {popcnt_all:02X?}"
    );
    assert!(
        popcnt_all
            .windows(5)
            .any(|bytes| bytes == [0xF3, 0x66, 0x0F, 0xB8, 0xD2]),
        "word POPCNT must count DX into DX: {popcnt_all:02X?}"
    );
    assert!(
        popcnt_all
            .windows(4)
            .any(|bytes| bytes == [0x66, 0x89, 0x55, 0x00]),
        "word POPCNT must partially synchronize guest RBP: {popcnt_all:02X?}"
    );

    let tzcnt_flags = lower_single_op(OpKind::X86Count {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rbp),
        width: OpWidth::W64,
        kind: X86CountKind::Tzcnt,
        flags: FlagUpdate::Specific(FlagSet::CF.union(FlagSet::ZF)),
    });
    assert_eq!(
        tzcnt_flags.iter().filter(|byte| **byte == 0x9C).count(),
        2,
        "state-backed TZCNT must save old and new RFLAGS: {tzcnt_flags:02X?}"
    );
    assert_eq!(tzcnt_flags.iter().filter(|byte| **byte == 0x9D).count(), 1);
    assert!(tzcnt_flags.contains(&0x41), "TZCNT must merge CF and ZF");

    for malformed in [
        OpKind::X86Count {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W8,
            kind: X86CountKind::Popcnt,
            flags: FlagUpdate::All,
        },
        OpKind::X86Count {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W64,
            kind: X86CountKind::Lzcnt,
            flags: FlagUpdate::All,
        },
        OpKind::X86Count {
            dst: x86(X86Reg::R16),
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            width: OpWidth::W64,
            kind: X86CountKind::Tzcnt,
            flags: FlagUpdate::None,
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. }
            ),
            "malformed state-backed count must fail lowering"
        );
    }

    let hinted = OpKind::X86Count {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rax),
        width: OpWidth::W64,
        kind: X86CountKind::Popcnt,
        flags: FlagUpdate::All,
    };
    assert!(matches!(
        lower_single_hinted_op_err(hinted, X86OpHint::Mulx),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_count_preserves_width_and_flag_contracts() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS_MASK: u64 = 0x8D5;

    struct Case {
        name: &'static str,
        dst: X86Reg,
        src: X86Reg,
        source: u64,
        width: OpWidth,
        kind: X86CountKind,
        flags: FlagUpdate,
    }

    let cases = [
        Case {
            name: "POPCNT BP,SP partial flag-setting destination",
            dst: X86Reg::Rbp,
            src: X86Reg::Rsp,
            source: 0x2233_4455_6677_5678,
            width: OpWidth::W16,
            kind: X86CountKind::Popcnt,
            flags: FlagUpdate::All,
        },
        Case {
            name: "TZCNT RSP,RBP full flag-merge destination",
            dst: X86Reg::Rsp,
            src: X86Reg::Rbp,
            source: 0,
            width: OpWidth::W64,
            kind: X86CountKind::Tzcnt,
            flags: FlagUpdate::Specific(FlagSet::CF.union(FlagSet::ZF)),
        },
        Case {
            name: "NF LZCNT R31D,R16D zero-extending destination",
            dst: X86Reg::R31,
            src: X86Reg::R16,
            source: 0xAABB_CCDD_8000_0000,
            width: OpWidth::W32,
            kind: X86CountKind::Lzcnt,
            flags: FlagUpdate::None,
        },
        Case {
            name: "POPCNT R16D in-place selective ZF destination",
            dst: X86Reg::R16,
            src: X86Reg::R16,
            source: 0,
            width: OpWidth::W32,
            kind: X86CountKind::Popcnt,
            flags: FlagUpdate::Specific(FlagSet::ZF),
        },
        Case {
            name: "NF TZCNT R16W,SP partial destination",
            dst: X86Reg::R16,
            src: X86Reg::Rsp,
            source: 0x2233_4455_6677_0080,
            width: OpWidth::W16,
            kind: X86CountKind::Tzcnt,
            flags: FlagUpdate::None,
        },
    ];

    let count_result = |source: u64, width: OpWidth, kind: X86CountKind| {
        let value = source & width.mask();
        match kind {
            X86CountKind::Popcnt => u64::from(value.count_ones()),
            X86CountKind::Tzcnt => u64::from(if value == 0 {
                width.bits()
            } else {
                value.trailing_zeros()
            }),
            X86CountKind::Lzcnt => u64::from(if value == 0 {
                width.bits()
            } else {
                value.leading_zeros() - (64 - width.bits())
            }),
        }
    };
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    for case in cases {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(
            0x1000,
            OpKind::X86Count {
                dst: x86(case.dst),
                src: x86(case.src),
                width: case.width,
                kind: case.kind,
                flags: case.flags,
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
            *value = 0xA1A2_0000_0000_8000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        regs.gpr[4] = 0x2233_4455_6677_5678;
        regs.gpr[5] = 0x3344_5566_8765_9ABC;
        regs.gpr[16] = 0xAABB_CCDD_EEFF_7788;
        regs.gpr[31] = 0xFFEE_DDCC_BBAA_1357;
        let src_idx = case.src.gpr_index().unwrap() as usize;
        regs.gpr[src_idx] = case.source;
        regs.rflags = STATUS_MASK;

        let mut expected = regs;
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let source = regs.gpr[src_idx];
        let result = count_result(source, case.width, case.kind);
        expected.gpr[dst_idx] = match case.width {
            OpWidth::W16 => (regs.gpr[dst_idx] & !case.width.mask()) | result,
            OpWidth::W32 | OpWidth::W64 => result,
            OpWidth::W8 | OpWidth::W128 => unreachable!(),
        };
        let requested = case.flags.as_set();
        if !requested.is_empty() {
            let new_status = match case.kind {
                X86CountKind::Popcnt => u64::from(source & case.width.mask() == 0) << 6,
                X86CountKind::Tzcnt | X86CountKind::Lzcnt => {
                    u64::from(source & case.width.mask() == 0) | (u64::from(result == 0) << 6)
                }
            };
            let requested_mask = X86_64Lowerer::x86_status_rflags_mask(requested) as u64;
            expected.rflags = (expected.rflags & !requested_mask) | (new_status & requested_mask);
        }

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS_MASK,
            expected.rflags & STATUS_MASK,
            "{} status flags",
            case.name
        );
    }
}
#[test]
fn lower_state_backed_gpr_bit_scan_restores_zero_destination_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let zf_only = FlagUpdate::Specific(FlagSet::ZF);

    let flagful = lower_single_op(OpKind::Bsf {
        dst: x86(X86Reg::Rsp),
        src: x86(X86Reg::Rbp),
        width: OpWidth::W64,
        flags: zf_only,
    });
    assert!(
        flagful
            .windows(4)
            .any(|bytes| bytes == [0x48, 0x0F, 0xBC, 0xD2]),
        "state-backed BSF must scan RDX in place: {flagful:02X?}"
    );
    assert!(
        flagful.windows(2).any(|bytes| bytes == [0x0F, 0x85]),
        "state-backed BSF must branch around zero-source restoration: {flagful:02X?}"
    );
    assert_eq!(
        flagful
            .windows(4)
            .filter(|bytes| *bytes == [0x48, 0x8B, 0x50, 0x28])
            .count(),
        1,
        "BSF must load RBP source once: {flagful:02X?}"
    );
    assert_eq!(
        flagful
            .windows(4)
            .filter(|bytes| *bytes == [0x48, 0x8B, 0x50, 0x20])
            .count(),
        1,
        "zero-source BSF must restore the retained RSP destination: {flagful:02X?}"
    );
    assert_eq!(
        flagful.iter().filter(|byte| **byte == 0x9C).count(),
        2,
        "ZF-only BSF must save old and new RFLAGS: {flagful:02X?}"
    );
    assert_eq!(flagful.iter().filter(|byte| **byte == 0x9D).count(), 1);

    let flagless = lower_single_op(OpKind::Bsr {
        dst: x86(X86Reg::R31),
        src: x86(X86Reg::Rsp),
        width: OpWidth::W32,
        flags: FlagUpdate::None,
    });
    assert!(
        flagless.windows(3).any(|bytes| bytes == [0x0F, 0xBD, 0xD2]),
        "state-backed BSR must scan EDX in place: {flagless:02X?}"
    );
    assert_eq!(
        flagless.iter().filter(|byte| **byte == 0x9C).count(),
        1,
        "flag-suppressed BSR must save RFLAGS once: {flagless:02X?}"
    );
    assert_eq!(flagless.iter().filter(|byte| **byte == 0x9D).count(), 1);
    assert!(
        flagless
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0xF8, 0x00, 0x00, 0x00]),
        "dword BSR must fully commit GuestRegs.gpr[31]: {flagless:02X?}"
    );

    for malformed in [
        OpKind::Bsf {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W8,
            flags: zf_only,
        },
        OpKind::Bsr {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
        OpKind::Bsf {
            dst: x86(X86Reg::R16),
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            width: OpWidth::W64,
            flags: zf_only,
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. }
            ),
            "malformed state-backed bit scan must fail lowering"
        );
    }

    let hinted = OpKind::Bsr {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rax),
        width: OpWidth::W64,
        flags: zf_only,
    };
    assert!(matches!(
        lower_single_hinted_op_err(hinted, X86OpHint::Mulx),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_bit_scan_preserves_width_zero_and_flag_contracts() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS_MASK: u64 = 0x8D5;

    struct Case {
        name: &'static str,
        dst: X86Reg,
        src: X86Reg,
        source: u64,
        width: OpWidth,
        reverse: bool,
        flags: FlagUpdate,
    }

    let zf_only = FlagUpdate::Specific(FlagSet::ZF);
    let cases = [
        Case {
            name: "BSF BP,SP partial destination",
            dst: X86Reg::Rbp,
            src: X86Reg::Rsp,
            source: 0x2233_4455_6677_8000,
            width: OpWidth::W16,
            reverse: false,
            flags: zf_only,
        },
        Case {
            name: "BSR RSP,RBP full destination",
            dst: X86Reg::Rsp,
            src: X86Reg::Rbp,
            source: 1u64 << 63,
            width: OpWidth::W64,
            reverse: true,
            flags: zf_only,
        },
        Case {
            name: "BSF R31,R16 extended destination",
            dst: X86Reg::R31,
            src: X86Reg::R16,
            source: 0x100,
            width: OpWidth::W64,
            reverse: false,
            flags: zf_only,
        },
        Case {
            name: "flag-suppressed zero BSR R16D,R16D alias",
            dst: X86Reg::R16,
            src: X86Reg::R16,
            source: 0,
            width: OpWidth::W32,
            reverse: true,
            flags: FlagUpdate::None,
        },
        Case {
            name: "zero BSF R16W,SP partial destination",
            dst: X86Reg::R16,
            src: X86Reg::Rsp,
            source: 0,
            width: OpWidth::W16,
            reverse: false,
            flags: zf_only,
        },
    ];

    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    for case in cases {
        let kind = if case.reverse {
            OpKind::Bsr {
                dst: x86(case.dst),
                src: x86(case.src),
                width: case.width,
                flags: case.flags,
            }
        } else {
            OpKind::Bsf {
                dst: x86(case.dst),
                src: x86(case.src),
                width: case.width,
                flags: case.flags,
            }
        };
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
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
            *value = 0xA1A2_0000_0000_8000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        regs.gpr[4] = 0x2233_4455_6677_5678;
        regs.gpr[5] = 0x3344_5566_8765_9ABC;
        regs.gpr[16] = 0xAABB_CCDD_EEFF_7788;
        regs.gpr[31] = 0xFFEE_DDCC_BBAA_1357;
        let src_idx = case.src.gpr_index().unwrap() as usize;
        regs.gpr[src_idx] = case.source;
        regs.rflags = STATUS_MASK;

        let mut expected = regs;
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let value = case.source & case.width.mask();
        let result = if value == 0 {
            None
        } else if case.reverse {
            Some(u64::from(case.width.bits() - 1 - value.leading_zeros()))
        } else {
            Some(u64::from(value.trailing_zeros()))
        };
        if let Some(result) = result {
            expected.gpr[dst_idx] = match case.width {
                OpWidth::W16 => (regs.gpr[dst_idx] & !case.width.mask()) | result,
                OpWidth::W32 | OpWidth::W64 => result,
                OpWidth::W8 | OpWidth::W128 => unreachable!(),
            };
        }
        if case.flags.updates_any() {
            let zf = u64::from(value == 0) << 6;
            expected.rflags = (expected.rflags & !(1 << 6)) | zf;
        }

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS_MASK,
            expected.rflags & STATUS_MASK,
            "{} status flags",
            case.name
        );
    }
}
#[test]
fn lower_state_backed_gpr_neg_emits_flag_contracts_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let flagless = lower_single_op(OpKind::Neg {
        dst: x86(X86Reg::Rbp),
        src: x86(X86Reg::R16),
        width: OpWidth::W8,
        flags: FlagUpdate::None,
    });
    assert!(
        flagless.contains(&0x9C) && flagless.contains(&0x9D),
        "APX NF Neg must preserve RFLAGS: {flagless:02X?}"
    );
    assert!(
        flagless.windows(2).any(|bytes| bytes == [0xF6, 0xDA]),
        "byte Neg must negate DL: {flagless:02X?}"
    );
    assert!(
        flagless.windows(3).any(|bytes| bytes == [0x88, 0x55, 0x00]),
        "byte Neg must partially synchronize guest RBP: {flagless:02X?}"
    );

    let flagful = lower_single_op(OpKind::Neg {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rsp),
        width: OpWidth::W32,
        flags: FlagUpdate::All,
    });
    assert!(
        !flagful.contains(&0x9C) && !flagful.contains(&0x9D),
        "flag-setting Neg must leave native flags live: {flagful:02X?}"
    );
    assert!(
        flagful.windows(2).any(|bytes| bytes == [0xF7, 0xDA]),
        "dword Neg must negate EDX: {flagful:02X?}"
    );
    assert!(
        flagful
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "dword Neg must fully commit GuestRegs.gpr[16]: {flagful:02X?}"
    );

    for malformed in [
        OpKind::Neg {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W128,
            flags: FlagUpdate::All,
        },
        OpKind::Neg {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W64,
            flags: FlagUpdate::Specific(FlagSet::CF),
        },
        OpKind::Neg {
            dst: x86(X86Reg::R16),
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. }
            ),
            "malformed state-backed Neg must fail lowering"
        );
    }

    let hinted = OpKind::Neg {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rax),
        width: OpWidth::W64,
        flags: FlagUpdate::All,
    };
    assert!(matches!(
        lower_single_hinted_op_err(hinted, X86OpHint::Mulx),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_neg_preserves_width_and_flag_contracts() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS_MASK: u64 = 0x8D5;

    struct Case {
        name: &'static str,
        dst: X86Reg,
        src: X86Reg,
        width: OpWidth,
        flags: FlagUpdate,
    }

    let cases = [
        Case {
            name: "NEG BPL,R16B partial flag-setting destination",
            dst: X86Reg::Rbp,
            src: X86Reg::R16,
            width: OpWidth::W8,
            flags: FlagUpdate::All,
        },
        Case {
            name: "NF NEG R16W,SP partial destination",
            dst: X86Reg::R16,
            src: X86Reg::Rsp,
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        Case {
            name: "NEG RSP in-place full destination",
            dst: X86Reg::Rsp,
            src: X86Reg::Rsp,
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
        Case {
            name: "NEG R31D,EBP zero-extending destination",
            dst: X86Reg::R31,
            src: X86Reg::Rbp,
            width: OpWidth::W32,
            flags: FlagUpdate::All,
        },
        Case {
            name: "NF NEG R16D in-place zero-extending destination",
            dst: X86Reg::R16,
            src: X86Reg::R16,
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
    ];

    let neg_status = |source: u64, width: OpWidth| {
        let mask = width.mask();
        let source = source & mask;
        let result = source.wrapping_neg() & mask;
        let sign_bit = width.sign_bit();
        u64::from(source != 0)
            | (u64::from((result as u8).count_ones().is_multiple_of(2)) << 2)
            | (u64::from(source & 0xF != 0) << 4)
            | (u64::from(result == 0) << 6)
            | (u64::from(result & sign_bit != 0) << 7)
            | (u64::from(source == sign_bit) << 11)
    };
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    for case in cases {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(
            0x1000,
            OpKind::Neg {
                dst: x86(case.dst),
                src: x86(case.src),
                width: case.width,
                flags: case.flags,
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
            *value = 0xA1A2_0000_0000_8000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        regs.gpr[4] = 0x2233_4455_6677_5678;
        regs.gpr[5] = 0x3344_5566_8765_9ABC;
        regs.gpr[16] = 0xAABB_CCDD_EEFF_7788;
        regs.gpr[31] = 0xFFEE_DDCC_BBAA_1357;
        regs.rflags = STATUS_MASK;
        let mut expected = regs;
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let src_idx = case.src.gpr_index().unwrap() as usize;
        let source = regs.gpr[src_idx];
        let result = source.wrapping_neg() & case.width.mask();
        expected.gpr[dst_idx] = match case.width {
            OpWidth::W8 | OpWidth::W16 => (regs.gpr[dst_idx] & !case.width.mask()) | result,
            OpWidth::W32 | OpWidth::W64 => result,
            OpWidth::W128 => unreachable!(),
        };
        if case.flags.updates_any() {
            expected.rflags = (expected.rflags & !STATUS_MASK) | neg_status(source, case.width);
        }

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS_MASK,
            expected.rflags & STATUS_MASK,
            "{} status flags",
            case.name
        );
    }
}
#[test]
fn lower_state_backed_gpr_inc_dec_emits_flag_contracts_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let flagless_inc = lower_single_op(OpKind::Inc {
        dst: x86(X86Reg::Rbp),
        src: x86(X86Reg::R16),
        width: OpWidth::W8,
        flags: FlagUpdate::None,
    });
    assert!(
        flagless_inc.contains(&0x9C) && flagless_inc.contains(&0x9D),
        "APX NF Inc must preserve RFLAGS: {flagless_inc:02X?}"
    );
    assert!(
        flagless_inc.windows(2).any(|bytes| bytes == [0xFE, 0xC2]),
        "byte Inc must increment DL: {flagless_inc:02X?}"
    );
    assert!(
        flagless_inc
            .windows(3)
            .any(|bytes| bytes == [0x88, 0x55, 0x00]),
        "byte Inc must partially synchronize guest RBP: {flagless_inc:02X?}"
    );

    let flagful_dec = lower_single_op(OpKind::Dec {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rsp),
        width: OpWidth::W32,
        flags: FlagUpdate::All,
    });
    assert!(
        !flagful_dec.contains(&0x9C) && !flagful_dec.contains(&0x9D),
        "flag-setting Dec must leave native flags live: {flagful_dec:02X?}"
    );
    assert!(
        flagful_dec.windows(2).any(|bytes| bytes == [0xFF, 0xCA]),
        "dword Dec must decrement EDX: {flagful_dec:02X?}"
    );
    assert!(
        flagful_dec
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "dword Dec must fully commit GuestRegs.gpr[16]: {flagful_dec:02X?}"
    );

    for malformed in [
        OpKind::Inc {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W128,
            flags: FlagUpdate::All,
        },
        OpKind::Dec {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W64,
            flags: FlagUpdate::Specific(FlagSet::CF),
        },
        OpKind::Inc {
            dst: x86(X86Reg::R16),
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. }
            ),
            "malformed state-backed Inc/Dec must fail lowering"
        );
    }

    let hinted = OpKind::Dec {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rax),
        width: OpWidth::W64,
        flags: FlagUpdate::All,
    };
    assert!(matches!(
        lower_single_hinted_op_err(hinted, X86OpHint::Mulx),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_inc_dec_preserve_width_and_flag_contracts() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS_MASK: u64 = 0x8D5;

    struct Case {
        name: &'static str,
        decrement: bool,
        dst: X86Reg,
        src: X86Reg,
        width: OpWidth,
        flags: FlagUpdate,
    }

    let cases = [
        Case {
            name: "INC BPL,R16B partial flag-setting destination",
            decrement: false,
            dst: X86Reg::Rbp,
            src: X86Reg::R16,
            width: OpWidth::W8,
            flags: FlagUpdate::All,
        },
        Case {
            name: "NF DEC R16W,SP partial destination",
            decrement: true,
            dst: X86Reg::R16,
            src: X86Reg::Rsp,
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        Case {
            name: "DEC RSP in-place full destination",
            decrement: true,
            dst: X86Reg::Rsp,
            src: X86Reg::Rsp,
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
        Case {
            name: "INC R31D,EBP zero-extending destination",
            decrement: false,
            dst: X86Reg::R31,
            src: X86Reg::Rbp,
            width: OpWidth::W32,
            flags: FlagUpdate::All,
        },
        Case {
            name: "NF INC R16D in-place zero-extending destination",
            decrement: false,
            dst: X86Reg::R16,
            src: X86Reg::R16,
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
    ];

    let inc_dec_status = |source: u64, width: OpWidth, decrement: bool, incoming: u64| {
        let mask = width.mask();
        let source = source & mask;
        let result = if decrement {
            source.wrapping_sub(1) & mask
        } else {
            source.wrapping_add(1) & mask
        };
        let sign_bit = width.sign_bit();
        (incoming & 1)
            | (u64::from((result as u8).count_ones().is_multiple_of(2)) << 2)
            | (u64::from(if decrement {
                source & 0xF == 0
            } else {
                source & 0xF == 0xF
            }) << 4)
            | (u64::from(result == 0) << 6)
            | (u64::from(result & sign_bit != 0) << 7)
            | (u64::from(if decrement {
                source == sign_bit
            } else {
                source == sign_bit - 1
            }) << 11)
    };
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    for case in cases {
        let kind = if case.decrement {
            OpKind::Dec {
                dst: x86(case.dst),
                src: x86(case.src),
                width: case.width,
                flags: case.flags,
            }
        } else {
            OpKind::Inc {
                dst: x86(case.dst),
                src: x86(case.src),
                width: case.width,
                flags: case.flags,
            }
        };
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
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
            *value = 0xA1A2_0000_0000_8000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        regs.gpr[4] = 0x2233_4455_6677_5678;
        regs.gpr[5] = 0x3344_5566_8765_9ABD;
        regs.gpr[16] = 0xAABB_CCDD_EEFF_778A;
        regs.gpr[31] = 0xFFEE_DDCC_BBAA_1357;
        regs.rflags = STATUS_MASK;
        let mut expected = regs;
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let src_idx = case.src.gpr_index().unwrap() as usize;
        let source = regs.gpr[src_idx];
        let result = if case.decrement {
            source.wrapping_sub(1) & case.width.mask()
        } else {
            source.wrapping_add(1) & case.width.mask()
        };
        expected.gpr[dst_idx] = match case.width {
            OpWidth::W8 | OpWidth::W16 => (regs.gpr[dst_idx] & !case.width.mask()) | result,
            OpWidth::W32 | OpWidth::W64 => result,
            OpWidth::W128 => unreachable!(),
        };
        if case.flags.updates_any() {
            expected.rflags = (expected.rflags & !STATUS_MASK)
                | inc_dec_status(source, case.width, case.decrement, expected.rflags);
        }

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS_MASK,
            expected.rflags & STATUS_MASK,
            "{} status flags",
            case.name
        );
    }
}
#[test]
fn lower_state_backed_gpr_not_emits_slot_commits_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let byte = lower_single_op(OpKind::Not {
        dst: x86(X86Reg::Rbp),
        src: x86(X86Reg::R16),
        width: OpWidth::W8,
    });
    assert!(
        byte.windows(2).any(|bytes| bytes == [0xF6, 0xD2]),
        "byte Not must complement DL: {byte:02X?}"
    );
    assert!(
        byte.windows(3).any(|bytes| bytes == [0x88, 0x55, 0x00]),
        "byte Not must partially synchronize guest RBP: {byte:02X?}"
    );

    let dword = lower_single_op(OpKind::Not {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rsp),
        width: OpWidth::W32,
    });
    assert!(
        dword.windows(2).any(|bytes| bytes == [0xF7, 0xD2]),
        "dword Not must complement EDX: {dword:02X?}"
    );
    assert!(
        dword
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "dword Not must fully commit GuestRegs.gpr[16]: {dword:02X?}"
    );

    for malformed in [
        OpKind::Not {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W128,
        },
        OpKind::Not {
            dst: x86(X86Reg::R16),
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            width: OpWidth::W64,
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. }
            ),
            "malformed state-backed Not must fail lowering"
        );
    }

    let hinted = OpKind::Not {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rax),
        width: OpWidth::W64,
    };
    assert!(matches!(
        lower_single_hinted_op_err(hinted, X86OpHint::Mulx),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_not_preserves_widths_flags_and_host_stack() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS: u64 = 0x8D5;

    struct Case {
        name: &'static str,
        dst: X86Reg,
        src: X86Reg,
        width: OpWidth,
    }

    let cases = [
        Case {
            name: "NOT BPL,R16B partial destination",
            dst: X86Reg::Rbp,
            src: X86Reg::R16,
            width: OpWidth::W8,
        },
        Case {
            name: "NOT R16W,SP partial destination",
            dst: X86Reg::R16,
            src: X86Reg::Rsp,
            width: OpWidth::W16,
        },
        Case {
            name: "NOT RSP in-place full destination",
            dst: X86Reg::Rsp,
            src: X86Reg::Rsp,
            width: OpWidth::W64,
        },
        Case {
            name: "NOT R31D,EBP zero-extending destination",
            dst: X86Reg::R31,
            src: X86Reg::Rbp,
            width: OpWidth::W32,
        },
        Case {
            name: "NOT R16D in-place zero-extending destination",
            dst: X86Reg::R16,
            src: X86Reg::R16,
            width: OpWidth::W32,
        },
    ];

    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    for case in cases {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(
            0x1000,
            OpKind::Not {
                dst: x86(case.dst),
                src: x86(case.src),
                width: case.width,
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
            *value = 0xA1A2_0000_0000_8000u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_0101));
        }
        regs.rflags = STATUS;
        let mut expected = regs;
        let dst_idx = case.dst.gpr_index().unwrap() as usize;
        let src_idx = case.src.gpr_index().unwrap() as usize;
        let source = regs.gpr[src_idx];
        expected.gpr[dst_idx] = match case.width {
            OpWidth::W8 => (regs.gpr[dst_idx] & !0xFF) | ((!source) & 0xFF),
            OpWidth::W16 => (regs.gpr[dst_idx] & !0xFFFF) | ((!source) & 0xFFFF),
            OpWidth::W32 => u64::from(!(source as u32)),
            OpWidth::W64 => !source,
            _ => unreachable!(),
        };

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(regs.rflags & STATUS, STATUS, "{} status flags", case.name);
    }
}
