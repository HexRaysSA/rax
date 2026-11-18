//! tests.rs

use super::*;

// ---- split test submodules ----
#[cfg(test)]
mod addr32;
#[cfg(test)]
mod addr32_assertions;
#[cfg(test)]
mod amx_disabled;
#[cfg(test)]
mod apx;
#[cfg(test)]
mod apx_adx;
#[cfg(test)]
mod apx_alu;
#[cfg(test)]
mod apx_bmi;
#[cfg(test)]
mod apx_cmpccxadd;
#[cfg(test)]
mod apx_conditional;
#[cfg(test)]
mod apx_count;
#[cfg(test)]
mod apx_crc32;
#[cfg(test)]
mod apx_dispatch;
#[cfg(test)]
mod apx_group3;
#[cfg(test)]
mod apx_movbe;
#[cfg(test)]
mod apx_movrs;
#[cfg(test)]
mod apx_prefixes;
#[cfg(test)]
mod apx_push2_pop2;
#[cfg(test)]
mod apx_shift;
#[cfg(test)]
mod bswap;
#[cfg(test)]
mod byte_xchg;
#[cfg(test)]
mod cache_maintenance;
#[cfg(test)]
mod callout;
#[cfg(test)]
mod clac_stac;
#[cfg(test)]
mod cli;
#[cfg(test)]
mod clts;
#[cfg(test)]
mod cmov;
#[cfg(test)]
mod cpuid;
#[cfg(test)]
mod decode;
#[cfg(test)]
mod descriptor_table;
#[cfg(test)]
mod evex;
#[cfg(test)]
mod far_call;
#[cfg(test)]
mod far_jump;
#[cfg(test)]
mod far_pointer_load;
#[cfg(test)]
mod far_return;
#[cfg(test)]
mod fast_system_transfer;
#[cfg(test)]
mod fence_aliases;
#[cfg(test)]
mod fma;
#[cfg(test)]
mod fsgsbase;
#[cfg(test)]
mod group11;
#[cfg(test)]
mod group3_alias;
#[cfg(test)]
mod group7_invalid;
#[cfg(test)]
mod group9;
#[cfg(test)]
mod group9_invalid;
#[cfg(test)]
mod hypercall_hints;
#[cfg(test)]
mod icebp;
#[cfg(test)]
mod int3;
#[cfg(test)]
mod interrupt_return;
#[cfg(test)]
mod invlpg;
#[cfg(test)]
mod invpcid;
#[cfg(test)]
mod leave;
#[cfg(test)]
mod legacy_0f;
#[cfg(test)]
mod legacy_0f38;
#[cfg(test)]
mod legacy_0f3a;
#[cfg(test)]
mod lmsw;
#[cfg(test)]
mod mmx_convert;
#[cfg(test)]
mod mmx_xmm_transfer;
#[cfg(test)]
mod monitor_mwait;
#[cfg(test)]
mod movdir64b;
#[cfg(test)]
mod movdiri;
#[cfg(test)]
mod msr;
#[cfg(test)]
mod msr_extensions;
#[cfg(test)]
mod opmask;
#[cfg(test)]
mod ordinary_stack;
#[cfg(test)]
mod packed_string;
#[cfg(test)]
mod pconfig;
#[cfg(test)]
mod pkru;
#[cfg(test)]
mod pop_segment;
#[cfg(test)]
mod primary_dispatch;
#[cfg(test)]
mod ptwrite;
#[cfg(test)]
mod push_segment;
#[cfg(test)]
mod rdpmc;
#[cfg(test)]
mod rdtscp;
#[cfg(test)]
mod read_control;
#[cfg(test)]
mod read_debug;
#[cfg(test)]
mod reserved_nop;
#[cfg(test)]
mod rex2_admission;
#[cfg(test)]
mod rex2_no_effect;
#[cfg(test)]
mod scalar;
#[cfg(test)]
mod segment_selector_load;
#[cfg(test)]
mod segment_selector_store;
#[cfg(test)]
mod selector;
#[cfg(test)]
mod selector_query;
#[cfg(test)]
mod selector_verify;
#[cfg(test)]
mod serialize;
#[cfg(test)]
mod sgx_controls;
#[cfg(test)]
mod sha_ni;
#[cfg(test)]
mod smsw;
#[cfg(test)]
mod software_interrupt;
#[cfg(test)]
mod sse;
#[cfg(test)]
mod sse3_fp_paired;
#[cfg(test)]
mod sse4a;
#[cfg(test)]
mod sse_packed_minmax;
#[cfg(test)]
mod stack_flags;
#[cfg(test)]
mod sti;
#[cfg(test)]
mod string_io;
#[cfg(test)]
mod svm_controls;
#[cfg(test)]
mod swapgs;
#[cfg(test)]
mod three_dnow;
#[cfg(test)]
mod tsx;
#[cfg(test)]
mod vector_legacy_prefix_reserved;
#[cfg(test)]
mod vector_prefix;
#[cfg(test)]
mod vex;
#[cfg(test)]
mod vex_aligned_packed_fp_move;
#[cfg(test)]
mod vex_bmi_reserved;
#[cfg(test)]
mod vex_chunk;
#[cfg(test)]
mod vex_chunk_extract;
#[cfg(test)]
mod vex_immediate_permute;
#[cfg(test)]
mod vex_integer_compare;
#[cfg(test)]
mod vex_lane_shuffle;
#[cfg(test)]
mod vex_memory_prefixes;
#[cfg(test)]
mod vex_mov_mask_stack_destination;
#[cfg(test)]
mod vex_mxcsr;
#[cfg(test)]
mod vex_packed_integer_move;
#[cfg(test)]
mod vex_register_broadcast;
#[cfg(test)]
mod vex_scalar_extract;
#[cfg(test)]
mod vex_unaligned_packed_fp_move;
#[cfg(test)]
mod vmx_controls;
#[cfg(test)]
mod vpblendd;
#[cfg(test)]
mod vpermil2;
#[cfg(test)]
mod waitpkg;
#[cfg(test)]
mod write_control;
#[cfg(test)]
mod write_debug;
#[cfg(test)]
mod x87_aliases;
#[cfg(test)]
mod x87_noops;
#[cfg(test)]
mod x87_reserved;
#[cfg(test)]
mod x87_transcendental;
#[cfg(test)]
mod xop_packed;
#[cfg(test)]
mod xop_tbm;
#[cfg(test)]
mod xop_vpcmov;
#[cfg(test)]
mod xop_vpcom;

/// Test memory reader for unit tests
struct TestMemory {
    data: Vec<u8>,
    base: u64,
}

impl TestMemory {
    fn new(base: u64, data: Vec<u8>) -> Self {
        TestMemory { data, base }
    }
}

impl MemoryReader for TestMemory {
    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        if addr < self.base {
            return Err(MemoryError::OutOfBounds { addr });
        }
        let offset = (addr - self.base) as usize;
        if offset >= self.data.len() {
            return Err(MemoryError::OutOfBounds { addr });
        }
        // Return as many bytes as possible up to size
        let available = (self.data.len() - offset).min(size);
        Ok(self.data[offset..offset + available].to_vec())
    }
}

/// Lift one instruction (a trailing HLT terminates the block) and return its ops.
fn lift_one(code: &[u8]) -> Result<Vec<SmirOp>, LiftError> {
    use crate::smir::lift::SmirLifter;
    let mut bytes = code.to_vec();
    bytes.push(0xF4); // hlt → block terminator
    let mem = TestMemory::new(0x1000, bytes);
    let mut lifter = X86_64Lifter::strict();
    let mut lctx = LiftContext::new(SourceArch::X86_64);
    lifter.lift_block(0x1000, &mem, &mut lctx).map(|b| b.ops)
}

fn x86_gpr(idx: u8) -> VReg {
    VReg::Arch(ArchReg::X86(X86Reg::gpr(idx)))
}

fn lift_single(bytes: &[u8]) -> Result<LiftResult, LiftError> {
    let mut lifter = X86_64Lifter::strict();
    let mut ctx = LiftContext::new(SourceArch::X86_64);
    lifter.lift_insn(0x1000, bytes, &mut ctx)
}

fn assert_adx_sequence(
    result: &LiftResult,
    start: usize,
    kind: X86AdxKind,
    dst: VReg,
    src1: VReg,
    src2: VReg,
    width: OpWidth,
) {
    let ops = &result.ops[start..];
    assert_eq!(ops.len(), 1);
    match &ops[0].kind {
        OpKind::X86Adx {
            dst: got_dst,
            src1: got_src1,
            src2: got_src2,
            width: got_width,
            kind: got_kind,
            flags,
        } => {
            assert_eq!(*got_dst, dst);
            assert_eq!(*got_src1, src1);
            assert_eq!(*got_src2, src2);
            assert_eq!(*got_width, width);
            assert_eq!(*got_kind, kind);
            let expected_flag = match kind {
                X86AdxKind::Adcx => FlagSet::CF,
                X86AdxKind::Adox => FlagSet::OF,
            };
            assert_eq!(*flags, FlagUpdate::Specific(expected_flag));
        }
        other => panic!("expected one exact X86Adx op, got {other:?}"),
    }
}

fn assert_vex_andn_op(
    ops: &[SmirOp],
    index: usize,
    dst: VReg,
    src: VReg,
    inverted: VReg,
    width: OpWidth,
) {
    match &ops[index].kind {
        OpKind::AndNot {
            dst: got_dst,
            src1,
            src2: SrcOperand::Reg(got_inverted),
            width: got_width,
            flags: FlagUpdate::Specific(flags),
        } => {
            assert_eq!(*got_dst, dst);
            assert_eq!(*src1, src);
            assert_eq!(*got_inverted, inverted);
            assert_eq!(*got_width, width);
            assert_eq!(
                *flags,
                FlagSet::CF
                    .union(FlagSet::ZF)
                    .union(FlagSet::SF)
                    .union(FlagSet::OF)
            );
        }
        other => panic!("expected VEX ANDN, got {other:?}"),
    }
}

fn assert_vex_bls_op(
    ops: &[SmirOp],
    index: usize,
    dst: VReg,
    src: VReg,
    width: OpWidth,
    kind: X86BlsKind,
    flags: FlagUpdate,
) {
    match &ops[index].kind {
        OpKind::X86Bls {
            dst: got_dst,
            src: got_src,
            width: got_width,
            kind: got_kind,
            flags: got_flags,
        } => {
            assert_eq!(*got_dst, dst);
            assert_eq!(*got_src, src);
            assert_eq!(*got_width, width);
            assert_eq!(*got_kind, kind);
            assert_eq!(*got_flags, flags);
        }
        other => panic!("expected VEX BLS op, got {other:?}"),
    }
}

fn assert_vex_bzhi_bextr_op(
    ops: &[SmirOp],
    index: usize,
    name: &str,
    dst: VReg,
    src: VReg,
    control: VReg,
    width: OpWidth,
) {
    match (&ops[index].kind, name) {
        (
            OpKind::Bzhi {
                dst: got_dst,
                src: got_src,
                index: got_control,
                width: got_width,
                flags: got_flags,
            },
            "bzhi",
        )
        | (
            OpKind::Bextr {
                dst: got_dst,
                src: got_src,
                control: got_control,
                width: got_width,
                flags: got_flags,
            },
            "bextr",
        ) => {
            let expected_flags = match name {
                "bzhi" => FlagSet::CF
                    .union(FlagSet::ZF)
                    .union(FlagSet::SF)
                    .union(FlagSet::OF),
                "bextr" => FlagSet::CF.union(FlagSet::ZF).union(FlagSet::OF),
                _ => unreachable!(),
            };
            assert_eq!(*got_dst, dst, "{name}");
            assert_eq!(*got_src, src, "{name}");
            assert_eq!(*got_control, control, "{name}");
            assert_eq!(*got_width, width, "{name}");
            assert_eq!(got_flags.as_set(), expected_flags, "{name}");
        }
        (other, _) => panic!("expected VEX {name}, got {other:?}"),
    }
}

fn assert_vex_pdep_pext_op(
    ops: &[SmirOp],
    index: usize,
    name: &str,
    dst: VReg,
    src: VReg,
    mask: VReg,
    width: OpWidth,
) {
    match (&ops[index].kind, name) {
        (
            OpKind::Pdep {
                dst: got_dst,
                src: got_src,
                mask: got_mask,
                width: got_width,
            },
            "pdep",
        )
        | (
            OpKind::Pext {
                dst: got_dst,
                src: got_src,
                mask: got_mask,
                width: got_width,
            },
            "pext",
        ) => {
            assert_eq!(*got_dst, dst, "{name}");
            assert_eq!(*got_src, src, "{name}");
            assert_eq!(*got_mask, mask, "{name}");
            assert_eq!(*got_width, width, "{name}");
        }
        (other, _) => panic!("expected VEX {name}, got {other:?}"),
    }
}

fn assert_vex_mulx_op(
    ops: &[SmirOp],
    index: usize,
    dst_hi: VReg,
    dst_lo: VReg,
    src2: VReg,
    width: OpWidth,
) {
    assert_eq!(ops[index].x86_hint, Some(X86OpHint::Mulx));
    match &ops[index].kind {
        OpKind::MulU {
            dst_lo: got_dst_lo,
            dst_hi: Some(got_dst_hi),
            src1,
            src2: SrcOperand::Reg(got_src2),
            width: got_width,
            flags: FlagUpdate::None,
        } => {
            assert_eq!(*got_dst_hi, dst_hi);
            assert_eq!(*got_dst_lo, dst_lo);
            assert_eq!(*src1, x86_gpr(2));
            assert_eq!(*got_src2, src2);
            assert_eq!(*got_width, width);
        }
        other => panic!("expected VEX MULX, got {other:?}"),
    }
}

fn assert_vex_bmi2_shift(
    bytes: &[u8],
    expected_op: &str,
    dst: VReg,
    src: VReg,
    count: VReg,
    width: OpWidth,
) {
    let result = lift_single(bytes).unwrap();
    assert_eq!(result.bytes_consumed, bytes.len(), "{expected_op}");
    assert_eq!(result.ops.len(), 1, "{expected_op}");
    assert_vex_bmi2_shift_ops(&result.ops, 0, expected_op, dst, src, count, width);
}

fn assert_vex_bmi2_shift_ops(
    ops: &[SmirOp],
    start: usize,
    expected_op: &str,
    dst: VReg,
    src: VReg,
    count: VReg,
    width: OpWidth,
) {
    match (&ops[start].kind, expected_op) {
        (
            OpKind::Sar {
                dst: got_dst,
                src: got_src,
                amount: SrcOperand::Reg(amount),
                width: got_width,
                flags: FlagUpdate::None,
            },
            "sarx",
        )
        | (
            OpKind::Shr {
                dst: got_dst,
                src: got_src,
                amount: SrcOperand::Reg(amount),
                width: got_width,
                flags: FlagUpdate::None,
            },
            "shrx",
        )
        | (
            OpKind::Shl {
                dst: got_dst,
                src: got_src,
                amount: SrcOperand::Reg(amount),
                width: got_width,
                flags: FlagUpdate::None,
            },
            "shlx",
        ) => {
            assert_eq!(*got_dst, dst, "{expected_op}");
            assert_eq!(*got_src, src, "{expected_op}");
            assert_eq!(*amount, count, "{expected_op}");
            assert_eq!(*got_width, width, "{expected_op}");
        }
        (other, _) => panic!("expected VEX BMI2 {expected_op}, got {other:?}"),
    }
}

fn assert_vex_rorx_op(
    ops: &[SmirOp],
    index: usize,
    dst: VReg,
    src: VReg,
    amount: i64,
    width: OpWidth,
) {
    match &ops[index].kind {
        OpKind::Ror {
            dst: got_dst,
            src: got_src,
            amount: SrcOperand::Imm(got_amount),
            width: got_width,
            flags: FlagUpdate::None,
        } => {
            assert_eq!(*got_dst, dst);
            assert_eq!(*got_src, src);
            assert_eq!(*got_amount, amount);
            assert_eq!(*got_width, width);
        }
        other => panic!("expected VEX RORX, got {other:?}"),
    }
}

fn assert_apx_guarded_payload<'a>(result: &'a LiftResult, expected: &str) -> &'a [SmirOp] {
    assert!(
        matches!(
            result.ops.first(),
            Some(SmirOp {
                kind: OpKind::X86RequireApx,
                ..
            })
        ),
        "{expected}: missing leading APX requirement: {:?}",
        result.ops
    );
    &result.ops[1..]
}

fn assert_apx_bmi2_shift(
    bytes: &[u8],
    expected_op: &str,
    dst: VReg,
    src: VReg,
    count: VReg,
    width: OpWidth,
) {
    let result = lift_single(bytes).unwrap();
    assert_eq!(result.bytes_consumed, bytes.len(), "{expected_op}");
    let payload = assert_apx_guarded_payload(&result, expected_op);
    assert_eq!(payload.len(), 1, "{expected_op}");
    assert_apx_bmi2_shift_ops(payload, 0, expected_op, dst, src, count, width);
}

fn assert_apx_bmi2_shift_ops(
    ops: &[SmirOp],
    start: usize,
    expected_op: &str,
    dst: VReg,
    src: VReg,
    count: VReg,
    width: OpWidth,
) {
    match (&ops[start].kind, expected_op) {
        (
            OpKind::Sar {
                dst: got_dst,
                src: got_src,
                amount: SrcOperand::Reg(amount),
                width: got_width,
                flags: FlagUpdate::None,
            },
            "sarx",
        )
        | (
            OpKind::Shr {
                dst: got_dst,
                src: got_src,
                amount: SrcOperand::Reg(amount),
                width: got_width,
                flags: FlagUpdate::None,
            },
            "shrx",
        )
        | (
            OpKind::Shl {
                dst: got_dst,
                src: got_src,
                amount: SrcOperand::Reg(amount),
                width: got_width,
                flags: FlagUpdate::None,
            },
            "shlx",
        ) => {
            assert_eq!(*got_dst, dst, "{expected_op}");
            assert_eq!(*got_src, src, "{expected_op}");
            assert_eq!(*amount, count, "{expected_op}");
            assert_eq!(*got_width, width, "{expected_op}");
        }
        (other, _) => panic!("expected APX BMI2 {expected_op}, got {other:?}"),
    }
}

fn assert_apx_bmi2_memory_load(op: &SmirOp, expected: &str) -> VReg {
    match &op.kind {
        OpKind::Load {
            dst,
            addr:
                Address::BaseIndexScale {
                    base: Some(base),
                    index,
                    scale: 4,
                    disp: 0x20,
                    ..
                },
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        } => {
            assert_eq!(*base, x86_gpr(17), "{expected}");
            assert_eq!(*index, x86_gpr(18), "{expected}");
            *dst
        }
        other => panic!("expected APX BMI2 {expected} memory load, got {other:?}"),
    }
}

fn assert_apx_conditional_flag_shape(result: &LiftResult, cond: Condition, default_rflags: i64) {
    assert_apx_conditional_flag_shape_with_true_ops(result, cond, default_rflags, 1);
}

fn assert_apx_conditional_flag_shape_with_true_ops(
    result: &LiftResult,
    cond: Condition,
    default_rflags: i64,
    true_op_count: usize,
) -> VReg {
    let start = result
        .ops
        .iter()
        .position(|op| matches!(op.kind, OpKind::ReadFlags { .. }))
        .expect("APX conditional must snapshot old flags");
    let true_flags_idx = start + 4 + true_op_count;
    let select_idx = true_flags_idx + 1;
    let write_flags_idx = select_idx + 1;
    assert_eq!(result.ops.len(), write_flags_idx + 1);

    let old_flags = match &result.ops[start].kind {
        OpKind::ReadFlags { dst } => *dst,
        other => panic!("expected APX conditional old ReadFlags, got {other:?}"),
    };
    let cond_reg = match &result.ops[start + 1].kind {
        OpKind::SetCC {
            dst,
            cond: got_cond,
            width: OpWidth::W64,
        } => {
            assert_eq!(*got_cond, cond);
            *dst
        }
        other => panic!("expected APX conditional SetCC, got {other:?}"),
    };
    let false_flags = match &result.ops[start + 2].kind {
        OpKind::And {
            dst,
            src1,
            src2: SrcOperand::Imm(mask),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        } => {
            assert_eq!(*src1, old_flags);
            assert_eq!(*mask, !APX_CCMP_FLAGS_MASK);
            *dst
        }
        other => panic!("expected APX conditional false-flag mask, got {other:?}"),
    };
    match &result.ops[start + 3].kind {
        OpKind::Or {
            dst,
            src1,
            src2: SrcOperand::Imm(flags),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        } => {
            assert_eq!(*dst, false_flags);
            assert_eq!(*src1, false_flags);
            assert_eq!(*flags, default_rflags);
        }
        other => panic!("expected APX conditional false-flag defaults, got {other:?}"),
    }
    let true_flags = match &result.ops[true_flags_idx].kind {
        OpKind::ReadFlags { dst } => *dst,
        other => panic!("expected APX conditional true ReadFlags, got {other:?}"),
    };
    let selected_flags = match &result.ops[select_idx].kind {
        OpKind::Select {
            dst,
            cond,
            src_true,
            src_false,
            width: OpWidth::W64,
        } => {
            assert_eq!(*cond, cond_reg);
            assert_eq!(*src_true, true_flags);
            assert_eq!(*src_false, false_flags);
            *dst
        }
        other => panic!("expected APX conditional flag Select, got {other:?}"),
    };
    match &result.ops[write_flags_idx].kind {
        OpKind::WriteFlags { src } => assert_eq!(*src, selected_flags),
        other => panic!("expected APX conditional WriteFlags, got {other:?}"),
    }
    cond_reg
}

fn assert_apx_conditional_load(result: &LiftResult, index: usize, width: MemWidth) -> VReg {
    match &result.ops[index].kind {
        OpKind::Load {
            dst,
            addr: Address::Direct(base),
            width: got_width,
            sign: SignExtend::Zero,
        } => {
            assert_eq!(*base, x86_gpr(3));
            assert_eq!(*got_width, width);
            *dst
        }
        other => panic!("expected APX conditional Load, got {other:?}"),
    }
}

fn assert_rex2_xadd_sib_addr(addr: &Address, name: &str) {
    match addr {
        Address::BaseIndexScale {
            base: Some(base),
            index,
            scale: 4,
            disp: 0x20,
            disp_size: DispSize::Disp8,
        } => {
            assert_eq!(*base, x86_gpr(16), "{name}");
            assert_eq!(*index, x86_gpr(17), "{name}");
        }
        other => panic!("expected REX2 {name} SIB address, got {other:?}"),
    }
}

fn assert_rex2_guarded_ops(result: &LiftResult, semantic_len: usize) -> &[SmirOp] {
    assert_eq!(result.ops.len(), semantic_len + 1);
    assert!(matches!(
        result.ops.first(),
        Some(SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::X86RequireApx,
            x86_hint: None,
        })
    ));
    for (index, op) in result.ops.iter().enumerate() {
        assert_eq!(op.id, OpId(index as u16));
    }
    &result.ops[1..]
}

fn assert_invalid_opcode_trap(result: &LiftResult, expected_len: usize) {
    assert_eq!(result.bytes_consumed, expected_len);
    assert!(result.ops.is_empty());
    assert!(result.branch_targets.is_empty());
    assert!(matches!(
        result.control_flow,
        ControlFlow::Trap {
            kind: TrapKind::InvalidOpcode
        }
    ));
}

fn assert_xadd_register_ops(
    result: &LiftResult,
    name: &str,
    dst_reg: VReg,
    src_reg: VReg,
    width: OpWidth,
) {
    let ops = if matches!(
        result.ops.first(),
        Some(SmirOp {
            kind: OpKind::X86RequireApx,
            ..
        })
    ) {
        &result.ops[1..]
    } else {
        result.ops.as_slice()
    };
    assert_eq!(ops.len(), 1, "{name}");
    match &ops[0].kind {
        OpKind::X86Xadd(xadd) => {
            assert_eq!(xadd.dst.vreg(), dst_reg, "{name}");
            assert_eq!(xadd.src.vreg(), src_reg, "{name}");
            assert!(!xadd.dst.high_byte, "{name}");
            assert!(!xadd.src.high_byte, "{name}");
            assert_eq!(xadd.width, width, "{name}");
            assert_eq!(xadd.flags, FlagUpdate::All, "{name}");
        }
        other => panic!("expected {name} dedicated XADD, got {other:?}"),
    }
}

fn assert_bswap_op(result: &LiftResult, name: &str, reg: VReg, width: OpWidth) {
    let ops = if matches!(
        result.ops.first(),
        Some(SmirOp {
            kind: OpKind::X86RequireApx,
            ..
        })
    ) {
        assert_rex2_guarded_ops(result, 1)
    } else {
        assert_eq!(result.ops.len(), 1, "{name}");
        result.ops.as_slice()
    };
    match &ops[0].kind {
        OpKind::Bswap {
            dst,
            src,
            width: got_width,
        } => {
            assert_eq!(*dst, reg, "{name}");
            assert_eq!(*src, reg, "{name}");
            assert_eq!(*got_width, width, "{name}");
        }
        other => panic!("expected {name} Bswap, got {other:?}"),
    }
}

fn assert_0f38_movbe_rex_sib_addr(addr: &Address, name: &str) {
    match addr {
        Address::BaseIndexScale {
            base: Some(base),
            index,
            scale: 4,
            disp: 0x20,
            disp_size: DispSize::Disp8,
        } => {
            assert_eq!(*base, x86_gpr(8), "{name}");
            assert_eq!(*index, x86_gpr(9), "{name}");
        }
        other => panic!("expected {name} REX SIB address, got {other:?}"),
    }
}
