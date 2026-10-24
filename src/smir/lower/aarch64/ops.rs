//! Operation dispatch and block terminator lowering.

use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::{
    ArchReg, ArmReg, BlockId, Condition, FpRoundMode, OpWidth, ShiftOp, VLaneOp, VReg,
    VecElementType,
};
use crate::smir::ir::{CallTarget, SmirBlock, Terminator, TrapKind};
use crate::smir::lower::LowerError;

use super::{Aarch64Lowerer, BitTestAction, SimdArithmeticOp, SimdLogicOp};

impl Aarch64Lowerer {
    pub(crate) fn lower_op(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !super::scalar_simd::integer_scalar_provenance_valid(op) {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 integer scalar operation with x86 provenance".to_string(),
            });
        }
        match &op.kind {
            OpKind::ArmInstructionBegin { raw, features } => self.lower_pauth_helper(0, *raw, op.guest_pc, *features),
            OpKind::ArmInstructionCommit { raw } => self.lower_pauth_helper(2, *raw, op.guest_pc, 0),
            OpKind::ArmPauth(operation) if operation.valid() => self.lower_pauth_helper(1, operation.raw, op.guest_pc, 0),
            OpKind::ArmPauth(..) => Err(LowerError::UnsupportedOp { op: "invalid AArch64 PAuth descriptor".into() }),
            OpKind::Nop => {
                self.emit(0xd503_201f);
                Ok(())
            }
            // A guest Breakpoint/Undefined must NOT lower to a host BRK/UDF: those
            // raise SIGTRAP/SIGILL on the host (no native signal-recovery path
            // exists), letting guest code terminate the emulator. Bail to the
            // interpreter, which models these as controlled guest exits. (#16)
            OpKind::Breakpoint => Err(LowerError::UnsupportedOp {
                op: "AArch64 native Breakpoint (host BRK would SIGTRAP); deopt to interpreter"
                    .into(),
            }),
            OpKind::Undefined { .. } => Err(LowerError::UnsupportedOp {
                op: "AArch64 native Undefined (host UDF would SIGILL); deopt to interpreter".into(),
            }),
            OpKind::Swi { .. } => Err(LowerError::UnsupportedOp {
                op: "AArch64 native SWI/SVC guest syscall trap".into(),
            }),
            OpKind::MaterializeFlags => Ok(()),
            OpKind::X86RequireApx => self.emit_x86_require_apx(op),
            OpKind::X86RequireTbm => self.emit_x86_require_tbm(op),
            OpKind::X86RequireSse4a
            | OpKind::X86Sse4aBitfield { .. }
            | OpKind::X86Sse4aMovntStore { .. } => Err(LowerError::UnsupportedOp {
                op: "x86 SSE4A state-backed operation has no AArch64 guest-vector bridge".into(),
            }),
            OpKind::ClearExclusive => {
                self.emit(0xd503_3f5f);
                Ok(())
            }
            OpKind::Prefetch { addr, write } => self.lower_prefetch(addr, *write, op.guest_pc),
            OpKind::Fence { kind } => self.lower_fence(*kind),
            OpKind::Mov { dst, src, width } => self.lower_mov(*dst, src, *width),
            OpKind::ReadSysReg { dst, reg } => self.lower_raw_sysreg_read(*dst, *reg),
            OpKind::WriteSysReg { reg, src } => self.lower_raw_sysreg_write(*reg, *src),
            OpKind::Add {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_addsub(*dst, *src1, src2, false, flags.updates_any(), *width),
            OpKind::Sub {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_addsub(*dst, *src1, src2, true, flags.updates_any(), *width),
            OpKind::Adc {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_addsub_carry(*dst, *src1, src2, false, flags.updates_any(), *width),
            OpKind::Sbb {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_sbb(*dst, *src1, src2, flags.updates_any(), *width),
            OpKind::And {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_logic_flag_contract(*dst, *src1, src2, 0b00, false, *flags, *width),
            OpKind::AndNot {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_logic_flag_contract(*dst, *src1, src2, 0b00, true, *flags, *width),
            OpKind::Or {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_logic_flag_contract(*dst, *src1, src2, 0b01, false, *flags, *width),
            OpKind::Xor {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_logic_flag_contract(*dst, *src1, src2, 0b10, false, *flags, *width),
            OpKind::Neg {
                dst,
                src,
                width,
                flags,
            } => self.lower_neg(*dst, *src, flags.updates_any(), *width),
            OpKind::Inc {
                dst,
                src,
                width,
                flags,
            } => self.lower_inc_dec(*dst, *src, false, flags.updates_any(), *width),
            OpKind::Dec {
                dst,
                src,
                width,
                flags,
            } => self.lower_inc_dec(*dst, *src, true, flags.updates_any(), *width),
            OpKind::MulU {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                flags,
            } => self.lower_mul_flag_contract(*dst_lo, *dst_hi, *src1, src2, *width, *flags, false),
            OpKind::MulS {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                flags,
            } => self.lower_mul_flag_contract(*dst_lo, *dst_hi, *src1, src2, *width, *flags, true),
            OpKind::MulAdd {
                dst,
                acc,
                src1,
                src2,
                width,
            } => self.lower_mul_acc(*dst, *acc, *src1, *src2, *width, false),
            OpKind::MulSub {
                dst,
                acc,
                src1,
                src2,
                width,
            } => self.lower_mul_acc(*dst, *acc, *src1, *src2, *width, true),
            OpKind::DivU {
                quot,
                rem,
                src1,
                src2,
                width,
                flags,
            } => self.lower_div(*quot, *rem, *src1, src2, *width, flags.updates_any(), false),
            OpKind::DivS {
                quot,
                rem,
                src1,
                src2,
                width,
                flags,
            } => self.lower_div(*quot, *rem, *src1, src2, *width, flags.updates_any(), true),
            OpKind::FAdd {
                dst,
                src1,
                src2,
                precision,
            } => self.lower_fp_binary(*dst, *src1, *src2, *precision, 0b0010),
            OpKind::FSub {
                dst,
                src1,
                src2,
                precision,
            } => self.lower_fp_binary(*dst, *src1, *src2, *precision, 0b0011),
            OpKind::FMul {
                dst,
                src1,
                src2,
                precision,
            } => self.lower_fp_binary(*dst, *src1, *src2, *precision, 0b0000),
            OpKind::FDiv {
                dst,
                src1,
                src2,
                precision,
            } => self.lower_fp_binary(*dst, *src1, *src2, *precision, 0b0001),
            OpKind::FFma {
                dst,
                src1,
                src2,
                src3,
                precision,
            } => self.lower_fp_fma(*dst, *src1, *src2, *src3, *precision),
            // The interpreter models scalar FMin/FMax with Rust `a.min(b)`/
            // `a.max(b)` (numeric: a lone quiet NaN loses), matching AArch64
            // FMINNM (0b0111) / FMAXNM (0b0110). Emit those rather than the
            // NaN-propagating FMIN (0b0101) / FMAX (0b0100) so the JIT agrees
            // with the interpreter for guest-controlled NaN inputs.
            OpKind::FMin {
                dst,
                src1,
                src2,
                precision,
            } => self.lower_fp_binary(*dst, *src1, *src2, *precision, 0b0111),
            OpKind::FMax {
                dst,
                src1,
                src2,
                precision,
            } => self.lower_fp_binary(*dst, *src1, *src2, *precision, 0b0110),
            OpKind::FCmp {
                src1,
                src2,
                precision,
            } => self.lower_fp_compare(*src1, *src2, *precision),
            OpKind::FConvert { dst, src, from, to } => {
                self.lower_fp_convert(*dst, *src, *from, *to)
            }
            OpKind::IntToFp {
                dst,
                src,
                int_width,
                fp_precision,
                signed,
            } => self.lower_int_to_fp(*dst, *src, *int_width, *fp_precision, *signed),
            OpKind::FpToInt {
                dst,
                src,
                fp_precision,
                int_width,
                signed,
                round,
            } => self.lower_fp_to_int(*dst, *src, *fp_precision, *int_width, *signed, *round),
            OpKind::FRound {
                dst,
                src,
                precision,
                mode,
            } => self.lower_fp_round(*dst, *src, *precision, *mode),
            OpKind::FAbs {
                dst,
                src,
                precision,
            } => self.lower_fp_unary(*dst, *src, *precision, 0b00001),
            OpKind::FNeg {
                dst,
                src,
                precision,
            } => self.lower_fp_unary(*dst, *src, *precision, 0b00010),
            OpKind::FSqrt {
                dst,
                src,
                precision,
            } => self.lower_fp_unary(*dst, *src, *precision, 0b00011),
            OpKind::VCmp {
                dst,
                src1,
                src2,
                cond,
                elem,
                lanes,
            } => {
                if !super::aarch64_vcmp_shape_valid(op) {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native vector compare {:?}", op.kind),
                    });
                }
                self.lower_vcmp(*dst, *src1, *src2, *cond, *elem, *lanes)
            }
            OpKind::VAdd {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => self.lower_varith(*dst, *src1, *src2, *elem, *lanes, SimdArithmeticOp::Add),
            OpKind::VSub {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => self.lower_varith(*dst, *src1, *src2, *elem, *lanes, SimdArithmeticOp::Sub),
            OpKind::VMul {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => self.lower_varith(*dst, *src1, *src2, *elem, *lanes, SimdArithmeticOp::Mul),
            OpKind::VDiv {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => self.lower_varith(*dst, *src1, *src2, *elem, *lanes, SimdArithmeticOp::Div),
            OpKind::VUnary {
                dst,
                src,
                elem,
                lanes,
                op,
            } => self.lower_vunary(*dst, *src, *elem, *lanes, *op),
            OpKind::VReduce {
                dst,
                src,
                elem,
                lanes,
                op,
            } => self.lower_vreduce(*dst, *src, *elem, *lanes, *op),
            OpKind::VFMinMaxNm {
                dst,
                src1,
                src2,
                elem,
                lanes,
                min,
            } => self.lower_vfminmaxnm(*dst, *src1, *src2, *elem, *lanes, *min),
            OpKind::VPermute2 {
                dst,
                src1,
                src2,
                elem,
                lanes,
                kind,
            } => self.lower_vpermute2(*dst, *src1, *src2, *elem, *lanes, *kind),
            OpKind::VTableLookup {
                dst,
                table,
                num_tables,
                index,
                lanes,
                is_tbx,
            } => self.lower_vtable(*dst, *table, *num_tables, *index, *lanes, *is_tbx),
            OpKind::VMax {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => self.lower_varith(*dst, *src1, *src2, *elem, *lanes, SimdArithmeticOp::Max),
            OpKind::VMin {
                dst,
                src1,
                src2,
                elem,
                lanes,
                signed,
            } => self.lower_varith(
                *dst,
                *src1,
                *src2,
                *elem,
                *lanes,
                SimdArithmeticOp::Min { signed: *signed },
            ),
            OpKind::VFma {
                dst,
                src1,
                src2,
                acc,
                elem,
                lanes,
                negate_product,
                negate_acc,
            } => self.lower_vfma(
                *dst,
                *src1,
                *src2,
                *acc,
                *elem,
                *lanes,
                *negate_product,
                *negate_acc,
            ),
            OpKind::VDotProduct {
                dst,
                acc,
                src1,
                src2,
                mask,
                src_elem,
                acc_elem,
                width,
                src1_unsigned,
                saturate,
                zeroing,
            } => {
                if mask.is_some() || *zeroing {
                    Err(LowerError::UnsupportedOp {
                        op: "masked x86 VDotProduct on AArch64".into(),
                    })
                } else {
                    self.lower_vdotproduct(
                        *dst,
                        *acc,
                        *src1,
                        *src2,
                        *src_elem,
                        *acc_elem,
                        *width,
                        *src1_unsigned,
                        *saturate,
                    )
                }
            }
            OpKind::VDotProductExt {
                dst,
                acc,
                src1,
                src2,
                src_elem,
                acc_elem,
                width,
                src1_signed,
                src2_signed,
                saturate,
            } => self.lower_vdotproduct_ext(
                *dst,
                *acc,
                *src1,
                *src2,
                *src_elem,
                *acc_elem,
                *width,
                *src1_signed,
                *src2_signed,
                *saturate,
            ),
            OpKind::VDotProductBF16 {
                dst,
                acc,
                src1,
                src2,
                mask,
                width,
                zeroing,
            } => {
                if mask.is_some() || *zeroing {
                    Err(LowerError::UnsupportedOp {
                        op: "masked x86 VDotProductBF16 on AArch64".into(),
                    })
                } else {
                    self.lower_vdotproduct_bf16(*dst, *acc, *src1, *src2, *width)
                }
            }
            OpKind::VFP16Arith {
                dst,
                src1,
                src2,
                mask,
                op,
                round,
                width,
                lanes,
                zeroing,
            } => {
                if u32::from(*lanes) != width.lanes(VecElementType::F16) {
                    Err(LowerError::UnsupportedOp {
                        op: "partial-lane x86 FP16 arithmetic on AArch64".into(),
                    })
                } else if *round != FpRoundMode::Dynamic {
                    Err(LowerError::UnsupportedOp {
                        op: "x86 FP16 embedded rounding / SAE on AArch64".into(),
                    })
                } else if mask.is_some() || *zeroing {
                    Err(LowerError::UnsupportedOp {
                        op: "masked x86 VFP16Arith on AArch64".into(),
                    })
                } else {
                    self.lower_vfp16_arith(*dst, *src1, *src2, *op, *width)
                }
            }
            OpKind::VCvtFP32ToBF16 {
                dst,
                src1,
                src2,
                mask,
                width,
                zeroing,
            } => {
                if mask.is_some() || *zeroing {
                    Err(LowerError::UnsupportedOp {
                        op: "masked x86 VCvtFP32ToBF16 on AArch64".into(),
                    })
                } else {
                    self.lower_vcvt_fp32_to_bf16(*dst, *src1, *src2, *width)
                }
            }
            OpKind::VCvtBF16ToFP32 { dst, src, width } => {
                self.lower_vcvt_bf16_to_fp32(*dst, *src, *width)
            }
            OpKind::X86ScalarFpToIntSat { .. } => {
                Err(LowerError::UnsupportedOp {
                    op: "x86 AVX10.2 scalar saturating conversion requires MXCSR and x86 GPR semantics"
                        .into(),
                })
            }
            OpKind::VCvtFpToIntSat { .. } => Err(LowerError::UnsupportedOp {
                op: "x86 AVX10.2 saturating conversion requires MXCSR, opmask, and x86 lane-layout semantics"
                    .into(),
            }),
            OpKind::VInterleave { .. } => Err(LowerError::UnsupportedOp {
                op: "x86 lane-block integer interleave".into(),
            }),
            OpKind::VShuffleBitQM { .. } => Err(LowerError::UnsupportedOp {
                op: "VShuffleBitQM requires x86 opmask K-register state".into(),
            }),
            OpKind::VCompress { .. } | OpKind::VExpand { .. } => Err(LowerError::UnsupportedOp {
                op: "x86 compress/expand vector permutation".into(),
            }),
            OpKind::X86NarrowInt { .. } => Err(LowerError::UnsupportedOp {
                op: "x86 EVEX integer narrowing".into(),
            }),
            OpKind::VPopcnt {
                dst,
                src,
                mask,
                elem,
                width,
                zeroing,
            } => {
                if mask.is_some() || *zeroing {
                    Err(LowerError::UnsupportedOp {
                        op: "masked x86 VPopcnt on AArch64".into(),
                    })
                } else {
                    self.lower_vpopcnt(*dst, *src, *elem, *width)
                }
            }
            OpKind::VConflict { .. } => Err(LowerError::UnsupportedOp {
                op: "AArch64 native VConflict".into(),
            }),
            OpKind::VMultiplyAdd52 {
                dst,
                acc,
                src1,
                src2,
                mask,
                width,
                high,
                zeroing,
            } => {
                if mask.is_some() || *zeroing {
                    Err(LowerError::UnsupportedOp {
                        op: "masked x86 VMultiplyAdd52 on AArch64".into(),
                    })
                } else {
                    self.lower_vmultiply_add52(*dst, *acc, *src1, *src2, *width, *high)
                }
            }
            OpKind::VMpsadbw {
                dst,
                src1,
                src2,
                mask,
                width,
                imm,
                zeroing,
            } => {
                if mask.is_some() || *zeroing {
                    Err(LowerError::UnsupportedOp {
                        op: "masked AVX10.2 VMPSADBW on AArch64".into(),
                    })
                } else {
                    self.lower_vmpsadbw(*dst, *src1, *src2, *width, *imm)
                }
            }
            OpKind::VMinMax {
                dst,
                src1,
                src2,
                elem,
                width,
                imm,
            } => self.lower_vminmax(*dst, *src1, *src2, *elem, *width, *imm),
            OpKind::VPermute {
                dst,
                src1,
                src2,
                indices,
                elem,
                width,
                overwrite_table,
            } => self.lower_vpermute(
                *dst,
                *src1,
                *src2,
                *indices,
                *elem,
                *width,
                *overwrite_table,
            ),
            OpKind::VLane {
                dst,
                src1,
                src2,
                elem,
                lanes,
                op: lane_op,
                signed,
                set_ovf,
            } => {
                let requires_neon_shape = matches!(
                    lane_op,
                    VLaneOp::ShiftSigned8 | VLaneOp::ShiftSigned8Rnd
                        | VLaneOp::AndNot | VLaneOp::OrNot
                );
                if requires_neon_shape && !super::aarch64_neon_lane_shape_valid(op) {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native vector lane {:?}", op.kind),
                    });
                }
                self.lower_vlane(*dst, *src1, *src2, *elem, *lanes, *lane_op, *signed, *set_ovf)
            }
            OpKind::VNavg {
                dst,
                src1,
                src2,
                elem,
                lanes,
                signed,
            } => self.lower_vnavg(*dst, *src1, *src2, *elem, *lanes, *signed),
            OpKind::VLaneUnary {
                dst,
                src,
                elem,
                lanes,
                op,
                signed,
            } => self.lower_vlane_unary(*dst, *src, *elem, *lanes, *op, *signed),
            OpKind::VBroadcast {
                dst,
                scalar,
                elem,
                lanes,
            } => self.lower_vbroadcast(*dst, *scalar, *elem, *lanes),
            OpKind::VShift {
                dst,
                src,
                amount,
                shift,
                elem,
                lanes,
            } => self.lower_vshift(*dst, *src, amount.clone(), *shift, *elem, *lanes),
            OpKind::VShiftAcc {
                dst,
                src,
                amount,
                shift,
                elem,
                lanes,
            } => self.lower_vshift_acc(*dst, *src, amount.clone(), *shift, *elem, *lanes),
            OpKind::VMov { dst, src, width } => self.lower_vmov(*dst, *src, *width),
            OpKind::VInsertLane {
                dst,
                vec,
                scalar,
                lane,
                elem,
            } => self.lower_vinsert_lane(*dst, *vec, *scalar, *lane, *elem),
            OpKind::VExtractLane {
                dst,
                vec,
                lane,
                elem,
                sign,
            } => self.lower_vextract_lane(*dst, *vec, *lane, *elem, *sign),
            OpKind::VAnd {
                dst,
                src1,
                src2,
                width,
            } => self.lower_vlogic(*dst, *src1, *src2, *width, SimdLogicOp::And),
            OpKind::VOr {
                dst,
                src1,
                src2,
                width,
            } => self.lower_vlogic(*dst, *src1, *src2, *width, SimdLogicOp::Or),
            OpKind::VXor {
                dst,
                src1,
                src2,
                width,
            } => self.lower_vlogic(*dst, *src1, *src2, *width, SimdLogicOp::Xor),
            OpKind::VBitSelect {
                dst,
                mask,
                src_true,
                src_false,
                width,
            } => self.lower_vbit_select(*dst, *mask, *src_true, *src_false, *width),
            OpKind::VLoad { dst, addr, width } => {
                if self.mem_helpers {
                    self.emit_jit_vload_op(op.guest_pc, *dst, addr, *width)
                } else {
                    self.lower_vload(*dst, addr, *width)
                }
            }
            OpKind::VStore { src, addr, width } => {
                if self.mem_helpers {
                    self.emit_jit_vstore_op(op.guest_pc, *src, addr, *width)
                } else {
                    self.lower_vstore(*src, addr, *width)
                }
            }
            OpKind::Load {
                dst,
                addr,
                width,
                sign,
            } => {
                if self.mem_helpers {
                    self.emit_jit_mem_load_op(op.guest_pc, *dst, addr, *width, *sign)
                } else {
                    self.lower_load(*dst, addr, *width, *sign)
                }
            }
            OpKind::Store { src, addr, width } => {
                if self.mem_helpers {
                    self.emit_jit_mem_store_op(op.guest_pc, *src, addr, *width)
                } else {
                    self.lower_store(*src, addr, *width)
                }
            }
            OpKind::PredLoad {
                dst,
                cond,
                addr,
                width,
                signed,
            } => self.lower_pred_load(*dst, *cond, addr, *width, *signed),
            OpKind::PredStore {
                src,
                cond,
                addr,
                width,
            } => self.lower_pred_store(src, *cond, addr, *width),
            OpKind::RepStos {
                dst,
                src,
                count,
                width,
            } => self.lower_rep_stos(*dst, *src, *count, *width),
            OpKind::RepMovs { .. } => Err(LowerError::UnsupportedOp {
                op: "AArch64 native RepMovs depends on the x86 direction flag".into(),
            }),
            OpKind::X86Enter(..) => Err(LowerError::UnsupportedOp {
                op: "AArch64 native x86 ENTER requires a fault-precise stack helper".into(),
            }),
            OpKind::X86Leave(..) => Err(LowerError::UnsupportedOp {
                op: "AArch64 native x86 LEAVE requires a fault-precise stack helper".into(),
            }),
            OpKind::IoIn { dst, width, .. } => self.lower_io_in(*dst, *width),
            OpKind::IoOut { width, .. } => self.lower_io_out(*width),
            OpKind::AtomicLoad {
                dst,
                addr,
                width,
                order,
            } => self.lower_atomic_load(*dst, addr, *width, *order),
            OpKind::AtomicStore {
                src,
                addr,
                width,
                order,
            } => self.lower_atomic_store(*src, addr, *width, *order),
            OpKind::LoadExclusive { dst, addr, width } => {
                self.lower_load_exclusive(*dst, addr, *width)
            }
            OpKind::StoreExclusive {
                status,
                src,
                addr,
                width,
            } => self.lower_store_exclusive(*status, *src, addr, *width),
            OpKind::AtomicRmw {
                dst,
                addr,
                src,
                op,
                width,
                order,
            } => self.lower_atomic_rmw(*dst, addr, *src, *op, *width, *order),
            OpKind::Cas {
                dst,
                success,
                addr,
                expected,
                new_val,
                width,
                order,
            } => self.lower_cas(*dst, *success, addr, *expected, *new_val, *width, *order),
            OpKind::AtomicCmpXadd {
                dst_old,
                addr,
                cmp,
                add,
                cond,
                width,
                order,
            } => self.lower_atomic_cmpxadd(*dst_old, addr, *cmp, *add, *cond, *width, *order),
            OpKind::LoadPair {
                dst1,
                dst2,
                addr,
                width,
            } => {
                if self.mem_helpers {
                    self.emit_jit_mem_load_pair_op(op.guest_pc, *dst1, *dst2, addr, *width)
                } else {
                    self.lower_load_pair(*dst1, *dst2, addr, *width)
                }
            }
            OpKind::StorePair {
                src1,
                src2,
                addr,
                width,
            } => {
                if self.mem_helpers {
                    self.emit_jit_mem_store_pair_op(op.guest_pc, *src1, *src2, addr, *width)
                } else {
                    self.lower_store_pair(*src1, *src2, addr, *width)
                }
            }
            OpKind::Not { dst, src, width } => self.lower_not(*dst, *src, *width),
            OpKind::Cmp { src1, src2, width } => self.lower_cmp(*src1, src2, *width),
            OpKind::ArmSimdSaturating(operation) => {
                if !super::aarch64_saturating_shape_valid(op) {
                    return Err(LowerError::UnsupportedOp {
                        op: "AArch64 saturating integer shape or provenance".to_string(),
                    });
                }
                self.lower_arm_simd_saturating(operation)
            }
            OpKind::ArmSimdLong(operation) => {
                if !super::aarch64_resize_shape_valid(op) {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native long shape {operation:?}"),
                    });
                }
                self.lower_arm_simd_long(operation)
            }
            OpKind::ArmSimdNarrow(operation) => {
                if !super::aarch64_resize_shape_valid(op) {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native narrow shape {operation:?}"),
                    });
                }
                self.lower_arm_simd_narrow(operation)
            }
            OpKind::Cmn { src1, src2, width } => {
                if !super::aarch64_cmn_shape_valid(op) {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native CMN shape {:?}", op.kind),
                    });
                }
                self.lower_cmn(*src1, src2, *width)
            }
            OpKind::Test { src1, src2, width } => self.lower_test(*src1, src2, *width),
            OpKind::Clz { dst, src, width } => self.lower_clz(*dst, *src, *width),
            OpKind::Ctz { dst, src, width } => self.lower_ctz(*dst, *src, *width),
            OpKind::Popcnt { dst, src, width } => self.lower_popcnt(*dst, *src, *width),
            OpKind::Crc32C {
                dst,
                crc,
                data,
                data_width,
            } => self.lower_crc32c(*dst, *crc, *data, *data_width),
            OpKind::X86Count {
                dst,
                src,
                width,
                kind,
                flags,
            } => self.lower_x86_count(*dst, *src, *width, *kind, *flags),
            OpKind::Bsf {
                dst,
                src,
                width,
                flags,
            } => self.lower_bsf(*dst, *src, *width, *flags),
            OpKind::Bsr {
                dst,
                src,
                width,
                flags,
            } => self.lower_bsr(*dst, *src, *width, *flags),
            OpKind::Bextr {
                dst,
                src,
                control,
                width,
                flags,
            } => self.lower_bextr(*dst, *src, *control, *width, *flags),
            OpKind::Bzhi {
                dst,
                src,
                index,
                width,
                flags,
            } => self.lower_bzhi(*dst, *src, *index, *width, *flags),
            OpKind::X86Bls {
                dst,
                src,
                width,
                kind,
                flags,
            } => self.lower_x86_bls(*dst, *src, *width, *kind, *flags),
            OpKind::X86Tbm {
                dst,
                src,
                width,
                kind,
                flags,
            } => {
                if op.x86_hint.is_some() {
                    return Err(LowerError::InvalidOperand {
                        op: "X86Tbm".to_string(),
                        operand: "encoding hints are unsupported".to_string(),
                    });
                }
                self.lower_x86_tbm(*dst, *src, *width, *kind, *flags)
            }
            OpKind::X86Adx {
                dst,
                src1,
                src2,
                width,
                kind,
                flags,
            } => self.lower_x86_adx(*dst, *src1, *src2, *width, *kind, *flags),
            OpKind::Pdep {
                dst,
                src,
                mask,
                width,
            } => self.lower_pdep_pext(*dst, *src, *mask, *width, true),
            OpKind::Pext {
                dst,
                src,
                mask,
                width,
            } => self.lower_pdep_pext(*dst, *src, *mask, *width, false),
            OpKind::ClMul {
                dst,
                dst_hi,
                src1,
                src2,
                elem_bits,
                lanes,
                acc,
            } => self.lower_clmul(*dst, *dst_hi, src1, src2, *elem_bits, *lanes, *acc),
            OpKind::Bswap { dst, src, width } => self.lower_bswap(*dst, *src, *width),
            OpKind::Rbit { dst, src, width } => self.lower_rbit(*dst, *src, *width),
            OpKind::Bfx {
                dst,
                src,
                lsb,
                width_bits,
                sign_extend,
                op_width,
            } => self.lower_bfx(*dst, *src, *lsb, *width_bits, *sign_extend, *op_width),
            OpKind::Bfi {
                dst,
                dst_in,
                src,
                lsb,
                width_bits,
                op_width,
            } => self.lower_bfi(*dst, *dst_in, *src, *lsb, *width_bits, *op_width),
            OpKind::Lea { dst, addr } => self.lower_lea(*dst, addr, op.guest_pc),
            // Width-aware x86 LEA is admitted only by the x86-64 host gate.
            // The AArch64 backend must reject it until W16 partial-register
            // merging and W32 zero-extension are implemented and tested.
            OpKind::X86Lea { .. } => Err(LowerError::UnsupportedOp {
                op: "x86 width-aware LEA on AArch64 host".to_string(),
            }),
            OpKind::ZeroExtend {
                dst,
                src,
                from_width,
                to_width,
            } => self.lower_extend(*dst, *src, *from_width, *to_width, false),
            OpKind::SignExtend {
                dst,
                src,
                from_width,
                to_width,
            } => self.lower_extend(*dst, *src, *from_width, *to_width, true),
            OpKind::Truncate {
                dst, src, to_width, ..
            } => self.lower_truncate(*dst, *src, *to_width),
            OpKind::Cwd { dst, src, width } => self.lower_cwd(*dst, *src, *width),
            OpKind::Xchg { reg1, reg2, width } => self.lower_xchg(*reg1, *reg2, *width),
            OpKind::Shl {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_shift_flag_contract(*dst, *src, amount, ShiftOp::Lsl, *flags, *width),
            OpKind::Shr {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_shift_flag_contract(*dst, *src, amount, ShiftOp::Lsr, *flags, *width),
            OpKind::Sar {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_shift_flag_contract(*dst, *src, amount, ShiftOp::Asr, *flags, *width),
            OpKind::Shld {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_double_shift(*dst, *src, amount, true, flags.updates_any(), *width),
            OpKind::Shrd {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_double_shift(*dst, *src, amount, false, flags.updates_any(), *width),
            OpKind::X86NddDoubleShift {
                dst,
                base,
                fill,
                amount,
                width,
                left,
                flags,
            } => self.lower_x86_ndd_double_shift(*dst, *base, *fill, amount, *width, *left, *flags),
            OpKind::Ror {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_shift(
                *dst,
                *src,
                amount,
                ShiftOp::Ror,
                flags.updates_any(),
                *width,
            ),
            OpKind::ArmRegShift {
                dst,
                src,
                amount,
                shift,
                width,
                flags,
            } => self.lower_arm_reg_shift(*dst, *src, amount, *shift, *width, *flags),
            OpKind::ArmDpRegShift {
                kind,
                dst,
                rn,
                rm,
                rs,
                shift,
                flags,
            } => self.lower_arm_dp_reg_shift(*kind, *dst, *rn, *rm, *rs, *shift, *flags),
            OpKind::Rol {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_rol(*dst, *src, amount, flags.updates_any(), *width),
            OpKind::Rcl {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_rotate_carry(*dst, *src, amount, *width, *flags, false),
            OpKind::Rcr {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_rotate_carry(*dst, *src, amount, *width, *flags, true),
            OpKind::BidirShift {
                dst,
                src,
                amount,
                kind,
                width,
            } => self.lower_bidir_shift(*dst, src, amount, *kind, *width),
            OpKind::Bt { src, index, width } => {
                self.lower_bit_test(None, *src, index, BitTestAction::Test, *width)
            }
            OpKind::Bts {
                dst,
                src,
                index,
                width,
            } => self.lower_bit_test(Some(*dst), *src, index, BitTestAction::Set, *width),
            OpKind::Btr {
                dst,
                src,
                index,
                width,
            } => self.lower_bit_test(Some(*dst), *src, index, BitTestAction::Reset, *width),
            OpKind::Btc {
                dst,
                src,
                index,
                width,
            } => self.lower_bit_test(Some(*dst), *src, index, BitTestAction::Toggle, *width),
            OpKind::Select {
                dst,
                cond,
                src_true,
                src_false,
                width,
            } => self.lower_select(*dst, *cond, *src_true, *src_false, *width),
            OpKind::CMove {
                dst,
                src,
                cond,
                width,
            } => self.lower_cmove(*dst, *src, *cond, *width),
            OpKind::SetCF { value } => self.lower_set_cf(*value),
            OpKind::CmcCF => self.lower_cfinv(),
            OpKind::SetCC { dst, cond, width } => self.lower_setcc(*dst, *cond, *width),
            OpKind::TestCondition { dst, cond } => self.lower_test_condition(*dst, *cond),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native lowering for {other:?}"),
            }),
        }
    }

    pub(crate) fn lower_switch(
        &mut self,
        index: VReg,
        targets: &[BlockId],
        default: BlockId,
    ) -> Result<(), LowerError> {
        if let VReg::Imm(value) = index {
            let target = if value >= 0 {
                targets.get(value as usize).copied().unwrap_or(default)
            } else {
                default
            };
            self.emit_branch_placeholder(target);
            return Ok(());
        }

        let index = Self::gpr_arm_or_x86(index)?;
        // Compare each case WITHOUT touching NZCV: a flag-setting CMP (SUBS) would
        // corrupt guest condition flags that may be live across the Switch (later
        // blocks read native NZCV as architectural state). Instead subtract into a
        // saved scratch (no flags) and branch on zero via CBZ/CBNZ. The scratch is
        // restored on every exit path so neither NZCV nor any guest register is
        // clobbered. (#20)
        let scratch = Self::scratch_regs(&[index], 1)?[0];
        self.emit_scratch_save(&[scratch]); // str scratch, [sp, #-16]!
        for (case, target) in targets.iter().enumerate() {
            let case = i64::try_from(case).map_err(|_| LowerError::InvalidOperand {
                op: "AArch64 native switch case".into(),
                operand: format!("case index {case}"),
            })?;
            // scratch = index - case  (no flags).
            self.emit_addsub_imm(scratch, index, case, true, false, OpWidth::W64)?;
            // CBNZ scratch, <skip>: if index != case, fall through to the next case.
            let skip = self.code.position();
            self.emit(0xb500_0000 | (scratch as u32));
            // Match path: restore the scratch (and SP) before branching to the case.
            self.emit_scratch_restore(&[scratch]); // ldr scratch, [sp], #16
            self.emit_branch_placeholder(*target);
            self.patch_compare_branch_to_current(skip, scratch, true)?;
        }
        // No case matched: restore the scratch and take the default edge.
        self.emit_scratch_restore(&[scratch]);
        self.emit_branch_placeholder(default);
        Ok(())
    }

    pub(crate) fn lower_terminator(
        &mut self,
        block: &SmirBlock,
        folded_cond: Option<Condition>,
    ) -> Result<(), LowerError> {
        match &block.terminator {
            Terminator::IndirectBranch {
                target: VReg::Arch(ArchReg::Arm(ArmReg::Pc)),
                ..
            } if self.pauth_helpers => self.emit_pauth_control_exit(),
            Terminator::Branch { target } => self.lower_branch_edge(block.id, *target),
            Terminator::CondBranch {
                cond,
                true_target,
                false_target,
            } => self.lower_cond_branch(block.id, *cond, *true_target, *false_target, folded_cond),
            Terminator::Switch {
                index,
                targets,
                default,
            } => self.lower_switch(*index, targets, *default),
            Terminator::IndirectBranch {
                target,
                possible_targets,
            } if self.guest_indirect_exits && possible_targets.is_empty() => {
                self.emit_guest_indirect_exit(*target)
            }
            // Do NOT emit a native `br Xn`: the lowerer is identity-mapped, so the
            // register holds GUEST-controlled data, and branching through it is a
            // host control-flow hijack (or a reliable crash). The only admitted
            // exception above records an AArch32 dispatcher exit; it does not
            // execute the target as a host address. (#18)
            Terminator::IndirectBranch { .. } => Err(LowerError::UnsupportedOp {
                op: "AArch64 native indirect branch to a guest-controlled target; deopt to \
                     interpreter"
                    .into(),
            }),
            Terminator::Call {
                target: CallTarget::GuestAddrInterworking { addr, thumb },
                args,
                ..
            } if self.guest_interworking_call_exits && args.is_empty() => {
                self.emit_guest_direct_interworking_exit(*addr, *thumb)
            }
            Terminator::Call {
                target: CallTarget::IndirectInterworking(target),
                args,
                ..
            } if self.guest_interworking_call_exits
                && args.is_empty()
                && matches!(
                    target,
                    VReg::Arch(ArchReg::Arm(ArmReg::X(index))) if *index < 14
                ) =>
            {
                self.emit_guest_indirect_exit(*target)
            }
            Terminator::Call {
                target: CallTarget::GuestAddr(target),
                args,
                ..
            } if self.guest_call_exits && args.is_empty() => self.emit_native_exit(*target),
            Terminator::Return { .. } => {
                self.emit(0xd65f_03c0);
                Ok(())
            }
            // See the OpKind::Breakpoint/Undefined note above: a host BRK/UDF would
            // raise SIGTRAP/SIGILL and kill the emulator. Bail to the interpreter,
            // which raises the proper guest exception. (#16)
            Terminator::Trap {
                kind: TrapKind::Breakpoint,
            } => Err(LowerError::UnsupportedOp {
                op: "AArch64 native Breakpoint trap (host BRK would SIGTRAP); deopt to interpreter"
                    .into(),
            }),
            Terminator::Trap {
                kind: TrapKind::SystemCall,
            } => Err(LowerError::UnsupportedOp {
                op: "AArch64 native SystemCall trap".into(),
            }),
            Terminator::Trap {
                kind: TrapKind::Halt,
            } => Err(LowerError::UnsupportedOp {
                op: "AArch64 native Halt trap".into(),
            }),
            Terminator::Trap {
                kind: TrapKind::Undefined | TrapKind::InvalidOpcode,
            }
            | Terminator::Unreachable => Err(LowerError::UnsupportedOp {
                op: "AArch64 native Undefined/Unreachable trap (host UDF would SIGILL); deopt to \
                     interpreter"
                    .into(),
            }),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native terminator {other:?}"),
            }),
        }
    }
}
