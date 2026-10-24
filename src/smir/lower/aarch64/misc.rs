//! Uncategorized lowering helpers

use crate::smir::lower::aarch64::*;
use std::collections::HashMap;

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{
    ArmDpRegShiftKind, OpKind, SmirOp, X86AdxKind, X86BlsKind, X86CountKind,
};
use crate::smir::ir::types::{
    Address, ArchReg, ArmReg, AtomicOp, Avx10FP16Op, BlockId, Condition, ExtendOp, FpPrecision,
    FpRoundMode, MemWidth, MemoryOrder, OpWidth, ShiftOp, SignExtend, SrcOperand, VLaneOp, VReg,
    VecElementType, VecPermuteKind, VecWidth,
};
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

use super::{CodeBuffer, LowerError, LowerResult, Relocation, SmirLowerer};

impl Aarch64Lowerer {
    pub fn new() -> Self {
        Self {
            code: CodeBuffer::with_capacity(1024),
            block_offsets: HashMap::new(),
            branch_fixups: Vec::new(),
            relocations: Vec::new(),
            native_exits: HashMap::new(),
            native_exit_edges: HashMap::new(),
            guest_call_exits: false,
            guest_interworking_call_exits: false,
            guest_indirect_exits: false,
            x86_guest_state_guards: false,
            mem_helpers: false,
            pauth_helpers: false,
            pauth_fp_helpers: false,
            mem_helper_addr_width: OpWidth::W64,
            flagm_available: Self::detect_flagm_available(),
            flagm2_available: Self::detect_flagm2_available(),
            fp16_available: Self::detect_fp16_available(),
            crc_available: Self::detect_crc_available(),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_crc_available_for_test(&mut self, available: bool) {
        self.crc_available = available;
    }

    /// Mark frontier blocks as native-exit stubs (block id → resume guest PC).
    /// Call before `lower_function`. See [`Aarch64Lowerer::native_exits`].
    pub fn set_native_exits(&mut self, exits: HashMap<BlockId, u64>) {
        self.native_exits = exits;
    }

    /// Mark frontier-crossing control-flow edges as native-exit stubs
    /// (`(source, target)` → resume guest PC). Call before `lower_function`.
    pub fn set_native_exit_edges(&mut self, exits: HashMap<(BlockId, BlockId), u64>) {
        self.native_exit_edges = exits;
    }

    pub(crate) fn emit(&mut self, word: u32) {
        self.code.emit_u32(word);
    }

    /// Emit a native-exit stub: record `resume_pc` into the guest state struct's
    /// PC field (via the state pointer in `A64_STATE_REG` = x28) and `ret` to
    /// the entry trampoline. The scratch register is spilled to the host stack
    /// around its use so the live guest GPRs the trampoline must write back are
    /// left intact.
    pub(crate) fn emit_native_exit(&mut self, resume_pc: u64) -> Result<(), LowerError> {
        const SCRATCH: u8 = 9;
        self.emit_push_scratch(SCRATCH); // str x9, [sp, #-16]!
        self.emit_mov_imm(SCRATCH, resume_pc as i64, OpWidth::W64);
        // str x9, [x28, #A64_GUEST_PC_OFFSET]  (64-bit unsigned scaled offset)
        self.emit_ldst_unsigned(SCRATCH, A64_STATE_REG, 3, 0b00, A64_GUEST_PC_OFFSET / 8);
        self.emit_mov_imm(SCRATCH, A64_EXIT_VALID, OpWidth::W64);
        self.emit_ldst_unsigned(
            SCRATCH,
            A64_STATE_REG,
            3,
            0b00,
            A64_GUEST_EXIT_FLAGS_OFFSET / 8,
        );
        self.emit_pop_scratch(SCRATCH); // ldr x9, [sp], #16
        self.emit(0xd65f_03c0); // ret
        Ok(())
    }

    /// Bytes accessed for a scalar memory width (the helper ABI `size` arg).
    pub(crate) fn mem_width_bytes(width: MemWidth) -> Result<u32, LowerError> {
        match width {
            MemWidth::B1 => Ok(1),
            MemWidth::B2 => Ok(2),
            MemWidth::B4 => Ok(4),
            MemWidth::B8 => Ok(8),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 mem-helper width {other:?}"),
            }),
        }
    }

    /// Vector access size in bytes for the helper ABI.
    pub(crate) fn vec_width_bytes(width: VecWidth) -> Result<u32, LowerError> {
        match width {
            VecWidth::V64 => Ok(8),
            VecWidth::V128 => Ok(16),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 vector mem-helper width {other:?}"),
            }),
        }
    }

    pub(crate) fn sf(width: OpWidth) -> Result<u32, LowerError> {
        match width {
            OpWidth::W32 => Ok(0),
            OpWidth::W64 => Ok(1),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native scalar width {other:?}"),
            }),
        }
    }

    pub(crate) fn gpr(vreg: VReg) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            VReg::Imm(0) => Ok(31),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected X register, got {other:?}"
            ))),
        }
    }

    pub(crate) fn dst_gpr(vreg: VReg) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected writable X register, got {other:?}"
            ))),
        }
    }

    pub(crate) fn fp_type(precision: FpPrecision) -> Result<u32, LowerError> {
        match precision {
            FpPrecision::F32 => Ok(0b00),
            FpPrecision::F64 => Ok(0b01),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native FP precision {other:?}"),
            }),
        }
    }

    pub(crate) fn base_gpr(vreg: VReg) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            VReg::Arch(ArchReg::Arm(ArmReg::Sp)) => Ok(31),
            VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index().filter(|&n| n < 31).ok_or_else(|| {
                LowerError::InvalidRegister(format!(
                    "AArch64 native lowerer expected memory base register, got X86({reg:?})"
                ))
            }),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected memory base register, got {other:?}"
            ))),
        }
    }

    pub(crate) fn lea_base_gpr(vreg: VReg) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::Sp)) => Ok(31),
            other => Self::gpr_arm_or_x86(other),
        }
    }

    pub(crate) fn dst_or_zero_for_flags(vreg: VReg, set_flags: bool) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            VReg::Virtual(_) if set_flags => Ok(31),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected writable X register, got {other:?}"
            ))),
        }
    }

    pub(crate) fn fp_convert_opcode(to: FpPrecision) -> Result<u32, LowerError> {
        match to {
            FpPrecision::F32 => Ok(0b00100),
            FpPrecision::F64 => Ok(0b00101),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native FP conversion destination {other:?}"),
            }),
        }
    }

    pub(crate) fn fp_to_int_rmode(round: FpRoundMode) -> Result<u32, LowerError> {
        match round {
            FpRoundMode::RoundNearest => Ok(0b00),
            FpRoundMode::RoundUp => Ok(0b01),
            FpRoundMode::RoundDown => Ok(0b10),
            FpRoundMode::RoundTowardZero => Ok(0b11),
            FpRoundMode::RoundNearestTiesAway => Err(LowerError::UnsupportedOp {
                op: "AArch64 native FpToInt ties-away rmode".to_string(),
            }),
            FpRoundMode::Dynamic => Err(LowerError::UnsupportedOp {
                op: "AArch64 native FpToInt dynamic rounding".to_string(),
            }),
        }
    }

    /// Emit `dst = extend(src) << amount` for an add/sub *extended-register*
    /// zero base. In the extended-register and immediate add/sub encodings
    /// `Rn = 31` denotes SP/WSP (not XZR/WZR), so a zero base must never be
    /// routed through them: doing so computes `SP ± extend(src)` and leaks the
    /// host stack pointer into guest-visible state (#58). Realize the
    /// extend+shift directly with UBFIZ / SBFIZ / LSL, none of which reference
    /// SP. `option` is the 3-bit add/sub extend field (bit2 = signed, bits[1:0]
    /// = source size: 00=B, 01=H, 10=W, 11=X); `amount` is the 0..4 shift.
    pub(crate) fn emit_zero_base_extended(
        &mut self,
        dst: u8,
        src: u8,
        option: u32,
        amount: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let regbits = width.bits();
        let signed = (option & 0b100) != 0;
        let ext_bits: u32 = match option & 0b011 {
            0b00 => 8,
            0b01 => 16,
            0b10 => 32,
            _ => 64,
        };
        let emit_width = if width == OpWidth::W64 {
            OpWidth::W64
        } else {
            OpWidth::W32
        };
        if ext_bits >= regbits {
            // No narrowing extension applies (UXTX/SXTX, or *XTW at W32): the
            // value is simply `src << amount`.
            if amount == 0 {
                return self.emit_mov_reg(dst, src, emit_width);
            }
            return self.lower_shift_imm(dst, src, i64::from(amount), ShiftOp::Lsl, emit_width);
        }
        // UBFIZ/SBFIZ dst, src, #amount, #ext_bits == (extend low ext_bits bits
        // of src) << amount, with the rest of the register zeroed.
        let immr = (regbits - amount) & (regbits - 1);
        let imms = ext_bits - 1;
        self.emit_bitfield(
            dst,
            src,
            if signed { 0b00 } else { 0b10 },
            immr,
            imms,
            emit_width,
        )
    }

    pub(crate) fn emit_zero_base_extended_flags(
        &mut self,
        src: u8,
        option: u32,
        amount: u32,
        subtract: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let scratch = Self::scratch_regs(&[src], 1)?[0];
        self.emit_scratch_save(&[scratch]);

        let mut result = self.emit_zero_base_extended(scratch, src, option, amount, width);
        if result.is_ok() {
            result = self.emit_addsub_reg(31, 31, scratch, subtract, true, width);
        }

        self.emit_scratch_restore(&[scratch]);
        result
    }

    pub(crate) fn emit_dp2(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        opcode2: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (0b0011010110 << 21)
                | ((rm as u32) << 16)
                | (opcode2 << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    pub(crate) fn emit_dp3(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        ra: u8,
        op31: u32,
        o0: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (0b11011 << 24)
                | (op31 << 21)
                | ((rm as u32) << 16)
                | (o0 << 15)
                | ((ra as u32) << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    pub(crate) fn emit_dp1(
        &mut self,
        dst: u8,
        rn: u8,
        opcode: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31) | (0b1011010110 << 21) | (opcode << 10) | ((rn as u32) << 5) | (dst as u32),
        );
        Ok(())
    }

    pub(crate) fn emit_prfm_literal(&mut self, prfop: u8, imm19: i32) {
        self.emit(
            (0b11 << 30)
                | (0b011 << 27)
                | (((imm19 as u32) & 0x7ffff) << 5)
                | u32::from(prfop & 0x1f),
        );
    }

    pub(crate) fn mem_size(width: MemWidth) -> Result<u32, LowerError> {
        match width {
            MemWidth::B1 => Ok(0),
            MemWidth::B2 => Ok(1),
            MemWidth::B4 => Ok(2),
            MemWidth::B8 => Ok(3),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native scalar memory width {other:?}"),
            }),
        }
    }

    pub(crate) fn pair_width(width: MemWidth) -> Result<(u32, i64), LowerError> {
        match width {
            MemWidth::B4 => Ok((0b00, 4)),
            MemWidth::B8 => Ok((0b10, 8)),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native pair memory width {other:?}"),
            }),
        }
    }

    pub(crate) fn load_opc(width: MemWidth, sign: SignExtend) -> Result<u32, LowerError> {
        match (sign, width) {
            (SignExtend::Zero, _) | (SignExtend::Sign, MemWidth::B8) => Ok(0b01),
            (SignExtend::Sign, MemWidth::B1 | MemWidth::B2 | MemWidth::B4) => Ok(0b10),
            _ => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native signed load width {width:?}"),
            }),
        }
    }

    pub(crate) fn mem_access_parts(
        kind: &OpKind,
    ) -> Result<Option<(u8, &Address, u32, u32)>, LowerError> {
        match kind {
            OpKind::Load {
                dst,
                addr,
                width,
                sign,
            } => Ok(Some((
                Self::dst_gpr_arm_or_x86(*dst)?,
                addr,
                Self::mem_size(*width)?,
                Self::load_opc(*width, *sign)?,
            ))),
            OpKind::Store {
                src: VReg::Imm(_), ..
            } => Ok(None),
            OpKind::Store { src, addr, width } => Ok(Some((
                Self::gpr_arm_or_x86(*src)?,
                addr,
                Self::mem_size(*width)?,
                0b00,
            ))),
            _ => Ok(None),
        }
    }

    pub(crate) fn mem_access_sequence_parts(
        ops: &[SmirOp],
    ) -> Result<Option<(u8, &Address, u32, u32, usize)>, LowerError> {
        if let [load, extend, ..] = ops {
            if let Some((rt, addr, size, opc)) =
                Self::signed_load_w_parts(&load.kind, &extend.kind)?
            {
                return Ok(Some((rt, addr, size, opc, 2)));
            }
        }

        if let [access, ..] = ops {
            if let Some((rt, addr, size, opc)) = Self::mem_access_parts(&access.kind)? {
                return Ok(Some((rt, addr, size, opc, 1)));
            }
        }

        Ok(None)
    }

    pub(crate) fn pair_access_parts(
        kind: &OpKind,
    ) -> Result<Option<(u8, u8, &Address, MemWidth, bool)>, LowerError> {
        match kind {
            OpKind::LoadPair {
                dst1,
                dst2,
                addr,
                width,
            } => Ok(Some((
                Self::dst_gpr_arm_or_x86(*dst1)?,
                Self::dst_gpr_arm_or_x86(*dst2)?,
                addr,
                *width,
                true,
            ))),
            OpKind::StorePair {
                src1,
                src2,
                addr,
                width,
            } => Ok(Some((
                Self::gpr_arm_or_x86(*src1)?,
                Self::gpr_arm_or_x86(*src2)?,
                addr,
                *width,
                false,
            ))),
            _ => Ok(None),
        }
    }

    pub(crate) fn addr_base_offset(addr: &Address) -> Option<(VReg, i64)> {
        match addr {
            Address::Direct(base) => Some((*base, 0)),
            Address::BaseOffset { base, offset, .. } => Some((*base, *offset)),
            _ => None,
        }
    }

    pub(crate) fn addr_plus_eq(base_addr: &Address, plus_addr: &Address, delta: i64) -> bool {
        match (
            Self::addr_base_offset(base_addr),
            Self::addr_base_offset(plus_addr),
        ) {
            (Some((base, offset)), Some((plus_base, plus_offset))) => {
                base == plus_base && plus_offset == offset + delta
            }
            _ => false,
        }
    }

    pub(crate) fn src_operand_is_zero(src: &SrcOperand) -> bool {
        match src {
            SrcOperand::Reg(VReg::Imm(0)) => true,
            SrcOperand::Shifted { reg, shift, .. } => {
                *reg == VReg::Imm(0)
                    && matches!(
                        shift,
                        ShiftOp::Lsl | ShiftOp::Lsr | ShiftOp::Asr | ShiftOp::Ror
                    )
            }
            SrcOperand::Extended { reg, .. } => *reg == VReg::Imm(0),
            _ => false,
        }
    }

    pub(crate) fn mem_extend_option(from_width: OpWidth, signed: bool) -> Option<u32> {
        match (from_width, signed) {
            (OpWidth::W32, false) => Some(0b010),
            (OpWidth::W64, false) => Some(0b011),
            (OpWidth::W32, true) => Some(0b110),
            (OpWidth::W64, true) => Some(0b111),
            _ => None,
        }
    }

    pub(crate) fn mem_extend_parts(kind: &OpKind) -> Option<(VReg, VReg, u32)> {
        match kind {
            OpKind::ZeroExtend {
                dst,
                src,
                from_width,
                to_width: OpWidth::W64,
            } => Some((*dst, *src, Self::mem_extend_option(*from_width, false)?)),
            OpKind::SignExtend {
                dst,
                src,
                from_width,
                to_width: OpWidth::W64,
            } => Some((*dst, *src, Self::mem_extend_option(*from_width, true)?)),
            _ => None,
        }
    }

    pub(crate) fn lower_vload(
        &mut self,
        dst: VReg,
        addr: &Address,
        width: VecWidth,
    ) -> Result<(), LowerError> {
        let rt = Self::fp_reg(dst)?;
        self.lower_simd_mem_access(rt, addr, width, true)
    }

    pub(crate) fn lower_vstore(
        &mut self,
        src: VReg,
        addr: &Address,
        width: VecWidth,
    ) -> Result<(), LowerError> {
        let rt = Self::fp_reg(src)?;
        self.lower_simd_mem_access(rt, addr, width, false)
    }

    pub(crate) fn lower_vmov(
        &mut self,
        dst: VReg,
        src: VReg,
        width: VecWidth,
    ) -> Result<(), LowerError> {
        let rd = Self::fp_reg(dst)?;
        let rn = Self::fp_reg(src)?;
        self.emit_simd_logical(rd, rn, rn, width, SimdLogicOp::Or)
    }

    pub(crate) fn lower_vbit_select(
        &mut self,
        dst: VReg,
        mask: VReg,
        src_true: VReg,
        src_false: VReg,
        width: VecWidth,
    ) -> Result<(), LowerError> {
        let rd = Self::fp_reg(dst)?;
        let q = Self::simd_vec_q(width)?;

        if mask == dst {
            let rn = Self::fp_reg(src_true)?;
            let rm = Self::fp_reg(src_false)?;
            self.emit_simd_three_same(rd, rn, rm, q, 1, 0b01, 0b00011);
            return Ok(());
        }

        if src_false == dst {
            let rn = Self::fp_reg(src_true)?;
            let rm = Self::fp_reg(mask)?;
            self.emit_simd_three_same(rd, rn, rm, q, 1, 0b10, 0b00011);
            return Ok(());
        }

        if src_true == dst {
            let rn = Self::fp_reg(src_false)?;
            let rm = Self::fp_reg(mask)?;
            self.emit_simd_three_same(rd, rn, rm, q, 1, 0b11, 0b00011);
            return Ok(());
        }

        Err(LowerError::UnsupportedOp {
            op: format!(
                "AArch64 native VBitSelect shape dst={dst:?} mask={mask:?} true={src_true:?} false={src_false:?}"
            ),
        })
    }

    /// Lower a vector two-source permute (ZIP/UZP/TRN) to the native AArch64
    /// "advanced SIMD permute" form.
    pub(crate) fn lower_vpermute2(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        kind: VecPermuteKind,
    ) -> Result<(), LowerError> {
        let rd = Self::fp_reg(dst)?;
        let rn = Self::fp_reg(src1)?;
        let rm = Self::fp_reg(src2)?;
        let (q, size) = Self::simd_integer_shape(elem, lanes)?;
        let opcode = match kind {
            VecPermuteKind::Uzp1 => 0b001,
            VecPermuteKind::Trn1 => 0b010,
            VecPermuteKind::Zip1 => 0b011,
            VecPermuteKind::Uzp2 => 0b101,
            VecPermuteKind::Trn2 => 0b110,
            VecPermuteKind::Zip2 => 0b111,
        };
        self.emit_simd_permute(rd, rn, rm, q, size, opcode);
        Ok(())
    }

    /// Lower a vector table lookup (TBL/TBX) to the native AArch64 "advanced
    /// SIMD table lookup" form: `0 Q 0 01110 00 0 Rm 0 len op 00 Rn Rd`, where
    /// len = num_tables - 1 (the native instruction reads the consecutive table
    /// registers Rn..Rn+len itself) and op = TBX.
    pub(crate) fn lower_vtable(
        &mut self,
        dst: VReg,
        table: VReg,
        num_tables: u8,
        index: VReg,
        lanes: u8,
        is_tbx: bool,
    ) -> Result<(), LowerError> {
        if !(1..=4).contains(&num_tables) {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 TBL/TBX table count {num_tables}"),
            });
        }
        let rd = Self::fp_reg(dst)?;
        let rn = Self::fp_reg(table)?;
        let rm = Self::fp_reg(index)?;
        let q = if lanes == 16 { 1 } else { 0 };
        let len = u32::from(num_tables - 1);
        let op = if is_tbx { 1 } else { 0 };
        self.emit(
            0x0e00_0000
                | (q << 30)
                | ((rm as u32) << 16)
                | (len << 13)
                | (op << 12)
                | ((rn as u32) << 5)
                | (rd as u32),
        );
        Ok(())
    }

    pub(crate) fn lower_vfp16_arith(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        op: Avx10FP16Op,
        width: VecWidth,
    ) -> Result<(), LowerError> {
        // FP16 Advanced SIMD arithmetic (FADD/FSUB/FMUL/FDIV .4h/.8h) requires the
        // optional FEAT_FP16 extension. On a host without it the emitted encodings
        // are UNDEFINED and would SIGILL, so bail to the interpreter (which performs
        // FP16 in software) when the host lacks the feature. (#32)
        if !self.fp16_available {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native FP16 vector arithmetic without host FEAT_FP16".into(),
            });
        }
        let rd = Self::fp_reg(dst)?;
        let rn = Self::fp_reg(src1)?;
        let rm = Self::fp_reg(src2)?;
        let q = Self::simd_fp16_shape(width)?;
        let (u, a, opcode) = match op {
            Avx10FP16Op::Add => (0, 0, 0b010),
            Avx10FP16Op::Sub => (0, 1, 0b010),
            Avx10FP16Op::Mul => (1, 0, 0b011),
            Avx10FP16Op::Div => (1, 0, 0b111),
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native AVX10 FP16 operation {other:?}"),
                });
            }
        };
        self.emit_simd_fp16_three_same(rd, rn, rm, q, u, a, opcode);
        Ok(())
    }

    pub(crate) fn lower_vfma(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        acc: VReg,
        elem: VecElementType,
        lanes: u8,
        negate_product: bool,
        negate_acc: bool,
    ) -> Result<(), LowerError> {
        if negate_acc {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native vector FMA negated accumulator".to_string(),
            });
        }

        let rd = Self::fp_reg(dst)?;
        let rn = Self::fp_reg(src1)?;
        let rm = Self::fp_reg(src2)?;
        let ra = Self::fp_reg(acc)?;
        let (q, elem_size) = Self::simd_float_shape(elem, lanes)?;
        if rd != ra {
            if rd == rn || rd == rm {
                return Err(LowerError::UnsupportedOp {
                    op: "AArch64 native vector FMA accumulator copy alias".to_string(),
                });
            }
            let width = if q == 1 {
                VecWidth::V128
            } else {
                VecWidth::V64
            };
            self.lower_vmov(dst, acc, width)?;
        }

        let size = if negate_product {
            elem_size | 0b10
        } else {
            elem_size
        };
        self.emit_simd_three_same(rd, rn, rm, q, 0, size, 0b11001);
        Ok(())
    }

    pub(crate) fn lower_vnavg(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        signed: bool,
    ) -> Result<(), LowerError> {
        self.lower_vlane_three_same(dst, src1, src2, elem, lanes, signed, 0b00100, false)
    }

    pub(crate) fn lower_vpopcnt(
        &mut self,
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        width: VecWidth,
    ) -> Result<(), LowerError> {
        if elem != VecElementType::I8 {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native VPopcnt element {elem:?}"),
            });
        }
        self.lower_vlane_unary_two_reg(dst, src, elem, width.lanes(elem) as u8, 0, 0b00101, false)
    }

    pub(crate) fn lower_vmpsadbw(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
        imm: u8,
    ) -> Result<(), LowerError> {
        if width != VecWidth::V128 {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native VMPSADBW width {width:?}"),
            });
        }

        let rd = Self::fp_reg(dst)?;
        let rn = Self::fp_reg(src1)?;
        let rm = Self::fp_reg(src2)?;
        let (src1_work, src2_work) = Self::scratch_fp_reg_pair(&[rd, rn, rm])?;
        let simd_scratches = [src1_work, src2_work];
        self.emit_simd_scratch_save(&simd_scratches);
        self.emit_simd_logical(src1_work, rn, rn, VecWidth::V128, SimdLogicOp::Or)?;
        self.emit_simd_logical(src2_work, rm, rm, VecWidth::V128, SimdLogicOp::Or)?;

        let scratches = Self::scratch_regs(&[], 6)?;
        self.emit_scratch_save(&scratches);
        let lhs = scratches[0];
        let rhs = scratches[1];
        let diff = scratches[2];
        let alt = scratches[3];
        let sum = scratches[4];
        let saved_flags = scratches[5];
        self.emit_sysreg(saved_flags, ArmReg::Nzcv, true)?;

        // VMPSADBW computes eight SAD results: lane `i` slides a 4-byte window over
        // SRC1 (window start = imm[2]*4, then + i) and compares it against a FIXED
        // 4-byte block from SRC2 (block = imm[1:0]*4). The previous code had this
        // backwards (fixed SRC1, sliding SRC2). Every byte index stays inside the
        // 128-bit lane (src1 max 4+7+3=14, src2 max 12+3=15), so no padding. (#33)
        let src1_base = ((imm >> 2) & 0x1) * 4;
        let src2_base = (imm & 0x3) * 4;
        let uge = Self::arm_cond_code(Condition::Uge)?;
        for lane in 0..8 {
            self.emit_mov_imm(sum, 0, OpWidth::W32)?;
            for offset in 0..4 {
                let (_, src1_imm5) =
                    Self::simd_lane_imm5(VecElementType::I8, src1_base + lane + offset)?;
                self.emit_simd_umov(lhs, src1_work, src1_imm5, false);

                let (_, src2_imm5) = Self::simd_lane_imm5(VecElementType::I8, src2_base + offset)?;
                self.emit_simd_umov(rhs, src2_work, src2_imm5, false);

                self.emit_addsub_reg(diff, lhs, rhs, true, true, OpWidth::W32)?;
                self.emit_addsub_reg(alt, rhs, lhs, true, false, OpWidth::W32)?;
                self.emit_cond_select(diff, diff, alt, uge, 0, 0, OpWidth::W32)?;
                self.emit_addsub_reg(sum, sum, diff, false, false, OpWidth::W32)?;
            }
            let (_, dst_imm5) = Self::simd_lane_imm5(VecElementType::I16, lane)?;
            self.emit_simd_ins_general(rd, sum, dst_imm5);
        }

        self.emit_sysreg(saved_flags, ArmReg::Nzcv, false)?;
        self.emit_scratch_restore(&scratches);
        self.emit_simd_scratch_restore(&simd_scratches);
        Ok(())
    }

    pub(crate) fn lower_vminmax(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        width: VecWidth,
        imm: u8,
    ) -> Result<(), LowerError> {
        if !matches!(elem, VecElementType::F32 | VecElementType::F64) {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native VMINMAX element {elem:?}"),
            });
        }

        let lanes = width.lanes(elem) as u8;
        let op = if imm & 1 == 0 {
            SimdArithmeticOp::Min { signed: false }
        } else {
            SimdArithmeticOp::Max
        };
        self.lower_vfloat_arith(dst, src1, src2, elem, lanes, op)
    }

    pub(crate) fn lower_vpermute_mask_indices(
        &mut self,
        rd: u8,
        rm: u8,
        mask: i64,
    ) -> Result<(), LowerError> {
        let (imm_n, immr, imms) = Self::logical_bitmask_imm(mask, OpWidth::W32)?;
        let mut lane_imm5 = Vec::with_capacity(16);
        for lane in 0..16 {
            let (_, imm5) = Self::simd_lane_imm5(VecElementType::I8, lane)?;
            lane_imm5.push(imm5);
        }

        let scratches = Self::scratch_regs(&[], 1)?;
        self.emit_scratch_save(&scratches);
        let scratch = scratches[0];
        for imm5 in lane_imm5 {
            self.emit_simd_umov(scratch, rm, imm5, false);
            self.emit_logic_imm(scratch, scratch, 0b00, imm_n, immr, imms, OpWidth::W32)?;
            self.emit_simd_ins_general(rd, scratch, imm5);
        }
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn lower_vpermute(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: Option<VReg>,
        indices: VReg,
        elem: VecElementType,
        width: VecWidth,
        overwrite_table: bool,
    ) -> Result<(), LowerError> {
        if elem != VecElementType::I8 || width != VecWidth::V128 {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native vector permute elem={elem:?} width={width:?}"),
            });
        }
        if src2.is_none() && overwrite_table {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native vector permute missing second table".to_string(),
            });
        }

        let rd = Self::fp_reg(dst)?;
        let rn = Self::fp_reg(src1)?;
        let rm = Self::fp_reg(indices)?;
        if let Some(src2) = src2 {
            let r2 = Self::fp_reg(src2)?;
            let (table0, table1) = Self::scratch_fp_reg_pair(&[rd, rn, r2, rm])?;
            let tables = [table0, table1];
            self.emit_simd_scratch_save(&tables);
            self.emit_simd_logical(table0, rn, rn, VecWidth::V128, SimdLogicOp::Or)?;
            self.emit_simd_logical(table1, r2, r2, VecWidth::V128, SimdLogicOp::Or)?;
            self.lower_vpermute_mask_indices(rd, rm, 0x1f)?;
            self.emit_simd_tbl(rd, table0, rd, 1, 1, 0);
            self.emit_simd_scratch_restore(&tables);
        } else if rd == rn {
            let table = Self::scratch_fp_reg(&[rd, rm])?;
            self.emit_simd_scratch_save(&[table]);
            self.emit_simd_logical(table, rn, rn, VecWidth::V128, SimdLogicOp::Or)?;
            self.lower_vpermute_mask_indices(rd, rm, 0x0f)?;
            self.emit_simd_tbl(rd, table, rd, 1, 0, 0);
            self.emit_simd_scratch_restore(&[table]);
        } else {
            self.lower_vpermute_mask_indices(rd, rm, 0x0f)?;
            self.emit_simd_tbl(rd, rn, rd, 1, 0, 0);
        }
        Ok(())
    }

    pub(crate) fn lower_rep_stos(
        &mut self,
        dst: VReg,
        src: VReg,
        count: VReg,
        width: MemWidth,
    ) -> Result<(), LowerError> {
        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        let src = Self::gpr_arm_or_x86(src)?;
        let count = Self::dst_gpr_arm_or_x86(count)?;
        let size = Self::mem_size(width)?;
        let stride = width.bytes() as i64;
        let scratches = Self::scratch_regs(&[dst, src, count], 2)?;
        let addr = scratches[0];
        let remaining = scratches[1];

        self.emit_scratch_save(&scratches);
        self.emit_mov_reg(addr, dst, OpWidth::W64)?;
        self.emit_mov_reg(remaining, count, OpWidth::W64)?;

        let loop_start = self.code.position();
        let done = self.code.position();
        self.emit(0xb400_0000 | u32::from(remaining));
        self.emit_ldst_unsigned(src, addr, size, 0b00, 0);
        self.emit_addsub_imm(addr, addr, stride, false, false, OpWidth::W64)?;
        self.emit_addsub_imm(remaining, remaining, 1, true, false, OpWidth::W64)?;
        self.emit_branch_to_offset(loop_start)?;

        self.patch_compare_branch_to_current(done, remaining, false)?;
        self.emit_mov_reg(dst, addr, OpWidth::W64)?;
        self.emit_mov_reg(count, remaining, OpWidth::W64)?;
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn io_width(width: MemWidth) -> Result<(), LowerError> {
        match width {
            MemWidth::B1 | MemWidth::B2 | MemWidth::B4 => Ok(()),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native I/O width {other:?}"),
            }),
        }
    }

    pub(crate) fn lower_io_in(&mut self, dst: VReg, width: MemWidth) -> Result<(), LowerError> {
        Self::io_width(width)?;
        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        self.emit_mov_imm(dst, 0, OpWidth::W64)
    }

    pub(crate) fn lower_io_out(&mut self, width: MemWidth) -> Result<(), LowerError> {
        Self::io_width(width)
    }

    pub(crate) fn lower_prefetch(
        &mut self,
        addr: &Address,
        write: bool,
        guest_pc: u64,
    ) -> Result<(), LowerError> {
        let prfop = if write { 0b10000 } else { 0b00000 };
        if let Address::PcRel { offset, base, .. } = addr {
            let base = base.unwrap_or(guest_pc) as i64;
            let target = base.wrapping_add(*offset);
            let insn_pc = guest_pc as i64;
            let imm19 = Self::literal_scaled_imm19("AArch64 PRFM literal", target, insn_pc)?;
            self.emit_prfm_literal(prfop, imm19);
            return Ok(());
        }

        self.lower_mem_access(prfop, addr, 3, 0b10)
    }

    pub(crate) fn exclusive_base_gpr(addr: &Address) -> Result<u8, LowerError> {
        match addr {
            Address::Direct(base) => Self::base_gpr(*base),
            Address::BaseOffset { base, offset, .. } if *offset == 0 => Self::base_gpr(*base),
            Address::BaseOffset { offset, .. } => Err(LowerError::InvalidOperand {
                op: "AArch64 native exclusive memory offset".into(),
                operand: format!("{offset:#x}"),
            }),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native exclusive memory address {other:?}"),
            }),
        }
    }

    pub(crate) fn lower_ldclr(
        &mut self,
        dst: VReg,
        addr: &Address,
        src: VReg,
        width: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), LowerError> {
        let rt = Self::dst_gpr_arm_or_x86(dst)?;
        let rs = Self::gpr_arm_or_x86(src)?;
        let size = Self::mem_size(width)?;
        let (acquire, release) = Self::atomic_order_bits(order);
        let (scratches, rn) = self.lower_atomic_addr_to_base(&[rt, rs], addr)?;
        self.emit_atomic_rmw(rt, rn, rs, size, acquire, release, 0, 0b001);
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn cas_compare_width(width: MemWidth) -> Result<OpWidth, LowerError> {
        match width {
            MemWidth::B1 | MemWidth::B2 | MemWidth::B4 => Ok(OpWidth::W32),
            MemWidth::B8 => Ok(OpWidth::W64),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native CAS width {other:?}"),
            }),
        }
    }

    /// Lower SBB while reconciling the source architecture's carry convention.
    ///
    /// AArch64 SBC consumes and produces C as "no borrow". x86 SBB instead
    /// consumes and produces CF as "borrow", while the x86/AArch64 trampoline
    /// deliberately stores canonical x86 CF directly in NZCV.C. Surround an
    /// x86-register SBB with CFINV so the shared SBC lowering sees its native
    /// convention and the surrounding region continues to see canonical x86
    /// CF. With `FlagUpdate::None`, the second inversion also restores the
    /// input CF exactly; N/Z/V are untouched by both inversions.
    pub(crate) fn lower_sbb(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: &SrcOperand,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if !matches!(dst, VReg::Arch(ArchReg::X86(_))) {
            return self.lower_addsub_carry(dst, src1, src2, true, set_flags, width);
        }

        self.lower_cfinv()?;
        self.lower_addsub_carry(dst, src1, src2, true, set_flags, width)?;
        self.lower_cfinv()
    }

    pub(crate) fn emit_preserve_saved_c_flag(
        &mut self,
        saved_flags: u8,
        flags: u8,
    ) -> Result<(), LowerError> {
        let (imm_n, immr, imms) = Self::logical_bitmask_imm(!(NZCV_C as u32) as i64, OpWidth::W32)?;
        self.emit_sysreg(flags, ArmReg::Nzcv, true)?;
        self.emit_logic_imm(flags, flags, 0b00, imm_n, immr, imms, OpWidth::W32)?;

        let (imm_n, immr, imms) = Self::logical_bitmask_imm(NZCV_C, OpWidth::W32)?;
        self.emit_logic_imm(
            saved_flags,
            saved_flags,
            0b00,
            imm_n,
            immr,
            imms,
            OpWidth::W32,
        )?;
        self.emit_logic_shifted(flags, flags, saved_flags, 0b01, false, 0, 0, OpWidth::W32)?;
        self.emit_sysreg(flags, ArmReg::Nzcv, false)
    }

    pub(crate) fn lower_set_cf(&mut self, value: bool) -> Result<(), LowerError> {
        let scratches = Self::scratch_regs(&[], 1)?;
        let flags = scratches[0];
        let mask = if value {
            NZCV_C
        } else {
            !(NZCV_C as u32) as i64
        };
        let opc = if value { 0b01 } else { 0b00 };
        let (imm_n, immr, imms) = Self::logical_bitmask_imm(mask, OpWidth::W32)?;

        self.emit_scratch_save(&scratches);
        self.emit_sysreg(flags, ArmReg::Nzcv, true)?;
        self.emit_logic_imm(flags, flags, opc, imm_n, immr, imms, OpWidth::W32)?;
        self.emit_sysreg(flags, ArmReg::Nzcv, false)?;
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn lower_cmc_cf(&mut self) -> Result<(), LowerError> {
        let scratches = Self::scratch_regs(&[], 1)?;
        let flags = scratches[0];

        self.emit_scratch_save(&scratches);
        self.emit_sysreg(flags, ArmReg::Nzcv, true)?;
        self.emit_logic_imm_mask(flags, flags, 0b10, NZCV_C, OpWidth::W32)?;
        self.emit_sysreg(flags, ArmReg::Nzcv, false)?;
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn lower_cfinv(&mut self) -> Result<(), LowerError> {
        if self.flagm_available {
            self.emit_flagm(0b000);
            Ok(())
        } else {
            self.lower_cmc_cf()
        }
    }

    pub(crate) fn lower_axflag_fallback(&mut self) -> Result<(), LowerError> {
        let scratches = Self::scratch_regs(&[], 3)?;
        let flags = scratches[0];
        let result = scratches[1];
        let temp = scratches[2];

        self.emit_scratch_save(&scratches);
        self.emit_sysreg(flags, ArmReg::Nzcv, true)?;

        self.emit_logic_shifted(temp, 31, flags, 0b01, false, 0, 1, OpWidth::W32)?;
        self.emit_logic_imm_mask(result, flags, 0b00, NZCV_C, OpWidth::W32)?;
        self.emit_logic_shifted(result, result, temp, 0b00, true, 0, 0, OpWidth::W32)?;

        self.emit_logic_shifted(temp, flags, flags, 0b01, false, 0, 2, OpWidth::W32)?;
        self.emit_logic_imm_mask(temp, temp, 0b00, NZCV_Z, OpWidth::W32)?;
        self.emit_logic_shifted(result, result, temp, 0b01, false, 0, 0, OpWidth::W32)?;

        self.emit_sysreg(result, ArmReg::Nzcv, false)?;
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn lower_axflag(&mut self) -> Result<(), LowerError> {
        if self.flagm2_available {
            self.emit_flagm(0b010);
            Ok(())
        } else {
            self.lower_axflag_fallback()
        }
    }

    pub(crate) fn lower_xaflag_fallback(&mut self) -> Result<(), LowerError> {
        let scratches = Self::scratch_regs(&[], 4)?;
        let flags = scratches[0];
        let result = scratches[1];
        let temp = scratches[2];
        let temp2 = scratches[3];

        self.emit_scratch_save(&scratches);
        self.emit_sysreg(flags, ArmReg::Nzcv, true)?;

        self.emit_logic_shifted(result, 31, flags, 0b01, false, 1, 2, OpWidth::W32)?;
        self.emit_logic_shifted(temp, 31, flags, 0b01, false, 1, 1, OpWidth::W32)?;
        self.emit_logic_shifted(result, result, temp, 0b00, true, 0, 0, OpWidth::W32)?;
        self.emit_logic_imm_mask(result, result, 0b00, NZCV_V, OpWidth::W32)?;

        self.emit_logic_shifted(temp, flags, flags, 0b01, false, 1, 1, OpWidth::W32)?;
        self.emit_logic_imm_mask(temp, temp, 0b00, NZCV_C, OpWidth::W32)?;
        self.emit_logic_shifted(result, result, temp, 0b01, false, 0, 0, OpWidth::W32)?;

        self.emit_logic_shifted(temp, 31, flags, 0b01, false, 0, 1, OpWidth::W32)?;
        self.emit_logic_shifted(temp, temp, flags, 0b00, false, 0, 0, OpWidth::W32)?;
        self.emit_logic_imm_mask(temp, temp, 0b00, NZCV_Z, OpWidth::W32)?;
        self.emit_logic_shifted(result, result, temp, 0b01, false, 0, 0, OpWidth::W32)?;

        self.emit_logic_shifted(temp, 31, flags, 0b01, false, 0, 1, OpWidth::W32)?;
        self.emit_logic_shifted(temp2, 31, flags, 0b01, false, 0, 2, OpWidth::W32)?;
        self.emit_logic_shifted(temp, temp, temp2, 0b01, false, 0, 0, OpWidth::W32)?;
        self.emit_logic_imm_mask(temp, temp, 0b00, NZCV_N, OpWidth::W32)?;
        self.emit_logic_imm_mask(temp, temp, 0b10, NZCV_N, OpWidth::W32)?;
        self.emit_logic_shifted(result, result, temp, 0b01, false, 0, 0, OpWidth::W32)?;

        self.emit_sysreg(result, ArmReg::Nzcv, false)?;
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn lower_xaflag(&mut self) -> Result<(), LowerError> {
        if self.flagm2_available {
            self.emit_flagm(0b001);
            Ok(())
        } else {
            self.lower_xaflag_fallback()
        }
    }

    pub(crate) fn bit_test_emit_width(width: OpWidth) -> Result<OpWidth, LowerError> {
        match width {
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => Ok(OpWidth::W32),
            OpWidth::W64 => Ok(OpWidth::W64),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native bit test width {other:?}"),
            }),
        }
    }

    pub(crate) fn lower_inc_dec(
        &mut self,
        dst: VReg,
        src: VReg,
        decrement: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if let Some((dst_reg, result)) = Self::x86_partial_write_scratch(dst, width, &[src], &[])? {
            let scratches = [result];
            self.emit_scratch_save(&scratches);
            self.lower_inc_dec(Self::arm_x_reg(result), src, decrement, set_flags, width)?;
            self.emit_bitfield(dst_reg, result, 0b01, 0, width.bits() - 1, OpWidth::W64)?;
            self.emit_scratch_restore(&scratches);
            return Ok(());
        }

        if !set_flags {
            if let VReg::Imm(value) = src {
                let emit_width = match width {
                    OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                    OpWidth::W64 => OpWidth::W64,
                    other => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("AArch64 native Inc/Dec width {other:?}"),
                        });
                    }
                };
                let value = (value as u64) & width.mask();
                let result = if decrement {
                    value.wrapping_sub(1)
                } else {
                    value.wrapping_add(1)
                } & width.mask();
                let dst = Self::dst_gpr_arm_or_x86(dst)?;
                if self.try_emit_movn_single(dst, result, emit_width)? {
                    return Ok(());
                }
                return self.emit_mov_imm(dst, result as i64, emit_width);
            }
        }

        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            if set_flags {
                return self.lower_subword_inc_dec_with_flags(dst, src, decrement, width);
            }

            let dst = Self::dst_gpr_arm_or_x86(dst)?;
            self.emit_addsub_imm(
                dst,
                Self::gpr_arm_or_x86(src)?,
                1,
                decrement,
                false,
                OpWidth::W32,
            )?;
            let imms = if width == OpWidth::W8 { 7 } else { 15 };
            return self.emit_bitfield(dst, dst, 0b10, 0, imms, OpWidth::W32);
        }

        if set_flags {
            let dst = Self::dst_or_zero_for_flags_arm_or_x86(dst, true)?;
            let src = Self::gpr_arm_or_x86(src)?;
            let scratches = Self::scratch_regs(&[dst, src], 2)?;
            let saved_flags = scratches[0];
            let flags = scratches[1];
            self.emit_scratch_save(&scratches);
            self.emit_sysreg(saved_flags, ArmReg::Nzcv, true)?;
            self.emit_addsub_imm(dst, src, 1, decrement, true, width)?;
            self.emit_preserve_saved_c_flag(saved_flags, flags)?;
            self.emit_scratch_restore(&scratches);
            return Ok(());
        }

        self.lower_addsub(dst, src, &SrcOperand::Imm(1), decrement, false, width)
    }

    pub(crate) fn lower_cwd(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if let VReg::Imm(value) = src {
            let emit_width = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                OpWidth::W64 => OpWidth::W64,
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native Cwd width {other:?}"),
                    });
                }
            };
            let value = (value as u64) & width.mask();
            let result = if (value & width.sign_bit()) != 0 {
                width.mask()
            } else {
                0
            };
            let dst = Self::dst_gpr(dst)?;
            if matches!(width, OpWidth::W32 | OpWidth::W64) && result == width.mask() {
                return self.emit_movn_zero(dst, emit_width);
            }
            return self.emit_mov_imm(dst, result as i64, emit_width);
        }

        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let sign_bit = width.bits() - 1;
            let dst_reg = Self::dst_gpr_arm_or_x86(dst)?;
            let src_reg = Self::gpr_arm_or_x86(src)?;
            // For an x86 destination, a W8/W16 write is PARTIAL: only the low 8/16
            // bits receive the sign mask; the rest of the register is preserved
            // (matching the interpreter's `write_x86_partial`). Build the sign mask
            // in a scratch register and merge it with BFI rather than overwriting
            // the whole destination (which cleared the preserved upper bits). (#31)
            if matches!(dst, VReg::Arch(ArchReg::X86(_))) {
                let scratch = Self::scratch_regs(&[dst_reg, src_reg], 1)?[0];
                self.emit_scratch_save(&[scratch]);
                // scratch = sign-extend(src[sign_bit]) -> 0 or all-ones; its low
                // `width` bits are the x86 sign mask (0x00.. or 0xff/0xffff).
                self.emit_bitfield(scratch, src_reg, 0b00, sign_bit, sign_bit, OpWidth::W32)?;
                // BFI Xdst, Xscratch, #0, #width: merge low bits, preserve the rest.
                self.emit_bitfield(dst_reg, scratch, 0b01, 0, sign_bit, OpWidth::W64)?;
                self.emit_scratch_restore(&[scratch]);
                return Ok(());
            }
            // Non-x86 destination: full zero-extended write of the sign mask.
            self.emit_bitfield(dst_reg, src_reg, 0b00, sign_bit, sign_bit, OpWidth::W32)?;
            return self.emit_bitfield(dst_reg, dst_reg, 0b10, 0, sign_bit, OpWidth::W32);
        }
        let bits = width.bits();
        self.lower_shift_imm(
            Self::dst_gpr_arm_or_x86(dst)?,
            Self::gpr_arm_or_x86(src)?,
            i64::from(bits - 1),
            ShiftOp::Asr,
            width,
        )
    }

    pub(crate) fn lower_xchg(
        &mut self,
        reg1: VReg,
        reg2: VReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let x86_partial = matches!(reg1, VReg::Arch(ArchReg::X86(_)))
            && matches!(reg2, VReg::Arch(ArchReg::X86(_)))
            && matches!(width, OpWidth::W8 | OpWidth::W16);
        let reg1 = Self::dst_gpr_arm_or_x86(reg1)?;
        let reg2 = Self::dst_gpr_arm_or_x86(reg2)?;
        if x86_partial {
            if reg1 == reg2 {
                return Ok(());
            }
            let scratches = Self::scratch_regs(&[reg1, reg2], 1)?;
            let top_bit = width.bits() - 1;
            self.emit_scratch_save(&scratches);
            self.emit_bitfield(scratches[0], reg1, 0b10, 0, top_bit, OpWidth::W32)?;
            self.emit_bitfield(reg1, reg2, 0b01, 0, top_bit, OpWidth::W64)?;
            self.emit_bitfield(reg2, scratches[0], 0b01, 0, top_bit, OpWidth::W64)?;
            self.emit_scratch_restore(&scratches);
            return Ok(());
        }
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let top_bit = width.bits() - 1;
            if reg1 == reg2 {
                return self.emit_bitfield(reg1, reg1, 0b10, 0, top_bit, OpWidth::W32);
            }

            self.emit_logic_reg_n(reg1, reg1, reg2, 0b10, false, OpWidth::W32)?;
            self.emit_logic_reg_n(reg2, reg1, reg2, 0b10, false, OpWidth::W32)?;
            self.emit_logic_reg_n(reg1, reg1, reg2, 0b10, false, OpWidth::W32)?;
            self.emit_bitfield(reg1, reg1, 0b10, 0, top_bit, OpWidth::W32)?;
            return self.emit_bitfield(reg2, reg2, 0b10, 0, top_bit, OpWidth::W32);
        }
        if reg1 == reg2 {
            if width == OpWidth::W64 {
                return Ok(());
            }
            return self.emit_mov_reg(reg1, reg1, width);
        }

        self.emit_logic_reg_n(reg1, reg1, reg2, 0b10, false, width)?;
        self.emit_logic_reg_n(reg2, reg1, reg2, 0b10, false, width)?;
        self.emit_logic_reg_n(reg1, reg1, reg2, 0b10, false, width)
    }

    pub(crate) fn lower_not(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if matches!(dst, VReg::Arch(ArchReg::X86(_))) && matches!(width, OpWidth::W8 | OpWidth::W16)
        {
            let dst_reg = Self::dst_gpr_arm_or_x86(dst)?;
            let mut avoid = vec![dst_reg];
            if !matches!(src, VReg::Imm(_)) {
                avoid.push(Self::gpr_arm_or_x86(src)?);
            }
            let scratches = Self::scratch_regs(&avoid, 1)?;
            self.emit_scratch_save(&scratches);
            self.lower_not(
                VReg::Arch(ArchReg::Arm(ArmReg::X(scratches[0]))),
                src,
                width,
            )?;
            self.emit_bitfield(
                dst_reg,
                scratches[0],
                0b01,
                0,
                width.bits() - 1,
                OpWidth::W64,
            )?;
            self.emit_scratch_restore(&scratches);
            return Ok(());
        }

        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        if let VReg::Imm(value) = src {
            let emit_width = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                OpWidth::W64 => OpWidth::W64,
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native Not width {other:?}"),
                    });
                }
            };
            let value = (!(value as u64)) & width.mask();
            if self.try_emit_movn_single(dst, value, emit_width)? {
                return Ok(());
            }
            return self.emit_mov_imm(dst, value as i64, emit_width);
        }

        let src = Self::gpr_arm_or_x86(src)?;
        match width {
            OpWidth::W8 | OpWidth::W16 => {
                self.emit_logic_reg_n(dst, 31, src, 0b01, true, OpWidth::W32)?;
                let imms = if width == OpWidth::W8 { 7 } else { 15 };
                self.emit_bitfield(dst, dst, 0b10, 0, imms, OpWidth::W32)
            }
            OpWidth::W32 | OpWidth::W64 => self.emit_logic_reg_n(dst, 31, src, 0b01, true, width),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Not width {other:?}"),
            }),
        }
    }

    pub(crate) fn lower_constant_test_result(
        &mut self,
        result: u64,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let emit_width = if width == OpWidth::W64 {
            OpWidth::W64
        } else {
            OpWidth::W32
        };
        if result == 0 {
            return self.emit_logic_reg_n(31, 31, 31, 0b11, false, emit_width);
        }
        if (result & width.sign_bit()) != 0 {
            // Logical result is negative: N=1, Z=C=V=0. Route through the
            // constant-NZCV helper (ccmp fallback) instead of `cmp sp, #1`,
            // whose Rn = 31 is SP and would take the flags from SP - 1.
            return self.lower_constant_cmp_nzcv(0b1000, emit_width);
        }
        self.emit_sysreg(31, ArmReg::Nzcv, false)
    }

    pub(crate) fn lower_ctz(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if width == OpWidth::W16 {
            if let Some((dst, result)) = Self::x86_partial_write_scratch(dst, width, &[src], &[])? {
                let scratches = [result];
                self.emit_scratch_save(&scratches);
                self.lower_ctz(Self::arm_x_reg(result), src, width)?;
                self.emit_bitfield(dst, result, 0b01, 0, 15, OpWidth::W64)?;
                self.emit_scratch_restore(&scratches);
                return Ok(());
            }
        }

        if let VReg::Imm(value) = src {
            let emit_width = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                OpWidth::W64 => OpWidth::W64,
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native Ctz width {other:?}"),
                    });
                }
            };
            let value = (value as u64) & width.mask();
            let result = if value == 0 {
                width.bits()
            } else {
                value.trailing_zeros()
            };
            return self.emit_mov_imm(
                Self::dst_gpr_arm_or_x86(dst)?,
                i64::from(result),
                emit_width,
            );
        }

        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        let src = Self::gpr_arm_or_x86(src)?;
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let sentinel = if width == OpWidth::W8 {
                0x100
            } else {
                0x1_0000
            };
            let (imm_n, immr, imms) = Self::logical_bitmask_imm(sentinel, OpWidth::W32)?;
            self.emit_bitfield(dst, src, 0b10, 0, width.bits() - 1, OpWidth::W32)?;
            self.emit_logic_imm(dst, dst, 0b01, imm_n, immr, imms, OpWidth::W32)?;
            self.emit_dp1(dst, dst, 0b000000, OpWidth::W32)?;
            return self.emit_dp1(dst, dst, 0b000100, OpWidth::W32);
        }
        self.emit_dp1(dst, src, 0b000000, width)?;
        self.emit_dp1(dst, dst, 0b000100, width)
    }

    pub(crate) fn lower_popcnt(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if width == OpWidth::W16 {
            if let Some((dst, result)) = Self::x86_partial_write_scratch(dst, width, &[src], &[])? {
                let scratches = [result];
                self.emit_scratch_save(&scratches);
                self.lower_popcnt(Self::arm_x_reg(result), src, width)?;
                self.emit_bitfield(dst, result, 0b01, 0, 15, OpWidth::W64)?;
                self.emit_scratch_restore(&scratches);
                return Ok(());
            }
        }

        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        let src = Self::gpr_arm_or_x86(src)?;
        let emit_width = match width {
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
            OpWidth::W64 => OpWidth::W64,
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native Popcnt width {other:?}"),
                });
            }
        };
        let (m1, m2, m4, final_mask) = match width {
            OpWidth::W8 => (0x5555_5555, 0x3333_3333, 0x0f0f_0f0f, 0x0f),
            OpWidth::W16 => (0x5555_5555, 0x3333_3333, 0x0f0f_0f0f, 0x1f),
            OpWidth::W32 => (0x5555_5555, 0x3333_3333, 0x0f0f_0f0f, 0x3f),
            OpWidth::W64 => (
                0x5555_5555_5555_5555,
                0x3333_3333_3333_3333,
                0x0f0f_0f0f_0f0f_0f0f,
                0x7f,
            ),
            _ => unreachable!(),
        };
        let scratches = Self::scratch_regs(&[dst, src], 1)?;
        let temp = scratches[0];

        self.emit_scratch_save(&scratches);
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            self.emit_bitfield(dst, src, 0b10, 0, width.bits() - 1, OpWidth::W32)?;
        } else {
            self.emit_mov_reg(dst, src, emit_width)?;
        }

        self.emit_bitfield(temp, dst, 0b10, 1, emit_width.bits() - 1, emit_width)?;
        let (imm_n, immr, imms) = Self::logical_bitmask_imm(m1, emit_width)?;
        self.emit_logic_imm(temp, temp, 0b00, imm_n, immr, imms, emit_width)?;
        self.emit_addsub_reg(dst, dst, temp, true, false, emit_width)?;

        let (imm_n, immr, imms) = Self::logical_bitmask_imm(m2, emit_width)?;
        self.emit_logic_imm(temp, dst, 0b00, imm_n, immr, imms, emit_width)?;
        self.emit_bitfield(dst, dst, 0b10, 2, emit_width.bits() - 1, emit_width)?;
        self.emit_logic_imm(dst, dst, 0b00, imm_n, immr, imms, emit_width)?;
        self.emit_addsub_reg(dst, temp, dst, false, false, emit_width)?;

        self.emit_bitfield(temp, dst, 0b10, 4, emit_width.bits() - 1, emit_width)?;
        self.emit_addsub_reg(dst, dst, temp, false, false, emit_width)?;
        let (imm_n, immr, imms) = Self::logical_bitmask_imm(m4, emit_width)?;
        self.emit_logic_imm(dst, dst, 0b00, imm_n, immr, imms, emit_width)?;

        for shift in [8, 16, 32] {
            if shift < width.bits() {
                self.emit_bitfield(temp, dst, 0b10, shift, emit_width.bits() - 1, emit_width)?;
                self.emit_addsub_reg(dst, dst, temp, false, false, emit_width)?;
            }
        }
        let (imm_n, immr, imms) = Self::logical_bitmask_imm(final_mask, emit_width)?;
        self.emit_logic_imm(dst, dst, 0b00, imm_n, immr, imms, emit_width)?;
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn lower_crc32c(
        &mut self,
        dst: VReg,
        crc: VReg,
        data: VReg,
        data_width: OpWidth,
    ) -> Result<(), LowerError> {
        if !self.crc_available {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native CRC32C requires FEAT_CRC32".into(),
            });
        }

        // CRC32C{B,H,W,X} reads the low 32 bits of Wn as the accumulator,
        // consumes the selected low part of Rm, and writes Wd. The Wd write
        // provides the architectural zero-extension required by x86 CRC32,
        // including its r64 source form. These encodings are naturally safe
        // for every dst/crc/data alias because all sources are read before Wd
        // is committed.
        let base = match data_width {
            OpWidth::W8 => 0x1ac0_5000,  // CRC32CB Wd, Wn, Wm
            OpWidth::W16 => 0x1ac0_5400, // CRC32CH Wd, Wn, Wm
            OpWidth::W32 => 0x1ac0_5800, // CRC32CW Wd, Wn, Wm
            OpWidth::W64 => 0x9ac0_5c00, // CRC32CX Wd, Wn, Xm
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native CRC32C data width {other:?}"),
                });
            }
        };
        let rd = Self::dst_gpr_arm_or_x86(dst)?;
        let rn = Self::gpr_arm_or_x86(crc)?;
        let rm = Self::gpr_arm_or_x86(data)?;
        self.emit(base | (u32::from(rm) << 16) | (u32::from(rn) << 5) | u32::from(rd));
        Ok(())
    }

    pub(crate) fn lower_bsf(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    ) -> Result<(), LowerError> {
        if width == OpWidth::W16 {
            if let Some((dst, result)) = Self::x86_partial_write_scratch(dst, width, &[src], &[])? {
                let scratches = [result];
                self.emit_scratch_save(&scratches);
                self.lower_bsf(Self::arm_x_reg(result), src, width, flags)?;
                self.emit_bitfield(dst, result, 0b01, 0, 15, OpWidth::W64)?;
                self.emit_scratch_restore(&scratches);
                return Ok(());
            }
        }

        if let VReg::Imm(value) = src {
            let emit_width = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                OpWidth::W64 => OpWidth::W64,
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native Bsf width {other:?}"),
                    });
                }
            };
            let value = (value as u64) & width.mask();
            let result = if value == 0 {
                0
            } else {
                value.trailing_zeros()
            };
            let dst = Self::dst_gpr_arm_or_x86(dst)?;
            self.lower_bit_scan_flags(dst, src, width, emit_width, flags)?;
            return self.emit_mov_imm(dst, i64::from(result), emit_width);
        }

        let (mask_bits, mask_width) = match width {
            OpWidth::W8 => (3, OpWidth::W32),
            OpWidth::W16 => (4, OpWidth::W32),
            OpWidth::W32 => (5, OpWidth::W32),
            OpWidth::W64 => (6, OpWidth::W64),
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native Bsf width {other:?}"),
                });
            }
        };
        let dst_reg = Self::dst_gpr_arm_or_x86(dst)?;
        let src_reg = Self::gpr_arm_or_x86(src)?;
        let saved_src = if flags.updates_any() && dst_reg == src_reg {
            Self::scratch_regs(&[dst_reg, src_reg], 1)?
        } else {
            Vec::new()
        };
        self.emit_scratch_save(&saved_src);
        if let Some(&saved_src) = saved_src.first() {
            let emit_width = if width == OpWidth::W64 {
                OpWidth::W64
            } else {
                OpWidth::W32
            };
            self.emit_mov_reg(saved_src, src_reg, emit_width)?;
        }

        self.lower_ctz(dst, src, width)?;
        self.lower_bfx(dst, dst, 0, mask_bits, false, mask_width)?;
        let flag_src = saved_src
            .first()
            .copied()
            .map(Self::arm_x_reg)
            .unwrap_or(src);
        self.lower_bit_scan_flags(dst_reg, flag_src, width, mask_width, flags)?;
        self.emit_scratch_restore(&saved_src);
        Ok(())
    }

    pub(crate) fn lower_bsr(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    ) -> Result<(), LowerError> {
        if width == OpWidth::W16 {
            if let Some((dst, result)) = Self::x86_partial_write_scratch(dst, width, &[src], &[])? {
                let scratches = [result];
                self.emit_scratch_save(&scratches);
                self.lower_bsr(Self::arm_x_reg(result), src, width, flags)?;
                self.emit_bitfield(dst, result, 0b01, 0, 15, OpWidth::W64)?;
                self.emit_scratch_restore(&scratches);
                return Ok(());
            }
        }

        if let VReg::Imm(value) = src {
            let emit_width = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                OpWidth::W64 => OpWidth::W64,
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native Bsr width {other:?}"),
                    });
                }
            };
            let value = (value as u64) & width.mask();
            let result = if value == 0 {
                0
            } else {
                u64::BITS - 1 - value.leading_zeros()
            };
            let dst = Self::dst_gpr_arm_or_x86(dst)?;
            self.lower_bit_scan_flags(dst, src, width, emit_width, flags)?;
            return self.emit_mov_imm(dst, i64::from(result), emit_width);
        }

        if !matches!(
            width,
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
        ) {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Bsr width {width:?}"),
            });
        }

        let dst_reg = Self::dst_gpr_arm_or_x86(dst)?;
        let src_reg = Self::gpr_arm_or_x86(src)?;
        let saved_src = if flags.updates_any() && dst_reg == src_reg {
            Self::scratch_regs(&[dst_reg, src_reg], 1)?
        } else {
            Vec::new()
        };
        self.emit_scratch_save(&saved_src);
        if let Some(&saved_src) = saved_src.first() {
            let emit_width = if width == OpWidth::W64 {
                OpWidth::W64
            } else {
                OpWidth::W32
            };
            self.emit_mov_reg(saved_src, src_reg, emit_width)?;
        }

        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let top_bit = width.bits() - 1;
            self.emit_bitfield(dst_reg, src_reg, 0b10, 0, top_bit, OpWidth::W32)?;
            self.emit_orr_imm_one(dst_reg, dst_reg, OpWidth::W32)?;
            self.emit_dp1(dst_reg, dst_reg, 0b000100, OpWidth::W32)?;
            self.emit_logic_imm(dst_reg, dst_reg, 0b10, 0, 0, 4, OpWidth::W32)?;
            let flag_src = saved_src
                .first()
                .copied()
                .map(Self::arm_x_reg)
                .unwrap_or(src);
            self.lower_bit_scan_flags(dst_reg, flag_src, width, OpWidth::W32, flags)?;
            self.emit_scratch_restore(&saved_src);
            return Ok(());
        }

        let mask_imms = match width {
            OpWidth::W32 => 4,
            OpWidth::W64 => 5,
            _ => unreachable!(),
        };
        self.emit_orr_imm_one(dst_reg, src_reg, width)?;
        self.emit_dp1(dst_reg, dst_reg, 0b000100, width)?;
        let n = Self::sf(width)?;
        self.emit_logic_imm(dst_reg, dst_reg, 0b10, n, 0, mask_imms, width)?;
        let flag_src = saved_src
            .first()
            .copied()
            .map(Self::arm_x_reg)
            .unwrap_or(src);
        self.lower_bit_scan_flags(dst_reg, flag_src, width, width, flags)?;
        self.emit_scratch_restore(&saved_src);
        Ok(())
    }

    pub(crate) fn lower_bmi_result_flags(
        &mut self,
        dst: u8,
        width: OpWidth,
        carry: bool,
    ) -> Result<(), LowerError> {
        match width {
            OpWidth::W8 | OpWidth::W16 => {
                self.emit_logic_flags_from_source(dst, width)?;
                if carry {
                    let scratches = Self::scratch_regs(&[dst], 2)?;
                    let flags = scratches[0];
                    let temp = scratches[1];
                    self.emit_scratch_save(&scratches);
                    self.emit_sysreg(flags, ArmReg::Nzcv, true)?;
                    self.emit_or_nzcv_const(flags, temp, NZCV_C)?;
                    self.emit_sysreg(flags, ArmReg::Nzcv, false)?;
                    self.emit_scratch_restore(&scratches);
                }
                return Ok(());
            }
            OpWidth::W32 | OpWidth::W64 => {
                self.emit_logic_reg_n(31, dst, dst, 0b11, false, width)?;
            }
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native BMI result flag width {other:?}"),
                });
            }
        }
        if carry {
            self.lower_cfinv()?;
        }
        Ok(())
    }

    pub(crate) fn lower_bzhi_result_flags(
        &mut self,
        dst: u8,
        result_width: OpWidth,
        emit_width: OpWidth,
        carry: bool,
        subword_sign_known_clear: bool,
    ) -> Result<(), LowerError> {
        match result_width {
            OpWidth::W8 | OpWidth::W16 if subword_sign_known_clear => {
                self.lower_bmi_result_flags(dst, emit_width, carry)
            }
            OpWidth::W8 | OpWidth::W16 => {
                let shift = OpWidth::W32.bits() - result_width.bits();
                self.lower_shift_imm(dst, dst, i64::from(shift), ShiftOp::Lsl, OpWidth::W32)?;
                self.emit_logic_reg_n(31, dst, dst, 0b11, false, OpWidth::W32)?;
                if carry {
                    let scratches = Self::scratch_regs(&[dst], 2)?;
                    let flags = scratches[0];
                    let temp = scratches[1];
                    self.emit_scratch_save(&scratches);
                    self.emit_sysreg(flags, ArmReg::Nzcv, true)?;
                    self.emit_or_nzcv_const(flags, temp, NZCV_C)?;
                    self.emit_sysreg(flags, ArmReg::Nzcv, false)?;
                    self.emit_scratch_restore(&scratches);
                }
                self.lower_shift_imm(dst, dst, i64::from(shift), ShiftOp::Lsr, OpWidth::W32)
            }
            OpWidth::W32 | OpWidth::W64 => self.lower_bmi_result_flags(dst, emit_width, carry),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Bzhi flag width {other:?}"),
            }),
        }
    }

    pub(crate) fn lower_bzhi(
        &mut self,
        dst: VReg,
        src: VReg,
        index: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    ) -> Result<(), LowerError> {
        let set_flags = flags.updates_any();
        let bits = match width {
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64 => width.bits(),
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native Bzhi width {other:?}"),
                });
            }
        };

        if !set_flags {
            if let VReg::Imm(value) = src {
                if (value as u64 & width.mask()) == 0 {
                    let emit_width = if width == OpWidth::W64 {
                        OpWidth::W64
                    } else {
                        OpWidth::W32
                    };
                    return self.emit_mov_imm(Self::dst_gpr_arm_or_x86(dst)?, 0, emit_width);
                }
            }
        }

        if let VReg::Imm(value) = index {
            let index = ((value as u64) & 0xff) as u32;
            let dst_reg = Self::dst_gpr_arm_or_x86(dst)?;
            let emit_width = if width == OpWidth::W64 {
                OpWidth::W64
            } else {
                OpWidth::W32
            };
            if let VReg::Imm(src_value) = src {
                let src = (src_value as u64) & width.mask();
                let result = if index >= bits {
                    src
                } else {
                    src & ((1_u64 << index) - 1)
                } & width.mask();
                if !self.try_emit_movn_single(dst_reg, result, emit_width)? {
                    self.emit_mov_imm(dst_reg, result as i64, emit_width)?;
                }
                if set_flags {
                    self.lower_bzhi_result_flags(
                        dst_reg,
                        width,
                        emit_width,
                        index >= bits,
                        index < bits,
                    )?;
                }
                return Ok(());
            }

            if index == 0 {
                self.emit_mov_imm(dst_reg, 0, emit_width)?;
                if set_flags {
                    self.lower_bzhi_result_flags(dst_reg, width, emit_width, false, true)?;
                }
                return Ok(());
            }
            if index >= bits {
                match width {
                    OpWidth::W8 | OpWidth::W16 => {
                        self.lower_bfx(dst, src, 0, bits as u8, false, OpWidth::W32)
                    }
                    OpWidth::W32 | OpWidth::W64 => {
                        self.emit_mov_reg(dst_reg, Self::gpr_arm_or_x86(src)?, emit_width)
                    }
                    _ => unreachable!(),
                }?;
                if set_flags {
                    self.lower_bzhi_result_flags(dst_reg, width, emit_width, true, false)?;
                }
                return Ok(());
            }

            let mask = (1_u64 << index) - 1;
            let mask = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => SrcOperand::Imm(mask as u32 as i64),
                OpWidth::W64 => SrcOperand::Imm64(mask as i64),
                _ => unreachable!(),
            };
            self.lower_logic(dst, src, &mask, 0b00, false, false, width)?;
            if set_flags {
                self.lower_bzhi_result_flags(dst_reg, width, emit_width, false, true)?;
            }
            return Ok(());
        }

        let (emit_width, guard_bits): (OpWidth, &[u32]) = match width {
            OpWidth::W8 => (OpWidth::W32, &[3, 4, 5, 6, 7]),
            OpWidth::W16 => (OpWidth::W32, &[4, 5, 6, 7]),
            OpWidth::W32 => (OpWidth::W32, &[5, 6, 7]),
            OpWidth::W64 => (OpWidth::W64, &[6, 7]),
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native register-index Bzhi width {other:?}"),
                });
            }
        };

        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        let src = Self::gpr_arm_or_x86(src)?;
        let index = Self::gpr_arm_or_x86(index)?;
        let scratches = if dst == src || dst == index {
            Self::scratch_regs(&[dst, src, index], 1)?
        } else {
            Vec::new()
        };
        let mask_reg = scratches.first().copied().unwrap_or(dst);
        self.emit_scratch_save(&scratches);

        let mut guards = Vec::with_capacity(guard_bits.len());
        for &bit in guard_bits {
            let offset = self.code.position();
            self.emit_test_branch(index, bit, true, 0)?;
            guards.push((offset, bit));
        }

        self.emit_movn_zero(mask_reg, emit_width)?;
        self.emit_dp2(mask_reg, mask_reg, index, 0b1000, emit_width)?;
        self.emit_logic_reg_n(dst, src, mask_reg, 0b00, true, emit_width)?;
        if set_flags {
            self.lower_bzhi_result_flags(dst, width, width, false, false)?;
        }
        let end_branch = self.code.position();
        self.emit(0x1400_0000);
        for (offset, bit) in guards {
            self.patch_test_branch_to_current(offset, index, bit, true)?;
        }
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            self.emit_bitfield(dst, src, 0b10, 0, bits - 1, OpWidth::W32)?;
        } else {
            self.emit_mov_reg(dst, src, width)?;
        }
        if set_flags {
            self.lower_bzhi_result_flags(dst, width, width, true, false)?;
        }
        self.patch_branch_to_current(end_branch)?;
        self.emit_scratch_restore(&scratches);
        Ok(())
    }

    pub(crate) fn emit_keep_nz_flags(&mut self, dst: u8, src: u8) -> Result<(), LowerError> {
        let (imm_n, immr, imms) = Self::logical_bitmask_imm(NZCV_N | NZCV_Z, OpWidth::W32)?;
        self.emit_logic_imm(dst, src, 0b00, imm_n, immr, imms, OpWidth::W32)
    }

    pub(crate) fn emit_normalize_rcl_rcr_count(
        &mut self,
        count: u8,
        amount: u8,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        self.emit_mov_reg(count, amount, OpWidth::W64)?;
        let mask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
        let (imm_n, immr, imms) = Self::logical_bitmask_imm(mask, OpWidth::W64)?;
        self.emit_logic_imm(count, count, 0b00, imm_n, immr, imms, OpWidth::W64)?;

        let period = match width {
            OpWidth::W8 => 9,
            OpWidth::W16 => 17,
            OpWidth::W32 | OpWidth::W64 => return Ok(()),
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native RCL/RCR count width {other:?}"),
                });
            }
        };

        let loop_start = self.code.position();
        self.emit_addsub_imm(31, count, period, true, true, OpWidth::W64)?;
        let done = self.code.position();
        self.emit(0x5400_0000 | Self::arm_cond_code(Condition::Ult)?);
        self.emit_addsub_imm(count, count, period, true, false, OpWidth::W64)?;
        self.emit_branch_to_offset(loop_start)?;
        self.patch_cond_branch_to_current(done, Self::arm_cond_code(Condition::Ult)?)
    }

    pub(crate) fn lower_bswap(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if let VReg::Imm(value) = src {
            let (result, emit_width) = match width {
                OpWidth::W8 => (value as u64, OpWidth::W64),
                OpWidth::W16 => ((value as u16).swap_bytes() as u64, OpWidth::W32),
                OpWidth::W32 => ((value as u32).swap_bytes() as u64, OpWidth::W32),
                OpWidth::W64 => ((value as u64).swap_bytes(), OpWidth::W64),
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native Bswap width {other:?}"),
                    });
                }
            };
            let dst = Self::dst_gpr(dst)?;
            if self.try_emit_movn_single(dst, result, emit_width)? {
                return Ok(());
            }
            return self.emit_mov_imm(dst, result as i64, emit_width);
        }

        let opcode = match width {
            OpWidth::W8 => {
                return self.emit_mov_reg(
                    Self::dst_gpr_arm_or_x86(dst)?,
                    Self::gpr_arm_or_x86(src)?,
                    OpWidth::W64,
                );
            }
            OpWidth::W16 => {
                let dst = Self::dst_gpr_arm_or_x86(dst)?;
                self.emit_dp1(dst, Self::gpr_arm_or_x86(src)?, 0b000001, OpWidth::W32)?;
                return self.emit_bitfield(dst, dst, 0b10, 0, 15, OpWidth::W32);
            }
            OpWidth::W32 => 0b000010,
            OpWidth::W64 => 0b000011,
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native Bswap width {other:?}"),
                });
            }
        };
        self.emit_dp1(
            Self::dst_gpr_arm_or_x86(dst)?,
            Self::gpr_arm_or_x86(src)?,
            opcode,
            width,
        )
    }

    pub(crate) fn lower_bfx(
        &mut self,
        dst: VReg,
        src: VReg,
        lsb: u8,
        width_bits: u8,
        sign_extend: bool,
        op_width: OpWidth,
    ) -> Result<(), LowerError> {
        let op_bits = Self::bitfield_args("Bfx", lsb, width_bits, op_width)?;
        if let VReg::Imm(value) = src {
            let width_bits = u32::from(width_bits);
            let mask = if width_bits == 64 {
                u64::MAX
            } else {
                (1_u64 << width_bits) - 1
            };
            let extracted = ((value as u64) >> lsb) & mask;
            let result = if sign_extend {
                let sign_bit = 1_u64 << (width_bits - 1);
                if (extracted & sign_bit) != 0 {
                    extracted | !mask
                } else {
                    extracted
                }
            } else {
                extracted
            } & op_width.mask();
            let dst = Self::dst_gpr(dst)?;
            if self.try_emit_movn_single(dst, result, op_width)? {
                return Ok(());
            }
            return self.emit_mov_imm(dst, result as i64, op_width);
        }

        if lsb == 0 && u32::from(width_bits) == op_bits {
            let dst = Self::dst_gpr(dst)?;
            let src = Self::gpr(src)?;
            if op_width == OpWidth::W64 && dst == src {
                return Ok(());
            }
            return self.emit_mov_reg(dst, src, op_width);
        }

        let opc = if sign_extend { 0b00 } else { 0b10 };
        self.emit_bitfield(
            Self::dst_gpr_arm_or_x86(dst)?,
            Self::gpr_arm_or_x86(src)?,
            opc,
            u32::from(lsb),
            u32::from(lsb + width_bits - 1),
            op_width,
        )
    }

    pub(crate) fn lower_bfi(
        &mut self,
        dst: VReg,
        dst_in: VReg,
        src: VReg,
        lsb: u8,
        width_bits: u8,
        op_width: OpWidth,
    ) -> Result<(), LowerError> {
        let op_bits = Self::bitfield_args("Bfi", lsb, width_bits, op_width)?;
        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        let dst_in = Self::gpr_arm_or_x86(dst_in)?;
        if let VReg::Imm(value) = src {
            let low_mask = if width_bits == 64 {
                u64::MAX
            } else {
                (1_u64 << u32::from(width_bits)) - 1
            };
            let inserted = (value as u64) & low_mask;
            if u32::from(width_bits) == op_bits && lsb == 0 {
                if inserted == op_width.mask() {
                    return self.emit_movn_zero(dst, op_width);
                }
                return self.emit_mov_imm_best(dst, inserted as i64, op_width);
            }
            if inserted == 0 && u32::from(width_bits) < op_bits {
                let field_mask = low_mask << lsb;
                let clear_mask = (!field_mask) & op_width.mask();
                if let Ok((n, immr, imms)) = Self::logical_bitmask_imm(clear_mask as i64, op_width)
                {
                    return self.emit_logic_imm(dst, dst_in, 0b00, n, immr, imms, op_width);
                }
            }
            if inserted == low_mask && u32::from(width_bits) < op_bits {
                let field_mask = low_mask << lsb;
                let (n, immr, imms) = Self::logical_bitmask_imm(field_mask as i64, op_width)?;
                return self.emit_logic_imm(dst, dst_in, 0b01, n, immr, imms, op_width);
            }
            if inserted != 0 && u32::from(width_bits) < op_bits {
                let field_mask = low_mask << lsb;
                let inserted_mask = inserted << lsb;
                let clear_mask = (!field_mask) & op_width.mask();
                if let (
                    Ok((clear_n, clear_immr, clear_imms)),
                    Ok((insert_n, insert_immr, insert_imms)),
                ) = (
                    Self::logical_bitmask_imm(clear_mask as i64, op_width),
                    Self::logical_bitmask_imm(inserted_mask as i64, op_width),
                ) {
                    self.emit_logic_imm(
                        dst, dst_in, 0b00, clear_n, clear_immr, clear_imms, op_width,
                    )?;
                    return self.emit_logic_imm(
                        dst,
                        dst,
                        0b01,
                        insert_n,
                        insert_immr,
                        insert_imms,
                        op_width,
                    );
                }
            }
        }
        let src = Self::gpr_arm_or_x86(src)?;

        if u32::from(width_bits) == op_bits && lsb == 0 {
            if op_width == OpWidth::W64 && dst == src {
                return Ok(());
            }
            return self.emit_mov_reg(dst, src, op_width);
        }
        if dst != dst_in {
            if dst == src {
                let scratches = Self::scratch_regs(&[dst, dst_in, src], 1)?;
                let work = scratches[0];
                self.emit_scratch_save(&scratches);
                self.emit_mov_reg(work, src, op_width)?;
                self.emit_mov_reg(dst, dst_in, op_width)?;
                self.emit_bitfield_merge_from_work(dst, work, 0, lsb, width_bits, op_width)?;
                self.emit_scratch_restore(&scratches);
                return Ok(());
            }
            self.emit_mov_reg(dst, dst_in, op_width)?;
        }

        let immr = if lsb == 0 {
            0
        } else {
            op_bits - u32::from(lsb)
        };
        self.emit_bitfield(dst, src, 0b01, immr, u32::from(width_bits - 1), op_width)
    }

    pub(crate) fn lower_extend(
        &mut self,
        dst: VReg,
        src: VReg,
        from_width: OpWidth,
        to_width: OpWidth,
        sign_extend: bool,
    ) -> Result<(), LowerError> {
        let from_bits = from_width.bits();
        let to_bits = to_width.bits();
        if from_bits > to_bits
            || !matches!(
                to_width,
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
            )
        {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native extend from {from_width:?} to {to_width:?}"),
            });
        }

        // An x86 byte/word destination is a partial register write: the
        // extended value replaces only the low 8/16 bits and the rest of the
        // architectural GPR survives. Compute the narrow result in a scratch
        // register before merging it so destructive forms such as CBW
        // (dst == src) still read the original source byte.
        if matches!(dst, VReg::Arch(ArchReg::X86(_)))
            && matches!(to_width, OpWidth::W8 | OpWidth::W16)
        {
            let dst_reg = Self::dst_gpr_arm_or_x86(dst)?;
            let mut avoid = vec![dst_reg];
            if !matches!(src, VReg::Imm(_)) {
                avoid.push(Self::gpr_arm_or_x86(src)?);
            }
            let scratches = Self::scratch_regs(&avoid, 1)?;
            self.emit_scratch_save(&scratches);
            self.lower_extend(
                VReg::Arch(ArchReg::Arm(ArmReg::X(scratches[0]))),
                src,
                from_width,
                to_width,
                sign_extend,
            )?;
            self.emit_bitfield(dst_reg, scratches[0], 0b01, 0, to_bits - 1, OpWidth::W64)?;
            self.emit_scratch_restore(&scratches);
            return Ok(());
        }

        if let VReg::Imm(value) = src {
            let emit_width = if to_width == OpWidth::W64 {
                OpWidth::W64
            } else {
                OpWidth::W32
            };
            let mut result = (value as u64) & from_width.mask();
            if sign_extend && (result & from_width.sign_bit()) != 0 {
                result |= !from_width.mask();
            }
            result &= to_width.mask();
            let dst = Self::dst_gpr_arm_or_x86(dst)?;
            if self.try_emit_movn_single(dst, result, emit_width)? {
                return Ok(());
            }
            return self.emit_mov_imm(dst, result as i64, emit_width);
        }

        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        let src = Self::gpr_arm_or_x86(src)?;
        if from_bits == to_bits {
            if matches!(to_width, OpWidth::W8 | OpWidth::W16) {
                return self.emit_bitfield(dst, src, 0b10, 0, from_bits - 1, OpWidth::W32);
            }
            if to_width == OpWidth::W64 && dst == src {
                return Ok(());
            }
            return self.emit_mov_reg(dst, src, to_width);
        }
        let emit_width = if to_width == OpWidth::W64 {
            OpWidth::W64
        } else {
            OpWidth::W32
        };
        self.emit_bitfield(
            dst,
            src,
            if sign_extend { 0b00 } else { 0b10 },
            0,
            from_bits - 1,
            emit_width,
        )?;
        if sign_extend && matches!(to_width, OpWidth::W8 | OpWidth::W16) {
            self.emit_bitfield(dst, dst, 0b10, 0, to_bits - 1, OpWidth::W32)?;
        }
        Ok(())
    }

    pub(crate) fn lower_truncate(
        &mut self,
        dst: VReg,
        src: VReg,
        to_width: OpWidth,
    ) -> Result<(), LowerError> {
        if !matches!(
            to_width,
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
        ) {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Truncate width {to_width:?}"),
            });
        }

        if let VReg::Imm(value) = src {
            let emit_width = if to_width == OpWidth::W64 {
                OpWidth::W64
            } else {
                OpWidth::W32
            };
            let result = (value as u64) & to_width.mask();
            let dst = Self::dst_gpr(dst)?;
            if self.try_emit_movn_single(dst, result, emit_width)? {
                return Ok(());
            }
            return self.emit_mov_imm(dst, result as i64, emit_width);
        }

        match to_width {
            OpWidth::W8 | OpWidth::W16 => {
                self.lower_bfx(dst, src, 0, to_width.bits() as u8, false, OpWidth::W64)
            }
            OpWidth::W32 | OpWidth::W64 => {
                let dst = Self::dst_gpr_arm_or_x86(dst)?;
                let src = Self::gpr_arm_or_x86(src)?;
                if to_width == OpWidth::W64 && dst == src {
                    return Ok(());
                }
                self.emit_mov_reg(dst, src, to_width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Truncate width {other:?}"),
            }),
        }
    }

    pub(crate) fn lower_div(
        &mut self,
        quot: VReg,
        rem: Option<VReg>,
        src1: VReg,
        src2: &SrcOperand,
        width: OpWidth,
        _flags_set: bool,
        signed: bool,
    ) -> Result<(), LowerError> {
        if !signed {
            if let (VReg::Imm(dividend), Some(divisor)) = (src1, Self::src_imm(src2)) {
                let emit_width = match width {
                    OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                    OpWidth::W64 => OpWidth::W64,
                    other => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("AArch64 native divide width {other:?}"),
                        });
                    }
                };
                let dividend = (dividend as u64) & width.mask();
                let divisor = (divisor as u64) & width.mask();
                if divisor != 0 {
                    let quot_dst = Self::dst_gpr_arm_or_x86(quot)?;
                    let quotient = dividend / divisor;
                    if !self.try_emit_movn_single(quot_dst, quotient, emit_width)? {
                        self.emit_mov_imm(quot_dst, quotient as i64, emit_width)?;
                    }
                    if let Some(rem) = rem {
                        let rem_dst = Self::dst_gpr_arm_or_x86(rem)?;
                        let remainder = dividend % divisor;
                        if !self.try_emit_movn_single(rem_dst, remainder, emit_width)? {
                            self.emit_mov_imm(rem_dst, remainder as i64, emit_width)?;
                        }
                    }
                    return Ok(());
                }
            }
        } else if let (VReg::Imm(dividend), Some(divisor)) = (src1, Self::src_imm(src2)) {
            let emit_width = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                OpWidth::W64 => OpWidth::W64,
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native divide width {other:?}"),
                    });
                }
            };
            let bits = width.bits();
            let mask = width.mask();
            let sign_extend = |value: u64| -> i128 {
                let shift = 128 - bits;
                (((value & mask) as u128) << shift) as i128 >> shift
            };
            let dividend = sign_extend(dividend as u64);
            let divisor = sign_extend(divisor as u64);
            if divisor == 0 {
                return Err(LowerError::UnsupportedOp {
                    op: "AArch64 native signed immediate divide by zero".into(),
                });
            }
            let quotient = dividend / divisor;
            let remainder = dividend % divisor;
            let qmin = -(1_i128 << (bits - 1));
            let qmax = (1_i128 << (bits - 1)) - 1;
            if quotient < qmin || quotient > qmax {
                return Err(LowerError::UnsupportedOp {
                    op: "AArch64 native signed immediate divide overflow".into(),
                });
            }
            let quot_dst = Self::dst_gpr_arm_or_x86(quot)?;
            let quotient = (quotient as u64) & mask;
            if !self.try_emit_movn_single(quot_dst, quotient, emit_width)? {
                self.emit_mov_imm(quot_dst, quotient as i64, emit_width)?;
            }
            if let Some(rem) = rem {
                let rem_dst = Self::dst_gpr_arm_or_x86(rem)?;
                let remainder = (remainder as u64) & mask;
                if !self.try_emit_movn_single(rem_dst, remainder, emit_width)? {
                    self.emit_mov_imm(rem_dst, remainder as i64, emit_width)?;
                }
            }
            return Ok(());
        }
        if Self::src_imm(src2).map(|imm| (imm as u64) & width.mask()) == Some(1) {
            let quot = Self::dst_gpr_arm_or_x86(quot)?;
            let rn = Self::gpr_arm_or_x86(src1)?;
            match width {
                OpWidth::W8 | OpWidth::W16 => {
                    if quot != rn {
                        self.emit_mov_reg(quot, rn, OpWidth::W32)?;
                    }
                    self.emit_bitfield(quot, quot, 0b10, 0, width.bits() - 1, OpWidth::W32)?;
                    if let Some(rem) = rem {
                        self.emit_mov_imm(Self::dst_gpr_arm_or_x86(rem)?, 0, OpWidth::W32)?;
                    }
                }
                OpWidth::W32 | OpWidth::W64 => {
                    if width != OpWidth::W64 || quot != rn {
                        self.emit_mov_reg(quot, rn, width)?;
                    }
                    if let Some(rem) = rem {
                        self.emit_mov_imm(Self::dst_gpr_arm_or_x86(rem)?, 0, width)?;
                    }
                }
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native divide width {other:?}"),
                    });
                }
            }
            return Ok(());
        }
        if signed {
            if let Some(imm) = Self::src_imm(src2) {
                if ((imm as u64) & width.mask()) == width.mask() {
                    if let Some(rem) = rem {
                        if quot == rem {
                            return Err(LowerError::UnsupportedOp {
                                op: "AArch64 native signed neg-one divide quotient/remainder overlap"
                                    .into(),
                            });
                        }
                        self.lower_neg(quot, src1, false, width)?;
                        let emit_width = match width {
                            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                            OpWidth::W64 => OpWidth::W64,
                            other => {
                                return Err(LowerError::UnsupportedOp {
                                    op: format!(
                                        "AArch64 native signed neg-one divide width {other:?}"
                                    ),
                                });
                            }
                        };
                        return self.emit_mov_imm(Self::dst_gpr(rem)?, 0, emit_width);
                    }
                    return match width {
                        OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64 => {
                            self.lower_neg(quot, src1, false, width)
                        }
                        other => Err(LowerError::UnsupportedOp {
                            op: format!("AArch64 native signed neg-one divide width {other:?}"),
                        }),
                    };
                }
            }
        }
        if !signed {
            if let Some(imm) = Self::src_imm(src2) {
                let divisor = (imm as u64) & width.mask();
                let subword_rem = rem.is_some() && matches!(width, OpWidth::W8 | OpWidth::W16);
                if divisor.is_power_of_two() && divisor > 1 && !subword_rem {
                    if let Some(rem) = rem {
                        let emit_width = match width {
                            OpWidth::W8 | OpWidth::W16 => OpWidth::W32,
                            OpWidth::W32 | OpWidth::W64 => width,
                            other => {
                                return Err(LowerError::UnsupportedOp {
                                    op: format!("AArch64 native divide width {other:?}"),
                                });
                            }
                        };
                        let quot = Self::dst_gpr_arm_or_x86(quot)?;
                        let rem = Self::dst_gpr_arm_or_x86(rem)?;
                        let rn = Self::gpr_arm_or_x86(src1)?;
                        let shift = divisor.trailing_zeros();
                        let mask = (divisor - 1) as i64;
                        let (n, immr, imms) = Self::logical_bitmask_imm(mask, emit_width)?;
                        if quot == rem {
                            return self.emit_logic_imm(rem, rn, 0b00, n, immr, imms, emit_width);
                        }
                        if quot == rn {
                            self.emit_logic_imm(rem, rn, 0b00, n, immr, imms, emit_width)?;
                            return self.emit_bitfield(
                                quot,
                                rn,
                                0b10,
                                shift,
                                width.bits() - 1,
                                emit_width,
                            );
                        }
                        self.emit_bitfield(quot, rn, 0b10, shift, width.bits() - 1, emit_width)?;
                        return self.emit_logic_imm(rem, rn, 0b00, n, immr, imms, emit_width);
                    }
                    let emit_width = match width {
                        OpWidth::W8 | OpWidth::W16 => OpWidth::W32,
                        OpWidth::W32 | OpWidth::W64 => width,
                        other => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("AArch64 native divide width {other:?}"),
                            });
                        }
                    };
                    return self.emit_bitfield(
                        Self::dst_gpr_arm_or_x86(quot)?,
                        Self::gpr_arm_or_x86(src1)?,
                        0b10,
                        divisor.trailing_zeros(),
                        width.bits() - 1,
                        emit_width,
                    );
                }
            }
        } else if rem.is_none() {
            if let Some(imm) = Self::src_imm(src2) {
                let divisor = (imm as u64) & width.mask();
                let bits = width.bits();
                if divisor.is_power_of_two() && divisor > 1 && divisor < (1_u64 << (bits - 1)) {
                    let emit_width = match width {
                        OpWidth::W32 | OpWidth::W64 => width,
                        other => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!(
                                    "AArch64 native signed power-of-two divide width {other:?}"
                                ),
                            });
                        }
                    };
                    let quot = Self::dst_gpr(quot)?;
                    let rn = Self::gpr(src1)?;
                    let shift = divisor.trailing_zeros();
                    if quot == rn {
                        let scratches = Self::scratch_regs(&[quot, rn], 1)?;
                        let sign = scratches[0];
                        self.emit_scratch_save(&scratches);
                        self.emit_bitfield(sign, rn, 0b00, bits - 1, bits - 1, emit_width)?;
                        self.emit_addsub_shifted(
                            quot,
                            rn,
                            sign,
                            false,
                            false,
                            1,
                            bits - shift,
                            emit_width,
                        )?;
                        self.emit_bitfield(quot, quot, 0b00, shift, bits - 1, emit_width)?;
                        self.emit_scratch_restore(&scratches);
                        return Ok(());
                    }
                    self.emit_bitfield(quot, rn, 0b00, bits - 1, bits - 1, emit_width)?;
                    self.emit_addsub_shifted(
                        quot,
                        rn,
                        quot,
                        false,
                        false,
                        1,
                        bits - shift,
                        emit_width,
                    )?;
                    return self.emit_bitfield(quot, quot, 0b00, shift, bits - 1, emit_width);
                }
            }
        }
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            return self.lower_subword_div(quot, rem, src1, src2, width, signed);
        }
        let quot = Self::dst_gpr_arm_or_x86(quot)?;
        let rn = Self::gpr_arm_or_x86(src1)?;
        let mut scratch = None;
        let rm = match src2 {
            SrcOperand::Reg(src2) => Self::gpr_arm_or_x86(*src2)?,
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                let mut avoid = vec![quot, rn];
                if let Some(rem) = rem {
                    avoid.push(Self::dst_gpr_arm_or_x86(rem)?);
                }
                let scratches = Self::scratch_regs(&avoid, 1)?;
                let rm = scratches[0];
                self.emit_scratch_save(&scratches);
                let divisor = (i128::from(*imm) & i128::from(width.mask())) as i64;
                self.emit_mov_imm(rm, divisor, width)?;
                scratch = Some(scratches);
                rm
            }
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native divide source {other:?}"),
                });
            }
        };
        self.lower_div_regs(quot, rem, rn, rm, width, signed)?;
        if let Some(scratch) = scratch {
            self.emit_scratch_restore(&scratch);
        }
        Ok(())
    }

    pub(crate) fn rev16_masks(width: OpWidth) -> Option<(i64, i64)> {
        match width {
            OpWidth::W32 => Some((0x00ff_00ff, 0xff00_ff00)),
            OpWidth::W64 => Some((
                0x00ff_00ff_00ff_00ff_u64 as i64,
                0xff00_ff00_ff00_ff00_u64 as i64,
            )),
            _ => None,
        }
    }

    pub(crate) fn matches_axflag_ops(ops: &[SmirOp]) -> bool {
        if ops.len() < 8 {
            return false;
        }
        let nzcv = VReg::Arch(ArchReg::Arm(ArmReg::Nzcv));
        let Some(v_to_z) = Self::op_dst(&ops[0].kind) else {
            return false;
        };
        let Some(z_or_v) = Self::op_dst(&ops[1].kind) else {
            return false;
        };
        let Some(z_bit) = Self::op_dst(&ops[2].kind) else {
            return false;
        };
        let Some(v_to_c) = Self::op_dst(&ops[3].kind) else {
            return false;
        };
        let Some(c_raw) = Self::op_dst(&ops[4].kind) else {
            return false;
        };
        let Some(c_bit) = Self::op_dst(&ops[5].kind) else {
            return false;
        };
        let Some(result) = Self::op_dst(&ops[6].kind) else {
            return false;
        };

        Self::flagm_shl(&ops[0].kind, v_to_z, nzcv, 2)
            && Self::flagm_or_reg(&ops[1].kind, z_or_v, nzcv, v_to_z)
            && Self::flagm_and_imm(&ops[2].kind, z_bit, z_or_v, NZCV_Z)
            && Self::flagm_shl(&ops[3].kind, v_to_c, nzcv, 1)
            && Self::flagm_and_imm(&ops[4].kind, c_raw, nzcv, NZCV_C)
            && Self::flagm_andnot_reg(&ops[5].kind, c_bit, c_raw, v_to_c)
            && Self::flagm_or_reg(&ops[6].kind, result, z_bit, c_bit)
            && Self::flagm_mov_to_nzcv(&ops[7].kind, result)
    }

    pub(crate) fn matches_xaflag_ops(ops: &[SmirOp]) -> bool {
        if ops.len() < 16 {
            return false;
        }
        let nzcv = VReg::Arch(ArchReg::Arm(ArmReg::Nzcv));
        let Some(shl1) = Self::op_dst(&ops[0].kind) else {
            return false;
        };
        let Some(shl2) = Self::op_dst(&ops[1].kind) else {
            return false;
        };
        let Some(has_c_or_z_as_n) = Self::op_dst(&ops[2].kind) else {
            return false;
        };
        let Some(n_bit) = Self::op_dst(&ops[3].kind) else {
            return false;
        };
        let Some(z_raw) = Self::op_dst(&ops[4].kind) else {
            return false;
        };
        let Some(z_bit) = Self::op_dst(&ops[5].kind) else {
            return false;
        };
        let Some(shr1) = Self::op_dst(&ops[6].kind) else {
            return false;
        };
        let Some(c_or_z) = Self::op_dst(&ops[7].kind) else {
            return false;
        };
        let Some(c_bit) = Self::op_dst(&ops[8].kind) else {
            return false;
        };
        let Some(shr2) = Self::op_dst(&ops[9].kind) else {
            return false;
        };
        let Some(v_unmasked) = Self::op_dst(&ops[10].kind) else {
            return false;
        };
        let Some(v_bit) = Self::op_dst(&ops[11].kind) else {
            return false;
        };
        let Some(nz) = Self::op_dst(&ops[12].kind) else {
            return false;
        };
        let Some(cv) = Self::op_dst(&ops[13].kind) else {
            return false;
        };
        let Some(result) = Self::op_dst(&ops[14].kind) else {
            return false;
        };

        Self::flagm_shl(&ops[0].kind, shl1, nzcv, 1)
            && Self::flagm_shl(&ops[1].kind, shl2, nzcv, 2)
            && Self::flagm_or_reg(&ops[2].kind, has_c_or_z_as_n, shl1, shl2)
            && Self::flagm_andnot_reg(&ops[3].kind, n_bit, VReg::Imm(NZCV_N), has_c_or_z_as_n)
            && Self::flagm_and_imm(&ops[4].kind, z_raw, nzcv, NZCV_Z)
            && Self::flagm_and_reg(&ops[5].kind, z_bit, z_raw, shl1)
            && Self::flagm_shr(&ops[6].kind, shr1, nzcv, 1)
            && Self::flagm_or_reg(&ops[7].kind, c_or_z, nzcv, shr1)
            && Self::flagm_and_imm(&ops[8].kind, c_bit, c_or_z, NZCV_C)
            && Self::flagm_shr(&ops[9].kind, shr2, nzcv, 2)
            && Self::flagm_andnot_reg(&ops[10].kind, v_unmasked, shr2, shr1)
            && Self::flagm_and_imm(&ops[11].kind, v_bit, v_unmasked, NZCV_V)
            && Self::flagm_or_reg(&ops[12].kind, nz, n_bit, z_bit)
            && Self::flagm_or_reg(&ops[13].kind, cv, c_bit, v_bit)
            && Self::flagm_or_reg(&ops[14].kind, result, nz, cv)
            && Self::flagm_mov_to_nzcv(&ops[15].kind, result)
    }

    pub(crate) fn lower_rol(
        &mut self,
        dst: VReg,
        src: VReg,
        amount: &SrcOperand,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if let Some((dst_reg, result)) =
            Self::x86_partial_write_scratch(dst, width, &[src], &[amount])?
        {
            let scratches = [result];
            self.emit_scratch_save(&scratches);
            self.lower_rol(Self::arm_x_reg(result), src, amount, set_flags, width)?;
            self.emit_bitfield(dst_reg, result, 0b01, 0, width.bits() - 1, OpWidth::W64)?;
            self.emit_scratch_restore(&scratches);
            return Ok(());
        }

        if set_flags {
            let dst = Self::dst_gpr_arm_or_x86(dst)?;
            let src = Self::gpr_arm_or_x86(src)?;
            return self.lower_rotate_with_flags(dst, src, amount, width, false);
        }

        if let VReg::Imm(value) = src {
            let emit_width = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                OpWidth::W64 => OpWidth::W64,
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native immediate-source Rol width {other:?}"),
                    });
                }
            };
            let mask = width.mask();
            let value = value as u64 & mask;
            if value == 0 || value == mask {
                return self.emit_mov_imm_best(Self::dst_gpr(dst)?, value as i64, emit_width);
            }
        }

        if let (VReg::Imm(value), Some(amount)) = (src, Self::src_imm(amount)) {
            let emit_width = match width {
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
                OpWidth::W64 => OpWidth::W64,
                other => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("AArch64 native immediate-source Rol width {other:?}"),
                    });
                }
            };
            let mask = width.mask();
            let value = (value as u64) & mask;
            let bits = width.bits() as u64;
            let cmask = if bits == 64 { 0x3f } else { 0x1f };
            let amount = ((amount as u64) & cmask) % bits;
            let result = if amount == 0 {
                value
            } else {
                ((value << amount) | (value >> (bits - amount))) & mask
            };
            let dst = Self::dst_gpr(dst)?;
            if self.try_emit_movn_single(dst, result, emit_width)? {
                return Ok(());
            }
            return self.emit_mov_imm(dst, result as i64, emit_width);
        }

        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        let src = Self::gpr_arm_or_x86(src)?;
        let bits = width.bits();
        if matches!(amount, SrcOperand::Reg(VReg::Imm(0))) {
            return self.lower_shift_imm(dst, src, 0, ShiftOp::Ror, width);
        }

        match amount {
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                let amount = (*imm as u64 & u64::from(bits - 1)) as u32;
                let ror = if amount == 0 { 0 } else { bits - amount };
                self.lower_shift_imm(dst, src, i64::from(ror), ShiftOp::Ror, width)
            }
            SrcOperand::Reg(reg) => {
                let amount = Self::gpr_arm_or_x86(*reg)?;
                let count_width = if matches!(width, OpWidth::W8 | OpWidth::W16) {
                    OpWidth::W32
                } else {
                    width
                };

                if dst == src {
                    let scratches = Self::scratch_regs(&[dst, src, amount], 1)?;
                    let count = scratches[0];
                    self.emit_scratch_save(&scratches);
                    self.emit_addsub_reg(count, 31, amount, true, false, count_width)?;
                    if matches!(width, OpWidth::W8 | OpWidth::W16) {
                        self.lower_subword_shift_reg(dst, src, count, ShiftOp::Ror, width)?;
                    } else {
                        self.emit_dp2(dst, src, count, 0b1011, width)?;
                    }
                    self.emit_scratch_restore(&scratches);
                    Ok(())
                } else {
                    self.emit_addsub_reg(dst, 31, amount, true, false, count_width)?;
                    if matches!(width, OpWidth::W8 | OpWidth::W16) {
                        self.lower_subword_shift_reg(dst, src, dst, ShiftOp::Ror, width)
                    } else {
                        self.emit_dp2(dst, src, dst, 0b1011, width)
                    }
                }
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Rol amount {other:?}"),
            }),
        }
    }

    pub(crate) fn is_low_contiguous_mask(mask: u64, width: OpWidth) -> bool {
        mask != 0 && mask != width.mask() && (mask & (mask + 1)) == 0
    }

    pub(crate) fn contiguous_mask_field(mask: u64) -> Option<(u8, u8)> {
        let lsb = mask.trailing_zeros();
        let shifted = mask >> lsb;
        if shifted != 0 && (shifted & (shifted + 1)) == 0 {
            Some((lsb as u8, shifted.count_ones() as u8))
        } else {
            None
        }
    }

    pub(crate) fn lower_cmove(
        &mut self,
        dst: VReg,
        src: VReg,
        cond: Condition,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if !matches!(
            width,
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
        ) {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native CMove width {width:?}"),
            });
        }

        if let VReg::Imm(value) = src {
            return self.lower_cmove_imm(dst, value, cond, width);
        }

        // W8/W16 conditional moves write only a sub-register. A false condition must
        // leave the ENTIRE destination unchanged (SMIR CMove does nothing on the
        // false path). Lower as a branch over a partial write so nothing is written
        // when the condition fails: for an x86 destination the true path MERGES the
        // low bits (upper bits preserved, matching `write_x86_partial`); for a
        // non-x86 destination it zero-extends the low bits. The previous
        // CSEL-then-UXTB always wrote (and truncated) the destination — corrupting it
        // on the false path. (#15)
        if matches!(width, OpWidth::W8 | OpWidth::W16) && cond != Condition::Always {
            let is_x86_dst = matches!(dst, VReg::Arch(ArchReg::X86(_)));
            let dst_reg = Self::dst_gpr_arm_or_x86(dst)?;
            let src_reg = Self::gpr_arm_or_x86(src)?;
            let imms = if width == OpWidth::W8 { 7 } else { 15 };
            let inverted = Self::inverted_arm_cond_code(cond)?;
            let skip = self.code.position();
            self.emit(0x5400_0000 | inverted); // B.<!cond> over the partial write
            if is_x86_dst {
                // BFI Xdst, Xsrc, #0, #n: insert the low n bits, preserve the rest.
                self.emit_bitfield(dst_reg, src_reg, 0b01, 0, imms, OpWidth::W64)?;
            } else {
                // UBFX Wdst, Wsrc, #0, #n: zero-extend the low n bits.
                self.emit_bitfield(dst_reg, src_reg, 0b10, 0, imms, OpWidth::W32)?;
            }
            return self.patch_cond_branch_to_current(skip, inverted);
        }

        if src == dst {
            let dst = Self::dst_gpr_arm_or_x86(dst)?;
            return self.finish_cmove_width(dst, width);
        }

        if cond == Condition::Always {
            return self.lower_select_mov(dst, &Self::vreg_src(src), width);
        }

        let dst = Self::dst_gpr_arm_or_x86(dst)?;
        let src = Self::gpr_arm_or_x86(src)?;
        self.emit_cond_select(dst, src, dst, Self::arm_cond_code(cond)?, 0, 0, width)
    }

    pub(crate) fn lower_select(
        &mut self,
        dst: VReg,
        cond: VReg,
        src_true: VReg,
        src_false: VReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if src_true == src_false {
            return self.lower_select_mov(dst, &Self::vreg_src(src_true), width);
        }

        match cond {
            VReg::Imm(value) => {
                let src = match if value != 0 { src_true } else { src_false } {
                    VReg::Imm(value) => SrcOperand::Imm(value),
                    reg => SrcOperand::Reg(reg),
                };
                self.lower_select_mov(dst, &src, width)
            }
            other => {
                let cond = Self::gpr_arm_or_x86(other)?;
                let true_src = Self::vreg_src(src_true);
                let false_src = Self::vreg_src(src_false);

                if width == OpWidth::W64 && src_true == dst {
                    let skip_false = self.code.position();
                    self.emit(0xb500_0000 | (cond as u32));
                    self.lower_select_mov(dst, &false_src, width)?;
                    return self.patch_compare_branch_to_current(skip_false, cond, true);
                }

                if width == OpWidth::W64 && src_false == dst {
                    let skip_true = self.code.position();
                    self.emit(0xb400_0000 | (cond as u32));
                    self.lower_select_mov(dst, &true_src, width)?;
                    return self.patch_compare_branch_to_current(skip_true, cond, false);
                }

                let false_branch = self.code.position();
                self.emit(0xb400_0000 | (cond as u32));
                self.lower_select_mov(dst, &true_src, width)?;

                let end_branch = self.code.position();
                self.emit(0x1400_0000);
                self.patch_compare_branch_to_current(false_branch, cond, false)?;

                self.lower_select_mov(dst, &false_src, width)?;
                self.patch_branch_to_current(end_branch)
            }
        }
    }
}
