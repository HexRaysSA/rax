//! Uncategorized instruction execution

use crate::isa::arm::ExecutionState;
use crate::isa::arm::aarch32::cpu::{
    ArmMemory, Armv7Cpu, MemoryError, ProcessorMode, Psr, add_with_carry, compute_n_flag,
    compute_z_flag, condition_passed, expand_imm_c, shift_c, sign_extend,
};
use crate::isa::arm::aarch32::instructions::*;
use crate::isa::arm::aarch32::vfp::{
    Fpscr, NeonSize, RoundingMode, vabs_f16_bits, vabs_f32, vabs_f64, vadd_f16_bits, vadd_f32,
    vadd_f64, vadd_i, vand, vbic, vcls_i, vclz_i, vcmp_f16_bits_with_exception,
    vcmp_f32_with_exception, vcmp_f64_with_exception, vcnt_i8, vcvt_f16_bits_f32,
    vcvt_f32_f16_bits, vcvt_f32_f64, vcvt_f32_s32, vcvt_f32_s32_fixed, vcvt_f32_u32,
    vcvt_f32_u32_fixed, vcvt_f64_f32, vcvt_f64_s32, vcvt_f64_s32_fixed, vcvt_f64_u32,
    vcvt_f64_u32_fixed, vcvt_s32_f32, vcvt_s32_f32_fixed, vcvt_s32_f32_round, vcvt_s32_f64,
    vcvt_s32_f64_fixed, vcvt_s32_f64_round, vcvt_u32_f32, vcvt_u32_f32_fixed, vcvt_u32_f32_round,
    vcvt_u32_f64, vcvt_u32_f64_fixed, vcvt_u32_f64_round, vcvtr_s32_f32, vcvtr_s32_f64,
    vcvtr_u32_f32, vcvtr_u32_f64, vdiv_f16_bits, vdiv_f32, vdiv_f64, veor, vfma_f16_bits, vfma_f32,
    vfma_f64, vfms_f16_bits, vfms_f32, vfms_f64, vfnma_f16_bits, vfnma_f32, vfnma_f64,
    vfnms_f16_bits, vfnms_f32, vfnms_f64, vfp_expand_imm_f16, vfp_expand_imm_f32,
    vfp_expand_imm_f64, vmaxnm_f16_bits, vmaxnm_f32, vmaxnm_f64, vminnm_f16_bits, vminnm_f32,
    vminnm_f64, vmla_f16_bits, vmla_f32, vmla_f64, vmls_f16_bits, vmls_f32, vmls_f64,
    vmul_f16_bits, vmul_f32, vmul_f64, vmvn, vneg_f16_bits, vneg_f32, vneg_f64, vnmla_f16_bits,
    vnmla_f32, vnmla_f64, vnmls_f16_bits, vnmls_f32, vnmls_f64, vnmul_f16_bits, vnmul_f32,
    vnmul_f64, vorn, vorr, vrev, vrint_f16_bits, vrint_f32, vrint_f64, vsqrt_f16_bits, vsqrt_f32,
    vsqrt_f64, vsub_f16_bits, vsub_f32, vsub_f64, vsub_i,
};
use crate::isa::arm::decoder::{Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType};

impl<'a, M: ArmMemory> Executor<'a, M> {
    /// Create a new executor.
    pub fn new(cpu: &'a mut Armv7Cpu, mem: &'a mut M) -> Self {
        Executor {
            cpu,
            mem,
            exclusive_monitor: ExclusiveMonitor::new(),
            vbar: 0,
        }
    }

    /// Create a new executor with custom VBAR.
    pub fn with_vbar(cpu: &'a mut Armv7Cpu, mem: &'a mut M, vbar: u32) -> Self {
        Executor {
            cpu,
            mem,
            exclusive_monitor: ExclusiveMonitor::new(),
            vbar,
        }
    }

    /// Execute a single decoded instruction.
    pub fn execute(&mut self, insn: &DecodedInsn) -> ExecResult {
        // Thumb IT state predicates the following instruction(s); the IT
        // instruction itself is unconditional and installs the state.
        let cond = if insn.state.is_thumb()
            && self.cpu.cpsr.in_it_block()
            && insn.mnemonic != Mnemonic::IT
        {
            Some(Condition::from_bits(self.cpu.cpsr.it_condition()))
        } else {
            insn.cond
        };

        // Check condition code.
        if let Some(cond) = cond {
            if !self.condition_passed(cond) {
                return ExecResult::Continue;
            }
        }

        // A 16-bit Thumb data-processing instruction sets the flags only
        // outside an IT block (`setflags = !InITBlock()`); the comparisons
        // always set them.
        let in_it_unflagged;
        let insn = if insn.state.is_thumb()
            && insn.size == 2
            && insn.sets_flags
            && self.cpu.cpsr.in_it_block()
            && !matches!(insn.mnemonic, Mnemonic::CMP | Mnemonic::CMN | Mnemonic::TST)
        {
            in_it_unflagged = DecodedInsn {
                sets_flags: false,
                ..insn.clone()
            };
            &in_it_unflagged
        } else {
            insn
        };

        // Dispatch based on mnemonic
        match insn.mnemonic {
            // Data Processing - Arithmetic
            Mnemonic::ADD | Mnemonic::ADDS => self.exec_add(insn),
            Mnemonic::ADC | Mnemonic::ADCS => self.exec_adc(insn),
            Mnemonic::SUB | Mnemonic::SUBS => self.exec_sub(insn),
            Mnemonic::SBC | Mnemonic::SBCS => self.exec_sbc(insn),
            Mnemonic::RSB | Mnemonic::RSBS => self.exec_rsb(insn),
            Mnemonic::RSC | Mnemonic::RSCS => self.exec_rsc(insn),
            Mnemonic::NEG | Mnemonic::NEGS => self.exec_neg(insn),

            // Data Processing - Logical
            Mnemonic::AND | Mnemonic::ANDS => self.exec_and(insn),
            Mnemonic::ORR | Mnemonic::ORRS => self.exec_orr(insn),
            Mnemonic::EOR | Mnemonic::EORS => self.exec_eor(insn),
            Mnemonic::BIC | Mnemonic::BICS => self.exec_bic(insn),
            Mnemonic::ORN | Mnemonic::ORNS => self.exec_orn(insn),

            // Data Processing - Move
            Mnemonic::MOV | Mnemonic::MOVS => self.exec_mov(insn),
            Mnemonic::MVN | Mnemonic::MVNS => self.exec_mvn(insn),
            Mnemonic::MOVZ => self.exec_movw(insn),
            Mnemonic::MOVK => self.exec_movt(insn),

            // Data Processing - Compare
            Mnemonic::CMP => self.exec_cmp(insn),
            Mnemonic::CMN => self.exec_cmn(insn),
            Mnemonic::TST => self.exec_tst(insn),
            Mnemonic::TEQ => self.exec_teq(insn),

            // Data Processing - Shift
            Mnemonic::LSL | Mnemonic::LSLS => self.exec_lsl(insn),
            Mnemonic::LSR | Mnemonic::LSRS => self.exec_lsr(insn),
            Mnemonic::ASR | Mnemonic::ASRS => self.exec_asr(insn),
            Mnemonic::ROR | Mnemonic::RORS => self.exec_ror(insn),
            Mnemonic::RRX | Mnemonic::RRXS => self.exec_rrx(insn),

            // Multiply
            Mnemonic::MUL | Mnemonic::MULS => self.exec_mul(insn),
            Mnemonic::MLA => self.exec_mla(insn),
            Mnemonic::MLS => self.exec_mls(insn),
            Mnemonic::UMULL | Mnemonic::UMULLS => self.exec_umull(insn),
            Mnemonic::SMULL | Mnemonic::SMULLS => self.exec_smull(insn),
            Mnemonic::UMLAL => self.exec_umlal(insn),
            Mnemonic::SMLAL => self.exec_smlal(insn),
            Mnemonic::UMAAL => self.exec_umaal(insn),
            Mnemonic::SDIV => self.exec_sdiv(insn),
            Mnemonic::UDIV => self.exec_udiv(insn),

            // Branch
            Mnemonic::B | Mnemonic::BCC => self.exec_b(insn),
            Mnemonic::BL => self.exec_bl(insn),
            Mnemonic::BX => self.exec_bx(insn),
            Mnemonic::BLX => self.exec_blx(insn),
            Mnemonic::CBZ => self.exec_cbz(insn),
            Mnemonic::CBNZ => self.exec_cbnz(insn),
            Mnemonic::TBB => self.exec_tbb(insn),
            Mnemonic::TBH => self.exec_tbh(insn),

            // Load/Store Word/Byte
            Mnemonic::LDR => self.exec_ldr(insn),
            Mnemonic::LDRB => self.exec_ldrb(insn),
            Mnemonic::STR => self.exec_str(insn),
            Mnemonic::STRB => self.exec_strb(insn),

            // Load/Store Halfword/Signed
            Mnemonic::LDRH => self.exec_ldrh(insn),
            Mnemonic::LDRSH => self.exec_ldrsh(insn),
            Mnemonic::LDRSB => self.exec_ldrsb(insn),
            Mnemonic::STRH => self.exec_strh(insn),

            // Load/Store Double (LDP/STP are the AArch64 names; A32/T32 LDRD/STRD)
            Mnemonic::LDP => self.exec_ldrd(insn),
            Mnemonic::STP => self.exec_strd(insn),

            // Load/Store Exclusive
            // The acquire/release exclusives order accesses no differently
            // for one thread.
            Mnemonic::LDXR | Mnemonic::LDAXR => self.exec_ldrex(insn),
            Mnemonic::STXR | Mnemonic::STLXR => self.exec_strex(insn),
            Mnemonic::LDXRB | Mnemonic::LDAXRB => self.exec_ldrexb(insn),
            Mnemonic::STXRB | Mnemonic::STLXRB => self.exec_strexb(insn),
            Mnemonic::LDXRH | Mnemonic::LDAXRH => self.exec_ldrexh(insn),
            Mnemonic::STXRH | Mnemonic::STLXRH => self.exec_strexh(insn),
            Mnemonic::LDXP | Mnemonic::LDAXP => self.exec_ldrexd(insn),
            Mnemonic::STXP | Mnemonic::STLXP => self.exec_strexd(insn),
            Mnemonic::LDAR => self.exec_lda(insn, 4),
            Mnemonic::LDARB => self.exec_lda(insn, 1),
            Mnemonic::LDARH => self.exec_lda(insn, 2),
            Mnemonic::STLR => self.exec_stl(insn, 4),
            Mnemonic::STLRB => self.exec_stl(insn, 1),
            Mnemonic::STLRH => self.exec_stl(insn, 2),
            Mnemonic::CLREX => self.exec_clrex(insn),

            // Load/Store Multiple
            Mnemonic::LDM | Mnemonic::LDMIA => self.exec_ldm_stm(insn, true, false, true),
            Mnemonic::LDMIB => self.exec_ldm_stm(insn, true, true, true),
            Mnemonic::LDMDA => self.exec_ldm_stm(insn, true, false, false),
            Mnemonic::LDMDB => self.exec_ldm_stm(insn, true, true, false),
            Mnemonic::STM | Mnemonic::STMIA => self.exec_ldm_stm(insn, false, false, true),
            Mnemonic::STMIB => self.exec_ldm_stm(insn, false, true, true),
            Mnemonic::STMDA => self.exec_ldm_stm(insn, false, false, false),
            Mnemonic::STMDB => self.exec_ldm_stm(insn, false, true, false),
            Mnemonic::PUSH => self.exec_push(insn),
            Mnemonic::POP => self.exec_pop(insn),

            // System
            Mnemonic::SVC | Mnemonic::SWI => self.exec_svc(insn),
            Mnemonic::NOP
            | Mnemonic::YIELD
            | Mnemonic::SEV
            | Mnemonic::SEVL
            | Mnemonic::DGH
            | Mnemonic::BTI
            | Mnemonic::WFET
            | Mnemonic::WFIT => ExecResult::Continue,
            Mnemonic::WFI | Mnemonic::WFE => ExecResult::Halt,
            Mnemonic::CPS => self.exec_cps(insn),
            Mnemonic::SRS => self.exec_srs(insn),
            Mnemonic::RFE => self.exec_rfe(insn),
            Mnemonic::SWP => self.exec_swp(insn),
            Mnemonic::BKPT => self.exec_bkpt(insn),
            Mnemonic::UDF => ExecResult::Exception(ExceptionType::UndefinedInstruction),
            Mnemonic::MRS => self.exec_mrs(insn),
            Mnemonic::MSR => self.exec_msr(insn),
            // Memory barriers
            Mnemonic::DMB | Mnemonic::DSB | Mnemonic::ISB | Mnemonic::SB => ExecResult::Continue,
            Mnemonic::IT => self.exec_it(insn),

            // Coprocessor
            Mnemonic::MCR => self.exec_mcr(insn),
            Mnemonic::MRC => self.exec_mrc(insn),
            Mnemonic::VMSR => self.exec_mcr(insn),
            Mnemonic::VMRS => self.exec_mrc(insn),
            Mnemonic::VLDR => self.exec_vldr(insn),
            Mnemonic::VSTR => self.exec_vstr(insn),
            Mnemonic::VLDM | Mnemonic::VPOP => self.exec_vldm(insn),
            Mnemonic::VSTM | Mnemonic::VPUSH => self.exec_vstm(insn),
            Mnemonic::VLD1 => self.exec_vld1_multiple(insn),
            Mnemonic::VST1 => self.exec_vst1_multiple(insn),
            Mnemonic::VLD2 => self.exec_vld2_multiple(insn),
            Mnemonic::VST2 => self.exec_vst2_multiple(insn),
            Mnemonic::VLD3 => self.exec_vld3_multiple(insn),
            Mnemonic::VST3 => self.exec_vst3_multiple(insn),
            Mnemonic::VLD4 => self.exec_vld4_multiple(insn),
            Mnemonic::VST4 => self.exec_vst4_multiple(insn),
            Mnemonic::VMOV => self.exec_vmov(insn),
            Mnemonic::VMOVL => self.exec_neon_widen_move(insn),
            Mnemonic::VMOVN | Mnemonic::VQMOVN | Mnemonic::VQMOVUN => {
                self.exec_neon_narrow_move(insn)
            }
            Mnemonic::VAND
            | Mnemonic::VBIC
            | Mnemonic::VORR
            | Mnemonic::VORN
            | Mnemonic::VEOR
            | Mnemonic::VBSL
            | Mnemonic::VBIT
            | Mnemonic::VBIF => self.exec_neon_logical_register(insn),
            Mnemonic::VMVN => self.exec_neon_vmvn_register(insn),
            Mnemonic::VREV16 | Mnemonic::VREV32 | Mnemonic::VREV64 => {
                self.exec_neon_vrev_register(insn)
            }
            Mnemonic::VSWP => self.exec_neon_vswp(insn),
            Mnemonic::VDUP => self.exec_neon_vdup(insn),
            Mnemonic::VSHL => self.exec_vshl(insn),
            Mnemonic::VQSHL => self.exec_vqshl(insn),
            Mnemonic::VRSHL | Mnemonic::VQRSHL => self.exec_neon_shift_register(insn),
            Mnemonic::VQSHLU => self.exec_neon_saturating_shift_left_immediate(insn),
            Mnemonic::VSHR
            | Mnemonic::VRSHR
            | Mnemonic::VSRA
            | Mnemonic::VRSRA
            | Mnemonic::VSLI
            | Mnemonic::VSRI => self.exec_neon_shift_immediate(insn),
            Mnemonic::VSHRN
            | Mnemonic::VRSHRN
            | Mnemonic::VQSHRN
            | Mnemonic::VQRSHRN
            | Mnemonic::VQSHRUN
            | Mnemonic::VQRSHRUN => self.exec_neon_shift_narrow_immediate(insn),
            Mnemonic::VTRN | Mnemonic::VUZP | Mnemonic::VZIP => {
                self.exec_neon_pairwise_permute(insn)
            }
            Mnemonic::VPADD | Mnemonic::VPMAX | Mnemonic::VPMIN => {
                self.exec_neon_pairwise_integer(insn)
            }
            Mnemonic::VPADDL | Mnemonic::VPADAL => self.exec_neon_pairwise_add_long(insn),
            Mnemonic::VHADD | Mnemonic::VRHADD | Mnemonic::VHSUB => {
                self.exec_neon_halving_add_sub(insn)
            }
            Mnemonic::VCEQ | Mnemonic::VCGT | Mnemonic::VCGE | Mnemonic::VTST => {
                self.exec_neon_compare(insn)
            }
            Mnemonic::VCLE | Mnemonic::VCLT => self.exec_neon_compare_zero(insn),
            Mnemonic::VACGT | Mnemonic::VACGE => self.exec_neon_fp_compare(insn),
            Mnemonic::VQADD | Mnemonic::VQSUB => self.exec_neon_saturating_add_sub(insn),
            Mnemonic::VQDMULH | Mnemonic::VQRDMULH => self.exec_neon_saturating_doubling_mulh(insn),
            Mnemonic::VQABS | Mnemonic::VQNEG => self.exec_neon_saturating_abs_neg(insn),
            Mnemonic::VRECPE | Mnemonic::VRSQRTE => self.exec_neon_recip_estimate(insn),
            Mnemonic::VRECPS | Mnemonic::VRSQRTS => self.exec_neon_recip_step(insn),
            Mnemonic::VADDL | Mnemonic::VADDW | Mnemonic::VSUBL | Mnemonic::VSUBW => {
                self.exec_neon_long_wide_add_sub(insn)
            }
            Mnemonic::VADDHN | Mnemonic::VRADDHN | Mnemonic::VSUBHN | Mnemonic::VRSUBHN => {
                self.exec_neon_narrow_add_sub(insn)
            }
            Mnemonic::VMULL
            | Mnemonic::VMLAL
            | Mnemonic::VMLSL
            | Mnemonic::VQDMULL
            | Mnemonic::VQDMLAL
            | Mnemonic::VQDMLSL => self.exec_neon_long_multiply(insn),
            Mnemonic::VCLS | Mnemonic::VCLZ | Mnemonic::VCNT => self.exec_neon_count_register(insn),
            Mnemonic::VEXT => self.exec_neon_vext(insn),
            Mnemonic::VTBL | Mnemonic::VTBX => self.exec_neon_table_lookup(insn),
            Mnemonic::VMAX | Mnemonic::VMIN => self.exec_neon_minmax(insn),
            Mnemonic::VABD => self.exec_neon_absdiff(insn),
            Mnemonic::VABA => self.exec_neon_integer_absdiff_accum(insn),
            Mnemonic::VABDL | Mnemonic::VABAL => self.exec_neon_integer_absdiff_long(insn),
            Mnemonic::VADD | Mnemonic::VSUB => self.exec_vadd_vsub(insn),
            Mnemonic::VMUL => self.exec_vmul(insn),
            Mnemonic::VDIV => self.exec_vfp_binop(insn),
            Mnemonic::VNMUL => self.exec_vfp_binop(insn),
            Mnemonic::VMAXNM_F32
            | Mnemonic::VMAXNM_F64
            | Mnemonic::VMAXNM_F16
            | Mnemonic::VMINNM_F32
            | Mnemonic::VMINNM_F64
            | Mnemonic::VMINNM_F16 => self.exec_vfp_binop(insn),
            Mnemonic::VSELEQ | Mnemonic::VSELGE | Mnemonic::VSELGT | Mnemonic::VSELVS => {
                self.exec_vsel(insn)
            }
            Mnemonic::VMLA | Mnemonic::VMLS => self.exec_vmla_vmls(insn),
            Mnemonic::VFMAL | Mnemonic::VFMLS => self.exec_neon_fp16_fused_multiply_long(insn),
            Mnemonic::VFMA
            | Mnemonic::VFMS
            | Mnemonic::VNMLA
            | Mnemonic::VNMLS
            | Mnemonic::VFNMA
            | Mnemonic::VFNMS => self.exec_vfp_accop(insn),
            Mnemonic::VABS | Mnemonic::VNEG if Self::is_neon_abs_neg(insn.raw) => {
                self.exec_neon_abs_neg(insn)
            }
            Mnemonic::VABS | Mnemonic::VNEG => self.exec_vfp_unop(insn),
            Mnemonic::VSQRT => self.exec_vfp_unop(insn),
            Mnemonic::VRINTA_F16
            | Mnemonic::VRINTA_F32
            | Mnemonic::VRINTM_F16
            | Mnemonic::VRINTM_F32
            | Mnemonic::VRINTN_F16
            | Mnemonic::VRINTN_F32
            | Mnemonic::VRINTP_F16
            | Mnemonic::VRINTP_F32
            | Mnemonic::VRINTX_F16
            | Mnemonic::VRINTX_F32
            | Mnemonic::VRINTZ_F16
            | Mnemonic::VRINTZ_F32
                if Self::is_neon_vrint_shape(insn.raw) =>
            {
                self.exec_neon_vrint(insn)
            }
            Mnemonic::VRINTA_F32
            | Mnemonic::VRINTA_F64
            | Mnemonic::VRINTM_F32
            | Mnemonic::VRINTM_F64
            | Mnemonic::VRINTN_F32
            | Mnemonic::VRINTN_F64
            | Mnemonic::VRINTP_F32
            | Mnemonic::VRINTP_F64
            | Mnemonic::VRINTP_F16
            | Mnemonic::VRINTR_F32
            | Mnemonic::VRINTR_F64
            | Mnemonic::VRINTR_F16
            | Mnemonic::VRINTX_F32
            | Mnemonic::VRINTX_F64
            | Mnemonic::VRINTX_F16
            | Mnemonic::VRINTZ_F32
            | Mnemonic::VRINTZ_F64
            | Mnemonic::VRINTZ_F16
            | Mnemonic::VRINTA_F16
            | Mnemonic::VRINTM_F16
            | Mnemonic::VRINTN_F16 => self.exec_vrint(insn),
            Mnemonic::VCMP | Mnemonic::VCMPE => self.exec_vcmp(insn),
            Mnemonic::VCVT_S32_F32
            | Mnemonic::VCVT_U32_F32
            | Mnemonic::VCVT_S32_F16
            | Mnemonic::VCVT_U32_F16
            | Mnemonic::VCVTM_S32_F32
            | Mnemonic::VCVTM_U32_F32
            | Mnemonic::VCVTM_S32_F16
            | Mnemonic::VCVTM_U32_F16
            | Mnemonic::VCVTN_S32_F32
            | Mnemonic::VCVTN_U32_F32
            | Mnemonic::VCVTN_S32_F16
            | Mnemonic::VCVTN_U32_F16
            | Mnemonic::VCVTP_S32_F16
            | Mnemonic::VCVTP_U32_F16
            | Mnemonic::VCVTP_S32_F32
            | Mnemonic::VCVTP_U32_F32
                if Self::is_neon_directed_convert_shape(insn.raw) =>
            {
                self.exec_neon_directed_convert(insn)
            }
            Mnemonic::VCVT_F32_S32
            | Mnemonic::VCVT_F32_U32
            | Mnemonic::VCVT_F16_S32
            | Mnemonic::VCVT_F16_U32
            | Mnemonic::VCVT_S32_F32
            | Mnemonic::VCVT_U32_F32
            | Mnemonic::VCVT_S32_F16
            | Mnemonic::VCVT_U32_F16
            | Mnemonic::VCVT_F64_S32
            | Mnemonic::VCVT_F64_U32
            | Mnemonic::VCVT_S32_F64
            | Mnemonic::VCVT_U32_F64
            | Mnemonic::VCVT_F64_F32
            | Mnemonic::VCVT_F32_F64
            | Mnemonic::VCVT_F16_F32
            | Mnemonic::VCVT_F32_F16
            | Mnemonic::VCVTB_F32_F16
            | Mnemonic::VCVTT_F32_F16
            | Mnemonic::VCVTB_F16_F32
            | Mnemonic::VCVTT_F16_F32
            | Mnemonic::VCVT_F32_S32_FIXED
            | Mnemonic::VCVT_F32_U32_FIXED
            | Mnemonic::VCVT_S32_F32_FIXED
            | Mnemonic::VCVT_U32_F32_FIXED
            | Mnemonic::VCVT_F64_S32_FIXED
            | Mnemonic::VCVT_F64_U32_FIXED
            | Mnemonic::VCVT_S32_F64_FIXED
            | Mnemonic::VCVT_U32_F64_FIXED
            | Mnemonic::VCVTA_S32_F32
            | Mnemonic::VCVTA_U32_F32
            | Mnemonic::VCVTA_S32_F16
            | Mnemonic::VCVTA_U32_F16
            | Mnemonic::VCVTA_S32_F64
            | Mnemonic::VCVTA_U32_F64
            | Mnemonic::VCVTM_S32_F32
            | Mnemonic::VCVTM_U32_F32
            | Mnemonic::VCVTM_S32_F16
            | Mnemonic::VCVTM_U32_F16
            | Mnemonic::VCVTM_S32_F64
            | Mnemonic::VCVTM_U32_F64
            | Mnemonic::VCVTN_S32_F32
            | Mnemonic::VCVTN_U32_F32
            | Mnemonic::VCVTN_S32_F16
            | Mnemonic::VCVTN_U32_F16
            | Mnemonic::VCVTN_S32_F64
            | Mnemonic::VCVTN_U32_F64
            | Mnemonic::VCVTP_S32_F16
            | Mnemonic::VCVTP_U32_F16
            | Mnemonic::VCVTP_S32_F32
            | Mnemonic::VCVTP_U32_F32
            | Mnemonic::VCVTP_S32_F64
            | Mnemonic::VCVTP_U32_F64
            | Mnemonic::VCVTR_S32_F16
            | Mnemonic::VCVTR_U32_F16
            | Mnemonic::VCVTR_S32_F32
            | Mnemonic::VCVTR_U32_F32
            | Mnemonic::VCVTR_S32_F64
            | Mnemonic::VCVTR_U32_F64 => self.exec_vcvt(insn),

            // Bit manipulation
            Mnemonic::CLZ => self.exec_clz(insn),
            Mnemonic::REV => self.exec_rev(insn),
            Mnemonic::REV16 => self.exec_rev16(insn),
            Mnemonic::REVSH => self.exec_revsh(insn),
            Mnemonic::RBIT => self.exec_rbit(insn),

            // Bit field
            Mnemonic::BFC => self.exec_bfc(insn),
            Mnemonic::BFI => self.exec_bfi(insn),
            Mnemonic::UBFX => self.exec_ubfx(insn),
            Mnemonic::SBFX => self.exec_sbfx(insn),

            // Extension
            Mnemonic::SXTB => self.exec_sxtb(insn),
            Mnemonic::SXTH => self.exec_sxth(insn),
            Mnemonic::UXTB => self.exec_uxtb(insn),
            Mnemonic::UXTH => self.exec_uxth(insn),

            // Saturating arithmetic
            Mnemonic::USAT => self.exec_usat(insn),
            Mnemonic::SSAT => self.exec_ssat(insn),

            // AArch32 media / DSP
            Mnemonic::A32_PARALLEL => self.exec_a32_parallel(insn),
            Mnemonic::A32_PKH => self.exec_a32_pkh(insn),
            Mnemonic::A32_EXTEND => self.exec_a32_extend(insn),
            Mnemonic::A32_SAT16 => self.exec_a32_sat16(insn),
            Mnemonic::A32_SAT_ADDSUB => self.exec_a32_sat_addsub(insn),
            Mnemonic::A32_HMUL => self.exec_a32_hmul(insn),
            Mnemonic::A32_DUAL => self.exec_a32_dual(insn),
            Mnemonic::A32_SMLALD => self.exec_a32_smlald(insn),
            Mnemonic::A32_SMMUL => self.exec_a32_smmul(insn),
            Mnemonic::A32_USAD => self.exec_a32_usad(insn),
            Mnemonic::A32_SEL => self.exec_a32_sel(insn),

            // Undefined/Unknown
            Mnemonic::UNDEFINED | Mnemonic::UNKNOWN => ExecResult::Undefined,

            // Not yet implemented
            _ => ExecResult::Undefined,
        }
    }

    // =========================================================================
    // Exception Handling
    // =========================================================================

    /// Take an exception and switch to the appropriate mode.
    pub fn take_exception(&mut self, exception: ExceptionType) {
        // Exception entry clears the local exclusive monitor. Without this,
        // a LDREX/STREX pair interrupted by IRQ/FIQ can incorrectly complete
        // against stale state after the handler has run.
        self.exclusive_monitor.clear();

        let target_mode = exception.target_mode();
        let vector_offset = exception.vector_offset();

        // Save CPSR to SPSR of target mode
        let cpsr_value = self.cpu.cpsr.to_u32();

        // Calculate return address based on exception type
        let return_addr = match &exception {
            ExceptionType::SupervisorCall(_) => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::UndefinedInstruction if self.cpu.cpsr.t => {
                self.cpu.regs[15].wrapping_add(2)
            }
            ExceptionType::UndefinedInstruction => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::PrefetchAbort(_) => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::DataAbort(_) => self.cpu.regs[15].wrapping_add(8),
            ExceptionType::Irq => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::Fiq => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::Breakpoint(_) => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::Reset => 0,
        };

        // Switch mode
        self.cpu.change_mode(target_mode);

        // Set SPSR
        if let Some(spsr) = self.cpu.get_current_spsr_mut() {
            *spsr = Psr::from_u32(cpsr_value);
        }

        // Set LR to return address
        self.cpu.regs[14] = return_addr;

        // Update CPSR
        self.cpu.cpsr.i = true; // Disable IRQ
        if matches!(exception, ExceptionType::Fiq | ExceptionType::Reset) {
            self.cpu.cpsr.f = true; // Disable FIQ
        }
        self.cpu.cpsr.t = false; // Enter ARM mode

        // Branch to vector
        self.cpu.regs[15] = self.vbar.wrapping_add(vector_offset);
    }

    /// Return from exception (MOVS PC, LR or SUBS PC, LR, #imm with S bit).
    pub fn exception_return(&mut self) {
        if let Some(spsr) = self.cpu.get_current_spsr() {
            let spsr_value = spsr.to_u32();

            if let Some(mode) = ProcessorMode::from_bits(spsr.mode) {
                // Bank-switch first: change_mode reads the OLD mode from
                // cpsr.mode to save the outgoing SP/LR, so the full CPSR
                // restore must happen after it.
                self.cpu.change_mode(mode);
                self.cpu.cpsr = Psr::from_u32(spsr_value);
            }
        }
    }

    /// Check if condition is passed.
    pub(crate) fn condition_passed(&self, cond: Condition) -> bool {
        condition_passed(
            cond as u8,
            self.cpu.cpsr.n,
            self.cpu.cpsr.z,
            self.cpu.cpsr.c,
            self.cpu.cpsr.v,
        )
    }

    /// Get register value with PC+8 handling.
    #[inline]
    pub(crate) fn reg(&self, r: usize) -> u32 {
        self.cpu.reg(r)
    }

    pub(crate) fn a32_s_bit(insn: &DecodedInsn) -> bool {
        Self::is_a32_state(insn.state) && (insn.raw >> 22) & 1 == 1
    }

    pub(crate) fn exec_rsc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self
            .cpu
            .add_with_carry(!self.reg(n), operand2, self.cpu.cpsr.c);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    pub(crate) fn exec_neg(&mut self, insn: &DecodedInsn) -> ExecResult {
        // NEG Rd, Rm is RSB Rd, Rm, #0
        let (d, m) = if insn.state.is_thumb() {
            let (r, _) = Self::thumb_reg_ops(insn, 2);
            (r[0], r[1])
        } else {
            (((insn.raw >> 12) & 0xF) as usize, (insn.raw & 0xF) as usize)
        };
        let result = self.cpu.add_with_carry(!self.reg(m), 0, true);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_orn(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) | !operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_cmn(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (_, n, operand2) = self.decode_dp_operands(insn);
        let result = self.cpu.add_with_carry(self.reg(n), operand2, false);
        self.set_flags_arithmetic(result);
        ExecResult::Continue
    }

    // =========================================================================
    // Branch Operations
    // =========================================================================

    pub(crate) fn exec_b(&mut self, insn: &DecodedInsn) -> ExecResult {
        if let Some(target) = self.decode_branch_target(insn) {
            ExecResult::Branch(target)
        } else {
            ExecResult::Undefined
        }
    }

    /// SRS: store return state (LR and SPSR of the current mode) to the
    /// stack of the mode given in the instruction.
    pub(crate) fn exec_srs(&mut self, insn: &DecodedInsn) -> ExecResult {
        if self.cpu.is_user_or_system() {
            return ExecResult::Undefined;
        }
        let raw = insn.raw;
        let p = (raw >> 24) & 1 == 1;
        let u = (raw >> 23) & 1 == 1;
        let w = (raw >> 21) & 1 == 1;
        let mode_bits = (raw & 0x1F) as u8;
        let cur_mode = self.cpu.cpsr.mode;
        let sp = self.banked_sp(mode_bits);
        let low = match (p, u) {
            (false, true) => sp,                  // IA
            (true, true) => sp.wrapping_add(4),   // IB
            (false, false) => sp.wrapping_sub(4), // DA
            (true, false) => sp.wrapping_sub(8),  // DB
        };
        let lr = self.cpu.regs[14];
        let spsr = self.current_spsr_bits();
        if let Err(e) = self.mem.write_word(low, lr) {
            return ExecResult::MemoryFault(e);
        }
        if let Err(e) = self.mem.write_word(low.wrapping_add(4), spsr) {
            return ExecResult::MemoryFault(e);
        }
        if w {
            let nb = if u {
                sp.wrapping_add(8)
            } else {
                sp.wrapping_sub(8)
            };
            self.set_banked_sp(mode_bits, nb);
        }
        let _ = cur_mode;
        ExecResult::Continue
    }

    /// RFE: return from exception — load PC and CPSR from [Rn].
    pub(crate) fn exec_rfe(&mut self, insn: &DecodedInsn) -> ExecResult {
        if self.cpu.is_user_or_system() {
            return ExecResult::Undefined;
        }
        let raw = insn.raw;
        let p = (raw >> 24) & 1 == 1;
        let u = (raw >> 23) & 1 == 1;
        let w = (raw >> 21) & 1 == 1;
        let n = ((raw >> 16) & 0xF) as usize;
        let base = self.cpu.regs[n];
        let low = match (p, u) {
            (false, true) => base,
            (true, true) => base.wrapping_add(4),
            (false, false) => base.wrapping_sub(4),
            (true, false) => base.wrapping_sub(8),
        };
        let new_pc = match self.mem.read_word(low) {
            Ok(v) => v,
            Err(e) => return ExecResult::MemoryFault(e),
        };
        let new_cpsr = match self.mem.read_word(low.wrapping_add(4)) {
            Ok(v) => v,
            Err(e) => return ExecResult::MemoryFault(e),
        };
        if w {
            let nb = if u {
                base.wrapping_add(8)
            } else {
                base.wrapping_sub(8)
            };
            self.cpu.regs[n] = nb;
        }
        self.write_cpsr_all(new_cpsr);
        ExecResult::Branch(new_pc)
    }

    /// SP of an arbitrary mode (live register if it is the current mode).
    pub(crate) fn banked_sp(&self, mode_bits: u8) -> u32 {
        if mode_bits == self.cpu.cpsr.mode {
            return self.cpu.regs[13];
        }
        match ProcessorMode::from_bits(mode_bits) {
            Some(ProcessorMode::User) | Some(ProcessorMode::System) => self.cpu.regs_usr[0],
            Some(ProcessorMode::Fiq) => self.cpu.regs_fiq[5],
            Some(ProcessorMode::Irq) => self.cpu.regs_irq[0],
            Some(ProcessorMode::Supervisor) => self.cpu.regs_svc[0],
            Some(ProcessorMode::Monitor) => self.cpu.regs_mon[0],
            Some(ProcessorMode::Abort) => self.cpu.regs_abt[0],
            Some(ProcessorMode::Undefined) => self.cpu.regs_und[0],
            _ => self.cpu.regs[13],
        }
    }

    pub(crate) fn exec_mcr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let cp = ((insn.raw >> 8) & 0xF) as u8;
        let opc1 = ((insn.raw >> 21) & 7) as u8;
        let reg = ((insn.raw >> 16) & 0xF) as u8;

        if cp == 10 && opc1 == 0b111 {
            if t == 15 || (reg != 1 && !self.cpu.is_privileged()) {
                return ExecResult::Undefined;
            }
            let value = self.reg(t);
            return match reg {
                0 => ExecResult::Continue,
                1 => {
                    if !self.cpu.vfp.is_enabled() {
                        ExecResult::Exception(ExceptionType::UndefinedInstruction)
                    } else {
                        self.cpu.vfp.fpscr = Fpscr::from_bits(value);
                        ExecResult::Continue
                    }
                }
                8 => {
                    self.cpu.vfp.fpexc = value;
                    ExecResult::Continue
                }
                _ => ExecResult::Undefined,
            };
        }

        if cp == 15 {
            let crm = (insn.raw & 0xF) as u8;
            let opc2 = ((insn.raw >> 5) & 0x7) as u8;
            if !self.cpu.is_privileged() && !self.pl0_cp15(insn, false, reg, opc1, crm, opc2) {
                return ExecResult::Undefined;
            }
            let value = self.reg(t);
            // WFI (MCR p15, 0, Rt, c7, c0, 4): ARMv6 wait-for-interrupt.
            if opc1 == 0 && reg == 7 && crm == 0 && opc2 == 4 {
                self.cpu.is_halted = true;
                return ExecResult::Halt;
            }
            let enc = crate::isa::arm::common::sysreg::Cp15Encoding::new(reg, opc1, crm, opc2);
            // Cache/TLB maintenance (CRn 7/8) and unmodelled registers are
            // accepted as no-ops; everything modelled lands in Cp15State.
            let _ = self.cpu.cp15.write(enc, value);
            return ExecResult::Continue;
        }

        if !self.cpu.is_privileged() {
            return ExecResult::Undefined;
        }
        // For now, just consume the value (would write to coprocessor)
        let _value = self.reg(t);

        ExecResult::Continue
    }

    pub(crate) fn exec_mrc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let cp = ((insn.raw >> 8) & 0xF) as u8;
        let opc1 = ((insn.raw >> 21) & 7) as u8;
        let reg = ((insn.raw >> 16) & 0xF) as u8;

        if cp == 10 && opc1 == 0b111 {
            if t == 15 && reg != 1 {
                return ExecResult::Undefined;
            }
            // Only FPSCR is accessible at PL0 (VMRS: "Non-FPSCR registers
            // accessible only at PL1 or above").
            if reg != 1 && !self.cpu.is_privileged() {
                return ExecResult::Undefined;
            }
            let value = match reg {
                0 => self.cpu.vfp.fpsid,
                1 => {
                    if !self.cpu.vfp.is_enabled() {
                        return ExecResult::Exception(ExceptionType::UndefinedInstruction);
                    }
                    self.cpu.vfp.fpscr.bits()
                }
                5 => self.cpu.vfp.mvfr2,
                6 => self.cpu.vfp.mvfr1,
                7 => self.cpu.vfp.mvfr0,
                8 => self.cpu.vfp.fpexc,
                _ => return ExecResult::Undefined,
            };
            if t == 15 && reg == 1 {
                self.cpu.cpsr.n = (value & (1 << 31)) != 0;
                self.cpu.cpsr.z = (value & (1 << 30)) != 0;
                self.cpu.cpsr.c = (value & (1 << 29)) != 0;
                self.cpu.cpsr.v = (value & (1 << 28)) != 0;
            } else if t != 15 {
                self.cpu.regs[t] = value;
            }
            return ExecResult::Continue;
        }

        if cp == 15 {
            let crm = (insn.raw & 0xF) as u8;
            let opc2 = ((insn.raw >> 5) & 0x7) as u8;
            if !self.cpu.is_privileged() && !self.pl0_cp15(insn, true, reg, opc1, crm, opc2) {
                return ExecResult::Undefined;
            }
            let enc = crate::isa::arm::common::sysreg::Cp15Encoding::new(reg, opc1, crm, opc2);
            let value = self.cpu.cp15.read(enc).unwrap_or(0);
            if t != 15 {
                self.cpu.regs[t] = value;
            } else {
                // MRC with Rt=15 moves bits[31:28] into the CPSR flags.
                self.cpu.cpsr.n = (value & (1 << 31)) != 0;
                self.cpu.cpsr.z = (value & (1 << 30)) != 0;
                self.cpu.cpsr.c = (value & (1 << 29)) != 0;
                self.cpu.cpsr.v = (value & (1 << 28)) != 0;
            }
            return ExecResult::Continue;
        }

        if !self.cpu.is_privileged() {
            return ExecResult::Undefined;
        }
        // For now, return 0 (would read from coprocessor)
        if t != 15 {
            self.cpu.regs[t] = 0;
        }

        ExecResult::Continue
    }

    /// Whether PL0 may make a CP15 transfer: reading TPIDRURW and
    /// TPIDRURO, writing TPIDRURW, and the CP15DMB/CP15DSB/CP15ISB
    /// barriers when SCTLR.CP15BEN is set. The MCR2/MRC2 forms (bits
    /// 31:28 = 0b1111 in both A32 and T32) are none of them.
    fn pl0_cp15(
        &self,
        insn: &DecodedInsn,
        read: bool,
        crn: u8,
        opc1: u8,
        crm: u8,
        opc2: u8,
    ) -> bool {
        if insn.raw >> 28 == 0xF || opc1 != 0 {
            return false;
        }
        match (crn, crm, opc2) {
            (13, 0, 2) => true,
            (13, 0, 3) => read,
            (7, 10, 4) | (7, 10, 5) | (7, 5, 4) => !read && self.cpu.cp15.sctlr.cp15ben(),
            _ => false,
        }
    }

    pub(crate) fn vrint_rounding(&self, mnemonic: Mnemonic) -> Option<(RoundingMode, bool)> {
        match mnemonic {
            Mnemonic::VRINTA_F16 | Mnemonic::VRINTA_F32 | Mnemonic::VRINTA_F64 => {
                Some((RoundingMode::RoundTiesAway, false))
            }
            Mnemonic::VRINTN_F16 | Mnemonic::VRINTN_F32 | Mnemonic::VRINTN_F64 => {
                Some((RoundingMode::RoundNearest, false))
            }
            Mnemonic::VRINTP_F16 | Mnemonic::VRINTP_F32 | Mnemonic::VRINTP_F64 => {
                Some((RoundingMode::RoundPlusInf, false))
            }
            Mnemonic::VRINTM_F16 | Mnemonic::VRINTM_F32 | Mnemonic::VRINTM_F64 => {
                Some((RoundingMode::RoundMinusInf, false))
            }
            Mnemonic::VRINTZ_F16 | Mnemonic::VRINTZ_F32 | Mnemonic::VRINTZ_F64 => {
                Some((RoundingMode::RoundZero, false))
            }
            Mnemonic::VRINTR_F16 | Mnemonic::VRINTR_F32 | Mnemonic::VRINTR_F64 => {
                Some((self.cpu.vfp.fpscr.rmode(), false))
            }
            Mnemonic::VRINTX_F16 | Mnemonic::VRINTX_F32 | Mnemonic::VRINTX_F64 => {
                Some((self.cpu.vfp.fpscr.rmode(), true))
            }
            _ => None,
        }
    }

    // =========================================================================
    // Bit Field Operations
    // =========================================================================

    pub(crate) fn bitfield_low_mask(width: u32) -> Option<u32> {
        match width {
            0 => None,
            1..=31 => Some((1u32 << width) - 1),
            32 => Some(u32::MAX),
            _ => None,
        }
    }

    pub(crate) fn bitfield_range_valid(lsb: u32, width: u32) -> bool {
        lsb < 32 && width != 0 && lsb.checked_add(width).is_some_and(|end| end <= 32)
    }

    /// Bitfield instruction fields (Rd, Rn, lsb, five) where `five` is the
    /// width-minus-1 (SBFX/UBFX) or msb (BFI/BFC) field. Handles A32 and T32.
    pub(crate) fn bitfield_fields(&self, insn: &DecodedInsn) -> (usize, usize, u32, u32) {
        let raw = insn.raw;
        if insn.state.is_thumb() {
            let d = ((raw >> 8) & 0xF) as usize;
            let n = ((raw >> 16) & 0xF) as usize;
            let lsb = (((raw >> 12) & 0x7) << 2) | ((raw >> 6) & 0x3);
            (d, n, lsb, raw & 0x1F)
        } else {
            let d = ((raw >> 12) & 0xF) as usize;
            let n = (raw & 0xF) as usize;
            (d, n, (raw >> 7) & 0x1F, (raw >> 16) & 0x1F)
        }
    }

    // =========================================================================
    // Saturating Arithmetic
    // =========================================================================

    /// Saturate instruction fields: (Rd, Rn, sat_imm5, sh, imm5). A32/T32.
    pub(crate) fn sat_fields(&self, insn: &DecodedInsn) -> (usize, usize, u32, bool, u32) {
        let raw = insn.raw;
        if insn.state.is_thumb() {
            let d = ((raw >> 8) & 0xF) as usize;
            let n = ((raw >> 16) & 0xF) as usize;
            let imm5 = (((raw >> 12) & 0x7) << 2) | ((raw >> 6) & 0x3);
            (d, n, raw & 0x1F, (raw >> 21) & 1 != 0, imm5)
        } else {
            let d = ((raw >> 12) & 0xF) as usize;
            let n = (raw & 0xF) as usize;
            (
                d,
                n,
                (raw >> 16) & 0x1F,
                (raw >> 6) & 1 != 0,
                (raw >> 7) & 0x1F,
            )
        }
    }

    /// Signed-saturate a value to 32 bits, setting the Q flag on saturation.
    pub(crate) fn ssat32(&mut self, x: i64) -> u32 {
        if x > i32::MAX as i64 {
            self.cpu.cpsr.q = true;
            i32::MAX as u32
        } else if x < i32::MIN as i64 {
            self.cpu.cpsr.q = true;
            i32::MIN as u32
        } else {
            x as u32
        }
    }

    /// SMUL/SMLA/SMULW/SMLAW/SMLAL <x><y> (halfword and word multiplies).
    pub(crate) fn exec_a32_hmul(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (rd, ra, rm, rn) = self.dsp4_regs(insn);
        let rn_v = self.reg(rn);
        let rm_v = self.reg(rm);
        let half = |v: u32, top: bool| -> i64 {
            if top {
                (v >> 16) as u16 as i16 as i64
            } else {
                v as u16 as i16 as i64
            }
        };
        // Normalized kind: 0=SMLA 1=SMLAW 2=SMULW 3=SMLAL 4=SMUL.
        let (kind, n_top, m_top) = if insn.state.is_thumb() {
            let op1 = (raw >> 20) & 0x7; // hw1[6:4]
            let nt = (raw >> 5) & 1 != 0;
            let mt = (raw >> 4) & 1 != 0;
            if op1 == 0b001 {
                (if ra == 15 { 4 } else { 0 }, nt, mt) // SMUL / SMLA
            } else {
                (if ra == 15 { 2 } else { 1 }, false, mt) // SMULW / SMLAW
            }
        } else {
            let nt = (raw >> 5) & 1 != 0;
            let mt = (raw >> 6) & 1 != 0;
            match (raw >> 21) & 0x3 {
                0b00 => (0, nt, mt),
                0b01 => (if (raw >> 5) & 1 != 0 { 2 } else { 1 }, false, mt),
                0b10 => (3, nt, mt),
                _ => (4, nt, mt),
            }
        };
        match kind {
            0 => {
                // SMLA<x><y>: Rd = Rn.x * Rm.y + Ra (Q on signed overflow)
                let result = half(rn_v, n_top) * half(rm_v, m_top) + self.reg(ra) as i32 as i64;
                let r32 = result as i32;
                if result != r32 as i64 {
                    self.cpu.cpsr.q = true;
                }
                self.set_reg(rd, r32 as u32)
            }
            1 => {
                // SMLAW<y>: Rd = (Rn * Rm.y)[47:16] + Ra (Q on overflow)
                let prod = (rn_v as i32 as i64) * half(rm_v, m_top);
                let result = (prod >> 16) + self.reg(ra) as i32 as i64;
                let r32 = result as i32;
                if result != r32 as i64 {
                    self.cpu.cpsr.q = true;
                }
                self.set_reg(rd, r32 as u32)
            }
            2 => {
                // SMULW<y>: Rd = (Rn * Rm.y)[47:16]
                let prod = (rn_v as i32 as i64) * half(rm_v, m_top);
                self.set_reg(rd, (prod >> 16) as i32 as u32)
            }
            3 => {
                // SMLAL<x><y>: RdHi:RdLo += Rn.x * Rm.y (RdHi=rd, RdLo=ra)
                let acc = (((self.cpu.regs[rd] as u64) << 32) | self.cpu.regs[ra] as u64) as i64;
                let result = acc.wrapping_add(half(rn_v, n_top) * half(rm_v, m_top)) as u64;
                self.cpu.regs[ra] = result as u32;
                self.cpu.regs[rd] = (result >> 32) as u32;
                ExecResult::Continue
            }
            _ => {
                // SMUL<x><y>: Rd = Rn.x * Rm.y
                self.set_reg(rd, (half(rn_v, n_top) * half(rm_v, m_top)) as i32 as u32)
            }
        }
    }

    /// SMUAD / SMUSD / SMLAD / SMLSD.
    pub(crate) fn exec_a32_dual(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (rd, ra, rm, rn) = self.dsp4_regs(insn);
        // X (swap Rm halves) and sub flags differ by encoding.
        let (swap, sub) = if insn.state.is_thumb() {
            ((raw >> 4) & 1 != 0, (raw >> 20) & 0x7 == 0b100)
        } else {
            ((raw >> 5) & 1 != 0, (raw >> 6) & 1 != 0)
        };
        let rn_v = self.reg(rn);
        let mut rm_v = self.reg(rm);
        if swap {
            rm_v = rm_v.rotate_right(16);
        }
        let p1 = (rn_v as u16 as i16 as i64) * (rm_v as u16 as i16 as i64);
        let p2 = ((rn_v >> 16) as u16 as i16 as i64) * ((rm_v >> 16) as u16 as i16 as i64);
        let mut result = if sub { p1 - p2 } else { p1 + p2 };
        if ra != 15 {
            result += self.reg(ra) as i32 as i64;
        }
        let r32 = result as i32;
        if result != r32 as i64 {
            self.cpu.cpsr.q = true;
        }
        self.set_reg(rd, r32 as u32)
    }

    /// SMMUL / SMMLA / SMMLS (signed most-significant-word multiply).
    pub(crate) fn exec_a32_smmul(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (rd, ra, rm, rn) = self.dsp4_regs(insn);
        let (round, sub) = if insn.state.is_thumb() {
            ((raw >> 4) & 1 != 0, (raw >> 20) & 0x7 == 0b110)
        } else {
            ((raw >> 5) & 1 != 0, (raw >> 6) & 1 != 0)
        };
        let prod = (self.reg(rn) as i32 as i64) * (self.reg(rm) as i32 as i64);
        let acc = if ra == 15 {
            0i64
        } else {
            (self.reg(ra) as i32 as i64) << 32
        };
        let mut result = if sub { acc - prod } else { acc + prod };
        if round {
            result += 0x8000_0000; // rounding
        }
        self.set_reg(rd, (result >> 32) as u32)
    }

    /// USAD8 / USADA8 (sum of absolute differences).
    pub(crate) fn exec_a32_usad(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (rd, ra, rm, rn) = self.dsp4_regs(insn);
        let n = self.reg(rn);
        let m = self.reg(rm);
        let mut sum: u32 = 0;
        for i in 0..4 {
            let a = ((n >> (i * 8)) & 0xFF) as i32;
            let b = ((m >> (i * 8)) & 0xFF) as i32;
            sum = sum.wrapping_add((a - b).unsigned_abs());
        }
        if ra != 15 {
            sum = sum.wrapping_add(self.reg(ra));
        }
        self.set_reg(rd, sum)
    }

    /// PKHBT / PKHTB (pack halfword).
    pub(crate) fn exec_a32_pkh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (rd, rn, rm) = self.media_regs(insn);
        let (tbform, imm5) = if insn.state.is_thumb() {
            (
                (raw >> 5) & 1 != 0,
                (((raw >> 12) & 0x7) << 2) | ((raw >> 6) & 0x3),
            )
        } else {
            ((raw >> 6) & 1 != 0, (raw >> 7) & 0x1F)
        };
        let n = self.reg(rn);
        let m = self.reg(rm);
        let result = if tbform {
            // PKHTB: top from Rn, bottom from (Rm ASR imm5; imm5==0 => 32)
            let op2 = if imm5 == 0 {
                ((m as i32) >> 31) as u32
            } else {
                ((m as i32) >> imm5) as u32
            };
            (n & 0xFFFF_0000) | (op2 & 0xFFFF)
        } else {
            // PKHBT: bottom from Rn, top from (Rm LSL imm5)
            let op2 = m.wrapping_shl(imm5);
            (op2 & 0xFFFF_0000) | (n & 0xFFFF)
        };
        self.set_reg(rd, result)
    }

    /// (U|S)XT(A)(B|H|B16) sign/zero extend, with optional add and rotate.
    pub(crate) fn exec_a32_extend(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (rd, rn, rm) = self.media_regs(insn);
        // size: 00=B16, 10=B, 11=H ; unsigned ; rotation.
        let (unsigned, size, rotation) = if insn.state.is_thumb() {
            let ty = (raw >> 20) & 0x7; // hw1[6:4]: 0SXTH 1UXTH 2SXTB16 3UXTB16 4SXTB 5UXTB
            let size = match ty >> 1 {
                0 => 0b11, // H
                1 => 0b00, // B16
                _ => 0b10, // B
            };
            (ty & 1 != 0, size, ((raw >> 4) & 0x3) * 8)
        } else {
            (
                (raw >> 22) & 1 != 0,
                (raw >> 20) & 0x3,
                ((raw >> 10) & 0x3) * 8,
            )
        };
        let rotated = self.reg(rm).rotate_right(rotation);
        let add = rn != 15;
        let n = self.reg(rn);
        let extb = |b: u32, u: bool| -> u32 {
            if u {
                b & 0xFF
            } else {
                (b & 0xFF) as u8 as i8 as i32 as u32
            }
        };
        let result = match size {
            0b10 => {
                let ext = extb(rotated, unsigned);
                if add { n.wrapping_add(ext) } else { ext }
            }
            0b11 => {
                let h = rotated & 0xFFFF;
                let ext = if unsigned {
                    h
                } else {
                    h as u16 as i16 as i32 as u32
                };
                if add { n.wrapping_add(ext) } else { ext }
            }
            _ => {
                let lo = extb(rotated, unsigned) & 0xFFFF;
                let hi = extb(rotated >> 16, unsigned) & 0xFFFF;
                if add {
                    let l = (n & 0xFFFF).wrapping_add(lo) & 0xFFFF;
                    let h = ((n >> 16) & 0xFFFF).wrapping_add(hi) & 0xFFFF;
                    l | (h << 16)
                } else {
                    lo | (hi << 16)
                }
            }
        };
        self.set_reg(rd, result)
    }

    /// SSAT16 / USAT16 (parallel halfword saturate).
    pub(crate) fn exec_a32_sat16(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (rd, rn, sat, unsigned) = if insn.state.is_thumb() {
            (
                ((raw >> 8) & 0xF) as usize,
                ((raw >> 16) & 0xF) as usize,
                raw & 0xF,
                (raw >> 23) & 1 != 0,
            )
        } else {
            (
                ((raw >> 12) & 0xF) as usize,
                (raw & 0xF) as usize,
                (raw >> 16) & 0xF,
                (raw >> 22) & 1 != 0,
            )
        };
        let n = self.reg(rn);
        let mut out: u32 = 0;
        for i in 0..2u32 {
            let h = ((n >> (i * 16)) & 0xFFFF) as u16 as i16 as i32;
            let clamped = if unsigned {
                let max = ((1u32 << sat) - 1) as i32;
                if h < 0 {
                    self.cpu.cpsr.q = true;
                    0
                } else if h > max {
                    self.cpu.cpsr.q = true;
                    max
                } else {
                    h
                }
            } else {
                let bits = sat + 1;
                let max = (1i32 << (bits - 1)) - 1;
                let min = -(1i32 << (bits - 1));
                if h > max {
                    self.cpu.cpsr.q = true;
                    max
                } else if h < min {
                    self.cpu.cpsr.q = true;
                    min
                } else {
                    h
                }
            };
            out |= ((clamped as u32) & 0xFFFF) << (i * 16);
        }
        self.set_reg(rd, out)
    }

    /// Signed/unsigned parallel add/sub (SADD8/QADD16/UHASX/...). Sets GE for
    /// the plain signed (S) and unsigned (U) prefixes.
    pub(crate) fn exec_a32_parallel(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (rd, rn, rm) = self.media_regs(insn);
        // Normalize to the A32 codes: prefix 001=S 010=Q 011=SH 101=U 110=UQ
        // 111=UH ; op2 000=add16 001=asx 010=sax 011=sub16 100=add8 111=sub8.
        let (prefix, op2) = if insn.state.is_thumb() {
            let prefix = match (raw >> 4) & 0x7 {
                // hw2[6:4]: 0=S 1=Q 2=SH 4=U 5=UQ 6=UH
                0 => 0b001,
                1 => 0b010,
                2 => 0b011,
                4 => 0b101,
                5 => 0b110,
                _ => 0b111,
            };
            let op2 = match (raw >> 20) & 0x7 {
                // hw1[6:4]: 0=add8 1=add16 2=asx 4=sub8 5=sub16 6=sax
                0 => 0b100,
                1 => 0b000,
                2 => 0b001,
                4 => 0b111,
                5 => 0b011,
                _ => 0b010,
            };
            (prefix, op2)
        } else {
            ((raw >> 20) & 0x7, (raw >> 5) & 0x7)
        };
        let n = self.reg(rn);
        let m = self.reg(rm);

        let eight = op2 == 0b100 || op2 == 0b111;
        let width: u32 = if eight { 8 } else { 16 };
        let lane = |v: u32, idx: u32, w: u32| (v >> (idx * w)) & ((1u32 << w) - 1);

        // (a, b, sub) per lane.
        let mut lanes: [(u32, u32, bool); 4] = [(0, 0, false); 4];
        let nlanes: usize = match op2 {
            0b000 => {
                for i in 0..2 {
                    lanes[i] = (lane(n, i as u32, 16), lane(m, i as u32, 16), false);
                }
                2
            }
            0b011 => {
                for i in 0..2 {
                    lanes[i] = (lane(n, i as u32, 16), lane(m, i as u32, 16), true);
                }
                2
            }
            0b001 => {
                // ASX: lane0 = n.lo - m.hi ; lane1 = n.hi + m.lo
                lanes[0] = (lane(n, 0, 16), lane(m, 1, 16), true);
                lanes[1] = (lane(n, 1, 16), lane(m, 0, 16), false);
                2
            }
            0b010 => {
                // SAX: lane0 = n.lo + m.hi ; lane1 = n.hi - m.lo
                lanes[0] = (lane(n, 0, 16), lane(m, 1, 16), false);
                lanes[1] = (lane(n, 1, 16), lane(m, 0, 16), true);
                2
            }
            0b100 => {
                for i in 0..4 {
                    lanes[i] = (lane(n, i as u32, 8), lane(m, i as u32, 8), false);
                }
                4
            }
            0b111 => {
                for i in 0..4 {
                    lanes[i] = (lane(n, i as u32, 8), lane(m, i as u32, 8), true);
                }
                4
            }
            _ => return ExecResult::Undefined,
        };

        let sign_ext = |v: u32, w: u32| -> i64 {
            let sh = 64 - w;
            ((v as i64) << sh) >> sh
        };
        let maskw: u32 = if width == 32 {
            u32::MAX
        } else {
            (1u32 << width) - 1
        };
        let smax = (1i64 << (width - 1)) - 1;
        let smin = -(1i64 << (width - 1));
        let umax = (1i64 << width) - 1;

        let mut result: u32 = 0;
        let mut ge: u8 = 0;
        let mut set_ge = false;
        for (idx, &(a, b, sub)) in lanes.iter().take(nlanes).enumerate() {
            let avs = sign_ext(a, width);
            let bvs = sign_ext(b, width);
            let avu = a as i64;
            let bvu = b as i64;
            let (val, ge_opt): (u32, Option<bool>) = match prefix {
                0b001 => {
                    let r = if sub { avs - bvs } else { avs + bvs };
                    (r as u32, Some(r >= 0))
                }
                0b101 => {
                    if sub {
                        ((avu - bvu) as u32, Some(avu >= bvu))
                    } else {
                        let r = avu + bvu;
                        (r as u32, Some(r >= (1i64 << width)))
                    }
                }
                0b010 => {
                    let r = if sub { avs - bvs } else { avs + bvs };
                    (r.clamp(smin, smax) as u32, None)
                }
                0b110 => {
                    let r = if sub { avu - bvu } else { avu + bvu };
                    (r.clamp(0, umax) as u32, None)
                }
                0b011 => {
                    let r = if sub { avs - bvs } else { avs + bvs };
                    ((r >> 1) as u32, None)
                }
                0b111 => {
                    let r = if sub { avu - bvu } else { avu + bvu };
                    ((r >> 1) as u32, None)
                }
                _ => return ExecResult::Undefined,
            };
            result |= (val & maskw) << (idx as u32 * width);
            if let Some(g) = ge_opt {
                set_ge = true;
                if g {
                    if eight {
                        ge |= 1 << idx;
                    } else {
                        ge |= 0b11 << (idx * 2);
                    }
                }
            }
        }

        if set_ge {
            self.cpu.cpsr.ge = ge;
        }
        self.set_reg(rd, result)
    }

    // =========================================================================
    // Operand Decoding Helpers
    // =========================================================================

    /// Collect up to `max` GPR numbers from the decoded operand list, in order.
    pub(crate) fn thumb_reg_ops(insn: &DecodedInsn, max: usize) -> ([usize; 4], usize) {
        use crate::isa::arm::decoder::Operand;
        let mut regs = [0usize; 4];
        let mut cnt = 0;
        for o in &insn.operands {
            if let Operand::Reg(r) = o {
                if cnt < max && cnt < 4 {
                    regs[cnt] = r.num as usize;
                    cnt += 1;
                }
            }
        }
        (regs, cnt)
    }

    /// (Rd, Rm) for two-register ops: from operands in Thumb, from raw in A32.
    pub(crate) fn dm_ops(&self, insn: &DecodedInsn) -> (usize, usize) {
        if insn.state.is_thumb() {
            let (r, _) = Self::thumb_reg_ops(insn, 2);
            (r[0], r[1])
        } else {
            (((insn.raw >> 12) & 0xF) as usize, (insn.raw & 0xF) as usize)
        }
    }

    /// Carry-out of a Thumb data-processing immediate (ThumbExpandImm_C). The
    /// rotated forms produce carry = result[31]; plain forms leave C unchanged.
    pub(crate) fn thumb_imm_carry(&self, insn: &DecodedInsn, value: u32) -> bool {
        if insn.state == crate::isa::arm::ExecutionState::Thumb2 {
            let raw = insn.raw;
            let imm12 = (((raw >> 26) & 1) << 11) | (((raw >> 12) & 0x7) << 8) | (raw & 0xFF);
            if (imm12 >> 8) >= 4 {
                return (value >> 31) & 1 != 0;
            }
        }
        self.cpu.cpsr.c
    }
}
