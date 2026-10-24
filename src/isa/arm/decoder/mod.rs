//! ARM instruction decoder for AArch64, AArch32, and Thumb/Thumb-2.
//!
//! This module provides comprehensive instruction decoding for all ARM execution states.
//! The decoder parses raw instruction bytes into structured representations that can be
//! used for disassembly, emulation, or analysis.
//!
//! # Supported Instruction Sets
//!
//! - **AArch64 (A64)**: 64-bit ARM instructions, all 32 bits wide
//! - **AArch32 (A32)**: 32-bit ARM instructions
//! - **Thumb (T16)**: 16-bit compact instructions
//! - **Thumb-2 (T32)**: Mixed 16/32-bit instructions
//!
//! # Usage
//!
//! ```ignore
//! use rax::isa::arm::decoder::{Decoder, DecodedInsn};
//!
//! let decoder = Decoder::new_aarch64();
//! let insn = decoder.decode(&[0x20, 0x00, 0x80, 0xd2]); // mov x0, #1
//! ```

pub mod aarch32;
pub mod aarch64;
mod aarch64_simd;
mod aarch64_simd_resize;
mod aarch64_simd_saturating;
mod aarch64_simd_scalar;
pub mod operand;
pub mod thumb;

use crate::isa::arm::ExecutionState;

pub use aarch32::Aarch32Decoder;
pub use aarch64::Aarch64Decoder;
pub use operand::*;
pub use thumb::ThumbDecoder;

/// Condition codes for conditional execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Condition {
    /// Equal (Z == 1)
    EQ = 0b0000,
    /// Not equal (Z == 0)
    NE = 0b0001,
    /// Carry set / unsigned higher or same (C == 1)
    CS = 0b0010,
    /// Carry clear / unsigned lower (C == 0)
    CC = 0b0011,
    /// Minus / negative (N == 1)
    MI = 0b0100,
    /// Plus / positive or zero (N == 0)
    PL = 0b0101,
    /// Overflow (V == 1)
    VS = 0b0110,
    /// No overflow (V == 0)
    VC = 0b0111,
    /// Unsigned higher (C == 1 && Z == 0)
    HI = 0b1000,
    /// Unsigned lower or same (C == 0 || Z == 1)
    LS = 0b1001,
    /// Signed greater than or equal (N == V)
    GE = 0b1010,
    /// Signed less than (N != V)
    LT = 0b1011,
    /// Signed greater than (Z == 0 && N == V)
    GT = 0b1100,
    /// Signed less than or equal (Z == 1 || N != V)
    LE = 0b1101,
    /// Always (unconditional)
    AL = 0b1110,
    /// Never / unconditional (ARMv5+: also means AL in some encodings)
    NV = 0b1111,
}

impl Condition {
    /// Decode condition from 4-bit value.
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0xF {
            0b0000 => Condition::EQ,
            0b0001 => Condition::NE,
            0b0010 => Condition::CS,
            0b0011 => Condition::CC,
            0b0100 => Condition::MI,
            0b0101 => Condition::PL,
            0b0110 => Condition::VS,
            0b0111 => Condition::VC,
            0b1000 => Condition::HI,
            0b1001 => Condition::LS,
            0b1010 => Condition::GE,
            0b1011 => Condition::LT,
            0b1100 => Condition::GT,
            0b1101 => Condition::LE,
            0b1110 => Condition::AL,
            0b1111 => Condition::NV,
            _ => unreachable!(),
        }
    }

    /// Get the inverted condition.
    pub fn invert(self) -> Self {
        Self::from_bits(self as u8 ^ 1)
    }

    /// Get the mnemonic suffix for this condition.
    pub fn suffix(self) -> &'static str {
        match self {
            Condition::EQ => "eq",
            Condition::NE => "ne",
            Condition::CS => "cs",
            Condition::CC => "cc",
            Condition::MI => "mi",
            Condition::PL => "pl",
            Condition::VS => "vs",
            Condition::VC => "vc",
            Condition::HI => "hi",
            Condition::LS => "ls",
            Condition::GE => "ge",
            Condition::LT => "lt",
            Condition::GT => "gt",
            Condition::LE => "le",
            Condition::AL => "",
            Condition::NV => "",
        }
    }
}

/// Shift type for register operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShiftType {
    /// Logical shift left
    LSL,
    /// Logical shift right
    LSR,
    /// Arithmetic shift right
    ASR,
    /// Rotate right
    ROR,
    /// Rotate right with extend (33-bit rotate through carry)
    RRX,
}

impl ShiftType {
    /// Decode shift type from 2-bit encoding.
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x3 {
            0b00 => ShiftType::LSL,
            0b01 => ShiftType::LSR,
            0b10 => ShiftType::ASR,
            0b11 => ShiftType::ROR,
            _ => unreachable!(),
        }
    }

    /// Get the mnemonic for this shift type.
    pub fn mnemonic(self) -> &'static str {
        match self {
            ShiftType::LSL => "lsl",
            ShiftType::LSR => "lsr",
            ShiftType::ASR => "asr",
            ShiftType::ROR => "ror",
            ShiftType::RRX => "rrx",
        }
    }
}

/// Extend type for register operands (AArch64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtendType {
    /// Unsigned byte extend
    UXTB,
    /// Unsigned halfword extend
    UXTH,
    /// Unsigned word extend
    UXTW,
    /// Unsigned doubleword extend (also LSL for 64-bit)
    UXTX,
    /// Signed byte extend
    SXTB,
    /// Signed halfword extend
    SXTH,
    /// Signed word extend
    SXTW,
    /// Signed doubleword extend
    SXTX,
}

impl ExtendType {
    /// Decode extend type from 3-bit encoding.
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x7 {
            0b000 => ExtendType::UXTB,
            0b001 => ExtendType::UXTH,
            0b010 => ExtendType::UXTW,
            0b011 => ExtendType::UXTX,
            0b100 => ExtendType::SXTB,
            0b101 => ExtendType::SXTH,
            0b110 => ExtendType::SXTW,
            0b111 => ExtendType::SXTX,
            _ => unreachable!(),
        }
    }

    /// Get the mnemonic for this extend type.
    pub fn mnemonic(self) -> &'static str {
        match self {
            ExtendType::UXTB => "uxtb",
            ExtendType::UXTH => "uxth",
            ExtendType::UXTW => "uxtw",
            ExtendType::UXTX => "uxtx",
            ExtendType::SXTB => "sxtb",
            ExtendType::SXTH => "sxth",
            ExtendType::SXTW => "sxtw",
            ExtendType::SXTX => "sxtx",
        }
    }
}

/// Result of decoding an instruction.
#[derive(Clone, Debug)]
pub struct DecodedInsn {
    /// The instruction mnemonic/opcode.
    pub mnemonic: Mnemonic,
    /// Condition code (for conditional instructions).
    pub cond: Option<Condition>,
    /// Operands (destination first, then sources).
    pub operands: Vec<Operand>,
    /// Whether the instruction sets flags.
    pub sets_flags: bool,
    /// Original instruction bytes.
    pub raw: u32,
    /// Size of the instruction in bytes (2 for T16, 4 for others).
    pub size: u8,
    /// The execution state this instruction was decoded in.
    pub state: ExecutionState,
}

impl DecodedInsn {
    /// Create a new decoded instruction.
    pub fn new(mnemonic: Mnemonic, state: ExecutionState, raw: u32, size: u8) -> Self {
        DecodedInsn {
            mnemonic,
            cond: None,
            operands: Vec::new(),
            sets_flags: false,
            raw,
            size,
            state,
        }
    }

    /// Add a condition code.
    pub fn with_cond(mut self, cond: Condition) -> Self {
        self.cond = Some(cond);
        self
    }

    /// Mark as flag-setting.
    pub fn with_flags(mut self) -> Self {
        self.sets_flags = true;
        self
    }

    /// Add an operand.
    pub fn with_operand(mut self, op: Operand) -> Self {
        self.operands.push(op);
        self
    }

    /// Add multiple operands.
    pub fn with_operands(mut self, ops: impl IntoIterator<Item = Operand>) -> Self {
        self.operands.extend(ops);
        self
    }
}

/// Instruction mnemonic enumeration.
///
/// This covers the major instruction categories across all ARM ISAs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Mnemonic {
    // =========================================================================
    // Data Processing - Arithmetic
    // =========================================================================
    ADD,
    ADDS,
    ADC,
    ADCS,
    SUB,
    SUBS,
    SBC,
    SBCS,
    NGC,
    NGCS,
    RSB,
    RSBS,
    RSC,
    RSCS,
    NEG,
    NEGS,
    MUL,
    MULS,
    MLA,
    MLS,
    UMULL,
    UMULLS,
    SMULL,
    SMULLS,
    UMLAL,
    SMLAL,
    UMAAL,
    // AArch32 media / DSP umbrella mnemonics. The concrete operation is derived
    // from the raw instruction word at execution time (A32 / T32 layout).
    A32_PARALLEL,   // signed/unsigned parallel add/sub (SADD8/QADD16/UHASX/...)
    A32_PKH,        // PKHBT / PKHTB
    A32_EXTEND,     // (U|S)XT(A)(B|H|B16)
    A32_SAT16,      // SSAT16 / USAT16
    A32_SAT_ADDSUB, // QADD / QSUB / QDADD / QDSUB
    A32_HMUL,       // SMUL/SMLA/SMULW/SMLAW/SMLAL <x><y>
    A32_DUAL,       // SMUAD / SMUSD / SMLAD / SMLSD
    A32_SMLALD,     // SMLALD / SMLSLD
    A32_SMMUL,      // SMMUL / SMMLA / SMMLS
    A32_USAD,       // USAD8 / USADA8
    A32_SEL,        // SEL
    UMADDL,
    SMADDL,
    UMSUBL,
    SMSUBL,
    UMNEGL,
    SMNEGL,
    UMULH,
    SMULH,
    UDIV,
    SDIV,
    MADD,
    MSUB,
    MNEG,
    CRC32B,
    CRC32H,
    CRC32W,
    CRC32X,
    CRC32CB,
    CRC32CH,
    CRC32CW,
    CRC32CX,

    // =========================================================================
    // Data Processing - Logical
    // =========================================================================
    AND,
    ANDS,
    ORR,
    ORRS,
    ORN,
    ORNS,
    EOR,
    EORS,
    EON,
    BIC,
    BICS,
    MVN,
    MVNS,
    TST,
    TEQ,

    // =========================================================================
    // Data Processing - Address Calculation
    // =========================================================================
    /// ADR - Form PC-relative address
    ADR,
    /// ADRP - Form PC-relative address to 4KB page
    ADRP,

    // =========================================================================
    // Data Processing - Move
    // =========================================================================
    MOV,
    MOVS,
    MOVZ,
    MOVN,
    MOVK,
    MVN_REG,

    // =========================================================================
    // Data Processing - Shift
    // =========================================================================
    LSL,
    LSLS,
    LSR,
    LSRS,
    ASR,
    ASRS,
    ROR,
    RORS,
    RRX,
    RRXS,

    // =========================================================================
    // Data Processing - Bit Field
    // =========================================================================
    BFI,
    BFXIL,
    BFC,
    SBFM,
    SBFX,
    SBFIZ,
    UBFM,
    UBFX,
    UBFIZ,
    EXTR,

    // =========================================================================
    // Data Processing - Compare
    // =========================================================================
    CMP,
    CMN,

    // =========================================================================
    // Data Processing - Conditional
    // =========================================================================
    CSEL,
    CSINC,
    CSINV,
    CSNEG,
    CSET,
    CSETM,
    CINC,
    CINV,
    CNEG,
    CCMP,
    CCMN,

    // =========================================================================
    // Data Processing - Extend
    // =========================================================================
    SXTB,
    SXTH,
    SXTW,
    UXTB,
    UXTH,

    // =========================================================================
    // Data Processing - Count/Reverse
    // =========================================================================
    CLZ,
    CLS,
    CNT,
    RBIT,
    REV,
    REV16,
    REV32,
    REV64,
    REVSH,

    // =========================================================================
    // Branch Instructions
    // =========================================================================
    B,
    BL,
    BLX,
    BX,
    BR,
    BLR,
    RET,
    ERET,
    DRPS,
    BCC, // Generic conditional branch (uses cond field)
    CBZ,
    CBNZ,
    TBZ,
    TBNZ,
    TBB, // Table Branch Byte (Thumb-2)
    TBH, // Table Branch Halfword (Thumb-2)

    // =========================================================================
    // Load/Store - Single Register
    // =========================================================================
    LDR,
    LDRB,
    LDRH,
    LDRSB,
    LDRSH,
    LDRSW,
    LDTR,
    LDTRB,
    LDTRH,
    LDTRSB,
    LDTRSH,
    LDTRSW,
    LDAPUR,
    LDAPURB,
    LDAPURH,
    LDAPURSB,
    LDAPURSH,
    LDAPURSW,
    PRFM,
    STR,
    STRB,
    STRH,
    STTR,
    STTRB,
    STTRH,
    STLUR,
    STLURB,
    STLURH,

    // =========================================================================
    // Load/Store - Pair
    // =========================================================================
    LDP,
    LDPSW,
    STP,
    LDNP,
    STNP,
    LDTP,
    STTP,
    LDTNP,
    STTNP,

    // =========================================================================
    // Load/Store - Exclusive
    // =========================================================================
    LDXR,
    LDXRB,
    LDXRH,
    LDXP,
    STXR,
    STXRB,
    STXRH,
    STXP,
    LDAXR,
    LDAXRB,
    LDAXRH,
    LDAXP,
    STLXR,
    STLXRB,
    STLXRH,
    STLXP,
    LDAR,
    LDARB,
    LDARH,
    LDLAR,
    LDLARB,
    LDLARH,
    LDAPR,
    LDAPRB,
    LDAPRH,
    STLR,
    STLRB,
    STLRH,
    STLLR,
    STLLRB,
    STLLRH,

    // =========================================================================
    // Load/Store - Multiple (AArch32/Thumb)
    // =========================================================================
    LDM,
    LDMIA,
    LDMIB,
    LDMDA,
    LDMDB,
    STM,
    STMIA,
    STMIB,
    STMDA,
    STMDB,
    PUSH,
    POP,

    // =========================================================================
    // Load/Store - Atomic (ARMv8.1+)
    // =========================================================================
    LDADD,
    LDADDA,
    LDADDAL,
    LDADDL,
    LDCLR,
    LDEOR,
    LDSET,
    LDSMAX,
    LDSMIN,
    LDUMAX,
    LDUMIN,
    SWP,
    SWPA,
    SWPAL,
    SWPL,
    CAS,
    CASA,
    CASAL,
    CASL,
    CASP,
    CASPA,
    CASPAL,
    CASPL,

    // =========================================================================
    // System Instructions
    // =========================================================================
    SVC,
    CPS,
    SRS,
    RFE,
    HVC,
    SMC,
    BRK,
    HLT,
    UDF,
    NOP,
    IT,
    YIELD,
    WFE,
    WFI,
    WFET,
    WFIT,
    SEV,
    SEVL,
    ISB,
    DMB,
    DSB,
    SB,
    DGH,
    CLREX,
    MSR,
    MRS,
    SYS,
    SYSL,
    DC,
    IC,
    AT,
    TLBI,
    HINT,

    // =========================================================================
    // Exception Generation
    // =========================================================================
    SWI, // Legacy name for SVC
    BKPT,

    // =========================================================================
    // Coprocessor (AArch32)
    // =========================================================================
    MCR,
    MRC,
    MCR2,
    MRC2,
    MCRR,
    MRRC,
    CDP,
    CDP2,
    LDC,
    STC,

    // =========================================================================
    // SIMD/FP - Data Processing
    // =========================================================================
    FADD,
    FSUB,
    FMUL,
    FDIV,
    FNMUL,
    FMADD,
    FMSUB,
    FNMADD,
    FNMSUB,
    FMAX,
    FMIN,
    FMAXNM,
    FMINNM,
    FABS,
    FNEG,
    FSQRT,
    FRINT,
    FRINTN,
    FRINTP,
    FRINTM,
    FRINTZ,
    FRINTA,
    FRINTX,
    FRINTI,

    // =========================================================================
    // SIMD/FP - Compare
    // =========================================================================
    FCMP,
    FCMPE,
    FCCMP,
    FCCMPE,

    // =========================================================================
    // SIMD/FP - Conversion
    // =========================================================================
    FCVT,
    FCVTAS,
    FCVTAU,
    FCVTMS,
    FCVTMU,
    FCVTNS,
    FCVTNU,
    FCVTPS,
    FCVTPU,
    FCVTZS,
    FCVTZU,
    SCVTF,
    UCVTF,
    FMOV,

    // =========================================================================
    // SIMD/FP - Conditional
    // =========================================================================
    FCSEL,

    // =========================================================================
    // SIMD Vector
    // =========================================================================
    VADD,
    VSUB,
    VMUL,
    VDIV,
    VMLA,
    VMLS,
    VSELEQ,
    VSELGE,
    VSELGT,
    VSELVS,
    VMAXNM_F32,
    VMAXNM_F64,
    VMAXNM_F16,
    VMINNM_F32,
    VMINNM_F64,
    VMINNM_F16,
    VRINTA_F32,
    VRINTA_F64,
    VRINTA_F16,
    VRINTM_F32,
    VRINTM_F64,
    VRINTM_F16,
    VRINTN_F32,
    VRINTN_F64,
    VRINTN_F16,
    VRINTP_F32,
    VRINTP_F64,
    VRINTP_F16,
    VRINTR_F32,
    VRINTR_F64,
    VRINTR_F16,
    VRINTX_F32,
    VRINTX_F64,
    VRINTX_F16,
    VRINTZ_F32,
    VRINTZ_F64,
    VRINTZ_F16,
    VFMA,
    VFMS,
    VFMAL,
    VFMLS,
    VNMLA,
    VNMLS,
    VFNMA,
    VFNMS,
    VNMUL,
    VAND,
    VORR,
    VEOR,
    VBIC,
    VORN,
    VBSL,
    VBIT,
    VBIF,
    VMOV,
    VMOVL,
    VMOVN,
    VQMOVN,
    VQMOVUN,
    VMRS,
    VMSR,
    VMVN,
    VCLS,
    VCLZ,
    VCNT,
    VREV16,
    VREV32,
    VREV64,
    VSWP,
    VDUP,
    VEXT,
    VSHL,
    VSHR,
    VRSHR,
    VSRA,
    VRSRA,
    VRSHL,
    VQSHL,
    VQRSHL,
    VQSHLU,
    VSHRN,
    VRSHRN,
    VQSHRN,
    VQRSHRN,
    VQSHRUN,
    VQRSHRUN,
    VSLI,
    VSRI,
    VZIP,
    VUZP,
    VTRN,
    VPADD,
    VPADDL,
    VPADAL,
    VPMAX,
    VPMIN,
    VTBL,
    VTBX,
    VHADD,
    VRHADD,
    VHSUB,
    VCEQ,
    VCGT,
    VCGE,
    VTST,
    VCLE,
    VCLT,
    VACGT,
    VACGE,
    VQADD,
    VQSUB,
    VQDMULH,
    VQRDMULH,
    VQABS,
    VQNEG,
    VABD,
    VABA,
    VABDL,
    VABAL,
    VADDL,
    VADDW,
    VADDHN,
    VRADDHN,
    VMULL,
    VMLAL,
    VMLSL,
    VQDMULL,
    VQDMLAL,
    VQDMLSL,
    VSUBL,
    VSUBW,
    VSUBHN,
    VRSUBHN,
    VCMP,
    VCMPE,
    VABS,
    VNEG,
    VSQRT,
    VRECPE,
    VRSQRTE,
    VRECPS,
    VRSQRTS,
    VCVT_F32_S32,
    VCVT_F32_U32,
    VCVT_F16_S32,
    VCVT_F16_U32,
    VCVT_S32_F32,
    VCVT_U32_F32,
    VCVT_S32_F16,
    VCVT_U32_F16,
    VCVT_F64_S32,
    VCVT_F64_U32,
    VCVT_S32_F64,
    VCVT_U32_F64,
    VCVT_F64_F32,
    VCVT_F32_F64,
    VCVT_F16_F32,
    VCVT_F32_F16,
    VCVTB_F32_F16,
    VCVTT_F32_F16,
    VCVTB_F16_F32,
    VCVTT_F16_F32,
    VCVT_F32_S32_FIXED,
    VCVT_F32_U32_FIXED,
    VCVT_S32_F32_FIXED,
    VCVT_U32_F32_FIXED,
    VCVT_F64_S32_FIXED,
    VCVT_F64_U32_FIXED,
    VCVT_S32_F64_FIXED,
    VCVT_U32_F64_FIXED,
    VCVTA_S32_F32,
    VCVTA_U32_F32,
    VCVTA_S32_F16,
    VCVTA_U32_F16,
    VCVTA_S32_F64,
    VCVTA_U32_F64,
    VCVTM_S32_F32,
    VCVTM_U32_F32,
    VCVTM_S32_F16,
    VCVTM_U32_F16,
    VCVTM_S32_F64,
    VCVTM_U32_F64,
    VCVTN_S32_F32,
    VCVTN_U32_F32,
    VCVTN_S32_F16,
    VCVTN_U32_F16,
    VCVTN_S32_F64,
    VCVTN_U32_F64,
    VCVTP_S32_F16,
    VCVTP_U32_F16,
    VCVTP_S32_F32,
    VCVTP_U32_F32,
    VCVTP_S32_F64,
    VCVTP_U32_F64,
    VCVTR_S32_F16,
    VCVTR_U32_F16,
    VCVTR_S32_F32,
    VCVTR_U32_F32,
    VCVTR_S32_F64,
    VCVTR_U32_F64,
    VMAX,
    VMIN,
    SADDV,
    SMAXV,
    SMINV,
    UADDV,
    UMAXV,
    UMINV,
    ADDV,
    ZIP1,
    ZIP2,
    UZP1,
    UZP2,
    TRN1,
    TRN2,
    TBL,
    TBX,
    VLD1,
    VLD2,
    VLD3,
    VLD4,
    VST1,
    VST2,
    VST3,
    VST4,
    VLDR,
    VSTR,
    VLDM,
    VSTM,
    VPUSH,
    VPOP,
    FMLA,
    FMLS,

    // =========================================================================
    // Pointer Authentication (ARMv8.3+)
    // =========================================================================
    PACIA,
    PACIB,
    PACDA,
    PACDB,
    PACGA,
    AUTIA,
    AUTIB,
    AUTDA,
    AUTDB,
    XPACI,
    XPACD,
    PACIZA,
    PACIZB,
    PACDZA,
    PACDZB,
    AUTIZA,
    AUTIZB,
    AUTDZA,
    AUTDZB,
    BLRAA,
    BLRAB,
    BRAA,
    BRAB,
    RETAA,
    RETAB,

    // =========================================================================
    // Memory Tagging Extension (ARMv8.5+)
    // =========================================================================
    SUBP,
    SUBPS,
    IRG,
    GMI,
    ADDG,
    SUBG,
    STG,
    STZG,
    ST2G,
    STZ2G,
    LDG,
    STGP,

    // =========================================================================
    // Branch Target Identification (ARMv8.5+)
    // =========================================================================
    BTI,

    // =========================================================================
    // Saturation Instructions (ARMv6+)
    // =========================================================================
    SSAT, // Signed Saturate
    USAT, // Unsigned Saturate

    // =========================================================================
    // Miscellaneous
    // =========================================================================
    SETF8,
    SETF16,
    RMIF,
    CFINV,
    AXFLAG,
    XAFLAG,

    // =========================================================================
    // SVE Instructions
    // =========================================================================
    // Arithmetic
    SVE_ADD,
    SVE_SUB,
    SVE_SUBR,
    SVE_MUL,
    SVE_SDIV,
    SVE_UDIV,
    SVE_SMAX,
    SVE_SMIN,
    SVE_UMAX,
    SVE_UMIN,
    SVE_SABD,
    SVE_UABD,
    SVE_SMULH,
    SVE_UMULH,
    SVE_MLA,
    SVE_MLS,
    SVE_MAD,
    SVE_MSB,
    SVE_NEG,
    SVE_ABS,
    // Logical
    SVE_AND,
    SVE_ORR,
    SVE_EOR,
    SVE_BIC,
    SVE_NOT,
    // Shift
    SVE_LSL,
    SVE_LSR,
    SVE_ASR,
    // Compare
    SVE_CMPEQ,
    SVE_CMPNE,
    SVE_CMPGT,
    SVE_CMPGE,
    SVE_CMPLT,
    SVE_CMPLE,
    SVE_CMPHI,
    SVE_CMPHS,
    SVE_CMPLO,
    SVE_CMPLS,
    // Load/Store
    SVE_LD1B,
    SVE_LD1H,
    SVE_LD1W,
    SVE_LD1D,
    SVE_ST1B,
    SVE_ST1H,
    SVE_ST1W,
    SVE_ST1D,
    SVE_LD1,
    SVE_ST1,
    SVE_LDR,
    SVE_STR,
    // Predicate
    SVE_PTRUE,
    SVE_PFALSE,
    SVE_PTEST,
    SVE_PNEXT,
    SVE_PFIRST,
    SVE_PUNPKHI,
    SVE_PUNPKLO,
    // While
    SVE_WHILELT,
    SVE_WHILELE,
    SVE_WHILELO,
    SVE_WHILELS,
    // Move/Copy
    SVE_MOV,
    SVE_DUP,
    SVE_SEL,
    SVE_CPY,
    SVE_COMPACT,
    // Reduction
    SVE_SADDV,
    SVE_UADDV,
    SVE_SMAXV,
    SVE_UMAXV,
    SVE_SMINV,
    SVE_UMINV,
    SVE_ORV,
    SVE_EORV,
    SVE_ANDV,
    // FP Operations
    SVE_FADD,
    SVE_FSUB,
    SVE_FMUL,
    SVE_FDIV,
    SVE_FMAX,
    SVE_FMIN,
    SVE_FABS,
    SVE_FNEG,
    SVE_FSQRT,
    SVE_FMLA,
    SVE_FMLS,
    SVE_FCVT,
    SVE_SCVTF,
    SVE_UCVTF,
    SVE_FCVTZS,
    SVE_FCVTZU,
    // Index/Address
    SVE_INDEX,
    SVE_INCD,
    SVE_INCW,
    SVE_INCH,
    SVE_INCB,
    SVE_DECD,
    SVE_DECW,
    SVE_DECH,
    SVE_DECB,
    SVE_CNTP,
    SVE_CNTB,
    SVE_CNTH,
    SVE_CNTW,
    SVE_CNTD,
    // Permute
    SVE_ZIP1,
    SVE_ZIP2,
    SVE_UZP1,
    SVE_UZP2,
    SVE_TRN1,
    SVE_TRN2,
    SVE_REV,
    SVE_REVB,
    SVE_REVH,
    SVE_REVW,
    SVE_SPLICE,
    SVE_EXT,
    SVE_TBL,
    // Misc
    SVE_MOVPRFX,
    SVE_RDVL,

    // =========================================================================
    // Unknown/Invalid
    // =========================================================================
    UNKNOWN,
    UNDEFINED,

    // A64 saturating accumulation with mixed source/destination signedness.
    SUQADD,
    USQADD,

    // Additional A32 floating conversions; preserve existing discriminants.
    VCVTB_F64_F16,
    VCVTT_F64_F16,
    VCVTB_F16_F64,
    VCVTT_F16_F64,
    VCVT_F16_S16,
    VCVT_F16_U16,
    VCVT_S16_F16,
    VCVT_U16_F16,
    VCVT_F16_S16_FIXED,
    VCVT_S16_F16_FIXED,
    VCVT_F16_U16_FIXED,
    VCVT_U16_F16_FIXED,
    VCVT_F16_S32_FIXED,
    VCVT_S32_F16_FIXED,
    VCVT_F16_U32_FIXED,
    VCVT_U32_F16_FIXED,
    VCVT_F32_S16_FIXED,
    VCVT_S16_F32_FIXED,
    VCVT_F32_U16_FIXED,
    VCVT_U16_F32_FIXED,
    VCVT_F64_S16_FIXED,
    VCVT_S16_F64_FIXED,
    VCVT_F64_U16_FIXED,
    VCVT_U16_F64_FIXED,
    VCVTA_S16_F16,
    VCVTA_U16_F16,
    VCVTN_S16_F16,
    VCVTN_U16_F16,
    VCVTP_S16_F16,
    VCVTP_U16_F16,
    VCVTM_S16_F16,
    VCVTM_U16_F16,
    VMOV_F16_CORE,
    VMOVX_F16,
    VINS_F16,

    // Authenticated branch/load forms and pointer-authentication HINT aliases.
    BRAAZ,
    BRABZ,
    BLRAAZ,
    BLRABZ,
    ERETAA,
    ERETAB,
    LDRAA,
    LDRAB,
    PACIA1716,
    PACIB1716,
    AUTIA1716,
    AUTIB1716,
    PACIAZ,
    PACIBZ,
    PACIASP,
    PACIBSP,
    AUTIAZ,
    AUTIBZ,
    AUTIASP,
    AUTIBSP,
    XPACLRI,
}

mod mnemonic_names;

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Unified decoder that handles all ARM execution states.
pub struct Decoder {
    state: ExecutionState,
}

impl Decoder {
    /// Create a new decoder for the specified execution state.
    pub fn new(state: ExecutionState) -> Self {
        Decoder { state }
    }

    /// Create a decoder for AArch64.
    pub fn new_aarch64() -> Self {
        Self::new(ExecutionState::Aarch64)
    }

    /// Create a decoder for AArch32 (ARM mode).
    pub fn new_aarch32() -> Self {
        Self::new(ExecutionState::Aarch32)
    }

    /// Create a decoder for 32-bit ARM mode.
    pub fn new_arm() -> Self {
        Self::new(ExecutionState::Arm)
    }

    /// Create a decoder for Thumb mode.
    pub fn new_thumb() -> Self {
        Self::new(ExecutionState::Thumb)
    }

    /// Decode an instruction from bytes.
    ///
    /// Returns the decoded instruction and the number of bytes consumed.
    pub fn decode(&self, bytes: &[u8]) -> Result<DecodedInsn, DecodeError> {
        match self.state {
            ExecutionState::Aarch64 => {
                if bytes.len() < 4 {
                    return Err(DecodeError::InsufficientBytes);
                }
                let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Aarch64Decoder::decode(raw)
            }
            ExecutionState::Arm | ExecutionState::Aarch32 => {
                if bytes.len() < 4 {
                    return Err(DecodeError::InsufficientBytes);
                }
                let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Aarch32Decoder::decode(raw)
            }
            ExecutionState::Thumb | ExecutionState::Thumb2 => {
                if bytes.len() < 2 {
                    return Err(DecodeError::InsufficientBytes);
                }
                let hw1 = u16::from_le_bytes([bytes[0], bytes[1]]);

                // Check if this is a 32-bit Thumb instruction
                if ThumbDecoder::is_32bit_instruction(hw1) {
                    if bytes.len() < 4 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let hw2 = u16::from_le_bytes([bytes[2], bytes[3]]);
                    let raw = ((hw1 as u32) << 16) | (hw2 as u32);
                    ThumbDecoder::decode_32bit(raw)
                } else {
                    ThumbDecoder::decode_16bit(hw1)
                }
            }
        }
    }

    /// Get the current execution state.
    pub fn state(&self) -> ExecutionState {
        self.state
    }

    /// Set the execution state.
    pub fn set_state(&mut self, state: ExecutionState) {
        self.state = state;
    }
}

/// Errors that can occur during decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes provided for decoding.
    InsufficientBytes,
    /// The instruction encoding is invalid or undefined.
    InvalidEncoding,
    /// The instruction is undefined for this architecture version.
    Undefined,
    /// The instruction is unpredictable.
    Unpredictable,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InsufficientBytes => write!(f, "insufficient bytes for decoding"),
            DecodeError::InvalidEncoding => write!(f, "invalid instruction encoding"),
            DecodeError::Undefined => write!(f, "undefined instruction"),
            DecodeError::Unpredictable => write!(f, "unpredictable instruction"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_decode() {
        assert_eq!(Condition::from_bits(0b0000), Condition::EQ);
        assert_eq!(Condition::from_bits(0b0001), Condition::NE);
        assert_eq!(Condition::from_bits(0b1110), Condition::AL);
    }

    #[test]
    fn test_condition_invert() {
        assert_eq!(Condition::EQ.invert(), Condition::NE);
        assert_eq!(Condition::NE.invert(), Condition::EQ);
        assert_eq!(Condition::LT.invert(), Condition::GE);
    }

    #[test]
    fn test_shift_type_decode() {
        assert_eq!(ShiftType::from_bits(0b00), ShiftType::LSL);
        assert_eq!(ShiftType::from_bits(0b01), ShiftType::LSR);
        assert_eq!(ShiftType::from_bits(0b10), ShiftType::ASR);
        assert_eq!(ShiftType::from_bits(0b11), ShiftType::ROR);
    }

    #[test]
    fn test_extend_type_decode() {
        assert_eq!(ExtendType::from_bits(0b000), ExtendType::UXTB);
        assert_eq!(ExtendType::from_bits(0b011), ExtendType::UXTX);
        assert_eq!(ExtendType::from_bits(0b110), ExtendType::SXTW);
    }

    #[test]
    fn test_mnemonic_display() {
        assert_eq!(Mnemonic::ADD.as_str(), "add");
        assert_eq!(Mnemonic::LDR.as_str(), "ldr");
        assert_eq!(Mnemonic::BL.as_str(), "bl");
    }
}
