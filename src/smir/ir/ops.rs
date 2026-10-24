//! SMIR operation definitions.
//!
//! This module defines all IR operations (`OpKind`) with their operands and semantics.

use crate::smir::ir::flags::FlagUpdate;
use crate::smir::ir::types::*;

mod arm_pauth;
pub use arm_pauth::ArmPauthOp;
pub(crate) use arm_pauth::architectural_state as arm_boundary_state;
mod arm_simd_resize;
mod arm_simd_saturating;
mod fp_side_effects;
pub(crate) use arm_simd_resize::ARM_FPSR_QC;
pub use arm_simd_resize::{
    ArmSimdLongKind, ArmSimdLongOp, ArmSimdNarrowKind, ArmSimdNarrowMode, ArmSimdNarrowOp,
    ArmSimdPart,
};
pub use arm_simd_saturating::{ArmSimdSaturatingForm, ArmSimdSaturatingKind, ArmSimdSaturatingOp};
mod x86_sat_convert_types;
pub use x86_sat_convert_types::X86SatFpFormat;
pub(crate) use x86_sat_convert_types::{x86_sat_fp_to_int_controls, x86_sat_fp_to_int_widths};
mod x86_fp_types;
pub use x86_fp_types::*;
mod x86_crypto_types;
pub use x86_crypto_types::*;
mod x86_packed_string_types;
pub use x86_packed_string_types::*;
mod x86_system_types;
pub use x86_system_types::*;
mod x86_opmask_types;
pub use x86_opmask_types::*;
mod x86_encoding_types;
pub use x86_encoding_types::*;
mod x86_xop_types;
pub use x86_xop_types::*;

// ============================================================================
// Operation Structure
// ============================================================================

/// A single SMIR operation
#[derive(Clone, Debug)]
pub struct SmirOp {
    /// Unique operation ID within the block
    pub id: OpId,
    /// Guest PC this operation corresponds to
    pub guest_pc: GuestAddr,
    /// The operation kind and operands
    pub kind: OpKind,
    /// x86-specific encoding hints
    pub x86_hint: Option<X86OpHint>,
}

impl SmirOp {
    /// Create a new operation
    pub fn new(id: OpId, guest_pc: GuestAddr, kind: OpKind) -> Self {
        SmirOp {
            id,
            guest_pc,
            kind,
            x86_hint: None,
        }
    }

    /// Create a new operation with x86 hint
    pub fn with_hint(id: OpId, guest_pc: GuestAddr, kind: OpKind, hint: X86OpHint) -> Self {
        SmirOp {
            id,
            guest_pc,
            kind,
            x86_hint: Some(hint),
        }
    }

    /// Fail-safe native-JIT eligibility for an operation, including encoding
    /// hints that affect lowering semantics.
    pub fn is_jit_safe(&self) -> bool {
        !matches!(self.x86_hint, Some(X86OpHint::ShiftGroup6))
            && !(self.x86_hint.is_some() && self.kind.x86_x87_state_jit_shape_valid())
            && self.kind.is_jit_safe()
    }
}

// ============================================================================
// x86 Encoding Hints
// ============================================================================

mod x86_cache_types;
pub use x86_cache_types::{X86CacheControlKind, X86CacheMaintenanceKind};

/// Architectural XSAVE-family save form. The form determines standard versus
/// compacted layout and which init/modified optimizations may be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86XSaveKind {
    XSave,
    XSaveOpt,
    XSaveC,
    XSaveS,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86StringKind {
    Movs,
    Stos,
    Lods,
    Scas,
    Cmps,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86RepMode {
    None,
    Rep,
    Repe,
    Repne,
}

/// x86 scalar bit-count instruction with its architectural status-flag
/// contract. Keeping this distinct from the cross-architecture `Clz`, `Ctz`,
/// and `Popcnt` operations prevents x86-only flag effects from leaking into
/// architectures whose count instructions do not update x86 RFLAGS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86CountKind {
    Popcnt,
    Tzcnt,
    Lzcnt,
}

/// BMI1 lowest-set-bit operation selected by VEX/EVEX.0F38.F3 /1..=/3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86BlsKind {
    /// Reset the lowest set bit: `src & (src - 1)`.
    Blsr,
    /// Create a mask through the lowest set bit: `src ^ (src - 1)`.
    Blsmsk,
    /// Isolate the lowest set bit: `src & -src`.
    Blsi,
}

/// AMD TBM scalar bit-manipulation operation selected by XOP map 9.
///
/// These operations derive CF from an internal increment/decrement and derive
/// OF/SF/ZF from the final logical result. PF and AF are architecturally
/// undefined and are preserved by RAX's deterministic undefined-flag policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86TbmKind {
    /// Fill through the lowest clear bit: `src & (src + 1)`.
    Blcfill,
    /// Isolate the lowest clear bit and complement the remainder:
    /// `src | !(src + 1)`.
    Blci,
    /// Isolate the lowest clear bit: `!src & (src + 1)`.
    Blcic,
    /// Create a mask through the lowest clear bit: `src ^ (src + 1)`.
    Blcmsk,
    /// Set the lowest clear bit: `src | (src + 1)`.
    Blcs,
    /// Fill through the lowest set bit: `src | (src - 1)`.
    Blsfill,
    /// Clear the lowest set bit and complement the remainder:
    /// `!src | (src - 1)`.
    Blsic,
    /// Inverse mask from trailing ones: `!src | (src + 1)`.
    T1mskc,
    /// Mask from trailing zeros: `!src & (src - 1)`.
    Tzmsk,
}

/// ADX carry-chain selected by the ADCX/ADOX mandatory prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86AdxKind {
    /// Read and write CF.
    Adcx,
    /// Read and write OF.
    Adox,
}

/// AMD SSE4A low-qword bitfield operation selected by EXTRQ or INSERTQ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86Sse4aBitfieldKind {
    Extract,
    Insert,
}

// ============================================================================
// OpKind Enum
// ============================================================================

/// Scalar and CSR SMIR operands used to bridge one opaque RISC-V Vector
/// instruction to the transient `RiscVCpu` vector engine.
#[derive(Clone, Debug)]
pub struct RvVectorState {
    pub x_srcs: [VReg; 32],
    pub x_dsts: [VReg; 32],
    pub f_srcs: [VReg; 32],
    pub f_dsts: [VReg; 32],
    pub fcsr_src: VReg,
    pub fcsr_dst: VReg,
    pub vl_src: VReg,
    pub vl_dst: VReg,
    pub vtype_src: VReg,
    pub vtype_dst: VReg,
    pub vstart_src: VReg,
    pub vstart_dst: VReg,
    pub vcsr_src: VReg,
    pub vcsr_dst: VReg,
}

/// A32 data-processing opcode with a register-specified shifter operand.
///
/// The discriminants match the architectural four-bit opcode field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ArmDpRegShiftKind {
    And = 0b0000,
    Eor = 0b0001,
    Sub = 0b0010,
    Rsb = 0b0011,
    Add = 0b0100,
    Adc = 0b0101,
    Sbc = 0b0110,
    Rsc = 0b0111,
    Tst = 0b1000,
    Teq = 0b1001,
    Cmp = 0b1010,
    Cmn = 0b1011,
    Orr = 0b1100,
    Mov = 0b1101,
    Bic = 0b1110,
    Mvn = 0b1111,
}

impl ArmDpRegShiftKind {
    pub fn from_opcode(opcode: u8) -> Option<Self> {
        Some(match opcode {
            0b0000 => Self::And,
            0b0001 => Self::Eor,
            0b0010 => Self::Sub,
            0b0011 => Self::Rsb,
            0b0100 => Self::Add,
            0b0101 => Self::Adc,
            0b0110 => Self::Sbc,
            0b0111 => Self::Rsc,
            0b1000 => Self::Tst,
            0b1001 => Self::Teq,
            0b1010 => Self::Cmp,
            0b1011 => Self::Cmn,
            0b1100 => Self::Orr,
            0b1101 => Self::Mov,
            0b1110 => Self::Bic,
            0b1111 => Self::Mvn,
            _ => return None,
        })
    }

    pub fn is_logical(self) -> bool {
        matches!(
            self,
            Self::And
                | Self::Eor
                | Self::Tst
                | Self::Teq
                | Self::Orr
                | Self::Mov
                | Self::Bic
                | Self::Mvn
        )
    }

    pub fn reads_carry(self) -> bool {
        matches!(self, Self::Adc | Self::Sbc | Self::Rsc)
    }

    pub fn uses_rn(self) -> bool {
        !matches!(self, Self::Mov | Self::Mvn)
    }

    pub fn writes_result(self) -> bool {
        !matches!(self, Self::Tst | Self::Teq | Self::Cmp | Self::Cmn)
    }
}

/// All SMIR operation kinds
#[derive(Clone, Debug)]
pub enum OpKind {
    /// Precise AArch64 entry check before any guest effects. The feature bits
    /// must equal the execution state's bits; absent state declines execution.
    ArmInstructionBegin {
        raw: u32,
        features: u64,
    },
    /// Successful retirement of one AArch64 instruction. Preserves PAuth's
    /// branch/return BTYPE and clears BTYPE for ordinary non-branch operations.
    ArmInstructionCommit {
        raw: u32,
    },
    /// Typed keyed PAuth operation; see `ArmPauthOp` for the state/fault contract.
    ArmPauth(ArmPauthOp),
    /// An observable eBPF guest instruction boundary. Preserved by optimization;
    /// carries the dialect/byte order and charges one guest instruction.
    EbpfInstruction {
        dialect: crate::isa::ebpf::EbpfDialect,
        endian: Endian,
        size: u8,
    },
    // ========================================================================
    // INTEGER ARITHMETIC
    // ========================================================================
    /// Integer addition: dst = src1 + src2
    Add {
        dst: VReg,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Integer subtraction: dst = src1 - src2
    Sub {
        dst: VReg,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Add with carry: dst = src1 + src2 + CF
    Adc {
        dst: VReg,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Subtract with borrow: dst = src1 - src2 - CF
    Sbb {
        dst: VReg,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Negate: dst = -src (two's complement)
    Neg {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Increment: dst = src + 1
    Inc {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Decrement: dst = src - 1
    Dec {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Compare (subtract without storing): flags = src1 - src2
    Cmp {
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
    },

    /// Compare negative (addition without storing): flags = src1 + src2.
    ///
    /// Uses the same width, carry, overflow, and lazy-flag contract as Add with
    /// FlagUpdate::All. No register result is produced. AArch64 CMN requires
    /// addition flags even when src2 is zero or the minimum signed integer.
    /// Native admission is target-specific; the generic whitelist stays closed.
    Cmn {
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
    },

    /// Unsigned multiply: (dst_hi, dst_lo) = src1 * src2
    MulU {
        dst_lo: VReg,
        dst_hi: Option<VReg>,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Signed multiply: (dst_hi, dst_lo) = src1 * src2
    MulS {
        dst_lo: VReg,
        dst_hi: Option<VReg>,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Multiply-add: dst = acc + (src1 * src2)
    MulAdd {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        width: OpWidth,
    },

    /// Multiply-sub: dst = acc - (src1 * src2)
    MulSub {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        width: OpWidth,
    },

    /// Unsigned divide: (quotient, remainder) = src1 / src2
    DivU {
        quot: VReg,
        rem: Option<VReg>,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Signed divide: (quotient, remainder) = src1 / src2
    DivS {
        quot: VReg,
        rem: Option<VReg>,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    // ========================================================================
    // BITWISE LOGICAL
    // ========================================================================
    /// Bitwise AND: dst = src1 & src2
    And {
        dst: VReg,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Bitwise OR: dst = src1 | src2
    Or {
        dst: VReg,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Bitwise XOR: dst = src1 ^ src2
    Xor {
        dst: VReg,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Bitwise NOT: dst = ~src
    Not {
        dst: VReg,
        src: VReg,
        width: OpWidth,
    },

    /// Test (AND without storing): flags = src1 & src2
    Test {
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
    },

    /// AND-NOT: dst = src1 & ~src2 (BMI1/ARM BIC)
    AndNot {
        dst: VReg,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    // ========================================================================
    // SHIFTS AND ROTATES
    // ========================================================================
    /// Logical shift left: dst = src << amount
    Shl {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Logical shift right: dst = src >> amount (zero-fill)
    Shr {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Arithmetic shift right: dst = src >> amount (sign-fill)
    Sar {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Shift left double: dst = (dst << amount) | (src >> (width - amount))
    Shld {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Shift right double: dst = (dst >> amount) | (src << (width - amount))
    Shrd {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// APX NDD double shift with independent destination, base, and fill.
    X86NddDoubleShift {
        dst: VReg,
        base: VReg,
        fill: VReg,
        amount: SrcOperand,
        width: OpWidth,
        left: bool,
        flags: FlagUpdate,
    },

    /// Rotate left
    Rol {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Rotate right
    Ror {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// AArch32 register-controlled shift/rotate.
    ///
    /// The effective count is the low 8 bits of `amount`, not the generic
    /// SMIR/x86 six-bit count.  For W32 operands, LSL/LSR counts above 32
    /// produce zero, ASR counts at or above 32 produce the sign fill, and ROR
    /// uses the count modulo 32. A zero count preserves carry when C is
    /// requested while N/Z are updated from the result. Current producers use
    /// W32 and one of LSL/LSR/ASR/ROR. T16 uses a destructive destination and
    /// `Specific(N|Z|C)`; T32 independently encodes all three registers and
    /// selects either `Specific(N|Z|C)` or `None`. Optimization may erase the
    /// flag update to `None` when all three outputs are dead.
    ArmRegShift {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        shift: ShiftOp,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// A32 data processing with a register-specified shifter operand.
    ///
    /// `rm` is shifted by `rs[7:0]` using the exact A32 saturating/modulo
    /// rules before `kind` combines it with optional `rn`. Logical flag forms
    /// update N/Z from the result and C from the shifter while preserving V;
    /// arithmetic flag forms update N/Z/C/V from the arithmetic result.
    ArmDpRegShift {
        kind: ArmDpRegShiftKind,
        dst: Option<VReg>,
        rn: Option<VReg>,
        rm: VReg,
        rs: VReg,
        shift: ShiftOp,
        flags: FlagUpdate,
    },

    /// Rotate through carry left
    Rcl {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Rotate through carry right
    Rcr {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Hexagon bidirectional register-amount shift.
    ///
    /// `dst = bidir_shift(src, sxtn7(amount))` where the effective shift count is
    /// the sign-extension of the low 7 bits of `amount` to the range `[-64, 63]`.
    /// A positive count shifts in the `kind` direction; a negative count shifts
    /// the OPPOSITE direction by `|count|`. A magnitude `>= width` yields 0 for
    /// logical shifts and an all-sign result for arithmetic right shifts.
    ///
    /// `kind`: 0 = arithmetic left (`asl`), 1 = arithmetic right (`asr`),
    ///         2 = logical left (`lsl`), 3 = logical right (`lsr`).
    ///
    /// `width` is W32 (single Rd) or W64 (Rdd pair, materialised into a W64 temp
    /// by the lifter). `amount` is normally `SrcOperand::Reg(Rt)`; the `S4_lsli`
    /// form uses `SrcOperand::Imm` for the source value while the count still
    /// comes from a register (the lifter composes that case explicitly).
    BidirShift {
        dst: VReg,
        src: SrcOperand,
        amount: SrcOperand,
        kind: u8,
        width: OpWidth,
    },

    /// Hexagon saturating clamp (`fSATN`/`fSATUN`), modelling the USR overflow
    /// sticky bit.
    ///
    /// `src` is read as a SIGNED `i64` (the lifter feeds it an already
    /// sign-extended wide temp, so reading the full register width and sign-
    /// extending from `src`'s natural width gives the intended value). The value
    /// is clamped to a `sat_bits`-wide range — signed `[-(2^(n-1)), 2^(n-1)-1]`
    /// if `signed`, else unsigned `[0, 2^n - 1]`. If the value was actually
    /// clamped AND `set_ovf` is set, bit 0 (OVF) is OR-ed into the Hexagon USR
    /// register (STICKY — other USR bits are preserved). The clamped result is
    /// truncated to `width` and written to `dst` (a negative signed-clamp result
    /// is written as its two's-complement low bits).
    SatN {
        dst: VReg,
        src: SrcOperand,
        /// Saturation width in bits (8/16/32).
        sat_bits: u8,
        /// true = signed clamp (`fSATN`), false = unsigned clamp (`fSATUN`).
        signed: bool,
        /// true = OR USR:OVF (bit 0) when the value was clamped.
        set_ovf: bool,
        /// Destination store width (W32 for all current Hexagon saturating ops).
        width: OpWidth,
    },

    /// Carry-less (GF(2) polynomial) multiply. The product is the XOR of
    /// shifted partial products, i.e. NO carries. This models Hexagon
    /// `pmpyw`/`vpmpyh` (and their `_acc` forms) and x86 PCLMULQDQ.
    /// Sign-ness is irrelevant because the operation is purely bitwise.
    ///
    /// `pmpyw`: a single 32x32 -> 64-bit carry-less product; `elem_bits = 32`,
    /// `lanes = 1`; the low 32 bits go to `dst`, the high 32 to `dst_hi`.
    /// `vpmpyh`: two independent 16x16 -> 32-bit carry-less products; the
    /// 16-bit halves of `dst`/`dst_hi` are filled per the Hexagon interleave
    /// (`dst.h0=p0.lo, dst.h1=p1.lo, dst_hi.h0=p0.hi, dst_hi.h1=p1.hi`).
    /// `PCLMULQDQ`: one 64x64 -> 128-bit product; the low 64 bits go to `dst`
    /// and the high 64 bits to `dst_hi` (`elem_bits = 64`, `lanes = 1`).
    /// When `acc` is set the products are XOR-ed into the existing `dst`/
    /// `dst_hi` register pair.
    ClMul {
        dst: VReg,
        dst_hi: Option<VReg>,
        src1: SrcOperand,
        src2: SrcOperand,
        /// Per-lane element width in bits (16, 32, or 64).
        elem_bits: u8,
        /// Number of independent lanes (1 for pmpyw, 2 for vpmpyh).
        lanes: u8,
        /// true = XOR the product into the existing dst/dst_hi (`_acc` forms).
        acc: bool,
    },

    /// Reflected CRC-32C (Castagnoli) accumulation used by x86 CRC32.
    /// `crc` contributes its low 32 bits; `data` contributes exactly
    /// `data_width` bits in little-endian byte order. The result is always a
    /// zero-extended 32-bit value, including the architectural r64 forms.
    Crc32C {
        dst: VReg,
        crc: VReg,
        data: VReg,
        data_width: OpWidth,
    },

    /// Hexagon `M7_wcmpy*` — 32x32 wide complex multiply with an i128
    /// intermediate, `:<<1` scale and signed-32 saturation (optional `:rnd`).
    ///
    /// `acc(i128) = (Rss.w[w0] * Rtt.w[w1]) {add ? +,-} (Rss.w[w2] * Rtt.w[w3])`
    /// with each `Rss/Rtt.w[..]` a signed 32-bit word of the source register
    /// pair. If `rnd`, `acc += 0x40000000` before the arithmetic `>> 31`; the
    /// shifted value is then saturated to a signed 32-bit word (USR:OVF set
    /// sticky on clamp) and stored to the single 32-bit `dst`.
    CmpyW128Sat {
        dst: VReg,
        /// The two R registers of the `Rss` pair (lo = even, hi = odd).
        rss_lo: VReg,
        rss_hi: VReg,
        /// The two R registers of the `Rtt` pair (lo = even, hi = odd).
        rtt_lo: VReg,
        rtt_hi: VReg,
        /// Word selectors: term0 = Rss.w[w0]*Rtt.w[w1], term1 = Rss.w[w2]*Rtt.w[w3].
        w0: u8,
        w1: u8,
        w2: u8,
        w3: u8,
        /// true = add the two terms, false = subtract (term0 - term1).
        add: bool,
        /// true = round (add 0x40000000 before the >>31).
        rnd: bool,
    },

    /// Hexagon `S2_asl_r_r_sat` / `S2_asr_r_r_sat` — register-amount saturating
    /// shift implementing `fSAT_ORIG_SHL`. The shift is bidirectional by
    /// `sxtn7(amount)`; the result is saturated to a signed 32-bit word, but the
    /// saturation predicate depends on the ORIGINAL pre-shift value's sign
    /// (saturate toward the original's extreme on a sign flip), PLUS the special
    /// case `orig > 0 && shifted == 0 -> INT_MAX` (both set USR:OVF, sticky).
    /// Only the saturating direction (left for asl, the negative-count "left"
    /// for asr) runs `sat_orig_shl`; the other direction is a plain bidirectional
    /// arithmetic shift with no saturation.
    SatOrigShl {
        dst: VReg,
        src: SrcOperand,
        amount: SrcOperand,
        /// false = asl_r_r_sat (positive count = left, saturating),
        /// true = asr_r_r_sat (negative count = left, saturating).
        right: bool,
        width: OpWidth,
    },

    // ========================================================================
    // BIT MANIPULATION
    // ========================================================================
    /// Bit test: CF = bit(src, index)
    Bt {
        src: VReg,
        index: SrcOperand,
        width: OpWidth,
    },

    /// Bit test and set: CF = bit(src, index); bit(dst, index) = 1
    Bts {
        dst: VReg,
        src: VReg,
        index: SrcOperand,
        width: OpWidth,
    },

    /// Bit test and reset: CF = bit(src, index); bit(dst, index) = 0
    Btr {
        dst: VReg,
        src: VReg,
        index: SrcOperand,
        width: OpWidth,
    },

    /// Bit test and complement
    Btc {
        dst: VReg,
        src: VReg,
        index: SrcOperand,
        width: OpWidth,
    },

    /// Bit scan forward (find lowest set bit)
    Bsf {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Bit scan reverse (find highest set bit)
    Bsr {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Bit field extract: dst = (src >> start(control[7:0])) & ((1 << len(control[15:8])) - 1)
    Bextr {
        dst: VReg,
        src: VReg,
        control: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// Zero high bits starting at index(control[7:0]).
    Bzhi {
        dst: VReg,
        src: VReg,
        index: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    },

    /// x86 BMI1 lowest-set-bit operation with its exact architectural flag contract.
    X86Bls {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        kind: X86BlsKind,
        flags: FlagUpdate,
    },

    /// AMD TBM scalar bit operation with its exact architectural flag contract.
    X86Tbm {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        kind: X86TbmKind,
        flags: FlagUpdate,
    },

    /// x86 ADX addition using CF (`ADCX`) or OF (`ADOX`) as an independent carry chain.
    X86Adx {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        width: OpWidth,
        kind: X86AdxKind,
        flags: FlagUpdate,
    },

    /// Parallel bits deposit: scatter low bits from src into selected mask bits.
    Pdep {
        dst: VReg,
        src: VReg,
        mask: VReg,
        width: OpWidth,
    },

    /// Parallel bits extract: gather selected src bits into contiguous low bits.
    Pext {
        dst: VReg,
        src: VReg,
        mask: VReg,
        width: OpWidth,
    },

    /// Count leading zeros
    Clz {
        dst: VReg,
        src: VReg,
        width: OpWidth,
    },

    /// Count trailing zeros
    Ctz {
        dst: VReg,
        src: VReg,
        width: OpWidth,
    },

    /// Population count
    Popcnt {
        dst: VReg,
        src: VReg,
        width: OpWidth,
    },

    /// x86 POPCNT/TZCNT/LZCNT, including legacy flag effects or APX NF flag
    /// suppression. POPCNT defines all six arithmetic status flags;
    /// TZCNT/LZCNT define CF and ZF while the remaining four are retained by
    /// the deterministic interpreter model.
    X86Count {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        kind: X86CountKind,
        flags: FlagUpdate,
    },

    /// Byte swap (endian conversion)
    Bswap {
        dst: VReg,
        src: VReg,
        width: OpWidth,
    },

    /// Bit reverse (ARM RBIT)
    Rbit {
        dst: VReg,
        src: VReg,
        width: OpWidth,
    },

    /// Extract bit field
    Bfx {
        dst: VReg,
        src: VReg,
        lsb: u8,
        width_bits: u8,
        sign_extend: bool,
        op_width: OpWidth,
    },

    /// Insert bit field
    Bfi {
        dst: VReg,
        dst_in: VReg,
        src: VReg,
        lsb: u8,
        width_bits: u8,
        op_width: OpWidth,
    },

    // ========================================================================
    // DATA MOVEMENT
    // ========================================================================
    /// Register-to-register move
    Mov {
        dst: VReg,
        src: SrcOperand,
        width: OpWidth,
    },

    /// Conditional move: dst = cond ? src : dst
    CMove {
        dst: VReg,
        src: VReg,
        cond: Condition,
        width: OpWidth,
    },

    /// Select: dst = cond ? src_true : src_false
    Select {
        dst: VReg,
        cond: VReg,
        src_true: VReg,
        src_false: VReg,
        width: OpWidth,
    },

    /// Zero-extend
    ZeroExtend {
        dst: VReg,
        src: VReg,
        from_width: OpWidth,
        to_width: OpWidth,
    },

    /// Sign-extend
    SignExtend {
        dst: VReg,
        src: VReg,
        from_width: OpWidth,
        to_width: OpWidth,
    },

    /// Sign-extend accumulator into high register (x86 CWD/CDQ/CQO)
    Cwd {
        dst: VReg,
        src: VReg,
        width: OpWidth,
    },

    /// Truncate
    Truncate {
        dst: VReg,
        src: VReg,
        from_width: OpWidth,
        to_width: OpWidth,
    },

    /// Load effective address
    Lea {
        dst: VReg,
        addr: Address,
    },

    /// x86 LEA with the architectural destination width. Address calculation
    /// remains 64-bit (or is explicitly narrowed by lifted address-size ops),
    /// while W32 zero-extends and W16 preserves the destination's upper bits.
    X86Lea {
        dst: VReg,
        addr: Address,
        width: OpWidth,
    },

    /// Exchange registers
    Xchg {
        reg1: VReg,
        reg2: VReg,
        width: OpWidth,
    },

    /// Register-only x86 XADD, including legacy high-byte and APX EGPR forms.
    X86Xadd(X86XaddOp),

    /// Register-only x86 CMPXCHG, including legacy high-byte and APX EGPR forms.
    X86Cmpxchg(X86CmpxchgOp),

    // ========================================================================
    // MEMORY OPERATIONS
    // ========================================================================
    /// Load from memory
    Load {
        dst: VReg,
        addr: Address,
        width: MemWidth,
        sign: SignExtend,
    },

    /// Store to memory
    Store {
        src: VReg,
        addr: Address,
        width: MemWidth,
    },

    /// Conditional (predicated) load — Hexagon `if (Pu) Rd = memX(...)`.
    /// COMMITS only when `cond`'s bit 0 is set: then `dst = load(EA, width,
    /// signed)`. When `cond` is clear the load CANCELS — `dst` is left
    /// UNCHANGED and NO memory access is performed (no fault on a false
    /// predicate). The lifter passes an already-inverted `cond` for the
    /// `if (!Pu)` forms (see `PredStore`).
    PredLoad {
        dst: VReg,
        cond: VReg,
        addr: Address,
        width: MemWidth,
        signed: SignExtend,
    },

    /// Conditional (predicated) store — Hexagon `if (Pu) memX(...) = Rt`.
    /// COMMITS only when `cond`'s bit 0 is set: then `store(EA, src, width)`.
    /// When `cond` is clear the store CANCELS — NO memory access is performed.
    /// The lifter passes an already-inverted `cond` for the `if (!Pu)` forms.
    PredStore {
        src: SrcOperand,
        cond: VReg,
        addr: Address,
        width: MemWidth,
    },

    /// Repeat store (x86 REP STOS)
    RepStos {
        dst: VReg,
        src: VReg,
        count: VReg,
        width: MemWidth,
    },

    /// Repeat move (x86 REP MOVS)
    RepMovs {
        dst: VReg,
        src: VReg,
        count: VReg,
        width: MemWidth,
    },

    /// Complete x86 string-operation semantics, including address-size index
    /// masking, source segment base, DF direction, REP count, and REPE/REPNE
    /// termination. Architectural registers are explicit for dataflow.
    X86String {
        kind: X86StringKind,
        rep: X86RepMode,
        accumulator: VReg,
        src_index: VReg,
        dst_index: VReg,
        count: VReg,
        src_segment: Option<VReg>,
        width: MemWidth,
        address_width: OpWidth,
    },

    /// Load pair (ARM LDP)
    LoadPair {
        dst1: VReg,
        dst2: VReg,
        addr: Address,
        width: MemWidth,
    },

    /// Store pair (ARM STP)
    StorePair {
        src1: VReg,
        src2: VReg,
        addr: Address,
        width: MemWidth,
    },

    /// Atomic load
    AtomicLoad {
        dst: VReg,
        addr: Address,
        width: MemWidth,
        order: MemoryOrder,
    },

    /// Atomic store
    AtomicStore {
        src: VReg,
        addr: Address,
        width: MemWidth,
        order: MemoryOrder,
    },

    /// Atomic read-modify-write
    AtomicRmw {
        dst: VReg,
        addr: Address,
        src: VReg,
        op: AtomicOp,
        width: MemWidth,
        order: MemoryOrder,
    },

    /// Compare-and-swap
    Cas {
        dst: VReg,
        success: VReg,
        addr: Address,
        expected: VReg,
        new_val: VReg,
        width: MemWidth,
        order: MemoryOrder,
    },

    /// Double-register compare-and-swap on one 128-bit memory object.
    ///
    /// The low word occupies the lower-addressed eight bytes. Both destination
    /// words receive the old memory value regardless of comparison success.
    CasPair {
        dst_lo: VReg,
        dst_hi: VReg,
        success: VReg,
        addr: Address,
        expected_lo: VReg,
        expected_hi: VReg,
        new_lo: VReg,
        new_hi: VReg,
        order: MemoryOrder,
        failure_order: MemoryOrder,
    },

    /// Atomic compare-and-conditional-add.
    ///
    /// Models x86 CMPccXADD: compare the old memory value with `cmp`, update
    /// flags from that comparison, store old+add when `cond` is true (else store
    /// old back through the locked transaction), and always write old to
    /// `dst_old`.
    AtomicCmpXadd {
        dst_old: VReg,
        addr: Address,
        cmp: VReg,
        add: VReg,
        cond: Condition,
        width: MemWidth,
        order: MemoryOrder,
    },

    /// Load-exclusive (ARM LDXR)
    LoadExclusive {
        dst: VReg,
        addr: Address,
        width: MemWidth,
    },

    /// Store-exclusive (ARM STXR)
    StoreExclusive {
        status: VReg,
        src: VReg,
        addr: Address,
        width: MemWidth,
    },

    /// Clear exclusive monitor
    ClearExclusive,

    /// Prefetch hint
    Prefetch {
        addr: Address,
        write: bool,
    },

    /// Start a fault-atomic Hexagon packet. This observable barrier must
    /// survive optimization and is never admitted to native lowering.
    HexagonPacketBegin,

    /// Publish the current Hexagon packet's validated memory/register effects.
    HexagonPacketCommit,

    /// Require natural byte-width alignment before a memory access. A clear
    /// predicate bit 0 cancels the check. Failure reports AlignmentFault at this
    /// operation's guest PC without accessing memory. Native admission must
    /// reject this guard until an equivalent fault-precise lowering exists.
    CheckMemoryAlignment {
        addr: Address,
        width: MemWidth,
        access: crate::error::MemoryAccessKind,
        cond: Option<VReg>,
    },

    /// x86 cache-line writeback/invalidation operation.
    X86CacheControl {
        addr: Address,
        kind: X86CacheControlKind,
    },

    /// Raise x86 #GP(0) when an effective address is not aligned to the given
    /// power-of-two byte boundary. This is separate from the following memory
    /// access so alignment is checked before any architectural side effect.
    X86CheckAlignment {
        addr: Address,
        alignment: u8,
    },

    /// Validate a fault-sensitive x86 memory operand before its access.
    /// `access_size` controls the complete canonical-address range while
    /// `alignment` independently controls the required byte boundary. In
    /// 64-bit mode a noncanonical range raises #GP(0), or #SS(0) for an
    /// SS-based address. A misaligned address raises #GP(0) when
    /// `natural_alignment` is true; otherwise it raises #AC(0) only while
    /// CR0.AM=1, RFLAGS.AC=1, and CPL=3. This operation precedes translation
    /// so the architecturally prior alignment exception has priority over
    /// #PF.
    X86CheckAlignmentAc {
        addr: Address,
        access_size: u8,
        alignment: u8,
        stack_segment: bool,
        natural_alignment: bool,
    },

    /// Memory fence
    Fence {
        kind: FenceKind,
    },

    // ========================================================================
    // FLOATING POINT (scalar)
    // ========================================================================
    /// FP add
    FAdd {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        precision: FpPrecision,
    },

    /// FP subtract
    FSub {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        precision: FpPrecision,
    },

    /// FP multiply
    FMul {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        precision: FpPrecision,
    },

    /// FP divide
    FDiv {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        precision: FpPrecision,
    },

    /// FP fused multiply-add: dst = (src1 * src2) + src3
    FFma {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        precision: FpPrecision,
    },

    /// FP absolute value
    FAbs {
        dst: VReg,
        src: VReg,
        precision: FpPrecision,
    },

    /// FP negate
    FNeg {
        dst: VReg,
        src: VReg,
        precision: FpPrecision,
    },

    /// FP square root
    FSqrt {
        dst: VReg,
        src: VReg,
        precision: FpPrecision,
    },

    /// FP minimum
    FMin {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        precision: FpPrecision,
    },

    /// FP maximum
    FMax {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        precision: FpPrecision,
    },

    /// FP compare
    FCmp {
        src1: VReg,
        src2: VReg,
        precision: FpPrecision,
    },

    /// x86 COMIS*/UCOMIS* scalar floating-point comparison. Writes the x86
    /// arithmetic flags with the architectural unordered/equal/less/greater
    /// truth table. `signaling` distinguishes COMI from UCOMI invalid-exception
    /// policy; `suppress_exceptions` models EVEX SAE.
    X86FpCompare {
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        signaling: bool,
        suppress_exceptions: bool,
    },

    /// x86 (V)CMP{PS,PD,PH,SS,SD,SH}. Legacy and VEX encodings write an
    /// all-zeros/all-ones element vector; EVEX encodings write one result bit
    /// per active element to an opmask register. `mask` is the EVEX write mask,
    /// whose inactive result bits are architecturally zero. `scalar` limits the
    /// comparison to lane zero; vector scalar forms merge the remaining XMM
    /// lanes from `src1`. `suppress_exceptions` models EVEX SAE.
    X86VectorFpCompare {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        predicate: u8,
        scalar: bool,
        mask_destination: bool,
        zero_upper: bool,
        suppress_exceptions: bool,
    },

    /// x86 EVEX VGETEXP{PH,PS,PD,SH,SS,SD}. Active lanes return the
    /// same-format floating-point representation of `floor(log2(abs(src)))`.
    /// Packed merging masks preserve the old destination. Scalar forms copy
    /// bits above the low element through bit 127 from `merge`, while an
    /// inactive merging mask preserves only the old destination low element.
    /// All forms clear shared vector state above their encoded vector length;
    /// `suppress_exceptions` records EVEX SAE.
    X86GetExponent {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        scalar: bool,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 EVEX VGETMANT{PH,PS,PD,SH,SS,SD}. `imm[1:0]` selects the
    /// normalized mantissa interval and `imm[3:2]` selects sign preservation,
    /// positive forcing, or rejection of negative nonzero inputs. Packed and
    /// scalar masking/merge behavior matches [`Self::X86GetExponent`]. The
    /// full immediate is retained so native lowering preserves reserved high
    /// bits even though only its low nibble affects current semantics.
    X86GetMantissa {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        imm: u8,
        scalar: bool,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 EVEX VRNDSCALE{PH,PS,PD,SH,SS,SD}. `imm[7:4]` selects the
    /// number of fractional bits retained, `imm[2]` selects MXCSR or immediate
    /// rounding control, and `imm[3]` suppresses only the precision exception.
    /// Packed and scalar masking/merge behavior matches
    /// [`Self::X86GetExponent`]; `suppress_exceptions` records EVEX SAE and
    /// suppresses every SIMD floating-point exception independently of SPE.
    X86RoundScale {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        imm: u8,
        scalar: bool,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 EVEX VREDUCE{PH,PS,PD,SH,SS,SD}. The operation subtracts the
    /// integer multiple of `2^-imm[7:4]` selected by the active rounding mode
    /// from each source element. `imm[2]` selects MXCSR or immediate rounding
    /// control and `imm[3]` suppresses only the precision exception. Packed
    /// and scalar masking/merge behavior matches [`Self::X86RoundScale`];
    /// `suppress_exceptions` records EVEX SAE and suppresses every SIMD
    /// floating-point exception independently of SPE.
    X86Reduce {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        imm: u8,
        scalar: bool,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 EVEX VRANGE{PS,PD,SS,SD}. `imm[1:0]` selects minimum, maximum,
    /// minimum magnitude, or maximum magnitude; `imm[3:2]` selects the result
    /// sign source. Scalar forms copy bits 127:element-width from `src1`;
    /// packed and scalar writemasking merge from the old destination when
    /// zeroing is disabled. `suppress_exceptions` records EVEX SAE.
    X86Range {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        imm: u8,
        scalar: bool,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 EVEX VFIXUPIMM{PS,PD,SS,SD}. Each active `src1` element is
    /// classified into one of eight architectural tokens; the corresponding
    /// nibble in the low 32 bits of `src2` selects one of sixteen result
    /// actions. The old destination is always an input because response zero
    /// preserves it. `imm` independently enables the zero and invalid sticky
    /// exception reports, while `suppress_exceptions` records EVEX SAE.
    X86FixupImm {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        imm: u8,
        scalar: bool,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 AVX512ER VEXP2{PS,PD}. Each active ZMM element receives an
    /// approximation to `2^src` with architectural relative error below
    /// `2^-23`. Denormal inputs are consumed as positive zero and denormal
    /// results are flushed to positive zero independently of MXCSR.DAZ/FTZ.
    /// `suppress_exceptions` records EVEX SAE; otherwise SNaN invalid and
    /// finite-result overflow can update MXCSR or raise #XM.
    X86Exp2 {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 AVX-512F VRCP14{PS,PD,SS,SD}. Each active element receives Intel's
    /// reciprocal approximation with less than `2^-14` relative error before
    /// final rounding. MXCSR.DAZ treats denormal inputs as signed zero and
    /// MXCSR.FTZ flushes denormal results to signed zero. Scalar forms copy
    /// bits above the low element through bit 127 from `merge`.
    X86Recip14 {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        scalar: bool,
        mask_zeroing: bool,
    },

    /// x86 AVX-512F VRSQRT14{PS,PD,SS,SD}. Each active positive element
    /// receives Intel's reciprocal-square-root approximation with less than
    /// `2^-14` relative error before final rounding. MXCSR.DAZ treats
    /// denormal inputs as signed zero; positive finite inputs always produce
    /// normal results, so MXCSR.FTZ is inapplicable. Scalar forms copy bits
    /// above the low element through bit 127 from `merge`.
    X86Rsqrt14 {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        scalar: bool,
        mask_zeroing: bool,
    },

    /// x86 AVX-512FP16 VRCP{PH,SH}. Each active binary16 element receives a
    /// reciprocal approximation with maximum relative error below
    /// `2^-11 + 2^-14`. The instruction neither raises SIMD floating-point
    /// exceptions nor consults MXCSR.DAZ/FTZ. Scalar forms copy bits 127:16
    /// from `merge` and zero bits above bit 127.
    X86RecipFp16 {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        width: VecWidth,
        lanes: u8,
        scalar: bool,
        mask_zeroing: bool,
    },

    /// x86 AVX-512FP16 VRSQRT{PH,SH}. Each active positive binary16 element
    /// receives a reciprocal-square-root approximation with maximum relative
    /// error below `2^-11 + 2^-14`. The instruction neither raises SIMD
    /// floating-point exceptions nor consults MXCSR.DAZ/FTZ. Scalar forms
    /// copy bits 127:16 from `merge` and zero bits above bit 127.
    X86RsqrtFp16 {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        width: VecWidth,
        lanes: u8,
        scalar: bool,
        mask_zeroing: bool,
    },

    /// x86 AVX512ER VRCP28{PS,PD,SS,SD}. Each active element receives Intel's
    /// reciprocal approximation with less than `2^-28` relative error before
    /// final rounding. Denormal inputs are treated as signed zero and denormal
    /// results are flushed to signed zero independently of MXCSR.DAZ/FTZ.
    /// Scalar forms copy bits above the low element through bit 127 from
    /// `merge`; `suppress_exceptions` records EVEX SAE.
    X86Recip28 {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        scalar: bool,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 AVX512ER VRSQRT28{PS,PD,SS,SD}. Each active positive element
    /// receives Intel's reciprocal-square-root approximation with less than
    /// `2^-28` relative error before final rounding. Denormal inputs are
    /// treated as signed zero and denormal results are flushed to positive
    /// zero independently of MXCSR.DAZ/FTZ. Scalar forms copy bits above the
    /// low element through bit 127 from `merge`; `suppress_exceptions` records
    /// EVEX SAE.
    X86Rsqrt28 {
        dst: VReg,
        merge: Option<VReg>,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        scalar: bool,
        mask_zeroing: bool,
        suppress_exceptions: bool,
    },

    /// x86 EVEX VSCALEF{PH,PS,PD,SH,SS,SD}. Each active element computes
    /// `src1 * 2^floor(src2)` using the selected MXCSR or embedded rounding
    /// mode. Scalar forms copy bits 127:element-width from `src1`; packed and
    /// scalar writemasking merge from the old destination when zeroing is
    /// disabled. `suppress_exceptions` records EVEX embedded rounding/SAE.
    X86ScaleF {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        scalar: bool,
        mask_zeroing: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
    },

    /// x86 CVT(T)SS2SI/CVT(T)SD2SI and EVEX VCVT(T)SS/SD/SH2SI/USI scalar
    /// conversion. Invalid or out-of-range inputs produce the signed
    /// integer-indefinite value, or `2^int_width - 1` when `signed` is false,
    /// if the SIMD invalid exception is masked. `round` records MXCSR-dynamic
    /// or EVEX embedded rounding; truncating forms require round-toward-zero.
    /// `suppress_exceptions` records EVEX ER/SAE.
    X86FpToInt {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        int_width: OpWidth,
        signed: bool,
        truncate: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
    },

    /// x86 AVX10.2 VCVTT{SS,SD}2{SIS,USIS} scalar saturating conversion.
    /// The low binary32/binary64 source is truncated toward zero and converted
    /// to a signed/unsigned 32- or 64-bit GPR result. Out-of-range inputs,
    /// including infinities, clamp to the nearest endpoint and NaNs produce
    /// zero. Invalid and Precision are the only SIMD floating-point exceptions;
    /// `suppress_exceptions` records the register-only EVEX `{sae}` form.
    X86ScalarFpToIntSat {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        int_width: OpWidth,
        signed: bool,
        suppress_exceptions: bool,
    },

    /// x86 CVTSI2SS/CVTSI2SD and EVEX VCVT(U)SI2SS/SD/SH scalar integer
    /// conversion. `merge` supplies destination bits above the converted
    /// scalar through bit 127. `signed` selects signed or unsigned integer
    /// interpretation. `round` records MXCSR-dynamic or EVEX embedded
    /// rounding, and `suppress_exceptions` records EVEX ER/SAE. VEX/EVEX
    /// forms set `zero_upper` to clear shared vector state above bit 127;
    /// legacy forms preserve it.
    X86IntToFp {
        dst: VReg,
        merge: VReg,
        src: VReg,
        elem: VecElementType,
        int_width: OpWidth,
        signed: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
        zero_upper: bool,
    },

    /// x86 scalar floating-point precision conversion. `merge` supplies the
    /// destination bits above the converted scalar through bit 127. `mask`
    /// selects the low scalar element for EVEX forms; an inactive merging mask
    /// preserves the old destination low element while an inactive zeroing
    /// mask clears it. `round` records MXCSR-dynamic or EVEX embedded rounding,
    /// and `suppress_exceptions` records EVEX ER/SAE. VEX/EVEX forms clear
    /// shared vector state above bit 127.
    X86FpConvert {
        dst: VReg,
        merge: VReg,
        src: VReg,
        mask: Option<VReg>,
        from: VecElementType,
        to: VecElementType,
        mask_zeroing: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
        zero_upper: bool,
    },

    /// x86 packed floating-point precision conversion. `lanes` is the number
    /// of converted source elements. `dst_width` identifies the
    /// architecturally written low region; narrowing conversions clear any
    /// unused bits in that region. `suppress_exceptions` records EVEX SAE/ER;
    /// `report_fp16_denormal` distinguishes FP16 conversions that preserve a
    /// denormal input and set MXCSR.DE from those that preserve it silently.
    /// VEX/EVEX forms set `zero_upper` to clear all shared vector state above
    /// `dst_width`, while legacy forms preserve it.
    X86PackedFpConvert {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        from: VecElementType,
        to: VecElementType,
        lanes: u8,
        dst_width: VecWidth,
        mask_zeroing: bool,
        zero_upper: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
        report_fp16_denormal: bool,
    },

    /// x86 packed signed/unsigned integer-to-floating-point conversion for
    /// I32/I64 and F32/F64 elements. `lanes` is the number of converted
    /// source elements; `src_width` and `dst_width` identify the exact low
    /// architectural regions read and written by full- and half-width tuple
    /// forms. Inactive EVEX lanes merge or zero before VEX/EVEX upper-state
    /// clearing. Dynamic rounding observes MXCSR.RC, while an explicit mode
    /// represents EVEX embedded rounding with SAE.
    X86PackedIntToFp {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        int_elem: VecElementType,
        fp_elem: VecElementType,
        signed: bool,
        lanes: u8,
        src_width: VecWidth,
        dst_width: VecWidth,
        mask_zeroing: bool,
        zero_upper: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
    },

    /// x86 packed F32/F64-to-signed/unsigned-I32/I64 conversion. `lanes` is
    /// the number of converted source elements and the source/destination
    /// widths preserve the full- versus half-width tuple relationship.
    /// Rounded forms use MXCSR.RC or EVEX embedded rounding; truncating forms
    /// always use round-toward-zero and may independently request EVEX SAE.
    X86PackedFpToInt {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        fp_elem: VecElementType,
        int_elem: VecElementType,
        signed: bool,
        truncate: bool,
        lanes: u8,
        src_width: VecWidth,
        dst_width: VecWidth,
        mask_zeroing: bool,
        zero_upper: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
    },

    /// x86 EVEX packed signed/unsigned integer-to-FP16 conversion. `src_width`
    /// is the encoded source vector length, while `dst_width` is the low
    /// destination region containing `lanes` FP16 results. Inactive masked
    /// lanes merge or zero before all bits above `dst_width` are cleared.
    /// Dynamic rounding observes MXCSR.RC and can update or trap on MXCSR.OE/PE;
    /// an explicit rounding mode represents EVEX embedded rounding with SAE.
    X86PackedIntToFp16 {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        int_elem: VecElementType,
        signed: bool,
        lanes: u8,
        src_width: VecWidth,
        dst_width: VecWidth,
        mask_zeroing: bool,
        zero_upper: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
    },

    /// x86 EVEX packed FP16-to-signed/unsigned-integer conversion. `dst_width`
    /// is the encoded integer destination vector length and `src_width` is the
    /// architectural register region containing `lanes` FP16 inputs. Rounded
    /// forms use MXCSR.RC or EVEX embedded rounding; truncating forms always
    /// use round-toward-zero and may independently request EVEX SAE.
    X86PackedFp16ToInt {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        int_elem: VecElementType,
        signed: bool,
        truncate: bool,
        lanes: u8,
        src_width: VecWidth,
        dst_width: VecWidth,
        mask_zeroing: bool,
        zero_upper: bool,
        round: FpRoundMode,
        suppress_exceptions: bool,
    },

    /// x86 VCVTPS2PH packed FP32-to-FP16 conversion with a memory
    /// destination. `mask` selects the 2-byte destination lanes that are
    /// written; inactive lanes perform no memory access and cannot fault.
    /// The interpreter preflights every active lane before conversion and
    /// commits no stores when an unmasked SIMD floating-point exception is
    /// raised. FP16 output denormals are retained regardless of MXCSR.FTZ.
    X86PackedFpConvertStore {
        addr: Address,
        src: VReg,
        mask: Option<VReg>,
        lanes: u8,
        round: FpRoundMode,
    },

    /// FP convert precision
    FConvert {
        dst: VReg,
        src: VReg,
        from: FpPrecision,
        to: FpPrecision,
    },

    /// Convert int to float
    IntToFp {
        dst: VReg,
        src: VReg,
        int_width: OpWidth,
        fp_precision: FpPrecision,
        signed: bool,
    },

    /// Convert float to int
    FpToInt {
        dst: VReg,
        src: VReg,
        fp_precision: FpPrecision,
        int_width: OpWidth,
        signed: bool,
        round: FpRoundMode,
    },

    /// Round to integral value
    FRound {
        dst: VReg,
        src: VReg,
        precision: FpPrecision,
        mode: FpRoundMode,
    },

    /// x86 ROUNDPS/ROUNDPD/ROUNDSS/ROUNDSD. In addition to integral
    /// rounding, these instructions observe MXCSR.DAZ, quiet SNaNs, update the
    /// MXCSR invalid/precision status bits, optionally suppress precision, and
    /// can raise an unmasked SIMD floating-point exception before destination
    /// writeback. `merge` supplies untouched lanes for scalar forms.
    X86Round {
        dst: VReg,
        merge: VReg,
        src: VReg,
        elem: VecElementType,
        width: VecWidth,
        lanes: u8,
        scalar_source: bool,
        zero_upper: bool,
        mode: FpRoundMode,
        suppress_precision: bool,
    },

    /// x86 DPPS/DPPD and VDPPS/VDPPD. Each selected multiplication and each
    /// horizontal addition is rounded separately under MXCSR; the operation
    /// also owns DAZ/FTZ processing, SIMD exception status, and exception-before-
    /// writeback atomicity. The immediate selects inputs in its high nibble and
    /// broadcast destinations in its low nibble (DPPD uses two bits per field).
    X86DotProduct {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        width: VecWidth,
        imm: u8,
    },

    /// Exact x86 ADD*/SUB*/MUL*/DIV*/MIN*/MAX*/ADDSUB*/HADD*/HSUB* SIMD
    /// floating-point compute. Arithmetic lanes observe MXCSR.DAZ/FTZ and
    /// rounding; non-NaN MIN/MAX lanes apply DAZ before the architecturally
    /// defined source selection. HADD/HSUB pair operands independently inside
    /// each 128-bit source lane, while ADDSUB subtracts even lanes and adds odd
    /// lanes. Inactive mask lanes produce zero without evaluating operands or
    /// reporting exceptions. Dynamic forms aggregate every active lane's
    /// status and raise #XM before destination writeback when an exception is
    /// unmasked. EVEX ER/SAE forms set `suppress_exceptions` and therefore
    /// leave MXCSR status unchanged. Destination merge/zero masking and scalar
    /// upper-lane copying are explicit lifter operations around this compute
    /// primitive.
    X86FpBinary {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        lanes: u8,
        op: X86FpBinaryOp,
        round: FpRoundMode,
        suppress_exceptions: bool,
    },

    // ========================================================================
    // SIMD / VECTOR OPERATIONS
    // ========================================================================
    /// Vector add
    VAdd {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Vector subtract
    VSub {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Per-lane signed/unsigned saturating packed integer add or subtract.
    /// x86 PADDS*/PADDUS*/PSUBS*/PSUBUS* use only I8/I16 elements.
    VAddSubSat {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        subtract: bool,
        signed: bool,
    },

    /// Vector max
    VMax {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// x86 MIN*/MAX* selection semantics. Unordered or equal FP operands
    /// select `src2` bit-for-bit; ordered unequal operands select the numeric
    /// minimum or maximum. This is distinct from AArch64 FMIN/FMAX and *NM.
    VX86MinMax {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        min: bool,
    },

    /// Vector multiply
    VMul {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Vector floating-point divide (FP element types only; AArch64 FDIV).
    VDiv {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Vector per-lane unary op: FP FABS/FNEG/FSQRT or integer NEG/ABS.
    VUnary {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        lanes: u8,
        op: VecUnaryOp,
    },

    /// x86 SQRTPS/SQRTPD/SQRTSS/SQRTSD square root with architectural
    /// MXCSR input processing and IEEE-754 rounding. `round` is either
    /// MXCSR-dynamic or an EVEX embedded rounding mode. For the latter,
    /// `suppress_exceptions` records the implied SAE behavior. This is a
    /// per-lane compute primitive; x86 masking, scalar merging, and upper-lane
    /// clearing are composed explicitly by the lifter.
    X86Sqrt {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        lanes: u8,
        round: FpRoundMode,
        suppress_exceptions: bool,
    },

    /// Vector across-lanes reduction: combine all `lanes` elements of `src`
    /// into a single scalar written to lane 0 of `dst` (other lanes zeroed).
    VReduce {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        lanes: u8,
        op: VecReduceOp,
    },

    /// Vector FP numeric min/max (AArch64 FMAXNM/FMINNM): IEEE maxNum/minNum,
    /// NaN-quiet (returns the numeric operand), unlike FMAX/FMIN.
    VFMinMaxNm {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        min: bool,
    },

    /// Vector two-source permute (AArch64 ZIP/UZP/TRN): combine `src1` and
    /// `src2` element-wise per `kind` into `dst`.
    VPermute2 {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        kind: VecPermuteKind,
    },

    /// Vector table lookup (AArch64 TBL/TBX). The table is `num_tables` (1-4)
    /// consecutive registers starting at `table`; each byte of `index` selects
    /// a table byte (out-of-range → 0 for TBL, keep `dst` byte for TBX).
    VTableLookup {
        dst: VReg,
        table: VReg,
        num_tables: u8,
        index: VReg,
        lanes: u8,
        is_tbx: bool,
    },

    /// Vector bitwise AND
    VAnd {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
    },

    /// Width-bounded bitwise `(!src1) & src2`.
    VAndNot {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
    },

    /// Vector bitwise OR
    VOr {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
    },

    /// Vector bitwise XOR
    VXor {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
    },

    /// Vector bit select: dst = (src_true & mask) | (src_false & ~mask)
    VBitSelect {
        dst: VReg,
        mask: VReg,
        src_true: VReg,
        src_false: VReg,
        width: VecWidth,
    },

    /// Width-general, architecture-register-aware elementwise lane operation.
    ///
    /// Operates on `lanes` elements of `elem` bits across the full vector
    /// register (up to 1024 bits), reading/writing via the arch-aware vector
    /// path so it works on Hexagon HVX V registers (and virtual regs). `op`
    /// selects the per-lane operation and `signed` its signedness where it
    /// matters (min/max/avg/saturate/absdiff/right shift). This is the lift target for HVX
    /// integer elementwise instructions and compact x86 packed-integer
    /// operations with identical lane semantics, including AArch64 signed-byte
    /// register shifts. This operation does not change AArch64 FPSR.QC.
    VLane {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        op: VLaneOp,
        signed: bool,
        /// When true (set only for the saturating opcodes whose sem calls
        /// `ctx.sat_n`/`ctx.satu_n`, e.g. `vsubuwsat`), OR the Hexagon USR:OVF
        /// sticky bit if any lane's saturating op clamped an out-of-range value.
        /// The other saturating VLane opcodes (`vaddhsat`/`vsubwsat`/… which use a
        /// bare `clamp` in their sem) leave this `false` and set no OVF.
        set_ovf: bool,
    },

    /// AArch64 128-bit long arithmetic and cumulative saturation.
    ArmSimdLong(ArmSimdLongOp),

    /// AArch64 narrowing with explicit scalar/half selection and cumulative QC.
    ArmSimdNarrow(ArmSimdNarrowOp),

    /// A64 same-width saturation with implicit cumulative FPSR.QC effects.
    ArmSimdSaturating(ArmSimdSaturatingOp),

    /// Widening elementwise multiply into a destination register pair.
    ///
    /// Models the HVX `Vdd.<2w> = vmpy(Vu.<w>, Vv.<w>)` family: each pair of
    /// adjacent `src_elem`-wide lanes is multiplied into a doubled-width result,
    /// with the EVEN source lanes' products written to `dst_lo` and the ODD
    /// lanes' products to `dst_hi` (the Hexagon even/odd vector-pair layout).
    /// `signed1`/`signed2` select per-operand signedness; when `acc` is set the
    /// products are added into the existing `dst_lo`/`dst_hi` lanes.
    VWidenMul {
        dst_lo: VReg,
        dst_hi: VReg,
        src1: VReg,
        src2: VReg,
        /// Narrow source element type (I8 or I16); result lanes are double width.
        src_elem: VecElementType,
        signed1: bool,
        signed2: bool,
        acc: bool,
    },

    /// Widening element extension into a destination register pair.
    ///
    /// Models the HVX `Vdd = vzxt/vsxt(Vu)` (interleaved: even narrow lanes ->
    /// dst_lo, odd -> dst_hi) and `Vdd = vunpack(Vu)` (sequential: the low half
    /// of the narrow lanes -> dst_lo, the high half -> dst_hi) widen-extend
    /// families. Each `src_elem`-wide lane is zero- or sign-extended (`signed`)
    /// to double width.
    VWidenExt {
        dst_lo: VReg,
        dst_hi: VReg,
        src: VReg,
        /// Narrow source element type (I8 or I16); result lanes are double width.
        src_elem: VecElementType,
        signed: bool,
        /// true = interleaved (even/odd -> lo/hi); false = sequential (low/high half).
        interleave: bool,
    },

    /// Widening elementwise add/sub into a destination register pair.
    ///
    /// Models the HVX `Vdd.<2w> = vadd/vsub(Vu.<w>, Vv.<w>)` widening family
    /// (`vaddubh`/`vadduhw`/`vaddhw`, `vsububh`/`vsubuhw`/`vsubhw`, and the
    /// `+=` acc forms). Each pair of adjacent `src_elem`-wide lanes is
    /// sign/zero-extended (`signed1`/`signed2`) and added (or, when `sub`,
    /// subtracted) into a doubled-width result, with the EVEN source lanes'
    /// results written to `dst_lo` and the ODD lanes' to `dst_hi` (the Hexagon
    /// even/odd vector-pair layout). When `acc` is set the result is added into
    /// the existing `dst_lo`/`dst_hi` lanes.
    VWidenAddSub {
        dst_lo: VReg,
        dst_hi: VReg,
        src1: VReg,
        src2: VReg,
        /// Narrow source element type (I8 or I16); result lanes are double width.
        src_elem: VecElementType,
        signed1: bool,
        signed2: bool,
        sub: bool,
        acc: bool,
    },

    /// Width-general per-lane UNARY operation (single source).
    ///
    /// Operates on `lanes` elements of `elem` bits across the full vector
    /// register, reading/writing via the arch-aware vector path (HVX V regs and
    /// virtual regs). `op` selects the per-lane kernel (a small u8 discriminant,
    /// no new enum type):
    ///   0 = Not       (`!a`, bitwise; signedness irrelevant)
    ///   1 = Abs       (`|a|` wrapping; signed lane)
    ///   2 = AbsSat    (`min(|a|, signed_max)`; signed lane, MIN saturates to MAX)
    ///   3 = Clz       (count leading zeros within the `elem`-wide lane)
    ///   4 = Popcount  (population count of the `elem`-wide lane)
    ///   5 = NormAmt   (`max(clz(a), clz(!a)) - 1` within the `elem`-wide lane)
    ///   6 = Neg       (`-a` wrapping; two's complement)
    ///   7 = Clb       (count leading SIGN bits: `max(clz, clo)`, capped at the
    ///                  `elem` width, within the left-justified lane)
    /// `signed` selects signedness where it matters (Abs/AbsSat/Neg).
    VLaneUnary {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        lanes: u8,
        op: u8,
        signed: bool,
    },

    /// Per-lane "negative average": `(ext(a) - ext(b)) >> 1` (arithmetic
    /// shift, truncating toward negative infinity). Models the HVX `vnavg`
    /// family (`vnavgb`/`vnavgh`/`vnavgw` signed, `vnavgub` unsigned source).
    /// `signed` sign-extends the lanes before subtracting; the subtraction and
    /// shift are done at full (i64) precision, so the result wraps into the
    /// `elem`-wide lane on store.
    VNavg {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        signed: bool,
    },

    /// Per-lane shift-by-scalar with accumulate into the destination.
    ///
    /// Models the HVX `Vx.<w> += (Vu.<w> {<<,>>} (Rt & (W-1)))` shift-accumulate
    /// family (`vaslh_acc`/`vaslw_acc`/`vasrh_acc`/`vasrw_acc`). Each `elem`-wide
    /// lane of `src` is shifted by `amount` masked to `log2(elem_bits)` bits
    /// (`Lsl`/`Lsr` logical, `Asr` arithmetic per the lane sign) and the
    /// (wrapping) result is added into the existing `dst` lane.
    VShiftAcc {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        shift: ShiftOp,
        elem: VecElementType,
        lanes: u8,
    },

    /// Pack the even (or odd) narrow sub-element of each wide element from two
    /// source vectors into one vector. Models HVX `vpackeb/ob/eh/oh`: output
    /// narrow lane `i` (low half) = src2's narrow lane `2i+odd`, lane `i+half`
    /// (high half) = src1's narrow lane `2i+odd`. `elem` is the NARROW element.
    VPack {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        /// false = even sub-element (low), true = odd sub-element (high).
        odd: bool,
    },

    /// Saturating narrowing pack. Each signed `src_elem`-wide lane is
    /// saturated to a half-width lane. Within each `block_lanes`-wide source
    /// group, src2 fills the low half of the output group and src1 the high
    /// half. `src_lanes` bounds the active lanes in each source; inactive
    /// backing state is zeroed. A single full-width group models HVX
    /// `vpackhub_sat/hb_sat/wuh_sat/wh_sat`; 128-bit groups model x86 PACK*.
    VPackSat {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        /// Wide source element type (I16 or I32); result lanes are half width.
        src_elem: VecElementType,
        /// true = saturate to the unsigned range (ub/uh), false = signed (b/h).
        to_unsigned: bool,
        /// Number of active wide lanes in each source.
        src_lanes: u8,
        /// Wide source lanes from each operand in one independent pack group.
        block_lanes: u8,
    },

    /// HVX halfword lookup-table gather into a register pair (`vlut16`: vlutvwh
    /// family). `matchval = sel & 0xF`, `oh = (sel>>1)&1`; per output halfword i:
    /// `idx0 = src_idx.b[2i]`, `idx1 = src_idx.b[2i+1]`; for each, match form yields
    /// `((idx&0xF0)==(matchval<<4)) ? table.h[(idx%32)*2+oh] : 0`, nomatch yields
    /// `table.h[(((idx&0x0F)|(matchval<<4))%32)*2+oh]`. idx0→dst_lo[i], idx1→dst_hi[i].
    /// `oracc` ORs into the existing dst pair. `sel` is Rt (Reg) or a #u3 (Imm).
    VLut16 {
        dst_lo: VReg,
        dst_hi: VReg,
        src_idx: VReg,
        table: VReg,
        sel: SrcOperand,
        nomatch: bool,
        oracc: bool,
    },

    /// HVX byte lookup-table gather (`vlut32`: vlutvvb/_nm/bi/_oracc/_oracci).
    /// `matchval = sel & 7`, `oh = (sel>>1)&1`; per byte i with `idx = src_idx.b[i]`:
    /// match form `out.b[i] = ((idx&0xe0)==(matchval<<5)) ? table.b[(idx%64)*2+oh] : 0`;
    /// nomatch form `out.b[i] = table.b[(((idx&0x1f)|(matchval<<5))%64)*2+oh]`.
    /// `oracc` ORs into the existing dst. `sel` is Rt (Reg) or a #u3 (Imm).
    VLut {
        dst: VReg,
        src_idx: VReg,
        table: VReg,
        sel: SrcOperand,
        nomatch: bool,
        oracc: bool,
    },

    /// HVX `vdelta`/`vrdelta`: a 7-stage byte butterfly permute network of `src`
    /// controlled per-byte by `control` (Vv). For each power-of-two `offset`
    /// (`ascending`: 1..64, else 64..1), `cur[k] = (control[k]&offset) ?
    /// cur[k^offset] : cur[k]`, feeding each stage's full result to the next.
    VDelta {
        dst: VReg,
        src: VReg,
        control: VReg,
        ascending: bool,
    },

    /// HVX `vshuffvdd` (`Vdd = vshuff(Vu, Vv, Rt)`): Rt-controlled byte swap
    /// network over the 256-byte pair (dst_lo=Vv, dst_hi=Vu initially). For each
    /// power-of-two `offset` (1..64) whose bit is set in `amount`, swap byte k of
    /// the high reg with byte k+offset of the low reg for every k with `k&offset==0`.
    VShuffVdd {
        dst_lo: VReg,
        dst_hi: VReg,
        src_lo: VReg,
        src_hi: VReg,
        amount: SrcOperand,
    },

    /// HVX `vdealb4w` (`Vd.b = vdeale(Vu.b, Vv.b)`): deal bytes 0 and 2 of each
    /// word. For word lane i (0..32): `dst.b[i]=src2.b[4i]`, `dst.b[32+i]=src2.b[4i+2]`,
    /// `dst.b[64+i]=src1.b[4i]`, `dst.b[96+i]=src1.b[4i+2]` (src1=Vu, src2=Vv).
    VDealB4W {
        dst: VReg,
        src1: VReg,
        src2: VReg,
    },

    /// Byte-granular alignment/rotate of the 256-byte concatenation `src1:src2`.
    /// Models HVX `valignb/vlalignb` (+imm forms) and `vror`: with byte shift
    /// `s` (right: `amount & 127`; left: `128 - (amount & 127)`), the result
    /// byte `i` = `src2[i+s]` when `i+s < 128`, else `src1[i+s-128]`. `vror` is
    /// `VAlign(src, src, Rt, left=false)`.
    VAlign {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        amount: SrcOperand,
        /// false = right-align (shift = amount&127); true = left (128 - amount&127).
        left: bool,
    },

    /// Single-vector shuffle (interleave) or deal (deinterleave) of narrow lanes.
    /// Models HVX `vshuffb/h` (shuffle: out[2i]=src[i], out[2i+1]=src[i+half]) and
    /// `vdealb/h` (deal: out[i]=src[2i], out[i+half]=src[2i+1]). `elem` is the lane.
    VShuffle2 {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        /// false = shuffle (interleave halves), true = deal (deinterleave).
        deal: bool,
    },

    /// Two-vector even/odd shuffle. Models HVX `vshuffeb/ob` and `vshufeh/oh`:
    /// `out[2i] = src2[2i+odd]`, `out[2i+1] = src1[2i+odd]` — interleaving the
    /// even (or odd) narrow sub-elements of two source vectors.
    VShuffleEO {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        /// false = even sub-elements, true = odd.
        odd: bool,
    },

    /// Vector compare producing a Hexagon Q vector predicate. Models HVX
    /// `veqb/vgtb/vgtub/...`: for each `elem`-wide lane, the comparison result
    /// (per `cond`) sets all of that lane's per-byte Q bits in `dst` (a Q reg).
    VCmpToQ {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        cond: VecCmpCond,
        elem: VecElementType,
        lanes: u8,
        /// None = overwrite `dst`; Some(And/Or/Xor) = combine the compare mask
        /// into the existing `dst` Q (HVX accumulating compares veqb_and/or/xor).
        accumulate: Option<VLaneOp>,
    },

    /// Build a Q vector predicate from a per-byte AND test. Models HVX `vandvrt`
    /// (with src2 = a VBroadcast of Rt): `dst.bit[i] = (src1.byte[i] & src2.byte[i]) != 0`.
    /// When `oracc` is set the test bits are OR'd into the existing `dst` Q
    /// instead of overwriting (HVX `vandvrt_acc`: `dst.bit[i] |= ...`).
    VQFromVAndR {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        oracc: bool,
    },

    /// Per-byte Q-gated mask-to-zero. Models HVX `vandvqv`/`vandvnqv` (and, via a
    /// VBroadcast of Rt, `vandqrt`/`vandnqrt`): `dst.byte[i] = (mask_q.bit[i] ^
    /// negate) ? src.byte[i] : 0`. When `oracc` is set the gated bytes are OR'd
    /// into the existing `dst` instead of overwriting (HVX `vandqrt_acc` /
    /// `vandnqrt_acc`: `dst.byte[i] |= (mask_q.bit[i] ^ negate) ? src.byte[i] : 0`).
    VMaskZero {
        dst: VReg,
        mask_q: VReg,
        src: VReg,
        negate: bool,
        oracc: bool,
    },

    /// Per-byte select by a Q vector predicate. Models HVX `vmux`:
    /// `dst.byte[i] = mask_q.bit[i] ? src_true.byte[i] : src_false.byte[i]`.
    VBlend {
        dst: VReg,
        mask_q: VReg,
        src_true: VReg,
        src_false: VReg,
    },

    /// Q-predicated per-lane conditional add/sub into the destination. Models HVX
    /// `if (Qv[!]) Vx {+,-}= Vu` (`vaddbq`/`vaddhnq`/`vsubwq`/...): `dst` is
    /// read-modify-written, each `elem`-wide lane's bytes are individually
    /// selected from `dst {+,-} src` or unchanged `dst` per the Q bit covering
    /// that vector byte (`fCONDMASK{8,16,32}`). `dst` and `mask_q` are read; the
    /// add/sub is wrapping (non-saturating).
    VLaneCond {
        dst: VReg,
        src: VReg,
        mask_q: VReg,
        elem: VecElementType,
        lanes: u8,
        /// false = add, true = subtract.
        sub: bool,
        /// false = take the op result when Q bit is set (q-form); true = when
        /// the Q bit is CLEAR (nq-form, `if (!Qv)`).
        negate: bool,
    },

    /// HVX per-word carry-chain add/sub with a Q vector-predicate carry. Models
    /// `vadd/vsub(Vu.w,Vv.w,Qx):carry` (carry-in and carry-out share `q_inout`),
    /// `vadd/vsub(Vu.w,Vv.w):carry` carryo (no carry-in; carry-out to `q_out`),
    /// and `vadd(Vu.w,Vv.w,Qs):carry:sat` (carry-in from `q_inout`, no carry-out,
    /// signed sat_32). For word lane `i` the carry-in is Q bit `4*i`; the
    /// carry-out sets the whole 4-bit group `[4*i+3:4*i]` (`-carry_from`).
    /// `sub` realises `Vu + ~Vv + cin`. Carry-in source: `q_inout` if `has_cin`,
    /// else a constant `cin0` (1 for subcarryo, 0 for addcarryo).
    VCarry {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        /// Q register that is the carry-in AND/OR carry-out. For carryo this is
        /// only written; for carry it is read and written; for carrysat read-only.
        q_inout: VReg,
        /// false = add, true = subtract (`Vu + ~Vv + cin`).
        sub: bool,
        /// true = read the carry-in from `q_inout` (carry / carrysat); false =
        /// use the constant `cin0` (carryo forms have no carry-in Q).
        has_cin: bool,
        /// Constant carry-in when `has_cin` is false (1 for subcarryo, else 0).
        cin0: bool,
        /// true = write the per-lane carry-out back into `q_inout` (carry /
        /// carryo). The saturating form writes no carry-out.
        has_cout: bool,
        /// true = signed-saturate the 33-bit sum to 32 bits (`vaddcarrysat`).
        sat: bool,
    },

    /// HVX `Vdd = vswap(Qt, Vu, Vv)`: a pair Q-blend. Per vector byte `i`:
    /// `dst_lo.b[i] = Qt[i] ? Vu.b[i] : Vv.b[i]`,
    /// `dst_hi.b[i] = Qt[i] ? Vv.b[i] : Vu.b[i]`.
    VSwap {
        dst_lo: VReg,
        dst_hi: VReg,
        mask_q: VReg,
        src1: VReg,
        src2: VReg,
    },

    /// HVX odd/even shuffle of two vectors into a register PAIR. Models
    /// `vshufoeb`/`vshufoeh` (`Vdd = vshuffoe(Vu, Vv)`): for each output narrow
    /// lane index `i` in 0..half, `dst_lo` (the EVEN shuffle) gets sub-lane `2i`
    /// of (src2, src1) interleaved, and `dst_hi` (the ODD shuffle) gets sub-lane
    /// `2i+1`. Per output wide pair k (0..half): low half from src2, high from
    /// src1, exactly like two `VShuffleEO` (even -> dst_lo, odd -> dst_hi).
    /// `elem` is the NARROW element. src1=Vu, src2=Vv.
    VShuffleEOPair {
        dst_lo: VReg,
        dst_hi: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
    },

    /// HVX in-place dual-register byte shuffle/deal network. Models
    /// `vshuff(Vy,Vx,Rt)` / `vdeal(Vy,Vx,Rt)`: both `dst_y`(=Vy) and `dst_x`(=Vx)
    /// are READ and WRITTEN. For each power-of-two `offset` (shuffle: ascending
    /// 1..64; deal: descending 64..1) whose bit is set in `amount`, swap byte k of
    /// Vy with byte `k+offset` of Vx for every k with `k&offset==0`.
    VShuffleDeal {
        dst_y: VReg,
        dst_x: VReg,
        amount: SrcOperand,
        /// false = shuffle (offsets ascending 1..64), true = deal (descending 64..1).
        deal: bool,
    },

    /// HVX `vdealvdd` (`Vdd = vdeal(Vu, Vv, Rt)`): Rt-controlled byte deal network
    /// over the 256-byte pair (dst_lo=Vv, dst_hi=Vu initially). For each
    /// power-of-two `offset` (descending 64..1) whose bit is set in `amount`, swap
    /// byte k of the high reg with byte `k+offset` of the low reg for every k with
    /// `k&offset==0`. (The deal-direction sibling of `VShuffVdd`.)
    VDealVdd {
        dst_lo: VReg,
        dst_hi: VReg,
        src_lo: VReg,
        src_hi: VReg,
        amount: SrcOperand,
    },

    /// HVX `vunpackob`/`vunpackoh` (`Vxx.<2w> |= vunpacko(Vu.<w>)`): read-modify-
    /// write OR-accumulate of the ODD-extended narrow lanes. Each `src_elem`-wide
    /// narrow lane `i` of `src` is zero-extended to double width, shifted left by
    /// `src_elem` bits (placing it in the high half of the wide lane), and OR'd
    /// into the existing dst pair lane: lanes 0..half -> dst_lo, half..total ->
    /// dst_hi (sequential, like `vunpack`). `dst_lo`/`dst_hi` are read and written.
    VUnpackOAcc {
        dst_lo: VReg,
        dst_hi: VReg,
        src: VReg,
        /// Narrow source element type (I8 or I16); result lanes are double width.
        src_elem: VecElementType,
    },

    /// HVX `vinsertwr` (`Vx.w[0] = Rt`): insert scalar GPR `scalar` into word lane
    /// 0 of vector `dst`; all other words preserved. `dst` is read-modify-written.
    VInsertWordR {
        dst: VReg,
        scalar: VReg,
    },

    /// HVX `extractw` (`Rd = vextract(Vu, Rs)`): extract word lane `(Rs & 127) >> 2`
    /// of vector `src` into the GPR `dst` (a SCALAR result, moving V -> R).
    VExtractWord {
        dst: VReg,
        src: VReg,
        sel: VReg,
    },

    /// HVX `vlut4` (`Vd.h = vlut4(Vu.uh, Rtt.h)`): each halfword lane `i` of `src`
    /// selects (via its top two bits, `(uh >> 14) & 3`) one of four halfwords
    /// packed in the 64-bit scalar pair `table`. `table` is a W64 temp holding Rtt.
    VLut4 {
        dst: VReg,
        src: VReg,
        table: VReg,
    },

    /// HVX `vrotr` (`Vd.uw = vrotr(Vu.uw, Vv.uw)`): per-word bit rotate-right of
    /// `src` lane by `amount` lane masked to 5 bits.
    VRotr {
        dst: VReg,
        src: VReg,
        amount: VReg,
    },

    /// HVX `vaddububb_sat`/`vsubububb_sat` (`Vd.ub = vadd/vsub(Vu.ub, Vv.b):sat`):
    /// per byte lane, unsigned src1 `+/-` SIGNED src2, saturated to the unsigned
    /// byte range. (Mixed-signedness saturating byte add/sub, no plain VLane form.)
    VAddSubMixedSat {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        /// false = add, true = subtract.
        sub: bool,
    },

    /// HVX `vsetq`/`vsetq2` (`Qd = vsetq(Rt)`): build a Q vector predicate from a
    /// scalar length. `v2` selects the variant:
    ///   false (`pred_scalar2`/vsetq): set the low `Rt & 127` byte-bits (`bit[i]=i<n`).
    ///   true  (`pred_scalar2v2`/vsetq2): set bits `0..=((Rt-1) & 127)` (Rt==0 -> all 128).
    VSetPredQ {
        dst: VReg,
        scalar: VReg,
        v2: bool,
    },

    /// HVX `shuffeqh`/`shuffeqw` (`Qd.<n> = vshuffe(Qs.<2n>, Qt.<2n>)`): predicate
    /// shrink/shuffle of two Q vectors. Per vector-byte bit `i` (0..128):
    ///   halfword form (`stride`=1): `bit[i] = (i&1) ? Qs[i-1] : Qt[i]`.
    ///   word form     (`stride`=2): `bit[i] = (i&2) ? Qs[i-2] : Qt[i]`.
    VShuffEqQ {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        /// 1 = halfword (shuffeqh), 2 = word (shuffeqw).
        stride: u8,
    },

    /// HVX saturating halfword multiply-accumulate-pair-scalar. Models
    /// `vmpahhsat`/`vmpauhuhsat`/`vmpsuhuhsat` (`Vx.h = vmpa/vmps(Vx.h, Vu.<h/uh>,
    /// Rtt.<h/uh>):sat`). Per halfword lane i: `x = Vx.h[i]` (signed), `u = Vu`
    /// lane (signed iff `signed_u`), `idx = (Vu.uh[i] >> 14) & 3` selects one of
    /// four scalar-pair halfwords `t = Rtt[idx]` (signed iff `signed_t`). The
    /// product `p = (x*u << shl) + (t << 15)` then `Vx.h[i] = sat16(p >> 16)`.
    /// `vmps` uses `sub=true` (`- (t<<15)`). `Vx` is read-modify-written; `table`
    /// is a W64 temp holding Rtt.
    VMpaHhSat {
        dst: VReg,
        src: VReg,
        table: VReg,
        signed_u: bool,
        signed_t: bool,
        /// extra left shift applied to the x*u product (1 for vmpahhsat, else 0).
        shl: u8,
        /// false = vmpa (add t<<15), true = vmps (subtract t<<15).
        sub: bool,
    },

    /// HVX `vmpyhsat_acc` (`Vxx.w += vmpy(Vu.h, Rt.h):sat`): saturating word
    /// accumulate. Per word lane i: `dst_lo.w[i] = sat32(dst_lo.w[i] + Vu.h[2i] *
    /// Rt.h[0])` and `dst_hi.w[i] = sat32(dst_hi.w[i] + Vu.h[2i+1] * Rt.h[1])`.
    /// Both halfwords signed; `dst_lo`/`dst_hi` are read-modify-written; `scalar`
    /// is the GPR Rt (its two signed halfwords).
    VMpyHsatAcc {
        dst_lo: VReg,
        dst_hi: VReg,
        src: VReg,
        scalar: VReg,
    },

    /// HVX `vasr_into` (`Vxx.w = vasrinto(Vu.w, Vv.w)`): bidirectional shift of
    /// each word lane of `src` (placed in the high 32 bits of a 64-bit value) into
    /// the running accumulator pair `dst_lo`(Vxx.v[0]) sign-hi / `dst_hi` overlay,
    /// controlled per-lane by `amount`(Vv) in [-0x40, 0x3f]. The dropped low bits
    /// spill into the MSBs of dst_lo; result hi32 -> dst_hi, lo32 -> dst_lo.
    /// `dst_lo`/`dst_hi` are read-modify-written.
    VAsrInto {
        dst_lo: VReg,
        dst_hi: VReg,
        src: VReg,
        amount: VReg,
    },

    /// HVX V69 byte-matrix multiply `v6mpy` (`Vdd.w = v6mpy(Vuu.ub, Vvv.b, #u2)
    /// :h/:v`). For each 32-bit lane i, six signed 10-bit coefficients are unpacked
    /// from the Vvv pair (`src2_lo`/`src2_hi`): low 8 bits from `ub[j]`, high 2 bits
    /// from `ub[3] >> (2j)`, sign-extended. The `phase` (`#u2`) and `horizontal`
    /// flag select a 9-term table mapping (which unsigned byte of which Vuu vector
    /// multiplies which coefficient, into dst_lo or dst_hi). `acc` adds into the
    /// existing dst pair. src_lo/src_hi = Vuu pair, src2_lo/src2_hi = Vvv pair.
    V6Mpy {
        dst_lo: VReg,
        dst_hi: VReg,
        src_lo: VReg,
        src_hi: VReg,
        src2_lo: VReg,
        src2_hi: VReg,
        /// true = `:h` (horizontal) term table, false = `:v` (vertical).
        horizontal: bool,
        /// `#u2` phase (0..3) selecting the term table row.
        phase: u8,
        acc: bool,
    },

    /// HVX histogram family (`vhist` / `vhistq` / `vwhist128*` / `vwhist256*`).
    ///
    /// These have NO conventional register destination: each tallies values from
    /// the 128-byte input vector (the `.tmp`-loaded data, qemu's `tmp_VRegs[0]`)
    /// into histogram bins spread across the WHOLE V0..V31 register file, which is
    /// read-modify-written. The input data lives in per-packet `.tmp` scratch that
    /// the SMIR context does not model, so we instead carry the effective address
    /// of the `.tmp` vmem load (`input`) and re-read the 128 input bytes from guest
    /// memory; `aligned` applies the vmem `&!127` alignment mask. `mask_q` is the
    /// vector-predicate gate for the q-forms (its LSBs gate each increment; ignored
    /// when `use_q` is false). `imm_match` is the `#u1` for the `*m` forms
    /// (`Some(u)` restricts adds to lanes whose bucket LSB == u). `sat` selects the
    /// unsigned-saturating vwhist256 forms. `kind` discriminates the family:
    ///   0 = vhist   (8 lanes x 16 bytes -> uh bins, += 1)
    ///   1 = vwhist128 (64 halfwords -> uw bins, += weight)
    ///   2 = vwhist256 (64 halfwords -> uh bins, += weight)
    /// See `src/isa/hexagon/semantics/hvx_hist.rs` for the exact pseudocode.
    VHist {
        /// Effective address of the same-packet `.tmp` vmem load that supplies the
        /// 128 input bytes (base register + offset).
        input: Address,
        /// Apply the vmem 128-byte alignment mask (`ea &= !127`) to `input`.
        aligned: bool,
        /// Vector-predicate gate (q-forms); placeholder when `use_q` is false.
        mask_q: VReg,
        /// Whether `mask_q` gates the increments (q-forms).
        use_q: bool,
        /// `#u1` bucket-LSB match for the `*m` forms; `None` otherwise.
        imm_match: Option<u8>,
        /// Unsigned-saturate the bin (vwhist256_sat / vwhist256q_sat).
        sat: bool,
        /// Family discriminator: 0 = vhist, 1 = vwhist128, 2 = vwhist256.
        kind: u8,
    },

    /// Scalar-predicate-gated whole-vector conditional move / combine. Models HVX
    /// `vcmov`/`vncmov` (`if (Ps[.lsb]) Vd = Vu`; CANCEL/no-write when false) and
    /// `vccombine`/`vnccombine` (`if (Ps) { Vdd.v[0]=Vv; Vdd.v[1]=Vu }`). The gate
    /// is the LSB of the scalar predicate `pred` (a Hexagon P reg, stored as bool);
    /// `negate` inverts it (n-forms). When the gate is false NOTHING is written
    /// (the dest register(s) keep their prior value).
    VCondMove {
        /// Low destination vector (vcmov: the single dest; vccombine: Vdd.v[0]).
        dst_lo: VReg,
        /// High destination for the pair combine; None for the single vcmov move.
        dst_hi: Option<VReg>,
        /// Source written to `dst_lo` (vcmov: Vu; vccombine: Vv).
        src_lo: VReg,
        /// Source written to `dst_hi` for the combine (Vu); ignored for vcmov.
        src_hi: VReg,
        /// Scalar predicate register; only its LSB matters.
        pred: VReg,
        /// true = gate on `!pred.lsb` (n-forms vncmov/vnccombine).
        negate: bool,
    },

    /// HVX `Vd = vprefixq{b,h,w}(Qv)`: parallel prefix (running) population count
    /// of a Q vector-predicate's bits, written into `elem`-wide lanes. Lane `i`
    /// gets the count of set Q bits in all vector bytes at index `< (i+1)*ebytes`
    /// (inclusive running sum over the bytes this lane and all lower lanes cover),
    /// wrapping into the lane width.
    VPrefixSumQ {
        dst: VReg,
        mask_q: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Per-lane shift by a vector amount (HVX vaslhv/vasrhv/vlsrhv + _w forms).
    /// Each lane is shifted by `sxtn(amount_lane, log2(elem_bits)+1)` — a signed
    /// per-lane amount; the `kind` selects arithmetic-left / arithmetic-right /
    /// logical-right, each bidirectional (negative amount shifts the other way).
    VShiftV {
        dst: VReg,
        src: VReg,
        amount: VReg,
        elem: VecElementType,
        lanes: u8,
        kind: VShiftVKind,
    },

    /// Multiply with post-shift, optional rounding, optional signed saturation,
    /// and high-part extraction. Models HVX `vmpyhvsrs` (`(Vu·Vv)<<1 +0x8000`,
    /// sat32, `>>16`), `vmpyuhvs` (`(Vu·Vv)>>16`), and (via a VBroadcast of Rt)
    /// the `vmpyhss`/`vmpyhsrs` scalar forms. Each lane: `p = ext(src1)·ext(src2)`
    /// (i64); `p <<= shift_left`; if `round` add `1<<(out_shift-1)`; if
    /// `sat_bits != 0` clamp `p` to the signed `sat_bits` range; result =
    /// `(p >> out_shift)` masked to `src_elem`. Output element = `src_elem`.
    VMulShiftSat {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        src_elem: VecElementType,
        lanes: u8,
        signed1: bool,
        signed2: bool,
        shift_left: u8,
        round: bool,
        /// 0 = no saturation; otherwise clamp to the signed `sat_bits` range.
        sat_bits: u8,
        out_shift: u8,
    },

    /// Narrowing shift-round-saturate / round / saturate-pack. Models the HVX
    /// `vasr*`, `vround*` and `vsat*` narrowing families: each wide `src_elem`
    /// lane is (arithmetically or logically per `arith`) right-shifted by
    /// `amount` (with an optional `+1<<(amount-1)` round bias), then narrowed to
    /// the half-width sub-lane. The two source vectors interleave: output narrow
    /// sub-lane `2i` (even/low) comes from `src_lo` lane `i`, sub-lane `2i+1`
    /// (odd/high) from `src_hi` lane `i` — matching the sem's NARROWING_SHIFT
    /// (`src_lo`=Vv, `src_hi`=Vu). Saturation: `sat==0` truncate (no clamp),
    /// `sat==1` clamp to the signed narrow range, `sat==2` clamp to unsigned.
    /// `vround*` lift as `amount = narrow_bits, round = true`; `vsat*` as
    /// `amount = 0, round = false`. `amount` is Rt (Reg) or an immediate.
    VNarrowShiftSat {
        dst: VReg,
        /// Even/low output sub-lanes (Vv in the sem).
        src_lo: VReg,
        /// Odd/high output sub-lanes (Vu in the sem).
        src_hi: VReg,
        /// Wide source element type (I16 -> byte out, or I32 -> half out).
        src_elem: VecElementType,
        amount: SrcOperand,
        /// true = arithmetic (signed source / arithmetic shift), false = logical.
        arith: bool,
        /// true = add the `+1<<(amount-1)` round bias before shifting.
        round: bool,
        /// 0 = truncate (no saturation), 1 = saturate signed, 2 = saturate unsigned.
        sat: u8,
        /// When true (set only for the opcodes whose sem calls `ctx.sat_n`/
        /// `ctx.satu_n`, e.g. `vround*`/`vsat*`), OR the Hexagon USR:OVF sticky
        /// bit if any lane's saturate clamped an out-of-range value. The bare-
        /// `clamp` siblings sharing this OpKind (`vasrwhsat`/`vasrhubsat`/…) leave
        /// this `false` and set no OVF.
        set_ovf: bool,
    },

    /// Saturate a wide 64-bit pair `{src_hi.w[i]:src_lo.w[i]}` to a signed 32-bit
    /// word per lane. Models HVX `vsatdw` (`Vd.w = vsat(Vu.w, Vv.w)`): for each
    /// word lane i the 64-bit value `(src_hi.w[i] << 32) | src_lo.uw[i]` is
    /// clamped to the signed i32 range. `src_hi`=Vu (sign), `src_lo`=Vv (low).
    VSatDW {
        dst: VReg,
        src_lo: VReg,
        src_hi: VReg,
    },

    /// Per-element variable-shift narrowing saturate (HVX V69+ `vasrv*`). The
    /// wide source is the register PAIR (`src_lo`=Vuu.v[0], `src_hi`=Vuu.v[1]);
    /// the per-sub-lane shift amount comes from `amount` (Vv). For output narrow
    /// sub-lane `2i`: shift `src_lo` lane `i` by `amount`'s sub-lane `2i` (masked
    /// to `log2(narrow_bits)` bits), saturate to unsigned narrow; sub-lane `2i+1`
    /// from `src_hi` lane `i` by `amount` sub-lane `2i+1`. Source is read
    /// signed-by-`arith`; `round` adds the `+1<<(s-1)` bias.
    VNarrowShiftV {
        dst: VReg,
        src_lo: VReg,
        src_hi: VReg,
        amount: VReg,
        /// Wide source element type (I32 -> unsigned half out, I16 -> unsigned byte out).
        src_elem: VecElementType,
        /// true = sign-extend source / arithmetic shift; false = zero-extend.
        arith: bool,
        round: bool,
    },

    /// Multiply each `out_elem` lane of src1 by the even/odd `sub_elem` sub-lane
    /// of src2 within that lane. Models HVX `vmpyiewuh`/`vmpyiowh` (Vu.w *
    /// Vv.uh[even] / Vv.h[odd] -> low word): per output lane i, src2 sub-lane
    /// index = i*(out_elem/sub_elem) + (odd?1:0). Optional wrapping accumulate.
    VMulSubLane {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        out_elem: VecElementType,
        sub_elem: VecElementType,
        odd: bool,
        signed1: bool,
        signed2: bool,
        acc: bool,
    },

    /// Fractional even/odd sub-lane multiply with shift/round/saturate. Models HVX
    /// `vmpyewuh` (Vu.w * Vv.uh[even], `>>16`) and `vmpyowh:<<1[:rnd]:sat`
    /// (Vu.w * Vv.h[odd], `<<1`, optional round, `>>16`, saturate to signed word).
    /// Per lane i: p = ext(src1.lane[i]@out_elem)·ext(src2.sub@sub_elem); if shl1
    /// p<<=1; if rnd p += 1<<(shift-1); p >>= shift; if sat clamp to signed out_elem.
    VMulSubLaneFrac {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        out_elem: VecElementType,
        sub_elem: VecElementType,
        odd: bool,
        signed1: bool,
        signed2: bool,
        shl1: bool,
        rnd: bool,
        shift: u8,
        sat: bool,
        /// sacc: add the existing dst lane (full precision) to the product before shifting.
        acc: bool,
        /// Alternate rounding `((p >> (shift-1)) + 1) >> 1` (HVX :rnd form) instead of `+1<<(shift-1)`.
        rnd2: bool,
    },

    /// Sub-lane multiply of BOTH operands with a fixed left shift. Models HVX
    /// `vmpyieoh` (`Vd.w[i] = (Vu.h[2i] * Vv.h[2i+1]) << 16`): within each
    /// `out_elem`-wide output lane i, read the even/odd `sub_elem` sub-lane of
    /// src1 (index `i*ratio + odd1`) and of src2 (index `i*ratio + odd2`),
    /// sign/zero-extend per `signed1`/`signed2`, multiply, left-shift by `shl`
    /// bits, and store the low `out_elem` bits. No accumulate.
    VMulSubLaneSh {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        out_elem: VecElementType,
        sub_elem: VecElementType,
        odd1: bool,
        odd2: bool,
        signed1: bool,
        signed2: bool,
        /// Left shift (bits) applied to the product before storing the low out_elem bits.
        shl: u8,
    },

    /// 64-bit (vector-pair) even/odd word*half multiply with repack. Models the
    /// HVX `vmpyewuh_64` / `vmpyowh_64_acc` forms. `mode` selects the kernel
    /// (small discriminant, no new enum):
    ///   0 = `vmpyewuh_64` (no acc): per word lane i,
    ///       `prod = sext32(src1.w[i]) * zext(src2.uh[2i])`;
    ///       `dst_hi.w[i] = (prod >> 16) as u32`; `dst_lo.w[i] = (prod << 16) as u32`.
    ///   1 = `vmpyowh_64_acc` (reads the dst pair): per word lane i,
    ///       `prod = sext32(src1.w[i]) * sext(src2.h[2i+1]) + sext32(dst_hi.w[i])`;
    ///       `dst_hi.w[i] = (prod >> 16) as u32`;
    ///       `dst_lo.w[i] = ((prod as u32 & 0xffff) << 16) | ((old dst_lo.w[i] >> 16) & 0xffff)`.
    VMulWord64Pair {
        dst_lo: VReg,
        dst_hi: VReg,
        src1: VReg,
        src2: VReg,
        mode: u8,
    },

    /// Even-lane widening multiply into a single vector. Models HVX `vmpyuhe`:
    /// `dst.wide[i] = (acc ? dst[i] : 0) + src1.narrow[2i] * src2.narrow[2i]`
    /// (only the even narrow sub-lane of each output-width lane is used), with
    /// optional wrapping accumulate.
    VMulEvenWiden {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        src_elem: VecElementType,
        signed1: bool,
        signed2: bool,
        acc: bool,
    },

    /// Pair-by-pair cross-register multiply-add. Models HVX `vmpabusv`/`vmpabuuv`:
    /// per output lane i (`out_elem` wide), `dst_lo[i] = src_lo.narrow[2i]*src2_lo
    /// .narrow[2i] + src_hi.narrow[2i]*src2_hi.narrow[2i]` and `dst_hi[i]` the same
    /// at index `2i+1`. Both multiplicands are register pairs (no Rt broadcast).
    VPairPairReduceMul {
        dst_lo: VReg,
        dst_hi: VReg,
        src_lo: VReg,
        src_hi: VReg,
        src2_lo: VReg,
        src2_hi: VReg,
        narrow_elem: VecElementType,
        out_elem: VecElementType,
        signed1: bool,
        signed2: bool,
    },

    /// Cross-register pair multiply-add into a destination pair. Models the HVX
    /// `vmpa*` family (`Vdd = vmpa(Vuu, Rt)`): with source pair (src_lo, src_hi)
    /// of `pair_elem` lanes and src2 (an Rt broadcast) of `rt_elem` sub-lanes,
    /// per output lane i (`out_elem` wide):
    ///   `dst_lo[i] = src_lo.narrow[2i]·src2.sub[0] + src_hi.narrow[2i]·src2.sub[1]`
    ///   `dst_hi[i] = src_lo.narrow[2i+1]·src2.sub[2] + src_hi.narrow[2i+1]·src2.sub[3]`
    /// `acc` adds into the existing dst pair.
    VPairReduceMul {
        dst_lo: VReg,
        dst_hi: VReg,
        src_lo: VReg,
        src_hi: VReg,
        src2: VReg,
        pair_elem: VecElementType,
        rt_elem: VecElementType,
        out_elem: VecElementType,
        signed1: bool,
        signed2: bool,
        acc: bool,
    },

    /// Cross-register SLIDING-WINDOW reduce. Models the HVX `vdmpy*_dv`,
    /// `vtmpy*` and `vdmpyh{i,sui}sat` families that read a SOURCE PAIR
    /// `Vuu = (src_lo, src_hi)` and whose output-lane taps straddle the pair
    /// boundary (`src_hi` supplies the "next" elements that slide in). `src2`
    /// is an I32 broadcast of Rt so that `src2.sub[k] = Rt.sub[k % subs]`.
    ///
    /// `mode` selects the exact window pattern (kept as a small discriminant so
    /// no new enum type is introduced):
    ///   0 = `_dv` 2-tap sliding (pair -> pair). Per output lane i:
    ///       `dst_lo[i] = src_lo.n[2i]*Rt[(2i)%4]   + src_lo.n[2i+1]*Rt[(2i+1)%4]`
    ///       `dst_hi[i] = src_lo.n[2i+1]*Rt[(2i)%4] + src_hi.n[2i]*Rt[(2i+1)%4]`
    ///   1 = `vtmpy*` 3-tap sliding with a FREE (un-multiplied) addend tap
    ///       (pair -> pair). Per output lane i:
    ///       `dst_lo[i] = src_lo.n[2i]*Rt[(2i)%4]   + src_lo.n[2i+1]*Rt[(2i+1)%4] + src_hi.n[2i]`
    ///       `dst_hi[i] = src_lo.n[2i+1]*Rt[(2i)%4] + src_hi.n[2i]*Rt[(2i+1)%4]   + src_hi.n[2i+1]`
    ///   2 = `vdmpyh{i,sui}sat` straddle (pair -> SINGLE, dst_lo only), saturated:
    ///       `dst[i] = src_lo.h[2i+1]*Rt.sub[0] + src_hi.h[2i]*Rt.sub[1]`
    /// `src_elem` is the multiplicand width (I8/I16), `rt_elem` the Rt sub-lane
    /// width (I8 for modes 0/1, I16 for mode 2), `out_elem` the result width.
    /// `signed1`/`signed2` select multiplicand / Rt signedness; `sat` saturates
    /// the lane (mode 2); `acc` adds into the existing dst lane(s).
    VSlideReduceMul {
        dst_lo: VReg,
        dst_hi: VReg,
        src_lo: VReg,
        src_hi: VReg,
        src2: VReg,
        src_elem: VecElementType,
        rt_elem: VecElementType,
        out_elem: VecElementType,
        mode: u8,
        signed1: bool,
        signed2: bool,
        sat: bool,
        /// When true (set only for the `:sat` opcodes whose sem calls `ctx.sat_n`,
        /// e.g. `vdmpyhisat`/`vdmpyhsuisat`), OR the Hexagon USR:OVF sticky bit if
        /// any output lane's saturate clamped. The non-saturating sliding reduces
        /// (mode 0/1, `sat=false`) leave this `false`.
        set_ovf: bool,
        acc: bool,
    },

    /// `#u1`-byte-rotate pair reduce. Models the HVX `vrmpyubi`/`vrmpybusi`,
    /// `vrsadubi` (sum-of-absolute-differences) and `vdsaduh` (dual SAD over
    /// halfwords) families. The source is a register PAIR `Vuu = (src_lo,
    /// src_hi)`; `src2` is an I32-broadcast of Rt so `src2.sub[k] = Rt.sub[k %
    /// subs]`. `abs_diff` picks the per-tap kernel: `false` sums `a·b` (vrmpy),
    /// `true` sums `|a − b|` (vrsad/vdsad).
    ///
    /// `mode` selects the window (small discriminant, no new enum):
    ///   0 = `vrmpyubi`/`vrmpybusi`/`vrsadubi` byte window with a `#u1` source-
    ///       select (`sel = imm ? src_hi : src_lo`) and an Rt byte-index rotate
    ///       by `-imm`. Per word lane i (taps over bytes 4i..4i+3), with
    ///       `rb(n) = Rt.byte[(n − imm) & 3]` and kernel `f`:
    ///         `dst_lo[i] = f(sel,4i+0,rb0)+f(src_lo,4i+1,rb1)
    ///                      +f(src_lo,4i+2,rb2)+f(src_lo,4i+3,rb3)`
    ///         `dst_hi[i] = f(src_hi,4i+0,rb2)+f(src_hi,4i+1,rb3)
    ///                      +f(sel,4i+2,rb0)+f(src_lo,4i+3,rb1)`
    ///   1 = `vdsaduh` halfword window (`imm` ignored). With `r0 = Rt.uh[0]`,
    ///       `r1 = Rt.uh[1]`, per word lane i:
    ///         `dst_lo[i] = |src_lo.uh[2i] − r0| + |src_lo.uh[2i+1] − r1|`
    ///         `dst_hi[i] = |src_lo.uh[2i+1] − r0| + |src_hi.uh[2i] − r1|`
    /// `src_elem` is the multiplicand width (I8 mode 0 / I16 mode 1), `rt_elem`
    /// the Rt sub-lane width (matches src_elem), `out_elem` the result width
    /// (I32). `signed1`/`signed2` select multiplicand / Rt signedness; `acc`
    /// adds into the existing dst pair.
    VRotReduceMulPair {
        dst_lo: VReg,
        dst_hi: VReg,
        src_lo: VReg,
        src_hi: VReg,
        src2: VReg,
        src_elem: VecElementType,
        rt_elem: VecElementType,
        out_elem: VecElementType,
        imm: u8,
        mode: u8,
        signed1: bool,
        signed2: bool,
        acc: bool,
        abs_diff: bool,
    },

    /// Reducing (dot-product) multiply.
    ///
    /// Models the HVX `vrmpy`/`vdmpy` vector-by-vector reduce family: each output
    /// lane is the sum of `taps` adjacent `src_elem`-wide sub-lane products, so the
    /// output element is `src_elem_bits * taps` wide:
    /// `dst[i] = (acc ? dst[i] : 0) + Σ_{k<taps} ext(src1[taps*i+k])·ext(src2[taps*i+k])`.
    /// `signed1`/`signed2` select per-operand signedness.
    VReduceMul {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        /// src1 source element type (I8 or I16).
        src1_elem: VecElementType,
        /// src2 source element type (may differ from src1 for mixed-width reduce).
        src2_elem: VecElementType,
        /// Output element type (e.g. I32 word for a byte×4 or half×2 reduce).
        out_elem: VecElementType,
        /// Number of source sub-lanes summed per output lane (2 or 4).
        taps: u8,
        signed1: bool,
        signed2: bool,
        /// Saturate the accumulated lane to the signed out_elem range.
        sat: bool,
        /// When true (set only for the `:sat` reduce opcodes whose sem calls
        /// `ctx.sat_n`, e.g. `vdmpyhsat`/`vdmpyhsusat`/`vdmpyhvsat`), OR the
        /// Hexagon USR:OVF sticky bit if any output lane's saturate clamped. The
        /// non-saturating reduces (`sat=false`) leave this `false`.
        set_ovf: bool,
        acc: bool,
    },

    /// Vector shift
    VShift {
        dst: VReg,
        src: VReg,
        amount: SrcOperand,
        shift: ShiftOp,
        elem: VecElementType,
        lanes: u8,
    },

    /// Vector compare
    VCmp {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        cond: VecCmpCond,
        elem: VecElementType,
        lanes: u8,
    },

    /// Vector move
    VMov {
        dst: VReg,
        src: VReg,
        width: VecWidth,
    },

    /// Insert scalar into vector lane
    VInsertLane {
        dst: VReg,
        vec: VReg,
        scalar: VReg,
        lane: u8,
        elem: VecElementType,
    },

    /// Extract scalar from vector lane
    VExtractLane {
        dst: VReg,
        vec: VReg,
        lane: u8,
        elem: VecElementType,
        sign: SignExtend,
    },

    /// Vector shuffle/permute. Each active output lane reads one element-sized
    /// index. Indices `[0, lanes)` select `src1`; with `src2`, indices
    /// `[lanes, 2*lanes)` select it. Out-of-range indices produce zero.
    VShuffle {
        dst: VReg,
        src1: VReg,
        src2: Option<VReg>,
        indices: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Lane-block-local interleave. Each output block alternates elements from
    /// `src1` and `src2`, selecting either the low or high half of the
    /// corresponding input block. `block_lanes` is the number of elements in
    /// one independently interleaved block and must be even.
    VInterleave {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        block_lanes: u8,
        high: bool,
    },

    /// Lane-local byte table shuffle with x86 PSHUFB semantics.
    ///
    /// For output byte `i`, the corresponding control byte selects within the
    /// `block_lanes`-byte source block containing `i`. Control bit 7 produces
    /// zero; otherwise the low `log2(block_lanes)` bits select the source byte.
    /// Only `lanes` bytes are active and inactive backing state is zeroed.
    VByteShuffle {
        dst: VReg,
        src: VReg,
        control: VReg,
        lanes: u8,
        /// Power-of-two source block size (8 for MMX, 16 for XMM/YMM/ZMM).
        block_lanes: u8,
    },

    /// Grouped horizontal binary operation. Within each `block_lanes` source
    /// group, adjacent pairs from `src1` produce the low half of the output
    /// group and adjacent pairs from `src2` produce the high half. This models
    /// x86 PHADD*/PHSUB* independently in every 128-bit vector block.
    VHorizontalBin {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        /// Total active element lanes in each source and the destination.
        lanes: u8,
        /// Source lanes per independent group (8 words or 4 dwords for x86).
        block_lanes: u8,
        subtract: bool,
        /// Signed saturation; valid for the I16 PHADDSW/PHSUBSW forms.
        saturating: bool,
    },

    /// Vector load
    VLoad {
        dst: VReg,
        addr: Address,
        width: VecWidth,
    },

    /// Conditional vector load. When `cond` bit zero is set, reads the entire
    /// vector-width memory operand as one SMIR memory transaction and replaces
    /// `dst`. Otherwise preserves `dst` and performs no memory access.
    PredVLoad {
        dst: VReg,
        cond: VReg,
        addr: Address,
        width: VecWidth,
    },

    /// Vector store
    VStore {
        src: VReg,
        addr: Address,
        width: VecWidth,
    },

    /// Create an x86 procedure stack frame as one fault-precise transaction.
    X86Enter(X86EnterOp),

    /// Push or pop the architectural FLAGS image as one fault-precise x86
    /// stack transaction, including privilege and virtual-8086 filtering.
    X86StackFlags(X86StackFlagsOp),

    /// Leave an x86 stack frame as one ordered implicit transaction.
    X86Leave(X86LeaveOp),

    /// I/O port input
    IoIn {
        dst: VReg,
        port: VReg,
        width: MemWidth,
    },

    /// I/O port output
    IoOut {
        port: VReg,
        value: VReg,
        width: MemWidth,
    },

    /// Broadcast scalar to all lanes
    VBroadcast {
        dst: VReg,
        scalar: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Vector minimum
    VMin {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        signed: bool,
    },

    /// Architecture-neutral vector FMA. Architectural floating-point control
    /// state and exception behavior remain the responsibility of the emitting
    /// ISA; x86 FMA3 uses `X86Fma` instead.
    VFma {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        acc: VReg,
        elem: VecElementType,
        lanes: u8,
        negate_product: bool,
        negate_acc: bool,
    },

    /// x86 binary32/binary64 FMA3 with MXCSR, writemask, source-order, and
    /// embedded-rounding semantics represented explicitly.
    X86Fma(X86FmaOp),

    /// x86 AVX512-FP16 fused multiply-add. Source numbering is architectural;
    /// interpretation applies the 132/213/231 permutation before Intel's
    /// arithmetic-order NaN selection. Explicit rounding denotes EVEX embedded
    /// rounding and therefore also suppresses SIMD floating-point exceptions.
    X86FP16Fma {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        mask: Option<VReg>,
        kind: X86FmaKind,
        order: X86FmaOrder,
        round: FpRoundMode,
        lanes: u8,
    },

    /// x86 AVX512-FP16 complex multiply and multiply-add. Each mask bit
    /// controls one adjacent real/imaginary FP16 pair. Dynamic rounding uses
    /// MXCSR and records sticky status while the instruction-specific rule
    /// masks every SIMD floating-point exception; explicit rounding denotes
    /// EVEX embedded rounding with status suppression.
    X86FP16Complex {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        width: VecWidth,
        pairs: u8,
        scalar: bool,
        mask_zeroing: bool,
        accumulate: bool,
        conjugate: bool,
        round: FpRoundMode,
    },

    /// Intel AVX512_4FMAPS four-iteration fused multiply-add. The four
    /// architectural source registers are explicit so dependency analysis and
    /// destination/source aliasing retain the source-block snapshot. `mem`
    /// contains the fault-suppressed 16-byte Tuple1_4X memory operand. Each
    /// active F32 lane rounds and raises MXCSR exceptions at every sequential
    /// FMA boundary.
    X86FourFma {
        dst: VReg,
        src0: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        mem: VReg,
        mask: Option<VReg>,
        scalar: bool,
        negate_product: bool,
        mask_zeroing: bool,
    },

    /// Intel AVX512_4VNNIW four-iteration signed-word dot product. Explicit
    /// source registers retain the aligned source-block snapshot when `dst`
    /// aliases one of them. Each active I32 lane accumulates two signed I16
    /// products per iteration; the saturating form clamps after every
    /// iteration rather than only after the final sum.
    X86FourDotProduct {
        dst: VReg,
        src0: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        mem: VReg,
        mask: Option<VReg>,
        saturating: bool,
        mask_zeroing: bool,
    },

    // ========================================================================
    // AVX10.1 OPERATIONS
    // ========================================================================
    /// Integer dot product: dst = acc + dot(src1, src2).
    ///
    /// VNNI uses I8/I16 sources with I32 accumulators. PMADDUBSW uses I8
    /// sources with an I16 zero accumulator, two products per result, and
    /// signed saturation. PMADDWD uses signed I16 sources with an I32 zero
    /// accumulator and wraps the adjacent-product sum to 32 bits.
    /// VPDPBUSD: unsigned bytes * signed bytes -> dword accumulate
    /// VPDPBUSDS: same with saturation
    /// VPDPWSSD: signed words * signed words -> dword accumulate
    /// VPDPWSSDS: same with saturation
    VDotProduct {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        /// Element type for src1 (I8 for byte, I16 for word)
        src_elem: VecElementType,
        /// Element type for accumulator (typically I32)
        acc_elem: VecElementType,
        width: VecWidth,
        /// true=src1 unsigned, src2 signed; false=both signed
        src1_unsigned: bool,
        /// Saturate result instead of wrapping
        saturate: bool,
        /// EVEX zeroing for masked-off accumulator lanes.
        zeroing: bool,
    },

    /// IFMA 52-bit multiply-add: dst = acc + (src1[51:0] * src2[51:0])
    /// VPMADD52LUQ: low 52 bits of product
    /// VPMADD52HUQ: high 52 bits of product
    VMultiplyAdd52 {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        width: VecWidth,
        /// true = high 52 bits, false = low 52 bits
        high: bool,
        /// EVEX zeroing for masked-off accumulator lanes.
        zeroing: bool,
    },

    /// Vector population count per element
    /// VPOPCNTB/W/D/Q
    VPopcnt {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        zeroing: bool,
    },

    /// Vector leading-zero count per element.
    /// VPLZCNTD/Q
    VLeadingZeros {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        zeroing: bool,
    },

    /// Per-element bit mask of equal elements at lower lane indices.
    /// VPCONFLICTD/Q
    VConflict {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        zeroing: bool,
    },

    /// Byte permutation from one or two sources
    /// VPERMB: permute bytes from single source
    /// VPERMI2B: permute bytes from two sources, overwrite index
    /// VPERMT2B: permute bytes from two sources, overwrite table
    VPermute {
        dst: VReg,
        src1: VReg,
        src2: Option<VReg>,
        indices: VReg,
        elem: VecElementType,
        width: VecWidth,
        /// Which register to overwrite (false=indices, true=table)
        overwrite_table: bool,
    },

    /// Direct masked AVX-512VBMI byte/word permutation.
    /// VPERMB/W, VPERMI2B/W, VPERMT2B/W
    X86PermuteBytesWords {
        dst: VReg,
        table1: VReg,
        table2: Option<VReg>,
        indices: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        /// false selects VPERMI2B/W; true selects VPERMT2B/W.
        overwrite_table: bool,
        zeroing: bool,
    },

    /// Shuffle bits from qwords using byte indices into mask
    /// VPSHUFBITQMB
    VShuffleBitQM {
        dst: VReg,
        src: VReg,
        indices: VReg,
        mask: Option<VReg>,
        width: VecWidth,
    },

    /// Compact active source elements into consecutive low destination lanes.
    /// Register forms preserve or zero the remaining lanes according to
    /// `zeroing`; a missing mask denotes the architectural k0/no-mask form.
    VCompress {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        zeroing: bool,
    },

    /// Distribute consecutive low source elements into mask-selected
    /// destination lanes. Inactive lanes merge or zero according to `zeroing`.
    VExpand {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        elem: VecElementType,
        width: VecWidth,
        zeroing: bool,
    },

    /// Narrow consecutive integer source lanes into a smaller register result.
    /// The writemask indexes source/result lanes; bits above the narrowed result
    /// width are always cleared for architectural register destinations.
    X86NarrowInt {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        src_elem: VecElementType,
        dst_elem: VecElementType,
        width: VecWidth,
        mode: X86NarrowMode,
        zeroing: bool,
    },

    /// BFloat16 dot product: dst = acc + dot(bf16_to_f32(src1), bf16_to_f32(src2))
    /// VDPBF16PS
    VDotProductBF16 {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        width: VecWidth,
        zeroing: bool,
    },

    /// Convert FP32 to BFloat16
    /// VCVTNEPS2BF16, VCVTNE2PS2BF16
    VCvtFP32ToBF16 {
        dst: VReg,
        src1: VReg,
        src2: Option<VReg>,
        mask: Option<VReg>,
        width: VecWidth,
        zeroing: bool,
    },

    /// Convert BFloat16 to FP32
    VCvtBF16ToFP32 {
        dst: VReg,
        src: VReg,
        width: VecWidth,
    },

    /// FP16 arithmetic operations: VADDPH, VSUBPH, VMULPH, VDIVPH, VSQRTPH,
    /// VMINPH, VMAXPH, and the scalar-compute component of the corresponding
    /// scalar instructions. `lanes` is the exact number of low binary16
    /// elements evaluated; scalar forms use one lane even though their
    /// temporary container is 128 bits wide.
    /// `round` is [`FpRoundMode::Dynamic`] for MXCSR-controlled forms. An
    /// explicit x86 rounding mode represents the 512-bit EVEX `{er}` form;
    /// embedded rounding also suppresses SIMD floating-point exceptions.
    VFP16Arith {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        mask: Option<VReg>,
        op: Avx10FP16Op,
        round: FpRoundMode,
        width: VecWidth,
        lanes: u8,
        zeroing: bool,
    },

    // ========================================================================
    // AVX10.2 OPERATIONS
    // ========================================================================
    /// x86 AVX10.2 saturating FP-to-integer conversion.
    ///
    /// This variant represents VCVT[T]{PH,PS,BF16}2I[U]BS and the AVX10.2
    /// packed FP32/FP64-to-I32/I64 saturating conversions. I8 results retain
    /// one slot per source lane: the converted byte occupies bits 7:0 and the
    /// remainder of the 16-bit or 32-bit source-sized slot is zero. `width` is
    /// the destination payload width; the source payload and encoded EVEX `VL`
    /// are derived from the source/result formats for FP64-to-I32 narrowing
    /// and FP32-to-I64 widening. Bits above `width` in the architectural
    /// destination register are zeroed.
    /// Truncating forms use `truncate=true` and
    /// [`FpRoundMode::RoundTowardZero`]. Non-truncating MXCSR-controlled forms
    /// use [`FpRoundMode::Dynamic`]; an explicit mode represents the 512-bit
    /// EVEX `{er}` form and therefore requires `suppress_exceptions=true`.
    /// BF16 forms instead use fixed RNE or RTZ, always apply DAZ, and neither
    /// consult nor update MXCSR; they encode `suppress_exceptions=false`
    /// because they have no EVEX SAE/embedded-rounding form.
    VCvtFpToIntSat {
        dst: VReg,
        src: VReg,
        mask: Option<VReg>,
        fp_elem: X86SatFpFormat,
        int_elem: VecElementType,
        width: VecWidth,
        signed: bool,
        truncate: bool,
        round: FpRoundMode,
        /// Zero masked-off destination lanes instead of merging old `dst`.
        zeroing: bool,
        /// Suppress MXCSR exception status and traps (`{sae}` or `{er}`).
        suppress_exceptions: bool,
    },

    /// VMINMAX with explicit predicate
    /// VMINMAXPS, VMINMAXPD, VMINMAXSS, VMINMAXSD
    VMinMax {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        width: VecWidth,
        /// Immediate encoding the min/max selection
        imm: u8,
    },

    /// Multiple packed sum of absolute differences
    /// VMPSADBW
    VMpsadbw {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        /// Optional AVX10.2 word-granular write mask.
        mask: Option<VReg>,
        width: VecWidth,
        imm: u8,
        /// Zero inactive destination words instead of merging them.
        zeroing: bool,
    },

    /// Packed sums of absolute byte differences. Each consecutive group of
    /// eight unsigned bytes produces one zero-extended 16-bit sum in the low
    /// word of the corresponding 64-bit result block.
    /// PSADBW, VPSADBW
    VSadBytes {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
    },

    /// Find the first unsigned minimum among eight packed 16-bit lanes and
    /// return the minimum in bits 15:0 and its lane index in bits 18:16.
    /// PHMINPOSUW, VPHMINPOSUW
    X86Phminposuw {
        dst: VReg,
        src: VReg,
    },

    /// Extract one sign bit from every packed source lane into consecutive
    /// low bits of a general-purpose destination. `dst_width` records the
    /// architectural GPR write width selected by the legacy encoding.
    /// MOVMSKPS, MOVMSKPD, PMOVMSKB and their VEX forms.
    X86MovMask {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        lanes: u8,
        dst_width: OpWidth,
    },

    /// Scalar integer transfer between GPR, MMX, and low-XMM register files.
    /// An MMX MOVD destination is zero-extended to 64 bits. An XMM destination
    /// clears bits 127:width; `zero_upper` additionally clears the shared
    /// backing state above bit 127 for VEX/EVEX encodings.
    /// MOVD, MOVQ, VMOVD, VMOVQ, MOVQ2DQ, and MOVDQ2Q register forms.
    X86MovdQ {
        dst: VReg,
        src: VReg,
        width: OpWidth,
        zero_upper: bool,
    },

    /// AES-NI/VAES transformation, applied independently to each 128-bit lane.
    /// `src2` is the round key for round operations and absent for AESIMC and
    /// AESKEYGENASSIST. `imm` is used only by AESKEYGENASSIST.
    X86Aes {
        dst: VReg,
        src1: VReg,
        src2: Option<VReg>,
        width: VecWidth,
        op: X86AesOp,
        imm: u8,
    },

    /// Legacy SHA-NI operation over one 128-bit vector of four 32-bit words.
    /// `src1` snapshots the architectural destination, `src2` is the explicit
    /// register-or-memory source, and `wk` is present only for SHA256RNDS2's
    /// implicit XMM0 input. The result is written independently to `dst`; no
    /// architectural flags are read or written.
    X86Sha32 {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        wk: Option<VReg>,
        op: X86Sha32Op,
        /// Full encoded immediate; only SHA1RNDS4 consumes bits 1:0.
        imm: u8,
    },

    /// Exact SSE4.2/AVX packed-string comparison (`(V)PCMPxSTRx`). `src1`
    /// names the ModR/M.reg XMM operand and `src2` the snapshotted register or
    /// memory operand. Explicit forms carry signed EAX/EDX or RAX/RDX sources;
    /// implicit forms carry neither length. Mask forms write XMM0 bits 127:0;
    /// `zero_upper` distinguishes VEX forms, which clear all shared vector
    /// state above bit 127, from legacy forms, which preserve it. Index forms
    /// write ECX, which zero-extends RCX. All six x86 status flags are defined.
    X86PackedStringCompare {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        len1: Option<VReg>,
        len2: Option<VReg>,
        length_width: OpWidth,
        kind: X86PackedStringKind,
        imm: u8,
        zero_upper: bool,
    },

    /// SHA-512 message schedule, first stage.
    X86Sha512Msg1 {
        dst: VReg,
        src: VReg,
    },

    /// SHA-512 message schedule, final stage.
    X86Sha512Msg2 {
        dst: VReg,
        src: VReg,
    },

    /// Two SHA-512 compression rounds.
    X86Sha512Rounds2 {
        dst: VReg,
        state: VReg,
        wk: VReg,
    },

    /// SM3 message-schedule first/final stages.
    X86Sm3Msg1 {
        dst: VReg,
        src1: VReg,
        src2: VReg,
    },
    X86Sm3Msg2 {
        dst: VReg,
        src1: VReg,
        src2: VReg,
    },

    /// Two SM3 compression rounds.
    X86Sm3Rounds2 {
        dst: VReg,
        state: VReg,
        words: VReg,
        imm: u8,
    },

    /// Four SM4 key-schedule or encryption rounds per 128-bit lane.
    X86Sm4 {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
        key_schedule: bool,
    },

    /// AVX_NE_CONVERT BF16/FP16 memory conversion to packed FP32. B1 forms
    /// broadcast one m16 element; B0 forms select even or odd m128/m256 words.
    X86Convert16ToFp32 {
        dst: VReg,
        src: VReg,
        width: VecWidth,
        fp16: bool,
        odd: bool,
        broadcast: bool,
    },

    /// VEX packed immediate shifts. `byte_lane` selects PSLLDQ/PSRLDQ,
    /// which shift independently within each 128-bit lane.
    X86PackedShiftImm {
        dst: VReg,
        src: VReg,
        width: VecWidth,
        elem: VecElementType,
        shift: ShiftOp,
        amount: u8,
        byte_lane: bool,
    },

    /// PALIGNR/VPALIGNR byte extraction from the per-lane concatenation
    /// `(high || low) >> (amount * 8)`. V64 has one 8-byte lane; wider forms
    /// operate independently in 16-byte lanes. Bytes beyond the two-source
    /// concatenation are zero.
    X86PackedAlignRight {
        dst: VReg,
        high: VReg,
        low: VReg,
        width: VecWidth,
        amount: u8,
    },

    /// PSHUFW/PSHUFD/PSHUFHW/PSHUFLW immediate-controlled lane shuffle.
    /// `high_words` is `None` for all-lane shuffles, `Some(true)` for the high
    /// four words, and `Some(false)` for the low four words.
    X86PackedShuffleImm {
        dst: VReg,
        src: VReg,
        width: VecWidth,
        elem: VecElementType,
        imm: u8,
        high_words: Option<bool>,
    },

    /// Atomic 3DNow! operation. `src1` is the old destructive destination and
    /// `src2` is the ModR/M source; keeping both explicit makes optimizer
    /// liveness exact for horizontal and Newton-Raphson forms.
    X86ThreeDNow {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        kind: X86ThreeDNowKind,
    },

    /// Packed element shift by the unsigned count in `count`. Architectural
    /// x86 forms consume the complete low 64 bits and apply the same count to
    /// every element; out-of-range counts zero logical results or sign-fill
    /// arithmetic-right results.
    X86PackedShift {
        dst: VReg,
        src: VReg,
        count: VReg,
        width: VecWidth,
        elem: VecElementType,
        shift: ShiftOp,
    },

    /// Packed per-element shift by unsigned counts from corresponding vector
    /// lanes (VPSLLV*/VPSRLV*/VPSRAV*).
    X86PackedShiftVariable {
        dst: VReg,
        src: VReg,
        count: VReg,
        mask: Option<VReg>,
        width: VecWidth,
        elem: VecElementType,
        shift: ShiftOp,
        zeroing: bool,
    },

    /// EVEX packed element rotate. Immediate forms use `amount`; variable
    /// forms use the corresponding element of `count`. Counts are reduced
    /// modulo the element width by the interpreter.
    X86PackedRotate {
        dst: VReg,
        src: VReg,
        count: Option<VReg>,
        mask: Option<VReg>,
        amount: u8,
        width: VecWidth,
        elem: VecElementType,
        left: bool,
        zeroing: bool,
    },

    /// AMD XOP VPROT*/VPSHL*/VPSHA*. `count` is either a vector whose low byte
    /// in each corresponding element is interpreted as signed i8, or an
    /// immediate byte applied to every element. Counts are reduced modulo the
    /// element width after extracting their sign. The operation is fixed to
    /// V128 and clears every destination bit above bit 127.
    X86XopPackedBit {
        dst: VReg,
        src: VReg,
        count: SrcOperand,
        elem: VecElementType,
        kind: X86XopPackedBitKind,
    },

    /// EVEX VPTERNLOGD/Q. For every bit, `(src1, src2, src3)` forms a
    /// three-bit index into `imm`; bit 0 of `imm` selects index 000 and bit 7
    /// selects 111. The architectural destination is supplied as `src1`.
    X86TernaryLogic {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        mask: Option<VReg>,
        imm: u8,
        width: VecWidth,
        elem: VecElementType,
        zeroing: bool,
    },

    /// EVEX VPSHLD*/VPSHRD* packed funnel shift. At a zero reduced count the
    /// result is `src`; nonzero left shifts fill its low bits from the high
    /// bits of `fill`, while right shifts fill its high bits from the low bits
    /// of `fill`. Immediate forms use `amount`; variable forms use `count`.
    X86PackedFunnelShift {
        dst: VReg,
        src: VReg,
        fill: VReg,
        count: Option<VReg>,
        mask: Option<VReg>,
        amount: u8,
        width: VecWidth,
        elem: VecElementType,
        left: bool,
        zeroing: bool,
    },

    /// EVEX VPMULTISHIFTQB. Each control byte selects an eight-bit circular
    /// window from the corresponding 64-bit element of `source`.
    X86MultiShiftQB {
        dst: VReg,
        control: VReg,
        source: VReg,
        mask: Option<VReg>,
        width: VecWidth,
        zeroing: bool,
    },

    /// AVX10.2 media acceleration dot products
    /// VPDPBSSD/S, VPDPBSUD/S, VPDPBUUD/S (byte variants)
    /// VPDPWSUD/S, VPDPWUSD/S, VPDPWUUD/S (word variants)
    VDotProductExt {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        src_elem: VecElementType,
        acc_elem: VecElementType,
        width: VecWidth,
        /// src1 signedness: true=signed, false=unsigned
        src1_signed: bool,
        /// src2 signedness: true=signed, false=unsigned
        src2_signed: bool,
        saturate: bool,
    },

    // ========================================================================
    // FLAG OPERATIONS
    // ========================================================================
    /// Read flags to register
    ReadFlags {
        dst: VReg,
    },

    /// Write register to flags
    WriteFlags {
        src: VReg,
    },

    /// Set carry flag
    SetCF {
        value: bool,
    },

    /// Set direction flag (x86 CLD/STD)
    SetDF {
        value: bool,
    },

    /// Set alignment-check flag (x86 CLAC/STAC). The operation performs its
    /// mode/privilege validation before changing AC.
    SetAC {
        value: bool,
    },

    /// Require x86 APX to be enabled before the remainder of the guest
    /// instruction may execute. The strict x86 lifter emits this guard when a
    /// REX2 instruction's ordinary SMIR semantics do not retain prefix
    /// provenance. Failure requests #UD at `SmirOp::guest_pc`.
    X86RequireApx,

    /// Require the AMD SSE4A feature and architectural SSE execution state.
    /// Failure deoptimizes at `SmirOp::guest_pc` so the direct path can deliver
    /// the precise #UD or #NM without committing the following operation.
    X86RequireSse4a,

    /// Require AMD TBM in protected, non-virtual-8086 64-bit mode before the
    /// remainder of the XOP instruction may execute. Architectural TBM also
    /// exists in 32-bit protected/compatibility mode, where XOP.W is ignored
    /// and address-size defaults differ; the strict x86-64 lifter therefore
    /// deoptimizes those modes to direct execution at `SmirOp::guest_pc`.
    /// Failure occurs before any following memory address calculation or load
    /// can fault.
    X86RequireTbm,

    /// Require AMD XOP in protected, non-virtual-8086 64-bit mode with
    /// CR4.OSXSAVE=1 and XCR0[2:1]=11b. CR0.TS is checked after every #UD
    /// condition and before address generation or memory access. Failure
    /// requests exact direct replay at `SmirOp::guest_pc`.
    X86RequireXop,

    /// AMD SSE4A EXTRQ/INSERTQ over the low 64 bits of XMM registers. A pair of
    /// immediate controls is represented by `Some(length), Some(index)`, both
    /// already truncated to six bits. `None, None` selects register controls:
    /// EXTRQ reads them from source bits 13:8 and 5:0, while INSERTQ reads them
    /// from source bits 77:72 and 69:64. The upper destination qword is retained
    /// as a deterministic value permitted by AMD's undefined-result contract.
    X86Sse4aBitfield {
        dst: VReg,
        source: VReg,
        kind: X86Sse4aBitfieldKind,
        length: Option<u8>,
        index: Option<u8>,
    },

    /// AMD SSE4A MOVNTSS/MOVNTSD scalar non-temporal store. `src` is the
    /// architectural XMM register and only its low 32 or 64 bits are written.
    /// The non-temporal cache hint is architectural provenance; SMIR memory
    /// backends that do not model cacheability perform an ordinary store.
    X86Sse4aMovntStore {
        src: VReg,
        addr: Address,
        width: MemWidth,
    },

    /// x86 CLI with architectural IOPL/VME/PVI routing. `requires_apx`
    /// records a REX2 encoding so execution can deliver #UD before privilege
    /// checks when APX is disabled. Native execution hands off at the exact
    /// `next_pc` after a successful control-flag update.
    X86Cli {
        requires_apx: bool,
        next_pc: GuestAddr,
    },

    /// x86 STI with architectural IOPL/VME/PVI/VIP routing. A successful IF
    /// transition from zero to one creates the one-instruction maskable-
    /// interrupt shadow. `requires_apx` records a REX2 encoding for #UD-before-
    /// privilege ordering; native execution exits at the exact `next_pc` so
    /// the shadowed instruction is retired by the boundary-aware direct path.
    X86Sti {
        requires_apx: bool,
        next_pc: GuestAddr,
    },

    /// Complement carry flag
    CmcCF,

    /// Force flag materialization
    MaterializeFlags,

    /// XTEST under the x86 execution profile with no active transaction.
    /// Sets ZF and clears CF, PF, AF, SF, and OF while preserving every other
    /// modeled RFLAGS field.
    X86XTest,

    /// x86 LDMXCSR/VLDMXCSR: load the 32-bit SIMD control/status register.
    /// `requires_apx` records a legacy REX2 encoding so #UD precedes the
    /// memory access when APX is disabled. Native execution leaves at the
    /// exact `next_pc` after a successful, reserved-bit-validated commit.
    X86LoadMxcsr {
        addr: Address,
        requires_apx: bool,
        next_pc: GuestAddr,
    },

    /// x86 STMXCSR/VSTMXCSR: store the 32-bit SIMD control/status register.
    /// `requires_apx` records a legacy REX2 encoding so #UD precedes CR0.TS
    /// and the memory access when APX is disabled.
    X86StoreMxcsr {
        addr: Address,
        requires_apx: bool,
    },

    /// x87 environment/control operation. Memory forms carry `Some(addr)`;
    /// register-only FNINIT/FNCLEX/FNSTSW AX/EMMS forms carry `None`.
    X86X87Control {
        kind: X86X87ControlKind,
        addr: Option<Address>,
    },

    /// x87 data-stack operation, conversion, arithmetic, or transcendental.
    /// Memory forms carry an address; register forms select logical `ST(st)`.
    /// `fop` is the 11-bit opcode recorded in the architectural environment.
    X86X87Data {
        kind: X86X87DataKind,
        addr: Option<Address>,
        st: u8,
        fop: u16,
    },

    /// FXSAVE/FXSAVE64: save the 512-byte legacy x87/SSE state image.
    X86FxSave {
        addr: Address,
        rex_w: bool,
    },

    /// FXRSTOR/FXRSTOR64: restore the 512-byte legacy x87/SSE state image.
    X86FxRstor {
        addr: Address,
        rex_w: bool,
    },

    /// XSAVE-family save selected by EDX:EAX and the enabled XCR0/IA32_XSS
    /// state appropriate to `kind`.
    X86XSave {
        addr: Address,
        rex_w: bool,
        kind: X86XSaveKind,
        src_low: VReg,
        src_high: VReg,
    },

    /// XRSTOR/XRSTORS restore. XRSTOR accepts standard or compacted images;
    /// XRSTORS (`supervisor`) requires a compacted image.
    X86XRstor {
        addr: Address,
        rex_w: bool,
        supervisor: bool,
        src_low: VReg,
        src_high: VReg,
    },

    /// CMPXCHG8B/CMPXCHG16B implicit-register memory transaction.
    X86Cmpxchg8b16b {
        addr: Address,
        wide: bool,
        locked: bool,
        compare_lo: VReg,
        compare_hi: VReg,
        new_lo: VReg,
        new_hi: VReg,
        dst_lo: VReg,
        dst_hi: VReg,
    },

    /// VEX-encoded AVX-512 mask-register arithmetic, logic, movement, unpack,
    /// immediate shift, and flag-only tests. The structured payload preserves
    /// architectural K-register identity and fault-precise KMOV memory forms.
    X86Opmask(X86OpmaskOp),

    /// RDRAND/RDSEED hardware nondeterministic value request.
    X86Random {
        dst: VReg,
        width: OpWidth,
        seed: bool,
    },

    /// RDPID: read IA32_TSC_AUX into a GPR without changing flags.
    X86ReadPid {
        dst: VReg,
    },

    /// XGETBV: read XCR0 or the init-optimization bitmap selected by ECX.
    X86XGetBv {
        dst_low: VReg,
        dst_high: VReg,
        selector: VReg,
    },

    /// XSETBV: update XCR0 from EDX:EAX using the selector in ECX.
    X86XSetBv {
        selector: VReg,
        src_low: VReg,
        src_high: VReg,
    },

    /// CLTS: clear CR0.TS after the real-mode/CPL privilege check. CR0 is
    /// architecture context rather than a scalar VReg, so this operation has
    /// no explicit operands but is stateful and potentially faulting.
    X86Clts,

    /// INVD/WBINVD/WBNOINVD retain their dynamic privilege fault and ordering
    /// boundary. Native execution resumes at next_pc after a permitted operation.
    X86CacheMaintenance {
        kind: X86CacheMaintenanceKind,
        next_pc: u64,
    },

    /// RDMSR/WRMSR. Selector, values, and destinations are the fixed implicit
    /// ECX/EDX:EAX registers; privilege and MSR-specific validation remain
    /// dynamic and fault before any destination or MSR state commits.
    X86Msr(X86MsrOp),

    /// `MOV r64, CR0/CR2/CR3/CR4/CR8`. The selected control register is
    /// implicit architecture state; `dst` is the encoded 64-bit GPR. The
    /// operation performs its dynamic real-mode/CPL check and is retained as
    /// side-effecting because it can fault and CR0/2/3/4 reads are serializing.
    X86ReadControl {
        dst: VReg,
        control: X86ControlReg,
    },

    /// SMSW reads implicit CR0 after APX/UMIP validation, then either writes a
    /// width-specific GPR destination or stores CR0[15:0] as exactly 2 bytes.
    /// The operation remains side-effecting when its result is dead because it
    /// can raise #UD/#GP(0), and a memory target can fault or reach MMIO.
    X86Smsw(X86SmswOp),

    /// Selector stores expose LDTR/TR for SLDT/STR or ES/CS/SS/DS/FS/GS for
    /// MOV r/m,Sreg. Register destinations use the encoded 16-/32-/64-bit
    /// width; memory destinations store exactly 2 bytes.
    X86SystemSelectorStore(X86SystemSelectorStoreOp),

    /// LLDT/LTR, `MOV Sreg,r/m`, and `POP FS/GS` load one visible selector plus
    /// its hidden cache. Descriptor side effects, selector commit, and any POP
    /// stack-pointer increment remain one fault-precise operation that
    /// terminates native execution at `next_pc`.
    X86SystemSelectorLoad(X86SystemSelectorLoadOp),

    /// VERR/VERW verify a fixed-width selector source and update only ZF.
    /// Selector/type/privilege failures are non-faulting; source and implicit
    /// descriptor-table reads retain their architectural fault behavior.
    X86SelectorVerify(X86SelectorVerifyOp),

    /// LAR/LSL query a fixed-width selector source, conditionally update one
    /// 16-/32-/64-bit GPR destination, and update only ZF. The source plus
    /// implicit 8-/16-byte descriptor reads remain one fault-precise op.
    X86SelectorQuery(X86SelectorQueryOp),

    /// `FF /5` indirect far JMP. The memory far pointer selects a code segment
    /// or IA-32e call gate; all descriptor effects precede one CS:RIP commit.
    X86FarJump(X86FarJumpOp),

    /// `FF /3` indirect far CALL. The operation owns pointer/descriptor/TSS
    /// reads, the complete return frame, and the terminal CS:RIP:RSP[:SS]
    /// commit so no generic load or near-CALL lowering can split its faults.
    X86FarCall(X86FarCallOp),

    /// `CA`/`CB` far RET. The operation owns stack/descriptor reads, optional
    /// outer-stack restoration, segment invalidation, and its terminal branch.
    X86FarReturn(X86FarReturnOp),

    /// Intel SYSENTER/SYSEXIT. Dynamic mode, privilege, selector, and
    /// canonicality checks precede one atomic RIP:RSP:CS:SS:CPL[:RFLAGS]
    /// transition. The operation owns its terminal indirect branch.
    X86FastSystemTransfer(X86FastSystemTransferOp),

    /// LMSW reads a fixed-width register or memory source after APX/CPL
    /// validation, updates CR0[3:0] without clearing PE, and is serializing.
    /// Native execution must hand off at `next_pc` after a successful commit.
    X86Lmsw(X86LmswOp),

    /// SGDT/SIDT store the selected implicit descriptor-table register as one
    /// fault-precise 10-byte long-mode memory transfer. The operation remains
    /// side-effecting because APX/UMIP validation and the memory write can
    /// fault even when the resulting bytes are otherwise unobserved.
    X86DescriptorTableStore(X86DescriptorTableStoreOp),

    /// LGDT/LIDT load the selected implicit descriptor-table register from one
    /// fault-precise 10-byte long-mode memory transfer. The operation remains
    /// side-effecting even when the implicit state is not consumed in the same
    /// block because it can fault and changes subsequent descriptor semantics.
    X86DescriptorTableLoad(X86DescriptorTableLoadOp),

    /// `INVLPG m` invalidates cached translations for the page containing its
    /// effective linear address. The operand performs no memory access. APX and
    /// CPL failures are non-committing, and a non-canonical 64-bit address is a
    /// successful no-op. Native execution hands off at `next_pc` after success.
    X86Invlpg(X86InvlpgOp),

    /// `INVPCID r64,m128` atomically owns APX/privilege validation, the complete
    /// descriptor read, descriptor-value checks, and translation invalidation.
    /// Native execution hands off at `next_pc` after a successful cache flush.
    X86Invpcid(X86InvpcidOp),

    /// `MOV CR0/CR2/CR3/CR4/CR8, r64`. Dynamic CPL, reserved-bit, PCID, and
    /// IA-32e transition checks are non-committing. `next_pc` is the exact
    /// post-instruction frontier: a successful native write must terminate its
    /// region because paging and instruction-admission state may have changed.
    X86WriteControl {
        src: VReg,
        control: X86ControlReg,
        next_pc: u64,
    },

    /// `MOV r64, DR0-DR7`. The selector remains encoded so DR4/DR5 can
    /// dynamically alias DR6/DR7 or fault according to CR4.DE. DR7.GD can
    /// raise a fault-class #DB before the destination commits. The six status
    /// flags are architecturally undefined; SMIR deterministically preserves
    /// them to match the direct implementation.
    X86ReadDebug {
        dst: VReg,
        debug: X86DebugReg,
    },

    /// `MOV DR0-DR7, r64`. The encoded selector retains dynamic DR4/DR5
    /// aliasing and CR4.DE invalidity. DR7.GD can fault before the write;
    /// effective DR6/DR7 reject nonzero source bits 63:32. A successful write
    /// is serializing. The six undefined status flags are deterministically
    /// preserved to match the direct implementation.
    X86WriteDebug {
        src: VReg,
        debug: X86DebugReg,
    },

    /// RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE. `operand` is the encoded GPR and
    /// `base` is exactly FS.base or GS.base. A read writes `operand` from
    /// `base`; a write commits `operand` to `base`. The operation performs its
    /// architectural CR4.FSGSBASE/APX checks and may therefore fault even when
    /// its data destination is dead.
    X86FsGsBase {
        operand: VReg,
        base: VReg,
        write: bool,
        width: OpWidth,
        requires_apx: bool,
    },

    /// SWAPGS atomically exchanges GS.base and IA32_KERNEL_GS_BASE after its
    /// architectural long-mode and CPL checks. Both state operands are
    /// explicit so liveness, interpretation, and native handoff agree.
    X86SwapGs {
        gs_base: VReg,
        kernel_gs_base: VReg,
    },

    X86MonitorMwait(X86MonitorMwaitOp),

    /// UMONITOR/UMWAIT/TPAUSE user-mode monitor and deterministic wait.
    X86WaitPkg(X86WaitPkgOp),

    /// RDPKRU/WRPKRU. The implicit GPR and PKRU operands are explicit so
    /// liveness, static analysis, interpretation, and native state handoff all
    /// observe the same architectural data flow. Dynamic CR4.PKE and selector
    /// checks may fault before any destination is committed.
    X86Pkru {
        eax: VReg,
        ecx: VReg,
        edx: VReg,
        pkru: VReg,
        write: bool,
    },

    /// Test condition and store result
    TestCondition {
        dst: VReg,
        cond: Condition,
    },

    /// Conditional set: dst = cond ? 1 : 0
    SetCC {
        dst: VReg,
        cond: Condition,
        width: OpWidth,
    },

    // ========================================================================
    // SYSTEM / PRIVILEGED
    // ========================================================================
    /// System call
    Syscall {
        num: VReg,
        args: Vec<VReg>,
    },

    /// Software interrupt
    Swi {
        imm: u32,
    },

    /// Read system register
    ReadSysReg {
        dst: VReg,
        reg: u32,
    },

    /// Write system register
    WriteSysReg {
        reg: u32,
        src: VReg,
    },

    /// x86 RDTSC/RDTSCP read of the monotonically increasing guest timestamp
    /// counter, with an optional IA32_TSC_AUX destination for RDTSCP.
    X86ReadTsc(X86ReadTscOp),

    /// x86 RDPMC read of a deterministic model-specific performance counter.
    /// The selector remains explicit because invalid runtime values raise
    /// #GP(0) before either destination commits.
    X86ReadPmc(X86ReadPmcOp),

    /// x86 CPUID: evaluate the emulator's guest CPU profile using EAX/ECX and
    /// commit zero-extended EAX, EBX, ECX, and EDX results atomically. The
    /// profile itself is runtime architectural/configuration state rather than
    /// an IR constant, so all four destinations and both query inputs remain
    /// explicit while the interpreter/native helper reads the profile state.
    X86Cpuid {
        dst_eax: VReg,
        dst_ebx: VReg,
        dst_ecx: VReg,
        dst_edx: VReg,
        leaf: VReg,
        subleaf: VReg,
    },

    // ========================================================================
    // HEXAGON SCALAR FLOATING POINT (F2_*)
    // ========================================================================
    /// Hexagon scalar FP operation, computed bit-exactly against the
    /// `qemu-hexagon` reference semantics (`sem/float.rs` / `sem/float_ext.rs`):
    /// native f32/f64 arithmetic plus Hexagon's default-NaN canonicalisation
    /// (all-ones), signed-zero min/max tie rules, and the int/float conversion
    /// special cases. `src1`/`src2` carry the raw operand bits (f32 in the low
    /// 32 bits, f64 in 64; conversion operands are raw ints). `dst` receives the
    /// raw result bits (a GPR/pair value, or a 0x00/0xff Hexagon predicate byte
    /// for the compare/classify forms). `src2` is ignored for the unary ops.
    ///
    /// Self-contained: the whole computation lives in the interp arm so it does
    /// NOT depend on (or perturb) the generic `FAdd`/`FCmp`/... ops shared with
    /// the other architectures.
    HexFp {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        op: HexFpOp,
    },

    /// Hexagon single-precision fused multiply-add `Rx {+,-}= Rs*Rt` (single
    /// IEEE rounding, native `f32::mul_add` + default-NaN canonicalisation).
    /// `src1`=Rs, `src2`=Rt, `src3`=Rx (accumulator). Matches the F2_sffma /
    /// F2_sffms reference result bits (the harness ignores the FP exception
    /// flags). Self-contained, like [`OpKind::HexFp`].
    HexFp3 {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        /// true => negate the product (sffms: `Rx - Rs*Rt`).
        negate_product: bool,
        /// true => the `:lib` form (F2_sffma_lib / F2_sffms_lib): an EXACT
        /// single-rounding fma with ties-AWAY rounding of subnormal results plus
        /// the Hexagon post-fixups (spurious-overflow inf backed off to
        /// max-finite, inf-minus-inf flushed to +0, true-zero accumulator sign
        /// preserved). Computed via the exact integer fma core, NOT native
        /// `f32::mul_add` — native ties-to-even would diverge on subnormal ties.
        lib: bool,
    },

    /// Hexagon reciprocal / inverse-sqrt seed + fixup family (F2_sfrecipa,
    /// F2_sfinvsqrta, F2_sffixupn/d/r). A byte-for-byte port of QEMU's
    /// `arch_sf_recip_common` / `arch_sf_invsqrt_common` (the extreme-exponent
    /// `scalbn` adjusts, special-case canonicalisation, the 128-entry seed
    /// tables, and the multi-bit `Pe` predicate). `src1`=Rs, `src2`=Rt (Rt is
    /// ignored by the invsqrt/`sffixupr` kinds). `dst` receives the raw f32
    /// result bits; `pred`, when `Some`, receives the FULL Hexagon predicate
    /// byte `Pe` (the seed ops produce both Rd and Pe; the fixup ops produce
    /// only Rd). Self-contained, like [`OpKind::HexFp`]; NOT JIT-whitelisted.
    HexFpRecip {
        dst: VReg,
        /// Predicate `Pe` output (sfrecipa/sfinvsqrta); `None` for the fixups.
        pred: Option<VReg>,
        src1: VReg,
        src2: VReg,
        kind: HexFpRecipKind,
    },

    /// Hexagon double-precision high-half multiply / fixup family
    /// (F2_dfmpyhh / F2_dfmpyfix). An EXACT 64-bit-mantissa rounding core
    /// (`hr_round_exact_to_f64`, the f64 analog of `hr_round_exact_to_f32`) is
    /// required because native `f64` arithmetic double-rounds. `src1`/`src2`
    /// carry the raw f64 bit patterns (64-bit register pairs); `src3` is the
    /// read-modify accumulator `Rxx` for dfmpyhh (ignored by dfmpyfix). `dst`
    /// receives the raw 64-bit result. Self-contained, like [`OpKind::HexFp`].
    HexFpDf {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        op: HexDfOp,
    },

    /// Hexagon single-precision scaled fused multiply-add `Rx += Rs*Rt` then
    /// `* 2^Pu` (F2_sffma_sc). `Pu` is a two's-complement (signed-8) scale folded
    /// into the EXACT product before the single rounding, so the exact integer
    /// fma core (`hr_sf_fma`) carries it — native `f32::mul_add` then scale would
    /// double-round. `src1`=Rs, `src2`=Rt, `src3`=Rx accumulator, `scale` holds
    /// the raw `Pu` predicate byte (interpreted as i8). Self-contained.
    HexFpScFma {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        /// VReg holding the raw `Pu` predicate byte (read as a signed-8 scale).
        scale: VReg,
    },

    /// Hexagon CABAC binary arithmetic decode (S2_cabacdecbin):
    /// `Rdd = decbin(Rss,Rtt)` plus `P0`. A PURE FUNCTION of the register inputs
    /// (`src1`=Rss={range,offset}, `src2`=Rtt={state,...}) and the constant
    /// H.264 transition tables (no hidden global state). `dst` receives the raw
    /// 64-bit `Rdd` pair; `pred` receives the `P0` predicate byte. Self-contained.
    HexCabacDecBin {
        dst: VReg,
        pred: VReg,
        src1: VReg,
        src2: VReg,
    },

    /// Hexagon TLB-entry match (A4_tlbmatch): `Pd = tlbmatch(Rss,Rt)`. A PURE
    /// FUNCTION of the register inputs — the "TLB entry" being matched IS the
    /// seeded register pair `Rss` (`src1`), NOT hidden TLB state — so it is fully
    /// reproducible. `src2`=Rt; `dst` receives the 0x00/0xff predicate byte.
    HexTlbMatch {
        dst: VReg,
        src1: VReg,
        src2: VReg,
    },

    // ========================================================================
    // RISC-V SCALAR FLOATING POINT (OP-FP / FMA)
    // ========================================================================
    /// RISC-V scalar OP-FP / FMA instruction, computed bit-exactly via the same
    /// soft-float primitives as the qemu-verified `RiscVCpu` interpreter
    /// (`crate::isa::riscv::float::eval_scalar_fp`). Covers arithmetic, FMA, min/max,
    /// compares, round, and every int/float/half conversion — i.e. all the FP ops
    /// whose result depends on `fflags`, NaN canonicalisation, or the dynamic
    /// rounding mode (`frm`), which the generic native-`f64` `FAdd`/`FMul`/… ops
    /// cannot reproduce.
    ///
    /// `src1`/`src2`/`src3` carry raw operand register values (f-register bits, or
    /// the x-register value in `src1` for int->fp / `fmv.*.x`; `src2`/`src3`
    /// unused for unary ops). `fcsr_src` is the current `fcsr`. `dst` receives the
    /// raw result (NaN-boxed for an f-register destination, or the integer result
    /// for compares / fp->int / `fcvtmod`); `fcsr_dst` receives `fcsr` with this
    /// op's exception flags accrued. `op` is the RISC-V opcode and `rm_field` the
    /// instruction's 3-bit rounding-mode field (resolved against `frm` for `Dyn`).
    /// `xlen` is 32 or 64 and canonicalizes integer destinations to the guest
    /// register width after the architectural 32-bit sign-extension rule.
    /// Self-contained, like [`OpKind::HexFp`]. The state-backed
    /// RISC-V-to-x86-64 lowerer executes this through an explicit pure helper
    /// ABI and traps before committing either destination if the helper reports
    /// an illegal static or dynamic rounding mode.
    RvFp {
        dst: VReg,
        fcsr_dst: VReg,
        src1: VReg,
        src2: VReg,
        src3: VReg,
        fcsr_src: VReg,
        op: crate::isa::riscv::Op,
        rm_field: u8,
        xlen: u8,
    },

    /// RISC-V scalar bit-manip / crypto op with no clean SMIR primitive:
    /// carry-less multiply (Zbc `clmul`/`clmulh`/`clmulr`), crossbar permute
    /// (Zbkx `xperm4`/`xperm8`), RV32 SHA-512 pair helpers, and the AES / SM4
    /// round and key-schedule helpers (Zkn*/Zks*), computed bit-exactly via
    /// `crate::isa::riscv::crypto::eval_int_crypto` — the same qemu-verified
    /// primitives the `RiscVCpu` interpreter uses (S-box tables, GF(2^8)
    /// MixColumns, crossbar gather), which would need 256-entry table lookups to
    /// express as plain SMIR. `src1`=rs1, `src2`=rs2 (ignored by the unary
    /// `aes64im`/`aes64ks1i`); `imm` carries the SM4/AES32 `bs` or
    /// `aes64ks1i` round number. `dst` receives the rd value. Self-contained like
    /// [`OpKind::RvFp`]. The state-backed RISC-V-to-x86-64 lowerer executes this
    /// operation through an explicit pure helper ABI.
    RvIntCrypto {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        op: crate::isa::riscv::Op,
        imm: u8,
        xlen: u8,
    },

    /// RISC-V Vector (RVV 1.0) instruction, executed bit-exactly by the verified
    /// vector engine of `RiscVCpu`. The element width and element count are
    /// runtime state (`vtype`/`vl`) unknown at lift time, so RVV cannot be lifted
    /// to static SMIR primitives; instead the interp loads the SMIR machine state
    /// (x/f/fcsr + the `RiscVRegState` vector file + vl/vtype/vstart/vcsr) into a
    /// transient `RiscVCpu` over a memory bridge to the SMIR memory, runs this one
    /// decoded instruction, and reads the full result state back. `insn` is the
    /// raw 32-bit encoding; `xlen` is 32 or 64; `rs1`/`rs2` are retained for
    /// compact oracle/debug output, while `state` carries the full scalar/CSR
    /// SSA snapshot. Vector results still live in the architectural vector
    /// state; scalar/CSR results are also written through the recorded
    /// destination VRegs. The x86-64 cross-lowerer implements the same boundary
    /// through the state ABI's transactional vector helper.
    RvVector {
        insn: u32,
        xlen: u8,
        rs1: VReg,
        rs2: VReg,
        state: Box<RvVectorState>,
    },

    // ========================================================================
    // META / DEBUG
    // ========================================================================
    /// No-op
    Nop,

    /// Undefined instruction (trap on execution)
    Undefined {
        opcode: u32,
    },

    /// Debug breakpoint
    Breakpoint,
}

/// Hexagon scalar floating-point sub-operation for [`OpKind::HexFp`]. Each
/// variant mirrors a `F2_*` opcode's reference semantics exactly (result bits
/// only — the harness compares result + USR:OVF, not the FP exception flags).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexFpOp {
    // --- compares -> predicate byte (0x00 / 0xff) ---
    SfCmpEq,
    SfCmpGt,
    SfCmpGe,
    SfCmpUo,
    DfCmpEq,
    DfCmpGt,
    DfCmpGe,
    DfCmpUo,
    // --- classify -> predicate byte (src2 = class-mask immediate bits) ---
    SfClass,
    DfClass,
    // --- min / max (operand bits returned; signed-zero + NaN tie rules) ---
    SfMin,
    SfMax,
    DfMin,
    DfMax,
    // --- arithmetic (native round-to-nearest result + default-NaN) ---
    SfAdd,
    SfSub,
    SfMpy,
    DfAdd,
    DfSub,
    // --- conversions ---
    /// f64 -> f32 narrowing
    ConvDf2Sf,
    /// f32 -> f64 widening
    ConvSf2Df,
    /// signed/unsigned int (W/D) -> f32/f64; encoded by the variant below
    ConvW2Sf,
    ConvUw2Sf,
    ConvD2Sf,
    ConvUd2Sf,
    ConvW2Df,
    ConvUw2Df,
    ConvD2Df,
    ConvUd2Df,
    /// f32 -> signed/unsigned int, round-to-nearest-even (base) or chop
    ConvSf2W,
    ConvSf2WChop,
    ConvSf2Uw,
    ConvSf2UwChop,
    ConvSf2D,
    ConvSf2DChop,
    ConvSf2Ud,
    ConvSf2UdChop,
    /// f64 -> signed/unsigned int
    ConvDf2W,
    ConvDf2WChop,
    ConvDf2Uw,
    ConvDf2UwChop,
    ConvDf2D,
    ConvDf2DChop,
    ConvDf2Ud,
    ConvDf2UdChop,
}

/// Reciprocal / inverse-sqrt seed + fixup sub-operation for
/// [`OpKind::HexFpRecip`]. Each variant maps to one `F2_*` opcode and selects
/// which value the byte-for-byte port of `arch_sf_recip_common` /
/// `arch_sf_invsqrt_common` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexFpRecipKind {
    /// `Rd,Pe = sfrecipa(Rs,Rt)`: reciprocal seed of Rt (writes Rd + Pe).
    SfRecipa,
    /// `Rd,Pe = sfinvsqrta(Rs)`: inverse-sqrt seed of Rs (writes Rd + Pe).
    SfInvSqrtA,
    /// `Rd = sffixupn(Rs,Rt)`: recip_common's adjusted numerator (Rs).
    SfFixupN,
    /// `Rd = sffixupd(Rs,Rt)`: recip_common's adjusted denominator (Rt).
    SfFixupD,
    /// `Rd = sffixupr(Rs)`: invsqrt_common's adjusted radicand (Rs).
    SfFixupR,
}

/// Double-precision high-half multiply / fixup sub-operation for
/// [`OpKind::HexFpDf`]. Each variant maps to one `F2_*` opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexDfOp {
    /// `Rxx += dfmpyhh(Rss,Rtt)`: high-32-bit-mantissa multiply + fixed-weight
    /// accumulate of `Rxx`, rounded once to nearest-even.
    DfMpyHh,
    /// `Rdd = dfmpyfix(Rss,Rtt)`: conditional exact `2^±52` denormal fixup.
    DfMpyFix,
}

mod metadata;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_fp16_fma_metadata_tracks_sources_mask_destination_and_mxcsr_effects() {
        let dst = VReg::virt(0);
        let src1 = VReg::virt(1);
        let src2 = VReg::virt(2);
        let src3 = VReg::virt(3);
        let mask = VReg::virt(4);
        let dynamic = OpKind::X86FP16Fma {
            dst,
            src1,
            src2,
            src3,
            mask: Some(mask),
            kind: X86FmaKind::Add,
            order: X86FmaOrder::Order132,
            round: FpRoundMode::Dynamic,
            lanes: 8,
        };
        assert_eq!(dynamic.dests(), vec![dst]);
        assert_eq!(dynamic.source_vregs(), vec![src1, src2, src3, mask]);
        assert!(dynamic.has_side_effects());

        let embedded = OpKind::X86FP16Fma {
            dst,
            src1,
            src2,
            src3,
            mask: Some(mask),
            kind: X86FmaKind::Add,
            order: X86FmaOrder::Order132,
            round: FpRoundMode::RoundNearest,
            lanes: 8,
        };
        assert!(!embedded.has_side_effects());
    }

    #[test]
    fn x86_fp16_complex_metadata_tracks_accumulator_merge_mask_and_mxcsr_status() {
        let dst = VReg::virt(0);
        let src1 = VReg::virt(1);
        let src2 = VReg::virt(2);
        let mask = VReg::virt(3);
        let accumulate = OpKind::X86FP16Complex {
            dst,
            src1,
            src2,
            mask: Some(mask),
            width: VecWidth::V512,
            pairs: 16,
            scalar: false,
            mask_zeroing: true,
            accumulate: true,
            conjugate: false,
            round: FpRoundMode::Dynamic,
        };
        assert_eq!(accumulate.dests(), vec![dst]);
        assert_eq!(accumulate.source_vregs(), vec![src1, src2, mask, dst]);
        assert!(accumulate.has_side_effects());

        let merge = OpKind::X86FP16Complex {
            dst,
            src1,
            src2,
            mask: Some(mask),
            width: VecWidth::V128,
            pairs: 1,
            scalar: true,
            mask_zeroing: false,
            accumulate: false,
            conjugate: true,
            round: FpRoundMode::RoundNearest,
        };
        assert_eq!(merge.source_vregs(), vec![src1, src2, mask, dst]);
        assert!(!merge.has_side_effects());

        let overwrite = OpKind::X86FP16Complex {
            dst,
            src1,
            src2,
            mask: None,
            width: VecWidth::V128,
            pairs: 4,
            scalar: false,
            mask_zeroing: false,
            accumulate: false,
            conjugate: false,
            round: FpRoundMode::RoundNearest,
        };
        assert_eq!(overwrite.source_vregs(), vec![src1, src2]);
        assert!(!overwrite.has_side_effects());
    }

    #[test]
    fn x86_four_iteration_metadata_tracks_sources_accumulators_masks_and_side_effects() {
        let dst = VReg::virt(0);
        let src0 = VReg::virt(1);
        let src1 = VReg::virt(2);
        let src2 = VReg::virt(3);
        let src3 = VReg::virt(4);
        let mem = VReg::virt(5);
        let mask = VReg::virt(6);
        let op = OpKind::X86FourFma {
            dst,
            src0,
            src1,
            src2,
            src3,
            mem,
            mask: Some(mask),
            scalar: false,
            negate_product: false,
            mask_zeroing: true,
        };
        assert_eq!(op.dests(), vec![dst]);
        assert_eq!(
            op.source_vregs(),
            vec![dst, src0, src1, src2, src3, mem, mask]
        );
        assert!(op.has_side_effects());

        let base = VReg::virt(7);
        let predicated_tuple = OpKind::PredVLoad {
            dst: mem,
            cond: mask,
            addr: Address::reg(base),
            width: VecWidth::V128,
        };
        assert_eq!(predicated_tuple.dests(), vec![mem]);
        assert_eq!(predicated_tuple.source_vregs(), vec![mem, mask, base]);
        assert!(predicated_tuple.reads_memory());
        assert!(predicated_tuple.has_side_effects());

        let dot = OpKind::X86FourDotProduct {
            dst,
            src0,
            src1,
            src2,
            src3,
            mem,
            mask: Some(mask),
            saturating: true,
            mask_zeroing: false,
        };
        assert_eq!(dot.dests(), vec![dst]);
        assert_eq!(
            dot.source_vregs(),
            vec![dst, src0, src1, src2, src3, mem, mask]
        );
        assert!(!dot.reads_memory());
        assert!(!dot.has_side_effects());
    }

    #[test]
    fn cas_pair_metadata_tracks_all_results_and_memory_effects() {
        let op = OpKind::CasPair {
            dst_lo: VReg::virt(0),
            dst_hi: VReg::virt(1),
            success: VReg::virt(2),
            addr: Address::Direct(VReg::virt(3)),
            expected_lo: VReg::virt(4),
            expected_hi: VReg::virt(5),
            new_lo: VReg::virt(6),
            new_hi: VReg::virt(7),
            order: MemoryOrder::SeqCst,
            failure_order: MemoryOrder::Acquire,
        };

        assert_eq!(
            op.dests(),
            vec![VReg::virt(0), VReg::virt(1), VReg::virt(2)]
        );
        assert_eq!(
            op.source_vregs(),
            vec![
                VReg::virt(3),
                VReg::virt(4),
                VReg::virt(5),
                VReg::virt(6),
                VReg::virt(7),
            ]
        );
        assert!(op.reads_memory());
        assert!(op.writes_memory());
        assert!(op.has_side_effects());
    }

    #[test]
    fn x86_x87_control_metadata_tracks_hidden_state_and_memory_effects() {
        let rbx = VReg::Arch(ArchReg::X86(X86Reg::Rbx));
        let init = OpKind::X86X87Control {
            kind: X86X87ControlKind::Init,
            addr: None,
        };
        assert!(init.has_side_effects());
        assert!(init.dests().is_empty());
        assert!(init.is_jit_safe());

        let clear = OpKind::X86X87Control {
            kind: X86X87ControlKind::ClearExceptions,
            addr: None,
        };
        assert!(clear.has_side_effects());
        assert!(clear.dests().is_empty());
        assert!(clear.is_jit_safe());

        let enter_mmx = OpKind::X86X87Control {
            kind: X86X87ControlKind::EnterMmx,
            addr: None,
        };
        assert!(enter_mmx.has_side_effects());
        assert!(enter_mmx.dests().is_empty());
        assert!(!enter_mmx.reads_memory());
        assert!(!enter_mmx.writes_memory());
        assert!(enter_mmx.is_jit_safe());

        let empty_mmx = OpKind::X86X87Control {
            kind: X86X87ControlKind::EmptyMmx,
            addr: None,
        };
        assert!(empty_mmx.has_side_effects());
        assert!(empty_mmx.dests().is_empty());
        assert!(!empty_mmx.reads_memory());
        assert!(!empty_mmx.writes_memory());
        assert!(empty_mmx.is_jit_safe());

        let status_ax = OpKind::X86X87Control {
            kind: X86X87ControlKind::StoreStatusAx,
            addr: None,
        };
        assert_eq!(
            status_ax.dests(),
            vec![VReg::Arch(ArchReg::X86(X86Reg::Rax))]
        );
        assert!(!status_ax.reads_memory());
        assert!(!status_ax.writes_memory());
        assert!(status_ax.is_jit_safe());

        let load = OpKind::X86X87Control {
            kind: X86X87ControlKind::LoadControlWord,
            addr: Some(Address::Direct(rbx)),
        };
        assert!(load.reads_memory());
        assert!(!load.writes_memory());
        assert!(load.has_side_effects());

        for kind in [
            X86X87ControlKind::LoadEnvironment(X86X87EnvWidth::W16),
            X86X87ControlKind::RestoreState(X86X87EnvWidth::W32),
        ] {
            let load = OpKind::X86X87Control {
                kind,
                addr: Some(Address::Direct(rbx)),
            };
            assert!(load.reads_memory());
            assert!(!load.writes_memory());
            assert!(load.has_side_effects());
            assert!(load.dests().is_empty());
        }

        for kind in [
            X86X87ControlKind::StoreControlWord,
            X86X87ControlKind::StoreStatusWord,
            X86X87ControlKind::StoreEnvironment(X86X87EnvWidth::W16),
            X86X87ControlKind::SaveState(X86X87EnvWidth::W32),
        ] {
            let store = OpKind::X86X87Control {
                kind,
                addr: Some(Address::Direct(rbx)),
            };
            assert!(!store.reads_memory());
            assert!(store.writes_memory());
            assert!(store.has_side_effects());
        }

        let load_extended = OpKind::X86X87Data {
            kind: X86X87DataKind::LoadExtended,
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0x328,
        };
        assert!(load_extended.reads_memory());
        assert!(!load_extended.writes_memory());
        assert!(load_extended.has_side_effects());
        assert!(load_extended.dests().is_empty());

        for kind in [
            X86X87DataKind::LoadSingle,
            X86X87DataKind::LoadDouble,
            X86X87DataKind::LoadInt16,
            X86X87DataKind::LoadInt32,
            X86X87DataKind::LoadInt64,
            X86X87DataKind::LoadBcd,
        ] {
            let load = OpKind::X86X87Data {
                kind,
                addr: Some(Address::Direct(rbx)),
                st: 0,
                fop: 0,
            };
            assert!(load.reads_memory());
            assert!(!load.writes_memory());
            assert!(load.has_side_effects());
        }

        let compare_memory = OpKind::X86X87Data {
            kind: X86X87DataKind::Compare {
                source: X86X87CompareSource::Double,
                unordered: false,
                pop: 1,
                eflags: false,
            },
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0,
        };
        assert!(compare_memory.reads_memory());
        assert!(!compare_memory.writes_memory());
        assert!(compare_memory.has_side_effects());

        let multiply_memory = OpKind::X86X87Data {
            kind: X86X87DataKind::Multiply {
                source: X86X87ArithmeticSource::Double,
                destination: X86X87ArithmeticDestination::St0,
                pop: false,
            },
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0,
        };
        assert!(multiply_memory.reads_memory());
        assert!(!multiply_memory.writes_memory());
        assert!(multiply_memory.has_side_effects());

        let add_memory = OpKind::X86X87Data {
            kind: X86X87DataKind::AddSubtract {
                source: X86X87ArithmeticSource::Int32,
                destination: X86X87ArithmeticDestination::St0,
                pop: false,
                subtract: false,
                reverse: false,
            },
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0,
        };
        assert!(add_memory.reads_memory());
        assert!(!add_memory.writes_memory());
        assert!(add_memory.has_side_effects());

        let divide_memory = OpKind::X86X87Data {
            kind: X86X87DataKind::Divide {
                source: X86X87ArithmeticSource::Single,
                destination: X86X87ArithmeticDestination::St0,
                pop: false,
                reverse: true,
            },
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0,
        };
        assert!(divide_memory.reads_memory());
        assert!(!divide_memory.writes_memory());
        assert!(divide_memory.has_side_effects());

        let store_extended = OpKind::X86X87Data {
            kind: X86X87DataKind::StorePopExtended,
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0x338,
        };
        assert!(!store_extended.reads_memory());
        assert!(store_extended.writes_memory());
        assert!(store_extended.has_side_effects());

        let store_integer = OpKind::X86X87Data {
            kind: X86X87DataKind::StoreInteger {
                width: X86X87IntWidth::I32,
                pop: true,
                truncate: false,
            },
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0x318,
        };
        assert!(!store_integer.reads_memory());
        assert!(store_integer.writes_memory());
        assert!(store_integer.has_side_effects());

        let store_float = OpKind::X86X87Data {
            kind: X86X87DataKind::StoreFloat {
                width: X86X87FloatWidth::F64,
                pop: true,
            },
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0x518,
        };
        assert!(!store_float.reads_memory());
        assert!(store_float.writes_memory());
        assert!(store_float.has_side_effects());

        let store_bcd = OpKind::X86X87Data {
            kind: X86X87DataKind::StoreBcd,
            addr: Some(Address::Direct(rbx)),
            st: 0,
            fop: 0x730,
        };
        assert!(!store_bcd.reads_memory());
        assert!(store_bcd.writes_memory());
        assert!(store_bcd.has_side_effects());

        for kind in [
            X86X87DataKind::LoadRegister,
            X86X87DataKind::StoreRegister,
            X86X87DataKind::StorePopRegister,
            X86X87DataKind::Exchange,
            X86X87DataKind::Free,
            X86X87DataKind::FreePop,
            X86X87DataKind::ChangeSign,
            X86X87DataKind::Absolute,
            X86X87DataKind::DecrementTop,
            X86X87DataKind::IncrementTop,
            X86X87DataKind::LoadConstant(X86X87Constant::Pi),
            X86X87DataKind::ConditionalMove(Condition::Eq),
            X86X87DataKind::Examine,
            X86X87DataKind::TestZero,
            X86X87DataKind::RoundInteger,
            X86X87DataKind::Extract,
            X86X87DataKind::Scale,
            X86X87DataKind::SquareRoot,
            X86X87DataKind::Multiply {
                source: X86X87ArithmeticSource::Register,
                destination: X86X87ArithmeticDestination::StI,
                pop: true,
            },
            X86X87DataKind::AddSubtract {
                source: X86X87ArithmeticSource::Register,
                destination: X86X87ArithmeticDestination::StI,
                pop: true,
                subtract: true,
                reverse: true,
            },
            X86X87DataKind::Divide {
                source: X86X87ArithmeticSource::Register,
                destination: X86X87ArithmeticDestination::StI,
                pop: true,
                reverse: false,
            },
            X86X87DataKind::Remainder { nearest: true },
            X86X87DataKind::Compare {
                source: X86X87CompareSource::Register,
                unordered: true,
                pop: 1,
                eflags: true,
            },
        ] {
            let register = OpKind::X86X87Data {
                kind,
                addr: None,
                st: 3,
                fop: 0x1C3,
            };
            assert!(!register.reads_memory());
            assert!(!register.writes_memory());
            assert!(register.has_side_effects());
            assert!(register.dests().is_empty());
        }

        let fxsave = OpKind::X86FxSave {
            addr: Address::Direct(rbx),
            rex_w: true,
        };
        assert!(!fxsave.reads_memory());
        assert!(fxsave.writes_memory());
        assert!(fxsave.has_side_effects());

        let fxrstor = OpKind::X86FxRstor {
            addr: Address::Direct(rbx),
            rex_w: false,
        };
        assert!(fxrstor.reads_memory());
        assert!(!fxrstor.writes_memory());
        assert!(fxrstor.has_side_effects());

        for kind in [
            X86XSaveKind::XSave,
            X86XSaveKind::XSaveOpt,
            X86XSaveKind::XSaveC,
            X86XSaveKind::XSaveS,
        ] {
            let xsave = OpKind::X86XSave {
                addr: Address::Direct(rbx),
                rex_w: true,
                kind,
                src_low: rbx,
                src_high: rbx,
            };
            assert!(xsave.dests().is_empty(), "{kind:?}");
            assert_eq!(
                xsave.reads_memory(),
                matches!(kind, X86XSaveKind::XSave | X86XSaveKind::XSaveOpt),
                "{kind:?}"
            );
            assert!(xsave.writes_memory(), "{kind:?}");
            assert!(xsave.has_side_effects(), "{kind:?}");
        }

        for supervisor in [false, true] {
            let xrstor = OpKind::X86XRstor {
                addr: Address::Direct(rbx),
                rex_w: false,
                supervisor,
                src_low: rbx,
                src_high: rbx,
            };
            assert!(xrstor.dests().is_empty());
            assert!(xrstor.reads_memory());
            assert!(!xrstor.writes_memory());
            assert!(xrstor.has_side_effects());
        }

        let cmpxchg = OpKind::X86Cmpxchg8b16b {
            addr: Address::Direct(rbx),
            wide: true,
            locked: true,
            compare_lo: rbx,
            compare_hi: rbx,
            new_lo: rbx,
            new_hi: rbx,
            dst_lo: rbx,
            dst_hi: rbx,
        };
        assert_eq!(cmpxchg.dests(), vec![rbx, rbx]);
        assert!(cmpxchg.reads_memory());
        assert!(cmpxchg.writes_memory());
        assert!(cmpxchg.has_side_effects());

        let random = OpKind::X86Random {
            dst: rbx,
            width: OpWidth::W64,
            seed: false,
        };
        assert_eq!(random.dests(), vec![rbx]);
        assert!(!random.reads_memory());
        assert!(!random.writes_memory());
        assert!(random.has_side_effects());

        let rdpid = OpKind::X86ReadPid { dst: rbx };
        assert_eq!(rdpid.dests(), vec![rbx]);
        assert!(!rdpid.reads_memory());
        assert!(!rdpid.writes_memory());
        assert!(!rdpid.has_side_effects());

        let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
        let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
        let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
        let xgetbv = OpKind::X86XGetBv {
            dst_low: rax,
            dst_high: rdx,
            selector: rcx,
        };
        assert_eq!(xgetbv.dests(), vec![rax, rdx]);
        assert!(xgetbv.has_side_effects());
        assert!(!xgetbv.reads_memory());
        assert!(!xgetbv.writes_memory());

        let xsetbv = OpKind::X86XSetBv {
            selector: rcx,
            src_low: rax,
            src_high: rdx,
        };
        assert!(xsetbv.dests().is_empty());
        assert!(xsetbv.has_side_effects());
        assert!(!xsetbv.reads_memory());
        assert!(!xsetbv.writes_memory());
    }

    #[test]
    fn x86_three_d_now_metadata_tracks_atomic_destructive_operands() {
        let dst = VReg::virt(0);
        let src1 = VReg::virt(1);
        let src2 = VReg::virt(2);
        let op = OpKind::X86ThreeDNow {
            dst,
            src1,
            src2,
            kind: X86ThreeDNowKind::PfAcc,
        };

        assert_eq!(op.dests(), vec![dst]);
        assert_eq!(op.source_vregs(), vec![src1, src2]);
        assert!(!op.reads_memory());
        assert!(!op.writes_memory());
        assert!(!op.has_side_effects());
        assert!(!op.is_jit_safe());

        let unary = OpKind::X86ThreeDNow {
            dst,
            src1,
            src2,
            kind: X86ThreeDNowKind::PfRcp,
        };
        assert_eq!(unary.source_vregs(), vec![src2]);
    }

    #[test]
    fn test_op_dests() {
        let op = OpKind::Add {
            dst: VReg::virt(0),
            src1: VReg::virt(1),
            src2: SrcOperand::imm(5),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        };
        assert_eq!(op.dests(), vec![VReg::virt(0)]);

        let op = OpKind::Store {
            src: VReg::virt(0),
            addr: Address::Absolute(0x1000),
            width: MemWidth::B8,
        };
        assert!(op.dests().is_empty());
        assert!(op.has_side_effects());
        assert!(op.writes_memory());
    }

    #[test]
    fn x86_string_dests_are_kind_and_rep_precise() {
        let rax = VReg::virt(0);
        let rcx = VReg::virt(1);
        let rsi = VReg::virt(2);
        let rdi = VReg::virt(3);
        let make = |kind, rep| OpKind::X86String {
            kind,
            rep,
            accumulator: rax,
            src_index: rsi,
            dst_index: rdi,
            count: rcx,
            src_segment: None,
            width: MemWidth::B1,
            address_width: OpWidth::W64,
        };

        assert_eq!(
            make(X86StringKind::Movs, X86RepMode::None).dests(),
            vec![rsi, rdi]
        );
        assert_eq!(
            make(X86StringKind::Stos, X86RepMode::Rep).dests(),
            vec![rdi, rcx]
        );
        assert_eq!(
            make(X86StringKind::Lods, X86RepMode::Rep).dests(),
            vec![rax, rsi, rcx]
        );
        assert_eq!(
            make(X86StringKind::Scas, X86RepMode::None).dests(),
            vec![rdi]
        );
        assert_eq!(
            make(X86StringKind::Cmps, X86RepMode::Repe).dests(),
            vec![rsi, rdi, rcx]
        );
    }
}
