//! SMIR operation definitions.
//!
//! This module defines all IR operations (`OpKind`) with their operands and semantics.

use crate::smir::flags::FlagUpdate;
use crate::smir::types::*;

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
}

// ============================================================================
// x86 Encoding Hints
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86AluEncoding {
    /// r/m, reg encoding
    RmReg,
    /// reg, r/m encoding
    RegRm,
    /// Accumulator immediate encoding
    AccImm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86SsePrefix {
    None,
    OpSize,
    Rep,
    Repne,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86VecMap {
    Map0F,
    Map0F38,
    Map0F3A,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86VecAlign {
    Aligned,
    Unaligned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86OpHint {
    /// ALU encoding preference
    AluEncoding(X86AluEncoding),
    /// Use ModR/M immediate encoding for MOV
    MovImmModRm,
    /// Push with 8-bit immediate
    PushImm8,
    /// Push with 32-bit immediate
    PushImm32,
    /// IMUL with 8-bit immediate
    ImulImm8,
    /// IMUL with 32-bit immediate
    ImulImm32,
    /// SSE mov with explicit prefix/opcode
    SseMov { prefix: X86SsePrefix, opcode: u8 },
    /// SSE opcode with explicit prefix/opcode
    SseOp { prefix: X86SsePrefix, opcode: u8 },
    /// VEX-encoded opcode (map/pp/opcode/width)
    VexOp {
        map: X86VecMap,
        pp: X86SsePrefix,
        opcode: u8,
        width: VecWidth,
    },
    /// EVEX-encoded opcode (map/pp/opcode/width)
    EvexOp {
        map: X86VecMap,
        pp: X86SsePrefix,
        opcode: u8,
        width: VecWidth,
    },
    /// Alignment hint for default vector moves
    VecAlign(X86VecAlign),
}

// ============================================================================
// OpKind Enum
// ============================================================================

/// All SMIR operation kinds
#[derive(Clone, Debug)]
pub enum OpKind {
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
    },

    /// Signed divide: (quotient, remainder) = src1 / src2
    DivS {
        quot: VReg,
        rem: Option<VReg>,
        src1: VReg,
        src2: SrcOperand,
        width: OpWidth,
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
    Lea { dst: VReg, addr: Address },

    /// Exchange registers
    Xchg {
        reg1: VReg,
        reg2: VReg,
        width: OpWidth,
    },

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
    Prefetch { addr: Address, write: bool },

    /// Memory fence
    Fence { kind: FenceKind },

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

    /// Vector max
    VMax {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Vector multiply
    VMul {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
    },

    /// Vector bitwise AND
    VAnd {
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

    /// Width-general, architecture-register-aware elementwise lane operation.
    ///
    /// Operates on `lanes` elements of `elem` bits across the full vector
    /// register (up to 1024 bits), reading/writing via the arch-aware vector
    /// path so it works on Hexagon HVX V registers (and virtual regs). `op`
    /// selects the per-lane operation and `signed` its signedness where it
    /// matters (min/max/avg/saturate/absdiff). This is the lift target for HVX
    /// integer elementwise instructions.
    VLane {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        op: VLaneOp,
        signed: bool,
    },

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

    /// Saturating narrowing pack. Models HVX `vpackhub_sat/hb_sat/wuh_sat/wh_sat`:
    /// each signed `src_elem`-wide lane is saturated to a half-width lane;
    /// src2's lanes fill the low half of the result, src1's the high half.
    VPackSat {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        /// Wide source element type (I16 or I32); result lanes are half width.
        src_elem: VecElementType,
        /// true = saturate to the unsigned range (ub/uh), false = signed (b/h).
        to_unsigned: bool,
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
    VQFromVAndR {
        dst: VReg,
        src1: VReg,
        src2: VReg,
    },

    /// Per-byte Q-gated mask-to-zero. Models HVX `vandvqv`/`vandvnqv` (and, via a
    /// VBroadcast of Rt, `vandqrt`/`vandnqrt`): `dst.byte[i] = (mask_q.bit[i] ^
    /// negate) ? src.byte[i] : 0`.
    VMaskZero {
        dst: VReg,
        mask_q: VReg,
        src: VReg,
        negate: bool,
    },

    /// Per-byte select by a Q vector predicate. Models HVX `vmux`:
    /// `dst.byte[i] = mask_q.bit[i] ? src_true.byte[i] : src_false.byte[i]`.
    VBlend {
        dst: VReg,
        mask_q: VReg,
        src_true: VReg,
        src_false: VReg,
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

    /// Vector shuffle/permute
    VShuffle {
        dst: VReg,
        src1: VReg,
        src2: Option<VReg>,
        indices: VReg,
        elem: VecElementType,
    },

    /// Vector load
    VLoad {
        dst: VReg,
        addr: Address,
        width: VecWidth,
    },

    /// Vector store
    VStore {
        src: VReg,
        addr: Address,
        width: VecWidth,
    },

    /// Leave stack frame (x86 LEAVE)
    Leave,

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

    /// Vector FMA: dst = acc + (src1 * src2) or dst = acc - (src1 * src2)
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

    // ========================================================================
    // AVX10.1 OPERATIONS
    // ========================================================================
    /// VNNI dot product: dst = acc + dot(src1, src2)
    /// VPDPBUSD: unsigned bytes * signed bytes -> dword accumulate
    /// VPDPBUSDS: same with saturation
    /// VPDPWSSD: signed words * signed words -> dword accumulate
    /// VPDPWSSDS: same with saturation
    VDotProduct {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        /// Element type for src1 (I8 for byte, I16 for word)
        src_elem: VecElementType,
        /// Element type for accumulator (typically I32)
        acc_elem: VecElementType,
        width: VecWidth,
        /// true=src1 unsigned, src2 signed; false=both signed
        src1_unsigned: bool,
        /// Saturate result instead of wrapping
        saturate: bool,
    },

    /// IFMA 52-bit multiply-add: dst = acc + (src1[51:0] * src2[51:0])
    /// VPMADD52LUQ: low 52 bits of product
    /// VPMADD52HUQ: high 52 bits of product
    VMultiplyAdd52 {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
        /// true = high 52 bits, false = low 52 bits
        high: bool,
    },

    /// Vector population count per element
    /// VPOPCNTB/W/D/Q
    VPopcnt {
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        width: VecWidth,
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

    /// Shuffle bits from qwords using byte indices into mask
    /// VPSHUFBITQMB
    VShuffleBitQM {
        dst: VReg,
        src: VReg,
        indices: VReg,
        width: VecWidth,
    },

    /// BFloat16 dot product: dst = acc + dot(bf16_to_f32(src1), bf16_to_f32(src2))
    /// VDPBF16PS
    VDotProductBF16 {
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
    },

    /// Convert FP32 to BFloat16
    /// VCVTNEPS2BF16, VCVTNE2PS2BF16
    VCvtFP32ToBF16 {
        dst: VReg,
        src1: VReg,
        src2: Option<VReg>,
        width: VecWidth,
    },

    /// Convert BFloat16 to FP32
    VCvtBF16ToFP32 {
        dst: VReg,
        src: VReg,
        width: VecWidth,
    },

    /// FP16 arithmetic operations
    /// VADDPH, VSUBPH, VMULPH, VDIVPH
    VFP16Arith {
        dst: VReg,
        src1: VReg,
        src2: VReg,
        op: Avx10FP16Op,
        width: VecWidth,
    },

    // ========================================================================
    // AVX10.2 OPERATIONS
    // ========================================================================
    /// Saturating FP to int conversion
    /// VCVTTPS2IBS, VCVTTPS2IUBS, VCVTTPD2QQS, VCVTTPD2UQQS
    VCvtFpToIntSat {
        dst: VReg,
        src: VReg,
        fp_elem: VecElementType,
        int_elem: VecElementType,
        width: VecWidth,
        signed: bool,
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
        width: VecWidth,
        imm: u8,
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
    ReadFlags { dst: VReg },

    /// Write register to flags
    WriteFlags { src: VReg },

    /// Set carry flag
    SetCF { value: bool },

    /// Set direction flag (x86 CLD/STD)
    SetDF { value: bool },

    /// Complement carry flag
    CmcCF,

    /// Force flag materialization
    MaterializeFlags,

    /// Test condition and store result
    TestCondition { dst: VReg, cond: Condition },

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
    Syscall { num: VReg, args: Vec<VReg> },

    /// Software interrupt
    Swi { imm: u32 },

    /// Read system register
    ReadSysReg { dst: VReg, reg: u32 },

    /// Write system register
    WriteSysReg { reg: u32, src: VReg },

    // ========================================================================
    // META / DEBUG
    // ========================================================================
    /// No-op
    Nop,

    /// Undefined instruction (trap on execution)
    Undefined { opcode: u32 },

    /// Debug breakpoint
    Breakpoint,
}

impl OpKind {
    /// Fail-safe whitelist for the SMIR native hot-block JIT: returns true ONLY
    /// for register/immediate-only integer ops that have been validated
    /// bit-exact against KVM (the `smir_native_*` differentials) and that touch
    /// NO memory (their operands are `VReg`/`SrcOperand`, never an `Address`).
    /// Everything else — memory/stack ops (Load/Store/Push/Pop/string/atomic),
    /// DivU/DivS (the shared single-width div IR mismodels x86's RDX:RAX
    /// dividend → wrong results), FP/SIMD, flags-register plumbing, syscalls,
    /// and any unvalidated op — returns false so the JIT BAILS to the
    /// interpreter rather than risk incorrect native execution. This is the
    /// correctness gate that makes the JIT safe to auto-trigger on real code
    /// (e.g. a booting kernel): an unknown or memory-touching op never executes
    /// natively.
    pub fn is_jit_safe(&self) -> bool {
        matches!(
            self,
            OpKind::Add { .. }
                | OpKind::Sub { .. }
                | OpKind::Adc { .. }
                | OpKind::Sbb { .. }
                | OpKind::Neg { .. }
                | OpKind::Inc { .. }
                | OpKind::Dec { .. }
                | OpKind::Cmp { .. }
                | OpKind::And { .. }
                | OpKind::Or { .. }
                | OpKind::Xor { .. }
                | OpKind::Not { .. }
                | OpKind::Test { .. }
                | OpKind::Shl { .. }
                | OpKind::Shr { .. }
                | OpKind::Sar { .. }
                | OpKind::Shld { .. }
                | OpKind::Shrd { .. }
                | OpKind::Rol { .. }
                | OpKind::Ror { .. }
                | OpKind::MulU { .. }
                | OpKind::MulS { .. }
                | OpKind::Mov { .. }
                | OpKind::ZeroExtend { .. }
                | OpKind::SignExtend { .. }
                | OpKind::SetCC { .. }
                | OpKind::TestCondition { .. }
                | OpKind::CMove { .. }
                | OpKind::Nop
        )
    }

    /// Get destination register(s) if any
    pub fn dests(&self) -> Vec<VReg> {
        match self {
            OpKind::Add { dst, .. }
            | OpKind::Sub { dst, .. }
            | OpKind::Adc { dst, .. }
            | OpKind::Sbb { dst, .. }
            | OpKind::Neg { dst, .. }
            | OpKind::Inc { dst, .. }
            | OpKind::Dec { dst, .. }
            | OpKind::And { dst, .. }
            | OpKind::Or { dst, .. }
            | OpKind::Xor { dst, .. }
            | OpKind::Not { dst, .. }
            | OpKind::AndNot { dst, .. }
            | OpKind::Shl { dst, .. }
            | OpKind::Shr { dst, .. }
            | OpKind::Sar { dst, .. }
            | OpKind::Shld { dst, .. }
            | OpKind::Shrd { dst, .. }
            | OpKind::Rol { dst, .. }
            | OpKind::Ror { dst, .. }
            | OpKind::Bts { dst, .. }
            | OpKind::Btr { dst, .. }
            | OpKind::Btc { dst, .. }
            | OpKind::Bsf { dst, .. }
            | OpKind::Bsr { dst, .. }
            | OpKind::Clz { dst, .. }
            | OpKind::Ctz { dst, .. }
            | OpKind::Popcnt { dst, .. }
            | OpKind::Bswap { dst, .. }
            | OpKind::Rbit { dst, .. }
            | OpKind::Bfx { dst, .. }
            | OpKind::Bfi { dst, .. }
            | OpKind::Mov { dst, .. }
            | OpKind::CMove { dst, .. }
            | OpKind::Select { dst, .. }
            | OpKind::ZeroExtend { dst, .. }
            | OpKind::SignExtend { dst, .. }
            | OpKind::Cwd { dst, .. }
            | OpKind::Truncate { dst, .. }
            | OpKind::Lea { dst, .. }
            | OpKind::Load { dst, .. }
            | OpKind::AtomicLoad { dst, .. }
            | OpKind::AtomicRmw { dst, .. }
            | OpKind::LoadExclusive { dst, .. }
            | OpKind::FAdd { dst, .. }
            | OpKind::FSub { dst, .. }
            | OpKind::FMul { dst, .. }
            | OpKind::FDiv { dst, .. }
            | OpKind::FFma { dst, .. }
            | OpKind::FAbs { dst, .. }
            | OpKind::FNeg { dst, .. }
            | OpKind::FSqrt { dst, .. }
            | OpKind::FMin { dst, .. }
            | OpKind::FMax { dst, .. }
            | OpKind::FConvert { dst, .. }
            | OpKind::IntToFp { dst, .. }
            | OpKind::FpToInt { dst, .. }
            | OpKind::FRound { dst, .. }
            | OpKind::VAdd { dst, .. }
            | OpKind::VSub { dst, .. }
            | OpKind::VMax { dst, .. }
            | OpKind::VMul { dst, .. }
            | OpKind::VLane { dst, .. }
            | OpKind::VAnd { dst, .. }
            | OpKind::VOr { dst, .. }
            | OpKind::VXor { dst, .. }
            | OpKind::VShift { dst, .. }
            | OpKind::VCmp { dst, .. }
            | OpKind::VMov { dst, .. }
            | OpKind::VInsertLane { dst, .. }
            | OpKind::VExtractLane { dst, .. }
            | OpKind::VShuffle { dst, .. }
            | OpKind::VLoad { dst, .. }
            | OpKind::VBroadcast { dst, .. }
            | OpKind::VMin { dst, .. }
            | OpKind::VFma { dst, .. }
            | OpKind::VDotProduct { dst, .. }
            | OpKind::VMultiplyAdd52 { dst, .. }
            | OpKind::VPopcnt { dst, .. }
            | OpKind::VPermute { dst, .. }
            | OpKind::VShuffleBitQM { dst, .. }
            | OpKind::VDotProductBF16 { dst, .. }
            | OpKind::VCvtFP32ToBF16 { dst, .. }
            | OpKind::VCvtBF16ToFP32 { dst, .. }
            | OpKind::VFP16Arith { dst, .. }
            | OpKind::VCvtFpToIntSat { dst, .. }
            | OpKind::VMinMax { dst, .. }
            | OpKind::VMpsadbw { dst, .. }
            | OpKind::VDotProductExt { dst, .. }
            | OpKind::IoIn { dst, .. }
            | OpKind::ReadFlags { dst, .. }
            | OpKind::TestCondition { dst, .. }
            | OpKind::SetCC { dst, .. }
            | OpKind::ReadSysReg { dst, .. } => vec![*dst],

            OpKind::Leave => vec![
                VReg::Arch(ArchReg::X86(X86Reg::Rsp)),
                VReg::Arch(ArchReg::X86(X86Reg::Rbp)),
            ],

            OpKind::VWidenMul { dst_lo, dst_hi, .. }
            | OpKind::VWidenExt { dst_lo, dst_hi, .. }
            | OpKind::VWidenAddSub { dst_lo, dst_hi, .. }
            | OpKind::VPairReduceMul { dst_lo, dst_hi, .. }
            | OpKind::VSlideReduceMul { dst_lo, dst_hi, .. }
            | OpKind::VRotReduceMulPair { dst_lo, dst_hi, .. }
            | OpKind::VPairPairReduceMul { dst_lo, dst_hi, .. }
            | OpKind::VLut16 { dst_lo, dst_hi, .. }
            | OpKind::VMulWord64Pair { dst_lo, dst_hi, .. }
            | OpKind::VShuffVdd { dst_lo, dst_hi, .. } => {
                vec![*dst_lo, *dst_hi]
            }

            OpKind::VReduceMul { dst, .. }
            | OpKind::VMulEvenWiden { dst, .. }
            | OpKind::VMulSubLane { dst, .. }
            | OpKind::VMulSubLaneSh { dst, .. }
            | OpKind::VMulSubLaneFrac { dst, .. }
            | OpKind::VPack { dst, .. }
            | OpKind::VPackSat { dst, .. }
            | OpKind::VShuffle2 { dst, .. }
            | OpKind::VShuffleEO { dst, .. }
            | OpKind::VDealB4W { dst, .. }
            | OpKind::VDelta { dst, .. }
            | OpKind::VLut { dst, .. }
            | OpKind::VAlign { dst, .. }
            | OpKind::VMulShiftSat { dst, .. }
            | OpKind::VNarrowShiftSat { dst, .. }
            | OpKind::VSatDW { dst, .. }
            | OpKind::VNarrowShiftV { dst, .. }
            | OpKind::VShiftV { dst, .. }
            | OpKind::VLaneUnary { dst, .. }
            | OpKind::VNavg { dst, .. }
            | OpKind::VShiftAcc { dst, .. }
            | OpKind::VCmpToQ { dst, .. }
            | OpKind::VBlend { dst, .. }
            | OpKind::VMaskZero { dst, .. }
            | OpKind::VQFromVAndR { dst, .. } => vec![*dst],

            OpKind::MulU { dst_lo, dst_hi, .. } | OpKind::MulS { dst_lo, dst_hi, .. } => {
                let mut v = vec![*dst_lo];
                if let Some(hi) = dst_hi {
                    v.push(*hi);
                }
                v
            }

            OpKind::DivU { quot, rem, .. } | OpKind::DivS { quot, rem, .. } => {
                let mut v = vec![*quot];
                if let Some(r) = rem {
                    v.push(*r);
                }
                v
            }

            OpKind::MulAdd { dst, .. } | OpKind::MulSub { dst, .. } => vec![*dst],

            OpKind::RepStos { dst, count, .. } => vec![*dst, *count],

            OpKind::RepMovs {
                dst, src, count, ..
            } => vec![*dst, *src, *count],

            OpKind::LoadPair { dst1, dst2, .. } => vec![*dst1, *dst2],

            OpKind::Cas { dst, success, .. } => vec![*dst, *success],

            OpKind::StoreExclusive { status, .. } => vec![*status],

            OpKind::Xchg { reg1, reg2, .. } => vec![*reg1, *reg2],

            // No destination
            OpKind::Cmp { .. }
            | OpKind::Test { .. }
            | OpKind::Bt { .. }
            | OpKind::Store { .. }
            | OpKind::StorePair { .. }
            | OpKind::AtomicStore { .. }
            | OpKind::ClearExclusive
            | OpKind::Prefetch { .. }
            | OpKind::Fence { .. }
            | OpKind::FCmp { .. }
            | OpKind::VStore { .. }
            | OpKind::WriteFlags { .. }
            | OpKind::SetCF { .. }
            | OpKind::SetDF { .. }
            | OpKind::CmcCF
            | OpKind::MaterializeFlags
            | OpKind::Syscall { .. }
            | OpKind::IoOut { .. }
            | OpKind::Swi { .. }
            | OpKind::WriteSysReg { .. }
            | OpKind::Leave
            | OpKind::Nop
            | OpKind::Undefined { .. }
            | OpKind::Breakpoint => vec![],
        }
    }

    /// Check if this operation has side effects
    pub fn has_side_effects(&self) -> bool {
        matches!(
            self,
            OpKind::Store { .. }
                | OpKind::RepStos { .. }
                | OpKind::RepMovs { .. }
                | OpKind::StorePair { .. }
                | OpKind::AtomicStore { .. }
                | OpKind::AtomicRmw { .. }
                | OpKind::Cas { .. }
                | OpKind::StoreExclusive { .. }
                | OpKind::IoIn { .. }
                | OpKind::IoOut { .. }
                | OpKind::Leave
                | OpKind::ClearExclusive
                | OpKind::Fence { .. }
                | OpKind::VStore { .. }
                | OpKind::WriteFlags { .. }
                | OpKind::SetCF { .. }
                | OpKind::SetDF { .. }
                | OpKind::CmcCF
                | OpKind::MaterializeFlags
                | OpKind::Syscall { .. }
                | OpKind::Swi { .. }
                | OpKind::WriteSysReg { .. }
                | OpKind::Breakpoint
        )
    }

    /// Check if this operation reads memory
    pub fn reads_memory(&self) -> bool {
        matches!(
            self,
            OpKind::Load { .. }
                | OpKind::LoadPair { .. }
                | OpKind::AtomicLoad { .. }
                | OpKind::AtomicRmw { .. }
                | OpKind::Cas { .. }
                | OpKind::LoadExclusive { .. }
                | OpKind::RepMovs { .. }
                | OpKind::VLoad { .. }
                | OpKind::Leave
        )
    }

    /// Check if this operation writes memory
    pub fn writes_memory(&self) -> bool {
        matches!(
            self,
            OpKind::Store { .. }
                | OpKind::RepStos { .. }
                | OpKind::RepMovs { .. }
                | OpKind::StorePair { .. }
                | OpKind::AtomicStore { .. }
                | OpKind::AtomicRmw { .. }
                | OpKind::Cas { .. }
                | OpKind::StoreExclusive { .. }
                | OpKind::VStore { .. }
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
}
