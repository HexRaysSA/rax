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
        /// Narrow source element type (I8 or I16).
        src_elem: VecElementType,
        /// Number of source sub-lanes summed per output lane (2 or 4).
        taps: u8,
        signed1: bool,
        signed2: bool,
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

            OpKind::VWidenMul { dst_lo, dst_hi, .. } => vec![*dst_lo, *dst_hi],

            OpKind::VReduceMul { dst, .. } => vec![*dst],

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
