//! x86 legacy floating-point and 3DNow! operation descriptors.

use crate::smir::ir::types::{
    Condition, FpRoundMode, VReg, VecElementType, X86FmaKind, X86FmaOrder,
};

/// Exact x86 FMA operation before architectural destination masking/merging.
///
/// Source numbering follows instruction syntax rather than arithmetic
/// placement. For FMA3, `src1` is also the architectural destination, `src2`
/// is the VEX/EVEX.vvvv source, and `src3` is the ModR/M source. FMA4 supplies
/// three independent sources and uses [`X86FmaOrder::Order123`]. Retaining
/// syntax order lets interpretation apply the architecture's NaN-priority rule
/// before arithmetic sign transformation. Masked-off lanes perform no
/// arithmetic and therefore cannot update MXCSR or raise a SIMD floating-point
/// exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86FmaOp {
    pub dst: VReg,
    pub src1: VReg,
    pub src2: VReg,
    pub src3: VReg,
    pub mask: Option<VReg>,
    pub elem: VecElementType,
    pub kind: X86FmaKind,
    pub order: X86FmaOrder,
    /// Dynamic rounding consults and updates MXCSR. An explicit mode denotes
    /// EVEX embedded rounding with suppress-all-exceptions semantics.
    pub round: FpRoundMode,
    pub lanes: u8,
}

impl X86FmaOp {
    /// Validate the semantic shapes admitted by x86 FMA encodings. This is
    /// intentionally stricter than the arithmetic core so malformed hand-built
    /// IR fails closed instead of reaching an unchecked lane operation.
    pub fn shape_valid(self) -> bool {
        let lane_shape = match self.elem {
            VecElementType::F32 => matches!(self.lanes, 1 | 4 | 8 | 16),
            VecElementType::F64 => matches!(self.lanes, 1 | 2 | 4 | 8),
            _ => false,
        };
        let alternating = matches!(self.kind, X86FmaKind::AddSub | X86FmaKind::SubAdd);
        let rounding_shape = match self.round {
            FpRoundMode::Dynamic => true,
            FpRoundMode::RoundNearest
            | FpRoundMode::RoundDown
            | FpRoundMode::RoundUp
            | FpRoundMode::RoundTowardZero => {
                self.lanes == 1
                    || matches!(
                        (self.elem, self.lanes),
                        (VecElementType::F32, 16) | (VecElementType::F64, 8)
                    )
            }
            FpRoundMode::RoundNearestTiesAway => false,
        };
        let order_shape = match self.order {
            X86FmaOrder::Order123 => {
                self.round == FpRoundMode::Dynamic
                    && self.mask.is_none()
                    && matches!(
                        (self.elem, self.lanes),
                        (VecElementType::F32, 1 | 4 | 8) | (VecElementType::F64, 1 | 2 | 4)
                    )
            }
            X86FmaOrder::Order132 | X86FmaOrder::Order213 | X86FmaOrder::Order231 => true,
        };
        lane_shape && (!alternating || self.lanes != 1) && rounding_shape && order_shape
    }

    pub fn source_vregs(self) -> Vec<VReg> {
        let mut sources = vec![self.src1, self.src2, self.src3];
        sources.extend(self.mask);
        sources
    }
}

/// 3DNow! operations selected by the trailing `imm8` of `0F 0F /r imm8`
/// that do not map exactly onto a generic packed-integer SMIR operation.
/// Operands and results are always one 64-bit MMX register containing either
/// two packed binary32 values or four packed signed 16-bit integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86ThreeDNowKind {
    Pf2Iw,
    PfNAcc,
    PfPNAcc,
    Pi2Fw,
    Pf2Id,
    PfAcc,
    PfAdd,
    PfCmpEq,
    PfCmpGe,
    PfCmpGt,
    PfMax,
    PfMin,
    PfMul,
    PfRcp,
    PfRcpIt1,
    PfRcpIt2,
    PfRsqIt1,
    PfRsqrt,
    PfSub,
    PfSubR,
    Pi2Fd,
    PmulHrw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87EnvWidth {
    W16,
    W32,
}

/// x87 environment/control operations that do not consume or produce an x87
/// data-stack value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87ControlKind {
    Init,
    ClearExceptions,
    /// Enter MMX state by marking all eight aliased x87 data registers valid.
    EnterMmx,
    /// Leave MMX state by marking all eight aliased x87 data registers empty.
    EmptyMmx,
    StoreStatusAx,
    LoadControlWord,
    StoreControlWord,
    StoreStatusWord,
    /// `FLDENV m14byte/m28byte`.
    LoadEnvironment(X86X87EnvWidth),
    /// `FNSTENV m14byte/m28byte` (the waiting `FSTENV` spelling is FWAIT
    /// followed by this instruction).
    StoreEnvironment(X86X87EnvWidth),
    /// `FRSTOR m94byte/m108byte`.
    RestoreState(X86X87EnvWidth),
    /// `FNSAVE m94byte/m108byte` (the waiting `FSAVE` spelling is FWAIT
    /// followed by this instruction).
    SaveState(X86X87EnvWidth),
}

/// x87 data-stack operations, explicit format conversions, and arithmetic.
/// Each arithmetic family has a distinct variant because binary80 rounding and
/// exception precedence differ from transfer/conversion responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87DataKind {
    /// `FLD ST(i)`.
    LoadRegister,
    /// `FLD m80fp`.
    LoadExtended,
    /// `FLD m32fp`.
    LoadSingle,
    /// `FLD m64fp`.
    LoadDouble,
    /// `FILD m16int`.
    LoadInt16,
    /// `FILD m32int`.
    LoadInt32,
    /// `FILD m64int`.
    LoadInt64,
    /// `FBLD m80bcd`.
    LoadBcd,
    /// `FST ST(i)`.
    StoreRegister,
    /// `FSTP ST(i)`.
    StorePopRegister,
    /// `FSTP m80fp`.
    StorePopExtended,
    /// `FXCH ST(i)`.
    Exchange,
    /// `FFREE ST(i)`.
    Free,
    /// Compatibility opcode `FFREEP ST(i)`: free ST(i), then pop the x87
    /// stack. Keeping this atomic preserves the waiting-exception frontier and
    /// the instruction's single FIP/FOP update.
    FreePop,
    /// `FCHS`.
    ChangeSign,
    /// `FABS`.
    Absolute,
    /// `FDECSTP`.
    DecrementTop,
    /// `FINCSTP`.
    IncrementTop,
    /// One of the seven `FLD*` architectural constants.
    LoadConstant(X86X87Constant),
    /// `FCMOVcc ST(0), ST(i)` using the integer condition flags.
    ConditionalMove(Condition),
    /// `FXAM` raw binary80/tag classification.
    Examine,
    /// `FTST` ordered comparison of ST(0) with +0.0.
    TestZero,
    /// `FRNDINT` integral rounding in binary80 format using FCW.RC.
    RoundInteger,
    /// `FXTRACT` exponent/significand decomposition with a stack push.
    Extract,
    /// `FSCALE` multiplication of ST(0) by 2^trunc(ST(1)).
    Scale,
    /// `FSQRT` square root rounded according to FCW.PC and FCW.RC.
    SquareRoot,
    /// One of the x87 exponential, logarithmic, or trigonometric operations.
    /// The operation kind captures its exact stack shape and status-word
    /// contract; the interpreter retains binary80 inputs and results.
    Transcendental(X86X87TranscendentalKind),
    /// `FMUL`, `FMULP`, or `FIMUL` exact binary80 multiplication.
    Multiply {
        source: X86X87ArithmeticSource,
        destination: X86X87ArithmeticDestination,
        pop: bool,
    },
    /// `FADD`/`FADDP`/`FIADD`, `FSUB`/`FSUBP`/`FISUB`, or the reverse-
    /// subtract forms. `subtract` selects subtraction and `reverse` selects
    /// source-minus-destination rather than destination-minus-source.
    AddSubtract {
        source: X86X87ArithmeticSource,
        destination: X86X87ArithmeticDestination,
        pop: bool,
        subtract: bool,
        reverse: bool,
    },
    /// `FDIV`/`FDIVP`/`FIDIV` or the reverse-divide forms. `reverse` selects
    /// source-over-destination rather than destination-over-source.
    Divide {
        source: X86X87ArithmeticSource,
        destination: X86X87ArithmeticDestination,
        pop: bool,
        reverse: bool,
    },
    /// `FPREM` or IEEE quotient-rounding `FPREM1` on ST(0)/ST(1).
    Remainder { nearest: bool },
    /// x87 floating-point compare family. `unordered` selects FUCOM policy,
    /// `pop` is the architectural pop count, and `eflags` selects the
    /// FCOMI/FUCOMI destination instead of C0/C2/C3.
    Compare {
        source: X86X87CompareSource,
        unordered: bool,
        pop: u8,
        eflags: bool,
    },
    /// `FIST`, `FISTP`, or `FISTTP` integer store.
    StoreInteger {
        width: X86X87IntWidth,
        pop: bool,
        truncate: bool,
    },
    /// `FST` or `FSTP` narrowing store to IEEE binary32/binary64.
    StoreFloat { width: X86X87FloatWidth, pop: bool },
    /// `FBSTP m80bcd`.
    StoreBcd,
}

impl X86X87DataKind {
    /// Operations whose complete architectural data effect is confined to the
    /// x87 status/tag environment; no binary80 payload is read or written.
    pub const fn is_stack_metadata(self) -> bool {
        matches!(
            self,
            Self::Free | Self::FreePop | Self::DecrementTop | Self::IncrementTop
        )
    }
}

impl super::OpKind {
    /// Exact operation-level x87 shapes eligible for the state-backed native
    /// tier. [`super::SmirOp`] validation additionally rejects encoding hints.
    pub(crate) fn x86_x87_state_jit_shape_valid(&self) -> bool {
        match self {
            Self::X86X87Control {
                kind:
                    X86X87ControlKind::Init
                    | X86X87ControlKind::ClearExceptions
                    | X86X87ControlKind::EnterMmx
                    | X86X87ControlKind::EmptyMmx
                    | X86X87ControlKind::StoreStatusAx,
                addr: None,
            } => true,
            Self::X86X87Data {
                kind,
                addr: None,
                st,
                fop,
            } => match kind {
                X86X87DataKind::Free => *st < 8 && *fop == 0x05C0 + u16::from(*st),
                X86X87DataKind::FreePop => *st < 8 && *fop == 0x07C0 + u16::from(*st),
                X86X87DataKind::ChangeSign => *st == 0 && *fop == 0x01E0,
                X86X87DataKind::Absolute => *st == 1 && *fop == 0x01E1,
                X86X87DataKind::StoreRegister => *st < 8 && *fop == 0x05D0 + u16::from(*st),
                X86X87DataKind::StorePopRegister => {
                    *st < 8 && (*fop == 0x05D8 + u16::from(*st) || *fop == 0x07D0 + u16::from(*st))
                }
                X86X87DataKind::DecrementTop => *st == 6 && *fop == 0x01F6,
                X86X87DataKind::IncrementTop => *st == 7 && *fop == 0x01F7,
                _ => false,
            },
            _ => false,
        }
    }
}

/// x87 operations whose architecturally specified result is a transcendental
/// approximation. Intel guarantees bounded error for reduced arguments while
/// defining instruction-specific stack, range, and exception behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87TranscendentalKind {
    /// `F2XM1`: replace ST(0) with `2^ST(0) - 1`.
    Exp2MinusOne,
    /// `FYL2X`: replace ST(1) with `ST(1) * log2(ST(0))`, then pop.
    YLog2X,
    /// `FPTAN`: replace ST(0) with its tangent, then push 1.0.
    Tangent,
    /// `FPATAN`: replace ST(1) with `atan2(ST(1), ST(0))`, then pop.
    Arctangent,
    /// `FYL2XP1`: replace ST(1) with `ST(1) * log2(ST(0) + 1)`, then pop.
    YLog2Xp1,
    /// `FSINCOS`: replace ST(0) with its sine, then push its cosine.
    SineCosine,
    /// `FSIN`: replace ST(0) with its sine.
    Sine,
    /// `FCOS`: replace ST(0) with its cosine.
    Cosine,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87CompareSource {
    Register,
    Single,
    Double,
    Int16,
    Int32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87ArithmeticSource {
    Register,
    Single,
    Double,
    Int16,
    Int32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87ArithmeticDestination {
    St0,
    StI,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87IntWidth {
    I16,
    I32,
    I64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87FloatWidth {
    F32,
    F64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87Constant {
    One,
    Log2Ten,
    Log2E,
    Pi,
    Log10Two,
    LnTwo,
    Zero,
}
