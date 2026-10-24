//! Operation destinations, effects, memory behavior, and JIT admission.

use crate::smir::ir::ops::{
    OpKind, X86CacheControlKind, X86FmaOp, X86LmswOp, X86LmswSource, X86MonitorMwaitOp, X86RepMode,
    X86SmswOp, X86SmswTarget, X86StackFlagsKind, X86StackFlagsOp, X86StringKind, X86SystemSelector,
    X86SystemSelectorLoadOp, X86SystemSelectorSource, X86SystemSelectorStoreOp,
    X86SystemSelectorTarget, X86WaitPkgOp, X86X87ArithmeticSource, X86X87CompareSource,
    X86X87ControlKind, X86X87DataKind, X86XSaveKind,
};
use crate::smir::ir::types::{ArchReg, HexagonReg, VReg, X86Reg};

impl OpKind {
    /// Fail-safe whitelist for the SMIR native hot-block JIT: returns true ONLY
    /// for register/immediate-only integer ops, explicitly state-backed control
    /// reads, and narrowly modeled system operations with exact helper-backed
    /// memory semantics. Every target gate must additionally validate operand
    /// shape, helper availability, and host support before execution.
    /// Everything else — memory/stack ops (Load/Store/Push/Pop/string/atomic),
    /// DivU/DivS (native x86 division can raise a host #DE until an exact
    /// guarded lowering rules out zero divisors and quotient overflow),
    /// FP/SIMD, flags-register plumbing, syscalls,
    /// and any unvalidated op — returns false so the JIT BAILS to the
    /// interpreter rather than risk incorrect native execution. This is the
    /// correctness gate that makes the JIT safe to auto-trigger on real code
    /// (e.g. a booting kernel): an unknown or memory-touching op never executes
    /// natively.
    pub fn is_jit_safe(&self) -> bool {
        self.x86_x87_state_jit_shape_valid()
            || matches!(
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
                | OpKind::X86NddDoubleShift { .. }
                | OpKind::Rol { .. }
                | OpKind::Ror { .. }
                | OpKind::Rcl { .. }
                | OpKind::Rcr { .. }
                | OpKind::MulU { .. }
                | OpKind::MulS { .. }
                | OpKind::Mov { .. }
                | OpKind::ZeroExtend { .. }
                | OpKind::SignExtend { .. }
                | OpKind::Cwd { .. }
                | OpKind::SetCC { .. }
                | OpKind::TestCondition { .. }
                | OpKind::CMove { .. }
                | OpKind::Bt { .. }
                | OpKind::Bts { .. }
                | OpKind::Btr { .. }
                | OpKind::Btc { .. }
                | OpKind::Bsf { .. }
                | OpKind::Bsr { .. }
                | OpKind::Bextr { .. }
                | OpKind::Bzhi { .. }
                | OpKind::Pdep { .. }
                | OpKind::Pext { .. }
                | OpKind::Clz { .. }
                | OpKind::Ctz { .. }
                | OpKind::Popcnt { .. }
                | OpKind::Crc32C { .. }
                | OpKind::Fence { .. }
                | OpKind::X86Random { .. }
                | OpKind::X86ReadPid { .. }
                | OpKind::X86XGetBv { .. }
                | OpKind::X86XSetBv { .. }
                | OpKind::X86Clts
                | OpKind::X86CacheMaintenance { .. }
                | OpKind::X86Msr(..)
                | OpKind::X86ReadControl { .. }
                | OpKind::X86Smsw(..)
                | OpKind::X86SystemSelectorStore(..)
                | OpKind::X86SystemSelectorLoad(..)
                | OpKind::X86SelectorVerify(..)
                | OpKind::X86SelectorQuery(..)
                | OpKind::X86FarJump(..)
                | OpKind::X86FarCall(..)
                | OpKind::X86FarReturn(..)
                | OpKind::X86FastSystemTransfer(..)
                | OpKind::X86Lmsw(..)
                | OpKind::X86DescriptorTableStore(..)
                | OpKind::X86DescriptorTableLoad(..)
                | OpKind::X86Invlpg(..)
                | OpKind::X86Invpcid(..)
                | OpKind::X86WriteControl { .. }
                | OpKind::X86ReadDebug { .. }
                | OpKind::X86WriteDebug { .. }
                | OpKind::X86FsGsBase { .. }
                | OpKind::X86SwapGs { .. }
                | OpKind::X86MonitorMwait(..)
                | OpKind::X86WaitPkg(..)
                | OpKind::X86Pkru { .. }
                | OpKind::X86ReadTsc(..)
                | OpKind::X86ReadPmc(..)
                | OpKind::SetAC { .. }
                | OpKind::X86RequireApx
                | OpKind::X86RequireSse4a
                | OpKind::X86RequireTbm
                | OpKind::X86RequireXop
                | OpKind::X86Sse4aBitfield { .. }
                | OpKind::X86Cli { .. }
                | OpKind::X86Sti { .. }
                | OpKind::X86Cpuid { .. }
                | OpKind::X86Count { .. }
                | OpKind::Bswap { .. }
                | OpKind::Xchg { .. }
                // Register-only address arithmetic (no memory dereference).
                // Dedicated x86 scan/count variants carry their flag contracts;
                // generic count ops remain flag-neutral across architectures.
                | OpKind::Lea { .. }
                | OpKind::X86Lea { .. }
                | OpKind::Nop
            )
    }

    /// Get destination register(s) if any
    pub fn dests(&self) -> Vec<VReg> {
        match self {
            OpKind::ArmPauth(operation) => operation.destinations(),
            OpKind::ArmInstructionBegin { .. } | OpKind::ArmInstructionCommit { .. } => {
                crate::smir::ir::ops::arm_boundary_state()
            }
            OpKind::ArmSimdLong(operation) => operation.destinations(),
            OpKind::ArmSimdNarrow(operation) => operation.destinations(),
            OpKind::ArmSimdSaturating(operation) => operation.destinations(),
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
            | OpKind::X86NddDoubleShift { dst, .. }
            | OpKind::Rol { dst, .. }
            | OpKind::Ror { dst, .. }
            | OpKind::ArmRegShift { dst, .. }
            | OpKind::Rcl { dst, .. }
            | OpKind::Rcr { dst, .. }
            | OpKind::BidirShift { dst, .. }
            | OpKind::SatN { dst, .. }
            | OpKind::Crc32C { dst, .. }
            | OpKind::Bts { dst, .. }
            | OpKind::Btr { dst, .. }
            | OpKind::Btc { dst, .. }
            | OpKind::Bsf { dst, .. }
            | OpKind::Bsr { dst, .. }
            | OpKind::Bextr { dst, .. }
            | OpKind::Bzhi { dst, .. }
            | OpKind::X86Bls { dst, .. }
            | OpKind::X86Tbm { dst, .. }
            | OpKind::X86Adx { dst, .. }
            | OpKind::Pdep { dst, .. }
            | OpKind::Pext { dst, .. }
            | OpKind::Clz { dst, .. }
            | OpKind::Ctz { dst, .. }
            | OpKind::Popcnt { dst, .. }
            | OpKind::X86Count { dst, .. }
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
            | OpKind::X86Lea { dst, .. }
            | OpKind::Load { dst, .. }
            | OpKind::PredLoad { dst, .. }
            | OpKind::AtomicLoad { dst, .. }
            | OpKind::AtomicRmw { dst, .. }
            | OpKind::AtomicCmpXadd { dst_old: dst, .. }
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
            | OpKind::HexFp { dst, .. }
            | OpKind::HexFp3 { dst, .. }
            | OpKind::HexFpDf { dst, .. }
            | OpKind::HexFpScFma { dst, .. }
            | OpKind::HexTlbMatch { dst, .. }
            | OpKind::IntToFp { dst, .. }
            | OpKind::FpToInt { dst, .. }
            | OpKind::X86FpToInt { dst, .. }
            | OpKind::X86ScalarFpToIntSat { dst, .. }
            | OpKind::X86VectorFpCompare { dst, .. }
            | OpKind::X86GetExponent { dst, .. }
            | OpKind::X86GetMantissa { dst, .. }
            | OpKind::X86RoundScale { dst, .. }
            | OpKind::X86Reduce { dst, .. }
            | OpKind::X86Range { dst, .. }
            | OpKind::X86FixupImm { dst, .. }
            | OpKind::X86Exp2 { dst, .. }
            | OpKind::X86Recip14 { dst, .. }
            | OpKind::X86Rsqrt14 { dst, .. }
            | OpKind::X86RecipFp16 { dst, .. }
            | OpKind::X86RsqrtFp16 { dst, .. }
            | OpKind::X86Recip28 { dst, .. }
            | OpKind::X86Rsqrt28 { dst, .. }
            | OpKind::X86ScaleF { dst, .. }
            | OpKind::X86IntToFp { dst, .. }
            | OpKind::X86FpConvert { dst, .. }
            | OpKind::X86PackedFpConvert { dst, .. }
            | OpKind::X86PackedIntToFp { dst, .. }
            | OpKind::X86PackedFpToInt { dst, .. }
            | OpKind::X86PackedIntToFp16 { dst, .. }
            | OpKind::X86PackedFp16ToInt { dst, .. }
            | OpKind::FRound { dst, .. }
            | OpKind::X86Round { dst, .. }
            | OpKind::X86DotProduct { dst, .. }
            | OpKind::X86FpBinary { dst, .. }
            | OpKind::VAdd { dst, .. }
            | OpKind::VSub { dst, .. }
            | OpKind::VAddSubSat { dst, .. }
            | OpKind::VMax { dst, .. }
            | OpKind::VX86MinMax { dst, .. }
            | OpKind::VMul { dst, .. }
            | OpKind::VDiv { dst, .. }
            | OpKind::VUnary { dst, .. }
            | OpKind::X86Sqrt { dst, .. }
            | OpKind::VReduce { dst, .. }
            | OpKind::VFMinMaxNm { dst, .. }
            | OpKind::VPermute2 { dst, .. }
            | OpKind::VTableLookup { dst, .. }
            | OpKind::VLane { dst, .. }
            | OpKind::VAnd { dst, .. }
            | OpKind::VAndNot { dst, .. }
            | OpKind::VOr { dst, .. }
            | OpKind::VXor { dst, .. }
            | OpKind::VBitSelect { dst, .. }
            | OpKind::VShift { dst, .. }
            | OpKind::VCmp { dst, .. }
            | OpKind::VMov { dst, .. }
            | OpKind::VInsertLane { dst, .. }
            | OpKind::VExtractLane { dst, .. }
            | OpKind::VShuffle { dst, .. }
            | OpKind::VInterleave { dst, .. }
            | OpKind::VByteShuffle { dst, .. }
            | OpKind::VHorizontalBin { dst, .. }
            | OpKind::VLoad { dst, .. }
            | OpKind::PredVLoad { dst, .. }
            | OpKind::VBroadcast { dst, .. }
            | OpKind::VMin { dst, .. }
            | OpKind::VFma { dst, .. }
            | OpKind::X86Fma(X86FmaOp { dst, .. })
            | OpKind::X86FP16Fma { dst, .. }
            | OpKind::X86FP16Complex { dst, .. }
            | OpKind::X86FourFma { dst, .. }
            | OpKind::X86FourDotProduct { dst, .. }
            | OpKind::VDotProduct { dst, .. }
            | OpKind::VMultiplyAdd52 { dst, .. }
            | OpKind::VPopcnt { dst, .. }
            | OpKind::VLeadingZeros { dst, .. }
            | OpKind::VConflict { dst, .. }
            | OpKind::VPermute { dst, .. }
            | OpKind::X86PermuteBytesWords { dst, .. }
            | OpKind::VShuffleBitQM { dst, .. }
            | OpKind::VCompress { dst, .. }
            | OpKind::VExpand { dst, .. }
            | OpKind::X86NarrowInt { dst, .. }
            | OpKind::VDotProductBF16 { dst, .. }
            | OpKind::VCvtFP32ToBF16 { dst, .. }
            | OpKind::VCvtBF16ToFP32 { dst, .. }
            | OpKind::VFP16Arith { dst, .. }
            | OpKind::VCvtFpToIntSat { dst, .. }
            | OpKind::VMinMax { dst, .. }
            | OpKind::VMpsadbw { dst, .. }
            | OpKind::VSadBytes { dst, .. }
            | OpKind::X86Phminposuw { dst, .. }
            | OpKind::X86MovMask { dst, .. }
            | OpKind::X86MovdQ { dst, .. }
            | OpKind::X86Sse4aBitfield { dst, .. }
            | OpKind::X86Aes { dst, .. }
            | OpKind::X86Sha32 { dst, .. }
            | OpKind::X86PackedStringCompare { dst, .. }
            | OpKind::X86Sha512Msg1 { dst, .. }
            | OpKind::X86Sha512Msg2 { dst, .. }
            | OpKind::X86Sha512Rounds2 { dst, .. }
            | OpKind::X86Sm3Msg1 { dst, .. }
            | OpKind::X86Sm3Msg2 { dst, .. }
            | OpKind::X86Sm3Rounds2 { dst, .. }
            | OpKind::X86Sm4 { dst, .. }
            | OpKind::X86Convert16ToFp32 { dst, .. }
            | OpKind::X86PackedShiftImm { dst, .. }
            | OpKind::X86PackedAlignRight { dst, .. }
            | OpKind::X86PackedShuffleImm { dst, .. }
            | OpKind::X86ThreeDNow { dst, .. }
            | OpKind::X86PackedShift { dst, .. }
            | OpKind::X86PackedShiftVariable { dst, .. }
            | OpKind::X86PackedRotate { dst, .. }
            | OpKind::X86XopPackedBit { dst, .. }
            | OpKind::X86TernaryLogic { dst, .. }
            | OpKind::X86PackedFunnelShift { dst, .. }
            | OpKind::X86MultiShiftQB { dst, .. }
            | OpKind::VDotProductExt { dst, .. }
            | OpKind::IoIn { dst, .. }
            | OpKind::ReadFlags { dst, .. }
            | OpKind::TestCondition { dst, .. }
            | OpKind::SetCC { dst, .. }
            | OpKind::ReadSysReg { dst, .. } => vec![*dst],

            OpKind::ArmDpRegShift { dst, .. } => dst.iter().copied().collect(),

            OpKind::X86ReadTsc(op) => {
                let mut dests = vec![op.dst_lo, op.dst_hi];
                dests.extend(op.dst_aux);
                dests
            }

            OpKind::X86ReadPmc(op) => vec![op.dst_lo, op.dst_hi],

            OpKind::X86Opmask(op) => op.dests(),

            OpKind::X86Cpuid {
                dst_eax,
                dst_ebx,
                dst_ecx,
                dst_edx,
                ..
            } => vec![*dst_eax, *dst_ebx, *dst_ecx, *dst_edx],

            OpKind::X86X87Control {
                kind: X86X87ControlKind::StoreStatusAx,
                ..
            } => vec![VReg::Arch(ArchReg::X86(X86Reg::Rax))],

            OpKind::X86Enter(..) | OpKind::X86Leave(..) => vec![
                VReg::Arch(ArchReg::X86(X86Reg::Rsp)),
                VReg::Arch(ArchReg::X86(X86Reg::Rbp)),
            ],

            OpKind::X86StackFlags(..) => {
                vec![VReg::Arch(ArchReg::X86(X86Reg::Rsp))]
            }

            OpKind::VWidenMul { dst_lo, dst_hi, .. }
            | OpKind::VWidenExt { dst_lo, dst_hi, .. }
            | OpKind::VWidenAddSub { dst_lo, dst_hi, .. }
            | OpKind::VPairReduceMul { dst_lo, dst_hi, .. }
            | OpKind::VSlideReduceMul { dst_lo, dst_hi, .. }
            | OpKind::VRotReduceMulPair { dst_lo, dst_hi, .. }
            | OpKind::VPairPairReduceMul { dst_lo, dst_hi, .. }
            | OpKind::VLut16 { dst_lo, dst_hi, .. }
            | OpKind::VMulWord64Pair { dst_lo, dst_hi, .. }
            | OpKind::VShuffleEOPair { dst_lo, dst_hi, .. }
            | OpKind::VDealVdd { dst_lo, dst_hi, .. }
            | OpKind::VUnpackOAcc { dst_lo, dst_hi, .. }
            | OpKind::VMpyHsatAcc { dst_lo, dst_hi, .. }
            | OpKind::VAsrInto { dst_lo, dst_hi, .. }
            | OpKind::V6Mpy { dst_lo, dst_hi, .. }
            | OpKind::VShuffVdd { dst_lo, dst_hi, .. } => {
                vec![*dst_lo, *dst_hi]
            }

            // In-place dual-register shuffle/deal writes BOTH Vy and Vx.
            OpKind::VShuffleDeal { dst_y, dst_x, .. } => vec![*dst_y, *dst_x],

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
            | OpKind::VLaneCond { dst, .. }
            | OpKind::VPrefixSumQ { dst, .. }
            | OpKind::VInsertWordR { dst, .. }
            | OpKind::VExtractWord { dst, .. }
            | OpKind::VLut4 { dst, .. }
            | OpKind::VRotr { dst, .. }
            | OpKind::VAddSubMixedSat { dst, .. }
            | OpKind::VSetPredQ { dst, .. }
            | OpKind::VShuffEqQ { dst, .. }
            | OpKind::VMpaHhSat { dst, .. }
            | OpKind::VQFromVAndR { dst, .. } => vec![*dst],

            // The histogram family read-modify-writes the WHOLE V0..V31 file.
            OpKind::VHist { .. } => (0..32)
                .map(|n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n))))
                .collect(),

            // Carry forms write the result vector and (carry/carryo) the Q.
            OpKind::VCarry {
                dst,
                q_inout,
                has_cout,
                ..
            } => {
                if *has_cout {
                    vec![*dst, *q_inout]
                } else {
                    vec![*dst]
                }
            }

            OpKind::VSwap { dst_lo, dst_hi, .. } => vec![*dst_lo, *dst_hi],

            OpKind::VCondMove { dst_lo, dst_hi, .. } => {
                let mut v = vec![*dst_lo];
                if let Some(hi) = dst_hi {
                    v.push(*hi);
                }
                v
            }

            // Reciprocal/invsqrt seed (sfrecipa/sfinvsqrta) writes Rd AND the
            // predicate Pe; the fixup ops write only Rd.
            OpKind::HexFpRecip { dst, pred, .. } => {
                let mut v = vec![*dst];
                if let Some(p) = pred {
                    v.push(*p);
                }
                v
            }

            // CABAC decode writes the Rdd pair (dst) AND the P0 predicate.
            OpKind::HexCabacDecBin { dst, pred, .. } => vec![*dst, *pred],

            OpKind::RvFp { dst, fcsr_dst, .. } => vec![*dst, *fcsr_dst],

            OpKind::RvIntCrypto { dst, .. } => vec![*dst],

            OpKind::RvVector { state, .. } => {
                let mut v = Vec::with_capacity(68);
                v.extend(state.x_dsts.iter().copied().filter(|r| !r.is_imm()));
                v.extend(state.f_dsts.iter().copied().filter(|r| !r.is_imm()));
                v.extend(
                    [
                        state.fcsr_dst,
                        state.vl_dst,
                        state.vtype_dst,
                        state.vstart_dst,
                        state.vcsr_dst,
                    ]
                    .into_iter()
                    .filter(|r| !r.is_imm()),
                );
                v
            }

            OpKind::MulU { dst_lo, dst_hi, .. } | OpKind::MulS { dst_lo, dst_hi, .. } => {
                let mut v = vec![*dst_lo];
                if let Some(hi) = dst_hi {
                    v.push(*hi);
                }
                v
            }

            OpKind::ClMul { dst, dst_hi, .. } => {
                let mut v = vec![*dst];
                if let Some(hi) = dst_hi {
                    v.push(*hi);
                }
                v
            }

            OpKind::X86XGetBv {
                dst_low, dst_high, ..
            } => vec![*dst_low, *dst_high],

            OpKind::X86FsGsBase {
                operand,
                base,
                write,
                ..
            } => vec![if *write { *base } else { *operand }],

            OpKind::X86SwapGs {
                gs_base,
                kernel_gs_base,
            } => vec![*gs_base, *kernel_gs_base],

            OpKind::X86Pkru {
                eax,
                edx,
                pkru,
                write,
                ..
            } => {
                if *write {
                    vec![*pkru]
                } else {
                    vec![*eax, *edx]
                }
            }

            OpKind::X86Msr(msr) => {
                if msr.write {
                    vec![]
                } else {
                    vec![msr.eax, msr.edx]
                }
            }

            OpKind::X86Cmpxchg8b16b { dst_lo, dst_hi, .. } => vec![*dst_lo, *dst_hi],

            OpKind::X86Random { dst, .. }
            | OpKind::X86ReadPid { dst }
            | OpKind::X86ReadControl { dst, .. } => vec![*dst],
            OpKind::X86Smsw(X86SmswOp {
                target: X86SmswTarget::Register { dst, .. },
                ..
            }) => vec![*dst],
            OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Register { dst, .. },
                ..
            }) => vec![*dst],
            OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Stack { stack_pointer, .. },
                ..
            }) => vec![*stack_pointer],
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source: X86SystemSelectorSource::Stack { stack_pointer, .. },
                ..
            }) => vec![*stack_pointer],
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source: X86SystemSelectorSource::FarPointer { dst, .. },
                ..
            }) => vec![*dst],
            OpKind::X86SelectorQuery(query) => vec![query.dst],
            OpKind::X86FarJump(jump) => vec![jump.target],
            OpKind::X86FarCall(call) => vec![call.target],
            OpKind::X86FarReturn(ret) => vec![ret.target],
            OpKind::X86FastSystemTransfer(transfer) => {
                vec![transfer.target, transfer.stack_pointer]
            }
            OpKind::X86ReadDebug { dst, .. } => vec![*dst],

            OpKind::CmpyW128Sat { dst, .. } | OpKind::SatOrigShl { dst, .. } => vec![*dst],

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

            OpKind::X86String {
                kind,
                rep,
                accumulator,
                src_index,
                dst_index,
                count,
                ..
            } => {
                let mut dsts = match kind {
                    X86StringKind::Movs => vec![*src_index, *dst_index],
                    X86StringKind::Stos => vec![*dst_index],
                    X86StringKind::Lods => vec![*accumulator, *src_index],
                    X86StringKind::Scas => vec![*dst_index],
                    X86StringKind::Cmps => vec![*src_index, *dst_index],
                };
                if *rep != X86RepMode::None {
                    dsts.push(*count);
                }
                dsts
            }

            OpKind::LoadPair { dst1, dst2, .. } => vec![*dst1, *dst2],

            OpKind::Cas { dst, success, .. } => vec![*dst, *success],

            OpKind::CasPair {
                dst_lo,
                dst_hi,
                success,
                ..
            } => vec![*dst_lo, *dst_hi, *success],

            OpKind::StoreExclusive { status, .. } => vec![*status],

            OpKind::Xchg { reg1, reg2, .. } => vec![*reg1, *reg2],
            OpKind::X86Xadd(xadd) => vec![xadd.dst.vreg(), xadd.src.vreg()],
            OpKind::X86Cmpxchg(cmpxchg) => {
                vec![cmpxchg.dst.vreg(), VReg::Arch(ArchReg::X86(X86Reg::Rax))]
            }

            // No destination
            OpKind::Cmp { .. }
            | OpKind::Cmn { .. }
            | OpKind::Test { .. }
            | OpKind::Bt { .. }
            | OpKind::Store { .. }
            | OpKind::PredStore { .. }
            | OpKind::X86PackedFpConvertStore { .. }
            | OpKind::StorePair { .. }
            | OpKind::AtomicStore { .. }
            | OpKind::ClearExclusive
            | OpKind::Prefetch { .. }
            | OpKind::X86CacheControl { .. }
            | OpKind::CheckMemoryAlignment { .. }
            | OpKind::X86CheckAlignment { .. }
            | OpKind::X86CheckAlignmentAc { .. }
            | OpKind::Fence { .. }
            | OpKind::FCmp { .. }
            | OpKind::X86FpCompare { .. }
            | OpKind::VStore { .. }
            | OpKind::X86Sse4aMovntStore { .. }
            | OpKind::WriteFlags { .. }
            | OpKind::SetCF { .. }
            | OpKind::SetDF { .. }
            | OpKind::SetAC { .. }
            | OpKind::X86RequireApx
            | OpKind::X86RequireSse4a
            | OpKind::X86RequireTbm
            | OpKind::X86RequireXop
            | OpKind::X86Cli { .. }
            | OpKind::X86Sti { .. }
            | OpKind::CmcCF
            | OpKind::MaterializeFlags
            | OpKind::X86XTest
            | OpKind::X86LoadMxcsr { .. }
            | OpKind::X86StoreMxcsr { .. }
            | OpKind::X86X87Control {
                kind:
                    X86X87ControlKind::Init
                    | X86X87ControlKind::ClearExceptions
                    | X86X87ControlKind::EnterMmx
                    | X86X87ControlKind::EmptyMmx
                    | X86X87ControlKind::LoadControlWord
                    | X86X87ControlKind::StoreControlWord
                    | X86X87ControlKind::StoreStatusWord
                    | X86X87ControlKind::LoadEnvironment(_)
                    | X86X87ControlKind::StoreEnvironment(_)
                    | X86X87ControlKind::RestoreState(_)
                    | X86X87ControlKind::SaveState(_),
                ..
            }
            | OpKind::X86X87Data { .. }
            | OpKind::X86FxSave { .. }
            | OpKind::X86FxRstor { .. }
            | OpKind::X86XSave { .. }
            | OpKind::X86XRstor { .. }
            | OpKind::X86XSetBv { .. }
            | OpKind::X86Clts
            | OpKind::X86CacheMaintenance { .. }
            | OpKind::X86Smsw(X86SmswOp {
                target: X86SmswTarget::Memory { .. },
                ..
            })
            | OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Memory { .. },
                ..
            })
            | OpKind::X86SystemSelectorLoad(..)
            | OpKind::X86SelectorVerify(..)
            | OpKind::X86Lmsw(..)
            | OpKind::X86DescriptorTableStore(..)
            | OpKind::X86DescriptorTableLoad(..)
            | OpKind::X86Invlpg(..)
            | OpKind::X86Invpcid(..)
            | OpKind::X86WriteControl { .. }
            | OpKind::X86WriteDebug { .. }
            | OpKind::X86MonitorMwait(..)
            | OpKind::X86WaitPkg(..)
            | OpKind::Syscall { .. }
            | OpKind::IoOut { .. }
            | OpKind::Swi { .. }
            | OpKind::WriteSysReg { .. }
            | OpKind::X86Enter(..)
            | OpKind::X86Leave(..)
            | OpKind::EbpfInstruction { .. }
            | OpKind::HexagonPacketBegin
            | OpKind::HexagonPacketCommit
            | OpKind::Nop
            | OpKind::Undefined { .. }
            | OpKind::Breakpoint => vec![],
        }
    }

    /// Check if this operation has side effects
    pub fn has_side_effects(&self) -> bool {
        // Guest memory reads can fault or trigger MMIO/device effects even when
        // their destination is dead. Canonical DivU/DivS raise a trap for a
        // zero divisor (and x86 or SBPF quotient overflow) in every
        // architecture context, so a dead division still has a fault effect.
        self.reads_memory()
            || matches!(self, OpKind::DivU { .. } | OpKind::DivS { .. })
            || self.has_fp_status_side_effects()
            || matches!(self, OpKind::X86Opmask(op) if op.writes_memory())
            || matches!(
                self,
                OpKind::ArmInstructionBegin { .. }
                    | OpKind::ArmInstructionCommit { .. }
                    | OpKind::ArmPauth(..)
                    | OpKind::EbpfInstruction { .. }
                    | OpKind::HexagonPacketBegin
                    | OpKind::HexagonPacketCommit
                    | OpKind::Store { .. }
                    | OpKind::PredStore { .. }
                    | OpKind::X86PackedFpConvertStore { .. }
                    | OpKind::RepStos { .. }
                    | OpKind::RepMovs { .. }
                    | OpKind::X86String { .. }
                    | OpKind::StorePair { .. }
                    | OpKind::AtomicStore { .. }
                    | OpKind::AtomicRmw { .. }
                    | OpKind::Cas { .. }
                    | OpKind::CasPair { .. }
                    | OpKind::AtomicCmpXadd { .. }
                    | OpKind::StoreExclusive { .. }
                    | OpKind::RvVector { .. }
                    | OpKind::IoIn { .. }
                    | OpKind::IoOut { .. }
                    | OpKind::X86Enter(..)
                    | OpKind::X86StackFlags(..)
                    | OpKind::X86Leave(..)
                    | OpKind::ClearExclusive
                    | OpKind::Fence { .. }
                    | OpKind::VStore { .. }
                    | OpKind::X86Sse4aMovntStore { .. }
                    | OpKind::WriteFlags { .. }
                    | OpKind::SetCF { .. }
                    | OpKind::SetDF { .. }
                    | OpKind::SetAC { .. }
                    | OpKind::X86RequireApx
                    | OpKind::X86RequireSse4a
                    | OpKind::X86RequireTbm
                    | OpKind::X86RequireXop
                    | OpKind::X86Cli { .. }
                    | OpKind::X86Sti { .. }
                    | OpKind::CmcCF
                    | OpKind::MaterializeFlags
                    | OpKind::X86XTest
                    | OpKind::X86LoadMxcsr { .. }
                    | OpKind::X86StoreMxcsr { .. }
                    | OpKind::X86CacheControl { .. }
                    | OpKind::CheckMemoryAlignment { .. }
                    | OpKind::X86CheckAlignment { .. }
                    | OpKind::X86CheckAlignmentAc { .. }
                    | OpKind::X86X87Control {
                        kind:
                            X86X87ControlKind::Init
                            | X86X87ControlKind::ClearExceptions
                            | X86X87ControlKind::EnterMmx
                            | X86X87ControlKind::EmptyMmx
                            | X86X87ControlKind::StoreControlWord
                            | X86X87ControlKind::StoreStatusWord
                            | X86X87ControlKind::StoreEnvironment(_)
                            | X86X87ControlKind::SaveState(_),
                        ..
                    }
                    | OpKind::X86X87Data { .. }
                    | OpKind::X86FxSave { .. }
                    | OpKind::X86XSave { .. }
                    | OpKind::X86XGetBv { .. }
                    | OpKind::X86XSetBv { .. }
                    | OpKind::X86Clts
                | OpKind::X86CacheMaintenance { .. }
                    | OpKind::X86Msr(..)
                    | OpKind::X86ReadControl { .. }
                    | OpKind::X86Smsw(..)
                    | OpKind::X86SystemSelectorStore(..)
                    | OpKind::X86SystemSelectorLoad(..)
                    | OpKind::X86SelectorVerify(..)
                    | OpKind::X86SelectorQuery(..)
                    | OpKind::X86FarJump(..)
                    | OpKind::X86FarCall(..)
                    | OpKind::X86FarReturn(..)
                    | OpKind::X86FastSystemTransfer(..)
                    | OpKind::X86Lmsw(..)
                    | OpKind::X86DescriptorTableStore(..)
                    | OpKind::X86DescriptorTableLoad(..)
                    | OpKind::X86Invlpg(..)
                    | OpKind::X86Invpcid(..)
                    | OpKind::X86WriteControl { .. }
                    | OpKind::X86ReadDebug { .. }
                    | OpKind::X86WriteDebug { .. }
                    | OpKind::X86FsGsBase { .. }
                    | OpKind::X86SwapGs { .. }
                    | OpKind::X86MonitorMwait(..)
                    | OpKind::X86WaitPkg(..)
                    | OpKind::X86Pkru { .. }
                    | OpKind::X86Random { .. }
                    // A saturating clamp ORs the Hexagon USR:OVF sticky bit when it
                    // actually clamps and `set_ovf` is set. That update is invisible
                    // to `dests()`, so the op must be treated as side-effecting or DCE
                    // would drop it whenever its data destination is dead and silently
                    // lose the OVF update. `set_ovf == false` SatN has no side effect
                    // and stays removable. (#108)
                    | OpKind::SatN { set_ovf: true, .. }
                    | OpKind::Syscall { .. }
                    | OpKind::Swi { .. }
                    | OpKind::WriteSysReg { .. }
                    | OpKind::X86ReadTsc(..)
                    | OpKind::X86ReadPmc(..)
                    | OpKind::X86Cpuid { .. }
                    | OpKind::Breakpoint
            )
            || matches!(
                self,
                OpKind::X86FixupImm {
                    imm,
                    suppress_exceptions: false,
                    ..
                } if *imm != 0
            )
    }

    /// Check if this operation reads memory
    pub fn reads_memory(&self) -> bool {
        if let OpKind::ArmPauth(operation) = self {
            return matches!(
                operation.instruction,
                crate::isa::arm::aarch64::pauth_instruction::PauthInstruction::Load { .. }
            );
        }
        matches!(
            self,
            OpKind::Load { .. }
                | OpKind::PredLoad { .. }
                | OpKind::LoadPair { .. }
                | OpKind::AtomicLoad { .. }
                | OpKind::AtomicRmw { .. }
                | OpKind::Cas { .. }
                | OpKind::CasPair { .. }
                | OpKind::AtomicCmpXadd { .. }
                | OpKind::LoadExclusive { .. }
                | OpKind::RepMovs { .. }
                | OpKind::X86String { .. }
                | OpKind::VLoad { .. }
                | OpKind::PredVLoad { .. }
                | OpKind::VHist { .. }
                | OpKind::X86LoadMxcsr { .. }
                | OpKind::X86MonitorMwait(X86MonitorMwaitOp { addr: Some(_), .. })
                | OpKind::X86WaitPkg(X86WaitPkgOp::Umonitor { .. })
                | OpKind::X86Invpcid(..)
                | OpKind::X86Lmsw(X86LmswOp {
                    source: X86LmswSource::Memory { .. },
                    ..
                })
                | OpKind::X86X87Control {
                    kind: X86X87ControlKind::LoadControlWord
                        | X86X87ControlKind::LoadEnvironment(_)
                        | X86X87ControlKind::RestoreState(_),
                    addr: Some(_),
                }
                | OpKind::X86X87Data {
                    kind: X86X87DataKind::LoadExtended
                        | X86X87DataKind::LoadSingle
                        | X86X87DataKind::LoadDouble
                        | X86X87DataKind::LoadInt16
                        | X86X87DataKind::LoadInt32
                        | X86X87DataKind::LoadInt64
                        | X86X87DataKind::LoadBcd,
                    addr: Some(_),
                    ..
                }
                | OpKind::X86X87Data {
                    kind: X86X87DataKind::Compare {
                        source: X86X87CompareSource::Single | X86X87CompareSource::Double,
                        ..
                    },
                    addr: Some(_),
                    ..
                }
                | OpKind::X86X87Data {
                    kind: X86X87DataKind::Compare {
                        source: X86X87CompareSource::Int16 | X86X87CompareSource::Int32,
                        ..
                    },
                    addr: Some(_),
                    ..
                }
                | OpKind::X86X87Data {
                    kind: X86X87DataKind::Multiply {
                        source: X86X87ArithmeticSource::Single
                            | X86X87ArithmeticSource::Double
                            | X86X87ArithmeticSource::Int16
                            | X86X87ArithmeticSource::Int32,
                        ..
                    } | X86X87DataKind::AddSubtract {
                        source: X86X87ArithmeticSource::Single
                            | X86X87ArithmeticSource::Double
                            | X86X87ArithmeticSource::Int16
                            | X86X87ArithmeticSource::Int32,
                        ..
                    } | X86X87DataKind::Divide {
                        source: X86X87ArithmeticSource::Single
                            | X86X87ArithmeticSource::Double
                            | X86X87ArithmeticSource::Int16
                            | X86X87ArithmeticSource::Int32,
                        ..
                    },
                    addr: Some(_),
                    ..
                }
                | OpKind::X86FxRstor { .. }
                | OpKind::X86XRstor { .. }
                | OpKind::X86SystemSelectorLoad(..)
                | OpKind::X86SelectorVerify(..)
                | OpKind::X86SelectorQuery(..)
                | OpKind::X86FarJump(..)
                | OpKind::X86FarCall(..)
                | OpKind::X86FarReturn(..)
                | OpKind::X86DescriptorTableLoad(..)
                | OpKind::X86Cmpxchg8b16b { .. }
                | OpKind::X86XSave {
                    kind: X86XSaveKind::XSave | X86XSaveKind::XSaveOpt,
                    ..
                }
                | OpKind::X86CacheControl {
                    kind: X86CacheControlKind::Clflush
                        | X86CacheControlKind::Clflushopt
                        | X86CacheControlKind::Clwb,
                    ..
                }
                | OpKind::RvVector { .. }
                | OpKind::X86Enter(..)
                | OpKind::X86StackFlags(X86StackFlagsOp {
                    kind: X86StackFlagsKind::Pop,
                    ..
                })
                | OpKind::X86Leave(..)
        ) || matches!(self, OpKind::X86Opmask(op) if op.reads_memory())
    }

    /// Check if this operation writes memory
    pub fn writes_memory(&self) -> bool {
        matches!(
            self,
            OpKind::HexagonPacketCommit
                | OpKind::Store { .. }
                | OpKind::PredStore { .. }
                | OpKind::X86PackedFpConvertStore { .. }
                | OpKind::RepStos { .. }
                | OpKind::RepMovs { .. }
                | OpKind::X86String {
                    kind: X86StringKind::Movs | X86StringKind::Stos,
                    ..
                }
                | OpKind::StorePair { .. }
                | OpKind::AtomicStore { .. }
                | OpKind::AtomicRmw { .. }
                | OpKind::Cas { .. }
                | OpKind::CasPair { .. }
                | OpKind::AtomicCmpXadd { .. }
                | OpKind::StoreExclusive { .. }
                | OpKind::VStore { .. }
                | OpKind::X86Sse4aMovntStore { .. }
                | OpKind::X86StoreMxcsr { .. }
                | OpKind::X86X87Control {
                    kind: X86X87ControlKind::StoreControlWord
                        | X86X87ControlKind::StoreStatusWord
                        | X86X87ControlKind::StoreEnvironment(_)
                        | X86X87ControlKind::SaveState(_),
                    addr: Some(_),
                }
                | OpKind::X86X87Data {
                    kind: X86X87DataKind::StorePopExtended,
                    addr: Some(_),
                    ..
                }
                | OpKind::X86X87Data {
                    kind: X86X87DataKind::StoreInteger { .. },
                    addr: Some(_),
                    ..
                }
                | OpKind::X86X87Data {
                    kind: X86X87DataKind::StoreFloat { .. },
                    addr: Some(_),
                    ..
                }
                | OpKind::X86X87Data {
                    kind: X86X87DataKind::StoreBcd,
                    addr: Some(_),
                    ..
                }
                | OpKind::X86FxSave { .. }
                | OpKind::X86XSave { .. }
                | OpKind::X86Cmpxchg8b16b { .. }
                | OpKind::X86Smsw(X86SmswOp {
                    target: X86SmswTarget::Memory { .. },
                    ..
                })
                | OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                    target: X86SystemSelectorTarget::Memory { .. }
                        | X86SystemSelectorTarget::Stack { .. },
                    ..
                })
                | OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                    selector: X86SystemSelector::Tr
                        | X86SystemSelector::Es
                        | X86SystemSelector::Ss
                        | X86SystemSelector::Ds
                        | X86SystemSelector::Fs
                        | X86SystemSelector::Gs,
                    ..
                })
                | OpKind::X86FarJump(..)
                | OpKind::X86FarCall(..)
                | OpKind::X86FarReturn(..)
                | OpKind::X86DescriptorTableStore(..)
                | OpKind::X86Enter(..)
                | OpKind::X86StackFlags(X86StackFlagsOp {
                    kind: X86StackFlagsKind::Push,
                    ..
                })
                | OpKind::RvVector { .. }
        ) || matches!(self, OpKind::X86Opmask(op) if op.writes_memory())
    }
}
