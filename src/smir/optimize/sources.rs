//! Exhaustive source-register metadata for scalar, memory, and system operations.

use super::scalar_metadata;
use crate::smir::ir::ops::{
    OpKind, X86LmswOp, X86LmswSource, X86MonitorMwaitOp, X86SelectorQueryOp,
    X86SelectorQuerySource, X86SelectorVerifyOp, X86SelectorVerifySource, X86SmswOp, X86SmswTarget,
    X86SystemSelectorLoadOp, X86SystemSelectorSource, X86SystemSelectorStoreOp,
    X86SystemSelectorTarget, X86ThreeDNowKind, X86WaitPkgOp,
};
use crate::smir::ir::types::{ArchReg, ArmReg, HexagonReg, OpWidth, SrcOperand, VReg, X86Reg};

impl OpKind {
    /// Get source registers used by this operation
    pub fn source_vregs(&self) -> Vec<VReg> {
        let mut result = Vec::new();

        match self {
            OpKind::ArmPauth(..)
            | OpKind::ArmInstructionBegin { .. }
            | OpKind::ArmInstructionCommit { .. } => {
                result.extend(crate::smir::ir::ops::arm_boundary_state());
            }
            OpKind::HexagonPacketBegin | OpKind::HexagonPacketCommit => {
                result.extend(super::hexagon_packets::boundary_sources());
            }
            OpKind::X86Opmask(op) => result.extend(op.source_vregs()),

            OpKind::Add { src1, src2, .. }
            | OpKind::Sub { src1, src2, .. }
            | OpKind::Adc { src1, src2, .. }
            | OpKind::Sbb { src1, src2, .. }
            | OpKind::And { src1, src2, .. }
            | OpKind::Or { src1, src2, .. }
            | OpKind::Xor { src1, src2, .. }
            | OpKind::AndNot { src1, src2, .. }
            | OpKind::Cmp { src1, src2, .. }
            | OpKind::Cmn { src1, src2, .. }
            | OpKind::Test { src1, src2, .. } => {
                result.extend(scalar_metadata::scalar_alu_sources(*src1, src2));
            }

            OpKind::Shld {
                dst: src1,
                src: src3,
                amount: src2,
                ..
            }
            | OpKind::Shrd {
                dst: src1,
                src: src3,
                amount: src2,
                ..
            } => {
                result.push(*src1);
                result.push(*src3);
                if let SrcOperand::Reg(r) = src2 {
                    result.push(*r);
                }
            }

            OpKind::X86NddDoubleShift {
                base, fill, amount, ..
            } => {
                result.push(*base);
                result.push(*fill);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::MulU { src1, src2, .. } | OpKind::MulS { src1, src2, .. } => {
                result.push(*src1);
                if let SrcOperand::Reg(r) = src2 {
                    result.push(*r);
                }
            }

            OpKind::DivU {
                quot,
                rem,
                src1,
                src2,
                width,
                ..
            }
            | OpKind::DivS {
                quot,
                rem,
                src1,
                src2,
                width,
                ..
            } => {
                result.push(*src1);

                // The x86 one-operand W16/W32/W64 forms consume the implicit
                // high dividend half in RDX. Model that use explicitly so
                // liveness/DCE cannot erase a preceding CWD/CDQ/CQO or other
                // RDX definition. Byte forms consume AX, which is already
                // represented by the RAX source.
                let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
                let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
                if *quot == rax
                    && *rem == Some(rdx)
                    && *src1 == rax
                    && matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                {
                    result.push(rdx);
                }

                if let SrcOperand::Reg(r) = src2 {
                    result.push(*r);
                }
            }

            OpKind::MulAdd {
                acc, src1, src2, ..
            }
            | OpKind::MulSub {
                acc, src1, src2, ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::Bextr { src, control, .. } => {
                result.push(*src);
                result.push(*control);
            }

            OpKind::Bzhi { src, index, .. } => {
                result.push(*src);
                result.push(*index);
            }

            OpKind::X86Bls { src, .. } | OpKind::X86Tbm { src, .. } => result.push(*src),

            OpKind::X86Adx { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::Pdep { src, mask, .. } | OpKind::Pext { src, mask, .. } => {
                result.push(*src);
                result.push(*mask);
            }

            OpKind::Neg { src, .. }
            | OpKind::Inc { src, .. }
            | OpKind::Dec { src, .. }
            | OpKind::Not { src, .. }
            | OpKind::Cwd { src, .. }
            | OpKind::Bsf { src, .. }
            | OpKind::Bsr { src, .. }
            | OpKind::Clz { src, .. }
            | OpKind::Ctz { src, .. }
            | OpKind::Popcnt { src, .. }
            | OpKind::X86Count { src, .. }
            | OpKind::Bswap { src, .. }
            | OpKind::Rbit { src, .. } => {
                result.push(*src);
            }

            OpKind::X86Enter(..) => {
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rsp)));
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rbp)));
            }

            OpKind::X86StackFlags(..) => {
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rsp)));
            }

            OpKind::X86Leave(..) => {
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rbp)));
            }

            OpKind::Shl { src, amount, .. }
            | OpKind::Shr { src, amount, .. }
            | OpKind::Sar { src, amount, .. }
            | OpKind::Rol { src, amount, .. }
            | OpKind::Ror { src, amount, .. }
            | OpKind::ArmRegShift { src, amount, .. }
            | OpKind::Rcl { src, amount, .. }
            | OpKind::Rcr { src, amount, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::ArmDpRegShift { rn, rm, rs, .. } => {
                if let Some(rn) = rn {
                    result.push(*rn);
                }
                result.push(*rm);
                result.push(*rs);
            }

            // Bidirectional shift: both `src` and `amount` are SrcOperand.
            OpKind::BidirShift { src, amount, .. } => {
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            // Saturating clamp: `src` is a SrcOperand (register or immediate).
            OpKind::SatN { src, .. } => {
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
            }

            OpKind::Bt { src, index, .. }
            | OpKind::Bts { src, index, .. }
            | OpKind::Btr { src, index, .. }
            | OpKind::Btc { src, index, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(r) = index {
                    result.push(*r);
                }
            }

            OpKind::Bfx { src, .. } => {
                result.push(*src);
            }

            OpKind::Bfi { src, dst_in, .. } => {
                result.push(*src);
                result.push(*dst_in);
            }

            OpKind::Mov { src, .. } => {
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
            }

            OpKind::CMove { src, .. } => {
                result.push(*src);
            }

            OpKind::Select {
                cond,
                src_true,
                src_false,
                ..
            } => {
                result.push(*cond);
                result.push(*src_true);
                result.push(*src_false);
            }

            OpKind::ZeroExtend { src, .. }
            | OpKind::SignExtend { src, .. }
            | OpKind::Truncate { src, .. } => {
                result.push(*src);
            }

            OpKind::Lea { addr, .. } | OpKind::X86Lea { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::Xchg { reg1, reg2, .. } => {
                result.push(*reg1);
                result.push(*reg2);
            }

            OpKind::X86Xadd(xadd) => {
                result.push(xadd.dst.vreg());
                result.push(xadd.src.vreg());
            }

            OpKind::X86Cmpxchg(cmpxchg) => {
                result.push(cmpxchg.dst.vreg());
                result.push(cmpxchg.src.vreg());
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rax)));
            }

            OpKind::Load { addr, .. }
            | OpKind::AtomicLoad { addr, .. }
            | OpKind::LoadExclusive { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::Store { src, addr, .. } | OpKind::AtomicStore { src, addr, .. } => {
                result.push(*src);
                result.extend(addr.regs());
            }

            // Predicated load: reads the predicate `cond` and the address base
            // register(s). The `dst` is conditionally written (in dests()).
            OpKind::PredLoad { cond, addr, .. } => {
                result.push(*cond);
                result.extend(addr.regs());
            }

            OpKind::PredVLoad {
                dst, cond, addr, ..
            } => {
                result.push(*dst);
                result.push(*cond);
                result.extend(addr.regs());
            }

            // Predicated store: reads the predicate `cond`, the source operand
            // (when a register), and the address base register(s).
            OpKind::PredStore {
                src, cond, addr, ..
            } => {
                result.push(*cond);
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
                result.extend(addr.regs());
            }

            OpKind::RepStos {
                dst, src, count, ..
            } => {
                result.push(*dst);
                result.push(*src);
                result.push(*count);
            }

            OpKind::RepMovs {
                dst, src, count, ..
            } => {
                result.push(*dst);
                result.push(*src);
                result.push(*count);
            }

            OpKind::LoadPair { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::StorePair {
                src1, src2, addr, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(addr.regs());
            }

            OpKind::AtomicRmw { addr, src, .. } => {
                result.extend(addr.regs());
                result.push(*src);
            }

            OpKind::Cas {
                addr,
                expected,
                new_val,
                ..
            } => {
                result.extend(addr.regs());
                result.push(*expected);
                result.push(*new_val);
            }

            OpKind::CasPair {
                addr,
                expected_lo,
                expected_hi,
                new_lo,
                new_hi,
                ..
            } => {
                result.extend(addr.regs());
                result.extend([*expected_lo, *expected_hi, *new_lo, *new_hi]);
            }

            OpKind::AtomicCmpXadd { addr, cmp, add, .. } => {
                result.extend(addr.regs());
                result.push(*cmp);
                result.push(*add);
            }

            OpKind::StoreExclusive { src, addr, .. } => {
                result.push(*src);
                result.extend(addr.regs());
            }

            OpKind::IoIn { port, .. } => {
                result.push(*port);
            }

            OpKind::IoOut { port, value, .. } => {
                result.push(*port);
                result.push(*value);
            }

            OpKind::WriteFlags { src } | OpKind::WriteSysReg { src, .. } => {
                result.push(*src);
            }

            OpKind::Syscall { num, args } => {
                result.push(*num);
                result.extend(args.iter().copied());
            }

            // FP operations
            OpKind::FAdd { src1, src2, .. }
            | OpKind::FSub { src1, src2, .. }
            | OpKind::FMul { src1, src2, .. }
            | OpKind::FDiv { src1, src2, .. }
            | OpKind::FMin { src1, src2, .. }
            | OpKind::FMax { src1, src2, .. }
            | OpKind::FCmp { src1, src2, .. }
            | OpKind::X86FpCompare { src1, src2, .. }
            | OpKind::HexFp { src1, src2, .. }
            | OpKind::HexFpRecip { src1, src2, .. }
            | OpKind::HexCabacDecBin { src1, src2, .. }
            | OpKind::HexTlbMatch { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::FFma {
                src1, src2, src3, ..
            }
            | OpKind::HexFp3 {
                src1, src2, src3, ..
            }
            | OpKind::HexFpDf {
                src1, src2, src3, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
            }

            OpKind::HexFpScFma {
                src1,
                src2,
                src3,
                scale,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.push(*scale);
            }

            OpKind::RvFp {
                src1,
                src2,
                src3,
                fcsr_src,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.push(*fcsr_src);
            }

            OpKind::RvIntCrypto { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::RvVector {
                rs1, rs2, state, ..
            } => {
                result.push(*rs1);
                result.push(*rs2);
                result.extend(state.x_srcs.iter().copied().filter(|r| !r.is_imm()));
                result.extend(state.f_srcs.iter().copied().filter(|r| !r.is_imm()));
                result.extend(
                    [
                        state.fcsr_src,
                        state.vl_src,
                        state.vtype_src,
                        state.vstart_src,
                        state.vcsr_src,
                    ]
                    .into_iter()
                    .filter(|r| !r.is_imm()),
                );
            }

            OpKind::FAbs { src, .. }
            | OpKind::FNeg { src, .. }
            | OpKind::FSqrt { src, .. }
            | OpKind::FConvert { src, .. }
            | OpKind::IntToFp { src, .. }
            | OpKind::FpToInt { src, .. }
            | OpKind::X86FpToInt { src, .. }
            | OpKind::X86ScalarFpToIntSat { src, .. }
            | OpKind::FRound { src, .. } => {
                result.push(*src);
            }

            OpKind::X86IntToFp { merge, src, .. } => {
                result.push(*merge);
                result.push(*src);
            }

            OpKind::X86FpConvert {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.push(*merge);
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Round { merge, src, .. } => {
                result.push(*merge);
                result.push(*src);
            }

            OpKind::X86VectorFpCompare {
                src1, src2, mask, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::X86GetExponent {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86GetMantissa {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86RoundScale {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Reduce {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Range {
                dst,
                src1,
                src2,
                mask,
                mask_zeroing,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86FixupImm {
                dst,
                src1,
                src2,
                mask,
                ..
            } => {
                // Response action zero preserves the old destination even for
                // an active, unmasked lane, so `dst` is always a source.
                result.push(*dst);
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::X86Exp2 {
                dst,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Recip14 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            }
            | OpKind::X86Rsqrt14 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            }
            | OpKind::X86RecipFp16 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            }
            | OpKind::X86RsqrtFp16 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            }
            | OpKind::X86Recip28 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Rsqrt28 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86ScaleF {
                dst,
                src1,
                src2,
                mask,
                mask_zeroing,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86FP16Complex {
                dst,
                src1,
                src2,
                mask,
                mask_zeroing,
                accumulate,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
                if *accumulate || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86FourFma {
                dst,
                src0,
                src1,
                src2,
                src3,
                mem,
                mask,
                ..
            } => {
                result.push(*dst);
                result.push(*src0);
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.push(*mem);
                result.extend(mask.iter().copied());
            }

            OpKind::X86FourDotProduct {
                dst,
                src0,
                src1,
                src2,
                src3,
                mem,
                mask,
                ..
            } => {
                result.push(*dst);
                result.push(*src0);
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.push(*mem);
                result.extend(mask.iter().copied());
            }

            OpKind::X86PackedFpConvert {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if !zero_upper || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86PackedIntToFp {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            }
            | OpKind::X86PackedFpToInt {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if !zero_upper || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86PackedIntToFp16 {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if !zero_upper || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86PackedFp16ToInt {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if !zero_upper || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86PackedFpConvertStore {
                addr, src, mask, ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                result.extend(addr.regs());
            }

            OpKind::ArmSimdLong(operation) => result.extend(operation.sources()),
            OpKind::ArmSimdNarrow(operation) => result.extend(operation.sources()),
            OpKind::ArmSimdSaturating(operation) => result.extend(operation.sources()),

            // Vector operations
            OpKind::VAdd { src1, src2, .. }
            | OpKind::VSub { src1, src2, .. }
            | OpKind::VAddSubSat { src1, src2, .. }
            | OpKind::VMax { src1, src2, .. }
            | OpKind::VX86MinMax { src1, src2, .. }
            | OpKind::VMul { src1, src2, .. }
            | OpKind::VDiv { src1, src2, .. }
            | OpKind::VLane { src1, src2, .. }
            | OpKind::VAnd { src1, src2, .. }
            | OpKind::VAndNot { src1, src2, .. }
            | OpKind::VOr { src1, src2, .. }
            | OpKind::VXor { src1, src2, .. }
            | OpKind::VFMinMaxNm { src1, src2, .. }
            | OpKind::VPermute2 { src1, src2, .. }
            | OpKind::VCmp { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::X86ThreeDNow {
                src1, src2, kind, ..
            } => {
                if !matches!(
                    kind,
                    X86ThreeDNowKind::Pf2Iw
                        | X86ThreeDNowKind::Pi2Fw
                        | X86ThreeDNowKind::Pf2Id
                        | X86ThreeDNowKind::PfRcp
                        | X86ThreeDNowKind::PfRsqrt
                        | X86ThreeDNowKind::Pi2Fd
                ) {
                    result.push(*src1);
                }
                result.push(*src2);
            }

            OpKind::VBitSelect {
                mask,
                src_true,
                src_false,
                ..
            } => {
                result.push(*mask);
                result.push(*src_true);
                result.push(*src_false);
            }

            OpKind::VPermute {
                src1,
                src2,
                indices,
                ..
            } => {
                result.push(*src1);
                result.extend(src2.iter().copied());
                result.push(*indices);
            }

            OpKind::X86PermuteBytesWords {
                dst,
                table1,
                table2,
                indices,
                mask,
                zeroing,
                ..
            } => {
                if mask.is_some() && !zeroing {
                    result.push(*dst);
                }
                result.push(*table1);
                result.extend(table2.iter().copied());
                result.push(*indices);
                result.extend(mask.iter().copied());
            }

            OpKind::VMultiplyAdd52 {
                acc,
                src1,
                src2,
                mask,
                ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::VUnary { src, .. }
            | OpKind::X86Sqrt { src, .. }
            | OpKind::VReduce { src, .. }
            | OpKind::X86Phminposuw { src, .. }
            | OpKind::X86MovMask { src, .. }
            | OpKind::X86MovdQ { src, .. } => {
                result.push(*src);
            }

            OpKind::X86Sse4aBitfield { dst, source, .. } => {
                // Both forms read the old destination. Register forms also
                // obtain their controls (and INSERTQ payload) from `source`.
                result.extend([*dst, *source]);
            }

            OpKind::X86Sse4aMovntStore { src, addr, .. } => {
                result.push(*src);
                result.extend(addr.regs());
            }

            OpKind::VConflict { src, mask, .. } => {
                result.push(*src);
                result.extend(mask.iter().copied());
            }

            OpKind::VPopcnt { src, mask, .. } | OpKind::VLeadingZeros { src, mask, .. } => {
                result.push(*src);
                result.extend(mask.iter().copied());
            }

            OpKind::X86Aes { src1, src2, .. } => {
                result.push(*src1);
                result.extend(src2.iter().copied());
            }

            OpKind::VTableLookup {
                dst,
                table,
                num_tables,
                index,
                is_tbx,
                ..
            } => {
                result.push(*index);
                // The table is `num_tables` consecutive registers from `table`.
                if let VReg::Arch(ArchReg::Arm(ArmReg::V(base))) = table {
                    for i in 0..*num_tables {
                        result.push(VReg::Arch(ArchReg::Arm(ArmReg::V((base + i) % 32))));
                    }
                } else {
                    result.push(*table);
                }
                // TBX reads the destination (out-of-range indices keep it).
                if *is_tbx {
                    result.push(*dst);
                }
            }

            OpKind::VShift { src, amount, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VWidenMul {
                src1,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            }
            | OpKind::VWidenAddSub {
                src1,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                if *acc {
                    // accumulating form reads the existing destination pair
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VLaneUnary { src, .. } => {
                result.push(*src);
            }

            OpKind::VNavg { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VShiftAcc {
                src, amount, dst, ..
            } => {
                result.push(*src);
                // shift-accumulate reads the existing destination lane
                result.push(*dst);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VPairReduceMul {
                src_lo,
                src_hi,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            }
            | OpKind::VSlideReduceMul {
                src_lo,
                src_hi,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            }
            | OpKind::VRotReduceMulPair {
                src_lo,
                src_hi,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*src2);
                if *acc {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VPairPairReduceMul {
                src_lo,
                src_hi,
                src2_lo,
                src2_hi,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*src2_lo);
                result.push(*src2_hi);
            }

            OpKind::VReduceMul {
                src1,
                src2,
                dst,
                acc,
                ..
            }
            | OpKind::VMulEvenWiden {
                src1,
                src2,
                dst,
                acc,
                ..
            }
            | OpKind::VMulSubLane {
                src1,
                src2,
                dst,
                acc,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                if *acc {
                    result.push(*dst);
                }
            }

            OpKind::VWidenExt { src, .. } => {
                result.push(*src);
            }

            OpKind::VLut {
                src_idx,
                table,
                sel,
                dst,
                oracc,
                ..
            } => {
                result.push(*src_idx);
                result.push(*table);
                if let SrcOperand::Reg(r) = sel {
                    result.push(*r);
                }
                if *oracc {
                    result.push(*dst);
                }
            }

            OpKind::VLut16 {
                src_idx,
                table,
                sel,
                dst_lo,
                dst_hi,
                oracc,
                ..
            } => {
                result.push(*src_idx);
                result.push(*table);
                if let SrcOperand::Reg(r) = sel {
                    result.push(*r);
                }
                if *oracc {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VShuffVdd {
                src_lo,
                src_hi,
                amount,
                ..
            }
            | OpKind::VDealVdd {
                src_lo,
                src_hi,
                amount,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VShuffleEOPair { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            // In-place dual-register shuffle/deal reads AND writes both Vy and Vx.
            OpKind::VShuffleDeal {
                dst_y,
                dst_x,
                amount,
                ..
            } => {
                result.push(*dst_y);
                result.push(*dst_x);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            // vunpacko OR-accumulates the source into the existing dst pair.
            OpKind::VUnpackOAcc {
                src,
                dst_lo,
                dst_hi,
                ..
            } => {
                result.push(*src);
                result.push(*dst_lo);
                result.push(*dst_hi);
            }

            OpKind::VInsertWordR { dst, scalar } => {
                // read-modify-write: preserves the other words of dst.
                result.push(*dst);
                result.push(*scalar);
            }

            OpKind::VExtractWord { src, sel, .. } => {
                result.push(*src);
                result.push(*sel);
            }

            OpKind::VLut4 { src, table, .. } => {
                result.push(*src);
                result.push(*table);
            }

            OpKind::VRotr { src, amount, .. } => {
                result.push(*src);
                result.push(*amount);
            }

            OpKind::VAddSubMixedSat { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VSetPredQ { scalar, .. } => {
                result.push(*scalar);
            }

            OpKind::VShuffEqQ { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            // vmpa(Vx, Vu, Rtt):sat reads the dst (Vx) accumulator, Vu, and Rtt.
            OpKind::VMpaHhSat {
                dst, src, table, ..
            } => {
                result.push(*dst);
                result.push(*src);
                result.push(*table);
            }

            // vmpyhsat_acc accumulates into the existing dst pair.
            OpKind::VMpyHsatAcc {
                dst_lo,
                dst_hi,
                src,
                scalar,
            } => {
                result.push(*dst_lo);
                result.push(*dst_hi);
                result.push(*src);
                result.push(*scalar);
            }

            // vasr_into shifts Vu into the running accumulator pair (read+write).
            OpKind::VAsrInto {
                dst_lo,
                dst_hi,
                src,
                amount,
            } => {
                result.push(*dst_lo);
                result.push(*dst_hi);
                result.push(*src);
                result.push(*amount);
            }

            OpKind::V6Mpy {
                src_lo,
                src_hi,
                src2_lo,
                src2_hi,
                dst_lo,
                dst_hi,
                acc,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*src2_lo);
                result.push(*src2_hi);
                if *acc {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VDelta { src, control, .. } => {
                result.push(*src);
                result.push(*control);
            }

            OpKind::VPack { src1, src2, .. }
            | OpKind::VPackSat { src1, src2, .. }
            | OpKind::VShuffleEO { src1, src2, .. }
            | OpKind::VDealB4W { src1, src2, .. }
            | OpKind::VMulSubLaneFrac { src1, src2, .. }
            | OpKind::VMulSubLaneSh { src1, src2, .. }
            | OpKind::VMulShiftSat { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VMulWord64Pair {
                src1,
                src2,
                dst_lo,
                dst_hi,
                mode,
            } => {
                result.push(*src1);
                result.push(*src2);
                // mode 1 (vmpyowh_64_acc) reads the existing dst pair.
                if *mode == 1 {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VShuffle2 { src, .. } => {
                result.push(*src);
            }

            OpKind::VAlign {
                src1, src2, amount, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VShiftV { src, amount, .. } => {
                result.push(*src);
                result.push(*amount);
            }

            OpKind::VNarrowShiftSat {
                src_lo,
                src_hi,
                amount,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VSatDW { src_lo, src_hi, .. } => {
                result.push(*src_lo);
                result.push(*src_hi);
            }

            OpKind::VNarrowShiftV {
                src_lo,
                src_hi,
                amount,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*amount);
            }

            OpKind::VCmpToQ {
                dst,
                src1,
                src2,
                accumulate,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                if accumulate.is_some() {
                    result.push(*dst);
                }
            }

            OpKind::VBlend {
                mask_q,
                src_true,
                src_false,
                ..
            } => {
                result.push(*mask_q);
                result.push(*src_true);
                result.push(*src_false);
            }

            OpKind::VMaskZero {
                mask_q,
                src,
                dst,
                oracc,
                ..
            } => {
                result.push(*mask_q);
                result.push(*src);
                // oracc (vandqrt_acc) OR-accumulates into the existing dst.
                if *oracc {
                    result.push(*dst);
                }
            }

            OpKind::VQFromVAndR {
                src1,
                src2,
                dst,
                oracc,
            } => {
                result.push(*src1);
                result.push(*src2);
                // oracc (vandvrt_acc) OR-accumulates into the existing dst Q.
                if *oracc {
                    result.push(*dst);
                }
            }

            // Q-predicated conditional add/sub: dst is read-modify-written.
            OpKind::VLaneCond {
                dst, src, mask_q, ..
            } => {
                result.push(*dst);
                result.push(*src);
                result.push(*mask_q);
            }

            // Carry add/sub: reads both vectors; reads the carry Q when it has a
            // carry-in (carry / carrysat forms).
            OpKind::VCarry {
                src1,
                src2,
                q_inout,
                has_cin,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                if *has_cin {
                    result.push(*q_inout);
                }
            }

            OpKind::VSwap {
                mask_q, src1, src2, ..
            } => {
                result.push(*mask_q);
                result.push(*src1);
                result.push(*src2);
            }

            // Scalar-predicate-gated move/combine: when the gate is false the
            // dest(s) keep their prior value, so they are read; also reads the
            // predicate and the candidate sources.
            OpKind::VCondMove {
                dst_lo,
                dst_hi,
                src_lo,
                src_hi,
                pred,
                ..
            } => {
                result.push(*pred);
                result.push(*src_lo);
                result.push(*dst_lo);
                if let Some(hi) = dst_hi {
                    result.push(*src_hi);
                    result.push(*hi);
                }
            }

            OpKind::VPrefixSumQ { mask_q, .. } => {
                result.push(*mask_q);
            }

            // The histogram family read-modify-writes the WHOLE V0..V31 file and
            // reads the input vector from memory (the `.tmp` load's address) plus
            // the q-mask for the q-forms.
            OpKind::VHist {
                input,
                mask_q,
                use_q,
                ..
            } => {
                result.extend(input.regs());
                if *use_q {
                    result.push(*mask_q);
                }
                for n in 0..32u8 {
                    result.push(VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n))));
                }
            }

            OpKind::VMov { src, .. } | OpKind::VBroadcast { scalar: src, .. } => {
                result.push(*src);
            }

            OpKind::VInsertLane { vec, scalar, .. } => {
                result.push(*vec);
                result.push(*scalar);
            }

            OpKind::VExtractLane { vec, .. } => {
                result.push(*vec);
            }

            OpKind::VShuffle {
                src1,
                src2,
                indices,
                ..
            } => {
                result.push(*src1);
                if let Some(s2) = src2 {
                    result.push(*s2);
                }
                result.push(*indices);
            }

            OpKind::VInterleave { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VByteShuffle { src, control, .. } => {
                result.push(*src);
                result.push(*control);
            }

            OpKind::VHorizontalBin { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VLoad { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::X86LoadMxcsr { addr, .. } | OpKind::X86StoreMxcsr { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::CheckMemoryAlignment { addr, cond, .. } => {
                result.extend(addr.regs());
                result.extend(*cond);
            }

            OpKind::X86CacheControl { addr, .. }
            | OpKind::X86CheckAlignment { addr, .. }
            | OpKind::X86CheckAlignmentAc { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::X86FxSave { addr, .. } | OpKind::X86FxRstor { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::X86XSave {
                addr,
                src_low,
                src_high,
                ..
            }
            | OpKind::X86XRstor {
                addr,
                src_low,
                src_high,
                ..
            } => {
                result.extend(addr.regs());
                result.extend([*src_low, *src_high]);
            }

            OpKind::X86XGetBv { selector, .. } => result.push(*selector),
            OpKind::X86XSetBv {
                selector,
                src_low,
                src_high,
            } => result.extend([*selector, *src_low, *src_high]),
            OpKind::X86FsGsBase {
                operand,
                base,
                write,
                ..
            } => result.push(if *write { *operand } else { *base }),
            OpKind::X86SwapGs {
                gs_base,
                kernel_gs_base,
            } => result.extend([*gs_base, *kernel_gs_base]),
            OpKind::X86MonitorMwait(X86MonitorMwaitOp {
                rcx, hint, addr, ..
            }) => {
                result.extend([*rcx, *hint]);
                if let Some(addr) = addr {
                    result.extend(addr.regs());
                }
            }
            OpKind::X86WaitPkg(X86WaitPkgOp::Umonitor { addr, .. }) => {
                result.extend(addr.regs());
            }
            OpKind::X86WaitPkg(
                X86WaitPkgOp::Umwait {
                    control,
                    deadline_low,
                    deadline_high,
                }
                | X86WaitPkgOp::Tpause {
                    control,
                    deadline_low,
                    deadline_high,
                },
            ) => result.extend([*control, *deadline_low, *deadline_high]),
            OpKind::X86Pkru {
                eax,
                ecx,
                edx,
                pkru,
                write,
            } => {
                if *write {
                    result.extend([*eax, *ecx, *edx]);
                } else {
                    result.extend([*ecx, *pkru]);
                }
            }
            OpKind::X86Cpuid { leaf, subleaf, .. } => result.extend([*leaf, *subleaf]),
            OpKind::X86ReadPmc(read) => result.push(read.selector),
            OpKind::X86Msr(msr) => {
                result.push(msr.ecx);
                if msr.write {
                    result.extend([msr.eax, msr.edx]);
                }
            }
            OpKind::X86WriteControl { src, .. } | OpKind::X86WriteDebug { src, .. } => {
                result.push(*src)
            }
            OpKind::X86Smsw(X86SmswOp {
                target: X86SmswTarget::Memory { addr },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Memory { addr },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Stack { stack_pointer, .. },
                ..
            }) => result.push(*stack_pointer),
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source: X86SystemSelectorSource::Register { src },
                ..
            }) => result.push(*src),
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source: X86SystemSelectorSource::Memory { addr, .. },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source: X86SystemSelectorSource::Stack { stack_pointer, .. },
                ..
            }) => result.push(*stack_pointer),
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source:
                    X86SystemSelectorSource::FarPointer {
                        addr,
                        dst,
                        offset_width,
                        ..
                    },
                ..
            }) => {
                result.extend(addr.regs());
                if *offset_width == OpWidth::W16 {
                    result.push(*dst);
                }
            }
            OpKind::X86SelectorVerify(X86SelectorVerifyOp {
                source: X86SelectorVerifySource::Register { src },
                ..
            }) => result.push(*src),
            OpKind::X86SelectorVerify(X86SelectorVerifyOp {
                source: X86SelectorVerifySource::Memory { addr, .. },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86SelectorQuery(X86SelectorQueryOp {
                dst,
                source: X86SelectorQuerySource::Register { src },
                ..
            }) => result.extend([*dst, *src]),
            OpKind::X86SelectorQuery(X86SelectorQueryOp {
                dst,
                source: X86SelectorQuerySource::Memory { addr, .. },
                ..
            }) => {
                result.push(*dst);
                result.extend(addr.regs());
            }
            OpKind::X86FarJump(jump) => result.extend(jump.addr.regs()),
            OpKind::X86FarCall(call) => result.extend(call.addr.regs()),
            OpKind::X86FarReturn(..) => {}
            OpKind::X86FastSystemTransfer(transfer) => {
                if transfer.kind == crate::smir::ir::ops::X86FastSystemTransferKind::Sysexit {
                    result.extend([transfer.return_stack_pointer, transfer.return_target]);
                }
            }
            OpKind::X86Lmsw(X86LmswOp {
                source: X86LmswSource::Register { src },
                ..
            }) => result.push(*src),
            OpKind::X86Lmsw(X86LmswOp {
                source: X86LmswSource::Memory { addr },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86DescriptorTableStore(store) => result.extend(store.addr.regs()),
            OpKind::X86DescriptorTableLoad(load) => result.extend(load.addr.regs()),
            OpKind::X86Invlpg(invlpg) => result.extend(invlpg.addr.regs()),
            OpKind::X86Invpcid(invpcid) => {
                result.push(invpcid.invpcid_type);
                result.extend(invpcid.addr.regs());
            }

            OpKind::X86Cmpxchg8b16b {
                addr,
                compare_lo,
                compare_hi,
                new_lo,
                new_hi,
                ..
            } => {
                result.extend(addr.regs());
                result.extend([*compare_lo, *compare_hi, *new_lo, *new_hi]);
            }

            OpKind::X86X87Control {
                addr: Some(addr), ..
            } => {
                result.extend(addr.regs());
            }

            OpKind::X86X87Data {
                addr: Some(addr), ..
            } => {
                result.extend(addr.regs());
            }

            OpKind::VStore { src, addr, .. } => {
                result.push(*src);
                result.extend(addr.regs());
            }

            // Operations with no source registers
            OpKind::ReadFlags { .. }
            | OpKind::SetCF { .. }
            | OpKind::SetDF { .. }
            | OpKind::SetAC { .. }
            | OpKind::X86RequireApx
            | OpKind::X86RequireSse4a
            | OpKind::X86RequireTbm
            | OpKind::X86RequireXop
            | OpKind::X86Cli { .. }
            | OpKind::X86Sti { .. }
            | OpKind::X86Clts
            | OpKind::X86CacheMaintenance { .. }
            | OpKind::X86ReadControl { .. }
            | OpKind::X86Smsw(X86SmswOp {
                target: X86SmswTarget::Register { .. },
                ..
            })
            | OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Register { .. },
                ..
            })
            | OpKind::X86ReadDebug { .. }
            | OpKind::X86ReadTsc(..)
            | OpKind::X86Random { .. }
            | OpKind::X86ReadPid { .. }
            | OpKind::X86X87Control { addr: None, .. }
            | OpKind::X86X87Data { addr: None, .. }
            | OpKind::CmcCF
            | OpKind::MaterializeFlags
            | OpKind::X86XTest
            | OpKind::TestCondition { .. }
            | OpKind::SetCC { .. }
            | OpKind::ClearExclusive
            | OpKind::Prefetch { .. }
            | OpKind::Fence { .. }
            | OpKind::IoIn { .. }
            | OpKind::IoOut { .. }
            | OpKind::Swi { .. }
            | OpKind::ReadSysReg { .. }
            | OpKind::EbpfInstruction { .. }
            | OpKind::Nop
            | OpKind::Undefined { .. }
            | OpKind::Breakpoint => {}

            OpKind::ClMul { .. }
            | OpKind::CmpyW128Sat { .. }
            | OpKind::Crc32C { .. }
            | OpKind::SatOrigShl { .. }
            | OpKind::VCompress { .. }
            | OpKind::VConflict { .. }
            | OpKind::VCvtBF16ToFP32 { .. }
            | OpKind::VCvtFP32ToBF16 { .. }
            | OpKind::VCvtFpToIntSat { .. }
            | OpKind::VDotProduct { .. }
            | OpKind::VDotProductBF16 { .. }
            | OpKind::VDotProductExt { .. }
            | OpKind::VExpand { .. }
            | OpKind::VFP16Arith { .. }
            | OpKind::VFma { .. }
            | OpKind::VLeadingZeros { .. }
            | OpKind::VMin { .. }
            | OpKind::VMinMax { .. }
            | OpKind::VMpsadbw { .. }
            | OpKind::VMultiplyAdd52 { .. }
            | OpKind::VPermute { .. }
            | OpKind::VPopcnt { .. }
            | OpKind::VSadBytes { .. }
            | OpKind::VShuffleBitQM { .. }
            | OpKind::X86Aes { .. }
            | OpKind::X86Convert16ToFp32 { .. }
            | OpKind::X86DotProduct { .. }
            | OpKind::X86FP16Fma { .. }
            | OpKind::X86Fma(..)
            | OpKind::X86FpBinary { .. }
            | OpKind::X86MultiShiftQB { .. }
            | OpKind::X86NarrowInt { .. }
            | OpKind::X86PackedAlignRight { .. }
            | OpKind::X86PackedFunnelShift { .. }
            | OpKind::X86PackedRotate { .. }
            | OpKind::X86PackedShift { .. }
            | OpKind::X86PackedShiftImm { .. }
            | OpKind::X86PackedShiftVariable { .. }
            | OpKind::X86PackedShuffleImm { .. }
            | OpKind::X86PackedStringCompare { .. }
            | OpKind::X86PermuteBytesWords { .. }
            | OpKind::X86Sha32 { .. }
            | OpKind::X86Sha512Msg1 { .. }
            | OpKind::X86Sha512Msg2 { .. }
            | OpKind::X86Sha512Rounds2 { .. }
            | OpKind::X86Sm3Msg1 { .. }
            | OpKind::X86Sm3Msg2 { .. }
            | OpKind::X86Sm3Rounds2 { .. }
            | OpKind::X86Sm4 { .. }
            | OpKind::X86String { .. }
            | OpKind::X86TernaryLogic { .. }
            | OpKind::X86XopPackedBit { .. } => result.extend(self.vector_source_vregs()),
        }

        result
    }
}
