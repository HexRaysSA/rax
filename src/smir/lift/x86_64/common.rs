//! Register, addressing, and condition-code lifting helpers

use crate::isa::x86_64::apx::rex2_reserved_opcode_len;
use crate::smir::lift::x86_64::*;
use std::collections::{HashMap, HashSet};

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::memory::MemoryError;
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86AdxKind, X86AluEncoding, X86BlsKind, X86CacheControlKind, X86CountKind,
    X86GprOperand, X86OpHint, X86RepMode, X86SsePrefix, X86StringKind, X86ThreeDNowKind,
    X86VecAlign, X86VecMap, X86X87ArithmeticDestination, X86X87ArithmeticSource,
    X86X87CompareSource, X86X87Constant, X86X87ControlKind, X86X87DataKind, X86X87EnvWidth,
    X86X87FloatWidth, X86X87IntWidth, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
    X86InstructionBytes,
};
use crate::smir::lift::{
    ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader, SmirLifter,
};

impl X86_64Lifter {
    /// Return the decode length at which a REX2 reservation is known.
    ///
    /// Intel APX reserves map-0 rows 4, 7, A (except JMPABS A1), and E,
    /// map-1 rows 3 and 8, and every memory XSAVE*/XRSTOR* encoding. A missing
    /// XSAVE-family ModR/M byte is not classified here so the owning decoder
    /// can report the exact incomplete-fetch boundary.
    pub(crate) fn rex2_reserved_bytes_consumed(
        &self,
        prefix: &X86Prefix,
        opcode_bytes: &[u8],
    ) -> Option<usize> {
        prefix.rex2?;
        let &opcode = opcode_bytes.first()?;
        let opcode_len =
            rex2_reserved_opcode_len(prefix.rex2_m(), opcode, opcode_bytes.get(1).copied())?;
        Some(prefix.cursor + opcode_len)
    }

    /// Materialize the dynamic APX availability requirement carried by a REX2
    /// encoding when the instruction's ordinary SMIR semantics do not retain
    /// prefix provenance themselves.
    pub(crate) fn rex2_apx_guard_ops(&self, prefix: &X86Prefix, pc: u64) -> Vec<SmirOp> {
        if prefix.rex2.is_some() {
            vec![SmirOp::new(OpId(0), pc, OpKind::X86RequireApx)]
        } else {
            Vec::new()
        }
    }

    /// Preserve the dynamic APX requirement when an existing EVEX instruction
    /// accesses an extended memory base or index register.
    pub(crate) fn retain_evex_memory_apx_requirement(
        &self,
        modrm: &ModRm,
        pc: u64,
        mut result: LiftResult,
    ) -> LiftResult {
        let requires_apx = modrm.addr.as_ref().is_some_and(|addr| {
            addr.base.is_some_and(|base| base >= 16) || addr.index.is_some_and(|index| index >= 16)
        });
        if !requires_apx || Self::result_starts_with_apx_requirement(&result) {
            return result;
        }

        result
            .ops
            .insert(0, SmirOp::new(OpId(0), pc, OpKind::X86RequireApx));
        for (index, op) in result.ops.iter_mut().enumerate() {
            op.id = OpId(index as u16);
        }
        result
    }

    /// Preserve the dynamic APX requirement at the common VEX/EVEX dispatch
    /// boundary. Current semantic EVEX forms with bytes beyond their opcode
    /// have a ModR/M byte at this cursor; terminal static-invalid results and
    /// current no-ModR/M forms retain their original decode frontier.
    pub(crate) fn retain_vec_memory_apx_requirement(
        &self,
        prefix: VecPrefix,
        bytes: &[u8],
        pc: u64,
        result: LiftResult,
    ) -> Result<LiftResult, LiftError> {
        if prefix.encoding != VecEncodingKind::Evex
            || (!prefix.mem_base_high && !prefix.mem_index_high)
            || matches!(
                result.control_flow,
                ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode
                }
            )
        {
            return Ok(result);
        }

        let cursor = prefix.bytes + 1;
        if result.bytes_consumed <= cursor {
            return Ok(result);
        }
        let mut modrm = decode_modrm(&bytes[cursor..], &prefix.modrm_prefix(cursor), pc)?;
        if cursor + modrm.bytes_consumed > result.bytes_consumed {
            return Ok(result);
        }

        if prefix.map == X86VecMap::Map0F38
            && matches!(bytes.get(prefix.bytes), Some(0x90..=0x93 | 0xA0..=0xA3))
        {
            // APX 355828-007US section 3.1.2.3.3/Table 3.3: the VSIB
            // index is a vector register selected by V'/X/SIB.index. X4
            // is unused, not an EGPR index extension. Only an actual B4
            // base can require APX; no-base B4 is likewise ignored.
            if let Some(addr) = &mut modrm.addr {
                addr.index = None;
            }
        }

        Ok(self.retain_evex_memory_apx_requirement(&modrm, pc, result))
    }

    /// Preserve the dynamic APX requirement for every successful REX2 lift.
    /// Dedicated fault-precise system operations retain the requirement in
    /// their first operation; all generic instruction decompositions receive
    /// an operand-free guard before their first temporary, memory access, flag
    /// update, architectural commit, or control-flow effect.
    pub(crate) fn retain_rex2_apx_requirement(
        &self,
        prefix: &X86Prefix,
        pc: u64,
        mut result: LiftResult,
    ) -> LiftResult {
        if prefix.rex2.is_none() || Self::result_starts_with_apx_requirement(&result) {
            return result;
        }

        result
            .ops
            .insert(0, SmirOp::new(OpId(0), pc, OpKind::X86RequireApx));
        for (index, op) in result.ops.iter_mut().enumerate() {
            op.id = OpId(index as u16);
        }
        result
    }

    fn result_starts_with_apx_requirement(result: &LiftResult) -> bool {
        let op_guarded = result.ops.first().is_some_and(|op| match &op.kind {
            OpKind::X86RequireApx => true,
            OpKind::X86Cli { requires_apx, .. }
            | OpKind::X86Sti { requires_apx, .. }
            | OpKind::X86FsGsBase { requires_apx, .. }
            | OpKind::X86LoadMxcsr { requires_apx, .. }
            | OpKind::X86StoreMxcsr { requires_apx, .. } => *requires_apx,
            OpKind::X86Smsw(op) => op.requires_apx,
            OpKind::X86SystemSelectorStore(op) => op.requires_apx,
            OpKind::X86SystemSelectorLoad(op) => op.requires_apx,
            OpKind::X86SelectorVerify(op) => op.requires_apx,
            OpKind::X86SelectorQuery(op) => op.requires_apx,
            OpKind::X86FarJump(op) => op.requires_apx,
            OpKind::X86FarCall(op) => op.requires_apx,
            OpKind::X86FarReturn(op) => op.requires_apx,
            OpKind::X86Enter(op) => op.requires_apx,
            OpKind::X86Leave(op) => op.requires_apx,
            OpKind::X86StackFlags(op) => op.requires_apx,
            OpKind::X86Lmsw(op) => op.requires_apx,
            OpKind::X86Invlpg(op) => op.requires_apx,
            OpKind::X86Invpcid(op) => op.requires_apx,
            OpKind::X86DescriptorTableStore(op) => op.requires_apx,
            OpKind::X86DescriptorTableLoad(op) => op.requires_apx,
            _ => false,
        });
        op_guarded
            || matches!(
                &result.control_flow,
                ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode
                } | ControlFlow::Trap {
                    kind: TrapKind::X86Debug {
                        requires_apx: true,
                        ..
                    } | TrapKind::X86Breakpoint {
                        requires_apx: true,
                        ..
                    } | TrapKind::X86SoftwareInterrupt {
                        requires_apx: true,
                        ..
                    } | TrapKind::X86InterruptReturn {
                        requires_apx: true,
                        ..
                    } | TrapKind::X86StringIo {
                        requires_apx: true,
                        ..
                    }
                }
            )
    }

    /// Convert x86 register number to VReg
    pub(crate) fn x86_gpr(&self, reg: u8) -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::gpr(reg)))
    }

    /// Get x86 register by number
    pub(crate) fn gpr(&self, reg: u8) -> VReg {
        self.x86_gpr(reg & 0x1F)
    }

    /// Decode one register operand while retaining the legacy high-byte lane
    /// that has no standalone architectural-register identity in SMIR.
    pub(crate) fn x86_gpr_operand(&self, reg: u8, prefix: &X86Prefix) -> X86GprOperand {
        if !prefix.has_rex() && (4..=7).contains(&(reg & 7)) {
            X86GprOperand::high(X86Reg::gpr((reg & 7) - 4))
        } else {
            X86GprOperand::low(X86Reg::gpr(reg & 0x1F))
        }
    }

    /// Decode an 8-bit register source, extracting AH/CH/DH/BH when no REX
    /// prefix is present. With REX, codes 4..7 remain SPL/BPL/SIL/DIL.
    pub(crate) fn read_byte_reg(
        &self,
        reg: u8,
        prefix: &X86Prefix,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> VReg {
        if !prefix.has_rex() && (4..=7).contains(&(reg & 7)) {
            let tmp = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Shr {
                    dst: tmp,
                    src: self.gpr((reg & 7) - 4),
                    amount: SrcOperand::Imm(8),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            tmp
        } else {
            self.gpr(reg)
        }
    }

    /// Return the aliased full GPR for an AH/CH/DH/BH destination.
    pub(crate) fn high_byte_base(&self, reg: u8, prefix: &X86Prefix) -> Option<VReg> {
        (!prefix.has_rex() && (4..=7).contains(&(reg & 7))).then(|| self.gpr((reg & 7) - 4))
    }

    /// Merge the low byte of `value` into bits 15:8 of `base`, preserving all
    /// other bits. All helper arithmetic is explicitly flag-free.
    pub(crate) fn merge_high_byte(
        &self,
        base: VReg,
        value: VReg,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) {
        let byte = ctx.alloc_vreg();
        let shifted = ctx.alloc_vreg();
        let preserved = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::And {
                dst: byte,
                src1: value,
                src2: SrcOperand::Imm(0xFF),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Shl {
                dst: shifted,
                src: byte,
                amount: SrcOperand::Imm(8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::And {
                dst: preserved,
                src1: base,
                src2: SrcOperand::Imm(!0xFF00u64 as i64),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Or {
                dst: base,
                src1: preserved,
                src2: SrcOperand::Reg(shifted),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
    }

    /// Write an 8-bit register destination from `value`, including the legacy
    /// high-byte aliases when no REX prefix is present.
    pub(crate) fn write_byte_reg(
        &self,
        reg: u8,
        prefix: &X86Prefix,
        value: VReg,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) {
        if let Some(base) = self.high_byte_base(reg, prefix) {
            self.merge_high_byte(base, value, pc, ctx, ops);
        } else {
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Mov {
                    dst: self.gpr(reg),
                    src: SrcOperand::Reg(value),
                    width: OpWidth::W8,
                },
            ));
        }
    }

    pub(crate) fn xmm(&self, reg: u8) -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::Xmm(reg)))
    }

    pub(crate) fn mm(&self, reg: u8) -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::Mm(reg & 0x7)))
    }

    pub(crate) fn ymm(&self, reg: u8) -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::Ymm(reg)))
    }

    pub(crate) fn zmm(&self, reg: u8) -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::Zmm(reg)))
    }

    pub(crate) fn vec_reg(&self, reg: u8, width: VecWidth) -> VReg {
        match width {
            VecWidth::V128 => self.xmm(reg),
            VecWidth::V256 => self.ymm(reg),
            VecWidth::V512 => self.zmm(reg),
            VecWidth::V64 => self.xmm(reg),
        }
    }

    /// Get RSP register
    pub(crate) fn rsp(&self) -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::Rsp))
    }

    /// Convert op_size to OpWidth
    pub(crate) fn size_to_width(&self, size: u8) -> OpWidth {
        match size {
            1 => OpWidth::W8,
            2 => OpWidth::W16,
            4 => OpWidth::W32,
            8 => OpWidth::W64,
            _ => OpWidth::W32,
        }
    }

    /// Convert op_size to MemWidth
    pub(crate) fn size_to_memwidth(&self, size: u8) -> MemWidth {
        match size {
            1 => MemWidth::B1,
            2 => MemWidth::B2,
            4 => MemWidth::B4,
            8 => MemWidth::B8,
            _ => MemWidth::B4,
        }
    }

    /// Materialize a 32-bit effective address selected by a `67h` override in
    /// 64-bit mode. Base, index, scaling, and displacement are evaluated
    /// modulo 2^32; RIP-relative forms first add the next RIP and displacement
    /// at that width. The resulting offset is zero-extended to 64 bits before
    /// an optional FS/GS segment base is added. Flag-neutral integer operations
    /// make this width rule explicit to interpreters and native lowerers.
    pub(crate) fn x86_addr32_to_smir(
        &self,
        x86_addr: &X86Address,
        next_rip: u64,
        ctx: &mut LiftContext,
        gpr_override: Option<(u8, VReg)>,
    ) -> (Address, Vec<SmirOp>) {
        debug_assert_eq!(x86_addr.address_width, OpWidth::W32);

        let mut pre_ops = Vec::new();
        let pc = ctx.guest_pc;
        let displacement = i64::from(if x86_addr.rip_relative {
            next_rip.wrapping_add_signed(x86_addr.disp) as u32
        } else {
            x86_addr.disp as u32
        });
        let segment = x86_addr.segment.map(|seg| VReg::Arch(ArchReg::X86(seg)));
        let gpr = |index| match gpr_override {
            Some((from, replacement)) if index == from => replacement,
            _ => self.gpr(index),
        };

        // A displacement-only address has no dynamic arithmetic operands.
        // Normalize either disp32 or EIP+disp32 directly to the architectural
        // zero-extended 32-bit offset.
        if x86_addr.base.is_none() && x86_addr.index.is_none() {
            return match segment {
                Some(segment) => (
                    Address::SegmentRel {
                        segment,
                        base: None,
                        index: None,
                        scale: 1,
                        disp: displacement,
                    },
                    pre_ops,
                ),
                None => (Address::Absolute(displacement as u64), pre_ops),
            };
        }

        let mut offset = match (x86_addr.base, x86_addr.index) {
            (Some(base), None) => {
                let dst = ctx.alloc_vreg();
                let kind = if x86_addr.disp == 0 {
                    OpKind::Mov {
                        dst,
                        src: SrcOperand::Reg(gpr(base)),
                        width: OpWidth::W32,
                    }
                } else {
                    OpKind::Add {
                        dst,
                        src1: gpr(base),
                        src2: SrcOperand::Imm(x86_addr.disp),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }
                };
                pre_ops.push(SmirOp::new(OpId(pre_ops.len() as u16), pc, kind));
                dst
            }
            (None, Some(index)) => {
                let dst = ctx.alloc_vreg();
                let kind = if x86_addr.scale == 1 {
                    OpKind::Mov {
                        dst,
                        src: SrcOperand::Reg(gpr(index)),
                        width: OpWidth::W32,
                    }
                } else {
                    OpKind::Shl {
                        dst,
                        src: gpr(index),
                        amount: SrcOperand::Imm(x86_addr.scale.trailing_zeros() as i64),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }
                };
                pre_ops.push(SmirOp::new(OpId(pre_ops.len() as u16), pc, kind));
                dst
            }
            (Some(base), Some(index)) => {
                let scaled_index = if x86_addr.scale == 1 {
                    gpr(index)
                } else {
                    let dst = ctx.alloc_vreg();
                    pre_ops.push(SmirOp::new(
                        OpId(pre_ops.len() as u16),
                        pc,
                        OpKind::Shl {
                            dst,
                            src: gpr(index),
                            amount: SrcOperand::Imm(x86_addr.scale.trailing_zeros() as i64),
                            width: OpWidth::W32,
                            flags: FlagUpdate::None,
                        },
                    ));
                    dst
                };
                let dst = ctx.alloc_vreg();
                pre_ops.push(SmirOp::new(
                    OpId(pre_ops.len() as u16),
                    pc,
                    OpKind::Add {
                        dst,
                        src1: gpr(base),
                        src2: SrcOperand::Reg(scaled_index),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    },
                ));
                dst
            }
            (None, None) => unreachable!(),
        };

        // The base-only case folded its displacement into the first Add. All
        // indexed forms apply it after scaling/base addition, still at W32.
        if x86_addr.index.is_some() && x86_addr.disp != 0 {
            let dst = ctx.alloc_vreg();
            pre_ops.push(SmirOp::new(
                OpId(pre_ops.len() as u16),
                pc,
                OpKind::Add {
                    dst,
                    src1: offset,
                    src2: SrcOperand::Imm(x86_addr.disp),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                },
            ));
            offset = dst;
        }

        let addr = match segment {
            Some(segment) => Address::SegmentRel {
                segment,
                base: Some(offset),
                index: None,
                scale: 1,
                disp: 0,
            },
            None => Address::Direct(offset),
        };
        (addr, pre_ops)
    }

    /// Preserve a decoded addr32 expression entirely in architectural address
    /// components. An enclosing address or call-target variant supplies the
    /// W32 arithmetic contract, so no virtual materialization operations are
    /// required. RIP-relative input is folded to its exact low-32-bit offset.
    pub(crate) fn x86_addr32_state_address(&self, x86_addr: &X86Address, next_rip: u64) -> Address {
        debug_assert_eq!(x86_addr.address_width, OpWidth::W32);
        debug_assert!(matches!(x86_addr.scale, 1 | 2 | 4 | 8));
        debug_assert!(
            !x86_addr.rip_relative || (x86_addr.base.is_none() && x86_addr.index.is_none())
        );

        let base = x86_addr.base.map(|index| self.gpr(index));
        let index = x86_addr.index.map(|index| self.gpr(index));
        let disp = if x86_addr.rip_relative {
            i64::from(next_rip.wrapping_add_signed(x86_addr.disp) as u32)
        } else {
            x86_addr.disp
        };
        let segment = x86_addr
            .segment
            .map(|segment| VReg::Arch(ArchReg::X86(segment)));

        if let Some(segment) = segment {
            return Address::SegmentRel {
                segment,
                base,
                index,
                scale: x86_addr.scale,
                disp,
            };
        }

        match (base, index) {
            (None, None) => Address::Absolute(disp as u32 as u64),
            (Some(base), None) if disp == 0 => Address::Direct(base),
            (Some(base), None) => Address::BaseOffset {
                base,
                offset: disp,
                disp_size: x86_addr.disp_size,
            },
            (base, Some(index)) => Address::BaseIndexScale {
                base,
                index,
                scale: x86_addr.scale,
                disp: disp as i32,
                disp_size: x86_addr.disp_size,
            },
        }
    }

    /// Convert x86 address to SMIR Address, optionally generating pre-ops
    pub(crate) fn x86_addr_to_smir(
        &self,
        x86_addr: &X86Address,
        next_rip: u64,
        ctx: &mut LiftContext,
    ) -> (Address, Vec<SmirOp>) {
        if x86_addr.address_width == OpWidth::W32 {
            return (
                Address::X86Addr32(Box::new(self.x86_addr32_state_address(x86_addr, next_rip))),
                Vec::new(),
            );
        }

        let mut pre_ops = Vec::new();
        let pc = ctx.guest_pc;
        let disp_i32 = |disp: i64| -> Option<i32> {
            if disp >= i32::MIN as i64 && disp <= i32::MAX as i64 {
                Some(disp as i32)
            } else {
                None
            }
        };

        // FS/GS segment override → segment-relative address. The effective
        // address is segment_base + base + index*scale + disp. A RIP-relative
        // segment operand folds the (constant) next-RIP into the displacement so
        // `base`/`index` stay true GPRs.
        if let Some(seg) = x86_addr.segment {
            let segment = VReg::Arch(ArchReg::X86(seg));
            let base = x86_addr.base.map(|b| self.gpr(b));
            let index = x86_addr.index.map(|i| self.gpr(i));
            let disp = if x86_addr.rip_relative {
                next_rip as i64 + x86_addr.disp
            } else {
                x86_addr.disp
            };
            return (
                Address::SegmentRel {
                    segment,
                    base,
                    index,
                    scale: x86_addr.scale,
                    disp,
                },
                pre_ops,
            );
        }

        if x86_addr.rip_relative {
            return (
                Address::PcRel {
                    offset: x86_addr.disp,
                    disp_size: x86_addr.disp_size,
                    base: Some(next_rip),
                },
                pre_ops,
            );
        }

        match (x86_addr.base, x86_addr.index) {
            (None, None) => {
                // Absolute address
                (Address::Absolute(x86_addr.disp as u64), pre_ops)
            }
            (Some(base), None) => {
                if x86_addr.disp == 0 && x86_addr.disp_size == DispSize::Auto {
                    (Address::Direct(self.gpr(base)), pre_ops)
                } else {
                    (
                        Address::BaseOffset {
                            base: self.gpr(base),
                            offset: x86_addr.disp,
                            disp_size: x86_addr.disp_size,
                        },
                        pre_ops,
                    )
                }
            }
            (None, Some(index)) => {
                if let Some(disp) = disp_i32(x86_addr.disp) {
                    (
                        Address::BaseIndexScale {
                            base: None,
                            index: self.gpr(index),
                            scale: x86_addr.scale,
                            disp,
                            disp_size: x86_addr.disp_size,
                        },
                        pre_ops,
                    )
                } else {
                    // Fallback to computed address
                    let tmp = ctx.alloc_vreg();
                    if x86_addr.scale > 1 {
                        pre_ops.push(SmirOp::new(
                            OpId(0),
                            pc,
                            OpKind::Shl {
                                dst: tmp,
                                src: self.gpr(index),
                                amount: SrcOperand::Imm(x86_addr.scale.trailing_zeros() as i64),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            },
                        ));
                        if x86_addr.disp != 0 {
                            let tmp2 = ctx.alloc_vreg();
                            pre_ops.push(SmirOp::new(
                                OpId(1),
                                pc,
                                OpKind::Add {
                                    dst: tmp2,
                                    src1: tmp,
                                    src2: SrcOperand::Imm(x86_addr.disp),
                                    width: OpWidth::W64,
                                    flags: FlagUpdate::None,
                                },
                            ));
                            (Address::Direct(tmp2), pre_ops)
                        } else {
                            (Address::Direct(tmp), pre_ops)
                        }
                    } else if x86_addr.disp != 0 {
                        pre_ops.push(SmirOp::new(
                            OpId(0),
                            pc,
                            OpKind::Add {
                                dst: tmp,
                                src1: self.gpr(index),
                                src2: SrcOperand::Imm(x86_addr.disp),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            },
                        ));
                        (Address::Direct(tmp), pre_ops)
                    } else {
                        (Address::Direct(self.gpr(index)), pre_ops)
                    }
                }
            }
            (Some(base), Some(index)) => {
                if let Some(disp) = disp_i32(x86_addr.disp) {
                    (
                        Address::BaseIndexScale {
                            base: Some(self.gpr(base)),
                            index: self.gpr(index),
                            scale: x86_addr.scale,
                            disp,
                            disp_size: x86_addr.disp_size,
                        },
                        pre_ops,
                    )
                } else {
                    // Fallback to computed address
                    let tmp_idx = ctx.alloc_vreg();
                    let tmp_sum = ctx.alloc_vreg();

                    // Scale the index
                    if x86_addr.scale > 1 {
                        pre_ops.push(SmirOp::new(
                            OpId(0),
                            pc,
                            OpKind::Shl {
                                dst: tmp_idx,
                                src: self.gpr(index),
                                amount: SrcOperand::Imm(x86_addr.scale.trailing_zeros() as i64),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            },
                        ));
                        pre_ops.push(SmirOp::new(
                            OpId(1),
                            pc,
                            OpKind::Add {
                                dst: tmp_sum,
                                src1: self.gpr(base),
                                src2: SrcOperand::Reg(tmp_idx),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            },
                        ));
                    } else {
                        pre_ops.push(SmirOp::new(
                            OpId(0),
                            pc,
                            OpKind::Add {
                                dst: tmp_sum,
                                src1: self.gpr(base),
                                src2: SrcOperand::Reg(self.gpr(index)),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            },
                        ));
                    }

                    if x86_addr.disp != 0 {
                        (
                            Address::BaseOffset {
                                base: tmp_sum,
                                offset: x86_addr.disp,
                                disp_size: x86_addr.disp_size,
                            },
                            pre_ops,
                        )
                    } else {
                        (Address::Direct(tmp_sum), pre_ops)
                    }
                }
            }
        }
    }

    pub(crate) fn vec_scalar_addr_to_smir(
        &self,
        prefix: VecPrefix,
        x86_addr: &X86Address,
        next_rip: u64,
        elem: VecElementType,
        ctx: &mut LiftContext,
    ) -> (Address, Vec<SmirOp>) {
        if prefix.encoding != VecEncodingKind::Evex || x86_addr.disp_size != DispSize::Disp8 {
            return self.x86_addr_to_smir(x86_addr, next_rip, ctx);
        }
        let mut scaled = x86_addr.clone();
        scaled.disp = scaled.disp.wrapping_mul(i64::from(elem.bytes()));
        self.x86_addr_to_smir(&scaled, next_rip, ctx)
    }

    /// Decode an EVEX full-vector memory tuple. A disp8 is compressed by the
    /// complete vector width (16, 32, or 64 bytes).
    pub(crate) fn vec_full_addr_to_smir(
        &self,
        prefix: VecPrefix,
        x86_addr: &X86Address,
        next_rip: u64,
        ctx: &mut LiftContext,
    ) -> (Address, Vec<SmirOp>) {
        if prefix.encoding != VecEncodingKind::Evex || x86_addr.disp_size != DispSize::Disp8 {
            return self.x86_addr_to_smir(x86_addr, next_rip, ctx);
        }
        let mut scaled = x86_addr.clone();
        scaled.disp = scaled.disp.wrapping_mul(i64::from(prefix.width.bytes()));
        self.x86_addr_to_smir(&scaled, next_rip, ctx)
    }

    pub(crate) fn vec_disp8_addr_to_smir(
        &self,
        prefix: VecPrefix,
        x86_addr: &X86Address,
        next_rip: u64,
        scale: u32,
        ctx: &mut LiftContext,
    ) -> (Address, Vec<SmirOp>) {
        if prefix.encoding != VecEncodingKind::Evex || x86_addr.disp_size != DispSize::Disp8 {
            return self.x86_addr_to_smir(x86_addr, next_rip, ctx);
        }
        let mut scaled = x86_addr.clone();
        scaled.disp = scaled.disp.wrapping_mul(i64::from(scale));
        self.x86_addr_to_smir(&scaled, next_rip, ctx)
    }

    /// Replace one register in an already-decoded address expression. Used by
    /// POP r/m memory forms, whose effective address observes the incremented
    /// stack pointer even though the architectural RSP update must not commit
    /// until the destination store succeeds.
    pub(crate) fn replace_address_reg(addr: Address, from: VReg, to: VReg) -> Address {
        let replace = |reg: VReg| if reg == from { to } else { reg };
        match addr {
            Address::Direct(reg) => Address::Direct(replace(reg)),
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => Address::BaseOffset {
                base: replace(base),
                offset,
                disp_size,
            },
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => Address::BaseIndexScale {
                base: base.map(replace),
                index: replace(index),
                scale,
                disp,
                disp_size,
            },
            Address::SegmentRel {
                segment,
                base,
                index,
                scale,
                disp,
            } => Address::SegmentRel {
                segment,
                base: base.map(replace),
                index: index.map(replace),
                scale,
                disp,
            },
            other => other,
        }
    }

    /// Map x86 condition code (0-15) to SMIR Condition
    pub(crate) fn x86_cond(&self, cc: u8) -> Condition {
        match cc & 0x0F {
            0x0 => Condition::Overflow,   // O
            0x1 => Condition::NoOverflow, // NO
            0x2 => Condition::Ult,        // B/C/NAE
            0x3 => Condition::Uge,        // AE/NB/NC
            0x4 => Condition::Eq,         // E/Z
            0x5 => Condition::Ne,         // NE/NZ
            0x6 => Condition::Ule,        // BE/NA
            0x7 => Condition::Ugt,        // A/NBE
            0x8 => Condition::Negative,   // S
            0x9 => Condition::Positive,   // NS
            0xA => Condition::Parity,     // P/PE
            0xB => Condition::NoParity,   // NP/PO
            0xC => Condition::Slt,        // L/NGE
            0xD => Condition::Sge,        // GE/NL
            0xE => Condition::Sle,        // LE/NG
            0xF => Condition::Sgt,        // G/NLE
            _ => Condition::Always,
        }
    }

    pub(crate) fn vec_hint(&self, prefix: VecPrefix, opcode: u8) -> X86OpHint {
        match prefix.encoding {
            VecEncodingKind::Vex => X86OpHint::VexOp {
                map: prefix.map,
                pp: prefix.pp,
                opcode,
                width: prefix.width,
                w: prefix.w,
            },
            VecEncodingKind::Evex => X86OpHint::EvexOp {
                map: prefix.map,
                pp: prefix.pp,
                opcode,
                width: prefix.width,
                w: prefix.w,
            },
        }
    }
}
