//! SMIR interpreter.
//!
//! This module provides the interpreter for executing SMIR code.

use std::collections::HashMap;

use crate::smir::context::{ArchRegState, ExitReason, SmirContext, VecValue};
use crate::smir::flags::{FlagUpdate, LazyFlagOp, LazyFlags};
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};
use crate::smir::memory::{MemoryError, SmirMemory};
use crate::smir::ops::{OpKind, SmirOp};
use crate::smir::types::*;

// ============================================================================
// Block Result
// ============================================================================

/// Result of executing a block
#[derive(Clone, Debug)]
pub enum BlockResult {
    /// Continue execution at the given address
    Continue(GuestAddr),
    /// Exit with a reason
    Exit(ExitReason),
}

// ============================================================================
// Interpreter
// ============================================================================

/// SMIR interpreter
pub struct SmirInterpreter {
    /// Block cache (guest address -> block)
    block_cache: HashMap<GuestAddr, SmirBlock>,
    /// Function cache
    func_cache: HashMap<GuestAddr, SmirFunction>,
    /// Maximum instructions per run
    max_insns_per_run: u64,
    /// Block address mapping (BlockId -> guest address)
    block_addrs: HashMap<BlockId, GuestAddr>,
}

impl SmirInterpreter {
    /// Create a new interpreter
    pub fn new() -> Self {
        SmirInterpreter {
            block_cache: HashMap::new(),
            func_cache: HashMap::new(),
            max_insns_per_run: 10000,
            block_addrs: HashMap::new(),
        }
    }

    /// Set the maximum instructions per run
    pub fn set_max_insns(&mut self, max: u64) {
        self.max_insns_per_run = max;
    }

    /// Add a block to the cache
    pub fn add_block(&mut self, addr: GuestAddr, block: SmirBlock) {
        self.block_addrs.insert(block.id, addr);
        self.block_cache.insert(addr, block);
    }

    /// Add a function to the cache
    pub fn add_function(&mut self, func: SmirFunction) {
        let addr = func.guest_range.0;
        for block in &func.blocks {
            self.block_addrs.insert(block.id, block.guest_pc);
        }
        self.func_cache.insert(addr, func);
    }

    /// Run until exit condition
    pub fn run(&mut self, ctx: &mut SmirContext, memory: &mut dyn SmirMemory) -> ExitReason {
        let limit = ctx.insn_count + self.max_insns_per_run;

        loop {
            // Check instruction limit
            if ctx.insn_count >= limit {
                return ExitReason::InsnLimit;
            }

            // Check for pending exit
            if let Some(reason) = ctx.exit_reason.take() {
                return reason;
            }

            // Check breakpoints
            if ctx.debug.has_breakpoint(ctx.pc) {
                return ExitReason::Breakpoint { addr: ctx.pc };
            }

            // Get block from cache
            let block = match self.block_cache.get(&ctx.pc) {
                Some(b) => b.clone(),
                None => {
                    return ExitReason::BlockNotFound { addr: ctx.pc };
                }
            };

            // Execute block
            match self.execute_block(ctx, memory, &block) {
                BlockResult::Continue(next_pc) => {
                    ctx.pc = next_pc;
                }
                BlockResult::Exit(reason) => {
                    return reason;
                }
            }

            // Single-step mode
            if ctx.debug.single_step {
                return ExitReason::SingleStep;
            }
        }
    }

    /// Execute a single block
    pub fn execute_block(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        block: &SmirBlock,
    ) -> BlockResult {
        // Execute each operation
        for op in &block.ops {
            if let Err(e) = self.execute_op(ctx, memory, op) {
                return BlockResult::Exit(ExitReason::MemoryFault {
                    addr: match e {
                        MemoryError::PageFault { addr, .. } => addr,
                        MemoryError::AccessViolation { addr, .. } => addr,
                        MemoryError::Alignment { addr, .. } => addr,
                        MemoryError::Mmio { addr, .. } => addr,
                        MemoryError::OutOfBounds { addr } => addr,
                        MemoryError::ExclusiveFailed => ctx.pc,
                    },
                    write: matches!(
                        e,
                        MemoryError::PageFault { write: true, .. }
                            | MemoryError::AccessViolation { write: true, .. }
                    ),
                });
            }
            ctx.insn_count += 1;
        }

        // Execute terminator
        self.execute_terminator(ctx, memory, &block.terminator)
    }

    /// Write a width-tagged operation result to a destination, applying x86
    /// sub-register write semantics for architectural GPRs: an 8-bit or 16-bit
    /// write MERGES into the existing register (the upper bits are preserved),
    /// a 32-bit write zero-extends (the caller already masked `value` to 32
    /// bits, so a full store clears the upper 32), and 64-bit is a full store.
    /// Virtual (SSA temp) and non-x86 destinations are written as-is. Without
    /// this, an 8/16-bit ALU result would zero-extend the whole register, which
    /// the smir_alu differential test against KVM flagged.
    #[inline]
    fn write_gpr(ctx: &mut SmirContext, dst: VReg, value: u64, width: OpWidth) {
        if let VReg::Arch(ArchReg::X86(_)) = dst {
            let merged = match width {
                OpWidth::W8 => (ctx.read_vreg(dst) & !0xFFu64) | (value & 0xFF),
                OpWidth::W16 => (ctx.read_vreg(dst) & !0xFFFFu64) | (value & 0xFFFF),
                _ => value,
            };
            ctx.write_vreg(dst, merged);
        } else {
            ctx.write_vreg(dst, value);
        }
    }

    /// Sign-extend the low `bits` of `v` to a full i128.
    #[inline]
    fn sext128(v: u128, bits: u32) -> i128 {
        if bits >= 128 {
            v as i128
        } else {
            let shift = 128 - bits;
            ((v << shift) as i128) >> shift
        }
    }

    /// Execute a single operation
    fn execute_op(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        op: &SmirOp,
    ) -> Result<(), MemoryError> {
        match &op.kind {
            // ==================================================================
            // INTEGER ARITHMETIC
            // ==================================================================
            OpKind::Add {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let result = a.wrapping_add(b) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_add(a, b, result, *width);
                }
            }

            OpKind::Sub {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let result = a.wrapping_sub(b) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_sub(a, b, result, *width);
                }
            }

            OpKind::Adc {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let cf = if ctx.flags.get_cf() { 1u64 } else { 0 };
                let result = a.wrapping_add(b).wrapping_add(cf) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    // Original operands + carry-in: CF/AF/OF must account for the
                    // carry (folding cf into `b` loses the carry-out).
                    ctx.flags.set_lazy_adc(a, b, cf, result, *width);
                }
            }

            OpKind::Sbb {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let cf = if ctx.flags.get_cf() { 1u64 } else { 0 };
                let result = a.wrapping_sub(b).wrapping_sub(cf) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_sbb(a, b, cf, result, *width);
                }
            }

            OpKind::Neg {
                dst,
                src,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src);
                let result = (0u64.wrapping_sub(a)) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Neg,
                        result,
                        left: a,
                        right: 0,
                        width: *width,
                        high: 0,
                    });
                }
            }

            OpKind::Inc {
                dst,
                src,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src);
                let result = a.wrapping_add(1) & width.mask();
                Self::write_x86_partial(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags::inc(a, result, *width));
                }
            }

            OpKind::Dec {
                dst,
                src,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src);
                let result = a.wrapping_sub(1) & width.mask();
                Self::write_x86_partial(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags::dec(a, result, *width));
                }
            }

            OpKind::Cmp { src1, src2, width } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let result = a.wrapping_sub(b) & width.mask();

                ctx.flags.set_lazy_sub(a, b, result, *width);
            }

            OpKind::MulU {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1) & width.mask();
                let b = self.read_src_operand(ctx, src2) & width.mask();

                let (result_lo, result_hi) = match width {
                    OpWidth::W8 => {
                        let r = (a as u16) * (b as u16);
                        ((r & 0xFF) as u64, ((r >> 8) & 0xFF) as u64)
                    }
                    OpWidth::W16 => {
                        let r = (a as u32) * (b as u32);
                        ((r & 0xFFFF) as u64, ((r >> 16) & 0xFFFF) as u64)
                    }
                    OpWidth::W32 => {
                        let r = (a as u64) * (b as u64);
                        (r & 0xFFFF_FFFF, (r >> 32) & 0xFFFF_FFFF)
                    }
                    OpWidth::W64 => {
                        let r = (a as u128) * (b as u128);
                        (r as u64, (r >> 64) as u64)
                    }
                    OpWidth::W128 => {
                        // 128-bit multiply not supported
                        (a.wrapping_mul(b), 0)
                    }
                };

                if *width == OpWidth::W8 {
                    // 8-bit MUL: the full 16-bit product lives in AX (AH:AL);
                    // DX is untouched. Merge the 16-bit product into AX.
                    Self::write_gpr(ctx, *dst_lo, result_lo | (result_hi << 8), OpWidth::W16);
                } else {
                    Self::write_gpr(ctx, *dst_lo, result_lo, *width);
                    if let Some(hi) = dst_hi {
                        Self::write_gpr(ctx, *hi, result_hi, *width);
                    }
                }

                if flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Mul,
                        result: result_lo,
                        left: a,
                        right: b,
                        width: *width,
                        high: result_hi,
                    });
                }
            }

            OpKind::MulS {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = self.sign_extend(ctx.read_vreg(*src1), *width);
                let b = self.sign_extend(self.read_src_operand(ctx, src2), *width);

                let (result_lo, result_hi) = match width {
                    OpWidth::W8 => {
                        let r = (a as i8 as i16) * (b as i8 as i16);
                        ((r as u16 & 0xFF) as u64, (((r as u16) >> 8) & 0xFF) as u64)
                    }
                    OpWidth::W16 => {
                        let r = (a as i16 as i32) * (b as i16 as i32);
                        (
                            (r as u32 & 0xFFFF) as u64,
                            (((r as u32) >> 16) & 0xFFFF) as u64,
                        )
                    }
                    OpWidth::W32 => {
                        let r = (a as i32 as i64) * (b as i32 as i64);
                        ((r as u64 & 0xFFFF_FFFF), ((r as u64) >> 32) & 0xFFFF_FFFF)
                    }
                    OpWidth::W64 => {
                        let r = (a as i64 as i128) * (b as i64 as i128);
                        (r as u64, (r >> 64) as u64)
                    }
                    OpWidth::W128 => ((a as i64).wrapping_mul(b as i64) as u64, 0),
                };

                if *width == OpWidth::W8 {
                    // 8-bit IMUL: the full 16-bit product lives in AX (AH:AL);
                    // DX is untouched.
                    Self::write_gpr(ctx, *dst_lo, result_lo | (result_hi << 8), OpWidth::W16);
                } else {
                    Self::write_gpr(ctx, *dst_lo, result_lo, *width);
                    if let Some(hi) = dst_hi {
                        Self::write_gpr(ctx, *hi, result_hi, *width);
                    }
                }

                if flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        // Signed: CF/OF iff the product isn't the sign-extension
                        // of the low half (distinct from unsigned Mul's high!=0).
                        op: LazyFlagOp::Imul,
                        result: result_lo,
                        left: a as u64,
                        right: b as u64,
                        width: *width,
                        high: result_hi,
                    });
                }
            }

            OpKind::MulAdd {
                dst,
                acc,
                src1,
                src2,
                width,
            } => {
                let a = ctx.read_vreg(*src1) & width.mask();
                let b = ctx.read_vreg(*src2) & width.mask();
                let c = ctx.read_vreg(*acc) & width.mask();
                let result = c.wrapping_add(a.wrapping_mul(b)) & width.mask();
                Self::write_gpr(ctx, *dst, result, *width);
            }

            OpKind::MulSub {
                dst,
                acc,
                src1,
                src2,
                width,
            } => {
                let a = ctx.read_vreg(*src1) & width.mask();
                let b = ctx.read_vreg(*src2) & width.mask();
                let c = ctx.read_vreg(*acc) & width.mask();
                let result = c.wrapping_sub(a.wrapping_mul(b)) & width.mask();
                Self::write_gpr(ctx, *dst, result, *width);
            }

            OpKind::DivU {
                quot,
                rem,
                src1,
                src2,
                width,
            } => {
                let mask = width.mask();
                let b = (self.read_src_operand(ctx, src2) & mask) as u128;
                if b == 0 {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: ctx.pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                // x86 DIV divides the double-width RDX:RAX (AX for 8-bit) by the
                // operand; non-x86 contexts have no high half (single-width div).
                let lo = ctx.read_vreg(*src1) & mask;
                let is_x86 = matches!(ctx.arch_regs, ArchRegState::X86_64(_));
                let dividend: u128 = if !is_x86 {
                    lo as u128
                } else if *width == OpWidth::W8 {
                    (ctx.read_arch_reg(ArchReg::X86(X86Reg::Rax)) & 0xFFFF) as u128
                } else {
                    let hi = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rdx)) & mask;
                    ((hi as u128) << width.bits()) | (lo as u128)
                };
                let q = dividend / b;
                let r = dividend % b;
                if q > mask as u128 {
                    // Quotient overflow -> #DE.
                    ctx.request_exit(ExitReason::Undefined {
                        addr: ctx.pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                let (q, r) = (q as u64, r as u64);
                if is_x86 && *width == OpWidth::W8 {
                    // 8-bit: quotient -> AL, remainder -> AH.
                    let rax = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rax));
                    let new = (rax & !0xFFFF) | ((r & 0xFF) << 8) | (q & 0xFF);
                    ctx.write_arch_reg(ArchReg::X86(X86Reg::Rax), new);
                } else {
                    Self::write_gpr(ctx, *quot, q, *width);
                    if let Some(rem_reg) = rem {
                        Self::write_gpr(ctx, *rem_reg, r, *width);
                    }
                }
            }

            OpKind::DivS {
                quot,
                rem,
                src1,
                src2,
                width,
            } => {
                let mask = width.mask();
                let bits = width.bits();
                let b = self.sign_extend(self.read_src_operand(ctx, src2), *width) as i64 as i128;
                if b == 0 {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: ctx.pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                let is_x86 = matches!(ctx.arch_regs, ArchRegState::X86_64(_));
                // Signed double-width dividend: RDX:RAX (AX for 8-bit) on x86.
                let dividend: i128 = if !is_x86 {
                    self.sign_extend(ctx.read_vreg(*src1), *width) as i64 as i128
                } else if *width == OpWidth::W8 {
                    ((ctx.read_arch_reg(ArchReg::X86(X86Reg::Rax)) & 0xFFFF) as u16) as i16 as i128
                } else {
                    let lo = ctx.read_vreg(*src1) & mask;
                    let hi = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rdx)) & mask;
                    let combined = ((hi as u128) << bits) | (lo as u128);
                    Self::sext128(combined, bits * 2)
                };
                let q = dividend.wrapping_div(b);
                let r = dividend.wrapping_rem(b);
                // Signed quotient must fit in `bits`, else #DE.
                let qmax = (1i128 << (bits - 1)) - 1;
                let qmin = -(1i128 << (bits - 1));
                if q < qmin || q > qmax {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: ctx.pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                let (q, r) = ((q as u64) & mask, (r as u64) & mask);
                if is_x86 && *width == OpWidth::W8 {
                    let rax = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rax));
                    let new = (rax & !0xFFFF) | ((r & 0xFF) << 8) | (q & 0xFF);
                    ctx.write_arch_reg(ArchReg::X86(X86Reg::Rax), new);
                } else {
                    Self::write_gpr(ctx, *quot, q, *width);
                    if let Some(rem_reg) = rem {
                        Self::write_gpr(ctx, *rem_reg, r, *width);
                    }
                }
            }

            // ==================================================================
            // BITWISE LOGICAL
            // ==================================================================
            OpKind::And {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let result = (a & b) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_logic(result, *width);
                }
            }

            OpKind::Or {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let result = (a | b) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_logic(result, *width);
                }
            }

            OpKind::Xor {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let result = (a ^ b) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_logic(result, *width);
                }
            }

            OpKind::Not { dst, src, width } => {
                let a = ctx.read_vreg(*src);
                let result = (!a) & width.mask();
                Self::write_gpr(ctx, *dst, result, *width);
            }

            OpKind::Test { src1, src2, width } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let result = (a & b) & width.mask();

                ctx.flags.set_lazy_logic(result, *width);
            }

            OpKind::AndNot {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let a = ctx.read_vreg(*src1);
                let b = self.read_src_operand(ctx, src2);
                let result = (a & !b) & width.mask();

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_logic(result, *width);
                }
            }

            // ==================================================================
            // SHIFTS AND ROTATES
            // ==================================================================
            OpKind::Shl {
                dst,
                src,
                amount,
                width,
                flags,
            } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let amt = self.read_src_operand(ctx, amount) & 0x3F;
                let result = if amt >= width.bits() as u64 {
                    0
                } else {
                    (val << amt) & width.mask()
                };

                Self::write_gpr(ctx, *dst, result, *width);

                if amt != 0 && flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Shl,
                        result,
                        left: val,
                        right: amt,
                        width: *width,
                        high: 0,
                    });
                }
            }

            OpKind::Shr {
                dst,
                src,
                amount,
                width,
                flags,
            } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let amt = self.read_src_operand(ctx, amount) & 0x3F;
                let result = if amt >= width.bits() as u64 {
                    0
                } else {
                    (val >> amt) & width.mask()
                };

                Self::write_gpr(ctx, *dst, result, *width);

                if amt != 0 && flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Shr,
                        result,
                        left: val,
                        right: amt,
                        width: *width,
                        high: 0,
                    });
                }
            }

            OpKind::Sar {
                dst,
                src,
                amount,
                width,
                flags,
            } => {
                // Mask to the operand width BEFORE sign-extending, or stale upper
                // register bits leak into both the shifted-out bits and the sign.
                let val = self.sign_extend(ctx.read_vreg(*src) & width.mask(), *width);
                let amt = self.read_src_operand(ctx, amount) & 0x3F;
                let result = if amt >= width.bits() as u64 {
                    if (val as i64) < 0 {
                        width.mask()
                    } else {
                        0
                    }
                } else {
                    ((val as i64 >> amt) as u64) & width.mask()
                };

                Self::write_gpr(ctx, *dst, result, *width);

                // A masked shift count of 0 leaves all status flags unchanged.
                if amt != 0 && flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Sar,
                        result,
                        left: val as u64,
                        right: amt,
                        width: *width,
                        high: 0,
                    });
                }
            }

            OpKind::Shld {
                dst,
                src,
                amount,
                width,
                flags,
            } => {
                let left = ctx.read_vreg(*dst) & width.mask();
                let right = ctx.read_vreg(*src) & width.mask();
                let bits = width.bits() as u64;
                let mask = if bits == 64 { 0x3F } else { 0x1F };
                let amt = self.read_src_operand(ctx, amount) & mask;
                let result = if amt == 0 {
                    left
                } else {
                    ((left << amt) | (right >> (bits - amt))) & width.mask()
                };

                Self::write_gpr(ctx, *dst, result, *width);

                // count==0 leaves flags unchanged; else CF = last bit out of dst's top.
                if amt != 0 && flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Shld,
                        result,
                        left,
                        right: amt,
                        width: *width,
                        high: 0,
                    });
                }
            }

            OpKind::Shrd {
                dst,
                src,
                amount,
                width,
                flags,
            } => {
                let left = ctx.read_vreg(*dst) & width.mask();
                let right = ctx.read_vreg(*src) & width.mask();
                let bits = width.bits() as u64;
                let mask = if bits == 64 { 0x3F } else { 0x1F };
                let amt = self.read_src_operand(ctx, amount) & mask;
                let result = if amt == 0 {
                    left
                } else {
                    ((left >> amt) | (right << (bits - amt))) & width.mask()
                };

                Self::write_gpr(ctx, *dst, result, *width);

                // count==0 leaves flags unchanged; else CF = last bit out of dst's bottom.
                if amt != 0 && flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Shrd,
                        result,
                        left,
                        right: amt,
                        width: *width,
                        high: 0,
                    });
                }
            }

            OpKind::Rol {
                dst,
                src,
                amount,
                width,
                flags,
            } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let bits = width.bits() as u64;
                // x86 masks the count to 5 bits (6 for 64-bit); the rotation
                // amount is that masked count mod the width.
                let cmask = if bits == 64 { 0x3F } else { 0x1F };
                let masked = self.read_src_operand(ctx, amount) & cmask;
                let amt = masked % bits;
                let result = if amt == 0 {
                    val
                } else {
                    ((val << amt) | (val >> (bits - amt))) & width.mask()
                };

                Self::write_gpr(ctx, *dst, result, *width);

                // CF/OF update iff the MASKED count != 0 — even when the rotation
                // amount (masked mod width) is 0, e.g. ROL r16 by 16. `right`
                // carries the masked count so OF keys on masked==1.
                if masked != 0 && flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Rotate,
                        result,
                        left: val,
                        right: masked,
                        width: *width,
                        high: 0,
                    });
                }
            }

            OpKind::Ror {
                dst,
                src,
                amount,
                width,
                flags,
            } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let bits = width.bits() as u64;
                let cmask = if bits == 64 { 0x3F } else { 0x1F };
                let masked = self.read_src_operand(ctx, amount) & cmask;
                let amt = masked % bits;
                let result = if amt == 0 {
                    val
                } else {
                    ((val >> amt) | (val << (bits - amt))) & width.mask()
                };

                Self::write_gpr(ctx, *dst, result, *width);

                // CF/OF update iff the MASKED count != 0 (see Rol).
                if masked != 0 && flags.updates_any() {
                    ctx.flags.lazy = Some(LazyFlags {
                        op: LazyFlagOp::Ror,
                        result,
                        left: val,
                        right: masked,
                        width: *width,
                        high: 0,
                    });
                }
            }

            // ==================================================================
            // BIT MANIPULATION
            // ==================================================================
            OpKind::Bt { src, index, width } => {
                let val = ctx.read_vreg(*src);
                let idx = self.read_src_operand(ctx, index) & (width.bits() as u64 - 1);

                ctx.flags.lazy = Some(LazyFlags {
                    op: LazyFlagOp::Bt,
                    result: 0,
                    left: val,
                    right: idx,
                    width: *width,
                    high: 0,
                });
            }

            OpKind::Bts {
                dst,
                src,
                index,
                width,
            } => {
                let val = ctx.read_vreg(*src);
                let idx = self.read_src_operand(ctx, index) & (width.bits() as u64 - 1);
                let result = val | (1u64 << idx);

                ctx.write_vreg(*dst, result & width.mask());

                ctx.flags.lazy = Some(LazyFlags {
                    op: LazyFlagOp::Bt,
                    result: 0,
                    left: val,
                    right: idx,
                    width: *width,
                    high: 0,
                });
            }

            OpKind::Btr {
                dst,
                src,
                index,
                width,
            } => {
                let val = ctx.read_vreg(*src);
                let idx = self.read_src_operand(ctx, index) & (width.bits() as u64 - 1);
                let result = val & !(1u64 << idx);

                ctx.write_vreg(*dst, result & width.mask());

                ctx.flags.lazy = Some(LazyFlags {
                    op: LazyFlagOp::Bt,
                    result: 0,
                    left: val,
                    right: idx,
                    width: *width,
                    high: 0,
                });
            }

            OpKind::Btc {
                dst,
                src,
                index,
                width,
            } => {
                let val = ctx.read_vreg(*src);
                let idx = self.read_src_operand(ctx, index) & (width.bits() as u64 - 1);
                let result = val ^ (1u64 << idx);

                ctx.write_vreg(*dst, result & width.mask());

                ctx.flags.lazy = Some(LazyFlags {
                    op: LazyFlagOp::Bt,
                    result: 0,
                    left: val,
                    right: idx,
                    width: *width,
                    high: 0,
                });
            }

            OpKind::Bsf {
                dst,
                src,
                width,
                flags,
            } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let result = if val == 0 {
                    0 // ZF will be set
                } else {
                    val.trailing_zeros() as u64
                };

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_logic(val, *width);
                }
            }

            OpKind::Bsr {
                dst,
                src,
                width,
                flags,
            } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let result = if val == 0 {
                    0 // ZF will be set
                } else {
                    (width.bits() - 1 - val.leading_zeros()) as u64
                };

                Self::write_gpr(ctx, *dst, result, *width);

                if flags.updates_any() {
                    ctx.flags.set_lazy_logic(val, *width);
                }
            }

            OpKind::Clz { dst, src, width } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let extra_bits = 64 - width.bits();
                let result = (val.leading_zeros() - extra_bits) as u64;
                Self::write_gpr(ctx, *dst, result, *width);
            }

            OpKind::Ctz { dst, src, width } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let result = if val == 0 {
                    width.bits() as u64
                } else {
                    val.trailing_zeros() as u64
                };
                Self::write_gpr(ctx, *dst, result, *width);
            }

            OpKind::Popcnt { dst, src, width } => {
                let val = ctx.read_vreg(*src) & width.mask();
                ctx.write_vreg(*dst, val.count_ones() as u64);
            }

            OpKind::Bswap { dst, src, width } => {
                let val = ctx.read_vreg(*src);
                let result = match width {
                    OpWidth::W16 => (val as u16).swap_bytes() as u64,
                    OpWidth::W32 => (val as u32).swap_bytes() as u64,
                    OpWidth::W64 => val.swap_bytes(),
                    _ => val,
                };
                Self::write_gpr(ctx, *dst, result, *width);
            }

            OpKind::Rbit { dst, src, width } => {
                let val = ctx.read_vreg(*src);
                let result = match width {
                    OpWidth::W32 => (val as u32).reverse_bits() as u64,
                    OpWidth::W64 => val.reverse_bits(),
                    _ => val,
                };
                Self::write_gpr(ctx, *dst, result, *width);
            }

            OpKind::Bfx {
                dst,
                src,
                lsb,
                width_bits,
                sign_extend,
                op_width,
            } => {
                let val = ctx.read_vreg(*src);
                let mask = (1u64 << *width_bits) - 1;
                let extracted = (val >> *lsb) & mask;

                let result = if *sign_extend && (*width_bits > 0) {
                    let sign_bit = 1u64 << (*width_bits - 1);
                    if (extracted & sign_bit) != 0 {
                        extracted | !mask
                    } else {
                        extracted
                    }
                } else {
                    extracted
                };

                ctx.write_vreg(*dst, result & op_width.mask());
            }

            OpKind::Bfi {
                dst,
                dst_in,
                src,
                lsb,
                width_bits,
                op_width,
            } => {
                let dest_val = ctx.read_vreg(*dst_in);
                let src_val = ctx.read_vreg(*src);
                let mask = ((1u64 << *width_bits) - 1) << *lsb;
                let result = (dest_val & !mask) | ((src_val << *lsb) & mask);
                ctx.write_vreg(*dst, result & op_width.mask());
            }

            // ==================================================================
            // DATA MOVEMENT
            // ==================================================================
            OpKind::Mov { dst, src, width } => {
                let val = self.read_src_operand(ctx, src);
                Self::write_x86_partial(ctx, *dst, val, *width);
            }

            OpKind::CMove {
                dst,
                src,
                cond,
                width,
            } => {
                if ctx.flags.eval_condition(*cond) {
                    let val = ctx.read_vreg(*src) & width.mask();
                    ctx.write_vreg(*dst, val);
                }
            }

            OpKind::Select {
                dst,
                cond,
                src_true,
                src_false,
                width,
            } => {
                let cond_val = ctx.read_vreg(*cond);
                let result = if cond_val != 0 {
                    ctx.read_vreg(*src_true)
                } else {
                    ctx.read_vreg(*src_false)
                };
                ctx.write_vreg(*dst, result & width.mask());
            }

            OpKind::ZeroExtend {
                dst,
                src,
                from_width,
                to_width: _,
            } => {
                let val = ctx.read_vreg(*src) & from_width.mask();
                ctx.write_vreg(*dst, val);
            }

            OpKind::SignExtend {
                dst,
                src,
                from_width,
                to_width,
            } => {
                let val = ctx.read_vreg(*src) & from_width.mask();
                let sign_bit = from_width.sign_bit();
                let extended = if (val & sign_bit) != 0 {
                    val | !from_width.mask()
                } else {
                    val
                };
                ctx.write_vreg(*dst, extended & to_width.mask());
            }

            OpKind::Cwd { dst, src, width } => {
                let val = ctx.read_vreg(*src) & width.mask();
                let sign_bit = width.sign_bit();
                let result = if (val & sign_bit) != 0 {
                    width.mask()
                } else {
                    0
                };
                Self::write_x86_partial(ctx, *dst, result, *width);
            }

            OpKind::Truncate {
                dst,
                src,
                from_width: _,
                to_width,
            } => {
                let val = ctx.read_vreg(*src);
                ctx.write_vreg(*dst, val & to_width.mask());
            }

            OpKind::Lea { dst, addr } => {
                let effective_addr = self.compute_address(ctx, addr);
                ctx.write_vreg(*dst, effective_addr);
            }

            OpKind::Xchg { reg1, reg2, width } => {
                let v1 = ctx.read_vreg(*reg1) & width.mask();
                let v2 = ctx.read_vreg(*reg2) & width.mask();
                ctx.write_vreg(*reg1, v2);
                ctx.write_vreg(*reg2, v1);
            }

            // ==================================================================
            // MEMORY OPERATIONS
            // ==================================================================
            OpKind::Load {
                dst,
                addr,
                width,
                sign,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val = self.load_memory(memory, effective_addr, *width, *sign)?;
                let op_width = width.to_op_width().unwrap_or(OpWidth::W64);
                if *sign == SignExtend::Zero {
                    Self::write_x86_partial(ctx, *dst, val, op_width);
                } else {
                    ctx.write_vreg(*dst, val);
                }
            }

            OpKind::Store { src, addr, width } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val = ctx.read_vreg(*src);
                self.store_memory(memory, effective_addr, val, *width)?;
            }

            OpKind::RepStos {
                dst,
                src,
                count,
                width,
            } => {
                let mut addr = ctx.read_vreg(*dst);
                let mut remaining = ctx.read_vreg(*count);
                let val = ctx.read_vreg(*src);
                let stride = width.bytes() as u64;

                while remaining > 0 {
                    self.store_memory(memory, addr, val, *width)?;
                    addr = addr.wrapping_add(stride);
                    remaining -= 1;
                }

                ctx.write_vreg(*dst, addr);
                ctx.write_vreg(*count, remaining);
            }

            OpKind::RepMovs {
                dst,
                src,
                count,
                width,
            } => {
                let mut dst_addr = ctx.read_vreg(*dst);
                let mut src_addr = ctx.read_vreg(*src);
                let mut remaining = ctx.read_vreg(*count);
                let stride = width.bytes() as u64;
                let forward = !ctx.flags.materialized.df;

                while remaining > 0 {
                    let val = self.load_memory(memory, src_addr, *width, SignExtend::Zero)?;
                    self.store_memory(memory, dst_addr, val, *width)?;
                    if forward {
                        dst_addr = dst_addr.wrapping_add(stride);
                        src_addr = src_addr.wrapping_add(stride);
                    } else {
                        dst_addr = dst_addr.wrapping_sub(stride);
                        src_addr = src_addr.wrapping_sub(stride);
                    }
                    remaining -= 1;
                }

                ctx.write_vreg(*dst, dst_addr);
                ctx.write_vreg(*src, src_addr);
                ctx.write_vreg(*count, remaining);
            }

            OpKind::Leave => {
                let rbp = VReg::Arch(ArchReg::X86(X86Reg::Rbp));
                let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
                let frame = ctx.read_vreg(rbp);
                let val = self.load_memory(memory, frame, MemWidth::B8, SignExtend::Zero)?;
                ctx.write_vreg(rsp, frame.wrapping_add(8));
                ctx.write_vreg(rbp, val);
            }

            OpKind::IoIn { dst, .. } => {
                ctx.write_vreg(*dst, 0);
            }

            OpKind::IoOut { .. } => {}

            OpKind::LoadPair {
                dst1,
                dst2,
                addr,
                width,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val1 = self.load_memory(memory, effective_addr, *width, SignExtend::Zero)?;
                let val2 = self.load_memory(
                    memory,
                    effective_addr + width.bytes() as u64,
                    *width,
                    SignExtend::Zero,
                )?;
                ctx.write_vreg(*dst1, val1);
                ctx.write_vreg(*dst2, val2);
            }

            OpKind::StorePair {
                src1,
                src2,
                addr,
                width,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val1 = ctx.read_vreg(*src1);
                let val2 = ctx.read_vreg(*src2);
                self.store_memory(memory, effective_addr, val1, *width)?;
                self.store_memory(memory, effective_addr + width.bytes() as u64, val2, *width)?;
            }

            OpKind::AtomicLoad {
                dst,
                addr,
                width,
                order,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val = memory.atomic_load(effective_addr, *width, *order)?;
                ctx.write_vreg(*dst, val);
            }

            OpKind::AtomicStore {
                src,
                addr,
                width,
                order,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val = ctx.read_vreg(*src);
                memory.atomic_store(effective_addr, val, *width, *order)?;
            }

            OpKind::AtomicRmw {
                dst,
                addr,
                src,
                op,
                width,
                order,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let operand = ctx.read_vreg(*src);
                let old = memory.atomic_rmw(effective_addr, *op, operand, *width, *order)?;
                ctx.write_vreg(*dst, old);
            }

            OpKind::Cas {
                dst,
                success,
                addr,
                expected,
                new_val,
                width,
                order,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let exp = ctx.read_vreg(*expected);
                let new = ctx.read_vreg(*new_val);
                let (old, succ) = memory.compare_and_swap(
                    effective_addr,
                    exp,
                    new,
                    *width,
                    *order,
                    MemoryOrder::Relaxed,
                )?;
                ctx.write_vreg(*dst, old);
                ctx.write_vreg(*success, if succ { 1 } else { 0 });
            }

            OpKind::LoadExclusive { dst, addr, width } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val = memory.load_exclusive(effective_addr, *width)?;
                ctx.exclusive_monitor
                    .mark_exclusive(effective_addr, *width, val);
                ctx.write_vreg(*dst, val);
            }

            OpKind::StoreExclusive {
                status,
                src,
                addr,
                width,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val = ctx.read_vreg(*src);
                let success = memory.store_exclusive(effective_addr, val, *width)?;
                ctx.write_vreg(*status, if success { 0 } else { 1 });
                ctx.exclusive_monitor.clear();
            }

            OpKind::ClearExclusive => {
                ctx.exclusive_monitor.clear();
                memory.clear_exclusive();
            }

            OpKind::Prefetch { addr, write } => {
                let effective_addr = self.compute_address(ctx, addr);
                memory.prefetch(effective_addr, *write);
            }

            OpKind::Fence { kind } => {
                memory.fence(*kind);
            }

            // ==================================================================
            // FLOATING POINT
            // ==================================================================
            OpKind::FAdd {
                dst,
                src1,
                src2,
                precision,
            } => {
                let a = self.read_fp(ctx, *src1, *precision);
                let b = self.read_fp(ctx, *src2, *precision);
                self.write_fp(ctx, *dst, a + b, *precision);
            }

            OpKind::FSub {
                dst,
                src1,
                src2,
                precision,
            } => {
                let a = self.read_fp(ctx, *src1, *precision);
                let b = self.read_fp(ctx, *src2, *precision);
                self.write_fp(ctx, *dst, a - b, *precision);
            }

            OpKind::FMul {
                dst,
                src1,
                src2,
                precision,
            } => {
                let a = self.read_fp(ctx, *src1, *precision);
                let b = self.read_fp(ctx, *src2, *precision);
                self.write_fp(ctx, *dst, a * b, *precision);
            }

            OpKind::FDiv {
                dst,
                src1,
                src2,
                precision,
            } => {
                let a = self.read_fp(ctx, *src1, *precision);
                let b = self.read_fp(ctx, *src2, *precision);
                self.write_fp(ctx, *dst, a / b, *precision);
            }

            OpKind::FFma {
                dst,
                src1,
                src2,
                src3,
                precision,
            } => {
                let a = self.read_fp(ctx, *src1, *precision);
                let b = self.read_fp(ctx, *src2, *precision);
                let c = self.read_fp(ctx, *src3, *precision);
                self.write_fp(ctx, *dst, a.mul_add(b, c), *precision);
            }

            OpKind::FAbs {
                dst,
                src,
                precision,
            } => {
                let a = self.read_fp(ctx, *src, *precision);
                self.write_fp(ctx, *dst, a.abs(), *precision);
            }

            OpKind::FNeg {
                dst,
                src,
                precision,
            } => {
                let a = self.read_fp(ctx, *src, *precision);
                self.write_fp(ctx, *dst, -a, *precision);
            }

            OpKind::FSqrt {
                dst,
                src,
                precision,
            } => {
                let a = self.read_fp(ctx, *src, *precision);
                self.write_fp(ctx, *dst, a.sqrt(), *precision);
            }

            OpKind::FMin {
                dst,
                src1,
                src2,
                precision,
            } => {
                let a = self.read_fp(ctx, *src1, *precision);
                let b = self.read_fp(ctx, *src2, *precision);
                self.write_fp(ctx, *dst, a.min(b), *precision);
            }

            OpKind::FMax {
                dst,
                src1,
                src2,
                precision,
            } => {
                let a = self.read_fp(ctx, *src1, *precision);
                let b = self.read_fp(ctx, *src2, *precision);
                self.write_fp(ctx, *dst, a.max(b), *precision);
            }

            OpKind::FCmp {
                src1,
                src2,
                precision,
            } => {
                let a = self.read_fp(ctx, *src1, *precision);
                let b = self.read_fp(ctx, *src2, *precision);
                // Set flags based on comparison
                let result = if a < b {
                    u64::MAX
                } else if a > b {
                    1
                } else {
                    0
                };
                ctx.flags.set_lazy_sub(
                    if a >= b { 1 } else { 0 },
                    if a <= b { 1 } else { 0 },
                    result,
                    OpWidth::W64,
                );
            }

            OpKind::FConvert { dst, src, from, to } => {
                let a = self.read_fp(ctx, *src, *from);
                self.write_fp(ctx, *dst, a, *to);
            }

            OpKind::IntToFp {
                dst,
                src,
                int_width,
                fp_precision,
                signed,
            } => {
                let val = ctx.read_vreg(*src) & int_width.mask();
                let f = if *signed {
                    self.sign_extend(val, *int_width) as i64 as f64
                } else {
                    val as f64
                };
                self.write_fp(ctx, *dst, f, *fp_precision);
            }

            OpKind::FpToInt {
                dst,
                src,
                fp_precision,
                int_width,
                signed,
                round: _,
            } => {
                let f = self.read_fp(ctx, *src, *fp_precision);
                let val = if *signed { (f as i64) as u64 } else { f as u64 };
                ctx.write_vreg(*dst, val & int_width.mask());
            }

            OpKind::FRound {
                dst,
                src,
                precision,
                mode: _,
            } => {
                let a = self.read_fp(ctx, *src, *precision);
                self.write_fp(ctx, *dst, a.round(), *precision);
            }

            // ==================================================================
            // SIMD / VECTOR (simplified)
            // ==================================================================
            OpKind::VAdd {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => match elem {
                VecElementType::F32 => {
                    self.vec_binary_op_f32(ctx, *dst, *src1, *src2, *lanes, |a, b| a + b);
                }
                VecElementType::F64 => {
                    self.vec_binary_op_f64(ctx, *dst, *src1, *src2, *lanes, |a, b| a + b);
                }
                _ => {
                    self.vec_binary_op(ctx, *dst, *src1, *src2, *elem, *lanes, |a, b| {
                        a.wrapping_add(b)
                    });
                }
            },

            OpKind::VSub {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => match elem {
                VecElementType::F32 => {
                    self.vec_binary_op_f32(ctx, *dst, *src1, *src2, *lanes, |a, b| a - b);
                }
                VecElementType::F64 => {
                    self.vec_binary_op_f64(ctx, *dst, *src1, *src2, *lanes, |a, b| a - b);
                }
                _ => {
                    self.vec_binary_op(ctx, *dst, *src1, *src2, *elem, *lanes, |a, b| {
                        a.wrapping_sub(b)
                    });
                }
            },

            OpKind::VMax {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => match elem {
                VecElementType::F32 => {
                    self.vec_binary_op_f32(ctx, *dst, *src1, *src2, *lanes, |a, b| a.max(b));
                }
                VecElementType::F64 => {
                    self.vec_binary_op_f64(ctx, *dst, *src1, *src2, *lanes, |a, b| a.max(b));
                }
                _ => {
                    self.vec_binary_op(ctx, *dst, *src1, *src2, *elem, *lanes, |a, b| a.max(b));
                }
            },

            OpKind::VMul {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => match elem {
                VecElementType::F32 => {
                    self.vec_binary_op_f32(ctx, *dst, *src1, *src2, *lanes, |a, b| a * b);
                }
                VecElementType::F64 => {
                    self.vec_binary_op_f64(ctx, *dst, *src1, *src2, *lanes, |a, b| a * b);
                }
                _ => {
                    self.vec_binary_op(ctx, *dst, *src1, *src2, *elem, *lanes, |a, b| {
                        a.wrapping_mul(b)
                    });
                }
            },

            OpKind::VAnd {
                dst,
                src1,
                src2,
                width,
            } => {
                let a = ctx.vregs.get_vec(match *src1 {
                    VReg::Virtual(id) => id,
                    _ => panic!(),
                });
                let b = ctx.vregs.get_vec(match *src2 {
                    VReg::Virtual(id) => id,
                    _ => panic!(),
                });
                if let VReg::Virtual(id) = *dst {
                    let mut result = [0u64; 16];
                    let word_count = (width.bytes() / 8) as usize;
                    for i in 0..word_count {
                        result[i] = a[i] & b[i];
                    }
                    ctx.vregs.set_vec(id, result);
                }
            }

            OpKind::VOr {
                dst,
                src1,
                src2,
                width,
            } => {
                let a = ctx.vregs.get_vec(match *src1 {
                    VReg::Virtual(id) => id,
                    _ => panic!(),
                });
                let b = ctx.vregs.get_vec(match *src2 {
                    VReg::Virtual(id) => id,
                    _ => panic!(),
                });
                if let VReg::Virtual(id) = *dst {
                    let mut result = [0u64; 16];
                    let word_count = (width.bytes() / 8) as usize;
                    for i in 0..word_count {
                        result[i] = a[i] | b[i];
                    }
                    ctx.vregs.set_vec(id, result);
                }
            }

            OpKind::VXor {
                dst,
                src1,
                src2,
                width,
            } => {
                let a = ctx.vregs.get_vec(match *src1 {
                    VReg::Virtual(id) => id,
                    _ => panic!(),
                });
                let b = ctx.vregs.get_vec(match *src2 {
                    VReg::Virtual(id) => id,
                    _ => panic!(),
                });
                if let VReg::Virtual(id) = *dst {
                    let mut result = [0u64; 16];
                    let word_count = (width.bytes() / 8) as usize;
                    for i in 0..word_count {
                        result[i] = a[i] ^ b[i];
                    }
                    ctx.vregs.set_vec(id, result);
                }
            }

            OpKind::VLane {
                dst,
                src1,
                src2,
                elem,
                lanes,
                op,
                signed,
            } => {
                let a = Self::read_vec(ctx, *src1);
                let b = Self::read_vec(ctx, *src2);
                let elem_bits = elem.bytes() * 8;
                let mut result = [0u64; 16];
                for lane in 0..*lanes {
                    let av = Self::get_lane(&a, lane, elem_bits);
                    let bv = Self::get_lane(&b, lane, elem_bits);
                    let rv = Self::apply_lane_op(*op, av, bv, elem_bits, *signed);
                    Self::set_lane(&mut result, lane, elem_bits, rv);
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VWidenMul {
                dst_lo,
                dst_hi,
                src1,
                src2,
                src_elem,
                signed1,
                signed2,
                acc,
            } => {
                let a = Self::read_vec(ctx, *src1);
                let b = Self::read_vec(ctx, *src2);
                let nbits = src_elem.bytes() * 8;
                let wbits = nbits * 2;
                let wide_lanes = (1024 / nbits as usize) / 2; // wide lanes per output vector
                let mut lo = if *acc { Self::read_vec(ctx, *dst_lo) } else { [0u64; 16] };
                let mut hi = if *acc { Self::read_vec(ctx, *dst_hi) } else { [0u64; 16] };
                // Sign- or zero-extend an `nbits` zero-extended lane value to i64.
                let ext = |v: u64, signed: bool| -> i64 {
                    if signed {
                        let shift = 64 - nbits;
                        ((v << shift) as i64) >> shift
                    } else {
                        v as i64
                    }
                };
                for i in 0..wide_lanes {
                    let even = i as u8 * 2;
                    let odd = even + 1;
                    let pe = ext(Self::get_lane(&a, even, nbits), *signed1)
                        .wrapping_mul(ext(Self::get_lane(&b, even, nbits), *signed2));
                    let po = ext(Self::get_lane(&a, odd, nbits), *signed1)
                        .wrapping_mul(ext(Self::get_lane(&b, odd, nbits), *signed2));
                    let ae = if *acc { Self::get_lane(&lo, i as u8, wbits) as i64 } else { 0 };
                    let ao = if *acc { Self::get_lane(&hi, i as u8, wbits) as i64 } else { 0 };
                    Self::set_lane(&mut lo, i as u8, wbits, ae.wrapping_add(pe) as u64);
                    Self::set_lane(&mut hi, i as u8, wbits, ao.wrapping_add(po) as u64);
                }
                Self::write_vec(ctx, *dst_lo, lo);
                Self::write_vec(ctx, *dst_hi, hi);
            }

            OpKind::VAlign {
                dst,
                src1,
                src2,
                amount,
                left,
            } => {
                let amt = match amount {
                    SrcOperand::Imm(v) => *v as usize,
                    SrcOperand::Reg(r) => ctx.read_vreg(*r) as usize,
                    _ => 0,
                };
                let shift = if *left { 128 - (amt & 127) } else { amt & 127 };
                let u = Self::read_vec(ctx, *src1);
                let v = Self::read_vec(ctx, *src2);
                let mut result = [0u64; 16];
                for i in 0..128u8 {
                    let j = i as usize + shift;
                    let byte = if j < 128 {
                        Self::get_lane(&v, j as u8, 8)
                    } else {
                        Self::get_lane(&u, (j - 128) as u8, 8)
                    };
                    Self::set_lane(&mut result, i, 8, byte);
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VShuffle2 { dst, src, elem, deal } => {
                let s = Self::read_vec(ctx, *src);
                let nbits = elem.bytes() * 8;
                let total = (1024 / nbits) as u8;
                let half = total / 2;
                let mut result = [0u64; 16];
                for i in 0..half {
                    if *deal {
                        Self::set_lane(&mut result, i, nbits, Self::get_lane(&s, i * 2, nbits));
                        Self::set_lane(&mut result, i + half, nbits, Self::get_lane(&s, i * 2 + 1, nbits));
                    } else {
                        Self::set_lane(&mut result, i * 2, nbits, Self::get_lane(&s, i, nbits));
                        Self::set_lane(&mut result, i * 2 + 1, nbits, Self::get_lane(&s, i + half, nbits));
                    }
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VShuffleEO {
                dst,
                src1,
                src2,
                elem,
                odd,
            } => {
                let u = Self::read_vec(ctx, *src1);
                let v = Self::read_vec(ctx, *src2);
                let nbits = elem.bytes() * 8;
                let total = (1024 / nbits) as u8;
                let half = total / 2;
                let parity = if *odd { 1 } else { 0 };
                let mut result = [0u64; 16];
                for i in 0..half {
                    let sel = i * 2 + parity;
                    Self::set_lane(&mut result, i * 2, nbits, Self::get_lane(&v, sel, nbits));
                    Self::set_lane(&mut result, i * 2 + 1, nbits, Self::get_lane(&u, sel, nbits));
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VPack {
                dst,
                src1,
                src2,
                elem,
                odd,
            } => {
                let u = Self::read_vec(ctx, *src1);
                let v = Self::read_vec(ctx, *src2);
                let nbits = elem.bytes() * 8;
                let total = (1024 / nbits) as u8;
                let half = total / 2;
                let parity = if *odd { 1 } else { 0 };
                let mut result = [0u64; 16];
                for i in 0..half {
                    let sel = i * 2 + parity;
                    Self::set_lane(&mut result, i, nbits, Self::get_lane(&v, sel, nbits));
                    Self::set_lane(&mut result, i + half, nbits, Self::get_lane(&u, sel, nbits));
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VPackSat {
                dst,
                src1,
                src2,
                src_elem,
                to_unsigned,
            } => {
                let u = Self::read_vec(ctx, *src1);
                let v = Self::read_vec(ctx, *src2);
                let wbits = src_elem.bytes() * 8;
                let nbits = wbits / 2;
                let wide_lanes = (1024 / wbits) as u8;
                let (lo_b, hi_b) = if *to_unsigned {
                    (0i64, ((1i64 << nbits) - 1))
                } else {
                    (-(1i64 << (nbits - 1)), (1i64 << (nbits - 1)) - 1)
                };
                let sat = |raw: u64| -> u64 {
                    let sh = 64 - wbits;
                    let sv = ((raw << sh) as i64) >> sh; // sign-extend wide source
                    sv.clamp(lo_b, hi_b) as u64
                };
                let mut result = [0u64; 16];
                for i in 0..wide_lanes {
                    Self::set_lane(&mut result, i, nbits, sat(Self::get_lane(&v, i, wbits)));
                    Self::set_lane(
                        &mut result,
                        i + wide_lanes,
                        nbits,
                        sat(Self::get_lane(&u, i, wbits)),
                    );
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VWidenExt {
                dst_lo,
                dst_hi,
                src,
                src_elem,
                signed,
                interleave,
            } => {
                let s = Self::read_vec(ctx, *src);
                let nbits = src_elem.bytes() * 8;
                let wbits = nbits * 2;
                let wide_lanes = (1024 / wbits) as u8; // wide lanes per output vector
                let ext = |raw: u64| -> u64 {
                    if *signed {
                        let sh = 64 - nbits;
                        (((raw << sh) as i64) >> sh) as u64
                    } else {
                        raw
                    }
                };
                let mut lo = [0u64; 16];
                let mut hi = [0u64; 16];
                for i in 0..wide_lanes {
                    let (lo_idx, hi_idx) = if *interleave {
                        (i * 2, i * 2 + 1)
                    } else {
                        (i, i + wide_lanes)
                    };
                    Self::set_lane(&mut lo, i, wbits, ext(Self::get_lane(&s, lo_idx, nbits)));
                    Self::set_lane(&mut hi, i, wbits, ext(Self::get_lane(&s, hi_idx, nbits)));
                }
                Self::write_vec(ctx, *dst_lo, lo);
                Self::write_vec(ctx, *dst_hi, hi);
            }

            OpKind::VCmpToQ {
                dst,
                src1,
                src2,
                cond,
                elem,
                lanes,
                accumulate,
            } => {
                let a = Self::read_vec(ctx, *src1);
                let b = Self::read_vec(ctx, *src2);
                let nbits = elem.bytes() * 8;
                let ebytes = elem.bytes() as usize;
                let sext = |v: u64| -> i64 {
                    let sh = 64 - nbits;
                    ((v << sh) as i64) >> sh
                };
                let mut q = [0u64; 16];
                for lane in 0..*lanes {
                    let av = Self::get_lane(&a, lane, nbits);
                    let bv = Self::get_lane(&b, lane, nbits);
                    let t = match cond {
                        VecCmpCond::Eq => av == bv,
                        VecCmpCond::Ne => av != bv,
                        VecCmpCond::Gt => sext(av) > sext(bv),
                        VecCmpCond::Ge => sext(av) >= sext(bv),
                        VecCmpCond::Lt => sext(av) < sext(bv),
                        VecCmpCond::Le => sext(av) <= sext(bv),
                        VecCmpCond::Gtu => av > bv,
                        VecCmpCond::Geu => av >= bv,
                        VecCmpCond::Ltu => av < bv,
                        VecCmpCond::Leu => av <= bv,
                    };
                    if t {
                        for byte in 0..ebytes {
                            let bit = lane as usize * ebytes + byte;
                            q[bit >> 6] |= 1u64 << (bit & 63);
                        }
                    }
                }
                // Accumulating compares combine the new mask into the existing Q.
                if let Some(combine) = accumulate {
                    let prev = Self::read_vec(ctx, *dst);
                    for w in 0..2 {
                        q[w] = match combine {
                            VLaneOp::And => prev[w] & q[w],
                            VLaneOp::Or => prev[w] | q[w],
                            VLaneOp::Xor => prev[w] ^ q[w],
                            _ => q[w],
                        };
                    }
                }
                Self::write_vec(ctx, *dst, q);
            }

            OpKind::VMaskZero {
                dst,
                mask_q,
                src,
                negate,
            } => {
                let m = Self::read_vec(ctx, *mask_q);
                let s = Self::read_vec(ctx, *src);
                let mut result = [0u64; 16];
                for byte in 0..128usize {
                    let bit = (m[byte >> 6] >> (byte & 63)) & 1 != 0;
                    if bit ^ *negate {
                        Self::set_lane(&mut result, byte as u8, 8, Self::get_lane(&s, byte as u8, 8));
                    }
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VBlend {
                dst,
                mask_q,
                src_true,
                src_false,
            } => {
                let m = Self::read_vec(ctx, *mask_q);
                let t = Self::read_vec(ctx, *src_true);
                let f = Self::read_vec(ctx, *src_false);
                let mut result = [0u64; 16];
                for byte in 0..128usize {
                    let bit_set = (m[byte >> 6] >> (byte & 63)) & 1 != 0;
                    let src = if bit_set { &t } else { &f };
                    Self::set_lane(&mut result, byte as u8, 8, Self::get_lane(src, byte as u8, 8));
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VShiftV {
                dst,
                src,
                amount,
                elem,
                lanes,
                kind,
            } => {
                let s = Self::read_vec(ctx, *src);
                let amt = Self::read_vec(ctx, *amount);
                let nbits = elem.bytes() * 8;
                let n_amt = nbits.trailing_zeros() + 1; // 16->5, 32->6
                let mut result = [0u64; 16];
                for i in 0..*lanes {
                    let raw = Self::get_lane(&s, i, nbits);
                    // sign-extend the low n_amt bits of the amount lane.
                    let araw = Self::get_lane(&amt, i, nbits) & ((1u64 << n_amt) - 1);
                    let sh = 64 - n_amt;
                    let shamt = (((araw << sh) as i64) >> sh) as i32;
                    let sext = |v: u64| -> i64 {
                        let sh = 64 - nbits;
                        ((v << sh) as i64) >> sh
                    };
                    let out: u64 = match kind {
                        VShiftVKind::AshiftL => {
                            let sa = sext(raw);
                            if shamt >= 0 {
                                (sa << shamt) as u64
                            } else {
                                (sa >> (-shamt)) as u64
                            }
                        }
                        VShiftVKind::AshiftR => {
                            let sa = sext(raw);
                            if shamt >= 0 {
                                (sa >> shamt) as u64
                            } else {
                                (sa << (-shamt)) as u64
                            }
                        }
                        VShiftVKind::LshiftR => {
                            if shamt >= 0 {
                                raw >> shamt
                            } else {
                                raw << (-shamt)
                            }
                        }
                    };
                    Self::set_lane(&mut result, i, nbits, out);
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VMulShiftSat {
                dst,
                src1,
                src2,
                src_elem,
                signed1,
                signed2,
                shift_left,
                round,
                sat_bits,
                out_shift,
            } => {
                let a = Self::read_vec(ctx, *src1);
                let b = Self::read_vec(ctx, *src2);
                let nbits = src_elem.bytes() * 8;
                let lanes = (1024 / nbits) as u8;
                let ext = |raw: u64, signed: bool| -> i64 {
                    if signed {
                        let sh = 64 - nbits;
                        ((raw << sh) as i64) >> sh
                    } else {
                        raw as i64
                    }
                };
                let mut result = [0u64; 16];
                for i in 0..lanes {
                    let mut p = ext(Self::get_lane(&a, i, nbits), *signed1)
                        .wrapping_mul(ext(Self::get_lane(&b, i, nbits), *signed2));
                    p <<= *shift_left;
                    if *round {
                        p += 1i64 << (*out_shift - 1);
                    }
                    if *sat_bits != 0 {
                        let lo = -(1i64 << (*sat_bits - 1));
                        let hi = (1i64 << (*sat_bits - 1)) - 1;
                        p = p.clamp(lo, hi);
                    }
                    Self::set_lane(&mut result, i, nbits, (p >> *out_shift) as u64);
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VMulEvenWiden {
                dst,
                src1,
                src2,
                src_elem,
                signed1,
                signed2,
                acc,
            } => {
                let a = Self::read_vec(ctx, *src1);
                let b = Self::read_vec(ctx, *src2);
                let nbits = src_elem.bytes() * 8;
                let wbits = nbits * 2;
                let olanes = (1024 / wbits) as u8;
                let mut out = if *acc { Self::read_vec(ctx, *dst) } else { [0u64; 16] };
                let ext = |v: u64, signed: bool| -> i64 {
                    if signed {
                        let sh = 64 - nbits;
                        ((v << sh) as i64) >> sh
                    } else {
                        v as i64
                    }
                };
                for i in 0..olanes {
                    let p = ext(Self::get_lane(&a, i * 2, nbits), *signed1)
                        .wrapping_mul(ext(Self::get_lane(&b, i * 2, nbits), *signed2));
                    let acc_v = if *acc { Self::get_lane(&out, i, wbits) as i64 } else { 0 };
                    Self::set_lane(&mut out, i, wbits, acc_v.wrapping_add(p) as u64);
                }
                Self::write_vec(ctx, *dst, out);
            }

            OpKind::VReduceMul {
                dst,
                src1,
                src2,
                src1_elem,
                src2_elem,
                out_elem,
                taps,
                signed1,
                signed2,
                sat,
                acc,
            } => {
                let a = Self::read_vec(ctx, *src1);
                let b = Self::read_vec(ctx, *src2);
                let n1 = src1_elem.bytes() * 8;
                let n2 = src2_elem.bytes() * 8;
                let obits = out_elem.bytes() * 8;
                let olanes = (1024 / obits) as u8;
                let mut out = if *acc { Self::read_vec(ctx, *dst) } else { [0u64; 16] };
                let ext = |v: u64, bits: u32, signed: bool| -> i64 {
                    if signed {
                        let shift = 64 - bits;
                        ((v << shift) as i64) >> shift
                    } else {
                        v as i64
                    }
                };
                for i in 0..olanes {
                    let mut s: i64 = if *acc {
                        // accumulator low `obits` bits, sign-extended for saturating sum.
                        ext(Self::get_lane(&out, i, obits), obits, true)
                    } else {
                        0
                    };
                    for k in 0..*taps {
                        let idx = i * *taps + k;
                        s = s.wrapping_add(
                            ext(Self::get_lane(&a, idx, n1), n1, *signed1)
                                .wrapping_mul(ext(Self::get_lane(&b, idx, n2), n2, *signed2)),
                        );
                    }
                    if *sat && obits < 64 {
                        let lo = -(1i64 << (obits - 1));
                        let hi = (1i64 << (obits - 1)) - 1;
                        s = s.clamp(lo, hi);
                    }
                    Self::set_lane(&mut out, i, obits, s as u64);
                }
                Self::write_vec(ctx, *dst, out);
            }

            OpKind::VMov { dst, src, width: _ } => {
                let val = Self::read_vec(ctx, *src);
                Self::write_vec(ctx, *dst, val);
            }

            OpKind::VShift {
                dst,
                src,
                amount,
                shift,
                elem,
                lanes,
            } => {
                let amt = match amount {
                    SrcOperand::Imm(val) => *val as u32,
                    SrcOperand::Reg(reg) => ctx.read_vreg(*reg) as u32,
                    _ => 0,
                };
                let elem_bits = elem.bytes() * 8;
                let mask = if elem_bits == 64 {
                    u64::MAX
                } else {
                    (1u64 << elem_bits) - 1
                };
                let src_val = Self::read_vec(ctx, *src);
                let mut result = [0u64; 16];
                for lane in 0..*lanes {
                    let val = Self::get_lane(&src_val, lane, elem_bits);
                    let shifted = match shift {
                        ShiftOp::Lsl => (val << (amt % elem_bits)) & mask,
                        ShiftOp::Lsr => (val >> (amt % elem_bits)) & mask,
                        ShiftOp::Asr => {
                            // Sign-extend the element to i64 before the arithmetic
                            // shift (get_lane zero-extends), so high lanes are
                            // replicated with the element's sign bit, not 0.
                            let sv = if elem_bits >= 64 {
                                val as i64
                            } else {
                                let sh = 64 - elem_bits;
                                ((val << sh) as i64) >> sh
                            };
                            ((sv >> (amt % elem_bits)) as u64) & mask
                        }
                        _ => val,
                    };
                    Self::set_lane(&mut result, lane, elem_bits, shifted);
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VBroadcast {
                dst,
                scalar,
                elem,
                lanes,
            } => {
                // Splat the low `elem` bits of the scalar register into every lane.
                let elem_bits = elem.bytes() * 8;
                let val = ctx.read_vreg(*scalar);
                let mut result = [0u64; 16];
                for lane in 0..*lanes {
                    Self::set_lane(&mut result, lane, elem_bits, val);
                }
                Self::write_vec(ctx, *dst, result);
            }

            OpKind::VCmp { .. }
            | OpKind::VInsertLane { .. }
            | OpKind::VExtractLane { .. }
            | OpKind::VShuffle { .. } => {
                // Simplified: not fully implemented
            }

            OpKind::VLoad { dst, addr, width } => {
                let effective_addr = self.compute_address(ctx, addr);
                let mut buf = [0u8; 64];
                let size = width.bytes() as usize;
                memory.read(effective_addr, &mut buf[..size])?;

                let mut vec = [0u64; 16];
                let words = (size + 7) / 8;
                for i in 0..words {
                    let start = i * 8;
                    let end = start + 8;
                    vec[i] = u64::from_le_bytes(buf[start..end].try_into().unwrap());
                }

                Self::write_vec(ctx, *dst, vec);
            }

            OpKind::VStore { src, addr, width } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val = Self::read_vec(ctx, *src);

                let size = width.bytes() as usize;
                let mut buf = [0u8; 64];
                let words = (size + 7) / 8;
                for i in 0..words {
                    let start = i * 8;
                    let end = start + 8;
                    buf[start..end].copy_from_slice(&val[i].to_le_bytes());
                }

                memory.write(effective_addr, &buf[..size])?;
            }

            // ==================================================================
            // FLAG OPERATIONS
            // ==================================================================
            OpKind::ReadFlags { dst } => {
                ctx.flags.materialize_all();
                let rflags = ctx.flags.materialized.to_rflags();
                ctx.write_vreg(*dst, rflags);
            }

            OpKind::WriteFlags { src } => {
                let rflags = ctx.read_vreg(*src);
                ctx.flags.materialized = crate::smir::flags::MaterializedFlags::from_rflags(rflags);
                ctx.flags.lazy = None;
            }

            OpKind::SetCF { value } => {
                ctx.flags.materialize_all();
                ctx.flags.materialized.cf = *value;
            }

            OpKind::SetDF { value } => {
                ctx.flags.materialize_all();
                ctx.flags.materialized.df = *value;
            }

            OpKind::CmcCF => {
                let cf = ctx.flags.get_cf();
                ctx.flags.materialize_all();
                ctx.flags.materialized.cf = !cf;
            }

            OpKind::MaterializeFlags => {
                ctx.flags.materialize_all();
            }

            OpKind::TestCondition { dst, cond } => {
                let result = if ctx.flags.eval_condition(*cond) {
                    1
                } else {
                    0
                };
                ctx.write_vreg(*dst, result);
            }

            OpKind::SetCC { dst, cond, width } => {
                let result = if ctx.flags.eval_condition(*cond) {
                    1u64
                } else {
                    0
                };
                ctx.write_vreg(*dst, result & width.mask());
            }

            // ==================================================================
            // SYSTEM / PRIVILEGED
            // ==================================================================
            OpKind::Syscall { num, args } => {
                let num_val = ctx.read_vreg(*num);
                let arg_vals: Vec<u64> = args.iter().map(|a| ctx.read_vreg(*a)).collect();
                ctx.request_exit(ExitReason::Syscall {
                    num: num_val,
                    args: arg_vals,
                });
            }

            OpKind::Swi { imm } => {
                ctx.request_exit(ExitReason::Syscall {
                    num: *imm as u64,
                    args: vec![],
                });
            }

            OpKind::ReadSysReg { dst, reg: _ } => {
                // Simplified: return 0
                ctx.write_vreg(*dst, 0);
            }

            OpKind::WriteSysReg { reg: _, src: _ } => {
                // Simplified: no-op
            }

            // ==================================================================
            // META / DEBUG
            // ==================================================================
            OpKind::Nop => {}

            OpKind::Undefined { opcode } => {
                ctx.request_exit(ExitReason::Undefined {
                    addr: ctx.pc,
                    opcode: *opcode,
                });
            }

            OpKind::Breakpoint => {
                ctx.request_exit(ExitReason::Breakpoint { addr: ctx.pc });
            }

            // ==================================================================
            // AVX10 OPERATIONS (Stubs - not yet implemented in interpreter)
            // ==================================================================
            OpKind::VMin { .. }
            | OpKind::VFma { .. }
            | OpKind::VDotProduct { .. }
            | OpKind::VMultiplyAdd52 { .. }
            | OpKind::VPopcnt { .. }
            | OpKind::VPermute { .. }
            | OpKind::VShuffleBitQM { .. }
            | OpKind::VDotProductBF16 { .. }
            | OpKind::VCvtFP32ToBF16 { .. }
            | OpKind::VCvtBF16ToFP32 { .. }
            | OpKind::VFP16Arith { .. }
            | OpKind::VCvtFpToIntSat { .. }
            | OpKind::VMinMax { .. }
            | OpKind::VMpsadbw { .. }
            | OpKind::VDotProductExt { .. } => {
                // AVX10 operations not yet implemented in interpreter
                // These would require full vector register state tracking
                ctx.request_exit(ExitReason::Undefined {
                    addr: ctx.pc,
                    opcode: 0,
                });
            }
        }

        Ok(())
    }

    fn read_vec(ctx: &SmirContext, reg: VReg) -> VecValue {
        match reg {
            VReg::Virtual(id) => ctx.vregs.get_vec(id),
            VReg::Arch(ArchReg::X86(X86Reg::Xmm(n)))
            | VReg::Arch(ArchReg::X86(X86Reg::Ymm(n)))
            | VReg::Arch(ArchReg::X86(X86Reg::Zmm(n))) => match &ctx.arch_regs {
                ArchRegState::X86_64(x86) => x86.xmm[n as usize],
                _ => [0; 16],
            },
            VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n))) => match &ctx.arch_regs {
                ArchRegState::Hexagon(hex) => hex.get_v(n),
                _ => [0; 16],
            },
            VReg::Arch(ArchReg::Hexagon(HexagonReg::Q(n))) => match &ctx.arch_regs {
                ArchRegState::Hexagon(hex) => hex.get_q(n),
                _ => [0; 16],
            },
            _ => [0; 16],
        }
    }

    fn write_vec(ctx: &mut SmirContext, reg: VReg, value: VecValue) {
        match reg {
            VReg::Virtual(id) => ctx.vregs.set_vec(id, value),
            VReg::Arch(ArchReg::X86(X86Reg::Xmm(n)))
            | VReg::Arch(ArchReg::X86(X86Reg::Ymm(n)))
            | VReg::Arch(ArchReg::X86(X86Reg::Zmm(n))) => {
                if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                    x86.xmm[n as usize] = value;
                }
            }
            VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n))) => {
                if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
                    hex.set_v(n, value);
                }
            }
            VReg::Arch(ArchReg::Hexagon(HexagonReg::Q(n))) => {
                if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
                    hex.set_q(n, value);
                }
            }
            _ => {}
        }
    }

    fn write_x86_partial(ctx: &mut SmirContext, dst: VReg, value: u64, width: OpWidth) {
        if let VReg::Arch(ArchReg::X86(_)) = dst {
            if matches!(width, OpWidth::W8 | OpWidth::W16) {
                let mask = width.mask();
                let prev = ctx.read_vreg(dst);
                ctx.write_vreg(dst, (prev & !mask) | (value & mask));
                return;
            }
        }
        ctx.write_vreg(dst, value & width.mask());
    }

    /// Execute block terminator
    fn execute_terminator(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        term: &Terminator,
    ) -> BlockResult {
        match term {
            Terminator::Branch { target } => {
                let addr = self
                    .block_addrs
                    .get(target)
                    .copied()
                    .unwrap_or(target.0 as u64);
                BlockResult::Continue(addr)
            }

            Terminator::CondBranch {
                cond,
                true_target,
                false_target,
            } => {
                let cond_val = ctx.read_vreg(*cond);
                let target = if cond_val != 0 {
                    true_target
                } else {
                    false_target
                };
                let addr = self
                    .block_addrs
                    .get(target)
                    .copied()
                    .unwrap_or(target.0 as u64);
                BlockResult::Continue(addr)
            }

            Terminator::Switch {
                index,
                targets,
                default,
            } => {
                let idx = ctx.read_vreg(*index) as usize;
                let target = if idx < targets.len() {
                    &targets[idx]
                } else {
                    default
                };
                let addr = self
                    .block_addrs
                    .get(target)
                    .copied()
                    .unwrap_or(target.0 as u64);
                BlockResult::Continue(addr)
            }

            Terminator::IndirectBranch { target, .. } => {
                let addr = ctx.read_vreg(*target);
                BlockResult::Continue(addr)
            }

            Terminator::IndirectBranchMem { addr, .. } => {
                let target_addr = self.compute_address(ctx, addr);
                let val = self
                    .load_memory(memory, target_addr, MemWidth::B8, SignExtend::Zero)
                    .unwrap_or(0);
                BlockResult::Continue(val)
            }

            Terminator::Return { values: _ } => {
                // Get return address from arch-specific location
                let ret_addr = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        // Pop from stack
                        let rsp = x86.gpr[4];
                        let mut buf = [0u8; 8];
                        if memory.read(rsp, &mut buf).is_ok() {
                            u64::from_le_bytes(buf)
                        } else {
                            0
                        }
                    }
                    ArchRegState::Aarch64(arm) => arm.x[30], // LR
                    ArchRegState::Hexagon(hex) => hex.lr as u64,
                    ArchRegState::RiscV(rv) => rv.x[1], // ra
                };
                BlockResult::Exit(ExitReason::Return { to: ret_addr })
            }

            Terminator::Call {
                target,
                args: _,
                continuation,
            } => {
                let target_addr = match target {
                    CallTarget::GuestAddr(addr) => *addr,
                    CallTarget::Direct(fid) => self
                        .func_cache
                        .get(&(fid.0 as u64))
                        .map(|f| f.guest_range.0)
                        .unwrap_or(0),
                    CallTarget::Indirect(reg) => ctx.read_vreg(*reg),
                    CallTarget::IndirectMem(addr) => {
                        let target_addr = self.compute_address(ctx, addr);
                        self.load_memory(memory, target_addr, MemWidth::B8, SignExtend::Zero)
                            .unwrap_or(0)
                    }
                    CallTarget::Runtime(_) => {
                        // Return to continuation for runtime calls
                        let addr = self
                            .block_addrs
                            .get(continuation)
                            .copied()
                            .unwrap_or(continuation.0 as u64);
                        return BlockResult::Continue(addr);
                    }
                };
                BlockResult::Continue(target_addr)
            }

            Terminator::TailCall { target, args: _ } => {
                let target_addr = match target {
                    CallTarget::GuestAddr(addr) => *addr,
                    CallTarget::Direct(fid) => self
                        .func_cache
                        .get(&(fid.0 as u64))
                        .map(|f| f.guest_range.0)
                        .unwrap_or(0),
                    CallTarget::Indirect(reg) => ctx.read_vreg(*reg),
                    CallTarget::IndirectMem(addr) => {
                        let target_addr = self.compute_address(ctx, addr);
                        self.load_memory(memory, target_addr, MemWidth::B8, SignExtend::Zero)
                            .unwrap_or(0)
                    }
                    CallTarget::Runtime(_) => 0,
                };
                BlockResult::Continue(target_addr)
            }

            Terminator::Trap { kind } => {
                match kind {
                    TrapKind::Halt => BlockResult::Exit(ExitReason::Halt),
                    TrapKind::Breakpoint => {
                        BlockResult::Exit(ExitReason::Breakpoint { addr: ctx.pc })
                    }
                    TrapKind::SystemCall => {
                        // Already handled in Syscall op
                        BlockResult::Continue(ctx.pc)
                    }
                    TrapKind::Undefined | TrapKind::InvalidOpcode => {
                        BlockResult::Exit(ExitReason::Undefined {
                            addr: ctx.pc,
                            opcode: 0,
                        })
                    }
                    TrapKind::DivideByZero | TrapKind::Overflow | TrapKind::Bounds => {
                        BlockResult::Exit(ExitReason::Undefined {
                            addr: ctx.pc,
                            opcode: 0,
                        })
                    }
                }
            }

            Terminator::Unreachable => BlockResult::Exit(ExitReason::Undefined {
                addr: ctx.pc,
                opcode: 0,
            }),
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Read source operand
    fn read_src_operand(&self, ctx: &SmirContext, src: &SrcOperand) -> u64 {
        match src {
            SrcOperand::Reg(r) => ctx.read_vreg(*r),
            SrcOperand::Imm(i) | SrcOperand::Imm64(i) => *i as u64,
            SrcOperand::Shifted { reg, shift, amount } => {
                let val = ctx.read_vreg(*reg);
                match shift {
                    ShiftOp::Lsl => val << amount,
                    ShiftOp::Lsr => val >> amount,
                    ShiftOp::Asr => ((val as i64) >> amount) as u64,
                    ShiftOp::Ror => val.rotate_right(*amount as u32),
                    ShiftOp::Rrx => {
                        // This needs the carry flag, simplified here
                        val >> 1
                    }
                }
            }
            SrcOperand::Extended { reg, extend, shift } => {
                let val = ctx.read_vreg(*reg);
                let extended = match extend {
                    ExtendOp::Uxtb => val & 0xFF,
                    ExtendOp::Uxth => val & 0xFFFF,
                    ExtendOp::Uxtw => val & 0xFFFF_FFFF,
                    ExtendOp::Uxtx => val,
                    ExtendOp::Sxtb => ((val as i8) as i64) as u64,
                    ExtendOp::Sxth => ((val as i16) as i64) as u64,
                    ExtendOp::Sxtw => ((val as i32) as i64) as u64,
                    ExtendOp::Sxtx => val,
                };
                extended << shift
            }
        }
    }

    /// Compute effective address
    fn compute_address(&self, ctx: &SmirContext, addr: &Address) -> GuestAddr {
        match addr {
            Address::Direct(r) => ctx.read_vreg(*r),
            Address::BaseOffset { base, offset, .. } => {
                (ctx.read_vreg(*base) as i64 + offset) as u64
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                ..
            } => {
                let base_val = base.map(|b| ctx.read_vreg(b)).unwrap_or(0);
                let index_val = ctx.read_vreg(*index);
                (base_val as i64 + (index_val as i64 * *scale as i64) + *disp as i64) as u64
            }
            Address::PcRel { offset, base, .. } => {
                let base_pc = base.unwrap_or(ctx.pc);
                (base_pc as i64 + offset) as u64
            }
            Address::GpRel { offset } => {
                let gp = match &ctx.arch_regs {
                    ArchRegState::Hexagon(hex) => hex.gp as u64,
                    _ => 0,
                };
                (gp as i64 + *offset as i64) as u64
            }
            Address::Absolute(a) => *a,
        }
    }

    /// Load from memory
    fn load_memory(
        &self,
        memory: &mut dyn SmirMemory,
        addr: GuestAddr,
        width: MemWidth,
        sign: SignExtend,
    ) -> Result<u64, MemoryError> {
        let mut buf = [0u8; 8];
        let size = width.bytes() as usize;
        memory.read(addr, &mut buf[..size])?;

        let raw = u64::from_le_bytes(buf);

        Ok(match sign {
            SignExtend::Zero => {
                if size >= 8 {
                    raw
                } else {
                    raw & ((1u64 << (size * 8)) - 1)
                }
            }
            SignExtend::Sign => {
                if size >= 8 {
                    raw
                } else {
                    let shift = 64 - size * 8;
                    ((raw as i64) << shift >> shift) as u64
                }
            }
        })
    }

    /// Store to memory
    fn store_memory(
        &self,
        memory: &mut dyn SmirMemory,
        addr: GuestAddr,
        value: u64,
        width: MemWidth,
    ) -> Result<(), MemoryError> {
        let bytes = value.to_le_bytes();
        let size = width.bytes() as usize;
        memory.write(addr, &bytes[..size])
    }

    /// Sign extend a value
    fn sign_extend(&self, val: u64, width: OpWidth) -> u64 {
        let sign_bit = width.sign_bit();
        if (val & sign_bit) != 0 {
            val | !width.mask()
        } else {
            val
        }
    }

    /// Read FP register as f64
    fn read_fp(&self, ctx: &SmirContext, vreg: VReg, precision: FpPrecision) -> f64 {
        let bits = ctx.read_vreg(vreg);
        match precision {
            FpPrecision::F16 => {
                // Simplified: treat as f32
                f32::from_bits(bits as u32) as f64
            }
            FpPrecision::F32 => f32::from_bits(bits as u32) as f64,
            FpPrecision::F64 => f64::from_bits(bits),
            FpPrecision::F80 => f64::from_bits(bits), // Simplified
        }
    }

    /// Write FP register from f64
    fn write_fp(&self, ctx: &mut SmirContext, vreg: VReg, value: f64, precision: FpPrecision) {
        let bits = match precision {
            FpPrecision::F16 | FpPrecision::F32 => (value as f32).to_bits() as u64,
            FpPrecision::F64 | FpPrecision::F80 => value.to_bits(),
        };
        ctx.write_vreg(vreg, bits);
    }

    fn get_lane(value: &VecValue, lane: u8, elem_bits: u32) -> u64 {
        let bit_index = lane as u32 * elem_bits;
        let word_index = (bit_index / 64) as usize;
        let bit_offset = bit_index % 64;

        if elem_bits == 64 {
            return value[word_index];
        }

        let mask = (1u64 << elem_bits) - 1;
        if bit_offset + elem_bits <= 64 {
            (value[word_index] >> bit_offset) & mask
        } else {
            let low = value[word_index] >> bit_offset;
            let high = value[word_index + 1] << (64 - bit_offset);
            (low | high) & mask
        }
    }

    fn set_lane(value: &mut VecValue, lane: u8, elem_bits: u32, bits: u64) {
        let bit_index = lane as u32 * elem_bits;
        let word_index = (bit_index / 64) as usize;
        let bit_offset = bit_index % 64;

        if elem_bits == 64 {
            value[word_index] = bits;
            return;
        }

        let mask = (1u64 << elem_bits) - 1;
        let bits = bits & mask;
        if bit_offset + elem_bits <= 64 {
            let clear = !(mask << bit_offset);
            value[word_index] = (value[word_index] & clear) | (bits << bit_offset);
        } else {
            let low_bits = 64 - bit_offset;
            let low_mask = (1u64 << low_bits) - 1;
            let high_bits = elem_bits - low_bits;
            let high_mask = (1u64 << high_bits) - 1;

            value[word_index] =
                (value[word_index] & !(low_mask << bit_offset)) | ((bits & low_mask) << bit_offset);
            value[word_index + 1] = (value[word_index + 1] & !high_mask) | (bits >> low_bits);
        }
    }

    /// Vector binary operation helper (integer)
    /// Apply a `VLaneOp` to two zero-extended `elem_bits`-wide lane values,
    /// returning the result masked to `elem_bits`. Signed ops sign-extend the
    /// inputs first; saturating ops clamp to the element's signed/unsigned range.
    fn apply_lane_op(op: VLaneOp, a: u64, b: u64, elem_bits: u32, signed: bool) -> u64 {
        let mask: u64 = if elem_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << elem_bits) - 1
        };
        // Sign-extend a zero-extended `elem_bits` value to i64.
        let sx = |v: u64| -> i64 {
            if elem_bits >= 64 {
                v as i64
            } else {
                let shift = 64 - elem_bits;
                ((v << shift) as i64) >> shift
            }
        };
        let smin: i64 = if elem_bits >= 64 {
            i64::MIN
        } else {
            -(1i64 << (elem_bits - 1))
        };
        let smax: i64 = if elem_bits >= 64 {
            i64::MAX
        } else {
            (1i64 << (elem_bits - 1)) - 1
        };
        let umax: u64 = mask;
        let res: u64 = match op {
            VLaneOp::Add => a.wrapping_add(b),
            VLaneOp::Sub => a.wrapping_sub(b),
            VLaneOp::Mul => a.wrapping_mul(b),
            VLaneOp::And => a & b,
            VLaneOp::Or => a | b,
            VLaneOp::Xor => a ^ b,
            VLaneOp::AndNot => a & !b,
            VLaneOp::OrNot => a | !b,
            VLaneOp::Not => !a,
            VLaneOp::Min => {
                if signed {
                    sx(a).min(sx(b)) as u64
                } else {
                    (a & mask).min(b & mask)
                }
            }
            VLaneOp::Max => {
                if signed {
                    sx(a).max(sx(b)) as u64
                } else {
                    (a & mask).max(b & mask)
                }
            }
            VLaneOp::AddSat => {
                if signed {
                    (sx(a) as i128 + sx(b) as i128).clamp(smin as i128, smax as i128) as u64
                } else {
                    ((a & mask) as u128 + (b & mask) as u128).min(umax as u128) as u64
                }
            }
            VLaneOp::SubSat => {
                if signed {
                    (sx(a) as i128 - sx(b) as i128).clamp(smin as i128, smax as i128) as u64
                } else {
                    (a & mask).saturating_sub(b & mask)
                }
            }
            VLaneOp::Avg => {
                if signed {
                    ((sx(a) as i128 + sx(b) as i128) >> 1) as u64
                } else {
                    (((a & mask) as u128 + (b & mask) as u128) >> 1) as u64
                }
            }
            VLaneOp::AvgRnd => {
                if signed {
                    ((sx(a) as i128 + sx(b) as i128 + 1) >> 1) as u64
                } else {
                    (((a & mask) as u128 + (b & mask) as u128 + 1) >> 1) as u64
                }
            }
            VLaneOp::AbsDiff => {
                if signed {
                    (sx(a) as i128 - sx(b) as i128).unsigned_abs() as u64
                } else {
                    let (x, y) = (a & mask, b & mask);
                    if x >= y {
                        x - y
                    } else {
                        y - x
                    }
                }
            }
        };
        res & mask
    }

    fn vec_binary_op<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        op: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        let a = Self::read_vec(ctx, src1);
        let b = Self::read_vec(ctx, src2);

        let elem_bits = elem.bytes() * 8;
        let mut result = [0u64; 16];

        for lane in 0..lanes {
            let a_elem = Self::get_lane(&a, lane, elem_bits);
            let b_elem = Self::get_lane(&b, lane, elem_bits);
            let res_elem = op(a_elem, b_elem);
            Self::set_lane(&mut result, lane, elem_bits, res_elem);
        }

        Self::write_vec(ctx, dst, result);
    }

    fn vec_binary_op_f32<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        lanes: u8,
        op: F,
    ) where
        F: Fn(f32, f32) -> f32,
    {
        let a = Self::read_vec(ctx, src1);
        let b = Self::read_vec(ctx, src2);
        let mut result = [0u64; 16];

        for lane in 0..lanes {
            let a_bits = Self::get_lane(&a, lane, 32) as u32;
            let b_bits = Self::get_lane(&b, lane, 32) as u32;
            let res = op(f32::from_bits(a_bits), f32::from_bits(b_bits));
            Self::set_lane(&mut result, lane, 32, res.to_bits() as u64);
        }

        Self::write_vec(ctx, dst, result);
    }

    fn vec_binary_op_f64<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        lanes: u8,
        op: F,
    ) where
        F: Fn(f64, f64) -> f64,
    {
        let a = Self::read_vec(ctx, src1);
        let b = Self::read_vec(ctx, src2);
        let mut result = [0u64; 16];

        for lane in 0..lanes {
            let a_bits = Self::get_lane(&a, lane, 64);
            let b_bits = Self::get_lane(&b, lane, 64);
            let res = op(f64::from_bits(a_bits), f64::from_bits(b_bits));
            Self::set_lane(&mut result, lane, 64, res.to_bits());
        }

        Self::write_vec(ctx, dst, result);
    }
}

impl Default for SmirInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::flags::FlagUpdate;
    use crate::smir::ir::FunctionBuilder;
    use crate::smir::memory::FlatMemory;

    #[test]
    fn test_basic_arithmetic() {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x1000);
        let mut interp = SmirInterpreter::new();

        // Build a simple function: v0 = 10 + 5
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        let v0 = builder.alloc_vreg();
        let v1 = builder.alloc_vreg();
        let v2 = builder.alloc_vreg();

        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: v0,
                src: SrcOperand::Imm(10),
                width: OpWidth::W64,
            },
        );

        builder.push_op(
            0x1004,
            OpKind::Mov {
                dst: v1,
                src: SrcOperand::Imm(5),
                width: OpWidth::W64,
            },
        );

        builder.push_op(
            0x1008,
            OpKind::Add {
                dst: v2,
                src1: v0,
                src2: SrcOperand::Reg(v1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );

        builder.set_terminator(Terminator::Trap {
            kind: TrapKind::Halt,
        });

        let func = builder.finish();
        let block = func.blocks[0].clone();

        interp.add_block(0x1000, block);
        ctx.pc = 0x1000;

        let exit = interp.run(&mut ctx, &mut memory);

        assert!(matches!(exit, ExitReason::Halt));
        assert_eq!(ctx.read_vreg(v2), 15);
    }

    #[test]
    fn test_memory_operations() {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x2000);
        let mut interp = SmirInterpreter::new();

        // Build: store 42 to [0x1000], load it back
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        let v0 = builder.alloc_vreg();
        let v1 = builder.alloc_vreg();

        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: v0,
                src: SrcOperand::Imm(42),
                width: OpWidth::W64,
            },
        );

        builder.push_op(
            0x1004,
            OpKind::Store {
                src: v0,
                addr: Address::Absolute(0x1800),
                width: MemWidth::B8,
            },
        );

        builder.push_op(
            0x1008,
            OpKind::Load {
                dst: v1,
                addr: Address::Absolute(0x1800),
                width: MemWidth::B8,
                sign: SignExtend::Zero,
            },
        );

        builder.set_terminator(Terminator::Trap {
            kind: TrapKind::Halt,
        });

        let func = builder.finish();
        let block = func.blocks[0].clone();

        interp.add_block(0x1000, block);
        ctx.pc = 0x1000;

        let exit = interp.run(&mut ctx, &mut memory);

        assert!(matches!(exit, ExitReason::Halt));
        assert_eq!(ctx.read_vreg(v1), 42);
    }

    #[test]
    fn test_conditional_branch() {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x1000);
        let mut interp = SmirInterpreter::new();

        // Build: if (1) goto taken else goto not_taken
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        let v_cond = builder.alloc_vreg();
        let v_result = builder.alloc_vreg();

        let taken = builder.create_block(0x1100);
        let not_taken = builder.create_block(0x1200);

        // Entry block
        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: v_cond,
                src: SrcOperand::Imm(1),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::CondBranch {
            cond: v_cond,
            true_target: taken,
            false_target: not_taken,
        });

        // Taken block
        builder.switch_to_block(taken);
        builder.push_op(
            0x1100,
            OpKind::Mov {
                dst: v_result,
                src: SrcOperand::Imm(100),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Trap {
            kind: TrapKind::Halt,
        });

        // Not taken block
        builder.switch_to_block(not_taken);
        builder.push_op(
            0x1200,
            OpKind::Mov {
                dst: v_result,
                src: SrcOperand::Imm(200),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Trap {
            kind: TrapKind::Halt,
        });

        let func = builder.finish();

        for block in &func.blocks {
            interp.add_block(block.guest_pc, block.clone());
        }

        ctx.pc = 0x1000;
        let exit = interp.run(&mut ctx, &mut memory);

        assert!(matches!(exit, ExitReason::Halt));
        assert_eq!(ctx.read_vreg(v_result), 100);
    }

    #[test]
    fn test_apply_lane_op_byte() {
        use VLaneOp::*;
        let f = SmirInterpreter::apply_lane_op;
        // wrapping add/sub/mul (signedness-agnostic)
        assert_eq!(f(Add, 0xFF, 0x02, 8, false), 0x01);
        assert_eq!(f(Sub, 0x01, 0x02, 8, false), 0xFF);
        assert_eq!(f(Mul, 0x10, 0x10, 8, false), 0x00); // 256 & 0xFF
        // bitwise
        assert_eq!(f(And, 0xF0, 0x3C, 8, false), 0x30);
        assert_eq!(f(Or, 0xF0, 0x0F, 8, false), 0xFF);
        assert_eq!(f(Xor, 0xFF, 0x0F, 8, false), 0xF0);
        assert_eq!(f(AndNot, 0xF0, 0x0F, 8, false), 0xF0);
        // min/max signed vs unsigned: 0xFF = -1 (signed) / 255 (unsigned)
        assert_eq!(f(Max, 0xFF, 0x01, 8, false), 0xFF); // umax(255,1)
        assert_eq!(f(Max, 0xFF, 0x01, 8, true), 0x01); // smax(-1,1)
        assert_eq!(f(Min, 0xFF, 0x01, 8, false), 0x01); // umin(255,1)
        assert_eq!(f(Min, 0xFF, 0x01, 8, true), 0xFF); // smin(-1,1)
        // saturating
        assert_eq!(f(AddSat, 0xFF, 0x10, 8, false), 0xFF); // u8 clamp
        assert_eq!(f(AddSat, 0x7F, 0x01, 8, true), 0x7F); // i8 +overflow -> 127
        assert_eq!(f(SubSat, 0x01, 0x02, 8, false), 0x00); // u8 underflow -> 0
        assert_eq!(f(SubSat, 0x80, 0x01, 8, true), 0x80); // i8 -128-1 -> -128
        // average (truncating vs rounding)
        assert_eq!(f(Avg, 0xFF, 0x01, 8, false), 0x80); // (255+1)/2
        assert_eq!(f(Avg, 0x02, 0x03, 8, false), 0x02); // (5)/2 trunc
        assert_eq!(f(AvgRnd, 0x02, 0x03, 8, false), 0x03); // (5+1)/2
        // absolute difference
        assert_eq!(f(AbsDiff, 0x01, 0x03, 8, false), 0x02);
        assert_eq!(f(AbsDiff, 0xFF, 0x01, 8, true), 0x02); // |-1 - 1|
    }

    #[test]
    fn test_apply_lane_op_word() {
        use VLaneOp::*;
        let f = SmirInterpreter::apply_lane_op;
        assert_eq!(f(Add, 0xFFFF_FFFF, 1, 32, false), 0);
        assert_eq!(f(Max, 0xFFFF_FFFF, 1, 32, true), 1); // smax(-1,1)
        assert_eq!(f(Max, 0xFFFF_FFFF, 1, 32, false), 0xFFFF_FFFF); // umax
        assert_eq!(f(AddSat, 0x7FFF_FFFF, 1, 32, true), 0x7FFF_FFFF);
        assert_eq!(f(SubSat, 0x8000_0000, 1, 32, true), 0x8000_0000);
        assert_eq!(f(Avg, 0xFFFF_FFFF, 1, 32, false), 0x8000_0000);
    }

    #[test]
    fn test_vlane_hexagon_vreg_end_to_end() {
        // VLane over a full 128-byte HVX vector: V2.b = vadd(V0.b, V1.b).
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, [0x0101_0101_0101_0101u64; 16]); // every byte = 1
            hex.set_v(1, [0x0202_0202_0202_0202u64; 16]); // every byte = 2
        }
        let v2 = VReg::Arch(ArchReg::Hexagon(HexagonReg::V(2)));
        let v0 = VReg::Arch(ArchReg::Hexagon(HexagonReg::V(0)));
        let v1 = VReg::Arch(ArchReg::Hexagon(HexagonReg::V(1)));
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::VLane {
                    dst: v2,
                    src1: v0,
                    src2: v1,
                    elem: VecElementType::I8,
                    lanes: 128,
                    op: VLaneOp::Add,
                    signed: false,
                },
                x86_hint: None,
            }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &block);
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            assert_eq!(hex.get_v(2), [0x0303_0303_0303_0303u64; 16]); // every byte = 3
        } else {
            panic!("not hexagon");
        }
    }

    fn run_widenmul(
        v0: [u64; 16],
        v1: [u64; 16],
        src_elem: VecElementType,
        signed1: bool,
        signed2: bool,
    ) -> ([u64; 16], [u64; 16]) {
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, v0);
            hex.set_v(1, v1);
        }
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::VWidenMul {
                    dst_lo: mkv(2),
                    dst_hi: mkv(3),
                    src1: mkv(0),
                    src2: mkv(1),
                    src_elem,
                    signed1,
                    signed2,
                    acc: false,
                },
                x86_hint: None,
            }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &block);
        match &ctx.arch_regs {
            ArchRegState::Hexagon(hex) => (hex.get_v(2), hex.get_v(3)),
            _ => panic!("not hexagon"),
        }
    }

    #[test]
    fn test_vwidenmul_byte_layout() {
        // V0 bytes = [3,7,3,7,...], V1 = [5,2,5,2,...].
        // lo.h[i] = even_byte products = 3*5 = 15; hi.h[i] = odd = 7*2 = 14.
        let v0 = [0x0703_0703_0703_0703u64; 16];
        let v1 = [0x0205_0205_0205_0205u64; 16];
        let (lo, hi) = run_widenmul(v0, v1, VecElementType::I8, true, true);
        assert_eq!(lo, [0x000F_000F_000F_000Fu64; 16]); // 15 per halfword
        assert_eq!(hi, [0x000E_000E_000E_000Eu64; 16]); // 14 per halfword
    }

    #[test]
    fn test_vwidenmul_signedness() {
        // Every byte of V0 = 0xFF, V1 = 0x02.
        let v0 = [0xFFFF_FFFF_FFFF_FFFFu64; 16];
        let v1 = [0x0202_0202_0202_0202u64; 16];
        // signed*signed: (-1)*2 = -2 = 0xFFFE per halfword.
        let (lo, _hi) = run_widenmul(v0, v1, VecElementType::I8, true, true);
        assert_eq!(lo, [0xFFFE_FFFE_FFFE_FFFEu64; 16]);
        // unsigned*unsigned: 255*2 = 510 = 0x01FE per halfword.
        let (lo_u, _hi) = run_widenmul(v0, v1, VecElementType::I8, false, false);
        assert_eq!(lo_u, [0x01FE_01FE_01FE_01FEu64; 16]);
    }

    #[test]
    fn test_vwidenmul_half_to_word() {
        // half*half -> word pair. V0 half = 0x0003, V1 half = 0x0005 -> 15.
        let v0 = [0x0003_0003_0003_0003u64; 16];
        let v1 = [0x0005_0005_0005_0005u64; 16];
        let (lo, hi) = run_widenmul(v0, v1, VecElementType::I16, true, true);
        assert_eq!(lo, [0x0000_000F_0000_000Fu64; 16]); // word = 15
        assert_eq!(hi, [0x0000_000F_0000_000Fu64; 16]);
    }

    #[test]
    fn test_vreducemul_byte4_to_word() {
        // 4-tap byte dot product -> word. Every byte of V0 = 2, V1 = 3.
        // Each word lane = sum of 4 products = 4 * (2*3) = 24 = 0x18.
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, [0x0202_0202_0202_0202u64; 16]);
            hex.set_v(1, [0x0303_0303_0303_0303u64; 16]);
        }
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let mk = |op| SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp { id: OpId(0), guest_pc: 0x1000, kind: op, x86_hint: None }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(
            &mut ctx,
            &mut memory,
            &mk(OpKind::VReduceMul {
                dst: mkv(2),
                src1: mkv(0),
                src2: mkv(1),
                src1_elem: VecElementType::I8,
                src2_elem: VecElementType::I8,
                out_elem: VecElementType::I32,
                taps: 4,
                sat: false,
                signed1: false,
                signed2: false,
                acc: false,
            }),
        );
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            assert_eq!(hex.get_v(2), [0x0000_0018_0000_0018u64; 16]); // word = 24
        }
        // Accumulate: dst already holds 24 per word; +24 -> 48 = 0x30.
        interp.execute_block(
            &mut ctx,
            &mut memory,
            &mk(OpKind::VReduceMul {
                dst: mkv(2),
                src1: mkv(0),
                src2: mkv(1),
                src1_elem: VecElementType::I8,
                src2_elem: VecElementType::I8,
                out_elem: VecElementType::I32,
                taps: 4,
                sat: false,
                signed1: false,
                signed2: false,
                acc: true,
            }),
        );
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            assert_eq!(hex.get_v(2), [0x0000_0030_0000_0030u64; 16]); // word = 48
        }
    }

    #[test]
    fn test_vmulevenwiden() {
        // vmpyuhe: out.uw[i] = Vu.uh[2i] * Vv.uh[2i]. V0 even halfwords = 3, V1 even = 5 -> 15.
        // V0 word = 0x0007_0003 (uh[2i]=3, uh[2i+1]=7); V1 word = 0x0009_0005 (uh[2i]=5).
        let v0 = [0x0007_0003_0007_0003u64; 16];
        let v1 = [0x0009_0005_0009_0005u64; 16];
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let out = run_vec2(
            v0,
            v1,
            OpKind::VMulEvenWiden {
                dst: mkv(2),
                src1: mkv(0),
                src2: mkv(1),
                src_elem: VecElementType::I16,
                signed1: false,
                signed2: false,
                acc: false,
            },
        );
        // each word = even_uh(3) * even_uh(5) = 15 = 0x0000000F.
        assert_eq!(out, [0x0000_000F_0000_000Fu64; 16]);
    }

    #[test]
    fn test_vreducemul_signed() {
        // signed byte dot product: V0 byte = 0xFF (-1), V1 byte = 2.
        // Each word = 4 * (-1 * 2) = -8 = 0xFFFFFFF8.
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, [0xFFFF_FFFF_FFFF_FFFFu64; 16]);
            hex.set_v(1, [0x0202_0202_0202_0202u64; 16]);
        }
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::VReduceMul {
                    dst: mkv(2),
                    src1: mkv(0),
                    src2: mkv(1),
                    src1_elem: VecElementType::I8,
                    src2_elem: VecElementType::I8,
                    out_elem: VecElementType::I32,
                    taps: 4,
                    sat: false,
                    signed1: true,
                    signed2: true,
                    acc: false,
                },
                x86_hint: None,
            }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &block);
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            assert_eq!(hex.get_v(2), [0xFFFF_FFF8_FFFF_FFF8u64; 16]); // word = -8
        }
    }

    fn run_widenext(
        v0: [u64; 16],
        src_elem: VecElementType,
        signed: bool,
        interleave: bool,
    ) -> ([u64; 16], [u64; 16]) {
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, v0);
        }
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::VWidenExt {
                    dst_lo: mkv(2),
                    dst_hi: mkv(3),
                    src: mkv(0),
                    src_elem,
                    signed,
                    interleave,
                },
                x86_hint: None,
            }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &block);
        match &ctx.arch_regs {
            ArchRegState::Hexagon(hex) => (hex.get_v(2), hex.get_v(3)),
            _ => panic!("not hexagon"),
        }
    }

    #[test]
    fn test_vwidenext_interleave_zero() {
        // vzb: every byte = 0xAB. Interleaved zero-extend byte->half.
        // lo.h[i] = ZE(byte 2i) = 0x00AB; hi.h[i] = ZE(byte 2i+1) = 0x00AB.
        let (lo, hi) = run_widenext([0xABAB_ABAB_ABAB_ABABu64; 16], VecElementType::I8, false, true);
        assert_eq!(lo, [0x00AB_00AB_00AB_00ABu64; 16]);
        assert_eq!(hi, [0x00AB_00AB_00AB_00ABu64; 16]);
    }

    #[test]
    fn test_vwidenext_interleave_sign() {
        // vsb: every byte = 0x80 (-128). Sign-extend byte->half = 0xFF80.
        let (lo, hi) = run_widenext([0x8080_8080_8080_8080u64; 16], VecElementType::I8, true, true);
        assert_eq!(lo, [0xFF80_FF80_FF80_FF80u64; 16]);
        assert_eq!(hi, [0xFF80_FF80_FF80_FF80u64; 16]);
    }

    #[test]
    fn test_vwidenext_sequential() {
        // vunpackub: sequential. lo.h[i] = ZE(byte i), hi.h[i] = ZE(byte i+64).
        // All bytes = 0x07 -> every output halfword = 0x0007.
        let (lo, hi) = run_widenext([0x0707_0707_0707_0707u64; 16], VecElementType::I8, false, false);
        assert_eq!(lo, [0x0007_0007_0007_0007u64; 16]);
        assert_eq!(hi, [0x0007_0007_0007_0007u64; 16]);
    }

    fn run_vec2(v0: [u64; 16], v1: [u64; 16], op: OpKind) -> [u64; 16] {
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, v0);
            hex.set_v(1, v1);
        }
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp { id: OpId(0), guest_pc: 0x1000, kind: op, x86_hint: None }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &block);
        match &ctx.arch_regs {
            ArchRegState::Hexagon(hex) => hex.get_v(2),
            _ => panic!("not hexagon"),
        }
    }

    #[test]
    fn test_vpack_even_byte() {
        // vpackeb: out.b[i] = V1(=Vv).b[2i] (low half), out.b[i+64] = V0(=Vu).b[2i] (high half).
        // V0 halfwords = 0xAA11 (byte0=0x11), V1 halfwords = 0xBB22 (byte0=0x22).
        // even byte of every half: V1 -> 0x22, V0 -> 0x11.
        let v0 = [0xAA11_AA11_AA11_AA11u64; 16];
        let v1 = [0xBB22_BB22_BB22_BB22u64; 16];
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let out = run_vec2(
            v0,
            v1,
            OpKind::VPack { dst: mkv(2), src1: mkv(0), src2: mkv(1), elem: VecElementType::I8, odd: false },
        );
        // low 64 bytes (lanes 0..7 u64) = 0x22 everywhere; high 64 bytes = 0x11.
        assert_eq!(out[0], 0x2222_2222_2222_2222u64);
        assert_eq!(out[7], 0x2222_2222_2222_2222u64);
        assert_eq!(out[8], 0x1111_1111_1111_1111u64);
        assert_eq!(out[15], 0x1111_1111_1111_1111u64);
    }

    #[test]
    fn test_vpacksat_hub() {
        // vpackhub_sat: saturate signed halfword -> unsigned byte [0,255].
        // V1 halfword = 0x0140 (320 -> clamps to 255=0xFF); V0 halfword = 0xFF00 (-256 -> 0).
        let v0 = [0xFF00_FF00_FF00_FF00u64; 16];
        let v1 = [0x0140_0140_0140_0140u64; 16];
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let out = run_vec2(
            v0,
            v1,
            OpKind::VPackSat {
                dst: mkv(2),
                src1: mkv(0),
                src2: mkv(1),
                src_elem: VecElementType::I16,
                to_unsigned: true,
            },
        );
        // low half = sat(V1 halfwords) = 0xFF; high half = sat(V0 halfwords) = 0x00.
        assert_eq!(out[0], 0xFFFF_FFFF_FFFF_FFFFu64);
        assert_eq!(out[7], 0xFFFF_FFFF_FFFF_FFFFu64);
        assert_eq!(out[8], 0x0000_0000_0000_0000u64);
        assert_eq!(out[15], 0x0000_0000_0000_0000u64);
    }

    #[test]
    fn test_vcmptoq_byte_eq() {
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        // V0 byte0 = 0x01, rest 0; V1 all 0. veqb -> byte0 differs (Q bit0=0), all others equal (1).
        let mut v0 = [0u64; 16];
        v0[0] = 0x01;
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, v0);
            hex.set_v(1, [0u64; 16]);
        }
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::VCmpToQ {
                    dst: VReg::Arch(ArchReg::Hexagon(HexagonReg::Q(0))),
                    src1: mkv(0),
                    src2: mkv(1),
                    cond: VecCmpCond::Eq,
                    elem: VecElementType::I8,
                    lanes: 128,
                    accumulate: None,
                },
                x86_hint: None,
            }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &block);
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            let q = hex.get_q(0);
            assert_eq!(q[0], 0xFFFF_FFFF_FFFF_FFFE); // bit0 (byte0) clear, rest set
            assert_eq!(q[1], 0xFFFF_FFFF_FFFF_FFFF); // bytes 64-127 all equal
        }
    }

    #[test]
    fn test_vmaskzero() {
        // vandvqv: Q0 byte0 bit set; src(V0)=0xAA. out.byte0=0xAA, rest 0.
        let mut q = [0u64; 16];
        q[0] = 0x1;
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, [0xAAAA_AAAA_AAAA_AAAAu64; 16]);
            hex.set_q(0, q);
        }
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let mkblock = |negate| SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::VMaskZero {
                    dst: mkv(2),
                    mask_q: VReg::Arch(ArchReg::Hexagon(HexagonReg::Q(0))),
                    src: mkv(0),
                    negate,
                },
                x86_hint: None,
            }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &mkblock(false));
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            assert_eq!(hex.get_v(2)[0], 0x0000_0000_0000_00AA); // byte0 = 0xAA, rest 0
            assert_eq!(hex.get_v(2)[1], 0);
        }
        // negate: byte0 -> 0, all other bytes -> 0xAA.
        interp.execute_block(&mut ctx, &mut memory, &mkblock(true));
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            assert_eq!(hex.get_v(2)[0], 0xAAAA_AAAA_AAAA_AA00);
            assert_eq!(hex.get_v(2)[1], 0xAAAA_AAAA_AAAA_AAAA);
        }
    }

    #[test]
    fn test_vblend_mux() {
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        // Q0 = byte0 bit set only; src_true(V0)=0xAA, src_false(V1)=0xBB.
        let mut q = [0u64; 16];
        q[0] = 0x1; // only byte 0
        if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
            hex.set_v(0, [0xAAAA_AAAA_AAAA_AAAAu64; 16]);
            hex.set_v(1, [0xBBBB_BBBB_BBBB_BBBBu64; 16]);
            hex.set_q(0, q);
        }
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::VBlend {
                    dst: mkv(2),
                    mask_q: VReg::Arch(ArchReg::Hexagon(HexagonReg::Q(0))),
                    src_true: mkv(0),
                    src_false: mkv(1),
                },
                x86_hint: None,
            }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &block);
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            // byte0 = 0xAA (Q bit set), bytes 1-7 = 0xBB.
            assert_eq!(hex.get_v(2)[0], 0xBBBB_BBBB_BBBB_BBAA);
            assert_eq!(hex.get_v(2)[1], 0xBBBB_BBBB_BBBB_BBBB);
        }
    }

    #[test]
    fn test_vshiftv_halfword() {
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let sv = |kind| OpKind::VShiftV {
            dst: mkv(2),
            src: mkv(0),
            amount: mkv(1),
            elem: VecElementType::I16,
            lanes: 64,
            kind,
        };
        // vasrhv, +2: 0x0100 >> 2 = 0x0040.
        let out = run_vec2([0x0100_0100_0100_0100u64; 16], [0x0002_0002_0002_0002u64; 16],
            sv(VShiftVKind::AshiftR));
        assert_eq!(out, [0x0040_0040_0040_0040u64; 16]);
        // vasrhv, amt=30 -> sxtn(30,5) = -2 -> arithmetic LEFT by 2: 0x0100 << 2 = 0x0400.
        let out2 = run_vec2([0x0100_0100_0100_0100u64; 16], [0x001E_001E_001E_001Eu64; 16],
            sv(VShiftVKind::AshiftR));
        assert_eq!(out2, [0x0400_0400_0400_0400u64; 16]);
        // vlsrhv, +2: logical right of 0x8000 = 0x2000 (no sign fill).
        let out3 = run_vec2([0x8000_8000_8000_8000u64; 16], [0x0002_0002_0002_0002u64; 16],
            sv(VShiftVKind::LshiftR));
        assert_eq!(out3, [0x2000_2000_2000_2000u64; 16]);
    }

    #[test]
    fn test_vmulshiftsat_vmpyhvsrs() {
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let op = |dst, s1, s2| OpKind::VMulShiftSat {
            dst,
            src1: s1,
            src2: s2,
            src_elem: VecElementType::I16,
            signed1: true,
            signed2: true,
            shift_left: 1,
            round: true,
            sat_bits: 32,
            out_shift: 16,
        };
        // non-saturating: 0x4000*0x4000<<1 +0x8000 = 0x20008000; >>16 = 0x2000.
        let out = run_vec2([0x4000_4000_4000_4000u64; 16], [0x4000_4000_4000_4000u64; 16],
            op(mkv(2), mkv(0), mkv(1)));
        assert_eq!(out, [0x2000_2000_2000_2000u64; 16]);
        // saturating: (-32768)^2<<1 +0x8000 overflows i32 -> clamp 0x7FFFFFFF; >>16 = 0x7FFF.
        let out2 = run_vec2([0x8000_8000_8000_8000u64; 16], [0x8000_8000_8000_8000u64; 16],
            op(mkv(2), mkv(0), mkv(1)));
        assert_eq!(out2, [0x7FFF_7FFF_7FFF_7FFFu64; 16]);
    }

    #[test]
    fn test_vmulshiftsat_vmpyuhvs() {
        // unsigned 16x16, no shift/round/sat, take high 16: 0xFFFF*0xFFFF>>16 = 0xFFFE.
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let out = run_vec2(
            [0xFFFF_FFFF_FFFF_FFFFu64; 16],
            [0xFFFF_FFFF_FFFF_FFFFu64; 16],
            OpKind::VMulShiftSat {
                dst: mkv(2),
                src1: mkv(0),
                src2: mkv(1),
                src_elem: VecElementType::I16,
                signed1: false,
                signed2: false,
                shift_left: 0,
                round: false,
                sat_bits: 0,
                out_shift: 16,
            },
        );
        assert_eq!(out, [0xFFFE_FFFE_FFFE_FFFEu64; 16]);
    }

    #[test]
    fn test_valign_right_shift4() {
        // valignb shift=4: out[i] = i+4<128 ? Vv[i+4] : Vu[i+4-128].
        // Vu(V0) all 0xAA, Vv(V1) all 0xBB -> bytes 0..123 = 0xBB, 124..127 = 0xAA.
        let v0 = [0xAAAA_AAAA_AAAA_AAAAu64; 16]; // Vu
        let v1 = [0xBBBB_BBBB_BBBB_BBBBu64; 16]; // Vv
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let out = run_vec2(
            v0,
            v1,
            OpKind::VAlign {
                dst: mkv(2),
                src1: mkv(0),
                src2: mkv(1),
                amount: SrcOperand::Imm(4),
                left: false,
            },
        );
        assert_eq!(out[0], 0xBBBB_BBBB_BBBB_BBBBu64); // bytes 0-7 from Vv
        // bytes 120-123 = 0xBB (from Vv), 124-127 = 0xAA (wrapped from Vu)
        assert_eq!(out[15], 0xAAAA_AAAA_BBBB_BBBBu64);
    }

    #[test]
    fn test_valign_vror() {
        // vror = VAlign(src,src,Rt,left=false): out[i] = src[(i+amt)&127].
        // Distinguishable: V0 lane0 low byte = 0x11, all else 0. amt=127 -> rotate so
        // the byte at index 0 moves to index 1 (out[127]=src[(127+127)&127]=src[126]=0,
        // out[0]=src[127]=0, ... out[1]=src[(1+127)&127]=src[0]=0x11).
        let mut v0 = [0u64; 16];
        v0[0] = 0x11; // byte 0 = 0x11
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let out = run_vec2(
            v0,
            v0,
            OpKind::VAlign {
                dst: mkv(2),
                src1: mkv(0),
                src2: mkv(0),
                amount: SrcOperand::Imm(127),
                left: false,
            },
        );
        // out byte 1 = src byte 0 = 0x11; everything else 0.
        assert_eq!(out[0], 0x0000_0000_0000_1100u64); // byte1 = 0x11
        for w in &out[1..] {
            assert_eq!(*w, 0);
        }
    }

    #[test]
    fn test_vshuffle2_byte_roundtrip() {
        // shuffle then deal must be identity. Use a distinguishable per-byte pattern.
        let mut v0 = [0u64; 16];
        for (i, w) in v0.iter_mut().enumerate() {
            // each byte = its global index (mod 256)
            let mut x = 0u64;
            for b in 0..8 {
                x |= (((i * 8 + b) as u64) & 0xff) << (b * 8);
            }
            *w = x;
        }
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        // shuffle V0 -> V2
        let shuffled = run_vec2(
            v0,
            [0u64; 16],
            OpKind::VShuffle2 { dst: mkv(2), src: mkv(0), elem: VecElementType::I8, deal: false },
        );
        // deal the shuffled value -> should recover v0
        let dealt = run_vec2(
            shuffled,
            [0u64; 16],
            OpKind::VShuffle2 { dst: mkv(2), src: mkv(0), elem: VecElementType::I8, deal: true },
        );
        assert_eq!(dealt, v0, "deal(shuffle(x)) must equal x");
        // explicit check: shuffle out[0]=src.b[0], out[1]=src.b[64].
        assert_eq!((shuffled[0] & 0xff) as u8, 0); // src byte 0
        assert_eq!(((shuffled[0] >> 8) & 0xff) as u8, 64); // src byte 64
    }

    #[test]
    fn test_vshuffleeo_even_byte() {
        // vshuffeb: out.b[2i] = Vv.b[2i], out.b[2i+1] = Vu.b[2i].
        // V0(=Vu) halfwords = 0x__11 (byte0=0x11), V1(=Vv) = 0x__22 (byte0=0x22).
        let v0 = [0xAA11_AA11_AA11_AA11u64; 16];
        let v1 = [0xBB22_BB22_BB22_BB22u64; 16];
        let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
        let out = run_vec2(
            v0,
            v1,
            OpKind::VShuffleEO { dst: mkv(2), src1: mkv(0), src2: mkv(1), elem: VecElementType::I8, odd: false },
        );
        // every output halfword = Vv.b0(0x22) | Vu.b0(0x11)<<8 = 0x1122.
        assert_eq!(out, [0x1122_1122_1122_1122u64; 16]);
    }

    #[test]
    fn test_vbroadcast_gpr_to_words() {
        // Splat GPR R5 = 0xDEADBEEF into every word lane of V2.
        let mut ctx = SmirContext::new_hexagon();
        let mut memory = FlatMemory::new(0x1000);
        let interp = SmirInterpreter::new();
        ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::R(5)), 0xDEAD_BEEF);
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops: vec![SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::VBroadcast {
                    dst: VReg::Arch(ArchReg::Hexagon(HexagonReg::V(2))),
                    scalar: VReg::Arch(ArchReg::Hexagon(HexagonReg::R(5))),
                    elem: VecElementType::I32,
                    lanes: 32,
                },
                x86_hint: None,
            }],
            terminator: Terminator::Trap { kind: TrapKind::Halt },
            exec_count: 0,
        };
        interp.execute_block(&mut ctx, &mut memory, &block);
        if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
            assert_eq!(hex.get_v(2), [0xDEAD_BEEF_DEAD_BEEFu64; 16]);
        }
    }
}
