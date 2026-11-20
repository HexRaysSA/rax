//! Memory op execution

use crate::smir::interpret::*;
use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext, VecValue};
use crate::smir::ir::flags::{FlagSet, FlagUpdate, LazyFlagOp, LazyFlags};
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::ops::{
    HexFpOp, HexFpRecipKind, OpKind, RvVectorState, SmirOp, X86AdxKind, X86BlsKind,
    X86CacheControlKind, X86CountKind, X86OpHint, X86ThreeDNowKind, X86X87ArithmeticDestination,
    X86X87ArithmeticSource, X86X87CompareSource, X86X87Constant, X86X87ControlKind, X86X87DataKind,
    X86X87EnvWidth, X86X87FloatWidth, X86X87IntWidth, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};
use std::cmp::Ordering;
use std::collections::HashMap;

impl SmirInterpreter {
    pub(crate) fn execute_op_memory(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        op: &SmirOp,
    ) -> Result<(), MemoryError> {
        let x86_hint = op.x86_hint;
        match &op.kind {
            // ==================================================================
            // MEMORY OPERATIONS
            // ==================================================================
            OpKind::CheckMemoryAlignment {
                addr,
                width,
                access,
                cond,
            } => {
                if cond.is_none_or(|predicate| ctx.read_vreg(predicate) & 1 != 0) {
                    let address = self.compute_address(ctx, addr);
                    let alignment = width.bytes();
                    if address % u64::from(alignment) != 0 {
                        ctx.pc = op.guest_pc;
                        ctx.arch_regs.set_pc(op.guest_pc);
                        ctx.request_exit(ExitReason::AlignmentFault {
                            pc: op.guest_pc,
                            address,
                            alignment,
                            access: *access,
                        });
                    }
                }
            }

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

            // Predicated load (Hexagon `if (Pu) Rd = memX(...)`). COMMITS only
            // when `cond`'s bit 0 is set: then `dst = load(EA)`. When the
            // predicate is FALSE the load CANCELS — `dst` is left UNCHANGED and
            // NO memory access is performed (so a false predicate never faults,
            // matching the sem's `return Ok(None)`).
            OpKind::PredLoad {
                dst,
                cond,
                addr,
                width,
                signed,
            } => {
                if (ctx.read_vreg(*cond) & 1) != 0 {
                    let effective_addr = self.compute_address(ctx, addr);
                    let val = self.load_memory(memory, effective_addr, *width, *signed)?;
                    let op_width = width.to_op_width().unwrap_or(OpWidth::W64);
                    if *signed == SignExtend::Zero {
                        Self::write_x86_partial(ctx, *dst, val, op_width);
                    } else {
                        ctx.write_vreg(*dst, val);
                    }
                }
            }

            // Predicated store (Hexagon `if (Pu) memX(...) = Rt`). COMMITS only
            // when `cond`'s bit 0 is set: then `store(EA, src)`. When the
            // predicate is FALSE the store CANCELS — NO memory access is
            // performed.
            OpKind::PredStore {
                src,
                cond,
                addr,
                width,
            } => {
                if (ctx.read_vreg(*cond) & 1) != 0 {
                    let effective_addr = self.compute_address(ctx, addr);
                    let val = self.read_src_operand(ctx, src);
                    self.store_memory(memory, effective_addr, val, *width)?;
                }
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

            OpKind::X86String {
                kind,
                rep,
                accumulator,
                src_index,
                dst_index,
                count,
                src_segment,
                width,
                address_width,
            } => {
                let addr_mask = match address_width {
                    OpWidth::W32 => u32::MAX as u64,
                    OpWidth::W64 => u64::MAX,
                    _ => {
                        return Err(MemoryError::OutOfBounds { addr: ctx.pc });
                    }
                };
                let op_width = width.to_op_width().unwrap_or(OpWidth::W64);
                let stride = width.bytes() as u64;
                ctx.flags.materialize_all();
                let forward = !ctx.flags.materialized.df;
                let segment_base = src_segment.map_or(0, |reg| ctx.read_vreg(reg));
                let repeated = *rep != crate::smir::ir::ops::X86RepMode::None;
                let mut remaining = if repeated {
                    ctx.read_vreg(*count) & addr_mask
                } else {
                    1
                };

                if repeated && remaining == 0 {
                    ctx.write_vreg(*count, 0);
                    if *address_width == OpWidth::W32 {
                        if *kind == crate::smir::ir::ops::X86StringKind::Movs {
                            ctx.write_vreg(*src_index, ctx.read_vreg(*src_index) & addr_mask);
                        }
                        if matches!(
                            kind,
                            crate::smir::ir::ops::X86StringKind::Movs
                                | crate::smir::ir::ops::X86StringKind::Stos
                        ) {
                            ctx.write_vreg(*dst_index, ctx.read_vreg(*dst_index) & addr_mask);
                        }
                    }
                }

                let mut comparison = None;
                while remaining != 0 {
                    let src_off = ctx.read_vreg(*src_index) & addr_mask;
                    let dst_off = ctx.read_vreg(*dst_index) & addr_mask;
                    let src_addr = segment_base.wrapping_add(src_off);

                    match kind {
                        crate::smir::ir::ops::X86StringKind::Movs => {
                            let value =
                                self.load_memory(memory, src_addr, *width, SignExtend::Zero)?;
                            self.store_memory(memory, dst_off, value, *width)?;
                        }
                        crate::smir::ir::ops::X86StringKind::Stos => {
                            self.store_memory(
                                memory,
                                dst_off,
                                ctx.read_vreg(*accumulator),
                                *width,
                            )?;
                        }
                        crate::smir::ir::ops::X86StringKind::Lods => {
                            let value =
                                self.load_memory(memory, src_addr, *width, SignExtend::Zero)?;
                            Self::write_gpr(ctx, *accumulator, value, op_width);
                        }
                        crate::smir::ir::ops::X86StringKind::Scas => {
                            let rhs =
                                self.load_memory(memory, dst_off, *width, SignExtend::Zero)?;
                            let lhs = ctx.read_vreg(*accumulator) & op_width.mask();
                            comparison = Some((lhs, rhs));
                        }
                        crate::smir::ir::ops::X86StringKind::Cmps => {
                            let lhs =
                                self.load_memory(memory, src_addr, *width, SignExtend::Zero)?;
                            let rhs =
                                self.load_memory(memory, dst_off, *width, SignExtend::Zero)?;
                            comparison = Some((lhs, rhs));
                        }
                    }

                    let advance = |value: u64| {
                        if forward {
                            value.wrapping_add(stride) & addr_mask
                        } else {
                            value.wrapping_sub(stride) & addr_mask
                        }
                    };
                    if matches!(
                        kind,
                        crate::smir::ir::ops::X86StringKind::Movs
                            | crate::smir::ir::ops::X86StringKind::Lods
                            | crate::smir::ir::ops::X86StringKind::Cmps
                    ) {
                        ctx.write_vreg(*src_index, advance(src_off));
                    }
                    if matches!(
                        kind,
                        crate::smir::ir::ops::X86StringKind::Movs
                            | crate::smir::ir::ops::X86StringKind::Stos
                            | crate::smir::ir::ops::X86StringKind::Scas
                            | crate::smir::ir::ops::X86StringKind::Cmps
                    ) {
                        ctx.write_vreg(*dst_index, advance(dst_off));
                    }

                    if repeated {
                        remaining = remaining.wrapping_sub(1) & addr_mask;
                        ctx.write_vreg(*count, remaining);
                    } else {
                        remaining = 0;
                    }

                    if let Some((lhs, rhs)) = comparison
                        && repeated
                    {
                        let equal = lhs == rhs;
                        if (*rep == crate::smir::ir::ops::X86RepMode::Repe && !equal)
                            || (*rep == crate::smir::ir::ops::X86RepMode::Repne && equal)
                        {
                            break;
                        }
                    }
                }
                // A later memory fault retains the completed indices and count
                // but reports the instruction's original arithmetic flags.
                if let Some((lhs, rhs)) = comparison {
                    let result = lhs.wrapping_sub(rhs) & op_width.mask();
                    ctx.flags.set_lazy_sub(lhs, rhs, result, op_width);
                }
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
                let old = if let ArchRegState::Ebpf(state) = &ctx.arch_regs {
                    memory.atomic_rmw_endian(
                        effective_addr,
                        *op,
                        operand,
                        *width,
                        *order,
                        state.config.endian,
                    )?
                } else {
                    memory.atomic_rmw(effective_addr, *op, operand, *width, *order)?
                };
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
                let (old, succ) = if let ArchRegState::Ebpf(state) = &ctx.arch_regs {
                    memory.compare_and_swap_endian(
                        effective_addr,
                        exp,
                        new,
                        *width,
                        *order,
                        order.cas_failure(),
                        state.config.endian,
                    )?
                } else {
                    memory.probe(effective_addr, width.bytes() as usize, true)?;
                    memory.compare_and_swap(
                        effective_addr,
                        exp,
                        new,
                        *width,
                        *order,
                        order.cas_failure(),
                    )?
                };
                ctx.write_vreg(*dst, old);
                ctx.write_vreg(*success, if succ { 1 } else { 0 });
            }

            OpKind::CasPair {
                dst_lo,
                dst_hi,
                success,
                addr,
                expected_lo,
                expected_hi,
                new_lo,
                new_hi,
                order,
                failure_order,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                if effective_addr & 0xf != 0 {
                    return Err(MemoryError::Alignment {
                        addr: effective_addr,
                        required: 16,
                    });
                }
                memory.probe(effective_addr, 16, true)?;
                let expected = [ctx.read_vreg(*expected_lo), ctx.read_vreg(*expected_hi)];
                let new = [ctx.read_vreg(*new_lo), ctx.read_vreg(*new_hi)];
                let (old, succ) = memory.compare_and_swap_pair(
                    effective_addr,
                    expected,
                    new,
                    *order,
                    *failure_order,
                )?;
                ctx.write_vreg(*dst_lo, old[0]);
                ctx.write_vreg(*dst_hi, old[1]);
                ctx.write_vreg(*success, u64::from(succ));
            }

            OpKind::AtomicCmpXadd {
                dst_old,
                addr,
                cmp,
                add,
                cond,
                width,
                order,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                let op_width = width.to_op_width().unwrap_or(OpWidth::W64);
                let mask = op_width.mask();
                let cmp_val = ctx.read_vreg(*cmp) & mask;
                let add_val = ctx.read_vreg(*add) & mask;
                let mut old = memory.atomic_load(effective_addr, *width, MemoryOrder::Acquire)?;

                loop {
                    let old_m = old & mask;
                    let cmp_result = old_m.wrapping_sub(cmp_val) & mask;
                    ctx.flags.set_lazy_sub(old_m, cmp_val, cmp_result, op_width);
                    let should_add = ctx.flags.eval_condition(*cond);
                    let new_val = if should_add {
                        old_m.wrapping_add(add_val) & mask
                    } else {
                        old_m
                    };

                    let (seen, succ) = memory.compare_and_swap(
                        effective_addr,
                        old_m,
                        new_val,
                        *width,
                        *order,
                        MemoryOrder::Relaxed,
                    )?;
                    if succ {
                        Self::write_gpr(ctx, *dst_old, old_m, op_width);
                        break;
                    }
                    old = seen;
                }
            }

            OpKind::LoadExclusive { dst, addr, width } => {
                let effective_addr = self.compute_address(ctx, addr);
                let val = if ctx.source_arch == SourceArch::Hexagon {
                    self.load_memory(memory, effective_addr, *width, SignExtend::Zero)?
                } else {
                    memory.load_exclusive(effective_addr, *width)?
                };
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
                let success = if ctx.source_arch == SourceArch::Hexagon {
                    let success = ctx
                        .exclusive_monitor
                        .check_exclusive(effective_addr, *width);
                    if success {
                        self.store_memory(memory, effective_addr, val, *width)?;
                    }
                    success
                } else {
                    memory.store_exclusive(effective_addr, val, *width)?
                };
                ctx.write_vreg(*status, if success { 0 } else { 1 });
                ctx.exclusive_monitor.clear();
            }

            OpKind::ClearExclusive => {
                ctx.exclusive_monitor.clear();
                if ctx.source_arch != SourceArch::Hexagon {
                    memory.clear_exclusive();
                }
            }

            OpKind::Prefetch { addr, write } => {
                let effective_addr = self.compute_address(ctx, addr);
                memory.prefetch(effective_addr, *write);
            }

            OpKind::X86CacheControl { addr, kind } => {
                let effective_addr = self.compute_address(ctx, addr);
                // Intel specifies no memory-address exceptions for CLDEMOTE;
                // it is permitted to be ignored even when the line is absent.
                // Flush/writeback operations perform an architectural address
                // access and therefore retain the explicit probe.
                if *kind != X86CacheControlKind::Cldemote {
                    memory.probe(effective_addr, 1, false)?;
                }
                memory.prefetch(effective_addr, matches!(kind, X86CacheControlKind::Clwb));
            }

            OpKind::Fence { kind } => {
                memory.fence(*kind);
            }

            _ => return self.execute_op_x86_stack_flags(ctx, memory, op),
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "memory_alignment_tests.rs"]
mod memory_alignment_tests;
