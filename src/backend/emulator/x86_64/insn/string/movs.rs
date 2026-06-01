//! Move string instructions: MOVSB, MOVSW, MOVSD, MOVSQ.

use crate::cpu::VcpuExit;
use crate::error::Result;

use super::super::super::cpu::{InsnContext, X86_64Vcpu};
use super::super::super::flags;
use super::super::super::mmu::AccessType;

/// Page size used by the MMU.
const PAGE_SIZE: u64 = 0x1000;
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// LAPIC MMIO window (mirrors the constants in mmu.rs). The bulk fast path must
/// never touch this region directly via `read_phys`/`write_phys`; those have
/// device side effects that the per-element path routes correctly, so we fall
/// back to the slow path whenever a chunk would land in this window.
const LAPIC_BASE: u64 = 0xFEE00000;
const LAPIC_SIZE: u64 = 0x1000;

#[inline(always)]
fn paddr_is_mmio(paddr: u64) -> bool {
    paddr >= LAPIC_BASE && paddr < LAPIC_BASE + LAPIC_SIZE
}

/// MOVSB (0xA4)
pub fn movsb(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    movs_common(vcpu, ctx, 1)
}

/// MOVSW/MOVSD/MOVSQ (0xA5)
pub fn movs(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    movs_common(vcpu, ctx, op_size)
}

/// Shared MOVS implementation for all operand sizes (1/2/4/8).
///
/// Tries a bulk, page-wise fast path for forward `REP MOVS`; otherwise falls
/// back to the element-by-element loop. Both paths produce identical
/// architectural state (RSI/RDI/RCX and memory) and fault behavior.
#[inline]
fn movs_common(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    op_size: u8,
) -> Result<Option<VcpuExit>> {
    let is_rep = ctx.rep_prefix.is_some();
    let delta = op_size as u64;

    // Fast path: REP-prefixed, forward (DF==0), count > 1.
    if is_rep && (vcpu.regs.rflags & flags::bits::DF) == 0 && vcpu.regs.rcx > 1 {
        movs_fast_path(vcpu, op_size)?;
        // The fast path advances RSI/RDI/RCX as far as it safely can. Any
        // remaining count (page-straddling element, code/MMIO page) is handled
        // by falling through to the slow loop below, which resumes from the
        // current register state.
    }

    // Slow path: element-by-element, bit-for-bit identical to the original loop.
    // Also serves as the tail/fallback for the fast path (RCX is already 0 when
    // the fast path fully completed, so this loop is a no-op in that case).
    let count = if is_rep { vcpu.regs.rcx } else { 1 };
    for _ in 0..count {
        if is_rep && vcpu.regs.rcx == 0 {
            break;
        }
        let val = vcpu.read_mem(vcpu.regs.rsi, op_size)?;
        vcpu.write_mem(vcpu.regs.rdi, val, op_size)?;
        if vcpu.regs.rflags & flags::bits::DF == 0 {
            vcpu.regs.rsi = vcpu.regs.rsi.wrapping_add(delta);
            vcpu.regs.rdi = vcpu.regs.rdi.wrapping_add(delta);
        } else {
            vcpu.regs.rsi = vcpu.regs.rsi.wrapping_sub(delta);
            vcpu.regs.rdi = vcpu.regs.rdi.wrapping_sub(delta);
        }
        if is_rep {
            vcpu.regs.rcx = vcpu.regs.rcx.wrapping_sub(1);
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Bulk, page-wise copy for forward `REP MOVS`.
///
/// Advances RSI/RDI/RCX by whole page-bounded chunks for as long as it is safe
/// to do so. It stops (leaving RCX > 0 for the slow loop to finish) when:
///   * the next element would straddle a page boundary, or
///   * the destination page is marked as code (SMC) or the source/destination
///     resolves to an MMIO region.
/// A page fault is propagated unchanged; because chunks are processed strictly
/// in address order, the fault fires at exactly the element the slow path would
/// fault on, and RSI/RDI/RCX reflect all fully-copied prior elements.
///
/// Preconditions (guaranteed by the caller): forward direction, RCX > 1.
fn movs_fast_path(vcpu: &mut X86_64Vcpu, op_size: u8) -> Result<()> {
    let delta = op_size as u64;
    debug_assert!(matches!(op_size, 1 | 2 | 4 | 8));

    // Scratch buffer sized for the largest possible single-page chunk.
    let mut buf = [0u8; PAGE_SIZE as usize];

    while vcpu.regs.rcx > 0 {
        let src = vcpu.regs.rsi;
        let dst = vcpu.regs.rdi;
        let src_off = src & PAGE_MASK;
        let dst_off = dst & PAGE_MASK;

        // A single element straddling a page boundary cannot be handled with a
        // single page translation - defer to the slow per-element path.
        if src_off + delta > PAGE_SIZE || dst_off + delta > PAGE_SIZE {
            return Ok(());
        }

        // Largest whole-element run staying within BOTH pages and the count.
        let src_room = (PAGE_SIZE - src_off) / delta;
        let dst_room = (PAGE_SIZE - dst_off) / delta;
        let elems = vcpu.regs.rcx.min(src_room).min(dst_room);
        debug_assert!(elems >= 1);
        let bytes = (elems * delta) as usize;

        // Overlap with forward propagation: real `REP MOVS` reads each element
        // AFTER the previous element's write, so when the destination overlaps
        // ahead of the source within the chunk the copied bytes propagate
        // (e.g. "ABCD" with dst=src+2 yields "ABAB..."). A bulk read-then-write
        // cannot reproduce that, so defer to the element-by-element path.
        let distance = dst.wrapping_sub(src);
        if distance != 0 && distance < bytes as u64 {
            return Ok(());
        }

        // Translate both pages once (also performs bounds/permission checks and
        // raises #PF at the correct element on failure).
        let src_paddr = vcpu.mmu.translate(src, AccessType::Read, &vcpu.sregs)?;
        let dst_paddr = vcpu.mmu.translate(dst, AccessType::Write, &vcpu.sregs)?;

        // Code page (SMC) or MMIO: defer the rest to the slow path so writes go
        // through the decode-cache invalidation and device emulation.
        if vcpu.mmu.is_code_page(dst) || paddr_is_mmio(dst_paddr) || paddr_is_mmio(src_paddr) {
            return Ok(());
        }

        // Bulk copy.
        vcpu.mmu.read_phys(src_paddr, &mut buf[..bytes])?;
        vcpu.mmu.write_phys(dst_paddr, &buf[..bytes])?;

        // Advance by the whole chunk.
        vcpu.regs.rsi = vcpu.regs.rsi.wrapping_add(bytes as u64);
        vcpu.regs.rdi = vcpu.regs.rdi.wrapping_add(bytes as u64);
        vcpu.regs.rcx -= elems;
    }

    Ok(())
}
