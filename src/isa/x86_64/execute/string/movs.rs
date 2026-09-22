//! Move string instructions: MOVSB, MOVSW, MOVSD, MOVSQ.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use super::super::super::mmu::AccessType;
use super::{
    StringAddressSize, address_size, advance_index, dec_count, index, normalize_count,
    normalize_index, rep_count,
};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

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

#[inline(always)]
fn forward_propagating_overlap(src: u64, dst: u64, bytes: u64) -> bool {
    let distance = dst.wrapping_sub(src);
    distance != 0 && distance < bytes
}

#[inline(always)]
fn movs_source_segment_base(vcpu: &X86_64Vcpu, segment_override: Option<u8>) -> u64 {
    if !vcpu.sregs.cs.l {
        return vcpu.get_segment_base(segment_override);
    }

    match segment_override {
        Some(0x64) => vcpu.sregs.fs.base,
        Some(0x65) => vcpu.sregs.gs.base,
        _ => 0,
    }
}

#[inline(always)]
fn movs_destination_segment_base(vcpu: &X86_64Vcpu) -> u64 {
    if vcpu.sregs.cs.l {
        0
    } else {
        vcpu.sregs.es.base
    }
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

    let addr_size = address_size(vcpu, ctx);
    // Source segment base. ES:[RDI] is NOT overridable; only the DS:[RSI] source
    // honors a segment-override prefix (FS/GS produce a non-zero base in 64-bit
    // mode).
    let src_base = movs_source_segment_base(vcpu, ctx.segment_override);

    // Fast path: REP-prefixed, forward (DF==0), count > 1. Only usable when there
    // is no source segment base and the address size is 64-bit, since the bulk
    // path translates RSI/RDI directly as full 64-bit linear addresses.
    // Destination is always ES:[RDI] (not overridable); long mode ignores ES.base.
    let dst_base = movs_destination_segment_base(vcpu);
    if is_rep
        && src_base == 0
        && dst_base == 0
        && addr_size == StringAddressSize::Addr64
        && (vcpu.regs.rflags & flags::bits::DF) == 0
        && vcpu.regs.rcx > 1
    {
        movs_fast_path(vcpu, op_size)?;
        // The fast path advances RSI/RDI/RCX as far as it safely can. Any
        // remaining count (page-straddling element, code/MMIO page) is handled
        // by falling through to the slow loop below, which resumes from the
        // current register state.
    }

    // Slow path: element-by-element, bit-for-bit identical to the original loop.
    // Also serves as the tail/fallback for the fast path (RCX is already 0 when
    // the fast path fully completed, so this loop is a no-op in that case).
    let count = if is_rep {
        rep_count(vcpu.regs.rcx, addr_size)
    } else {
        1
    };
    if is_rep && count == 0 {
        vcpu.regs.rsi = normalize_index(vcpu.regs.rsi, addr_size);
        vcpu.regs.rdi = normalize_index(vcpu.regs.rdi, addr_size);
        vcpu.regs.rcx = normalize_count(vcpu.regs.rcx, addr_size);
    }
    for _ in 0..count {
        if is_rep && rep_count(vcpu.regs.rcx, addr_size) == 0 {
            break;
        }
        let src = src_base.wrapping_add(index(vcpu.regs.rsi, addr_size));
        let dst = dst_base.wrapping_add(index(vcpu.regs.rdi, addr_size));
        let val = vcpu.read_mem(src, op_size)?;
        vcpu.write_mem(dst, val, op_size)?;
        let forward = vcpu.regs.rflags & flags::bits::DF == 0;
        vcpu.regs.rsi = advance_index(vcpu.regs.rsi, delta, forward, addr_size);
        vcpu.regs.rdi = advance_index(vcpu.regs.rdi, delta, forward, addr_size);
        if is_rep {
            vcpu.regs.rcx = dec_count(vcpu.regs.rcx, addr_size);
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
        if forward_propagating_overlap(src, dst, bytes as u64) {
            return Ok(());
        }

        // Translate both pages once (also performs bounds/permission checks and
        // raises #PF at the correct element on failure).
        let src_paddr = vcpu.mmu.translate(src, AccessType::Read, &vcpu.sregs)?;
        let dst_paddr = vcpu.mmu.translate(dst, AccessType::Write, &vcpu.sregs)?;

        if forward_propagating_overlap(src_paddr, dst_paddr, bytes as u64) {
            return Ok(());
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::isa::x86_64::cpu::MAX_INSN_LEN;

    const EFER_LMA: u64 = 1 << 10;

    fn test_vcpu() -> X86_64Vcpu {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        X86_64Vcpu::new(0, mem)
    }

    fn context(opcode: u8) -> InsnContext {
        let mut bytes = [0; MAX_INSN_LEN];
        bytes[0] = opcode;
        InsnContext {
            bytes,
            bytes_len: 1,
            cursor: 1,
            rex: None,
            rex2: None,
            operand_size_override: false,
            address_size_override: false,
            rep_prefix: None,
            op_size: 1,
            rip_relative_offset: 0,
            segment_override: None,
            evex: None,
            opcode,
            boundary_gp: false,
            boundary_fault: None,
        }
    }

    fn enable_long_mode(vcpu: &mut X86_64Vcpu) {
        vcpu.sregs.efer = EFER_LMA;
        vcpu.sregs.cs.l = true;
    }

    fn read_byte(vcpu: &mut X86_64Vcpu, addr: u64) -> u8 {
        let sregs = vcpu.sregs.clone();
        let mut buf = [0];
        vcpu.mmu.read(addr, &mut buf, &sregs).unwrap();
        buf[0]
    }

    fn write_byte(vcpu: &mut X86_64Vcpu, addr: u64, value: u8) {
        let sregs = vcpu.sregs.clone();
        vcpu.mmu.write(addr, &[value], &sregs).unwrap();
    }

    #[test]
    fn long_mode_movsb_ignores_es_destination_base() {
        let mut vcpu = test_vcpu();
        enable_long_mode(&mut vcpu);
        vcpu.sregs.es.base = 0x1000;
        vcpu.regs.rflags = 0x2;
        vcpu.regs.rsi = 0x2000;
        vcpu.regs.rdi = 0x4000;
        write_byte(&mut vcpu, 0x2000, 0x5a);
        let mut ctx = context(0xa4);

        movsb(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(read_byte(&mut vcpu, 0x4000), 0x5a);
        assert_eq!(read_byte(&mut vcpu, 0x5000), 0);
        assert_eq!(vcpu.regs.rsi, 0x2001);
        assert_eq!(vcpu.regs.rdi, 0x4001);
    }

    #[test]
    fn long_mode_movsb_ignores_ds_source_override_base() {
        let mut vcpu = test_vcpu();
        enable_long_mode(&mut vcpu);
        vcpu.sregs.ds.base = 0x1000;
        vcpu.regs.rflags = 0x2;
        vcpu.regs.rsi = 0x2000;
        vcpu.regs.rdi = 0x4000;
        write_byte(&mut vcpu, 0x2000, 0x5a);
        write_byte(&mut vcpu, 0x3000, 0xa5);
        let mut ctx = context(0xa4);
        ctx.segment_override = Some(0x3e);

        movsb(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(read_byte(&mut vcpu, 0x4000), 0x5a);
    }

    #[test]
    fn long_mode_movsb_honors_fs_source_override_base() {
        let mut vcpu = test_vcpu();
        enable_long_mode(&mut vcpu);
        vcpu.sregs.fs.base = 0x1000;
        vcpu.regs.rflags = 0x2;
        vcpu.regs.rsi = 0x2000;
        vcpu.regs.rdi = 0x4000;
        write_byte(&mut vcpu, 0x2000, 0x5a);
        write_byte(&mut vcpu, 0x3000, 0xa5);
        let mut ctx = context(0xa4);
        ctx.segment_override = Some(0x64);

        movsb(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(read_byte(&mut vcpu, 0x4000), 0xa5);
    }

    #[test]
    fn non_long_mode_movsb_uses_es_destination_base() {
        let mut vcpu = test_vcpu();
        vcpu.sregs.es.base = 0x1000;
        vcpu.regs.rflags = 0x2;
        vcpu.regs.rsi = 0x2000;
        vcpu.regs.rdi = 0x4000;
        write_byte(&mut vcpu, 0x2000, 0x5a);
        let mut ctx = context(0xa4);

        movsb(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(read_byte(&mut vcpu, 0x4000), 0);
        assert_eq!(read_byte(&mut vcpu, 0x5000), 0x5a);
    }
}
