//! Windows ARM64 packed and version-0 `.xdata` virtual unwinding.
//!
//! Layouts, scalar/SIMD save codes, and the mapping of unwind codes to
//! partially executed prologs/epilogs follow Microsoft's "ARM64 exception
//! handling". SVE state, authenticated return addresses, and custom kernel
//! stack records need state not represented by `RegContext` and are rejected.
//! Windows currently selects a non-PAuth ARMv8.2 guest CPU: PACIBSP and
//! AUTIBSP are hint-space no-ops on that CPU. Their unwind markers still count
//! as instructions for partial prolog/epilog selection. If Windows gains a
//! configurable PAuth CPU, its feature state must reach this unwinder and
//! authenticated returns must be implemented or rejected before admission.
//! All memory/metadata failures leave the caller's context unchanged.
//! Complexity is O(unwind bytes + epilog scopes), with O(unwind bytes) space.

use super::unwind::{FunctionEntry, Unwound};
use crate::user::windows::arch::WinArch;
use crate::user::windows::context::{CONTEXT_UNWOUND_TO_CALL, RegContext};
use crate::user::windows::memory::{Mem, MemFault};

fn bad(addr: u64) -> MemFault {
    MemFault { addr, write: false }
}
fn add(a: u64, b: u64) -> Result<u64, MemFault> {
    a.checked_add(b).ok_or_else(|| bad(a))
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Alloc(u64),
    Save {
        kind: u8,
        first: usize,
        second: Option<usize>,
        offset: u64,
        post: u64,
    },
    Frame(u64),
    Nop,
    /// PACIBSP/AUTIBSP, a counted hint on the selected non-PAuth guest CPU.
    PacHint,
    Boundary,
}

fn save(kind: u8, first: usize, second: Option<usize>, offset: u64, post: u64) -> Op {
    Op::Save {
        kind,
        first,
        second,
        offset,
        post,
    }
}

/// Virtually restores the caller through one ARM64 function table entry.
pub fn virtual_unwind(
    mem: &impl Mem,
    handler_type: u32,
    f: &FunctionEntry,
    ctx: &mut RegContext,
) -> Result<Unwound, MemFault> {
    virtual_unwind_with_metadata(mem, mem, handler_type, f, ctx)
}

/// Separate image-bounded metadata reads from caller-stack reads.
pub(super) fn virtual_unwind_with_metadata(
    mem: &impl Mem,
    metadata: &impl Mem,
    handler_type: u32,
    f: &FunctionEntry,
    ctx: &mut RegContext,
) -> Result<Unwound, MemFault> {
    if ctx.arch() != WinArch::Arm64 {
        return Err(bad(f.entry));
    }
    let mut next = ctx.clone();
    let result = match f.unwind & 3 {
        0 => full(mem, metadata, handler_type, f, &mut next)?,
        1 | 2 => packed(mem, f, &mut next)?,
        _ => return Err(bad(f.entry)),
    };
    next.set_flags(next.flags() | CONTEXT_UNWOUND_TO_CALL);
    *ctx = next;
    Ok(result)
}

fn execute(mem: &impl Mem, ops: &[Op], ctx: &mut RegContext) -> Result<(), MemFault> {
    for &op in ops {
        match op {
            Op::Alloc(bytes) => ctx.set_sp(add(ctx.sp(), bytes)?),
            Op::Frame(offset) => ctx.set_sp(
                ctx.gpr(29)
                    .checked_sub(offset)
                    .ok_or_else(|| bad(ctx.gpr(29)))?,
            ),
            Op::Nop | Op::PacHint | Op::Boundary => {}
            Op::Save {
                kind,
                first,
                second,
                offset,
                post,
            } => {
                let width = if kind == 2 { 16 } else { 8 };
                let at = add(ctx.sp(), offset)?;
                for (i, reg) in [Some(first), second].into_iter().enumerate() {
                    let Some(reg) = reg else { continue };
                    let address = add(at, i as u64 * width)?;
                    match kind {
                        0 if reg <= 30 => ctx.set_gpr(reg, mem.u64(address)?),
                        1 if reg < 32 => {
                            // Only Dn is nonvolatile for these save codes;
                            // preserve the upper 64 bits of the context's Vn.
                            let low = u128::from(mem.u64(address)?);
                            ctx.set_v(reg, (ctx.v(reg) & !(u64::MAX as u128)) | low);
                        }
                        2 if reg < 32 => {
                            let mut value = [0u8; 16];
                            mem.rd(address, &mut value)?;
                            ctx.set_v(reg, u128::from_le_bytes(value));
                        }
                        _ => return Err(bad(address)),
                    }
                }
                ctx.set_sp(add(ctx.sp(), post)?);
            }
        }
    }
    ctx.set_pc(ctx.gpr(30));
    Ok(())
}

/// Decodes a sequence ending at `end`; `end_c` contributes zero instructions
/// to the local prolog but its parent operations still execute during unwind.
fn decode(bytes: &[u8], start: usize, at: u64) -> Result<Vec<Op>, MemFault> {
    let mut i = start;
    let mut ops = Vec::new();
    // SAVE_NEXT follows the earlier pair save in *prolog instruction*
    // order. Bytes are in reverse order: SAVE_NEXT precedes the base pair.
    let mut next_pairs = 0usize;
    while i < bytes.len() {
        let code_at = add(at, i as u64)?;
        let b = bytes[i];
        i += 1;
        let mut byte = || {
            let value = bytes.get(i).copied().ok_or_else(|| bad(code_at));
            i += 1;
            value
        };
        let op = match b {
            0x00..=0x1F => Op::Alloc(u64::from(b & 31) * 16),
            0x20..=0x3F => save(0, 19, Some(20), 0, u64::from(b & 31) * 8),
            0x40..=0x7F => save(0, 29, Some(30), u64::from(b & 63) * 8, 0),
            0x80..=0xBF => save(0, 29, Some(30), 0, (u64::from(b & 63) + 1) * 8),
            0xC0..=0xC7 => Op::Alloc(((u64::from(b & 7) << 8) | u64::from(byte()?)) * 16),
            0xC8..=0xD3 => {
                let c = byte()?;
                let reg = 19 + (usize::from(b & 3) << 2) + usize::from(c >> 6);
                let pair = b < 0xD0;
                let post = (0xCC..0xD0).contains(&b);
                let offset = u64::from(c & 63) * 8;
                save(
                    0,
                    reg,
                    pair.then_some(reg + 1),
                    if post { 0 } else { offset },
                    if post { offset + 8 } else { 0 },
                )
            }
            0xD4..=0xD5 => {
                let c = byte()?;
                let reg = 19 + (usize::from(b & 1) << 3) + usize::from(c >> 5);
                save(0, reg, None, 0, (u64::from(c & 31) + 1) * 8)
            }
            0xD6..=0xD7 => {
                let c = byte()?;
                let reg = 19 + 2 * ((usize::from(b & 1) << 2) + usize::from(c >> 6));
                save(0, reg, Some(30), u64::from(c & 63) * 8, 0)
            }
            0xD8..=0xDD => {
                let c = byte()?;
                let reg = 8 + (usize::from(b & 1) << 2) + usize::from(c >> 6);
                let pair = b < 0xDC;
                let post = b >= 0xDA && b < 0xDC;
                let offset = u64::from(c & 63) * 8;
                save(
                    1,
                    reg,
                    pair.then_some(reg + 1),
                    if post { 0 } else { offset },
                    if post { offset + 8 } else { 0 },
                )
            }
            0xDE => {
                let c = byte()?;
                save(
                    1,
                    8 + usize::from(c >> 5),
                    None,
                    0,
                    (u64::from(c & 31) + 1) * 8,
                )
            }
            0xE0 => Op::Alloc(
                ((u64::from(byte()?) << 16) | (u64::from(byte()?) << 8) | u64::from(byte()?)) * 16,
            ),
            0xE1 => Op::Frame(0),
            0xE2 => Op::Frame(u64::from(byte()?) * 8),
            0xE3 => Op::Nop,
            0xE4 => {
                if next_pairs != 0 {
                    return Err(bad(code_at));
                }
                return Ok(ops);
            }
            0xE5 => Op::Boundary,
            0xE6 => {
                next_pairs += 1;
                if next_pairs >= 16 {
                    return Err(bad(code_at));
                }
                continue;
            }
            0xE7 => {
                let a = byte()?;
                let c = byte()?;
                if a & 0x80 != 0 || c >> 6 == 3 {
                    return Err(bad(code_at));
                }
                let kind = c >> 6;
                let pair = a & 0x40 != 0;
                let post = a & 0x20 != 0;
                let reg = usize::from(a & 31);
                let scale = if kind == 2 || pair || post { 16 } else { 8 };
                let offset = u64::from(c & 63) * scale;
                save(
                    kind,
                    reg,
                    pair.then_some(reg + 1),
                    if post { 0 } else { offset },
                    if post { offset + scale } else { 0 },
                )
            }
            0xFC => Op::PacHint,
            // SVE/custom-stack records require architectural state absent
            // from this CONTEXT model. Other PAC encodings are reserved.
            _ => return Err(bad(code_at)),
        };
        if let Op::Save {
            kind,
            first,
            second,
            offset,
            post: _,
        } = op
        {
            let limit = if kind == 0 { 31 } else { 32 };
            if first >= limit || second.is_some_and(|r| r >= limit) {
                return Err(bad(code_at));
            }
            if next_pairs != 0 {
                if second != Some(first + 1) || first + 2 * next_pairs + 1 >= limit {
                    return Err(bad(code_at));
                }
                let width = if kind == 2 { 16 } else { 8 };
                for pair in (1..=next_pairs).rev() {
                    ops.push(save(
                        kind,
                        first + 2 * pair,
                        Some(first + 2 * pair + 1),
                        offset + 2 * pair as u64 * width,
                        0,
                    ));
                }
                next_pairs = 0;
            }
        } else if next_pairs != 0 {
            return Err(bad(code_at));
        }
        ops.push(op);
    }
    Err(bad(add(at, bytes.len() as u64)?))
}

fn prolog_count(ops: &[Op]) -> usize {
    ops.iter()
        .position(|op| matches!(op, Op::Boundary))
        .unwrap_or(ops.len())
}

fn full(
    mem: &impl Mem,
    metadata: &impl Mem,
    handler_type: u32,
    f: &FunctionEntry,
    ctx: &mut RegContext,
) -> Result<Unwound, MemFault> {
    let at = add(f.image_base, u64::from(f.unwind))?;
    let header = metadata.u32(at)?;
    if (header >> 18) & 3 != 0 {
        return Err(bad(at));
    }
    let length = u64::from(header & 0x3FFFF) * 4;
    let start = add(f.image_base, u64::from(f.begin))?;
    let offset = ctx
        .pc()
        .checked_sub(start)
        .filter(|&n| n < length && n % 4 == 0)
        .ok_or_else(|| bad(ctx.pc()))?;
    let single = header & (1 << 21) != 0;
    let mut scopes = usize::try_from((header >> 22) & 31).unwrap();
    let mut words = usize::try_from(header >> 27).unwrap();
    let mut cursor = add(at, 4)?;
    if scopes == 0 && words == 0 {
        let extended = metadata.u32(cursor)?;
        if extended >> 24 != 0 {
            return Err(bad(cursor));
        }
        scopes = (extended & 0xFFFF) as usize;
        words = ((extended >> 16) & 0xFF) as usize;
        cursor = add(cursor, 4)?;
    }
    if words == 0 {
        return Err(bad(cursor));
    }
    let scope_start = cursor;
    if !single {
        cursor = add(cursor, 4 * scopes as u64)?;
    }
    let mut bytes = vec![0u8; 4 * words];
    metadata.rd(cursor, &mut bytes)?;
    let mut ops = decode(&bytes, 0, cursor)?;
    let prolog = prolog_count(&ops);
    let mut partial = offset / 4 < prolog as u64;
    let mut skip = if partial {
        prolog - (offset / 4) as usize
    } else {
        0
    };
    if single {
        let epilog = decode(&bytes, scopes, cursor)?;
        let start = length
            .checked_sub(4 * (prolog_count(&epilog) as u64 + 1))
            .ok_or_else(|| bad(at))?;
        if offset >= start {
            ops = epilog;
            skip = ((offset - start) / 4) as usize;
            partial = true;
        }
    } else {
        let mut previous = 0;
        for i in 0..scopes {
            let scope_at = add(scope_start, i as u64 * 4)?;
            let scope = metadata.u32(scope_at)?;
            let begin = u64::from(scope & 0x3FFFF) * 4;
            if scope & 0x003C_0000 != 0 || begin >= length || (i > 0 && begin < previous) {
                return Err(bad(scope_at));
            }
            previous = begin;
            let epilog = decode(&bytes, (scope >> 22) as usize, cursor)?;
            let end = add(begin, 4 * (prolog_count(&epilog) as u64 + 1))?;
            if end > length {
                return Err(bad(scope_at));
            }
            if offset >= begin && offset < end {
                ops = epilog;
                skip = ((offset - begin) / 4) as usize;
                partial = true;
            }
        }
    }
    let handler_at = add(cursor, bytes.len() as u64)?;
    let handler = if !partial && header & (1 << 20) != 0 && handler_type & 3 != 0 {
        Some(add(f.image_base, u64::from(metadata.u32(handler_at)?))?)
    } else {
        None
    };
    execute(mem, &ops[skip.min(ops.len())..], ctx)?;
    Ok(Unwound {
        handler,
        handler_data: if handler.is_some() {
            add(handler_at, 4)?
        } else {
            0
        },
        establisher: ctx.sp(),
    })
}

fn packed(mem: &impl Mem, f: &FunctionEntry, ctx: &mut RegContext) -> Result<Unwound, MemFault> {
    let value = f.unwind;
    let length = u64::from((value >> 2) & 0x7FF) * 4;
    let frame = u64::from(value >> 23) * 16;
    let regi = ((value >> 16) & 15) as usize;
    let regf = ((value >> 13) & 7) as usize;
    let cr = (value >> 21) & 3;
    let homes = value & (1 << 20) != 0;
    if regi > 10 {
        return Err(bad(f.entry));
    }
    let start = add(f.image_base, u64::from(f.begin))?;
    let offset = ctx
        .pc()
        .checked_sub(start)
        .filter(|&n| n < length && n % 4 == 0)
        .ok_or_else(|| bad(ctx.pc()))?;
    let int_size = regi as u64 * 8 + if cr == 1 { 8 } else { 0 };
    let float_count = if regf == 0 { 0 } else { regf + 1 };
    let save_size = (int_size + float_count as u64 * 8 + if homes { 64 } else { 0 } + 15) & !15;
    let local_size = frame.checked_sub(save_size).ok_or_else(|| bad(f.entry))?;
    let mut forward = Vec::new();
    let mut allocated = false;
    let mut i = 0;
    if cr == 2 {
        // Packed CR=2 begins with PACIBSP. Keep its unwind operation even
        // when constructing the epilog: AUTIBSP occupies one instruction,
        // unlike the synthetic NOP used for set_fp and argument homing.
        forward.push(Op::PacHint);
    }
    // RegI=1 with LR uses an explicit allocation followed by STP X19,LR;
    // the pre-indexed LR pair has no matching packed scalar unwind code.
    if regi == 1 && cr == 1 {
        forward.push(Op::Alloc(save_size));
        allocated = true;
    }
    while i < regi {
        let second = if i + 1 < regi {
            Some(20 + i)
        } else if cr == 1 {
            Some(30)
        } else {
            None
        };
        forward.push(save(
            0,
            19 + i,
            second,
            if allocated { i as u64 * 8 } else { 0 },
            if allocated { 0 } else { save_size },
        ));
        allocated = true;
        i += 2;
    }
    if cr == 1 && regi % 2 == 0 {
        if !allocated {
            forward.push(Op::Alloc(save_size));
            allocated = true;
        }
        forward.push(save(0, 30, None, regi as u64 * 8, 0));
    }
    for i in (0..float_count).step_by(2) {
        forward.push(save(
            1,
            8 + i,
            (i + 1 < float_count).then_some(9 + i),
            if allocated {
                int_size + i as u64 * 8
            } else {
                0
            },
            if allocated { 0 } else { save_size },
        ));
        allocated = true;
    }
    if homes {
        if !allocated {
            forward.push(Op::Alloc(save_size));
            forward.extend([Op::Nop; 3]);
        } else {
            forward.extend([Op::Nop; 4]);
        }
    }
    if cr == 2 || cr == 3 {
        if local_size < 16 {
            return Err(bad(f.entry));
        }
        if local_size <= 512 {
            forward.push(save(0, 29, Some(30), 0, local_size));
        } else {
            forward.push(Op::Alloc(local_size.min(4080)));
            if local_size > 4080 {
                forward.push(Op::Alloc(local_size - 4080));
            }
            forward.push(save(0, 29, Some(30), 0, 0));
        }
        forward.push(Op::Nop); // Packed set_fp must never reset SP from FP.
    } else if local_size != 0 {
        forward.push(Op::Alloc(local_size.min(4080)));
        if local_size > 4080 {
            forward.push(Op::Alloc(local_size - 4080));
        }
    }
    let mut reverse: Vec<_> = forward.iter().rev().copied().collect();
    let mut skip = 0;
    if value & 3 == 1 {
        let prolog = reverse.len();
        if offset / 4 < prolog as u64 {
            skip = prolog - (offset / 4) as usize;
        } else {
            let epilog: Vec<_> = reverse
                .iter()
                .filter(|op| !matches!(op, Op::Nop))
                .copied()
                .collect();
            let begin = length
                .checked_sub(4 * (epilog.len() as u64 + 1))
                .ok_or_else(|| bad(f.entry))?;
            if offset >= begin {
                reverse = epilog;
                skip = ((offset - begin) / 4) as usize;
            }
        }
    }
    execute(mem, &reverse[skip.min(reverse.len())..], ctx)?;
    Ok(Unwound {
        establisher: ctx.sp(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::arm::common::ArmFeatures;
    use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};
    use crate::user::windows::arch::WinCpu;
    const BASE: u64 = 0x10000;
    const STACK: u64 = 0x20000;
    fn setup() -> (AddressSpace, FunctionEntry, RegContext) {
        let mem = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 64 * PAGE_SIZE,
            reserved_phys: Vec::new(),
        })
        .unwrap();
        for at in [BASE, STACK] {
            mem.map(
                at,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        }
        let f = FunctionEntry {
            image_base: BASE,
            entry: BASE + 0x80,
            begin: 0x200,
            end: 0,
            unwind: 0x100,
        };
        let mut ctx = RegContext::new(WinArch::Arm64);
        ctx.set_pc(BASE + 0x240);
        ctx.set_sp(STACK);
        ctx.set_gpr(30, 0x1234);
        (mem, f, ctx)
    }
    #[test]
    fn arm64_windows_cpu_keeps_pac_unwind_in_hint_profile() {
        let (mem, _, _) = setup();
        let cpu = WinCpu::new(WinArch::Arm64, &mem);
        let features = cpu.a64().unwrap().core().config().features;
        assert!(!features.intersects(ArmFeatures::PACA | ArmFeatures::PACG));
    }
    #[test]
    fn arm64_full_frame_pair_restores_caller_and_handler() {
        let (mem, f, mut ctx) = setup();
        mem.w32(BASE + 0x100, 64 | (1 << 20) | (1 << 27)).unwrap();
        mem.wr(BASE + 0x104, &[0xE1, 0x87, 0xE4, 0]).unwrap();
        mem.w32(BASE + 0x108, 0x400).unwrap();
        ctx.set_gpr(29, STACK);
        mem.w64(STACK, 0x9876).unwrap();
        mem.w64(STACK + 8, 0x5678).unwrap();
        let u = virtual_unwind(&mem, 1, &f, &mut ctx).unwrap();
        assert_eq!(
            (ctx.gpr(29), ctx.pc(), ctx.sp()),
            (0x9876, 0x5678, STACK + 64)
        );
        assert_eq!(u.handler, Some(BASE + 0x400));
        assert_eq!(u.establisher, STACK + 64);
    }
    #[test]
    fn arm64_full_partial_prolog_and_epilog_skip_completed_instructions() {
        let (mem, f, mut ctx) = setup();
        mem.w32(BASE + 0x100, 64 | (1 << 21) | (1 << 27)).unwrap();
        mem.wr(BASE + 0x104, &[0xE1, 0x87, 0xE4, 0]).unwrap();
        mem.w64(STACK, 0x9876).unwrap();
        mem.w64(STACK + 8, 0x5678).unwrap();
        ctx.set_pc(BASE + 0x204); // STP completed; MOV FP,SP not yet executed.
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!(ctx.sp(), STACK + 64);
        ctx.set_pc(BASE + 0x2FC);
        ctx.set_gpr(30, 0xABC0); // RET only remains.
        let sp = ctx.sp();
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!((ctx.pc(), ctx.sp()), (0xABC0, sp));
    }
    #[test]
    fn arm64_packed_chained_frame_restores_fp_lr() {
        let (mem, mut f, mut ctx) = setup();
        f.unwind = 1 | (64 << 2) | (3 << 21) | (4 << 23);
        mem.w64(STACK, 0x9876).unwrap();
        mem.w64(STACK + 8, 0x5678).unwrap();
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!(
            (ctx.gpr(29), ctx.pc(), ctx.sp()),
            (0x9876, 0x5678, STACK + 64)
        );
    }
    #[test]
    fn arm64_full_pac_hint_counts_partial_prolog_and_epilog() {
        // Microsoft ARM64 unwind code FC denotes PACIBSP in the prolog and
        // AUTIBSP in the epilog. On this personality's non-PAuth v8.2 CPU,
        // both instructions are architectural hints, but each still counts
        // as one instruction when selecting partial unwind operations.
        let (mem, f, mut ctx) = setup();
        mem.w32(BASE + 0x100, 64 | (1 << 21) | (1 << 27)).unwrap();
        mem.wr(BASE + 0x104, &[0xE1, 0x87, 0xFC, 0xE4]).unwrap();
        mem.w64(STACK, 0x9876).unwrap();
        mem.w64(STACK + 8, 0x5678).unwrap();

        ctx.set_gpr(29, STACK);
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!(
            (ctx.gpr(29), ctx.pc(), ctx.sp()),
            (0x9876, 0x5678, STACK + 64)
        );

        for offset in [0, 4] {
            let (_, _, mut partial) = setup();
            partial.set_pc(BASE + 0x200 + offset);
            partial.set_sp(STACK + 64);
            partial.set_gpr(29, 0xABCD);
            virtual_unwind(&mem, 0, &f, &mut partial).unwrap();
            assert_eq!(
                (partial.gpr(29), partial.pc(), partial.sp()),
                (0xABCD, 0x1234, STACK + 64)
            );
        }

        let (_, _, mut after_save) = setup();
        after_save.set_pc(BASE + 0x208);
        virtual_unwind(&mem, 0, &f, &mut after_save).unwrap();
        assert_eq!(
            (after_save.gpr(29), after_save.pc(), after_save.sp()),
            (0x9876, 0x5678, STACK + 64)
        );

        let (_, _, mut after_epilog_restore) = setup();
        after_epilog_restore.set_pc(BASE + 0x2F8);
        after_epilog_restore.set_sp(STACK + 64);
        after_epilog_restore.set_gpr(30, 0x5678);
        virtual_unwind(&mem, 0, &f, &mut after_epilog_restore).unwrap();
        assert_eq!(
            (after_epilog_restore.pc(), after_epilog_restore.sp()),
            (0x5678, STACK + 64)
        );
    }
    #[test]
    fn arm64_packed_pac_hint_chained_and_fragment_frames() {
        let (mem, mut f, mut ctx) = setup();
        f.unwind = 1 | (64 << 2) | (2 << 21) | (4 << 23);
        mem.w64(STACK, 0x9876).unwrap();
        mem.w64(STACK + 8, 0x5678).unwrap();
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!(
            (ctx.gpr(29), ctx.pc(), ctx.sp()),
            (0x9876, 0x5678, STACK + 64)
        );

        let (_, _, mut after_pac) = setup();
        after_pac.set_pc(BASE + 0x204);
        after_pac.set_sp(STACK + 64);
        virtual_unwind(&mem, 0, &f, &mut after_pac).unwrap();
        assert_eq!((after_pac.pc(), after_pac.sp()), (0x1234, STACK + 64));

        let (_, _, mut after_epilog_restore) = setup();
        after_epilog_restore.set_pc(BASE + 0x2F8);
        after_epilog_restore.set_sp(STACK + 64);
        after_epilog_restore.set_gpr(30, 0x5678);
        virtual_unwind(&mem, 0, &f, &mut after_epilog_restore).unwrap();
        assert_eq!(
            (after_epilog_restore.pc(), after_epilog_restore.sp()),
            (0x5678, STACK + 64)
        );

        let (_, _, mut fragment) = setup();
        fragment.set_pc(BASE + 0x240);
        f.unwind = (f.unwind & !3) | 2;
        virtual_unwind(&mem, 0, &f, &mut fragment).unwrap();
        assert_eq!(
            (fragment.gpr(29), fragment.pc(), fragment.sp()),
            (0x9876, 0x5678, STACK + 64)
        );
    }
    #[test]
    fn arm64_scalar_float_saves_preserve_high_vector_bits() {
        let (mem, f, mut ctx) = setup();
        mem.w32(BASE + 0x100, 64 | (2 << 27)).unwrap();
        mem.wr(BASE + 0x104, &[0xD8, 0, 4, 0xE4, 0, 0, 0, 0])
            .unwrap();
        mem.w64(STACK, 0x1234).unwrap();
        mem.w64(STACK + 8, 0x5678).unwrap();
        ctx.set_v(8, 0xABCDu128 << 64);
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!(ctx.v(8), (0xABCDu128 << 64) | 0x1234);
        assert_eq!(ctx.v(9), 0x5678);
        assert_eq!(ctx.sp(), STACK + 64);
    }
    #[test]
    fn arm64_llvm_save_next_precedes_base_pair_in_reverse_unwind_order() {
        // LLVM 23.0.0git: .seh_save_regp_x x19,32; .seh_save_next
        // emits E6 24 E4. The higher pair restores before the SP writeback.
        let (mem, f, mut ctx) = setup();
        mem.w32(BASE + 0x100, 64 | (1 << 27)).unwrap();
        mem.wr(BASE + 0x104, &[0xE6, 0x24, 0xE4, 0]).unwrap();
        for i in 0..4 {
            mem.w64(STACK + i * 8, 0x100 + i).unwrap();
        }
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!(
            (ctx.gpr(19), ctx.gpr(20), ctx.gpr(21), ctx.gpr(22)),
            (0x100, 0x101, 0x102, 0x103)
        );
        assert_eq!(ctx.sp(), STACK + 32);
    }
    #[test]
    fn arm64_llvm_save_any_preindex_zero_encodes_16_bytes() {
        // LLVM 23.0.0git .seh_save_any_reg_x x19,16 emits E7 33 00.
        let (mem, f, mut ctx) = setup();
        mem.w32(BASE + 0x100, 64 | (1 << 27)).unwrap();
        mem.wr(BASE + 0x104, &[0xE7, 0x33, 0, 0xE4]).unwrap();
        mem.w64(STACK, 0xABC0).unwrap();
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!((ctx.gpr(19), ctx.sp()), (0xABC0, STACK + 16));
    }
    #[test]
    fn arm64_reserved_and_faulting_unwind_leave_context_unchanged() {
        let (mem, f, mut ctx) = setup();
        mem.w32(BASE + 0x100, 64 | (1 << 27)).unwrap();
        for reserved in [0xFD, 0xFE, 0xFF] {
            mem.wr(BASE + 0x104, &[reserved, 0xE4, 0, 0]).unwrap();
            let before = ctx.clone();
            assert!(virtual_unwind(&mem, 0, &f, &mut ctx).is_err());
            assert_eq!(ctx, before);
        }
        mem.wr(BASE + 0x104, &[0x87, 0xE4, 0, 0]).unwrap();
        ctx.set_sp(STACK + PAGE_SIZE - 8);
        let before = ctx.clone();
        assert!(virtual_unwind(&mem, 0, &f, &mut ctx).is_err());
        assert_eq!(ctx, before);

        let (_, mut malformed, mut ctx) = setup();
        malformed.unwind = 1 | (64 << 2) | (2 << 21); // CR=2 requires FP/LR space.
        let before = ctx.clone();
        assert!(virtual_unwind(&mem, 0, &malformed, &mut ctx).is_err());
        assert_eq!(ctx, before);
    }
}
