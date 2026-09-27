//! Microsoft x64 version-1 `UNWIND_INFO` interpretation.
//!
//! The operation definitions, partial-prolog rule, chained records, and
//! epilog grammar follow Microsoft Learn, "x64 exception handling" and
//! "x64 prolog and epilog". Unknown versions and reserved operations are
//! rejected. Context updates are transactional on memory/metadata errors.
//! Work is O(unwind slots + epilog instructions), with bounded chain depth.

use super::unwind::{FunctionEntry, Unwound};
use crate::user::windows::arch::WinArch;
use crate::user::windows::context::RegContext;
use crate::user::windows::memory::{Mem, MemFault};

fn bad(addr: u64) -> MemFault {
    MemFault { addr, write: false }
}
fn add(a: u64, b: u64) -> Result<u64, MemFault> {
    a.checked_add(b).ok_or_else(|| bad(a))
}
fn sub(a: u64, b: u64) -> Result<u64, MemFault> {
    a.checked_sub(b).ok_or_else(|| bad(a))
}
fn nonvolatile(n: usize) -> bool {
    matches!(n, 3 | 5 | 6 | 7 | 12..=15)
}

fn slots(op: u8, info: usize) -> Option<usize> {
    match op {
        0 | 2 | 3 | 10 => Some(1),
        1 if info == 0 => Some(2),
        1 if info == 1 => Some(3),
        4 | 8 => Some(2),
        5 | 9 => Some(3),
        _ => None,
    }
}

/// Virtually restores the caller through one x64 function table entry.
pub fn virtual_unwind(
    mem: &impl Mem,
    handler_type: u32,
    function: &FunctionEntry,
    ctx: &mut RegContext,
) -> Result<Unwound, MemFault> {
    virtual_unwind_with_metadata(mem, mem, handler_type, function, ctx)
}

/// Separate image-bounded metadata/code reads from caller-stack reads.
pub(super) fn virtual_unwind_with_metadata(
    mem: &impl Mem,
    metadata: &impl Mem,
    handler_type: u32,
    function: &FunctionEntry,
    ctx: &mut RegContext,
) -> Result<Unwound, MemFault> {
    if ctx.arch() != WinArch::X64 {
        return Err(bad(function.entry));
    }
    let mut next = ctx.clone();
    let result = unwind(mem, metadata, handler_type, function, &mut next)?;
    *ctx = next;
    Ok(result)
}

fn unwind(
    mem: &impl Mem,
    metadata: &impl Mem,
    handler_type: u32,
    f: &FunctionEntry,
    ctx: &mut RegContext,
) -> Result<Unwound, MemFault> {
    let start = add(f.image_base, u64::from(f.begin))?;
    let end = add(f.image_base, u64::from(f.end))?;
    if start >= end || ctx.pc() < start || ctx.pc() >= end {
        return Err(bad(f.entry));
    }
    let control_offset = ctx.pc() - start;
    let initial_sp = ctx.sp();
    let mut current = *f;
    let mut seen = Vec::new();
    let mut result = Unwound {
        establisher: initial_sp,
        ..Default::default()
    };
    let mut machine_frame = false;
    let mut initial_partial = false;
    for depth in 0..32 {
        let at = add(f.image_base, u64::from(current.unwind))?;
        if at % 4 != 0 || seen.contains(&at) {
            return Err(bad(at));
        }
        seen.push(at);
        let mut h = [0u8; 4];
        metadata.rd(at, &mut h)?;
        let version = h[0] & 7;
        let flags = h[0] >> 3;
        let count = usize::from(h[2]);
        let frame = usize::from(h[3] & 15);
        let frame_offset = u64::from(h[3] >> 4) * 16;
        if version != 1
            || flags & !7 != 0
            || (flags & 4 != 0 && flags & 3 != 0)
            || (frame != 0 && !nonvolatile(frame))
            || (frame == 0 && frame_offset != 0)
        {
            return Err(bad(at));
        }
        let mut codes = vec![0u8; 2 * count];
        metadata.rd(add(at, 4)?, &mut codes)?;
        let partial = depth == 0 && control_offset <= u64::from(h[1]);
        if depth == 0 {
            initial_partial = partial;
        }
        // Operand slots contain raw offsets and must never be mistaken for
        // UWOP_SET_FPREG, even if their bytes happen to match that opcode.
        let mut fp_ready = frame != 0 && !partial;
        let mut scan = 0;
        while scan < count {
            let op = codes[2 * scan + 1] & 15;
            let info = usize::from(codes[2 * scan + 1] >> 4);
            let code_at = add(at, 4 + 2 * scan as u64)?;
            let size = slots(op, info).ok_or_else(|| bad(code_at))?;
            if scan + size > count {
                return Err(bad(add(at, 4 + 2 * scan as u64)?));
            }
            if op == 3 && u64::from(codes[2 * scan]) <= control_offset {
                fp_ready = frame != 0;
            }
            scan += size;
        }
        let frame_base = if fp_ready {
            sub(ctx.gpr(frame), frame_offset)?
        } else {
            ctx.sp()
        };
        if depth == 0 {
            result.establisher = frame_base;
            if !partial && simulate_epilog(mem, metadata, f, frame, ctx)? {
                return Ok(result);
            }
        }
        let mut i = 0;
        let mut previous_offset = u8::MAX;
        while i < count {
            let code_at = add(at, 4 + 2 * i as u64)?;
            let code_offset = codes[2 * i];
            let op = codes[2 * i + 1] & 15;
            let info = usize::from(codes[2 * i + 1] >> 4);
            if code_offset > previous_offset || code_offset > h[1] {
                return Err(bad(code_at));
            }
            previous_offset = code_offset;
            let slots = slots(op, info).ok_or_else(|| bad(code_at))?;
            if i + slots > count {
                return Err(bad(code_at));
            }
            let extra = |slot: usize| {
                u16::from_le_bytes([codes[2 * (i + slot)], codes[2 * (i + slot) + 1]])
            };
            let offset = match slots {
                2 => u64::from(extra(1)),
                3 => u64::from(extra(1)) | (u64::from(extra(2)) << 16),
                _ => 0,
            };
            let execute = !partial || u64::from(code_offset) <= control_offset;
            if execute {
                match op {
                    0 => {
                        if !nonvolatile(info) {
                            return Err(bad(code_at));
                        }
                        let value = mem.u64(ctx.sp())?;
                        ctx.set_gpr(info, value);
                        ctx.set_sp(add(ctx.sp(), 8)?);
                    }
                    1 => {
                        let bytes = if info == 0 { offset * 8 } else { offset };
                        if bytes == 0 || bytes % 8 != 0 {
                            return Err(bad(code_at));
                        }
                        ctx.set_sp(add(ctx.sp(), bytes)?);
                    }
                    2 => ctx.set_sp(add(ctx.sp(), info as u64 * 8 + 8)?),
                    3 => {
                        if frame == 0 || info != 0 {
                            return Err(bad(code_at));
                        }
                        ctx.set_sp(sub(ctx.gpr(frame), frame_offset)?);
                    }
                    4 | 5 => {
                        if !nonvolatile(info) {
                            return Err(bad(code_at));
                        }
                        let displacement = if op == 4 { offset * 8 } else { offset };
                        if displacement % 8 != 0 {
                            return Err(bad(code_at));
                        }
                        ctx.set_gpr(info, mem.u64(add(frame_base, displacement)?)?);
                    }
                    8 | 9 => {
                        if !(6..16).contains(&info) {
                            return Err(bad(code_at));
                        }
                        let displacement = if op == 8 { offset * 16 } else { offset };
                        if displacement % 16 != 0 {
                            return Err(bad(code_at));
                        }
                        let mut value = [0u8; 16];
                        mem.rd(add(frame_base, displacement)?, &mut value)?;
                        ctx.set_xmm(info, u128::from_le_bytes(value));
                    }
                    10 => {
                        if info > 1 || machine_frame {
                            return Err(bad(code_at));
                        }
                        let frame_sp = add(ctx.sp(), info as u64 * 8)?;
                        let pc = mem.u64(frame_sp)?;
                        let cs = mem.u64(add(frame_sp, 8)?)? as u16;
                        let flags = mem.u64(add(frame_sp, 16)?)? as u32;
                        let sp = mem.u64(add(frame_sp, 24)?)?;
                        let ss = mem.u64(add(frame_sp, 32)?)? as u16;
                        ctx.set_x64_machine_frame(pc, cs, flags, sp, ss);
                        machine_frame = true;
                    }
                    _ => return Err(bad(code_at)),
                }
            }
            i += slots;
        }
        let tail = add(at, 4 + 2 * ((count + 1) & !1) as u64)?;
        if flags & 4 != 0 {
            current = FunctionEntry {
                image_base: f.image_base,
                entry: tail,
                begin: metadata.u32(tail)?,
                end: metadata.u32(add(tail, 4)?)?,
                unwind: metadata.u32(add(tail, 8)?)?,
            };
            continue;
        }
        if !initial_partial && u32::from(flags) & handler_type & 3 != 0 {
            result.handler = Some(add(f.image_base, u64::from(metadata.u32(tail)?))?);
            result.handler_data = add(tail, 4)?;
        }
        if !machine_frame {
            let pc = mem.u64(ctx.sp())?;
            ctx.set_sp(add(ctx.sp(), 8)?);
            ctx.set_pc(pc);
        }
        return Ok(result);
    }
    Err(bad(current.entry))
}

#[derive(Clone, Copy)]
enum EpilogOp {
    Add(u64),
    Frame(usize, i64),
    Pop(usize),
    Return(u64),
}

/// Parses the complete legal suffix before reading any stack or updating ctx.
fn simulate_epilog(
    stack: &impl Mem,
    mem: &impl Mem,
    f: &FunctionEntry,
    frame: usize,
    ctx: &mut RegContext,
) -> Result<bool, MemFault> {
    let mut at = ctx.pc();
    let end = add(f.image_base, u64::from(f.end))?;
    let mut ops = Vec::new();
    let mut first = true;
    for _ in 0..32 {
        if at >= end {
            return Ok(false);
        }
        let byte = mem.u8(at)?;
        let mut length = 1;
        if first && byte == 0x48 && mem.u8(add(at, 1)?)? == 0x83 && mem.u8(add(at, 2)?)? == 0xC4 {
            let value = mem.u8(add(at, 3)?)? as i8;
            if value < 0 {
                return Ok(false);
            }
            ops.push(EpilogOp::Add(value as u64));
            length = 4;
        } else if first
            && byte == 0x48
            && mem.u8(add(at, 1)?)? == 0x81
            && mem.u8(add(at, 2)?)? == 0xC4
        {
            let value = mem.u32(add(at, 3)?)? as i32;
            if value < 0 {
                return Ok(false);
            }
            ops.push(EpilogOp::Add(value as u64));
            length = 7;
        } else if first && byte & 0xFE == 0x48 && mem.u8(add(at, 1)?)? == 0x8D {
            let modrm = mem.u8(add(at, 2)?)?;
            let base = usize::from(modrm & 7) + usize::from(byte & 1) * 8;
            if frame == 0 || base != frame || modrm & 0x38 != 0x20 {
                return Ok(false);
            }
            let mut displacement_at = add(at, 3)?;
            let sib_bytes = if modrm & 7 == 4 {
                if mem.u8(displacement_at)? != 0x24 {
                    return Ok(false);
                }
                displacement_at = add(displacement_at, 1)?;
                1
            } else {
                0
            };
            let displacement = match modrm >> 6 {
                1 => {
                    length = 4 + sib_bytes;
                    i64::from(mem.u8(displacement_at)? as i8)
                }
                2 => {
                    length = 7 + sib_bytes;
                    i64::from(mem.u32(displacement_at)? as i32)
                }
                _ => return Ok(false),
            };
            ops.push(EpilogOp::Frame(base, displacement));
        } else if (0x58..=0x5F).contains(&byte)
            || ((byte == 0x41 || byte == 0x48 || byte == 0x49)
                && (0x58..=0x5F).contains(&mem.u8(add(at, 1)?)?))
        {
            let reg = if byte >= 0x58 {
                usize::from(byte - 0x58)
            } else {
                length = 2;
                usize::from(mem.u8(add(at, 1)?)? - 0x58) + usize::from(byte & 1) * 8
            };
            if !nonvolatile(reg) {
                return Ok(false);
            }
            ops.push(EpilogOp::Pop(reg));
        } else if byte == 0xC3 || (byte == 0xF3 && mem.u8(add(at, 1)?)? == 0xC3) {
            ops.push(EpilogOp::Return(0));
            break;
        } else if byte == 0xC2 {
            ops.push(EpilogOp::Return(u64::from(mem.u16(add(at, 1)?)?)));
            break;
        } else if byte == 0xEB || byte == 0xE9 {
            // RtlVirtualUnwind's documented direct-tail-JMP marker is
            // admitted only when the target leaves this RUNTIME_FUNCTION.
            let (displacement, size) = if byte == 0xEB {
                (i64::from(mem.u8(add(at, 1)?)? as i8), 2)
            } else {
                (i64::from(mem.u32(add(at, 1)?)? as i32), 5)
            };
            let following = add(at, size)?;
            let target = if displacement >= 0 {
                add(following, displacement as u64)?
            } else {
                sub(following, displacement.unsigned_abs())?
            };
            let begin = add(f.image_base, u64::from(f.begin))?;
            if target >= begin && target < end {
                return Ok(false);
            }
            ops.push(EpilogOp::Return(0));
            break;
        } else if (byte == 0x48 || byte == 0x49)
            && mem.u8(add(at, 1)?)? == 0xFF
            && mem.u8(add(at, 2)?)? & 0xF8 == 0xE0
        {
            ops.push(EpilogOp::Return(0));
            break;
        } else if byte == 0xFF && mem.u8(add(at, 1)?)? & 0xF8 == 0x20 {
            // A legal memory tail JMP forwards this frame's return address
            // to the target; unwinding it still restores the original caller.
            ops.push(EpilogOp::Return(0));
            break;
        } else {
            return Ok(false);
        }
        first = false;
        at = add(at, length)?;
    }
    if !matches!(ops.last(), Some(EpilogOp::Return(_))) {
        return Ok(false);
    }
    let mut next = ctx.clone();
    for op in ops {
        match op {
            EpilogOp::Add(bytes) => next.set_sp(add(next.sp(), bytes)?),
            EpilogOp::Frame(reg, off) => next.set_sp(if off >= 0 {
                add(next.gpr(reg), off as u64)?
            } else {
                sub(next.gpr(reg), off.unsigned_abs())?
            }),
            EpilogOp::Pop(reg) => {
                next.set_gpr(reg, stack.u64(next.sp())?);
                next.set_sp(add(next.sp(), 8)?);
            }
            EpilogOp::Return(pop) => {
                next.set_pc(stack.u64(next.sp())?);
                next.set_sp(add(next.sp(), add(8, pop)?)?);
            }
        }
    }
    *ctx = next;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};
    const BASE: u64 = 0x10000;
    const STACK: u64 = 0x20000;
    fn setup(info: &[u8], offset: u64, sp: u64) -> (AddressSpace, FunctionEntry, RegContext) {
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
        mem.wr(BASE + 0x100, info).unwrap();
        let f = FunctionEntry {
            image_base: BASE,
            entry: BASE + 0x80,
            begin: 0x200,
            end: 0x300,
            unwind: 0x100,
        };
        let mut ctx = RegContext::new(WinArch::X64);
        ctx.set_pc(BASE + 0x200 + offset);
        ctx.set_sp(sp);
        (mem, f, ctx)
    }
    #[test]
    fn x64_small_allocation_and_push_restore_caller() {
        let (mem, f, mut ctx) = setup(&[1, 5, 2, 0, 5, 0x32, 1, 0x50], 32, STACK);
        mem.w64(STACK + 32, 0x1234).unwrap();
        mem.w64(STACK + 40, 0x5678).unwrap();
        let u = virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!(
            (ctx.gpr(5), ctx.pc(), ctx.sp(), u.establisher),
            (0x1234, 0x5678, STACK + 48, STACK)
        );
    }
    #[test]
    fn x64_partial_prolog_skips_unexecuted_stack_allocation() {
        let (mem, f, mut ctx) = setup(&[1, 5, 2, 0, 5, 0x32, 1, 0x50], 1, STACK + 32);
        mem.w64(STACK + 32, 0x1234).unwrap();
        mem.w64(STACK + 40, 0x5678).unwrap();
        virtual_unwind(&mem, 1, &f, &mut ctx).unwrap();
        assert_eq!(
            (ctx.gpr(5), ctx.pc(), ctx.sp()),
            (0x1234, 0x5678, STACK + 48)
        );
    }
    #[test]
    fn x64_frame_register_saved_integer_and_xmm_and_handler() {
        let (mem, f, mut ctx) = setup(
            &[
                9, 10, 6, 0x25, 10, 0x68, 2, 0, 9, 0x34, 6, 0, 8, 3, 7, 0x72, 0, 4, 0, 0,
            ],
            32,
            STACK - 0x100,
        );
        ctx.set_gpr(5, STACK + 32);
        mem.w64(STACK + 48, 0x1234).unwrap();
        mem.wr(STACK + 32, &0x1234_5678_9ABC_DEF0u128.to_le_bytes())
            .unwrap();
        mem.w64(STACK + 64, 0x5678).unwrap();
        let u = virtual_unwind(&mem, 1, &f, &mut ctx).unwrap();
        assert_eq!(ctx.gpr(3), 0x1234);
        assert_eq!(ctx.xmm(6), 0x1234_5678_9ABC_DEF0);
        assert_eq!((ctx.pc(), ctx.sp()), (0x5678, STACK + 72));
        assert_eq!(u.handler, Some(BASE + 0x400));
        assert_eq!(u.establisher, STACK);
    }
    #[test]
    fn x64_epilog_suffix_is_simulated_instead_of_replaying_prolog() {
        let (mem, f, mut ctx) = setup(&[1, 5, 2, 0, 5, 0x32, 1, 0x50], 0x80, STACK + 32);
        mem.wr(ctx.pc(), &[0x5D, 0xC3]).unwrap();
        mem.w64(STACK + 32, 0x1234).unwrap();
        mem.w64(STACK + 40, 0x5678).unwrap();
        virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
        assert_eq!(
            (ctx.gpr(5), ctx.pc(), ctx.sp()),
            (0x1234, 0x5678, STACK + 48)
        );
    }
    #[test]
    fn x64_fault_and_reserved_metadata_leave_context_unchanged() {
        let (mem, f, mut ctx) = setup(&[1, 5, 2, 0, 5, 0x32, 1, 0x50], 32, STACK + PAGE_SIZE - 32);
        let before = ctx.clone();
        assert!(virtual_unwind(&mem, 0, &f, &mut ctx).is_err());
        assert_eq!(ctx, before);
        mem.w8(BASE + 0x100, 3).unwrap();
        assert!(virtual_unwind(&mem, 0, &f, &mut ctx).is_err());
        assert_eq!(ctx, before);
    }
    #[test]
    fn x64_chained_record_cycle_is_rejected() {
        let (mem, f, mut ctx) = setup(
            &[0x21, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0],
            32,
            STACK,
        );
        let before = ctx.clone();
        assert!(virtual_unwind(&mem, 0, &f, &mut ctx).is_err());
        assert_eq!(ctx, before);
    }
    #[test]
    fn x64_tail_jump_outside_function_and_rex_register_tail_jump() {
        for code in [&[0xE9, 0, 1, 0, 0][..], &[0x49, 0xFF, 0xE0][..]] {
            let (mem, f, mut ctx) = setup(&[1, 5, 2, 0, 5, 0x32, 1, 0x50], 0x80, STACK + 40);
            mem.wr(ctx.pc(), code).unwrap();
            mem.w64(STACK + 40, 0x5678).unwrap();
            virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
            assert_eq!((ctx.pc(), ctx.sp()), (0x5678, STACK + 48));
        }
    }
    #[test]
    fn x64_machine_frame_restores_all_five_slots_with_or_without_error_code() {
        for info in 0..=1u8 {
            let (mem, f, mut ctx) = setup(&[1, 1, 1, 0, 1, 10 | (info << 4)], 32, STACK);
            let frame = STACK + u64::from(info) * 8;
            let slots = [0x1234_5678, 0x33, 0x246, STACK + 0x800, 0x2b];
            for (i, value) in slots.into_iter().enumerate() {
                mem.w64(frame + 8 * i as u64, value).unwrap();
            }
            virtual_unwind(&mem, 0, &f, &mut ctx).unwrap();
            assert_eq!((ctx.pc(), ctx.sp()), (slots[0], slots[3]));
            assert_eq!(ctx.flags_register(), slots[2] as u32);
            let bytes = ctx.bytes();
            use crate::user::windows::context::x64;
            assert_eq!(
                u16::from_le_bytes(bytes[x64::SEG_CS..x64::SEG_CS + 2].try_into().unwrap()),
                0x33
            );
            assert_eq!(
                u16::from_le_bytes(bytes[x64::SEG_SS..x64::SEG_SS + 2].try_into().unwrap()),
                0x2b
            );
        }
    }
    #[test]
    fn x64_machine_frame_late_slot_fault_is_transactional() {
        let (mem, f, mut ctx) = setup(&[1, 1, 1, 0, 1, 10], 32, STACK + PAGE_SIZE - 32);
        mem.w64(ctx.sp(), 0x1234).unwrap();
        mem.w64(ctx.sp() + 24, STACK + 0x800).unwrap();
        let before = ctx.clone();
        let fault = virtual_unwind(&mem, 0, &f, &mut ctx).unwrap_err();
        assert_eq!(fault.addr, STACK + PAGE_SIZE);
        assert_eq!(ctx, before);
    }
}
