//! Stack frame instructions: ENTER, LEAVE, BOUND, and EVEX dispatch.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{EvexPrefix, InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute::system::is_canonical_48;
use crate::isa::x86_64::flags;

const CR0_AM: u64 = 1 << 18;

fn frame_op_size(vcpu: &X86_64Vcpu, ctx: &InsnContext) -> u8 {
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0;
    let in_64bit_mode = in_long_mode && vcpu.sregs.cs.l;

    if in_64bit_mode {
        if ctx.any_rex_w() || !ctx.operand_size_override {
            8
        } else {
            2
        }
    } else {
        let default_16bit = !vcpu.sregs.cs.db;
        let is_16bit = default_16bit ^ ctx.operand_size_override;
        if is_16bit { 2 } else { 4 }
    }
}

fn wrapping_stack_sub(value: u64, delta: u64, address_size: u8) -> u64 {
    match address_size {
        2 => u64::from((value as u16).wrapping_sub(delta as u16)),
        4 => u64::from((value as u32).wrapping_sub(delta as u32)),
        8 => value.wrapping_sub(delta),
        _ => unreachable!("validated x86 stack-address size"),
    }
}

fn stack_linear_address(vcpu: &X86_64Vcpu, offset: u64) -> u64 {
    if vcpu.sregs.cs.l {
        offset
    } else {
        vcpu.sregs.ss.base.wrapping_add(offset)
    }
}

fn long_mode_stack_range_is_canonical(vcpu: &X86_64Vcpu, address: u64, size: u8) -> bool {
    !vcpu.sregs.cs.l
        || address
            .checked_add(u64::from(size) - 1)
            .is_some_and(|last| is_canonical_48(address) && is_canonical_48(last))
}

/// ENTER imm16, imm8 (0xC8) - Create stack frame
pub fn enter(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let alloc_size = ctx.consume_u16()? as u64;
    let nesting_level = ctx.consume_u8()? & 0x1F;
    let op_size = frame_op_size(vcpu, ctx);
    let delta = op_size as u64;
    let stack_address_size = if vcpu.sregs.cs.l {
        8
    } else if vcpu.sregs.ss.db {
        4
    } else {
        2
    };
    let old_rbp = vcpu.regs.rbp;
    let old_bp = vcpu.get_reg(5, op_size);
    let mut stack_pointer =
        wrapping_stack_sub(vcpu.stack_pointer_offset(), delta, stack_address_size);
    let mut stack_address = stack_linear_address(vcpu, stack_pointer);
    if !long_mode_stack_range_is_canonical(vcpu, stack_address, op_size) {
        vcpu.inject_exception(12, Some(0))?;
        return Ok(None);
    }
    vcpu.write_mem(stack_address, old_bp, op_size)?;
    let frame_ptr = stack_pointer;

    let mut parent_offset = match stack_address_size {
        2 => old_rbp & 0xFFFF,
        4 => old_rbp & 0xFFFF_FFFF,
        8 => old_rbp,
        _ => unreachable!("validated x86 stack-address size"),
    };
    for _ in 1..nesting_level {
        parent_offset = wrapping_stack_sub(parent_offset, delta, stack_address_size);
        let parent_address = stack_linear_address(vcpu, parent_offset);
        if !long_mode_stack_range_is_canonical(vcpu, parent_address, op_size) {
            vcpu.inject_exception(12, Some(0))?;
            return Ok(None);
        }
        let parent = vcpu.read_mem(parent_address, op_size)?;
        stack_pointer = wrapping_stack_sub(stack_pointer, delta, stack_address_size);
        stack_address = stack_linear_address(vcpu, stack_pointer);
        if !long_mode_stack_range_is_canonical(vcpu, stack_address, op_size) {
            vcpu.inject_exception(12, Some(0))?;
            return Ok(None);
        }
        vcpu.write_mem(stack_address, parent, op_size)?;
    }
    if nesting_level != 0 {
        stack_pointer = wrapping_stack_sub(stack_pointer, delta, stack_address_size);
        stack_address = stack_linear_address(vcpu, stack_pointer);
        if !long_mode_stack_range_is_canonical(vcpu, stack_address, op_size) {
            vcpu.inject_exception(12, Some(0))?;
            return Ok(None);
        }
        vcpu.write_mem(stack_address, frame_ptr, op_size)?;
    }

    let final_sp = wrapping_stack_sub(stack_pointer, alloc_size, stack_address_size);
    let final_address = stack_linear_address(vcpu, final_sp);
    if !long_mode_stack_range_is_canonical(vcpu, final_address, 1) {
        vcpu.inject_exception(12, Some(0))?;
        return Ok(None);
    }
    // Intel SDM Vol. 3C §31.4.4 specifies a write check for the byte at the
    // final stack pointer without an actual data write.
    vcpu.mmu
        .preflight_write_range(final_address, 1, &vcpu.sregs)?;

    vcpu.set_reg(5, frame_ptr, op_size);
    vcpu.set_stack_pointer_offset(final_sp);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// LEAVE (0xC9)
pub fn leave(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = frame_op_size(vcpu, ctx);
    let old_rsp = vcpu.regs.rsp;
    vcpu.set_stack_pointer_offset(vcpu.regs.rbp);
    let address = vcpu.stack_pointer_offset();
    if !long_mode_stack_range_is_canonical(vcpu, address, op_size) {
        vcpu.regs.rsp = old_rsp;
        vcpu.inject_exception(12, Some(0))?;
        return Ok(None);
    }
    if vcpu.sregs.cs.l
        && address & (u64::from(op_size) - 1) != 0
        && vcpu.sregs.cr0 & CR0_AM != 0
        && vcpu.regs.rflags & flags::bits::AC != 0
        && vcpu.sregs.cs.selector & 3 == 3
    {
        vcpu.regs.rsp = old_rsp;
        vcpu.inject_exception(17, Some(0))?;
        return Ok(None);
    }
    let popped = match op_size {
        2 => vcpu.pop16().map(u64::from),
        4 => vcpu.pop32().map(u64::from),
        8 => vcpu.pop64(),
        _ => unreachable!(),
    };
    let value = match popped {
        Ok(value) => value,
        Err(error) => {
            vcpu.regs.rsp = old_rsp;
            return Err(error);
        }
    };
    vcpu.set_reg(5, value, op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

fn evex_vsib_memory_extensions(ctx: &InsnContext, map: u8, pp: u8, opcode_offset: usize) -> bool {
    let bytes = &ctx.bytes[..ctx.bytes_len];
    map == 2
        && pp == 1
        && bytes
            .get(opcode_offset)
            .is_some_and(|opcode| matches!(opcode, 0x90..=0x93 | 0xA0..=0xA3))
        && bytes
            .get(opcode_offset + 1)
            .is_some_and(|modrm| modrm >> 6 != 3 && modrm & 7 == 4)
}

fn looks_like_evex_prefix(vcpu: &X86_64Vcpu, ctx: &InsnContext) -> bool {
    if ctx.cursor + 3 > ctx.bytes_len {
        return false;
    }

    let p0 = ctx.bytes[ctx.cursor];
    let p1 = ctx.bytes[ctx.cursor + 1];
    let mm = p0 & 0x07;
    let promoted_cmpccxadd = mm == 2
        && ctx
            .bytes
            .get(ctx.cursor + 3)
            .copied()
            .is_some_and(|opcode| matches!(opcode, 0xE0..=0xEF));
    let apx_mode = (mm == 4 && vcpu.apx_enabled()) || promoted_cmpccxadd;
    let vsib_memory_extensions = evex_vsib_memory_extensions(ctx, mm, p1 & 3, ctx.cursor + 3);
    let supported_map = matches!(mm, 1 | 2 | 3 | 5 | 6) || apx_mode;

    supported_map
        && ((p0 & 0x08) == 0 || apx_mode || vsib_memory_extensions)
        && ((p1 & 0x04) != 0 || apx_mode || vsib_memory_extensions)
}

/// BOUND (legacy/compatibility) or EVEX prefix (0x62)
pub fn bound_or_evex(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    // Check if we're in 64-bit mode by looking at EFER.LMA AND CS.L.
    // In 64-bit mode BOUND is invalid and 0x62 is always an EVEX/APX prefix.
    // In compatibility/legacy modes, valid EVEX payloads still decode as EVEX;
    // otherwise 0x62 remains the legacy BOUND opcode.
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0; // EFER.LMA = bit 10
    let in_64bit_mode = in_long_mode && vcpu.sregs.cs.l;

    if in_64bit_mode || looks_like_evex_prefix(vcpu, ctx) {
        // Address-size and segment overrides are the only legacy prefixes that
        // may precede VEX/EVEX (including APX extended EVEX). Inspect the raw
        // prefix bytes: the generic scanner intentionally applies x86's
        // last-REX rule, so a later 67H or segment override can clear ctx.rex and
        // must not hide an earlier forbidden REX. Reject every other legacy byte
        // before decoding the EVEX payload or allowing stale extension state to
        // reach decode_modrm().
        // RIP is left on the faulting instruction (advanced only on retire), so the
        // fault points at it.
        let opcode_offset = ctx.cursor.saturating_sub(1).min(ctx.bytes_len);
        let has_forbidden_legacy_prefix = ctx.bytes[..opcode_offset]
            .iter()
            .any(|byte| !matches!(byte, 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x67));
        if has_forbidden_legacy_prefix || ctx.has_any_rex() {
            vcpu.inject_exception(6, None)?; // #UD = vector 6
            return Ok(None);
        }

        // Decode 3-byte EVEX payload.
        let p0 = ctx.consume_u8()?;
        let p1 = ctx.consume_u8()?;
        let p2 = ctx.consume_u8()?;

        let mm = p0 & 0x07; // mm field (opcode map)
        let promoted_cmpccxadd = mm == 2
            && ctx
                .bytes
                .get(ctx.cursor)
                .copied()
                .is_some_and(|opcode| matches!(opcode, 0xE0..=0xEF));
        let apx_mode = mm == 4 || promoted_cmpccxadd;
        let vsib_memory_extensions = evex_vsib_memory_extensions(ctx, mm, p1 & 3, ctx.cursor);

        // Validate EVEX format:
        // P0 bit 3 is fixed zero for standard EVEX, but APX MAP4 and promoted
        // CMPccXADD reuse it as B4. P1 bit 2 is fixed one for standard EVEX,
        // but those APX encodings reuse it as X4. Existing EVEX VSIB gather/
        // scatter memory forms also accept B4; their unused X4 is ignored.
        // The VSIB handler checks APX enablement only for an actual EGPR base.
        if (((p0 & 0x08) != 0 || (p1 & 0x04) == 0) && !apx_mode) && !vsib_memory_extensions {
            return vcpu.inject_undefined_instruction();
        }

        // Decode P0: R X B R' 0 m m m
        let r = (p0 & 0x80) != 0; // R bit (inverted)
        let x = (p0 & 0x40) != 0; // X bit (inverted)
        let b = (p0 & 0x20) != 0; // B bit (inverted)
        let r_prime = (p0 & 0x10) != 0; // R' bit (inverted)

        // Decode P1: W v v v v 1 p p
        let w = (p1 & 0x80) != 0; // W bit
        let vvvv = (p1 >> 3) & 0x0F; // vvvv field (inverted)
        let pp = p1 & 0x03; // pp field (implied prefix)

        // Decode P2: z L' L b V' a a a
        let z = (p2 & 0x80) != 0; // z bit (zeroing)
        let ll = (p2 >> 5) & 0x03; // L'L field
        let broadcast = (p2 & 0x10) != 0; // b bit
        let v_prime = (p2 & 0x08) != 0; // V' bit (inverted)
        let aaa = p2 & 0x07; // aaa field (opmask)

        // For APX mode, including promoted CMPccXADD in map 2, decode
        // additional bits differently:
        // - P2[2] becomes NF (No Flags)
        // - P2[4] (broadcast bit) becomes ND (New Data Destination)
        // - P0[3] becomes B4, the high r/m/base extension bit for EGPR
        // - P1[2] becomes X4, the inverted high SIB index extension bit
        let (nf, nd, b4, x4) = if apx_mode {
            // In APX mode:
            // NF is encoded in P2 bit 2 and is non-inverted.
            // ND is in P2 bit 4 (broadcast position)
            // B4 is encoded in P0 bit 3 and is non-inverted.
            // X4 is encoded in P1 bit 2 and is inverted like EVEX.X.
            let nf_bit = (p2 & 0x04) != 0;
            let nd_bit = broadcast; // ND uses broadcast position when mm=4
            let b4_bit = (p0 & 0x08) != 0;
            let x4_bit = (p1 & 0x04) != 0;
            (nf_bit, nd_bit, b4_bit, x4_bit)
        } else if vsib_memory_extensions {
            // APX 355828-007US §3.1.2.3.3/Table 3.3: BASE uses B4/B3,
            // whereas VIDX uses V4/X3, not X4. Preserve ordinary EVEX
            // opmask/broadcast meanings rather than enabling NF or ND.
            (false, false, (p0 & 0x08) != 0, (p1 & 0x04) != 0)
        } else {
            (false, false, false, false)
        };

        // Store EVEX prefix in context
        ctx.evex = Some(EvexPrefix {
            r,
            x,
            b,
            r_prime,
            mm,
            w,
            vvvv,
            pp,
            z,
            ll,
            broadcast,
            v_prime,
            aaa,
            // APX-specific fields
            b4,
            x4,
            nd,
            nf,
            apx_mode,
        });

        // Set operand size based on W bit
        ctx.op_size = if w { 8 } else { 4 };

        // Set implied prefix flags based on pp
        match pp {
            1 => ctx.operand_size_override = true, // 66
            2 => ctx.rep_prefix = Some(0xF3),      // F3
            3 => ctx.rep_prefix = Some(0xF2),      // F2
            _ => {}
        }

        // Dispatch to EVEX instruction handler
        return vcpu.execute_evex(ctx, mm);
    } else {
        // In 32-bit/compatibility mode, this is BOUND (bounds check)
        let modrm_start = ctx.cursor;
        let modrm = ctx.consume_u8()?;
        let reg = (modrm >> 3) & 7;

        // BOUND requires memory operand (mod != 11)
        if modrm >> 6 == 3 {
            return vcpu.inject_undefined_instruction();
        }

        let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
        ctx.cursor = modrm_start + 1 + extra;

        // Determine operand size (16-bit or 32-bit)
        // CS.D (db flag) determines default: D=0 means 16-bit default, D=1 means 32-bit default
        let default_16bit = !vcpu.sregs.cs.db;
        let is_16bit = default_16bit ^ ctx.operand_size_override;

        // Read the index from the register
        // Read bounds from memory: [addr] = lower, [addr+size] = upper
        if is_16bit {
            let index = vcpu.get_reg(reg, 2) as i16;
            let lower = vcpu.read_mem16(addr)? as i16;
            let upper = vcpu.read_mem16(addr + 2)? as i16;

            // Check: lower <= index <= upper
            if index < lower || index > upper {
                vcpu.inject_exception(5, None)?;
                return Ok(None);
            }
        } else {
            let index = vcpu.get_reg(reg, 4) as i32;
            let lower = vcpu.read_mem32(addr)? as i32;
            let upper = vcpu.read_mem32(addr + 4)? as i32;

            // Check: lower <= index <= upper
            if index < lower || index > upper {
                vcpu.inject_exception(5, None)?;
                return Ok(None);
            }
        }

        vcpu.regs.rip += ctx.cursor as u64;
    }
    Ok(None)
}
