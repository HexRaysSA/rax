//! EVEX gather, scatter, and VSIB prefetch execution.
//!
//! Intel SDM 086, Vol. 2A Tables 2-38/2-63 and Vol. 2C gather/scatter
//! instruction descriptions define completion masks and right-to-left fault
//! delivery. Process lanes from least to most significant, preserving each
//! completed lane across a later fault. Unused destination and mask bits are
//! cleared only on successful completion; mixed-width gather also permits this
//! ordering. Execution uses O(KL) time and O(1) auxiliary space (64-byte vectors).

use super::*;

#[cfg(test)]
#[path = "avx512_vsib_smir_tests.rs"]
mod vsib_smir_tests;
#[cfg(test)]
#[path = "avx512_vsib_tests.rs"]
mod vsib_tests;

struct EvexVsib {
    reg: u8,
    subop: u8,
    index: u8,
    /// Base plus displacement, before effective-address truncation or segment addition.
    base: u64,
    scale: u64,
    address_32: bool,
    segment_base: u64,
}

fn decode_evex_vsib(
    vcpu: &X86_64Vcpu,
    ctx: &mut InsnContext,
    evex: &crate::isa::x86_64::cpu::EvexPrefix,
    disp8_scale: usize,
) -> Result<EvexVsib> {
    let modrm = ctx.consume_u8()?;
    let mod_bits = modrm >> 6;
    if mod_bits == 3 {
        return Err(Error::Emulator(
            "EVEX VSIB requires memory operand".to_string(),
        ));
    }
    if modrm & 7 != 4 {
        return Err(Error::Emulator("EVEX VSIB requires SIB byte".to_string()));
    }

    let sib = ctx.consume_u8()?;
    let scale = 1u64 << (sib >> 6);
    let index = ((sib >> 3) & 7)
        | if vcpu.sregs.cs.l && !evex.x { 8 } else { 0 }
        | if !evex.v_prime { 16 } else { 0 };
    let raw_base = sib & 7;
    // In mod=00, SIB.base=101 names disp32 without a base, irrespective of B3/B4.
    let no_base = mod_bits == 0 && raw_base == 5;
    let base_reg =
        raw_base | if vcpu.sregs.cs.l && !evex.b { 8 } else { 0 } | if evex.b4 { 16 } else { 0 };
    let address_32 = !vcpu.sregs.cs.l || ctx.address_size_override;
    let base = if no_base {
        0
    } else {
        vcpu.get_reg(base_reg, if address_32 { 4 } else { 8 })
    };
    let displacement = match mod_bits {
        0 if no_base => i64::from(ctx.consume_u32()? as i32),
        1 => i64::from(ctx.consume_u8()? as i8) * disp8_scale as i64,
        2 => i64::from(ctx.consume_u32()? as i32),
        _ => 0,
    };

    let segment_base = if vcpu.sregs.cs.l {
        // Long mode ignores DS/ES/SS/CS bases, including explicit overrides.
        match ctx.segment_override {
            Some(0x64) => vcpu.sregs.fs.base,
            Some(0x65) => vcpu.sregs.gs.base,
            _ => 0,
        }
    } else {
        match ctx.segment_override {
            Some(0x26) => vcpu.sregs.es.base,
            Some(0x2E) => vcpu.sregs.cs.base,
            Some(0x36) => vcpu.sregs.ss.base,
            Some(0x3E) => vcpu.sregs.ds.base,
            Some(0x64) => vcpu.sregs.fs.base,
            Some(0x65) => vcpu.sregs.gs.base,
            _ if !no_base && matches!(raw_base, 4 | 5) => vcpu.sregs.ss.base,
            _ => vcpu.sregs.ds.base,
        }
    };

    Ok(EvexVsib {
        reg: if vcpu.sregs.cs.l {
            evex_reg_vec(evex, (modrm >> 3) & 7)
        } else {
            (modrm >> 3) & 7
        },
        subop: (modrm >> 3) & 7,
        index,
        base: base.wrapping_add(displacement as u64),
        scale,
        address_32,
        segment_base,
    })
}

fn invalid_evex_vsib_encoding(
    vcpu: &X86_64Vcpu,
    ctx: &InsnContext,
    evex: &crate::isa::x86_64::cpu::EvexPrefix,
) -> Result<bool> {
    // Type E12 rejects 16-bit effective addresses. In a non-64-bit code
    // segment CS.D selects the default, and 67 inverts it; V' must remain one.
    let address_16 = !vcpu.sregs.cs.l && vcpu.sregs.cs.db == ctx.address_size_override;
    if evex.aaa == 0
        || evex.z
        || evex.broadcast
        || evex.vvvv != 0xF
        || evex.ll == 3
        || address_16
        || (!vcpu.sregs.cs.l && !evex.v_prime)
    {
        return Ok(true);
    }

    let modrm = ctx.peek_u8()?;
    if (modrm >> 6) == 3 || (modrm & 7) != 4 {
        return Ok(true);
    }
    // APX 355828-007US §3.1.2.3.3: an actual R16-R31 base requires
    // APX-enabled 64-bit mode, even with a zero mask. B4 is ignored for
    // mod=00/base=101; X4 never selects a VSIB vector index.
    let invalid_egpr_base = evex.b4
        && (!vcpu.apx_enabled() || !vcpu.sregs.cs.l)
        && ctx.bytes[..ctx.bytes_len]
            .get(ctx.cursor + 1)
            .is_some_and(|sib| modrm >> 6 != 0 || sib & 7 != 5);
    Ok(invalid_egpr_base)
}

fn evex_vsib_layout(opcode: u8, evex_w: bool, ll: u8) -> (usize, usize, usize, usize, usize) {
    let vl_bytes = vl_bytes_of(ll);
    let index_size = if opcode & 1 == 0 { 4 } else { 8 };
    let data_size = if evex_w { 8 } else { 4 };
    let num_elems = vl_bytes / index_size.max(data_size);
    let data_bytes = num_elems * data_size;
    let index_bytes = num_elems * index_size;
    (index_size, data_size, num_elems, index_bytes, data_bytes)
}

fn evex_vsib_lane_addr(
    vsib: &EvexVsib,
    index_bytes: &[u8; 64],
    lane: usize,
    index_size: usize,
) -> u64 {
    let index = if index_size == 4 {
        i64::from(read_lane_u64(index_bytes, lane, 4) as u32 as i32) as u64
    } else {
        read_lane_u64(index_bytes, lane, 8)
    };
    // Two's-complement modulo arithmetic preserves sign extension and index
    // scaling, including qword overflow. Truncate the complete effective
    // address before adding FS/GS (or the protected-mode segment base).
    let effective = vsib.base.wrapping_add(index.wrapping_mul(vsib.scale));
    let effective = if vsib.address_32 {
        u64::from(effective as u32)
    } else {
        effective
    };
    vsib.segment_base.wrapping_add(effective)
}

/// EVEX VGATHER*/VPGATHER*: masked VSIB gather into a vector destination.
pub fn evex_gather(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX gather requires EVEX prefix".to_string()))?;
    if invalid_evex_vsib_encoding(vcpu, ctx, &evex)? {
        return vcpu.inject_undefined_instruction();
    }

    let (index_size, data_size, num_elems, index_bytes_len, data_bytes) =
        evex_vsib_layout(opcode, evex.w, evex.ll);
    let vsib = decode_evex_vsib(vcpu, ctx, &evex, data_size)?;
    if vsib.reg == vsib.index {
        return vcpu.inject_undefined_instruction();
    }
    let index_bytes = read_reg_bytes(vcpu, vsib.index, index_bytes_len.max(16));
    // Preserve all 512 destination bits until the instruction completes. Each
    // successful lane is visible before any subsequent memory helper can fault.
    let mut result = read_reg_bytes(vcpu, vsib.reg, 64);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mask_reg = usize::from(evex.aaa);
    for lane in 0..num_elems {
        if (mask >> lane) & 1 == 0 {
            continue;
        }
        let addr = evex_vsib_lane_addr(&vsib, &index_bytes, lane, index_size);
        let value = vcpu.read_mem(addr, data_size as u8)?;
        write_lane_bits(&mut result, lane, data_size, value);
        write_vec_vl(vcpu, vsib.reg, 64, &result);
        vcpu.regs.k[mask_reg] &= !(1u64 << lane);
    }

    // QD/QPS with 128-bit indices has only eight bytes of data, not a full
    // XMM result. Clear its unused high 64 bits as well as all upper vectors.
    result[data_bytes..].fill(0);
    write_vec_vl(vcpu, vsib.reg, 64, &result);
    vcpu.regs.k[mask_reg] = 0;
    vcpu.regs.rip = vcpu.regs.rip.wrapping_add(ctx.cursor as u64);
    Ok(None)
}

/// EVEX VSCATTER*/VPSCATTER*: masked VSIB scatter from a vector source.
pub fn evex_scatter(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX scatter requires EVEX prefix".to_string()))?;
    if invalid_evex_vsib_encoding(vcpu, ctx, &evex)? {
        return vcpu.inject_undefined_instruction();
    }

    let (index_size, data_size, num_elems, index_bytes_len, data_bytes) =
        evex_vsib_layout(opcode, evex.w, evex.ll);
    let vsib = decode_evex_vsib(vcpu, ctx, &evex, data_size)?;
    // Source/index alias is legal for scatter. Snapshot both interpretations
    // before the first store; the instruction modifies neither vector register.
    let index_bytes = read_reg_bytes(vcpu, vsib.index, index_bytes_len.max(16));
    let src_bytes = read_reg_bytes(vcpu, vsib.reg, data_bytes.max(16));
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mask_reg = usize::from(evex.aaa);
    for lane in 0..num_elems {
        if (mask >> lane) & 1 == 0 {
            continue;
        }
        let addr = evex_vsib_lane_addr(&vsib, &index_bytes, lane, index_size);
        let value = read_lane_u64(&src_bytes, lane, data_size);
        vcpu.write_mem(addr, value, data_size as u8)?;
        // A later fault must not cause an already completed store to execute
        // again on restart. Keep every other mask bit, including unused bits.
        vcpu.regs.k[mask_reg] &= !(1u64 << lane);
    }

    vcpu.regs.k[mask_reg] = 0;
    vcpu.regs.rip = vcpu.regs.rip.wrapping_add(ctx.cursor as u64);
    Ok(None)
}

/// EVEX gather/scatter prefetch forms: decode VSIB and clear the mask, but do
/// not perform a data access. Prefetch is architecturally non-faulting here.
pub fn evex_vsib_prefetch(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX VSIB prefetch requires EVEX prefix".to_string()))?;
    if invalid_evex_vsib_encoding(vcpu, ctx, &evex)? {
        return vcpu.inject_undefined_instruction();
    }

    let (_, data_size, _, _, _) = evex_vsib_layout(opcode, evex.w, evex.ll);
    let vsib = decode_evex_vsib(vcpu, ctx, &evex, data_size)?;
    if !matches!(vsib.subop, 1 | 2 | 5 | 6) {
        return vcpu.inject_undefined_instruction();
    }

    vcpu.regs.k[evex.aaa as usize] = 0;
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}
