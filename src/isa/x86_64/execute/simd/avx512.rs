//! AVX-512 SIMD instruction implementations (EVEX-encoded).

use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;

use super::gfni::gf_inv;
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute::crypto::aes;

#[path = "avx512_fp_special.rs"]
mod fp_special;
pub use fp_special::{evex_fixupimm, evex_fp_unary_math};
#[path = "avx512_fp_ternary_math.rs"]
mod fp_ternary_math;
pub use fp_ternary_math::{FpTernaryMathOp, evex_fp_ternary_math};

#[path = "avx512_vsib.rs"]
mod vsib;
pub use vsib::{evex_gather, evex_scatter, evex_vsib_prefetch};

/// Helper to get ZMM register value (all 8 qwords)
fn get_zmm(vcpu: &X86_64Vcpu, reg: u8) -> [u64; 8] {
    if reg < 16 {
        // ZMM0-15: composed of xmm[0..2], ymm_high[0..2], zmm_high[0..4]
        let r = reg as usize;
        [
            vcpu.regs.xmm[r][0],
            vcpu.regs.xmm[r][1],
            vcpu.regs.ymm_high[r][0],
            vcpu.regs.ymm_high[r][1],
            vcpu.regs.zmm_high[r][0],
            vcpu.regs.zmm_high[r][1],
            vcpu.regs.zmm_high[r][2],
            vcpu.regs.zmm_high[r][3],
        ]
    } else {
        // ZMM16-31: stored in zmm_ext
        let r = (reg - 16) as usize;
        vcpu.regs.zmm_ext[r]
    }
}

/// Helper to set ZMM register value (all 8 qwords)
fn set_zmm(vcpu: &mut X86_64Vcpu, reg: u8, val: [u64; 8]) {
    if reg < 16 {
        let r = reg as usize;
        vcpu.regs.xmm[r][0] = val[0];
        vcpu.regs.xmm[r][1] = val[1];
        vcpu.regs.ymm_high[r][0] = val[2];
        vcpu.regs.ymm_high[r][1] = val[3];
        vcpu.regs.zmm_high[r][0] = val[4];
        vcpu.regs.zmm_high[r][1] = val[5];
        vcpu.regs.zmm_high[r][2] = val[6];
        vcpu.regs.zmm_high[r][3] = val[7];
    } else {
        let r = (reg - 16) as usize;
        vcpu.regs.zmm_ext[r] = val;
    }
}

/// Helper to get XMM register value (2 qwords)
fn get_xmm(vcpu: &X86_64Vcpu, reg: u8) -> [u64; 2] {
    if reg < 16 {
        vcpu.regs.xmm[reg as usize]
    } else {
        let r = (reg - 16) as usize;
        [vcpu.regs.zmm_ext[r][0], vcpu.regs.zmm_ext[r][1]]
    }
}

/// Helper to set XMM register value (2 qwords), zeroing upper bits
fn set_xmm_zero_upper(vcpu: &mut X86_64Vcpu, reg: u8, val: [u64; 2]) {
    if reg < 16 {
        let r = reg as usize;
        vcpu.regs.xmm[r] = val;
        vcpu.regs.ymm_high[r] = [0, 0];
        vcpu.regs.zmm_high[r] = [0, 0, 0, 0];
    } else {
        let r = (reg - 16) as usize;
        vcpu.regs.zmm_ext[r] = [val[0], val[1], 0, 0, 0, 0, 0, 0];
    }
}

/// Helper to get YMM register value (4 qwords)
fn get_ymm(vcpu: &X86_64Vcpu, reg: u8) -> [u64; 4] {
    if reg < 16 {
        let r = reg as usize;
        [
            vcpu.regs.xmm[r][0],
            vcpu.regs.xmm[r][1],
            vcpu.regs.ymm_high[r][0],
            vcpu.regs.ymm_high[r][1],
        ]
    } else {
        let r = (reg - 16) as usize;
        [
            vcpu.regs.zmm_ext[r][0],
            vcpu.regs.zmm_ext[r][1],
            vcpu.regs.zmm_ext[r][2],
            vcpu.regs.zmm_ext[r][3],
        ]
    }
}

/// Helper to set YMM register value (4 qwords), zeroing upper bits
fn set_ymm_zero_upper(vcpu: &mut X86_64Vcpu, reg: u8, val: [u64; 4]) {
    if reg < 16 {
        let r = reg as usize;
        vcpu.regs.xmm[r][0] = val[0];
        vcpu.regs.xmm[r][1] = val[1];
        vcpu.regs.ymm_high[r][0] = val[2];
        vcpu.regs.ymm_high[r][1] = val[3];
        vcpu.regs.zmm_high[r] = [0, 0, 0, 0];
    } else {
        let r = (reg - 16) as usize;
        vcpu.regs.zmm_ext[r] = [val[0], val[1], val[2], val[3], 0, 0, 0, 0];
    }
}

fn evex_vl_bytes(ll: u8) -> usize {
    match ll {
        0 => 16,
        1 => 32,
        2 => 64,
        _ => 16,
    }
}

pub(super) fn evex_mask(vcpu: &X86_64Vcpu, aaa: u8, num_elems: usize) -> u64 {
    let full_mask = if num_elems == 64 {
        u64::MAX
    } else {
        (1u64 << num_elems) - 1
    };
    if aaa == 0 {
        full_mask
    } else {
        vcpu.regs.k[aaa as usize] & full_mask
    }
}

pub(super) fn read_reg_bytes(vcpu: &X86_64Vcpu, reg: u8, vl_bytes: usize) -> [u8; 64] {
    let mut data = [0u8; 64];
    match vl_bytes {
        16 => {
            let vals = get_xmm(vcpu, reg);
            for i in 0..2 {
                let start = i * 8;
                data[start..start + 8].copy_from_slice(&vals[i].to_le_bytes());
            }
        }
        32 => {
            let vals = get_ymm(vcpu, reg);
            for i in 0..4 {
                let start = i * 8;
                data[start..start + 8].copy_from_slice(&vals[i].to_le_bytes());
            }
        }
        64 => {
            let vals = get_zmm(vcpu, reg);
            for i in 0..8 {
                let start = i * 8;
                data[start..start + 8].copy_from_slice(&vals[i].to_le_bytes());
            }
        }
        _ => {}
    }
    data
}

fn write_reg_bytes(vcpu: &mut X86_64Vcpu, reg: u8, vl_bytes: usize, data: &[u8; 64]) {
    match vl_bytes {
        16 => {
            let mut vals = [0u64; 2];
            for i in 0..2 {
                let start = i * 8;
                vals[i] = u64::from_le_bytes([
                    data[start],
                    data[start + 1],
                    data[start + 2],
                    data[start + 3],
                    data[start + 4],
                    data[start + 5],
                    data[start + 6],
                    data[start + 7],
                ]);
            }
            set_xmm_zero_upper(vcpu, reg, vals);
        }
        32 => {
            let mut vals = [0u64; 4];
            for i in 0..4 {
                let start = i * 8;
                vals[i] = u64::from_le_bytes([
                    data[start],
                    data[start + 1],
                    data[start + 2],
                    data[start + 3],
                    data[start + 4],
                    data[start + 5],
                    data[start + 6],
                    data[start + 7],
                ]);
            }
            set_ymm_zero_upper(vcpu, reg, vals);
        }
        64 => {
            let mut vals = [0u64; 8];
            for i in 0..8 {
                let start = i * 8;
                vals[i] = u64::from_le_bytes([
                    data[start],
                    data[start + 1],
                    data[start + 2],
                    data[start + 3],
                    data[start + 4],
                    data[start + 5],
                    data[start + 6],
                    data[start + 7],
                ]);
            }
            set_zmm(vcpu, reg, vals);
        }
        _ => {}
    }
}

pub(super) fn load_mem_bytes(
    vcpu: &mut X86_64Vcpu,
    addr: u64,
    elem_size: usize,
    num_elems: usize,
) -> Result<[u8; 64]> {
    let mut data = [0u8; 64];
    for i in 0..num_elems {
        let value = vcpu.read_mem(addr + (i * elem_size) as u64, elem_size as u8)?;
        let start = i * elem_size;
        let bytes = value.to_le_bytes();
        data[start..start + elem_size].copy_from_slice(&bytes[..elem_size]);
    }
    Ok(data)
}

pub(in crate::isa::x86_64) fn evex_scaled_disp8_addr(
    ctx: &InsnContext,
    modrm_start: usize,
    addr: u64,
    scale: usize,
) -> u64 {
    if scale <= 1 || modrm_start >= ctx.bytes_len {
        return addr;
    }

    let modrm = ctx.bytes[modrm_start];
    if modrm >> 6 != 1 {
        return addr;
    }

    let mut disp_idx = modrm_start + 1;
    if modrm & 0x07 == 4 {
        disp_idx += 1;
    }
    if disp_idx >= ctx.bytes_len {
        return addr;
    }

    let disp = ctx.bytes[disp_idx] as i8 as i64;
    let delta = disp.wrapping_mul(scale as i64 - 1);
    (addr as i64).wrapping_add(delta) as u64
}

pub(super) fn store_mem_bytes(
    vcpu: &mut X86_64Vcpu,
    addr: u64,
    elem_size: usize,
    num_elems: usize,
    data: &[u8; 64],
) -> Result<()> {
    for i in 0..num_elems {
        let start = i * elem_size;
        let mut bytes = [0u8; 8];
        bytes[..elem_size].copy_from_slice(&data[start..start + elem_size]);
        let value = u64::from_le_bytes(bytes);
        vcpu.write_mem(addr + (i * elem_size) as u64, value, elem_size as u8)?;
    }
    Ok(())
}

/// VPMULLQ - Multiply Packed Signed Quadword Integers and Store Low Result
/// EVEX.128/256/512.66.0F38.W1 40 /r
///
/// Multiplies packed signed qword integers and stores the low 64 bits
/// of each 128-bit result.
pub fn vpmullq(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VPMULLQ requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    // Calculate full register indices using EVEX extension bits
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src1 = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src2_base = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl = match evex.ll {
        0 => 128,
        1 => 256,
        2 => 512,
        _ => 128,
    };
    let num_elements = vl / 64; // Number of qword elements
    let addr = if is_memory {
        let scale = if evex.broadcast { 8 } else { vl / 8 };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    // Get source 1 register
    let src1_val = get_zmm(vcpu, src1);

    // Get source 2 (register or memory, with broadcast support)
    let src2_val = if is_memory {
        if evex.broadcast {
            // Broadcast single qword to all elements
            let elem = vcpu.read_mem(addr, 8)?;
            [elem, elem, elem, elem, elem, elem, elem, elem]
        } else {
            // Read vector from memory
            let mut val = [0u64; 8];
            for i in 0..num_elements {
                val[i] = vcpu.read_mem(addr + (i as u64) * 8, 8)?;
            }
            val
        }
    } else {
        get_zmm(vcpu, src2_base)
    };

    // Get opmask register value (k0 means no masking)
    let mask = if evex.aaa == 0 {
        0xFF // No masking
    } else {
        vcpu.regs.k[evex.aaa as usize] as u8
    };

    // Get current destination value (for merge-masking)
    let dest_val = get_zmm(vcpu, dest);

    // Perform multiplication
    let mut result = [0u64; 8];
    for i in 0..num_elements {
        let bit = 1 << i;
        if mask & bit != 0 {
            // Multiply and keep low 64 bits
            let a = src1_val[i] as i64;
            let b = src2_val[i] as i64;
            result[i] = a.wrapping_mul(b) as u64;
        } else if evex.z {
            // Zeroing-masking
            result[i] = 0;
        } else {
            // Merge-masking: keep original value
            result[i] = dest_val[i];
        }
    }

    // Zero upper elements beyond vector length
    for i in num_elements..8 {
        result[i] = 0;
    }

    // Write result based on vector length
    match vl {
        128 => set_xmm_zero_upper(vcpu, dest, [result[0], result[1]]),
        256 => set_ymm_zero_upper(vcpu, dest, [result[0], result[1], result[2], result[3]]),
        512 => set_zmm(vcpu, dest, result),
        _ => {}
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// VPMULLD (EVEX) - Multiply Packed Signed Dword Integers and Store Low Result
/// EVEX.128/256/512.66.0F38.W0 40 /r
pub fn vpmulld_evex(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VPMULLD requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    // Calculate full register indices
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src1 = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src2_base = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl = match evex.ll {
        0 => 128,
        1 => 256,
        2 => 512,
        _ => 128,
    };
    let num_elements = vl / 32; // Number of dword elements
    let addr = if is_memory {
        let scale = if evex.broadcast { 4 } else { vl / 8 };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    // Get source 1 register
    let src1_val = get_zmm(vcpu, src1);

    // Get source 2 (register or memory, with broadcast support)
    let src2_val = if is_memory {
        if evex.broadcast {
            // Broadcast single dword to all elements
            let elem = vcpu.read_mem(addr, 4)? as u32;
            let mut val = [0u64; 8];
            for i in 0..8 {
                val[i] = ((elem as u64) << 32) | (elem as u64);
            }
            val
        } else {
            // Read vector from memory
            let mut val = [0u64; 8];
            for i in 0..(num_elements / 2) {
                val[i] = vcpu.read_mem(addr + (i as u64) * 8, 8)?;
            }
            val
        }
    } else {
        get_zmm(vcpu, src2_base)
    };

    // Get opmask register value
    let mask = if evex.aaa == 0 {
        0xFFFF // No masking
    } else {
        vcpu.regs.k[evex.aaa as usize] as u16
    };

    // Get current destination value
    let dest_val = get_zmm(vcpu, dest);

    // Perform multiplication on dwords
    let mut result = [0u64; 8];
    for qword_idx in 0..(num_elements / 2) {
        let src1_qword = src1_val[qword_idx];
        let src2_qword = src2_val[qword_idx];

        // Process two dwords per qword
        for dword_idx in 0..2 {
            let elem_idx = qword_idx * 2 + dword_idx;
            let bit = 1 << elem_idx;
            let shift = dword_idx * 32;

            if mask & bit != 0 {
                let a = ((src1_qword >> shift) & 0xFFFFFFFF) as i32;
                let b = ((src2_qword >> shift) & 0xFFFFFFFF) as i32;
                let prod = a.wrapping_mul(b) as u32;
                result[qword_idx] |= (prod as u64) << shift;
            } else if evex.z {
                // Zeroing: leave as 0
            } else {
                // Merge: keep original dword
                // NB: `<<` binds tighter than `&` in Rust, so the mask+shift-back
                // must be parenthesized explicitly.
                result[qword_idx] |= ((dest_val[qword_idx] >> shift) & 0xFFFFFFFF) << shift;
            }
        }
    }

    // Write result based on vector length
    match vl {
        128 => set_xmm_zero_upper(vcpu, dest, [result[0], result[1]]),
        256 => set_ymm_zero_upper(vcpu, dest, [result[0], result[1], result[2], result[3]]),
        512 => set_zmm(vcpu, dest, result),
        _ => {}
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

pub fn vcompress_evex(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    name: &str,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator(format!("{} requires EVEX prefix", name)))?;

    if evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };

    let src = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let dest = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = evex_vl_bytes(evex.ll);
    if elem_size == 0 || vl_bytes % elem_size != 0 {
        return Err(Error::Emulator(format!("{} invalid element size", name)));
    }
    let num_elems = vl_bytes / elem_size;
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let src_bytes = read_reg_bytes(vcpu, src, vl_bytes);
    let mut out_bytes = [0u8; 64];
    let mut out_count = 0usize;

    for j in 0..num_elems {
        if (mask >> j) & 1 != 0 {
            let src_start = j * elem_size;
            let dst_start = out_count * elem_size;
            out_bytes[dst_start..dst_start + elem_size]
                .copy_from_slice(&src_bytes[src_start..src_start + elem_size]);
            out_count += 1;
        }
    }

    if is_memory {
        if evex.z {
            return vcpu.inject_undefined_instruction();
        }
        store_mem_bytes(vcpu, addr, elem_size, out_count, &out_bytes)?;
    } else {
        let compressed_len = out_count * elem_size;
        if !evex.z && compressed_len < vl_bytes {
            let dest_bytes = read_reg_bytes(vcpu, dest, vl_bytes);
            out_bytes[compressed_len..vl_bytes]
                .copy_from_slice(&dest_bytes[compressed_len..vl_bytes]);
        }
        write_reg_bytes(vcpu, dest, vl_bytes, &out_bytes);
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

pub fn vexpand_evex(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    name: &str,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator(format!("{} requires EVEX prefix", name)))?;

    if evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };

    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = evex_vl_bytes(evex.ll);
    if elem_size == 0 || vl_bytes % elem_size != 0 {
        return Err(Error::Emulator(format!("{} invalid element size", name)));
    }
    let num_elems = vl_bytes / elem_size;
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let src_bytes = if is_memory {
        load_mem_bytes(vcpu, addr, elem_size, num_elems)?
    } else {
        read_reg_bytes(vcpu, src, vl_bytes)
    };

    let mut out_bytes = if evex.z {
        [0u8; 64]
    } else {
        read_reg_bytes(vcpu, dest, vl_bytes)
    };

    let mut src_index = 0usize;
    for j in 0..num_elems {
        let dst_start = j * elem_size;
        if (mask >> j) & 1 != 0 {
            let src_start = src_index * elem_size;
            out_bytes[dst_start..dst_start + elem_size]
                .copy_from_slice(&src_bytes[src_start..src_start + elem_size]);
            src_index += 1;
        } else if evex.z {
            out_bytes[dst_start..dst_start + elem_size].fill(0);
        }
    }

    write_reg_bytes(vcpu, dest, vl_bytes, &out_bytes);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

// ============================================================================
// Broadened AVX-512 EVEX integer / logical / compare / broadcast / move / shift
// coverage with k-mask (merge/zero) handling, VL (128/256/512) upper-zeroing,
// and broadcast for the dword/qword element forms.
// ============================================================================

/// Resolve VL in bytes (16/32/64) from EVEX.L'L.
#[inline]
pub(super) fn vl_bytes_of(ll: u8) -> usize {
    match ll {
        0 => 16,
        1 => 32,
        2 => 64,
        _ => 16,
    }
}

/// Write a result byte-buffer back to the destination vector register with the
/// proper VL upper-zeroing semantics (128/256 zero the unused high bits).
#[inline]
pub(super) fn write_vec_vl(vcpu: &mut X86_64Vcpu, dest: u8, vl_bytes: usize, data: &[u8; 64]) {
    write_reg_bytes(vcpu, dest, vl_bytes, data);
}

/// Decode the three vector operands of a typical EVEX `op dest{k}, src1, src2/m`
/// instruction. Returns (dest, src1, src2 reg, is_memory, addr).
#[inline]
pub(super) fn evex_three_op(
    evex: &crate::isa::x86_64::cpu::EvexPrefix,
    reg: u8,
    rm: u8,
) -> (u8, u8, u8) {
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src1 = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src2 = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };
    (dest, src1, src2)
}

/// Element-wise integer arithmetic/logical operation kind.
#[derive(Clone, Copy)]
pub enum IntOp {
    AddB,
    AddW,
    AddD,
    AddQ,
    AddSatSB,
    AddSatSW,
    AddSatUB,
    AddSatUW,
    SubB,
    SubW,
    SubD,
    SubQ,
    SubSatSB,
    SubSatSW,
    SubSatUB,
    SubSatUW,
    AvgB,
    AvgW,
    MullW,
    MullD,
    MulHighSW,
    MulHighRoundSW,
    MulHighUW,
    MulDQ,
    MulUDQ,
    MaddWD,
    MaddUBSW,
    MinSB,
    MinSW,
    MinSD,
    MinSQ,
    MinUB,
    MinUW,
    MinUD,
    MinUQ,
    MaxSB,
    MaxSW,
    MaxSD,
    MaxSQ,
    MaxUB,
    MaxUW,
    MaxUD,
    MaxUQ,
    And,
    Or,
    Xor,
    Andn,
    Gf2p8MulB,
}

impl IntOp {
    /// Element size in bytes for masking granularity.
    fn elem_size(self, evex_w: bool) -> usize {
        match self {
            IntOp::AddB
            | IntOp::AddSatSB
            | IntOp::AddSatUB
            | IntOp::SubB
            | IntOp::SubSatSB
            | IntOp::SubSatUB
            | IntOp::AvgB
            | IntOp::MinSB
            | IntOp::MinUB
            | IntOp::MaxSB
            | IntOp::MaxUB
            | IntOp::Gf2p8MulB => 1,
            IntOp::AddW
            | IntOp::AddSatSW
            | IntOp::AddSatUW
            | IntOp::SubW
            | IntOp::SubSatSW
            | IntOp::SubSatUW
            | IntOp::AvgW
            | IntOp::MullW
            | IntOp::MulHighSW
            | IntOp::MulHighRoundSW
            | IntOp::MulHighUW
            | IntOp::MaddUBSW
            | IntOp::MinSW
            | IntOp::MinUW
            | IntOp::MaxSW
            | IntOp::MaxUW => 2,
            IntOp::AddD
            | IntOp::SubD
            | IntOp::MullD
            | IntOp::MaddWD
            | IntOp::MinSD
            | IntOp::MinUD
            | IntOp::MaxSD
            | IntOp::MaxUD => 4,
            IntOp::AddQ
            | IntOp::SubQ
            | IntOp::MulDQ
            | IntOp::MulUDQ
            | IntOp::MinSQ
            | IntOp::MinUQ
            | IntOp::MaxSQ
            | IntOp::MaxUQ => 8,
            IntOp::And | IntOp::Or | IntOp::Xor | IntOp::Andn => {
                if evex_w {
                    8
                } else {
                    4
                }
            }
        }
    }

    /// True when this op uses a dword/qword element width and therefore supports
    /// embedded broadcast (`{1toN}`) of a single element from memory.
    fn supports_broadcast(self) -> bool {
        matches!(
            self,
            IntOp::AddD
                | IntOp::SubD
                | IntOp::MullD
                | IntOp::MulDQ
                | IntOp::MulUDQ
                | IntOp::MinSD
                | IntOp::MinSQ
                | IntOp::MinUD
                | IntOp::MinUQ
                | IntOp::MaxSD
                | IntOp::MaxSQ
                | IntOp::MaxUD
                | IntOp::MaxUQ
                | IntOp::And
                | IntOp::Or
                | IntOp::Xor
                | IntOp::Andn
                | IntOp::AddQ
                | IntOp::SubQ
        )
    }
}

fn gf2p8_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

#[inline]
fn gf2p8_affine_byte(matrix: &[u8], input: u8, imm8: u8) -> u8 {
    let mut out = 0u8;
    for i in 0..8 {
        let parity = (matrix[7 - i] & input).count_ones() as u8 & 1;
        out |= (parity ^ ((imm8 >> i) & 1)) << i;
    }
    out
}

/// Compute a single element result given the element bytes of src1 and src2.
fn int_op_elem(op: IntOp, a: &[u8], b: &[u8], out: &mut [u8]) {
    match op {
        IntOp::AddB => out[0] = a[0].wrapping_add(b[0]),
        IntOp::SubB => out[0] = a[0].wrapping_sub(b[0]),
        IntOp::AddSatSB => out[0] = (a[0] as i8).saturating_add(b[0] as i8) as u8,
        IntOp::SubSatSB => out[0] = (a[0] as i8).saturating_sub(b[0] as i8) as u8,
        IntOp::AddSatUB => out[0] = a[0].saturating_add(b[0]),
        IntOp::SubSatUB => out[0] = a[0].saturating_sub(b[0]),
        IntOp::AvgB => out[0] = (((a[0] as u16) + (b[0] as u16) + 1) >> 1) as u8,
        IntOp::MinSB => out[0] = (a[0] as i8).min(b[0] as i8) as u8,
        IntOp::MinUB => out[0] = a[0].min(b[0]),
        IntOp::MaxSB => out[0] = (a[0] as i8).max(b[0] as i8) as u8,
        IntOp::MaxUB => out[0] = a[0].max(b[0]),
        IntOp::Gf2p8MulB => out[0] = gf2p8_mul(a[0], b[0]),
        IntOp::AddW => {
            let r = u16::from_le_bytes([a[0], a[1]]).wrapping_add(u16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::SubW => {
            let r = u16::from_le_bytes([a[0], a[1]]).wrapping_sub(u16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::AddSatSW => {
            let r =
                i16::from_le_bytes([a[0], a[1]]).saturating_add(i16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&(r as u16).to_le_bytes());
        }
        IntOp::SubSatSW => {
            let r =
                i16::from_le_bytes([a[0], a[1]]).saturating_sub(i16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&(r as u16).to_le_bytes());
        }
        IntOp::AddSatUW => {
            let r =
                u16::from_le_bytes([a[0], a[1]]).saturating_add(u16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::SubSatUW => {
            let r =
                u16::from_le_bytes([a[0], a[1]]).saturating_sub(u16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::AvgW => {
            let r = ((u16::from_le_bytes([a[0], a[1]]) as u32
                + u16::from_le_bytes([b[0], b[1]]) as u32
                + 1)
                >> 1) as u16;
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MullW => {
            let r = (i16::from_le_bytes([a[0], a[1]]) as i32)
                .wrapping_mul(i16::from_le_bytes([b[0], b[1]]) as i32) as u16;
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MulHighSW => {
            let r = ((i16::from_le_bytes([a[0], a[1]]) as i32)
                .wrapping_mul(i16::from_le_bytes([b[0], b[1]]) as i32)
                >> 16) as u16;
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MulHighRoundSW => {
            let product = (i16::from_le_bytes([a[0], a[1]]) as i32)
                .wrapping_mul(i16::from_le_bytes([b[0], b[1]]) as i32);
            let r = product.wrapping_add(0x4000) >> 15;
            out[0..2].copy_from_slice(&(r as u16).to_le_bytes());
        }
        IntOp::MulHighUW => {
            let r = ((u16::from_le_bytes([a[0], a[1]]) as u32)
                * (u16::from_le_bytes([b[0], b[1]]) as u32)
                >> 16) as u16;
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MaddUBSW => {
            let p0 = (a[0] as i32) * (b[0] as i8 as i32);
            let p1 = (a[1] as i32) * (b[1] as i8 as i32);
            let r = (p0 + p1).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            out[0..2].copy_from_slice(&(r as u16).to_le_bytes());
        }
        IntOp::MinSW => {
            let r = i16::from_le_bytes([a[0], a[1]]).min(i16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&(r as u16).to_le_bytes());
        }
        IntOp::MinUW => {
            let r = u16::from_le_bytes([a[0], a[1]]).min(u16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MaxSW => {
            let r = i16::from_le_bytes([a[0], a[1]]).max(i16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&(r as u16).to_le_bytes());
        }
        IntOp::MaxUW => {
            let r = u16::from_le_bytes([a[0], a[1]]).max(u16::from_le_bytes([b[0], b[1]]));
            out[0..2].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::AddD => {
            let r = u32::from_le_bytes([a[0], a[1], a[2], a[3]])
                .wrapping_add(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            out[0..4].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::SubD => {
            let r = u32::from_le_bytes([a[0], a[1], a[2], a[3]])
                .wrapping_sub(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            out[0..4].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MullD => {
            let r = (i32::from_le_bytes([a[0], a[1], a[2], a[3]]))
                .wrapping_mul(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                as u32;
            out[0..4].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MaddWD => {
            let a0 = i16::from_le_bytes([a[0], a[1]]) as i32;
            let a1 = i16::from_le_bytes([a[2], a[3]]) as i32;
            let b0 = i16::from_le_bytes([b[0], b[1]]) as i32;
            let b1 = i16::from_le_bytes([b[2], b[3]]) as i32;
            let r = a0.wrapping_mul(b0).wrapping_add(a1.wrapping_mul(b1));
            out[0..4].copy_from_slice(&(r as u32).to_le_bytes());
        }
        IntOp::MinSD => {
            let r = i32::from_le_bytes([a[0], a[1], a[2], a[3]])
                .min(i32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            out[0..4].copy_from_slice(&(r as u32).to_le_bytes());
        }
        IntOp::MinUD => {
            let r = u32::from_le_bytes([a[0], a[1], a[2], a[3]])
                .min(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            out[0..4].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MaxSD => {
            let r = i32::from_le_bytes([a[0], a[1], a[2], a[3]])
                .max(i32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            out[0..4].copy_from_slice(&(r as u32).to_le_bytes());
        }
        IntOp::MaxUD => {
            let r = u32::from_le_bytes([a[0], a[1], a[2], a[3]])
                .max(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            out[0..4].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::And => {
            for i in 0..out.len() {
                out[i] = a[i] & b[i];
            }
        }
        IntOp::Or => {
            for i in 0..out.len() {
                out[i] = a[i] | b[i];
            }
        }
        IntOp::Xor => {
            for i in 0..out.len() {
                out[i] = a[i] ^ b[i];
            }
        }
        IntOp::Andn => {
            // NOT(a) AND b  (a == src1 == vvvv)
            for i in 0..out.len() {
                out[i] = (!a[i]) & b[i];
            }
        }
        IntOp::AddQ => {
            let r = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]])
                .wrapping_add(u64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]));
            out[0..8].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::SubQ => {
            let r = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]])
                .wrapping_sub(u64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]));
            out[0..8].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MulDQ => {
            let r = (i32::from_le_bytes([a[0], a[1], a[2], a[3]]) as i64)
                .wrapping_mul(i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64);
            out[0..8].copy_from_slice(&(r as u64).to_le_bytes());
        }
        IntOp::MulUDQ => {
            let r = (u32::from_le_bytes([a[0], a[1], a[2], a[3]]) as u64)
                .wrapping_mul(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64);
            out[0..8].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MinSQ => {
            let r = i64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]).min(
                i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            );
            out[0..8].copy_from_slice(&(r as u64).to_le_bytes());
        }
        IntOp::MinUQ => {
            let r = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]).min(
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            );
            out[0..8].copy_from_slice(&r.to_le_bytes());
        }
        IntOp::MaxSQ => {
            let r = i64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]).max(
                i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            );
            out[0..8].copy_from_slice(&(r as u64).to_le_bytes());
        }
        IntOp::MaxUQ => {
            let r = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]).max(
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            );
            out[0..8].copy_from_slice(&r.to_le_bytes());
        }
    }
}

/// VGF2P8AFFINEQB / VGF2P8AFFINEINVQB (EVEX).
pub fn evex_gf2p8_affine(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    inverse: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VGF2P8AFFINE* requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let imm8 = ctx.consume_u8()?;

    let dest = evex_reg_vec(&evex, reg);
    let src1 = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src2 = evex_rm_vec(&evex, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let qwords = vl_bytes / 8;
    let addr = if is_memory && !evex.broadcast {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };

    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let matrix_bytes = if is_memory {
        if evex.broadcast {
            load_mem_bytes(vcpu, addr, 8, 1)?
        } else {
            load_mem_bytes(vcpu, addr, 8, qwords)?
        }
    } else {
        read_reg_bytes(vcpu, src2, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for qword in 0..qwords {
        let matrix_base = if is_memory && evex.broadcast {
            0
        } else {
            qword * 8
        };
        let matrix = &matrix_bytes[matrix_base..matrix_base + 8];
        for byte in 0..8 {
            let lane = qword * 8 + byte;
            let input = if inverse {
                gf_inv(src1_bytes[lane])
            } else {
                src1_bytes[lane]
            };
            raw[lane] = gf2p8_affine_byte(matrix, input, imm8);
        }
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, 1, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// VPMULTISHIFTQB: select unaligned byte windows from qword sources.
pub fn evex_multishift_qb(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VPMULTISHIFTQB requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let qwords = vl_bytes / 8;
    let addr = if is_memory {
        let scale = if evex.broadcast { 8 } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let control = read_reg_bytes(vcpu, src1, vl_bytes);
    let source = if is_memory {
        if evex.broadcast {
            load_mem_bytes(vcpu, addr, 8, 1)?
        } else {
            load_mem_bytes(vcpu, addr, 8, qwords)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for qword in 0..qwords {
        let src_base = if is_memory && evex.broadcast {
            0
        } else {
            qword * 8
        };
        let data = u64::from_le_bytes(source[src_base..src_base + 8].try_into().unwrap());
        for byte in 0..8 {
            let lane = qword * 8 + byte;
            let shift = (control[lane] & 0x3f) as u32;
            raw[lane] = (data.rotate_right(shift) & 0xff) as u8;
        }
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, 1, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

fn clmul_qword(a: u64, b: u64) -> [u8; 16] {
    let mut lo = 0u64;
    let mut hi = 0u64;
    for i in 0..64 {
        if (b >> i) & 1 != 0 {
            if i == 0 {
                lo ^= a;
            } else {
                lo ^= a << i;
                hi ^= a >> (64 - i);
            }
        }
    }

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&lo.to_le_bytes());
    out[8..].copy_from_slice(&hi.to_le_bytes());
    out
}

/// VPCLMULQDQ: carry-less qword multiply per 128-bit lane.
pub fn evex_pclmulqdq(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VPCLMULQDQ requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast {
        return Err(Error::Emulator(
            "VPCLMULQDQ does not support EVEX masking or broadcast".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let imm8 = ctx.consume_u8()?;

    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let lanes = vl_bytes / 16;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        load_mem_bytes(vcpu, addr, 8, lanes * 2)?
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let mut result = [0u8; 64];
    for lane in 0..lanes {
        let base = lane * 16;
        let src1_base = base + if imm8 & 0x01 != 0 { 8 } else { 0 };
        let src2_base = base + if imm8 & 0x10 != 0 { 8 } else { 0 };
        let a = u64::from_le_bytes(src1_bytes[src1_base..src1_base + 8].try_into().unwrap());
        let b = u64::from_le_bytes(src2_bytes[src2_base..src2_base + 8].try_into().unwrap());
        result[base..base + 16].copy_from_slice(&clmul_qword(a, b));
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

#[derive(Clone, Copy)]
pub enum VaesRound {
    Enc,
    EncLast,
    Dec,
    DecLast,
}

/// VAESENC/VAESENCLAST/VAESDEC/VAESDECLAST: AES round per 128-bit lane.
pub fn evex_vaes(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    round: VaesRound,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VAES requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast {
        return Err(Error::Emulator(
            "VAES does not support EVEX masking or broadcast".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let lanes = vl_bytes / 16;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };

    let states = read_reg_bytes(vcpu, src1, vl_bytes);
    let keys = if is_memory {
        load_mem_bytes(vcpu, addr, 8, lanes * 2)?
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let mut result = [0u8; 64];
    for lane in 0..lanes {
        let base = lane * 16;
        let state_lo = u64::from_le_bytes(states[base..base + 8].try_into().unwrap());
        let state_hi = u64::from_le_bytes(states[base + 8..base + 16].try_into().unwrap());
        let key_lo = u64::from_le_bytes(keys[base..base + 8].try_into().unwrap());
        let key_hi = u64::from_le_bytes(keys[base + 8..base + 16].try_into().unwrap());
        let (out_lo, out_hi) = match round {
            VaesRound::Enc => aes::aesenc(state_lo, state_hi, key_lo, key_hi),
            VaesRound::EncLast => aes::aesenclast(state_lo, state_hi, key_lo, key_hi),
            VaesRound::Dec => aes::aesdec(state_lo, state_hi, key_lo, key_hi),
            VaesRound::DecLast => aes::aesdeclast(state_lo, state_hi, key_lo, key_hi),
        };
        result[base..base + 8].copy_from_slice(&out_lo.to_le_bytes());
        result[base + 8..base + 16].copy_from_slice(&out_hi.to_le_bytes());
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

#[derive(Clone, Copy)]
enum FmaKind {
    Add,
    Sub,
    Nmadd,
    Nmsub,
    AddSub,
    SubAdd,
}

#[derive(Clone, Copy)]
enum FmaOrder {
    Order132,
    Order213,
    Order231,
}

fn decode_fma_opcode(opcode: u8) -> Option<(FmaKind, FmaOrder, bool)> {
    let (kind, order, scalar) = match opcode {
        0x96 => (FmaKind::AddSub, FmaOrder::Order132, false),
        0x97 => (FmaKind::SubAdd, FmaOrder::Order132, false),
        0xA6 => (FmaKind::AddSub, FmaOrder::Order213, false),
        0xA7 => (FmaKind::SubAdd, FmaOrder::Order213, false),
        0xB6 => (FmaKind::AddSub, FmaOrder::Order231, false),
        0xB7 => (FmaKind::SubAdd, FmaOrder::Order231, false),
        _ => {
            let scalar = (opcode & 1) != 0;
            let base = opcode & 0xFE;
            let (kind, order) = match base {
                0x98 => (FmaKind::Add, FmaOrder::Order132),
                0x9A => (FmaKind::Sub, FmaOrder::Order132),
                0x9C => (FmaKind::Nmadd, FmaOrder::Order132),
                0x9E => (FmaKind::Nmsub, FmaOrder::Order132),
                0xA8 => (FmaKind::Add, FmaOrder::Order213),
                0xAA => (FmaKind::Sub, FmaOrder::Order213),
                0xAC => (FmaKind::Nmadd, FmaOrder::Order213),
                0xAE => (FmaKind::Nmsub, FmaOrder::Order213),
                0xB8 => (FmaKind::Add, FmaOrder::Order231),
                0xBA => (FmaKind::Sub, FmaOrder::Order231),
                0xBC => (FmaKind::Nmadd, FmaOrder::Order231),
                0xBE => (FmaKind::Nmsub, FmaOrder::Order231),
                _ => return None,
            };
            (kind, order, scalar)
        }
    };
    Some((kind, order, scalar))
}

fn fma_operands_f32(order: FmaOrder, src1: f32, src2: f32, src3: f32) -> (f32, f32, f32) {
    match order {
        FmaOrder::Order132 => (src1, src3, src2),
        FmaOrder::Order213 => (src2, src1, src3),
        FmaOrder::Order231 => (src2, src3, src1),
    }
}

fn fma_operands_f64(order: FmaOrder, src1: f64, src2: f64, src3: f64) -> (f64, f64, f64) {
    match order {
        FmaOrder::Order132 => (src1, src3, src2),
        FmaOrder::Order213 => (src2, src1, src3),
        FmaOrder::Order231 => (src2, src3, src1),
    }
}

fn fma_result_f32(kind: FmaKind, lane: usize, a: f32, b: f32, c: f32) -> f32 {
    match kind {
        FmaKind::Add => a.mul_add(b, c),
        FmaKind::Sub => a.mul_add(b, -c),
        FmaKind::Nmadd => (-a).mul_add(b, c),
        FmaKind::Nmsub => (-a).mul_add(b, -c),
        FmaKind::AddSub => a.mul_add(b, if (lane & 1) == 0 { -c } else { c }),
        FmaKind::SubAdd => a.mul_add(b, if (lane & 1) == 0 { c } else { -c }),
    }
}

fn fma_result_f64(kind: FmaKind, lane: usize, a: f64, b: f64, c: f64) -> f64 {
    match kind {
        FmaKind::Add => a.mul_add(b, c),
        FmaKind::Sub => a.mul_add(b, -c),
        FmaKind::Nmadd => (-a).mul_add(b, c),
        FmaKind::Nmsub => (-a).mul_add(b, -c),
        FmaKind::AddSub => a.mul_add(b, if (lane & 1) == 0 { -c } else { c }),
        FmaKind::SubAdd => a.mul_add(b, if (lane & 1) == 0 { c } else { -c }),
    }
}

fn read_fma_src3(
    vcpu: &mut X86_64Vcpu,
    evex: &crate::isa::x86_64::cpu::EvexPrefix,
    src3_reg: u8,
    is_memory: bool,
    addr: u64,
    vl_bytes: usize,
    elem_size: usize,
    scalar: bool,
) -> Result<[u8; 64]> {
    if !is_memory {
        return Ok(read_reg_bytes(vcpu, src3_reg, vl_bytes));
    }

    let num_elems = if scalar { 1 } else { vl_bytes / elem_size };
    if evex.broadcast && !scalar {
        let value = load_mem_bytes(vcpu, addr, elem_size, 1)?;
        let mut data = [0u8; 64];
        for lane in 0..num_elems {
            let base = lane * elem_size;
            data[base..base + elem_size].copy_from_slice(&value[..elem_size]);
        }
        Ok(data)
    } else {
        load_mem_bytes(vcpu, addr, elem_size, num_elems)
    }
}

/// EVEX FP32/FP64 FMA family, including packed and scalar 132/213/231 forms.
pub fn evex_fma(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX FMA requires EVEX prefix".to_string()))?;
    let (kind, order, scalar) =
        decode_fma_opcode(opcode).expect("EVEX FMA opcode is filtered by dispatch");

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src2, src3_reg) = evex_three_op(&evex, reg, rm);
    let elem_size = if evex.w { 8 } else { 4 };
    let vl_bytes = if scalar { 16 } else { vl_bytes_of(evex.ll) };
    let num_elems = if scalar { 1 } else { vl_bytes / elem_size };
    let addr = if is_memory {
        let scale = if evex.broadcast || scalar {
            elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src1_bytes = read_reg_bytes(vcpu, dest, vl_bytes);
    let src2_bytes = read_reg_bytes(vcpu, src2, vl_bytes);
    let src3_bytes = read_fma_src3(
        vcpu, &evex, src3_reg, is_memory, addr, vl_bytes, elem_size, scalar,
    )?;

    let mut raw = if scalar { src1_bytes } else { [0u8; 64] };
    for lane in 0..num_elems {
        let s1 = read_lane_u64(&src1_bytes, lane, elem_size);
        let s2 = read_lane_u64(&src2_bytes, lane, elem_size);
        let s3 = read_lane_u64(&src3_bytes, lane, elem_size);
        // x86 FMA: if any source is NaN, the result is that NaN quieted with its
        // sign+payload preserved (priority src1, src2, src3) — the add/sub/negate
        // must NOT flip a NaN operand's sign. If no input is NaN but the op is
        // invalid (e.g. 0*Inf, Inf-Inf), the result is the QNaN indefinite.
        let out_bits = if fp_is_nan(s1, elem_size) {
            fp_quiet_nan(s1, elem_size)
        } else if fp_is_nan(s2, elem_size) {
            fp_quiet_nan(s2, elem_size)
        } else if fp_is_nan(s3, elem_size) {
            fp_quiet_nan(s3, elem_size)
        } else {
            let computed = if elem_size == 4 {
                let (a, b, c) = fma_operands_f32(
                    order,
                    f32::from_bits(s1 as u32),
                    f32::from_bits(s2 as u32),
                    f32::from_bits(s3 as u32),
                );
                fma_result_f32(kind, lane, a, b, c).to_bits() as u64
            } else {
                let (a, b, c) = fma_operands_f64(
                    order,
                    f64::from_bits(s1),
                    f64::from_bits(s2),
                    f64::from_bits(s3),
                );
                fma_result_f64(kind, lane, a, b, c).to_bits()
            };
            if fp_is_nan(computed, elem_size) {
                fp_qnan_indefinite(elem_size)
            } else {
                computed
            }
        };
        write_lane_bits(&mut raw, lane, elem_size, out_bits);
    }

    let result = if scalar {
        let mut result = src1_bytes;
        let active = evex.aaa == 0 || (vcpu.regs.k[evex.aaa as usize] & 1) != 0;
        if active {
            result[..elem_size].copy_from_slice(&raw[..elem_size]);
        } else if evex.z {
            result[..elem_size].fill(0);
        }
        result
    } else {
        apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw)
    };

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX MAP6 FP16 FMA family, including packed PH and scalar SH forms.
pub fn evex_fma_fp16(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX FP16 FMA requires EVEX prefix".to_string()))?;
    if evex.w {
        return Err(Error::Emulator(
            "EVEX FP16 FMA requires W0 encoding".to_string(),
        ));
    }
    let (kind, order, scalar) =
        decode_fma_opcode(opcode).expect("EVEX FP16 FMA opcode is filtered by dispatch");

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src2, src3_reg) = evex_three_op(&evex, reg, rm);
    let elem_size = 2;
    let vl_bytes = if scalar { 16 } else { vl_bytes_of(evex.ll) };
    let num_elems = if scalar { 1 } else { vl_bytes / elem_size };
    let addr = if is_memory {
        let scale = if evex.broadcast || scalar {
            elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src1_bytes = read_reg_bytes(vcpu, dest, vl_bytes);
    let src2_bytes = read_reg_bytes(vcpu, src2, vl_bytes);
    let src3_bytes = read_fma_src3(
        vcpu, &evex, src3_reg, is_memory, addr, vl_bytes, elem_size, scalar,
    )?;

    let mut raw = if scalar { src1_bytes } else { [0u8; 64] };
    for lane in 0..num_elems {
        let base = lane * elem_size;
        let src1 = f16_to_f32(u16::from_le_bytes(
            src1_bytes[base..base + 2].try_into().unwrap(),
        ));
        let src2 = f16_to_f32(u16::from_le_bytes(
            src2_bytes[base..base + 2].try_into().unwrap(),
        ));
        let src3 = f16_to_f32(u16::from_le_bytes(
            src3_bytes[base..base + 2].try_into().unwrap(),
        ));
        let (a, b, c) = fma_operands_f32(order, src1, src2, src3);
        raw[base..base + 2]
            .copy_from_slice(&f32_to_f16(fma_result_f32(kind, lane, a, b, c)).to_le_bytes());
    }

    let result = if scalar {
        let mut result = src1_bytes;
        let active = evex.aaa == 0 || (vcpu.regs.k[evex.aaa as usize] & 1) != 0;
        if active {
            result[..elem_size].copy_from_slice(&raw[..elem_size]);
        } else if evex.z {
            result[..elem_size].fill(0);
        }
        result
    } else {
        apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw)
    };

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

fn fixup_token_f32(bits: u32) -> usize {
    let exp = (bits >> 23) & 0xff;
    let frac = bits & 0x007f_ffff;
    let sign = (bits >> 31) != 0;

    if exp == 0xff && frac != 0 {
        if (frac & 0x0040_0000) != 0 { 0 } else { 1 }
    } else if exp == 0 && frac == 0 {
        2
    } else if bits == 0x3f80_0000 {
        3
    } else if bits == 0xff80_0000 {
        4
    } else if bits == 0x7f80_0000 {
        5
    } else if sign {
        6
    } else {
        7
    }
}

fn fixup_token_f64(bits: u64) -> usize {
    let exp = (bits >> 52) & 0x7ff;
    let frac = bits & 0x000f_ffff_ffff_ffff;
    let sign = (bits >> 63) != 0;

    if exp == 0x7ff && frac != 0 {
        if (frac & 0x0008_0000_0000_0000) != 0 {
            0
        } else {
            1
        }
    } else if exp == 0 && frac == 0 {
        2
    } else if bits == 0x3ff0_0000_0000_0000 {
        3
    } else if bits == 0xfff0_0000_0000_0000 {
        4
    } else if bits == 0x7ff0_0000_0000_0000 {
        5
    } else if sign {
        6
    } else {
        7
    }
}

fn fixup_response_f32(dest_bits: u32, src_bits: u32, table: u64) -> u32 {
    let token = fixup_token_f32(src_bits);
    let response = ((table >> (token * 4)) & 0x0f) as u8;
    match response {
        0x0 => dest_bits,
        0x1 => src_bits,
        0x2 => {
            let exp = (src_bits >> 23) & 0xff;
            let frac = src_bits & 0x007f_ffff;
            if exp == 0xff && frac != 0 {
                src_bits | 0x0040_0000
            } else {
                0x7fc0_0000
            }
        }
        0x3 => 0xffc0_0000,
        0x4 => f32::NEG_INFINITY.to_bits(),
        0x5 => f32::INFINITY.to_bits(),
        0x6 => {
            if (src_bits >> 31) != 0 {
                f32::NEG_INFINITY.to_bits()
            } else {
                f32::INFINITY.to_bits()
            }
        }
        0x7 => (-0.0f32).to_bits(),
        0x8 => 0.0f32.to_bits(),
        0x9 => (-1.0f32).to_bits(),
        0xa => 1.0f32.to_bits(),
        0xb => 0.5f32.to_bits(),
        0xc => 90.0f32.to_bits(),
        0xd => std::f32::consts::FRAC_PI_2.to_bits(),
        0xe => f32::MAX.to_bits(),
        0xf => (-f32::MAX).to_bits(),
        _ => dest_bits,
    }
}

fn fixup_response_f64(dest_bits: u64, src_bits: u64, table: u64) -> u64 {
    let token = fixup_token_f64(src_bits);
    let response = ((table >> (token * 4)) & 0x0f) as u8;
    match response {
        0x0 => dest_bits,
        0x1 => src_bits,
        0x2 => {
            let exp = (src_bits >> 52) & 0x7ff;
            let frac = src_bits & 0x000f_ffff_ffff_ffff;
            if exp == 0x7ff && frac != 0 {
                src_bits | 0x0008_0000_0000_0000
            } else {
                0x7ff8_0000_0000_0000
            }
        }
        0x3 => 0xfff8_0000_0000_0000,
        0x4 => f64::NEG_INFINITY.to_bits(),
        0x5 => f64::INFINITY.to_bits(),
        0x6 => {
            if (src_bits >> 63) != 0 {
                f64::NEG_INFINITY.to_bits()
            } else {
                f64::INFINITY.to_bits()
            }
        }
        0x7 => (-0.0f64).to_bits(),
        0x8 => 0.0f64.to_bits(),
        0x9 => (-1.0f64).to_bits(),
        0xa => 1.0f64.to_bits(),
        0xb => 0.5f64.to_bits(),
        0xc => 90.0f64.to_bits(),
        0xd => std::f64::consts::FRAC_PI_2.to_bits(),
        0xe => f64::MAX.to_bits(),
        0xf => (-f64::MAX).to_bits(),
        _ => dest_bits,
    }
}

fn read_fp16_pair_bits(bytes: &[u8; 64], pair: usize) -> (u16, u16) {
    let base = pair * 4;
    let real = u16::from_le_bytes([bytes[base], bytes[base + 1]]);
    let imag = u16::from_le_bytes([bytes[base + 2], bytes[base + 3]]);
    (real, imag)
}

fn write_fp16_pair_bits(bytes: &mut [u8; 64], pair: usize, real: u16, imag: u16) {
    let base = pair * 4;
    bytes[base..base + 2].copy_from_slice(&real.to_le_bytes());
    bytes[base + 2..base + 4].copy_from_slice(&imag.to_le_bytes());
}

fn fp16_fma_boundary_bits(a_bits: u16, b_bits: u16, c_bits: u16, negate_a: bool) -> u16 {
    if fp_is_nan(a_bits as u64, 2) {
        return fp_quiet_nan(a_bits as u64, 2) as u16;
    }
    if fp_is_nan(b_bits as u64, 2) {
        return fp_quiet_nan(b_bits as u64, 2) as u16;
    }
    if fp_is_nan(c_bits as u64, 2) {
        return fp_quiet_nan(c_bits as u64, 2) as u16;
    }

    let a = if negate_a {
        -f16_to_f32(a_bits)
    } else {
        f16_to_f32(a_bits)
    };
    let computed = a.mul_add(f16_to_f32(b_bits), f16_to_f32(c_bits));
    if computed.is_nan() {
        fp_qnan_indefinite(2) as u16
    } else {
        f32_to_f16(computed)
    }
}

/// EVEX V[FC]MULCPH/SH and V[FC]MADDCPH/SH complex FP16 arithmetic.
pub fn evex_fp16_complex(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    accumulate: bool,
    conjugate: bool,
    scalar: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX FP16 complex requires EVEX prefix".to_string()))?;
    if evex.w {
        return Err(Error::Emulator(
            "EVEX FP16 complex requires W0 encoding".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    if dest == src1 || (!is_memory && dest == src2_reg) {
        return Err(Error::Emulator(
            "EVEX FP16 complex destination aliases a source".to_string(),
        ));
    }

    let vl_bytes = if scalar { 16 } else { vl_bytes_of(evex.ll) };
    let num_pairs = if scalar { 1 } else { vl_bytes / 4 };
    let addr = if is_memory {
        let scale = if scalar || evex.broadcast {
            4
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        if evex.broadcast && !scalar {
            let pair = vcpu.read_mem(addr, 4)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_pairs {
                let base = lane * 4;
                data[base..base + 4].copy_from_slice(&pair[..4]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, 4, num_pairs)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mut raw = if scalar { src1_bytes } else { [0u8; 64] };

    for pair in 0..num_pairs {
        let (a_re, a_im) = read_fp16_pair_bits(&src1_bytes, pair);
        let (b_re, b_im) = read_fp16_pair_bits(&src2_bytes, pair);
        let (acc_re, acc_im) = if accumulate {
            read_fp16_pair_bits(&dest_old, pair)
        } else {
            (0, 0)
        };

        let tmp_re = fp16_fma_boundary_bits(a_re, b_re, acc_re, false);
        let tmp_im = fp16_fma_boundary_bits(a_im, b_re, acc_im, false);
        let (real, imag) = if conjugate {
            (
                fp16_fma_boundary_bits(a_im, b_im, tmp_re, false),
                fp16_fma_boundary_bits(a_re, b_im, tmp_im, true),
            )
        } else {
            (
                fp16_fma_boundary_bits(a_im, b_im, tmp_re, true),
                fp16_fma_boundary_bits(a_re, b_im, tmp_im, false),
            )
        };
        write_fp16_pair_bits(&mut raw, pair, real, imag);
    }

    let result = if scalar {
        let mut result = [0u8; 64];
        result[4..16].copy_from_slice(&src1_bytes[4..16]);
        let active = evex.aaa == 0 || (vcpu.regs.k[evex.aaa as usize] & 1) != 0;
        if active {
            result[..4].copy_from_slice(&raw[..4]);
        } else if !evex.z {
            result[..4].copy_from_slice(&dest_old[..4]);
        }
        result
    } else {
        apply_evex_mask(vcpu, &evex, dest, vl_bytes, 4, &raw)
    };

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX V4FMADDPS/SS and V4FNMADDPS/SS source-block memory forms.
pub fn evex_4fmaddps(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    scalar: bool,
    negative: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX 4FMAPS requires EVEX prefix".to_string()))?;
    if evex.w || evex.broadcast {
        return Err(Error::Emulator(
            "EVEX 4FMAPS requires W0 and no broadcast".to_string(),
        ));
    }

    let (reg, _rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    if !is_memory {
        return Err(Error::Emulator(
            "EVEX 4FMAPS requires a memory operand".to_string(),
        ));
    }

    let dest = evex_reg_vec(&evex, reg);
    let src_base = ((evex.vvvv ^ 0x0f) | if evex.v_prime { 0 } else { 16 }) & !0x03;
    let vl_bytes = if scalar { 16 } else { 64 };
    let num_lanes = if scalar { 1 } else { 16 };
    let msrc = load_mem_bytes(vcpu, addr, 4, 4)?;
    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mut raw = dest_old;

    for lane in 0..num_lanes {
        let mut acc = f32::from_bits(read_fp_elem(&dest_old, lane, 4) as u32);
        for block in 0..4 {
            let src = read_reg_bytes(vcpu, src_base + block as u8, 64);
            let a = f32::from_bits(read_fp_elem(&src, lane, 4) as u32);
            let b = f32::from_bits(read_fp_elem(&msrc, block, 4) as u32);
            acc = if negative {
                (-a).mul_add(b, acc)
            } else {
                a.mul_add(b, acc)
            };
        }
        write_lane_bits(&mut raw, lane, 4, acc.to_bits() as u64);
    }

    let result = if scalar {
        let mut result = dest_old;
        let active = evex.aaa == 0 || (vcpu.regs.k[evex.aaa as usize] & 1) != 0;
        if active {
            result[..4].copy_from_slice(&raw[..4]);
        } else if evex.z {
            result[..4].fill(0);
        }
        result
    } else {
        apply_evex_mask(vcpu, &evex, dest, vl_bytes, 4, &raw)
    };
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

fn signed_saturate_i32(value: i64) -> i32 {
    value.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

fn read_i16_lane(bytes: &[u8; 64], lane: usize) -> i16 {
    let base = lane * 2;
    i16::from_le_bytes([bytes[base], bytes[base + 1]])
}

/// EVEX VP4DPWSSD/VP4DPWSSDS source-block memory forms.
pub fn evex_4dpwssd(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    saturating: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX 4VNNIW requires EVEX prefix".to_string()))?;
    if evex.w || evex.broadcast {
        return Err(Error::Emulator(
            "EVEX 4VNNIW requires W0 and no broadcast".to_string(),
        ));
    }

    let (reg, _rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    if !is_memory {
        return Err(Error::Emulator(
            "EVEX 4VNNIW requires a memory operand".to_string(),
        ));
    }

    let dest = evex_reg_vec(&evex, reg);
    let src_base = ((evex.vvvv ^ 0x0f) | if evex.v_prime { 0 } else { 16 }) & !0x03;
    let msrc = load_mem_bytes(vcpu, addr, 4, 4)?;
    let dest_old = read_reg_bytes(vcpu, dest, 64);
    let mask = evex_mask(vcpu, evex.aaa, 16);
    let mut result = [0u8; 64];

    for lane in 0..16 {
        let base = lane * 4;
        if (mask >> lane) & 1 == 0 {
            if !evex.z {
                result[base..base + 4].copy_from_slice(&dest_old[base..base + 4]);
            }
            continue;
        }

        let mut acc = read_fp_elem(&dest_old, lane, 4) as u32 as i32;
        for block in 0..4 {
            let src = read_reg_bytes(vcpu, src_base + block as u8, 64);
            let mem_lo = read_i16_lane(&msrc, block * 2) as i32;
            let mem_hi = read_i16_lane(&msrc, block * 2 + 1) as i32;
            let reg_lo = read_i16_lane(&src, lane * 2) as i32;
            let reg_hi = read_i16_lane(&src, lane * 2 + 1) as i32;
            let sum = acc as i64 + (reg_lo * mem_lo) as i64 + (reg_hi * mem_hi) as i64;
            acc = if saturating {
                signed_saturate_i32(sum)
            } else {
                sum as i32
            };
        }
        write_lane_bits(&mut result, lane, 4, acc as u32 as u64);
    }

    write_vec_vl(vcpu, dest, 64, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Generic EVEX integer arithmetic / logical instruction with per-element
/// k-masking (merge/zero), VL handling and (for D/Q forms) embedded broadcast.
pub fn evex_int_arith(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    op: IntOp,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX integer op requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);

    let vl_bytes = vl_bytes_of(evex.ll);
    let elem_size = op.elem_size(evex.w);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast && op.supports_broadcast() {
            elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);

    // Load src2 from register or memory (with embedded broadcast for D/Q forms).
    let src2_bytes = if is_memory {
        if evex.broadcast && op.supports_broadcast() {
            // Broadcast a single element across all lanes.
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for i in 0..num_elems {
                let base = i * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let mut result = [0u8; 64];
    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            int_op_elem(
                op,
                &src1_bytes[base..base + elem_size],
                &src2_bytes[base..base + elem_size],
                &mut result[base..base + elem_size],
            );
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Saturating pack operation kind for VPACKSSWB/DW and VPACKUSWB/DW.
#[derive(Clone, Copy)]
pub enum PackKind {
    SignedWordToSignedByte,
    SignedDwordToSignedWord,
    UnsignedWordToUnsignedByte,
    UnsignedDwordToUnsignedWord,
}

impl PackKind {
    fn name(self) -> &'static str {
        match self {
            PackKind::SignedWordToSignedByte => "VPACKSSWB",
            PackKind::SignedDwordToSignedWord => "VPACKSSDW",
            PackKind::UnsignedWordToUnsignedByte => "VPACKUSWB",
            PackKind::UnsignedDwordToUnsignedWord => "VPACKUSDW",
        }
    }

    fn src_elem_size(self) -> usize {
        match self {
            PackKind::SignedWordToSignedByte | PackKind::UnsignedWordToUnsignedByte => 2,
            PackKind::SignedDwordToSignedWord | PackKind::UnsignedDwordToUnsignedWord => 4,
        }
    }

    fn dst_elem_size(self) -> usize {
        match self {
            PackKind::SignedWordToSignedByte | PackKind::UnsignedWordToUnsignedByte => 1,
            PackKind::SignedDwordToSignedWord | PackKind::UnsignedDwordToUnsignedWord => 2,
        }
    }

    fn supports_broadcast(self) -> bool {
        matches!(
            self,
            PackKind::SignedDwordToSignedWord | PackKind::UnsignedDwordToUnsignedWord
        )
    }
}

fn pack_saturate_elem(kind: PackKind, src: &[u8]) -> u64 {
    match kind {
        PackKind::SignedWordToSignedByte => {
            let value = i16::from_le_bytes([src[0], src[1]]);
            value.clamp(i8::MIN as i16, i8::MAX as i16) as i8 as u8 as u64
        }
        PackKind::UnsignedWordToUnsignedByte => {
            let value = i16::from_le_bytes([src[0], src[1]]);
            value.clamp(0, u8::MAX as i16) as u8 as u64
        }
        PackKind::SignedDwordToSignedWord => {
            let value = i32::from_le_bytes([src[0], src[1], src[2], src[3]]);
            value.clamp(i16::MIN as i32, i16::MAX as i32) as i16 as u16 as u64
        }
        PackKind::UnsignedDwordToUnsignedWord => {
            let value = i32::from_le_bytes([src[0], src[1], src[2], src[3]]);
            value.clamp(0, u16::MAX as i32) as u16 as u64
        }
    }
}

/// Generic EVEX saturating pack. Results are packed independently in each
/// 128-bit lane: low half from src1, high half from src2/mem.
pub fn evex_pack_saturate(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: PackKind,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator(format!("{} requires EVEX prefix", kind.name())))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);

    let vl_bytes = vl_bytes_of(evex.ll);
    let src_elem_size = kind.src_elem_size();
    let dst_elem_size = kind.dst_elem_size();
    let num_src_elems = vl_bytes / src_elem_size;
    let num_dst_elems = vl_bytes / dst_elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast && kind.supports_broadcast() {
            src_elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        if evex.broadcast {
            if !kind.supports_broadcast() {
                return Err(Error::Emulator(format!(
                    "{} does not support embedded broadcast",
                    kind.name()
                )));
            }
            let elem = vcpu.read_mem(addr, src_elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_src_elems {
                let base = lane * src_elem_size;
                data[base..base + src_elem_size].copy_from_slice(&elem_le[..src_elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, src_elem_size, num_src_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let src_elems_per_128 = 16 / src_elem_size;
    let mut packed = [0u8; 64];

    for block_base in (0..vl_bytes).step_by(16) {
        for lane in 0..src_elems_per_128 {
            let src_base = block_base + lane * src_elem_size;
            let dst_base = block_base + lane * dst_elem_size;
            packed[dst_base..dst_base + dst_elem_size].copy_from_slice(
                &pack_saturate_elem(kind, &src1_bytes[src_base..src_base + src_elem_size])
                    .to_le_bytes()[..dst_elem_size],
            );
        }
        for lane in 0..src_elems_per_128 {
            let src_base = block_base + lane * src_elem_size;
            let dst_base = block_base + (src_elems_per_128 + lane) * dst_elem_size;
            packed[dst_base..dst_base + dst_elem_size].copy_from_slice(
                &pack_saturate_elem(kind, &src2_bytes[src_base..src_base + src_elem_size])
                    .to_le_bytes()[..dst_elem_size],
            );
        }
    }

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_dst_elems);
    let mut result = [0u8; 64];

    for lane in 0..num_dst_elems {
        let base = lane * dst_elem_size;
        if (mask >> lane) & 1 != 0 {
            result[base..base + dst_elem_size].copy_from_slice(&packed[base..base + dst_elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + dst_elem_size]
                .copy_from_slice(&dest_old[base..base + dst_elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Immediate shuffle operation kind for VPSHUFD/HW/LW.
#[derive(Clone, Copy)]
pub enum ShuffleImmKind {
    Dword,
    HighWord,
    LowWord,
}

impl ShuffleImmKind {
    fn name(self) -> &'static str {
        match self {
            ShuffleImmKind::Dword => "VPSHUFD",
            ShuffleImmKind::HighWord => "VPSHUFHW",
            ShuffleImmKind::LowWord => "VPSHUFLW",
        }
    }

    fn elem_size(self) -> usize {
        match self {
            ShuffleImmKind::Dword => 4,
            ShuffleImmKind::HighWord | ShuffleImmKind::LowWord => 2,
        }
    }
}

pub(super) fn apply_evex_mask(
    vcpu: &X86_64Vcpu,
    evex: &crate::isa::x86_64::cpu::EvexPrefix,
    dest: u8,
    vl_bytes: usize,
    elem_size: usize,
    raw: &[u8; 64],
) -> [u8; 64] {
    let num_elems = vl_bytes / elem_size;
    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];

    for lane in 0..num_elems {
        let base = lane * elem_size;
        if (mask >> lane) & 1 != 0 {
            result[base..base + elem_size].copy_from_slice(&raw[base..base + elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }
    result
}

#[inline]
pub(super) fn evex_reg_vec(evex: &crate::isa::x86_64::cpu::EvexPrefix, reg: u8) -> u8 {
    (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 }
}

#[inline]
fn evex_reg_gpr(evex: &crate::isa::x86_64::cpu::EvexPrefix, reg: u8) -> u8 {
    (reg & 0x07) | if evex.r { 0 } else { 8 }
}

#[inline]
pub(super) fn evex_rm_vec(evex: &crate::isa::x86_64::cpu::EvexPrefix, rm: u8) -> u8 {
    (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 }
}

#[inline]
pub(super) fn evex_rm_gpr(evex: &crate::isa::x86_64::cpu::EvexPrefix, rm: u8) -> u8 {
    (rm & 0x07) | if evex.b { 0 } else { 8 }
}

#[inline]
pub(super) fn scalar_low_bytes(value: u64, elem_size: usize) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[..elem_size].copy_from_slice(&value.to_le_bytes()[..elem_size]);
    bytes
}

#[inline]
fn read_vec_scalar(vcpu: &X86_64Vcpu, reg: u8, elem_size: usize) -> u64 {
    let bytes = read_reg_bytes(vcpu, reg, 16);
    let mut raw = [0u8; 8];
    raw[..elem_size].copy_from_slice(&bytes[..elem_size]);
    u64::from_le_bytes(raw)
}

fn write_vec_scalar_zero_upper(vcpu: &mut X86_64Vcpu, dest: u8, elem_size: usize, value: u64) {
    let mut raw = [0u8; 64];
    raw[..elem_size].copy_from_slice(&scalar_low_bytes(value, elem_size)[..elem_size]);
    write_vec_vl(vcpu, dest, 16, &raw);
}

pub(super) fn f16_to_f32(bits: u16) -> f32 {
    let sign = ((bits & 0x8000) as u32) << 16;
    let exp = (bits >> 10) & 0x1f;
    let frac = (bits & 0x03ff) as u32;

    let out = match exp {
        0 => {
            if frac == 0 {
                sign
            } else {
                let mut mant = frac;
                let mut unbiased_exp = -14i32;
                while (mant & 0x0400) == 0 {
                    mant <<= 1;
                    unbiased_exp -= 1;
                }
                mant &= 0x03ff;
                sign | (((unbiased_exp + 127) as u32) << 23) | (mant << 13)
            }
        }
        0x1f => sign | 0x7f80_0000 | (frac << 13),
        _ => sign | ((((exp as i32) - 15 + 127) as u32) << 23) | (frac << 13),
    };

    f32::from_bits(out)
}

fn f32_to_f16(value: f32) -> u16 {
    let bits = value.to_bits();
    let sign = (bits >> 16) & 0x8000;
    let abs = bits & 0x7fff_ffff;
    let exp = (abs >> 23) as i32;
    let mant = abs & 0x007f_ffff;

    if exp == 0xff {
        if mant == 0 {
            return (sign | 0x7c00) as u16;
        }
        let payload = (mant >> 13).max(1);
        return (sign | 0x7c00 | payload) as u16;
    }

    if abs < 0x3300_0000 {
        return sign as u16;
    }

    if abs < 0x3880_0000 {
        let mant24 = mant | 0x0080_0000;
        let shift = (126 - exp) as u32;
        let round = 1u32 << (shift - 1);
        let half_mant = (mant24 + round - 1 + ((mant24 >> shift) & 1)) >> shift;
        return (sign | half_mant) as u16;
    }

    let mut half = (abs - 0x3800_0000) >> 13;
    let remainder = abs & 0x1fff;
    if remainder > 0x1000 || (remainder == 0x1000 && (half & 1) != 0) {
        half += 1;
    }

    if half >= 0x7c00 {
        (sign | 0x7c00) as u16
    } else {
        (sign | half) as u16
    }
}

fn fp_bits_to_f64(bits: u64, elem_size: usize) -> f64 {
    match elem_size {
        2 => f16_to_f32(bits as u16) as f64,
        4 => f32::from_bits(bits as u32) as f64,
        8 => f64::from_bits(bits),
        _ => 0.0,
    }
}

fn f64_to_fp_bits(value: f64, elem_size: usize) -> u64 {
    match elem_size {
        2 => f32_to_f16(value as f32) as u64,
        4 => (value as f32).to_bits() as u64,
        8 => value.to_bits(),
        _ => 0,
    }
}

fn rounded_int_magnitude_to_fp_bits(
    negative: bool,
    magnitude: u128,
    frac_bits: u32,
    exp_bits: u32,
    bias: i32,
    rounding: u8,
) -> u64 {
    let sign_shift = exp_bits + frac_bits;
    let sign = if negative { 1u64 << sign_shift } else { 0 };
    if magnitude == 0 {
        return sign;
    }

    let precision = frac_bits + 1;
    let mut exponent = (u128::BITS - 1 - magnitude.leading_zeros()) as i32;
    let mut significand = if exponent as u32 <= frac_bits {
        magnitude << (frac_bits - exponent as u32)
    } else {
        let shift = exponent as u32 - frac_bits;
        let mut significand = magnitude >> shift;
        let remainder = magnitude & ((1u128 << shift) - 1);
        let increment = if remainder == 0 {
            false
        } else {
            match rounding & 0x03 {
                0 => {
                    let half = 1u128 << (shift - 1);
                    remainder > half || (remainder == half && (significand & 1) != 0)
                }
                1 => negative,
                2 => !negative,
                _ => false,
            }
        };
        if increment {
            significand += 1;
        }
        significand
    };

    if significand == (1u128 << precision) {
        significand >>= 1;
        exponent += 1;
    }

    let max_exp = (1u64 << exp_bits) - 1;
    let biased = exponent + bias;
    if biased >= max_exp as i32 {
        let round_to_infinity = match rounding & 0x03 {
            0 => true,
            1 => negative,
            2 => !negative,
            _ => false,
        };
        if round_to_infinity {
            return sign | (max_exp << frac_bits);
        }
        return sign | ((max_exp - 1) << frac_bits) | ((1u64 << frac_bits) - 1);
    }

    let frac = (significand & ((1u128 << frac_bits) - 1)) as u64;
    sign | ((biased as u64) << frac_bits) | frac
}

fn int_elem_parts(bits: u64, elem_size: usize, signed: bool) -> (bool, u128) {
    if signed {
        let value = match elem_size {
            2 => (bits as u16 as i16) as i128,
            4 => (bits as u32 as i32) as i128,
            8 => (bits as i64) as i128,
            _ => 0,
        };
        if value < 0 {
            (true, (-value) as u128)
        } else {
            (false, value as u128)
        }
    } else {
        let value = match elem_size {
            2 => bits as u16 as u128,
            4 => bits as u32 as u128,
            8 => bits as u128,
            _ => 0,
        };
        (false, value)
    }
}

fn int_to_fp_bits(
    bits: u64,
    src_elem_size: usize,
    dst_elem_size: usize,
    signed: bool,
    rounding: u8,
) -> u64 {
    let (negative, magnitude) = int_elem_parts(bits, src_elem_size, signed);
    match dst_elem_size {
        2 => rounded_int_magnitude_to_fp_bits(negative, magnitude, 10, 5, 15, rounding),
        4 => rounded_int_magnitude_to_fp_bits(negative, magnitude, 23, 8, 127, rounding),
        8 => rounded_int_magnitude_to_fp_bits(negative, magnitude, 52, 11, 1023, rounding),
        _ => 0,
    }
}

fn evex_rounding_mode(
    evex: &crate::isa::x86_64::cpu::EvexPrefix,
    is_memory: bool,
    mxcsr: u32,
) -> u8 {
    if !is_memory && evex.broadcast {
        evex.ll
    } else {
        ((mxcsr >> 13) & 0x03) as u8
    }
}

fn evex_conversion_vl_bytes(evex: &crate::isa::x86_64::cpu::EvexPrefix, is_memory: bool) -> usize {
    if !is_memory && evex.broadcast {
        64
    } else {
        vl_bytes_of(evex.ll)
    }
}

// --- Bit-level FP special-value helpers ---------------------------------
//
// The f64 round-trip above is lossy for NaN payloads (every f32 NaN collapses
// to the canonical f64 NaN, and back to 0x7fc00000), so special-value handling
// that must preserve a source NaN's sign+payload has to work on the raw element
// bits. These operate directly on the per-lane bit pattern for the given size.

/// Is the element a NaN (max exponent, non-zero mantissa)?
fn fp_is_nan(bits: u64, elem_size: usize) -> bool {
    match elem_size {
        2 => (bits as u16 & 0x7c00) == 0x7c00 && (bits as u16 & 0x03ff) != 0,
        4 => {
            let b = bits as u32;
            (b & 0x7f80_0000) == 0x7f80_0000 && (b & 0x007f_ffff) != 0
        }
        8 => {
            (bits & 0x7ff0_0000_0000_0000) == 0x7ff0_0000_0000_0000
                && (bits & 0x000f_ffff_ffff_ffff) != 0
        }
        _ => false,
    }
}

/// Is a NaN element a quiet NaN (mantissa MSB set)?
fn fp_is_quiet_nan(bits: u64, elem_size: usize) -> bool {
    let quiet_bit = match elem_size {
        2 => 0x0200,
        4 => 0x0040_0000,
        8 => 0x0008_0000_0000_0000,
        _ => return true,
    };
    (bits & quiet_bit) != 0
}

/// Quiet a NaN element, preserving its sign and payload (sets the mantissa MSB).
fn fp_quiet_nan(bits: u64, elem_size: usize) -> u64 {
    match elem_size {
        2 => bits | 0x0200,
        4 => bits | 0x0040_0000,
        8 => bits | 0x0008_0000_0000_0000,
        _ => bits,
    }
}

/// The architectural QNaN indefinite (sign=1) for the element size.
fn fp_qnan_indefinite(elem_size: usize) -> u64 {
    match elem_size {
        2 => 0xfe00,
        4 => 0xffc0_0000,
        8 => 0xfff8_0000_0000_0000,
        _ => 0,
    }
}

fn fp_round_to_int(value: f64, truncate: bool, rounding: u8) -> f64 {
    if truncate {
        return value.trunc();
    }

    match rounding & 0x03 {
        0 => value.round_ties_even(),
        1 => value.floor(),
        2 => value.ceil(),
        _ => value.trunc(),
    }
}

fn fp_to_int_bits(value: f64, dst_size: u8, unsigned: bool, truncate: bool, rounding: u8) -> u64 {
    let rounded = fp_round_to_int(value, truncate, rounding);
    const I64_MAX_EXCLUSIVE: f64 = 9_223_372_036_854_775_808.0;
    const U64_MAX_EXCLUSIVE: f64 = 18_446_744_073_709_551_616.0;

    if unsigned {
        if !rounded.is_finite() || rounded < 0.0 {
            return if dst_size == 8 {
                u64::MAX
            } else if dst_size == 2 {
                u16::MAX as u64
            } else {
                u32::MAX as u64
            };
        }
        if dst_size == 8 {
            if rounded >= U64_MAX_EXCLUSIVE {
                u64::MAX
            } else {
                rounded as u64
            }
        } else if dst_size == 2 {
            if rounded > u16::MAX as f64 {
                u16::MAX as u64
            } else {
                rounded as u16 as u64
            }
        } else if rounded > u32::MAX as f64 {
            u32::MAX as u64
        } else {
            rounded as u32 as u64
        }
    } else if dst_size == 8 {
        if !rounded.is_finite() || rounded >= I64_MAX_EXCLUSIVE || rounded < i64::MIN as f64 {
            i64::MIN as u64
        } else {
            (rounded as i64) as u64
        }
    } else if dst_size == 2 {
        if !rounded.is_finite() || rounded > i16::MAX as f64 || rounded < i16::MIN as f64 {
            i16::MIN as u16 as u64
        } else {
            rounded as i16 as u16 as u64
        }
    } else if !rounded.is_finite() || rounded > i32::MAX as f64 || rounded < i32::MIN as f64 {
        i32::MIN as u32 as u64
    } else {
        rounded as i32 as u32 as u64
    }
}

#[inline]
fn reg_vl_for_bytes(bytes: usize) -> usize {
    if bytes <= 16 {
        16
    } else if bytes <= 32 {
        32
    } else {
        64
    }
}

#[inline]
fn packed_conversion_layout(
    operation_vl: usize,
    src_elem_size: usize,
    dst_elem_size: usize,
) -> (usize, usize, usize) {
    if dst_elem_size >= src_elem_size {
        let num_elems = operation_vl / dst_elem_size;
        let src_bytes = num_elems * src_elem_size;
        (src_bytes, operation_vl, num_elems)
    } else {
        let num_elems = operation_vl / src_elem_size;
        let dst_bytes = num_elems * dst_elem_size;
        (operation_vl, reg_vl_for_bytes(dst_bytes), num_elems)
    }
}

fn read_packed_conversion_src(
    vcpu: &mut X86_64Vcpu,
    evex: &crate::isa::x86_64::cpu::EvexPrefix,
    src_reg: u8,
    is_memory: bool,
    addr: u64,
    src_elem_size: usize,
    src_bytes: usize,
    num_elems: usize,
) -> Result<[u8; 64]> {
    if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, src_elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * src_elem_size;
                data[base..base + src_elem_size].copy_from_slice(&elem_le[..src_elem_size]);
            }
            Ok(data)
        } else {
            load_mem_bytes(vcpu, addr, src_elem_size, num_elems)
        }
    } else {
        Ok(read_reg_bytes(vcpu, src_reg, reg_vl_for_bytes(src_bytes)))
    }
}

#[inline]
fn write_lane_bits(data: &mut [u8; 64], lane: usize, elem_size: usize, value: u64) {
    let base = lane * elem_size;
    data[base..base + elem_size].copy_from_slice(&value.to_le_bytes()[..elem_size]);
}

#[inline]
fn int_elem_to_f64(bits: u64, elem_size: usize, signed: bool) -> f64 {
    match (elem_size, signed) {
        (2, true) => (bits as u16 as i16) as f64,
        (2, false) => (bits as u16) as f64,
        (4, true) => (bits as u32 as i32) as f64,
        (4, false) => (bits as u32) as f64,
        (8, true) => (bits as i64) as f64,
        (8, false) => bits as f64,
        _ => 0.0,
    }
}

fn write_masked_conversion_result(
    vcpu: &mut X86_64Vcpu,
    evex: &crate::isa::x86_64::cpu::EvexPrefix,
    dest: u8,
    dst_elem_size: usize,
    dst_vl_bytes: usize,
    num_elems: usize,
    raw: &[u8; 64],
) {
    let old = read_reg_bytes(vcpu, dest, dst_vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];
    for lane in 0..num_elems {
        let base = lane * dst_elem_size;
        if (mask >> lane) & 1 != 0 {
            result[base..base + dst_elem_size].copy_from_slice(&raw[base..base + dst_elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + dst_elem_size].copy_from_slice(&old[base..base + dst_elem_size]);
        }
    }
    write_vec_vl(vcpu, dest, dst_vl_bytes, &result);
}

pub(super) fn read_fp_elem(bytes: &[u8; 64], lane: usize, elem_size: usize) -> u64 {
    let base = lane * elem_size;
    let mut raw = [0u8; 8];
    raw[..elem_size].copy_from_slice(&bytes[base..base + elem_size]);
    u64::from_le_bytes(raw)
}

/// EVEX scalar FP-to-GPR conversions: VCVT*/VCVTT*SS/SD/SH2SI/USI.
pub fn evex_fp_to_gpr(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    unsigned: bool,
    truncate: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX scalar FP-to-GPR conversion requires EVEX prefix".to_string())
    })?;

    if evex.aaa != 0 || evex.z || evex.vvvv != 0xF || !evex.v_prime {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };
    let src_bits = if is_memory {
        vcpu.read_mem(addr, elem_size as u8)?
    } else {
        let src = evex_rm_vec(&evex, rm);
        read_vec_scalar(vcpu, src, elem_size)
    };
    let value = fp_bits_to_f64(src_bits, elem_size);
    let dst_size = if evex.w { 8 } else { 4 };
    let rounding = evex_rounding_mode(&evex, is_memory, vcpu.mxcsr);
    let result = fp_to_int_bits(value, dst_size, unsigned, truncate, rounding);
    let dest = evex_reg_gpr(&evex, reg);

    vcpu.set_reg(dest, result, dst_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX scalar GPR/memory-to-FP conversions: VCVT(U)SI2SS/SD/SH.
pub fn evex_gpr_to_fp(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    unsigned: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX scalar GPR-to-FP conversion requires EVEX prefix".to_string())
    })?;

    if evex.aaa != 0 || evex.z {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src_size = if evex.w { 8 } else { 4 };
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, src_size as usize)
    } else {
        addr
    };
    let int_bits = if is_memory {
        vcpu.read_mem(addr, src_size)?
    } else {
        let src = evex_rm_gpr(&evex, rm);
        vcpu.get_reg(src, src_size)
    };
    let dest = evex_reg_vec(&evex, reg);
    let src1 = ctx.evex_vvvv();
    let mut result = read_reg_bytes(vcpu, src1, 16);
    let rounding = evex_rounding_mode(&evex, is_memory, vcpu.mxcsr);
    let fp_bits = int_to_fp_bits(int_bits, src_size as usize, elem_size, !unsigned, rounding);
    result[..elem_size].copy_from_slice(&scalar_low_bytes(fp_bits, elem_size)[..elem_size]);

    write_vec_vl(vcpu, dest, 16, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX scalar FP width conversions: VCVTSS2SD, VCVTSD2SS, and FP16 SH forms.
pub fn evex_fp_scalar_convert(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    src_elem_size: usize,
    dst_elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX scalar FP width conversion requires EVEX prefix".to_string())
    })?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = evex_reg_vec(&evex, reg);
    let src1 = ctx.evex_vvvv();
    let src2 = evex_rm_vec(&evex, rm);
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, src_elem_size)
    } else {
        addr
    };
    let src_bits = if is_memory {
        vcpu.read_mem(addr, src_elem_size as u8)?
    } else {
        read_vec_scalar(vcpu, src2, src_elem_size)
    };

    let converted = f64_to_fp_bits(fp_bits_to_f64(src_bits, src_elem_size), dst_elem_size);
    let mut result = read_reg_bytes(vcpu, src1, 16);
    let dest_old = read_reg_bytes(vcpu, dest, 16);
    let active = (evex_mask(vcpu, evex.aaa, 1) & 1) != 0;

    if active {
        result[..dst_elem_size]
            .copy_from_slice(&scalar_low_bytes(converted, dst_elem_size)[..dst_elem_size]);
    } else if evex.z {
        result[..dst_elem_size].fill(0);
    } else {
        result[..dst_elem_size].copy_from_slice(&dest_old[..dst_elem_size]);
    }

    write_vec_vl(vcpu, dest, 16, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed FP width conversions, including FP16 widening/narrowing forms.
pub fn evex_packed_fp_convert(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    src_elem_size: usize,
    dst_elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX packed FP conversion requires EVEX prefix".to_string())
    })?;

    if evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }
    if !matches!(src_elem_size, 2 | 4 | 8) || !matches!(dst_elem_size, 2 | 4 | 8) {
        return Err(Error::Emulator(
            "EVEX packed FP conversion has invalid operands".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = evex_reg_vec(&evex, reg);
    let src = evex_rm_vec(&evex, rm);
    let (src_bytes, dst_vl_bytes, num_elems) = packed_conversion_layout(
        evex_conversion_vl_bytes(&evex, is_memory),
        src_elem_size,
        dst_elem_size,
    );
    let addr = if is_memory {
        let scale = if evex.broadcast {
            src_elem_size
        } else {
            src_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src_data = read_packed_conversion_src(
        vcpu,
        &evex,
        src,
        is_memory,
        addr,
        src_elem_size,
        src_bytes,
        num_elems,
    )?;

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        let value = fp_bits_to_f64(read_lane_u64(&src_data, lane, src_elem_size), src_elem_size);
        write_lane_bits(
            &mut raw,
            lane,
            dst_elem_size,
            f64_to_fp_bits(value, dst_elem_size),
        );
    }

    write_masked_conversion_result(
        vcpu,
        &evex,
        dest,
        dst_elem_size,
        dst_vl_bytes,
        num_elems,
        &raw,
    );
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed integer-to-FP conversions.
pub fn evex_packed_int_to_fp(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    src_elem_size: usize,
    dst_elem_size: usize,
    signed: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX packed integer-to-FP conversion requires EVEX prefix".to_string())
    })?;

    if evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }
    if !matches!(src_elem_size, 2 | 4 | 8) || !matches!(dst_elem_size, 2 | 4 | 8) {
        return Err(Error::Emulator(
            "EVEX packed integer-to-FP conversion has invalid operands".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = evex_reg_vec(&evex, reg);
    let src = evex_rm_vec(&evex, rm);
    let (src_bytes, dst_vl_bytes, num_elems) = packed_conversion_layout(
        evex_conversion_vl_bytes(&evex, is_memory),
        src_elem_size,
        dst_elem_size,
    );
    let addr = if is_memory {
        let scale = if evex.broadcast {
            src_elem_size
        } else {
            src_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src_data = read_packed_conversion_src(
        vcpu,
        &evex,
        src,
        is_memory,
        addr,
        src_elem_size,
        src_bytes,
        num_elems,
    )?;

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        write_lane_bits(
            &mut raw,
            lane,
            dst_elem_size,
            int_to_fp_bits(
                read_lane_u64(&src_data, lane, src_elem_size),
                src_elem_size,
                dst_elem_size,
                signed,
                evex_rounding_mode(&evex, is_memory, vcpu.mxcsr),
            ),
        );
    }

    write_masked_conversion_result(
        vcpu,
        &evex,
        dest,
        dst_elem_size,
        dst_vl_bytes,
        num_elems,
        &raw,
    );
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed FP-to-integer conversions.
pub fn evex_packed_fp_to_int(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    src_elem_size: usize,
    dst_elem_size: usize,
    unsigned: bool,
    truncate: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX packed FP-to-integer conversion requires EVEX prefix".to_string())
    })?;

    if evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }
    if !matches!(src_elem_size, 2 | 4 | 8) || !matches!(dst_elem_size, 2 | 4 | 8) {
        return Err(Error::Emulator(
            "EVEX packed FP-to-integer conversion has invalid operands".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = evex_reg_vec(&evex, reg);
    let src = evex_rm_vec(&evex, rm);
    let (src_bytes, dst_vl_bytes, num_elems) = packed_conversion_layout(
        evex_conversion_vl_bytes(&evex, is_memory),
        src_elem_size,
        dst_elem_size,
    );
    let addr = if is_memory {
        let scale = if evex.broadcast {
            src_elem_size
        } else {
            src_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src_data = read_packed_conversion_src(
        vcpu,
        &evex,
        src,
        is_memory,
        addr,
        src_elem_size,
        src_bytes,
        num_elems,
    )?;

    let mut raw = [0u8; 64];
    let rounding = evex_rounding_mode(&evex, is_memory, vcpu.mxcsr);
    for lane in 0..num_elems {
        let value = fp_bits_to_f64(read_lane_u64(&src_data, lane, src_elem_size), src_elem_size);
        write_lane_bits(
            &mut raw,
            lane,
            dst_elem_size,
            fp_to_int_bits(value, dst_elem_size as u8, unsigned, truncate, rounding),
        );
    }

    write_masked_conversion_result(
        vcpu,
        &evex,
        dest,
        dst_elem_size,
        dst_vl_bytes,
        num_elems,
        &raw,
    );
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// VCVTPS2PH store-style EVEX form: destination is ModRM r/m and source is ModRM.reg.
pub fn evex_packed_fp_convert_store(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    src_elem_size: usize,
    dst_elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX packed FP conversion store requires EVEX prefix".to_string())
    })?;

    if evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }
    if !matches!(src_elem_size, 2 | 4 | 8) || !matches!(dst_elem_size, 2 | 4 | 8) {
        return Err(Error::Emulator(
            "EVEX packed FP conversion store has invalid operands".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let _imm = ctx.consume_u8()?;
    let src = evex_reg_vec(&evex, reg);
    let dest = evex_rm_vec(&evex, rm);
    let src_vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = src_vl_bytes / src_elem_size;
    let dst_bytes = num_elems * dst_elem_size;
    let dst_vl_bytes = reg_vl_for_bytes(dst_bytes);
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, dst_bytes)
    } else {
        addr
    };
    let src_data = read_reg_bytes(vcpu, src, src_vl_bytes);

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        let value = fp_bits_to_f64(read_lane_u64(&src_data, lane, src_elem_size), src_elem_size);
        write_lane_bits(
            &mut raw,
            lane,
            dst_elem_size,
            f64_to_fp_bits(value, dst_elem_size),
        );
    }

    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    if is_memory {
        if evex.z {
            return vcpu.inject_undefined_instruction();
        }
        for lane in 0..num_elems {
            if (mask >> lane) & 1 != 0 {
                let base = lane * dst_elem_size;
                let mut bytes = [0u8; 8];
                bytes[..dst_elem_size].copy_from_slice(&raw[base..base + dst_elem_size]);
                vcpu.write_mem(
                    addr + base as u64,
                    u64::from_le_bytes(bytes),
                    dst_elem_size as u8,
                )?;
            }
        }
    } else {
        write_masked_conversion_result(
            vcpu,
            &evex,
            dest,
            dst_elem_size,
            dst_vl_bytes,
            num_elems,
            &raw,
        );
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

#[derive(Clone, Copy)]
pub enum FpUnaryMathOp {
    GetExp,
    Rcp14,
    Rsqrt14,
    Rcp,
    Rsqrt,
    Exp2,
    RndScale,
    Reduce,
    GetMant,
}

fn fp_round_by_imm(value: f64, imm: u8, mxcsr: u32) -> f64 {
    let rounding = if imm & 0x04 != 0 {
        ((mxcsr >> 13) & 0x03) as u8
    } else {
        imm & 0x03
    };

    match rounding {
        0 => value.round_ties_even(),
        1 => value.floor(),
        2 => value.ceil(),
        _ => value.trunc(),
    }
}

fn fp_getexp(value: f64) -> f64 {
    if value.is_nan() {
        f64::NAN
    } else if value.is_infinite() {
        f64::INFINITY
    } else if value == 0.0 {
        f64::NEG_INFINITY
    } else {
        value.abs().log2().floor()
    }
}

fn fp_getmant_bits(bits: u64, elem_size: usize, imm: u8) -> u64 {
    let (sign_mask, frac_mask, frac_bits, max_exp, bias, one_bits) = match elem_size {
        2 => (0x8000, 0x03ff, 10, 0x1f, 15, 0x3c00),
        4 => (0x8000_0000, 0x007f_ffff, 23, 0xff, 127, 0x3f80_0000),
        8 => (
            0x8000_0000_0000_0000,
            0x000f_ffff_ffff_ffff,
            52,
            0x7ff,
            1023,
            0x3ff0_0000_0000_0000,
        ),
        _ => return bits,
    };

    let sign = bits & sign_mask;
    let exp = (bits >> frac_bits) & max_exp;
    let frac = bits & frac_mask;
    let sign_control = (imm >> 2) & 0x03;
    let interval = imm & 0x03;
    let zero = exp == 0 && frac == 0;
    let infinity = exp == max_exp && frac == 0;
    let nan = exp == max_exp && frac != 0;

    if nan {
        return fp_quiet_nan(bits, elem_size);
    }
    if sign != 0 {
        let signed_one = if sign_control & 0x01 != 0 {
            one_bits
        } else {
            one_bits | sign_mask
        };
        if zero {
            return signed_one;
        }
        if sign_control & 0x02 != 0 {
            return fp_qnan_indefinite(elem_size);
        }
        if infinity {
            return signed_one;
        }
    } else if zero || infinity {
        return one_bits;
    }

    let mut dst_exp = exp as i32;
    let mut dst_frac = frac;
    if exp == 0 {
        dst_exp = bias;
        loop {
            let jbit = (dst_frac >> (frac_bits - 1)) & 1;
            dst_frac = (dst_frac << 1) & frac_mask;
            dst_exp -= 1;
            if jbit != 0 {
                break;
            }
        }
    }

    let unbiased_exp = dst_exp - bias;
    let odd_exp = (unbiased_exp & 1) != 0;
    let signaling_bit = (dst_frac >> (frac_bits - 1)) & 1 != 0;
    let normalized_exp = match interval {
        0 => bias,
        1 => {
            if odd_exp {
                bias - 1
            } else {
                bias
            }
        }
        2 => bias - 1,
        _ => {
            if signaling_bit {
                bias - 1
            } else {
                bias
            }
        }
    } as u64;
    let dst_sign = if sign_control & 0x01 != 0 { 0 } else { sign };

    dst_sign | (normalized_exp << frac_bits) | dst_frac
}

fn fp_unary_math_result(op: FpUnaryMathOp, value: f64, imm: u8, mxcsr: u32) -> f64 {
    match op {
        FpUnaryMathOp::GetExp => fp_getexp(value),
        FpUnaryMathOp::Rcp14 => 1.0 / value,
        FpUnaryMathOp::Rsqrt14 => 1.0 / value.sqrt(),
        FpUnaryMathOp::Rcp => 1.0 / value,
        FpUnaryMathOp::Rsqrt => 1.0 / value.sqrt(),
        FpUnaryMathOp::Exp2 => value.exp2(),
        FpUnaryMathOp::RndScale => {
            let scale = 2.0f64.powi(((imm >> 4) & 0x0f) as i32);
            fp_round_by_imm(value * scale, imm, mxcsr) / scale
        }
        FpUnaryMathOp::Reduce => {
            // REDUCE(±Inf) = +0.0 (the naive value - round(value) would be the
            // invalid inf - inf = NaN). NaN inputs are quieted by the caller.
            if value.is_infinite() {
                0.0
            } else {
                let scale = 2.0f64.powi(((imm >> 4) & 0x0f) as i32);
                value - fp_round_by_imm(value * scale, imm, mxcsr) / scale
            }
        }
        FpUnaryMathOp::GetMant => unreachable!("GetMant is handled at the bit level"),
    }
}

fn fp_unary_math_bits(op: FpUnaryMathOp, bits: u64, elem_size: usize, imm: u8, mxcsr: u32) -> u64 {
    match (op, elem_size) {
        (FpUnaryMathOp::Rcp14, 4) => rcp14_f32_bits(bits as u32) as u64,
        (FpUnaryMathOp::Rsqrt14, 4) => rsqrt14_f32_bits(bits as u32) as u64,
        (FpUnaryMathOp::Rcp14, 8) => rcp14_f64_bits(bits),
        (FpUnaryMathOp::Rsqrt14, 8) => rsqrt14_f64_bits(bits),
        (FpUnaryMathOp::GetMant, _) => fp_getmant_bits(bits, elem_size, imm),
        _ => f64_to_fp_bits(
            fp_unary_math_result(op, fp_bits_to_f64(bits, elem_size), imm, mxcsr),
            elem_size,
        ),
    }
}

fn rcp14_f32_bits(bits: u32) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            return unsafe { rcp14_f32_bits_native(bits) };
        }
    }

    (1.0f32 / f32::from_bits(bits)).to_bits()
}

fn rsqrt14_f32_bits(bits: u32) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            return unsafe { rsqrt14_f32_bits_native(bits) };
        }
    }

    (1.0f32 / f32::from_bits(bits).sqrt()).to_bits()
}

fn rcp14_f64_bits(bits: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            return unsafe { rcp14_f64_bits_native(bits) };
        }
    }

    (1.0f64 / f64::from_bits(bits)).to_bits()
}

fn rsqrt14_f64_bits(bits: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            return unsafe { rsqrt14_f64_bits_native(bits) };
        }
    }

    (1.0f64 / f64::from_bits(bits).sqrt()).to_bits()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn rcp14_f32_bits_native(bits: u32) -> u32 {
    use std::arch::x86_64::*;

    let src = _mm_set_ss(f32::from_bits(bits));
    _mm_cvtss_f32(_mm_rcp14_ss(_mm_setzero_ps(), src)).to_bits()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn rsqrt14_f32_bits_native(bits: u32) -> u32 {
    use std::arch::x86_64::*;

    let src = _mm_set_ss(f32::from_bits(bits));
    _mm_cvtss_f32(_mm_rsqrt14_ss(_mm_setzero_ps(), src)).to_bits()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn rcp14_f64_bits_native(bits: u64) -> u64 {
    use std::arch::x86_64::*;

    let src = _mm_set_sd(f64::from_bits(bits));
    _mm_cvtsd_f64(_mm_rcp14_sd(_mm_setzero_pd(), src)).to_bits()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn rsqrt14_f64_bits_native(bits: u64) -> u64 {
    use std::arch::x86_64::*;

    let src = _mm_set_sd(f64::from_bits(bits));
    _mm_cvtsd_f64(_mm_rsqrt14_sd(_mm_setzero_pd(), src)).to_bits()
}

/// EVEX VMOVD/VMOVQ/VMOVW load form: GPR or memory scalar into XMM, zeroing
/// the rest of the architectural vector register.
pub fn evex_gpr_or_mem_to_xmm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX scalar integer move requires EVEX prefix".to_string())
    })?;

    if evex.aaa != 0 || evex.z || evex.broadcast || evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };
    let dest = evex_reg_vec(&evex, reg);
    let value = if is_memory {
        vcpu.read_mem(addr, elem_size as u8)?
    } else {
        let src = evex_rm_gpr(&evex, rm);
        let reg_size = if elem_size == 8 { 8 } else { 4 };
        vcpu.get_reg(src, reg_size)
    };

    write_vec_scalar_zero_upper(vcpu, dest, elem_size, value);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VMOVD/VMOVQ/VMOVW store form: low scalar from XMM to GPR or memory.
pub fn evex_xmm_to_gpr_or_mem(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX scalar integer move requires EVEX prefix".to_string())
    })?;

    if evex.aaa != 0 || evex.z || evex.broadcast || evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };
    let src = evex_reg_vec(&evex, reg);
    let value = read_vec_scalar(vcpu, src, elem_size);

    if is_memory {
        vcpu.write_mem(addr, value, elem_size as u8)?;
    } else {
        let dest = evex_rm_gpr(&evex, rm);
        let reg_size = if elem_size == 8 { 8 } else { 4 };
        vcpu.set_reg(dest, value, reg_size);
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPEXTR*/VEXTRACTPS: extract a scalar element from XMM into a GPR or
/// memory destination.
pub fn evex_extract_scalar(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    gpr_size: u8,
    allow_memory: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX scalar extract requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast || evex.vvvv != 0xF || evex.ll != 0 {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };
    let imm = ctx.consume_u8()? as usize;
    if is_memory && !allow_memory {
        return Err(Error::Emulator(
            "EVEX scalar extract form requires register destination".to_string(),
        ));
    }

    let src = evex_reg_vec(&evex, reg);
    let idx = imm & ((16 / elem_size) - 1);
    let base = idx * elem_size;
    let src_bytes = read_reg_bytes(vcpu, src, 16);
    let mut raw = [0u8; 8];
    raw[..elem_size].copy_from_slice(&src_bytes[base..base + elem_size]);
    let value = u64::from_le_bytes(raw);

    if is_memory {
        vcpu.write_mem(addr, value, elem_size as u8)?;
    } else {
        let dest = evex_rm_gpr(&evex, rm);
        vcpu.set_reg(dest, value, gpr_size);
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX 0F.C5 VPEXTRW: extract a word from XMM r/m into the GPR reg field.
pub fn evex_extract_word_rm_src(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX VPEXTRW requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast || evex.vvvv != 0xF || evex.ll != 0 {
        return vcpu.inject_undefined_instruction();
    }

    let (reg, rm, is_memory, _addr, _) = vcpu.decode_modrm(ctx)?;
    if is_memory {
        return vcpu.inject_undefined_instruction();
    }

    let imm = ctx.consume_u8()? as usize;
    let src = evex_rm_vec(&evex, rm);
    let idx = imm & 0x07;
    let base = idx * 2;
    let src_bytes = read_reg_bytes(vcpu, src, 16);
    let value = u16::from_le_bytes([src_bytes[base], src_bytes[base + 1]]) as u64;
    let dest = evex_reg_gpr(&evex, reg);
    vcpu.set_reg(dest, value, 4);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPINSRB/W/D/Q: insert a scalar GPR/memory element into the XMM value
/// from EVEX.vvvv and zero all bits above 128 in the destination register.
pub fn evex_pinsr(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX scalar insert requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast || evex.ll != 0 {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };
    let imm = ctx.consume_u8()? as usize;
    let dest = evex_reg_vec(&evex, reg);
    let src1 = ctx.evex_vvvv();
    let src2_value = if is_memory {
        vcpu.read_mem(addr, elem_size as u8)?
    } else {
        let src2 = evex_rm_gpr(&evex, rm);
        let reg_size = if elem_size == 8 { 8 } else { 4 };
        vcpu.get_reg(src2, reg_size)
    };

    let mut raw = read_reg_bytes(vcpu, src1, 16);
    let elem_count = 16 / elem_size;
    let idx = imm & (elem_count - 1);
    let base = idx * elem_size;
    raw[base..base + elem_size].copy_from_slice(&src2_value.to_le_bytes()[..elem_size]);

    write_vec_vl(vcpu, dest, 16, &raw);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VINSERTPS: insert one 32-bit FP lane from XMM/m32 into the XMM value
/// from EVEX.vvvv, then apply the immediate zero mask.
pub fn evex_insertps(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX VINSERTPS requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast || evex.ll != 0 || evex.w {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, 4)
    } else {
        addr
    };
    let imm = ctx.consume_u8()?;
    let dest = evex_reg_vec(&evex, reg);
    let src1 = ctx.evex_vvvv();
    let mut raw = read_reg_bytes(vcpu, src1, 16);

    let src_value = if is_memory {
        vcpu.read_mem(addr, 4)? as u32
    } else {
        let src2 = evex_rm_vec(&evex, rm);
        let src2_bytes = read_reg_bytes(vcpu, src2, 16);
        let src_lane = ((imm >> 6) & 0x03) as usize;
        let base = src_lane * 4;
        u32::from_le_bytes(src2_bytes[base..base + 4].try_into().unwrap())
    };

    let dest_lane = ((imm >> 4) & 0x03) as usize;
    let dest_base = dest_lane * 4;
    raw[dest_base..dest_base + 4].copy_from_slice(&src_value.to_le_bytes());

    for lane in 0..4 {
        if (imm >> lane) & 1 != 0 {
            raw[lane * 4..lane * 4 + 4].fill(0);
        }
    }

    write_vec_vl(vcpu, dest, 16, &raw);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VMOVQ F3.0F.7E load form: XMM/m64 to XMM, zeroing upper bits.
pub fn evex_movq_vec_load(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX VMOVQ requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast || evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, 8)
    } else {
        addr
    };
    let dest = evex_reg_vec(&evex, reg);
    let value = if is_memory {
        vcpu.read_mem(addr, 8)?
    } else {
        let src = evex_rm_vec(&evex, rm);
        read_vec_scalar(vcpu, src, 8)
    };

    write_vec_scalar_zero_upper(vcpu, dest, 8, value);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VMOVQ 66.0F.D6 store form: low qword from XMM to XMM/m64.
pub fn evex_movq_vec_store(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX VMOVQ requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast || evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, 8)
    } else {
        addr
    };
    let src = evex_reg_vec(&evex, reg);
    let value = read_vec_scalar(vcpu, src, 8);

    if is_memory {
        vcpu.write_mem(addr, value, 8)?;
    } else {
        let dest = evex_rm_vec(&evex, rm);
        write_vec_scalar_zero_upper(vcpu, dest, 8, value);
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VMOVSS/VMOVSD/VMOVSH scalar move.
pub fn evex_scalar_fp_move(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    store_form: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX scalar FP move requires EVEX prefix".to_string()))?;

    if evex.broadcast {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };
    let reg_vec = evex_reg_vec(&evex, reg);
    let active = evex.aaa == 0 || (vcpu.regs.k[evex.aaa as usize] & 1) != 0;

    if is_memory && store_form {
        if evex.z {
            return vcpu.inject_undefined_instruction();
        }
        if evex.vvvv != 0xF {
            return vcpu.inject_undefined_instruction();
        }
        if active {
            let value = read_vec_scalar(vcpu, reg_vec, elem_size);
            vcpu.write_mem(addr, value, elem_size as u8)?;
        }
        vcpu.regs.rip += ctx.cursor as u64;
        return Ok(None);
    }

    let dest = reg_vec;
    let dest_old = read_reg_bytes(vcpu, dest, 16);
    let mut result = [0u8; 64];

    if is_memory {
        if evex.vvvv != 0xF {
            return vcpu.inject_undefined_instruction();
        }
        if active {
            let value = vcpu.read_mem(addr, elem_size as u8)?;
            result[..elem_size].copy_from_slice(&scalar_low_bytes(value, elem_size)[..elem_size]);
        } else if !evex.z {
            result[..elem_size].copy_from_slice(&dest_old[..elem_size]);
        }
    } else {
        let src1 = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
        let src2 = evex_rm_vec(&evex, rm);
        let src1_bytes = read_reg_bytes(vcpu, src1, 16);
        result[elem_size..16].copy_from_slice(&src1_bytes[elem_size..16]);
        if active {
            let src2_bytes = read_reg_bytes(vcpu, src2, 16);
            result[..elem_size].copy_from_slice(&src2_bytes[..elem_size]);
        } else if !evex.z {
            result[..elem_size].copy_from_slice(&dest_old[..elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, 16, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VMOVLPS/VMOVHPS/VMOVLPD/VMOVHPD and register aliases
/// VMOVHLPS/VMOVLHPS.
pub fn evex_high_low_move(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    high: bool,
    packed_single: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX high/low move requires EVEX prefix".to_string()))?;

    if evex.ll != 0 || evex.aaa != 0 || evex.z || evex.broadcast {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, 8)
    } else {
        addr
    };
    let dest = evex_reg_vec(&evex, reg);
    let src1 = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src1_bytes = read_reg_bytes(vcpu, src1, 16);
    let mut result = [0u8; 64];

    if is_memory {
        let mem = vcpu.read_mem(addr, 8)?.to_le_bytes();
        if high {
            result[..8].copy_from_slice(&src1_bytes[..8]);
            result[8..16].copy_from_slice(&mem);
        } else {
            result[..8].copy_from_slice(&mem);
            result[8..16].copy_from_slice(&src1_bytes[8..16]);
        }
    } else {
        if !packed_single {
            return vcpu.inject_undefined_instruction();
        }
        let src2 = evex_rm_vec(&evex, rm);
        let src2_bytes = read_reg_bytes(vcpu, src2, 16);
        if high {
            result[..8].copy_from_slice(&src1_bytes[..8]);
            result[8..16].copy_from_slice(&src2_bytes[..8]);
        } else {
            result[..8].copy_from_slice(&src2_bytes[8..16]);
            result[8..16].copy_from_slice(&src1_bytes[8..16]);
        }
    }

    write_vec_vl(vcpu, dest, 16, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VMOVSLDUP/VMOVSHDUP/VMOVDDUP.
pub fn evex_duplicate_lanes(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    high: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX duplicate move requires EVEX prefix".to_string()))?;

    if evex.broadcast || evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = evex_reg_vec(&evex, reg);
    let src_reg = evex_rm_vec(&evex, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let xmm_movddup_mem = is_memory && elem_size == 8 && vl_bytes == 16;
    let addr = if is_memory {
        let tuple_bytes = if xmm_movddup_mem { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, tuple_bytes)
    } else {
        addr
    };
    let src = if is_memory {
        let mem_elems = if xmm_movddup_mem { 1 } else { num_elems };
        load_mem_bytes(vcpu, addr, elem_size, mem_elems)?
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        let src_lane = if elem_size == 8 {
            lane & !1
        } else if high {
            lane | 1
        } else {
            lane & !1
        };
        let dst_base = lane * elem_size;
        let src_base = src_lane * elem_size;
        raw[dst_base..dst_base + elem_size].copy_from_slice(&src[src_base..src_base + elem_size]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPSHUFD/HW/LW immediate shuffle.
pub fn evex_shuffle_imm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: ShuffleImmKind,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator(format!("{} requires EVEX prefix", kind.name())))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let imm8 = ctx.consume_u8()?;
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };
    let vl_bytes = vl_bytes_of(evex.ll);
    let elem_size = kind.elem_size();
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src_bytes = if is_memory {
        if evex.broadcast {
            if !matches!(kind, ShuffleImmKind::Dword) {
                return Err(Error::Emulator(format!(
                    "{} does not support embedded broadcast",
                    kind.name()
                )));
            }
            let elem = vcpu.read_mem(addr, 4)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..(vl_bytes / 4) {
                let base = lane * 4;
                data[base..base + 4].copy_from_slice(&elem[..4]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for block_base in (0..vl_bytes).step_by(16) {
        match kind {
            ShuffleImmKind::Dword => {
                for dst_lane in 0..4 {
                    let src_lane = ((imm8 >> (dst_lane * 2)) & 0x3) as usize;
                    let dst_base = block_base + dst_lane * 4;
                    let src_base = block_base + src_lane * 4;
                    raw[dst_base..dst_base + 4].copy_from_slice(&src_bytes[src_base..src_base + 4]);
                }
            }
            ShuffleImmKind::HighWord => {
                raw[block_base..block_base + 8]
                    .copy_from_slice(&src_bytes[block_base..block_base + 8]);
                for dst_lane in 0..4 {
                    let src_lane = ((imm8 >> (dst_lane * 2)) & 0x3) as usize;
                    let dst_base = block_base + 8 + dst_lane * 2;
                    let src_base = block_base + 8 + src_lane * 2;
                    raw[dst_base..dst_base + 2].copy_from_slice(&src_bytes[src_base..src_base + 2]);
                }
            }
            ShuffleImmKind::LowWord => {
                for dst_lane in 0..4 {
                    let src_lane = ((imm8 >> (dst_lane * 2)) & 0x3) as usize;
                    let dst_base = block_base + dst_lane * 2;
                    let src_base = block_base + src_lane * 2;
                    raw[dst_base..dst_base + 2].copy_from_slice(&src_bytes[src_base..src_base + 2]);
                }
                raw[block_base + 8..block_base + 16]
                    .copy_from_slice(&src_bytes[block_base + 8..block_base + 16]);
            }
        }
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VSHUFPS/VSHUFPD: lane-local immediate shuffle from src1 and src2/mem.
pub fn evex_shufp(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX VSHUFP* requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let imm8 = ctx.consume_u8()?;
    let dest = evex_reg_vec(&evex, reg);
    let src1 = ctx.evex_vvvv();
    let src2_reg = evex_rm_vec(&evex, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, elem_size as u8)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for block_base in (0..vl_bytes).step_by(16) {
        match elem_size {
            4 => {
                for dst_lane in 0..4 {
                    let src_lane = ((imm8 >> (dst_lane * 2)) & 0x3) as usize;
                    let src_bytes = if dst_lane < 2 {
                        &src1_bytes
                    } else {
                        &src2_bytes
                    };
                    let dst_base = block_base + dst_lane * 4;
                    let src_base = block_base + src_lane * 4;
                    raw[dst_base..dst_base + 4].copy_from_slice(&src_bytes[src_base..src_base + 4]);
                }
            }
            8 => {
                let pair = block_base / 16;
                let src1_lane = ((imm8 >> (pair * 2)) & 0x1) as usize;
                let src2_lane = ((imm8 >> (pair * 2 + 1)) & 0x1) as usize;
                let src1_base = block_base + src1_lane * 8;
                let src2_base = block_base + src2_lane * 8;
                raw[block_base..block_base + 8]
                    .copy_from_slice(&src1_bytes[src1_base..src1_base + 8]);
                raw[block_base + 8..block_base + 16]
                    .copy_from_slice(&src2_bytes[src2_base..src2_base + 8]);
            }
            _ => {
                return Err(Error::Emulator(
                    "EVEX VSHUFP* requires dword or qword elements".to_string(),
                ));
            }
        }
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

fn read_lane_u64(data: &[u8; 64], lane: usize, elem_size: usize) -> u64 {
    let base = lane * elem_size;
    let mut bytes = [0u8; 8];
    bytes[..elem_size].copy_from_slice(&data[base..base + elem_size]);
    u64::from_le_bytes(bytes)
}

/// EVEX VPERMPS/VPERMPD/VPERMD/VPERMQ/VPERMW variable-index forms.
pub fn evex_permute_var(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    allow_128: bool,
    allow_broadcast: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX variable permute requires EVEX prefix".to_string()))?;

    let vl_bytes = vl_bytes_of(evex.ll);
    if vl_bytes == 16 && !allow_128 {
        return Err(Error::Emulator(
            "EVEX variable permute has no 128-bit form".to_string(),
        ));
    }
    if !matches!(elem_size, 2 | 4 | 8) {
        return Err(Error::Emulator(
            "EVEX variable permute requires word, dword, or qword elements".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, index_reg, src_reg) = evex_three_op(&evex, reg, rm);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src = if is_memory {
        if evex.broadcast {
            if !allow_broadcast {
                return Err(Error::Emulator(
                    "EVEX variable permute form does not support embedded broadcast".to_string(),
                ));
            }
            let elem = vcpu.read_mem(addr, elem_size as u8)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };
    let index = read_reg_bytes(vcpu, index_reg, vl_bytes);

    let mut raw = [0u8; 64];
    let selector_mask = num_elems - 1;
    for lane in 0..num_elems {
        let selected = (read_lane_u64(&index, lane, elem_size) as usize) & selector_mask;
        let dst_base = lane * elem_size;
        let src_base = selected * elem_size;
        raw[dst_base..dst_base + elem_size].copy_from_slice(&src[src_base..src_base + elem_size]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPERMI2*/VPERMT2* two-table permutes.
///
/// VPERMI2 overwrites the index vector held in the ModR/M.reg destination.
/// VPERMT2 overwrites the first table held in the ModR/M.reg destination.
pub fn evex_two_table_permute(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    dest_is_index: bool,
    allow_broadcast: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX two-table permute requires EVEX prefix".to_string())
    })?;
    if !matches!(elem_size, 1 | 2 | 4 | 8) {
        return Err(Error::Emulator(
            "EVEX two-table permute requires byte, word, dword, or qword elements".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src2 = if is_memory {
        if evex.broadcast {
            if !allow_broadcast {
                return Err(Error::Emulator(
                    "EVEX two-table permute form does not support embedded broadcast".to_string(),
                ));
            }
            let elem = vcpu.read_mem(addr, elem_size as u8)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let table1_reg = if dest_is_index { src1 } else { dest };
    let index_reg = if dest_is_index { dest } else { src1 };
    let table1 = read_reg_bytes(vcpu, table1_reg, vl_bytes);
    let index = read_reg_bytes(vcpu, index_reg, vl_bytes);

    let mut raw = [0u8; 64];
    let selector_mask = (num_elems * 2) - 1;
    for lane in 0..num_elems {
        let selected = (read_lane_u64(&index, lane, elem_size) as usize) & selector_mask;
        let dst_base = lane * elem_size;
        let (src, src_lane) = if selected < num_elems {
            (&table1, selected)
        } else {
            (&src2, selected - num_elems)
        };
        let src_base = src_lane * elem_size;
        raw[dst_base..dst_base + elem_size].copy_from_slice(&src[src_base..src_base + elem_size]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPERMQ/VPERMPD immediate qword forms.
pub fn evex_permute_qword_imm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX qword permute requires EVEX prefix".to_string()))?;

    let vl_bytes = vl_bytes_of(evex.ll);
    if vl_bytes == 16 {
        return Err(Error::Emulator(
            "EVEX qword immediate permute has no 128-bit form".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let imm8 = ctx.consume_u8()?;
    let dest = evex_reg_vec(&evex, reg);
    let src_reg = evex_rm_vec(&evex, rm);
    let num_elems = vl_bytes / 8;
    let addr = if is_memory {
        let scale = if evex.broadcast { 8 } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, 8)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * 8;
                data[base..base + 8].copy_from_slice(&elem);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, 8, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        let half_base = (lane / 4) * 4;
        let control = (lane % 4) * 2;
        let selected = half_base + (((imm8 >> control) & 0x3) as usize);
        let dst_base = lane * 8;
        let src_base = selected * 8;
        raw[dst_base..dst_base + 8].copy_from_slice(&src[src_base..src_base + 8]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, 8, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPERMILPS/VPERMILPD variable-control forms.
pub fn evex_permil_var(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX VPERMIL* requires EVEX prefix".to_string()))?;
    if !matches!(elem_size, 4 | 8) {
        return Err(Error::Emulator(
            "EVEX VPERMIL* requires dword or qword elements".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, control_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let elems_per_lane = 16 / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let control = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, elem_size as u8)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, control_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    let selector_mask = elems_per_lane - 1;
    for lane in 0..num_elems {
        let lane_base = (lane / elems_per_lane) * elems_per_lane;
        let control_value = read_lane_u64(&control, lane, elem_size) as usize;
        let selector = if elem_size == 8 {
            (control_value >> 1) & selector_mask
        } else {
            control_value & selector_mask
        };
        let selected = lane_base + selector;
        let dst_base = lane * elem_size;
        let src_base = selected * elem_size;
        raw[dst_base..dst_base + elem_size]
            .copy_from_slice(&src1_bytes[src_base..src_base + elem_size]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPERMILPS/VPERMILPD immediate-control forms.
pub fn evex_permil_imm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX VPERMIL* immediate requires EVEX prefix".to_string())
    })?;
    if !matches!(elem_size, 4 | 8) {
        return Err(Error::Emulator(
            "EVEX VPERMIL* immediate requires dword or qword elements".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let imm8 = ctx.consume_u8()?;
    let dest = evex_reg_vec(&evex, reg);
    let src_reg = evex_rm_vec(&evex, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let elems_per_lane = 16 / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, elem_size as u8)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        let lane_base = (lane / elems_per_lane) * elems_per_lane;
        let lane_offset = lane % elems_per_lane;
        let selected = if elem_size == 4 {
            lane_base + (((imm8 >> (lane_offset * 2)) & 0x3) as usize)
        } else {
            lane_base + (((imm8 >> lane) & 0x1) as usize)
        };
        let dst_base = lane * elem_size;
        let src_base = selected * elem_size;
        raw[dst_base..dst_base + elem_size].copy_from_slice(&src[src_base..src_base + elem_size]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPCONFLICTD/VPCONFLICTQ.
pub fn evex_conflict(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX VPCONFLICT* requires EVEX prefix".to_string()))?;
    if !matches!(elem_size, 4 | 8) {
        return Err(Error::Emulator(
            "EVEX VPCONFLICT* requires dword or qword elements".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = evex_reg_vec(&evex, reg);
    let src_reg = evex_rm_vec(&evex, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    let src = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, elem_size as u8)?.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        let value = read_lane_u64(&src, lane, elem_size);
        let mut conflict = 0u64;
        for previous in 0..lane {
            if read_lane_u64(&src, previous, elem_size) == value {
                conflict |= 1u64 << previous;
            }
        }
        let base = lane * elem_size;
        raw[base..base + elem_size].copy_from_slice(&conflict.to_le_bytes()[..elem_size]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPSHUFB: lane-local byte shuffle using src2 control bytes.
pub fn evex_pshufb(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VPSHUFB requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, control_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let control = if is_memory {
        load_mem_bytes(vcpu, addr, 1, vl_bytes)?
    } else {
        read_reg_bytes(vcpu, control_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for block_base in (0..vl_bytes).step_by(16) {
        for lane in 0..16 {
            let selector = control[block_base + lane];
            raw[block_base + lane] = if selector & 0x80 != 0 {
                0
            } else {
                src1_bytes[block_base + (selector & 0x0f) as usize]
            };
        }
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, 1, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPALIGNR: byte-align each 128-bit lane from src2|src1.
pub fn evex_palignr(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VPALIGNR requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let imm8 = ctx.consume_u8()? as usize;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        load_mem_bytes(vcpu, addr, 1, vl_bytes)?
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let mut raw = [0u8; 64];
    for block_base in (0..vl_bytes).step_by(16) {
        let mut concatenated = [0u8; 32];
        concatenated[..16].copy_from_slice(&src2_bytes[block_base..block_base + 16]);
        concatenated[16..].copy_from_slice(&src1_bytes[block_base..block_base + 16]);
        for lane in 0..16 {
            let idx = imm8 + lane;
            raw[block_base + lane] = if idx < 32 { concatenated[idx] } else { 0 };
        }
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, 1, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPSADBW: sum absolute byte differences into qword lanes.
pub fn evex_psadbw(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("VPSADBW requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z {
        return Err(Error::Emulator(
            "VPSADBW does not support EVEX writemasks".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        load_mem_bytes(vcpu, addr, 1, vl_bytes)?
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };
    let mut result = [0u8; 64];

    for group_base in (0..vl_bytes).step_by(8) {
        let mut sum = 0u16;
        for lane in 0..8 {
            let a = src1_bytes[group_base + lane] as i16;
            let b = src2_bytes[group_base + lane] as i16;
            sum = sum.wrapping_add((a - b).unsigned_abs());
        }
        result[group_base..group_base + 2].copy_from_slice(&sum.to_le_bytes());
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VUNPCKL/HPS/PD and VPUNPCKL/H* lane-local interleave.
pub fn evex_unpack(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    high_half: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX unpack requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        if evex.broadcast {
            if !matches!(elem_size, 4 | 8) {
                return Err(Error::Emulator(
                    "EVEX unpack broadcast requires dword/qword elements".to_string(),
                ));
            }
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let elems_per_128 = 16 / elem_size;
    let half = elems_per_128 / 2;
    let first = if high_half { half } else { 0 };
    let mut raw = [0u8; 64];

    for block_base in (0..vl_bytes).step_by(16) {
        for lane in 0..half {
            let src_elem = first + lane;
            let dst0 = block_base + (lane * 2) * elem_size;
            let dst1 = dst0 + elem_size;
            let src_base = block_base + src_elem * elem_size;
            raw[dst0..dst0 + elem_size]
                .copy_from_slice(&src1_bytes[src_base..src_base + elem_size]);
            raw[dst1..dst1 + elem_size]
                .copy_from_slice(&src2_bytes[src_base..src_base + elem_size]);
        }
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Generic EVEX integer absolute-value instruction (VPABSB/W/D/Q).
pub fn evex_int_abs(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX integer abs requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast && matches!(elem_size, 4 | 8) {
            elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src_bytes = if is_memory {
        if evex.broadcast && matches!(elem_size, 4 | 8) {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for i in 0..num_elems {
                let base = i * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];

    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            match elem_size {
                1 => result[base] = (src_bytes[base] as i8).wrapping_abs() as u8,
                2 => {
                    let value = i16::from_le_bytes([src_bytes[base], src_bytes[base + 1]]);
                    result[base..base + 2]
                        .copy_from_slice(&(value.wrapping_abs() as u16).to_le_bytes());
                }
                4 => {
                    let value = i32::from_le_bytes([
                        src_bytes[base],
                        src_bytes[base + 1],
                        src_bytes[base + 2],
                        src_bytes[base + 3],
                    ]);
                    result[base..base + 4]
                        .copy_from_slice(&(value.wrapping_abs() as u32).to_le_bytes());
                }
                8 => {
                    let value = i64::from_le_bytes([
                        src_bytes[base],
                        src_bytes[base + 1],
                        src_bytes[base + 2],
                        src_bytes[base + 3],
                        src_bytes[base + 4],
                        src_bytes[base + 5],
                        src_bytes[base + 6],
                        src_bytes[base + 7],
                    ]);
                    result[base..base + 8]
                        .copy_from_slice(&(value.wrapping_abs() as u64).to_le_bytes());
                }
                _ => {}
            }
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Packed bit-count operation for unary EVEX integer count instructions.
#[derive(Clone, Copy)]
pub enum CountKind {
    Popcnt,
    Lzcnt,
}

fn count_elem(kind: CountKind, value: u128, elem_size: usize) -> u64 {
    match kind {
        CountKind::Popcnt => value.count_ones() as u64,
        CountKind::Lzcnt => match elem_size {
            4 => (value as u32).leading_zeros() as u64,
            8 => (value as u64).leading_zeros() as u64,
            2 => (value as u16).leading_zeros() as u64,
            _ => (value as u8).leading_zeros() as u64,
        },
    }
}

/// EVEX VPOPCNTB/W/D/Q and VPLZCNTD/Q.
pub fn evex_count(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: CountKind,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX count requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = if !evex.r { reg + 8 } else { reg };
    let dest = if !evex.r_prime { dest + 16 } else { dest };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src_bytes = if is_memory {
        if evex.broadcast && matches!(elem_size, 4 | 8) {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];

    for lane in 0..num_elems {
        let base = lane * elem_size;
        if (mask >> lane) & 1 != 0 {
            let value = elem_unsigned(&src_bytes[base..base + elem_size], elem_size);
            let counted = count_elem(kind, value, elem_size);
            result[base..base + elem_size].copy_from_slice(&counted.to_le_bytes()[..elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

fn reg_read_vl_for_bytes(bytes: usize) -> usize {
    if bytes <= 16 {
        16
    } else if bytes <= 32 {
        32
    } else {
        64
    }
}

fn extend_int_value(src: &[u8], src_elem_size: usize, signed: bool) -> u64 {
    if signed {
        match src_elem_size {
            1 => src[0] as i8 as i64 as u64,
            2 => i16::from_le_bytes([src[0], src[1]]) as i64 as u64,
            4 => i32::from_le_bytes([src[0], src[1], src[2], src[3]]) as i64 as u64,
            _ => 0,
        }
    } else {
        match src_elem_size {
            1 => src[0] as u64,
            2 => u16::from_le_bytes([src[0], src[1]]) as u64,
            4 => u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as u64,
            _ => 0,
        }
    }
}

#[derive(Clone, Copy)]
pub enum NarrowMode {
    Truncate,
    SignedSaturate,
    UnsignedSaturate,
}

fn narrow_int_value(
    src: &[u8],
    src_elem_size: usize,
    dst_elem_size: usize,
    mode: NarrowMode,
) -> u64 {
    match mode {
        NarrowMode::Truncate => elem_unsigned(src, src_elem_size) as u64,
        NarrowMode::SignedSaturate => {
            let value = elem_signed(src, src_elem_size);
            let dst_bits = (dst_elem_size * 8) as u32;
            let min = -(1i128 << (dst_bits - 1));
            let max = (1i128 << (dst_bits - 1)) - 1;
            value.clamp(min, max) as i64 as u64
        }
        NarrowMode::UnsignedSaturate => {
            // The source element is interpreted as UNSIGNED and clamped to
            // [0, 2^dstbits - 1]; reading it as signed would wrongly collapse
            // any high-bit-set source to 0 instead of saturating to the max.
            let value = elem_unsigned(src, src_elem_size) as i128;
            let dst_bits = (dst_elem_size * 8) as u32;
            let max = (1i128 << dst_bits) - 1;
            value.clamp(0, max) as u64
        }
    }
}

/// EVEX VPMOVSX*/VPMOVZX*: sign/zero extend packed integer elements into a
/// wider destination vector, with destination-element writemasking.
pub fn evex_int_extend(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    src_elem_size: usize,
    dst_elem_size: usize,
    signed: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX integer extend requires EVEX prefix".to_string()))?;

    if evex.broadcast {
        return Err(Error::Emulator(
            "EVEX integer extend does not support embedded broadcast".to_string(),
        ));
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / dst_elem_size;
    let src_bytes_len = num_elems * src_elem_size;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, src_bytes_len)
    } else {
        addr
    };
    let src_bytes = if is_memory {
        load_mem_bytes(vcpu, addr, src_elem_size, num_elems)?
    } else {
        read_reg_bytes(vcpu, src_reg, reg_read_vl_for_bytes(src_bytes_len))
    };

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        let src_base = lane * src_elem_size;
        let dst_base = lane * dst_elem_size;
        let value = extend_int_value(
            &src_bytes[src_base..src_base + src_elem_size],
            src_elem_size,
            signed,
        );
        raw[dst_base..dst_base + dst_elem_size]
            .copy_from_slice(&value.to_le_bytes()[..dst_elem_size]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, dst_elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPMOV*/VPMOVS*/VPMOVUS*: narrow packed integer elements into a smaller
/// vector or memory destination, with destination-element writemasking.
pub fn evex_int_narrow(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    src_elem_size: usize,
    dst_elem_size: usize,
    mode: NarrowMode,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX integer narrow requires EVEX prefix".to_string()))?;

    if evex.broadcast {
        return vcpu.inject_undefined_instruction();
    }
    if evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let dest = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let src_vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = src_vl_bytes / src_elem_size;
    let dst_bytes_len = num_elems * dst_elem_size;
    let dst_reg_vl_bytes = reg_read_vl_for_bytes(dst_bytes_len);
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, dst_bytes_len)
    } else {
        addr
    };
    let src_bytes = read_reg_bytes(vcpu, src, src_vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let mut raw = [0u8; 64];
    for lane in 0..num_elems {
        let src_base = lane * src_elem_size;
        let dst_base = lane * dst_elem_size;
        let value = narrow_int_value(
            &src_bytes[src_base..src_base + src_elem_size],
            src_elem_size,
            dst_elem_size,
            mode,
        );
        raw[dst_base..dst_base + dst_elem_size]
            .copy_from_slice(&value.to_le_bytes()[..dst_elem_size]);
    }

    if is_memory {
        if evex.z {
            return vcpu.inject_undefined_instruction();
        }
        for lane in 0..num_elems {
            if (mask >> lane) & 1 == 0 {
                continue;
            }
            let base = lane * dst_elem_size;
            let mut bytes = [0u8; 8];
            bytes[..dst_elem_size].copy_from_slice(&raw[base..base + dst_elem_size]);
            vcpu.write_mem(
                addr + base as u64,
                u64::from_le_bytes(bytes),
                dst_elem_size as u8,
            )?;
        }
    } else {
        let mut result = [0u8; 64];
        let dest_old = read_reg_bytes(vcpu, dest, dst_reg_vl_bytes);
        for lane in 0..num_elems {
            let base = lane * dst_elem_size;
            if (mask >> lane) & 1 != 0 {
                result[base..base + dst_elem_size]
                    .copy_from_slice(&raw[base..base + dst_elem_size]);
            } else if evex.z {
                // Zeroing: leave as 0.
            } else {
                result[base..base + dst_elem_size]
                    .copy_from_slice(&dest_old[base..base + dst_elem_size]);
            }
        }
        write_vec_vl(vcpu, dest, dst_reg_vl_bytes, &result);
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VEXTRACTF*/VEXTRACTI*: extract a 128-bit or 256-bit chunk from a
/// larger vector into a register or memory destination.
pub fn evex_extract_chunk(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    chunk_bytes: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX extract chunk requires EVEX prefix".to_string()))?;

    if evex.vvvv != 0xF {
        return vcpu.inject_undefined_instruction();
    }
    if evex.broadcast {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, chunk_bytes)
    } else {
        addr
    };
    let imm = ctx.consume_u8()? as usize;
    let src = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let dest = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let src_vl_bytes = vl_bytes_of(evex.ll);
    if chunk_bytes == 0 || src_vl_bytes <= chunk_bytes || chunk_bytes % elem_size != 0 {
        return Err(Error::Emulator(
            "EVEX extract chunk has invalid vector length".to_string(),
        ));
    }

    let num_chunks = src_vl_bytes / chunk_bytes;
    let chunk = imm & (num_chunks - 1);
    let src_base = chunk * chunk_bytes;
    let num_elems = chunk_bytes / elem_size;
    let src_bytes = read_reg_bytes(vcpu, src, src_vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let mut raw = [0u8; 64];
    raw[..chunk_bytes].copy_from_slice(&src_bytes[src_base..src_base + chunk_bytes]);

    if is_memory {
        if evex.z {
            return vcpu.inject_undefined_instruction();
        }
        for lane in 0..num_elems {
            if (mask >> lane) & 1 == 0 {
                continue;
            }
            let base = lane * elem_size;
            let mut bytes = [0u8; 8];
            bytes[..elem_size].copy_from_slice(&raw[base..base + elem_size]);
            vcpu.write_mem(
                addr + base as u64,
                u64::from_le_bytes(bytes),
                elem_size as u8,
            )?;
        }
    } else {
        let result = apply_evex_mask(vcpu, &evex, dest, chunk_bytes, elem_size, &raw);
        write_vec_vl(vcpu, dest, chunk_bytes, &result);
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VINSERTF*/VINSERTI*: insert a 128-bit or 256-bit chunk into a larger
/// vector built from EVEX.vvvv/source1, then apply destination writemasking.
pub fn evex_insert_chunk(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    chunk_bytes: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX insert chunk requires EVEX prefix".to_string()))?;

    if evex.broadcast {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, chunk_bytes)
    } else {
        addr
    };
    let imm = ctx.consume_u8()? as usize;
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src1 = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src2 = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    if chunk_bytes == 0 || vl_bytes <= chunk_bytes || chunk_bytes % elem_size != 0 {
        return Err(Error::Emulator(
            "EVEX insert chunk has invalid vector length".to_string(),
        ));
    }

    let num_chunks = vl_bytes / chunk_bytes;
    let chunk = imm & (num_chunks - 1);
    let dst_base = chunk * chunk_bytes;
    let mut raw = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        load_mem_bytes(vcpu, addr, 1, chunk_bytes)?
    } else {
        read_reg_bytes(vcpu, src2, chunk_bytes)
    };
    raw[dst_base..dst_base + chunk_bytes].copy_from_slice(&src2_bytes[..chunk_bytes]);

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX VPBROADCASTMB2Q/MW2D: broadcast low mask byte/word into qword/dword lanes.
pub fn evex_broadcast_mask(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    src_bits: usize,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX mask broadcast requires EVEX prefix".to_string()))?;

    // Type E6NF is register-only and has no writemask/broadcast controls.
    // EVEX.vvvv/V' are reserved. EVEX.X/B are deliberately not checked:
    // Intel SDM Table 2-41 defines both fields as ignored when ModR/M.r/m
    // encodes a K register. Validate before ModR/M decoding so no reserved
    // form can perform address calculation or commit architectural state.
    let modrm = ctx.peek_u8()?;
    if evex.aaa != 0
        || evex.z
        || evex.broadcast
        || evex.ll == 3
        || evex.vvvv != 0xF
        || !evex.v_prime
        || modrm >> 6 != 3
    {
        return vcpu.inject_undefined_instruction();
    }

    let (reg, rm, _, _, _) = vcpu.decode_modrm(ctx)?;

    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let mask = if src_bits == 8 { 0xff } else { 0xffff };
    let value = vcpu.regs.k[(rm & 0x07) as usize] & mask;
    let value_bytes = value.to_le_bytes();
    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let mut result = [0u8; 64];

    for lane in 0..num_elems {
        let base = lane * elem_size;
        result[base..base + elem_size].copy_from_slice(&value_bytes[..elem_size]);
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Read a single element as a signed i128 (sign-extended) from a byte slice.
pub(super) fn elem_signed(bytes: &[u8], elem_size: usize) -> i128 {
    match elem_size {
        1 => bytes[0] as i8 as i128,
        2 => i16::from_le_bytes([bytes[0], bytes[1]]) as i128,
        4 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i128,
        8 => i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]) as i128,
        _ => 0,
    }
}

/// Read a single element as an unsigned u128 from a byte slice.
pub(super) fn elem_unsigned(bytes: &[u8], elem_size: usize) -> u128 {
    match elem_size {
        1 => bytes[0] as u128,
        2 => u16::from_le_bytes([bytes[0], bytes[1]]) as u128,
        4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u128,
        8 => u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]) as u128,
        _ => 0,
    }
}

/// EVEX ternary bitwise logic (VPTERNLOGD/Q).
pub fn evex_ternlog(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX ternary logic requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let imm = ctx.consume_u8()?;

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for i in 0..num_elems {
                let base = i * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];
    for elem in 0..num_elems {
        let base = elem * elem_size;
        if (mask >> elem) & 1 != 0 {
            for byte in 0..elem_size {
                let a = dest_old[base + byte];
                let b = src1_bytes[base + byte];
                let c = src2_bytes[base + byte];
                let mut out = 0u8;
                for bit in 0..8 {
                    let idx = (((a >> bit) & 1) << 2) | (((b >> bit) & 1) << 1) | ((c >> bit) & 1);
                    out |= ((imm >> idx) & 1) << bit;
                }
                result[base + byte] = out;
            }
        } else if evex.z {
            // Zeroing: leave this element as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX integer test into a k-mask (VPTESTM* / VPTESTNM*).
pub fn evex_int_test_mask(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    inverted: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX integer test requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let k_dst = (reg & 0x7) as usize;
    let src1 = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src2_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast && matches!(elem_size, 4 | 8) {
            elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let src2_bytes = if is_memory {
        if evex.broadcast && matches!(elem_size, 4 | 8) {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for i in 0..num_elems {
                let base = i * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let writemask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = 0u64;
    for i in 0..num_elems {
        if (writemask >> i) & 1 == 0 {
            continue;
        }
        let base = i * elem_size;
        let mut any = false;
        for byte in 0..elem_size {
            if (src1_bytes[base + byte] & src2_bytes[base + byte]) != 0 {
                any = true;
                break;
            }
        }
        if any != inverted {
            result |= 1u64 << i;
        }
    }

    vcpu.regs.k[k_dst] = result;
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX broadcast of a scalar element to all lanes (VPBROADCASTB/W/D/Q,
/// VBROADCASTSS/SD). Source is xmm[0] (or memory scalar). Honors masking and VL.
pub fn evex_broadcast(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX broadcast requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, elem_size)
    } else {
        addr
    };
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;

    // Fetch the scalar element bytes.
    let mut elem = [0u8; 8];
    if is_memory {
        let v = vcpu.read_mem(addr, elem_size as u8)?;
        let le = v.to_le_bytes();
        elem[..elem_size].copy_from_slice(&le[..elem_size]);
    } else {
        let src_bytes = read_reg_bytes(vcpu, src_reg, 16);
        elem[..elem_size].copy_from_slice(&src_bytes[..elem_size]);
    }

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let mut result = [0u8; 64];
    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            result[base..base + elem_size].copy_from_slice(&elem[..elem_size]);
        } else if evex.z {
            // zeroing
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX broadcast of a 64/128/256-bit vector block to all lanes
/// (VBROADCASTF32X*/F64X*/I32X*/I64X*). Only the x2 forms have a register
/// source; larger block broadcasts are memory-only.
pub fn evex_broadcast_block(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    block_bytes: usize,
    min_vl_bytes: usize,
    allow_reg_source: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX block broadcast requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    if vl_bytes < min_vl_bytes {
        return Err(Error::Emulator(format!(
            "EVEX block broadcast requires VL >= {} bytes",
            min_vl_bytes
        )));
    }
    if block_bytes == 0 || block_bytes > vl_bytes || vl_bytes % block_bytes != 0 {
        return Err(Error::Emulator(
            "EVEX block broadcast has invalid block/VL combination".to_string(),
        ));
    }
    if !is_memory && !allow_reg_source {
        return Err(Error::Emulator(
            "EVEX block broadcast form requires memory source".to_string(),
        ));
    }
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, block_bytes)
    } else {
        addr
    };

    let mut block = [0u8; 32];
    if is_memory {
        let memory_bytes = load_mem_bytes(vcpu, addr, elem_size, block_bytes / elem_size)?;
        block[..block_bytes].copy_from_slice(&memory_bytes[..block_bytes]);
    } else {
        let src_bytes = read_reg_bytes(vcpu, src_reg, 16);
        block[..block_bytes].copy_from_slice(&src_bytes[..block_bytes]);
    }

    let mut raw = [0u8; 64];
    for base in (0..vl_bytes).step_by(block_bytes) {
        raw[base..base + block_bytes].copy_from_slice(&block[..block_bytes]);
    }

    let result = apply_evex_mask(vcpu, &evex, dest, vl_bytes, elem_size, &raw);
    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX masked move (VMOVDQA32/64, VMOVDQU8/16/32/64, VMOVUPS/PD) - load form
/// (reg <- reg/mem). `elem_size` is the masking granularity. `aligned` enforces
/// alignment for the A-forms when the operand is memory.
pub fn evex_mov_masked_load(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    aligned: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX masked move requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };

    if is_memory && aligned && (addr % vl_bytes as u64) != 0 {
        vcpu.inject_exception(13, Some(0))?;
        return Ok(None);
    }

    let src_bytes = if is_memory {
        load_mem_bytes(vcpu, addr, elem_size, num_elems)?
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let mut result = [0u8; 64];
    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            result[base..base + elem_size].copy_from_slice(&src_bytes[base..base + elem_size]);
        } else if evex.z {
            // zeroing
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX masked move store form (reg/mem <- reg). For memory destinations only
/// active elements are written; for register destinations merge/zero applies.
pub fn evex_mov_masked_store(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    elem_size: usize,
    aligned: bool,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX masked move requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = (reg & 0x07) | if evex.r { 0 } else { 8 } | if evex.r_prime { 0 } else { 16 };
    let dest_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };

    if is_memory && aligned && (addr % vl_bytes as u64) != 0 {
        vcpu.inject_exception(13, Some(0))?;
        return Ok(None);
    }

    let src_bytes = read_reg_bytes(vcpu, src, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    if is_memory {
        // Write only active elements; inactive lanes leave memory unchanged.
        for i in 0..num_elems {
            if (mask >> i) & 1 != 0 {
                let base = i * elem_size;
                let value = if elem_size == 4 {
                    u32::from_le_bytes([
                        src_bytes[base],
                        src_bytes[base + 1],
                        src_bytes[base + 2],
                        src_bytes[base + 3],
                    ]) as u64
                } else if elem_size == 8 {
                    u64::from_le_bytes([
                        src_bytes[base],
                        src_bytes[base + 1],
                        src_bytes[base + 2],
                        src_bytes[base + 3],
                        src_bytes[base + 4],
                        src_bytes[base + 5],
                        src_bytes[base + 6],
                        src_bytes[base + 7],
                    ])
                } else if elem_size == 2 {
                    u16::from_le_bytes([src_bytes[base], src_bytes[base + 1]]) as u64
                } else {
                    src_bytes[base] as u64
                };
                vcpu.write_mem(addr + (i * elem_size) as u64, value, elem_size as u8)?;
            }
        }
    } else {
        let dest_old = read_reg_bytes(vcpu, dest_reg, vl_bytes);
        let mut result = [0u8; 64];
        for i in 0..num_elems {
            let base = i * elem_size;
            if (mask >> i) & 1 != 0 {
                result[base..base + elem_size].copy_from_slice(&src_bytes[base..base + elem_size]);
            } else if evex.z {
                // zeroing
            } else {
                result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
            }
        }
        write_vec_vl(vcpu, dest_reg, vl_bytes, &result);
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Shift kind for the EVEX packed-shift implementation.
#[derive(Clone, Copy)]
pub enum ShiftKind {
    Sll,
    Srl,
    Sra,
}

/// Apply a logical/arithmetic shift to a single element value (as u64), masking
/// to `elem_size`. Shift counts >= bit width produce 0 (logical) or the sign
/// fill (arithmetic), matching x86 packed-shift semantics.
fn shift_elem(kind: ShiftKind, val: u64, count: u64, elem_size: usize) -> u64 {
    let bits = (elem_size * 8) as u64;
    match kind {
        ShiftKind::Sll => {
            if count >= bits {
                0
            } else {
                let r = val << count;
                match elem_size {
                    4 => r & 0xFFFF_FFFF,
                    8 => r,
                    2 => r & 0xFFFF,
                    _ => r & 0xFF,
                }
            }
        }
        ShiftKind::Srl => {
            if count >= bits {
                0
            } else {
                let m = if elem_size == 8 {
                    u64::MAX
                } else {
                    (1u64 << bits) - 1
                };
                (val & m) >> count
            }
        }
        ShiftKind::Sra => {
            let sh = if count >= bits { bits - 1 } else { count };
            match elem_size {
                4 => (((val as u32) as i32) >> sh) as u32 as u64,
                8 => ((val as i64) >> sh) as u64,
                2 => (((val as u16) as i16) >> sh) as u16 as u64,
                _ => (((val as u8) as i8) >> sh) as u8 as u64,
            }
        }
    }
}

/// Rotate direction for EVEX packed rotate operations.
#[derive(Clone, Copy)]
pub enum RotateKind {
    Left,
    Right,
}

/// Direction for EVEX packed funnel shifts (VPSHLD*/VPSHRD*).
#[derive(Clone, Copy)]
pub enum FunnelShiftKind {
    Left,
    Right,
}

#[derive(Clone, Copy)]
pub enum ByteShiftKind {
    Left,
    Right,
}

fn rotate_elem(kind: RotateKind, val: u64, count: u64, elem_size: usize) -> u64 {
    match elem_size {
        4 => {
            let count = (count & 31) as u32;
            let value = val as u32;
            match kind {
                RotateKind::Left => value.rotate_left(count) as u64,
                RotateKind::Right => value.rotate_right(count) as u64,
            }
        }
        8 => {
            let count = (count & 63) as u32;
            match kind {
                RotateKind::Left => val.rotate_left(count),
                RotateKind::Right => val.rotate_right(count),
            }
        }
        2 => {
            let count = (count & 15) as u32;
            let value = val as u16;
            match kind {
                RotateKind::Left => value.rotate_left(count) as u64,
                RotateKind::Right => value.rotate_right(count) as u64,
            }
        }
        _ => {
            let count = (count & 7) as u32;
            let value = val as u8;
            match kind {
                RotateKind::Left => value.rotate_left(count) as u64,
                RotateKind::Right => value.rotate_right(count) as u64,
            }
        }
    }
}

fn elem_mask(elem_size: usize) -> u128 {
    let bits = elem_size * 8;
    if bits == 64 {
        u64::MAX as u128
    } else {
        (1u128 << bits) - 1
    }
}

fn funnel_shift_elem(
    kind: FunnelShiftKind,
    primary: u64,
    secondary: u64,
    count: u64,
    elem_size: usize,
) -> u64 {
    let bits = (elem_size * 8) as u32;
    let mask = elem_mask(elem_size);
    let count = (count & (bits as u64 - 1)) as u32;
    let primary = primary as u128 & mask;
    let secondary = secondary as u128 & mask;

    let result = if count == 0 {
        primary
    } else {
        match kind {
            FunnelShiftKind::Left => (primary << count) | (secondary >> (bits - count)),
            FunnelShiftKind::Right => (primary >> count) | (secondary << (bits - count)),
        }
    };

    (result & mask) as u64
}

/// EVEX packed byte shift by immediate (VPSLLDQ/VPSRLDQ).
///
/// The shift is lane-local to each 128-bit chunk and does not support EVEX
/// writemasks.
pub fn evex_shift_bytes_imm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: ByteShiftKind,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX byte shift requires EVEX prefix".to_string()))?;

    if evex.aaa != 0 || evex.z || evex.broadcast {
        return vcpu.inject_undefined_instruction();
    }

    let modrm_start = ctx.cursor;
    let (_reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src_reg = evex_rm_vec(&evex, rm);
    let imm = ctx.consume_u8()? as usize;

    let vl_bytes = vl_bytes_of(evex.ll);
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, vl_bytes)
    } else {
        addr
    };
    let src = if is_memory {
        load_mem_bytes(vcpu, addr, 1, vl_bytes)?
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let count = imm.min(16);
    let mut result = [0u8; 64];
    for lane_base in (0..vl_bytes).step_by(16) {
        match kind {
            ByteShiftKind::Left => {
                result[lane_base + count..lane_base + 16]
                    .copy_from_slice(&src[lane_base..lane_base + 16 - count]);
            }
            ByteShiftKind::Right => {
                result[lane_base..lane_base + 16 - count]
                    .copy_from_slice(&src[lane_base + count..lane_base + 16]);
            }
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed shift by immediate (VPSLLD/Q, VPSRLD/Q, VPSRAD/Q with imm8).
/// These are the `/r` group forms where the destination comes from EVEX.vvvv
/// (NDD) and the shifted source is the ModR/M r/m operand. Honors masking + VL.
pub fn evex_shift_imm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: ShiftKind,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX shift requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (_reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    // Destination = EVEX.vvvv (the group-encoded shift writes back to vvvv).
    let dest = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };

    // src elements, then imm8 shift count.
    let src_bytes = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for i in 0..num_elems {
                let base = i * elem_size;
                data[base..base + elem_size].copy_from_slice(&le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };

    let count = ctx.consume_u8()? as u64;

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let mut result = [0u8; 64];
    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            let val = elem_unsigned(&src_bytes[base..base + elem_size], elem_size) as u64;
            let r = shift_elem(kind, val, count, elem_size);
            let le = r.to_le_bytes();
            result[base..base + elem_size].copy_from_slice(&le[..elem_size]);
        } else if evex.z {
            // zeroing
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed rotate by immediate (VPROLD/Q, VPRORD/Q with imm8).
pub fn evex_rotate_imm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: RotateKind,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX rotate requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (_reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dest = (evex.vvvv ^ 0xF) | if evex.v_prime { 0 } else { 16 };
    let src_reg = (rm & 0x07) | if evex.b { 0 } else { 8 } | if evex.x { 0 } else { 16 };

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src_bytes = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for i in 0..num_elems {
                let base = i * elem_size;
                data[base..base + elem_size].copy_from_slice(&le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src_reg, vl_bytes)
    };
    let count = ctx.consume_u8()? as u64;
    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let mut result = [0u8; 64];
    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            let val = elem_unsigned(&src_bytes[base..base + elem_size], elem_size) as u64;
            let r = rotate_elem(kind, val, count, elem_size);
            let le = r.to_le_bytes();
            result[base..base + elem_size].copy_from_slice(&le[..elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed funnel shift by immediate (VPSHLD*/VPSHRD* with imm8).
pub fn evex_funnel_shift_imm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: FunnelShiftKind,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX funnel shift requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);
    let imm = ctx.consume_u8()? as u64;

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast && matches!(elem_size, 4 | 8) {
            elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let primary_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let secondary_bytes = if is_memory {
        if evex.broadcast && matches!(elem_size, 4 | 8) {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];

    for lane in 0..num_elems {
        let base = lane * elem_size;
        if (mask >> lane) & 1 != 0 {
            let primary = elem_unsigned(&primary_bytes[base..base + elem_size], elem_size) as u64;
            let secondary =
                elem_unsigned(&secondary_bytes[base..base + elem_size], elem_size) as u64;
            let shifted = funnel_shift_elem(kind, primary, secondary, imm, elem_size);
            result[base..base + elem_size].copy_from_slice(&shifted.to_le_bytes()[..elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed shift by xmm count (VPSLLD/Q, VPSRLD/Q, VPSRAD/Q with xmm count).
/// dest{k} = src1 shifted by the scalar count in the low 64 bits of src2/m128.
pub fn evex_shift_var(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: ShiftKind,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX shift requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        evex_scaled_disp8_addr(ctx, modrm_start, addr, 16)
    } else {
        addr
    };

    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);

    // Count is the full low 64-bit value of the xmm/m128 source.
    let count = if is_memory {
        vcpu.read_mem(addr, 8)?
    } else {
        let c = read_reg_bytes(vcpu, src2_reg, 16);
        u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]])
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);

    let mut result = [0u8; 64];
    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            let val = elem_unsigned(&src1_bytes[base..base + elem_size], elem_size) as u64;
            let r = shift_elem(kind, val, count, elem_size);
            let le = r.to_le_bytes();
            result[base..base + elem_size].copy_from_slice(&le[..elem_size]);
        } else if evex.z {
            // zeroing
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed funnel shift by per-element counts (VPSHLDV*/VPSHRDV*).
pub fn evex_funnel_shift_per_elem(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: FunnelShiftKind,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx.evex.ok_or_else(|| {
        Error::Emulator("EVEX variable funnel shift requires EVEX prefix".to_string())
    })?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, count_reg) = evex_three_op(&evex, reg, rm);

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast && matches!(elem_size, 4 | 8) {
            elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let secondary_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let count_bytes = if is_memory {
        if evex.broadcast && matches!(elem_size, 4 | 8) {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for lane in 0..num_elems {
                let base = lane * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, count_reg, vl_bytes)
    };

    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];

    for lane in 0..num_elems {
        let base = lane * elem_size;
        if (mask >> lane) & 1 != 0 {
            let primary = elem_unsigned(&dest_old[base..base + elem_size], elem_size) as u64;
            let secondary =
                elem_unsigned(&secondary_bytes[base..base + elem_size], elem_size) as u64;
            let count = elem_unsigned(&count_bytes[base..base + elem_size], elem_size) as u64;
            let shifted = funnel_shift_elem(kind, primary, secondary, count, elem_size);
            result[base..base + elem_size].copy_from_slice(&shifted.to_le_bytes()[..elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed shift by per-element vector counts (VPSLLV*, VPSRLV*, VPSRAV*).
/// dest{k} = src1 shifted by the corresponding element count from src2/mem.
pub fn evex_shift_per_elem(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: ShiftKind,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX variable shift requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast && matches!(elem_size, 4 | 8) {
            elem_size
        } else {
            vl_bytes
        };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let count_bytes = if is_memory {
        if evex.broadcast && matches!(elem_size, 4 | 8) {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for i in 0..num_elems {
                let base = i * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];

    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            let val = elem_unsigned(&src1_bytes[base..base + elem_size], elem_size) as u64;
            let count = elem_unsigned(&count_bytes[base..base + elem_size], elem_size) as u64;
            let r = shift_elem(kind, val, count, elem_size);
            let le = r.to_le_bytes();
            result[base..base + elem_size].copy_from_slice(&le[..elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// EVEX packed rotate by per-element vector counts (VPROLV*, VPRORV*).
pub fn evex_rotate_per_elem(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    kind: RotateKind,
    elem_size: usize,
) -> Result<Option<VcpuExit>> {
    let evex = ctx
        .evex
        .ok_or_else(|| Error::Emulator("EVEX variable rotate requires EVEX prefix".to_string()))?;

    let modrm_start = ctx.cursor;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let (dest, src1, src2_reg) = evex_three_op(&evex, reg, rm);

    let vl_bytes = vl_bytes_of(evex.ll);
    let num_elems = vl_bytes / elem_size;
    let addr = if is_memory {
        let scale = if evex.broadcast { elem_size } else { vl_bytes };
        evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
    } else {
        addr
    };
    let src1_bytes = read_reg_bytes(vcpu, src1, vl_bytes);
    let count_bytes = if is_memory {
        if evex.broadcast {
            let elem = vcpu.read_mem(addr, elem_size as u8)?;
            let elem_le = elem.to_le_bytes();
            let mut data = [0u8; 64];
            for i in 0..num_elems {
                let base = i * elem_size;
                data[base..base + elem_size].copy_from_slice(&elem_le[..elem_size]);
            }
            data
        } else {
            load_mem_bytes(vcpu, addr, elem_size, num_elems)?
        }
    } else {
        read_reg_bytes(vcpu, src2_reg, vl_bytes)
    };

    let dest_old = read_reg_bytes(vcpu, dest, vl_bytes);
    let mask = evex_mask(vcpu, evex.aaa, num_elems);
    let mut result = [0u8; 64];

    for i in 0..num_elems {
        let base = i * elem_size;
        if (mask >> i) & 1 != 0 {
            let val = elem_unsigned(&src1_bytes[base..base + elem_size], elem_size) as u64;
            let count = elem_unsigned(&count_bytes[base..base + elem_size], elem_size) as u64;
            let r = rotate_elem(kind, val, count, elem_size);
            let le = r.to_le_bytes();
            result[base..base + elem_size].copy_from_slice(&le[..elem_size]);
        } else if evex.z {
            // Zeroing: leave as 0.
        } else {
            result[base..base + elem_size].copy_from_slice(&dest_old[base..base + elem_size]);
        }
    }

    write_vec_vl(vcpu, dest, vl_bytes, &result);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}
