//! RVC (compressed, 16-bit) instruction decoding.
//!
//! Each compressed parcel expands to exactly one base-ISA operation; the
//! expansion is performed here at decode time so the execution path is shared
//! with the 32-bit encodings (and inherits their verified semantics). Every
//! produced [`Insn`] carries `len = 2` so the PC advances by two bytes and
//! link registers receive `pc + 2`.
//!
//! Both RV32C and RV64C are handled; the few encodings that differ between
//! XLENs (C.LD/C.FLW, C.SD/C.FSW, C.ADDIW/C.JAL, the *SP loads/stores) are
//! selected on [`Xlen`].

use super::decode::{Insn, Op};
use super::{Isa, Xlen};

/// Construct a decoded compressed instruction (always 2 bytes).
fn mk(op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64, half: u16) -> Insn {
    Insn {
        op,
        rd,
        rs1,
        rs2,
        rs3: 0,
        imm,
        funct3: 0,
        csr: 0,
        aq: false,
        rl: false,
        len: 2,
        raw: half as u32,
    }
}

#[inline]
fn ill(half: u16) -> Insn {
    Insn::illegal_compressed(half)
}

/// Extract bits `[hi:lo]` of `h` as a u32.
#[inline]
fn bits(h: u16, hi: u32, lo: u32) -> u32 {
    ((h as u32) >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}
#[inline]
fn bit(h: u16, n: u32) -> u32 {
    ((h as u32) >> n) & 1
}
/// Compressed 3-bit register field -> x8..x15.
#[inline]
fn rvc_reg(r: u32) -> u8 {
    (r as u8 & 0x7) + 8
}

/// Zcmp compressed s-register field -> s0,s1,s2..s7.
#[inline]
fn zcmp_sreg(r: u32) -> u8 {
    match r & 0x7 {
        0 => 8,                    // s0/fp
        1 => 9,                    // s1
        n => (18 + (n - 2)) as u8, // s2..s7
    }
}

#[inline]
fn zcmp_reg_count(rlist: u32) -> Option<u32> {
    match rlist {
        4 => Some(1),              // ra
        5 => Some(2),              // ra, s0
        6 => Some(3),              // ra, s0-s1
        7..=14 => Some(rlist - 3), // ra, s0-s1, s2..s(rlist-6)
        15 => Some(13),            // ra, s0-s1, s2-s11
        _ => None,
    }
}

#[inline]
fn zcmp_stack_adj(rlist: u32, spimm: u32, rv64: bool) -> Option<i64> {
    let slotsize = if rv64 { 8 } else { 4 };
    let bytes = zcmp_reg_count(rlist)? * slotsize;
    let base = ((bytes + 15) / 16) * 16;
    Some((base + spimm * 16) as i64)
}

/// Sign-extend the low `n` bits of `v`.
#[inline]
fn sext(v: u32, n: u32) -> i64 {
    let shift = 32 - n;
    (((v << shift) as i32) >> shift) as i64
}

/// Decode a non-zero compressed parcel.
pub fn decode_rvc(half: u16, xlen: Xlen, isa: &Isa) -> Insn {
    let rv64 = xlen == Xlen::Rv64;
    let quadrant = half & 0x3;
    let funct3 = bits(half, 15, 13);
    match quadrant {
        0 => decode_q0(half, funct3, rv64, isa),
        1 => decode_q1(half, funct3, rv64, isa),
        2 => decode_q2(half, funct3, rv64, isa),
        _ => ill(half), // quadrant 3 is not compressed
    }
}

fn decode_q0(h: u16, funct3: u32, rv64: bool, isa: &Isa) -> Insn {
    let rd_ = rvc_reg(bits(h, 4, 2));
    let rs1_ = rvc_reg(bits(h, 9, 7));
    match funct3 {
        0b000 => {
            // C.ADDI4SPN -> addi rd', x2, nzuimm
            let nzuimm = (bits(h, 12, 11) << 4)
                | (bits(h, 10, 7) << 6)
                | (bit(h, 6) << 2)
                | (bit(h, 5) << 3);
            if nzuimm == 0 {
                return ill(h); // reserved
            }
            mk(Op::Addi, rd_, 2, 0, nzuimm as i64, h)
        }
        0b001 => {
            // C.FLD -> fld rd', off(rs1')  (RV32 & RV64; double)
            if !isa.d {
                return ill(h);
            }
            let off = (bits(h, 12, 10) << 3) | (bits(h, 6, 5) << 6);
            mk(Op::Fld, rd_, rs1_, 0, off as i64, h)
        }
        0b010 => {
            // C.LW -> lw rd', off(rs1')
            let off = (bits(h, 12, 10) << 3) | (bit(h, 6) << 2) | (bit(h, 5) << 6);
            mk(Op::Lw, rd_, rs1_, 0, off as i64, h)
        }
        0b011 => {
            let off_d = (bits(h, 12, 10) << 3) | (bits(h, 6, 5) << 6);
            if rv64 {
                // C.LD -> ld rd', off(rs1')
                mk(Op::Ld, rd_, rs1_, 0, off_d as i64, h)
            } else if isa.zclsd {
                if rd_ & 1 != 0 {
                    return ill(h);
                }
                mk(Op::LdPair, rd_, rs1_, 0, off_d as i64, h)
            } else {
                // C.FLW -> flw rd', off(rs1')
                if !isa.f {
                    return ill(h);
                }
                let off = (bits(h, 12, 10) << 3) | (bit(h, 6) << 2) | (bit(h, 5) << 6);
                mk(Op::Flw, rd_, rs1_, 0, off as i64, h)
            }
        }
        0b101 => {
            // C.FSD -> fsd rs2', off(rs1')
            if !isa.d {
                return ill(h);
            }
            let off = (bits(h, 12, 10) << 3) | (bits(h, 6, 5) << 6);
            mk(Op::Fsd, 0, rs1_, rvc_reg(bits(h, 4, 2)), off as i64, h)
        }
        0b110 => {
            // C.SW -> sw rs2', off(rs1')
            let off = (bits(h, 12, 10) << 3) | (bit(h, 6) << 2) | (bit(h, 5) << 6);
            mk(Op::Sw, 0, rs1_, rvc_reg(bits(h, 4, 2)), off as i64, h)
        }
        0b111 => {
            let off_d = (bits(h, 12, 10) << 3) | (bits(h, 6, 5) << 6);
            if rv64 {
                // C.SD -> sd rs2', off(rs1')
                mk(Op::Sd, 0, rs1_, rvc_reg(bits(h, 4, 2)), off_d as i64, h)
            } else if isa.zclsd {
                let rs2_ = rvc_reg(bits(h, 4, 2));
                if rs2_ & 1 != 0 {
                    return ill(h);
                }
                mk(Op::SdPair, 0, rs1_, rs2_, off_d as i64, h)
            } else {
                // C.FSW -> fsw rs2', off(rs1')
                if !isa.f {
                    return ill(h);
                }
                let off = (bits(h, 12, 10) << 3) | (bit(h, 6) << 2) | (bit(h, 5) << 6);
                mk(Op::Fsw, 0, rs1_, rvc_reg(bits(h, 4, 2)), off as i64, h)
            }
        }
        0b100 if isa.zcb => decode_zcb_q0(h, rd_, rs1_),
        _ => ill(h),
    }
}

/// Zcb quadrant-0 byte/half loads and stores.
fn decode_zcb_q0(h: u16, rd_: u8, rs1_: u8) -> Insn {
    let rs2_ = rvc_reg(bits(h, 4, 2));
    match bits(h, 12, 10) {
        0b000 => {
            // c.lbu: uimm = {bit5, bit6}
            let uimm = (bit(h, 5) << 1) | bit(h, 6);
            mk(Op::Lbu, rd_, rs1_, 0, uimm as i64, h)
        }
        0b001 => {
            // c.lhu (bit6=0) / c.lh (bit6=1); uimm = bit5 << 1
            let uimm = (bit(h, 5) << 1) as i64;
            if bit(h, 6) == 1 {
                mk(Op::Lh, rd_, rs1_, 0, uimm, h)
            } else {
                mk(Op::Lhu, rd_, rs1_, 0, uimm, h)
            }
        }
        0b010 => {
            // c.sb: uimm = {bit5, bit6}
            let uimm = (bit(h, 5) << 1) | bit(h, 6);
            mk(Op::Sb, 0, rs1_, rs2_, uimm as i64, h)
        }
        0b011 => {
            // c.sh (bit6 must be 0); uimm = bit5 << 1
            if bit(h, 6) != 0 {
                return ill(h);
            }
            mk(Op::Sh, 0, rs1_, rs2_, (bit(h, 5) << 1) as i64, h)
        }
        _ => ill(h),
    }
}

fn decode_q1(h: u16, funct3: u32, rv64: bool, isa: &Isa) -> Insn {
    let rd = bits(h, 11, 7) as u8;
    match funct3 {
        0b000 => {
            // C.ADDI -> addi rd, rd, nzimm (rd==0 -> C.NOP; both still addi)
            let imm = sext((bit(h, 12) << 5) | bits(h, 6, 2), 6);
            mk(Op::Addi, rd, rd, 0, imm, h)
        }
        0b001 => {
            let imm = sext((bit(h, 12) << 5) | bits(h, 6, 2), 6);
            if rv64 {
                // C.ADDIW -> addiw rd, rd, imm (rd==0 reserved)
                if rd == 0 {
                    return ill(h);
                }
                mk(Op::Addiw, rd, rd, 0, imm, h)
            } else {
                // C.JAL -> jal x1, offset
                let off = cj_offset(h);
                mk(Op::Jal, 1, 0, 0, off, h)
            }
        }
        0b010 => {
            // C.LI -> addi rd, x0, imm
            let imm = sext((bit(h, 12) << 5) | bits(h, 6, 2), 6);
            mk(Op::Addi, rd, 0, 0, imm, h)
        }
        0b011 => {
            if rd == 2 {
                // C.ADDI16SP -> addi x2, x2, nzimm
                let v = (bit(h, 12) << 5)
                    | (bits(h, 4, 3) << 3)
                    | (bit(h, 5) << 2)
                    | (bit(h, 2) << 1)
                    | bit(h, 6);
                if v == 0 {
                    return ill(h);
                }
                mk(Op::Addi, 2, 2, 0, sext(v, 6) << 4, h)
            } else {
                // C.LUI -> lui rd, nzimm (value already sign-extended << 12)
                let v = (bit(h, 12) << 17) | (bits(h, 6, 2) << 12);
                // rd==x0 with nzimm!=0 is a HINT (executes as a no-op, never
                // traps); only the nzimm==0 code point is reserved.
                if v == 0 {
                    return ill(h);
                }
                mk(Op::Lui, rd, 0, 0, sext(v, 18), h)
            }
        }
        0b100 => decode_q1_alu(h, rv64, isa),
        0b101 => {
            // C.J -> jal x0, offset
            mk(Op::Jal, 0, 0, 0, cj_offset(h), h)
        }
        0b110 => {
            // C.BEQZ -> beq rs1', x0, offset
            mk(Op::Beq, 0, rvc_reg(bits(h, 9, 7)), 0, cb_offset(h), h)
        }
        0b111 => {
            // C.BNEZ -> bne rs1', x0, offset
            mk(Op::Bne, 0, rvc_reg(bits(h, 9, 7)), 0, cb_offset(h), h)
        }
        _ => ill(h),
    }
}

fn decode_q1_alu(h: u16, rv64: bool, isa: &Isa) -> Insn {
    let rd_ = rvc_reg(bits(h, 9, 7));
    let funct2 = bits(h, 11, 10);
    match funct2 {
        0b00 => {
            // C.SRLI -> srli rd', rd', shamt
            let shamt = (bit(h, 12) << 5) | bits(h, 6, 2);
            // On RV32 the high shift bit (shamt[5]) must be 0; shamt >= 32 is a
            // reserved encoding and must not execute as a masked 5-bit shift.
            if !rv64 && shamt >= 32 {
                return ill(h);
            }
            mk(Op::Srli, rd_, rd_, 0, shamt as i64, h)
        }
        0b01 => {
            // C.SRAI -> srai rd', rd', shamt
            let shamt = (bit(h, 12) << 5) | bits(h, 6, 2);
            if !rv64 && shamt >= 32 {
                return ill(h);
            }
            mk(Op::Srai, rd_, rd_, 0, shamt as i64, h)
        }
        0b10 => {
            // C.ANDI -> andi rd', rd', imm
            let imm = sext((bit(h, 12) << 5) | bits(h, 6, 2), 6);
            mk(Op::Andi, rd_, rd_, 0, imm, h)
        }
        0b11 => {
            let rs2_ = rvc_reg(bits(h, 4, 2));
            match (bit(h, 12), bits(h, 6, 5)) {
                (0, 0b00) => mk(Op::Sub, rd_, rd_, rs2_, 0, h),
                (0, 0b01) => mk(Op::Xor, rd_, rd_, rs2_, 0, h),
                (0, 0b10) => mk(Op::Or, rd_, rd_, rs2_, 0, h),
                (0, 0b11) => mk(Op::And, rd_, rd_, rs2_, 0, h),
                (1, 0b00) if rv64 => mk(Op::Subw, rd_, rd_, rs2_, 0, h),
                (1, 0b01) if rv64 => mk(Op::Addw, rd_, rd_, rs2_, 0, h),
                // Zcb: c.mul (10) and the zext/sext/not unary ops (11). Several
                // of these alias instructions from dependent extensions and are
                // only legal when those extensions (and XLEN) are also present:
                //   c.mul   -> needs M (no separate Zmmul flag here)
                //   c.sext.b/c.zext.h/c.sext.h -> need Zbb
                //   c.zext.w (add.uw) -> needs Zba and RV64
                // c.zext.b (andi) and c.not (xori) need only Zcb (base ops).
                (1, 0b10) if isa.zcb && isa.m => mk(Op::Mul, rd_, rd_, rs2_, 0, h),
                (1, 0b11) if isa.zcb => match bits(h, 4, 2) {
                    0b000 => mk(Op::Andi, rd_, rd_, 0, 0xff, h), // c.zext.b
                    0b001 if isa.zbb => mk(Op::SextB, rd_, rd_, 0, 0, h), // c.sext.b
                    0b010 if isa.zbb => mk(Op::ZextH, rd_, rd_, 0, 0, h), // c.zext.h
                    0b011 if isa.zbb => mk(Op::SextH, rd_, rd_, 0, 0, h), // c.sext.h
                    // c.zext.w (add.uw rd',rd',x0)
                    0b100 if isa.zba && rv64 => mk(Op::AddUw, rd_, rd_, 0, 0, h),
                    0b101 => mk(Op::Xori, rd_, rd_, 0, -1, h), // c.not
                    _ => ill(h),
                },
                _ => ill(h),
            }
        }
        _ => ill(h),
    }
}

fn decode_q2(h: u16, funct3: u32, rv64: bool, isa: &Isa) -> Insn {
    let rd = bits(h, 11, 7) as u8;
    match funct3 {
        0b000 => {
            // C.SLLI -> slli rd, rd, shamt (rd==0 hint)
            let shamt = (bit(h, 12) << 5) | bits(h, 6, 2);
            // On RV32 shamt[5] must be 0; shamt >= 32 is a reserved encoding.
            if !rv64 && shamt >= 32 {
                return ill(h);
            }
            mk(Op::Slli, rd, rd, 0, shamt as i64, h)
        }
        0b001 => {
            // C.FLDSP -> fld rd, off(x2)
            if !isa.d {
                return ill(h);
            }
            let off = (bit(h, 12) << 5) | (bits(h, 6, 5) << 3) | (bits(h, 4, 2) << 6);
            mk(Op::Fld, rd, 2, 0, off as i64, h)
        }
        0b010 => {
            // C.LWSP -> lw rd, off(x2) (rd==0 reserved)
            if rd == 0 {
                return ill(h);
            }
            let off = (bit(h, 12) << 5) | (bits(h, 6, 4) << 2) | (bits(h, 3, 2) << 6);
            mk(Op::Lw, rd, 2, 0, off as i64, h)
        }
        0b011 => {
            if rv64 {
                // C.LDSP -> ld rd, off(x2) (rd==0 reserved)
                if rd == 0 {
                    return ill(h);
                }
                let off = (bit(h, 12) << 5) | (bits(h, 6, 5) << 3) | (bits(h, 4, 2) << 6);
                mk(Op::Ld, rd, 2, 0, off as i64, h)
            } else if isa.zclsd {
                if rd == 0 || rd & 1 != 0 {
                    return ill(h);
                }
                let off = (bit(h, 12) << 5) | (bits(h, 6, 5) << 3) | (bits(h, 4, 2) << 6);
                mk(Op::LdPair, rd, 2, 0, off as i64, h)
            } else {
                // C.FLWSP -> flw rd, off(x2)
                if !isa.f {
                    return ill(h);
                }
                let off = (bit(h, 12) << 5) | (bits(h, 6, 4) << 2) | (bits(h, 3, 2) << 6);
                mk(Op::Flw, rd, 2, 0, off as i64, h)
            }
        }
        0b100 => {
            let rs2 = bits(h, 6, 2) as u8;
            if bit(h, 12) == 0 {
                if rs2 == 0 {
                    // C.JR -> jalr x0, 0(rs1) (rs1==0 reserved)
                    if rd == 0 {
                        return ill(h);
                    }
                    mk(Op::Jalr, 0, rd, 0, 0, h)
                } else {
                    // C.MV -> add rd, x0, rs2
                    mk(Op::Add, rd, 0, rs2, 0, h)
                }
            } else if rs2 == 0 {
                if rd == 0 {
                    // C.EBREAK
                    mk(Op::Ebreak, 0, 0, 0, 0, h)
                } else {
                    // C.JALR -> jalr x1, 0(rs1)
                    mk(Op::Jalr, 1, rd, 0, 0, h)
                }
            } else {
                // C.ADD -> add rd, rd, rs2
                if isa.zihintntl && rd == 0 {
                    match rs2 {
                        2 => mk(Op::NtlP1, 0, 0, rs2, 0, h),
                        3 => mk(Op::NtlPall, 0, 0, rs2, 0, h),
                        4 => mk(Op::NtlS1, 0, 0, rs2, 0, h),
                        5 => mk(Op::NtlAll, 0, 0, rs2, 0, h),
                        _ => mk(Op::Add, rd, rd, rs2, 0, h),
                    }
                } else {
                    mk(Op::Add, rd, rd, rs2, 0, h)
                }
            }
        }
        0b101 => {
            if isa.zcmp || isa.zcmt {
                return decode_zcmp_zcmt(h, rv64, isa);
            }
            // C.FSDSP -> fsd rs2, off(x2)
            if !isa.d {
                return ill(h);
            }
            let off = (bits(h, 12, 10) << 3) | (bits(h, 9, 7) << 6);
            mk(Op::Fsd, 0, 2, bits(h, 6, 2) as u8, off as i64, h)
        }
        0b110 => {
            // C.SWSP -> sw rs2, off(x2)
            let off = (bits(h, 12, 9) << 2) | (bits(h, 8, 7) << 6);
            mk(Op::Sw, 0, 2, bits(h, 6, 2) as u8, off as i64, h)
        }
        0b111 => {
            if rv64 {
                // C.SDSP -> sd rs2, off(x2)
                let off = (bits(h, 12, 10) << 3) | (bits(h, 9, 7) << 6);
                mk(Op::Sd, 0, 2, bits(h, 6, 2) as u8, off as i64, h)
            } else if isa.zclsd {
                let rs2 = bits(h, 6, 2) as u8;
                if rs2 & 1 != 0 {
                    return ill(h);
                }
                let off = (bits(h, 12, 10) << 3) | (bits(h, 9, 7) << 6);
                mk(Op::SdPair, 0, 2, rs2, off as i64, h)
            } else {
                // C.FSWSP -> fsw rs2, off(x2)
                if !isa.f {
                    return ill(h);
                }
                let off = (bits(h, 12, 9) << 2) | (bits(h, 8, 7) << 6);
                mk(Op::Fsw, 0, 2, bits(h, 6, 2) as u8, off as i64, h)
            }
        }
        _ => ill(h),
    }
}

fn decode_zcmp_zcmt(h: u16, rv64: bool, isa: &Isa) -> Insn {
    if isa.zcmp {
        let funct5 = bits(h, 12, 8);
        if matches!(funct5, 0x18 | 0x1a | 0x1c | 0x1e) {
            let rlist = bits(h, 7, 4);
            let spimm = bits(h, 3, 2);
            let Some(stack_adj) = zcmp_stack_adj(rlist, spimm, rv64) else {
                return ill(h);
            };
            let op = match funct5 {
                0x18 => Op::CmPush,
                0x1a => Op::CmPop,
                0x1c => Op::CmPopRetz,
                0x1e => Op::CmPopRet,
                _ => unreachable!(),
            };
            return mk(op, rlist as u8, 0, 0, stack_adj, h);
        }

        if bits(h, 12, 10) == 0x03 {
            let r1s = zcmp_sreg(bits(h, 9, 7));
            let r2s = zcmp_sreg(bits(h, 4, 2));
            match bits(h, 6, 5) {
                0x01 => {
                    if r1s == r2s {
                        return ill(h);
                    }
                    return mk(Op::CmMvsa01, r1s, r2s, 0, 0, h);
                }
                0x03 => return mk(Op::CmMva01s, r1s, r2s, 0, 0, h),
                _ => return ill(h),
            }
        }
    }

    if isa.zcmt && bits(h, 12, 10) == 0 {
        let index = bits(h, 9, 2);
        let op = if index < 32 { Op::CmJt } else { Op::CmJalt };
        return mk(op, 0, 0, 0, index as i64, h);
    }

    ill(h)
}

/// C.J / C.JAL jump offset (sign-extended, even).
fn cj_offset(h: u16) -> i64 {
    let v = (bit(h, 12) << 11)
        | (bit(h, 11) << 4)
        | (bits(h, 10, 9) << 8)
        | (bit(h, 8) << 10)
        | (bit(h, 7) << 6)
        | (bit(h, 6) << 7)
        | (bits(h, 5, 3) << 1)
        | (bit(h, 2) << 5);
    sext(v, 12)
}

/// C.BEQZ / C.BNEZ branch offset (sign-extended, even).
fn cb_offset(h: u16) -> i64 {
    let v = (bit(h, 12) << 8)
        | (bits(h, 11, 10) << 3)
        | (bits(h, 6, 5) << 6)
        | (bits(h, 4, 3) << 1)
        | (bit(h, 2) << 5);
    sext(v, 9)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(h: u16) -> Insn {
        decode_rvc(h, Xlen::Rv64, &Isa::rv64gc())
    }

    #[test]
    fn c_addi() {
        // c.addi x8, 1 : funct3=000, rd=8, imm=1 -> 0x0405? build by fields
        // [15:13]=000, [12]=imm5=0, [11:7]=rd=8, [6:2]=imm[4:0]=1, [1:0]=01
        let h = (0 << 13) | (8 << 7) | (1 << 2) | 0b01;
        let i = dec(h as u16);
        assert_eq!(i.op, Op::Addi);
        assert_eq!(i.rd, 8);
        assert_eq!(i.rs1, 8);
        assert_eq!(i.imm, 1);
        assert_eq!(i.len, 2);
    }

    #[test]
    fn compressed_double_memory_encodings_require_d() {
        let cases = [
            (0x2000, Op::Fld), // C.FLD
            (0x2002, Op::Fld), // C.FLDSP
            (0xA000, Op::Fsd), // C.FSD
            (0xA002, Op::Fsd), // C.FSDSP
        ];
        let with_d = Isa::rv64gc();
        let no_d = Isa { d: false, ..with_d };

        for xlen in [Xlen::Rv32, Xlen::Rv64] {
            for (half, expected) in cases {
                assert_eq!(
                    decode_rvc(half, xlen, &with_d).op,
                    expected,
                    "{xlen:?}, half={half:#06x}, D enabled"
                );
                assert_eq!(
                    decode_rvc(half, xlen, &no_d).op,
                    Op::Illegal,
                    "{xlen:?}, half={half:#06x}, D disabled"
                );
            }
        }

        // The Q2/FUNCT3=101 slot belongs to Zcmp/Zcmt when either extension is
        // enabled; a D gate must not hide a valid compressed macro encoding.
        let mut zcmp_without_d = no_d;
        zcmp_without_d.zcmp = true;
        let cm_push = ((0b101 << 13) | (0x18 << 8) | (5 << 4) | (1 << 2) | 0b10) as u16;
        assert_eq!(
            decode_rvc(cm_push, Xlen::Rv64, &zcmp_without_d).op,
            Op::CmPush
        );
    }

    #[test]
    fn c_li() {
        // c.li x10, -1 : funct3=010, rd=10, imm=-1 (all imm bits set)
        let h = (0b010 << 13) | (1 << 12) | (10 << 7) | (0x1f << 2) | 0b01;
        let i = dec(h as u16);
        assert_eq!(i.op, Op::Addi);
        assert_eq!(i.rd, 10);
        assert_eq!(i.rs1, 0);
        assert_eq!(i.imm, -1);
    }

    #[test]
    fn c_lui_rd0_hint() {
        // c.lui x0, 1 (0x6005): rd=x0 with nzimm!=0 is a HINT and must decode
        // as lui x0, imm (a no-op), not as a reserved encoding.
        let h = 0x6005u16; // funct3=011, rd=0, imm[17:12]=00001
        let i = dec(h);
        assert_eq!(i.op, Op::Lui);
        assert_eq!(i.rd, 0);
        assert_eq!(i.imm, 0x1000);

        // Control: c.lui x1, 1 (rd!=0) still decodes normally.
        let h1 = (0b011 << 13) | (1 << 12) | (1 << 7) | (1 << 2) | 0b01;
        let i1 = dec(h1 as u16);
        assert_eq!(i1.op, Op::Lui);
        assert_eq!(i1.rd, 1);

        // c.lui x0, 0 (nzimm==0) remains reserved.
        let h0 = (0b011 << 13) | (0 << 12) | (0 << 7) | 0b01;
        assert_eq!(dec(h0 as u16).op, Op::Illegal);
    }

    #[test]
    fn rv32c_reserved_shifts_are_illegal() {
        // C.SRLI/C.SRAI (Q1, funct2=00/01) and C.SLLI (Q2, funct3=000) with the
        // high shift bit (shamt[5], bit12) set are reserved on RV32 and must be
        // illegal; on RV64 the same encodings are legal (shamt up to 63).
        let isa = Isa::rv64gc();
        // C.SRLI x8, 32 : funct3=100, funct2=00, bit12=1, rd'=x8, shamt[4:0]=0.
        let c_srli = ((0b100 << 13) | (1 << 12) | (0b00 << 10) | (0 << 7) | 0b01) as u16;
        // C.SLLI x8, 32 : funct3=000, bit12=1, rd=8, shamt[4:0]=0.
        let c_slli = ((0b000 << 13) | (1 << 12) | (8 << 7) | 0b10) as u16;

        assert_eq!(decode_rvc(c_srli, Xlen::Rv32, &isa).op, Op::Illegal);
        assert_eq!(decode_rvc(c_slli, Xlen::Rv32, &isa).op, Op::Illegal);
        // RV64: legal (shamt 32).
        assert_eq!(decode_rvc(c_srli, Xlen::Rv64, &isa).op, Op::Srli);
        assert_eq!(decode_rvc(c_slli, Xlen::Rv64, &isa).op, Op::Slli);
    }

    #[test]
    fn zcb_aliases_require_dependent_extensions() {
        // Q1 ALU, funct3=100, funct2=11, bit12=1. rd'=x8, rs2'=x9.
        let c_mul =
            ((0b100 << 13) | (1 << 12) | (0b11 << 10) | (0b10 << 5) | (1 << 2) | 0b01) as u16;
        let c_sextb =
            ((0b100 << 13) | (1 << 12) | (0b11 << 10) | (0b11 << 5) | (0b001 << 2) | 0b01) as u16;
        let c_zextw =
            ((0b100 << 13) | (1 << 12) | (0b11 << 10) | (0b11 << 5) | (0b100 << 2) | 0b01) as u16;

        // Fully-featured RV64GC decodes all of them.
        assert_eq!(decode_rvc(c_mul, Xlen::Rv64, &Isa::rv64gc()).op, Op::Mul);
        assert_eq!(
            decode_rvc(c_sextb, Xlen::Rv64, &Isa::rv64gc()).op,
            Op::SextB
        );
        assert_eq!(
            decode_rvc(c_zextw, Xlen::Rv64, &Isa::rv64gc()).op,
            Op::AddUw
        );

        // c.mul needs M.
        let mut no_m = Isa::rv64gc();
        no_m.m = false;
        assert_eq!(decode_rvc(c_mul, Xlen::Rv64, &no_m).op, Op::Illegal);

        // c.sext.b needs Zbb.
        let mut no_zbb = Isa::rv64gc();
        no_zbb.zbb = false;
        assert_eq!(decode_rvc(c_sextb, Xlen::Rv64, &no_zbb).op, Op::Illegal);

        // c.zext.w needs Zba and RV64.
        let mut no_zba = Isa::rv64gc();
        no_zba.zba = false;
        assert_eq!(decode_rvc(c_zextw, Xlen::Rv64, &no_zba).op, Op::Illegal);
        assert_eq!(
            decode_rvc(c_zextw, Xlen::Rv32, &Isa::rv64gc()).op,
            Op::Illegal
        );
    }

    #[test]
    fn c_mv_add() {
        // c.mv x10, x11 : funct3=100, bit12=0, rd=10, rs2=11
        let h = (0b100 << 13) | (0 << 12) | (10 << 7) | (11 << 2) | 0b10;
        let i = dec(h as u16);
        assert_eq!(i.op, Op::Add);
        assert_eq!(i.rd, 10);
        assert_eq!(i.rs1, 0);
        assert_eq!(i.rs2, 11);
    }

    #[test]
    fn c_ntl_hints() {
        let h = (0b100 << 13) | (1 << 12) | (2 << 2) | 0b10;
        assert_eq!(dec(h as u16).op, Op::NtlP1);

        let mut isa = Isa::rv64gc();
        isa.zihintntl = false;
        assert_eq!(decode_rvc(h as u16, Xlen::Rv64, &isa).op, Op::Add);
    }

    #[test]
    fn zclsd_rv32_pair_load_store_overlap_slots() {
        let mut isa = Isa::rv64gc();
        isa.zclsd = true;

        let c_ld = ((0b011 << 13) | (2 << 7) | 0b00) as u16; // rd'=x8, rs1'=x10
        let i = decode_rvc(c_ld, Xlen::Rv32, &isa);
        assert_eq!(i.op, Op::LdPair);
        assert_eq!(i.rd, 8);
        assert_eq!(i.rs1, 10);

        let c_ld_odd = ((0b011 << 13) | (2 << 7) | (1 << 2) | 0b00) as u16;
        assert_eq!(decode_rvc(c_ld_odd, Xlen::Rv32, &isa).op, Op::Illegal);

        let c_sd = ((0b111 << 13) | (2 << 7) | 0b00) as u16; // rs2'=x8, rs1'=x10
        let i = decode_rvc(c_sd, Xlen::Rv32, &isa);
        assert_eq!(i.op, Op::SdPair);
        assert_eq!(i.rs1, 10);
        assert_eq!(i.rs2, 8);

        let c_ldsp = ((0b011 << 13) | (8 << 7) | 0b10) as u16;
        let i = decode_rvc(c_ldsp, Xlen::Rv32, &isa);
        assert_eq!(i.op, Op::LdPair);
        assert_eq!(i.rd, 8);
        assert_eq!(i.rs1, 2);

        let c_sdsp = ((0b111 << 13) | 0b10) as u16;
        let i = decode_rvc(c_sdsp, Xlen::Rv32, &isa);
        assert_eq!(i.op, Op::SdPair);
        assert_eq!(i.rs1, 2);
        assert_eq!(i.rs2, 0);

        isa.zclsd = false;
        assert_eq!(decode_rvc(c_ld, Xlen::Rv32, &isa).op, Op::Flw);
        assert_eq!(decode_rvc(c_sd, Xlen::Rv32, &isa).op, Op::Fsw);
    }

    #[test]
    fn rv32_compressed_single_precision_memory_requires_f() {
        let encodings = [
            ((0b011 << 13) | (2 << 7) | 0b00, Op::Flw),
            ((0b111 << 13) | (2 << 7) | 0b00, Op::Fsw),
            ((0b011 << 13) | (8 << 7) | 0b10, Op::Flw),
            ((0b111 << 13) | (8 << 2) | 0b10, Op::Fsw),
        ];

        let enabled = Isa::rv64gc();
        let mut disabled = enabled;
        disabled.f = false;
        disabled.d = false;
        disabled.zclsd = false;
        for (raw, expected) in encodings {
            assert_eq!(decode_rvc(raw as u16, Xlen::Rv32, &enabled).op, expected);
            assert_eq!(
                decode_rvc(raw as u16, Xlen::Rv32, &disabled).op,
                Op::Illegal
            );
        }
    }

    #[test]
    fn zcmp_zcmt_decode_overlap_slot() {
        let mut isa = Isa::rv64gc();
        isa.zcmp = true;
        isa.zcmt = true;

        let cm_push = ((0b101 << 13) | (0x18 << 8) | (5 << 4) | (1 << 2) | 0b10) as u16;
        let i = decode_rvc(cm_push, Xlen::Rv64, &isa);
        assert_eq!(i.op, Op::CmPush);
        assert_eq!(i.rd, 5);
        assert_eq!(i.imm, 32);

        let cm_popretz = ((0b101 << 13) | (0x1c << 8) | (5 << 4) | 0b10) as u16;
        let i = decode_rvc(cm_popretz, Xlen::Rv64, &isa);
        assert_eq!(i.op, Op::CmPopRetz);
        assert_eq!(i.imm, 16);

        let cm_push_s1 = ((0b101 << 13) | (0x18 << 8) | (6 << 4) | (1 << 2) | 0b10) as u16;
        let i = decode_rvc(cm_push_s1, Xlen::Rv64, &isa);
        assert_eq!(i.op, Op::CmPush);
        assert_eq!(i.rd, 6);
        assert_eq!(i.imm, 48);

        let cm_mvsa01 =
            ((0b101 << 13) | (0b011 << 10) | (0 << 7) | (0b01 << 5) | (2 << 2) | 0b10) as u16;
        let i = decode_rvc(cm_mvsa01, Xlen::Rv64, &isa);
        assert_eq!(i.op, Op::CmMvsa01);
        assert_eq!(i.rd, 8);
        assert_eq!(i.rs1, 18);

        let cm_mva01s =
            ((0b101 << 13) | (0b011 << 10) | (1 << 7) | (0b11 << 5) | (3 << 2) | 0b10) as u16;
        let i = decode_rvc(cm_mva01s, Xlen::Rv64, &isa);
        assert_eq!(i.op, Op::CmMva01s);
        assert_eq!(i.rd, 9);
        assert_eq!(i.rs1, 19);

        let cm_jt = ((0b101 << 13) | (17 << 2) | 0b10) as u16;
        let i = decode_rvc(cm_jt, Xlen::Rv64, &isa);
        assert_eq!(i.op, Op::CmJt);
        assert_eq!(i.imm, 17);

        let cm_jalt = ((0b101 << 13) | (32 << 2) | 0b10) as u16;
        let i = decode_rvc(cm_jalt, Xlen::Rv64, &isa);
        assert_eq!(i.op, Op::CmJalt);
        assert_eq!(i.imm, 32);

        let reserved = ((0b101 << 13) | (0b011 << 10) | 0b10) as u16;
        assert_eq!(decode_rvc(reserved, Xlen::Rv64, &isa).op, Op::Illegal);

        isa.zcmp = false;
        isa.zcmt = false;
        assert_eq!(decode_rvc(cm_push, Xlen::Rv64, &isa).op, Op::Fsd);
    }

    #[test]
    fn c_ebreak() {
        let h = (0b100 << 13) | (1 << 12) | 0b10;
        assert_eq!(dec(h as u16).op, Op::Ebreak);
    }
}
