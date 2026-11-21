//! Semantics of the base ISA and the integer options (loops, MUL16/32, DIV32,
//! MIN/MAX, NSA, SEXT, CLAMPS, booleans, S32C1I, windowed registers, interrupts,
//! timers, region protection).

use std::sync::OnceLock;

use super::cpu::{Exit, Trap, XtensaBus, XtensaCpu};
use super::generated::opcodes::{MNEMONICS, OPCODE_COUNT, Opcode};
use super::mac16::{self, Mac16};
use super::regs::{cause, ps, sr, ur};

// Instruction fields (x24: RRR, RRI8, RI16, CALL, CALLX, BRI8, BRI12, RSR;
// x16: RRRN, RI6, RI7).
#[inline]
fn t(w: u32) -> u32 {
    (w >> 4) & 0xf
}
#[inline]
fn s(w: u32) -> u32 {
    (w >> 8) & 0xf
}
#[inline]
fn r(w: u32) -> u32 {
    (w >> 12) & 0xf
}
#[inline]
fn op1(w: u32) -> u32 {
    (w >> 16) & 0xf
}
#[inline]
fn op2(w: u32) -> u32 {
    (w >> 20) & 0xf
}
#[inline]
fn imm8(w: u32) -> u32 {
    (w >> 16) & 0xff
}
#[inline]
fn simm8(w: u32) -> u32 {
    sext(imm8(w), 8)
}
#[inline]
fn simm12(w: u32) -> u32 {
    sext(w >> 12, 12)
}
#[inline]
fn sr_num(w: u32) -> usize {
    ((w >> 8) & 0xff) as usize
}

/// Sign-extends the low `bits` bits of `v`.
#[inline]
pub(crate) fn sext(v: u32, bits: u32) -> u32 {
    let sh = 32 - bits;
    (((v << sh) as i32) >> sh) as u32
}

const B4CONST: [u32; 16] = [
    0xffff_ffff,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    10,
    12,
    16,
    32,
    64,
    128,
    256,
];
const B4CONSTU: [u32; 16] = [
    32768, 65536, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256,
];

/// How an opcode is executed, derived from its mnemonic.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Plain,
    Rsr,
    Wsr,
    Xsr,
    Rur,
    Wur,
    Mac16(Mac16),
    Fp,
    /// No semantics (PIE and debug instructions).
    Unimplemented,
}

pub(crate) fn kinds() -> &'static [Kind; OPCODE_COUNT] {
    static KINDS: OnceLock<Box<[Kind; OPCODE_COUNT]>> = OnceLock::new();
    KINDS.get_or_init(|| {
        let mut k = Box::new([Kind::Plain; OPCODE_COUNT]);
        for (i, m) in MNEMONICS.iter().enumerate() {
            k[i] = if let Some(rest) = m.strip_prefix("rsr.") {
                let _ = rest;
                Kind::Rsr
            } else if m.starts_with("wsr.") {
                Kind::Wsr
            } else if m.starts_with("xsr.") {
                Kind::Xsr
            } else if m.starts_with("rur.") {
                Kind::Rur
            } else if m.starts_with("wur.") {
                Kind::Wur
            } else if let Some(d) = mac16::parse(m) {
                Kind::Mac16(d)
            } else if super::fpu::is_fp(m) {
                Kind::Fp
            } else if m.starts_with("ee.")
                || matches!(
                    *m,
                    "st.qr" | "ld.qr" | "mv.qr" | "lddr32.p" | "sddr32.p" | "rfdo" | "rfdd"
                )
            {
                Kind::Unimplemented
            } else {
                Kind::Plain
            };
        }
        k
    })
}

type R = Result<(), Trap>;

#[inline]
fn lse(addr: u32) -> Trap {
    Trap::Exception(cause::LOAD_STORE_ERROR, Some(addr))
}

impl XtensaCpu {
    #[inline]
    pub(crate) fn load32<B: XtensaBus>(&mut self, bus: &mut B, addr: u32) -> Result<u32, Trap> {
        bus.read32(addr).map_err(|()| lse(addr))
    }

    #[inline]
    pub(crate) fn store32<B: XtensaBus>(&mut self, bus: &mut B, addr: u32, v: u32) -> R {
        bus.write32(addr, v).map_err(|()| lse(addr))
    }

    #[inline]
    fn branch(&mut self, cond: bool, target: u32) {
        if cond {
            self.jump(target);
        }
    }

    #[inline]
    pub(crate) fn exec<B: XtensaBus>(&mut self, bus: &mut B, op: Opcode, w: u32) -> R {
        match self.kinds[op as usize] {
            Kind::Plain => self.exec_plain(bus, op, w),
            Kind::Rsr => {
                let v = self.read_sr(sr_num(w));
                self.set_a(t(w), v);
                Ok(())
            }
            Kind::Wsr => {
                let v = self.a(t(w));
                self.write_sr(sr_num(w), v)
            }
            Kind::Xsr => {
                let n = sr_num(w);
                let old = self.read_sr(n);
                let v = self.a(t(w));
                self.write_sr(n, v)?;
                self.set_a(t(w), old);
                Ok(())
            }
            Kind::Rur => {
                let n = ((s(w) << 4) | t(w)) as usize;
                if (n == ur::FCR || n == ur::FSR) && self.sr[sr::CPENABLE] & 1 == 0 {
                    return Err(Trap::Exception(cause::COPROCESSOR0_DISABLED, None));
                }
                let v = self.ur[n];
                self.set_a(r(w), v);
                Ok(())
            }
            Kind::Wur => {
                let n = ((r(w) << 4) | s(w)) as usize;
                if (n == ur::FCR || n == ur::FSR) && self.sr[sr::CPENABLE] & 1 == 0 {
                    return Err(Trap::Exception(cause::COPROCESSOR0_DISABLED, None));
                }
                let v = self.a(t(w));
                self.ur[n] = match n {
                    ur::FCR => v & 0xffff_f07f,
                    ur::FSR => v & 0x0000_0f80,
                    _ => v,
                };
                Ok(())
            }
            Kind::Mac16(d) => self.exec_mac16(bus, d, w),
            Kind::Fp => self.exec_fp(bus, op, w),
            Kind::Unimplemented => Err(Trap::Exception(cause::ILLEGAL_INSTRUCTION, None)),
        }
    }

    pub fn read_sr(&self, n: usize) -> u32 {
        match n {
            sr::ACCHI => sext(self.sr[n], 8),
            sr::INTCLEAR => 0,
            _ => self.sr[n],
        }
    }

    pub(crate) fn write_sr(&mut self, n: usize, v: u32) -> R {
        match n {
            sr::SAR => self.sr[n] = v & 0x3f,
            sr::BR => self.sr[n] = v & 0xffff,
            sr::ACCHI => self.sr[n] = sext(v, 8),
            sr::WINDOWBASE => self.sr[n] = v & (self.cfg.nareg as u32 / 4 - 1),
            sr::WINDOWSTART => self.sr[n] = v & ((1 << (self.cfg.nareg / 4)) - 1),
            sr::PS => self.sr[n] = v & ps::MASK,
            sr::INTERRUPT => {
                // INTSET: only software interrupts can be set.
                let sw = self.cfg.type_mask(super::config::IntType::Software);
                self.sr[sr::INTERRUPT] |= v & sw;
            }
            sr::INTCLEAR => {
                let clearable = self.cfg.type_mask(super::config::IntType::Software)
                    | self.cfg.type_mask(super::config::IntType::ExternEdge);
                self.sr[sr::INTERRUPT] &= !(v & clearable);
            }
            sr::CCOUNT => {
                self.sr[n] = v;
                self.recompute_ccompare();
            }
            n if (sr::CCOMPARE0..sr::CCOMPARE0 + 3).contains(&n) => {
                self.sr[n] = v;
                let int = self.cfg.timer_int[n - sr::CCOMPARE0];
                self.sr[sr::INTERRUPT] &= !(1 << int);
                self.recompute_ccompare();
            }
            sr::CPENABLE => self.sr[n] = v & 0xff,
            sr::ATOMCTL => self.sr[n] = v & 0x3f,
            sr::PRID | sr::CONFIGID0 | sr::CONFIGID1 => {}
            sr::MMID => {}
            _ => self.sr[n] = v,
        }
        Ok(())
    }

    fn exec_mac16<B: XtensaBus>(&mut self, bus: &mut B, d: Mac16, w: u32) -> R {
        // Operands are read before the load updates them.
        let mx = sr::M0 + ((r(w) >> 2) & 1) as usize;
        let my = sr::M0 + 2 + ((t(w) >> 2) & 1) as usize;
        let src1 = match d.src1 {
            mac16::Src::A => self.a(s(w)),
            mac16::Src::M => self.sr[mx],
        };
        let src2 = match d.src2 {
            mac16::Src::A => self.a(t(w)),
            mac16::Src::M => self.sr[my],
        };
        let load = match d.load {
            mac16::Load::None => None,
            mac16::Load::Inc => Some(self.a(s(w)).wrapping_add(4)),
            mac16::Load::Dec => Some(self.a(s(w)).wrapping_sub(4)),
        };
        let loaded = match load {
            Some(addr) => Some((addr, self.load32(bus, addr)?)),
            None => None,
        };
        if let Some(acc_op) = d.acc {
            let h1 = if d.hi1 { src1 >> 16 } else { src1 } & 0xffff;
            let h2 = if d.hi2 { src2 >> 16 } else { src2 } & 0xffff;
            let product: i64 = if d.unsigned {
                i64::from(h1) * i64::from(h2)
            } else {
                i64::from(h1 as u16 as i16) * i64::from(h2 as u16 as i16)
            };
            let acc = (i64::from(sext(self.sr[sr::ACCHI], 8) as i32) << 32)
                | i64::from(self.sr[sr::ACCLO]);
            let acc = match acc_op {
                mac16::Acc::Set => product,
                mac16::Acc::Add => acc.wrapping_add(product),
                mac16::Acc::Sub => acc.wrapping_sub(product),
            };
            self.sr[sr::ACCLO] = acc as u32;
            self.sr[sr::ACCHI] = sext((acc >> 32) as u32, 8);
        }
        if let Some((addr, value)) = loaded {
            self.sr[sr::M0 + (r(w) & 3) as usize] = value;
            self.set_a(s(w), addr);
        }
        Ok(())
    }

    fn exec_plain<B: XtensaBus>(&mut self, bus: &mut B, op: Opcode, w: u32) -> R {
        use Opcode::*;
        let pc = self.pc;
        match op {
            // ---- loads and stores ----
            L8UI => {
                let addr = self.a(s(w)).wrapping_add(imm8(w));
                let v = bus.read8(addr).map_err(|()| lse(addr))?;
                self.set_a(t(w), u32::from(v));
            }
            L16UI | L16SI => {
                let addr = self.a(s(w)).wrapping_add(imm8(w) << 1);
                let v = u32::from(bus.read16(addr).map_err(|()| lse(addr))?);
                self.set_a(t(w), if op == L16SI { sext(v, 16) } else { v });
            }
            L32I | L32AI => {
                let addr = self.a(s(w)).wrapping_add(imm8(w) << 2);
                let v = self.load32(bus, addr)?;
                self.set_a(t(w), v);
            }
            S8I => {
                let addr = self.a(s(w)).wrapping_add(imm8(w));
                bus.write8(addr, self.a(t(w)) as u8)
                    .map_err(|()| lse(addr))?;
            }
            S16I => {
                let addr = self.a(s(w)).wrapping_add(imm8(w) << 1);
                bus.write16(addr, self.a(t(w)) as u16)
                    .map_err(|()| lse(addr))?;
            }
            S32I | S32RI | S32NB => {
                let addr = self.a(s(w)).wrapping_add(imm8(w) << 2);
                let v = self.a(t(w));
                self.store32(bus, addr, v)?;
            }
            S32C1I => {
                let addr = self.a(s(w)).wrapping_add(imm8(w) << 2);
                let old = self.load32(bus, addr)?;
                if old == self.sr[sr::SCOMPARE1] {
                    let v = self.a(t(w));
                    self.store32(bus, addr, v)?;
                }
                self.set_a(t(w), old);
            }
            L32I_N => {
                let addr = self.a(s(w)).wrapping_add(r(w) << 2);
                let v = self.load32(bus, addr)?;
                self.set_a(t(w), v);
            }
            S32I_N => {
                let addr = self.a(s(w)).wrapping_add(r(w) << 2);
                let v = self.a(t(w));
                self.store32(bus, addr, v)?;
            }
            L32R => {
                let addr = (pc.wrapping_add(3) & !3)
                    .wrapping_add((((w >> 8) & 0xffff) | 0xffff_0000) << 2);
                let v = self.load32(bus, addr)?;
                self.set_a(t(w), v);
            }
            L32E => {
                let addr = self.a(s(w)).wrapping_add((r(w) << 2).wrapping_sub(64));
                let v = self.load32(bus, addr)?;
                self.set_a(t(w), v);
            }
            S32E => {
                let addr = self.a(s(w)).wrapping_add((r(w) << 2).wrapping_sub(64));
                let v = self.a(t(w));
                self.store32(bus, addr, v)?;
            }

            // ---- constants and moves ----
            MOVI => self.set_a(t(w), sext((s(w) << 8) | imm8(w), 12)),
            MOVI_N => {
                let imm7 = ((t(w) & 7) << 4) | r(w);
                let v = if imm7 >= 96 {
                    imm7.wrapping_sub(128)
                } else {
                    imm7
                };
                self.set_a(s(w), v);
            }
            MOV_N => {
                let v = self.a(s(w));
                self.set_a(t(w), v);
            }
            ADDI => {
                let v = self.a(s(w)).wrapping_add(simm8(w));
                self.set_a(t(w), v);
            }
            ADDMI => {
                let v = self.a(s(w)).wrapping_add(simm8(w) << 8);
                self.set_a(t(w), v);
            }
            ADDI_N => {
                let imm = if t(w) == 0 { 0xffff_ffff } else { t(w) };
                let v = self.a(s(w)).wrapping_add(imm);
                self.set_a(r(w), v);
            }
            MOVEQZ | MOVNEZ | MOVLTZ | MOVGEZ => {
                let c = self.a(t(w));
                let take = match op {
                    MOVEQZ => c == 0,
                    MOVNEZ => c != 0,
                    MOVLTZ => (c as i32) < 0,
                    _ => (c as i32) >= 0,
                };
                if take {
                    let v = self.a(s(w));
                    self.set_a(r(w), v);
                }
            }
            MOVF | MOVT => {
                let b = (self.sr[sr::BR] >> t(w)) & 1 != 0;
                if b == (op == MOVT) {
                    let v = self.a(s(w));
                    self.set_a(r(w), v);
                }
            }

            // ---- arithmetic and logic ----
            ADD | ADD_N | ADDX2 | ADDX4 | ADDX8 | SUB | SUBX2 | SUBX4 | SUBX8 | AND | OR | XOR
            | MIN | MAX | MINU | MAXU | MULL | MULUH | MULSH | MUL16U | MUL16S | SALT | SALTU => {
                let a = self.a(s(w));
                let b = self.a(t(w));
                let v = match op {
                    ADD | ADD_N => a.wrapping_add(b),
                    ADDX2 => (a << 1).wrapping_add(b),
                    ADDX4 => (a << 2).wrapping_add(b),
                    ADDX8 => (a << 3).wrapping_add(b),
                    SUB => a.wrapping_sub(b),
                    SUBX2 => (a << 1).wrapping_sub(b),
                    SUBX4 => (a << 2).wrapping_sub(b),
                    SUBX8 => (a << 3).wrapping_sub(b),
                    AND => a & b,
                    OR => a | b,
                    XOR => a ^ b,
                    MIN => (a as i32).min(b as i32) as u32,
                    MAX => (a as i32).max(b as i32) as u32,
                    MINU => a.min(b),
                    MAXU => a.max(b),
                    MULL => a.wrapping_mul(b),
                    MULUH => ((u64::from(a) * u64::from(b)) >> 32) as u32,
                    MULSH => ((i64::from(a as i32) * i64::from(b as i32)) >> 32) as u32,
                    MUL16U => (a & 0xffff) * (b & 0xffff),
                    MUL16S => (i32::from(a as u16 as i16) * i32::from(b as u16 as i16)) as u32,
                    SALT => u32::from((a as i32) < (b as i32)),
                    _ => u32::from(a < b),
                };
                self.set_a(r(w), v);
            }
            QUOU | QUOS | REMU | REMS => {
                let a = self.a(s(w));
                let b = self.a(t(w));
                if b == 0 {
                    return Err(Trap::Exception(cause::INTEGER_DIVIDE_BY_ZERO, None));
                }
                let v = match op {
                    QUOU => a / b,
                    REMU => a % b,
                    QUOS => (a as i32).wrapping_div(b as i32) as u32,
                    _ => (a as i32).wrapping_rem(b as i32) as u32,
                };
                self.set_a(r(w), v);
            }
            NEG => {
                let v = self.a(t(w)).wrapping_neg();
                self.set_a(r(w), v);
            }
            ABS => {
                let v = (self.a(t(w)) as i32).wrapping_abs() as u32;
                self.set_a(r(w), v);
            }
            NSA => {
                let a = self.a(s(w));
                let x = if (a as i32) < 0 { !a } else { a };
                let v = if x == 0 { 31 } else { x.leading_zeros() - 1 };
                self.set_a(t(w), v);
            }
            NSAU => {
                let v = self.a(s(w)).leading_zeros();
                self.set_a(t(w), v);
            }
            SEXT => {
                let v = sext(self.a(s(w)), t(w) + 8);
                self.set_a(r(w), v);
            }
            CLAMPS => {
                let bits = t(w) + 7;
                let a = self.a(s(w)) as i32;
                let hi = (1i32 << bits) - 1;
                let lo = -(1i32 << bits);
                self.set_a(r(w), a.clamp(lo, hi) as u32);
            }

            // ---- shifts ----
            EXTUI => {
                let shift = s(w) | ((op1(w) & 1) << 4);
                let bits = op2(w) + 1;
                let v = (self.a(t(w)) >> shift) & (u32::MAX >> (32 - bits));
                self.set_a(r(w), v);
            }
            SLLI => {
                let amount = 32 - ((t(w) | ((op2(w) & 1) << 4)) & 31);
                let v = self.a(s(w)).checked_shl(amount).unwrap_or(0);
                self.set_a(r(w), v);
            }
            SRAI => {
                let amount = s(w) | ((op2(w) & 1) << 4);
                let v = ((self.a(t(w)) as i32) >> amount) as u32;
                self.set_a(r(w), v);
            }
            SRLI => {
                let v = self.a(t(w)) >> s(w);
                self.set_a(r(w), v);
            }
            SRC => {
                let sar = self.sr[sr::SAR] & 0x3f;
                let wide = (u64::from(self.a(s(w))) << 32) | u64::from(self.a(t(w)));
                self.set_a(r(w), wide.checked_shr(sar).unwrap_or(0) as u32);
            }
            SRL => {
                let sar = self.sr[sr::SAR] & 0x3f;
                self.set_a(
                    r(w),
                    u64::from(self.a(t(w))).checked_shr(sar).unwrap_or(0) as u32,
                );
            }
            SLL => {
                let sar = self.sr[sr::SAR] & 0x3f;
                let wide = u64::from(self.a(s(w))) << 32;
                self.set_a(r(w), wide.checked_shr(sar).unwrap_or(0) as u32);
            }
            SRA => {
                let sar = (self.sr[sr::SAR] & 0x3f).min(63);
                let v = (i64::from(self.a(t(w)) as i32) >> sar) as u32;
                self.set_a(r(w), v);
            }
            SSR => self.sr[sr::SAR] = self.a(s(w)) & 0x1f,
            SSL => self.sr[sr::SAR] = 32 - (self.a(s(w)) & 0x1f),
            SSA8L => self.sr[sr::SAR] = (self.a(s(w)) & 3) << 3,
            SSA8B => self.sr[sr::SAR] = 32 - ((self.a(s(w)) & 3) << 3),
            SSAI => self.sr[sr::SAR] = s(w) | ((t(w) & 1) << 4),

            // ---- branches and jumps ----
            BEQZ | BNEZ | BLTZ | BGEZ => {
                let a = self.a(s(w));
                let c = match op {
                    BEQZ => a == 0,
                    BNEZ => a != 0,
                    BLTZ => (a as i32) < 0,
                    _ => (a as i32) >= 0,
                };
                self.branch(c, pc.wrapping_add(4).wrapping_add(simm12(w)));
            }
            BEQZ_N | BNEZ_N => {
                let imm6 = ((t(w) & 3) << 4) | r(w);
                let a = self.a(s(w));
                self.branch(
                    (a == 0) == (op == BEQZ_N),
                    pc.wrapping_add(4).wrapping_add(imm6),
                );
            }
            BEQI | BNEI | BLTI | BGEI => {
                let a = self.a(s(w));
                let b = B4CONST[r(w) as usize];
                let c = match op {
                    BEQI => a == b,
                    BNEI => a != b,
                    BLTI => (a as i32) < (b as i32),
                    _ => (a as i32) >= (b as i32),
                };
                self.branch(c, pc.wrapping_add(4).wrapping_add(simm8(w)));
            }
            BLTUI | BGEUI => {
                let a = self.a(s(w));
                let b = B4CONSTU[r(w) as usize];
                self.branch(
                    (a < b) == (op == BLTUI),
                    pc.wrapping_add(4).wrapping_add(simm8(w)),
                );
            }
            BEQ | BNE | BLT | BGE | BLTU | BGEU | BANY | BNONE | BALL | BNALL | BBC | BBS => {
                let a = self.a(s(w));
                let b = self.a(t(w));
                let c = match op {
                    BEQ => a == b,
                    BNE => a != b,
                    BLT => (a as i32) < (b as i32),
                    BGE => (a as i32) >= (b as i32),
                    BLTU => a < b,
                    BGEU => a >= b,
                    BANY => a & b != 0,
                    BNONE => a & b == 0,
                    BALL => !a & b == 0,
                    BNALL => !a & b != 0,
                    BBC => (a >> (b & 31)) & 1 == 0,
                    _ => (a >> (b & 31)) & 1 != 0,
                };
                self.branch(c, pc.wrapping_add(4).wrapping_add(simm8(w)));
            }
            BBCI | BBSI => {
                let bitn = t(w) | ((r(w) & 1) << 4);
                let set = (self.a(s(w)) >> bitn) & 1 != 0;
                self.branch(
                    set == (op == BBSI),
                    pc.wrapping_add(4).wrapping_add(simm8(w)),
                );
            }
            BF | BT => {
                let b = (self.sr[sr::BR] >> s(w)) & 1 != 0;
                self.branch(b == (op == BT), pc.wrapping_add(4).wrapping_add(simm8(w)));
            }
            J => self.jump(pc.wrapping_add(4).wrapping_add(sext(w >> 6, 18))),
            JX => {
                let target = self.a(s(w));
                self.jump(target);
            }
            CALL0 | CALL4 | CALL8 | CALL12 => {
                let target = (pc & !3)
                    .wrapping_add(sext(w >> 6, 18) << 2)
                    .wrapping_add(4);
                let n = match op {
                    CALL0 => 0,
                    CALL4 => 1,
                    CALL8 => 2,
                    _ => 3,
                };
                self.call(n, target);
            }
            CALLX0 | CALLX4 | CALLX8 | CALLX12 => {
                let target = self.a(s(w));
                let n = match op {
                    CALLX0 => 0,
                    CALLX4 => 1,
                    CALLX8 => 2,
                    _ => 3,
                };
                self.call(n, target);
            }
            RET | RET_N => {
                let target = self.a(0);
                self.jump(target);
            }
            RETW | RETW_N => return self.retw(),
            ENTRY => return self.entry(s(w), (w >> 12) << 3),
            MOVSP => {
                let wb = self.sr[sr::WINDOWBASE];
                let live = self.windowstart_bit(wb.wrapping_sub(1))
                    | self.windowstart_bit(wb.wrapping_sub(2))
                    | self.windowstart_bit(wb.wrapping_sub(3));
                if self.sr[sr::WINDOWSTART] & live == 0 {
                    return Err(Trap::Exception(cause::ALLOCA, None));
                }
                let v = self.a(s(w));
                self.set_a(t(w), v);
            }
            ROTW => self.rotate_window(sext(t(w), 4)),
            RFWO | RFWU => {
                self.sr[sr::PS] &= !ps::EXCM;
                let b = self.windowstart_bit(self.sr[sr::WINDOWBASE]);
                if op == RFWO {
                    self.sr[sr::WINDOWSTART] &= !b;
                } else {
                    self.sr[sr::WINDOWSTART] |= b;
                }
                self.sr[sr::WINDOWBASE] = (self.sr[sr::PS] & ps::OWB) >> ps::OWB_SHIFT;
                let target = self.sr[sr::EPC1];
                self.jump(target);
            }

            // ---- zero-overhead loops ----
            LOOP | LOOPNEZ | LOOPGTZ => {
                let count = self.a(s(w));
                let lend = pc.wrapping_add(4).wrapping_add(imm8(w));
                self.sr[sr::LCOUNT] = count.wrapping_sub(1);
                self.sr[sr::LBEG] = self.npc;
                self.sr[sr::LEND] = lend;
                let skip = match op {
                    LOOPNEZ => count == 0,
                    LOOPGTZ => (count as i32) <= 0,
                    _ => false,
                };
                if skip {
                    self.jump(lend);
                } else {
                    // A loop instruction never takes its own back-edge.
                    self.jumped = true;
                }
            }

            // ---- booleans ----
            ANDB | ANDBC | ORB | ORBC | XORB => {
                let br = self.sr[sr::BR];
                let bs = (br >> s(w)) & 1;
                let bt = (br >> t(w)) & 1;
                let v = match op {
                    ANDB => bs & bt,
                    ANDBC => bs & !bt & 1,
                    ORB => bs | bt,
                    ORBC => (bs | !bt) & 1,
                    _ => bs ^ bt,
                };
                self.sr[sr::BR] = (br & !(1 << r(w))) | (v << r(w));
            }
            ANY4 | ALL4 | ANY8 | ALL8 => {
                let br = self.sr[sr::BR];
                let n = if matches!(op, ANY4 | ALL4) { 4 } else { 8 };
                let field = (br >> s(w)) & ((1 << n) - 1);
                let v = match op {
                    ANY4 | ANY8 => u32::from(field != 0),
                    _ => u32::from(field == (1 << n) - 1),
                };
                self.sr[sr::BR] = (br & !(1 << t(w))) | (v << t(w));
            }

            // ---- processor control ----
            NOP | NOP_N | MEMW | EXTW | ISYNC | RSYNC | ESYNC | DSYNC | EXCW => {}
            RSIL => {
                let old = self.sr[sr::PS];
                self.sr[sr::PS] = (old & !ps::INTLEVEL) | s(w);
                self.set_a(t(w), old);
            }
            WAITI => {
                self.sr[sr::PS] = (self.sr[sr::PS] & !ps::INTLEVEL) | s(w);
                self.waiting = true;
            }
            RFE => {
                self.sr[sr::PS] &= !ps::EXCM;
                let target = self.sr[sr::EPC1];
                self.jump(target);
            }
            RFDE => {
                let target = self.sr[sr::DEPC];
                self.jump(target);
            }
            RFI => {
                let level = s(w) as usize;
                if !(2..=7).contains(&level) {
                    return Err(Trap::Exception(cause::ILLEGAL_INSTRUCTION, None));
                }
                self.sr[sr::PS] = self.sr[sr::EPS2 + level - 2];
                let target = self.sr[sr::EPC1 + level - 1];
                self.jump(target);
            }
            SYSCALL => return Err(Trap::Exception(cause::SYSCALL, None)),
            ILL | ILL_N => return Err(Trap::Exception(cause::ILLEGAL_INSTRUCTION, None)),
            BREAK => return Err(Trap::Exit(Exit::Break { s: s(w), t: t(w) })),
            BREAK_N => return Err(Trap::Exit(Exit::Break { s: s(w), t: 0 })),
            SIMCALL => return Err(Trap::Exit(Exit::Simcall)),
            RER => {
                let v = bus.eri_read(self.a(s(w)));
                self.set_a(t(w), v);
            }
            WER => {
                let (addr, v) = (self.a(s(w)), self.a(t(w)));
                bus.eri_write(addr, v);
            }

            // ---- region protection ----
            WITLB | WDTLB => {
                let region = (self.a(s(w)) >> 29) as usize;
                self.region_attr[region] = self.a(t(w)) & 0xf;
            }
            RITLB0 | RDTLB0 => {
                let v = self.a(s(w)) & 0xe000_0000;
                self.set_a(t(w), v);
            }
            RITLB1 | RDTLB1 | PITLB | PDTLB => {
                let region = (self.a(s(w)) >> 29) as usize;
                let v = (self.a(s(w)) & 0xe000_0000) | self.region_attr[region];
                self.set_a(t(w), v);
            }
            IITLB | IDTLB => {}

            _ => return Err(Trap::Exception(cause::ILLEGAL_INSTRUCTION, None)),
        }
        Ok(())
    }

    fn call(&mut self, n: u32, target: u32) {
        if n > 0 {
            self.sr[sr::PS] = (self.sr[sr::PS] & !ps::CALLINC) | (n << ps::CALLINC_SHIFT);
        }
        // Windowed calls keep the window increment in the top bits of the return address.
        let ret = if n == 0 {
            self.npc
        } else {
            (n << 30) | (self.npc & 0x3fff_ffff)
        };
        self.set_a(n << 2, ret);
        self.jump(target);
    }

    fn entry(&mut self, s: u32, frame: u32) -> R {
        if s > 3 || !self.cwoe() {
            return Err(Trap::Exception(cause::ILLEGAL_INSTRUCTION, None));
        }
        let callinc = (self.sr[sr::PS] & ps::CALLINC) >> ps::CALLINC_SHIFT;
        let sp = self.a(s).wrapping_sub(frame);
        self.set_a((callinc << 2) | (s & 3), sp);
        let wb = self.sr[sr::WINDOWBASE].wrapping_add(callinc);
        self.sr[sr::WINDOWSTART] |= self.windowstart_bit(wb);
        self.rotate_window(callinc);
        Ok(())
    }

    fn retw(&mut self) -> R {
        if !self.cwoe() {
            return Err(Trap::Exception(cause::ILLEGAL_INSTRUCTION, None));
        }
        let a0 = self.a(0);
        let n = a0 >> 30;
        let wb = self.sr[sr::WINDOWBASE];
        let ws = self.sr[sr::WINDOWSTART];
        let m = (1..=3)
            .find(|&k| ws & self.windowstart_bit(wb.wrapping_sub(k)) != 0)
            .unwrap_or(0);
        if n == 0 || (m != 0 && m != n) {
            return Err(Trap::Exception(cause::ILLEGAL_INSTRUCTION, None));
        }
        if ws & self.windowstart_bit(wb.wrapping_sub(n)) == 0 {
            self.window_underflow(n);
            return Err(Trap::Vectored);
        }
        self.sr[sr::WINDOWSTART] &= !self.windowstart_bit(wb);
        let target = (self.pc & 0xc000_0000) | (a0 & 0x3fff_ffff);
        self.rotate_window(n.wrapping_neg());
        self.jump(target);
        Ok(())
    }
}
