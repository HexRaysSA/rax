//! Single-precision floating-point coprocessor (coprocessor 0).
//!
//! Arithmetic uses the host's IEEE-754 single precision, rounding to nearest even
//! whatever FCR.RM says, and FSR flags are not raised. The division and square
//! root step instructions are reduced to whole operations:
//! `mkdadj.s` divides and `mksadj.s` takes the square root in one step,
//! `addexpm.s` moves, and `div0.s`, `nexp01.s`, `addexp.s`, `maddn.s` and
//! `divn.s` do nothing; `sqrt0.s`, `recip0.s` and `rsqrt0.s` are illegal.

use super::cpu::{Trap, XtensaBus, XtensaCpu};
use super::generated::opcodes::Opcode;
use super::regs::{cause, sr};

const FP_MNEMONICS: &[&str] = &[
    "lsi",
    "lsip",
    "lsx",
    "lsxp",
    "ssi",
    "ssip",
    "ssx",
    "ssxp",
    "abs.s",
    "neg.s",
    "mov.s",
    "moveqz.s",
    "movnez.s",
    "movltz.s",
    "movgez.s",
    "movf.s",
    "movt.s",
    "wfr",
    "rfr",
    "round.s",
    "ceil.s",
    "floor.s",
    "trunc.s",
    "utrunc.s",
    "float.s",
    "ufloat.s",
    "un.s",
    "ult.s",
    "ule.s",
    "ueq.s",
    "olt.s",
    "ole.s",
    "oeq.s",
    "add.s",
    "sub.s",
    "mul.s",
    "madd.s",
    "msub.s",
    "sqrt0.s",
    "div0.s",
    "recip0.s",
    "rsqrt0.s",
    "maddn.s",
    "divn.s",
    "const.s",
    "nexp01.s",
    "addexp.s",
    "addexpm.s",
    "mkdadj.s",
    "mksadj.s",
];

pub(crate) fn is_fp(mnemonic: &str) -> bool {
    FP_MNEMONICS.contains(&mnemonic)
}

#[derive(Clone, Copy)]
enum Round {
    NearestEven,
    Zero,
    Down,
    Up,
}

fn round(v: f64, mode: Round) -> f64 {
    match mode {
        Round::NearestEven => v.round_ties_even(),
        Round::Zero => v.trunc(),
        Round::Down => v.floor(),
        Round::Up => v.ceil(),
    }
}

/// `fs * 2^scale` to a signed integer, saturating; NaN gives `i32::MAX`.
fn to_i32(v: f32, scale: u32, mode: Round) -> u32 {
    if v.is_nan() {
        return i32::MAX as u32;
    }
    let x = round(f64::from(v) * f64::from(1u32 << scale), mode);
    (x.clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32) as u32
}

/// `utrunc.s`: negative values convert as signed, the rest unsigned, saturating;
/// NaN gives `u32::MAX`.
fn to_u32_trunc(v: f32, scale: u32) -> u32 {
    if v.is_nan() {
        return u32::MAX;
    }
    if v.is_sign_negative() {
        return to_i32(v, scale, Round::Zero);
    }
    let x = (f64::from(v) * f64::from(1u32 << scale)).trunc();
    x.min(f64::from(u32::MAX)) as u32
}

#[inline]
fn f(bits: u32) -> f32 {
    f32::from_bits(bits)
}

impl XtensaCpu {
    pub(crate) fn exec_fp<B: XtensaBus>(
        &mut self,
        bus: &mut B,
        op: Opcode,
        w: u32,
    ) -> Result<(), Trap> {
        use Opcode::*;
        if self.sr[sr::CPENABLE] & 1 == 0 {
            return Err(Trap::Exception(cause::COPROCESSOR0_DISABLED, None));
        }
        let t = (w >> 4) & 0xf;
        let s = (w >> 8) & 0xf;
        let r = (w >> 12) & 0xf;
        let imm8 = (w >> 16) & 0xff;
        let (fr, fs, ft) = (r as usize, s as usize, t as usize);
        match op {
            LSI | LSIP | SSI | SSIP => {
                let base = self.a(s);
                let offset = imm8 << 2;
                let addr = if matches!(op, LSI | SSI) {
                    base.wrapping_add(offset)
                } else {
                    base
                };
                if matches!(op, LSI | LSIP) {
                    let v = self.load32(bus, addr)?;
                    self.fr[ft] = v;
                } else {
                    let v = self.fr[ft];
                    self.store32(bus, addr, v)?;
                }
                if matches!(op, LSIP | SSIP) {
                    self.set_a(s, base.wrapping_add(offset));
                }
            }
            LSX | LSXP | SSX | SSXP => {
                let base = self.a(s);
                let offset = self.a(t);
                let addr = if matches!(op, LSX | SSX) {
                    base.wrapping_add(offset)
                } else {
                    base
                };
                if matches!(op, LSX | LSXP) {
                    let v = self.load32(bus, addr)?;
                    self.fr[fr] = v;
                } else {
                    let v = self.fr[fr];
                    self.store32(bus, addr, v)?;
                }
                if matches!(op, LSXP | SSXP) {
                    self.set_a(s, base.wrapping_add(offset));
                }
            }
            ADD_S => self.fr[fr] = (f(self.fr[fs]) + f(self.fr[ft])).to_bits(),
            SUB_S => self.fr[fr] = (f(self.fr[fs]) - f(self.fr[ft])).to_bits(),
            MUL_S => self.fr[fr] = (f(self.fr[fs]) * f(self.fr[ft])).to_bits(),
            MADD_S => {
                self.fr[fr] = f(self.fr[fs])
                    .mul_add(f(self.fr[ft]), f(self.fr[fr]))
                    .to_bits()
            }
            MSUB_S => {
                self.fr[fr] = (-f(self.fr[fs]))
                    .mul_add(f(self.fr[ft]), f(self.fr[fr]))
                    .to_bits()
            }
            ABS_S => self.fr[fr] = self.fr[fs] & 0x7fff_ffff,
            NEG_S => self.fr[fr] = self.fr[fs] ^ 0x8000_0000,
            MOV_S | ADDEXPM_S => self.fr[fr] = self.fr[fs],
            MOVEQZ_S | MOVNEZ_S | MOVLTZ_S | MOVGEZ_S => {
                let c = self.a(t);
                let take = match op {
                    MOVEQZ_S => c == 0,
                    MOVNEZ_S => c != 0,
                    MOVLTZ_S => (c as i32) < 0,
                    _ => (c as i32) >= 0,
                };
                if take {
                    self.fr[fr] = self.fr[fs];
                }
            }
            MOVF_S | MOVT_S => {
                let b = (self.sr[sr::BR] >> t) & 1 != 0;
                if b == (op == MOVT_S) {
                    self.fr[fr] = self.fr[fs];
                }
            }
            RFR => {
                let v = self.fr[fs];
                self.set_a(r, v);
            }
            WFR => self.fr[fr] = self.a(s),
            ROUND_S | TRUNC_S | FLOOR_S | CEIL_S => {
                let mode = match op {
                    ROUND_S => Round::NearestEven,
                    TRUNC_S => Round::Zero,
                    FLOOR_S => Round::Down,
                    _ => Round::Up,
                };
                let v = to_i32(f(self.fr[fs]), t, mode);
                self.set_a(r, v);
            }
            UTRUNC_S => {
                let v = to_u32_trunc(f(self.fr[fs]), t);
                self.set_a(r, v);
            }
            FLOAT_S | UFLOAT_S => {
                let a = self.a(s);
                let x = if op == FLOAT_S {
                    f64::from(a as i32)
                } else {
                    f64::from(a)
                };
                self.fr[fr] = ((x / f64::from(1u32 << t)) as f32).to_bits();
            }
            UN_S | OEQ_S | UEQ_S | OLT_S | ULT_S | OLE_S | ULE_S => {
                let (a, b) = (f(self.fr[fs]), f(self.fr[ft]));
                let un = a.is_nan() || b.is_nan();
                let v = match op {
                    UN_S => un,
                    OEQ_S => a == b,
                    UEQ_S => un || a == b,
                    OLT_S => a < b,
                    ULT_S => un || a < b,
                    OLE_S => a <= b,
                    _ => un || a <= b,
                };
                let br = self.sr[sr::BR];
                self.sr[sr::BR] = (br & !(1 << r)) | (u32::from(v) << r);
            }
            CONST_S => {
                const V: [u32; 4] = [0x0000_0000, 0x3f80_0000, 0x4000_0000, 0x3f00_0000];
                self.fr[fr] = V[(s % 4) as usize];
            }
            MKDADJ_S => self.fr[fr] = (f(self.fr[fs]) / f(self.fr[fr])).to_bits(),
            MKSADJ_S => self.fr[fr] = f(self.fr[fs]).sqrt().to_bits(),
            DIV0_S | NEXP01_S | ADDEXP_S | MADDN_S | DIVN_S => {}
            _ => return Err(Trap::Exception(cause::ILLEGAL_INSTRUCTION, None)),
        }
        Ok(())
    }
}
