//! Direct opcode-dispatch semantic execution layer.
//!
//! This complements the legacy `DecodedInsn` interpreter in `cpu.rs`: when that
//! path yields `Unknown`, the packet driver calls [`dispatch`], which routes the
//! decoded opcode to a per-class handler that reads operand fields straight from
//! the [`DecodedOp`] and records its effects into the in-flight packet state.
//!
//! Every handler is verified against the `qemu-hexagon` reference oracle
//! (`tests/hexagon_diff.rs`); semantics are taken verbatim from the Hexagon
//! V68 spec (`tools/hexagon/qemu/imported/*.idef`, expanded via gen_semantics.c).
//!
//! Register reads observe the *old* architectural state (Hexagon reads
//! previous-packet values); writes are buffered in `new_r`/`new_p` and committed
//! when the packet completes, matching VLIW semantics.

use super::opcode::DecodedOp;
use crate::cpu::HexagonRegisters;

mod alu;
mod alu_ext;
mod alu_pred;
mod bitmanip;
mod compare;
mod extra;
mod float;
mod float_ext;
mod mpy;
mod mpy_ext;
mod shift;
mod shift_ext;
mod vecalu;

/// USR sticky overflow / saturation bit (`USR:0`).
pub const USR_OVF: u32 = 1 << 0;

/// Mutable execution context handed to each per-class handler.
pub struct SemCtx<'a> {
    /// Old architectural register file (read side).
    pub regs: &'a HexagonRegisters,
    /// In-flight GPR writes for this packet.
    pub new_r: &'a mut [Option<u32>; 32],
    /// In-flight predicate writes for this packet.
    pub new_p: &'a mut [Option<u8>; 4],
    /// Pending constant extender for this instruction's immediate, if any.
    pub immext: Option<u32>,
    /// Bits to OR into USR on commit (sticky saturation flag).
    pub usr_or: u32,
}

impl SemCtx<'_> {
    /// Read a 32-bit GPR.
    #[inline]
    pub fn r(&self, reg: u8) -> u32 {
        self.regs.r[reg as usize]
    }

    /// Read a 64-bit register pair (even-aligned).
    #[inline]
    pub fn rp(&self, reg: u8) -> u64 {
        let e = (reg & !1) as usize;
        (self.regs.r[e] as u64) | ((self.regs.r[e + 1] as u64) << 32)
    }

    /// Read an 8-bit predicate register.
    #[inline]
    pub fn p(&self, pred: u8) -> u8 {
        self.regs.p[pred as usize]
    }

    /// Write a 32-bit GPR.
    #[inline]
    pub fn set_r(&mut self, reg: u8, value: u32) {
        self.new_r[reg as usize] = Some(value);
    }

    /// Write a 64-bit register pair (even-aligned).
    #[inline]
    pub fn set_rp(&mut self, reg: u8, value: u64) {
        let e = (reg & !1) as usize;
        self.new_r[e] = Some(value as u32);
        self.new_r[e + 1] = Some((value >> 32) as u32);
    }

    /// Write an 8-bit predicate register.
    #[inline]
    pub fn set_p(&mut self, pred: u8, value: u8) {
        self.new_p[pred as usize] = Some(value);
    }

    /// Raise the sticky saturation/overflow flag.
    #[inline]
    pub fn set_ovf(&mut self) {
        self.usr_or |= USR_OVF;
    }

    /// Saturate a value to a signed `n`-bit range, flagging overflow (`fSATN`).
    #[inline]
    pub fn sat_n(&mut self, val: i64, n: u32) -> i64 {
        let lo = -(1i64 << (n - 1));
        let hi = (1i64 << (n - 1)) - 1;
        if val < lo {
            self.set_ovf();
            lo
        } else if val > hi {
            self.set_ovf();
            hi
        } else {
            val
        }
    }

    /// Saturate a value to an unsigned `n`-bit range, flagging overflow (`fSATUN`).
    #[inline]
    pub fn satu_n(&mut self, val: i64, n: u32) -> i64 {
        let hi = (1i64 << n) - 1;
        if val < 0 {
            self.set_ovf();
            0
        } else if val > hi {
            self.set_ovf();
            hi
        } else {
            val
        }
    }
}

// --- field-extraction helpers shared by the class handlers -----------------

fn sign_extend(value: u32, bits: u8) -> i32 {
    let shift = 32u8.saturating_sub(bits);
    ((value << shift) as i32) >> shift
}

fn apply_immext(imm: u32, ext: u32) -> u32 {
    ((ext & 0x03ff_ffff) << 6) | (imm & 0x3f)
}

/// Read an operand register/predicate field (the raw small field value).
#[inline]
pub(crate) fn fld(d: &DecodedOp, letter: u8) -> u8 {
    d.field(letter).map(|f| f.value as u8).unwrap_or(0)
}

/// Read a signed immediate field, applying a constant extender if present.
#[inline]
pub(crate) fn fimm_s(d: &DecodedOp, letter: u8, immext: Option<u32>) -> i32 {
    match d.field(letter) {
        Some(f) => match immext {
            Some(ext) => apply_immext(f.value, ext) as i32,
            None => sign_extend(f.value, f.bits),
        },
        None => 0,
    }
}

/// Read an unsigned immediate field, applying a constant extender if present.
#[inline]
pub(crate) fn fimm_u(d: &DecodedOp, letter: u8, immext: Option<u32>) -> u32 {
    match d.field(letter) {
        Some(f) => match immext {
            Some(ext) => apply_immext(f.value, ext),
            None => f.value,
        },
        None => 0,
    }
}

/// Dispatch a decoded opcode to its class handler.
/// Returns `true` if a handler executed the instruction.
pub fn dispatch(d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    // Each class returns `false` for opcodes it does not own; try them in turn.
    let op = d.opcode;
    alu::exec(op, d, ctx)
        || alu_pred::exec(op, d, ctx)
        || bitmanip::exec(op, d, ctx)
        || compare::exec(op, d, ctx)
        || float::exec(op, d, ctx)
        || mpy::exec(op, d, ctx)
        || shift::exec(op, d, ctx)
        || vecalu::exec(op, d, ctx)
        || extra::exec(op, d, ctx)
        || mpy_ext::exec(op, d, ctx)
        || shift_ext::exec(op, d, ctx)
        || alu_ext::exec(op, d, ctx)
        || float_ext::exec(op, d, ctx)
}
