//! A/Zacas width, extension and register-pair admission.
use super::{Insn, Isa, Op, base, funct3, rd, rs2};

pub(super) fn decode_amo(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    let funct5 = (w >> 27) & 0x1f;
    let width = match f3 {
        0b010 => 4, // .W
        0b011 if rv64 || (funct5 == 0b00101 && isa.zacas) => 8,
        0b100 if rv64 => 16,
        _ => return Insn::illegal(w, 4),
    };
    let op = match (funct5, width) {
        (0b00010, 4) => Op::LrW,
        (0b00011, 4) => Op::ScW,
        (0b00001, 4) => Op::AmoswapW,
        (0b00000, 4) => Op::AmoaddW,
        (0b00100, 4) => Op::AmoxorW,
        (0b01100, 4) => Op::AmoandW,
        (0b01000, 4) => Op::AmoorW,
        (0b10000, 4) => Op::AmominW,
        (0b10100, 4) => Op::AmomaxW,
        (0b11000, 4) => Op::AmominuW,
        (0b11100, 4) => Op::AmomaxuW,
        (0b00101, 4) if isa.zacas => Op::AmocasW,
        (0b00010, 8) => Op::LrD,
        (0b00011, 8) => Op::ScD,
        (0b00001, 8) => Op::AmoswapD,
        (0b00000, 8) => Op::AmoaddD,
        (0b00100, 8) => Op::AmoxorD,
        (0b01100, 8) => Op::AmoandD,
        (0b01000, 8) => Op::AmoorD,
        (0b10000, 8) => Op::AmominD,
        (0b10100, 8) => Op::AmomaxD,
        (0b11000, 8) => Op::AmominuD,
        (0b11100, 8) => Op::AmomaxuD,
        (0b00101, 8) if isa.zacas => Op::AmocasD,
        (0b00101, 16) if isa.zacas => Op::AmocasQ,
        _ => return Insn::illegal(w, 4),
    };
    // Zacas implies Zaamo, not Zalrsc. LR/SC still requires the A profile.
    if !isa.a && matches!(op, Op::LrW | Op::LrD | Op::ScW | Op::ScD) {
        return Insn::illegal(w, 4);
    }
    // LR requires rs2 == 0.
    if matches!(op, Op::LrW | Op::LrD) && rs2(w) != 0 {
        return Insn::illegal(w, 4);
    }
    if (matches!(op, Op::AmocasQ) || (!rv64 && matches!(op, Op::AmocasD)))
        && (rd(w) & 1 != 0 || rs2(w) & 1 != 0)
    {
        return Insn::illegal(w, 4);
    }
    base(op, w)
}
