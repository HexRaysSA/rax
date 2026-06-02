//! RISC-V instruction decoder.
//!
//! [`decode`] resolves a 32-bit instruction word into a fully-populated
//! [`Insn`]; [`decode_compressed`] handles the 16-bit RVC encodings.
//! [`decode_at`] fetches from memory, selecting the width from the low two bits
//! of the first parcel, and is the entry point used by the execution loop.
//!
//! Decoding is gated by the active [`Isa`]: encodings belonging to a disabled
//! extension resolve to [`Op::Illegal`] so the CPU raises an illegal-instruction
//! exception, exactly as hardware would when the extension is absent.

use super::memory::{MemError, Memory};
use super::{Isa, Xlen};

/// A decoded RISC-V operation. One variant per architectural operation across
/// the I/M/A/F/D/C and Zb* extensions; operand fields live in [`Insn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Op {
    // ---- RV32I / RV64I base ----
    Lui,
    Auipc,
    Jal,
    Jalr,
    Beq,
    Bne,
    Blt,
    Bge,
    Bltu,
    Bgeu,
    Lb,
    Lh,
    Lw,
    Lbu,
    Lhu,
    Lwu,
    Ld,
    Sb,
    Sh,
    Sw,
    Sd,
    Addi,
    Slti,
    Sltiu,
    Xori,
    Ori,
    Andi,
    Slli,
    Srli,
    Srai,
    Add,
    Sub,
    Sll,
    Slt,
    Sltu,
    Xor,
    Srl,
    Sra,
    Or,
    And,
    Addiw,
    Slliw,
    Srliw,
    Sraiw,
    Addw,
    Subw,
    Sllw,
    Srlw,
    Sraw,
    Fence,
    FenceI,
    Ecall,
    Ebreak,
    // ---- privileged / system (subset) ----
    Mret,
    Sret,
    Wfi,
    // ---- Zicsr ----
    Csrrw,
    Csrrs,
    Csrrc,
    Csrrwi,
    Csrrsi,
    Csrrci,
    // ---- M ----
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Div,
    Divu,
    Rem,
    Remu,
    Mulw,
    Divw,
    Divuw,
    Remw,
    Remuw,
    // ---- A (word) ----
    LrW,
    ScW,
    AmoswapW,
    AmoaddW,
    AmoxorW,
    AmoandW,
    AmoorW,
    AmominW,
    AmomaxW,
    AmominuW,
    AmomaxuW,
    // ---- A (double) ----
    LrD,
    ScD,
    AmoswapD,
    AmoaddD,
    AmoxorD,
    AmoandD,
    AmoorD,
    AmominD,
    AmomaxD,
    AmominuD,
    AmomaxuD,
    // ---- F (single precision) ----
    Flw,
    Fsw,
    FmaddS,
    FmsubS,
    FnmsubS,
    FnmaddS,
    FaddS,
    FsubS,
    FmulS,
    FdivS,
    FsqrtS,
    FsgnjS,
    FsgnjnS,
    FsgnjxS,
    FminS,
    FmaxS,
    FcvtWS,
    FcvtWuS,
    FcvtLS,
    FcvtLuS,
    FmvXW,
    FeqS,
    FltS,
    FleS,
    FclassS,
    FcvtSW,
    FcvtSWu,
    FcvtSL,
    FcvtSLu,
    FmvWX,
    // ---- D (double precision) ----
    Fld,
    Fsd,
    FmaddD,
    FmsubD,
    FnmsubD,
    FnmaddD,
    FaddD,
    FsubD,
    FmulD,
    FdivD,
    FsqrtD,
    FsgnjD,
    FsgnjnD,
    FsgnjxD,
    FminD,
    FmaxD,
    FcvtSD,
    FcvtDS,
    FeqD,
    FltD,
    FleD,
    FclassD,
    FcvtWD,
    FcvtWuD,
    FcvtLD,
    FcvtLuD,
    FcvtDW,
    FcvtDWu,
    FcvtDL,
    FcvtDLu,
    FmvXD,
    FmvDX,
    // ---- Zba ----
    Sh1add,
    Sh2add,
    Sh3add,
    AddUw,
    Sh1addUw,
    Sh2addUw,
    Sh3addUw,
    SlliUw,
    // ---- Zbb ----
    Andn,
    Orn,
    Xnor,
    Clz,
    Ctz,
    Cpop,
    Max,
    Maxu,
    Min,
    Minu,
    SextB,
    SextH,
    ZextH,
    Rol,
    Ror,
    Rori,
    Orcb,
    Rev8,
    Clzw,
    Ctzw,
    Cpopw,
    Rolw,
    Rorw,
    Roriw,
    // ---- Zbc ----
    Clmul,
    Clmulh,
    Clmulr,
    // ---- Zbs ----
    Bclr,
    Bclri,
    Bext,
    Bexti,
    Binv,
    Binvi,
    Bset,
    Bseti,
    // ---- sentinel ----
    Illegal,
}

impl Op {
    /// `true` if this is a floating-point (F/D) operation handled by the FP
    /// execution path.
    pub fn is_fp(self) -> bool {
        use Op::*;
        matches!(
            self,
            Flw | Fsw
                | FmaddS | FmsubS | FnmsubS | FnmaddS
                | FaddS | FsubS | FmulS | FdivS | FsqrtS
                | FsgnjS | FsgnjnS | FsgnjxS | FminS | FmaxS
                | FcvtWS | FcvtWuS | FcvtLS | FcvtLuS | FmvXW
                | FeqS | FltS | FleS | FclassS
                | FcvtSW | FcvtSWu | FcvtSL | FcvtSLu | FmvWX
                | Fld | Fsd
                | FmaddD | FmsubD | FnmsubD | FnmaddD
                | FaddD | FsubD | FmulD | FdivD | FsqrtD
                | FsgnjD | FsgnjnD | FsgnjxD | FminD | FmaxD
                | FcvtSD | FcvtDS
                | FeqD | FltD | FleD | FclassD
                | FcvtWD | FcvtWuD | FcvtLD | FcvtLuD
                | FcvtDW | FcvtDWu | FcvtDL | FcvtDLu
                | FmvXD | FmvDX
        )
    }
}

/// A fully decoded instruction with all operand fields resolved.
#[derive(Clone, Copy, Debug)]
pub struct Insn {
    /// The operation.
    pub op: Op,
    /// Destination register (or `rd` for FP).
    pub rd: u8,
    /// First source register.
    pub rs1: u8,
    /// Second source register.
    pub rs2: u8,
    /// Third source register (FMA only).
    pub rs3: u8,
    /// Sign-extended immediate (semantics depend on `op`).
    pub imm: i64,
    /// `funct3` field, reused as the FP rounding-mode field.
    pub funct3: u8,
    /// CSR address (Zicsr) — also carries the 5-bit zimm in `rs1` for the
    /// immediate CSR forms.
    pub csr: u16,
    /// Atomic ordering bit `aq`.
    pub aq: bool,
    /// Atomic ordering bit `rl`.
    pub rl: bool,
    /// Encoded length in bytes (2 for compressed, 4 otherwise).
    pub len: u8,
    /// The raw little-endian instruction bits.
    pub raw: u32,
}

impl Insn {
    /// An illegal instruction of the given length carrying its raw bits.
    fn illegal(raw: u32, len: u8) -> Self {
        Insn {
            op: Op::Illegal,
            rd: 0,
            rs1: 0,
            rs2: 0,
            rs3: 0,
            imm: 0,
            funct3: 0,
            csr: 0,
            aq: false,
            rl: false,
            len,
            raw,
        }
    }

    /// An illegal 16-bit (compressed) parcel.
    pub(crate) fn illegal_compressed(half: u16) -> Self {
        Insn::illegal(half as u32, 2)
    }

    /// `true` for [`Op::Illegal`].
    #[inline]
    pub fn is_illegal(&self) -> bool {
        matches!(self.op, Op::Illegal)
    }

    /// The rounding-mode field of a floating-point instruction.
    #[inline]
    pub fn rm(&self) -> u8 {
        self.funct3
    }
}

/// Errors that can occur while fetching an instruction for decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The instruction parcel could not be read from memory.
    Fetch(MemError),
}

// ---------------------------------------------------------------------------
// Field extraction helpers (operate on the 32-bit instruction word).
// ---------------------------------------------------------------------------

#[inline]
fn opcode(w: u32) -> u32 {
    w & 0x7f
}
#[inline]
fn rd(w: u32) -> u8 {
    ((w >> 7) & 0x1f) as u8
}
#[inline]
fn funct3(w: u32) -> u8 {
    ((w >> 12) & 0x7) as u8
}
#[inline]
fn rs1(w: u32) -> u8 {
    ((w >> 15) & 0x1f) as u8
}
#[inline]
fn rs2(w: u32) -> u8 {
    ((w >> 20) & 0x1f) as u8
}
#[inline]
fn rs3(w: u32) -> u8 {
    ((w >> 27) & 0x1f) as u8
}
#[inline]
fn funct7(w: u32) -> u32 {
    (w >> 25) & 0x7f
}
#[inline]
fn funct2(w: u32) -> u32 {
    (w >> 25) & 0x3
}

// Sign-extended immediates.
#[inline]
fn imm_i(w: u32) -> i64 {
    (w as i32 as i64) >> 20
}
#[inline]
fn imm_s(w: u32) -> i64 {
    let hi = (w >> 25) & 0x7f;
    let lo = (w >> 7) & 0x1f;
    let v = (hi << 5) | lo;
    // sign extend 12 bits
    ((v as i32) << 20 >> 20) as i64
}
#[inline]
fn imm_b(w: u32) -> i64 {
    let b12 = (w >> 31) & 1;
    let b11 = (w >> 7) & 1;
    let b10_5 = (w >> 25) & 0x3f;
    let b4_1 = (w >> 8) & 0xf;
    let v = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    ((v as i32) << 19 >> 19) as i64
}
#[inline]
fn imm_u(w: u32) -> i64 {
    (w & 0xffff_f000) as i32 as i64
}
#[inline]
fn imm_j(w: u32) -> i64 {
    let b20 = (w >> 31) & 1;
    let b19_12 = (w >> 12) & 0xff;
    let b11 = (w >> 20) & 1;
    let b10_1 = (w >> 21) & 0x3ff;
    let v = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    ((v as i32) << 11 >> 11) as i64
}

/// Build a base [`Insn`] with the common register/length fields populated.
fn base(op: Op, w: u32) -> Insn {
    Insn {
        op,
        rd: rd(w),
        rs1: rs1(w),
        rs2: rs2(w),
        rs3: rs3(w),
        imm: 0,
        funct3: funct3(w),
        csr: ((w >> 20) & 0xfff) as u16,
        aq: (w >> 26) & 1 != 0,
        rl: (w >> 25) & 1 != 0,
        len: 4,
        raw: w,
    }
}

/// Decode a 32-bit instruction word under the given XLEN and ISA.
pub fn decode(w: u32, xlen: Xlen, isa: &Isa) -> Insn {
    let rv64 = xlen == Xlen::Rv64;
    match opcode(w) {
        0x37 => with_imm(Op::Lui, w, imm_u(w)),
        0x17 => with_imm(Op::Auipc, w, imm_u(w)),
        0x6f => with_imm(Op::Jal, w, imm_j(w)),
        0x67 if funct3(w) == 0 => with_imm(Op::Jalr, w, imm_i(w)),
        0x63 => decode_branch(w),
        0x03 => decode_load(w, rv64),
        0x23 => decode_store(w, rv64),
        0x13 => decode_op_imm(w, rv64, isa),
        0x1b if rv64 => decode_op_imm32(w, isa),
        0x33 => decode_op(w, isa),
        0x3b if rv64 => decode_op32(w, isa),
        0x0f => decode_fence(w, isa),
        0x73 => decode_system(w, isa),
        0x2f if isa.a => decode_amo(w, rv64),
        0x07 if isa.f => decode_load_fp(w, isa),
        0x27 if isa.f => decode_store_fp(w, isa),
        0x53 if isa.f => decode_op_fp(w, rv64, isa),
        0x43 if isa.f => decode_fma(Op::FmaddS, Op::FmaddD, w, isa),
        0x47 if isa.f => decode_fma(Op::FmsubS, Op::FmsubD, w, isa),
        0x4b if isa.f => decode_fma(Op::FnmsubS, Op::FnmsubD, w, isa),
        0x4f if isa.f => decode_fma(Op::FnmaddS, Op::FnmaddD, w, isa),
        _ => Insn::illegal(w, 4),
    }
}

#[inline]
fn with_imm(op: Op, w: u32, imm: i64) -> Insn {
    let mut i = base(op, w);
    i.imm = imm;
    i
}

fn decode_branch(w: u32) -> Insn {
    let op = match funct3(w) {
        0 => Op::Beq,
        1 => Op::Bne,
        4 => Op::Blt,
        5 => Op::Bge,
        6 => Op::Bltu,
        7 => Op::Bgeu,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_b(w))
}

fn decode_load(w: u32, rv64: bool) -> Insn {
    let op = match funct3(w) {
        0 => Op::Lb,
        1 => Op::Lh,
        2 => Op::Lw,
        3 if rv64 => Op::Ld,
        4 => Op::Lbu,
        5 => Op::Lhu,
        6 if rv64 => Op::Lwu,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_i(w))
}

fn decode_store(w: u32, rv64: bool) -> Insn {
    let op = match funct3(w) {
        0 => Op::Sb,
        1 => Op::Sh,
        2 => Op::Sw,
        3 if rv64 => Op::Sd,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_s(w))
}

fn decode_op_imm(w: u32, rv64: bool, isa: &Isa) -> Insn {
    match funct3(w) {
        0 => with_imm(Op::Addi, w, imm_i(w)),
        2 => with_imm(Op::Slti, w, imm_i(w)),
        3 => with_imm(Op::Sltiu, w, imm_i(w)),
        4 => with_imm(Op::Xori, w, imm_i(w)),
        6 => with_imm(Op::Ori, w, imm_i(w)),
        7 => with_imm(Op::Andi, w, imm_i(w)),
        1 => decode_shift_left_imm(w, rv64, isa),
        5 => decode_shift_right_imm(w, rv64, isa),
        _ => Insn::illegal(w, 4),
    }
}

// OP-IMM funct3==1 (SLLI and Zbb/Zbs left-shift-immediate overlays).
fn decode_shift_left_imm(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let funct6 = (w >> 26) & 0x3f;
    let funct7 = funct7(w);
    let shamt = ((w >> 20) & if rv64 { 0x3f } else { 0x1f }) as i64;
    let rs2f = rs2(w);
    // CLZ/CTZ/CPOP/SEXT.B/SEXT.H share funct7=0b0110000.
    if isa.zbb && funct7 == 0b0110000 {
        let op = match rs2f {
            0b00000 => Op::Clz,
            0b00001 => Op::Ctz,
            0b00010 => Op::Cpop,
            0b00100 => Op::SextB,
            0b00101 => Op::SextH,
            _ => return Insn::illegal(w, 4),
        };
        return base(op, w);
    }
    if isa.zbs {
        match funct6 {
            0b010010 => return with_imm(Op::Bclri, w, shamt),
            0b011010 => return with_imm(Op::Binvi, w, shamt),
            0b001010 => return with_imm(Op::Bseti, w, shamt),
            _ => {}
        }
    }
    // SLLI: funct6 must be zero (RV64) / funct7 zero (RV32).
    if (rv64 && funct6 == 0) || (!rv64 && funct7 == 0) {
        return with_imm(Op::Slli, w, shamt);
    }
    Insn::illegal(w, 4)
}

// OP-IMM funct3==5 (SRLI/SRAI and Zbb/Zbs right-shift-immediate overlays).
fn decode_shift_right_imm(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let funct6 = (w >> 26) & 0x3f;
    let funct7 = funct7(w);
    let rs2f = rs2(w);
    let shamt = ((w >> 20) & if rv64 { 0x3f } else { 0x1f }) as i64;
    if isa.zbb {
        // ORC.B: funct7=0b0010100, rs2=0b00111.
        if funct7 == 0b0010100 && rs2f == 0b00111 {
            return base(Op::Orcb, w);
        }
        // REV8: RV64 funct12=0b011010111000, RV32 funct12=0b011010011000.
        let funct12 = (w >> 20) & 0xfff;
        if (rv64 && funct12 == 0b0110_1011_1000) || (!rv64 && funct12 == 0b0110_1001_1000) {
            return base(Op::Rev8, w);
        }
        if funct6 == 0b011000 {
            return with_imm(Op::Rori, w, shamt);
        }
    }
    if isa.zbs && funct6 == 0b010010 {
        return with_imm(Op::Bexti, w, shamt);
    }
    match funct6 {
        0b000000 => with_imm(Op::Srli, w, shamt),
        0b010000 => with_imm(Op::Srai, w, shamt),
        _ if !rv64 && funct7 == 0b0000000 => with_imm(Op::Srli, w, shamt),
        _ if !rv64 && funct7 == 0b0100000 => with_imm(Op::Srai, w, shamt),
        _ => Insn::illegal(w, 4),
    }
}

// OP-IMM-32 (RV64 word immediate ops + Zba/Zbb word overlays).
fn decode_op_imm32(w: u32, isa: &Isa) -> Insn {
    let funct7 = funct7(w);
    let funct6 = (w >> 26) & 0x3f;
    let rs2f = rs2(w);
    let shamt5 = ((w >> 20) & 0x1f) as i64;
    let shamt6 = ((w >> 20) & 0x3f) as i64;
    match funct3(w) {
        0 => with_imm(Op::Addiw, w, imm_i(w)),
        1 => {
            if isa.zba && funct6 == 0b000010 {
                return with_imm(Op::SlliUw, w, shamt6);
            }
            if isa.zbb && funct7 == 0b0110000 {
                let op = match rs2f {
                    0b00000 => Op::Clzw,
                    0b00001 => Op::Ctzw,
                    0b00010 => Op::Cpopw,
                    _ => return Insn::illegal(w, 4),
                };
                return base(op, w);
            }
            if funct7 == 0 {
                return with_imm(Op::Slliw, w, shamt5);
            }
            Insn::illegal(w, 4)
        }
        5 => {
            if isa.zbb && funct7 == 0b0110000 {
                return with_imm(Op::Roriw, w, shamt5);
            }
            match funct7 {
                0b0000000 => with_imm(Op::Srliw, w, shamt5),
                0b0100000 => with_imm(Op::Sraiw, w, shamt5),
                _ => Insn::illegal(w, 4),
            }
        }
        _ => Insn::illegal(w, 4),
    }
}

// OP (R-type): base, M, Zba/Zbb/Zbc/Zbs overlays.
fn decode_op(w: u32, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    let f7 = funct7(w);
    // M extension.
    if isa.m && f7 == 0b0000001 {
        let op = match f3 {
            0 => Op::Mul,
            1 => Op::Mulh,
            2 => Op::Mulhsu,
            3 => Op::Mulhu,
            4 => Op::Div,
            5 => Op::Divu,
            6 => Op::Rem,
            7 => Op::Remu,
            _ => unreachable!(),
        };
        return base(op, w);
    }
    // Zba.
    if isa.zba && f7 == 0b0010000 {
        let op = match f3 {
            2 => Op::Sh1add,
            4 => Op::Sh2add,
            6 => Op::Sh3add,
            _ => return Insn::illegal(w, 4),
        };
        return base(op, w);
    }
    // Zbb logical-with-negate.
    if isa.zbb && f7 == 0b0100000 {
        match f3 {
            7 => return base(Op::Andn, w),
            6 => return base(Op::Orn, w),
            4 => return base(Op::Xnor, w),
            _ => {}
        }
    }
    // Zbb rotate.
    if isa.zbb && f7 == 0b0110000 {
        match f3 {
            1 => return base(Op::Rol, w),
            5 => return base(Op::Ror, w),
            _ => {}
        }
    }
    // Zbb min/max and Zbc carry-less multiply share funct7=0b0000101.
    if f7 == 0b0000101 {
        if isa.zbc {
            match f3 {
                1 => return base(Op::Clmul, w),
                2 => return base(Op::Clmulr, w),
                3 => return base(Op::Clmulh, w),
                _ => {}
            }
        }
        if isa.zbb {
            match f3 {
                4 => return base(Op::Min, w),
                5 => return base(Op::Minu, w),
                6 => return base(Op::Max, w),
                7 => return base(Op::Maxu, w),
                _ => {}
            }
        }
    }
    // Zbs single-bit (register).
    if isa.zbs {
        match (f7, f3) {
            (0b0100100, 1) => return base(Op::Bclr, w),
            (0b0100100, 5) => return base(Op::Bext, w),
            (0b0110100, 1) => return base(Op::Binv, w),
            (0b0010100, 1) => return base(Op::Bset, w),
            _ => {}
        }
    }
    // Base RV32I/RV64I.
    let op = match (f7, f3) {
        (0b0000000, 0) => Op::Add,
        (0b0100000, 0) => Op::Sub,
        (0b0000000, 1) => Op::Sll,
        (0b0000000, 2) => Op::Slt,
        (0b0000000, 3) => Op::Sltu,
        (0b0000000, 4) => Op::Xor,
        (0b0000000, 5) => Op::Srl,
        (0b0100000, 5) => Op::Sra,
        (0b0000000, 6) => Op::Or,
        (0b0000000, 7) => Op::And,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

// OP-32 (RV64 R-type word ops): base, M, Zba/Zbb overlays.
fn decode_op32(w: u32, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    let f7 = funct7(w);
    if isa.m && f7 == 0b0000001 {
        let op = match f3 {
            0 => Op::Mulw,
            4 => Op::Divw,
            5 => Op::Divuw,
            6 => Op::Remw,
            7 => Op::Remuw,
            _ => return Insn::illegal(w, 4),
        };
        return base(op, w);
    }
    if isa.zba {
        match (f7, f3) {
            (0b0000100, 0) => return base(Op::AddUw, w),
            (0b0010000, 2) => return base(Op::Sh1addUw, w),
            (0b0010000, 4) => return base(Op::Sh2addUw, w),
            (0b0010000, 6) => return base(Op::Sh3addUw, w),
            _ => {}
        }
    }
    if isa.zbb {
        // ZEXT.H (RV64): funct7=0b0000100, funct3=4, rs2=0.
        if f7 == 0b0000100 && f3 == 4 && rs2(w) == 0 {
            return base(Op::ZextH, w);
        }
        if f7 == 0b0110000 {
            match f3 {
                1 => return base(Op::Rolw, w),
                5 => return base(Op::Rorw, w),
                _ => {}
            }
        }
    }
    let op = match (f7, f3) {
        (0b0000000, 0) => Op::Addw,
        (0b0100000, 0) => Op::Subw,
        (0b0000000, 1) => Op::Sllw,
        (0b0000000, 5) => Op::Srlw,
        (0b0100000, 5) => Op::Sraw,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

fn decode_fence(w: u32, isa: &Isa) -> Insn {
    match funct3(w) {
        0 => base(Op::Fence, w),
        1 if isa.zifencei => base(Op::FenceI, w),
        _ => Insn::illegal(w, 4),
    }
}

fn decode_system(w: u32, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    if f3 == 0 {
        // PRIV: distinguished by the full 12-bit funct12 and rs1/rd == 0.
        let funct12 = (w >> 20) & 0xfff;
        return match funct12 {
            0x000 => base(Op::Ecall, w),
            0x001 => base(Op::Ebreak, w),
            0x302 => base(Op::Mret, w),
            0x102 => base(Op::Sret, w),
            0x105 => base(Op::Wfi, w),
            _ => Insn::illegal(w, 4),
        };
    }
    if !isa.zicsr {
        return Insn::illegal(w, 4);
    }
    let op = match f3 {
        1 => Op::Csrrw,
        2 => Op::Csrrs,
        3 => Op::Csrrc,
        5 => Op::Csrrwi,
        6 => Op::Csrrsi,
        7 => Op::Csrrci,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

fn decode_amo(w: u32, rv64: bool) -> Insn {
    let f3 = funct3(w);
    let funct5 = (w >> 27) & 0x1f;
    let is_d = match f3 {
        0b010 => false, // .W
        0b011 if rv64 => true,
        _ => return Insn::illegal(w, 4),
    };
    let op = match (funct5, is_d) {
        (0b00010, false) => Op::LrW,
        (0b00011, false) => Op::ScW,
        (0b00001, false) => Op::AmoswapW,
        (0b00000, false) => Op::AmoaddW,
        (0b00100, false) => Op::AmoxorW,
        (0b01100, false) => Op::AmoandW,
        (0b01000, false) => Op::AmoorW,
        (0b10000, false) => Op::AmominW,
        (0b10100, false) => Op::AmomaxW,
        (0b11000, false) => Op::AmominuW,
        (0b11100, false) => Op::AmomaxuW,
        (0b00010, true) => Op::LrD,
        (0b00011, true) => Op::ScD,
        (0b00001, true) => Op::AmoswapD,
        (0b00000, true) => Op::AmoaddD,
        (0b00100, true) => Op::AmoxorD,
        (0b01100, true) => Op::AmoandD,
        (0b01000, true) => Op::AmoorD,
        (0b10000, true) => Op::AmominD,
        (0b10100, true) => Op::AmomaxD,
        (0b11000, true) => Op::AmominuD,
        (0b11100, true) => Op::AmomaxuD,
        _ => return Insn::illegal(w, 4),
    };
    // LR requires rs2 == 0.
    if matches!(op, Op::LrW | Op::LrD) && rs2(w) != 0 {
        return Insn::illegal(w, 4);
    }
    base(op, w)
}

fn decode_load_fp(w: u32, isa: &Isa) -> Insn {
    let op = match funct3(w) {
        2 => Op::Flw,
        3 if isa.d => Op::Fld,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_i(w))
}

fn decode_store_fp(w: u32, isa: &Isa) -> Insn {
    let op = match funct3(w) {
        2 => Op::Fsw,
        3 if isa.d => Op::Fsd,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_s(w))
}

fn decode_fma(single: Op, double: Op, w: u32, isa: &Isa) -> Insn {
    match funct2(w) {
        0b00 => base(single, w),
        0b01 if isa.d => base(double, w),
        _ => Insn::illegal(w, 4),
    }
}

// OP-FP (0x53): selected by funct7, with funct3 reused as rm or sub-op.
fn decode_op_fp(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let f7 = funct7(w);
    let f3 = funct3(w);
    let rs2f = rs2(w);
    let d = isa.d;
    let op = match f7 {
        0b0000000 => Op::FaddS,
        0b0000001 if d => Op::FaddD,
        0b0000100 => Op::FsubS,
        0b0000101 if d => Op::FsubD,
        0b0001000 => Op::FmulS,
        0b0001001 if d => Op::FmulD,
        0b0001100 => Op::FdivS,
        0b0001101 if d => Op::FdivD,
        0b0101100 if rs2f == 0 => Op::FsqrtS,
        0b0101101 if d && rs2f == 0 => Op::FsqrtD,
        0b0010000 => match f3 {
            0 => Op::FsgnjS,
            1 => Op::FsgnjnS,
            2 => Op::FsgnjxS,
            _ => return Insn::illegal(w, 4),
        },
        0b0010001 if d => match f3 {
            0 => Op::FsgnjD,
            1 => Op::FsgnjnD,
            2 => Op::FsgnjxD,
            _ => return Insn::illegal(w, 4),
        },
        0b0010100 => match f3 {
            0 => Op::FminS,
            1 => Op::FmaxS,
            _ => return Insn::illegal(w, 4),
        },
        0b0010101 if d => match f3 {
            0 => Op::FminD,
            1 => Op::FmaxD,
            _ => return Insn::illegal(w, 4),
        },
        0b0100000 if d && rs2f == 1 => Op::FcvtSD,
        0b0100001 if d && rs2f == 0 => Op::FcvtDS,
        0b1100000 => match rs2f {
            0 => Op::FcvtWS,
            1 => Op::FcvtWuS,
            2 if rv64 => Op::FcvtLS,
            3 if rv64 => Op::FcvtLuS,
            _ => return Insn::illegal(w, 4),
        },
        0b1100001 if d => match rs2f {
            0 => Op::FcvtWD,
            1 => Op::FcvtWuD,
            2 if rv64 => Op::FcvtLD,
            3 if rv64 => Op::FcvtLuD,
            _ => return Insn::illegal(w, 4),
        },
        0b1101000 => match rs2f {
            0 => Op::FcvtSW,
            1 => Op::FcvtSWu,
            2 if rv64 => Op::FcvtSL,
            3 if rv64 => Op::FcvtSLu,
            _ => return Insn::illegal(w, 4),
        },
        0b1101001 if d => match rs2f {
            0 => Op::FcvtDW,
            1 => Op::FcvtDWu,
            2 if rv64 => Op::FcvtDL,
            3 if rv64 => Op::FcvtDLu,
            _ => return Insn::illegal(w, 4),
        },
        0b1110000 if rs2f == 0 => match f3 {
            0 => Op::FmvXW,
            1 => Op::FclassS,
            _ => return Insn::illegal(w, 4),
        },
        0b1110001 if d && rs2f == 0 => match f3 {
            0 if rv64 => Op::FmvXD,
            1 => Op::FclassD,
            _ => return Insn::illegal(w, 4),
        },
        0b1010000 => match f3 {
            0 => Op::FleS,
            1 => Op::FltS,
            2 => Op::FeqS,
            _ => return Insn::illegal(w, 4),
        },
        0b1010001 if d => match f3 {
            0 => Op::FleD,
            1 => Op::FltD,
            2 => Op::FeqD,
            _ => return Insn::illegal(w, 4),
        },
        0b1111000 if rs2f == 0 && f3 == 0 => Op::FmvWX,
        0b1111001 if d && rv64 && rs2f == 0 && f3 == 0 => Op::FmvDX,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

/// Fetch and decode the instruction at `pc`, selecting 16- or 32-bit width.
pub fn decode_at(
    mem: &dyn Memory,
    pc: u64,
    xlen: Xlen,
    isa: &Isa,
) -> Result<Insn, DecodeError> {
    let lo = mem.read_u16(pc).map_err(DecodeError::Fetch)?;
    if lo & 0b11 != 0b11 {
        // 16-bit compressed parcel.
        return Ok(decode_compressed(lo, xlen, isa));
    }
    let hi = mem.read_u16(pc + 2).map_err(DecodeError::Fetch)?;
    let w = (lo as u32) | ((hi as u32) << 16);
    Ok(decode(w, xlen, isa))
}

/// Decode a 16-bit compressed parcel. When `C` is disabled (or the parcel is
/// the reserved all-zero word) the result is an illegal instruction.
pub fn decode_compressed(half: u16, xlen: Xlen, isa: &Isa) -> Insn {
    if !isa.c || half == 0 {
        return Insn::illegal(half as u32, 2);
    }
    decode_rvc(half, xlen, isa)
}

/// Decode a non-zero 16-bit compressed parcel into the equivalent base
/// operation. Implemented in full by the C-extension phase.
fn decode_rvc(half: u16, xlen: Xlen, isa: &Isa) -> Insn {
    super::rvc::decode_rvc(half, xlen, isa)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(w: u32) -> Insn {
        decode(w, Xlen::Rv64, &Isa::rv64gc())
    }

    #[test]
    fn decode_addi() {
        // addi a0, a1, 5  => imm=5, rs1=11, rd=10, funct3=0, opcode=0x13
        let w = (5u32 << 20) | (11 << 15) | (0 << 12) | (10 << 7) | 0x13;
        let i = dec(w);
        assert_eq!(i.op, Op::Addi);
        assert_eq!(i.rd, 10);
        assert_eq!(i.rs1, 11);
        assert_eq!(i.imm, 5);
    }

    #[test]
    fn decode_add_sub() {
        let add = (1u32 << 20) | (2 << 15) | (0 << 12) | (3 << 7) | 0x33;
        assert_eq!(dec(add).op, Op::Add);
        let sub = (0b0100000u32 << 25) | (1 << 20) | (2 << 15) | (0 << 12) | (3 << 7) | 0x33;
        assert_eq!(dec(sub).op, Op::Sub);
    }

    #[test]
    fn decode_branch_imm() {
        // beq x1, x2, +8 : imm=8
        // imm[12|10:5]=funct7, imm[4:1|11]=rd-ish. Build via fields.
        // For +8: bit3 set. b4_1 = 0b0100 (=4 -> *2=8). b11=0,b12=0,b10_5=0.
        let b4_1 = 0b0100u32; // bits [4:1] => value 8
        let w = (b4_1 << 8) | (2 << 20) | (1 << 15) | (0 << 12) | 0x63;
        let i = dec(w);
        assert_eq!(i.op, Op::Beq);
        assert_eq!(i.imm, 8);
    }

    #[test]
    fn decode_m_mul() {
        let w = (0b0000001u32 << 25) | (2 << 20) | (1 << 15) | (0 << 12) | (3 << 7) | 0x33;
        assert_eq!(dec(w).op, Op::Mul);
    }

    #[test]
    fn decode_slli_rv64() {
        // slli a0, a1, 40 (6-bit shamt)
        let w = (40u32 << 20) | (11 << 15) | (1 << 12) | (10 << 7) | 0x13;
        let i = dec(w);
        assert_eq!(i.op, Op::Slli);
        assert_eq!(i.imm, 40);
    }
}
