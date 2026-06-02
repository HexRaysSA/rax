use crate::config::HexagonIsa;

use super::opcode::{self, DecodedOp, EncClass, FieldVal, Opcode};

#[derive(Clone, Copy, Debug)]
pub struct PredCond {
    pub pred: u8,
    pub sense: bool,
    pub pred_new: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemWidth {
    Byte,
    Half,
    Word,
    Double,
}

#[derive(Clone, Copy, Debug)]
pub enum MemSign {
    Signed,
    Unsigned,
}

#[derive(Clone, Copy, Debug)]
pub enum AddrMode {
    Offset { base: u8, offset: i32 },
    PostIncImm { base: u8, offset: i32 },
    GpOffset { offset: i32 },
    Abs { addr: u32 },
    /// `memX(Rx++Mu)` — post-increment the base by the M register (M0 or M1
    /// selected by `modsel`; the raw M value is added, not the I-field).
    PostIncReg { base: u8, modsel: u8 },
    /// `memX(Rx++Mu:brev)` — the effective address is the bit-reversed base;
    /// the base is then post-incremented by the M register.
    PostIncBrev { base: u8, modsel: u8 },
    /// `memX(Rx++#s4:N:circ(Mu))` — circular post-increment by an immediate.
    /// `incr` is the (already scaled) byte increment; the buffer length/K come
    /// from M[modsel] and the base wraps within [CS[modsel], CS+length).
    PostIncCircImm { base: u8, modsel: u8, incr: i32 },
    /// `memX(Rx++I:circ(Mu))` — circular post-increment by register. The
    /// increment is the I field of M[modsel] (`fREAD_IREG`), shifted by the
    /// access size, applied with the same circular wrap.
    PostIncCircReg { base: u8, modsel: u8, shift: u8 },
}

#[derive(Clone, Copy, Debug)]
pub enum ShiftKind {
    Lsl,
    Lsr,
    Asr,
}

#[derive(Clone, Copy, Debug)]
pub enum CmpKind {
    Eq,
    Gt,
    Gtu,
    Ne,
    Lte,
    Lteu,
}

#[derive(Clone, Copy, Debug)]
pub enum ExtendKind {
    Sxt8,
    Sxt16,
    Zxt8,
    Zxt16,
}

#[derive(Clone, Copy, Debug)]
pub enum CombineOperand {
    Reg(u8),
    Imm(u32),
}

/// Read-modify-write memory operation (`memX(Rs+#u) OP= ...`).
#[derive(Clone, Copy, Debug)]
pub enum MemOpKind {
    Add,
    Sub,
    And,
    Or,
    /// `mem &= ~(1 << src)` — clear bit `src`.
    ClrBit,
    /// `mem |= (1 << src)` — set bit `src`.
    SetBit,
}

#[derive(Clone, Copy, Debug)]
pub enum MemOpSrc {
    Reg(u8),
    Imm(u32),
}

#[derive(Clone, Copy, Debug)]
pub enum DecodedInsn {
    ImmExt {
        value: u32,
    },
    Add {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    Sub {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    And {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    AndImm {
        dst: u8,
        src: u8,
        imm: u32,
    },
    OrImm {
        dst: u8,
        src: u8,
        imm: u32,
    },
    Or {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    Xor {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    AddImm {
        dst: u8,
        src: u8,
        imm: i32,
    },
    SubImmRev {
        dst: u8,
        src: u8,
        imm: i32,
    },
    Mov {
        dst: u8,
        src: u8,
    },
    MovImm {
        dst: u8,
        imm: i32,
    },
    Abs {
        dst: u8,
        src: u8,
        sat: bool,
    },
    NegSat {
        dst: u8,
        src: u8,
    },
    Max {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    Maxu {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    Min {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    Minu {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    ClearCond {
        dst: u8,
        pred: PredCond,
    },
    Extend {
        dst: u8,
        src: u8,
        kind: ExtendKind,
    },
    Combine {
        dst: u8,
        high: CombineOperand,
        low: CombineOperand,
    },
    Load {
        dst: u8,
        addr: AddrMode,
        width: MemWidth,
        sign: MemSign,
        pred: Option<PredCond>,
    },
    Store {
        src: u8,
        addr: AddrMode,
        width: MemWidth,
        pred: Option<PredCond>,
        src_new: bool,
    },
    StoreImm {
        value: u32,
        addr: AddrMode,
        width: MemWidth,
        pred: Option<PredCond>,
    },
    AllocFrame {
        base: u8,
        size: u32,
    },
    DeallocFrame {
        base: u8,
        dst: Option<u8>,
        update_lr_fp: bool,
    },
    DeallocReturn {
        base: u8,
        dst: Option<u8>,
        pred: Option<PredCond>,
        update_lr_fp: bool,
    },
    Jump {
        offset: i32,
    },
    JumpCond {
        offset: i32,
        pred: u8,
        sense: bool,
        pred_new: bool,
    },
    JumpReg {
        src: u8,
    },
    JumpRegCond {
        src: u8,
        pred: u8,
        sense: bool,
        pred_new: bool,
    },
    Call {
        offset: i32,
    },
    CallReg {
        src: u8,
    },
    Cmp {
        pred: u8,
        src1: u8,
        src2: u8,
        kind: CmpKind,
    },
    CmpImm {
        pred: u8,
        src: u8,
        imm: i32,
        kind: CmpKind,
        unsigned: bool,
    },
    Mul {
        dst: u8,
        src1: u8,
        src2: u8,
    },
    ShiftImm {
        dst: u8,
        src: u8,
        kind: ShiftKind,
        amount: u8,
    },
    ShiftReg {
        dst: u8,
        src: u8,
        amt: u8,
        kind: ShiftKind,
    },
    TfrCrR {
        dst: u8,
        src: u8,
    },
    TfrRrCr {
        dst: u8,
        src: u8,
    },
    LoopStartReg {
        loop_id: u8,
        start_offset: i32,
        count_reg: u8,
    },
    LoopStartImm {
        loop_id: u8,
        start_offset: i32,
        count: u32,
    },
    Trap0,
    /// HVX vector load: `Vd = vmem(base + offset)`; `post_inc` updates `base` by
    /// that many bytes; `aligned` masks the effective address to a 128-byte
    /// boundary (false for the `vmemu` unaligned form).
    VLoad {
        dst: u8,
        base: u8,
        offset: i32,
        post_inc: Option<i32>,
        aligned: bool,
    },
    /// HVX vector store: `vmem(base + offset) = Vs`, optionally scalar-predicated
    /// (`if (Pv[!]) vmem(...) = Vs`).
    VStore {
        src: u8,
        base: u8,
        offset: i32,
        post_inc: Option<i32>,
        aligned: bool,
        pred: Option<PredCond>,
    },
    /// New-value store: stores the register produced earlier in this packet,
    /// selected by the `Nt8` field. The packet driver resolves `nt` to the
    /// producer register (using `Nt8 >> 1` as the back-distance among the
    /// packet's GPR producers) before execution.
    StoreNew {
        nt: u8,
        addr: AddrMode,
        width: MemWidth,
        pred: Option<PredCond>,
    },
    MemOp {
        base: u8,
        offset: i32,
        width: MemWidth,
        op: MemOpKind,
        src: MemOpSrc,
    },
    Unknown(u32),
}

pub struct DecodedWord {
    pub insn: DecodedInsn,
    pub used_ext: bool,
    pub opcode: Option<Opcode>,
}

pub struct DecodedSub {
    pub insn: DecodedInsn,
    pub opcode: Option<Opcode>,
}

fn sign_extend(value: u32, bits: u8) -> i32 {
    let shift = 32u8.saturating_sub(bits);
    ((value << shift) as i32) >> shift
}

fn isa_version(isa: HexagonIsa) -> u16 {
    match isa {
        HexagonIsa::V4 => 4,
        HexagonIsa::V5 => 5,
        HexagonIsa::V55 => 55,
        HexagonIsa::V60 => 60,
        HexagonIsa::V62 => 62,
        HexagonIsa::V65 => 65,
        HexagonIsa::V66 => 66,
        HexagonIsa::V67 => 67,
        HexagonIsa::V68 => 68,
        HexagonIsa::V69 => 69,
    }
}

fn isa_at_least(isa: HexagonIsa, min: HexagonIsa) -> bool {
    isa_version(isa) >= isa_version(min)
}

fn isa_supports_duplex(isa: HexagonIsa) -> bool {
    isa_at_least(isa, HexagonIsa::V4)
}

fn isa_supports_dotnew(isa: HexagonIsa) -> bool {
    isa_at_least(isa, HexagonIsa::V4)
}

fn pred_uses_dotnew(pred: Option<PredCond>) -> bool {
    pred.map_or(false, |cond| cond.pred_new)
}

fn insn_uses_dotnew(insn: &DecodedInsn) -> bool {
    match insn {
        DecodedInsn::Load { pred, .. } => pred_uses_dotnew(*pred),
        DecodedInsn::Store { pred, src_new, .. } => pred_uses_dotnew(*pred) || *src_new,
        DecodedInsn::StoreImm { pred, .. } => pred_uses_dotnew(*pred),
        DecodedInsn::JumpCond { pred_new, .. } => *pred_new,
        DecodedInsn::JumpRegCond { pred_new, .. } => *pred_new,
        DecodedInsn::DeallocReturn { pred, .. } => pred_uses_dotnew(*pred),
        DecodedInsn::ClearCond { pred, .. } => pred.pred_new,
        _ => false,
    }
}

pub(crate) fn isa_supports_insn(
    isa: HexagonIsa,
    insn: &DecodedInsn,
    opcode: Option<Opcode>,
) -> bool {
    if insn_uses_dotnew(insn) && !isa_supports_dotnew(isa) {
        return false;
    }
    if let Some(opcode) = opcode {
        return isa_version(isa) >= opcode::opcode_min_version(opcode);
    }
    true
}

fn apply_immext(imm: u32, immext: u32) -> u32 {
    let ext = immext & 0x03ff_ffff;
    (ext << 6) | (imm & 0x3f)
}

fn decode_simm_val(imm: u32, bits: u8, immext: Option<u32>) -> (i32, bool) {
    if let Some(ext) = immext {
        return (apply_immext(imm, ext) as i32, true);
    }
    (sign_extend(imm, bits), false)
}

fn decode_uimm_val(imm: u32, immext: Option<u32>) -> (u32, bool) {
    if let Some(ext) = immext {
        return (apply_immext(imm, ext), true);
    }
    (imm, false)
}

fn field_val(decoded: &DecodedOp, letter: u8) -> Option<FieldVal> {
    decoded.field(letter)
}

fn field_u8(decoded: &DecodedOp, letter: u8) -> Option<u8> {
    decoded.field(letter).map(|val| val.value as u8)
}

fn decode_field_simm(decoded: &DecodedOp, letter: u8, immext: Option<u32>) -> Option<(i32, bool)> {
    let field = field_val(decoded, letter)?;
    Some(decode_simm_val(field.value, field.bits, immext))
}

fn decode_field_uimm(decoded: &DecodedOp, letter: u8, immext: Option<u32>) -> Option<(u32, bool)> {
    let field = field_val(decoded, letter)?;
    Some(decode_uimm_val(field.value, immext))
}

fn width_shift(width: MemWidth) -> u8 {
    match width {
        MemWidth::Byte => 0,
        MemWidth::Half => 1,
        MemWidth::Word => 2,
        MemWidth::Double => 3,
    }
}

fn subreg(code: u8) -> u8 {
    if code < 8 {
        code
    } else {
        code + 8
    }
}

fn subreg_pair(code: u8) -> u8 {
    let code = code & 0x7;
    if code < 4 {
        code * 2
    } else {
        16 + (code - 4) * 2
    }
}

fn pred_cond(pred: u8, sense: bool, pred_new: bool) -> PredCond {
    PredCond {
        pred,
        sense,
        pred_new,
    }
}

fn load_io(
    decoded: &DecodedOp,
    width: MemWidth,
    sign: MemSign,
    immext: Option<u32>,
) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b's')?;
    let dst = field_u8(decoded, b'd')?;
    let (imm, used) = decode_field_simm(decoded, b'i', immext)?;
    let offset = imm.wrapping_shl(width_shift(width) as u32);
    Some((
        DecodedInsn::Load {
            dst,
            addr: AddrMode::Offset { base, offset },
            width,
            sign,
            pred: None,
        },
        used,
    ))
}

fn load_gp(
    decoded: &DecodedOp,
    width: MemWidth,
    sign: MemSign,
    immext: Option<u32>,
) -> Option<(DecodedInsn, bool)> {
    let dst = field_u8(decoded, b'd')?;
    let (imm, used) = decode_field_uimm(decoded, b'i', immext)?;
    // A constant extender turns the GP-relative form into an *absolute* access
    // (the extended immediate is the full byte address; GP is not added).
    let addr = if used {
        AddrMode::Abs { addr: imm }
    } else {
        AddrMode::GpOffset {
            offset: (imm << width_shift(width)) as i32,
        }
    };
    Some((
        DecodedInsn::Load {
            dst,
            addr,
            width,
            sign,
            pred: None,
        },
        used,
    ))
}

fn load_pi(decoded: &DecodedOp, width: MemWidth, sign: MemSign) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let dst = field_u8(decoded, b'd')?;
    let (imm, _) = decode_field_simm(decoded, b'i', None)?;
    let offset = imm.wrapping_shl(width_shift(width) as u32);
    Some((
        DecodedInsn::Load {
            dst,
            addr: AddrMode::PostIncImm { base, offset },
            width,
            sign,
            pred: None,
        },
        false,
    ))
}

fn store_io(
    decoded: &DecodedOp,
    width: MemWidth,
    immext: Option<u32>,
    src_new: bool,
) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b's')?;
    let src = field_u8(decoded, b't')?;
    let (imm, used) = decode_field_simm(decoded, b'i', immext)?;
    let offset = imm.wrapping_shl(width_shift(width) as u32);
    Some((
        DecodedInsn::Store {
            src,
            addr: AddrMode::Offset { base, offset },
            width,
            pred: None,
            src_new,
        },
        used,
    ))
}

/// New-value store with register+immediate offset (`memX(Rs+#s11:N)=Nt8.new`).
fn store_new_io(
    decoded: &DecodedOp,
    width: MemWidth,
    immext: Option<u32>,
) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b's')?;
    let nt = field_u8(decoded, b't')?;
    let (imm, used) = decode_field_simm(decoded, b'i', immext)?;
    let offset = imm.wrapping_shl(width_shift(width) as u32);
    Some((
        DecodedInsn::StoreNew {
            nt,
            addr: AddrMode::Offset { base, offset },
            width,
            pred: None,
        },
        used,
    ))
}

/// Predicated new-value store (`if ([!]Pv) memX(Rs+#u6:N)=Nt8.new`). The store
/// data is the `Nt8` producer (field `t`), resolved against the packet's
/// producers, not a direct register read — hence `StoreNew` with a predicate.
fn pred_store_new_io(
    decoded: &DecodedOp,
    width: MemWidth,
    sense: bool,
) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b's')?;
    let nt = field_u8(decoded, b't')?;
    let pred = field_u8(decoded, b'v')?;
    let (imm, _) = decode_field_uimm(decoded, b'i', None)?;
    let offset = (imm << width_shift(width)) as i32;
    Some((
        DecodedInsn::StoreNew {
            nt,
            addr: AddrMode::Offset { base, offset },
            width,
            pred: Some(pred_cond(pred, sense, false)),
        },
        false,
    ))
}

fn store_gp(
    decoded: &DecodedOp,
    width: MemWidth,
    src_new: bool,
    immext: Option<u32>,
) -> Option<(DecodedInsn, bool)> {
    let src = field_u8(decoded, b't')?;
    let (imm, used) = decode_field_uimm(decoded, b'i', immext)?;
    let addr = if used {
        AddrMode::Abs { addr: imm }
    } else {
        AddrMode::GpOffset {
            offset: (imm << width_shift(width)) as i32,
        }
    };
    Some((
        DecodedInsn::Store {
            src,
            addr,
            width,
            pred: None,
            src_new,
        },
        used,
    ))
}

fn store_pi(decoded: &DecodedOp, width: MemWidth, src_new: bool) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let src = field_u8(decoded, b't')?;
    let (imm, _) = decode_field_simm(decoded, b'i', None)?;
    let offset = imm.wrapping_shl(width_shift(width) as u32);
    Some((
        DecodedInsn::Store {
            src,
            addr: AddrMode::PostIncImm { base, offset },
            width,
            pred: None,
            src_new,
        },
        false,
    ))
}

/// `memX(Rx++Mu)` post-increment by the M register (`L2_load*_pr`).
fn load_pr(decoded: &DecodedOp, width: MemWidth, sign: MemSign) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let dst = field_u8(decoded, b'd')?;
    let modsel = field_u8(decoded, b'u')?;
    Some((
        DecodedInsn::Load {
            dst,
            addr: AddrMode::PostIncReg { base, modsel },
            width,
            sign,
            pred: None,
        },
        false,
    ))
}

/// `memX(Rx++Mu:brev)` bit-reverse post-increment (`L2_load*_pbr`).
fn load_pbr(decoded: &DecodedOp, width: MemWidth, sign: MemSign) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let dst = field_u8(decoded, b'd')?;
    let modsel = field_u8(decoded, b'u')?;
    Some((
        DecodedInsn::Load {
            dst,
            addr: AddrMode::PostIncBrev { base, modsel },
            width,
            sign,
            pred: None,
        },
        false,
    ))
}

/// `memX(Rx++#s4:N:circ(Mu))` circular post-increment by immediate
/// (`L2_load*_pci`). The s4 field is scaled by the access size.
fn load_pci(decoded: &DecodedOp, width: MemWidth, sign: MemSign) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let dst = field_u8(decoded, b'd')?;
    let modsel = field_u8(decoded, b'u')?;
    let (imm, _) = decode_field_simm(decoded, b'i', None)?;
    let incr = imm.wrapping_shl(width_shift(width) as u32);
    Some((
        DecodedInsn::Load {
            dst,
            addr: AddrMode::PostIncCircImm {
                base,
                modsel,
                incr,
            },
            width,
            sign,
            pred: None,
        },
        false,
    ))
}

/// `memX(Rx++I:circ(Mu))` circular post-increment by the M register's I field
/// (`L2_load*_pcr`).
fn load_pcr(decoded: &DecodedOp, width: MemWidth, sign: MemSign) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let dst = field_u8(decoded, b'd')?;
    let modsel = field_u8(decoded, b'u')?;
    Some((
        DecodedInsn::Load {
            dst,
            addr: AddrMode::PostIncCircReg {
                base,
                modsel,
                shift: width_shift(width),
            },
            width,
            sign,
            pred: None,
        },
        false,
    ))
}

/// `memX(Rx++Mu)=Rt` post-increment store by the M register (`S2_store*_pr`).
fn store_pr(decoded: &DecodedOp, width: MemWidth, src_new: bool) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let src = field_u8(decoded, b't')?;
    let modsel = field_u8(decoded, b'u')?;
    Some((
        DecodedInsn::Store {
            src,
            addr: AddrMode::PostIncReg { base, modsel },
            width,
            pred: None,
            src_new,
        },
        false,
    ))
}

/// `memX(Rx++Mu:brev)=Rt` bit-reverse post-increment store (`S2_store*_pbr`).
fn store_pbr(decoded: &DecodedOp, width: MemWidth, src_new: bool) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let src = field_u8(decoded, b't')?;
    let modsel = field_u8(decoded, b'u')?;
    Some((
        DecodedInsn::Store {
            src,
            addr: AddrMode::PostIncBrev { base, modsel },
            width,
            pred: None,
            src_new,
        },
        false,
    ))
}

/// `memX(Rx++#s4:N:circ(Mu))=Rt` circular post-increment store by immediate
/// (`S2_store*_pci`). The store source for *_pci uses the `t`/`SRC` field.
fn store_pci(decoded: &DecodedOp, width: MemWidth, src_new: bool) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let src = field_u8(decoded, b't')?;
    let modsel = field_u8(decoded, b'u')?;
    let (imm, _) = decode_field_simm(decoded, b'i', None)?;
    let incr = imm.wrapping_shl(width_shift(width) as u32);
    Some((
        DecodedInsn::Store {
            src,
            addr: AddrMode::PostIncCircImm {
                base,
                modsel,
                incr,
            },
            width,
            pred: None,
            src_new,
        },
        false,
    ))
}

/// `memX(Rx++I:circ(Mu))=Rt` circular post-increment store by register
/// (`S2_store*_pcr`).
fn store_pcr(decoded: &DecodedOp, width: MemWidth, src_new: bool) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let src = field_u8(decoded, b't')?;
    let modsel = field_u8(decoded, b'u')?;
    Some((
        DecodedInsn::Store {
            src,
            addr: AddrMode::PostIncCircReg {
                base,
                modsel,
                shift: width_shift(width),
            },
            width,
            pred: None,
            src_new,
        },
        false,
    ))
}

/// New-value store with circular/post-increment register addressing. The
/// new-value source register comes from `t` (the `Nt8` field).
fn store_new_addr(
    decoded: &DecodedOp,
    width: MemWidth,
    addr: AddrMode,
) -> Option<(DecodedInsn, bool)> {
    let nt = field_u8(decoded, b't')?;
    Some((
        DecodedInsn::StoreNew {
            nt,
            addr,
            width,
            pred: None,
        },
        false,
    ))
}

fn store_new_pi(decoded: &DecodedOp, width: MemWidth) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let (imm, _) = decode_field_simm(decoded, b'i', None)?;
    let offset = imm.wrapping_shl(width_shift(width) as u32);
    store_new_addr(decoded, width, AddrMode::PostIncImm { base, offset })
}

fn store_new_pr(decoded: &DecodedOp, width: MemWidth) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let modsel = field_u8(decoded, b'u')?;
    store_new_addr(decoded, width, AddrMode::PostIncReg { base, modsel })
}

fn store_new_pbr(decoded: &DecodedOp, width: MemWidth) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let modsel = field_u8(decoded, b'u')?;
    store_new_addr(decoded, width, AddrMode::PostIncBrev { base, modsel })
}

fn store_new_pci(decoded: &DecodedOp, width: MemWidth) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let modsel = field_u8(decoded, b'u')?;
    let (imm, _) = decode_field_simm(decoded, b'i', None)?;
    let incr = imm.wrapping_shl(width_shift(width) as u32);
    store_new_addr(
        decoded,
        width,
        AddrMode::PostIncCircImm {
            base,
            modsel,
            incr,
        },
    )
}

fn store_new_pcr(decoded: &DecodedOp, width: MemWidth) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b'x')?;
    let modsel = field_u8(decoded, b'u')?;
    store_new_addr(
        decoded,
        width,
        AddrMode::PostIncCircReg {
            base,
            modsel,
            shift: width_shift(width),
        },
    )
}

fn pred_load_io(
    decoded: &DecodedOp,
    width: MemWidth,
    sign: MemSign,
    sense: bool,
    pred_new: bool,
) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b's')?;
    let dst = field_u8(decoded, b'd')?;
    let pred = field_u8(decoded, b't')?;
    let (imm, _) = decode_field_uimm(decoded, b'i', None)?;
    let offset = (imm << width_shift(width)) as i32;
    Some((
        DecodedInsn::Load {
            dst,
            addr: AddrMode::Offset { base, offset },
            width,
            sign,
            pred: Some(pred_cond(pred, sense, pred_new)),
        },
        false,
    ))
}

fn pred_store_io(
    decoded: &DecodedOp,
    width: MemWidth,
    sense: bool,
    pred_new: bool,
    src_new: bool,
) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b's')?;
    let src = field_u8(decoded, b't')?;
    let pred = field_u8(decoded, b'v')?;
    let (imm, _) = decode_field_uimm(decoded, b'i', None)?;
    let offset = (imm << width_shift(width)) as i32;
    Some((
        DecodedInsn::Store {
            src,
            addr: AddrMode::Offset { base, offset },
            width,
            pred: Some(pred_cond(pred, sense, pred_new)),
            src_new,
        },
        false,
    ))
}

/// Decode a read-modify-write memop (`memX(Rs+#u6:N) OP= Rt|#U5`).
/// `op` selects the operation; `imm_src` chooses the `#U5` immediate operand
/// (field `I`) over the register operand (field `t`).
fn memop(
    decoded: &DecodedOp,
    width: MemWidth,
    op: MemOpKind,
    imm_src: bool,
) -> Option<(DecodedInsn, bool)> {
    let base = field_u8(decoded, b's')?;
    let imm = decode_field_uimm(decoded, b'i', None)?.0;
    let offset = (imm << width_shift(width)) as i32;
    let src = if imm_src {
        MemOpSrc::Imm(decode_field_uimm(decoded, b'I', None)?.0)
    } else {
        MemOpSrc::Reg(field_u8(decoded, b't')?)
    };
    Some((
        DecodedInsn::MemOp {
            base,
            offset,
            width,
            op,
            src,
        },
        false,
    ))
}

const HVX_VEC_BYTES: i32 = 128;

/// Decode an HVX vector load `Vd = vmem(...)`. `post_inc` selects the `Rx++#s3`
/// form (base field `x`, immediate is the post-increment) vs the `Rt+#s4` form
/// (base field `t`, immediate is the offset). The immediate is in vector units.
fn vmem_load(decoded: &DecodedOp, post_inc: bool, aligned: bool) -> Option<(DecodedInsn, bool)> {
    let dst = field_u8(decoded, b'd')?;
    let base = field_u8(decoded, if post_inc { b'x' } else { b't' })?;
    let imm = decode_field_simm(decoded, b'i', None)?.0 * HVX_VEC_BYTES;
    let (offset, pi) = if post_inc { (0, Some(imm)) } else { (imm, None) };
    Some((
        DecodedInsn::VLoad {
            dst,
            base,
            offset,
            post_inc: pi,
            aligned,
        },
        false,
    ))
}

fn vmem_store(decoded: &DecodedOp, post_inc: bool, aligned: bool) -> Option<(DecodedInsn, bool)> {
    vmem_store_pred(decoded, post_inc, aligned, None)
}

/// `pred_sense`: `Some(true)` for `if (Pv) ...`, `Some(false)` for `if (!Pv) ...`,
/// `None` for an unconditional store. The predicate operand is field `v`.
fn vmem_store_pred(
    decoded: &DecodedOp,
    post_inc: bool,
    aligned: bool,
    pred_sense: Option<bool>,
) -> Option<(DecodedInsn, bool)> {
    let src = field_u8(decoded, b's')?;
    let base = field_u8(decoded, if post_inc { b'x' } else { b't' })?;
    let imm = decode_field_simm(decoded, b'i', None)?.0 * HVX_VEC_BYTES;
    let (offset, pi) = if post_inc { (0, Some(imm)) } else { (imm, None) };
    let pred = match pred_sense {
        Some(sense) => Some(pred_cond(field_u8(decoded, b'v')?, sense, false)),
        None => None,
    };
    Some((
        DecodedInsn::VStore {
            src,
            base,
            offset,
            post_inc: pi,
            aligned,
            pred,
        },
        false,
    ))
}

fn decode_main(decoded: &DecodedOp, word: u32, immext: Option<u32>) -> (DecodedInsn, bool) {
    macro_rules! req {
        ($expr:expr) => {
            match $expr {
                Some(value) => value,
                None => return (DecodedInsn::Unknown(word), false),
            }
        };
    }

    match decoded.opcode {
        Opcode::A4_ext => {
            let imm = req!(field_val(decoded, b'i')).value;
            (DecodedInsn::ImmExt { value: imm }, false)
        }
        Opcode::A2_add => {
            let dst = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b's'));
            let src2 = req!(field_u8(decoded, b't'));
            (DecodedInsn::Add { dst, src1, src2 }, false)
        }
        Opcode::A2_sub => {
            let dst = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b't'));
            let src2 = req!(field_u8(decoded, b's'));
            (DecodedInsn::Sub { dst, src1, src2 }, false)
        }
        Opcode::A2_and => {
            let dst = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b's'));
            let src2 = req!(field_u8(decoded, b't'));
            (DecodedInsn::And { dst, src1, src2 }, false)
        }
        Opcode::A2_or => {
            let dst = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b's'));
            let src2 = req!(field_u8(decoded, b't'));
            (DecodedInsn::Or { dst, src1, src2 }, false)
        }
        Opcode::A2_xor => {
            let dst = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b's'));
            let src2 = req!(field_u8(decoded, b't'));
            (DecodedInsn::Xor { dst, src1, src2 }, false)
        }
        Opcode::A2_addi => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            (DecodedInsn::AddImm { dst, src, imm }, used)
        }
        Opcode::A2_tfr => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            (DecodedInsn::Mov { dst, src }, false)
        }
        Opcode::A2_tfrsi => {
            let dst = req!(field_u8(decoded, b'd'));
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            (DecodedInsn::MovImm { dst, imm }, used)
        }
        Opcode::A2_andir => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            (
                DecodedInsn::AndImm {
                    dst,
                    src,
                    imm: imm as u32,
                },
                used,
            )
        }
        Opcode::A2_sxtb => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            (
                DecodedInsn::Extend {
                    dst,
                    src,
                    kind: ExtendKind::Sxt8,
                },
                false,
            )
        }
        Opcode::A2_sxth => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            (
                DecodedInsn::Extend {
                    dst,
                    src,
                    kind: ExtendKind::Sxt16,
                },
                false,
            )
        }
        Opcode::A2_zxth => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            (
                DecodedInsn::Extend {
                    dst,
                    src,
                    kind: ExtendKind::Zxt16,
                },
                false,
            )
        }
        Opcode::A2_tfrcrr => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            (DecodedInsn::TfrCrR { dst, src }, false)
        }
        Opcode::A2_tfrrcr => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            (DecodedInsn::TfrRrCr { dst, src }, false)
        }
        Opcode::M2_mpyi => {
            let dst = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b's'));
            let src2 = req!(field_u8(decoded, b't'));
            (DecodedInsn::Mul { dst, src1, src2 }, false)
        }
        Opcode::S2_asr_i_r => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let amount = req!(decode_field_uimm(decoded, b'i', None)).0 as u8;
            (
                DecodedInsn::ShiftImm {
                    dst,
                    src,
                    kind: ShiftKind::Asr,
                    amount,
                },
                false,
            )
        }
        Opcode::S2_lsr_i_r => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let amount = req!(decode_field_uimm(decoded, b'i', None)).0 as u8;
            (
                DecodedInsn::ShiftImm {
                    dst,
                    src,
                    kind: ShiftKind::Lsr,
                    amount,
                },
                false,
            )
        }
        Opcode::S2_asl_i_r => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let amount = req!(decode_field_uimm(decoded, b'i', None)).0 as u8;
            (
                DecodedInsn::ShiftImm {
                    dst,
                    src,
                    kind: ShiftKind::Lsl,
                    amount,
                },
                false,
            )
        }
        Opcode::S2_asr_r_r => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let amt = req!(field_u8(decoded, b't'));
            (
                DecodedInsn::ShiftReg {
                    dst,
                    src,
                    amt,
                    kind: ShiftKind::Asr,
                },
                false,
            )
        }
        Opcode::S2_lsr_r_r => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let amt = req!(field_u8(decoded, b't'));
            (
                DecodedInsn::ShiftReg {
                    dst,
                    src,
                    amt,
                    kind: ShiftKind::Lsr,
                },
                false,
            )
        }
        Opcode::S2_asl_r_r => {
            let dst = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let amt = req!(field_u8(decoded, b't'));
            (
                DecodedInsn::ShiftReg {
                    dst,
                    src,
                    amt,
                    kind: ShiftKind::Lsl,
                },
                false,
            )
        }
        Opcode::C2_cmpeq => {
            let pred = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b's'));
            let src2 = req!(field_u8(decoded, b't'));
            (
                DecodedInsn::Cmp {
                    pred,
                    src1,
                    src2,
                    kind: CmpKind::Eq,
                },
                false,
            )
        }
        Opcode::C2_cmpgt => {
            let pred = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b's'));
            let src2 = req!(field_u8(decoded, b't'));
            (
                DecodedInsn::Cmp {
                    pred,
                    src1,
                    src2,
                    kind: CmpKind::Gt,
                },
                false,
            )
        }
        Opcode::C2_cmpgtu => {
            let pred = req!(field_u8(decoded, b'd'));
            let src1 = req!(field_u8(decoded, b's'));
            let src2 = req!(field_u8(decoded, b't'));
            (
                DecodedInsn::Cmp {
                    pred,
                    src1,
                    src2,
                    kind: CmpKind::Gtu,
                },
                false,
            )
        }
        Opcode::C2_cmpeqi => {
            let pred = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            (
                DecodedInsn::CmpImm {
                    pred,
                    src,
                    imm,
                    kind: CmpKind::Eq,
                    unsigned: false,
                },
                used,
            )
        }
        Opcode::C2_cmpgti => {
            let pred = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            (
                DecodedInsn::CmpImm {
                    pred,
                    src,
                    imm,
                    kind: CmpKind::Gt,
                    unsigned: false,
                },
                used,
            )
        }
        Opcode::C2_cmpgtui => {
            let pred = req!(field_u8(decoded, b'd'));
            let src = req!(field_u8(decoded, b's'));
            let (imm, used) = req!(decode_field_uimm(decoded, b'i', immext));
            (
                DecodedInsn::CmpImm {
                    pred,
                    src,
                    imm: imm as i32,
                    kind: CmpKind::Gtu,
                    unsigned: true,
                },
                used,
            )
        }
        Opcode::J2_jump => {
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            (DecodedInsn::Jump { offset: imm << 2 }, used)
        }
        Opcode::J2_call => {
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            (DecodedInsn::Call { offset: imm << 2 }, used)
        }
        Opcode::J2_jumpr => {
            let src = req!(field_u8(decoded, b's'));
            (DecodedInsn::JumpReg { src }, false)
        }
        Opcode::J2_callr => {
            let src = req!(field_u8(decoded, b's'));
            (DecodedInsn::CallReg { src }, false)
        }
        Opcode::J2_jumpt
        | Opcode::J2_jumptpt
        | Opcode::J2_jumptnew
        | Opcode::J2_jumptnewpt
        | Opcode::J2_jumpf
        | Opcode::J2_jumpfpt
        | Opcode::J2_jumpfnew
        | Opcode::J2_jumpfnewpt => {
            let pred = req!(field_u8(decoded, b'u'));
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            let (sense, pred_new) = match decoded.opcode {
                Opcode::J2_jumpt | Opcode::J2_jumptpt => (true, false),
                Opcode::J2_jumpf | Opcode::J2_jumpfpt => (false, false),
                Opcode::J2_jumptnew | Opcode::J2_jumptnewpt => (true, true),
                _ => (false, true),
            };
            (
                DecodedInsn::JumpCond {
                    offset: imm << 2,
                    pred,
                    sense,
                    pred_new,
                },
                used,
            )
        }
        Opcode::J2_jumprt
        | Opcode::J2_jumprtpt
        | Opcode::J2_jumprtnew
        | Opcode::J2_jumprtnewpt
        | Opcode::J2_jumprf
        | Opcode::J2_jumprfpt
        | Opcode::J2_jumprfnew
        | Opcode::J2_jumprfnewpt => {
            let src = req!(field_u8(decoded, b's'));
            let pred = req!(field_u8(decoded, b'u'));
            let (sense, pred_new) = match decoded.opcode {
                Opcode::J2_jumprt | Opcode::J2_jumprtpt => (true, false),
                Opcode::J2_jumprf | Opcode::J2_jumprfpt => (false, false),
                Opcode::J2_jumprtnew | Opcode::J2_jumprtnewpt => (true, true),
                _ => (false, true),
            };
            (
                DecodedInsn::JumpRegCond {
                    src,
                    pred,
                    sense,
                    pred_new,
                },
                false,
            )
        }
        Opcode::J2_loop0r | Opcode::J2_loop1r => {
            let loop_id = if matches!(decoded.opcode, Opcode::J2_loop0r) {
                0
            } else {
                1
            };
            let count_reg = req!(field_u8(decoded, b's'));
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            (
                DecodedInsn::LoopStartReg {
                    loop_id,
                    start_offset: imm << 2,
                    count_reg,
                },
                used,
            )
        }
        Opcode::J2_loop0i | Opcode::J2_loop1i => {
            let loop_id = if matches!(decoded.opcode, Opcode::J2_loop0i) {
                0
            } else {
                1
            };
            let (imm, used) = req!(decode_field_simm(decoded, b'i', immext));
            let count = req!(decode_field_uimm(decoded, b'I', None)).0;
            (
                DecodedInsn::LoopStartImm {
                    loop_id,
                    start_offset: imm << 2,
                    count,
                },
                used,
            )
        }
        Opcode::J2_trap0 => (DecodedInsn::Trap0, false),
        Opcode::S2_allocframe => {
            let base = req!(field_u8(decoded, b'x'));
            let imm = req!(decode_field_uimm(decoded, b'i', None)).0;
            (
                DecodedInsn::AllocFrame {
                    base,
                    size: imm << 3,
                },
                false,
            )
        }
        Opcode::L2_deallocframe => {
            let base = req!(field_u8(decoded, b's'));
            let dst = req!(field_u8(decoded, b'd'));
            (
                DecodedInsn::DeallocFrame {
                    base,
                    dst: Some(dst),
                    update_lr_fp: false,
                },
                false,
            )
        }
        Opcode::L4_return
        | Opcode::L4_return_t
        | Opcode::L4_return_f
        | Opcode::L4_return_tnew_pt
        | Opcode::L4_return_tnew_pnt
        | Opcode::L4_return_fnew_pt
        | Opcode::L4_return_fnew_pnt => {
            let base = req!(field_u8(decoded, b's'));
            let dst = req!(field_u8(decoded, b'd'));
            let pred = match decoded.opcode {
                Opcode::L4_return => None,
                Opcode::L4_return_t => Some(pred_cond(req!(field_u8(decoded, b'v')), true, false)),
                Opcode::L4_return_f => Some(pred_cond(req!(field_u8(decoded, b'v')), false, false)),
                Opcode::L4_return_tnew_pt | Opcode::L4_return_tnew_pnt => {
                    Some(pred_cond(req!(field_u8(decoded, b'v')), true, true))
                }
                _ => Some(pred_cond(req!(field_u8(decoded, b'v')), false, true)),
            };
            (
                DecodedInsn::DeallocReturn {
                    base,
                    dst: Some(dst),
                    pred,
                    update_lr_fp: false,
                },
                false,
            )
        }
        Opcode::L2_loadrb_io => req!(load_io(decoded, MemWidth::Byte, MemSign::Signed, immext)),
        Opcode::L2_loadrub_io => req!(load_io(decoded, MemWidth::Byte, MemSign::Unsigned, immext)),
        Opcode::L2_loadrh_io => req!(load_io(decoded, MemWidth::Half, MemSign::Signed, immext)),
        Opcode::L2_loadruh_io => req!(load_io(decoded, MemWidth::Half, MemSign::Unsigned, immext)),
        Opcode::L2_loadri_io => req!(load_io(decoded, MemWidth::Word, MemSign::Unsigned, immext)),
        Opcode::L2_loadrd_io => req!(load_io(
            decoded,
            MemWidth::Double,
            MemSign::Unsigned,
            immext
        )),
        Opcode::L2_loadrbgp => req!(load_gp(decoded, MemWidth::Byte, MemSign::Signed, immext)),
        Opcode::L2_loadrubgp => req!(load_gp(decoded, MemWidth::Byte, MemSign::Unsigned, immext)),
        Opcode::L2_loadrhgp => req!(load_gp(decoded, MemWidth::Half, MemSign::Signed, immext)),
        Opcode::L2_loadruhgp => req!(load_gp(decoded, MemWidth::Half, MemSign::Unsigned, immext)),
        Opcode::L2_loadrigp => req!(load_gp(decoded, MemWidth::Word, MemSign::Unsigned, immext)),
        Opcode::L2_loadrdgp => req!(load_gp(decoded, MemWidth::Double, MemSign::Unsigned, immext)),
        Opcode::L2_loadrb_pi => req!(load_pi(decoded, MemWidth::Byte, MemSign::Signed)),
        Opcode::L2_loadrub_pi => req!(load_pi(decoded, MemWidth::Byte, MemSign::Unsigned)),
        Opcode::L2_loadrh_pi => req!(load_pi(decoded, MemWidth::Half, MemSign::Signed)),
        Opcode::L2_loadruh_pi => req!(load_pi(decoded, MemWidth::Half, MemSign::Unsigned)),
        Opcode::L2_loadri_pi => req!(load_pi(decoded, MemWidth::Word, MemSign::Unsigned)),
        Opcode::L2_loadrd_pi => req!(load_pi(decoded, MemWidth::Double, MemSign::Unsigned)),
        Opcode::S2_storerb_io => req!(store_io(decoded, MemWidth::Byte, immext, false)),
        Opcode::S2_storerh_io => req!(store_io(decoded, MemWidth::Half, immext, false)),
        Opcode::S2_storeri_io => req!(store_io(decoded, MemWidth::Word, immext, false)),
        Opcode::S2_storerd_io => req!(store_io(decoded, MemWidth::Double, immext, false)),
        Opcode::S2_storerbgp => req!(store_gp(decoded, MemWidth::Byte, false, immext)),
        Opcode::S2_storerhgp => req!(store_gp(decoded, MemWidth::Half, false, immext)),
        Opcode::S2_storerigp => req!(store_gp(decoded, MemWidth::Word, false, immext)),
        Opcode::S2_storerdgp => req!(store_gp(decoded, MemWidth::Double, false, immext)),
        Opcode::S2_storerbnew_io => req!(store_new_io(decoded, MemWidth::Byte, immext)),
        Opcode::S2_storerhnew_io => req!(store_new_io(decoded, MemWidth::Half, immext)),
        Opcode::S2_storerinew_io => req!(store_new_io(decoded, MemWidth::Word, immext)),
        Opcode::S2_storerb_pi => req!(store_pi(decoded, MemWidth::Byte, false)),
        Opcode::S2_storerh_pi => req!(store_pi(decoded, MemWidth::Half, false)),
        Opcode::S2_storeri_pi => req!(store_pi(decoded, MemWidth::Word, false)),
        Opcode::S2_storerd_pi => req!(store_pi(decoded, MemWidth::Double, false)),
        // ---- register / bit-reverse / circular post-increment loads ----
        Opcode::L2_loadrb_pr => req!(load_pr(decoded, MemWidth::Byte, MemSign::Signed)),
        Opcode::L2_loadrub_pr => req!(load_pr(decoded, MemWidth::Byte, MemSign::Unsigned)),
        Opcode::L2_loadrh_pr => req!(load_pr(decoded, MemWidth::Half, MemSign::Signed)),
        Opcode::L2_loadruh_pr => req!(load_pr(decoded, MemWidth::Half, MemSign::Unsigned)),
        Opcode::L2_loadri_pr => req!(load_pr(decoded, MemWidth::Word, MemSign::Unsigned)),
        Opcode::L2_loadrd_pr => req!(load_pr(decoded, MemWidth::Double, MemSign::Unsigned)),
        Opcode::L2_loadrb_pbr => req!(load_pbr(decoded, MemWidth::Byte, MemSign::Signed)),
        Opcode::L2_loadrub_pbr => req!(load_pbr(decoded, MemWidth::Byte, MemSign::Unsigned)),
        Opcode::L2_loadrh_pbr => req!(load_pbr(decoded, MemWidth::Half, MemSign::Signed)),
        Opcode::L2_loadruh_pbr => req!(load_pbr(decoded, MemWidth::Half, MemSign::Unsigned)),
        Opcode::L2_loadri_pbr => req!(load_pbr(decoded, MemWidth::Word, MemSign::Unsigned)),
        Opcode::L2_loadrd_pbr => req!(load_pbr(decoded, MemWidth::Double, MemSign::Unsigned)),
        Opcode::L2_loadrb_pci => req!(load_pci(decoded, MemWidth::Byte, MemSign::Signed)),
        Opcode::L2_loadrub_pci => req!(load_pci(decoded, MemWidth::Byte, MemSign::Unsigned)),
        Opcode::L2_loadrh_pci => req!(load_pci(decoded, MemWidth::Half, MemSign::Signed)),
        Opcode::L2_loadruh_pci => req!(load_pci(decoded, MemWidth::Half, MemSign::Unsigned)),
        Opcode::L2_loadri_pci => req!(load_pci(decoded, MemWidth::Word, MemSign::Unsigned)),
        Opcode::L2_loadrd_pci => req!(load_pci(decoded, MemWidth::Double, MemSign::Unsigned)),
        Opcode::L2_loadrb_pcr => req!(load_pcr(decoded, MemWidth::Byte, MemSign::Signed)),
        Opcode::L2_loadrub_pcr => req!(load_pcr(decoded, MemWidth::Byte, MemSign::Unsigned)),
        Opcode::L2_loadrh_pcr => req!(load_pcr(decoded, MemWidth::Half, MemSign::Signed)),
        Opcode::L2_loadruh_pcr => req!(load_pcr(decoded, MemWidth::Half, MemSign::Unsigned)),
        Opcode::L2_loadri_pcr => req!(load_pcr(decoded, MemWidth::Word, MemSign::Unsigned)),
        Opcode::L2_loadrd_pcr => req!(load_pcr(decoded, MemWidth::Double, MemSign::Unsigned)),
        // ---- register / bit-reverse / circular post-increment stores ----
        Opcode::S2_storerb_pr => req!(store_pr(decoded, MemWidth::Byte, false)),
        Opcode::S2_storerh_pr => req!(store_pr(decoded, MemWidth::Half, false)),
        Opcode::S2_storeri_pr => req!(store_pr(decoded, MemWidth::Word, false)),
        Opcode::S2_storerd_pr => req!(store_pr(decoded, MemWidth::Double, false)),
        Opcode::S2_storerb_pbr => req!(store_pbr(decoded, MemWidth::Byte, false)),
        Opcode::S2_storerh_pbr => req!(store_pbr(decoded, MemWidth::Half, false)),
        Opcode::S2_storeri_pbr => req!(store_pbr(decoded, MemWidth::Word, false)),
        Opcode::S2_storerd_pbr => req!(store_pbr(decoded, MemWidth::Double, false)),
        Opcode::S2_storerb_pci => req!(store_pci(decoded, MemWidth::Byte, false)),
        Opcode::S2_storerh_pci => req!(store_pci(decoded, MemWidth::Half, false)),
        Opcode::S2_storeri_pci => req!(store_pci(decoded, MemWidth::Word, false)),
        Opcode::S2_storerd_pci => req!(store_pci(decoded, MemWidth::Double, false)),
        Opcode::S2_storerb_pcr => req!(store_pcr(decoded, MemWidth::Byte, false)),
        Opcode::S2_storerh_pcr => req!(store_pcr(decoded, MemWidth::Half, false)),
        Opcode::S2_storeri_pcr => req!(store_pcr(decoded, MemWidth::Word, false)),
        Opcode::S2_storerd_pcr => req!(store_pcr(decoded, MemWidth::Double, false)),
        // ---- new-value post-increment stores (register/brev/circular) ----
        Opcode::S2_storerbnew_pi => req!(store_new_pi(decoded, MemWidth::Byte)),
        Opcode::S2_storerhnew_pi => req!(store_new_pi(decoded, MemWidth::Half)),
        Opcode::S2_storerinew_pi => req!(store_new_pi(decoded, MemWidth::Word)),
        Opcode::S2_storerbnew_pr => req!(store_new_pr(decoded, MemWidth::Byte)),
        Opcode::S2_storerhnew_pr => req!(store_new_pr(decoded, MemWidth::Half)),
        Opcode::S2_storerinew_pr => req!(store_new_pr(decoded, MemWidth::Word)),
        Opcode::S2_storerbnew_pbr => req!(store_new_pbr(decoded, MemWidth::Byte)),
        Opcode::S2_storerhnew_pbr => req!(store_new_pbr(decoded, MemWidth::Half)),
        Opcode::S2_storerinew_pbr => req!(store_new_pbr(decoded, MemWidth::Word)),
        Opcode::S2_storerbnew_pci => req!(store_new_pci(decoded, MemWidth::Byte)),
        Opcode::S2_storerhnew_pci => req!(store_new_pci(decoded, MemWidth::Half)),
        Opcode::S2_storerinew_pci => req!(store_new_pci(decoded, MemWidth::Word)),
        Opcode::S2_storerbnew_pcr => req!(store_new_pcr(decoded, MemWidth::Byte)),
        Opcode::S2_storerhnew_pcr => req!(store_new_pcr(decoded, MemWidth::Half)),
        Opcode::S2_storerinew_pcr => req!(store_new_pcr(decoded, MemWidth::Word)),
        Opcode::L2_ploadrbt_io
        | Opcode::L2_ploadrbf_io
        | Opcode::L2_ploadrbtnew_io
        | Opcode::L2_ploadrbfnew_io => {
            let (sense, pred_new) = match decoded.opcode {
                Opcode::L2_ploadrbt_io => (true, false),
                Opcode::L2_ploadrbf_io => (false, false),
                Opcode::L2_ploadrbtnew_io => (true, true),
                _ => (false, true),
            };
            req!(pred_load_io(
                decoded,
                MemWidth::Byte,
                MemSign::Signed,
                sense,
                pred_new
            ))
        }
        Opcode::L2_ploadrubt_io
        | Opcode::L2_ploadrubf_io
        | Opcode::L2_ploadrubtnew_io
        | Opcode::L2_ploadrubfnew_io => {
            let (sense, pred_new) = match decoded.opcode {
                Opcode::L2_ploadrubt_io => (true, false),
                Opcode::L2_ploadrubf_io => (false, false),
                Opcode::L2_ploadrubtnew_io => (true, true),
                _ => (false, true),
            };
            req!(pred_load_io(
                decoded,
                MemWidth::Byte,
                MemSign::Unsigned,
                sense,
                pred_new
            ))
        }
        Opcode::L2_ploadrht_io
        | Opcode::L2_ploadrhf_io
        | Opcode::L2_ploadrhtnew_io
        | Opcode::L2_ploadrhfnew_io => {
            let (sense, pred_new) = match decoded.opcode {
                Opcode::L2_ploadrht_io => (true, false),
                Opcode::L2_ploadrhf_io => (false, false),
                Opcode::L2_ploadrhtnew_io => (true, true),
                _ => (false, true),
            };
            req!(pred_load_io(
                decoded,
                MemWidth::Half,
                MemSign::Signed,
                sense,
                pred_new
            ))
        }
        Opcode::L2_ploadruht_io
        | Opcode::L2_ploadruhf_io
        | Opcode::L2_ploadruhtnew_io
        | Opcode::L2_ploadruhfnew_io => {
            let (sense, pred_new) = match decoded.opcode {
                Opcode::L2_ploadruht_io => (true, false),
                Opcode::L2_ploadruhf_io => (false, false),
                Opcode::L2_ploadruhtnew_io => (true, true),
                _ => (false, true),
            };
            req!(pred_load_io(
                decoded,
                MemWidth::Half,
                MemSign::Unsigned,
                sense,
                pred_new
            ))
        }
        Opcode::L2_ploadrit_io
        | Opcode::L2_ploadrif_io
        | Opcode::L2_ploadritnew_io
        | Opcode::L2_ploadrifnew_io => {
            let (sense, pred_new) = match decoded.opcode {
                Opcode::L2_ploadrit_io => (true, false),
                Opcode::L2_ploadrif_io => (false, false),
                Opcode::L2_ploadritnew_io => (true, true),
                _ => (false, true),
            };
            req!(pred_load_io(
                decoded,
                MemWidth::Word,
                MemSign::Unsigned,
                sense,
                pred_new
            ))
        }
        Opcode::L2_ploadrdt_io
        | Opcode::L2_ploadrdf_io
        | Opcode::L2_ploadrdtnew_io
        | Opcode::L2_ploadrdfnew_io => {
            let (sense, pred_new) = match decoded.opcode {
                Opcode::L2_ploadrdt_io => (true, false),
                Opcode::L2_ploadrdf_io => (false, false),
                Opcode::L2_ploadrdtnew_io => (true, true),
                _ => (false, true),
            };
            req!(pred_load_io(
                decoded,
                MemWidth::Double,
                MemSign::Unsigned,
                sense,
                pred_new
            ))
        }
        Opcode::S2_pstorerbt_io | Opcode::S2_pstorerbf_io => {
            let sense = matches!(decoded.opcode, Opcode::S2_pstorerbt_io);
            req!(pred_store_io(decoded, MemWidth::Byte, sense, false, false))
        }
        Opcode::S2_pstorerbnewt_io | Opcode::S2_pstorerbnewf_io => {
            let sense = matches!(decoded.opcode, Opcode::S2_pstorerbnewt_io);
            req!(pred_store_new_io(decoded, MemWidth::Byte, sense))
        }
        Opcode::S2_pstorerht_io | Opcode::S2_pstorerhf_io => {
            let sense = matches!(decoded.opcode, Opcode::S2_pstorerht_io);
            req!(pred_store_io(decoded, MemWidth::Half, sense, false, false))
        }
        Opcode::S2_pstorerhnewt_io | Opcode::S2_pstorerhnewf_io => {
            let sense = matches!(decoded.opcode, Opcode::S2_pstorerhnewt_io);
            req!(pred_store_new_io(decoded, MemWidth::Half, sense))
        }
        Opcode::S2_pstorerit_io | Opcode::S2_pstorerif_io => {
            let sense = matches!(decoded.opcode, Opcode::S2_pstorerit_io);
            req!(pred_store_io(decoded, MemWidth::Word, sense, false, false))
        }
        Opcode::S2_pstorerinewt_io | Opcode::S2_pstorerinewf_io => {
            let sense = matches!(decoded.opcode, Opcode::S2_pstorerinewt_io);
            req!(pred_store_new_io(decoded, MemWidth::Word, sense))
        }
        Opcode::S2_pstorerdt_io | Opcode::S2_pstorerdf_io => {
            let sense = matches!(decoded.opcode, Opcode::S2_pstorerdt_io);
            req!(pred_store_io(
                decoded,
                MemWidth::Double,
                sense,
                false,
                false
            ))
        }
        // ---- read-modify-write memops (memX(Rs+#u6:N) OP= Rt | #U5) ----
        Opcode::L4_add_memopb_io => req!(memop(decoded, MemWidth::Byte, MemOpKind::Add, false)),
        Opcode::L4_sub_memopb_io => req!(memop(decoded, MemWidth::Byte, MemOpKind::Sub, false)),
        Opcode::L4_and_memopb_io => req!(memop(decoded, MemWidth::Byte, MemOpKind::And, false)),
        Opcode::L4_or_memopb_io => req!(memop(decoded, MemWidth::Byte, MemOpKind::Or, false)),
        Opcode::L4_iadd_memopb_io => req!(memop(decoded, MemWidth::Byte, MemOpKind::Add, true)),
        Opcode::L4_isub_memopb_io => req!(memop(decoded, MemWidth::Byte, MemOpKind::Sub, true)),
        Opcode::L4_iand_memopb_io => req!(memop(decoded, MemWidth::Byte, MemOpKind::ClrBit, true)),
        Opcode::L4_ior_memopb_io => req!(memop(decoded, MemWidth::Byte, MemOpKind::SetBit, true)),
        Opcode::L4_add_memoph_io => req!(memop(decoded, MemWidth::Half, MemOpKind::Add, false)),
        Opcode::L4_sub_memoph_io => req!(memop(decoded, MemWidth::Half, MemOpKind::Sub, false)),
        Opcode::L4_and_memoph_io => req!(memop(decoded, MemWidth::Half, MemOpKind::And, false)),
        Opcode::L4_or_memoph_io => req!(memop(decoded, MemWidth::Half, MemOpKind::Or, false)),
        Opcode::L4_iadd_memoph_io => req!(memop(decoded, MemWidth::Half, MemOpKind::Add, true)),
        Opcode::L4_isub_memoph_io => req!(memop(decoded, MemWidth::Half, MemOpKind::Sub, true)),
        Opcode::L4_iand_memoph_io => req!(memop(decoded, MemWidth::Half, MemOpKind::ClrBit, true)),
        Opcode::L4_ior_memoph_io => req!(memop(decoded, MemWidth::Half, MemOpKind::SetBit, true)),
        Opcode::L4_add_memopw_io => req!(memop(decoded, MemWidth::Word, MemOpKind::Add, false)),
        Opcode::L4_sub_memopw_io => req!(memop(decoded, MemWidth::Word, MemOpKind::Sub, false)),
        Opcode::L4_and_memopw_io => req!(memop(decoded, MemWidth::Word, MemOpKind::And, false)),
        Opcode::L4_or_memopw_io => req!(memop(decoded, MemWidth::Word, MemOpKind::Or, false)),
        Opcode::L4_iadd_memopw_io => req!(memop(decoded, MemWidth::Word, MemOpKind::Add, true)),
        Opcode::L4_isub_memopw_io => req!(memop(decoded, MemWidth::Word, MemOpKind::Sub, true)),
        Opcode::L4_iand_memopw_io => req!(memop(decoded, MemWidth::Word, MemOpKind::ClrBit, true)),
        Opcode::L4_ior_memopw_io => req!(memop(decoded, MemWidth::Word, MemOpKind::SetBit, true)),
        // ---- HVX vector loads/stores (vmem / vmemu) ----
        Opcode::V6_vL32b_ai | Opcode::V6_vL32b_nt_ai => req!(vmem_load(decoded, false, true)),
        Opcode::V6_vL32Ub_ai => req!(vmem_load(decoded, false, false)),
        Opcode::V6_vL32b_pi | Opcode::V6_vL32b_nt_pi => req!(vmem_load(decoded, true, true)),
        Opcode::V6_vL32Ub_pi => req!(vmem_load(decoded, true, false)),
        Opcode::V6_vS32b_ai | Opcode::V6_vS32b_nt_ai => req!(vmem_store(decoded, false, true)),
        Opcode::V6_vS32Ub_ai => req!(vmem_store(decoded, false, false)),
        Opcode::V6_vS32b_pi | Opcode::V6_vS32b_nt_pi => req!(vmem_store(decoded, true, true)),
        Opcode::V6_vS32Ub_pi => req!(vmem_store(decoded, true, false)),
        // Scalar-predicated vector stores: if (Pv[!]) vmem(...) = Vs.
        Opcode::V6_vS32b_pred_ai => req!(vmem_store_pred(decoded, false, true, Some(true))),
        Opcode::V6_vS32b_npred_ai => req!(vmem_store_pred(decoded, false, true, Some(false))),
        Opcode::V6_vS32b_pred_pi => req!(vmem_store_pred(decoded, true, true, Some(true))),
        Opcode::V6_vS32b_npred_pi => req!(vmem_store_pred(decoded, true, true, Some(false))),
        _ => (DecodedInsn::Unknown(word), false),
    }
}

fn decode_subinsn(sub: u16, class: EncClass, isa: HexagonIsa) -> Option<DecodedSub> {
    let decoded = opcode::decode_sub(sub, class)?;
    let opcode = decoded.opcode;
    let insn = match opcode {
        Opcode::SL1_loadri_io => {
            let base = subreg(field_u8(&decoded, b's')?);
            let dst = subreg(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            let offset = imm << 2;
            DecodedInsn::Load {
                dst,
                addr: AddrMode::Offset { base, offset },
                width: MemWidth::Word,
                sign: MemSign::Unsigned,
                pred: None,
            }
        }
        Opcode::SL1_loadrub_io => {
            let base = subreg(field_u8(&decoded, b's')?);
            let dst = subreg(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Load {
                dst,
                addr: AddrMode::Offset { base, offset: imm },
                width: MemWidth::Byte,
                sign: MemSign::Unsigned,
                pred: None,
            }
        }
        Opcode::SS1_storew_io => {
            let base = subreg(field_u8(&decoded, b's')?);
            let src = subreg(field_u8(&decoded, b't')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Store {
                src,
                addr: AddrMode::Offset {
                    base,
                    offset: imm << 2,
                },
                width: MemWidth::Word,
                pred: None,
                src_new: false,
            }
        }
        Opcode::SS1_storeb_io => {
            let base = subreg(field_u8(&decoded, b's')?);
            let src = subreg(field_u8(&decoded, b't')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Store {
                src,
                addr: AddrMode::Offset { base, offset: imm },
                width: MemWidth::Byte,
                pred: None,
                src_new: false,
            }
        }
        Opcode::SL2_loadrh_io => {
            let base = subreg(field_u8(&decoded, b's')?);
            let dst = subreg(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Load {
                dst,
                addr: AddrMode::Offset {
                    base,
                    offset: imm << 1,
                },
                width: MemWidth::Half,
                sign: MemSign::Signed,
                pred: None,
            }
        }
        Opcode::SL2_loadruh_io => {
            let base = subreg(field_u8(&decoded, b's')?);
            let dst = subreg(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Load {
                dst,
                addr: AddrMode::Offset {
                    base,
                    offset: imm << 1,
                },
                width: MemWidth::Half,
                sign: MemSign::Unsigned,
                pred: None,
            }
        }
        Opcode::SL2_loadrb_io => {
            let base = subreg(field_u8(&decoded, b's')?);
            let dst = subreg(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Load {
                dst,
                addr: AddrMode::Offset { base, offset: imm },
                width: MemWidth::Byte,
                sign: MemSign::Signed,
                pred: None,
            }
        }
        Opcode::SL2_loadri_sp => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Load {
                dst,
                addr: AddrMode::Offset {
                    base: 29,
                    offset: imm << 2,
                },
                width: MemWidth::Word,
                sign: MemSign::Unsigned,
                pred: None,
            }
        }
        Opcode::SL2_loadrd_sp => {
            let dst = subreg_pair(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Load {
                dst,
                addr: AddrMode::Offset {
                    base: 29,
                    offset: imm << 3,
                },
                width: MemWidth::Double,
                sign: MemSign::Unsigned,
                pred: None,
            }
        }
        Opcode::SL2_deallocframe => DecodedInsn::DeallocFrame {
            base: 30,
            dst: None,
            update_lr_fp: true,
        },
        Opcode::SL2_return => DecodedInsn::DeallocReturn {
            base: 30,
            dst: None,
            pred: None,
            update_lr_fp: true,
        },
        Opcode::SL2_return_t => DecodedInsn::DeallocReturn {
            base: 30,
            dst: None,
            pred: Some(pred_cond(0, true, false)),
            update_lr_fp: true,
        },
        Opcode::SL2_return_f => DecodedInsn::DeallocReturn {
            base: 30,
            dst: None,
            pred: Some(pred_cond(0, false, false)),
            update_lr_fp: true,
        },
        Opcode::SL2_return_tnew => DecodedInsn::DeallocReturn {
            base: 30,
            dst: None,
            pred: Some(pred_cond(0, true, true)),
            update_lr_fp: true,
        },
        Opcode::SL2_return_fnew => DecodedInsn::DeallocReturn {
            base: 30,
            dst: None,
            pred: Some(pred_cond(0, false, true)),
            update_lr_fp: true,
        },
        Opcode::SL2_jumpr31 => DecodedInsn::JumpReg { src: 31 },
        Opcode::SL2_jumpr31_t => DecodedInsn::JumpRegCond {
            src: 31,
            pred: 0,
            sense: true,
            pred_new: false,
        },
        Opcode::SL2_jumpr31_f => DecodedInsn::JumpRegCond {
            src: 31,
            pred: 0,
            sense: false,
            pred_new: false,
        },
        Opcode::SL2_jumpr31_tnew => DecodedInsn::JumpRegCond {
            src: 31,
            pred: 0,
            sense: true,
            pred_new: true,
        },
        Opcode::SL2_jumpr31_fnew => DecodedInsn::JumpRegCond {
            src: 31,
            pred: 0,
            sense: false,
            pred_new: true,
        },
        Opcode::SS2_allocframe => {
            let imm = decode_field_uimm(&decoded, b'i', None)?.0;
            DecodedInsn::AllocFrame {
                base: 29,
                size: imm << 3,
            }
        }
        Opcode::SS2_storeh_io => {
            let base = subreg(field_u8(&decoded, b's')?);
            let src = subreg(field_u8(&decoded, b't')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Store {
                src,
                addr: AddrMode::Offset {
                    base,
                    offset: imm << 1,
                },
                width: MemWidth::Half,
                pred: None,
                src_new: false,
            }
        }
        Opcode::SS2_storew_sp => {
            let src = subreg(field_u8(&decoded, b't')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::Store {
                src,
                addr: AddrMode::Offset {
                    base: 29,
                    offset: imm << 2,
                },
                width: MemWidth::Word,
                pred: None,
                src_new: false,
            }
        }
        Opcode::SS2_stored_sp => {
            let src = subreg_pair(field_u8(&decoded, b't')?);
            let imm = decode_simm_val(decode_field_uimm(&decoded, b'i', None)?.0, 6, None).0;
            DecodedInsn::Store {
                src,
                addr: AddrMode::Offset {
                    base: 29,
                    offset: imm << 3,
                },
                width: MemWidth::Double,
                pred: None,
                src_new: false,
            }
        }
        Opcode::SS2_storewi0 => {
            let base = subreg(field_u8(&decoded, b's')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::StoreImm {
                value: 0,
                addr: AddrMode::Offset {
                    base,
                    offset: imm << 2,
                },
                width: MemWidth::Word,
                pred: None,
            }
        }
        Opcode::SS2_storewi1 => {
            let base = subreg(field_u8(&decoded, b's')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::StoreImm {
                value: 1,
                addr: AddrMode::Offset {
                    base,
                    offset: imm << 2,
                },
                width: MemWidth::Word,
                pred: None,
            }
        }
        Opcode::SS2_storebi0 => {
            let base = subreg(field_u8(&decoded, b's')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::StoreImm {
                value: 0,
                addr: AddrMode::Offset { base, offset: imm },
                width: MemWidth::Byte,
                pred: None,
            }
        }
        Opcode::SS2_storebi1 => {
            let base = subreg(field_u8(&decoded, b's')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::StoreImm {
                value: 1,
                addr: AddrMode::Offset { base, offset: imm },
                width: MemWidth::Byte,
                pred: None,
            }
        }
        Opcode::SA1_addi => {
            let rx = subreg(field_u8(&decoded, b'x')?);
            let imm = decode_simm_val(decode_field_uimm(&decoded, b'i', None)?.0, 7, None).0;
            DecodedInsn::AddImm {
                dst: rx,
                src: rx,
                imm,
            }
        }
        Opcode::SA1_addsp => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::AddImm {
                dst,
                src: 29,
                imm: imm << 2,
            }
        }
        Opcode::SA1_seti => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::MovImm { dst, imm }
        }
        Opcode::SA1_setin1 => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            DecodedInsn::MovImm { dst, imm: -1 }
        }
        Opcode::SA1_tfr => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::Mov { dst, src }
        }
        Opcode::SA1_inc => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::AddImm { dst, src, imm: 1 }
        }
        Opcode::SA1_dec => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::AddImm { dst, src, imm: -1 }
        }
        Opcode::SA1_and1 => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::AndImm { dst, src, imm: 1 }
        }
        Opcode::SA1_sxtb => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::Extend {
                dst,
                src,
                kind: ExtendKind::Sxt8,
            }
        }
        Opcode::SA1_sxth => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::Extend {
                dst,
                src,
                kind: ExtendKind::Sxt16,
            }
        }
        Opcode::SA1_zxtb => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::Extend {
                dst,
                src,
                kind: ExtendKind::Zxt8,
            }
        }
        Opcode::SA1_zxth => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::Extend {
                dst,
                src,
                kind: ExtendKind::Zxt16,
            }
        }
        Opcode::SA1_cmpeqi => {
            let src = subreg(field_u8(&decoded, b's')?);
            let imm = decode_field_uimm(&decoded, b'i', None)?.0 as i32;
            DecodedInsn::CmpImm {
                pred: 0,
                src,
                imm,
                kind: CmpKind::Eq,
                unsigned: false,
            }
        }
        Opcode::SA1_clrt => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            DecodedInsn::ClearCond {
                dst,
                pred: pred_cond(0, true, false),
            }
        }
        Opcode::SA1_clrf => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            DecodedInsn::ClearCond {
                dst,
                pred: pred_cond(0, false, false),
            }
        }
        Opcode::SA1_clrtnew => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            DecodedInsn::ClearCond {
                dst,
                pred: pred_cond(0, true, true),
            }
        }
        Opcode::SA1_clrfnew => {
            let dst = subreg(field_u8(&decoded, b'd')?);
            DecodedInsn::ClearCond {
                dst,
                pred: pred_cond(0, false, true),
            }
        }
        Opcode::SA1_combinezr => {
            let dst = subreg_pair(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::Combine {
                dst,
                high: CombineOperand::Imm(0),
                low: CombineOperand::Reg(src),
            }
        }
        Opcode::SA1_combinerz => {
            let dst = subreg_pair(field_u8(&decoded, b'd')?);
            let src = subreg(field_u8(&decoded, b's')?);
            DecodedInsn::Combine {
                dst,
                high: CombineOperand::Reg(src),
                low: CombineOperand::Imm(0),
            }
        }
        Opcode::SA1_combine0i
        | Opcode::SA1_combine1i
        | Opcode::SA1_combine2i
        | Opcode::SA1_combine3i => {
            let dst = subreg_pair(field_u8(&decoded, b'd')?);
            let low = decode_field_uimm(&decoded, b'i', None)?.0;
            let high = match decoded.opcode {
                Opcode::SA1_combine0i => 0,
                Opcode::SA1_combine1i => 1,
                Opcode::SA1_combine2i => 2,
                _ => 3,
            };
            DecodedInsn::Combine {
                dst,
                high: CombineOperand::Imm(high),
                low: CombineOperand::Imm(low),
            }
        }
        _ => DecodedInsn::Unknown(sub as u32),
    };

    if insn_uses_dotnew(&insn) && !isa_supports_dotnew(isa) {
        return None;
    }

    Some(DecodedSub {
        insn,
        opcode: Some(opcode),
    })
}

fn duplex_iclass(word: u32) -> u8 {
    let low = ((word >> 13) & 0x1) as u8;
    let high = ((word >> 29) & 0x7) as u8;
    (high << 1) | low
}

pub fn decode_duplex(word: u32, isa: HexagonIsa) -> Option<(DecodedSub, DecodedSub)> {
    if !isa_supports_duplex(isa) {
        return None;
    }
    let iclass = duplex_iclass(word);
    let slot0 = (word & 0x1fff) as u16;
    let slot1 = ((word >> 16) & 0x1fff) as u16;

    let (class1, class0) = match iclass {
        0x0 => (EncClass::SubinsnL1, EncClass::SubinsnL1),
        0x1 => (EncClass::SubinsnL2, EncClass::SubinsnL1),
        0x2 => (EncClass::SubinsnL2, EncClass::SubinsnL2),
        0x3 => (EncClass::SubinsnA, EncClass::SubinsnA),
        0x4 => (EncClass::SubinsnL1, EncClass::SubinsnA),
        0x5 => (EncClass::SubinsnL2, EncClass::SubinsnA),
        0x6 => (EncClass::SubinsnS1, EncClass::SubinsnA),
        0x7 => (EncClass::SubinsnS2, EncClass::SubinsnA),
        0x8 => (EncClass::SubinsnS1, EncClass::SubinsnL1),
        0x9 => (EncClass::SubinsnS1, EncClass::SubinsnL2),
        0xa => (EncClass::SubinsnS1, EncClass::SubinsnS1),
        0xb => (EncClass::SubinsnS2, EncClass::SubinsnS1),
        0xc => (EncClass::SubinsnS2, EncClass::SubinsnL1),
        0xd => (EncClass::SubinsnS2, EncClass::SubinsnL2),
        0xe => (EncClass::SubinsnS2, EncClass::SubinsnS2),
        _ => return None,
    };

    let insn1 = decode_subinsn(slot1, class1, isa)?;
    let insn0 = decode_subinsn(slot0, class0, isa)?;
    Some((insn1, insn0))
}

pub fn decode(word: u32, immext: Option<u32>, _isa: HexagonIsa) -> DecodedWord {
    let decoded = match opcode::decode_word(word) {
        Some(decoded) => decoded,
        None => {
            return DecodedWord {
                insn: DecodedInsn::Unknown(word),
                used_ext: false,
                opcode: None,
            };
        }
    };

    let (insn, used_ext) = decode_main(&decoded, word, immext);
    DecodedWord {
        insn,
        used_ext,
        opcode: Some(decoded.opcode),
    }
}
