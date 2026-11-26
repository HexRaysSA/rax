//! Bounded scalar/legacy-XMM SMIR export. Unsupported operations fail atomically.
use crate::{RaxStatus, guard};
use rax_engine::smir::{
    ir::{
        CallTarget,
        flags::FlagUpdate,
        ops::{OpKind, SmirOp, X86OpHint},
        types::*,
    },
    lift::{ControlFlow, LiftContext, SmirLifter, x86_64::X86_64Lifter},
};
use std::{ffi::c_void, mem::size_of, slice};
pub const RAX_SMIR_ABI_VERSION: u32 = 1;
pub const RAX_SMIR_COMPLETE: u32 = 1;
pub const RAX_SMIR_UNSUPPORTED: u32 = 2;
pub const RAX_SMIR_TRUNCATED: u32 = 4;
pub const RAX_SMIR_MOV: u32 = 1;
pub const RAX_SMIR_ADD: u32 = 2;
pub const RAX_SMIR_SUB: u32 = 3;
pub const RAX_SMIR_ADC: u32 = 4;
pub const RAX_SMIR_SBB: u32 = 5;
pub const RAX_SMIR_AND: u32 = 6;
pub const RAX_SMIR_OR: u32 = 7;
pub const RAX_SMIR_XOR: u32 = 8;
pub const RAX_SMIR_AND_NOT: u32 = 9;
pub const RAX_SMIR_SHL: u32 = 10;
pub const RAX_SMIR_SHR: u32 = 11;
pub const RAX_SMIR_SAR: u32 = 12;
pub const RAX_SMIR_ROL: u32 = 13;
pub const RAX_SMIR_ROR: u32 = 14;
pub const RAX_SMIR_RCL: u32 = 15;
pub const RAX_SMIR_RCR: u32 = 16;
pub const RAX_SMIR_NEG: u32 = 17;
pub const RAX_SMIR_INC: u32 = 18;
pub const RAX_SMIR_DEC: u32 = 19;
pub const RAX_SMIR_NOT: u32 = 20;
pub const RAX_SMIR_CMP: u32 = 21;
pub const RAX_SMIR_TEST: u32 = 22;
pub const RAX_SMIR_MUL_U: u32 = 23;
pub const RAX_SMIR_MUL_S: u32 = 24;
pub const RAX_SMIR_DIV_U: u32 = 25;
pub const RAX_SMIR_DIV_S: u32 = 26;
pub const RAX_SMIR_BSWAP: u32 = 27;
pub const RAX_SMIR_ZERO_EXTEND: u32 = 28;
pub const RAX_SMIR_SIGN_EXTEND: u32 = 29;
pub const RAX_SMIR_TRUNCATE: u32 = 30;
pub const RAX_SMIR_LEA: u32 = 31;
pub const RAX_SMIR_LOAD: u32 = 32;
pub const RAX_SMIR_STORE: u32 = 33;
pub const RAX_SMIR_SELECT: u32 = 34;
pub const RAX_SMIR_CMOVE: u32 = 35;
pub const RAX_SMIR_SET_CC: u32 = 36;
pub const RAX_SMIR_READ_FLAGS: u32 = 37;
pub const RAX_SMIR_WRITE_FLAGS: u32 = 38;
pub const RAX_SMIR_SET_CF: u32 = 39;
pub const RAX_SMIR_SET_DF: u32 = 40;
pub const RAX_SMIR_CMC_CF: u32 = 41;
pub const RAX_SMIR_MATERIALIZE_FLAGS: u32 = 42;
pub const RAX_SMIR_NOP: u32 = 43;
pub const RAX_SMIR_BT: u32 = 44;
pub const RAX_SMIR_BTS: u32 = 45;
pub const RAX_SMIR_BTR: u32 = 46;
pub const RAX_SMIR_BTC: u32 = 47;
pub const RAX_SMIR_OPERAND_XMM: u32 = 4;
pub const RAX_SMIR_VMOV: u32 = 48;
pub const RAX_SMIR_VLOAD: u32 = 49;
pub const RAX_SMIR_VSTORE: u32 = 50;
pub const RAX_SMIR_VINSERT: u32 = 51;
pub const RAX_SMIR_VEXTRACT: u32 = 52;
pub const RAX_SMIR_X86_MOVDQ: u32 = 53;
pub const RAX_SMIR_CHECK_ALIGNMENT: u32 = 54;
pub const RAX_SMIR_VXOR: u32 = 55;
pub const RAX_SMIR_VBROADCAST: u32 = 56;
pub const RAX_SMIR_OPERAND_ARM: u32 = 5;
pub const RAX_SMIR_CMN: u32 = 57;
pub const RAX_SMIR_LOAD_PAIR: u32 = 58;
pub const RAX_SMIR_STORE_PAIR: u32 = 59;
pub const RAX_SMIR_GUARD_CC: u32 = 60;
pub const RAX_SMIR_ARM_PC_RELATIVE: u32 = 1 << 16;
mod arm;
mod arm_system;
pub use arm::rax_smir_lift_arm;
pub use arm_system::{RaxArmSystemInfo, rax_arm_system_info};
mod vector;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RaxSmirOperand {
    pub kind: u32,
    pub id: u32,
    pub value: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RaxSmirAddress {
    pub base: RaxSmirOperand,
    pub index: RaxSmirOperand,
    pub segment: RaxSmirOperand,
    pub displacement: u64,
    pub scale: u32,
    pub address_bits: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RaxSmirOp {
    pub struct_size: u32,
    pub abi_version: u32,
    pub opcode: u32,
    pub width_bits: u32,
    pub source_width_bits: u32,
    pub flags_mask: u32,
    pub condition: u32,
    pub auxiliary: u32,
    pub dst: RaxSmirOperand,
    pub dst2: RaxSmirOperand,
    pub a: RaxSmirOperand,
    pub b: RaxSmirOperand,
    pub c: RaxSmirOperand,
    pub address: RaxSmirAddress,
    pub guest_pc: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RaxSmirInstruction {
    pub struct_size: u32,
    pub abi_version: u32,
    pub flags: u32,
    pub bytes_consumed: u32,
    pub op_count: u32,
    pub required_op_count: u32,
    pub temporary_count: u32,
    pub flow: u32,
    pub condition: u32,
    pub reserved: u32,
    pub target: u64,
    pub fallthrough: u64,
    pub predicate: RaxSmirOperand,
    pub address: RaxSmirAddress,
}
type Checked<T> = Result<T, ()>;
fn reg(r: VReg) -> Checked<RaxSmirOperand> {
    if let VReg::Arch(ArchReg::X86(X86Reg::Xmm(index))) = r {
        return (index < 16)
            .then_some(RaxSmirOperand {
                kind: 4,
                id: index.into(),
                value: 0,
            })
            .ok_or(());
    }
    Ok(match r {
        VReg::Virtual(v) => RaxSmirOperand {
            kind: 1,
            id: v.0,
            value: 0,
        },
        VReg::Imm(v) => imm(v as u64),
        VReg::Arch(ArchReg::Arm(r)) => {
            let id = match r {
                ArmReg::X(n) if n < 31 => u32::from(n),
                ArmReg::Sp => 31,
                ArmReg::Pc => 32,
                ArmReg::Nzcv => 33,
                ArmReg::Pstate => 34,
                ArmReg::Fpcr => 35,
                ArmReg::Fpsr => 36,
                ArmReg::SpEl(n) if n <= 3 => 40 + u32::from(n),
                ArmReg::SysReg(encoding) => 0x10000 + u32::from(encoding),
                _ => return Err(()),
            };
            RaxSmirOperand {
                kind: RAX_SMIR_OPERAND_ARM,
                id,
                value: 0,
            }
        }
        VReg::Arch(ArchReg::X86(r)) => {
            let id = if let Some(i) = r.gpr_index() {
                i as u32
            } else {
                match r {
                    X86Reg::Rip => 32,
                    X86Reg::Rflags => 33,
                    X86Reg::FsBase => 34,
                    X86Reg::GsBase => 35,
                    _ => return Err(()),
                }
            };
            RaxSmirOperand {
                kind: 2,
                id,
                value: 0,
            }
        }
        _ => return Err(()),
    })
}
fn imm(value: u64) -> RaxSmirOperand {
    RaxSmirOperand {
        kind: 3,
        id: 0,
        value,
    }
}
fn src(s: &SrcOperand) -> Checked<RaxSmirOperand> {
    match s {
        SrcOperand::Reg(r) => reg(*r),
        SrcOperand::Imm(v) | SrcOperand::Imm64(v) => Ok(imm(*v as u64)),
        _ => Err(()),
    }
}
fn condition(c: Condition) -> u32 {
    match c {
        Condition::Eq => 0,
        Condition::Ne => 1,
        Condition::Ult => 2,
        Condition::Ule => 3,
        Condition::Ugt => 4,
        Condition::Uge => 5,
        Condition::Slt => 6,
        Condition::Sle => 7,
        Condition::Sgt => 8,
        Condition::Sge => 9,
        Condition::Negative => 10,
        Condition::Positive => 11,
        Condition::Overflow => 12,
        Condition::NoOverflow => 13,
        Condition::Parity => 14,
        Condition::NoParity => 15,
        Condition::Always => 16,
    }
}
fn addr(a: &Address, pc: u64) -> Checked<RaxSmirAddress> {
    let mut out = RaxSmirAddress {
        scale: 1,
        address_bits: 64,
        ..Default::default()
    };
    match a {
        Address::Direct(r) => out.base = reg(*r)?,
        Address::BaseOffset { base, offset, .. } => {
            out.base = reg(*base)?;
            out.displacement = *offset as u64;
        }
        Address::BaseIndexScale {
            base,
            index,
            scale,
            disp,
            ..
        } => {
            if let Some(r) = base {
                out.base = reg(*r)?
            };
            out.index = reg(*index)?;
            out.scale = *scale as u32;
            out.displacement = *disp as u64;
        }
        Address::Absolute(v) => out.displacement = *v,
        Address::PcRel { offset, base, .. } => {
            out.displacement = base.unwrap_or(pc).wrapping_add(*offset as u64)
        }
        Address::SegmentRel {
            segment,
            base,
            index,
            scale,
            disp,
        } => {
            out.segment = reg(*segment)?;
            if let Some(r) = base {
                out.base = reg(*r)?
            };
            if let Some(r) = index {
                out.index = reg(*r)?
            };
            out.scale = *scale as u32;
            out.displacement = *disp as u64;
        }
        Address::X86Addr32(inner) => {
            out = addr(inner, pc)?;
            out.address_bits = 32;
        }
        _ => return Err(()),
    }
    Ok(out)
}
fn operation(op: &SmirOp) -> Checked<RaxSmirOp> {
    if matches!(op.x86_hint, Some(X86OpHint::ShiftGroup6)) {
        return Err(());
    }
    if let Some(record) = vector::operation(op)? {
        return Ok(record);
    }
    let mut o = RaxSmirOp {
        struct_size: size_of::<RaxSmirOp>() as u32,
        abi_version: 1,
        width_bits: 64,
        guest_pc: op.guest_pc,
        ..Default::default()
    };
    macro_rules! bin {
        ($code:expr,$d:expr,$a:expr,$b:expr,$w:expr,$f:expr) => {{
            o.opcode = $code;
            o.dst = reg(*$d)?;
            o.a = reg(*$a)?;
            o.b = src($b)?;
            o.width_bits = $w.bits();
            o.flags_mask = $f.as_set().0 as u32;
        }};
    }
    macro_rules! unary {
        ($code:expr,$d:expr,$a:expr,$w:expr,$f:expr) => {{
            o.opcode = $code;
            o.dst = reg(*$d)?;
            o.a = reg(*$a)?;
            o.width_bits = $w.bits();
            o.flags_mask = $f.as_set().0 as u32;
        }};
    }
    match &op.kind {
        OpKind::Add {
            dst,
            src1,
            src2,
            width,
            flags,
        } => bin!(RAX_SMIR_ADD, dst, src1, src2, width, flags),
        OpKind::Sub {
            dst,
            src1,
            src2,
            width,
            flags,
        } => bin!(RAX_SMIR_SUB, dst, src1, src2, width, flags),
        OpKind::Adc {
            dst,
            src1,
            src2,
            width,
            flags,
        } => bin!(RAX_SMIR_ADC, dst, src1, src2, width, flags),
        OpKind::Sbb {
            dst,
            src1,
            src2,
            width,
            flags,
        } => bin!(RAX_SMIR_SBB, dst, src1, src2, width, flags),
        OpKind::And {
            dst,
            src1,
            src2,
            width,
            flags,
        } => bin!(RAX_SMIR_AND, dst, src1, src2, width, flags),
        OpKind::Or {
            dst,
            src1,
            src2,
            width,
            flags,
        } => bin!(RAX_SMIR_OR, dst, src1, src2, width, flags),
        OpKind::Xor {
            dst,
            src1,
            src2,
            width,
            flags,
        } => bin!(RAX_SMIR_XOR, dst, src1, src2, width, flags),
        OpKind::AndNot {
            dst,
            src1,
            src2,
            width,
            flags,
        } => bin!(RAX_SMIR_AND_NOT, dst, src1, src2, width, flags),
        OpKind::Shl {
            dst,
            src,
            amount,
            width,
            flags,
        } => bin!(RAX_SMIR_SHL, dst, src, amount, width, flags),
        OpKind::Shr {
            dst,
            src,
            amount,
            width,
            flags,
        } => bin!(RAX_SMIR_SHR, dst, src, amount, width, flags),
        OpKind::Sar {
            dst,
            src,
            amount,
            width,
            flags,
        } => bin!(RAX_SMIR_SAR, dst, src, amount, width, flags),
        OpKind::Rol {
            dst,
            src,
            amount,
            width,
            flags,
        } => bin!(RAX_SMIR_ROL, dst, src, amount, width, flags),
        OpKind::Ror {
            dst,
            src,
            amount,
            width,
            flags,
        } => bin!(RAX_SMIR_ROR, dst, src, amount, width, flags),
        OpKind::Rcl {
            dst,
            src,
            amount,
            width,
            flags,
        } => bin!(RAX_SMIR_RCL, dst, src, amount, width, flags),
        OpKind::Rcr {
            dst,
            src,
            amount,
            width,
            flags,
        } => bin!(RAX_SMIR_RCR, dst, src, amount, width, flags),
        OpKind::Neg {
            dst,
            src,
            width,
            flags,
        } => unary!(RAX_SMIR_NEG, dst, src, width, flags),
        OpKind::Inc {
            dst,
            src,
            width,
            flags,
        } => unary!(RAX_SMIR_INC, dst, src, width, flags),
        OpKind::Dec {
            dst,
            src,
            width,
            flags,
        } => unary!(RAX_SMIR_DEC, dst, src, width, flags),
        OpKind::Bt {
            src: value,
            index,
            width,
        } => {
            o.opcode = RAX_SMIR_BT;
            o.a = reg(*value)?;
            o.b = src(index)?;
            o.width_bits = width.bits();
            o.flags_mask = 1;
        }
        OpKind::Bts {
            dst,
            src: value,
            index,
            width,
        } => {
            bin!(RAX_SMIR_BTS, dst, value, index, width, FlagUpdate::None);
            o.flags_mask = 1;
        }
        OpKind::Btr {
            dst,
            src: value,
            index,
            width,
        } => {
            bin!(RAX_SMIR_BTR, dst, value, index, width, FlagUpdate::None);
            o.flags_mask = 1;
        }
        OpKind::Btc {
            dst,
            src: value,
            index,
            width,
        } => {
            bin!(RAX_SMIR_BTC, dst, value, index, width, FlagUpdate::None);
            o.flags_mask = 1;
        }
        OpKind::Not { dst, src, width } => unary!(RAX_SMIR_NOT, dst, src, width, FlagUpdate::None),
        OpKind::Bswap { dst, src, width } => {
            unary!(RAX_SMIR_BSWAP, dst, src, width, FlagUpdate::None)
        }
        OpKind::Cmp { src1, src2, width } => {
            o.opcode = RAX_SMIR_CMP;
            o.a = reg(*src1)?;
            o.b = src(src2)?;
            o.width_bits = width.bits();
            o.flags_mask = 63;
        }
        OpKind::Cmn { src1, src2, width } => {
            o.opcode = RAX_SMIR_CMN;
            o.a = reg(*src1)?;
            o.b = src(src2)?;
            o.width_bits = width.bits();
            o.flags_mask = 63;
        }
        OpKind::Test { src1, src2, width } => {
            o.opcode = RAX_SMIR_TEST;
            o.a = reg(*src1)?;
            o.b = src(src2)?;
            o.width_bits = width.bits();
            o.flags_mask = 63;
        }
        OpKind::MulU {
            dst_lo,
            dst_hi,
            src1,
            src2,
            width,
            flags,
        } => {
            bin!(RAX_SMIR_MUL_U, dst_lo, src1, src2, width, flags);
            if let Some(r) = dst_hi {
                o.dst2 = reg(*r)?
            }
        }
        OpKind::MulS {
            dst_lo,
            dst_hi,
            src1,
            src2,
            width,
            flags,
        } => {
            bin!(RAX_SMIR_MUL_S, dst_lo, src1, src2, width, flags);
            if let Some(r) = dst_hi {
                o.dst2 = reg(*r)?
            }
        }
        OpKind::DivU {
            quot,
            rem,
            src1,
            src2,
            width,
            flags,
        } => {
            bin!(RAX_SMIR_DIV_U, quot, src1, src2, width, flags);
            if let Some(r) = rem {
                o.dst2 = reg(*r)?
            }
        }
        OpKind::DivS {
            quot,
            rem,
            src1,
            src2,
            width,
            flags,
        } => {
            bin!(RAX_SMIR_DIV_S, quot, src1, src2, width, flags);
            if let Some(r) = rem {
                o.dst2 = reg(*r)?
            }
        }
        OpKind::ZeroExtend {
            dst,
            src,
            from_width,
            to_width,
        } => {
            unary!(RAX_SMIR_ZERO_EXTEND, dst, src, to_width, FlagUpdate::None);
            o.source_width_bits = from_width.bits();
        }
        OpKind::SignExtend {
            dst,
            src,
            from_width,
            to_width,
        } => {
            unary!(RAX_SMIR_SIGN_EXTEND, dst, src, to_width, FlagUpdate::None);
            o.source_width_bits = from_width.bits();
        }
        OpKind::Truncate {
            dst,
            src,
            from_width,
            to_width,
        } => {
            unary!(RAX_SMIR_TRUNCATE, dst, src, to_width, FlagUpdate::None);
            o.source_width_bits = from_width.bits();
        }
        OpKind::Mov { dst, src: s, width } => {
            o.opcode = RAX_SMIR_MOV;
            o.dst = reg(*dst)?;
            o.a = src(s)?;
            o.width_bits = width.bits();
        }
        OpKind::Lea { dst, addr: a } => {
            o.opcode = RAX_SMIR_LEA;
            o.dst = reg(*dst)?;
            o.address = addr(a, op.guest_pc)?;
        }
        OpKind::X86Lea {
            dst,
            addr: address,
            width,
        } => {
            o.opcode = RAX_SMIR_LEA;
            o.dst = reg(*dst)?;
            o.address = addr(address, op.guest_pc)?;
            o.width_bits = width.bits();
        }
        OpKind::Load {
            dst,
            addr: a,
            width,
            sign,
        } => {
            o.opcode = RAX_SMIR_LOAD;
            o.dst = reg(*dst)?;
            o.address = addr(a, op.guest_pc)?;
            o.width_bits = width.bytes() * 8;
            o.auxiliary = (*sign == SignExtend::Sign) as u32;
        }
        OpKind::Store {
            src,
            addr: a,
            width,
        } => {
            o.opcode = RAX_SMIR_STORE;
            o.a = reg(*src)?;
            o.address = addr(a, op.guest_pc)?;
            o.width_bits = width.bytes() * 8;
        }
        OpKind::LoadPair {
            dst1,
            dst2,
            addr: address,
            width,
        } => {
            o.opcode = RAX_SMIR_LOAD_PAIR;
            o.dst = reg(*dst1)?;
            o.dst2 = reg(*dst2)?;
            o.address = addr(address, op.guest_pc)?;
            o.width_bits = width.bytes() * 8;
        }
        OpKind::StorePair {
            src1,
            src2,
            addr: address,
            width,
        } => {
            o.opcode = RAX_SMIR_STORE_PAIR;
            o.a = reg(*src1)?;
            o.b = reg(*src2)?;
            o.address = addr(address, op.guest_pc)?;
            o.width_bits = width.bytes() * 8;
        }
        OpKind::Select {
            dst,
            cond,
            src_true,
            src_false,
            width,
        } => {
            o.opcode = RAX_SMIR_SELECT;
            o.dst = reg(*dst)?;
            o.a = reg(*cond)?;
            o.b = reg(*src_true)?;
            o.c = reg(*src_false)?;
            o.width_bits = width.bits();
        }
        OpKind::CMove {
            dst,
            src,
            width,
            cond,
        } => {
            unary!(RAX_SMIR_CMOVE, dst, src, width, FlagUpdate::None);
            o.condition = condition(*cond);
        }
        OpKind::SetCC { dst, cond, width } => {
            o.opcode = RAX_SMIR_SET_CC;
            o.dst = reg(*dst)?;
            o.condition = condition(*cond);
            o.width_bits = width.bits();
        }
        OpKind::TestCondition { dst, cond } => {
            o.opcode = RAX_SMIR_SET_CC;
            o.dst = reg(*dst)?;
            o.condition = condition(*cond);
        }
        OpKind::ReadFlags { dst } => {
            o.opcode = RAX_SMIR_READ_FLAGS;
            o.dst = reg(*dst)?;
        }
        OpKind::WriteFlags { src } => {
            o.opcode = RAX_SMIR_WRITE_FLAGS;
            o.a = reg(*src)?;
        }
        OpKind::SetCF { value } => {
            o.opcode = RAX_SMIR_SET_CF;
            o.auxiliary = *value as u32;
        }
        OpKind::SetDF { value } => {
            o.opcode = RAX_SMIR_SET_DF;
            o.auxiliary = *value as u32;
        }
        OpKind::CmcCF => o.opcode = RAX_SMIR_CMC_CF,
        OpKind::MaterializeFlags => o.opcode = RAX_SMIR_MATERIALIZE_FLAGS,
        OpKind::Nop => o.opcode = RAX_SMIR_NOP,
        _ => return Err(()),
    }
    if matches!(op.x86_hint, Some(X86OpHint::LegacyHighByteReg)) {
        if !matches!(
            op.kind,
            OpKind::ZeroExtend { .. } | OpKind::SignExtend { .. }
        ) {
            return Err(());
        }
        o.auxiliary |= 0x100;
    }
    if o.width_bits > 64
        || o.source_width_bits > 64
        || [o.dst, o.dst2, o.a, o.b, o.c].iter().any(|r| r.kind == 4)
    {
        return Err(());
    }
    Ok(o)
}
fn flow(f: &ControlFlow, pc: u64, out: &mut RaxSmirInstruction) -> Checked<()> {
    match f {
        ControlFlow::Fallthrough | ControlFlow::NextInsn => out.flow = 0,
        ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
            out.flow = 1;
            out.target = *target
        }
        ControlFlow::CondBranch {
            cond,
            target,
            fallthrough,
        } => {
            out.flow = 2;
            out.condition = condition(*cond);
            out.target = *target;
            out.fallthrough = *fallthrough;
        }
        ControlFlow::CondBranchReg {
            cond,
            taken,
            not_taken,
        } => {
            out.flow = 3;
            out.predicate = reg(*cond)?;
            out.target = *taken;
            out.fallthrough = *not_taken;
        }
        ControlFlow::IndirectBranch { target } => {
            out.flow = 4;
            out.predicate = reg(*target)?
        }
        ControlFlow::IndirectBranchMem { addr: a } => {
            out.flow = 5;
            out.address = addr(a, pc)?
        }
        ControlFlow::Call { target } => match target {
            CallTarget::GuestAddr(t) => {
                out.flow = 6;
                out.target = *t
            }
            CallTarget::Indirect(r) => {
                out.flow = 7;
                out.predicate = reg(*r)?
            }
            CallTarget::GuestAddrInterworking { addr, thumb } => {
                if addr & 1 != 0 {
                    return Err(());
                }
                out.flow = 12;
                out.target = *addr | u64::from(*thumb);
            }
            CallTarget::IndirectInterworking(r) => {
                out.flow = 13;
                out.predicate = reg(*r)?;
            }
            CallTarget::IndirectMem(a) => {
                out.flow = 8;
                out.address = addr(a, pc)?
            }
            CallTarget::X86IndirectMemAddr32(a) => {
                out.flow = 8;
                out.address = addr(a, pc)?;
                out.address.address_bits = 32
            }
            _ => return Err(()),
        },
        ControlFlow::Return => out.flow = 9,
        ControlFlow::Trap { .. } => out.flow = 10,
        ControlFlow::Syscall => out.flow = 11,
    }
    Ok(())
}
/// Lift one AMD64 instruction. See rax.h for the caller buffer contract.
#[unsafe(no_mangle)]
pub extern "C" fn rax_smir_lift_x64(
    pc: u64,
    bytes: *const c_void,
    len: usize,
    out: *mut RaxSmirInstruction,
    ops: *mut RaxSmirOp,
    capacity: usize,
) -> RaxStatus {
    guard(|| {
        if out.is_null() {
            return RaxStatus::Arg;
        }
        let mut result = RaxSmirInstruction {
            struct_size: size_of::<RaxSmirInstruction>() as u32,
            abi_version: 1,
            ..Default::default()
        };
        // SAFETY: the caller promises a valid aligned writable output of its full
        // published size, disjoint from input and operations. Nothing is retained.
        unsafe { out.write(result) };
        if bytes.is_null()
            || len == 0
            || len > 15
            || (ops.is_null() && capacity != 0)
            || capacity > isize::MAX as usize / size_of::<RaxSmirOp>()
        {
            return RaxStatus::Arg;
        }
        // SAFETY: len is bounded to 15 and the caller promises this readable extent.
        let input = unsafe { slice::from_raw_parts(bytes.cast::<u8>(), len) };
        let mut ctx = LiftContext::new(SourceArch::X86_64);
        let lift = X86_64Lifter::strict().lift_insn(pc, input, &mut ctx);
        let exported = (|| -> Checked<Vec<RaxSmirOp>> {
            let lift = lift.map_err(|_| ())?;
            if lift.bytes_consumed == 0 || lift.bytes_consumed > len {
                return Err(());
            }
            result.bytes_consumed = lift.bytes_consumed as u32;
            result.fallthrough = pc.wrapping_add(lift.bytes_consumed as u64);
            result.temporary_count = ctx.vreg_alloc.count();
            flow(&lift.control_flow, pc, &mut result)?;
            let mut records = lift
                .ops
                .iter()
                .map(operation)
                .collect::<Checked<Vec<_>>>()?;
            let mut bindings = ctx
                .vreg_alloc
                .arch_bindings()
                .into_iter()
                .map(|(r, v)| Ok((reg(VReg::Arch(r))?, reg(v)?)))
                .collect::<Checked<Vec<_>>>()?;
            bindings.sort_by_key(|(r, _)| (r.kind, r.id));
            for (dst, a) in bindings {
                records.push(RaxSmirOp {
                    struct_size: size_of::<RaxSmirOp>() as u32,
                    abi_version: 1,
                    opcode: if dst.kind == 4 {
                        RAX_SMIR_VMOV
                    } else {
                        RAX_SMIR_MOV
                    },
                    width_bits: if dst.kind == 4 { 128 } else { 64 },
                    dst,
                    a,
                    guest_pc: pc,
                    ..Default::default()
                });
            }
            if records
                .iter()
                .any(|r| (RAX_SMIR_VMOV..=RAX_SMIR_VBROADCAST).contains(&r.opcode))
                && !vector::legacy_encoding(input)
            {
                return Err(());
            }
            Ok(records)
        })();
        let status = match exported {
            Err(()) => {
                result.flags = RAX_SMIR_UNSUPPORTED;
                RaxStatus::Unsupported
            }
            Ok(records) => {
                result.required_op_count = records.len() as u32;
                if ops.is_null() {
                    result.flags = RAX_SMIR_COMPLETE;
                    RaxStatus::Ok
                } else if capacity < records.len() {
                    result.flags = RAX_SMIR_TRUNCATED;
                    RaxStatus::Bounds
                } else {
                    // SAFETY: caller promises capacity aligned writable elements, disjoint
                    // from input/out; the bounds check above covers the complete copy.
                    unsafe { std::ptr::copy_nonoverlapping(records.as_ptr(), ops, records.len()) };
                    result.op_count = records.len() as u32;
                    result.flags = RAX_SMIR_COMPLETE;
                    RaxStatus::Ok
                }
            }
        };
        // SAFETY: same output contract as the initial write above.
        unsafe { out.write(result) };
        status
    })
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod vector_tests;

#[cfg(test)]
mod arm_tests;
