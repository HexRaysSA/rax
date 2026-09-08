//! tests.rs

use super::*;

// ---- split test submodules ----
#[cfg(test)]
mod constant;
#[cfg(test)]
mod dead_code;
#[cfg(test)]
mod flags;
#[cfg(test)]
mod misc;
#[cfg(test)]
mod strength;
#[cfg(test)]
mod vector;
#[cfg(test)]
mod vector_alignment;
#[cfg(test)]
mod x86_fma;
#[cfg(test)]
mod xop;
use crate::smir::ir::FunctionBuilder;
use crate::smir::ir::ops::{
    ArmDpRegShiftKind, OpKind, X86AdxKind, X86BlsKind, X86CacheControlKind, X86CountKind,
    X86SsePrefix, X86X87ControlKind, X86X87DataKind,
};
use crate::smir::ir::types::{
    Avx10FP16Op, Condition, FpRoundMode, FunctionId, OpId, VLaneOp, VecCmpCond, VecElementType,
    X86AesOp, X86NarrowMode,
};

fn make_op(id: u16, kind: OpKind) -> SmirOp {
    SmirOp::new(OpId(id), 0x1000, kind)
}

fn string_compare(rep: X86RepMode) -> OpKind {
    OpKind::X86String {
        kind: X86StringKind::Cmps,
        rep,
        accumulator: VReg::virt(0),
        src_index: VReg::virt(1),
        dst_index: VReg::virt(2),
        count: VReg::virt(3),
        src_segment: None,
        width: MemWidth::B1,
        address_width: OpWidth::W64,
    }
}
