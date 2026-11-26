//! ARM scalar SMIR projection. Unknown operations reject the whole instruction.
use super::*;
use crate::arch::RaxArch;
use crate::{RAX_MODE_ARM, RAX_MODE_LITTLE_ENDIAN, RAX_MODE_THUMB};
use rax_engine::isa::arm::decoder::{Aarch32Decoder, Condition as ArmCondition, Mnemonic};
use rax_engine::smir::lift::{aarch32::Aarch32Lifter, aarch64::Aarch64Lifter, thumb::ThumbLifter};
mod a32_flags;

fn expand_source(
    source: &mut SrcOperand,
    width: OpWidth,
    pc: u64,
    context: &mut LiftContext,
    prefix: &mut Vec<SmirOp>,
) -> Checked<()> {
    let mut emit = |kind| prefix.push(SmirOp::new(OpId(0), pc, kind));
    let temporary = match source.clone() {
        SrcOperand::Shifted { reg, shift, amount } => {
            let dst = context.alloc_vreg();
            let amount = SrcOperand::Imm(i64::from(amount));
            let flags = FlagUpdate::None;
            emit(match shift {
                ShiftOp::Lsl => OpKind::Shl {
                    dst,
                    src: reg,
                    amount,
                    width,
                    flags,
                },
                ShiftOp::Lsr => OpKind::Shr {
                    dst,
                    src: reg,
                    amount,
                    width,
                    flags,
                },
                ShiftOp::Asr => OpKind::Sar {
                    dst,
                    src: reg,
                    amount,
                    width,
                    flags,
                },
                ShiftOp::Ror => OpKind::Ror {
                    dst,
                    src: reg,
                    amount,
                    width,
                    flags,
                },
                ShiftOp::Rrx => return Err(()),
            });
            dst
        }
        SrcOperand::Extended { reg, extend, shift } => {
            let (from_width, signed) = match extend {
                ExtendOp::Uxtb => (OpWidth::W8, false),
                ExtendOp::Uxth => (OpWidth::W16, false),
                ExtendOp::Uxtw => (OpWidth::W32, false),
                ExtendOp::Uxtx => (OpWidth::W64, false),
                ExtendOp::Sxtb => (OpWidth::W8, true),
                ExtendOp::Sxth => (OpWidth::W16, true),
                ExtendOp::Sxtw => (OpWidth::W32, true),
                ExtendOp::Sxtx => (OpWidth::W64, true),
            };
            if from_width.bits() > width.bits() {
                return Err(());
            }
            let dst = context.alloc_vreg();
            emit(if signed {
                OpKind::SignExtend {
                    dst,
                    src: reg,
                    from_width,
                    to_width: width,
                }
            } else {
                OpKind::ZeroExtend {
                    dst,
                    src: reg,
                    from_width,
                    to_width: width,
                }
            });
            if shift == 0 {
                dst
            } else {
                let shifted = context.alloc_vreg();
                emit(OpKind::Shl {
                    dst: shifted,
                    src: dst,
                    amount: SrcOperand::Imm(i64::from(shift)),
                    width,
                    flags: FlagUpdate::None,
                });
                shifted
            }
        }
        _ => return Ok(()),
    };
    *source = SrcOperand::Reg(temporary);
    Ok(())
}

fn lift_records(
    arch: SourceArch,
    pc: u64,
    bytes: &[u8],
) -> Checked<(RaxSmirInstruction, Vec<RaxSmirOp>)> {
    // A32 predication belongs to the entire instruction, including memory
    // accesses and control flow. Lift its unconditional body with the strict
    // lifter and publish an explicit instruction guard before that body. No
    // upstream interpreter/JIT semantics are relaxed by this export framing.
    let normalized;
    let mut guard_condition = None;
    let input = if arch == SourceArch::Aarch32 {
        let raw = u32::from_le_bytes(bytes.try_into().map_err(|_| ())?);
        let decoded = Aarch32Decoder::decode(raw).map_err(|_| ())?;
        if let Some(cond) = decoded.cond.filter(|_| decoded.mnemonic != Mnemonic::B) {
            let cond = match cond {
                ArmCondition::EQ => Condition::Eq,
                ArmCondition::NE => Condition::Ne,
                ArmCondition::CS => Condition::Uge,
                ArmCondition::CC => Condition::Ult,
                ArmCondition::MI => Condition::Negative,
                ArmCondition::PL => Condition::Positive,
                ArmCondition::VS => Condition::Overflow,
                ArmCondition::VC => Condition::NoOverflow,
                ArmCondition::HI => Condition::Ugt,
                ArmCondition::LS => Condition::Ule,
                ArmCondition::GE => Condition::Sge,
                ArmCondition::LT => Condition::Slt,
                ArmCondition::GT => Condition::Sgt,
                ArmCondition::LE => Condition::Sle,
                ArmCondition::AL | ArmCondition::NV => return Err(()),
            };
            guard_condition = Some(condition(cond));
            normalized = ((raw & 0x0fffffff) | 0xe0000000).to_le_bytes();
            normalized.as_slice()
        } else {
            bytes
        }
    } else {
        bytes
    };
    let mut context = LiftContext::new(arch);
    let mut lifter: Box<dyn SmirLifter> = match arch {
        SourceArch::Aarch64 => Box::new(Aarch64Lifter::strict()),
        SourceArch::Aarch32 => Box::new(Aarch32Lifter::new()),
        SourceArch::Thumb => Box::new(ThumbLifter::new()),
        _ => return Err(()),
    };
    let lift = match lifter.lift_insn(pc, input, &mut context) {
        Ok(lift) => lift,
        Err(_) if arch == SourceArch::Aarch32 => a32_flags::lift(pc, input, &mut context)?,
        Err(_) => return Err(()),
    };
    if lift.bytes_consumed == 0 || lift.bytes_consumed > bytes.len() {
        return Err(());
    }
    let mut result = RaxSmirInstruction {
        struct_size: size_of::<RaxSmirInstruction>() as u32,
        abi_version: RAX_SMIR_ABI_VERSION,
        bytes_consumed: lift.bytes_consumed as u32,
        fallthrough: pc.wrapping_add(lift.bytes_consumed as u64)
            & if arch == SourceArch::Aarch64 {
                u64::MAX
            } else {
                u32::MAX as u64
            },
        ..Default::default()
    };
    flow(&lift.control_flow, pc, &mut result)?;
    let mut records = Vec::new();
    if let Some(condition) = guard_condition {
        records.push(RaxSmirOp {
            struct_size: size_of::<RaxSmirOp>() as u32,
            abi_version: RAX_SMIR_ABI_VERSION,
            opcode: RAX_SMIR_GUARD_CC,
            condition,
            guest_pc: pc,
            ..Default::default()
        });
    }
    for mut op in lift.ops {
        let mut prefix = Vec::new();
        // Preserve multiply-accumulate semantics with existing public scalar ops.
        if let OpKind::MulAdd {
            dst,
            acc,
            src1,
            src2,
            width,
        }
        | OpKind::MulSub {
            dst,
            acc,
            src1,
            src2,
            width,
        } = op.kind
        {
            let product = context.alloc_vreg();
            prefix.push(SmirOp::new(
                OpId(0),
                pc,
                OpKind::MulU {
                    dst_lo: product,
                    dst_hi: None,
                    src1,
                    src2: SrcOperand::Reg(src2),
                    width,
                    flags: FlagUpdate::None,
                },
            ));
            op.kind = if matches!(op.kind, OpKind::MulAdd { .. }) {
                OpKind::Add {
                    dst,
                    src1: acc,
                    src2: SrcOperand::Reg(product),
                    width,
                    flags: FlagUpdate::None,
                }
            } else {
                OpKind::Sub {
                    dst,
                    src1: acc,
                    src2: SrcOperand::Reg(product),
                    width,
                    flags: FlagUpdate::None,
                }
            };
        }
        match &mut op.kind {
            OpKind::Add { src2, width, .. }
            | OpKind::Sub { src2, width, .. }
            | OpKind::Adc { src2, width, .. }
            | OpKind::Sbb { src2, width, .. }
            | OpKind::And { src2, width, .. }
            | OpKind::Or { src2, width, .. }
            | OpKind::Xor { src2, width, .. }
            | OpKind::AndNot { src2, width, .. }
            | OpKind::Cmp { src2, width, .. }
            | OpKind::Cmn { src2, width, .. }
            | OpKind::Test { src2, width, .. } => {
                expand_source(src2, *width, pc, &mut context, &mut prefix)?;
            }
            OpKind::Mov { src, width, .. } => {
                expand_source(src, *width, pc, &mut context, &mut prefix)?;
            }
            _ => {}
        }
        for expanded in prefix.iter().chain(std::iter::once(&op)) {
            records.push(operation(expanded)?);
        }
    }
    let mut bindings = context
        .vreg_alloc
        .arch_bindings()
        .into_iter()
        .collect::<Vec<_>>();
    bindings.sort_by_key(|(architectural, _)| {
        reg(VReg::Arch(*architectural))
            .map(|r| (r.kind, r.id))
            .unwrap_or((u32::MAX, u32::MAX))
    });
    for (architectural, value) in bindings {
        records.push(RaxSmirOp {
            struct_size: size_of::<RaxSmirOp>() as u32,
            abi_version: RAX_SMIR_ABI_VERSION,
            opcode: RAX_SMIR_MOV,
            width_bits: if arch == SourceArch::Aarch64 { 64 } else { 32 },
            dst: reg(VReg::Arch(architectural))?,
            a: reg(value)?,
            guest_pc: pc,
            ..Default::default()
        });
    }
    result.temporary_count = context.vreg_alloc.count();
    Ok((result, records))
}

/// ARM scalar lifting. Buffer/panic behavior matches the legacy x86 export.
#[unsafe(no_mangle)]
pub extern "C" fn rax_smir_lift_arm(
    arch: i32,
    mode: u32,
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
            abi_version: RAX_SMIR_ABI_VERSION,
            ..Default::default()
        };
        // SAFETY: caller provides a full aligned writable output, disjoint from input/ops.
        unsafe { out.write(result) };
        let source = match RaxArch::from_i32(arch) {
            Some(RaxArch::Arm64) if mode & !RAX_MODE_LITTLE_ENDIAN == 0 => SourceArch::Aarch64,
            Some(RaxArch::Arm) if mode & !(RAX_MODE_ARM | RAX_MODE_LITTLE_ENDIAN) == 0 => {
                SourceArch::Aarch32
            }
            RAX_ARCH_ARM
                if mode & !(RAX_MODE_THUMB | RAX_MODE_LITTLE_ENDIAN) == 0
                    && mode & RAX_MODE_THUMB != 0 =>
            {
                SourceArch::Thumb
            }
            Some(RaxArch::Arm | RaxArch::Arm64) => return RaxStatus::Mode,
            _ => return RaxStatus::Arch,
        };
        let alignment = if source == SourceArch::Thumb { 2 } else { 4 };
        if bytes.is_null()
            || len < alignment
            || len > 4
            || pc % alignment as u64 != 0
            || (source != SourceArch::Aarch64 && pc > u32::MAX as u64)
            || (ops.is_null() && capacity != 0)
            || capacity > isize::MAX as usize / size_of::<RaxSmirOp>()
        {
            return RaxStatus::Arg;
        }
        // SAFETY: input is a caller-guaranteed readable, disjoint range bounded to four bytes.
        let input = unsafe { slice::from_raw_parts(bytes.cast::<u8>(), len) };
        let projected = lift_records(source, pc, input);
        let Ok((mut header, mut records)) = projected else {
            result.flags = RAX_SMIR_UNSUPPORTED;
            // SAFETY: same full output contract as above.
            unsafe { out.write(result) };
            return RaxStatus::Unsupported;
        };
        // Lift at a second origin to retain proven PC dependence erased by constant
        // folding (ADR/ADRP and literal effective addresses). This is annotation,
        // not a change to the exported SMIR values or executable semantics.
        let delta = if source == SourceArch::Aarch64 {
            1u64 << 32
        } else {
            1u64 << 28
        };
        let mask = if source == SourceArch::Aarch64 {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        if let Ok((_, shifted)) = lift_records(source, pc.wrapping_add(delta) & mask, input) {
            if shifted.len() == records.len() {
                for (op, translated) in records.iter_mut().zip(&shifted) {
                    if op.opcode != translated.opcode {
                        continue;
                    }
                    let immediate = op.opcode == RAX_SMIR_MOV
                        && op.a.kind == 3
                        && translated.a.kind == 3
                        && translated.a.value == op.a.value.wrapping_add(delta) & mask;
                    let address = matches!(
                        op.opcode,
                        RAX_SMIR_LEA
                            | RAX_SMIR_LOAD
                            | RAX_SMIR_LOAD_PAIR
                            | RAX_SMIR_STORE
                            | RAX_SMIR_STORE_PAIR
                    ) && op.address.base.kind == 0
                        && op.address.index.kind == 0
                        && translated.address.displacement
                            == op.address.displacement.wrapping_add(delta) & mask;
                    let mut expected = *op;
                    expected.guest_pc = translated.guest_pc;
                    if immediate {
                        expected.a.value = translated.a.value;
                    } else if address {
                        expected.address.displacement = translated.address.displacement;
                    }
                    if (immediate || address) && expected == *translated {
                        op.auxiliary |= RAX_SMIR_ARM_PC_RELATIVE;
                    }
                }
            }
        }
        header.required_op_count = records.len() as u32;
        let status = if ops.is_null() {
            header.flags = RAX_SMIR_COMPLETE;
            RaxStatus::Ok
        } else if capacity < records.len() {
            header.flags = RAX_SMIR_TRUNCATED;
            RaxStatus::Bounds
        } else {
            // SAFETY: caller provides capacity aligned writable records; all records
            // are validated before publishing, and the complete extent fits capacity.
            unsafe { std::ptr::copy_nonoverlapping(records.as_ptr(), ops, records.len()) };
            header.op_count = records.len() as u32;
            header.flags = RAX_SMIR_COMPLETE;
            RaxStatus::Ok
        };
        // SAFETY: same output contract as the initial write.
        unsafe { out.write(header) };
        status
    })
}
