//! x87 escape instruction lifting.

use crate::smir::ir::TrapKind;
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86X87ArithmeticDestination, X86X87ArithmeticSource, X86X87CompareSource,
    X86X87Constant, X86X87ControlKind, X86X87DataKind, X86X87EnvWidth, X86X87FloatWidth,
    X86X87IntWidth, X86X87TranscendentalKind,
};
use crate::smir::ir::types::{Condition, OpId};
use crate::smir::lift::x86_64::{X86_64Lifter, X86Prefix, decode_modrm};
use crate::smir::lift::{ControlFlow, LiftContext, LiftError, LiftResult};

impl X86_64Lifter {
    fn x87_invalid_opcode(prefix: &X86Prefix, modrm_bytes: usize) -> LiftResult {
        LiftResult {
            ops: Vec::new(),
            bytes_consumed: prefix.cursor + modrm_bytes,
            control_flow: ControlFlow::Trap {
                kind: TrapKind::InvalidOpcode,
            },
            branch_targets: Vec::new(),
        }
    }

    /// Lift exact x87 environment/control, stack transfers, conversions, and
    /// the arithmetic families whose FCW-controlled binary80 semantics are
    /// represented explicitly in SMIR.
    pub(crate) fn lift_x87_escape(
        &self,
        opcode: u8,
        bytes: &[u8],
        prefix: &X86Prefix,
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        let modrm = decode_modrm(bytes, prefix, pc)?;
        if prefix.lock {
            return Ok(Self::x87_invalid_opcode(prefix, modrm.bytes_consumed));
        }

        let st = modrm.byte & 7;
        let fop = (((opcode & 7) as u16) << 8) | modrm.byte as u16;

        let form = x87_form(
            opcode,
            modrm.is_memory,
            modrm.byte,
            prefix.operand_size_override,
        );
        if let X87Form::Data(kind) = form {
            let mut ops = Vec::new();
            let addr = if modrm.is_memory {
                let next_pc = pc + prefix.cursor as u64 + modrm.bytes_consumed as u64;
                let (addr, pre_ops) =
                    self.x86_addr_to_smir(modrm.addr.as_ref().unwrap(), next_pc, ctx);
                ops.extend(pre_ops);
                Some(addr)
            } else {
                None
            };
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::X86X87Data {
                    kind,
                    addr,
                    st,
                    fop,
                },
            ));
            return Ok(LiftResult::fallthrough(
                ops,
                prefix.cursor + modrm.bytes_consumed,
            ));
        }

        let kind = match form {
            X87Form::Data(_) => unreachable!("x87 data forms returned above"),
            X87Form::Control(kind) => Some(kind),
            X87Form::NoOperation => None,
            X87Form::Invalid => {
                // Intel SDM Tables A-7 through A-22 leave every residual cell
                // blank. The direct engine injects #UD for these reserved
                // forms after decoding the complete ModR/M address, so expose
                // the same terminal frontier to strict SMIR.
                return Ok(Self::x87_invalid_opcode(prefix, modrm.bytes_consumed));
            }
        };

        let mut ops = if kind.is_none() {
            self.rex2_apx_guard_ops(prefix, pc)
        } else {
            Vec::new()
        };
        if let Some(kind) = kind {
            let addr = if modrm.is_memory {
                let next_pc = pc + prefix.cursor as u64 + modrm.bytes_consumed as u64;
                let (addr, pre_ops) =
                    self.x86_addr_to_smir(modrm.addr.as_ref().unwrap(), next_pc, ctx);
                ops.extend(pre_ops);
                Some(addr)
            } else {
                None
            };
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::X86X87Control { kind, addr },
            ));
        }

        Ok(LiftResult::fallthrough(
            ops,
            prefix.cursor + modrm.bytes_consumed,
        ))
    }
}

/// How an x87 escape instruction (`D8`-`DF` and its ModR/M byte) executes:
/// the one encoding table behind the SMIR lifter and the direct x86-64
/// engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X87Form {
    /// A data-stack operation on logical `ST(modrm & 7)`.
    Data(X86X87DataKind),
    /// An environment or control operation.
    Control(X86X87ControlKind),
    /// FNOP and the obsolete FENI, FDISI, and FSETPM encodings, which have no
    /// architectural state effect in the supported x86-64 profile.
    NoOperation,
    /// A reserved encoding (#UD).
    Invalid,
}

/// Classify escape `opcode` with ModR/M byte `modrm` (`is_memory` when its
/// mod field is not 11b); `operand_size_override` selects the 16-bit
/// environment formats.
pub(crate) fn x87_form(
    opcode: u8,
    is_memory: bool,
    modrm: u8,
    operand_size_override: bool,
) -> X87Form {
    let group = (modrm >> 3) & 7;
    let data_kind = match (opcode, is_memory, group, modrm) {
        (0xD8, true, 0, _) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Single,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: false,
            reverse: false,
        }),
        (0xDC, true, 0, _) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Double,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: false,
            reverse: false,
        }),
        (0xDE, true, 0, _) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Int16,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: false,
            reverse: false,
        }),
        (0xDA, true, 0, _) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Int32,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: false,
            reverse: false,
        }),
        (0xD8, true, group @ 4..=5, _) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Single,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: true,
            reverse: group == 5,
        }),
        (0xDC, true, group @ 4..=5, _) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Double,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: true,
            reverse: group == 5,
        }),
        (0xDE, true, group @ 4..=5, _) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Int16,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: true,
            reverse: group == 5,
        }),
        (0xDA, true, group @ 4..=5, _) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Int32,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: true,
            reverse: group == 5,
        }),
        (0xD8, true, group @ 6..=7, _) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Single,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            reverse: group == 7,
        }),
        (0xDC, true, group @ 6..=7, _) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Double,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            reverse: group == 7,
        }),
        (0xDE, true, group @ 6..=7, _) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Int16,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            reverse: group == 7,
        }),
        (0xDA, true, group @ 6..=7, _) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Int32,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            reverse: group == 7,
        }),
        (0xD8, true, 1, _) => Some(X86X87DataKind::Multiply {
            source: X86X87ArithmeticSource::Single,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
        }),
        (0xDC, true, 1, _) => Some(X86X87DataKind::Multiply {
            source: X86X87ArithmeticSource::Double,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
        }),
        (0xDE, true, 1, _) => Some(X86X87DataKind::Multiply {
            source: X86X87ArithmeticSource::Int16,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
        }),
        (0xDA, true, 1, _) => Some(X86X87DataKind::Multiply {
            source: X86X87ArithmeticSource::Int32,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
        }),
        (0xD9, true, 2, _) => Some(X86X87DataKind::StoreFloat {
            width: X86X87FloatWidth::F32,
            pop: false,
        }),
        (0xD9, true, 3, _) => Some(X86X87DataKind::StoreFloat {
            width: X86X87FloatWidth::F32,
            pop: true,
        }),
        (0xDD, true, 2, _) => Some(X86X87DataKind::StoreFloat {
            width: X86X87FloatWidth::F64,
            pop: false,
        }),
        (0xDD, true, 3, _) => Some(X86X87DataKind::StoreFloat {
            width: X86X87FloatWidth::F64,
            pop: true,
        }),
        (0xDF, true, 2, _) => Some(X86X87DataKind::StoreInteger {
            width: X86X87IntWidth::I16,
            pop: false,
            truncate: false,
        }),
        (0xDB, true, 2, _) => Some(X86X87DataKind::StoreInteger {
            width: X86X87IntWidth::I32,
            pop: false,
            truncate: false,
        }),
        (0xDF, true, 3, _) => Some(X86X87DataKind::StoreInteger {
            width: X86X87IntWidth::I16,
            pop: true,
            truncate: false,
        }),
        (0xDB, true, 3, _) => Some(X86X87DataKind::StoreInteger {
            width: X86X87IntWidth::I32,
            pop: true,
            truncate: false,
        }),
        (0xDF, true, 7, _) => Some(X86X87DataKind::StoreInteger {
            width: X86X87IntWidth::I64,
            pop: true,
            truncate: false,
        }),
        (0xDF, true, 1, _) => Some(X86X87DataKind::StoreInteger {
            width: X86X87IntWidth::I16,
            pop: true,
            truncate: true,
        }),
        (0xDB, true, 1, _) => Some(X86X87DataKind::StoreInteger {
            width: X86X87IntWidth::I32,
            pop: true,
            truncate: true,
        }),
        (0xDD, true, 1, _) => Some(X86X87DataKind::StoreInteger {
            width: X86X87IntWidth::I64,
            pop: true,
            truncate: true,
        }),
        (0xD8, true, 2, _) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Single,
            unordered: false,
            pop: 0,
            eflags: false,
        }),
        (0xD8, true, 3, _) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Single,
            unordered: false,
            pop: 1,
            eflags: false,
        }),
        (0xDC, true, 2, _) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Double,
            unordered: false,
            pop: 0,
            eflags: false,
        }),
        (0xDC, true, 3, _) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Double,
            unordered: false,
            pop: 1,
            eflags: false,
        }),
        (0xDE, true, 2, _) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Int16,
            unordered: false,
            pop: 0,
            eflags: false,
        }),
        (0xDE, true, 3, _) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Int16,
            unordered: false,
            pop: 1,
            eflags: false,
        }),
        (0xDA, true, 2, _) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Int32,
            unordered: false,
            pop: 0,
            eflags: false,
        }),
        (0xDA, true, 3, _) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Int32,
            unordered: false,
            pop: 1,
            eflags: false,
        }),
        (0xD8, false, _, 0xC8..=0xCF) => Some(X86X87DataKind::Multiply {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
        }),
        (0xDC, false, _, 0xC8..=0xCF) => Some(X86X87DataKind::Multiply {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: false,
        }),
        (0xDE, false, _, 0xC8..=0xCF) => Some(X86X87DataKind::Multiply {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: true,
        }),
        (0xD8, false, _, 0xC0..=0xC7) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: false,
            reverse: false,
        }),
        (0xDC, false, _, 0xC0..=0xC7) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: false,
            subtract: false,
            reverse: false,
        }),
        (0xDE, false, _, 0xC0..=0xC7) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: true,
            subtract: false,
            reverse: false,
        }),
        (0xD8, false, _, 0xE0..=0xE7) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: true,
            reverse: false,
        }),
        (0xDC, false, _, 0xE8..=0xEF) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: false,
            subtract: true,
            reverse: false,
        }),
        (0xDE, false, _, 0xE8..=0xEF) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: true,
            subtract: true,
            reverse: false,
        }),
        (0xD8, false, _, 0xE8..=0xEF) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            subtract: true,
            reverse: true,
        }),
        (0xDC, false, _, 0xE0..=0xE7) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: false,
            subtract: true,
            reverse: true,
        }),
        (0xDE, false, _, 0xE0..=0xE7) => Some(X86X87DataKind::AddSubtract {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: true,
            subtract: true,
            reverse: true,
        }),
        (0xD8, false, _, 0xF0..=0xF7) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            reverse: false,
        }),
        (0xDC, false, _, 0xF8..=0xFF) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: false,
            reverse: false,
        }),
        (0xDE, false, _, 0xF8..=0xFF) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: true,
            reverse: false,
        }),
        (0xD8, false, _, 0xF8..=0xFF) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::St0,
            pop: false,
            reverse: true,
        }),
        (0xDC, false, _, 0xF0..=0xF7) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: false,
            reverse: true,
        }),
        (0xDE, false, _, 0xF0..=0xF7) => Some(X86X87DataKind::Divide {
            source: X86X87ArithmeticSource::Register,
            destination: X86X87ArithmeticDestination::StI,
            pop: true,
            reverse: true,
        }),
        (0xD8, false, _, 0xD0..=0xD7) | (0xDC, false, _, 0xD0..=0xD7) => {
            Some(X86X87DataKind::Compare {
                source: X86X87CompareSource::Register,
                unordered: false,
                pop: 0,
                eflags: false,
            })
        }
        (0xD8, false, _, 0xD8..=0xDF)
        | (0xDC, false, _, 0xD8..=0xDF)
        | (0xDE, false, _, 0xD0..=0xD7) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: false,
            pop: 1,
            eflags: false,
        }),
        (0xDD, false, _, 0xE0..=0xE7) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: true,
            pop: 0,
            eflags: false,
        }),
        (0xDD, false, _, 0xE8..=0xEF) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: true,
            pop: 1,
            eflags: false,
        }),
        (0xDE, false, _, 0xD9) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: false,
            pop: 2,
            eflags: false,
        }),
        (0xDA, false, _, 0xE9) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: true,
            pop: 2,
            eflags: false,
        }),
        (0xDB, false, _, 0xE8..=0xEF) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: true,
            pop: 0,
            eflags: true,
        }),
        (0xDB, false, _, 0xF0..=0xF7) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: false,
            pop: 0,
            eflags: true,
        }),
        (0xDF, false, _, 0xE8..=0xEF) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: true,
            pop: 1,
            eflags: true,
        }),
        (0xDF, false, _, 0xF0..=0xF7) => Some(X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: false,
            pop: 1,
            eflags: true,
        }),
        (0xD9, true, 0, _) => Some(X86X87DataKind::LoadSingle),
        (0xDD, true, 0, _) => Some(X86X87DataKind::LoadDouble),
        (0xDF, true, 0, _) => Some(X86X87DataKind::LoadInt16),
        (0xDB, true, 0, _) => Some(X86X87DataKind::LoadInt32),
        (0xDF, true, 5, _) => Some(X86X87DataKind::LoadInt64),
        (0xDF, true, 4, _) => Some(X86X87DataKind::LoadBcd),
        (0xD9, false, _, 0xC0..=0xC7) => Some(X86X87DataKind::LoadRegister),
        (0xDB, true, 5, _) => Some(X86X87DataKind::LoadExtended),
        (0xDD, false, _, 0xD0..=0xD7) => Some(X86X87DataKind::StoreRegister),
        (0xDD, false, _, 0xD8..=0xDF) | (0xDF, false, _, 0xD0..=0xD7) => {
            Some(X86X87DataKind::StorePopRegister)
        }
        (0xDB, true, 7, _) => Some(X86X87DataKind::StorePopExtended),
        (0xDF, true, 6, _) => Some(X86X87DataKind::StoreBcd),
        (0xD9, false, _, 0xC8..=0xCF) | (0xDD, false, _, 0xC8..=0xCF) => {
            Some(X86X87DataKind::Exchange)
        }
        (0xDD, false, _, 0xC0..=0xC7) => Some(X86X87DataKind::Free),
        (0xDF, false, _, 0xC0..=0xC7) => Some(X86X87DataKind::FreePop),
        (0xD9, false, _, 0xE0) => Some(X86X87DataKind::ChangeSign),
        (0xD9, false, _, 0xE1) => Some(X86X87DataKind::Absolute),
        (0xD9, false, _, 0xE4) => Some(X86X87DataKind::TestZero),
        (0xD9, false, _, 0xE5) => Some(X86X87DataKind::Examine),
        (0xD9, false, _, 0xF4) => Some(X86X87DataKind::Extract),
        (0xD9, false, _, 0xF0) => Some(X86X87DataKind::Transcendental(
            X86X87TranscendentalKind::Exp2MinusOne,
        )),
        (0xD9, false, _, 0xF1) => Some(X86X87DataKind::Transcendental(
            X86X87TranscendentalKind::YLog2X,
        )),
        (0xD9, false, _, 0xF2) => Some(X86X87DataKind::Transcendental(
            X86X87TranscendentalKind::Tangent,
        )),
        (0xD9, false, _, 0xF3) => Some(X86X87DataKind::Transcendental(
            X86X87TranscendentalKind::Arctangent,
        )),
        (0xD9, false, _, 0xF5) => Some(X86X87DataKind::Remainder { nearest: true }),
        (0xD9, false, _, 0xF8) => Some(X86X87DataKind::Remainder { nearest: false }),
        (0xD9, false, _, 0xF9) => Some(X86X87DataKind::Transcendental(
            X86X87TranscendentalKind::YLog2Xp1,
        )),
        (0xD9, false, _, 0xFA) => Some(X86X87DataKind::SquareRoot),
        (0xD9, false, _, 0xFB) => Some(X86X87DataKind::Transcendental(
            X86X87TranscendentalKind::SineCosine,
        )),
        (0xD9, false, _, 0xFC) => Some(X86X87DataKind::RoundInteger),
        (0xD9, false, _, 0xFD) => Some(X86X87DataKind::Scale),
        (0xD9, false, _, 0xFE) => Some(X86X87DataKind::Transcendental(
            X86X87TranscendentalKind::Sine,
        )),
        (0xD9, false, _, 0xFF) => Some(X86X87DataKind::Transcendental(
            X86X87TranscendentalKind::Cosine,
        )),
        (0xD9, false, _, 0xF6) => Some(X86X87DataKind::DecrementTop),
        (0xD9, false, _, 0xF7) => Some(X86X87DataKind::IncrementTop),
        (0xD9, false, _, 0xE8) => Some(X86X87DataKind::LoadConstant(X86X87Constant::One)),
        (0xD9, false, _, 0xE9) => Some(X86X87DataKind::LoadConstant(X86X87Constant::Log2Ten)),
        (0xD9, false, _, 0xEA) => Some(X86X87DataKind::LoadConstant(X86X87Constant::Log2E)),
        (0xD9, false, _, 0xEB) => Some(X86X87DataKind::LoadConstant(X86X87Constant::Pi)),
        (0xD9, false, _, 0xEC) => Some(X86X87DataKind::LoadConstant(X86X87Constant::Log10Two)),
        (0xD9, false, _, 0xED) => Some(X86X87DataKind::LoadConstant(X86X87Constant::LnTwo)),
        (0xD9, false, _, 0xEE) => Some(X86X87DataKind::LoadConstant(X86X87Constant::Zero)),
        (0xDA, false, _, 0xC0..=0xC7) => Some(X86X87DataKind::ConditionalMove(Condition::Ult)),
        (0xDA, false, _, 0xC8..=0xCF) => Some(X86X87DataKind::ConditionalMove(Condition::Eq)),
        (0xDA, false, _, 0xD0..=0xD7) => Some(X86X87DataKind::ConditionalMove(Condition::Ule)),
        (0xDA, false, _, 0xD8..=0xDF) => Some(X86X87DataKind::ConditionalMove(Condition::Parity)),
        (0xDB, false, _, 0xC0..=0xC7) => Some(X86X87DataKind::ConditionalMove(Condition::Uge)),
        (0xDB, false, _, 0xC8..=0xCF) => Some(X86X87DataKind::ConditionalMove(Condition::Ne)),
        (0xDB, false, _, 0xD0..=0xD7) => Some(X86X87DataKind::ConditionalMove(Condition::Ugt)),
        (0xDB, false, _, 0xD8..=0xDF) => Some(X86X87DataKind::ConditionalMove(Condition::NoParity)),
        _ => None,
    };
    if let Some(kind) = data_kind {
        return X87Form::Data(kind);
    }

    let env_width = if operand_size_override {
        X86X87EnvWidth::W16
    } else {
        X86X87EnvWidth::W32
    };
    match (opcode, is_memory, group, modrm) {
        (0xD9, true, 4, _) => X87Form::Control(X86X87ControlKind::LoadEnvironment(env_width)),
        (0xD9, true, 5, _) => X87Form::Control(X86X87ControlKind::LoadControlWord),
        (0xD9, true, 6, _) => X87Form::Control(X86X87ControlKind::StoreEnvironment(env_width)),
        (0xD9, true, 7, _) => X87Form::Control(X86X87ControlKind::StoreControlWord),
        (0xDD, true, 4, _) => X87Form::Control(X86X87ControlKind::RestoreState(env_width)),
        (0xDD, true, 6, _) => X87Form::Control(X86X87ControlKind::SaveState(env_width)),
        (0xDD, true, 7, _) => X87Form::Control(X86X87ControlKind::StoreStatusWord),
        (0xDB, false, _, 0xE2) => X87Form::Control(X86X87ControlKind::ClearExceptions),
        (0xDB, false, _, 0xE3) => X87Form::Control(X86X87ControlKind::Init),
        (0xDF, false, _, 0xE0) => X87Form::Control(X86X87ControlKind::StoreStatusAx),
        // FNOP and the obsolete FENI, FDISI, and FSETPM encodings have no
        // architectural state effect in the supported x86-64 profile.
        (0xD9, false, _, 0xD0)
        | (0xDB, false, _, 0xE0)
        | (0xDB, false, _, 0xE1)
        | (0xDB, false, _, 0xE4) => X87Form::NoOperation,
        // Intel SDM Tables A-7 through A-22 leave every residual cell blank.
        _ => X87Form::Invalid,
    }
}
