//! Scalar modifying MMIO plans and architectural completion after the device
//! transaction. No device callback or SDK register mutation occurs in planning.
use serde::{Deserialize, Serialize};

use super::PhysicalMemory;
use super::{
    Action, Context, ExitRecord, Flow, Instruction, Operand, OperandKind, Plan, RegisterPart,
};
use crate::devices::bus::MmioRmwOp;
use crate::isa::x86_64::flags::{self, bits};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum FlagEffect {
    Preserve,
    Add,
    Adc,
    Subtract,
    Sbb,
    Logic,
    Increment,
    Decrement,
    Negate,
    Compare,
    Bit(u8),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RmwInput {
    pub(crate) size: u8,
    pub(crate) operation: MmioRmwOp,
    length: u64,
    flags_before: u64,
    flags: FlagEffect,
    /// A source register receives the old memory operand (XCHG/XADD), or
    /// the accumulator receives it only on a failed comparison (CMPXCHG).
    register: Option<(RegisterPart, u64)>,
}

impl RmwInput {
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.operation
            .validate(self.size)
            .map_err(|e| e.to_string())?;
        if !(1..=15).contains(&self.length) {
            return Err("invalid RMW instruction length".into());
        }
        if let FlagEffect::Bit(bit) = self.flags {
            if u32::from(bit) >= u32::from(self.size) * 8 {
                return Err("invalid RMW flag bit".into());
            }
        }
        let carry = self.flags_before & bits::CF != 0;
        let compatible = match (self.flags, self.operation) {
            (FlagEffect::Preserve, MmioRmwOp::Exchange(_)) => self.register.is_some(),
            (FlagEffect::Preserve, MmioRmwOp::Not) => self.register.is_none(),
            (FlagEffect::Add, MmioRmwOp::Add { carry: false, .. }) => true,
            (FlagEffect::Adc, MmioRmwOp::Add { carry: actual, .. }) => {
                actual == carry && self.register.is_none()
            }
            (FlagEffect::Subtract, MmioRmwOp::Subtract { borrow: false, .. }) => {
                self.register.is_none()
            }
            (FlagEffect::Sbb, MmioRmwOp::Subtract { borrow, .. }) => {
                borrow == carry && self.register.is_none()
            }
            (FlagEffect::Logic, MmioRmwOp::And(_) | MmioRmwOp::Or(_) | MmioRmwOp::Xor(_)) => {
                self.register.is_none()
            }
            (
                FlagEffect::Increment,
                MmioRmwOp::Add {
                    value: 1,
                    carry: false,
                },
            ) => self.register.is_none(),
            (
                FlagEffect::Decrement,
                MmioRmwOp::Subtract {
                    value: 1,
                    borrow: false,
                },
            ) => self.register.is_none(),
            (FlagEffect::Negate, MmioRmwOp::Negate) => self.register.is_none(),
            (FlagEffect::Compare, MmioRmwOp::CompareExchange { expected, .. }) => {
                self.register.is_some_and(|(part, original)| {
                    part.index == 0
                        && part.shift == 0
                        && expected == original & (u64::MAX >> (64 - u32::from(self.size) * 8))
                })
            }
            (
                FlagEffect::Bit(expected),
                MmioRmwOp::BitSet(actual)
                | MmioRmwOp::BitReset(actual)
                | MmioRmwOp::BitComplement(actual),
            ) => expected == actual && self.register.is_none(),
            _ => false,
        };
        if !compatible {
            return Err("RMW flag effect differs from the device operation".into());
        }
        if let Some((part, _)) = self.register {
            if !part.valid() || part.bits != u32::from(self.size) * 8 {
                return Err("invalid RMW register writeback".into());
            }
        }
        Ok(())
    }

    pub(crate) fn completion(
        &self,
        data: &[u8],
    ) -> Result<(Option<(usize, u64)>, Option<u64>, u64), String> {
        self.validate()?;
        if data.len() != usize::from(self.size) {
            return Err("MMIO RMW completion width differs from request".into());
        }
        let mut raw = [0; 8];
        raw[..data.len()].copy_from_slice(data);
        let old = u64::from_le_bytes(raw);
        let mut updated = data.to_vec();
        self.operation
            .apply(&mut updated)
            .map_err(|e| e.to_string())?;
        raw.fill(0);
        raw[..updated.len()].copy_from_slice(&updated);
        let result = u64::from_le_bytes(raw);
        let mut rflags = self.flags_before;
        let operand = match self.operation {
            MmioRmwOp::Add { value, .. } | MmioRmwOp::Subtract { value, .. } => value,
            _ => 0,
        };
        match self.flags {
            FlagEffect::Preserve => (),
            FlagEffect::Add | FlagEffect::Increment => {
                flags::update_flags_add(&mut rflags, old, operand, result, self.size);
            }
            FlagEffect::Adc => flags::update_flags_adc(
                &mut rflags,
                old,
                operand,
                self.flags_before & bits::CF != 0,
                result,
                self.size,
            ),
            FlagEffect::Subtract | FlagEffect::Decrement => {
                flags::update_flags_sub(&mut rflags, old, operand, result, self.size);
            }
            FlagEffect::Sbb => flags::update_flags_sbb(
                &mut rflags,
                old,
                operand,
                self.flags_before & bits::CF != 0,
                result,
                self.size,
            ),
            FlagEffect::Logic => flags::update_flags_logic(&mut rflags, result, self.size),
            FlagEffect::Negate => flags::update_flags_sub(&mut rflags, 0, old, result, self.size),
            FlagEffect::Compare => {
                let MmioRmwOp::CompareExchange { expected, .. } = self.operation else {
                    return Err("inconsistent CMPXCHG completion".into());
                };
                flags::update_flags_sub(
                    &mut rflags,
                    expected,
                    old,
                    expected.wrapping_sub(old),
                    self.size,
                );
            }
            FlagEffect::Bit(bit) => {
                rflags = (rflags & !bits::CF) | u64::from(old & (1u64 << bit) != 0);
            }
        }
        if matches!(self.flags, FlagEffect::Increment | FlagEffect::Decrement) {
            rflags = (rflags & !bits::CF) | (self.flags_before & bits::CF);
        }
        let register = self.register.and_then(|(part, original)| {
            if let MmioRmwOp::CompareExchange { expected, .. } = self.operation {
                let mask = u64::MAX >> (64 - u32::from(self.size) * 8);
                if old == expected & mask {
                    return None;
                }
            }
            Some((part.index, part.merge(original, old)))
        });
        let flags = (!matches!(self.flags, FlagEffect::Preserve)).then_some(rflags);
        Ok((register, flags, self.length))
    }
}

fn source(
    context: &Context,
    operand: &Operand,
    size: u8,
) -> Result<(u64, Option<RegisterPart>), String> {
    match operand.kind {
        OperandKind::Immediate => Ok((operand.value, None)),
        OperandKind::Register => {
            let part =
                RegisterPart::parse(&operand.reg).ok_or("unsupported MMIO RMW source register")?;
            if part.bits != u32::from(size) * 8 || part.bits != operand.width_bits {
                return Err("inconsistent MMIO RMW source width".into());
            }
            Ok((part.value(&context.registers), Some(part)))
        }
        _ => Err("unsupported MMIO RMW source".into()),
    }
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
) -> Result<Option<Plan>, String> {
    let mnemonic = instruction.mnemonic.as_str();
    if !matches!(
        mnemonic,
        "add"
            | "adc"
            | "sub"
            | "sbb"
            | "and"
            | "or"
            | "xor"
            | "inc"
            | "dec"
            | "not"
            | "neg"
            | "xchg"
            | "xadd"
            | "cmpxchg"
            | "bts"
            | "btr"
            | "btc"
    ) {
        return Ok(None);
    }
    if !instruction.operands_complete || instruction.flow != Flow::Next {
        return Err("incomplete MMIO RMW instruction effects".into());
    }
    let Some(operand) = instruction.operands.first() else {
        return Err("missing MMIO RMW destination".into());
    };
    if operand.kind != OperandKind::Memory || !operand.read || !operand.write {
        return Ok(None);
    }
    // SDM29.2.1: RMW always sets write; its read bit is implementation-specific.
    if record.qualification & 2 == 0 {
        return Err("MMIO RMW EPT record lacks its required write bit".into());
    }
    let size = match operand.width_bits {
        8 => 1,
        16 => 2,
        32 => 4,
        64 => 8,
        _ => return Err("unsupported MMIO RMW width".into()),
    };
    let unary = matches!(mnemonic, "inc" | "dec" | "not" | "neg");
    if instruction.operands.len() != if unary { 1 } else { 2 }
        || instruction.operands.iter().any(|o| o.conditional)
    {
        return Err("unsupported MMIO RMW operand effects".into());
    }
    let (value, part) = if unary {
        (0, None)
    } else {
        let other = &instruction.operands[1];
        if !other.read || (other.write && !matches!(mnemonic, "xchg" | "xadd")) {
            return Err("unsupported MMIO RMW source effects".into());
        }
        source(context, other, size)?
    };
    let carry = context.rflags & bits::CF != 0;
    let mut operand = operand.clone();
    let mut register = None;
    let (operation, flags) = match mnemonic {
        "add" => (
            MmioRmwOp::Add {
                value,
                carry: false,
            },
            FlagEffect::Add,
        ),
        "adc" => (MmioRmwOp::Add { value, carry }, FlagEffect::Adc),
        "sub" => (
            MmioRmwOp::Subtract {
                value,
                borrow: false,
            },
            FlagEffect::Subtract,
        ),
        "sbb" => (
            MmioRmwOp::Subtract {
                value,
                borrow: carry,
            },
            FlagEffect::Sbb,
        ),
        "and" => (MmioRmwOp::And(value), FlagEffect::Logic),
        "or" => (MmioRmwOp::Or(value), FlagEffect::Logic),
        "xor" => (MmioRmwOp::Xor(value), FlagEffect::Logic),
        "inc" => (
            MmioRmwOp::Add {
                value: 1,
                carry: false,
            },
            FlagEffect::Increment,
        ),
        "dec" => (
            MmioRmwOp::Subtract {
                value: 1,
                borrow: false,
            },
            FlagEffect::Decrement,
        ),
        "not" => (MmioRmwOp::Not, FlagEffect::Preserve),
        "neg" => (MmioRmwOp::Negate, FlagEffect::Negate),
        "xchg" | "xadd" => {
            let part = part.ok_or("MMIO exchange source must be a register")?;
            register = Some((part, context.registers[part.index]));
            if mnemonic == "xchg" {
                (MmioRmwOp::Exchange(value), FlagEffect::Preserve)
            } else {
                (
                    MmioRmwOp::Add {
                        value,
                        carry: false,
                    },
                    FlagEffect::Add,
                )
            }
        }
        "cmpxchg" => {
            part.ok_or("CMPXCHG source must be a register")?;
            let accumulator = RegisterPart {
                index: 0,
                bits: u32::from(size) * 8,
                shift: 0,
            };
            register = Some((accumulator, context.registers[0]));
            (
                MmioRmwOp::CompareExchange {
                    expected: accumulator.value(&context.registers),
                    replacement: value,
                },
                FlagEffect::Compare,
            )
        }
        "bts" | "btr" | "btc" => {
            // Register bit strings adjust the address by a signed word offset.
            // An immediate selects only a bit within the addressed operand.
            if instruction.operands[1].kind == OperandKind::Register {
                let shift = 64 - u32::from(size) * 8;
                let signed = ((value << shift) as i64) >> shift;
                let words = signed.div_euclid(i64::from(size) * 8);
                operand.displacement = operand
                    .displacement
                    .wrapping_add((words * i64::from(size)) as u64);
            }
            let bit = (value & (u64::from(size) * 8 - 1)) as u8;
            let op = match mnemonic {
                "bts" => MmioRmwOp::BitSet(bit),
                "btr" => MmioRmwOp::BitReset(bit),
                _ => MmioRmwOp::BitComplement(bit),
            };
            (op, FlagEffect::Bit(bit))
        }
        _ => return Err("unsupported MMIO RMW operation".into()),
    };
    super::validate_memory(context, memory, record, &operand, size)?;
    let input = RmwInput {
        size,
        operation,
        length: u64::from(instruction.size),
        flags_before: context.rflags,
        flags,
        register,
    };
    input.validate()?;
    Ok(Some(Plan {
        physical: record.physical,
        length: u64::from(instruction.size),
        action: Action::Rmw(input),
    }))
}
