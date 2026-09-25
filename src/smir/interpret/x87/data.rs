//! x87 data-stack operations on an explicit x87 state: the one
//! implementation that both the SMIR interpreter and the direct x86-64
//! engine execute.

use super::stack_metadata;

use crate::smir::interpret::*;
use std::cmp::Ordering;
use std::collections::HashMap;

use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext, VecValue};
use crate::smir::ir::flags::{FlagSet, FlagUpdate, LazyFlagOp, LazyFlags};
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::ops::{
    HexFpOp, HexFpRecipKind, OpKind, RvVectorState, SmirOp, X86AdxKind, X86BlsKind,
    X86CacheControlKind, X86CountKind, X86OpHint, X86ThreeDNowKind, X86X87ArithmeticDestination,
    X86X87ArithmeticSource, X86X87CompareSource, X86X87Constant, X86X87ControlKind, X86X87DataKind,
    X86X87EnvWidth, X86X87FloatWidth, X86X87IntWidth, X86X87TranscendentalKind, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

/// The RFLAGS effect of an FCOMI, FCOMIP, FUCOMI, or FUCOMIP: OF, SF, and AF
/// are cleared, and ZF, PF, and CF are set from the C3, C2, and C0 bits of
/// `codes` when the comparison completed (an unmasked invalid-operation or
/// stack fault leaves them unchanged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X87EflagsUpdate {
    pub(crate) codes: Option<u16>,
}

/// The guest memory an x87 data operation reads and writes: SMIR memory, or
/// the direct engine's memory with its own fault reporting.
pub(crate) trait X87Memory {
    /// Read `buf.len()` bytes at `addr`.
    fn read_x87(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError>;
    /// Write `data` at `addr`.
    fn write_x87(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), MemoryError>;
}

impl<T: SmirMemory + ?Sized> X87Memory for T {
    fn read_x87(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        self.read(addr, buf)
    }

    fn write_x87(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), MemoryError> {
        self.write(addr, data)
    }
}

impl SmirInterpreter {
    /// Execute one x87 data operation on `x87`. Memory operands are read
    /// before any state changes and stores are written before `x87` is
    /// updated, so a memory error leaves `x87` as it was. FCMOVcc takes its
    /// evaluated condition in `conditional_move_taken`; the FCOMI family
    /// returns its RFLAGS effect.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn x86_x87_data_step<M: X87Memory + ?Sized>(
        x87: &mut crate::smir::X86X87State,
        memory: &mut M,
        guest_pc: GuestAddr,
        kind: X86X87DataKind,
        effective_addr: Option<u64>,
        st: u8,
        fop: u16,
        conditional_move_taken: Option<bool>,
    ) -> Result<Option<X87EflagsUpdate>, MemoryError> {
        let mut eflags_update = None;

        // FLD reads the complete source before changing TOP or any environment
        // field. This also makes a memory fault restartable.
        let loaded = match kind {
            X86X87DataKind::LoadSingle => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FLD m32fp requires an address"),
                    &mut source[..4],
                )?;
                Some(source)
            }
            X86X87DataKind::LoadDouble => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FLD m64fp requires an address"),
                    &mut source[..8],
                )?;
                Some(source)
            }
            X86X87DataKind::Compare {
                source: X86X87CompareSource::Single,
                ..
            } => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FCOM m32fp requires an address"),
                    &mut source[..4],
                )?;
                Some(source)
            }
            X86X87DataKind::Compare {
                source: X86X87CompareSource::Double,
                ..
            } => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FCOM m64fp requires an address"),
                    &mut source[..8],
                )?;
                Some(source)
            }
            X86X87DataKind::Compare {
                source: X86X87CompareSource::Int16,
                ..
            } => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FICOM m16int requires an address"),
                    &mut source[..2],
                )?;
                Some(source)
            }
            X86X87DataKind::Compare {
                source: X86X87CompareSource::Int32,
                ..
            } => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FICOM m32int requires an address"),
                    &mut source[..4],
                )?;
                Some(source)
            }
            X86X87DataKind::Multiply {
                source: X86X87ArithmeticSource::Single,
                ..
            }
            | X86X87DataKind::AddSubtract {
                source: X86X87ArithmeticSource::Single,
                ..
            }
            | X86X87DataKind::Divide {
                source: X86X87ArithmeticSource::Single,
                ..
            } => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FMUL m32fp requires an address"),
                    &mut source[..4],
                )?;
                Some(source)
            }
            X86X87DataKind::Multiply {
                source: X86X87ArithmeticSource::Double,
                ..
            }
            | X86X87DataKind::AddSubtract {
                source: X86X87ArithmeticSource::Double,
                ..
            }
            | X86X87DataKind::Divide {
                source: X86X87ArithmeticSource::Double,
                ..
            } => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FMUL m64fp requires an address"),
                    &mut source[..8],
                )?;
                Some(source)
            }
            X86X87DataKind::Multiply {
                source: X86X87ArithmeticSource::Int16,
                ..
            }
            | X86X87DataKind::AddSubtract {
                source: X86X87ArithmeticSource::Int16,
                ..
            }
            | X86X87DataKind::Divide {
                source: X86X87ArithmeticSource::Int16,
                ..
            } => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FIMUL m16int requires an address"),
                    &mut source[..2],
                )?;
                Some(source)
            }
            X86X87DataKind::Multiply {
                source: X86X87ArithmeticSource::Int32,
                ..
            }
            | X86X87DataKind::AddSubtract {
                source: X86X87ArithmeticSource::Int32,
                ..
            }
            | X86X87DataKind::Divide {
                source: X86X87ArithmeticSource::Int32,
                ..
            } => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FIMUL m32int requires an address"),
                    &mut source[..4],
                )?;
                Some(source)
            }
            X86X87DataKind::LoadExtended => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FLD m80fp requires an address"),
                    &mut source,
                )?;
                Some(source)
            }
            X86X87DataKind::LoadInt16 => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FILD m16int requires an address"),
                    &mut source[..2],
                )?;
                Some(source)
            }
            X86X87DataKind::LoadInt32 => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FILD m32int requires an address"),
                    &mut source[..4],
                )?;
                Some(source)
            }
            X86X87DataKind::LoadInt64 => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FILD m64int requires an address"),
                    &mut source[..8],
                )?;
                Some(source)
            }
            X86X87DataKind::LoadBcd => {
                let mut source = [0u8; 10];
                memory.read_x87(
                    effective_addr.expect("FBLD m80bcd requires an address"),
                    &mut source,
                )?;
                Some(source)
            }
            _ => None,
        };

        let original = x87.clone();
        let mut next = original.clone();
        next.instr_ptr = guest_pc;
        next.last_opcode = fop & 0x07FF;
        if let Some(address) = effective_addr {
            next.data_ptr = address;
        }

        match kind {
            X86X87DataKind::LoadRegister
            | X86X87DataKind::LoadSingle
            | X86X87DataKind::LoadDouble
            | X86X87DataKind::LoadExtended
            | X86X87DataKind::LoadInt16
            | X86X87DataKind::LoadInt32
            | X86X87DataKind::LoadInt64
            | X86X87DataKind::LoadBcd
            | X86X87DataKind::LoadConstant(_) => {
                let source = if kind == X86X87DataKind::LoadRegister {
                    let physical = original.physical_index(st);
                    Some((original.regs[physical], original.physical_tag(physical)))
                } else {
                    None
                };
                let underflow = source.is_some_and(|(_, tag)| tag == 3);
                let new_top = original.top().wrapping_sub(1) & 7;
                let overflow = original.physical_tag(new_top as usize) != 3;

                if underflow || overflow {
                    // Intel exception precedence gives stack underflow priority
                    // over stack overflow when both conditions are present.
                    let masked = next.signal_stack_fault(!underflow && overflow);
                    if !masked {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.set_top(new_top);
                    next.set_logical_raw_tagged(0, crate::smir::X86X87State::INDEFINITE, 2);
                } else {
                    next.status_word &= !0x0200; // C1=0: no stack overflow
                    next.set_top(new_top);
                    if let Some((raw, tag)) = source {
                        next.set_logical_raw_tagged(0, raw, tag);
                    } else if let X86X87DataKind::LoadConstant(constant) = kind {
                        next.set_logical_raw(
                            0,
                            Self::x86_x87_constant(constant, original.control_word),
                        );
                    } else if kind == X86X87DataKind::LoadBcd {
                        let source = loaded.expect("FBLD source missing");
                        let mut magnitude = 0u64;
                        for byte in source[..9].iter().rev() {
                            magnitude = magnitude * 10 + u64::from(byte >> 4);
                            magnitude = magnitude * 10 + u64::from(byte & 0x0F);
                        }
                        // Bits 78:72 are architecturally ignored. Invalid BCD
                        // digits produce an undefined value without #IA; the
                        // deterministic nibble interpretation here is one
                        // permitted result for that undefined input domain.
                        next.set_logical_raw(
                            0,
                            Self::x86_x87_from_signed_magnitude(magnitude, source[9] & 0x80 != 0),
                        );
                    } else if matches!(
                        kind,
                        X86X87DataKind::LoadSingle | X86X87DataKind::LoadDouble
                    ) {
                        let source = loaded.expect("FLD narrow source missing");
                        let bits = if kind == X86X87DataKind::LoadSingle {
                            u32::from_le_bytes(source[..4].try_into().unwrap()) as u64
                        } else {
                            u64::from_le_bytes(source[..8].try_into().unwrap())
                        };
                        let (raw, signaling_nan, denormal) = if kind == X86X87DataKind::LoadSingle {
                            Self::x86_x87_widen_ieee(bits, 8, 23)
                        } else {
                            Self::x86_x87_widen_ieee(bits, 11, 52)
                        };
                        if signaling_nan {
                            next.status_word |= 0x0001; // IE
                            if next.control_word & 0x0001 == 0 {
                                next.status_word |= 0x8080; // B | ES
                                next.set_top(original.top());
                                *x87 = next;
                                return Ok(eflags_update);
                            }
                        }
                        if denormal {
                            next.status_word |= 0x0002; // DE
                            // FLD is exceptional: even with DM clear, Intel
                            // specifies that the denormal value is still pushed.
                            if next.control_word & 0x0002 == 0 {
                                next.status_word |= 0x8080; // B | ES
                            }
                        }
                        next.set_logical_raw(0, raw);
                    } else if matches!(
                        kind,
                        X86X87DataKind::LoadInt16
                            | X86X87DataKind::LoadInt32
                            | X86X87DataKind::LoadInt64
                    ) {
                        let source = loaded.expect("FILD source missing");
                        let value = match kind {
                            X86X87DataKind::LoadInt16 => {
                                i16::from_le_bytes(source[..2].try_into().unwrap()) as i64
                            }
                            X86X87DataKind::LoadInt32 => {
                                i32::from_le_bytes(source[..4].try_into().unwrap()) as i64
                            }
                            X86X87DataKind::LoadInt64 => {
                                i64::from_le_bytes(source[..8].try_into().unwrap())
                            }
                            _ => unreachable!(),
                        };
                        next.set_logical_raw(0, Self::x86_x87_from_i64(value));
                    } else {
                        next.set_logical_raw(0, loaded.expect("FLD m80fp source missing"));
                    }
                }
            }
            X86X87DataKind::StoreRegister | X86X87DataKind::StorePopRegister => {
                let source_physical = original.physical_index(0);
                let empty = original.physical_tag(source_physical) == 3;
                let (raw, tag) = if empty {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    (crate::smir::X86X87State::INDEFINITE, 2)
                } else {
                    next.status_word &= !0x0200;
                    (
                        original.regs[source_physical],
                        original.physical_tag(source_physical),
                    )
                };
                next.set_logical_raw_tagged(st, raw, tag);
                if kind == X86X87DataKind::StorePopRegister {
                    next.pop();
                }
            }
            X86X87DataKind::StorePopExtended => {
                let source_physical = original.physical_index(0);
                let empty = original.physical_tag(source_physical) == 3;
                let raw = if empty {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    crate::smir::X86X87State::INDEFINITE
                } else {
                    next.status_word &= !0x0200;
                    original.regs[source_physical]
                };
                next.pop();
                // Commit the pop, environment, and any masked stack-fault flags
                // only after the complete ten-byte store succeeds.
                memory.write_x87(
                    effective_addr.expect("FSTP m80fp requires an address"),
                    &raw,
                )?;
            }
            X86X87DataKind::StoreInteger {
                width,
                pop,
                truncate,
            } => {
                let physical = original.physical_index(0);
                let width_bits: u32 = match width {
                    X86X87IntWidth::I16 => 16,
                    X86X87IntWidth::I32 => 32,
                    X86X87IntWidth::I64 => 64,
                };
                let indefinite = 1u64 << (width_bits - 1);
                let value = if original.physical_tag(physical) == 3 {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    indefinite
                } else {
                    let conversion = Self::x86_x87_to_integer(
                        &original.regs[physical],
                        width_bits,
                        if truncate {
                            3
                        } else {
                            (original.control_word >> 10) & 3
                        },
                    );
                    if conversion.invalid {
                        next.status_word |= 0x0001; // IE
                        next.status_word &= !0x0200; // C1=0
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                        indefinite
                    } else {
                        next.status_word &= !0x0200;
                        if conversion.inexact {
                            next.status_word |= 0x0020; // PE
                            if !truncate && conversion.rounded_up {
                                next.status_word |= 0x0200; // C1 roundup
                            }
                            if next.control_word & 0x0020 == 0 {
                                next.status_word |= 0x8080; // B | ES
                            }
                        }
                        conversion.value
                    }
                };
                if pop {
                    next.pop();
                }
                let bytes = value.to_le_bytes();
                let len = (width_bits / 8) as usize;
                memory.write_x87(
                    effective_addr.expect("FIST/FISTP/FISTTP requires an address"),
                    &bytes[..len],
                )?;
            }
            X86X87DataKind::StoreFloat { width, pop } => {
                let physical = original.physical_index(0);
                let (fraction_bits, exponent_bits, indefinite, len) = match width {
                    X86X87FloatWidth::F32 => (23, 8, 0xFFC0_0000u64, 4usize),
                    X86X87FloatWidth::F64 => (52, 11, 0xFFF8_0000_0000_0000u64, 8usize),
                };
                next.status_word &= !0x0200; // C1=0 unless rounded upward
                let bits = if original.physical_tag(physical) == 3 {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    indefinite
                } else {
                    let conversion = Self::x86_x87_to_ieee(
                        &original.regs[physical],
                        exponent_bits,
                        fraction_bits,
                        (original.control_word >> 10) & 3,
                    );
                    if conversion.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if conversion.overflow {
                        next.status_word |= 0x0008; // OE
                        if next.control_word & 0x0008 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if conversion.underflow {
                        next.status_word |= 0x0010; // UE
                        if next.control_word & 0x0010 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    }

                    if !conversion.invalid && conversion.inexact {
                        next.status_word |= 0x0020; // PE
                        if conversion.rounded_up {
                            next.status_word |= 0x0200; // C1 roundup
                        }
                        if next.control_word & 0x0020 == 0 {
                            next.status_word |= 0x8080; // B | ES
                        }
                    }
                    conversion.bits
                };
                if pop {
                    next.pop();
                }
                memory.write_x87(
                    effective_addr.expect("FST/FSTP requires an address"),
                    &bits.to_le_bytes()[..len],
                )?;
            }
            X86X87DataKind::StoreBcd => {
                const MAX_BCD: u64 = 999_999_999_999_999_999;
                const BCD_INDEFINITE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF, 0xFF];

                let physical = original.physical_index(0);
                next.status_word &= !0x0200; // C1=0 unless rounded upward
                let output = if original.physical_tag(physical) == 3 {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    BCD_INDEFINITE
                } else {
                    let raw = &original.regs[physical];
                    let info = Self::x86_x87_raw_info(raw);
                    let conversion =
                        Self::x86_x87_to_integer(raw, 64, (original.control_word >> 10) & 3);
                    let magnitude = if conversion.invalid {
                        0
                    } else if info.sign {
                        (conversion.value as i64).unsigned_abs()
                    } else {
                        conversion.value
                    };
                    let invalid = conversion.invalid || magnitude > MAX_BCD;
                    if invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                        BCD_INDEFINITE
                    } else {
                        if conversion.inexact {
                            next.status_word |= 0x0020; // PE
                            if conversion.rounded_up {
                                next.status_word |= 0x0200; // C1 roundup
                            }
                            if next.control_word & 0x0020 == 0 {
                                next.status_word |= 0x8080; // B | ES
                            }
                        }
                        let mut bcd = [0u8; 10];
                        let mut remaining = magnitude;
                        for byte in &mut bcd[..9] {
                            let low = (remaining % 10) as u8;
                            remaining /= 10;
                            let high = (remaining % 10) as u8;
                            remaining /= 10;
                            *byte = (high << 4) | low;
                        }
                        bcd[9] = u8::from(info.sign) << 7;
                        bcd
                    }
                };
                next.pop();
                memory.write_x87(
                    effective_addr.expect("FBSTP m80bcd requires an address"),
                    &output,
                )?;
            }
            X86X87DataKind::Exchange => {
                let p0 = original.physical_index(0);
                let pi = original.physical_index(st);
                let empty0 = original.physical_tag(p0) == 3;
                let emptyi = original.physical_tag(pi) == 3;
                if empty0 || emptyi {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    if empty0 {
                        next.regs[p0] = crate::smir::X86X87State::INDEFINITE;
                        next.set_physical_tag(p0, 2);
                    }
                    if emptyi {
                        next.regs[pi] = crate::smir::X86X87State::INDEFINITE;
                        next.set_physical_tag(pi, 2);
                    }
                } else {
                    next.status_word &= !0x0200;
                }
                next.regs.swap(p0, pi);
                let tag0 = next.physical_tag(p0);
                let tagi = next.physical_tag(pi);
                next.set_physical_tag(p0, tagi);
                next.set_physical_tag(pi, tag0);
            }
            X86X87DataKind::Free => {
                stack_metadata::free(&mut next, st, false);
            }
            X86X87DataKind::FreePop => {
                stack_metadata::free(&mut next, st, true);
            }
            X86X87DataKind::ChangeSign | X86X87DataKind::Absolute => {
                let physical = original.physical_index(0);
                if original.physical_tag(physical) == 3 {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.regs[physical] = crate::smir::X86X87State::INDEFINITE;
                    next.set_physical_tag(physical, 2);
                } else {
                    next.status_word &= !0x0200;
                    if kind == X86X87DataKind::ChangeSign {
                        next.regs[physical][9] ^= 0x80;
                    } else {
                        next.regs[physical][9] &= 0x7F;
                    }
                }
            }
            X86X87DataKind::RoundInteger => {
                let physical = original.physical_index(0);
                if original.physical_tag(physical) == 3 {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.set_logical_raw_tagged(0, crate::smir::X86X87State::INDEFINITE, 2);
                } else {
                    next.status_word &= !0x0200; // C1=0 unless magnitude increments
                    let conversion = Self::x86_x87_round_to_integral(
                        &original.regs[physical],
                        (original.control_word >> 10) & 3,
                    );
                    if conversion.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if conversion.denormal {
                        next.status_word |= 0x0002; // DE
                        if next.control_word & 0x0002 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    }
                    if conversion.inexact {
                        next.status_word |= 0x0020; // PE
                        if conversion.rounded_up {
                            next.status_word |= 0x0200; // C1 roundup
                        }
                        // Precision is a post-computation exception: the
                        // rounded result is committed even when PM is clear.
                        if next.control_word & 0x0020 == 0 {
                            next.status_word |= 0x8080; // B | ES
                        }
                    }
                    next.set_logical_raw(0, conversion.raw);
                }
            }
            X86X87DataKind::Extract => {
                let source_physical = original.physical_index(0);
                let new_top = original.top().wrapping_sub(1) & 7;
                let underflow = original.physical_tag(source_physical) == 3;
                let overflow = original.physical_tag(new_top as usize) != 3;
                if underflow || overflow {
                    // Source underflow takes priority when both stack
                    // conditions are present, matching other x87 push forms.
                    if !next.signal_stack_fault(!underflow && overflow) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.regs[source_physical] = crate::smir::X86X87State::INDEFINITE;
                    next.set_physical_tag(source_physical, 2);
                    next.set_top(new_top);
                    next.set_logical_raw_tagged(0, crate::smir::X86X87State::INDEFINITE, 2);
                } else {
                    next.status_word &= !0x0200; // C1=0: no stack fault
                    let result = Self::x86_x87_extract(&original.regs[source_physical]);
                    if result.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if result.denormal {
                        next.status_word |= 0x0002; // DE
                        if next.control_word & 0x0002 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if result.zero {
                        next.status_word |= 0x0004; // ZE
                        if next.control_word & 0x0004 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    }
                    // The old ST(0) becomes ST(1) after the push.
                    next.set_top(new_top);
                    next.set_logical_raw(1, result.exponent);
                    next.set_logical_raw(0, result.significand);
                }
            }
            X86X87DataKind::Scale => {
                let destination = original.physical_index(0);
                let source = original.physical_index(1);
                if original.physical_tag(destination) == 3 || original.physical_tag(source) == 3 {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.set_logical_raw_tagged(0, crate::smir::X86X87State::INDEFINITE, 2);
                } else {
                    next.status_word &= !0x0200; // C1=0 unless magnitude increments
                    let result = Self::x86_x87_scale(
                        &original.regs[destination],
                        &original.regs[source],
                        original.control_word,
                    );
                    if result.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if result.denormal {
                        next.status_word |= 0x0002; // DE
                        if next.control_word & 0x0002 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    }
                    if result.overflow {
                        next.status_word |= 0x0008; // OE
                    }
                    if result.underflow {
                        next.status_word |= 0x0010; // UE
                    }
                    if result.inexact {
                        next.status_word |= 0x0020; // PE
                    }
                    if result.rounded_up {
                        next.status_word |= 0x0200; // C1 roundup
                    }
                    if (result.overflow && next.control_word & 0x0008 == 0)
                        || (result.underflow && next.control_word & 0x0010 == 0)
                        || (result.inexact && next.control_word & 0x0020 == 0)
                    {
                        next.status_word |= 0x8080; // B | ES
                    }
                    next.set_logical_raw(0, result.raw);
                }
            }
            X86X87DataKind::SquareRoot => {
                let physical = original.physical_index(0);
                if original.physical_tag(physical) == 3 {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.set_logical_raw_tagged(0, crate::smir::X86X87State::INDEFINITE, 2);
                } else {
                    next.status_word &= !0x0200; // C1=0 unless significand increments
                    let result =
                        Self::x86_x87_sqrt(&original.regs[physical], original.control_word);
                    if result.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if result.denormal {
                        next.status_word |= 0x0002; // DE
                        if next.control_word & 0x0002 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    }
                    if result.inexact {
                        next.status_word |= 0x0020; // PE
                        if result.rounded_up {
                            next.status_word |= 0x0200; // C1 roundup
                        }
                        if next.control_word & 0x0020 == 0 {
                            next.status_word |= 0x8080; // B | ES
                        }
                    }
                    next.set_logical_raw(0, result.raw);
                }
            }
            X86X87DataKind::Transcendental(transcendental) => {
                Self::x86_x87_execute_transcendental(&original, &mut next, transcendental);
            }
            X86X87DataKind::Multiply {
                source,
                destination,
                pop,
            } => {
                let destination_logical = match destination {
                    X86X87ArithmeticDestination::St0 => 0,
                    X86X87ArithmeticDestination::StI => st,
                };
                let destination_physical = original.physical_index(destination_logical);
                let (source_raw, source_empty, source_signaling_nan, source_denormal) = match source
                {
                    X86X87ArithmeticSource::Register => {
                        let source_logical = match destination {
                            X86X87ArithmeticDestination::St0 => st,
                            X86X87ArithmeticDestination::StI => 0,
                        };
                        let physical = original.physical_index(source_logical);
                        (
                            original.regs[physical],
                            original.physical_tag(physical) == 3,
                            false,
                            false,
                        )
                    }
                    X86X87ArithmeticSource::Single | X86X87ArithmeticSource::Double => {
                        let source_bytes = loaded.expect("FMUL memory source missing");
                        let bits = if source == X86X87ArithmeticSource::Single {
                            u32::from_le_bytes(source_bytes[..4].try_into().unwrap()) as u64
                        } else {
                            u64::from_le_bytes(source_bytes[..8].try_into().unwrap())
                        };
                        let (raw, signaling_nan, denormal) =
                            if source == X86X87ArithmeticSource::Single {
                                Self::x86_x87_widen_ieee(bits, 8, 23)
                            } else {
                                Self::x86_x87_widen_ieee(bits, 11, 52)
                            };
                        (raw, false, signaling_nan, denormal)
                    }
                    X86X87ArithmeticSource::Int16 => {
                        let source_bytes = loaded.expect("FIMUL m16int source missing");
                        (
                            Self::x86_x87_from_i64(i16::from_le_bytes(
                                source_bytes[..2].try_into().unwrap(),
                            ) as i64),
                            false,
                            false,
                            false,
                        )
                    }
                    X86X87ArithmeticSource::Int32 => {
                        let source_bytes = loaded.expect("FIMUL m32int source missing");
                        (
                            Self::x86_x87_from_i64(i32::from_le_bytes(
                                source_bytes[..4].try_into().unwrap(),
                            ) as i64),
                            false,
                            false,
                            false,
                        )
                    }
                };
                let destination_empty = original.physical_tag(destination_physical) == 3;
                if destination_empty || source_empty {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.set_logical_raw_tagged(
                        destination_logical,
                        crate::smir::X86X87State::INDEFINITE,
                        2,
                    );
                    if pop {
                        next.pop();
                    }
                } else {
                    next.status_word &= !0x0200; // C1=0 unless magnitude increments
                    let result = Self::x86_x87_multiply(
                        &original.regs[destination_physical],
                        &source_raw,
                        source_signaling_nan,
                        source_denormal,
                        original.control_word,
                    );
                    if result.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if result.denormal {
                        next.status_word |= 0x0002; // DE
                        if next.control_word & 0x0002 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    }
                    if result.overflow {
                        next.status_word |= 0x0008; // OE
                    }
                    if result.underflow {
                        next.status_word |= 0x0010; // UE
                    }
                    if result.inexact {
                        next.status_word |= 0x0020; // PE
                    }
                    if result.rounded_up {
                        next.status_word |= 0x0200; // C1 roundup
                    }
                    if (result.overflow && next.control_word & 0x0008 == 0)
                        || (result.underflow && next.control_word & 0x0010 == 0)
                        || (result.inexact && next.control_word & 0x0020 == 0)
                    {
                        next.status_word |= 0x8080; // B | ES
                    }
                    next.set_logical_raw(destination_logical, result.raw);
                    if pop {
                        next.pop();
                    }
                }
            }
            X86X87DataKind::AddSubtract {
                source,
                destination,
                pop,
                subtract,
                reverse,
            } => {
                let destination_logical = match destination {
                    X86X87ArithmeticDestination::St0 => 0,
                    X86X87ArithmeticDestination::StI => st,
                };
                let destination_physical = original.physical_index(destination_logical);
                let (source_raw, source_empty, source_signaling_nan, source_denormal) = match source
                {
                    X86X87ArithmeticSource::Register => {
                        let source_logical = match destination {
                            X86X87ArithmeticDestination::St0 => st,
                            X86X87ArithmeticDestination::StI => 0,
                        };
                        let physical = original.physical_index(source_logical);
                        (
                            original.regs[physical],
                            original.physical_tag(physical) == 3,
                            false,
                            false,
                        )
                    }
                    X86X87ArithmeticSource::Single | X86X87ArithmeticSource::Double => {
                        let source_bytes = loaded.expect("x87 add/subtract memory source missing");
                        let bits = if source == X86X87ArithmeticSource::Single {
                            u32::from_le_bytes(source_bytes[..4].try_into().unwrap()) as u64
                        } else {
                            u64::from_le_bytes(source_bytes[..8].try_into().unwrap())
                        };
                        let (raw, signaling_nan, denormal) =
                            if source == X86X87ArithmeticSource::Single {
                                Self::x86_x87_widen_ieee(bits, 8, 23)
                            } else {
                                Self::x86_x87_widen_ieee(bits, 11, 52)
                            };
                        (raw, false, signaling_nan, denormal)
                    }
                    X86X87ArithmeticSource::Int16 => {
                        let source_bytes = loaded.expect("FIADD/FISUB m16int source missing");
                        (
                            Self::x86_x87_from_i64(i16::from_le_bytes(
                                source_bytes[..2].try_into().unwrap(),
                            ) as i64),
                            false,
                            false,
                            false,
                        )
                    }
                    X86X87ArithmeticSource::Int32 => {
                        let source_bytes = loaded.expect("FIADD/FISUB m32int source missing");
                        (
                            Self::x86_x87_from_i64(i32::from_le_bytes(
                                source_bytes[..4].try_into().unwrap(),
                            ) as i64),
                            false,
                            false,
                            false,
                        )
                    }
                };
                let destination_empty = original.physical_tag(destination_physical) == 3;
                if destination_empty || source_empty {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.set_logical_raw_tagged(
                        destination_logical,
                        crate::smir::X86X87State::INDEFINITE,
                        2,
                    );
                    if pop {
                        next.pop();
                    }
                } else {
                    next.status_word &= !0x0200; // C1=0 unless magnitude increments
                    let result = Self::x86_x87_add_subtract(
                        &original.regs[destination_physical],
                        &source_raw,
                        source_signaling_nan,
                        source_denormal,
                        original.control_word,
                        subtract,
                        reverse,
                    );
                    if result.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if result.denormal {
                        next.status_word |= 0x0002; // DE
                        if next.control_word & 0x0002 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    }
                    if result.overflow {
                        next.status_word |= 0x0008; // OE
                    }
                    if result.underflow {
                        next.status_word |= 0x0010; // UE
                    }
                    if result.inexact {
                        next.status_word |= 0x0020; // PE
                    }
                    if result.rounded_up {
                        next.status_word |= 0x0200; // C1 roundup
                    }
                    if (result.overflow && next.control_word & 0x0008 == 0)
                        || (result.underflow && next.control_word & 0x0010 == 0)
                        || (result.inexact && next.control_word & 0x0020 == 0)
                    {
                        next.status_word |= 0x8080; // B | ES
                    }
                    next.set_logical_raw(destination_logical, result.raw);
                    if pop {
                        next.pop();
                    }
                }
            }
            X86X87DataKind::Divide {
                source,
                destination,
                pop,
                reverse,
            } => {
                let destination_logical = match destination {
                    X86X87ArithmeticDestination::St0 => 0,
                    X86X87ArithmeticDestination::StI => st,
                };
                let destination_physical = original.physical_index(destination_logical);
                let (source_raw, source_empty, source_signaling_nan, source_denormal) = match source
                {
                    X86X87ArithmeticSource::Register => {
                        let source_logical = match destination {
                            X86X87ArithmeticDestination::St0 => st,
                            X86X87ArithmeticDestination::StI => 0,
                        };
                        let physical = original.physical_index(source_logical);
                        (
                            original.regs[physical],
                            original.physical_tag(physical) == 3,
                            false,
                            false,
                        )
                    }
                    X86X87ArithmeticSource::Single | X86X87ArithmeticSource::Double => {
                        let source_bytes = loaded.expect("x87 divide memory source missing");
                        let bits = if source == X86X87ArithmeticSource::Single {
                            u32::from_le_bytes(source_bytes[..4].try_into().unwrap()) as u64
                        } else {
                            u64::from_le_bytes(source_bytes[..8].try_into().unwrap())
                        };
                        let (raw, signaling_nan, denormal) =
                            if source == X86X87ArithmeticSource::Single {
                                Self::x86_x87_widen_ieee(bits, 8, 23)
                            } else {
                                Self::x86_x87_widen_ieee(bits, 11, 52)
                            };
                        (raw, false, signaling_nan, denormal)
                    }
                    X86X87ArithmeticSource::Int16 => {
                        let source_bytes = loaded.expect("FIDIV m16int source missing");
                        (
                            Self::x86_x87_from_i64(i16::from_le_bytes(
                                source_bytes[..2].try_into().unwrap(),
                            ) as i64),
                            false,
                            false,
                            false,
                        )
                    }
                    X86X87ArithmeticSource::Int32 => {
                        let source_bytes = loaded.expect("FIDIV m32int source missing");
                        (
                            Self::x86_x87_from_i64(i32::from_le_bytes(
                                source_bytes[..4].try_into().unwrap(),
                            ) as i64),
                            false,
                            false,
                            false,
                        )
                    }
                };
                let destination_empty = original.physical_tag(destination_physical) == 3;
                if destination_empty || source_empty {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.set_logical_raw_tagged(
                        destination_logical,
                        crate::smir::X86X87State::INDEFINITE,
                        2,
                    );
                    if pop {
                        next.pop();
                    }
                } else {
                    next.status_word &= !0x0200; // C1=0 unless magnitude increments
                    let result = Self::x86_x87_divide(
                        &original.regs[destination_physical],
                        &source_raw,
                        source_signaling_nan,
                        source_denormal,
                        original.control_word,
                        reverse,
                    );
                    if result.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else {
                        if result.denormal {
                            next.status_word |= 0x0002; // DE
                            if next.control_word & 0x0002 == 0 {
                                next.status_word |= 0x8080; // B | ES
                                *x87 = next;
                                return Ok(eflags_update);
                            }
                        }
                        if result.zero_divide {
                            next.status_word |= 0x0004; // ZE
                            if next.control_word & 0x0004 == 0 {
                                next.status_word |= 0x8080; // B | ES
                                *x87 = next;
                                return Ok(eflags_update);
                            }
                        }
                    }
                    if result.overflow {
                        next.status_word |= 0x0008; // OE
                    }
                    if result.underflow {
                        next.status_word |= 0x0010; // UE
                    }
                    if result.inexact {
                        next.status_word |= 0x0020; // PE
                    }
                    if result.rounded_up {
                        next.status_word |= 0x0200; // C1 roundup
                    }
                    if (result.overflow && next.control_word & 0x0008 == 0)
                        || (result.underflow && next.control_word & 0x0010 == 0)
                        || (result.inexact && next.control_word & 0x0020 == 0)
                    {
                        next.status_word |= 0x8080; // B | ES
                    }
                    next.set_logical_raw(destination_logical, result.raw);
                    if pop {
                        next.pop();
                    }
                }
            }
            X86X87DataKind::Remainder { nearest } => {
                let dividend_physical = original.physical_index(0);
                let modulus_physical = original.physical_index(1);
                if original.physical_tag(dividend_physical) == 3
                    || original.physical_tag(modulus_physical) == 3
                {
                    if !next.signal_stack_fault(false) {
                        *x87 = next;
                        return Ok(eflags_update);
                    }
                    next.set_logical_raw_tagged(0, crate::smir::X86X87State::INDEFINITE, 2);
                } else {
                    let result = Self::x86_x87_remainder(
                        &original.regs[dividend_physical],
                        &original.regs[modulus_physical],
                        nearest,
                    );
                    if result.invalid {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    } else if result.denormal {
                        next.status_word |= 0x0002; // DE
                        if next.control_word & 0x0002 == 0 {
                            next.status_word |= 0x8080; // B | ES
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                    }
                    next.set_logical_raw(0, result.raw);
                    if result.incomplete {
                        next.status_word |= 0x0400; // C2=1; C0/C1/C3 undefined
                    } else {
                        next.status_word &= !0x4700;
                        if result.quotient_bits & 4 != 0 {
                            next.status_word |= 0x0100; // C0=Q2
                        }
                        if result.quotient_bits & 2 != 0 {
                            next.status_word |= 0x4000; // C3=Q1
                        }
                        if result.quotient_bits & 1 != 0 {
                            next.status_word |= 0x0200; // C1=Q0
                        }
                    }
                }
            }
            X86X87DataKind::DecrementTop => {
                stack_metadata::rotate_top(&mut next, false);
            }
            X86X87DataKind::IncrementTop => {
                stack_metadata::rotate_top(&mut next, true);
            }
            X86X87DataKind::ConditionalMove(_) => {
                if conditional_move_taken.expect("FCMOV condition missing") {
                    let source_physical = original.physical_index(st);
                    if original.physical_tag(source_physical) == 3 {
                        if !next.signal_stack_fault(false) {
                            *x87 = next;
                            return Ok(eflags_update);
                        }
                        next.set_logical_raw_tagged(0, crate::smir::X86X87State::INDEFINITE, 2);
                    } else {
                        next.set_logical_raw_tagged(
                            0,
                            original.regs[source_physical],
                            original.physical_tag(source_physical),
                        );
                    }
                }
            }
            X86X87DataKind::Examine => {
                let physical = original.physical_index(0);
                let raw = original.regs[physical];
                let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
                let exponent_sign = u16::from_le_bytes(raw[8..].try_into().unwrap());
                let exponent = exponent_sign & 0x7FFF;
                let integer_bit = significand >> 63;
                let fraction = significand & 0x7FFF_FFFF_FFFF_FFFF;
                let condition_codes = if original.physical_tag(physical) == 3 {
                    0x4100 // Empty: C3,C2,C0 = 101
                } else if exponent == 0 {
                    if significand == 0 {
                        0x4000 // Zero: 100
                    } else {
                        0x4400 // Denormal or pseudo-denormal: 110
                    }
                } else if exponent == 0x7FFF {
                    if integer_bit == 0 {
                        0x0000 // Pseudo-NaN/pseudo-infinity: unsupported 000
                    } else if fraction == 0 {
                        0x0500 // Infinity: 011
                    } else {
                        0x0100 // NaN: 001
                    }
                } else if integer_bit == 0 {
                    0x0000 // Unnormal: unsupported 000
                } else {
                    0x0400 // Normal finite: 010
                };
                next.status_word = (next.status_word & !0x4700) | condition_codes;
                if exponent_sign & 0x8000 != 0 {
                    next.status_word |= 0x0200;
                }
            }
            X86X87DataKind::TestZero => {
                let physical = original.physical_index(0);
                let prior_codes = next.status_word & 0x4500;
                next.status_word &= !0x0200; // C1=0
                if original.physical_tag(physical) == 3 {
                    if next.signal_stack_fault(false) {
                        next.status_word = (next.status_word & !0x4500) | 0x4500;
                    } else {
                        next.status_word = (next.status_word & !0x4500) | prior_codes;
                    }
                } else {
                    let raw = original.regs[physical];
                    let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
                    let exponent_sign = u16::from_le_bytes(raw[8..].try_into().unwrap());
                    let exponent = exponent_sign & 0x7FFF;
                    let integer_bit = significand >> 63;
                    let fraction = significand & 0x7FFF_FFFF_FFFF_FFFF;
                    let unsupported = (exponent == 0x7FFF && integer_bit == 0)
                        || (exponent != 0 && exponent != 0x7FFF && integer_bit == 0);
                    let nan = exponent == 0x7FFF && integer_bit == 1 && fraction != 0;
                    let denormal = exponent == 0 && significand != 0;
                    if unsupported || nan {
                        next.status_word |= 0x0001; // IE
                        if next.control_word & 0x0001 != 0 {
                            next.status_word = (next.status_word & !0x4500) | 0x4500;
                        } else {
                            next.status_word |= 0x8080; // B | ES
                            next.status_word = (next.status_word & !0x4500) | prior_codes;
                        }
                    } else if denormal && next.control_word & 0x0002 == 0 {
                        next.status_word |= 0x8082; // B | ES | DE
                        next.status_word = (next.status_word & !0x4500) | prior_codes;
                    } else {
                        if denormal {
                            next.status_word |= 0x0002; // DE
                        }
                        let codes = if significand == 0 && exponent == 0 {
                            0x4000 // equal, including -0.0
                        } else if exponent_sign & 0x8000 != 0 {
                            0x0100 // less than zero
                        } else {
                            0x0000 // greater than zero
                        };
                        next.status_word = (next.status_word & !0x4500) | codes;
                    }
                }
            }
            X86X87DataKind::Compare {
                source,
                unordered,
                pop,
                eflags,
            } => {
                let p0 = original.physical_index(0);
                let (source_raw, source_empty, memory_snan) = match source {
                    X86X87CompareSource::Register => {
                        let physical = original.physical_index(st);
                        (
                            original.regs[physical],
                            original.physical_tag(physical) == 3,
                            false,
                        )
                    }
                    X86X87CompareSource::Single => {
                        let bytes = loaded.expect("FCOM m32fp source missing");
                        let bits = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64;
                        let (raw, snan, _) = Self::x86_x87_widen_ieee(bits, 8, 23);
                        (raw, false, snan)
                    }
                    X86X87CompareSource::Double => {
                        let bytes = loaded.expect("FCOM m64fp source missing");
                        let bits = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                        let (raw, snan, _) = Self::x86_x87_widen_ieee(bits, 11, 52);
                        (raw, false, snan)
                    }
                    X86X87CompareSource::Int16 => {
                        let bytes = loaded.expect("FICOM m16int source missing");
                        let value = i16::from_le_bytes(bytes[..2].try_into().unwrap()) as i64;
                        (Self::x86_x87_from_i64(value), false, false)
                    }
                    X86X87CompareSource::Int32 => {
                        let bytes = loaded.expect("FICOM m32int source missing");
                        let value = i32::from_le_bytes(bytes[..4].try_into().unwrap()) as i64;
                        (Self::x86_x87_from_i64(value), false, false)
                    }
                };
                let lhs_empty = original.physical_tag(p0) == 3;
                let lhs_raw = original.regs[p0];
                let lhs_info = Self::x86_x87_raw_info(&lhs_raw);
                let mut rhs_info = Self::x86_x87_raw_info(&source_raw);
                rhs_info.signaling_nan |= memory_snan;

                // C1 is cleared by every compare form. FCOMI/FUCOMI also clear
                // OF/SF/AF even when an unmasked invalid exception suppresses
                // updates to ZF/PF/CF.
                next.status_word &= !0x0200;
                if eflags {
                    eflags_update = Some(X87EflagsUpdate { codes: None });
                }

                let prior_codes = next.status_word & 0x4500;
                let stack_fault = lhs_empty || source_empty;
                let invalid = lhs_info.unsupported
                    || rhs_info.unsupported
                    || if unordered {
                        lhs_info.signaling_nan || rhs_info.signaling_nan
                    } else {
                        lhs_info.nan || rhs_info.nan
                    };
                let qnan_unordered = unordered && !invalid && (lhs_info.nan || rhs_info.nan);
                let denormal = lhs_info.denormal || rhs_info.denormal;
                let mut result_codes = None;
                let mut complete = true;

                if stack_fault {
                    if next.signal_stack_fault(false) {
                        result_codes = Some(0x4500);
                    } else {
                        complete = false;
                    }
                } else if invalid {
                    next.status_word |= 0x0001; // IE
                    if next.control_word & 0x0001 != 0 {
                        result_codes = Some(0x4500);
                    } else {
                        next.status_word |= 0x8080; // B | ES
                        complete = false;
                    }
                } else if qnan_unordered {
                    result_codes = Some(0x4500);
                } else if !eflags && denormal && next.control_word & 0x0002 == 0 {
                    next.status_word |= 0x8082; // B | ES | DE
                    complete = false;
                } else {
                    if !eflags && denormal {
                        next.status_word |= 0x0002; // DE
                    }
                    result_codes = Some(match Self::x86_x87_compare_raw(&lhs_raw, &source_raw) {
                        Ordering::Greater => 0x0000,
                        Ordering::Less => 0x0100,
                        Ordering::Equal => 0x4000,
                    });
                }

                if complete {
                    let codes = result_codes.expect("completed x87 comparison lacks result");
                    if eflags {
                        eflags_update = Some(X87EflagsUpdate { codes: Some(codes) });
                    } else {
                        next.status_word = (next.status_word & !0x4500) | codes;
                    }
                    for _ in 0..pop {
                        next.pop();
                    }
                } else if !eflags {
                    next.status_word = (next.status_word & !0x4500) | prior_codes;
                }
            }
        }

        *x87 = next;
        Ok(eflags_update)
    }
}
