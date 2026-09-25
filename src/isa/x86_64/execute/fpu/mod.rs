//! x87 FPU instructions: the escapes `D8`-`DF`.
//!
//! The direct engine executes x87 instructions with the same code as SMIR:
//! `x87_form` (the SMIR lifter's encoding table) classifies each escape, and
//! `SmirInterpreter::x86_x87_data_step` executes data operations on the exact
//! binary80 registers, with precision control, rounding control, exception
//! flags, masked responses, and stack faults. This module adds what belongs to
//! the direct engine: the availability checks (#NM, then #MF for waiting
//! instructions) in their architectural order, guest memory with the engine's
//! own fault reporting, the environment and state images, and RFLAGS for
//! FCMOVcc and the FCOMI family.

use crate::error::{Error, Result};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::smir::interpret::{SmirInterpreter, X87Memory};
use crate::smir::ir::memory::MemoryError;
use crate::smir::ir::ops::{X86X87ControlKind, X86X87DataKind};
use crate::smir::ir::types::Condition;
use crate::smir::lift::x86_64::{X87Form, x87_form};
use crate::vm::vcpu::VcpuExit;

const CR0_EM: u64 = 1 << 2;
const CR0_NE: u64 = 1 << 5;
const CR0_TS: u64 = 1 << 3;
const FSW_ES: u16 = 1 << 7;

const RFLAGS_CF: u64 = 1 << 0;
const RFLAGS_PF: u64 = 1 << 2;
const RFLAGS_AF: u64 = 1 << 4;
const RFLAGS_ZF: u64 = 1 << 6;
const RFLAGS_SF: u64 = 1 << 7;
const RFLAGS_OF: u64 = 1 << 11;

macro_rules! escapes {
    ($($name:ident = $opcode:literal),* $(,)?) => {
        $(
            #[doc = concat!("x87 escape `", stringify!($opcode), "`.")]
            pub fn $name(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
                escape(vcpu, ctx, $opcode)
            }
        )*
    };
}

escapes!(
    escape_d8 = 0xD8,
    escape_d9 = 0xD9,
    escape_da = 0xDA,
    escape_db = 0xDB,
    escape_dc = 0xDC,
    escape_dd = 0xDD,
    escape_de = 0xDE,
    escape_df = 0xDF,
);

/// Deliver x87 device-not-available before a decoded instruction observes or
/// commits architectural state. Encoding and LOCK/REX2 validity are resolved
/// by the caller and common decoder first, preserving #UD priority.
fn require_x87_available(vcpu: &mut X86_64Vcpu) -> Result<bool> {
    if vcpu.sregs.cr0 & (CR0_EM | CR0_TS) != 0 {
        vcpu.inject_exception(7, None)?;
        return Ok(false);
    }
    Ok(true)
}

/// Deliver the two pre-execution faults shared by waiting x87 operations.
/// Device-not-available has priority over a pending floating-point error.
fn require_waiting_x87_available(vcpu: &mut X86_64Vcpu) -> Result<bool> {
    if !require_x87_available(vcpu)? {
        return Ok(false);
    }
    if vcpu.sregs.cr0 & CR0_NE != 0 && vcpu.fpu.status_word & FSW_ES != 0 {
        vcpu.inject_exception(16, None)?;
        return Ok(false);
    }
    Ok(true)
}

/// Whether a control operation is one of the non-waiting instructions
/// (FNINIT, FNCLEX, FNSTSW, FNSTCW, FNSTENV, FNSAVE; SDM Vol. 1, 8.3.11 and
/// 8.7), which ignore a pending unmasked exception.
fn is_non_waiting(kind: X86X87ControlKind) -> bool {
    matches!(
        kind,
        X86X87ControlKind::Init
            | X86X87ControlKind::ClearExceptions
            | X86X87ControlKind::StoreStatusAx
            | X86X87ControlKind::StoreStatusWord
            | X86X87ControlKind::StoreControlWord
            | X86X87ControlKind::StoreEnvironment(_)
            | X86X87ControlKind::SaveState(_)
    )
}

/// Guest memory for the shared x87 core. A fault is kept as the engine's own
/// error, which the escape returns exactly as a direct memory access would.
struct DirectMemory<'a> {
    vcpu: &'a mut X86_64Vcpu,
    fault: Option<Error>,
}

impl X87Memory for DirectMemory<'_> {
    fn read_x87(&mut self, addr: u64, buf: &mut [u8]) -> std::result::Result<(), MemoryError> {
        match self.vcpu.read_bytes(addr, buf.len()) {
            Ok(bytes) => {
                buf.copy_from_slice(&bytes);
                Ok(())
            }
            Err(error) => {
                self.fault = Some(error);
                Err(MemoryError::AccessViolation { addr, write: false })
            }
        }
    }

    fn write_x87(&mut self, addr: u64, data: &[u8]) -> std::result::Result<(), MemoryError> {
        self.vcpu.write_bytes(addr, data).map_err(|error| {
            self.fault = Some(error);
            MemoryError::AccessViolation { addr, write: true }
        })
    }
}

/// The FCMOVcc condition over the architectural (materialized) flags.
fn fcmov_condition(vcpu: &mut X86_64Vcpu, condition: Condition) -> Result<bool> {
    vcpu.materialize_flags();
    let flags = vcpu.regs.rflags;
    let (cf, pf, zf) = (
        flags & RFLAGS_CF != 0,
        flags & RFLAGS_PF != 0,
        flags & RFLAGS_ZF != 0,
    );
    Ok(match condition {
        Condition::Ult => cf,
        Condition::Eq => zf,
        Condition::Ule => cf || zf,
        Condition::Parity => pf,
        Condition::Uge => !cf,
        Condition::Ne => !zf,
        Condition::Ugt => !cf && !zf,
        Condition::NoParity => !pf,
        other => {
            return Err(Error::Emulator(format!(
                "x87 FCMOV has no condition {other:?}"
            )));
        }
    })
}

/// Execute one x87 escape instruction.
fn escape(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, opcode: u8) -> Result<Option<VcpuExit>> {
    let modrm = ctx.consume_u8()?;
    let is_memory = modrm >> 6 != 3;
    let addr = if is_memory {
        Some(vcpu.decode_fpu_modrm_addr(ctx, modrm)?)
    } else {
        None
    };
    match x87_form(opcode, is_memory, modrm, ctx.operand_size_override) {
        X87Form::Invalid => {
            vcpu.inject_exception(6, None)?;
            return Ok(None);
        }
        X87Form::NoOperation => {
            // FNOP waits; the obsolete FNENI, FNDISI, and FNSETPM do not.
            let waits = opcode == 0xD9;
            let available = if waits {
                require_waiting_x87_available(vcpu)?
            } else {
                require_x87_available(vcpu)?
            };
            if !available {
                return Ok(None);
            }
        }
        X87Form::Data(kind) => {
            if !require_waiting_x87_available(vcpu)? {
                return Ok(None);
            }
            let condition = match kind {
                X86X87DataKind::ConditionalMove(condition) => {
                    Some(fcmov_condition(vcpu, condition)?)
                }
                _ => None,
            };
            let mut state = vcpu.fpu.to_x87();
            let guest_pc = vcpu.regs.rip;
            let fop = (u16::from(opcode & 7) << 8) | u16::from(modrm);
            let mut memory = DirectMemory { vcpu, fault: None };
            let result = SmirInterpreter::x86_x87_data_step(
                &mut state,
                &mut memory,
                guest_pc,
                kind,
                addr,
                modrm & 7,
                fop,
                condition,
            );
            let eflags = match result {
                Ok(eflags) => eflags,
                Err(error) => {
                    return Err(memory.fault.take().unwrap_or_else(|| {
                        Error::Emulator(format!("x87 memory access failed: {error}"))
                    }));
                }
            };
            vcpu.fpu.load_x87(&state);
            if let Some(update) = eflags {
                // FCOMI, FCOMIP, FUCOMI, FUCOMIP: OF, SF, and AF are cleared
                // even when an unmasked exception leaves ZF, PF, and CF.
                vcpu.materialize_flags();
                vcpu.regs.rflags &= !(RFLAGS_OF | RFLAGS_SF | RFLAGS_AF);
                if let Some(codes) = update.codes {
                    vcpu.regs.rflags &= !(RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);
                    if codes & 0x4000 != 0 {
                        vcpu.regs.rflags |= RFLAGS_ZF;
                    }
                    if codes & 0x0400 != 0 {
                        vcpu.regs.rflags |= RFLAGS_PF;
                    }
                    if codes & 0x0100 != 0 {
                        vcpu.regs.rflags |= RFLAGS_CF;
                    }
                }
            }
        }
        X87Form::Control(kind) => {
            let available = if is_non_waiting(kind) {
                require_x87_available(vcpu)?
            } else {
                require_waiting_x87_available(vcpu)?
            };
            if !available {
                return Ok(None);
            }
            control(vcpu, kind, addr)?;
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Execute an environment or control operation. Memory is read in full
/// before any state changes, and stores complete before FNSTENV masks the
/// exceptions or FNSAVE reinitializes, so a fault changes nothing.
fn control(vcpu: &mut X86_64Vcpu, kind: X86X87ControlKind, addr: Option<u64>) -> Result<()> {
    let address =
        || addr.ok_or_else(|| Error::Emulator(format!("x87 {kind:?} requires a memory operand")));
    let mut state = vcpu.fpu.to_x87();
    match kind {
        X86X87ControlKind::Init => state.init(),
        X86X87ControlKind::ClearExceptions => state.clear_exceptions(),
        X86X87ControlKind::StoreStatusAx => {
            vcpu.regs.rax = (vcpu.regs.rax & !0xFFFF) | u64::from(state.status_word);
        }
        X86X87ControlKind::StoreStatusWord => {
            vcpu.write_bytes(address()?, &state.status_word.to_le_bytes())?;
        }
        X86X87ControlKind::StoreControlWord => {
            vcpu.write_bytes(address()?, &state.control_word.to_le_bytes())?;
        }
        X86X87ControlKind::LoadControlWord => {
            let bytes = vcpu.read_bytes(address()?, 2)?;
            state.control_word = u16::from_le_bytes([bytes[0], bytes[1]]);
        }
        X86X87ControlKind::LoadEnvironment(width) => {
            let len = SmirInterpreter::x86_x87_environment_len(width);
            let image = vcpu.read_bytes(address()?, len)?;
            SmirInterpreter::restore_x86_x87_environment(&mut state, &image, width);
        }
        X86X87ControlKind::StoreEnvironment(width) => {
            let (image, len) = SmirInterpreter::x86_x87_environment_image(&state, width);
            vcpu.write_bytes(address()?, &image[..len])?;
            // The image keeps the old FCW; then every exception is masked.
            state.control_word |= 0x003F;
        }
        X86X87ControlKind::RestoreState(width) => {
            let len = SmirInterpreter::x86_x87_environment_len(width) + 80;
            let image = vcpu.read_bytes(address()?, len)?;
            SmirInterpreter::restore_x86_x87_state(&mut state, &image, width);
        }
        X86X87ControlKind::SaveState(width) => {
            let (image, len) = SmirInterpreter::x86_x87_state_image(&state, width);
            vcpu.write_bytes(address()?, &image[..len])?;
            state.init();
        }
        X86X87ControlKind::EnterMmx | X86X87ControlKind::EmptyMmx => {
            return Err(Error::Emulator(format!(
                "{kind:?} is not an x87 escape form"
            )));
        }
    }
    vcpu.fpu.load_x87(&state);
    Ok(())
}
