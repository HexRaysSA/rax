//! Canonical state-backed PAuth effects; shared with native runtime helpers.

use crate::isa::arm::aarch64::exception_return::{
    ExceptionReturnMode, aarch64_return_pstate, classify_exception_return, exception_return_ss,
};
use crate::isa::arm::aarch64::pauth_execution::{PauthEffect, PauthExecutionError, PauthInputs};
use crate::isa::arm::aarch64::pauth_instruction::PauthInstruction;
use crate::isa::arm::common::cpu::{AccessType, ArmError, MemoryFaultInfo, MemoryFaultType};
use crate::smir::ir::context::{Aarch64RegState, ExitReason};
use crate::smir::ir::memory::SmirMemory;
use crate::smir::ir::ops::ArmPauthOp;

pub(crate) fn unsupported(pc: u64, operation: &'static str) -> ExitReason {
    ExitReason::Unsupported {
        addr: pc,
        operation,
    }
}

pub(crate) fn execution_error(pc: u64, raw: u32, error: PauthExecutionError) -> ExitReason {
    match error {
        PauthExecutionError::Undefined => ExitReason::Undefined {
            addr: pc,
            opcode: raw,
        },
        PauthExecutionError::UnsupportedState => unsupported(pc, "AArch64 execution state"),
        PauthExecutionError::Exception(exception) => ExitReason::Aarch64Exception {
            pc,
            ec: exception.ec,
            iss: exception.iss,
            target_el: exception.target_el.unwrap_or(1),
        },
        PauthExecutionError::SpAlignment { address } => ExitReason::Aarch64Fault {
            pc,
            error: ArmError::MemoryError(MemoryFaultInfo {
                address,
                access: AccessType::Read,
                fault_type: MemoryFaultType::SpAlignment,
                stage2: false,
            }),
        },
    }
}

/// Entry checks shared by canonical interpretation and native helper calls.
pub(crate) fn begin_instruction(
    state: &mut Aarch64RegState,
    memory: &mut dyn SmirMemory,
    raw: u32,
    features: u64,
    pc: u64,
) -> Result<(), ExitReason> {
    if state.pstate & 16 != 0 {
        return Err(unsupported(pc, "AArch64 instruction in AArch32 state"));
    }
    let environment = state
        .pauth_environment()
        .ok_or_else(|| unsupported(pc, "AArch64 system state"))?;
    if environment.features.bits() != features {
        return Err(unsupported(pc, "AArch64 lift feature mismatch"));
    }
    if let Some(metadata) = memory.aarch64_instruction_guarded(pc, state) {
        state.instruction_guarded =
            Some(metadata.map_err(|error| ExitReason::Aarch64Fault { pc, error })?);
    }
    environment
        .check_entry(raw, state.pstate_bits(), state.guarded_instruction())
        .map_err(|error| execution_error(pc, raw, error))?;
    let rn = (raw >> 5) & 31;
    if raw & 0xffff_fc1f == 0xd61f_0000
        && rn != 16
        && rn != 17
        && state.guarded_instruction().is_none()
    {
        return Err(unsupported(pc, "AArch64 fetch GP metadata"));
    }
    Ok(())
}

/// Successful retirement: ordinary instructions clear BTYPE; PAuth control
/// transfers have already established their PC/PSTATE through the plan.
pub(crate) fn commit_instruction(state: &mut Aarch64RegState, raw: u32, pc: u64) {
    let pauth_flow = PauthInstruction::decode(raw).is_some_and(|insn| insn.is_control_flow());
    if pauth_flow {
        return;
    }
    let btype = if raw & 0xffff_fc1f == 0xd63f_0000 {
        2
    } else if raw & 0xffff_fc1f == 0xd61f_0000 {
        let rn = (raw >> 5) & 31;
        if state.guarded_instruction() == Some(true) && rn != 16 && rn != 17 {
            3
        } else {
            1
        }
    } else {
        0
    };
    state.pstate = (state.pstate & !(3 << 10)) | (btype << 10);
    state.pc = pc.wrapping_add(4);
}

/// Commit one plan only after every faultable check/access succeeds. The
/// descriptor is fixed-size and QARMA has a bounded round count: O(1) space and
/// time apart from the memory backend's address translation/access.
pub(crate) fn execute_pauth(
    state: &mut Aarch64RegState,
    memory: &mut dyn SmirMemory,
    operation: ArmPauthOp,
    pc: u64,
) -> Result<(), ExitReason> {
    if state.pstate & 16 != 0 {
        return Err(unsupported(pc, "AArch64 instruction in AArch32 state"));
    }
    if !operation.valid() {
        return Err(ExitReason::Undefined {
            addr: pc,
            opcode: operation.raw,
        });
    }
    let environment = state
        .pauth_environment()
        .ok_or_else(|| unsupported(pc, "AArch64 PAuth state"))?;
    environment
        .check_entry(
            operation.raw,
            state.pstate_bits(),
            state.guarded_instruction(),
        )
        .map_err(|error| execution_error(pc, operation.raw, error))?;
    let needs_guarded = matches!(operation.instruction,
        PauthInstruction::Branch { link: false, target: 0..=15 | 18..=31, .. });
    let guarded = if needs_guarded {
        state
            .guarded_instruction()
            .ok_or_else(|| unsupported(pc, "AArch64 fetch GP metadata"))?
    } else {
        false
    };
    let exported = state
        .to_cpu_state()
        .ok_or_else(|| unsupported(pc, "AArch64 banked state"))?;
    let execution = exported.sregs.execution.as_ref().unwrap();
    let el = state.current_el();
    let (elr, saved) = if el == 1 {
        (exported.sregs.elr_el1, exported.sregs.spsr_el1)
    } else {
        let bank = execution.sysregs.bank(el);
        (bank.elr, bank.spsr)
    };
    let effect = environment
        .plan(
            operation.instruction,
            PauthInputs {
                x: &state.x,
                sp: state.sp,
                pc,
                elr,
                guarded,
            },
        )
        .map_err(|error| execution_error(pc, operation.raw, error))?;
    match effect {
        PauthEffect::None => {}
        PauthEffect::Register { dst, value } => {
            if let Some(destination) = state.x.get_mut(usize::from(dst)) {
                *destination = value;
            }
        }
        PauthEffect::Branch {
            target,
            link,
            btype,
        } => {
            if let Some(link) = link {
                state.x[30] = link;
            }
            state.pc = target;
            state.pstate = (state.pstate & !(3 << 10)) | (u64::from(btype) << 10);
        }
        PauthEffect::ExceptionReturn { mut target } => {
            let mode = classify_exception_return(
                environment.controls,
                execution.sysregs.id_aa64pfr0_el1,
                saved,
            );
            let ss = exception_return_ss(
                environment.controls,
                &execution.sysregs,
                state.pstate_bits(),
                saved,
                mode,
            );
            let restored = match mode {
                ExceptionReturnMode::Aarch32 { .. } => {
                    crate::isa::arm::aarch64::aarch32_state::return_pstate(
                        saved,
                        ss,
                        environment.controls,
                    )
                }
                _ => aarch64_return_pstate(state.pstate_bits(), saved, mode, ss),
            }
            .ok_or_else(|| unsupported(pc, "exception-return state"))?;
            if mode == ExceptionReturnMode::Illegal && saved & 16 != 0 {
                target &= 0xffff_fffc;
            }
            if !state.set_pstate_value(restored) {
                return Err(unsupported(pc, "AArch64 exception-return SP bank"));
            }
            memory.clear_exclusive();
            state.event_register = true;
            // Destination regime selection follows the restored PSTATE.
            state.pc = if restored & 16 != 0 {
                crate::isa::arm::aarch64::aarch32_state::return_address(target, restored)
            } else {
                state
                    .pauth_environment()
                    .unwrap()
                    .controls
                    .branch_address(target)
            };
        }
        PauthEffect::Load {
            address,
            dst,
            writeback,
        } => {
            let value = load64(state, memory, pc, address)?;
            if let Some(destination) = state.x.get_mut(usize::from(dst)) {
                *destination = value;
            }
            if let Some((base, value)) = writeback {
                if base == 31 {
                    state.set_sp_value(value);
                } else {
                    state.x[usize::from(base)] = value;
                }
            }
        }
    }
    Ok(())
}

fn load64(
    state: &Aarch64RegState,
    memory: &mut dyn SmirMemory,
    pc: u64,
    address: u64,
) -> Result<u64, ExitReason> {
    if let Some(result) = memory.aarch64_load64(address, state) {
        return result.map_err(|error| ExitReason::Aarch64Fault { pc, error });
    }
    let environment = state.pauth_environment().unwrap();
    let sctlr = environment.controls.sctlr[environment.controls.regime_el()];
    if sctlr & 1 != 0 {
        return Err(unsupported(pc, "AArch64 translated load bridge"));
    }
    let effective = environment.controls.effective_address(address, true);
    if sctlr & 2 != 0 && effective & 7 != 0 {
        return Err(ExitReason::Aarch64Fault {
            pc,
            error: ArmError::MemoryError(MemoryFaultInfo {
                address,
                access: AccessType::Read,
                fault_type: MemoryFaultType::Alignment,
                stage2: false,
            }),
        });
    }
    let mut bytes = [0; 8];
    memory
        .read(effective, &mut bytes)
        .map_err(|_| ExitReason::MemoryFault {
            addr: address,
            write: false,
        })?;
    let endian_bit = if state.current_el() == 0 { 24 } else { 25 };
    Ok(if sctlr & (1 << endian_bit) != 0 {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    })
}
