//! Shared, side-effect-free PAuth execution planning.
//!
//! The plan authenticates before returning any commit action. A load's caller
//! performs one checked 64-bit access before committing destination/writeback;
//! an exception-return caller restores the classified banked state afterward.

use super::pauth::{
    PauthConfig, PauthControls, PauthException, PauthFailure, PauthKeyKind, PauthKeys,
};
use super::pauth_instruction::{PauthInstruction, PauthModifier};
use crate::isa::arm::common::features::ArmFeatures;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauthExecutionError {
    Undefined,
    Exception(PauthException),
    SpAlignment { address: u64 },
    UnsupportedState,
}

impl From<PauthException> for PauthExecutionError {
    fn from(value: PauthException) -> Self {
        Self::Exception(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauthEffect {
    None,
    Register {
        dst: u8,
        value: u64,
    },
    Branch {
        target: u64,
        link: Option<u64>,
        btype: u8,
    },
    ExceptionReturn {
        target: u64,
    },
    Load {
        address: u64,
        dst: u8,
        writeback: Option<(u8, u64)>,
    },
}

pub struct PauthInputs<'a> {
    pub x: &'a [u64; 31],
    pub sp: u64,
    /// Address of this instruction, before any advance.
    pub pc: u64,
    pub elr: u64,
    pub guarded: bool,
}

impl PauthInputs<'_> {
    fn register(&self, index: u8) -> u64 {
        self.x.get(usize::from(index)).copied().unwrap_or(0)
    }
    fn modifier(&self, modifier: PauthModifier) -> u64 {
        match modifier {
            PauthModifier::Zero => 0,
            PauthModifier::Sp => self.sp,
            PauthModifier::Register(index) => self.register(index),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PauthEnvironment {
    pub features: ArmFeatures,
    pub config: PauthConfig,
    pub controls: PauthControls,
    pub keys: PauthKeys,
}

impl PauthEnvironment {
    /// Decode-time checks run before PC advance, BTYPE clearing or data effects.
    pub fn check_entry(
        &self,
        raw: u32,
        pstate: u64,
        guarded: Option<bool>,
    ) -> Result<(), PauthExecutionError> {
        let exception = |ec, iss| {
            PauthExecutionError::Exception(PauthException {
                ec,
                iss,
                target_el: Some(self.controls.local_exception_target()),
            })
        };
        if pstate & (1 << 20) != 0 {
            return Err(exception(0x0e, 0));
        }
        let btype = ((pstate >> 10) & 3) as u8;
        if self.features.contains(ArmFeatures::BTI) && btype != 0 {
            let guarded = guarded.ok_or(PauthExecutionError::UnsupportedState)?;
            if guarded
                && !self.controls.branch_target_compatible(
                    raw,
                    btype,
                    self.features.contains(ArmFeatures::PACA),
                )
            {
                return Err(exception(0x0d, u32::from(btype)));
            }
        }
        Ok(())
    }

    pub fn value(
        &self,
        pointer: u64,
        modifier: u64,
        key: PauthKeyKind,
        authenticate: bool,
        combined: bool,
    ) -> Result<u64, PauthExecutionError> {
        if !self.controls.key_enabled(key)? {
            return Ok(pointer);
        }
        let layout = self.controls.layout(pointer, key.data());
        let key_value = self.keys.get(key);
        if !authenticate {
            return Ok(layout.sign(
                self.config.algorithm,
                self.config.profile,
                pointer,
                modifier,
                key_value,
            ));
        }
        layout
            .authenticate(
                self.config.algorithm,
                self.config.profile,
                pointer,
                modifier,
                key_value,
                PauthFailure {
                    data: key.data(),
                    key_b: key.key_b(),
                },
                combined,
            )
            .map_err(|failure| {
                let mut exception = PauthException::authentication(failure.data, failure.key_b);
                exception.target_el = Some(self.controls.local_exception_target());
                PauthExecutionError::Exception(exception)
            })
    }

    pub fn plan(
        &self,
        instruction: PauthInstruction,
        inputs: PauthInputs<'_>,
    ) -> Result<PauthEffect, PauthExecutionError> {
        let controls = self.controls;
        if controls.current_el > 3
            || controls.implemented_els & 3 != 3
            || controls.implemented_els & !15 != 0
            || controls.implemented_els & (1 << controls.current_el) == 0
            || controls.vhe != self.features.contains(ArmFeatures::VHE)
            || controls.secure_el2 != self.features.contains(ArmFeatures::SEL2)
            || controls.sctlr[0] != 0
            || controls.tcr[0] != 0
        {
            return Err(PauthExecutionError::UnsupportedState);
        }
        if !instruction.valid_operands() {
            return Err(PauthExecutionError::Undefined);
        }
        let required = if matches!(instruction, PauthInstruction::Generic { .. }) {
            ArmFeatures::PACG
        } else {
            ArmFeatures::PACA
        };
        if !self.features.contains(required) {
            return if instruction.is_hint() {
                Ok(PauthEffect::None)
            } else {
                Err(PauthExecutionError::Undefined)
            };
        }
        let ia = |key_b| {
            if key_b {
                PauthKeyKind::Ib
            } else {
                PauthKeyKind::Ia
            }
        };
        Ok(match instruction {
            PauthInstruction::Sign {
                dst, modifier, key, ..
            } => PauthEffect::Register {
                dst,
                value: self.value(
                    inputs.register(dst),
                    inputs.modifier(modifier),
                    key,
                    false,
                    false,
                )?,
            },
            PauthInstruction::Authenticate {
                dst, modifier, key, ..
            } => PauthEffect::Register {
                dst,
                value: self.value(
                    inputs.register(dst),
                    inputs.modifier(modifier),
                    key,
                    true,
                    false,
                )?,
            },
            PauthInstruction::Strip { dst, data, .. } => PauthEffect::Register {
                dst,
                value: controls
                    .layout(inputs.register(dst), data)
                    .strip(inputs.register(dst)),
            },
            PauthInstruction::Generic {
                dst,
                data,
                modifier,
            } => {
                controls.key_enabled(PauthKeyKind::Ga)?;
                PauthEffect::Register {
                    dst,
                    value: self.config.algorithm.compute(
                        inputs.register(data),
                        inputs.modifier(modifier),
                        self.keys.ga,
                    ) & 0xffff_ffff_0000_0000,
                }
            }
            PauthInstruction::Branch {
                target,
                modifier,
                key_b,
                link,
            } => {
                let address = self.value(
                    inputs.register(target),
                    inputs.modifier(modifier),
                    ia(key_b),
                    true,
                    true,
                )?;
                PauthEffect::Branch {
                    target: controls.branch_address(address),
                    link: link.then(|| inputs.pc.wrapping_add(4)),
                    btype: if link {
                        2
                    } else if inputs.guarded && target != 16 && target != 17 {
                        3
                    } else {
                        1
                    },
                }
            }
            PauthInstruction::Return { key_b } => PauthEffect::Branch {
                target: controls.branch_address(self.value(
                    inputs.register(30),
                    inputs.sp,
                    ia(key_b),
                    true,
                    true,
                )?),
                link: None,
                btype: 0,
            },
            PauthInstruction::ExceptionReturn { key_b } => {
                if controls.current_el == 0 {
                    return Err(PauthExecutionError::Undefined);
                }
                if controls.current_el == 1
                    && controls.el2_enabled()
                    && self.features.contains(ArmFeatures::NV)
                    && controls.hcr_el2 & (1 << 42) != 0
                {
                    return Err(PauthException {
                        ec: 0x1a,
                        iss: 2 | u32::from(key_b),
                        target_el: Some(2),
                    }
                    .into());
                }
                PauthEffect::ExceptionReturn {
                    target: self.value(inputs.elr, inputs.sp, ia(key_b), true, true)?,
                }
            }
            PauthInstruction::Load {
                dst,
                base,
                offset,
                writeback,
                key_b,
            } => {
                let key = if key_b {
                    PauthKeyKind::Db
                } else {
                    PauthKeyKind::Da
                };
                let pointer = if base == 31 {
                    inputs.sp
                } else {
                    inputs.register(base)
                };
                let original = self.value(pointer, 0, key, true, true)?;
                let alignment_bit = if controls.current_el == 0 { 4 } else { 3 };
                if base == 31
                    && controls.sctlr[controls.regime_el()] & (1 << alignment_bit) != 0
                    && inputs.sp & 15 != 0
                {
                    return Err(PauthExecutionError::SpAlignment { address: inputs.sp });
                }
                let address = original.wrapping_add(i64::from(offset) as u64);
                PauthEffect::Load {
                    address,
                    dst,
                    writeback: writeback.then_some((base, address)),
                }
            }
        })
    }
}
