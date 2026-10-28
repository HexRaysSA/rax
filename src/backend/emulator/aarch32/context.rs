//! Complete represented instruction-boundary state of the standalone backend.

use super::{Aarch32Vcpu, BridgeState};
use crate::error::{Error, Result};
use crate::isa::arm::instructions::ExclusiveMonitor;
use crate::isa::arm::{Armv7Cpu, ProcessorMode};
use serde::{Deserialize, Serialize};

const TAG: &[u8; 8] = b"RAXA3202";
const LEGACY_TAG: &[u8; 8] = b"RAXA3201";
const MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct Context<C = Armv7Cpu> {
    id: u32,
    cpu: C,
    exclusive_address: Option<u32>,
    exclusive_size: u8,
    instruction_count: u64,
}

impl Context<crate::isa::arm::aarch32::checkpoint::legacy::LegacyArmv7Cpu> {
    fn into_current(self) -> Context {
        Context {
            id: self.id,
            cpu: self.cpu.into_current(),
            exclusive_address: self.exclusive_address,
            exclusive_size: self.exclusive_size,
            instruction_count: self.instruction_count,
        }
    }
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("AArch32 context: {message}"))
}

pub(crate) fn validate_cpu(cpu: &Armv7Cpu) -> Result<()> {
    if ProcessorMode::from_bits(cpu.cpsr.mode).is_none() {
        return Err(invalid("invalid current processor mode"));
    }
    for psr in [
        &cpu.cpsr,
        &cpu.spsr_fiq,
        &cpu.spsr_irq,
        &cpu.spsr_svc,
        &cpu.spsr_mon,
        &cpu.spsr_abt,
        &cpu.spsr_und,
        &cpu.spsr_hyp,
    ] {
        if psr.ge > 15 || psr.mode & !31 != 0 {
            return Err(invalid("status field exceeds its architectural width"));
        }
    }
    if !matches!(cpu.instruction_size, 2 | 4) {
        return Err(invalid("invalid instruction width"));
    }
    // This adapter owns a standalone A32 PE. An enclosing A64 PE must save
    // its own complete state instead of importing a projected access view.
    if cpu.fp_access_context.is_some() {
        return Err(invalid(
            "enclosing-PE access context is not standalone state",
        ));
    }
    Ok(())
}

impl Context {
    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > TAG.len() + MAX_PAYLOAD {
            return Err(invalid("context exceeds budget"));
        }
        if let Some(payload) = raw.strip_prefix(TAG) {
            crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)
        } else if let Some(payload) = raw.strip_prefix(LEGACY_TAG) {
            let old: Context<crate::isa::arm::aarch32::checkpoint::legacy::LegacyArmv7Cpu> =
                crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?;
            Ok(old.into_current())
        } else {
            Err(invalid("invalid context tag"))
        }
    }

    fn validate(&self, id: u32) -> Result<()> {
        if self.id != id {
            return Err(invalid("vCPU identity differs from target"));
        }
        validate_cpu(&self.cpu)?;
        if self.exclusive_address.is_some() && !matches!(self.exclusive_size, 1 | 2 | 4 | 8) {
            return Err(invalid("invalid exclusive reservation width"));
        }
        Ok(())
    }
}

impl Aarch32Vcpu {
    pub(super) fn validate_context_record(
        &self,
        state: &crate::vm::vcpu::CpuState,
        raw: &[u8],
    ) -> Result<()> {
        let context = Context::decode(raw)?;
        context.validate(self.id)?;
        if crate::codec::serialize(&super::public_state(&context.cpu)).map_err(invalid)?
            != crate::codec::serialize(state).map_err(invalid)?
        {
            return Err(invalid("public registers disagree with backend context"));
        }
        Ok(())
    }

    /// Captures all represented standalone backend state, including banked
    /// registers, CP15, FP controls, exclusives, halt state and the retired count.
    /// Guest RAM remains owned by the caller and must be captured at this same
    /// instruction boundary. The opaque versioned format is separate from the
    /// public register projection returned by `VCpu::get_state`.
    pub fn save_context(&self) -> Result<Vec<u8>> {
        let context = Context {
            id: self.id,
            cpu: self.cpu.clone(),
            exclusive_address: self.excl.address,
            exclusive_size: self.excl.size,
            instruction_count: self.insn_count,
        };
        context.validate(self.id)?;
        let payload = crate::codec::serialize_limited(&context, MAX_PAYLOAD).map_err(invalid)?;
        let mut raw = Vec::with_capacity(TAG.len() + payload.len());
        raw.extend_from_slice(TAG);
        raw.extend_from_slice(&payload);
        Ok(raw)
    }

    /// Restores a context into the same vCPU identity. Decoding and admission
    /// finish before any live state changes; rejected inputs preserve the target.
    /// Cached MMU/fault information is derived again before the next access.
    pub fn restore_context(&mut self, raw: &[u8]) -> Result<()> {
        let context = Context::decode(raw)?;
        context.validate(self.id)?;
        self.cpu = context.cpu;
        self.excl = ExclusiveMonitor {
            address: context.exclusive_address,
            size: context.exclusive_size,
        };
        self.insn_count = context.instruction_count;
        *self.bridge.state.borrow_mut() = BridgeState::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
