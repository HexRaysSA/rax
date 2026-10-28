//! RISC-V instruction-boundary state, including ordered unpublished events.
use super::{PendingEvent, RiscVVcpu, RvUser, RvUserTrap};
use crate::error::{Error, GuestMemoryFault, Result};
use crate::isa::riscv::cpu::{Priv, checkpoint::CoreContext};
use crate::vm::vcpu::CpuState;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const TAG: &[u8; 8] = b"RAXRV001";
const MAX_PAYLOAD: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct UserContext {
    last_fault: Option<GuestMemoryFault>,
    trap: Option<RvUserTrap>,
    ecalls: u64,
}

#[derive(Serialize, Deserialize)]
struct Context {
    id: u32,
    cpu: CoreContext,
    pending: VecDeque<PendingEvent>,
    tohost: Option<u64>,
    halted: bool,
    devices_enabled: bool,
    user: Option<UserContext>,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("RISC-V context: {message}"))
}

impl Context {
    fn validate(&self, target: &RiscVVcpu) -> Result<()> {
        self.cpu.validate().map_err(invalid)?;
        if self.id != target.id || self.cpu.hart_id() != u64::from(self.id) {
            return Err(invalid("hart identity differs from target"));
        }
        if self.devices_enabled != target.devices_enabled
            || self.user.is_some() != target.user.is_some()
        {
            return Err(invalid("memory/device binding mode differs from target"));
        }
        if self.user.is_some() && (self.cpu.privilege() != Priv::User || !self.pending.is_empty()) {
            return Err(invalid("invalid process-mode privilege or event queue"));
        }
        for event in &self.pending {
            match event {
                PendingEvent::MmioWrite { addr, data }
                    if !super::in_uart(*addr) || data.is_empty() =>
                {
                    return Err(invalid("invalid queued UART transaction"));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn decode(raw: &[u8], target: &RiscVVcpu) -> Result<Self> {
        if raw.len() > TAG.len() + MAX_PAYLOAD || !raw.starts_with(TAG) {
            return Err(invalid("invalid context tag or length"));
        }
        let context: Self = crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(&raw[TAG.len()..])
            .map_err(invalid)?;
        context.validate(target)?;
        Ok(context)
    }
}

impl RiscVVcpu {
    pub(super) fn context_configuration(
        &self,
        raw: &[u8],
    ) -> Result<crate::isa::riscv::RiscVConfig> {
        Ok(Context::decode(raw, self)?.cpu.configuration())
    }

    pub(super) fn validate_context_record(&self, state: &CpuState, raw: &[u8]) -> Result<()> {
        let context = Context::decode(raw, self)?;
        if crate::codec::serialize(&context.cpu.public_state(context.tohost)).map_err(invalid)?
            != crate::codec::serialize(state).map_err(invalid)?
        {
            return Err(invalid("public registers disagree with backend context"));
        }
        let _events = self
            .pending
            .lock()
            .map_err(|_| invalid("event queue poisoned"))?;
        let _tohost = self
            .tohost_addr
            .lock()
            .map_err(|_| invalid("tohost lock poisoned"))?;
        if let Some(user) = &self.user {
            drop(
                user.last_fault
                    .lock()
                    .map_err(|_| invalid("fault lock poisoned"))?,
            );
        }
        Ok(())
    }

    /// Save the complete represented hart and adapter state at an instruction
    /// boundary. The caller owns matching RAM and any process translation map.
    /// Host code-cache entries and their diagnostic counters are derived.
    pub fn save_context(&self) -> Result<Vec<u8>> {
        // Exhaustive: future adapter fields require an explicit classification.
        let Self {
            id,
            cpu,
            pending,
            tohost_addr,
            halted,
            devices_enabled,
            user,
        } = self;
        let events = pending
            .lock()
            .map_err(|_| invalid("event queue poisoned"))?;
        let tohost = tohost_addr
            .lock()
            .map_err(|_| invalid("tohost lock poisoned"))?;
        let user = match user {
            Some(RvUser {
                translation: _,
                last_fault,
                trap,
                ecalls,
            }) => Some(UserContext {
                last_fault: *last_fault
                    .lock()
                    .map_err(|_| invalid("fault lock poisoned"))?,
                trap: *trap,
                ecalls: *ecalls,
            }),
            None => None,
        };
        let context = Context {
            id: *id,
            cpu: cpu.checkpoint_state(),
            pending: events.clone(),
            tohost: *tohost,
            halted: *halted,
            devices_enabled: *devices_enabled,
            user,
        };
        context.validate(self)?;
        let payload = crate::codec::serialize_limited(&context, MAX_PAYLOAD).map_err(invalid)?;
        let mut raw = Vec::with_capacity(TAG.len() + payload.len());
        raw.extend_from_slice(TAG);
        raw.extend_from_slice(&payload);
        Ok(raw)
    }

    /// Admit the record and acquire every fallible adapter lock before changing
    /// any live hart or adapter field. Existing memory/translation bindings stay
    /// attached; importing another binding mode is rejected before mutation.
    pub fn restore_context(&mut self, raw: &[u8]) -> Result<()> {
        let context = Context::decode(raw, self)?;
        let mut events = self
            .pending
            .lock()
            .map_err(|_| invalid("event queue poisoned"))?;
        let mut tohost = self
            .tohost_addr
            .lock()
            .map_err(|_| invalid("tohost lock poisoned"))?;
        let user_parts = match self.user.as_mut() {
            Some(RvUser {
                translation: _,
                last_fault,
                trap,
                ecalls,
            }) => Some((
                last_fault
                    .lock()
                    .map_err(|_| invalid("fault lock poisoned"))?,
                trap,
                ecalls,
            )),
            None => None,
        };
        context.cpu.install(&mut self.cpu);
        *events = context.pending;
        *tohost = context.tohost;
        self.halted = context.halted;
        if let (Some((mut fault, trap, ecalls)), Some(saved)) = (user_parts, context.user) {
            *fault = saved.last_fault;
            *trap = saved.trap;
            *ecalls = saved.ecalls;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "cpu_context_tests.rs"]
mod tests;
