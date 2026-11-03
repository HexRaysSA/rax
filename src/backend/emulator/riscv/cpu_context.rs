//! RISC-V instruction-boundary state, including ordered unpublished events.
use super::{PendingEvent, RiscVVcpu, RvUser, RvUserTrap};
use crate::error::{Error, GuestMemoryFault, Result};
use crate::isa::riscv::cpu::{Priv, checkpoint::CoreContext};
use crate::vm::memory::checkpoint::{CheckpointBindings, CheckpointPublication, CpuPublication};
use crate::vm::memory::reservations::Reservation;
use crate::vm::vcpu::CpuState;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(super) struct PendingActivation {
    reservation: Option<Reservation>,
    completed: Arc<AtomicBool>,
}

const TAG: &[u8; 8] = b"RAXRV002";
const LEGACY_TAG: &[u8; 8] = b"RAXRV001";
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
    #[serde(skip)]
    reservation: Option<Reservation>,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("RISC-V context: {message}"))
}

impl Context {
    fn encode(&self) -> Result<Vec<u8>> {
        let payload = crate::codec::serialize_limited(&(self.reservation, self), MAX_PAYLOAD)
            .map_err(invalid)?;
        let mut raw = TAG.to_vec();
        raw.extend_from_slice(&payload);
        Ok(raw)
    }

    fn validate(&self, target: &RiscVVcpu) -> Result<()> {
        self.cpu.validate().map_err(invalid)?;
        if self
            .reservation
            .is_some_and(|r| !r.valid() || !matches!(r.size, 4 | 8))
            || self.reservation.is_some() != self.cpu.reservation_address().is_some()
            || (self.user.is_none()
                && self
                    .reservation
                    .is_some_and(|r| Some(r.address) != self.cpu.reservation_address()))
        {
            return Err(invalid("physical reservation and core LR state differ"));
        }
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
        if raw.len() > TAG.len() + MAX_PAYLOAD {
            return Err(invalid("invalid context length"));
        }
        let context: Self = if raw.starts_with(TAG) {
            let (reservation, mut context): (Option<Reservation>, Self) =
                crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(&raw[8..]).map_err(invalid)?;
            context.reservation = reservation;
            context
        } else if raw.starts_with(LEGACY_TAG) {
            let context: Self =
                crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(&raw[8..]).map_err(invalid)?;
            if context.cpu.reservation_address().is_some() {
                return Err(invalid(
                    "legacy active LR reservation lacks width and shared invalidation state",
                ));
            }
            context
        } else {
            return Err(invalid("invalid context tag"));
        };
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
        let bindings = CheckpointBindings::new(&self.physical_memory, Vec::new());
        let scope = bindings.enter()?;
        self.context_in_scope(&scope)
    }

    pub(super) fn context_for_mapping(
        &self,
        memory: &vm_memory::GuestMemoryMmap,
    ) -> Result<Vec<u8>> {
        let bindings = CheckpointBindings::new(&self.physical_memory, Vec::new());
        let scope = bindings.enter()?;
        let mut context = Context::decode(&self.context_in_scope(&scope)?, self)?;
        if context
            .reservation
            .is_some_and(|reservation| !self.exclusive.same_backing(memory, reservation))
        {
            context.cpu.discard_reservation();
            context.reservation = None;
        }
        context.encode()
    }

    pub(super) fn stage_without_reservation(&mut self) {
        self.checkpoint_activation = Some(PendingActivation {
            reservation: None,
            completed: Arc::new(AtomicBool::new(false)),
        });
    }

    pub(super) fn context_in_scope(&self, scope: &CheckpointPublication<'_>) -> Result<Vec<u8>> {
        if self
            .checkpoint_activation
            .as_ref()
            .is_some_and(|p| !p.completed.load(Ordering::Acquire))
        {
            return Err(invalid("detached CPU has not been published"));
        }
        // Exhaustive: future adapter fields require an explicit classification.
        let Self {
            id,
            cpu,
            pending,
            tohost_addr,
            halted,
            devices_enabled,
            user,
            physical_memory: _,
            exclusive,
            checkpoint_activation: _,
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
        let reservation = scope.capture_reservation(exclusive)?;
        let mut core = cpu.checkpoint_state();
        if reservation.is_none() {
            core.discard_reservation();
        }
        let context = Context {
            id: *id,
            cpu: core,
            reservation,
            pending: events.clone(),
            tohost: *tohost,
            halted: *halted,
            devices_enabled: *devices_enabled,
            user,
        };
        context.validate(self)?;
        context.encode()
    }

    /// Admit the record and acquire every fallible adapter lock before changing
    /// any live hart or adapter field. Existing memory/translation bindings stay
    /// attached; importing another binding mode is rejected before mutation.
    pub fn restore_context(&mut self, raw: &[u8]) -> Result<()> {
        let mut prepared = self.prepare_context(raw)?;
        let bindings = CheckpointBindings::new(&prepared.physical_memory, Vec::new());
        let scope = bindings.enter()?;
        prepared.publication(&scope)?.commit();
        *self = prepared;
        Ok(())
    }

    pub(super) fn prepare_context(&self, raw: &[u8]) -> Result<Self> {
        let context = Context::decode(raw, self)?;
        self.validate_context_record(&context.cpu.public_state(context.tohost), raw)?;
        let mut candidate = match &self.user {
            Some(user) => Self::new_user(
                self.id,
                self.physical_memory.clone(),
                context.cpu.configuration(),
                user.translation.clone(),
            ),
            None => Self::build(
                self.id,
                self.physical_memory.clone(),
                context.cpu.configuration(),
                self.devices_enabled,
            ),
        };
        let reservation = context.reservation;
        candidate.install_context(context)?;
        candidate.checkpoint_activation = Some(PendingActivation {
            reservation,
            completed: Arc::new(AtomicBool::new(false)),
        });
        Ok(candidate)
    }

    fn install_context(&mut self, context: Context) -> Result<()> {
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
    pub(super) fn publication<'scope, 'bindings>(
        &mut self,
        scope: &'scope CheckpointPublication<'bindings>,
    ) -> Result<CpuPublication<'scope, 'bindings>> {
        match &self.checkpoint_activation {
            Some(pending) if !pending.completed.load(Ordering::Acquire) => scope.prepare_memory(
                self.exclusive.clone(),
                pending.reservation,
                pending.completed.clone(),
            ),
            _ => Ok(scope.empty()),
        }
    }

    pub(super) fn ensure_checkpoint_active(&mut self) -> Result<()> {
        if self
            .checkpoint_activation
            .as_ref()
            .is_some_and(|p| !p.completed.load(Ordering::Acquire))
        {
            return Err(invalid("detached CPU has not been published"));
        }
        self.checkpoint_activation = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "cpu_context_tests.rs"]
mod tests;
