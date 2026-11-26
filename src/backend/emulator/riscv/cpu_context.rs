//! RISC-V instruction-boundary state, including ordered unpublished events.
use super::{PendingEvent, RiscVVcpu, RvUser, RvUserTrap};
use crate::backend::emulator::riscv::platform::Signals;
use crate::error::{Error, GuestMemoryFault, Result};
use crate::isa::riscv::cpu::{Priv, checkpoint::CoreContext};
use crate::vm::memory::checkpoint::{CheckpointBindings, CheckpointPublication, CpuPublication};
use crate::vm::memory::reservations::Reservation;
use crate::vm::snapshot::{BackendContext, CpuSnapshot, RISCV_CONTEXT};
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

const TAG: &[u8; 8] = b"RAXRV005";
const WAITING_TAG: &[u8; 8] = b"RAXRV006";
const SV39_TAG: &[u8; 8] = b"RAXRV007";
const ISSUED_UART_TAG: &[u8; 8] = b"RAXRV008";
const SV39_HART_PROFILE: u8 = 0b0111;
const SV39_WAITING_FLAG: u8 = 0b1000;
const SPLIT_SEIP_TAG: &[u8; 8] = b"RAXRV004";
const PLATFORM_TAG: &[u8; 8] = b"RAXRV003";
const PREVIOUS_TAG: &[u8; 8] = b"RAXRV002";
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
    #[serde(skip)]
    platform: bool,
    #[serde(skip)]
    plic: bool,
    #[serde(skip)]
    sv39: bool,
    #[serde(skip)]
    waiting_for_interrupt: bool,
    #[serde(skip)]
    uart_write_issued: bool,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("RISC-V context: {message}"))
}

struct Header {
    platform: bool,
    plic: bool,
    sv39: bool,
    external_seip: bool,
    payload_offset: usize,
    has_reservation_record: bool,
    waiting_for_interrupt: bool,
    uart_write_issued: bool,
}

impl Header {
    const MAX_LEN: usize = 10;

    fn decode(raw: &[u8]) -> Result<Self> {
        let flag = |index, name| match raw.get(index) {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(invalid(name)),
        };
        let profiles = || match raw.get(8) {
            Some(0) => Ok((false, false)),
            Some(1) => Ok((true, false)),
            Some(3) => Ok((true, true)),
            _ => Err(invalid("invalid platform profile")),
        };
        let uart_write_issued = raw.starts_with(ISSUED_UART_TAG);
        let sv39 = raw.starts_with(SV39_TAG)
            || (uart_write_issued && raw.get(8) == Some(&SV39_HART_PROFILE));
        let ((platform, plic), external_seip, payload_offset, has_reservation_record) =
            match raw.get(..8) {
                Some(_) if sv39 => {
                    let profile = *raw.get(8).ok_or_else(|| invalid("missing Sv39 profile"))?;
                    if profile & !SV39_WAITING_FLAG != SV39_HART_PROFILE {
                        return Err(invalid("invalid Sv39 profile"));
                    }
                    (
                        (true, true),
                        flag(9, "invalid external SEIP level")?,
                        Self::MAX_LEN,
                        true,
                    )
                }
                Some(tag) if tag == TAG || tag == WAITING_TAG || uart_write_issued => (
                    profiles()?,
                    flag(9, "invalid external SEIP level")?,
                    Self::MAX_LEN,
                    true,
                ),
                Some(tag) if tag == SPLIT_SEIP_TAG => (
                    (flag(8, "invalid platform profile")?, false),
                    flag(9, "invalid external SEIP level")?,
                    Self::MAX_LEN,
                    true,
                ),
                Some(tag) if tag == PLATFORM_TAG => (
                    (flag(8, "invalid platform profile")?, false),
                    false,
                    9,
                    true,
                ),
                Some(tag) if tag == PREVIOUS_TAG => ((false, false), false, 8, true),
                Some(tag) if tag == LEGACY_TAG => ((false, false), false, 8, false),
                _ => return Err(invalid("invalid context tag")),
            };
        Ok(Self {
            platform,
            plic,
            sv39,
            external_seip,
            payload_offset,
            has_reservation_record,
            waiting_for_interrupt: raw.starts_with(WAITING_TAG)
                || (sv39 && raw[8] & SV39_WAITING_FLAG != 0),
            uart_write_issued,
        })
    }
}

pub(super) fn platform_profiles(raw: &[u8]) -> Result<(bool, bool, bool)> {
    let header = Header::decode(raw)?;
    Ok((header.platform, header.plic, header.sv39))
}

pub(super) fn checkpoint_profiles(raw: &[u8]) -> Result<([bool; 3], bool)> {
    let header = Header::decode(raw)?;
    Ok((
        [header.platform, header.plic, header.sv39],
        header.uart_write_issued,
    ))
}

impl Context {
    fn encode(&self) -> Result<Vec<u8>> {
        let payload = crate::codec::serialize_limited(&(self.reservation, self), MAX_PAYLOAD)
            .map_err(invalid)?;
        let mut raw = if self.uart_write_issued {
            ISSUED_UART_TAG
        } else if self.sv39 {
            SV39_TAG
        } else if self.waiting_for_interrupt {
            WAITING_TAG
        } else {
            TAG
        }
        .to_vec();
        if self.sv39 {
            raw.push(SV39_HART_PROFILE | (u8::from(self.waiting_for_interrupt) << 3));
        } else {
            raw.push(u8::from(self.platform) | (u8::from(self.plic) << 1));
        }
        raw.push(u8::from(self.cpu.external_seip()));
        raw.extend_from_slice(&payload);
        Ok(raw)
    }

    fn validate(&self, target: &RiscVVcpu) -> Result<()> {
        self.cpu.validate().map_err(invalid)?;
        self.cpu
            .validate_supervisor_translation(self.sv39)
            .map_err(invalid)?;
        if self.sv39 && (!self.platform || !self.plic || self.user.is_some()) {
            return Err(invalid("Sv39 requires the coordinated system platform"));
        }
        if self.platform && target.platform.is_none() {
            return Err(invalid(
                "CLINT context requires a configured shared platform",
            ));
        }
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
        if self.user.is_some()
            && (self.cpu.privilege() != Priv::User
                || !self.pending.is_empty()
                || self.cpu.external_seip())
        {
            return Err(invalid(
                "invalid process-mode privilege, event queue or external SEIP line",
            ));
        }
        if self.waiting_for_interrupt
            && (self.halted
                || self.user.is_some()
                || !self.pending.is_empty()
                || !self.platform
                || !target
                    .platform
                    .as_ref()
                    .is_some_and(|p| p.supports_interrupt_wait(self.sv39)))
        {
            return Err(invalid(
                "interrupt wait requires a supported system profile and clock",
            ));
        }
        if self.uart_write_issued
            && (!target.uses_coordinated_uart()
                || self.halted
                || !matches!(self.pending.front(), Some(PendingEvent::MmioWrite { .. })))
        {
            return Err(invalid(
                "issued UART write requires a bound VMM and queued write",
            ));
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

    fn decode_record(raw: &[u8]) -> Result<Self> {
        if raw.len() > Header::MAX_LEN + MAX_PAYLOAD {
            return Err(invalid("invalid context length"));
        }
        let header = Header::decode(raw)?;
        let payload = &raw[header.payload_offset..];
        let mut context = if header.has_reservation_record {
            let (reservation, mut context): (Option<Reservation>, Self) =
                crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?;
            context.reservation = reservation;
            context
        } else {
            let context: Self =
                crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?;
            if context.cpu.reservation_address().is_some() {
                return Err(invalid(
                    "legacy active LR reservation lacks width and shared invalidation state",
                ));
            }
            context
        };
        context.platform = header.platform;
        context.plic = header.plic;
        context.sv39 = header.sv39;
        context.waiting_for_interrupt = header.waiting_for_interrupt;
        context.uart_write_issued = header.uart_write_issued;
        context.cpu.set_external_seip(header.external_seip);
        Ok(context)
    }

    fn decode(raw: &[u8], target: &RiscVVcpu) -> Result<Self> {
        let context = Self::decode_record(raw)?;
        context.validate(target)?;
        Ok(context)
    }
}

/// Refresh a freshly captured pair under the shared platform boundary. The
/// hart's last execution sample can precede the file's clock and device state.
pub(crate) fn refresh_checkpoint_signals(
    hart: usize,
    signals: Signals,
    public: &mut CpuSnapshot,
    private: Option<&mut BackendContext>,
) -> Result<()> {
    let record = private
        .filter(|record| record.kind == RISCV_CONTEXT)
        .ok_or_else(|| invalid("shared platform capture requires a private hart record"))?;
    let mut context = Context::decode_record(&record.data)?;
    if context.id as usize != hart
        || !context.platform
        || context.plic != signals.external.is_some()
    {
        return Err(invalid("captured hart differs from shared platform"));
    }
    context.cpu.set_platform_inputs(
        signals.time,
        signals.software,
        signals.timer,
        signals.external,
    );
    public.state = context.cpu.public_state(context.tohost);
    record.data = context.encode()?;
    Ok(())
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
            uart_write_issued,
            tohost_addr,
            halted,
            waiting_for_interrupt,
            devices_enabled,
            platform,
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
            waiting_for_interrupt: *waiting_for_interrupt,
            uart_write_issued: *uart_write_issued,
            devices_enabled: *devices_enabled,
            platform: platform.as_ref().is_some_and(|p| p.enabled()),
            plic: platform.as_ref().is_some_and(|p| p.plic_enabled()),
            sv39: platform.as_ref().is_some_and(|p| p.sv39_enabled()),
            user,
        };
        context.validate(self)?;
        context.encode()
    }

    /// Admit the record and acquire every fallible adapter lock before changing
    /// any live hart or adapter field. Existing memory/translation bindings stay
    /// attached; importing another binding mode is rejected before mutation.
    pub fn restore_context(&mut self, raw: &[u8]) -> Result<()> {
        let live = self.platform.as_ref().map_or((false, false, false), |p| {
            (p.enabled(), p.plic_enabled(), p.sv39_enabled())
        });
        if platform_profiles(raw)? != live {
            return Err(invalid(
                "single-hart restore requires matching shared platform profile",
            ));
        }
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
                self.platform.clone(),
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
        self.uart_write_issued = context.uart_write_issued;
        *tohost = context.tohost;
        self.halted = context.halted;
        self.waiting_for_interrupt = context.waiting_for_interrupt;
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
