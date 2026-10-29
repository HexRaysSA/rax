//! Versioned private execution record and detached publication plan.

use super::*;
use crate::isa::arm::aarch64::cpu::CoreCheckpoint;
use crate::isa::arm::aarch64::gic::checkpoint::GicCheckpoint;
use crate::vm::memory::checkpoint::{CheckpointBindings, CheckpointPublication, CpuPublication};
use crate::vm::memory::reservations::{Monitor, Reservation};
use crate::vm::snapshot::{AARCH64_CONTEXT, BackendContext};
use serde::{Deserialize, Serialize};

const TAG: &[u8; 8] = b"RAXA6403";
const PREVIOUS_TAG: &[u8; 8] = b"RAXA6402";
const LEGACY_TAG: &[u8; 8] = b"RAXA6401";
const MAX_PAYLOAD: usize = 16 * 1024 * 1024 - TAG.len();

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "optional_profile_tests.rs"]
mod optional_profile_tests;

pub(super) struct PendingActivation {
    completed: Arc<AtomicBool>,
    reservation: Option<Reservation>,
    owned_gic: Option<GicCheckpoint>,
    event: (Arc<AtomicBool>, bool),
}

#[derive(Serialize, Deserialize)]
struct UserCheckpoint {
    trap: Option<A64UserTrap>,
    not_retired: u64,
}

#[derive(Serialize, Deserialize)]
struct Context {
    id: u32,
    core: CoreCheckpoint,
    observed_instructions: u64,
    trace_reg_last: u64,
    heartbeat_age: std::time::Duration,
    shutdown: bool,
    fault_exits: bool,
    powered_off: bool,
    clustered: bool,
    uart_bound: bool,
    recording: bool,
    observations: Vec<MemRecord>,
    user: Option<UserCheckpoint>,
    reservation: Option<Reservation>,
    owned_gic: Option<GicCheckpoint>,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("AArch64 backend context: {message}"))
}

impl Context {
    fn capture(cpu: &Aarch64Vcpu, scope: &CheckpointPublication<'_>) -> Result<Self> {
        let Aarch64Vcpu {
            id,
            cpu,
            late,
            recorder,
            insn_count,
            last_heartbeat,
            heartbeat_offset,
            trace_reg_last,
            shutdown,
            fault_exits,
            user,
            cluster,
            powered_off,
            physical_memory: _,
            exclusive,
            checkpoint_activation,
        } = cpu;
        if checkpoint_activation
            .as_ref()
            .is_some_and(|state| !state.completed.load(Ordering::Acquire))
        {
            return Err(invalid("detached CPU has not been published"));
        }
        cpu.validate_fp_profile().map_err(invalid)?;
        let core = CoreCheckpoint::capture(cpu).map_err(invalid)?;
        let observations = recorder
            .records
            .lock()
            .map_err(|_| invalid("observation lock poisoned"))?;
        // A record needs at least one access byte, one width byte and three
        // u64 fields, independent of the codec's enum representation.
        if observations.len() > MAX_PAYLOAD / 26 {
            return Err(invalid("memory observations exceed record budget"));
        }
        let owned_gic = if core.owns_gic() {
            Some(
                scope.capture_gic(
                    &cpu.gic_handle()
                        .ok_or_else(|| invalid("missing owned GIC"))?,
                )?,
            )
        } else {
            None
        };
        Ok(Self {
            id: *id,
            core,
            observed_instructions: insn_count.load(Ordering::Relaxed),
            trace_reg_last: *trace_reg_last,
            heartbeat_age: last_heartbeat.elapsed().saturating_add(*heartbeat_offset),
            shutdown: *shutdown,
            fault_exits: *fault_exits,
            powered_off: *powered_off,
            clustered: cluster.is_some(),
            uart_bound: late.uart.get().is_some(),
            recording: recorder.enabled.load(Ordering::Relaxed),
            observations: observations.clone(),
            user: user.as_ref().map(|state| UserCheckpoint {
                trap: state.trap,
                not_retired: state.not_retired,
            }),
            reservation: exclusive.get(),
            owned_gic,
        })
    }

    fn decode(raw: &[u8], target: &Aarch64Vcpu) -> Result<Self> {
        let payload = raw
            .strip_prefix(TAG)
            .or_else(|| raw.strip_prefix(PREVIOUS_TAG))
            .or_else(|| raw.strip_prefix(LEGACY_TAG))
            .ok_or_else(|| invalid("invalid tag"))?;
        if payload.len() > MAX_PAYLOAD {
            return Err(invalid("record exceeds budget"));
        }
        let state: Self =
            crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?;
        if state.id != target.id
            || state.user.is_some() != target.user.is_some()
            || state.clustered != target.cluster.is_some()
            || state.uart_bound != target.late.uart.get().is_some()
            || state.fault_exits != target.fault_exits
        {
            return Err(invalid("target CPU/device/translation binding differs"));
        }
        if state.core.owns_gic() != state.owned_gic.is_some()
            || state.reservation.is_some_and(|value| !value.valid())
        {
            return Err(invalid("invalid controller or reservation state"));
        }
        Ok(state)
    }

    fn prepare(self, target: &Aarch64Vcpu) -> Result<Aarch64Vcpu> {
        let late = target.late.clone();
        let recorder = Arc::new(MemRecorder {
            enabled: AtomicBool::new(self.recording),
            records: Mutex::new(self.observations),
        });
        let exclusive =
            crate::vm::memory::reservations::MemoryDomain::for_memory(&target.physical_memory)
                .register();
        let bridge = GuestBridge {
            cluster: target.cluster.clone(),
            mem: target.physical_memory.clone(),
            late: late.clone(),
            recorder: recorder.clone(),
            devices_enabled: !self.fault_exits,
            gic_cpus: target.cluster.as_ref().map_or(1, |cluster| cluster.count()),
            gic_high_base: target.cluster.as_ref().map_or(
                crate::machine::arm_virt::AARCH64_GICR_HIGH_BASE,
                |cluster| cluster.high_redist_base,
            ),
            translation: target.user.as_ref().map(|user| user.translation.clone()),
            exclusive: exclusive.clone(),
        };
        let mut cpu =
            AArch64Cpu::new_with_cpu_id(self.core.configuration(), Box::new(bridge), self.id);
        cpu.retain_checkpoint_bindings(&target.cpu);
        self.core.install_in_prepared(&mut cpu).map_err(invalid)?;
        if let Some(state) = &self.owned_gic {
            cpu.gic_handle()
                .ok_or_else(|| invalid("missing target GIC"))?
                .lock()
                .map_err(|_| invalid("target GIC lock poisoned"))?
                .validate_checkpoint(state)?;
        }
        let user = match (self.user, &target.user) {
            (Some(state), Some(binding)) => Some(A64User {
                translation: binding.translation.clone(),
                trap: state.trap,
                not_retired: state.not_retired,
            }),
            (None, None) => None,
            _ => return Err(invalid("user binding differs")),
        };
        let event = (target.cpu.event_register_handle(), cpu.event_pending());
        Ok(Aarch64Vcpu {
            id: self.id,
            cpu,
            late,
            recorder,
            insn_count: Arc::new(AtomicU64::new(self.observed_instructions)),
            last_heartbeat: crate::host::time::Instant::now(),
            heartbeat_offset: self.heartbeat_age,
            trace_reg_last: self.trace_reg_last,
            shutdown: self.shutdown,
            fault_exits: self.fault_exits,
            user,
            cluster: target.cluster.clone(),
            powered_off: self.powered_off,
            physical_memory: target.physical_memory.clone(),
            exclusive,
            checkpoint_activation: Some(PendingActivation {
                completed: Arc::new(AtomicBool::new(false)),
                reservation: self.reservation,
                owned_gic: self.owned_gic,
                event,
            }),
        })
    }
}

impl Aarch64Vcpu {
    pub(super) fn checkpoint_for_remap(&self) -> Result<BackendContext> {
        let bindings = CheckpointBindings::new(&self.physical_memory, self.checkpoint_owned_gics());
        let scope = bindings.enter()?;
        let mut context = Context::capture(self, &scope)?;
        context.reservation = None;
        context.core.invalidate_mapping_reservation();
        let payload = crate::codec::serialize_limited(&context, MAX_PAYLOAD).map_err(invalid)?;
        let mut data = TAG.to_vec();
        data.extend_from_slice(&payload);
        Ok(BackendContext {
            kind: AARCH64_CONTEXT,
            data,
        })
    }
    pub(super) fn checkpoint_in_scope(
        &self,
        scope: &CheckpointPublication<'_>,
    ) -> Result<BackendContext> {
        let context = Context::capture(self, scope)?;
        let payload = crate::codec::serialize_limited(&context, MAX_PAYLOAD).map_err(invalid)?;
        let mut data = Vec::with_capacity(TAG.len() + payload.len());
        data.extend_from_slice(TAG);
        data.extend_from_slice(&payload);
        Ok(BackendContext {
            kind: AARCH64_CONTEXT,
            data,
        })
    }

    pub(super) fn prepare_private_checkpoint(
        &self,
        state: &CpuState,
        raw: &BackendContext,
    ) -> Result<Self> {
        if raw.kind != AARCH64_CONTEXT {
            return Err(invalid("producer differs"));
        }
        let mut candidate = Context::decode(&raw.data, self)?.prepare(self)?;
        candidate
            .validate_checkpoint_state(state, &crate::vm::snapshot::EmulatorState::default())?;
        match (candidate.get_state()?, state) {
            (CpuState::Aarch64(actual), CpuState::Aarch64(expected)) if actual == *expected => {}
            _ => return Err(invalid("public and private projections differ")),
        }
        // Compare the original public/private projection before any legacy ID
        // normalization, so migration cannot hide a conflicting source image.
        if raw.data.starts_with(LEGACY_TAG) {
            candidate.cpu.migrate_legacy_fp_profile();
        }
        if !raw.data.starts_with(TAG) {
            candidate
                .cpu
                .migrate_legacy_optional_fp_profile()
                .map_err(invalid)?;
        }
        candidate.cpu.validate_fp_profile().map_err(invalid)?;
        Ok(candidate)
    }

    pub(super) fn publication<'scope, 'bindings>(
        &mut self,
        scope: &'scope CheckpointPublication<'bindings>,
    ) -> Result<CpuPublication<'scope, 'bindings>> {
        let Some(pending) = &mut self.checkpoint_activation else {
            return Ok(scope.empty());
        };
        if pending.completed.load(Ordering::Acquire) {
            return Ok(scope.empty());
        }
        let owned = pending
            .owned_gic
            .as_ref()
            .map(|state| {
                self.cpu
                    .gic_handle()
                    .map(|handle| (handle, state.clone()))
                    .ok_or_else(|| invalid("missing owned controller"))
            })
            .transpose()?;
        let permit = scope.prepare_aarch64(
            self.exclusive.clone(),
            pending.reservation,
            owned,
            pending.event.clone(),
            pending.completed.clone(),
        )?;
        self.cpu.bind_event_register(pending.event.0.clone());
        Ok(permit)
    }

    pub(super) fn ensure_checkpoint_active(&mut self) -> Result<()> {
        if self
            .checkpoint_activation
            .as_ref()
            .is_some_and(|pending| !pending.completed.load(Ordering::Acquire))
        {
            return Err(invalid("detached CPU has not completed publication"));
        }
        self.checkpoint_activation = None;
        Ok(())
    }

    pub(super) fn checkpoint_without_scope(&self) -> Result<BackendContext> {
        let bindings = CheckpointBindings::new(&self.physical_memory, self.checkpoint_owned_gics());
        let scope = bindings.enter()?;
        self.checkpoint_in_scope(&scope)
    }
}

#[cfg(test)]
#[path = "retirement_counter_tests.rs"]
mod retirement_counters;

#[cfg(test)]
#[path = "event_checkpoint_tests.rs"]
mod event_tests;
