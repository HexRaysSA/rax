//! Versioned private execution record and detached publication plan.

use super::*;
use crate::isa::arm::aarch64::cpu::CoreCheckpoint;
use crate::isa::arm::aarch64::cpu::SystemCounterState;
use crate::isa::arm::aarch64::gic::checkpoint::GicCheckpoint;
use crate::vm::memory::checkpoint::{CheckpointBindings, CheckpointPublication, CpuPublication};
use crate::vm::memory::reservations::{Monitor, Reservation};
use crate::vm::snapshot::{AARCH64_CONTEXT, BackendContext};
use serde::{Deserialize, Serialize};

#[path = "checkpoint_clock.rs"]
mod counter_clock;
#[path = "checkpoint_sources.rs"]
mod gic_sources;

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
struct Context<GicState = GicCheckpoint> {
    #[serde(skip)]
    counter_clock: Option<SystemCounterState>,
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
    owned_gic: Option<GicState>,
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
        if cpu.system_counter_state().is_some() && cpu.has_legacy_counter_offset() {
            return Err(invalid("shared system counter has a legacy offset shadow"));
        }
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
            counter_clock: cpu.system_counter_state(),
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
        let state = gic_sources::decode(raw)?;
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

    fn record(&self) -> Result<BackendContext> {
        gic_sources::validate_owned(self)?;
        let mut data = match self.counter_clock {
            Some(clock) => {
                let mut data = if self.owned_gic.is_some() {
                    counter_clock::OWNED_TAG
                } else {
                    counter_clock::TAG
                }
                .to_vec();
                data.extend_from_slice(&counter_clock::encode(clock)?);
                data
            }
            None => if self.owned_gic.is_some() {
                gic_sources::TAG
            } else {
                TAG
            }
            .to_vec(),
        };
        let limit = MAX_PAYLOAD - (data.len() - TAG.len());
        let payload = crate::codec::serialize_limited(self, limit).map_err(invalid)?;
        data.extend_from_slice(&payload);
        Ok(BackendContext {
            kind: AARCH64_CONTEXT,
            data,
        })
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
        cpu.restore_system_counter_binding(self.counter_clock, &target.cpu)
            .map_err(invalid)?;
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
    /// A shared counter is a VM-wide profile, not a per-CPU optional overlay.
    /// This declaration check runs at capture, configuration admission and
    /// in-place restore, before CPU/resource preparation or publication.
    pub(crate) fn validate_counter_clock_set(
        bundle: &crate::vm::snapshot::SnapshotBundle,
    ) -> Result<()> {
        gic_sources::validate_set(bundle)?;
        let Some(records) = bundle.backend_contexts() else {
            return Ok(());
        };
        let entries = records.entries();
        let Some(first) = entries
            .iter()
            .flatten()
            .find(|record| record.kind == AARCH64_CONTEXT && counter_clock::is_tag(&record.data))
        else {
            return Ok(()); // Explicit legacy profiles retain their own domain.
        };
        let declaration = |record: &BackendContext| -> Result<SystemCounterState> {
            if record.kind != AARCH64_CONTEXT || !counter_clock::is_tag(&record.data) {
                return Err(invalid("mixed legacy/shared system counter records"));
            }
            if record.data.len() > MAX_PAYLOAD + TAG.len() {
                return Err(invalid("record exceeds budget"));
            }
            counter_clock::decode(
                record
                    .data
                    .get(8..8 + counter_clock::SIZE)
                    .ok_or_else(|| invalid("truncated system counter header"))?,
            )
        };
        let expected = declaration(first)?;
        let clock = bundle
            .clock()
            .ok_or_else(|| invalid("system counter requires complete VM clock state"))?;
        if clock.mode != expected.mode {
            return Err(invalid("system counter and VM clock modes differ"));
        }
        if bundle.cpus().is_none() || bundle.execution().is_none() {
            return Err(invalid(
                "system counter requires complete CPU/coordinator state",
            ));
        }
        for record in entries {
            let record = record
                .as_ref()
                .ok_or_else(|| invalid("missing system counter private CPU record"))?;
            if declaration(record)? != expected {
                return Err(invalid("system counter declarations differ across CPUs"));
            }
        }
        Ok(())
    }

    pub(super) fn checkpoint_for_remap(&self) -> Result<BackendContext> {
        let bindings = CheckpointBindings::new(&self.physical_memory, self.checkpoint_owned_gics());
        let scope = bindings.enter()?;
        let mut context = Context::capture(self, &scope)?;
        context.reservation = None;
        context.core.invalidate_mapping_reservation();
        context.record()
    }
    pub(super) fn checkpoint_in_scope(
        &self,
        scope: &CheckpointPublication<'_>,
    ) -> Result<BackendContext> {
        let context = Context::capture(self, scope)?;
        context.record()
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
        if counter_clock::is_tag(&raw.data) {
            if candidate.cpu.has_legacy_counter_offset() {
                return Err(invalid("shared system counter has a legacy offset shadow"));
            }
        } else {
            candidate.cpu.migrate_legacy_counter_offset();
        }
        // Compare the original public/private projection before any legacy ID
        // normalization, so migration cannot hide a conflicting source image.
        if raw.data.starts_with(LEGACY_TAG) {
            candidate.cpu.migrate_legacy_fp_profile();
        }
        if !raw.data.starts_with(TAG)
            && !raw.data.starts_with(gic_sources::TAG)
            && !raw.data.starts_with(b"RAXA6405")
            && !counter_clock::is_tag(&raw.data)
        {
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

#[cfg(test)]
#[path = "sve_profile_tests.rs"]
mod sve_profile_tests;

#[cfg(test)]
#[path = "checkpoint_source_tests.rs"]
mod source_tests;
