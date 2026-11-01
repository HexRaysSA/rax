//! Versioned private Cortex-M context and detached CPU publication.
use super::*;
use crate::isa::arm::cortex_m::cpu::CoreCheckpoint;
use crate::vm::memory::checkpoint::{CheckpointBindings, CheckpointPublication, CpuPublication};
use crate::vm::snapshot::{BackendContext, CORTEX_M_CONTEXT, EmulatorState};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

const TAG: &[u8; 8] = b"RAXCM001";
const MAX_PAYLOAD: usize = 16 * 1024 * 1024 - 8;
#[derive(Serialize, Deserialize)]
struct Context {
    id: u32,
    core: CoreCheckpoint,
    fault: Option<GuestMemoryFault>,
    exclusive: Option<(u64, u8)>,
}
fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("Cortex-M checkpoint: {message}"))
}
impl CortexMVcpu {
    fn check_publication(&self) -> Result<()> {
        if self
            .checkpoint_publication
            .as_ref()
            .is_some_and(|done| !done.load(Ordering::Acquire))
        {
            return Err(invalid("detached CPU has not been published"));
        }
        Ok(())
    }
    pub(super) fn finish_publication(&mut self) -> Result<()> {
        self.check_publication()?;
        self.checkpoint_publication = None;
        Ok(())
    }
    fn validate_exclusive(&self, exclusive: Option<(u64, u8)>) -> Result<()> {
        if let Some((address, size)) = exclusive {
            if !matches!(size, 1 | 2 | 4 | 8 | 16)
                || address & (u64::from(size) - 1) != 0
                || !self
                    .memory
                    .check_range(GuestAddress(address), usize::from(size))
            {
                return Err(invalid("exclusive reservation range or width differs"));
            }
        }
        Ok(())
    }
    pub(super) fn capture_private(&self) -> Result<BackendContext> {
        self.capture_private_with_reservation(true)
    }
    pub(super) fn capture_for_remap(&self) -> Result<BackendContext> {
        // Reconstructing the address space invalidates local monitor rights.
        self.capture_private_with_reservation(false)
    }
    fn capture_private_with_reservation(&self, retain_reservation: bool) -> Result<BackendContext> {
        self.check_publication()?;
        let context = Context {
            id: self.id,
            core: CoreCheckpoint::capture(&self.cpu)?,
            fault: *self
                .fault
                .lock()
                .map_err(|_| invalid("fault lock poisoned"))?,
            exclusive: if retain_reservation {
                *self
                    .exclusive
                    .lock()
                    .map_err(|_| invalid("exclusive lock poisoned"))?
            } else {
                None
            },
        };
        self.validate_exclusive(context.exclusive)?;
        let payload = crate::codec::serialize_limited(&context, MAX_PAYLOAD).map_err(invalid)?;
        let mut data = Vec::with_capacity(TAG.len() + payload.len());
        data.extend_from_slice(TAG);
        data.extend_from_slice(&payload);
        Ok(BackendContext {
            kind: CORTEX_M_CONTEXT,
            data,
        })
    }
    pub(super) fn prepare_private(&self, state: &CpuState, raw: &BackendContext) -> Result<Self> {
        if raw.kind != CORTEX_M_CONTEXT {
            return Err(invalid("producer differs"));
        }
        let payload = raw
            .data
            .strip_prefix(TAG)
            .ok_or_else(|| invalid("tag differs"))?;
        if payload.len() > MAX_PAYLOAD {
            return Err(invalid("record exceeds budget"));
        }
        let image: Context =
            crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?;
        if image.id != self.id {
            return Err(invalid("CPU identity differs"));
        }
        image.core.validate(&self.cpu)?;
        self.validate_exclusive(image.exclusive)?;
        // Resolve poisoned target locks before constructing or publishing state.
        drop(
            self.fault
                .lock()
                .map_err(|_| invalid("fault lock poisoned"))?,
        );
        drop(
            self.exclusive
                .lock()
                .map_err(|_| invalid("exclusive lock poisoned"))?,
        );
        let mut candidate = Self::with_variant(self.id, self.memory.clone(), self.cpu.variant());
        image.core.install(&mut candidate.cpu);
        candidate.cpu.retain_checkpoint_host_controls(&self.cpu);
        *candidate
            .fault
            .lock()
            .map_err(|_| invalid("fresh fault lock poisoned"))? = image.fault;
        *candidate
            .exclusive
            .lock()
            .map_err(|_| invalid("fresh exclusive lock poisoned"))? = image.exclusive;
        if crate::codec::serialize(&candidate.get_state()?).map_err(invalid)?
            != crate::codec::serialize(state).map_err(invalid)?
        {
            return Err(invalid("public registers disagree with private record"));
        }
        candidate.checkpoint_publication = Some(Arc::new(AtomicBool::new(false)));
        Ok(candidate)
    }
    pub(super) fn validate_private(
        &self,
        state: &CpuState,
        emulator: &EmulatorState,
        raw: &BackendContext,
    ) -> Result<()> {
        if crate::codec::serialize(emulator).map_err(invalid)?
            != crate::codec::serialize(&EmulatorState::default()).map_err(invalid)?
        {
            return Err(invalid("legacy emulator projection disagrees"));
        }
        self.prepare_private(state, raw).map(drop)
    }
    pub(super) fn publication<'scope, 'bindings>(
        &self,
        scope: &'scope CheckpointPublication<'bindings>,
    ) -> Result<CpuPublication<'scope, 'bindings>> {
        match &self.checkpoint_publication {
            Some(done) if !done.load(Ordering::Acquire) => {
                scope.prepare_detached(&self.memory, done.clone())
            }
            _ => Ok(scope.empty()),
        }
    }
    pub(super) fn restore_private(&mut self, state: &CpuState, raw: &BackendContext) -> Result<()> {
        let candidate = self.prepare_private(state, raw)?;
        let bindings = CheckpointBindings::new(&self.memory, vec![]);
        let scope = bindings.enter()?;
        candidate.publication(&scope)?.commit();
        *self = candidate;
        Ok(())
    }
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
