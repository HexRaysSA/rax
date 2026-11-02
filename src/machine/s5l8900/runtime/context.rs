//! Complete S5L producer, source-bound media preparation and UART/RAM publication.
use super::*;
use crate::vm::memory::checkpoint::{CheckpointPublication, CpuPublication};
use crate::vm::snapshot::{
    BackendContext, CheckpointResource, EmulatorState, MAX_S5L_STATE_BYTES, PreparedResources,
    ResourceKey, S5L_NAND_RESOURCE, S5L_STATE_RESOURCE, S5L8900_CONTEXT,
};
use crate::vm::vcpu::PreparedCheckpointCapture;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
mod image;
#[cfg(test)]
mod tests;
const TAG: &[u8; 8] = b"RAXS5L01";
const MAX_STATE: usize = MAX_S5L_STATE_BYTES;
fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("S5L checkpoint: {message}"))
}

pub(super) struct PreparedPublication {
    uart: Option<(Arc<Mutex<S3cUart>>, S3cUart)>,
    completed: Arc<AtomicBool>,
    epoch: Arc<OnceLock<crate::host::time::Instant>>,
}
#[derive(Serialize, Deserialize)]
struct Descriptor {
    id: u32,
    state: ResourceKey,
    nand: ResourceKey,
}
impl Descriptor {
    fn decode(id: u32, raw: &BackendContext) -> Result<Self> {
        if raw.kind != S5L8900_CONTEXT || raw.data.len() > 256 || !raw.data.starts_with(TAG) {
            return Err(invalid("producer/tag/length differs"));
        }
        let d: Self =
            crate::codec::deserialize_limited::<_, 256>(&raw.data[8..]).map_err(invalid)?;
        d.state.validate()?;
        d.nand.validate()?;
        if d.id != id || d.state.kind() != S5L_STATE_RESOURCE || d.nand.kind() != S5L_NAND_RESOURCE
        {
            return Err(invalid("identity or resource interpretation differs"));
        }
        Ok(d)
    }
    fn encode(&self) -> Result<BackendContext> {
        let mut data = TAG.to_vec();
        data.extend_from_slice(&crate::codec::serialize(self).map_err(invalid)?);
        Ok(BackendContext {
            kind: S5L8900_CONTEXT,
            data,
        })
    }
}
impl S5L8900Vcpu {
    pub(crate) fn new_checkpoint_target(id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Self> {
        let (cpu, _) = image::Image::empty(id)?.into_cpu(
            mem,
            S5lNand::new(None),
            Arc::new(OnceLock::new()),
        )?;
        Ok(cpu)
    }
    pub(super) fn check_publication(&self) -> Result<()> {
        if self
            .checkpoint_publication
            .as_ref()
            .is_some_and(|p| !p.completed.load(Ordering::Acquire))
        {
            return Err(invalid("detached CPU has not been published"));
        }
        Ok(())
    }
    pub(super) fn finish_publication(&mut self) -> Result<()> {
        self.check_publication()?;
        if self.checkpoint_publication.take().is_some() {
            let now = crate::host::time::Instant::now();
            self.boot_clock.resume_at(now);
            self.heartbeat_clock.resume_at(now);
        }
        Ok(())
    }
    fn source_witness(&self) -> Result<Vec<u8>> {
        let control = self
            .bridge
            .inner
            .borrow()
            .nand
            .checkpoint_controller_state()?;
        let digest: [u8; 32] = Sha256::digest(&control).into();
        crate::codec::serialize_limited(&(self.id, &self.cpu, self.insn_count, digest), MAX_STATE)
            .map_err(invalid)
    }
    pub(super) fn prepare_source(&self) -> Result<PreparedCheckpointCapture> {
        self.check_publication()?;
        let witness = self.source_witness()?;
        let bytes = self
            .bridge
            .inner
            .borrow()
            .nand
            .capture_checkpoint((64u64 * 1024 * 1024 * 1024).min(usize::MAX as u64) as usize)?;
        let nand = CheckpointResource::s5l_nand(bytes)?;
        if self.source_witness()? != witness {
            return Err(invalid("source changed during media preparation"));
        }
        Ok(PreparedCheckpointCapture {
            owner: self.capture_owner.clone(),
            witness,
            resources: vec![nand],
        })
    }
    pub(super) fn capture_parts(
        &self,
        scope: Option<&CheckpointPublication<'_>>,
        prepared: Option<&PreparedCheckpointCapture>,
    ) -> Result<(BackendContext, Vec<CheckpointResource>)> {
        self.check_publication()?;
        let owned;
        let prepared = match prepared {
            Some(prepared) => prepared,
            None if scope.is_none() => {
                owned = self.prepare_source()?;
                &owned
            }
            None => return Err(invalid("scoped capture requires prepared host media")),
        };
        if !Arc::ptr_eq(&prepared.owner, &self.capture_owner)
            || prepared.witness != self.source_witness()?
            || prepared.resources.len() != 1
            || prepared.resources[0].key().kind() != S5L_NAND_RESOURCE
        {
            return Err(invalid("foreign/stale source media preparation"));
        }
        let image = image::Image::capture(self, scope)?;
        let state = CheckpointResource::s5l_state(image.encode()?)?;
        let d = Descriptor {
            id: self.id,
            state: state.key(),
            nand: prepared.resources[0].key(),
        };
        let mut resources = prepared.resources.clone();
        resources.push(state);
        Ok((d.encode()?, resources))
    }
    pub(super) fn admit_descriptor(
        &self,
        state: &CpuState,
        emulator: &EmulatorState,
        raw: &BackendContext,
    ) -> Result<()> {
        self.validate_checkpoint_state(state, emulator)?;
        if crate::codec::serialize(emulator).map_err(invalid)?
            != crate::codec::serialize(&EmulatorState::default()).map_err(invalid)?
        {
            return Err(invalid("foreign legacy emulator projection"));
        }
        Descriptor::decode(self.id, raw)?;
        Ok(())
    }
    pub(super) fn resource_references(
        &self,
        raw: Option<&BackendContext>,
    ) -> Result<Vec<ResourceKey>> {
        match raw {
            Some(raw) => {
                let d = Descriptor::decode(self.id, raw)?;
                Ok(vec![d.state, d.nand])
            }
            None => Ok(Vec::new()),
        }
    }
    pub(super) fn prepare_private(
        &self,
        state: &CpuState,
        emulator: &EmulatorState,
        raw: &BackendContext,
        resources: &PreparedResources,
    ) -> Result<Self> {
        self.admit_descriptor(state, emulator, raw)?;
        let d = Descriptor::decode(self.id, raw)?;
        let image = image::Image::decode(resources.resolve(d.state)?.as_slice())?;
        if image.id() != self.id {
            return Err(invalid("resource CPU identity differs"));
        }
        let nand_bytes = resources.resolve(d.nand)?;
        let nand = S5lNand::from_checkpoint(nand_bytes.as_slice(), nand_bytes.len())?;
        let (mut candidate, saved_uart) =
            image.into_cpu(self.bridge.mem.clone(), nand, self.uart.clone())?;
        if crate::codec::serialize(&candidate.get_state()?).map_err(invalid)?
            != crate::codec::serialize(state).map_err(invalid)?
        {
            return Err(invalid("public registers disagree with private image"));
        }
        if saved_uart.is_some() != self.uart.get().is_some() {
            return Err(invalid("UART attachment differs"));
        }
        let epoch = Arc::new(OnceLock::new());
        candidate.boot_clock.bind_publication_epoch(epoch.clone());
        candidate
            .heartbeat_clock
            .bind_publication_epoch(epoch.clone());
        candidate.checkpoint_publication = Some(PreparedPublication {
            epoch,
            uart: self.uart.get().cloned().zip(saved_uart),
            completed: Arc::new(AtomicBool::new(false)),
        });
        Ok(candidate)
    }
    pub(super) fn publication<'scope, 'bindings>(
        &mut self,
        scope: &'scope CheckpointPublication<'bindings>,
    ) -> Result<CpuPublication<'scope, 'bindings>> {
        match &self.checkpoint_publication {
            Some(pending) if !pending.completed.load(Ordering::Acquire) => scope.prepare_s3c_clock(
                &self.bridge.mem,
                pending
                    .uart
                    .as_ref()
                    .map(|(owner, state)| {
                        state.checkpoint_clone().map(|state| (owner.clone(), state))
                    })
                    .transpose()?,
                pending.completed.clone(),
                pending.epoch.clone(),
            ),
            _ => Ok(scope.empty()),
        }
    }
}
