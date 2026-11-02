//! Resource-backed GSC producer and matching-RAM publication.
use super::*;
use crate::vm::memory::checkpoint::{CheckpointPublication, CpuPublication};
use crate::vm::snapshot::{
    BackendContext, CheckpointResource, EmulatorState, GSC_AP_FLASH_RESOURCE, GSC_CONTEXT,
    GSC_STATE_RESOURCE, MAX_GSC_STATE_BYTES, PreparedResources, ResourceKey,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
#[path = "checkpoint/image.rs"]
mod image;
const TAG: &[u8; 8] = b"RAXGSC01";
const MAX_STATE: usize = MAX_GSC_STATE_BYTES;
fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("GSC checkpoint: {message}"))
}
#[derive(Serialize, Deserialize)]
struct Descriptor {
    id: u32,
    state: ResourceKey,
    ap_flash: ResourceKey,
}
impl Descriptor {
    fn decode(id: u32, raw: &BackendContext) -> Result<Self> {
        if raw.kind != GSC_CONTEXT || raw.data.len() > 256 || !raw.data.starts_with(TAG) {
            return Err(invalid("producer/tag/length differs"));
        }
        let d: Self =
            crate::codec::deserialize_limited::<_, 256>(&raw.data[8..]).map_err(invalid)?;
        d.state.validate()?;
        d.ap_flash.validate()?;
        if d.id != id
            || d.state.kind() != GSC_STATE_RESOURCE
            || d.ap_flash.kind() != GSC_AP_FLASH_RESOURCE
            || d.state.size() < 9
        {
            return Err(invalid("identity or resource interpretation differs"));
        }
        Ok(d)
    }
    fn encode(&self) -> Result<BackendContext> {
        let mut data = TAG.to_vec();
        data.extend_from_slice(&crate::codec::serialize(self).map_err(invalid)?);
        Ok(BackendContext {
            kind: GSC_CONTEXT,
            data,
        })
    }
}
impl GscVcpu {
    /// A constructor for an unexposed checkpoint target: no environment, files or guest writes.
    pub(crate) fn new_checkpoint_target(id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Self> {
        image::Image::empty(id)?.into_cpu(mem, Arc::new(Vec::new()))
    }
    fn check_publication(&self) -> Result<()> {
        if self
            .checkpoint_publication
            .as_ref()
            .is_some_and(|p| !p.load(Ordering::Acquire))
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
    pub(super) fn checkpoint_parts(&self) -> Result<(BackendContext, Vec<CheckpointResource>)> {
        self.check_publication()?;
        let image = image::Image::capture(self)?;
        let state = CheckpointResource::gsc_state(image.encode()?)?;
        let ap_flash = CheckpointResource::gsc_ap_flash(self.bridge.ap_flash.clone())?;
        let descriptor = Descriptor {
            id: self.id,
            state: state.key(),
            ap_flash: ap_flash.key(),
        };
        Ok((descriptor.encode()?, vec![state, ap_flash]))
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
            return Err(invalid("legacy emulator projection differs"));
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
                Ok(vec![d.state, d.ap_flash])
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
        let bytes = resources.resolve(d.state)?;
        let ap_flash = resources.resolve(d.ap_flash)?;
        let image = image::Image::decode(bytes.as_slice())?;
        if image.id != self.id {
            return Err(invalid("resource CPU identity differs"));
        }
        let mut candidate = image.into_cpu(self.bridge.mem.clone(), ap_flash)?;
        if crate::codec::serialize(&candidate.get_state()?).map_err(invalid)?
            != crate::codec::serialize(state).map_err(invalid)?
        {
            return Err(invalid("public registers disagree with private image"));
        }
        candidate.checkpoint_publication = Some(Arc::new(AtomicBool::new(false)));
        Ok(candidate)
    }
    pub(super) fn publication<'scope, 'bindings>(
        &self,
        scope: &'scope CheckpointPublication<'bindings>,
    ) -> Result<CpuPublication<'scope, 'bindings>> {
        match &self.checkpoint_publication {
            Some(done) if !done.load(Ordering::Acquire) => {
                scope.prepare_detached(&self.bridge.mem, done.clone())
            }
            _ => Ok(scope.empty()),
        }
    }
}
