//! Typed PC ownership. Aliases retain the target VM's Arc identities.
use crate::devices::{
    dma::Dma, fdc::Fdc, fw_cfg::FwCfg, i8042::I8042, ide::IdeController, ioapic::IoApic,
    rtc::RtcStub, sysctl::SystemControl,
};
use crate::error::{Error, Result};
use crate::vm::snapshot::{CheckpointResource, PreparedResources, ResourceKey};
use std::sync::{Arc, Mutex, MutexGuard};

const LIMIT: usize = 60 * 1024 * 1024;
const TAG: &[u8; 8] = b"RAXPCD02";
const LEGACY_TAG: &[u8; 8] = b"RAXPCD01";

/// Retained by the VMM, with the same handles registered in the PIO/MMIO buses.
pub struct PcDevices {
    pub(crate) rtc: Arc<Mutex<RtcStub>>,
    pub(crate) fw_cfg: Arc<Mutex<FwCfg>>,
    pub(crate) ioapic: Arc<Mutex<IoApic>>,
    pub(crate) dma: Arc<Mutex<Dma>>,
    pub(crate) sysctl: Arc<Mutex<SystemControl>>,
    pub(crate) i8042: Arc<Mutex<I8042>>,
    pub(crate) ide_primary: Arc<Mutex<IdeController>>,
    pub(crate) ide_secondary: Arc<Mutex<IdeController>>,
    pub(crate) fdc: Arc<Mutex<Fdc>>,
}

/// Versioned private control image. Large immutable CDs live in the resource table.
/// Owned mutable bytes bind from immutable resource images before publication.
#[derive(Clone)]
pub(crate) struct PcCheckpoint {
    data: Vec<u8>,
    legacy_calendar: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct State {
    rtc: crate::devices::rtc::RtcCheckpoint,
    fw_cfg: FwCfg,
    ioapic: crate::devices::ioapic::IoApicCheckpoint,
    dma: Dma,
    sysctl: crate::devices::sysctl::SystemControlCheckpoint,
    i8042: I8042,
    ide_primary: IdeController,
    ide_secondary: IdeController,
    fdc: Fdc,
    cds: [Option<ResourceKey>; 2],
    // Primary disk/PIO/ATAPI, secondary disk/PIO/ATAPI, then floppy media.
    buffers: [ResourceKey; 7],
}

pub(crate) struct PreparedPcCheckpoint {
    legacy_calendar: bool,
    rtc: crate::devices::rtc::PreparedRtcCheckpoint,
    ioapic: crate::devices::ioapic::PreparedIoApicCheckpoint,
    sysctl: crate::devices::sysctl::PreparedSystemControlCheckpoint,
    state: State,
}

fn invalid(e: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("PC checkpoint: {e}"))
}
fn lock<T>(device: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    device.lock().map_err(|_| invalid("device lock poisoned"))
}

struct Held<'a> {
    rtc: MutexGuard<'a, RtcStub>,
    fw_cfg: MutexGuard<'a, FwCfg>,
    ioapic: MutexGuard<'a, IoApic>,
    dma: MutexGuard<'a, Dma>,
    sysctl: MutexGuard<'a, SystemControl>,
    i8042: MutexGuard<'a, I8042>,
    ide_primary: MutexGuard<'a, IdeController>,
    ide_secondary: MutexGuard<'a, IdeController>,
    fdc: MutexGuard<'a, Fdc>,
}
impl PcDevices {
    fn hold(&self) -> Result<Held<'_>> {
        // PCI -> PC inventory order below -> shared ARM -> legacy -> GIC -> RAM.
        // Bus transactions acquire one of these locks and invoke no callbacks.
        Ok(Held {
            rtc: lock(&self.rtc)?,
            fw_cfg: lock(&self.fw_cfg)?,
            ioapic: lock(&self.ioapic)?,
            dma: lock(&self.dma)?,
            sysctl: lock(&self.sysctl)?,
            i8042: lock(&self.i8042)?,
            ide_primary: lock(&self.ide_primary)?,
            ide_secondary: lock(&self.ide_secondary)?,
            fdc: lock(&self.fdc)?,
        })
    }
    pub(crate) fn checkpoint_with<T>(
        &self,
        capture: impl FnOnce(PcCheckpoint, Vec<CheckpointResource>) -> Result<T>,
    ) -> Result<T> {
        let held = self.hold()?;
        let mut resources = Vec::new();
        let mut cds = [None; 2];
        for (slot, ide) in cds
            .iter_mut()
            .zip([&*held.ide_primary, &*held.ide_secondary])
        {
            if let Some(cd) = ide.checkpoint_cdrom() {
                let resource = CheckpointResource::boot_cdrom(cd)?;
                *slot = Some(resource.key());
                resources.push(resource);
            }
        }
        let mut primary = held.ide_primary.clone();
        let mut secondary = held.ide_secondary.clone();
        let mut fdc = held.fdc.clone();
        let [pd, pb, pa] = primary.take_checkpoint_buffers();
        let [sd, sb, sa] = secondary.take_checkpoint_buffers();
        let mut keys = Vec::with_capacity(7);
        for bytes in [pd, pb, pa, sd, sb, sa, fdc.take_checkpoint_image()] {
            let resource = CheckpointResource::pc_device_bytes(bytes)?;
            keys.push(resource.key());
            resources.push(resource);
        }
        let buffers: [ResourceKey; 7] = keys.try_into().map_err(|_| invalid("buffer inventory"))?;
        let state = State {
            rtc: held.rtc.checkpoint_state(),
            fw_cfg: held.fw_cfg.clone(),
            ioapic: held.ioapic.checkpoint_state()?,
            dma: held.dma.clone(),
            sysctl: held.sysctl.checkpoint_state(),
            i8042: held.i8042.clone(),
            ide_primary: primary,
            ide_secondary: secondary,
            fdc,
            cds,
            buffers,
        };
        state.validate()?;
        let data = crate::codec::serialize_limited(&state, LIMIT).map_err(invalid)?;
        let result = capture(
            PcCheckpoint {
                data,
                legacy_calendar: false,
            },
            resources,
        );
        drop(held);
        result
    }
    pub(crate) fn restore_with<T>(
        &self,
        prepared: PreparedPcCheckpoint,
        publish: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut held = self.hold()?;
        if prepared.legacy_calendar && held.rtc.uses_retired_calendar() {
            return Err(invalid("legacy PC calendar requires Wall mode"));
        }
        let result = publish()?;
        // Admission, allocation and all fallible guest/backend work have finished.
        prepared.rtc.commit(&mut held.rtc);
        prepared.ioapic.commit(&mut held.ioapic);
        prepared.sysctl.commit(&mut held.sysctl);
        *held.fw_cfg = prepared.state.fw_cfg;
        *held.dma = prepared.state.dma;
        *held.i8042 = prepared.state.i8042;
        *held.ide_primary = prepared.state.ide_primary;
        *held.ide_secondary = prepared.state.ide_secondary;
        *held.fdc = prepared.state.fdc;
        Ok(result)
    }
}
impl State {
    fn buffer_sizes(&self) -> Result<[usize; 7]> {
        let mut sizes = [0; 7];
        for (size, key) in sizes.iter_mut().zip(self.buffers) {
            key.validate()?;
            if key.kind() != crate::vm::snapshot::PC_DEVICE_BYTES_RESOURCE {
                return Err(invalid("wrong mutable buffer resource kind"));
            }
            *size = usize::try_from(key.size()).map_err(invalid)?;
        }
        Ok(sizes)
    }
    fn validate(&self) -> Result<()> {
        self.rtc.prepare()?;
        self.ioapic.prepare()?;
        self.sysctl.prepare()?;
        self.fw_cfg.validate_checkpoint()?;
        self.dma.validate_checkpoint()?;
        self.i8042.validate_checkpoint()?;
        let sizes = self.buffer_sizes()?;
        self.fdc.validate_checkpoint(sizes[6])?;
        for (index, ((ide, key), (cmd, ctrl))) in [&self.ide_primary, &self.ide_secondary]
            .into_iter()
            .zip(self.cds)
            .zip([(0x1f0, 0x3f6), (0x170, 0x376)])
            .enumerate()
        {
            let size = key
                .map(|key| {
                    key.validate()?;
                    if key.kind() != crate::vm::snapshot::BOOT_CDROM_RESOURCE {
                        return Err(invalid("wrong CD resource kind"));
                    }
                    usize::try_from(key.size()).map_err(invalid)
                })
                .transpose()?;
            ide.validate_checkpoint(
                cmd,
                ctrl,
                size,
                sizes[index * 3..index * 3 + 3].try_into().unwrap(),
            )?;
        }
        Ok(())
    }
}
impl PcCheckpoint {
    fn state(&self) -> Result<State> {
        if self.data.is_empty() || self.data.len() > LIMIT {
            return Err(invalid("control image length"));
        }
        let state: State =
            crate::codec::deserialize_limited::<_, LIMIT>(&self.data).map_err(invalid)?;
        state.validate()?;
        Ok(state)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.state().map(|_| ())
    }
    pub(crate) fn references(&self) -> Result<Vec<ResourceKey>> {
        let state = self.state()?;
        Ok(state
            .cds
            .into_iter()
            .flatten()
            .chain(state.buffers)
            .collect())
    }
    pub(crate) fn admit_calendar(&self, retired: bool) -> Result<()> {
        if self.legacy_calendar && retired {
            return Err(invalid("legacy PC calendar requires Wall mode"));
        }
        Ok(())
    }
    pub(crate) fn encoded(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = if self.legacy_calendar {
            LEGACY_TAG
        } else {
            TAG
        }
        .to_vec();
        bytes.extend_from_slice(&self.data);
        Ok(bytes)
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self> {
        if ![Some(TAG.as_slice()), Some(LEGACY_TAG.as_slice())].contains(&raw.get(..8)) {
            return Err(invalid("unsupported control tag"));
        }
        let image = Self {
            data: raw[8..].to_vec(),
            legacy_calendar: raw.starts_with(LEGACY_TAG),
        };
        image.validate()?;
        Ok(image)
    }
    pub(crate) fn prepare(&self, resources: &PreparedResources) -> Result<PreparedPcCheckpoint> {
        let mut state = self.state()?;
        for (ide, key) in [&mut state.ide_primary, &mut state.ide_secondary]
            .into_iter()
            .zip(state.cds)
        {
            ide.bind_checkpoint_cdrom(key.map(|key| resources.resolve(key)).transpose()?);
        }
        let copy = |key| -> Result<Vec<u8>> {
            let source = resources.resolve(key)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(source.len()).map_err(invalid)?;
            bytes.extend_from_slice(&source);
            Ok(bytes)
        };
        let keys = state.buffers;
        state
            .ide_primary
            .bind_checkpoint_buffers([copy(keys[0])?, copy(keys[1])?, copy(keys[2])?]);
        state.ide_secondary.bind_checkpoint_buffers([
            copy(keys[3])?,
            copy(keys[4])?,
            copy(keys[5])?,
        ]);
        state.fdc.bind_checkpoint_image(copy(keys[6])?);
        Ok(PreparedPcCheckpoint {
            legacy_calendar: self.legacy_calendar,
            rtc: state.rtc.prepare()?,
            ioapic: state.ioapic.prepare()?,
            sysctl: state.sysctl.prepare()?,
            state,
        })
    }
}

#[cfg(test)]
mod tests;
