//! Bounded tagged-v8 file framing and compatibility with the original v8 wire.
use super::config_v1::TaggedConfigV1;
use super::legacy::LegacyConfig;
use super::{CHECKPOINT_MAGIC, CHECKPOINT_VERSION, DeviceState, EmulatorState, Snapshot};
use super::{CpuSnapshots, PciSnapshot, PhysicalMemorySnapshot, SnapshotBundle};
use crate::config::CheckpointConfig;
use crate::error::{Error, Result};
use crate::vm::{memory::validate_guest_memory_size, vcpu::state::CpuState};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const TAG: u32 = u32::from_le_bytes(*b"RXS8");
const SCHEMA: u32 = 1;
const MAX_SECTIONS: u32 = 64;
const MAX_CONFIG: u64 = 1024 * 1024;
const MAX_METADATA: u64 = 16 * 1024 * 1024;
const OPTIONAL: u32 = 1 << 31;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
struct Metadata {
    instruction_count: u64,
    elapsed_nanos: u64,
    memory_size: u64,
}
fn invalid(message: impl Into<String>) -> Error {
    Error::Emulator(message.into())
}
fn io(error: std::io::Error) -> Error {
    invalid(format!("checkpoint I/O: {error}"))
}
fn encode<T: Serialize>(value: &T, limit: u64) -> Result<Vec<u8>> {
    let limit = usize::try_from(limit)
        .map_err(|_| invalid("checkpoint section limit exceeds host width"))?;
    crate::codec::serialize_limited(value, limit)
        .map_err(|e| invalid(format!("Failed to serialize checkpoint section: {e}")))
}
fn decode<T: DeserializeOwned>(bytes: &[u8], limit: u64) -> Result<T> {
    let decoded = match limit {
        MAX_CONFIG => crate::codec::deserialize_limited::<T, { MAX_CONFIG as usize }>(bytes),
        MAX_METADATA => crate::codec::deserialize_limited::<T, { MAX_METADATA as usize }>(bytes),
        _ => return Err(invalid("unknown checkpoint section limit")),
    };
    decoded.map_err(|e| invalid(format!("Failed to deserialize checkpoint section: {e}")))
}
fn legacy_value<T: DeserializeOwned, R: Read>(reader: &mut R, limit: u64) -> Result<T> {
    let decoded = match limit {
        4 => crate::codec::deserialize_from_limited::<_, T, 4>(reader),
        8 => crate::codec::deserialize_from_limited::<_, T, 8>(reader),
        MAX_CONFIG => {
            crate::codec::deserialize_from_limited::<_, T, { MAX_CONFIG as usize }>(reader)
        }
        MAX_METADATA => {
            crate::codec::deserialize_from_limited::<_, T, { MAX_METADATA as usize }>(reader)
        }
        _ => return Err(invalid("unknown legacy checkpoint value limit")),
    };
    decoded.map_err(|e| invalid(format!("Failed to deserialize legacy checkpoint: {e}")))
}
fn word<R: Read>(reader: &mut R) -> Result<u32> {
    let mut b = [0; 4];
    reader.read_exact(&mut b).map_err(io)?;
    Ok(u32::from_le_bytes(b))
}
fn long<R: Read>(reader: &mut R) -> Result<u64> {
    let mut b = [0; 8];
    reader.read_exact(&mut b).map_err(io)?;
    Ok(u64::from_le_bytes(b))
}
fn section<W: Write>(writer: &mut W, kind: u32, bytes: &[u8]) -> Result<()> {
    writer.write_all(&kind.to_le_bytes()).map_err(io)?;
    let schema = if kind == 1 { 2 } else { SCHEMA };
    writer.write_all(&schema.to_le_bytes()).map_err(io)?;
    writer
        .write_all(&(bytes.len() as u64).to_le_bytes())
        .map_err(io)?;
    writer.write_all(bytes).map_err(io)
}
fn compressed_limit(size: u64) -> u64 {
    size + size / 128 + 1024 * 1024
}

pub(super) fn write_to<W: Write>(snapshot: &Snapshot, writer: &mut W) -> Result<()> {
    write_to_parts(snapshot, None, None, None, None, None, None, None, writer)
}
fn write_to_parts<W: Write>(
    snapshot: &Snapshot,
    execution: Option<&super::ExecutionSnapshot>,
    clock: Option<&crate::vm::timing::ClockState>,
    cpus: Option<&CpuSnapshots>,
    backend_contexts: Option<&super::BackendContexts>,
    resources: Option<&super::ResourcesSnapshot>,
    pci: Option<&PciSnapshot>,
    physical: Option<&PhysicalMemorySnapshot>,
    writer: &mut W,
) -> Result<()> {
    if snapshot.version != CHECKPOINT_VERSION {
        return Err(invalid(format!(
            "Unsupported checkpoint version {} (expected {})",
            snapshot.version, CHECKPOINT_VERSION
        )));
    }
    memory_metadata(&snapshot.config, snapshot.memory_size)?;
    if snapshot.memory_data.len() as u64 > compressed_limit(snapshot.memory_size) {
        return Err(invalid(
            "checkpoint compressed memory exceeds section limit",
        ));
    }
    let execution_record = execution
        .map(|state| {
            state.validate(snapshot)?;
            state.encoded()
        })
        .transpose()?;
    let clock_record = clock
        .map(|state| {
            super::clock::validate(state, snapshot)?;
            super::clock::encode(state)
        })
        .transpose()?;
    let cpu_records = cpus
        .map(|c| {
            c.validate(snapshot)?;
            c.encoded()
        })
        .transpose()?;
    let backend_records = backend_contexts
        .map(|c| c.encoded(snapshot.config.vcpus))
        .transpose()?;
    if let Some(resources) = resources {
        resources.validate_metadata()?;
    }
    let control = if let Some(state) = pci {
        state.validate(&snapshot.config, snapshot.memory_size)?;
        Some(state.control()?)
    } else {
        None
    };
    // Serialize bounded metadata before touching an output file's contents.
    let config = encode(&snapshot.config, MAX_CONFIG)?;
    let metadata = encode(
        &Metadata {
            instruction_count: snapshot.instruction_count,
            elapsed_nanos: snapshot.elapsed_nanos,
            memory_size: snapshot.memory_size,
        },
        MAX_METADATA,
    )?;
    let cpu = encode(&snapshot.cpu_state, MAX_METADATA)?;
    let emulator = encode(&snapshot.emulator_state, MAX_METADATA)?;
    let devices = encode(&snapshot.devices, MAX_METADATA)?;
    writer.write_all(&CHECKPOINT_MAGIC).map_err(io)?;
    writer
        .write_all(&CHECKPOINT_VERSION.to_le_bytes())
        .map_err(io)?;
    writer.write_all(&TAG.to_le_bytes()).map_err(io)?;
    let count = 6u32
        + u32::from(execution.is_some())
        + u32::from(clock.is_some())
        + u32::from(cpus.is_some())
        + u32::from(backend_contexts.is_some())
        + u32::from(resources.is_some())
        + u32::from(physical.is_some())
        + if let Some(state) = pci {
            1 + if state.has_endpoints() { 2 } else { 0 }
        } else {
            0
        };
    writer.write_all(&count.to_le_bytes()).map_err(io)?;
    for (kind, bytes) in [
        (1, &config),
        (2, &metadata),
        (3, &cpu),
        (4, &emulator),
        (5, &devices),
    ] {
        section(writer, kind, bytes)?;
    }
    if let Some(raw) = clock_record {
        section(writer, 12, &raw)?;
    }
    if let Some(raw) = cpu_records {
        section(writer, 11, &raw)?;
    }
    if let Some(raw) = execution_record {
        section(writer, 13, &raw)?;
    }
    if let Some(raw) = backend_records {
        section(writer, 14, &raw)?;
    }
    if let Some(resources) = resources {
        writer.write_all(&15u32.to_le_bytes()).map_err(io)?;
        writer.write_all(&SCHEMA.to_le_bytes()).map_err(io)?;
        writer
            .write_all(&resources.encoded_len()?.to_le_bytes())
            .map_err(io)?;
        resources.write_to(writer)?;
    }
    if let Some(raw) = control {
        section(writer, 7, &raw)?;
    }
    if let Some(state) = physical {
        writer.write_all(&10u32.to_le_bytes()).map_err(io)?;
        writer.write_all(&SCHEMA.to_le_bytes()).map_err(io)?;
        writer
            .write_all(&state.encoded_len()?.to_le_bytes())
            .map_err(io)?;
        state.write_to(writer)?;
    }
    if let Some(state) = pci {
        for kind in [8, 9] {
            if let Some(raw) = state.media_data(kind) {
                section(writer, kind, raw)?;
            }
        }
    }
    section(writer, 6, &snapshot.memory_data)
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
pub(super) fn save_atomic(snapshot: &Snapshot, path: &Path) -> Result<()> {
    save_atomic_with(path, |writer| write_to(snapshot, writer))
}
pub(super) fn save_bundle_atomic(bundle: &SnapshotBundle, path: &Path) -> Result<()> {
    save_atomic_with(path, |writer| {
        write_to_parts(
            &bundle.base,
            bundle.execution.as_ref(),
            bundle.clock.as_ref(),
            bundle.cpus.as_ref(),
            bundle.backend_contexts.as_ref(),
            bundle.resources.as_ref(),
            bundle.pci.as_ref(),
            bundle.physical_memory.as_ref(),
            writer,
        )
    })
}
fn save_atomic_with(
    path: &Path,
    write: impl FnOnce(&mut BufWriter<File>) -> Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| invalid("checkpoint output path has no file name"))?;
    let mut selected = None;
    for _ in 0..128 {
        let temporary = parent.join(format!(
            ".{}.rax-{}-{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => {
                selected = Some((Temporary(temporary), file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io(e)),
        }
    }
    let (temporary, file) =
        selected.ok_or_else(|| invalid("could not create unique checkpoint temporary file"))?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.is_file() {
            file.set_permissions(metadata.permissions()).map_err(io)?;
        }
    }
    let mut writer = BufWriter::new(file);
    write(&mut writer)?;
    writer.flush().map_err(io)?;
    writer.get_ref().sync_all().map_err(io)?;
    drop(writer);
    std::fs::rename(&temporary.0, path).map_err(io)?;
    Ok(())
}
fn remaining<R: Seek>(reader: &mut R, file_size: u64) -> Result<u64> {
    file_size
        .checked_sub(reader.stream_position().map_err(io)?)
        .ok_or_else(|| invalid("checkpoint position exceeds file size"))
}
fn bytes<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    length: u64,
    limit: u64,
) -> Result<Vec<u8>> {
    if length > limit {
        return Err(invalid("checkpoint section exceeds its size limit"));
    }
    if length > remaining(reader, file_size)? {
        return Err(invalid("truncated checkpoint section"));
    }
    let size = usize::try_from(length)
        .map_err(|_| invalid("checkpoint section does not fit host address size"))?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(size)
        .map_err(|e| invalid(format!("checkpoint allocation: {e}")))?;
    raw.resize(size, 0);
    reader.read_exact(&mut raw).map_err(io)?;
    Ok(raw)
}
fn memory_metadata(config: &CheckpointConfig, size: u64) -> Result<()> {
    if config.memory_bytes != size {
        return Err(Error::InvalidConfig(format!(
            "checkpoint config memory_bytes ({}) does not match snapshot memory_size ({})",
            config.memory_bytes, size
        )));
    }
    config.storage.validate_metadata()?;
    if config.storage.has_images()
        && (!config.pci_devices || config.arch != crate::config::ArchKind::X86_64)
    {
        return Err(invalid(
            "recorded PCI storage metadata requires x86 PCI topology",
        ));
    }
    validate_guest_memory_size(size)
}
fn read_legacy<R: Read + Seek>(reader: &mut R, file_size: u64) -> Result<Snapshot> {
    reader.seek(SeekFrom::Start(8)).map_err(io)?;
    let version: u32 = legacy_value(reader, 4)?;
    let old: LegacyConfig = legacy_value(reader, MAX_CONFIG)?;
    let config = CheckpointConfig::from(old);
    let instruction_count: u64 = legacy_value(reader, 8)?;
    let elapsed_nanos: u64 = legacy_value(reader, 8)?;
    let cpu_state: CpuState = legacy_value(reader, MAX_METADATA)?;
    let emulator_state: EmulatorState = legacy_value(reader, MAX_METADATA)?;
    let devices: DeviceState = legacy_value(reader, MAX_METADATA)?;
    let memory_size: u64 = legacy_value(reader, 8)?;
    memory_metadata(&config, memory_size)?;
    let length = long(reader)?;
    let memory_data = bytes(reader, file_size, length, compressed_limit(memory_size))?;
    if remaining(reader, file_size)? != 0 {
        return Err(invalid("trailing checkpoint bytes"));
    }
    Ok(Snapshot {
        version,
        config,
        instruction_count,
        elapsed_nanos,
        cpu_state,
        emulator_state,
        devices,
        memory_size,
        memory_data,
    })
}
fn read_sections<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    allow_extensions: bool,
) -> Result<SnapshotBundle> {
    let count = word(reader)?;
    if count > MAX_SECTIONS {
        return Err(invalid("checkpoint section count exceeds limit"));
    }
    let mut config: Option<CheckpointConfig> = None;
    let mut metadata: Option<Metadata> = None;
    let mut cpu: Option<CpuState> = None;
    let mut emulator: Option<EmulatorState> = None;
    let mut devices: Option<DeviceState> = None;
    let mut memory: Option<Vec<u8>> = None;
    let mut pci: Option<PciSnapshot> = None;
    let mut physical_memory = None;
    let mut cpus = None;
    let mut backend_contexts = None;
    let mut resources: Option<super::ResourcesSnapshot> = None;
    let mut clock = None;
    let mut execution = None;
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let kind = word(reader)?;
        let schema = word(reader)?;
        let length = long(reader)?;
        if kind & OPTIONAL != 0 && (1..=15).contains(&(kind & !OPTIONAL)) {
            return Err(invalid("required checkpoint section marked optional"));
        }
        if !seen.insert(kind) {
            return Err(invalid("duplicate checkpoint section"));
        }
        if !(1..=15).contains(&kind) {
            if kind & OPTIONAL == 0 {
                return Err(invalid("unknown required checkpoint section"));
            }
            if length > remaining(reader, file_size)? {
                return Err(invalid("truncated optional checkpoint section"));
            }
            let offset = i64::try_from(length)
                .map_err(|_| invalid("optional checkpoint section exceeds seek range"))?;
            reader.seek(SeekFrom::Current(offset)).map_err(io)?;
            continue;
        }
        if schema != SCHEMA && !(kind == 1 && schema == 2) {
            return Err(invalid("unsupported checkpoint section schema"));
        }
        if kind == 15 {
            if !allow_extensions {
                return Err(invalid(
                    "checkpoint contains required resources; use SnapshotBundle::load",
                ));
            }
            if [6, 7, 8, 9, 10].iter().any(|kind| seen.contains(kind)) {
                return Err(invalid(
                    "resources must precede PCI/physical/media/RAM payloads",
                ));
            }
            if cpus.is_none() || backend_contexts.is_none() {
                return Err(invalid(
                    "resources require preceding CPU and backend context sets",
                ));
            }
            if length > remaining(reader, file_size)? {
                return Err(invalid("truncated resource section"));
            }
            let config = config
                .as_ref()
                .ok_or_else(|| invalid("resources require preceding configuration"))?;
            let memory = metadata
                .as_ref()
                .map_or(config.memory_bytes, |meta: &Metadata| {
                    meta.memory_size.max(config.memory_bytes)
                });
            let configured_media = config
                .storage
                .nvme
                .as_ref()
                .map_or(0, |image| image.identity.bytes)
                .checked_add(
                    config
                        .storage
                        .ahci
                        .as_ref()
                        .map_or(0, |image| image.identity.bytes),
                )
                .ok_or_else(|| invalid("resource media size overflow"))?;
            let budget = super::resources::remaining_budget(memory, configured_media)?;
            resources = Some(super::ResourcesSnapshot::read_from_with_budget(
                reader, length, budget,
            )?);
            continue;
        }
        if kind == 14 {
            if !allow_extensions {
                return Err(invalid(
                    "checkpoint contains required backend contexts; use SnapshotBundle::load",
                ));
            }
            if [6, 7, 8, 9, 10, 15].iter().any(|kind| seen.contains(kind)) {
                return Err(invalid(
                    "backend contexts must precede PCI/physical/media/RAM payloads",
                ));
            }
            let conf = config
                .as_ref()
                .ok_or_else(|| invalid("backend contexts precede config"))?;
            if cpus.is_none() {
                return Err(invalid("backend contexts require the preceding CPU set"));
            }
            if length > remaining(reader, file_size)? {
                return Err(invalid("truncated backend context section"));
            }
            backend_contexts = Some(super::BackendContexts::read_from(
                reader, length, conf.vcpus,
            )?);
            continue;
        }
        if kind == 13 {
            if !allow_extensions {
                return Err(invalid(
                    "checkpoint contains required execution state; use SnapshotBundle::load",
                ));
            }
            if [6, 7, 8, 9, 10, 14, 15]
                .iter()
                .any(|kind| seen.contains(kind))
            {
                return Err(invalid(
                    "execution state must precede PCI/physical/media/RAM payloads",
                ));
            }
            let conf = config
                .as_ref()
                .ok_or_else(|| invalid("execution state precedes config"))?;
            let raw = bytes(reader, file_size, length, super::execution::MAX_SECTION)?;
            execution = Some(super::ExecutionSnapshot::decode(&raw, conf.vcpus)?);
            continue;
        }
        if kind == 12 {
            if !allow_extensions {
                return Err(invalid(
                    "checkpoint contains required clock state; use SnapshotBundle::load",
                ));
            }
            if [6, 7, 8, 9, 10, 11, 13, 14, 15]
                .iter()
                .any(|k| seen.contains(k))
            {
                return Err(invalid(
                    "clock state must precede CPU sets and PCI/physical/media/RAM payloads",
                ));
            }
            let conf = config
                .as_ref()
                .ok_or_else(|| invalid("clock state precedes checkpoint config"))?;
            let meta = metadata
                .as_ref()
                .ok_or_else(|| invalid("clock state precedes checkpoint metadata"))?;
            memory_metadata(conf, meta.memory_size)?;
            if length != super::clock::SIZE {
                return Err(invalid("clock record length must be exactly 44 bytes"));
            }
            if length > remaining(reader, file_size)? {
                return Err(invalid("truncated clock state"));
            }
            clock = Some(super::clock::read(reader, length, meta.elapsed_nanos)?);
            continue;
        }
        if kind == 11 {
            if !allow_extensions {
                return Err(invalid(
                    "checkpoint contains required CPU set; use SnapshotBundle::load",
                ));
            }
            if [6, 7, 8, 9, 10, 13, 14, 15]
                .iter()
                .any(|k| seen.contains(k))
            {
                return Err(invalid(
                    "CPU set must precede PCI and physical/media/RAM payloads",
                ));
            }
            let conf = config
                .as_ref()
                .ok_or_else(|| invalid("CPU set precedes checkpoint config"))?;
            let meta = metadata
                .as_ref()
                .ok_or_else(|| invalid("CPU set precedes checkpoint metadata"))?;
            memory_metadata(conf, meta.memory_size)?;
            let cpu = cpu
                .as_ref()
                .ok_or_else(|| invalid("CPU set precedes base CPU"))?;
            let emulator = emulator
                .as_ref()
                .ok_or_else(|| invalid("CPU set precedes base emulator state"))?;
            if length > remaining(reader, file_size)? {
                return Err(invalid("truncated CPU section"));
            }
            cpus = Some(CpuSnapshots::read_from(
                reader, length, conf.vcpus, cpu, emulator,
            )?);
            continue;
        }
        if kind == 10 {
            if !allow_extensions {
                return Err(invalid(
                    "checkpoint contains required physical memory; use SnapshotBundle::load",
                ));
            }
            if memory.is_some() || seen.contains(&8) || seen.contains(&9) {
                return Err(invalid("physical memory must precede RAM/media payloads"));
            }
            let meta = metadata
                .as_ref()
                .ok_or_else(|| invalid("physical memory precedes checkpoint metadata"))?;
            let conf = config
                .as_ref()
                .ok_or_else(|| invalid("physical memory precedes checkpoint config"))?;
            memory_metadata(conf, meta.memory_size)?;
            if length > remaining(reader, file_size)? {
                return Err(invalid("truncated physical memory section"));
            }
            // Config identities are admitted before any physical payload, even
            // if a later malformed file attempts to omit/reorder PCI control.
            let configured_media: u64 = [&conf.storage.nvme, &conf.storage.ahci]
                .into_iter()
                .flatten()
                .map(|image| image.identity.bytes)
                .sum();
            let represented_media = pci.as_ref().map_or(0, |p| {
                p.nvme_media().map_or(0, |m| m.size()) + p.ahci_media().map_or(0, |m| m.size())
            });
            let media = configured_media
                .max(represented_media)
                .checked_add(resources.as_ref().map_or(0, |r| r.total_bytes()))
                .ok_or_else(|| invalid("checkpoint media/resource size overflow"))?;
            physical_memory = Some(PhysicalMemorySnapshot::read_from(reader, length, media)?);
            continue;
        }
        if kind == 7 {
            if !allow_extensions {
                return Err(invalid(
                    "checkpoint contains required PCI state; use SnapshotBundle::load",
                ));
            }
            if memory.is_some() || physical_memory.is_some() {
                return Err(invalid("PCI control must precede physical memory and RAM"));
            }
            let meta = metadata
                .as_ref()
                .ok_or_else(|| invalid("PCI section precedes checkpoint metadata"))?;
            let conf = config
                .as_ref()
                .ok_or_else(|| invalid("PCI section precedes checkpoint config"))?;
            memory_metadata(conf, meta.memory_size)?;
            let raw = bytes(reader, file_size, length, super::pci::MAX_CONTROL)?;
            let state = PciSnapshot::parse_control(&raw)?;
            state.validate_metadata(conf, meta.memory_size)?;
            if let Some(resources) = &resources {
                let media = state.nvme_media().map_or(0, |m| m.size())
                    + state.ahci_media().map_or(0, |m| m.size());
                if resources.total_bytes()
                    > super::resources::remaining_budget(meta.memory_size, media)?
                {
                    return Err(invalid("RAM plus media/resources exceeds bundle budget"));
                }
            }
            pci = Some(state);
            continue;
        }
        if kind == 8 || kind == 9 {
            let state = pci
                .as_mut()
                .ok_or_else(|| invalid("media section precedes PCI control"))?;
            let size = state.media_size(kind)?;
            let raw = bytes(
                reader,
                file_size,
                length,
                super::pci::compressed_limit(size),
            )?;
            state.set_media(kind, raw)?;
            continue;
        }
        if kind == 6 {
            let meta = metadata
                .as_ref()
                .ok_or_else(|| invalid("memory section precedes checkpoint metadata"))?;
            let conf = config
                .as_ref()
                .ok_or_else(|| invalid("memory section precedes checkpoint config"))?;
            memory_metadata(conf, meta.memory_size)?;
            if let Some(state) = &pci {
                state.validate(conf, meta.memory_size)?;
            }
            memory = Some(bytes(
                reader,
                file_size,
                length,
                compressed_limit(meta.memory_size),
            )?);
            continue;
        }
        let limit = if kind == 1 { MAX_CONFIG } else { MAX_METADATA };
        let raw = bytes(reader, file_size, length, limit)?;
        match kind {
            1 => {
                config = Some(if schema == 1 {
                    CheckpointConfig::from(decode::<TaggedConfigV1>(&raw, limit)?)
                } else {
                    decode::<CheckpointConfig>(&raw, limit)?
                })
            }
            2 => metadata = Some(decode::<Metadata>(&raw, limit)?),
            3 => cpu = Some(decode::<CpuState>(&raw, limit)?),
            4 => emulator = Some(decode::<EmulatorState>(&raw, limit)?),
            5 => devices = Some(decode::<DeviceState>(&raw, limit)?),
            _ => unreachable!(),
        }
    }
    if remaining(reader, file_size)? != 0 {
        return Err(invalid("trailing checkpoint bytes"));
    }
    let required = || invalid("missing required checkpoint section");
    let meta = metadata.ok_or_else(required)?;
    let base = Snapshot {
        version: CHECKPOINT_VERSION,
        config: config.ok_or_else(required)?,
        instruction_count: meta.instruction_count,
        elapsed_nanos: meta.elapsed_nanos,
        cpu_state: cpu.ok_or_else(required)?,
        emulator_state: emulator.ok_or_else(required)?,
        devices: devices.ok_or_else(required)?,
        memory_size: meta.memory_size,
        memory_data: memory.ok_or_else(required)?,
    };
    let bundle = SnapshotBundle {
        base,
        resources,
        backend_contexts,
        execution,
        clock,
        cpus,
        pci,
        physical_memory,
    };
    bundle.validate()?;
    Ok(bundle)
}
pub(super) fn load_bundle(path: &Path) -> Result<SnapshotBundle> {
    load_inner(path, true)
}
fn load_inner(path: &Path, allow_extensions: bool) -> Result<SnapshotBundle> {
    let file =
        File::open(path).map_err(|e| invalid(format!("Failed to open snapshot file: {e}")))?;
    let file_size = file.metadata().map_err(io)?.len();
    let mut reader = BufReader::new(file);
    let mut magic = [0; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|e| invalid(format!("Failed to read snapshot magic: {e}")))?;
    if magic != CHECKPOINT_MAGIC {
        return Err(invalid(if &magic == b"RAXSNAP\0" {
            "this is a legacy .snap snapshot (no device/config state); it cannot be resumed as a full checkpoint"
        } else {
            "not a rax checkpoint file (bad magic)"
        }));
    }
    let version = word(&mut reader)?;
    if version != CHECKPOINT_VERSION {
        return Err(invalid(format!(
            "Unsupported checkpoint version {} (expected {})",
            version, CHECKPOINT_VERSION
        )));
    }
    let tag = word(&mut reader)?;
    if tag == TAG {
        read_sections(&mut reader, file_size, allow_extensions)
    } else {
        read_legacy(&mut reader, file_size).map(SnapshotBundle::new)
    }
}

pub(super) fn load(path: &Path) -> Result<Snapshot> {
    load_inner(path, false)?.into_base()
}
