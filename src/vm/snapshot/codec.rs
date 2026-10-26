//! Bounded tagged-v8 file framing and compatibility with the original v8 wire.
use super::legacy::LegacyConfig;
use super::{CHECKPOINT_MAGIC, CHECKPOINT_VERSION, DeviceState, EmulatorState, Snapshot};
use crate::config::CheckpointConfig;
use crate::error::{Error, Result};
use crate::vm::{memory::validate_guest_memory_size, vcpu::state::CpuState};
use bincode::Options;
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
fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}
fn encode<T: Serialize>(value: &T, limit: u64) -> Result<Vec<u8>> {
    options()
        .with_limit(limit)
        .serialize(value)
        .map_err(|e| invalid(format!("Failed to serialize checkpoint section: {e}")))
}
fn decode<T: DeserializeOwned>(bytes: &[u8], limit: u64) -> Result<T> {
    options()
        .with_limit(limit)
        .deserialize(bytes)
        .map_err(|e| invalid(format!("Failed to deserialize checkpoint section: {e}")))
}
fn legacy_value<T: DeserializeOwned, R: Read>(reader: &mut R, limit: u64) -> Result<T> {
    options()
        .with_limit(limit)
        .deserialize_from(reader)
        .map_err(|e| invalid(format!("Failed to deserialize legacy checkpoint: {e}")))
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
    writer.write_all(&SCHEMA.to_le_bytes()).map_err(io)?;
    writer
        .write_all(&(bytes.len() as u64).to_le_bytes())
        .map_err(io)?;
    writer.write_all(bytes).map_err(io)
}
fn compressed_limit(size: u64) -> u64 {
    size + size / 128 + 1024 * 1024
}

pub(super) fn write_to<W: Write>(snapshot: &Snapshot, writer: &mut W) -> Result<()> {
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
    writer.write_all(&6u32.to_le_bytes()).map_err(io)?;
    for (kind, bytes) in [
        (1, &config),
        (2, &metadata),
        (3, &cpu),
        (4, &emulator),
        (5, &devices),
    ] {
        section(writer, kind, bytes)?;
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
    write_to(snapshot, &mut writer)?;
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
    let mut raw = vec![0; size];
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
fn read_sections<R: Read + Seek>(reader: &mut R, file_size: u64) -> Result<Snapshot> {
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
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let kind = word(reader)?;
        let schema = word(reader)?;
        let length = long(reader)?;
        if kind & OPTIONAL != 0 && (1..=6).contains(&(kind & !OPTIONAL)) {
            return Err(invalid("required checkpoint section marked optional"));
        }
        if !seen.insert(kind) {
            return Err(invalid("duplicate checkpoint section"));
        }
        if !(1..=6).contains(&kind) {
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
        if schema != SCHEMA {
            return Err(invalid("unsupported checkpoint section schema"));
        }
        if kind == 6 {
            let meta = metadata
                .as_ref()
                .ok_or_else(|| invalid("memory section precedes checkpoint metadata"))?;
            let conf = config
                .as_ref()
                .ok_or_else(|| invalid("memory section precedes checkpoint config"))?;
            memory_metadata(conf, meta.memory_size)?;
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
            1 => config = Some(decode::<CheckpointConfig>(&raw, limit)?),
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
    Ok(Snapshot {
        version: CHECKPOINT_VERSION,
        config: config.ok_or_else(required)?,
        instruction_count: meta.instruction_count,
        elapsed_nanos: meta.elapsed_nanos,
        cpu_state: cpu.ok_or_else(required)?,
        emulator_state: emulator.ok_or_else(required)?,
        devices: devices.ok_or_else(required)?,
        memory_size: meta.memory_size,
        memory_data: memory.ok_or_else(required)?,
    })
}
pub(super) fn load(path: &Path) -> Result<Snapshot> {
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
        read_sections(&mut reader, file_size)
    } else {
        read_legacy(&mut reader, file_size)
    }
}
