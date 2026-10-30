//! Ordered represented public/base-private contexts for every configured vCPU.
use super::{EmulatorState, Snapshot};
use crate::error::{Error, Result};
use crate::vm::vcpu::state::CpuState;
use serde::{Serialize, de::DeserializeOwned};
use std::io::Read;
const TAG: &[u8; 8] = b"RAXCPU01";
const MAX_CPUS: usize = u8::MAX as usize;
const MAX_RECORD: u64 = 16 * 1024 * 1024;
const MAX_SECTION: u64 = 1024 * 1024 * 1024;

#[cfg(test)]
#[path = "cpu_coherence_tests.rs"]
mod tests;
fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("CPU checkpoint set: {message}"))
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    crate::codec::serialize_limited(value, MAX_RECORD as usize).map_err(invalid)
}
fn decode<T: DeserializeOwned>(raw: &[u8]) -> Result<T> {
    crate::codec::deserialize_limited::<T, { MAX_RECORD as usize }>(raw).map_err(invalid)
}
/// One backend's currently represented public and base-private payload.
/// Additional backend-private context must be added explicitly; this type does
/// not establish complete native/extended-register/scheduler capture.
#[derive(Clone, Debug)]
pub struct CpuSnapshot {
    pub state: CpuState,
    pub emulator: EmulatorState,
}
#[derive(Clone, Debug)]
pub struct CpuSnapshots {
    entries: Vec<CpuSnapshot>,
}
impl CpuSnapshots {
    pub fn entries(&self) -> &[CpuSnapshot] {
        &self.entries
    }
    pub(super) fn capture(entries: Vec<CpuSnapshot>, base: &Snapshot) -> Result<Self> {
        let set = Self { entries };
        set.validate(base)?;
        Ok(set)
    }
    /// Native payload semantics are admitted with the complete producer graph.
    pub(super) fn capture_native(entries: Vec<CpuSnapshot>, base: &Snapshot) -> Result<Self> {
        let set = Self { entries };
        set.validate_structure(base)?;
        Ok(set)
    }
    pub(super) fn validate(&self, base: &Snapshot) -> Result<()> {
        self.validate_structure(base)?;
        for entry in &self.entries {
            Snapshot::validate_cpu_payload(&entry.state)?;
        }
        Ok(())
    }
    pub(super) fn validate_structure(&self, base: &Snapshot) -> Result<()> {
        if self.entries.is_empty()
            || self.entries.len() > MAX_CPUS
            || self.entries.len() as u64 != u64::from(base.config.vcpus)
        {
            return Err(invalid(
                "CPU count does not match recorded configuration or format limit",
            ));
        }
        Self::validate_entries(&self.entries, &base.cpu_state, &base.emulator_state)
    }
    fn validate_entries(
        entries: &[CpuSnapshot],
        cpu: &CpuState,
        emulator: &EmulatorState,
    ) -> Result<()> {
        for entry in entries {
            if std::mem::discriminant(&entry.state) != std::mem::discriminant(cpu) {
                return Err(invalid("mixed CPU kinds"));
            }
        }
        let first = entries.first().ok_or_else(|| invalid("empty CPU set"))?;
        // Retain both bounded encodes for admission, but compare AArch64's
        // typed state: independently decoded implementation-defined register
        // maps can serialize in different orders while holding equal entries.
        let first_state = encode(&first.state)?;
        let base_state = encode(cpu)?;
        let same_state = match (&first.state, cpu) {
            (CpuState::Aarch64(first), CpuState::Aarch64(base)) => first == base,
            _ => first_state == base_state,
        };
        if !same_state || encode(&first.emulator)? != encode(emulator)? {
            return Err(invalid("CPU0 disagrees with base checkpoint"));
        }
        Ok(())
    }
    pub(super) fn encoded(&self) -> Result<Vec<u8>> {
        if self.entries.is_empty() || self.entries.len() > MAX_CPUS {
            return Err(invalid("CPU count outside format limit"));
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.entries.len())
            .map_err(invalid)?;
        let mut length = 12 + 16 * self.entries.len() as u64;
        for entry in &self.entries {
            let state = encode(&entry.state)?;
            let emulator = encode(&entry.emulator)?;
            length = length
                .checked_add(state.len() as u64)
                .and_then(|n| n.checked_add(emulator.len() as u64))
                .ok_or_else(|| invalid("encoded length overflow"))?;
            if length > MAX_SECTION {
                return Err(invalid("CPU section exceeds limit"));
            }
            records.push((state, emulator));
        }
        let mut raw = Vec::new();
        raw.try_reserve_exact(usize::try_from(length).map_err(invalid)?)
            .map_err(invalid)?;
        raw.extend_from_slice(TAG);
        raw.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for (state, emulator) in &records {
            raw.extend_from_slice(&(state.len() as u64).to_le_bytes());
            raw.extend_from_slice(&(emulator.len() as u64).to_le_bytes());
        }
        for (state, emulator) in records {
            raw.extend_from_slice(&state);
            raw.extend_from_slice(&emulator);
        }
        Ok(raw)
    }
    /// Admit the full table and aggregate encoded size before allocating any
    /// serialized CPU payload. Count is also bound to already-decoded config.
    pub(super) fn read_from(
        reader: &mut impl Read,
        length: u64,
        expected: u8,
        cpu: &CpuState,
        emulator: &EmulatorState,
        native: bool,
    ) -> Result<Self> {
        if length > MAX_SECTION {
            return Err(invalid("CPU section exceeds limit"));
        }
        let mut reader = reader.take(length);
        let mut tag = [0; 8];
        reader.read_exact(&mut tag).map_err(invalid)?;
        if &tag != TAG {
            return Err(invalid("bad CPU set tag"));
        }
        let mut word = [0; 4];
        reader.read_exact(&mut word).map_err(invalid)?;
        let count = u32::from_le_bytes(word) as usize;
        if count == 0 || count > MAX_CPUS || count as u64 != u64::from(expected) {
            return Err(invalid(
                "CPU count does not match recorded configuration or format limit",
            ));
        }
        let table = 12 + 16 * count as u64;
        if length < table {
            return Err(invalid("truncated CPU table"));
        }
        let mut lengths = Vec::new();
        lengths.try_reserve_exact(count).map_err(invalid)?;
        let mut total = table;
        for _ in 0..count {
            let mut raw = [0; 16];
            reader.read_exact(&mut raw).map_err(invalid)?;
            let state = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let emulator = u64::from_le_bytes(raw[8..].try_into().unwrap());
            if state == 0 || emulator == 0 || state > MAX_RECORD || emulator > MAX_RECORD {
                return Err(invalid("CPU record length exceeds limit"));
            }
            total = total
                .checked_add(state)
                .and_then(|n| n.checked_add(emulator))
                .ok_or_else(|| invalid("CPU length overflow"))?;
            if total > MAX_SECTION {
                return Err(invalid("CPU section exceeds limit"));
            }
            lengths.push((state, emulator));
        }
        if total != length {
            return Err(invalid("CPU encoded length mismatch"));
        }
        fn record(reader: &mut impl Read, n: u64) -> Result<Vec<u8>> {
            let n = usize::try_from(n).map_err(invalid)?;
            let mut raw = Vec::new();
            raw.try_reserve_exact(n).map_err(invalid)?;
            raw.resize(n, 0);
            reader.read_exact(&mut raw).map_err(invalid)?;
            Ok(raw)
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(invalid)?;
        for (state, emulator) in lengths {
            entries.push(CpuSnapshot {
                state: decode(&record(&mut reader, state)?)?,
                emulator: decode(&record(&mut reader, emulator)?)?,
            });
        }
        Self::validate_entries(&entries, cpu, emulator)?;
        if !native {
            for entry in &entries {
                Snapshot::validate_cpu_payload(&entry.state)?;
            }
        }
        Ok(Self { entries })
    }
}
