//! CPU callbacks over one imported view of the authoritative owner's storage.
//!
//! Fatal callback errors are latched separately from the guest-fault-shaped
//! return required by ISA memory interfaces. Every CPU entry/exit checks this
//! latch; the personality can recover the original typed error exactly once.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use vm_memory::GuestMemoryMmap;

use super::{Access, MemoryFailure, Operation, ReadKind, RemoteError, Value, View};
use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::user::cpu::CpuAddressSpace;
use crate::user::cpu::arm::A32AddressSpace;
use crate::user::cpu::memory::TraceMapping;
use crate::user::mm::{CodeChanges, PAGE_SIZE};
use crate::vm::memory::FlatTranslation;

#[derive(Clone)]
pub(crate) struct OwnerMemory(Arc<Inner>);

pub(super) struct Inner {
    access: Access,
    view: View,
    physical: Arc<GuestMemoryMmap>,
    code_epoch: AtomicU64,
    execution: Mutex<Execution>,
    failure: Mutex<Option<Failure>>,
    trace_mappings: Mutex<Option<Vec<TraceMapping>>>,
}

#[derive(Default)]
struct Execution {
    previous: Option<(u64, u64, u64, u64)>,
    epoch: u64,
}

struct Failure {
    summary: String,
    original: Option<RemoteError>,
}

impl std::fmt::Debug for OwnerMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("OwnerCpuMemory").field(&self.0.view).finish()
    }
}

impl OwnerMemory {
    /// Query the owner without populating a page. Used by Linux x86 fault
    /// frames, where resident and PROT_NONE entries have different P bits.
    pub(crate) fn query_resident_accessible(&self, address: u64) -> Result<bool, String> {
        if let Some(error) = self.fatal_error() {
            return Err(error);
        }
        let result = self
            .0
            .access
            .call(Operation::ResidentAccessible { address });
        match result {
            Ok(Value::ResidentAccessible { accessible }) => Ok(accessible),
            Ok(_) => {
                let error = self
                    .0
                    .access
                    .fail(io::Error::other("invalid owner page-state reply"));
                Err(self.fail(error))
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    pub(super) fn import(access: Access) -> Result<Self, RemoteError> {
        let view = View::import(access.clone())?;
        let physical = view.physical_memory()?.clone();
        Ok(Self(Arc::new(Inner {
            access,
            view,
            physical,
            code_epoch: AtomicU64::new(0),
            execution: Mutex::new(Execution::default()),
            failure: Mutex::new(None),
            trace_mappings: Mutex::new(None),
        })))
    }

    pub(super) fn from_inner(inner: Arc<Inner>) -> Self {
        Self(inner)
    }

    pub(super) fn space(&self) -> u64 {
        self.0.access.space()
    }

    pub(super) fn inner(&self) -> &Arc<Inner> {
        &self.0
    }

    /// Final metadata belongs to this worker's last acknowledged execution
    /// window. Preserve it before releasing the lease so CPU Drop can record
    /// it without accessing a later worker's MM or sending an inactive RPC.
    pub(super) fn finish_trace_turn(&self) -> Result<(), RemoteError> {
        if !crate::observability::memtrace::is_active() || self.fatal_error().is_some() {
            return Ok(());
        }
        let used = self
            .0
            .trace_mappings
            .lock()
            .map_err(|_| {
                self.0
                    .access
                    .fail(io::Error::other("owner trace cache poisoned"))
            })?
            .is_some();
        if used {
            self.refresh_trace_mappings()?;
        }
        Ok(())
    }

    fn refresh_trace_mappings(&self) -> Result<Vec<TraceMapping>, RemoteError> {
        let ranges = self.query_mappings()?;
        *self.0.trace_mappings.lock().map_err(|_| {
            self.0
                .access
                .fail(io::Error::other("owner trace cache poisoned"))
        })? = Some(ranges.clone());
        Ok(ranges)
    }

    fn cached_trace_mappings(&self) -> Result<Vec<TraceMapping>, RemoteError> {
        Ok(self
            .0
            .trace_mappings
            .lock()
            .map_err(|_| {
                self.0
                    .access
                    .fail(io::Error::other("owner trace cache poisoned"))
            })?
            .clone()
            .unwrap_or_default())
    }

    /// Draining the original error does not restore execution rights or clear
    /// the diagnostic latch. Return it from the owning Client::with callback.
    pub(crate) fn take_error(&self) -> Option<RemoteError> {
        self.0
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .and_then(|failure| failure.original.take())
    }

    fn fail(&self, error: RemoteError) -> String {
        let mut failure = self
            .0
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let failure = failure.get_or_insert_with(|| Failure {
            summary: error.to_string(),
            original: Some(error),
        });
        failure.summary.clone()
    }

    fn callback<T>(
        &self,
        address: u64,
        size: usize,
        access: MemoryAccessKind,
        operation: impl FnOnce() -> Result<T, RemoteError>,
    ) -> Result<T, GuestMemoryFault> {
        let internal = || GuestMemoryFault {
            address,
            size: size.min(u32::MAX as usize) as u32,
            access,
            kind: MemoryFaultKind::Other,
        };
        if self.fatal_error().is_some() {
            return Err(internal());
        }
        match operation() {
            Ok(value) => Ok(value),
            Err(RemoteError::Memory(MemoryFailure::Fault { fault })) => Err(fault),
            Err(error) => {
                self.fail(error);
                Err(internal())
            }
        }
    }

    /// The active family lease fixes the mapping snapshot across chunks.
    /// Encoding is repeated by the stateless owner for each request: O(B *
    /// ceil(B / TRANSFER_BYTES)) work and O(B) local storage for B JSON bytes.
    /// Tracing consumes this metadata only at initial/final map snapshots.
    fn query_mappings(&self) -> Result<Vec<TraceMapping>, RemoteError> {
        let mut encoded = Vec::new();
        let mut expected_total = None;
        loop {
            let Value::Mappings { total, bytes } = self.0.access.call(Operation::Mappings {
                offset: encoded.len() as u64,
            })?
            else {
                return Err(self
                    .0
                    .access
                    .fail(io::Error::other("invalid mapping metadata")));
            };
            if expected_total.is_some_and(|previous| previous != total) {
                return Err(self
                    .0
                    .access
                    .fail(io::Error::other("mapping snapshot changed")));
            }
            expected_total = Some(total);
            encoded.try_reserve(bytes.len()).map_err(|_| {
                RemoteError::Preparation(io::Error::from(io::ErrorKind::OutOfMemory).into())
            })?;
            encoded.extend_from_slice(&bytes);
            if encoded.len() as u64 == total {
                break;
            }
        }
        let ranges: Vec<TraceMapping> = serde_json::from_slice(&encoded).map_err(|_| {
            self.0
                .access
                .fail(io::Error::other("invalid mapping snapshot JSON"))
        })?;
        if ranges
            .iter()
            .any(|(start, end, perms, _)| start >= end || perms & !7 != 0)
            || ranges.windows(2).any(|pair| pair[0].1 > pair[1].0)
        {
            return Err(self
                .0
                .access
                .fail(io::Error::other("invalid mapping snapshot ranges")));
        }
        Ok(ranges)
    }

    fn query_code(&self, epoch: u64) -> Result<(CodeChanges, u64), RemoteError> {
        let Value::Code {
            epoch: now,
            all,
            ranges,
        } = self.0.access.call(Operation::CodeChanges { epoch })?
        else {
            return Err(self
                .0
                .access
                .fail(io::Error::other("invalid code-change reply")));
        };
        if now < epoch
            || ranges
                .iter()
                .any(|(start, len)| *len == 0 || start.checked_add(*len).is_none())
            || (all && !ranges.is_empty())
        {
            return Err(self
                .0
                .access
                .fail(io::Error::other("invalid code-change ranges")));
        }
        self.0.code_epoch.store(now, Ordering::Release);
        Ok((
            if all {
                CodeChanges::All
            } else if ranges.is_empty() {
                CodeChanges::None
            } else {
                CodeChanges::Ranges(ranges)
            },
            now,
        ))
    }
}

impl A32AddressSpace for OwnerMemory {
    fn available(&self) -> bool {
        self.fatal_error().is_none() && self.0.view.active()
    }

    fn fatal_error(&self) -> Option<String> {
        match self.0.failure.lock() {
            Ok(failure) => failure.as_ref().map(|failure| failure.summary.clone()),
            Err(_) => Some("owner CPU failure latch poisoned".into()),
        }
    }

    fn execution_epoch(&self, consumer: u64) -> Result<u64, String> {
        if let Some(error) = self.fatal_error() {
            return Err(error);
        }
        // An attempted entry outside a turn executes nothing and need not
        // permanently poison storage that a later valid turn may reuse.
        if !self.0.view.active() {
            return Err("inactive memory-owner execution window".into());
        }
        let (serial, mutation) = self
            .0
            .access
            .execution_identity()
            .map_err(|error| self.fail(error))?;
        // This synchronous owner round trip also detects a dead broker before
        // cached native code can execute without another memory callback.
        self.query_code(self.code_epoch())
            .map_err(|error| self.fail(error))?;
        let mapping = self.0.view.change_epoch();
        let mut execution = self
            .0
            .execution
            .lock()
            .map_err(|_| "owner CPU admission state poisoned".to_string())?;
        if let Some((previous_serial, previous_consumer, previous_mutation, previous_mapping)) =
            execution.previous
        {
            let uninterrupted =
                serial == previous_serial || previous_serial.checked_add(1) == Some(serial);
            if !uninterrupted
                || consumer != previous_consumer
                || mutation != previous_mutation
                || mapping != previous_mapping
            {
                execution.epoch = execution
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| "owner CPU execution generation exhausted".to_string())?;
            }
        }
        execution.previous = Some((serial, consumer, mutation, mapping));
        Ok(execution.epoch)
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), GuestMemoryFault> {
        self.callback(address, bytes.len(), MemoryAccessKind::Read, || {
            self.0.view.read(address, bytes, ReadKind::Read)
        })
    }

    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), GuestMemoryFault> {
        self.callback(address, bytes.len(), MemoryAccessKind::Write, || {
            self.0.view.write(address, bytes, false)
        })
    }

    fn fetch(&self, address: u64, bytes: &mut [u8]) -> Result<(), GuestMemoryFault> {
        self.callback(address, bytes.len(), MemoryAccessKind::Fetch, || {
            self.0.view.read(address, bytes, ReadKind::Fetch)
        })
    }
}

impl FlatTranslation for OwnerMemory {
    fn translate(&self, address: u64, access: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        self.callback(address, 1, access, || {
            self.0.view.translate(address, access, false)
        })
    }
}

impl CpuAddressSpace for OwnerMemory {
    fn physical_memory(&self) -> &Arc<GuestMemoryMmap> {
        &self.0.physical
    }

    fn code_epoch(&self) -> u64 {
        self.0.code_epoch.load(Ordering::Acquire)
    }

    fn code_changes_since(&self, epoch: u64) -> (CodeChanges, u64) {
        match self.query_code(epoch) {
            Ok(value) => value,
            Err(error) => {
                self.fail(error);
                (CodeChanges::All, epoch)
            }
        }
    }

    fn probe(
        &self,
        address: u64,
        len: usize,
        access: MemoryAccessKind,
    ) -> Result<(), GuestMemoryFault> {
        self.callback(address, len, access, || {
            self.0.access.check()?;
            let mut left = len;
            let mut current = address;
            while left != 0 {
                self.0.view.translate(current, access, false)?;
                let count = (PAGE_SIZE - current % PAGE_SIZE).min(left as u64) as usize;
                left -= count;
                if left != 0 {
                    current = current.checked_add(count as u64).ok_or_else(|| {
                        self.0
                            .access
                            .fail(io::Error::other("CPU probe range overflow"))
                    })?;
                }
            }
            Ok(())
        })
    }

    fn trace_mappings(&self) -> Vec<TraceMapping> {
        let ranges = if self.0.view.active() {
            self.refresh_trace_mappings()
        } else {
            self.cached_trace_mappings()
        };
        match ranges {
            Ok(ranges) => ranges,
            Err(error) => {
                self.fail(error);
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests;
