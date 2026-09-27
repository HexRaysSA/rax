//! Host-owned explicit on-exit tables and detached callback generations.
//!
//! The caller owns the 3P-byte table object. Its plain first/last/end fields
//! are a MinGW-compatible profile, not a native UCRT opaque-layout claim.
//! Internal heap blocks are never ordinary CRT malloc-ledger entries. A drain
//! owns its old generation independently of reinitialization at the same table.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};

use crate::error::MemoryAccessKind;
use crate::user::windows::heap::HeapError;
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::process::Proc;

const INITIAL_CAPACITY: u64 = 32;
const COPY_BYTES: usize = 256;

#[derive(Debug)]
pub(super) enum TableError {
    Fault(MemFault),
    NoMemory,
    Invalid,
    GenerationExhausted,
    Internal(String),
}

impl From<MemFault> for TableError {
    fn from(fault: MemFault) -> Self {
        Self::Fault(fault)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Buffer {
    heap: u64,
    base: u64,
    capacity: u64,
    table: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug)]
struct Table {
    generation: u64,
    initialized: bool,
    buffer: Option<Buffer>,
    length: u64,
}

#[derive(Default)]
struct Registry {
    tables: HashMap<u64, Table>,
    /// Includes current buffers and buffers owned by outstanding drain tickets.
    owned: HashMap<u64, Buffer>,
    active: usize,
    abandoned: Vec<Abandoned>,
}

/// Per-runtime state. Clone the handle before borrowing the mutable process.
#[derive(Clone, Default)]
pub(in crate::user::windows::dll::crt) struct OnExitState(Rc<RefCell<Registry>>);

/// Dropping a continuation never accesses guest storage or reports API success.
/// The scheduler classifies the owner, then reaps the exact recorded heap block.
pub(super) struct Abandoned {
    pub(super) tid: u32,
    pub(super) table: u64,
    pub(super) generation: u64,
    buffer: Option<Buffer>,
    registry: Weak<RefCell<Registry>>,
}

/// A single detached generation. No registry borrow crosses guest execution.
pub(super) struct Drain {
    registry: Rc<RefCell<Registry>>,
    table: u64,
    generation: u64,
    tid: u32,
    buffer: Option<Buffer>,
    remaining: u64,
    finished: bool,
}

fn internal(message: impl Into<String>) -> TableError {
    TableError::Internal(message.into())
}

fn range(p: &Proc, base: u64, bytes: u64, write: bool) -> Result<(), TableError> {
    let max = p.arch.ptr(u64::MAX);
    let last = base
        .checked_add(bytes.saturating_sub(1))
        .ok_or(MemFault { addr: max, write })?;
    if base > max || last > max {
        return Err(MemFault {
            addr: max.saturating_add(1),
            write,
        }
        .into());
    }
    Ok(())
}

fn probe(p: &Proc, base: u64, bytes: u64, write: bool) -> Result<(), TableError> {
    range(p, base, bytes, write)?;
    let bytes = usize::try_from(bytes).map_err(|_| TableError::NoMemory)?;
    p.space
        .probe(
            base,
            bytes,
            if write {
                MemoryAccessKind::Write
            } else {
                MemoryAccessKind::Read
            },
        )
        .map_err(|fault| {
            TableError::Fault(MemFault {
                addr: fault.address,
                write,
            })
        })
}

fn table_range(p: &Proc, table: u64, write: bool) -> Result<(), TableError> {
    if table == 0 || table % p.arch.ptr_size() != 0 {
        return Err(TableError::Invalid);
    }
    probe(p, table, 3 * p.arch.ptr_size(), write)
}

fn bytes(p: &Proc, capacity: u64) -> Result<u64, TableError> {
    capacity
        .checked_mul(p.arch.ptr_size())
        .filter(|&n| n <= p.arch.ptr(u64::MAX) - 31)
        .ok_or(TableError::NoMemory)
}

fn overlaps(a: u64, a_bytes: u64, b: u64, b_bytes: u64) -> bool {
    // Validated allocations/table spans never overflow; subtraction avoids
    // needing an exclusive-end address representable at the guest upper bound.
    if a <= b {
        b - a < a_bytes
    } else {
        a - b < b_bytes
    }
}

fn table_alias(p: &Proc, registry: &Registry, table: u64) -> Result<(), TableError> {
    let table_bytes = 3 * p.arch.ptr_size();
    for buffer in registry.owned.values() {
        if overlaps(table, table_bytes, buffer.base, bytes(p, buffer.capacity)?) {
            return Err(TableError::Invalid);
        }
    }
    for (&other, state) in &registry.tables {
        if other != table && state.initialized && overlaps(table, table_bytes, other, table_bytes) {
            return Err(TableError::Invalid);
        }
    }
    Ok(())
}

fn representation(p: &Proc, state: Table) -> Result<[u64; 3], TableError> {
    let Some(buffer) = state.buffer else {
        return Ok([0; 3]);
    };
    if state.length > buffer.capacity {
        return Err(internal("on-exit length exceeds owned capacity"));
    }
    let end = buffer
        .base
        .checked_add(bytes(p, buffer.capacity)?)
        .ok_or(TableError::NoMemory)?;
    let last = buffer
        .base
        .checked_add(bytes(p, state.length)?)
        .ok_or(TableError::NoMemory)?;
    if p.arch.ptr(end) != end || p.arch.ptr(last) != last {
        return Err(TableError::NoMemory);
    }
    Ok([buffer.base, last, end])
}

fn read_table(p: &Proc, table: u64) -> Result<[u64; 3], TableError> {
    table_range(p, table, false)?;
    let width = p.arch.ptr_size();
    let mut values = [0; 3];
    for (index, value) in values.iter_mut().enumerate() {
        *value = p.space.ptr(table + index as u64 * width, width)?;
    }
    Ok(values)
}

fn write_table(p: &Proc, table: u64, values: [u64; 3]) -> Result<(), TableError> {
    table_range(p, table, true)?;
    let width = p.arch.ptr_size() as usize;
    let mut encoded = [0u8; 24];
    for (index, value) in values.into_iter().enumerate() {
        if p.arch.ptr(value) != value {
            return Err(TableError::Invalid);
        }
        encoded[index * width..(index + 1) * width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    // AddressSpace::write checks the complete span before moving any byte.
    p.space.wr(table, &encoded[..3 * width])?;
    Ok(())
}

fn validate_buffer(p: &Proc, buffer: Buffer) -> Result<(), TableError> {
    match p.heaps.size(buffer.heap, buffer.base) {
        Ok(size) if size == bytes(p, buffer.capacity)? => Ok(()),
        _ => Err(internal("on-exit internal heap block is no longer live")),
    }
}

fn heap_error(error: HeapError) -> TableError {
    match error {
        HeapError::NoMemory => TableError::NoMemory,
        HeapError::MemoryFault(fault) => TableError::Fault(fault),
        HeapError::BadHeap | HeapError::BadBlock => internal("on-exit private heap is invalid"),
    }
}

fn release_buffer(
    p: &mut Proc,
    registry: &Rc<RefCell<Registry>>,
    buffer: Buffer,
) -> Result<(), TableError> {
    if registry.borrow().owned.get(&buffer.base) != Some(&buffer) {
        return Err(internal("on-exit allocation ownership receipt mismatch"));
    }
    // Reject an externally freed/reallocated opaque block before freeing it.
    // The heap has no allocation-generation ID: equal-address/equal-size ABA
    // after an ownership-violating raw HeapFree cannot be distinguished here.
    validate_buffer(p, buffer)?;
    p.heaps.free(buffer.heap, buffer.base).map_err(heap_error)?;
    registry.borrow_mut().owned.remove(&buffer.base);
    Ok(())
}

fn rollback(p: &mut Proc, buffer: Buffer, original: &TableError) {
    if let Err(cleanup) = p.heaps.free(buffer.heap, buffer.base) {
        p.fail(format!(
            "on-exit candidate cleanup failed: {cleanup:?}; original: {original:?}"
        ));
    }
}

fn initialize_buffer(
    p: &Proc,
    from: Option<Buffer>,
    target: Buffer,
    length: u64,
) -> Result<(), TableError> {
    let total = bytes(p, target.capacity)?;
    probe(p, target.base, total, true)?;
    let copied = bytes(p, length)?;
    if let Some(old) = from {
        probe(p, old.base, copied, false)?;
    }
    let mut scratch = [0u8; COPY_BYTES];
    let mut offset = 0;
    while offset < total {
        let count = (total - offset).min(COPY_BYTES as u64) as usize;
        scratch[..count].fill(0);
        if offset < copied {
            let read = (copied - offset).min(count as u64) as usize;
            let source = from.ok_or_else(|| internal("on-exit live entries lack a buffer"))?;
            p.space.rd(source.base + offset, &mut scratch[..read])?;
        }
        p.space.wr(target.base + offset, &scratch[..count])?;
        offset += count as u64;
    }
    Ok(())
}

impl OnExitState {
    /// Initialization accepts arbitrary old guest bytes, but never uses them
    /// as allocation identities. A live current generation is reset/freed;
    /// detached generations remain owned by their continuations.
    pub(super) fn initialize(&self, p: &mut Proc, table: u64) -> Result<(), TableError> {
        table_range(p, table, true)?;
        let (generation, old) = {
            let mut registry = self.0.borrow_mut();
            table_alias(p, &registry, table)?;
            let old = registry.tables.get(&table).copied();
            let generation = old
                .map_or(0, |entry| entry.generation)
                .checked_add(1)
                .ok_or(TableError::GenerationExhausted)?;
            registry
                .tables
                .try_reserve(1)
                .map_err(|_| TableError::NoMemory)?;
            (generation, old.and_then(|entry| entry.buffer))
        };
        if let Some(buffer) = old {
            validate_buffer(p, buffer)?;
        }
        write_table(p, table, [0; 3])?;
        self.0.borrow_mut().tables.insert(
            table,
            Table {
                generation,
                initialized: true,
                buffer: None,
                length: 0,
            },
        );
        if let Some(buffer) = old {
            release_buffer(p, &self.0, buffer)?;
        }
        Ok(())
    }

    /// O(N) growth copy and O(1) fixed scratch. Doubling gives amortized O(1)
    /// copy work, but ownership/alias validation scans O(T + B) registered
    /// tables and owned blocks per registration, excluding heap indexing and
    /// guest-page residency. No registry borrow crosses guest execution.
    pub(super) fn register(
        &self,
        p: &mut Proc,
        heap: u64,
        table: u64,
        target: u64,
    ) -> Result<(), TableError> {
        if p.arch.ptr(target) != target {
            return Err(TableError::Invalid);
        }
        let observed = read_table(p, table)?;
        let entry = {
            let registry = self.0.borrow();
            table_alias(p, &registry, table)?;
            registry
                .tables
                .get(&table)
                .copied()
                .filter(|e| e.initialized)
                .ok_or(TableError::Invalid)?
        };
        if observed != representation(p, entry)? {
            return Err(TableError::Invalid);
        }
        table_range(p, table, true)?;
        if let Some(buffer) = entry.buffer {
            validate_buffer(p, buffer)?;
            if entry.length < buffer.capacity {
                let at = buffer.base + bytes(p, entry.length)?;
                probe(p, at, p.arch.ptr_size(), true)?;
                let next = Table {
                    length: entry.length + 1,
                    ..entry
                };
                let fields = representation(p, next)?;
                p.space.wptr(at, p.arch.ptr_size(), target)?;
                write_table(p, table, fields)?;
                self.0.borrow_mut().tables.insert(table, next);
                return Ok(());
            }
        }
        let capacity = match entry.buffer {
            Some(buffer) => buffer.capacity.checked_mul(2).ok_or(TableError::NoMemory)?,
            None => INITIAL_CAPACITY,
        };
        let size = bytes(p, capacity)?;
        self.0
            .borrow_mut()
            .owned
            .try_reserve(1)
            .map_err(|_| TableError::NoMemory)?;
        // Do not zero an allocator-selected block until alias checks succeed:
        // caller objects maliciously placed in free heap storage stay intact.
        let base = p
            .heaps
            .alloc_checked(&mut p.vm, heap, size, false)
            .map_err(heap_error)?;
        let candidate = Buffer {
            heap,
            base,
            capacity,
            table,
            generation: entry.generation,
        };
        let result = (|| {
            range(p, base, size, true)?;
            let registry = self.0.borrow();
            for (&address, current) in &registry.tables {
                if current.initialized && overlaps(base, size, address, 3 * p.arch.ptr_size()) {
                    return Err(TableError::Invalid);
                }
            }
            for owned in registry.owned.values() {
                if overlaps(base, size, owned.base, bytes(p, owned.capacity)?) {
                    return Err(internal("on-exit candidate overlaps an owned block"));
                }
            }
            drop(registry);
            initialize_buffer(p, entry.buffer, candidate, entry.length)?;
            let next = Table {
                buffer: Some(candidate),
                length: entry.length + 1,
                ..entry
            };
            let fields = representation(p, next)?;
            p.space
                .wptr(base + bytes(p, entry.length)?, p.arch.ptr_size(), target)?;
            write_table(p, table, fields)?;
            Ok(next)
        })();
        let next = match result {
            Ok(next) => next,
            Err(original) => {
                rollback(p, candidate, &original);
                return Err(original);
            }
        };
        {
            let mut registry = self.0.borrow_mut();
            registry.owned.insert(base, candidate);
            registry.tables.insert(table, next);
        }
        if let Some(old) = entry.buffer {
            release_buffer(p, &self.0, old)?;
        }
        Ok(())
    }

    /// Detaches before guest invocation. Execute/registration require a fresh
    /// initialize afterward. Reinitialization cannot reclaim this old buffer.
    pub(super) fn begin_execute(
        &self,
        p: &mut Proc,
        table: u64,
        tid: u32,
    ) -> Result<Drain, TableError> {
        let observed = read_table(p, table)?;
        let entry = {
            let mut registry = self.0.borrow_mut();
            table_alias(p, &registry, table)?;
            let entry = registry
                .tables
                .get(&table)
                .copied()
                .filter(|e| e.initialized)
                .ok_or(TableError::Invalid)?;
            let active = registry
                .active
                .checked_add(1)
                .ok_or(TableError::GenerationExhausted)?;
            // Existing queue capacity is retained when receipts are extracted.
            registry
                .abandoned
                .try_reserve(active)
                .map_err(|_| TableError::NoMemory)?;
            entry
        };
        if observed != representation(p, entry)? {
            return Err(TableError::Invalid);
        }
        if let Some(buffer) = entry.buffer {
            validate_buffer(p, buffer)?;
        }
        write_table(p, table, [0; 3])?;
        {
            let mut registry = self.0.borrow_mut();
            registry.tables.insert(
                table,
                Table {
                    initialized: false,
                    buffer: None,
                    length: 0,
                    ..entry
                },
            );
            registry.active += 1; // Preflighted above; no intervening callback.
        }
        Ok(Drain {
            registry: Rc::clone(&self.0),
            table,
            generation: entry.generation,
            tid,
            buffer: entry.buffer,
            remaining: entry.length,
            finished: false,
        })
    }

    /// Fallible output reservation happens before draining. The registry keeps
    /// capacity promised to every still-live ticket's allocation-free Drop.
    pub(super) fn take_abandoned(&self) -> Result<Vec<Abandoned>, TableError> {
        let mut registry = self.0.borrow_mut();
        let mut result = Vec::new();
        result
            .try_reserve_exact(registry.abandoned.len())
            .map_err(|_| TableError::NoMemory)?;
        result.extend(registry.abandoned.drain(..));
        Ok(result)
    }

    /// Host-only process cleanup, after all frames/tickets have been dropped.
    /// Attempt every known block; neither table fields nor callback code run.
    pub(super) fn discard_process(&self, p: &mut Proc) -> Result<(), TableError> {
        if self.0.borrow().active != 0 {
            return Err(internal("on-exit process cleanup still has live tickets"));
        }
        let mut first_error = None;
        let mut registry = self.0.borrow_mut();
        for (_, buffer) in registry.owned.drain() {
            let result = validate_buffer(p, buffer)
                .and_then(|()| p.heaps.free(buffer.heap, buffer.base).map_err(heap_error));
            if let Err(error) = result {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        registry.tables.clear();
        registry.abandoned.clear();
        first_error.map_or(Ok(()), Err)
    }
}

impl Drain {
    /// Lazy LIFO read and logical pop. A fault leaves that unread slot pending;
    /// earlier NULL holes stay consumed. The checked-call dispatcher must keep
    /// the selected target and this ticket across callback-stack setup faults.
    pub(super) fn next(&mut self, p: &Proc) -> Result<Option<u64>, TableError> {
        if self.finished {
            return Ok(None);
        }
        while self.remaining != 0 {
            let buffer = self
                .buffer
                .ok_or_else(|| internal("on-exit drain lacks owned storage"))?;
            validate_buffer(p, buffer)?;
            let at = buffer.base + bytes(p, self.remaining - 1)?;
            probe(p, at, p.arch.ptr_size(), false)?;
            let target = p.space.ptr(at, p.arch.ptr_size())?;
            self.remaining -= 1;
            if target != 0 {
                return Ok(Some(target));
            }
        }
        Ok(None)
    }

    pub(super) fn finish(mut self, p: &mut Proc) -> Result<(), TableError> {
        if self.remaining != 0 {
            return Err(internal(
                "on-exit drain finished before all entries were consumed",
            ));
        }
        if let Some(buffer) = self.buffer {
            release_buffer(p, &self.registry, buffer)?;
            self.buffer = None;
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        let mut registry = self.registry.borrow_mut();
        registry.active -= 1;
        if !self.finished {
            registry.abandoned.push(Abandoned {
                tid: self.tid,
                table: self.table,
                generation: self.generation,
                buffer: self.buffer.take(),
                registry: Rc::downgrade(&self.registry),
            });
        }
    }
}

/// Reap one typed receipt without guest reads/writes. Its weak registry link
/// avoids a cycle between the registry and its queued abandonment records.
pub(super) fn cleanup_abandoned(p: &mut Proc, receipt: Abandoned) -> Result<(), TableError> {
    if let Some(buffer) = receipt.buffer {
        let registry = receipt
            .registry
            .upgrade()
            .ok_or_else(|| internal("on-exit receipt lost its registry"))?;
        release_buffer(p, &registry, buffer)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
