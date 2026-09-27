//! Runtime-global ordinary/quick callback queues, separate from DLL tables.
//!
//! The SDK reverse visited-slot scan and insertion endpoint are retained; raw
//! pointer encoding and allocation addresses are not native-layout claims.
//! The facade owns the shared reentrant exit lock; TLS callbacks and termination
//! completion flags are future facade responsibilities, not implemented here.
//! No registry borrow survives guest execution. Private heap blocks must
//! not be raw-freed by callers: equal-address/equal-size heap ABA is unknown.

use std::cell::RefCell;
use std::rc::{Rc, Weak};

use crate::error::MemoryAccessKind;
use crate::user::windows::heap::HeapError;
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::process::Proc;

const INITIAL_CAPACITY: u64 = 32;
const MAXIMUM_INCREMENT: u64 = 512;
const MINIMUM_INCREMENT: u64 = 4;
const COPY_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Ordinary,
    Quick,
}
impl Kind {
    fn index(self) -> usize {
        match self {
            Self::Ordinary => 0,
            Self::Quick => 1,
        }
    }
}

#[derive(Debug)]
pub(super) enum TerminationError {
    Fault(MemFault),
    NoMemory,
    Invalid,
    GenerationExhausted,
    Internal(String),
}
impl From<MemFault> for TerminationError {
    fn from(fault: MemFault) -> Self {
        Self::Fault(fault)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Buffer {
    heap: u64,
    base: u64,
    capacity: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Queue {
    buffer: Option<Buffer>,
    /// Insertion endpoint; visited slots remain NULL until the queue resets.
    length: u64,
    revision: u64,
}

#[derive(Clone, Copy)]
struct Active {
    generation: u64,
    tid: u32,
    kind: Kind,
}

#[derive(Default)]
struct Registry {
    queues: [Queue; 2],
    next_buffer: u64,
    next_ticket: u64,
    active: Vec<Active>,
    abandoned: Vec<Abandoned>,
    discarded: bool,
}

#[derive(Clone, Default)]
pub(in crate::user::windows::dll::crt) struct TerminationState(Rc<RefCell<Registry>>);

/// A dropped ticket does not consume the remaining global queue or free it.
/// The weak link avoids retaining a registry through its own receipt queue.
pub(super) struct Abandoned {
    pub(super) tid: u32,
    pub(super) kind: Kind,
    pub(super) generation: u64,
    registry: Weak<RefCell<Registry>>,
}

#[derive(Clone, Copy)]
struct Pending {
    queue: Queue,
    index: u64,
    target: u64,
}

pub(super) struct Drain {
    registry: Rc<RefCell<Registry>>,
    ticket: Active,
    observed: Option<(Option<Buffer>, u64)>,
    cursor: u64,
    pending: Option<Pending>,
    finished: bool,
}

fn internal(message: impl Into<String>) -> TerminationError {
    TerminationError::Internal(message.into())
}
fn heap_error(error: HeapError) -> TerminationError {
    match error {
        HeapError::NoMemory => TerminationError::NoMemory,
        HeapError::MemoryFault(fault) => fault.into(),
        HeapError::BadHeap | HeapError::BadBlock => internal("termination private heap invalid"),
    }
}
fn bytes(p: &Proc, capacity: u64) -> Result<u64, TerminationError> {
    capacity
        .checked_mul(p.arch.ptr_size())
        .filter(|&n| n <= p.arch.ptr(u64::MAX) - 31)
        .ok_or(TerminationError::NoMemory)
}
fn range(p: &Proc, base: u64, count: u64, write: bool) -> Result<(), TerminationError> {
    let max = p.arch.ptr(u64::MAX);
    let last = base
        .checked_add(count.saturating_sub(1))
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
fn probe(p: &Proc, base: u64, count: u64, write: bool) -> Result<(), TerminationError> {
    range(p, base, count, write)?;
    p.space
        .probe(
            base,
            usize::try_from(count).map_err(|_| TerminationError::NoMemory)?,
            if write {
                MemoryAccessKind::Write
            } else {
                MemoryAccessKind::Read
            },
        )
        .map_err(|fault| {
            TerminationError::Fault(MemFault {
                addr: fault.address,
                write,
            })
        })
}
fn validate(p: &Proc, buffer: Buffer) -> Result<(), TerminationError> {
    match p.heaps.size(buffer.heap, buffer.base) {
        Ok(size) if size == bytes(p, buffer.capacity)? => Ok(()),
        _ => Err(internal("termination private callback block invalidated")),
    }
}
fn free(p: &mut Proc, buffer: Buffer) -> Result<(), TerminationError> {
    validate(p, buffer)?;
    p.heaps.free(buffer.heap, buffer.base).map_err(heap_error)
}
fn rollback(p: &mut Proc, buffer: Buffer, original: &TerminationError) {
    if let Err(cleanup) = p.heaps.free(buffer.heap, buffer.base) {
        p.fail(format!(
            "termination candidate rollback: {cleanup:?}; original: {original:?}"
        ));
    }
}
fn copy(p: &Proc, from: Option<Buffer>, length: u64, to: Buffer) -> Result<(), TerminationError> {
    let total = bytes(p, to.capacity)?;
    let copied = bytes(p, length)?;
    probe(p, to.base, total, true)?;
    if let Some(from) = from {
        validate(p, from)?;
        probe(p, from.base, copied, false)?;
    } else if copied != 0 {
        return Err(internal("termination entries lack storage"));
    }
    let mut scratch = [0u8; COPY_BYTES];
    let mut offset = 0;
    while offset < total {
        let count = (total - offset).min(COPY_BYTES as u64) as usize;
        scratch[..count].fill(0);
        if offset < copied {
            let count = (copied - offset).min(count as u64) as usize;
            let from = from.ok_or_else(|| internal("termination copy lacks source"))?;
            p.space.rd(from.base + offset, &mut scratch[..count])?;
        }
        p.space.wr(to.base + offset, &scratch[..count])?;
        offset += count as u64;
    }
    Ok(())
}

impl TerminationState {
    /// O(N) bounded-scratch growth; O(1) otherwise, excluding heap indexing and
    /// guest residency. The SDK's capped +512 growth gives O(N^2) worst-case
    /// aggregate copy work for N registrations, not amortized constant growth.
    pub(super) fn register(
        &self,
        p: &mut Proc,
        heap: u64,
        kind: Kind,
        target: u64,
    ) -> Result<(), TerminationError> {
        if p.arch.ptr(target) != target {
            return Err(TerminationError::Invalid);
        }
        let queue = {
            let r = self.0.borrow();
            if r.discarded {
                return Err(internal("discarded termination state"));
            }
            r.queues[kind.index()]
        };
        let revision = queue
            .revision
            .checked_add(1)
            .ok_or(TerminationError::GenerationExhausted)?;
        if let Some(buffer) = queue.buffer {
            validate(p, buffer)?;
            if buffer.heap != heap || queue.length > buffer.capacity {
                return Err(internal("termination queue ownership mismatch"));
            }
            if queue.length < buffer.capacity {
                let at = buffer.base + bytes(p, queue.length)?;
                p.space.wptr(at, p.arch.ptr_size(), target)?;
                self.0.borrow_mut().queues[kind.index()] = Queue {
                    length: queue.length + 1,
                    revision,
                    ..queue
                };
                return Ok(());
            }
        } else if queue.length != 0 {
            return Err(internal("termination length without storage"));
        }
        let generation = self
            .0
            .borrow()
            .next_buffer
            .checked_add(1)
            .ok_or(TerminationError::GenerationExhausted)?;
        let old = queue.buffer.map_or(0, |b| b.capacity);
        let preferred = if old == 0 {
            Some(INITIAL_CAPACITY)
        } else {
            old.checked_add(old.min(MAXIMUM_INCREMENT))
        };
        let fallback = old.checked_add(MINIMUM_INCREMENT);
        for capacity in [preferred, fallback].into_iter().flatten() {
            let size = match bytes(p, capacity) {
                Ok(size) => size,
                Err(TerminationError::NoMemory) => continue,
                Err(error) => return Err(error),
            };
            let base = match p.heaps.alloc_checked(&mut p.vm, heap, size, false) {
                Ok(base) => base,
                Err(HeapError::NoMemory) => continue,
                Err(error) => return Err(heap_error(error)),
            };
            let candidate = Buffer {
                heap,
                base,
                capacity,
                generation,
            };
            let initialized = (|| {
                range(p, base, size, true)?;
                copy(p, queue.buffer, queue.length, candidate)?;
                p.space
                    .wptr(base + bytes(p, queue.length)?, p.arch.ptr_size(), target)?;
                // HeapFree uses host metadata only. No guest callback occurs
                // between validating the old block and this final free.
                if let Some(old) = queue.buffer {
                    free(p, old)?;
                }
                Ok(())
            })();
            if let Err(error) = initialized {
                rollback(p, candidate, &error);
                return Err(error);
            }
            let mut r = self.0.borrow_mut();
            r.queues[kind.index()] = Queue {
                buffer: Some(candidate),
                length: queue.length + 1,
                revision,
            };
            r.next_buffer = generation;
            return Ok(());
        }
        // Both allocator attempts leave the old queue and its block intact.
        Err(TerminationError::NoMemory)
    }

    /// The facade holds its shared ordinary/quick recursive exit lock. Mixed
    /// kinds and nested same-thread drains are not rejected by this storage.
    pub(super) fn begin(&self, kind: Kind, tid: u32) -> Result<Drain, TerminationError> {
        let mut r = self.0.borrow_mut();
        if r.discarded {
            return Err(internal("discarded termination state"));
        }
        let generation = r
            .next_ticket
            .checked_add(1)
            .ok_or(TerminationError::GenerationExhausted)?;
        let count = r
            .active
            .len()
            .checked_add(1)
            .ok_or(TerminationError::GenerationExhausted)?;
        r.active
            .try_reserve(1)
            .map_err(|_| TerminationError::NoMemory)?;
        // Reserve for all live tickets' allocation-free Drop, in addition to
        // receipts already queued. Extraction retains this reserved capacity.
        r.abandoned
            .try_reserve(count)
            .map_err(|_| TerminationError::NoMemory)?;
        let ticket = Active {
            generation,
            tid,
            kind,
        };
        r.active.push(ticket);
        r.next_ticket = generation;
        drop(r);
        Ok(Drain {
            registry: Rc::clone(&self.0),
            ticket,
            observed: None,
            cursor: 0,
            pending: None,
            finished: false,
        })
    }

    pub(super) fn take_abandoned(&self) -> Result<Vec<Abandoned>, TerminationError> {
        let mut r = self.0.borrow_mut();
        let mut result = Vec::new();
        result
            .try_reserve_exact(r.abandoned.len())
            .map_err(|_| TerminationError::NoMemory)?;
        result.extend(r.abandoned.drain(..));
        Ok(result)
    }

    /// Host-only process discard after all continuation tickets were dropped.
    /// No slot reads/writes or callbacks, even when guest pages are NOACCESS.
    pub(super) fn discard_process(&self, p: &mut Proc) -> Result<(), TerminationError> {
        let queues = {
            let mut r = self.0.borrow_mut();
            if !r.active.is_empty() {
                return Err(internal("termination discard has live tickets"));
            }
            r.discarded = true;
            r.abandoned.clear();
            std::mem::take(&mut r.queues)
        };
        let mut failure = None;
        for queue in queues {
            if let Some(buffer) = queue.buffer
                && let Err(error) = free(p, buffer)
            {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drain {
    /// SDK-compatible visited-slot scan with ownership-safe nested reset.
    /// Changes to insertion endpoint/storage after callback return restart the
    /// scan; consumed NULL slots prevent replay. Raw native pointer-underflow
    /// behavior after nested reset is unknown and is not reproduced.
    pub(super) fn next(&mut self, p: &mut Proc) -> Result<Option<u64>, TerminationError> {
        if self.finished {
            return Ok(None);
        }
        if self.pending.is_some() {
            return self.consume_pending(p).map(Some);
        }
        loop {
            let queue = self.registry.borrow().queues[self.ticket.kind.index()];
            if self.observed != Some((queue.buffer, queue.length)) {
                self.observed = Some((queue.buffer, queue.length));
                self.cursor = queue.length;
            }
            if self.cursor == 0 {
                return Ok(None);
            }
            let buffer = queue
                .buffer
                .ok_or_else(|| internal("termination scan lacks buffer"))?;
            if queue.length > buffer.capacity || self.cursor > queue.length {
                return Err(internal("termination scan outside owned buffer"));
            }
            validate(p, buffer)?;
            let index = self.cursor - 1;
            let at = buffer.base + bytes(p, index)?;
            let target = p.space.ptr(at, p.arch.ptr_size())?;
            if target == 0 {
                self.cursor = index;
                continue;
            }
            // Capture before the clearing store: readonly/guard repair must
            // not reread a target after handler clobber. Queue mutation during
            // that repair is fail-closed, not inferred native SEH behavior.
            self.pending = Some(Pending {
                queue,
                index,
                target,
            });
            return self.consume_pending(p).map(Some);
        }
    }

    fn consume_pending(&mut self, p: &mut Proc) -> Result<u64, TerminationError> {
        let pending = self
            .pending
            .ok_or_else(|| internal("termination selection missing"))?;
        let queue = self.registry.borrow().queues[self.ticket.kind.index()];
        if queue != pending.queue {
            return Err(internal(
                "termination queue changed during selected-slot repair",
            ));
        }
        let revision = queue
            .revision
            .checked_add(1)
            .ok_or(TerminationError::GenerationExhausted)?;
        let buffer = queue
            .buffer
            .ok_or_else(|| internal("termination selected slot lacks buffer"))?;
        validate(p, buffer)?;
        let at = buffer.base + bytes(p, pending.index)?;
        p.space.wptr(at, p.arch.ptr_size(), 0)?;
        self.registry.borrow_mut().queues[self.ticket.kind.index()].revision = revision;
        self.cursor = pending.index;
        self.pending = None;
        Ok(pending.target)
    }

    pub(super) fn finish(mut self, p: &mut Proc) -> Result<(), TerminationError> {
        let queue = self.registry.borrow().queues[self.ticket.kind.index()];
        if self.pending.is_some()
            || self.cursor != 0
            || self.observed != Some((queue.buffer, queue.length))
        {
            return Err(internal(
                "termination drain finished before current queue exhausted",
            ));
        }
        let revision = queue
            .revision
            .checked_add(1)
            .ok_or(TerminationError::GenerationExhausted)?;
        if let Some(buffer) = queue.buffer {
            free(p, buffer)?;
        }
        self.registry.borrow_mut().queues[self.ticket.kind.index()] = Queue {
            revision,
            ..Queue::default()
        };
        self.finished = true;
        Ok(())
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        let mut r = self.registry.borrow_mut();
        if let Some(index) = r
            .active
            .iter()
            .position(|a| a.generation == self.ticket.generation)
        {
            r.active.swap_remove(index);
        }
        if !self.finished {
            r.abandoned.push(Abandoned {
                tid: self.ticket.tid,
                kind: self.ticket.kind,
                generation: self.ticket.generation,
                registry: Rc::downgrade(&self.registry),
            });
        }
    }
}

/// A receipt retires an interrupted invocation, not the process-global queue.
/// Remaining callbacks stay registered; terminal process discard owns final
/// freeing. Validation uses only heap metadata and performs no guest access.
pub(super) fn cleanup_abandoned(p: &mut Proc, receipt: Abandoned) -> Result<(), TerminationError> {
    let registry = receipt
        .registry
        .upgrade()
        .ok_or_else(|| internal("termination receipt lost runtime registry"))?;
    let queue = registry.borrow().queues[receipt.kind.index()];
    if let Some(buffer) = queue.buffer {
        validate(p, buffer)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
