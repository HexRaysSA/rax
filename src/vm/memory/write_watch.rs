//! Byte-precise intent for bounded shared register images, including stores
//! that leave RAM unchanged. Tracked writers already hold the domain locks.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const MAX_WATCH_BYTES: usize = 4096;
static ACTIVE_WATCHES: AtomicUsize = AtomicUsize::new(0);

pub(super) fn active() -> bool {
    ACTIVE_WATCHES.load(Ordering::Acquire) != 0
}

struct Span {
    start: usize,
    end: usize,
    offset: usize,
}

pub(super) struct WatchedWrites {
    spans: Vec<Span>,
    dirty: Mutex<Vec<u8>>,
    pending: AtomicBool,
    invalid: AtomicBool,
}

impl Drop for WatchedWrites {
    fn drop(&mut self) {
        ACTIVE_WATCHES.fetch_sub(1, Ordering::Release);
    }
}

impl WatchedWrites {
    pub(super) fn invalidate(&self) {
        self.invalid.store(true, Ordering::Release);
    }

    pub(super) fn record(&self, address: usize, size: usize) {
        let end = address as u128 + size as u128;
        if !self
            .spans
            .iter()
            .any(|span| (address as u128) < span.end as u128 && end > span.start as u128)
        {
            return;
        }
        let Ok(mut dirty) = self.dirty.lock() else {
            self.invalidate();
            return;
        };
        for span in &self.spans {
            let first = (address as u128).max(span.start as u128);
            let last = end.min(span.end as u128);
            if first < last {
                let offset = span.offset + first as usize - span.start;
                dirty[offset..offset + (last - first) as usize].fill(1);
            }
        }
        self.pending.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
pub(crate) struct WriteWatch {
    domain: Arc<MemoryDomain>,
    writes: Arc<WatchedWrites>,
    address: u64,
    size: usize,
}

impl std::fmt::Debug for WriteWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteWatch")
            .field("address", &self.address)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

pub(crate) struct WriteSnapshot {
    pub(crate) bytes: Vec<u8>,
    pub(crate) written: Vec<u8>,
}

impl WriteWatch {
    fn error(&self) -> GuestMemoryError {
        GuestMemoryError::InvalidGuestAddress(GuestAddress(self.address))
    }

    /// A copied CPU context must not import observations from another arena.
    /// O(source and destination backing spans); no bytes are read or written.
    pub(crate) fn same_backing(&self, memory: &GuestMemoryMmap, address: u64, size: usize) -> bool {
        address == self.address
            && size == self.size
            && !self.writes.invalid.load(Ordering::Acquire)
            && self.writes.spans.iter().all(|span| {
                let mut done = 0;
                let size = span.end - span.start;
                while done < size {
                    let current = address + (span.offset + done) as u64;
                    let Some(region) = memory.find_region(GuestAddress(current)) else {
                        return false;
                    };
                    let offset = (current - region.start_addr().0) as usize;
                    if (region.as_ptr() as usize).checked_add(offset) != Some(span.start + done) {
                        return false;
                    }
                    done += (region.len() as usize - offset).min(size - done);
                }
                true
            })
    }

    /// Keep intent pending until the owning state machine accepts the update.
    /// Both the bytes and mask are copied under the tracked-writer lock, so
    /// an admitted multi-byte store cannot appear as a partial snapshot.
    pub(crate) fn snapshot(&self) -> Result<Option<WriteSnapshot>, GuestMemoryError> {
        if self.writes.invalid.load(Ordering::Acquire) {
            return Err(self.error());
        }
        if !self.writes.pending.load(Ordering::Acquire) {
            return Ok(None);
        }
        let _domain = self.domain.lock();
        if self.writes.invalid.load(Ordering::Acquire) {
            return Err(self.error());
        }
        let written = self.writes.dirty.lock().map_err(|_| self.error())?;
        if !written.iter().any(|&byte| byte != 0) {
            return Ok(None);
        }
        let mut bytes = vec![0; self.size];
        self.domain
            ._backing
            .read_slice(&mut bytes, GuestAddress(self.address))?;
        Ok(Some(WriteSnapshot {
            bytes,
            written: written.clone(),
        }))
    }

    /// The owner calls this after publishing its accepted register image,
    /// with guest writers stopped. Publication stores are not guest updates.
    pub(crate) fn reset(&self) -> Result<(), GuestMemoryError> {
        let _domain = self.domain.lock();
        if self.writes.invalid.load(Ordering::Acquire) {
            return Err(self.error());
        }
        self.writes.dirty.lock().map_err(|_| self.error())?.fill(0);
        self.writes.pending.store(false, Ordering::Release);
        Ok(())
    }
}

impl MemoryDomain {
    /// Observe a nonempty register image of at most one page. The image may
    /// cross backing-region boundaries. Locks and identities are shared with
    /// aliased mappings, exactly as for the exclusive monitors.
    pub(crate) fn watch_writes(
        self: &Arc<Self>,
        address: u64,
        size: usize,
    ) -> Result<WriteWatch, GuestMemoryError> {
        let error = || GuestMemoryError::InvalidGuestAddress(GuestAddress(address));
        if size == 0 || size > MAX_WATCH_BYTES {
            return Err(error());
        }
        preflight_read(&self._backing, address, size)?;
        let mut spans = Vec::new();
        let mut done = 0;
        while done < size {
            let current = address.checked_add(done as u64).ok_or_else(error)?;
            let region = self
                ._backing
                .find_region(GuestAddress(current))
                .ok_or_else(error)?;
            let offset = (current - region.start_addr().0) as usize;
            let count = (region.len() as usize - offset).min(size - done);
            let start = (region.as_ptr() as usize)
                .checked_add(offset)
                .ok_or_else(error)?;
            let end = start.checked_add(count).ok_or_else(error)?;
            spans.push(Span {
                start,
                end,
                offset: done,
            });
            done += count;
        }
        ACTIVE_WATCHES.fetch_add(1, Ordering::Release);
        let writes = Arc::new(WatchedWrites {
            spans,
            dirty: Mutex::new(vec![0; size]),
            pending: AtomicBool::new(false),
            invalid: AtomicBool::new(false),
        });
        let mut guards = self.lock();
        for (index, allocation) in self.allocations.iter().enumerate() {
            if writes
                .spans
                .iter()
                .any(|span| span.start < allocation.key.1 && span.end > allocation.key.0)
            {
                let state = &mut guards.states()[index];
                state.writes.retain(|watch| watch.strong_count() != 0);
                state.writes.push(Arc::downgrade(&writes));
            }
        }
        Ok(WriteWatch {
            domain: self.clone(),
            writes,
            address,
            size,
        })
    }
}

#[cfg(test)]
#[path = "write_watch_tests.rs"]
mod tests;
