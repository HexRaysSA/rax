//! Ordinary-fork snapshots made by the process memory owner.
//!
//! Snapshotting copies populated private frames to distinct physical storage.
//! Unix retains the process-owner file; Windows uses the native placeholder
//! arena constructor. This storage primitive does not add Windows worker IPC.
//! Shared extents attach the same objects, preserving shared-file coherence.
//! Unpopulated pages retain their original backing and remain demand-paged.
//! This primitive does not select clone policy or replace the owner protocol.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use super::pagetable::{PTE_FRAME, PTE_VALID, PageTable};
use super::{AddressSpace, Inner, MmError, PAGE_SIZE, attach};

impl AddressSpace {
    /// Snapshot a quiescent address space into distinct owner-managed storage.
    ///
    /// The caller must exclude guest execution and all MM changes for the
    /// complete operation. Lock order matches population: VMA, extents, arena.
    /// Failure drops only the unpublished snapshot; the source is unchanged.
    /// Work is O(V + S + E), plus copying 4096 bytes per private resident page,
    /// for V VMAs, S visited sparse-table slots, and E attached extents.
    pub(crate) fn process_snapshot(&self) -> Result<Self, MmError> {
        if !self.available() {
            return Err(MmError::InvalidArgument("source arena unavailable"));
        }
        let vmas = self.vmas();
        let source_extents = self.inner.extents.lock().unwrap();
        let arena = self.inner.arena.snapshot_storage()?;
        let mut extents = source_extents.clone();
        for (&base, attached) in &mut extents.at {
            attached.len = attach(&arena, base, &attached.object, attached.key.2)?;
        }

        let table = PageTable::new();
        let mut page = [0; PAGE_SIZE as usize];
        self.inner
            .table
            .for_each_populated(0, self.inner.va_limit >> 12, |vpn, source_slot| {
                let pte = source_slot.load(Ordering::Acquire);
                if pte & PTE_VALID == 0 {
                    return;
                }
                let frame = pte & PTE_FRAME;
                if !self.inner.arena.is_extent(frame) {
                    self.inner.arena.read(frame, &mut page);
                    arena.write(frame, &page);
                }
                table.slot(vpn).store(pte, Ordering::Release);
            });
        Ok(Self {
            inner: Arc::new(Inner {
                va_limit: self.inner.va_limit,
                arena,
                table,
                vmas: Mutex::new(vmas.clone()),
                code: Mutex::new(self.inner.code.lock().unwrap().clone()),
                epoch: std::sync::atomic::AtomicU64::new(self.code_epoch()),
                extents: Mutex::new(extents),
            }),
        })
    }
}

#[cfg(test)]
mod tests;
