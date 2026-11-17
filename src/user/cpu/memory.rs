//! Storage contract shared by the user-mode CPU adapters.

use std::sync::Arc;

use vm_memory::GuestMemoryMmap;

use super::arm::A32AddressSpace;
use crate::error::{GuestMemoryFault, MemoryAccessKind};
use crate::user::mm::{AddressSpace, CodeChanges};
use crate::vm::memory::FlatTranslation;

/// An authoritative mapping description for memory-access tracing.
pub type TraceMapping = (u64, u64, u8, Option<String>);

/// User storage with real physical backing. Implementations must admit CPU
/// entry before cached physical pointers can be used and preserve fatal host
/// failures separately from architectural guest faults.
pub trait CpuAddressSpace: A32AddressSpace + FlatTranslation + Send + Sync + 'static {
    fn physical_memory(&self) -> &Arc<GuestMemoryMmap>;
    fn code_epoch(&self) -> u64;
    fn code_changes_since(&self, epoch: u64) -> (CodeChanges, u64);
    fn probe(
        &self,
        address: u64,
        len: usize,
        access: MemoryAccessKind,
    ) -> Result<(), GuestMemoryFault>;
    fn trace_mappings(&self) -> Vec<TraceMapping>;
}

impl CpuAddressSpace for AddressSpace {
    fn physical_memory(&self) -> &Arc<GuestMemoryMmap> {
        AddressSpace::physical_memory(self)
    }

    fn code_epoch(&self) -> u64 {
        AddressSpace::code_epoch(self)
    }

    fn code_changes_since(&self, epoch: u64) -> (CodeChanges, u64) {
        AddressSpace::code_changes_since(self, epoch)
    }

    fn probe(
        &self,
        address: u64,
        len: usize,
        access: MemoryAccessKind,
    ) -> Result<(), GuestMemoryFault> {
        AddressSpace::probe(self, address, len, access)
    }

    fn trace_mappings(&self) -> Vec<TraceMapping> {
        self.vma_snapshot()
            .into_iter()
            .map(|vma| {
                (
                    vma.start,
                    vma.end,
                    vma.perms.bits(),
                    vma.name.as_ref().map(|name| name.to_string()),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
