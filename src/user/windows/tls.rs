//! Thread-local storage.
//!
//! Dynamic TLS (`TlsAlloc`, `TlsGetValue`, `TlsSetValue`, `TlsFree`): 64
//! slots in `TEB.TlsSlots`, then 1024 expansion slots in a per-thread
//! array that `TEB.TlsExpansionSlots` points to, allocated on first use
//! (`TLS_MINIMUM_AVAILABLE` = 64, `TLS_EXPANSION_SLOTS` = 1024). The
//! values live in guest memory, so code that reads `TlsSlots` directly
//! agrees with `TlsGetValue`.
//!
//! Fiber-local storage lives in a host-authoritative, generation-checked
//! registry keyed by disjoint thread/fiber identities. Cleanup tickets never
//! hold a registry borrow across guest callbacks. Slot zero and a 4080-slot
//! ceiling are explicit personality admission bounds, not native guarantees.
//!
//! Static TLS (the `.tls` directory): each module that has one gets an
//! index; every thread's `ThreadLocalStoragePointer` array holds, per
//! index, a block initialized from the module's template.

mod fls;
pub use fls::{FlsAbandoned, FlsCallback, FlsCleanup, FlsError, FlsFree, FlsKey};

/// `TLS_MINIMUM_AVAILABLE`.
pub const TLS_MINIMUM_AVAILABLE: u32 = 64;
/// `TLS_EXPANSION_SLOTS`.
pub const TLS_EXPANSION_SLOTS: u32 = 1024;
/// `TLS_OUT_OF_INDEXES` / `FLS_OUT_OF_INDEXES`.
pub const TLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;
/// `FLS_MAXIMUM_AVAILABLE`.
pub const FLS_MAXIMUM_AVAILABLE: u32 = 4080;

/// Slot allocation state.
#[derive(Debug, Default)]
pub struct TlsState {
    tls: Vec<bool>,
    fls: fls::FlsRegistry,
}

impl TlsState {
    /// Allocates the lowest free TLS index.
    pub fn alloc(&mut self) -> Option<u32> {
        let limit = (TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS) as usize;
        if self.tls.len() < limit {
            self.tls.resize(limit, false);
        }
        let i = self.tls.iter().position(|&used| !used)?;
        self.tls[i] = true;
        Some(i as u32)
    }

    /// Frees a TLS index; false if it was not allocated.
    pub fn free(&mut self, index: u32) -> bool {
        match self.tls.get_mut(index as usize) {
            Some(used) if *used => {
                *used = false;
                true
            }
            _ => false,
        }
    }

    /// Whether a TLS index is allocated.
    pub fn allocated(&self, index: u32) -> bool {
        self.tls.get(index as usize).copied().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_indices_are_lowest_free_and_bounded() {
        let mut t = TlsState::default();
        assert_eq!(t.alloc(), Some(0));
        assert_eq!(t.alloc(), Some(1));
        assert!(t.free(0));
        assert!(!t.free(0));
        assert_eq!(t.alloc(), Some(0));
        let mut n = 2;
        while t.alloc().is_some() {
            n += 1;
        }
        assert_eq!(n, TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS);
    }
}
