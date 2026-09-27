//! Thread-local storage.
//!
//! Dynamic TLS (`TlsAlloc`, `TlsGetValue`, `TlsSetValue`, `TlsFree`): 64
//! slots in `TEB.TlsSlots`, then 1024 expansion slots in a per-thread
//! array that `TEB.TlsExpansionSlots` points to, allocated on first use
//! (`TLS_MINIMUM_AVAILABLE` = 64, `TLS_EXPANSION_SLOTS` = 1024). The
//! values live in guest memory, so code that reads `TlsSlots` directly
//! agrees with `TlsGetValue`.
//!
//! Fiber-local storage (`FlsAlloc`, ...): 4080 slots
//! (`FLS_MAXIMUM_AVAILABLE`) with per-slot destructors, kept per thread on
//! the host; a thread's non-null values are passed to the destructors when
//! it exits or the slot is freed.
//!
//! Static TLS (the `.tls` directory): each module that has one gets an
//! index; every thread's `ThreadLocalStoragePointer` array holds, per
//! index, a block initialized from the module's template.

use std::collections::HashMap;

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
    fls: Vec<Option<u64>>,
    /// Per-thread FLS values: tid → slot → value.
    pub fls_values: HashMap<u32, HashMap<u32, u64>>,
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

    /// Allocates an FLS index with `callback` (0 for none). Index 0 is
    /// never returned (Windows reserves it).
    pub fn fls_alloc(&mut self, callback: u64) -> Option<u32> {
        if self.fls.is_empty() {
            self.fls.push(Some(0));
        }
        if let Some(i) = self.fls.iter().position(Option::is_none) {
            self.fls[i] = Some(callback);
            return Some(i as u32);
        }
        if self.fls.len() >= FLS_MAXIMUM_AVAILABLE as usize {
            return None;
        }
        self.fls.push(Some(callback));
        Some(self.fls.len() as u32 - 1)
    }

    /// Frees an FLS index, returning its callback and the non-null values
    /// threads held in it (which the callback receives).
    pub fn fls_free(&mut self, index: u32) -> Option<(u64, Vec<u64>)> {
        if index == 0 {
            return None;
        }
        let cb = self.fls.get_mut(index as usize)?.take()?;
        let values = self
            .fls_values
            .values_mut()
            .filter_map(|m| m.remove(&index))
            .filter(|&v| v != 0)
            .collect();
        Some((cb, values))
    }

    /// Whether an FLS index is allocated.
    pub fn fls_allocated(&self, index: u32) -> bool {
        index != 0 && matches!(self.fls.get(index as usize), Some(Some(_)))
    }

    /// Thread `tid`'s value in FLS slot `index`.
    pub fn fls_get(&self, tid: u32, index: u32) -> u64 {
        self.fls_values
            .get(&tid)
            .and_then(|m| m.get(&index))
            .copied()
            .unwrap_or(0)
    }

    /// Sets thread `tid`'s value in FLS slot `index`.
    pub fn fls_set(&mut self, tid: u32, index: u32, value: u64) {
        self.fls_values.entry(tid).or_default().insert(index, value);
    }

    /// Removes thread `tid`'s FLS values, returning `(callback, value)`
    /// pairs to run for its non-null values with a callback.
    pub fn fls_thread_exit(&mut self, tid: u32) -> Vec<(u64, u64)> {
        let Some(values) = self.fls_values.remove(&tid) else {
            return Vec::new();
        };
        let mut out: Vec<(u32, u64, u64)> = values
            .into_iter()
            .filter(|&(_, v)| v != 0)
            .filter_map(|(i, v)| match self.fls.get(i as usize) {
                Some(Some(cb)) if *cb != 0 => Some((i, *cb, v)),
                _ => None,
            })
            .collect();
        out.sort_unstable();
        out.into_iter().map(|(_, cb, v)| (cb, v)).collect()
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

    #[test]
    fn fls_values_and_callbacks() {
        let mut t = TlsState::default();
        let a = t.fls_alloc(0x1000).unwrap();
        assert_eq!(a, 1, "index 0 is reserved");
        let b = t.fls_alloc(0).unwrap();
        t.fls_set(7, a, 42);
        t.fls_set(7, b, 43);
        assert_eq!(t.fls_get(7, a), 42);
        assert_eq!(t.fls_get(8, a), 0);
        assert_eq!(t.fls_thread_exit(7), vec![(0x1000, 42)]);
        t.fls_set(9, a, 5);
        assert_eq!(t.fls_free(a), Some((0x1000, vec![5])));
        assert!(!t.fls_allocated(a));
    }
}
