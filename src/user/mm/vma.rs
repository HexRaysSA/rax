//! Virtual-memory-area (VMA) bookkeeping.
//!
//! A [`VmaMap`] is an ordered set of non-overlapping, page-aligned,
//! half-open ranges `[start, end)`, each with the permissions and backing
//! that govern its pages. Operations follow Linux `mm/mmap.c` range
//! semantics: inserting a mapping replaces whatever overlapped it (as
//! `MAP_FIXED` does), and unmapping or reprotecting part of a VMA splits it.
//! All operations are `O(k log n)` for `k` affected VMAs.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{Perms, backing::Backing};

/// One mapped range.
#[derive(Clone, Debug)]
pub struct Vma {
    /// First byte (page-aligned).
    pub start: u64,
    /// One past the last byte (page-aligned, > `start`).
    pub end: u64,
    /// Effective page permissions enforced on access.
    pub perms: Perms,
    /// Where page contents come from on first touch.
    pub backing: Backing,
    /// Shared (`MAP_SHARED`) rather than private.
    pub shared: bool,
    /// Descriptive label for `/proc/self/maps` (`[stack]`, `[heap]`, a path).
    pub name: Option<Arc<str>>,
    /// OS-personality bits carried unchanged (for example Linux `VM_GROWSDOWN`).
    pub flags: u32,
}

impl Vma {
    /// Length in bytes.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Always false: a VMA is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether `addr` lies inside this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// The part of this VMA inside `[lo, hi)`, adjusting file offsets.
    fn slice(&self, lo: u64, hi: u64) -> Vma {
        debug_assert!(lo >= self.start && hi <= self.end && lo < hi);
        Vma {
            start: lo,
            end: hi,
            perms: self.perms,
            backing: self.backing.advanced(lo - self.start),
            shared: self.shared,
            name: self.name.clone(),
            flags: self.flags,
        }
    }
}

/// Ordered, non-overlapping VMA set keyed by start address.
#[derive(Clone, Debug, Default)]
pub struct VmaMap {
    map: BTreeMap<u64, Vma>,
}

impl VmaMap {
    /// Creates an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of VMAs.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no VMA exists.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterates VMAs in ascending address order.
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.map.values()
    }

    /// The VMA containing `addr`, if any.
    pub fn find(&self, addr: u64) -> Option<&Vma> {
        self.map
            .range(..=addr)
            .next_back()
            .map(|(_, v)| v)
            .filter(|v| v.contains(addr))
    }

    /// VMAs intersecting `[lo, hi)` in ascending order.
    pub fn overlapping(&self, lo: u64, hi: u64) -> impl Iterator<Item = &Vma> {
        // The first candidate may start before `lo`.
        let first = self
            .map
            .range(..lo)
            .next_back()
            .filter(|(_, v)| v.end > lo)
            .map(|(&k, _)| k)
            .unwrap_or(lo);
        self.map
            .range(first..hi)
            .map(|(_, v)| v)
            .filter(move |v| v.end > lo && v.start < hi)
    }

    /// Whether every byte of `[lo, hi)` is covered by some VMA.
    pub fn covers(&self, lo: u64, hi: u64) -> bool {
        let mut cursor = lo;
        for v in self.overlapping(lo, hi) {
            if v.start > cursor {
                return false;
            }
            cursor = v.end;
            if cursor >= hi {
                return true;
            }
        }
        cursor >= hi
    }

    /// Whether no byte of `[lo, hi)` is covered.
    pub fn is_free(&self, lo: u64, hi: u64) -> bool {
        self.overlapping(lo, hi).next().is_none()
    }

    /// Removes `[lo, hi)` from every VMA, splitting partially covered ones,
    /// and returns the removed pieces in ascending order.
    pub fn remove(&mut self, lo: u64, hi: u64) -> Vec<Vma> {
        let hits: Vec<u64> = self.overlapping(lo, hi).map(|v| v.start).collect();
        let mut removed = Vec::with_capacity(hits.len());
        for key in hits {
            let v = self.map.remove(&key).expect("overlapping VMA present");
            if v.start < lo {
                self.map.insert(v.start, v.slice(v.start, lo));
            }
            if v.end > hi {
                self.map.insert(hi, v.slice(hi, v.end));
            }
            removed.push(v.slice(v.start.max(lo), v.end.min(hi)));
        }
        removed
    }

    /// Inserts `vma`, replacing any overlapped ranges; returns what was
    /// replaced.
    pub fn insert(&mut self, vma: Vma) -> Vec<Vma> {
        debug_assert!(vma.start < vma.end);
        let replaced = self.remove(vma.start, vma.end);
        self.map.insert(vma.start, vma);
        replaced
    }

    /// Applies `f` to the parts of VMAs inside `[lo, hi)`, splitting VMAs at
    /// the range boundaries. Returns the number of VMAs updated.
    pub fn update(&mut self, lo: u64, hi: u64, mut f: impl FnMut(&mut Vma)) -> usize {
        let pieces = self.remove(lo, hi);
        let n = pieces.len();
        for mut piece in pieces {
            f(&mut piece);
            self.map.insert(piece.start, piece);
        }
        n
    }

    /// Merges adjacent VMAs whose attributes and backing continue each other
    /// (Linux `vma_merge`), within `[lo, hi)` extended by one neighbour on
    /// each side. Purely cosmetic for `/proc/self/maps`; semantics are
    /// unchanged.
    pub fn coalesce(&mut self, lo: u64, hi: u64) {
        let keys: Vec<u64> = self
            .map
            .range(..=hi)
            .rev()
            .take_while(|(_, v)| v.end >= lo)
            .map(|(&k, _)| k)
            .collect();
        // Walk ascending so each merge folds into its predecessor.
        for key in keys.into_iter().rev() {
            let Some(cur) = self.map.get(&key).cloned() else {
                continue;
            };
            let Some((&pk, prev)) = self.map.range(..key).next_back() else {
                continue;
            };
            if prev.end == cur.start
                && prev.perms == cur.perms
                && prev.shared == cur.shared
                && prev.flags == cur.flags
                && prev.name == cur.name
                && prev.backing.continues_into(prev.len(), &cur.backing)
            {
                let end = cur.end;
                self.map.remove(&key);
                self.map.get_mut(&pk).expect("predecessor").end = end;
            }
        }
    }

    /// Highest free, `align`-aligned range of `len` bytes lying entirely in
    /// `[low, high)` (Linux top-down `unmapped_area_topdown`).
    pub fn find_free_top_down(&self, len: u64, align: u64, low: u64, high: u64) -> Option<u64> {
        debug_assert!(align.is_power_of_two());
        if len == 0 || high < low || high - low < len {
            return None;
        }
        let fit = |gap_start: u64, gap_end: u64| {
            if gap_end > gap_start && gap_end - gap_start >= len {
                let candidate = (gap_end - len) & !(align - 1);
                (candidate >= gap_start).then_some(candidate)
            } else {
                None
            }
        };
        let mut gap_end = high;
        // VMAs starting below `high`, highest first; each bounds the gap above it.
        for v in self.map.range(..high).rev().map(|(_, v)| v) {
            if let Some(candidate) = fit(v.end.max(low), gap_end) {
                return Some(candidate);
            }
            if v.start <= low {
                return None;
            }
            gap_end = gap_end.min(v.start);
        }
        fit(low, gap_end)
    }

    /// Lowest free, `align`-aligned range of `len` bytes lying entirely in
    /// `[low, high)` (Linux bottom-up `unmapped_area`).
    pub fn find_free_bottom_up(&self, len: u64, align: u64, low: u64, high: u64) -> Option<u64> {
        debug_assert!(align.is_power_of_two());
        if len == 0 || high < low || high - low < len {
            return None;
        }
        let mut cursor = low;
        for v in self.overlapping(low, high) {
            let candidate = cursor.checked_add(align - 1)? & !(align - 1);
            if candidate.checked_add(len)? <= v.start {
                return Some(candidate);
            }
            cursor = cursor.max(v.end);
        }
        let candidate = cursor.checked_add(align - 1)? & !(align - 1);
        (candidate.checked_add(len)? <= high).then_some(candidate)
    }
}
