//! Lock-free cache of populated pages.
//!
//! The table maps a 36-bit virtual page number (48-bit virtual addresses,
//! 4 KiB pages) to a page-table entry through a three-level radix tree of
//! 4096-entry nodes. Interior nodes are created on demand with
//! [`OnceLock`] and are never freed while the table lives, so readers need
//! no lock: a lookup is two acquire loads of node pointers and one load of
//! the entry. Entries are written only while the owning address space holds
//! its mapping lock.
//!
//! Entry layout (`u64`):
//!
//! | Bits | Meaning |
//! |---|---|
//! | 0 | readable |
//! | 1 | writable |
//! | 2 | executable |
//! | 3 | valid |
//! | 12..63 | frame address in the arena |
//!
//! A zero entry means "not populated"; the address space then consults its
//! VMAs to populate the page or classify the fault.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use super::Perms;

const FANOUT_BITS: u32 = 12;
const FANOUT: usize = 1 << FANOUT_BITS;
const MASK: u64 = (FANOUT as u64) - 1;

/// Number of virtual-page-number bits the table covers.
pub const VPN_BITS: u32 = 3 * FANOUT_BITS;

/// Entry flag: the entry holds a frame.
pub const PTE_VALID: u64 = 1 << 3;
/// Entry field: permission bits.
pub const PTE_PERMS: u64 = 0x7;
/// Entry field: frame address.
pub const PTE_FRAME: u64 = !0xFFF;

type Leaf = Box<[AtomicU64]>;
type Mid = Box<[OnceLock<Leaf>]>;

/// Radix tree of populated-page entries.
pub struct PageTable {
    root: Box<[OnceLock<Mid>]>,
}

impl std::fmt::Debug for PageTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageTable").finish_non_exhaustive()
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds an entry for `frame` with `perms`.
#[inline]
pub fn make_pte(frame: u64, perms: Perms) -> u64 {
    debug_assert_eq!(frame & 0xFFF, 0);
    frame | PTE_VALID | u64::from(perms.bits())
}

/// Permissions of a valid entry.
#[inline]
pub fn pte_perms(pte: u64) -> Perms {
    Perms::from_bits_truncate((pte & PTE_PERMS) as u8)
}

impl PageTable {
    /// Creates an empty table.
    pub fn new() -> Self {
        PageTable {
            root: (0..FANOUT).map(|_| OnceLock::new()).collect(),
        }
    }

    #[inline]
    fn split(vpn: u64) -> (usize, usize, usize) {
        debug_assert!(vpn >> VPN_BITS == 0);
        (
            ((vpn >> (2 * FANOUT_BITS)) & MASK) as usize,
            ((vpn >> FANOUT_BITS) & MASK) as usize,
            (vpn & MASK) as usize,
        )
    }

    /// The entry for `vpn`, or zero when not populated.
    #[inline]
    pub fn get(&self, vpn: u64) -> u64 {
        let (a, b, c) = Self::split(vpn);
        match self.root[a].get().and_then(|mid| mid[b].get()) {
            Some(leaf) => leaf[c].load(Ordering::Acquire),
            None => 0,
        }
    }

    /// The entry slot for `vpn`, creating interior nodes as needed.
    pub fn slot(&self, vpn: u64) -> &AtomicU64 {
        let (a, b, c) = Self::split(vpn);
        let mid = self.root[a].get_or_init(|| (0..FANOUT).map(|_| OnceLock::new()).collect());
        let leaf = mid[b].get_or_init(|| (0..FANOUT).map(|_| AtomicU64::new(0)).collect());
        &leaf[c]
    }

    /// Calls `f(vpn, slot)` for every non-zero entry with `lo <= vpn < hi`,
    /// in ascending order, skipping absent subtrees.
    pub fn for_each_populated(&self, lo: u64, hi: u64, mut f: impl FnMut(u64, &AtomicU64)) {
        let hi = hi.min(1 << VPN_BITS);
        if lo >= hi {
            return;
        }
        let span_mid = 1u64 << (2 * FANOUT_BITS);
        let span_leaf = 1u64 << FANOUT_BITS;
        let mut vpn = lo;
        while vpn < hi {
            let (a, b, c) = Self::split(vpn);
            let Some(mid) = self.root[a].get() else {
                vpn = (vpn / span_mid + 1) * span_mid;
                continue;
            };
            let Some(leaf) = mid[b].get() else {
                vpn = (vpn / span_leaf + 1) * span_leaf;
                continue;
            };
            let leaf_end = ((vpn / span_leaf + 1) * span_leaf).min(hi);
            for (i, slot) in leaf[c..(c + (leaf_end - vpn) as usize)].iter().enumerate() {
                if slot.load(Ordering::Acquire) != 0 {
                    f(vpn + i as u64, slot);
                }
            }
            vpn = leaf_end;
        }
    }
}
