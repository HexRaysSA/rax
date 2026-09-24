//! Guest address spaces for process-level emulation.
//!
//! An [`AddressSpace`] is the complete user virtual memory of one guest
//! process, shared by all of its threads. It combines:
//!
//! - a [`VmaMap`] that is the source of truth for which ranges are mapped,
//!   with what permissions and contents;
//! - a lock-free [`pagetable`] caching the frames of pages that have been
//!   touched, so a CPU's translation is a few atomic loads;
//! - a [`FrameArena`] of host-backed 4 KiB frames addressed as guest-physical
//!   memory.
//!
//! Pages are populated on first touch, as with demand paging: an access to
//! a mapped but unpopulated page allocates a zeroed frame and fills it from
//! the range's [`Backing`]. Faults are classified exactly as Linux does:
//! an address outside every VMA is *unmapped* (`SEGV_MAPERR`), an access the
//! VMA's permissions forbid is a *permission* fault (`SEGV_ACCERR`), and a
//! file-backed page wholly past end of file is a bus error (`SIGBUS`).
//!
//! # Concurrency
//!
//! Translation reads are lock-free. Every structural change — mapping,
//! unmapping, protection changes, and page population — happens under the
//! VMA lock. A frame freed by `unmap` may be reused immediately, so guest
//! execution must not run concurrently with a mapping change on another host
//! thread; the process scheduler guarantees this by running all guest
//! threads of an address space on one host thread.
//!
//! # Code invalidation
//!
//! CPU models cache decoded or compiled guest code. The address space logs
//! every event that can make such a cache stale — removal of execute
//! permission, unmapping or replacing executable pages, and writes (by any
//! vCPU or by the host) to executable pages — with a monotonically increasing
//! epoch. Each CPU adapter applies [`AddressSpace::code_changes_since`]
//! before it resumes guest execution.

mod arena;
mod backing;
pub mod pagetable;
mod vma;

#[cfg(test)]
mod tests;

pub use arena::FrameArena;
pub use backing::{Backing, BytesSource, HostFileSource, PageSource, SourceIdentity};
pub use vma::{Vma, VmaMap};

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vm_memory::GuestMemoryMmap;

use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::vm::memory::FlatTranslation;
use pagetable::{PTE_FRAME, PTE_VALID, PageTable, make_pte};

/// Guest page size in bytes.
pub const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Maximum code-invalidation log length before consumers must flush all.
const CODE_LOG_CAPACITY: usize = 4096;

bitflags::bitflags! {
    /// Effective page permissions.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct Perms: u8 {
        /// Data reads.
        const READ = 1;
        /// Data writes.
        const WRITE = 2;
        /// Instruction fetches.
        const EXEC = 4;
    }
}

impl Perms {
    /// Whether an access of kind `access` is permitted.
    #[inline]
    pub fn allows(self, access: MemoryAccessKind) -> bool {
        self.contains(Self::required(access))
    }

    /// The permission an access of kind `access` requires.
    #[inline]
    pub fn required(access: MemoryAccessKind) -> Perms {
        match access {
            MemoryAccessKind::Read => Perms::READ,
            MemoryAccessKind::Write => Perms::WRITE,
            MemoryAccessKind::Fetch => Perms::EXEC,
        }
    }
}

/// Address-space operation errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MmError {
    /// Misaligned or zero-length request, or an invalid configuration value.
    InvalidArgument(&'static str),
    /// The range extends beyond the address-space limit.
    OutOfRange,
    /// Part of the range is not mapped; `addr` is the first unmapped byte.
    NotMapped { addr: u64 },
    /// The frame arena is exhausted.
    OutOfMemory,
}

impl fmt::Display for MmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmError::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            MmError::OutOfRange => f.write_str("range exceeds the address-space limit"),
            MmError::NotMapped { addr } => write!(f, "address {addr:#x} is not mapped"),
            MmError::OutOfMemory => f.write_str("guest memory arena exhausted"),
        }
    }
}

impl std::error::Error for MmError {}

/// Linux-style classification of a failed access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultClass {
    /// No VMA covers the address (`SEGV_MAPERR`).
    Unmapped,
    /// A VMA covers the address but forbids the access (`SEGV_ACCERR`).
    Protection,
    /// The page is backed by a source that ends before it (`SIGBUS`,
    /// `BUS_ADRERR`).
    BeyondSource,
    /// The access is allowed but no frame could be allocated.
    OutOfMemory,
}

/// Address-space construction parameters.
#[derive(Clone, Debug)]
pub struct SpaceConfig {
    /// Exclusive upper bound of user virtual addresses; at most 2^48.
    pub va_limit: u64,
    /// Capacity of the frame arena in bytes.
    pub arena_bytes: u64,
    /// Guest-physical ranges the arena must never allocate.
    pub reserved_phys: Vec<(u64, u64)>,
}

/// Attributes of a new mapping.
#[derive(Clone, Debug)]
pub struct Mapping {
    /// Effective permissions.
    pub perms: Perms,
    /// Initial contents.
    pub backing: Backing,
    /// `MAP_SHARED` rather than private.
    pub shared: bool,
    /// Label for diagnostics (`[stack]`, a path, ...).
    pub name: Option<Arc<str>>,
    /// Personality-defined flags carried with the VMA.
    pub flags: u32,
}

impl Mapping {
    /// Private anonymous memory with `perms`.
    pub fn anonymous(perms: Perms) -> Self {
        Mapping {
            perms,
            backing: Backing::Anonymous,
            shared: false,
            name: None,
            flags: 0,
        }
    }

    /// Sets the diagnostic name.
    pub fn named(mut self, name: impl Into<Arc<str>>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// Pending code-cache invalidations for a consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeChanges {
    /// Nothing changed since the consumer's epoch.
    None,
    /// These `(start, len)` ranges changed.
    Ranges(Vec<(u64, u64)>),
    /// Too much changed to enumerate; discard every cached translation.
    All,
}

#[derive(Debug)]
struct CodeLog {
    /// Epoch of the entry before `entries[0]`.
    base: u64,
    entries: VecDeque<(u64, u64)>,
}

struct Inner {
    va_limit: u64,
    arena: FrameArena,
    table: PageTable,
    vmas: Mutex<VmaMap>,
    code: Mutex<CodeLog>,
    epoch: AtomicU64,
}

/// A guest process's user address space. Clones share the same space.
#[derive(Clone)]
pub struct AddressSpace {
    inner: Arc<Inner>,
}

impl fmt::Debug for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressSpace")
            .field("va_limit", &self.inner.va_limit)
            .field("vmas", &self.inner.vmas.lock().unwrap().len())
            .finish_non_exhaustive()
    }
}

#[inline]
fn fault(addr: u64, access: MemoryAccessKind, kind: MemoryFaultKind) -> GuestMemoryFault {
    GuestMemoryFault {
        address: addr,
        size: 1,
        access,
        kind,
    }
}

/// Validates a page-aligned, non-empty `[start, start + len)` below `limit`.
fn check_range(start: u64, len: u64, limit: u64) -> Result<u64, MmError> {
    if start & PAGE_MASK != 0 || len & PAGE_MASK != 0 {
        return Err(MmError::InvalidArgument("range is not page-aligned"));
    }
    if len == 0 {
        return Err(MmError::InvalidArgument("empty range"));
    }
    let end = start.checked_add(len).ok_or(MmError::OutOfRange)?;
    if end > limit {
        return Err(MmError::OutOfRange);
    }
    Ok(end)
}

impl AddressSpace {
    /// Creates an empty address space.
    pub fn new(config: SpaceConfig) -> Result<Self, MmError> {
        if config.va_limit == 0
            || config.va_limit & PAGE_MASK != 0
            || config.va_limit > 1 << (pagetable::VPN_BITS + 12)
        {
            return Err(MmError::InvalidArgument("va_limit"));
        }
        Ok(AddressSpace {
            inner: Arc::new(Inner {
                va_limit: config.va_limit,
                arena: FrameArena::new(config.arena_bytes, &config.reserved_phys)?,
                table: PageTable::new(),
                vmas: Mutex::new(VmaMap::new()),
                code: Mutex::new(CodeLog {
                    base: 0,
                    entries: VecDeque::new(),
                }),
                epoch: AtomicU64::new(0),
            }),
        })
    }

    /// Exclusive upper bound of user virtual addresses.
    pub fn va_limit(&self) -> u64 {
        self.inner.va_limit
    }

    /// The guest-physical memory holding every frame (for CPU models that
    /// address memory physically).
    pub fn physical_memory(&self) -> &Arc<GuestMemoryMmap> {
        self.inner.arena.memory()
    }

    /// Frames currently populated.
    pub fn resident_pages(&self) -> u64 {
        self.inner.arena.frames_in_use()
    }

    /// Whether two handles refer to the same address space.
    pub fn same_space(&self, other: &AddressSpace) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn vmas(&self) -> MutexGuard<'_, VmaMap> {
        self.inner.vmas.lock().unwrap()
    }

    // ------------------------------------------------------------------
    // Mapping changes
    // ------------------------------------------------------------------

    /// Maps `[start, start + len)` with `mapping`, replacing anything mapped
    /// there (Linux `MAP_FIXED` semantics). Replaced pages are discarded.
    pub fn map(&self, start: u64, len: u64, mapping: Mapping) -> Result<(), MmError> {
        let end = check_range(start, len, self.inner.va_limit)?;
        let mut vmas = self.vmas();
        let replaced = vmas.insert(Vma {
            start,
            end,
            perms: mapping.perms,
            backing: mapping.backing,
            shared: mapping.shared,
            name: mapping.name,
            flags: mapping.flags,
        });
        self.release_pages(start, end);
        if replaced.iter().any(|v| v.perms.contains(Perms::EXEC)) {
            self.log_code_change(start, len);
        }
        vmas.coalesce(start, end);
        Ok(())
    }

    /// Unmaps `[start, start + len)`. Unmapped holes inside the range are not
    /// an error (Linux `munmap`).
    pub fn unmap(&self, start: u64, len: u64) -> Result<(), MmError> {
        let end = check_range(start, len, self.inner.va_limit)?;
        let mut vmas = self.vmas();
        let removed = vmas.remove(start, end);
        self.release_pages(start, end);
        if removed.iter().any(|v| v.perms.contains(Perms::EXEC)) {
            self.log_code_change(start, len);
        }
        Ok(())
    }

    /// Changes the permissions of `[start, start + len)`. Every byte must be
    /// mapped; otherwise nothing changes and the first hole is reported
    /// (Linux `mprotect` fails with `ENOMEM`).
    pub fn protect(&self, start: u64, len: u64, perms: Perms) -> Result<(), MmError> {
        let end = check_range(start, len, self.inner.va_limit)?;
        let mut vmas = self.vmas();
        if let Some(hole) = first_hole(&vmas, start, end) {
            return Err(MmError::NotMapped { addr: hole });
        }
        let mut lost_exec = false;
        vmas.update(start, end, |v| {
            lost_exec |= v.perms.contains(Perms::EXEC) && !perms.contains(Perms::EXEC);
            v.perms = perms;
        });
        self.inner
            .table
            .for_each_populated(start >> 12, end >> 12, |_, slot| {
                let pte = slot.load(Ordering::Acquire);
                slot.store(make_pte(pte & PTE_FRAME, perms), Ordering::Release);
            });
        if lost_exec {
            self.log_code_change(start, len);
        }
        vmas.coalesce(start, end);
        Ok(())
    }

    /// Moves the mapped range `[old, old + len)` to `[new, new + len)`,
    /// keeping page contents without copying, and replacing anything mapped
    /// at the destination (Linux `mremap` with `MREMAP_FIXED`). The source
    /// must be entirely mapped and the ranges must not overlap.
    pub fn remap(&self, old: u64, len: u64, new: u64) -> Result<(), MmError> {
        let old_end = check_range(old, len, self.inner.va_limit)?;
        let new_end = check_range(new, len, self.inner.va_limit)?;
        if old < new_end && new < old_end {
            return Err(MmError::InvalidArgument("overlapping remap"));
        }
        let mut vmas = self.vmas();
        if let Some(hole) = first_hole(&vmas, old, old_end) {
            return Err(MmError::NotMapped { addr: hole });
        }
        let replaced = vmas.remove(new, new_end);
        self.release_pages(new, new_end);
        let pieces = vmas.remove(old, old_end);
        let had_exec = pieces.iter().any(|v| v.perms.contains(Perms::EXEC))
            || replaced.iter().any(|v| v.perms.contains(Perms::EXEC));
        for mut piece in pieces {
            piece.start = piece.start - old + new;
            piece.end = piece.end - old + new;
            vmas.insert(piece);
        }
        let table = &self.inner.table;
        let delta_vpn = (new >> 12).wrapping_sub(old >> 12);
        let mut moved = Vec::new();
        table.for_each_populated(old >> 12, old_end >> 12, |vpn, slot| {
            moved.push((vpn, slot.swap(0, Ordering::AcqRel)));
        });
        for (vpn, pte) in moved {
            table
                .slot(vpn.wrapping_add(delta_vpn))
                .store(pte, Ordering::Release);
        }
        if had_exec {
            self.log_code_change(old, len);
            self.log_code_change(new, len);
        }
        vmas.coalesce(new, new_end);
        Ok(())
    }

    /// Frees every populated frame in `[start, end)`. Caller holds the VMA lock.
    fn release_pages(&self, start: u64, end: u64) {
        let arena = &self.inner.arena;
        self.inner
            .table
            .for_each_populated(start >> 12, end >> 12, |_, slot| {
                let pte = slot.swap(0, Ordering::AcqRel);
                if pte & PTE_VALID != 0 {
                    arena.free(pte & PTE_FRAME);
                }
            });
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// A copy of the VMA containing `addr`.
    pub fn vma_at(&self, addr: u64) -> Option<Vma> {
        self.vmas().find(addr).cloned()
    }

    /// Copies of every VMA in ascending order.
    pub fn vma_snapshot(&self) -> Vec<Vma> {
        self.vmas().iter().cloned().collect()
    }

    /// Copies of the VMAs intersecting `[lo, hi)`.
    pub fn vmas_in(&self, lo: u64, hi: u64) -> Vec<Vma> {
        self.vmas().overlapping(lo, hi).cloned().collect()
    }

    /// Whether no byte of `[start, start + len)` is mapped.
    pub fn is_free(&self, start: u64, len: u64) -> bool {
        match start.checked_add(len) {
            Some(end) => self.vmas().is_free(start, end),
            None => false,
        }
    }

    /// First unmapped byte of `[start, start + len)`, if any.
    pub fn first_unmapped(&self, start: u64, len: u64) -> Option<u64> {
        let end = start.saturating_add(len);
        first_hole(&self.vmas(), start, end)
    }

    /// Highest free `align`-aligned range of `len` bytes within `[low, high)`.
    pub fn find_free_top_down(&self, len: u64, align: u64, low: u64, high: u64) -> Option<u64> {
        self.vmas()
            .find_free_top_down(len, align, low, high.min(self.inner.va_limit))
    }

    /// Lowest free `align`-aligned range of `len` bytes within `[low, high)`.
    pub fn find_free_bottom_up(&self, len: u64, align: u64, low: u64, high: u64) -> Option<u64> {
        self.vmas()
            .find_free_bottom_up(len, align, low, high.min(self.inner.va_limit))
    }

    /// Classifies why an access of kind `access` at `addr` fails (or would
    /// fail), following Linux's signal selection.
    pub fn classify_fault(&self, addr: u64, access: MemoryAccessKind) -> FaultClass {
        let vmas = self.vmas();
        let Some(vma) = vmas.find(addr) else {
            return FaultClass::Unmapped;
        };
        if !vma.perms.allows(access) {
            return FaultClass::Protection;
        }
        if let Backing::Source { source, offset } = &vma.backing {
            let file_offset = offset + ((addr & !PAGE_MASK) - vma.start);
            if file_offset >= source.len().div_ceil(PAGE_SIZE) * PAGE_SIZE {
                return FaultClass::BeyondSource;
            }
        }
        FaultClass::OutOfMemory
    }

    // ------------------------------------------------------------------
    // Translation
    // ------------------------------------------------------------------

    /// Translates `addr` for an access of kind `access`, populating the page
    /// on first touch. Returns the guest-physical address in the arena.
    #[inline]
    pub fn translate(&self, addr: u64, access: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        if addr >= self.inner.va_limit {
            return Err(fault(addr, access, MemoryFaultKind::Unmapped));
        }
        let pte = self.inner.table.get(addr >> 12);
        if pte & PTE_VALID != 0 {
            let need = u64::from(Perms::required(access).bits());
            if pte & need == 0 {
                return Err(fault(addr, access, MemoryFaultKind::Permission));
            }
            if access == MemoryAccessKind::Write && pte & u64::from(Perms::EXEC.bits()) != 0 {
                self.log_code_change(addr & !PAGE_MASK, PAGE_SIZE);
            }
            return Ok((pte & PTE_FRAME) | (addr & PAGE_MASK));
        }
        self.populate(addr, access, false)
    }

    /// Translates ignoring page permissions (loader and debugger access).
    /// The address must still be mapped.
    pub fn translate_raw(
        &self,
        addr: u64,
        access: MemoryAccessKind,
    ) -> Result<u64, GuestMemoryFault> {
        if addr >= self.inner.va_limit {
            return Err(fault(addr, access, MemoryFaultKind::Unmapped));
        }
        let pte = self.inner.table.get(addr >> 12);
        if pte & PTE_VALID != 0 {
            if access == MemoryAccessKind::Write && pte & u64::from(Perms::EXEC.bits()) != 0 {
                self.log_code_change(addr & !PAGE_MASK, PAGE_SIZE);
            }
            return Ok((pte & PTE_FRAME) | (addr & PAGE_MASK));
        }
        self.populate(addr, access, true)
    }

    #[cold]
    fn populate(
        &self,
        addr: u64,
        access: MemoryAccessKind,
        ignore_perms: bool,
    ) -> Result<u64, GuestMemoryFault> {
        let vmas = self.vmas();
        let Some(vma) = vmas.find(addr) else {
            return Err(fault(addr, access, MemoryFaultKind::Unmapped));
        };
        if !ignore_perms && !vma.perms.allows(access) {
            return Err(fault(addr, access, MemoryFaultKind::Permission));
        }
        let page = addr & !PAGE_MASK;
        let slot = self.inner.table.slot(addr >> 12);
        // Populated while this thread waited for the lock.
        let existing = slot.load(Ordering::Acquire);
        if existing & PTE_VALID != 0 {
            return Ok((existing & PTE_FRAME) | (addr & PAGE_MASK));
        }
        let arena = &self.inner.arena;
        let frame = arena
            .alloc_zeroed()
            .map_err(|_| fault(addr, access, MemoryFaultKind::Other))?;
        if let Backing::Source { .. } = vma.backing {
            let mut buf = [0u8; PAGE_SIZE as usize];
            match vma.backing.fill_page(page - vma.start, &mut buf) {
                Ok(true) => arena.write(frame, &buf),
                Ok(false) | Err(_) => {
                    arena.free(frame);
                    return Err(fault(addr, access, MemoryFaultKind::Other));
                }
            }
        }
        slot.store(make_pte(frame, vma.perms), Ordering::Release);
        if access == MemoryAccessKind::Write && vma.perms.contains(Perms::EXEC) {
            self.log_code_change(page, PAGE_SIZE);
        }
        Ok(frame | (addr & PAGE_MASK))
    }

    // ------------------------------------------------------------------
    // Host access
    // ------------------------------------------------------------------

    /// Walks `[addr, addr + len)` page by page, translating each chunk before
    /// any data moves so a fault leaves memory untouched.
    fn chunks(
        &self,
        addr: u64,
        len: usize,
        access: MemoryAccessKind,
        raw: bool,
    ) -> Result<Vec<(u64, usize)>, GuestMemoryFault> {
        let mut out = Vec::with_capacity(len / PAGE_SIZE as usize + 2);
        let mut cur = addr;
        let mut left = len;
        while left > 0 {
            let chunk = ((PAGE_SIZE - (cur & PAGE_MASK)) as usize).min(left);
            let pa = if raw {
                self.translate_raw(cur, access)?
            } else {
                self.translate(cur, access)?
            };
            out.push((pa, chunk));
            left -= chunk;
            cur = cur
                .checked_add(chunk as u64)
                .ok_or_else(|| fault(u64::MAX, access, MemoryFaultKind::Unmapped))?;
        }
        Ok(out)
    }

    fn copy_out(&self, chunks: &[(u64, usize)], buf: &mut [u8]) {
        let mut off = 0;
        for &(pa, n) in chunks {
            self.inner.arena.read(pa, &mut buf[off..off + n]);
            off += n;
        }
    }

    fn copy_in(&self, chunks: &[(u64, usize)], data: &[u8]) {
        let mut off = 0;
        for &(pa, n) in chunks {
            self.inner.arena.write(pa, &data[off..off + n]);
            off += n;
        }
    }

    /// Reads guest memory with user-access permission checks.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), GuestMemoryFault> {
        let chunks = self.chunks(addr, buf.len(), MemoryAccessKind::Read, false)?;
        self.copy_out(&chunks, buf);
        Ok(())
    }

    /// Writes guest memory with user-access permission checks. On a fault no
    /// byte is written.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryFault> {
        let chunks = self.chunks(addr, data.len(), MemoryAccessKind::Write, false)?;
        self.copy_in(&chunks, data);
        Ok(())
    }

    /// Reads mapped memory ignoring permissions.
    pub fn read_raw(&self, addr: u64, buf: &mut [u8]) -> Result<(), GuestMemoryFault> {
        let chunks = self.chunks(addr, buf.len(), MemoryAccessKind::Read, true)?;
        self.copy_out(&chunks, buf);
        Ok(())
    }

    /// Writes mapped memory ignoring permissions.
    pub fn write_raw(&self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryFault> {
        let chunks = self.chunks(addr, data.len(), MemoryAccessKind::Write, true)?;
        self.copy_in(&chunks, data);
        Ok(())
    }

    /// Reads a NUL-terminated string of at most `max` bytes (excluding the
    /// NUL) with user-access checks. Returns `Ok(None)` when no NUL occurs
    /// within `max + 1` bytes.
    pub fn read_cstr(&self, addr: u64, max: usize) -> Result<Option<Vec<u8>>, GuestMemoryFault> {
        let mut out = Vec::new();
        let mut cur = addr;
        loop {
            let chunk = (PAGE_SIZE - (cur & PAGE_MASK)) as usize;
            let mut buf = vec![0u8; chunk];
            self.read(cur, &mut buf)?;
            if let Some(nul) = buf.iter().position(|&b| b == 0) {
                out.extend_from_slice(&buf[..nul]);
                return Ok((out.len() <= max).then_some(out));
            }
            out.extend_from_slice(&buf);
            if out.len() > max {
                return Ok(None);
            }
            cur = cur.checked_add(chunk as u64).ok_or_else(|| {
                fault(u64::MAX, MemoryAccessKind::Read, MemoryFaultKind::Unmapped)
            })?;
        }
    }

    /// Loads bytes at a guest-physical address from [`AddressSpace::translate`].
    /// The range must not cross the translated page.
    #[inline]
    pub fn load_phys(&self, pa: u64, buf: &mut [u8]) {
        self.inner.arena.read(pa, buf);
    }

    /// Stores bytes at a guest-physical address from [`AddressSpace::translate`].
    /// The range must not cross the translated page.
    #[inline]
    pub fn store_phys(&self, pa: u64, data: &[u8]) {
        self.inner.arena.write(pa, data);
    }

    // ------------------------------------------------------------------
    // Code invalidation
    // ------------------------------------------------------------------

    fn log_code_change(&self, start: u64, len: u64) {
        let mut log = self.inner.code.lock().unwrap();
        if log.entries.len() == CODE_LOG_CAPACITY {
            log.entries.pop_front();
            log.base += 1;
        }
        log.entries.push_back((start, len));
        self.inner
            .epoch
            .store(log.base + log.entries.len() as u64, Ordering::Release);
    }

    /// The current code-change epoch.
    #[inline]
    pub fn code_epoch(&self) -> u64 {
        self.inner.epoch.load(Ordering::Acquire)
    }

    /// Code changes after `epoch`, and the epoch they bring a consumer to.
    pub fn code_changes_since(&self, epoch: u64) -> (CodeChanges, u64) {
        let log = self.inner.code.lock().unwrap();
        let now = log.base + log.entries.len() as u64;
        if epoch >= now {
            return (CodeChanges::None, now);
        }
        if epoch < log.base {
            return (CodeChanges::All, now);
        }
        let skip = (epoch - log.base) as usize;
        (
            CodeChanges::Ranges(log.entries.iter().skip(skip).copied().collect()),
            now,
        )
    }
}

fn first_hole(vmas: &VmaMap, start: u64, end: u64) -> Option<u64> {
    let mut cursor = start;
    for v in vmas.overlapping(start, end) {
        if v.start > cursor {
            return Some(cursor);
        }
        cursor = v.end;
        if cursor >= end {
            return None;
        }
    }
    (cursor < end).then_some(cursor)
}

impl FlatTranslation for AddressSpace {
    #[inline]
    fn translate(&self, linear: u64, access: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        AddressSpace::translate(self, linear, access)
    }
}
