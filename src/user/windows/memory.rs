//! Guest memory: typed access for built-in DLL code, and the Windows
//! virtual-memory manager.
//!
//! Built-in (HLE) code reads and writes guest memory with the thread's
//! user-mode permissions through [`Mem`]; a fault becomes
//! [`MemFault`]. The dispatcher classifies it at the call site as
//! `STATUS_ACCESS_VIOLATION`, a one-shot `STATUS_GUARD_PAGE_VIOLATION`, or
//! `STATUS_STACK_OVERFLOW` for the fixed stack guard.
//!
//! [`VirtualMemory`] owns every mapping of the address space and keeps the
//! state `VirtualQuery` reports: allocations are reserved at 64 KiB
//! granularity, and each 4 KiB page is free, reserved, or committed with a
//! `PAGE_*` protection. Committed pages are mapped in the [`AddressSpace`]
//! with the protection's access rights; reserved pages are not mapped, so
//! touching them faults, as on Windows.
//!
//! The contract is the Microsoft `VirtualAlloc`, `VirtualFree`,
//! `VirtualProtect`, `VirtualQuery`, and memory-protection documentation:
//! <https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc>,
//! <https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualfree>,
//! <https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect>,
//! <https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualquery>,
//! <https://learn.microsoft.com/windows/win32/memory/memory-protection-constants>.
//! State runs use `O(r)` metadata for `r` protection/state boundaries rather
//! than `O(size / 4096)` metadata for a reservation. Guest threads share one
//! scheduler host thread, as required by [`AddressSpace`]'s mapping contract.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use vm_memory::{Address, GuestMemory};

use crate::error::MemoryAccessKind;
use crate::user::mm::{AddressSpace, Mapping, MmError, PAGE_SIZE, Perms};

mod allocation;
mod call_targets;
mod code_bitmap;
mod data_section;
mod protection;
pub(crate) use data_section::KernelDataView;
mod extended;
mod file_section;
pub(crate) use file_section::FileViewOptions;
mod mapped_filename;
mod prefetch;
mod region;
pub use region::RegionInfo;
mod scheduler;
mod section;
#[cfg(test)]
mod section_extension_tests;
#[cfg(test)]
mod section_padding_tests;
#[cfg(test)]
mod section_tests;
mod shared_section;
mod usage;
pub use usage::MemoryUsage;
#[cfg(test)]
mod usage_tests;
pub use extended::AddressRequirements;
pub(crate) use extended::PrivateAttributes;
pub(crate) use scheduler::SchedulerView;
pub(crate) use shared_section::SharedViewOwner;

/// `SYSTEM_INFO.dwAllocationGranularity`.
pub const ALLOCATION_GRANULARITY: u64 = 0x1_0000;

/// A guest access that faulted in built-in code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemFault {
    /// First inaccessible byte.
    pub addr: u64,
    /// Whether the access was a write.
    pub write: bool,
}

/// Typed guest-memory access with user-mode permissions.
pub trait Mem {
    /// Reads `buf.len()` bytes.
    fn rd(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemFault>;
    /// Writes `data`.
    fn wr(&self, addr: u64, data: &[u8]) -> Result<(), MemFault>;

    /// Reads a byte.
    fn u8(&self, addr: u64) -> Result<u8, MemFault> {
        let mut b = [0u8; 1];
        self.rd(addr, &mut b)?;
        Ok(b[0])
    }
    /// Reads a little-endian `u16`.
    fn u16(&self, addr: u64) -> Result<u16, MemFault> {
        let mut b = [0u8; 2];
        self.rd(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    /// Reads a little-endian `u32`.
    fn u32(&self, addr: u64) -> Result<u32, MemFault> {
        let mut b = [0u8; 4];
        self.rd(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    /// Reads a little-endian `u64`.
    fn u64(&self, addr: u64) -> Result<u64, MemFault> {
        let mut b = [0u8; 8];
        self.rd(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    /// Reads a pointer of `size` bytes (4 or 8).
    fn ptr(&self, addr: u64, size: u64) -> Result<u64, MemFault> {
        if size == 4 {
            self.u32(addr).map(u64::from)
        } else {
            self.u64(addr)
        }
    }
    /// Writes a byte.
    fn w8(&self, addr: u64, v: u8) -> Result<(), MemFault> {
        self.wr(addr, &[v])
    }
    /// Writes a little-endian `u16`.
    fn w16(&self, addr: u64, v: u16) -> Result<(), MemFault> {
        self.wr(addr, &v.to_le_bytes())
    }
    /// Writes a little-endian `u32`.
    fn w32(&self, addr: u64, v: u32) -> Result<(), MemFault> {
        self.wr(addr, &v.to_le_bytes())
    }
    /// Writes a little-endian `u64`.
    fn w64(&self, addr: u64, v: u64) -> Result<(), MemFault> {
        self.wr(addr, &v.to_le_bytes())
    }
    /// Writes a pointer of `size` bytes (4 or 8).
    fn wptr(&self, addr: u64, size: u64, v: u64) -> Result<(), MemFault> {
        if size == 4 {
            self.w32(addr, v as u32)
        } else {
            self.w64(addr, v)
        }
    }
    /// Reads `len` bytes.
    fn bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemFault> {
        let mut v = vec![0u8; len];
        self.rd(addr, &mut v)?;
        Ok(v)
    }
    /// Reads a NUL-terminated byte string (without the NUL), scanning at
    /// most `max` bytes; a string that reaches `max` is returned truncated.
    fn cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>, MemFault> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 64];
        let mut at = addr;
        while out.len() < max {
            // Read up to the end of the page so a string ending just
            // before an inaccessible page does not fault.
            let room = (PAGE_SIZE - (at % PAGE_SIZE)) as usize;
            let n = room.min(chunk.len()).min(max - out.len());
            self.rd(at, &mut chunk[..n])?;
            if let Some(i) = chunk[..n].iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..i]);
                return Ok(out);
            }
            out.extend_from_slice(&chunk[..n]);
            if out.len() == max {
                break;
            }
            at = at.checked_add(n as u64).ok_or(MemFault {
                addr: u64::MAX,
                write: false,
            })?;
        }
        Ok(out)
    }
    /// Reads a NUL-terminated UTF-16 string (without the NUL) of at most
    /// `max` units.
    fn wstr(&self, addr: u64, max: usize) -> Result<Vec<u16>, MemFault> {
        let mut out = Vec::new();
        let mut at = addr;
        while out.len() < max {
            let c = self.u16(at)?;
            if c == 0 {
                break;
            }
            out.push(c);
            if out.len() == max {
                break;
            }
            at = at.checked_add(2).ok_or(MemFault {
                addr: u64::MAX,
                write: false,
            })?;
        }
        Ok(out)
    }
    /// Reads `len` UTF-16 units.
    fn wunits(&self, addr: u64, len: usize) -> Result<Vec<u16>, MemFault> {
        let bytes = len.checked_mul(2).ok_or(MemFault { addr, write: false })?;
        let raw = self.bytes(addr, bytes)?;
        Ok(raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect())
    }
    /// Writes `s` followed by a NUL.
    fn put_cstr(&self, addr: u64, s: &[u8]) -> Result<(), MemFault> {
        let mut v = s.to_vec();
        v.push(0);
        self.wr(addr, &v)
    }
    /// Writes UTF-16 `s` followed by a NUL unit.
    fn put_wstr(&self, addr: u64, s: &[u16]) -> Result<(), MemFault> {
        let mut v: Vec<u8> = s.iter().flat_map(|c| c.to_le_bytes()).collect();
        v.extend_from_slice(&[0, 0]);
        self.wr(addr, &v)
    }
    /// Writes UTF-16 units without a terminator.
    fn put_wunits(&self, addr: u64, s: &[u16]) -> Result<(), MemFault> {
        let v: Vec<u8> = s.iter().flat_map(|c| c.to_le_bytes()).collect();
        self.wr(addr, &v)
    }
}

impl Mem for AddressSpace {
    fn rd(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemFault> {
        if buf.is_empty() {
            return Ok(());
        }
        self.read(addr, buf).map_err(|f| MemFault {
            addr: f.address,
            write: false,
        })
    }

    fn wr(&self, addr: u64, data: &[u8]) -> Result<(), MemFault> {
        if data.is_empty() {
            return Ok(());
        }
        self.write(addr, data).map_err(|f| MemFault {
            addr: f.address,
            write: true,
        })
    }
}

/// `PAGE_*` protection constants.
pub mod prot {
    /// `PAGE_NOACCESS`.
    pub const NOACCESS: u32 = 0x01;
    /// `PAGE_READONLY`.
    pub const READONLY: u32 = 0x02;
    /// `PAGE_READWRITE`.
    pub const READWRITE: u32 = 0x04;
    /// `PAGE_WRITECOPY`.
    pub const WRITECOPY: u32 = 0x08;
    /// `PAGE_EXECUTE`.
    pub const EXECUTE: u32 = 0x10;
    /// `PAGE_EXECUTE_READ`.
    pub const EXECUTE_READ: u32 = 0x20;
    /// `PAGE_EXECUTE_READWRITE`.
    pub const EXECUTE_READWRITE: u32 = 0x40;
    /// `PAGE_EXECUTE_WRITECOPY`.
    pub const EXECUTE_WRITECOPY: u32 = 0x80;
    /// `PAGE_GUARD`.
    pub const GUARD: u32 = 0x100;
    /// `PAGE_NOCACHE`.
    pub const NOCACHE: u32 = 0x200;
    /// `PAGE_WRITECOMBINE`.
    pub const WRITECOMBINE: u32 = 0x400;
    /// Allocation-time invalid CFG targets; not reported by VirtualQuery.
    pub const TARGETS_INVALID: u32 = 0x4000_0000;
    /// Protection-time preservation of CFG targets (same request bit).
    pub const TARGETS_NO_UPDATE: u32 = TARGETS_INVALID;
}

/// `MEM_*` state, type, and allocation-type constants.
pub mod mem {
    /// `MEM_COMMIT`.
    pub const COMMIT: u32 = 0x1000;
    /// `MEM_RESERVE`.
    pub const RESERVE: u32 = 0x2000;
    /// `MEM_DECOMMIT`.
    pub const DECOMMIT: u32 = 0x4000;
    /// `MEM_RELEASE`.
    pub const RELEASE: u32 = 0x8000;
    /// `MEM_FREE`.
    pub const FREE: u32 = 0x1_0000;
    /// `MEM_PRIVATE`.
    pub const PRIVATE: u32 = 0x2_0000;
    /// `MEM_MAPPED`.
    pub const MAPPED: u32 = 0x4_0000;
    /// `MEM_RESET`.
    pub const RESET: u32 = 0x8_0000;
    /// `MEM_TOP_DOWN`.
    pub const TOP_DOWN: u32 = 0x10_0000;
    /// `MEM_WRITE_WATCH`.
    pub const WRITE_WATCH: u32 = 0x20_0000;
    /// `MEM_PHYSICAL`.
    pub const PHYSICAL: u32 = 0x40_0000;
    /// `MEM_RESET_UNDO`.
    pub const RESET_UNDO: u32 = 0x100_0000;
    /// `MEM_LARGE_PAGES`.
    pub const LARGE_PAGES: u32 = 0x2000_0000;
    /// `MEM_IMAGE`.
    pub const IMAGE: u32 = 0x100_0000;
}

/// Whether `p` is a valid `PAGE_*` base and modifier combination.
/// Operation-specific CFG requests are validated separately; section creation
/// must not inherit private-allocation modifiers. Enclave flags are unsupported.
pub fn valid_protection(p: u32) -> bool {
    let base = p & 0xFF;
    if base.count_ones() != 1 || p & !0x7FF != 0 {
        return false;
    }
    let modifiers = p & !0xFF;
    if base == prot::NOACCESS && modifiers != 0 {
        return false;
    }
    if p & prot::NOCACHE != 0 && p & (prot::GUARD | prot::WRITECOMBINE) != 0 {
        return false;
    }
    if p & prot::WRITECOMBINE != 0 && p & (prot::GUARD | prot::NOCACHE) != 0 {
        return false;
    }
    true
}

/// The documented access rights a protection grants (modifiers ignored;
/// a guard page is mapped inaccessible separately).
pub fn perms_of(p: u32) -> Perms {
    match p & 0xFF {
        prot::READONLY => Perms::READ,
        prot::READWRITE | prot::WRITECOPY => Perms::READ | Perms::WRITE,
        prot::EXECUTE => Perms::EXEC,
        prot::EXECUTE_READ => Perms::READ | Perms::EXEC,
        prot::EXECUTE_READWRITE | prot::EXECUTE_WRITECOPY => {
            Perms::READ | Perms::WRITE | Perms::EXEC
        }
        _ => Perms::empty(),
    }
}

/// The kind of an allocation (`MEMORY_BASIC_INFORMATION.Type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocKind {
    /// `MEM_PRIVATE`.
    Private,
    /// `MEM_IMAGE`.
    Image,
    /// `MEM_MAPPED`.
    Mapped,
}

impl AllocKind {
    /// The `MEM_*` type value.
    pub fn value(self) -> u32 {
        match self {
            AllocKind::Private => mem::PRIVATE,
            AllocKind::Image => mem::IMAGE,
            AllocKind::Mapped => mem::MAPPED,
        }
    }
}

/// The state of one page of an allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageState {
    /// Committed (otherwise reserved).
    pub committed: bool,
    /// The `PAGE_*` protection (with `PAGE_GUARD` while the guard is armed).
    pub protect: u32,
    /// The protection reported for a committed page when it differs from
    /// the mapping (a trap page of a built-in DLL reports
    /// `PAGE_EXECUTE_READ` while it is mapped read-only so fetches trap).
    pub reported: Option<u32>,
}

const RESERVED: PageState = PageState {
    committed: false,
    protect: 0,
    reported: None,
};

fn effective_perms(protect: u32) -> Perms {
    if protect & prot::GUARD != 0 {
        Perms::empty()
    } else {
        perms_of(protect)
    }
}

/// One reservation (`VirtualAlloc` with `MEM_RESERVE`, a mapped image, a
/// mapped view).
#[derive(Clone, Debug)]
pub struct Allocation {
    /// `AllocationBase`.
    pub base: u64,
    /// Size in bytes (a multiple of the page size).
    pub size: u64,
    /// `AllocationProtect`.
    pub protect: u32,
    /// `Type`.
    pub kind: AllocKind,
    /// State runs, keyed by the first page index of each run. Index zero
    /// is always present; a run ends at the next key or at `size / PAGE_SIZE`.
    pub pages: BTreeMap<u64, PageState>,
    /// Diagnostic name (module path, `[stack]`, ...).
    pub name: Option<Arc<str>>,
}

impl Allocation {
    fn state(&self, page: u64) -> PageState {
        *self
            .pages
            .range(..=page)
            .next_back()
            .expect("initial state run")
            .1
    }

    /// Copies runs intersecting the half-open page-index interval.
    fn runs(&self, first: u64, end: u64) -> Vec<(u64, u64, PageState)> {
        let mut out = Vec::new();
        let mut at = first;
        let mut state = self.state(first);
        for (&next, &following) in self.pages.range((
            std::ops::Bound::Excluded(first),
            std::ops::Bound::Excluded(end),
        )) {
            out.push((at, next, state));
            at = next;
            state = following;
        }
        out.push((at, end, state));
        out
    }

    /// Replaces a range then coalesces equal neighbours. `O(k log r)` for
    /// `k` removed boundaries in `r` state runs; no loop over reserved pages.
    fn set_state(&mut self, first: u64, end: u64, state: PageState) {
        let after = (end < self.size / PAGE_SIZE).then(|| self.state(end));
        let keys: Vec<u64> = self.pages.range(first..end).map(|(&k, _)| k).collect();
        for k in keys {
            self.pages.remove(&k);
        }
        self.pages.insert(first, state);
        if let Some(after) = after {
            self.pages.insert(end, after);
        }
        for key in [first, end] {
            if let Some((&previous, &before)) = self.pages.range(..key).next_back()
                && let Some(&current) = self.pages.get(&key)
                && before == current
            {
                debug_assert!(previous < key);
                self.pages.remove(&key);
            }
        }
    }
}

/// Why a virtual-memory operation failed, as an `NTSTATUS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmError {
    /// `STATUS_INVALID_PARAMETER`.
    InvalidParameter,
    /// `STATUS_INVALID_PAGE_PROTECTION`.
    InvalidProtection,
    /// `STATUS_SECTION_PROTECTION`: requested view permissions exceed the section.
    SectionProtection,
    /// `STATUS_INVALID_PARAMETER_4`: unsupported NtProtectVirtualMemory modifiers.
    InvalidParameter4,
    /// `STATUS_CONFLICTING_ADDRESSES`: the range is not free.
    Conflicting,
    /// `STATUS_NO_MEMORY`: no free range of the size exists.
    NoMemory,
    /// `STATUS_COMMITMENT_LIMIT`: the committed backing budget is exhausted.
    CommitmentLimit,
    /// A fixed mapped section cannot be freed as private memory.
    CannotDeleteSection,
    /// Existing fixed section commitment cannot be repeated as private memory.
    AlreadyCommitted,
    /// `STATUS_MEMORY_NOT_ALLOCATED`: the address is not in an allocation.
    NotAllocated,
    /// `STATUS_FREE_VM_NOT_AT_BASE`: a release not at the allocation base.
    NotAtBase,
    /// `STATUS_UNABLE_TO_FREE_VM`: a release whose size is not zero.
    UnableToFree,
    /// `STATUS_NOT_COMMITTED`: part of the range is reserved only.
    NotCommitted,
    /// `STATUS_INVALID_ADDRESS`: the range spans allocations.
    InvalidAddress,
    /// `STATUS_ACCESS_VIOLATION`: target bitmap storage is not committed.
    CallTargetStorage,
    /// `STATUS_NOT_SUPPORTED`: a known facility is not implemented.
    NotSupported,
}

impl VmError {
    /// The `NTSTATUS` value.
    pub fn status(self) -> u32 {
        use super::nt::status::*;
        match self {
            VmError::InvalidParameter => STATUS_INVALID_PARAMETER,
            VmError::InvalidProtection => STATUS_INVALID_PAGE_PROTECTION,
            VmError::SectionProtection => 0xC000_004E,
            VmError::InvalidParameter4 => STATUS_INVALID_PARAMETER_4,
            VmError::Conflicting => STATUS_CONFLICTING_ADDRESSES,
            VmError::NoMemory => STATUS_NO_MEMORY,
            VmError::CommitmentLimit => STATUS_COMMITMENT_LIMIT,
            VmError::CannotDeleteSection => STATUS_UNABLE_TO_DELETE_SECTION,
            VmError::AlreadyCommitted => STATUS_ALREADY_COMMITTED,
            VmError::NotAllocated => STATUS_MEMORY_NOT_ALLOCATED,
            VmError::NotAtBase => STATUS_FREE_VM_NOT_AT_BASE,
            VmError::UnableToFree => STATUS_UNABLE_TO_FREE_VM,
            VmError::NotCommitted => STATUS_NOT_COMMITTED,
            VmError::InvalidAddress => STATUS_INVALID_ADDRESS,
            VmError::CallTargetStorage => STATUS_ACCESS_VIOLATION,
            VmError::NotSupported => STATUS_NOT_SUPPORTED,
        }
    }
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?} (NTSTATUS {:#010x})", self.status())
    }
}

impl std::error::Error for VmError {}

fn mm(e: MmError) -> VmError {
    match e {
        MmError::OutOfMemory => VmError::NoMemory,
        MmError::OutOfRange => VmError::Conflicting,
        MmError::NotMapped { .. } => VmError::NotCommitted,
        MmError::InvalidArgument(_) => VmError::InvalidParameter,
    }
}

/// Converts a nonempty byte range to pages without host arithmetic wrap:
/// `first = floor(start / 4096) * 4096`,
/// `end = ceil((start + len) / 4096) * 4096` (all quantities in bytes).
pub fn page_range(start: u64, len: u64) -> Result<(u64, u64), VmError> {
    if len == 0 {
        return Err(VmError::InvalidParameter);
    }
    let first = start & !(PAGE_SIZE - 1);
    let end = start
        .checked_add(len)
        .and_then(|e| e.checked_add(PAGE_SIZE - 1))
        .ok_or(VmError::InvalidParameter)?
        & !(PAGE_SIZE - 1);
    Ok((first, end))
}

/// The Windows view of the address space.
pub struct VirtualMemory {
    space: AddressSpace,
    allocs: BTreeMap<u64, Allocation>,
    call_targets: call_targets::CallTargets,
    mapped_filenames: BTreeMap<u64, super::mapped_filename::Filename>,
    allocation_nodes: BTreeMap<u64, u32>,
    nls_views: BTreeSet<u64>,
    pagefile_views: BTreeSet<u64>,
    section_views: BTreeMap<u64, section::SectionView>,
    data_views: BTreeMap<u64, data_section::DataView>,
    code_bitmap: Option<code_bitmap::CodeBitmap>,
    file_views: BTreeMap<u64, file_section::FileView>,
    shared_views: shared_section::SharedViews,
    section_low_placements: BTreeMap<usize, section::LowPlacement>,
    default_low_image_placement: Option<u64>,
    /// Backing bytes promised for committed pages. No guest paging file
    /// is modeled; the usable frame arena bounds commitment.
    committed: u64,
    /// Highest successfully published commitment since this manager was created.
    peak_committed: u64,
    commit_limit: u64,
    /// Lowest address an allocation may use.
    low: u64,
    /// Exclusive upper bound of user addresses.
    high: u64,
}

impl VirtualMemory {
    /// A manager over an empty `space` for user addresses `[low, high)`.
    /// With no excluded physical frames, the arena is the commit budget.
    /// Use [`Self::new_with_commit_limit`] when physical frames are reserved.
    pub fn new(space: AddressSpace, low: u64, high: u64) -> Self {
        let high = high.min(space.va_limit()) & !(PAGE_SIZE - 1);
        let low = low.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        // FrameArena exposes a single region [0, capacity) (arena.rs).
        let commit_limit = space
            .physical_memory()
            .last_addr()
            .raw_value()
            .saturating_add(1);
        VirtualMemory {
            space,
            allocs: BTreeMap::new(),
            call_targets: call_targets::CallTargets::default(),
            mapped_filenames: BTreeMap::new(),
            allocation_nodes: BTreeMap::new(),
            nls_views: BTreeSet::new(),
            pagefile_views: BTreeSet::new(),
            section_views: BTreeMap::new(),
            data_views: BTreeMap::new(),
            code_bitmap: None,
            file_views: BTreeMap::new(),
            shared_views: shared_section::SharedViews::default(),
            section_low_placements: BTreeMap::new(),
            default_low_image_placement: None,
            committed: 0,
            peak_committed: 0,
            commit_limit,
            low,
            high,
        }
    }

    /// Creates a manager with an explicitly bounded usable backing budget.
    /// The caller excludes physical frames unavailable to guest pages.
    /// The budget is rounded down to pages and clamped to arena capacity.
    pub fn new_with_commit_limit(space: AddressSpace, low: u64, high: u64, limit: u64) -> Self {
        let mut vm = Self::new(space, low, high);
        vm.commit_limit = vm.commit_limit.min(limit & !(PAGE_SIZE - 1));
        vm
    }

    /// Bytes currently promised for committed guest pages (resident or not).
    pub fn committed_bytes(&self) -> u64 {
        self.committed
    }

    /// Maximum backing bytes the personality can promise without a paging file.
    pub fn commit_limit(&self) -> u64 {
        self.commit_limit
    }

    /// The address space.
    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    /// Exclusive upper bound of user addresses.
    pub fn high(&self) -> u64 {
        self.high
    }

    /// Lowest user address.
    pub fn low(&self) -> u64 {
        self.low
    }

    /// The allocation containing `addr`.
    pub fn allocation(&self, addr: u64) -> Option<&Allocation> {
        let (_, a) = self.allocs.range(..=addr).next_back()?;
        (addr < a.base + a.size).then_some(a)
    }

    fn allocation_mut(&mut self, addr: u64) -> Option<&mut Allocation> {
        let (_, a) = self.allocs.range_mut(..=addr).next_back()?;
        (addr < a.base + a.size).then_some(a)
    }

    /// Whether `[start, start + len)` overlaps no allocation.
    pub fn is_free(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        if len == 0 || start < self.low || end > self.high {
            return false;
        }
        if let Some((_, a)) = self.allocs.range(..end).next_back()
            && a.base + a.size > start
        {
            return false;
        }
        self.space.is_free(start, len)
    }

    /// The lowest (or, with `top_down`, highest) free range of `len` bytes
    /// aligned to `align` within `[lo, hi)`.
    pub fn find_free(&self, len: u64, align: u64, lo: u64, hi: u64, top_down: bool) -> Option<u64> {
        let lo = lo.max(self.low);
        let hi = hi.min(self.high);
        if len == 0 || !align.is_power_of_two() || hi <= lo || len > hi - lo {
            return None;
        }
        // Include mappings placed directly in AddressSpace, so an untracked
        // mapping can never be replaced by a Windows allocation. Committed
        // portions duplicate reservations; the scan handles overlapping runs.
        let mut occupied: Vec<(u64, u64)> = self
            .allocs
            .values()
            .filter(|a| a.base < hi && a.base + a.size > lo)
            .map(|a| (a.base, a.base + a.size))
            .collect();
        occupied.extend(
            self.space
                .vmas_in(lo, hi)
                .into_iter()
                .map(|v| (v.start, v.end)),
        );
        occupied.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(occupied.len());
        for (base, end) in occupied {
            if let Some(last) = merged.last_mut()
                && base <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((base, end));
            }
        }
        let align_up = |v: u64| v.checked_add(align - 1).map(|x| x & !(align - 1));
        if top_down {
            // Walk the gaps below `hi` from the top: each allocation (in
            // descending order) bounds the gap above it.
            let fits = |floor: u64, ceiling: u64| -> Option<u64> {
                let cand = ceiling.checked_sub(len)? & !(align - 1);
                (cand >= floor.max(lo)).then_some(cand)
            };
            let mut ceiling = hi;
            for &(base, end) in merged.iter().rev() {
                if end < ceiling
                    && let Some(c) = fits(end, ceiling)
                {
                    return Some(c);
                }
                ceiling = ceiling.min(base);
                if ceiling <= lo {
                    return None;
                }
            }
            return fits(lo, ceiling);
        }
        let mut cand = align_up(lo)?;
        for &(base, end) in &merged {
            if end <= cand {
                continue;
            }
            if cand.checked_add(len)? <= base {
                break;
            }
            cand = align_up(end)?;
        }
        (cand.checked_add(len)? <= hi).then_some(cand)
    }

    /// The `VirtualFree` / `NtFreeVirtualMemory` state operation. A release
    /// requires size zero and the original reservation base. The returned
    /// range reports the full released allocation or rounded decommit range.
    pub fn free(&mut self, base: u64, size: u64, free_type: u32) -> Result<(u64, u64), VmError> {
        if (self.is_nls_view(base)
            || self.section_view(base).is_some()
            || self.is_data_view(base)
            || self.is_file_view(base)
            || self.is_shared_view(base))
            && matches!(free_type, mem::RELEASE | mem::DECOMMIT)
        {
            return Err(VmError::CannotDeleteSection);
        }
        match free_type {
            mem::RELEASE => {
                if size != 0 {
                    return Err(VmError::UnableToFree);
                }
                self.release(base).map(|len| (base, len))
            }
            mem::DECOMMIT => self.decommit(base, size),
            _ => Err(VmError::InvalidParameter),
        }
    }

    /// Decommits `[start, start + len)` (page-rounded outward); a length of
    /// zero decommits the entire allocation and requires its exact base.
    pub fn decommit(&mut self, start: u64, len: u64) -> Result<(u64, u64), VmError> {
        let first = start & !(PAGE_SIZE - 1);
        let a = self.allocation(first).ok_or(VmError::NotAllocated)?;
        if self.nls_views.contains(&a.base) {
            return Err(VmError::CannotDeleteSection);
        }
        if self.section_views.contains_key(&a.base)
            || self.data_views.contains_key(&a.base)
            || self.is_code_bitmap(a.base)
            || self.is_shared_view(a.base)
            || self.is_file_view(a.base)
        {
            return Err(VmError::CannotDeleteSection);
        }

        let end = if len == 0 {
            if start != a.base {
                return Err(VmError::NotAtBase);
            }
            a.base + a.size
        } else {
            page_range(start, len)?.1
        };
        if end > a.base + a.size {
            return Err(VmError::InvalidAddress);
        }
        let base = a.base;
        let returned: u64 = a
            .runs((first - base) / PAGE_SIZE, (end - base) / PAGE_SIZE)
            .iter()
            .filter(|(_, _, p)| p.committed)
            .map(|(lo, hi, _)| (hi - lo) * PAGE_SIZE)
            .sum();
        // Unmapping a valid range tolerates holes and cannot fail after
        // range validation. One unmap also invalidates executable caches.
        self.space.unmap(first, end - first).map_err(mm)?;
        self.allocs
            .get_mut(&base)
            .expect("validated allocation")
            .set_state(
                (first - base) / PAGE_SIZE,
                (end - base) / PAGE_SIZE,
                RESERVED,
            );
        self.committed -= returned;
        Ok((first, end - first))
    }

    /// Marks an initialized NLS view as a fixed read-only mapped section.
    /// Guest protect/commit/free paths cannot replace its section semantics.
    pub(crate) fn seal_nls_view(&mut self, base: u64) -> Result<(), VmError> {
        let a = self.allocation(base).ok_or(VmError::NotAllocated)?;
        if a.base != base
            || a.kind != AllocKind::Mapped
            || a.protect != prot::READONLY
            || a.runs(0, a.size / PAGE_SIZE)
                .iter()
                .any(|(_, _, p)| !p.committed || p.protect != prot::READONLY)
        {
            return Err(VmError::InvalidParameter);
        }
        self.nls_views.insert(base);
        Ok(())
    }
    pub(crate) fn is_nls_view(&self, address: u64) -> bool {
        self.allocation(address)
            .is_some_and(|a| self.nls_views.contains(&a.base))
    }
    #[cfg(test)]
    pub(crate) fn nls_view_count(&self) -> usize {
        self.nls_views.len()
    }

    /// Releases the whole allocation whose base is `base`.
    pub fn release(&mut self, base: u64) -> Result<u64, VmError> {
        let a = match self.allocation(base) {
            Some(a) if a.base == base => a,
            Some(_) => return Err(VmError::NotAtBase),
            None => return Err(VmError::NotAllocated),
        };
        let size = a.size;
        let returned: u64 = self.released_shared_charge(base).unwrap_or_else(|| {
            a.runs(0, size / PAGE_SIZE)
                .iter()
                .filter(|(_, _, p)| p.committed)
                .map(|(lo, hi, _)| (hi - lo) * PAGE_SIZE)
                .sum()
        });
        self.space.unmap(base, size).map_err(mm)?;
        self.allocs.remove(&base);
        self.call_targets.release(base);
        if let Some(bitmap) = self
            .code_bitmap
            .as_mut()
            .filter(|bitmap| bitmap.base == base)
        {
            bitmap.retired = true;
        }
        self.mapped_filenames.remove(&base);
        self.allocation_nodes.remove(&base);
        self.nls_views.remove(&base);
        self.pagefile_views.remove(&base);
        self.section_views.remove(&base);
        self.data_views.remove(&base);
        self.file_views.remove(&base);
        self.forget_shared_view(base);
        self.committed -= returned;
        Ok(size)
    }

    /// Sets the protection `VirtualQuery` reports for committed pages
    /// `[start, start + len)` without changing their mapping.
    pub fn set_reported(&mut self, start: u64, len: u64, protect: u32) {
        if !valid_protection(protect) {
            return;
        }
        if let Ok((first, end)) = page_range(start, len)
            && let Some(a) = self.allocation_mut(first)
        {
            let i0 = (first - a.base) / PAGE_SIZE;
            let i1 = (end.min(a.base + a.size) - a.base) / PAGE_SIZE;
            for (lo, hi, mut p) in a.runs(i0, i1) {
                if p.committed {
                    p.reported = Some(protect);
                    a.set_state(lo, hi, p);
                }
            }
        }
    }

    /// If `addr` lies in an armed guard page, disarms it (the page takes
    /// its protection without `PAGE_GUARD`) and returns true: the access
    /// raises `STATUS_GUARD_PAGE_VIOLATION` once.
    pub fn take_guard(&mut self, addr: u64) -> bool {
        let page = addr & !(PAGE_SIZE - 1);
        let Some(a) = self.allocation(page) else {
            return false;
        };
        let base = a.base;
        let i = (page - base) / PAGE_SIZE;
        let mut p = a.state(i);
        if !p.committed || p.protect & prot::GUARD == 0 {
            return false;
        }
        p.protect &= !prot::GUARD;
        if self
            .space
            .protect(page, PAGE_SIZE, effective_perms(p.protect))
            .is_err()
        {
            return false;
        }
        if let Some(reported) = p.reported.as_mut() {
            *reported &= !prot::GUARD;
        }
        self.allocs
            .get_mut(&base)
            .expect("validated allocation")
            .set_state(i, i + 1, p);
        true
    }

    /// Writes `data` at `addr` regardless of page protection (a loader or
    /// kernel write).
    pub fn poke(&self, addr: u64, data: &[u8]) -> Result<(), MemFault> {
        self.space.write_raw(addr, data).map_err(|f| MemFault {
            addr: f.address,
            write: true,
        })
    }

    /// Reads `buf.len()` bytes at `addr` regardless of page protection.
    pub fn peek(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemFault> {
        self.space.read_raw(addr, buf).map_err(|f| MemFault {
            addr: f.address,
            write: false,
        })
    }

    /// Iterates allocations in address order.
    pub fn allocations(&self) -> impl Iterator<Item = &Allocation> {
        self.allocs.values()
    }

    /// Whether an access of `access` at `addr` is allowed by the current
    /// protections (a probe, as `IsBadReadPtr` performs).
    pub fn accessible(&self, addr: u64, access: MemoryAccessKind) -> bool {
        self.space.translate(addr, access).is_ok()
    }
}

#[cfg(test)]
mod tests;
