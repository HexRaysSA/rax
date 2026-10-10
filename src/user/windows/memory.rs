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
/// CFG and enclave flags require contracts this manager does not implement.
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

/// `MEMORY_BASIC_INFORMATION` in host form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionInfo {
    /// `BaseAddress`.
    pub base: u64,
    /// `AllocationBase` (0 for free memory).
    pub allocation_base: u64,
    /// `AllocationProtect` (0 for free memory).
    pub allocation_protect: u32,
    /// `RegionSize`.
    pub size: u64,
    /// `State`: `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`.
    pub state: u32,
    /// `Protect` (0 unless committed).
    pub protect: u32,
    /// `Type` (0 for free memory).
    pub kind: u32,
}

impl RegionInfo {
    /// Size of `MEMORY_BASIC_INFORMATION32` or the native 64-bit structure.
    pub fn encoded_size(ptr_size: u64) -> usize {
        if ptr_size == 4 { 28 } else { 48 }
    }

    /// Serializes the Windows ABI, including zeroed 64-bit padding and
    /// `PartitionId`. The 32-bit fields are narrowed to the guest width.
    pub fn write(&self, mem: &impl Mem, addr: u64, ptr_size: u64) -> Result<usize, MemFault> {
        let mut b = [0u8; 48];
        if ptr_size == 4 {
            for (i, value) in [
                self.base as u32,
                self.allocation_base as u32,
                self.allocation_protect,
                self.size as u32,
                self.state,
                self.protect,
                self.kind,
            ]
            .into_iter()
            .enumerate()
            {
                b[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
            }
        } else {
            b[0..8].copy_from_slice(&self.base.to_le_bytes());
            b[8..16].copy_from_slice(&self.allocation_base.to_le_bytes());
            b[16..20].copy_from_slice(&self.allocation_protect.to_le_bytes());
            b[24..32].copy_from_slice(&self.size.to_le_bytes());
            b[32..36].copy_from_slice(&self.state.to_le_bytes());
            b[36..40].copy_from_slice(&self.protect.to_le_bytes());
            b[40..44].copy_from_slice(&self.kind.to_le_bytes());
        }
        let size = Self::encoded_size(ptr_size);
        mem.wr(addr, &b[..size])?;
        Ok(size)
    }
}

/// Why a virtual-memory operation failed, as an `NTSTATUS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmError {
    /// `STATUS_INVALID_PARAMETER`.
    InvalidParameter,
    /// `STATUS_INVALID_PAGE_PROTECTION`.
    InvalidProtection,
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
    nls_views: BTreeSet<u64>,
    /// Backing bytes promised for committed pages. No guest paging file
    /// is modeled; the usable frame arena bounds commitment.
    committed: u64,
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
            nls_views: BTreeSet::new(),
            committed: 0,
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

    /// Reserves `size` bytes (rounded up to pages) at `base` (rounded down
    /// to the allocation granularity), or anywhere when `base` is `None`.
    pub fn reserve(
        &mut self,
        base: Option<u64>,
        size: u64,
        protect: u32,
        kind: AllocKind,
        top_down: bool,
        name: Option<Arc<str>>,
    ) -> Result<u64, VmError> {
        if size == 0 {
            return Err(VmError::InvalidParameter);
        }
        if !valid_protection(protect) {
            return Err(VmError::InvalidProtection);
        }
        if kind == AllocKind::Private
            && matches!(protect & 0xFF, prot::WRITECOPY | prot::EXECUTE_WRITECOPY)
            || kind != AllocKind::Private && protect & (prot::NOCACHE | prot::WRITECOMBINE) != 0
        {
            return Err(VmError::InvalidProtection);
        }
        let (start, end) = match base {
            Some(b) => {
                let start = b & !(ALLOCATION_GRANULARITY - 1);
                let (_, end) = page_range(b, size)?;
                if !self.is_free(start, end - start) {
                    return Err(VmError::Conflicting);
                }
                (start, end)
            }
            None => {
                let len = size
                    .checked_add(PAGE_SIZE - 1)
                    .ok_or(VmError::InvalidParameter)?
                    & !(PAGE_SIZE - 1);
                let start = self
                    .find_free(len, ALLOCATION_GRANULARITY, self.low, self.high, top_down)
                    .ok_or(VmError::NoMemory)?;
                (start, start + len)
            }
        };
        self.allocs.insert(
            start,
            Allocation {
                base: start,
                size: end - start,
                protect,
                kind,
                pages: BTreeMap::from([(0, RESERVED)]),
                name,
            },
        );
        Ok(start)
    }

    /// The private-memory `VirtualAlloc` operation. `None` and `Some(0)`
    /// both request a system-selected address. Committing with a null base
    /// reserves implicitly. Returns the actual base and size, in bytes.
    /// Known facilities requiring additional state (AWE, write watch,
    /// large pages, reset undo) fail explicitly rather than being ignored.
    pub fn allocate(
        &mut self,
        base: Option<u64>,
        size: u64,
        allocation_type: u32,
        protect: u32,
    ) -> Result<(u64, u64), VmError> {
        const KNOWN: u32 = mem::COMMIT
            | mem::RESERVE
            | mem::TOP_DOWN
            | mem::RESET
            | mem::RESET_UNDO
            | mem::WRITE_WATCH
            | mem::PHYSICAL
            | mem::LARGE_PAGES;
        if size == 0 || allocation_type & !KNOWN != 0 || allocation_type == 0 {
            return Err(VmError::InvalidParameter);
        }
        if !valid_protection(protect)
            || matches!(protect & 0xFF, prot::WRITECOPY | prot::EXECUTE_WRITECOPY)
        {
            return Err(VmError::InvalidProtection);
        }
        let base = base.filter(|&b| b != 0);
        if allocation_type & (mem::RESET | mem::RESET_UNDO) != 0 {
            if allocation_type != mem::RESET && allocation_type != mem::RESET_UNDO {
                return Err(VmError::InvalidParameter);
            }
            if allocation_type == mem::RESET_UNDO {
                return Err(VmError::NotSupported);
            }
            let (first, end) = page_range(base.ok_or(VmError::InvalidParameter)?, size)?;
            let a = self.allocation(first).ok_or(VmError::NotAllocated)?;
            if end > a.base + a.size {
                return Err(VmError::Conflicting);
            }
            if a.kind != AllocKind::Private {
                return Err(VmError::InvalidParameter);
            }
            if a.runs((first - a.base) / PAGE_SIZE, (end - a.base) / PAGE_SIZE)
                .iter()
                .any(|(_, _, p)| !p.committed)
            {
                return Err(VmError::NotCommitted);
            }
            // This emulator has no paging file. Resident data remains intact,
            // which MEM_RESET explicitly permits; no protection is changed.
            return Ok((first, end - first));
        }
        if allocation_type & (mem::WRITE_WATCH | mem::PHYSICAL | mem::LARGE_PAGES) != 0 {
            return Err(VmError::NotSupported);
        }
        if allocation_type & (mem::COMMIT | mem::RESERVE) == 0 {
            return Err(VmError::InvalidParameter);
        }
        if allocation_type & mem::RESERVE != 0 || base.is_none() {
            let at = self.reserve(
                base,
                size,
                protect,
                AllocKind::Private,
                allocation_type & mem::TOP_DOWN != 0,
                None,
            )?;
            let len = self.allocation(at).expect("new reservation").size;
            if allocation_type & mem::COMMIT != 0
                && let Err(e) = self.commit(at, len, protect)
            {
                // Reservation was new, so it cannot contain earlier data.
                self.release(at)?;
                return Err(e);
            }
            Ok((at, len))
        } else {
            self.commit(base.expect("non-null commit"), size, protect)
        }
    }

    /// The `VirtualFree` / `NtFreeVirtualMemory` state operation. A release
    /// requires size zero and the original reservation base. The returned
    /// range reports the full released allocation or rounded decommit range.
    pub fn free(&mut self, base: u64, size: u64, free_type: u32) -> Result<(u64, u64), VmError> {
        if self.is_nls_view(base) && matches!(free_type, mem::RELEASE | mem::DECOMMIT) {
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

    fn check_protection(a: &Allocation, protect: u32) -> Result<(), VmError> {
        if !valid_protection(protect)
            || a.kind == AllocKind::Private
                && matches!(protect & 0xFF, prot::WRITECOPY | prot::EXECUTE_WRITECOPY)
            || a.kind != AllocKind::Private && protect & (prot::NOCACHE | prot::WRITECOMBINE) != 0
        {
            Err(VmError::InvalidProtection)
        } else {
            Ok(())
        }
    }

    /// Commits `[start, start + len)` (page-rounded outward) inside one
    /// allocation with `protect`. Already committed pages keep their
    /// contents and take the new protection.
    pub fn commit(&mut self, start: u64, len: u64, protect: u32) -> Result<(u64, u64), VmError> {
        if !valid_protection(protect) {
            return Err(VmError::InvalidProtection);
        }
        let (first, end) = page_range(start, len)?;
        let a = self.allocation(first).ok_or(VmError::NotAllocated)?;
        if self.nls_views.contains(&a.base) {
            return Err(if protect == prot::READONLY {
                VmError::AlreadyCommitted
            } else {
                VmError::InvalidProtection
            });
        }

        if end > a.base + a.size {
            return Err(VmError::Conflicting);
        }
        Self::check_protection(a, protect)?;
        let base = a.base;
        let name = a.name.clone();
        let i0 = (first - base) / PAGE_SIZE;
        let i1 = (end - base) / PAGE_SIZE;
        let runs = a.runs(i0, i1);
        let newly_committed: u64 = runs
            .iter()
            .filter(|(_, _, p)| !p.committed)
            .map(|(lo, hi, _)| (hi - lo) * PAGE_SIZE)
            .sum();
        let charge = self
            .committed
            .checked_add(newly_committed)
            .ok_or(VmError::CommitmentLimit)?;
        // AddressSpace::map replaces existing data. Verify all reserved
        // runs are unmapped and all committed runs are mapped before any
        // mutation. With scheduler serialization, subsequent map/protect
        // calls cannot fail their checked-range/coverage preconditions.
        for &(lo, hi, state) in &runs {
            let at = base + lo * PAGE_SIZE;
            let size = (hi - lo) * PAGE_SIZE;
            if state.committed {
                if self.space.first_unmapped(at, size).is_some() {
                    return Err(VmError::NotCommitted);
                }
            } else if !self.space.is_free(at, size) {
                return Err(VmError::Conflicting);
            }
        }
        if charge > self.commit_limit {
            return Err(VmError::CommitmentLimit);
        }
        for &(lo, hi, state) in &runs {
            if !state.committed {
                let mut mapping = Mapping::anonymous(effective_perms(protect));
                mapping.name = name.clone();
                self.space
                    .map(base + lo * PAGE_SIZE, (hi - lo) * PAGE_SIZE, mapping)
                    .map_err(mm)?;
            }
        }
        self.space
            .protect(first, end - first, effective_perms(protect))
            .map_err(mm)?;
        self.allocs
            .get_mut(&base)
            .expect("validated allocation")
            .set_state(
                i0,
                i1,
                PageState {
                    committed: true,
                    protect,
                    reported: None,
                },
            );
        self.committed = charge;
        Ok((first, end - first))
    }

    /// Decommits `[start, start + len)` (page-rounded outward); a length of
    /// zero decommits the entire allocation and requires its exact base.
    pub fn decommit(&mut self, start: u64, len: u64) -> Result<(u64, u64), VmError> {
        let first = start & !(PAGE_SIZE - 1);
        let a = self.allocation(first).ok_or(VmError::NotAllocated)?;
        if self.nls_views.contains(&a.base) {
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
        let returned: u64 = a
            .runs(0, size / PAGE_SIZE)
            .iter()
            .filter(|(_, _, p)| p.committed)
            .map(|(lo, hi, _)| (hi - lo) * PAGE_SIZE)
            .sum();
        self.space.unmap(base, size).map_err(mm)?;
        self.allocs.remove(&base);
        self.nls_views.remove(&base);
        self.committed -= returned;
        Ok(size)
    }

    /// Changes the protection of committed pages `[start, start + len)`;
    /// returns the old protection of the first page.
    pub fn protect(&mut self, start: u64, len: u64, protect: u32) -> Result<u32, VmError> {
        if !valid_protection(protect) {
            return Err(VmError::InvalidProtection);
        }
        let (first, end) = page_range(start, len)?;
        let a = self.allocation(first).ok_or(VmError::NotAllocated)?;
        if self.nls_views.contains(&a.base) && protect != prot::READONLY {
            return Err(VmError::InvalidProtection);
        }

        if end > a.base + a.size {
            return Err(VmError::InvalidAddress);
        }
        Self::check_protection(a, protect)?;
        let base = a.base;
        let i0 = (first - base) / PAGE_SIZE;
        let i1 = (end - base) / PAGE_SIZE;
        if a.runs(i0, i1).iter().any(|(_, _, p)| !p.committed) {
            return Err(VmError::NotCommitted);
        }
        let p = a.state(i0);
        let old = p.reported.unwrap_or(p.protect);
        // This single AddressSpace operation checks all mapping coverage
        // before changing permissions; metadata changes only on success.
        self.space
            .protect(first, end - first, effective_perms(protect))
            .map_err(mm)?;
        self.allocs
            .get_mut(&base)
            .expect("validated allocation")
            .set_state(
                i0,
                i1,
                PageState {
                    committed: true,
                    protect,
                    reported: None,
                },
            );
        Ok(old)
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

    /// `VirtualQuery` of `addr`: the run of pages with identical state
    /// starting at `addr`'s page, or the free range containing it.
    pub fn query(&self, addr: u64) -> Option<RegionInfo> {
        if addr >= self.high {
            return None;
        }
        let page = addr & !(PAGE_SIZE - 1);
        match self.allocation(page) {
            Some(a) => {
                let i = (page - a.base) / PAGE_SIZE;
                let key = |p: &PageState| (p.committed, p.reported.unwrap_or(p.protect));
                let k = key(&a.state(i));
                let end = a
                    .pages
                    .range((std::ops::Bound::Excluded(i), std::ops::Bound::Unbounded))
                    .find(|(_, p)| key(p) != k)
                    .map(|(&index, _)| index)
                    .unwrap_or(a.size / PAGE_SIZE);
                Some(RegionInfo {
                    base: page,
                    allocation_base: a.base,
                    allocation_protect: a.protect,
                    size: (end - i) * PAGE_SIZE,
                    state: if k.0 { mem::COMMIT } else { mem::RESERVE },
                    protect: if k.0 { k.1 } else { 0 },
                    kind: a.kind.value(),
                })
            }
            None => {
                let next = self
                    .allocs
                    .range(page..)
                    .next()
                    .map(|(&b, _)| b)
                    .unwrap_or(self.high);
                Some(RegionInfo {
                    base: page,
                    allocation_base: 0,
                    allocation_protect: 0,
                    size: next - page,
                    state: mem::FREE,
                    protect: prot::NOACCESS,
                    kind: 0,
                })
            }
        }
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
mod tests {
    use super::*;
    use crate::user::mm::{CodeChanges, SpaceConfig};

    fn vm(high: u64) -> VirtualMemory {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: high,
            arena_bytes: 4 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        VirtualMemory::new(space, ALLOCATION_GRANULARITY, high)
    }

    fn reservation(vm: &mut VirtualMemory, size: u64) -> u64 {
        vm.reserve(None, size, prot::READWRITE, AllocKind::Private, false, None)
            .unwrap()
    }

    #[test]
    fn protection_combinations_follow_documented_constraints() {
        for base in [
            prot::NOACCESS,
            prot::READONLY,
            prot::READWRITE,
            prot::WRITECOPY,
            prot::EXECUTE,
            prot::EXECUTE_READ,
            prot::EXECUTE_READWRITE,
            prot::EXECUTE_WRITECOPY,
        ] {
            assert!(valid_protection(base));
            assert_eq!(valid_protection(base | prot::GUARD), base != prot::NOACCESS);
            assert_eq!(
                valid_protection(base | prot::NOCACHE),
                base != prot::NOACCESS
            );
            assert_eq!(
                valid_protection(base | prot::WRITECOMBINE),
                base != prot::NOACCESS
            );
            assert!(!valid_protection(base | prot::GUARD | prot::NOCACHE));
            assert!(!valid_protection(base | prot::GUARD | prot::WRITECOMBINE));
            assert!(!valid_protection(base | prot::NOCACHE | prot::WRITECOMBINE));
        }
        for invalid in [0, prot::READONLY | prot::READWRITE, 0x800, 0x4000_0010] {
            assert!(!valid_protection(invalid));
        }
        assert_eq!(perms_of(prot::EXECUTE), Perms::EXEC);
        assert_eq!(perms_of(prot::EXECUTE_READ), Perms::READ | Perms::EXEC);
    }

    #[test]
    fn reservation_rounds_base_and_inclusive_byte_coverage() {
        let mut vm = vm(1 << 32);
        let base = vm
            .reserve(
                Some(0x2_0801),
                0x1000,
                prot::READONLY,
                AllocKind::Private,
                false,
                None,
            )
            .unwrap();
        assert_eq!(base, 0x2_0000);
        assert_eq!(vm.allocation(base).unwrap().size, 0x2000);
        assert_eq!(vm.query(base).unwrap().state, mem::RESERVE);
        assert!(!vm.accessible(base, MemoryAccessKind::Read));
        assert_eq!(
            vm.reserve(
                Some(base),
                PAGE_SIZE,
                prot::READWRITE,
                AllocKind::Private,
                false,
                None
            ),
            Err(VmError::Conflicting)
        );
    }

    #[test]
    fn commitment_crosses_pages_and_preserves_existing_contents() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, 4 * PAGE_SIZE);
        assert_eq!(
            vm.commit(base + PAGE_SIZE - 1, 2, prot::READWRITE),
            Ok((base, 2 * PAGE_SIZE))
        );
        assert_eq!(vm.space().u32(base).unwrap(), 0);
        vm.space().w32(base, 0xC0DE_1234).unwrap();
        vm.commit(base, 2 * PAGE_SIZE, prot::READONLY).unwrap();
        assert_eq!(vm.space().u32(base).unwrap(), 0xC0DE_1234);
        assert!(!vm.accessible(base, MemoryAccessKind::Write));
        assert_eq!(vm.query(base).unwrap().size, 2 * PAGE_SIZE);
        assert_eq!(vm.query(base + 2 * PAGE_SIZE).unwrap().state, mem::RESERVE);
    }

    #[test]
    fn decommit_is_idempotent_and_recommit_is_zeroed() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, 3 * PAGE_SIZE);
        vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
        vm.space().w32(base, u32::MAX).unwrap();
        vm.decommit(base, 2 * PAGE_SIZE).unwrap();
        vm.decommit(base, 2 * PAGE_SIZE).unwrap();
        assert!(!vm.accessible(base, MemoryAccessKind::Read));
        vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(vm.space().u32(base).unwrap(), 0);
        assert_eq!(vm.decommit(base + PAGE_SIZE, 0), Err(VmError::NotAtBase));
        assert_eq!(vm.decommit(base, 0), Ok((base, 3 * PAGE_SIZE)));
        assert_eq!(vm.allocation(base).unwrap().pages.len(), 1);
    }

    #[test]
    fn invalid_ranges_do_not_wrap_or_mutate_memory() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, 2 * PAGE_SIZE);
        vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
        for result in [
            vm.commit(base, 0, prot::READONLY),
            vm.commit(base, u64::MAX, prot::READONLY),
        ] {
            assert_eq!(result, Err(VmError::InvalidParameter));
        }
        assert_eq!(
            vm.protect(base, 0, prot::READONLY),
            Err(VmError::InvalidParameter)
        );
        assert_eq!(
            vm.protect(base, u64::MAX, prot::READONLY),
            Err(VmError::InvalidParameter)
        );
        assert_eq!(vm.decommit(base, u64::MAX), Err(VmError::InvalidParameter));
        assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
        assert!(vm.accessible(base, MemoryAccessKind::Write));
        assert_eq!(vm.find_free(0, 0, 0, u64::MAX, false), None);
        assert_eq!(vm.find_free(1, 3, 0, u64::MAX, true), None);
        assert_eq!(
            vm.find_free(PAGE_SIZE, PAGE_SIZE, 0x2000, 0x1000, false),
            None
        );
    }

    #[test]
    fn protection_checks_every_page_before_changing_any() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, 3 * PAGE_SIZE);
        vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(
            vm.protect(base, 2 * PAGE_SIZE, prot::READONLY),
            Err(VmError::NotCommitted)
        );
        assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
        vm.commit(base, 3 * PAGE_SIZE, prot::READWRITE).unwrap();
        // An inconsistent shared AddressSpace must also fail before metadata
        // or another page's actual permissions change.
        vm.space().unmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            vm.protect(base, 3 * PAGE_SIZE, prot::READONLY),
            Err(VmError::NotCommitted)
        );
        assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
        assert!(vm.accessible(base, MemoryAccessKind::Write));
    }

    #[test]
    fn distinct_reservations_are_not_one_protection_region() {
        let mut vm = vm(1 << 32);
        let base = vm
            .reserve(
                Some(0x2_0000),
                ALLOCATION_GRANULARITY,
                prot::READWRITE,
                AllocKind::Private,
                false,
                None,
            )
            .unwrap();
        vm.reserve(
            Some(base + ALLOCATION_GRANULARITY),
            ALLOCATION_GRANULARITY,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
        vm.commit(base, ALLOCATION_GRANULARITY, prot::READWRITE)
            .unwrap();
        assert_eq!(
            vm.protect(base + ALLOCATION_GRANULARITY - 1, 2, prot::READONLY),
            Err(VmError::InvalidAddress)
        );
        assert_eq!(
            vm.query(base + PAGE_SIZE).unwrap().size,
            ALLOCATION_GRANULARITY - PAGE_SIZE
        );
    }

    #[test]
    fn release_requires_original_base_and_zero_size() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, 3 * PAGE_SIZE);
        vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(vm.free(base + 1, 0, mem::RELEASE), Err(VmError::NotAtBase));
        assert_eq!(vm.free(base, 1, mem::RELEASE), Err(VmError::UnableToFree));
        assert_eq!(
            vm.free(base, 0, mem::RELEASE | mem::DECOMMIT),
            Err(VmError::InvalidParameter)
        );
        assert_eq!(vm.free(base, 0, mem::RELEASE), Ok((base, 3 * PAGE_SIZE)));
        assert_eq!(vm.query(base).unwrap().state, mem::FREE);
        assert!(!vm.accessible(base, MemoryAccessKind::Read));
    }

    #[test]
    fn guard_is_one_shot_for_each_page() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, 2 * PAGE_SIZE);
        vm.commit(base, 2 * PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        assert!(!vm.accessible(base, MemoryAccessKind::Read));
        assert!(vm.take_guard(base + 3));
        assert!(!vm.take_guard(base));
        assert!(vm.accessible(base, MemoryAccessKind::Write));
        assert!(!vm.accessible(base + PAGE_SIZE, MemoryAccessKind::Read));
        assert_eq!(vm.query(base).unwrap().size, PAGE_SIZE);
        assert!(vm.take_guard(base + PAGE_SIZE));
        assert_eq!(vm.allocation(base).unwrap().pages.len(), 1);
    }

    #[test]
    fn huge_reservations_use_only_state_boundaries() {
        let mut vm = vm(1 << 47);
        let size = 1 << 42;
        let base = reservation(&mut vm, size);
        assert_eq!(vm.allocation(base).unwrap().pages.len(), 1);
        assert_eq!(vm.query(base).unwrap().size, size);
        vm.commit(base + size - PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        assert_eq!(vm.allocation(base).unwrap().pages.len(), 2);
        assert_eq!(vm.query(base).unwrap().size, size - PAGE_SIZE);
        assert_eq!(vm.space().u32(base + size - PAGE_SIZE).unwrap(), 0);
        vm.decommit(base + size - PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(vm.allocation(base).unwrap().pages.len(), 1);
    }

    #[test]
    fn free_search_handles_limits_alignment_overlap_and_both_directions() {
        let mut vm = vm(0x10_0000);
        let base = vm
            .reserve(
                Some(0x4_0000),
                3 * ALLOCATION_GRANULARITY,
                prot::READWRITE,
                AllocKind::Private,
                false,
                None,
            )
            .unwrap();
        vm.commit(base + ALLOCATION_GRANULARITY, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        assert_eq!(
            vm.find_free(
                ALLOCATION_GRANULARITY,
                ALLOCATION_GRANULARITY,
                base,
                base + 4 * ALLOCATION_GRANULARITY,
                true
            ),
            Some(0x7_0000)
        );
        assert_eq!(
            vm.find_free(
                ALLOCATION_GRANULARITY,
                ALLOCATION_GRANULARITY,
                base,
                base + 3 * ALLOCATION_GRANULARITY,
                true
            ),
            None
        );
        assert_eq!(
            vm.find_free(
                ALLOCATION_GRANULARITY,
                ALLOCATION_GRANULARITY,
                0x3_0001,
                0x8_0000,
                false
            ),
            Some(0x7_0000)
        );
        vm.space()
            .map(0x7_0000, PAGE_SIZE, Mapping::anonymous(Perms::READ))
            .unwrap();
        assert_eq!(
            vm.reserve(
                Some(0x7_0000),
                PAGE_SIZE,
                prot::READWRITE,
                AllocKind::Private,
                false,
                None
            ),
            Err(VmError::Conflicting)
        );
        assert_eq!(
            vm.find_free(
                ALLOCATION_GRANULARITY,
                ALLOCATION_GRANULARITY,
                0x3_0001,
                0x9_0000,
                false
            ),
            Some(0x8_0000)
        );
    }

    #[test]
    fn commit_never_replaces_untracked_existing_bytes() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, 2 * PAGE_SIZE);
        vm.space()
            .map(
                base + PAGE_SIZE,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        vm.space().w32(base + PAGE_SIZE, 0x1234_5678).unwrap();
        assert_eq!(
            vm.commit(base, 2 * PAGE_SIZE, prot::READWRITE),
            Err(VmError::Conflicting)
        );
        assert_eq!(vm.query(base).unwrap().state, mem::RESERVE);
        assert!(!vm.accessible(base, MemoryAccessKind::Read));
        assert_eq!(vm.space().u32(base + PAGE_SIZE).unwrap(), 0x1234_5678);
    }

    #[test]
    fn allocate_flags_are_supported_or_explicitly_rejected() {
        let mut vm = vm(1 << 32);
        let (base, size) = vm
            .allocate(Some(0), 1, mem::COMMIT, prot::READWRITE)
            .unwrap();
        assert_eq!(size, PAGE_SIZE);
        assert_eq!(vm.query(base).unwrap().state, mem::COMMIT);
        vm.space().w32(base, 0x1234_5678).unwrap();
        vm.allocate(Some(base), 1, mem::RESET, prot::NOACCESS)
            .unwrap();
        assert_eq!(vm.space().u32(base).unwrap(), 0x1234_5678);
        assert_eq!(vm.query(base).unwrap().protect, prot::READWRITE);
        for flags in [
            mem::RESET_UNDO,
            mem::RESERVE | mem::WRITE_WATCH,
            mem::RESERVE | mem::PHYSICAL,
            mem::RESERVE | mem::COMMIT | mem::LARGE_PAGES,
        ] {
            assert_eq!(
                vm.allocate(Some(base), PAGE_SIZE, flags, prot::READWRITE),
                Err(VmError::NotSupported)
            );
        }
        for flags in [0, mem::TOP_DOWN, mem::COMMIT | mem::RESET, 0x8000_0000] {
            assert_eq!(
                vm.allocate(None, PAGE_SIZE, flags, prot::READWRITE),
                Err(VmError::InvalidParameter)
            );
        }
        for protect in [
            prot::WRITECOPY,
            prot::EXECUTE_WRITECOPY,
            prot::NOACCESS | prot::GUARD,
        ] {
            assert_eq!(
                vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, protect),
                Err(VmError::InvalidProtection)
            );
        }
    }

    #[test]
    fn query_reports_forward_runs_and_distinct_initial_protection() {
        let mut vm = vm(0x10_0000);
        let base = reservation(&mut vm, 4 * PAGE_SIZE);
        vm.commit(base, 3 * PAGE_SIZE, prot::READONLY).unwrap();
        let r = vm.query(base + PAGE_SIZE + 31).unwrap();
        assert_eq!(r.base, base + PAGE_SIZE);
        assert_eq!(r.size, 2 * PAGE_SIZE);
        assert_eq!(r.allocation_protect, prot::READWRITE);
        assert_eq!(r.protect, prot::READONLY);
        assert_eq!(r.kind, mem::PRIVATE);
        assert_eq!(vm.query(vm.high()), None);
        assert_eq!(vm.query(vm.high() - 1).unwrap().size, PAGE_SIZE);
    }

    #[test]
    fn image_reported_protection_preserves_trap_mapping() {
        let mut vm = vm(1 << 32);
        let base = vm
            .reserve(
                None,
                2 * PAGE_SIZE,
                prot::EXECUTE_WRITECOPY,
                AllocKind::Image,
                false,
                None,
            )
            .unwrap();
        vm.commit(base, 2 * PAGE_SIZE, prot::READONLY).unwrap();
        vm.set_reported(base, 2 * PAGE_SIZE, prot::EXECUTE_READ);
        assert_eq!(vm.query(base).unwrap().protect, prot::EXECUTE_READ);
        assert!(!vm.accessible(base, MemoryAccessKind::Fetch));
        vm.set_reported(base, 0, prot::READWRITE);
        vm.set_reported(base, u64::MAX, prot::READWRITE);
        assert_eq!(vm.query(base).unwrap().protect, prot::EXECUTE_READ);
        assert_eq!(
            vm.protect(base, PAGE_SIZE, prot::READWRITE),
            Ok(prot::EXECUTE_READ)
        );
        assert_eq!(vm.query(base).unwrap().size, PAGE_SIZE);
    }

    #[test]
    fn guest_memory_information_abi_matches_both_pointer_widths() {
        let mut vm = vm(1 << 32);
        let (base, _) = vm
            .allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
        let r = RegionInfo {
            base: 0x1234_5000,
            allocation_base: 0x1234_0000,
            allocation_protect: prot::READONLY,
            size: 0x6000,
            state: mem::COMMIT,
            protect: prot::READWRITE,
            kind: mem::PRIVATE,
        };
        assert_eq!(r.write(vm.space(), base, 4).unwrap(), 28);
        assert_eq!(vm.space().u32(base + 12).unwrap(), 0x6000);
        assert_eq!(vm.space().u32(base + 24).unwrap(), mem::PRIVATE);
        assert_eq!(r.write(vm.space(), base, 8).unwrap(), 48);
        assert_eq!(vm.space().u64(base).unwrap(), 0x1234_5000);
        assert_eq!(vm.space().u64(base + 24).unwrap(), 0x6000);
        assert_eq!(vm.space().u32(base + 40).unwrap(), mem::PRIVATE);
        assert_eq!(vm.space().u32(base + 20).unwrap(), 0);
        assert_eq!(vm.space().u32(base + 44).unwrap(), 0);
    }

    #[test]
    fn protection_and_decommit_invalidate_executable_code() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, PAGE_SIZE);
        vm.commit(base, PAGE_SIZE, prot::EXECUTE_READWRITE).unwrap();
        let epoch = vm.space().code_epoch();
        vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
        assert!(matches!(
            vm.space().code_changes_since(epoch).0,
            CodeChanges::Ranges(_)
        ));
        vm.protect(base, PAGE_SIZE, prot::EXECUTE_READWRITE)
            .unwrap();
        let epoch = vm.space().code_epoch();
        vm.decommit(base, PAGE_SIZE).unwrap();
        assert!(matches!(
            vm.space().code_changes_since(epoch).0,
            CodeChanges::Ranges(_)
        ));
    }

    #[test]
    fn state_run_boundaries_match_independent_page_model() {
        let mut vm = vm(1 << 32);
        let base = reservation(&mut vm, 64 * PAGE_SIZE);
        let mut expected = [None; 64];
        let mut seed = 0x67E3_29B1_u32;
        for step in 0..128 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let first = (seed & 63) as usize;
            let end = (first + 1 + ((seed >> 6) & 15) as usize).min(64);
            let at = base + first as u64 * PAGE_SIZE;
            let len = (end - first) as u64 * PAGE_SIZE;
            let protect = if seed & 0x10000 == 0 {
                prot::READWRITE
            } else {
                prot::READONLY
            };
            match step % 3 {
                0 => {
                    vm.commit(at, len, protect).unwrap();
                    expected[first..end].fill(Some(protect));
                }
                1 => {
                    vm.decommit(at, len).unwrap();
                    expected[first..end].fill(None);
                }
                _ => {
                    let result = vm.protect(at, len, protect);
                    if expected[first..end].iter().all(Option::is_some) {
                        assert_eq!(result, Ok(expected[first].unwrap()));
                        expected[first..end].fill(Some(protect));
                    } else {
                        assert_eq!(result, Err(VmError::NotCommitted));
                    }
                }
            }
            for i in 0..64 {
                let r = vm.query(base + i as u64 * PAGE_SIZE).unwrap();
                let count = expected[i..]
                    .iter()
                    .take_while(|&&p| p == expected[i])
                    .count();
                assert_eq!(
                    r.size,
                    count as u64 * PAGE_SIZE,
                    "seed={seed:#x} step={step} page={i}"
                );
                assert_eq!(
                    r.state,
                    if expected[i].is_some() {
                        mem::COMMIT
                    } else {
                        mem::RESERVE
                    }
                );
                assert_eq!(r.protect, expected[i].unwrap_or(0));
            }
        }
    }

    #[test]
    fn commitment_charge_counts_only_new_pages_and_returns_on_free() {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 4 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut vm = VirtualMemory::new_with_commit_limit(space, 0x10000, 1 << 32, 2 * PAGE_SIZE);
        let base = reservation(&mut vm, 4 * PAGE_SIZE);
        assert_eq!(vm.committed_bytes(), 0);
        assert_eq!(vm.commit_limit(), 2 * PAGE_SIZE);
        vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
        vm.commit(base, PAGE_SIZE, prot::READONLY).unwrap();
        assert_eq!(vm.committed_bytes(), PAGE_SIZE);
        vm.commit(base, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(vm.committed_bytes(), 2 * PAGE_SIZE);
        assert_eq!(
            vm.commit(base + PAGE_SIZE, 2 * PAGE_SIZE, prot::READONLY),
            Err(VmError::CommitmentLimit)
        );
        assert_eq!(vm.committed_bytes(), 2 * PAGE_SIZE);
        assert_eq!(vm.query(base + PAGE_SIZE).unwrap().protect, prot::READWRITE);
        assert_eq!(vm.query(base + 2 * PAGE_SIZE).unwrap().state, mem::RESERVE);
        vm.decommit(base, PAGE_SIZE).unwrap();
        vm.decommit(base, PAGE_SIZE).unwrap();
        assert_eq!(vm.committed_bytes(), PAGE_SIZE);
        vm.commit(base + 2 * PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        vm.release(base).unwrap();
        assert_eq!(vm.committed_bytes(), 0);
        assert_eq!(VmError::CommitmentLimit.status(), 0xC000_012D);
    }

    #[test]
    fn exhausted_combined_allocation_rolls_back_new_reservation() {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 4 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut vm = VirtualMemory::new_with_commit_limit(space, 0x10000, 1 << 32, PAGE_SIZE);
        let (base, _) = vm
            .allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
        assert_eq!(
            vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE),
            Err(VmError::CommitmentLimit)
        );
        assert_eq!(vm.allocations().count(), 1);
        assert_eq!(vm.committed_bytes(), PAGE_SIZE);
        assert_eq!(vm.space().u32(base).unwrap(), 0);
        vm.release(base).unwrap();
        assert_eq!(
            vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0,
            base
        );
    }

    #[test]
    fn utf16_unit_count_cannot_wrap_byte_length() {
        let vm = vm(1 << 32);
        assert_eq!(
            vm.space().wunits(0x10000, usize::MAX),
            Err(MemFault {
                addr: 0x10000,
                write: false
            })
        );
    }
}
