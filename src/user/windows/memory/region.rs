//! Page-run and allocation-wide region information. Queries do not populate frames.
use super::{AllocKind, Mem, MemFault, PageState, VirtualMemory, mem, prot};
use crate::user::mm::PAGE_SIZE;

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

/// Allocation-wide fields used by MemoryRegionInformation and its Ex variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocationRegionInfo {
    pub(crate) base: u64,
    pub(crate) protect: u32,
    pub(crate) kind: u32,
    pub(crate) flags: u32,
    pub(crate) size: u64,
    pub(crate) commit: u64,
    pub(crate) node: u64,
}

impl VirtualMemory {
    /// Actual page state for kernel-mediated guest access. Reported image
    /// protection is query metadata and must not authorize a memory access.
    pub(crate) fn page_state(&self, address: u64) -> Option<PageState> {
        let allocation = self.allocation(address)?;
        Some(allocation.state((address - allocation.base) / PAGE_SIZE))
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
                let mut k = key(&a.state(i));
                let mut end = a
                    .pages
                    .range((std::ops::Bound::Excluded(i), std::ops::Bound::Unbounded))
                    .find(|(_, p)| key(p) != k)
                    .map(|(&index, _)| index)
                    .unwrap_or(a.size / PAGE_SIZE);
                if k.0
                    && self.file_views.contains_key(&a.base)
                    && matches!(k.1 & 0xFF, prot::WRITECOPY | prot::EXECUTE_WRITECOPY)
                {
                    let (copied, len) = self.space.private_copy_run(page, (end - i) * PAGE_SIZE);
                    end = i + len / PAGE_SIZE;
                    if copied {
                        k.1 = (k.1 & !0xFF)
                            | if k.1 & 0xFF == prot::WRITECOPY {
                                prot::READWRITE
                            } else {
                                prot::EXECUTE_READWRITE
                            };
                    }
                }
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

    /// Complete reservation extent and process-local private commitment.
    /// O(R log T + I + S) for R state runs, T copy-range boundaries, I clipped
    /// copy intervals and S visited page-table slots. Absent subtrees are skipped;
    /// temporary interval storage is bounded by the intersections in one run.
    pub(crate) fn allocation_region(&self, address: u64) -> Option<AllocationRegionInfo> {
        let allocation = self.allocation(address)?;
        let pagefile = self.pagefile_views.contains(&allocation.base);
        let (kind, flags) = match allocation.kind {
            AllocKind::Private => (mem::PRIVATE, 1),
            AllocKind::Image => (mem::IMAGE, 4),
            AllocKind::Mapped if pagefile => (0x0800_0000, 8),
            AllocKind::Mapped => (mem::MAPPED, 2),
        };
        let mut commit = 0;
        for (first, end, state) in allocation.runs(0, allocation.size / PAGE_SIZE) {
            if !state.committed {
                // An initially copy-on-write pagefile view reserves private
                // commitment even for its uncommitted section pages. No guest
                // frame or address-space mapping is needed for that charge.
                if self.data_views.contains_key(&allocation.base)
                    && allocation.protect & 0xFF == prot::WRITECOPY
                {
                    commit += (end - first) * PAGE_SIZE;
                }
                continue;
            }
            let start = allocation.base + first * PAGE_SIZE;
            let len = (end - first) * PAGE_SIZE;
            if allocation.kind == AllocKind::Private {
                commit += len;
            } else if self.file_views.contains_key(&allocation.base) {
                commit += if matches!(
                    state.protect & 0xFF,
                    prot::WRITECOPY | prot::EXECUTE_WRITECOPY
                ) {
                    len
                } else {
                    self.space.acquired_private_bytes(start, len)
                };
            } else if super::perms_of(state.protect).contains(crate::user::mm::Perms::WRITE) {
                commit += self.space.private_copy_capacity(start, len);
            } else {
                commit += self.space.acquired_private_bytes(start, len);
            }
        }
        Some(AllocationRegionInfo {
            base: allocation.base,
            protect: allocation.protect,
            kind,
            flags,
            size: allocation.size,
            commit,
            node: u64::from(
                self.allocation_nodes
                    .get(&allocation.base)
                    .copied()
                    .unwrap_or(u32::MAX),
            ),
        })
    }
}

#[cfg(test)]
mod tests;
