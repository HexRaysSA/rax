//! Guest memory: sparse arbitrary-address mapping, permissions, and access.
//!
//! Memory is modelled as a set of non-overlapping regions, each backed by its
//! own demand-paged anonymous mapping. The set is materialized into a
//! [`GuestMemoryMmap`] (rebuilt cheaply from `Arc` region backings whenever the
//! mapping set changes) which both the host-access path and the vCPU share, so
//! host writes are immediately visible to the guest and vice versa.

use std::os::raw::c_int;
use std::sync::Arc;

use rax_engine::cpu::MemAccess;
use rax_engine::memory::vm::{Bytes, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

use crate::arch::build_vcpu;
use crate::engine::{Engine, PAGE, engine_mut, engine_ref};
use crate::guard;
use crate::status::RaxStatus;

// Permission flags. Mirror `RAX_PROT_*` in `rax.h`.
pub const RAX_PROT_NONE: u32 = 0;
pub const RAX_PROT_READ: u32 = 1 << 0;
pub const RAX_PROT_WRITE: u32 = 1 << 1;
pub const RAX_PROT_EXEC: u32 = 1 << 2;
pub const RAX_PROT_ALL: u32 = RAX_PROT_READ | RAX_PROT_WRITE | RAX_PROT_EXEC;

/// One mapped guest memory region.
pub struct Region {
    pub base: u64,
    pub size: u64,
    pub perms: u32,
    pub backing: Arc<GuestRegionMmap>,
}

/// Allocates a fresh, zero-filled, demand-paged backing for `[base, base+size)`.
pub fn alloc_backing(base: u64, size: u64) -> Result<Arc<GuestRegionMmap>, ()> {
    let mr = MmapRegion::new(size as usize).map_err(|_| ())?;
    let gr = GuestRegionMmap::new(mr, GuestAddress(base)).ok_or(())?;
    Ok(Arc::new(gr))
}

/// C view of a mapped region, for enumeration. Mirrors `rax_mem_region`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RaxMemRegion {
    pub base: u64,
    pub size: u64,
    pub perms: u32,
    pub _reserved: u32,
}

impl Engine {
    /// Current mapping as `(base, size, perms)` specs.
    fn region_specs(&self) -> Vec<(u64, u64, u32)> {
        self.regions
            .iter()
            .map(|r| (r.base, r.size, r.perms))
            .collect()
    }

    /// Whether `[addr, addr+len)` is fully covered by mapped regions.
    pub(crate) fn range_mapped(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let end = match addr.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        let mut cur = addr;
        for r in &self.regions {
            let rend = r.base + r.size;
            if rend <= cur {
                continue;
            }
            if r.base > cur {
                return false; // gap
            }
            if rend >= end {
                return true;
            }
            cur = rend;
        }
        cur >= end
    }

    /// Reads physical memory. Validates that the range is mapped; ignores
    /// region permissions (host/debugger access).
    pub(crate) fn phys_read(&self, addr: u64, buf: &mut [u8]) -> RaxStatus {
        if buf.is_empty() {
            return RaxStatus::Ok;
        }
        if !self.range_mapped(addr, buf.len() as u64) {
            return RaxStatus::Map;
        }
        match self.mem.read_slice(buf, GuestAddress(addr)) {
            Ok(()) => RaxStatus::Ok,
            Err(_) => RaxStatus::Map,
        }
    }

    /// Writes physical memory. Validates that the range is mapped; ignores
    /// region permissions (host/debugger access).
    pub(crate) fn phys_write(&self, addr: u64, buf: &[u8]) -> RaxStatus {
        if buf.is_empty() {
            return RaxStatus::Ok;
        }
        if !self.range_mapped(addr, buf.len() as u64) {
            return RaxStatus::Map;
        }
        match self.mem.write_slice(buf, GuestAddress(addr)) {
            Ok(()) => RaxStatus::Ok,
            Err(_) => RaxStatus::Map,
        }
    }

    /// Translates a virtual address through the vCPU's paging state.
    pub(crate) fn translate(&mut self, vaddr: u64, access: MemAccess) -> Result<u64, RaxStatus> {
        self.vcpu.translate_addr(vaddr, access).map_err(|e| {
            self.err_msg = e.to_string();
            RaxStatus::Fault
        })
    }

    /// Reads/writes virtual memory by translating each page, then performing a
    /// physical access. `write == true` selects the write direction; `buf` is
    /// the source (write) or destination (read).
    pub(crate) fn virt_access(&mut self, vaddr: u64, buf: &mut [u8], write: bool) -> RaxStatus {
        if buf.is_empty() {
            return RaxStatus::Ok;
        }
        let access = if write {
            MemAccess::Write
        } else {
            MemAccess::Read
        };
        let len = buf.len() as u64;
        let mut done: u64 = 0;
        while done < len {
            let va = match vaddr.checked_add(done) {
                Some(v) => v,
                None => return RaxStatus::Bounds,
            };
            let page_off = va & (PAGE - 1);
            let chunk = (PAGE - page_off).min(len - done);
            let pa = match self.translate(va, access) {
                Ok(p) => p,
                Err(s) => return s,
            };
            let slice = &mut buf[done as usize..(done + chunk) as usize];
            let st = if write {
                self.phys_write(pa, slice)
            } else {
                self.phys_read(pa, slice)
            };
            if st != RaxStatus::Ok {
                return st;
            }
            done += chunk;
        }
        RaxStatus::Ok
    }

    /// Rebuilds the mapping to match `specs`, preserving the contents of any
    /// surviving address range and reconstructing the vCPU (with CPU state
    /// round-tripped) when the backing set changes.
    fn apply_specs(&mut self, mut specs: Vec<(u64, u64, u32)>) -> RaxStatus {
        specs.sort_by_key(|s| s.0);

        // Validate alignment, sizes, and non-overlap.
        let mut prev_end = 0u64;
        for &(b, s, _) in &specs {
            if s == 0 || b % PAGE != 0 || s % PAGE != 0 {
                return self.fail(RaxStatus::Arg, "region base and size must be page-aligned");
            }
            let e = match b.checked_add(s) {
                Some(e) => e,
                None => return self.fail(RaxStatus::Bounds, "region end overflows address space"),
            };
            if b < prev_end {
                return self.fail(RaxStatus::Map, "overlapping regions");
            }
            prev_end = e;
        }
        if specs.is_empty() {
            return self.fail(RaxStatus::Map, "at least one region must remain mapped");
        }

        // Build the new region list, reusing backings for unchanged (base,size).
        let mut new_regions: Vec<Region> = Vec::with_capacity(specs.len());
        let mut fresh_idx: Vec<usize> = Vec::new();
        for (i, &(b, s, p)) in specs.iter().enumerate() {
            if let Some(old) = self.regions.iter().find(|r| r.base == b && r.size == s) {
                new_regions.push(Region {
                    base: b,
                    size: s,
                    perms: p & RAX_PROT_ALL,
                    backing: old.backing.clone(),
                });
            } else {
                let backing = match alloc_backing(b, s) {
                    Ok(x) => x,
                    Err(_) => {
                        return self.fail(RaxStatus::NoMem, "failed to allocate region backing");
                    }
                };
                new_regions.push(Region {
                    base: b,
                    size: s,
                    perms: p & RAX_PROT_ALL,
                    backing,
                });
                fresh_idx.push(i);
            }
        }

        // Perms-only change (identical backing set): update in place.
        if fresh_idx.is_empty() && new_regions.len() == self.regions.len() {
            self.regions = new_regions;
            return RaxStatus::Ok;
        }

        // Materialize the new backing store.
        let arcs: Vec<Arc<GuestRegionMmap>> =
            new_regions.iter().map(|r| r.backing.clone()).collect();
        let new_mem = match GuestMemoryMmap::from_arc_regions(arcs) {
            Ok(m) => Arc::new(m),
            Err(_) => return self.fail(RaxStatus::Map, "failed to assemble memory map"),
        };

        // Preserve overlapping bytes for any freshly allocated region.
        for &i in &fresh_idx {
            let r = &new_regions[i];
            for old in &self.regions {
                let lo = r.base.max(old.base);
                let hi = (r.base + r.size).min(old.base + old.size);
                if lo < hi {
                    let mut tmp = vec![0u8; (hi - lo) as usize];
                    if self.mem.read_slice(&mut tmp, GuestAddress(lo)).is_ok() {
                        let _ = new_mem.write_slice(&tmp, GuestAddress(lo));
                    }
                }
            }
        }

        // Reconstruct the vCPU over the new memory, round-tripping CPU state.
        let st = match self.vcpu.get_state() {
            Ok(s) => s,
            Err(e) => return self.fail_engine(&e),
        };
        let es = self.vcpu.get_emulator_state();
        let mut v = match build_vcpu(self.arch, self.mode, new_mem.clone(), self.riscv_config) {
            Ok(v) => v,
            Err(e) => return self.fail_engine(&e),
        };
        if let Err(e) = v.set_state(&st) {
            return self.fail_engine(&e);
        }
        if let Some(es) = es {
            let _ = v.set_emulator_state(&es);
        }

        // Rebuilding physical backing must not reset the embedding counter.
        self.icount_base = self
            .icount_base
            .saturating_add(self.vcpu.instruction_count())
            .saturating_sub(v.instruction_count());
        self.vcpu = v;
        self.mem = new_mem;
        self.regions = new_regions;
        RaxStatus::Ok
    }

    /// Maps a new region.
    fn do_map(&mut self, addr: u64, size: u64, perms: u32) -> RaxStatus {
        if size == 0 || addr % PAGE != 0 || size % PAGE != 0 {
            return self.fail(
                RaxStatus::Arg,
                "address and size must be page-aligned, size > 0",
            );
        }
        if addr.checked_add(size).is_none() {
            return self.fail(RaxStatus::Bounds, "region end overflows address space");
        }
        let mut specs = self.region_specs();
        specs.push((addr, size, perms & RAX_PROT_ALL));
        self.apply_specs(specs)
    }

    /// Unmaps an address range, trimming/splitting affected regions.
    fn do_unmap(&mut self, addr: u64, size: u64) -> RaxStatus {
        if size == 0 || addr % PAGE != 0 || size % PAGE != 0 {
            return self.fail(
                RaxStatus::Arg,
                "address and size must be page-aligned, size > 0",
            );
        }
        if !self.range_mapped(addr, size) {
            return self.fail(RaxStatus::Map, "unmap range is not fully mapped");
        }
        let ra = addr;
        let rb = addr + size;
        let mut out = Vec::new();
        for &(b, s, p) in &self.region_specs() {
            let re = b + s;
            if re <= ra || b >= rb {
                out.push((b, s, p)); // untouched
                continue;
            }
            if b < ra {
                out.push((b, ra - b, p));
            }
            if rb < re {
                out.push((rb, re - rb, p));
            }
        }
        if out.is_empty() {
            return self.fail(RaxStatus::Map, "at least one region must remain mapped");
        }
        self.apply_specs(out)
    }

    /// Changes permissions over an address range, splitting regions as needed.
    fn do_protect(&mut self, addr: u64, size: u64, perms: u32) -> RaxStatus {
        if size == 0 || addr % PAGE != 0 || size % PAGE != 0 {
            return self.fail(
                RaxStatus::Arg,
                "address and size must be page-aligned, size > 0",
            );
        }
        if !self.range_mapped(addr, size) {
            return self.fail(RaxStatus::Map, "protect range is not fully mapped");
        }
        let np = perms & RAX_PROT_ALL;
        let ra = addr;
        let rb = addr + size;
        let mut out = Vec::new();
        for &(b, s, p) in &self.region_specs() {
            let re = b + s;
            if re <= ra || b >= rb {
                out.push((b, s, p));
                continue;
            }
            if b < ra {
                out.push((b, ra - b, p));
            }
            let mid_lo = b.max(ra);
            let mid_hi = re.min(rb);
            out.push((mid_lo, mid_hi - mid_lo, np));
            if rb < re {
                out.push((rb, re - rb, p));
            }
        }
        self.apply_specs(out)
    }
}

// ===========================================================================
// FFI: memory mapping
// ===========================================================================

/// Maps `[addr, addr+size)` (page-aligned) with permissions `perms`.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_map(engine: *mut Engine, addr: u64, size: u64, perms: u32) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        if e.running {
            return e.fail(
                RaxStatus::State,
                "cannot modify the memory map while running",
            );
        }
        e.clear_err();
        e.do_map(addr, size, perms)
    })
}

/// Unmaps `[addr, addr+size)` (page-aligned). The range must be fully mapped,
/// and at least one region must remain afterwards.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_unmap(engine: *mut Engine, addr: u64, size: u64) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        if e.running {
            return e.fail(
                RaxStatus::State,
                "cannot modify the memory map while running",
            );
        }
        e.clear_err();
        e.do_unmap(addr, size)
    })
}

/// Changes the permissions of the mapped range `[addr, addr+size)`.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_protect(
    engine: *mut Engine,
    addr: u64,
    size: u64,
    perms: u32,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        if e.running {
            return e.fail(
                RaxStatus::State,
                "cannot modify the memory map while running",
            );
        }
        e.clear_err();
        e.do_protect(addr, size, perms)
    })
}

// ===========================================================================
// FFI: memory access
// ===========================================================================

/// Writes `len` bytes from `bytes` to guest physical address `addr`.
/// Host access: succeeds for any mapped range regardless of permissions.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_write(
    engine: *mut Engine,
    addr: u64,
    bytes: *const u8,
    len: usize,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        e.clear_err();
        if len == 0 {
            return RaxStatus::Ok;
        }
        if bytes.is_null() {
            return e.fail(RaxStatus::Arg, "null source buffer");
        }
        let buf = unsafe { std::slice::from_raw_parts(bytes, len) };
        let st = e.phys_write(addr, buf);
        if st != RaxStatus::Ok {
            e.err_msg = "physical write out of mapped range".to_string();
        }
        st
    })
}

/// Reads `len` bytes from guest physical address `addr` into `bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_read(
    engine: *mut Engine,
    addr: u64,
    bytes: *mut u8,
    len: usize,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        e.clear_err();
        if len == 0 {
            return RaxStatus::Ok;
        }
        if bytes.is_null() {
            return e.fail(RaxStatus::Arg, "null destination buffer");
        }
        let buf = unsafe { std::slice::from_raw_parts_mut(bytes, len) };
        let st = e.phys_read(addr, buf);
        if st != RaxStatus::Ok {
            e.err_msg = "physical read out of mapped range".to_string();
        }
        st
    })
}

/// Writes `len` bytes to guest *virtual* address `vaddr`, translating through
/// the current paging state.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_write_virt(
    engine: *mut Engine,
    vaddr: u64,
    bytes: *const u8,
    len: usize,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        e.clear_err();
        if len == 0 {
            return RaxStatus::Ok;
        }
        if bytes.is_null() {
            return e.fail(RaxStatus::Arg, "null source buffer");
        }
        // Copy into a temporary so virt_access can use one direction signature.
        let mut tmp = unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec();
        e.virt_access(vaddr, &mut tmp, true)
    })
}

/// Reads `len` bytes from guest *virtual* address `vaddr` into `bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_read_virt(
    engine: *mut Engine,
    vaddr: u64,
    bytes: *mut u8,
    len: usize,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        e.clear_err();
        if len == 0 {
            return RaxStatus::Ok;
        }
        if bytes.is_null() {
            return e.fail(RaxStatus::Arg, "null destination buffer");
        }
        let buf = unsafe { std::slice::from_raw_parts_mut(bytes, len) };
        e.virt_access(vaddr, buf, false)
    })
}

/// Translates virtual address `vaddr` (with intent `access`: 0=read, 1=write,
/// 2=exec) to a guest physical address, written to `*paddr`.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_translate(
    engine: *mut Engine,
    vaddr: u64,
    access: c_int,
    paddr: *mut u64,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        e.clear_err();
        if paddr.is_null() {
            return e.fail(RaxStatus::Arg, "null output pointer");
        }
        let acc = match access {
            0 => MemAccess::Read,
            1 => MemAccess::Write,
            2 => MemAccess::Exec,
            _ => return e.fail(RaxStatus::Arg, "invalid access kind"),
        };
        match e.translate(vaddr, acc) {
            Ok(pa) => {
                unsafe {
                    *paddr = pa;
                }
                RaxStatus::Ok
            }
            Err(s) => s,
        }
    })
}

/// Enumerates mapped regions. If `out` is non-NULL, up to `*count` regions are
/// written; `*count` is always set to the total number of regions.
#[unsafe(no_mangle)]
pub extern "C" fn rax_mem_regions(
    engine: *const Engine,
    out: *mut RaxMemRegion,
    count: *mut usize,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_ref(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        if count.is_null() {
            return RaxStatus::Arg;
        }
        let total = e.regions.len();
        let cap = unsafe { *count };
        if !out.is_null() && cap > 0 {
            let n = total.min(cap);
            for (i, r) in e.regions.iter().take(n).enumerate() {
                unsafe {
                    *out.add(i) = RaxMemRegion {
                        base: r.base,
                        size: r.size,
                        perms: r.perms,
                        _reserved: 0,
                    };
                }
            }
        }
        unsafe {
            *count = total;
        }
        RaxStatus::Ok
    })
}
