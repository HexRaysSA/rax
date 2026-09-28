//! Memory host services map into the process's task.
//!
//! A host service the guest hands its task control port or identity token
//! can map memory into the task: CoreServices' `coreservicesd` maps the
//! session's shared file-ID universe into a client ("via identity-token"),
//! returns its address, and later maps segments of it, whose addresses it
//! publishes in the memory it shares. The guest's task is the emulator's
//! host task, so that memory lands in the emulator's address space, where
//! the host chose, and the guest then uses the address. The bridge makes
//! the memory the guest's at the same address:
//!
//! - Once the guest has handed its task out, what the guest maps is
//!   reserved in the host (inaccessible mappings) before each message goes
//!   to the host, so that the host chooses addresses the guest leaves free.
//! - After each message from the host, a region that is new since the last
//!   look, accessible, shared with another task, and outside the frame
//!   arena is mapped at its address in the guest, shared: the guest's pages
//!   are the host memory itself, through a memory entry of it (and, in a
//!   host child, of the child's own region there: a copy, or the memory the
//!   region still shares).
//!
//! The host's own shared mappings (a notification page one of the
//! emulator's libraries maps, say) made while the bridge looks cannot be
//! told from a service's; they appear in the guest as further shared
//! regions.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use super::host::{self, Name};
use crate::user::darwin::process::Proc;
use crate::user::darwin::vm::{self, VmFlags};
use crate::user::mm::{Backing, HostMemory, Mapping, SharedObject};

/// The user tag of the host reservations (`VM_MEMORY_APPLICATION_SPECIFIC_16`).
const RESERVED_TAG: u32 = 255;

/// The mirroring state of a process's bridge.
#[derive(Debug, Default)]
pub struct Mirror {
    /// The guest has handed a host service its task.
    armed: bool,
    /// The host's regions at the last look, as `(start, end)`; empty until
    /// the first.
    known: HashSet<(u64, u64)>,
    /// The host's virtual size and region count at the last look.
    stamp: (u64, u32),
    /// Guest ranges reserved on the host or found in use there (sorted,
    /// merged).
    covered: Vec<(u64, u64)>,
}

impl Mirror {
    /// The guest hands a host service its task (control port or identity
    /// token).
    pub fn arm(&mut self) {
        self.armed = true;
    }
}

/// Before a message goes to the host: what the guest maps is reserved on
/// the host, and the first time the host's regions are noted.
pub fn before_send(proc: &mut Proc) {
    if !proc.bridge.mirror.armed {
        return;
    }
    reserve(proc);
    let m = &mut proc.bridge.mirror;
    if m.known.is_empty() {
        m.known = host::regions().iter().map(|r| (r.start, r.end)).collect();
        m.stamp = host::vm_stamp();
    }
}

/// After a message from the host: the regions host services mapped into
/// the task since the last look become the guest's.
pub fn after_receive(proc: &mut Proc) {
    let m = &proc.bridge.mirror;
    if !m.armed || m.known.is_empty() {
        return;
    }
    let stamp = host::vm_stamp();
    if stamp == m.stamp {
        return;
    }
    let (lo, hi) = arena(proc);
    let now = host::regions();
    for r in &now {
        if proc.bridge.mirror.known.contains(&(r.start, r.end))
            || r.submap
            || r.prot & vm::VM_PROT_READ == 0
            || !matches!(
                r.share_mode,
                host::share::SHARED
                    | host::share::TRUESHARED
                    | host::share::PRIVATE_ALIASED
                    | host::share::SHARED_ALIASED
            )
            || (r.start < hi && r.end > lo)
        {
            continue;
        }
        adopt(proc, r);
    }
    let m = &mut proc.bridge.mirror;
    m.known = now.iter().map(|r| (r.start, r.end)).collect();
    m.stamp = host::vm_stamp();
}

/// The frame arena's host address range.
fn arena(proc: &Proc) -> (u64, u64) {
    use vm_memory::{GuestAddress, GuestMemory, GuestMemoryRegion};
    let mem = proc.space.physical_memory();
    let len: u64 = mem.iter().map(|r| r.len()).sum();
    match mem.get_host_address(GuestAddress(0)) {
        Ok(p) => (p as u64, p as u64 + len),
        Err(_) => (0, 0),
    }
}

/// Maps host region `r` at its address in the guest, shared, unless the
/// guest uses any of it.
fn adopt(proc: &mut Proc, r: &host::Region) {
    let len = r.end - r.start;
    let strace = proc.config.strace;
    if !proc.space.is_free(r.start, len) {
        if strace {
            eprintln!(
                "rax-user: bridge: host mapping {:#x}-{:#x} overlaps the guest's memory",
                r.start, r.end
            );
        }
        return;
    }
    // An entry of the memory itself takes what the region allows now
    // (mach_make_memory_entry_share requires it of the current protection).
    let prot = r.prot & (vm::VM_PROT_READ | vm::VM_PROT_WRITE);
    let name = match host::share_entry(r.start, len, prot) {
        Ok(n) => n,
        Err(kr) => {
            if strace {
                eprintln!(
                    "rax-user: bridge: no memory entry of host mapping {:#x}-{:#x}: {kr:#x}",
                    r.start, r.end
                );
            }
            return;
        }
    };
    let memory = Arc::new(HostEntry::new(name, r.start, len, prot));
    let object = SharedObject::host_memory(memory, prot & vm::VM_PROT_WRITE != 0);
    let mapping = Mapping {
        perms: vm::perms(r.prot & vm::VM_PROT_ALL),
        backing: Backing::Shared {
            object: Arc::new(object),
            offset: 0,
        },
        shared: true,
        name: None,
        flags: VmFlags::new(r.max & vm::VM_PROT_ALL, r.inheritance, r.tag).bits(),
    };
    let done = proc.space.map(r.start, len, mapping);
    if strace {
        eprintln!(
            "rax-user: bridge: host service mapped {:#x}-{:#x} (prot {}/{}): {}",
            r.start,
            r.end,
            r.prot,
            r.max,
            if done.is_ok() {
                "the guest's too"
            } else {
                "not mapped in the guest"
            }
        );
    }
}

/// Reserves on the host the guest's mapped ranges not reserved yet.
fn reserve(proc: &mut Proc) {
    // SAFETY: sysconf takes no pointers.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let guest = merge(
        proc.space
            .vma_snapshot()
            .iter()
            .map(|v| (v.start & !(page - 1), v.end.div_ceil(page) * page))
            .collect(),
    );
    let work = subtract(&guest, &proc.bridge.mirror.covered);
    for &(s, e) in &work {
        let mut at = s;
        while at < e {
            match host::region_from(at) {
                Some(r) if r.start <= at => at = r.end,
                next => {
                    let end = next.map_or(e, |r| r.start.min(e));
                    host::reserve(at, end - at, RESERVED_TAG);
                    at = end;
                }
            }
        }
    }
    let m = &mut proc.bridge.mirror;
    let mut all = std::mem::take(&mut m.covered);
    all.extend(work);
    m.covered = merge(all);
}

/// `ranges` sorted and merged where they touch or overlap.
fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if s >= e {
            continue;
        }
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// The parts of `a` outside `b` (both sorted and merged).
fn subtract(a: &[(u64, u64)], b: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut j = 0;
    for &(s, e) in a {
        let mut at = s;
        while j < b.len() && b[j].1 <= at {
            j += 1;
        }
        let mut k = j;
        while at < e {
            match b.get(k) {
                Some(&(bs, be)) if bs < e => {
                    if bs > at {
                        out.push((at, bs));
                    }
                    at = at.max(be);
                    k += 1;
                }
                _ => {
                    out.push((at, e));
                    at = e;
                }
            }
        }
    }
    out
}

/// A shared mapping in the guest of `size` bytes from `offset` of the
/// memory entry a service made, behind host right `object` (`vm_map` of it
/// without a copy): the host memory, and the guest mapping's protections
/// (`cur`, `max` as the guest asked, `VM_PROT_IS_MASK` included). The
/// emulator maps the entry itself (the anchor a host child makes its own
/// entry from), which the bridge does not take for a service's mapping.
pub fn map_service(
    proc: &mut Proc,
    object: Name,
    size: u64,
    offset: u64,
    cur: u32,
    max: u32,
) -> Result<(Arc<SharedObject>, u32, u32), i32> {
    // SAFETY: sysconf takes no pointers.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let size = size.div_ceil(page) * page;
    let (addr, cur, max) = host::map_shared(object, size, offset, cur, max)?;
    let m = &mut proc.bridge.mirror;
    if !m.known.is_empty() {
        m.known.insert((addr, addr + size));
    }
    let prot = max & (vm::VM_PROT_READ | vm::VM_PROT_WRITE) | vm::VM_PROT_READ;
    let name = match host::share_entry(addr, size, prot) {
        Ok(n) => n,
        Err(kr) => {
            host::free(addr, size);
            return Err(kr);
        }
    };
    let mut memory = HostEntry::new(name, addr, size, prot);
    memory.anchor = true;
    let object = SharedObject::host_memory(Arc::new(memory), prot & vm::VM_PROT_WRITE != 0);
    Ok((Arc::new(object), cur, max))
}

/// The host memory behind a mirrored region: a memory entry of the host
/// region at `addr`, remade from the region in a host child (where the
/// parent's right is not the child's).
#[derive(Debug)]
pub struct HostEntry {
    addr: u64,
    size: u64,
    /// `VM_PROT_READ`, with `VM_PROT_WRITE` when the entry allows writes.
    prot: u32,
    /// The region is the emulator's own mapping of a service's entry,
    /// unmapped with it.
    anchor: bool,
    /// The entry's right, and the epoch of the process it belongs to.
    right: Mutex<(u64, Name)>,
}

impl HostEntry {
    fn new(name: Name, addr: u64, size: u64, prot: u32) -> Self {
        HostEntry {
            addr,
            size,
            prot,
            anchor: false,
            right: Mutex::new((super::epoch(), name)),
        }
    }

    /// The entry's right in this process.
    fn name(&self) -> std::io::Result<Name> {
        let mut r = self.right.lock().unwrap();
        if r.0 != super::epoch() {
            let n = host::share_entry(self.addr, self.size, self.prot)
                .map_err(|kr| std::io::Error::other(format!("memory entry: {kr:#x}")))?;
            *r = (super::epoch(), n);
        }
        Ok(r.1)
    }
}

impl Drop for HostEntry {
    fn drop(&mut self) {
        let r = self.right.get_mut().unwrap();
        if r.0 == super::epoch() {
            host::deallocate(r.1);
        }
        // A host child has its own copy of the anchor, as the parent has.
        if self.anchor {
            host::free(self.addr, self.size);
        }
    }
}

impl HostMemory for HostEntry {
    fn size(&self) -> u64 {
        self.size
    }

    unsafe fn map_at(
        &self,
        at: *mut u8,
        offset: u64,
        len: u64,
        writable: bool,
    ) -> std::io::Result<()> {
        let name = self.name()?;
        let prot = if writable {
            self.prot
        } else {
            vm::VM_PROT_READ
        };
        // SAFETY: as the caller promises of `[at, at + len)`.
        let kr = unsafe { host::map_entry_at(at as u64, name, offset, len, prot) };
        if kr != 0 {
            return Err(std::io::Error::other(format!("mach_vm_map: {kr:#x}")));
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        host::read_entry(self.name()?, self.size, offset, buf)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A host memory entry of `len` bytes from `offset` of mirrored host memory
/// `memory`, allowing `prot`.
pub fn sub_entry(
    memory: &Arc<dyn HostMemory>,
    offset: u64,
    len: u64,
    prot: u32,
) -> Result<Name, i32> {
    let Some(e) = memory.as_any().downcast_ref::<HostEntry>() else {
        return Err(crate::user::darwin::mach::kr::KERN_INVALID_ARGUMENT);
    };
    let name = e
        .name()
        .map_err(|_| crate::user::darwin::mach::kr::KERN_INVALID_ARGUMENT)?;
    host::sub_entry(name, offset, len, prot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_merge_and_subtract() {
        assert_eq!(
            merge(vec![(30, 40), (0, 10), (10, 20), (35, 50), (60, 60)]),
            vec![(0, 20), (30, 50)]
        );
        let a = [(0, 100), (200, 300)];
        assert_eq!(subtract(&a, &[]), a.to_vec());
        assert_eq!(
            subtract(&a, &[(10, 20), (90, 210), (250, 260)]),
            vec![(0, 10), (20, 90), (210, 250), (260, 300)]
        );
        assert_eq!(subtract(&a, &[(0, 300)]), vec![]);
        assert_eq!(subtract(&[(5, 15)], &[(0, 5), (15, 20)]), vec![(5, 15)]);
    }

    #[test]
    fn a_service_mapping_is_found_as_a_new_shared_region() {
        // Memory another object shares: a memory entry mapped twice.
        let before: HashSet<(u64, u64)> =
            host::regions().iter().map(|r| (r.start, r.end)).collect();
        let page = 16384;
        let mut a = 0u64;
        // SAFETY: allocates fresh anonymous memory anywhere.
        let kr = unsafe {
            unsafe extern "C" {
                fn mach_vm_allocate(task: Name, addr: *mut u64, size: u64, flags: i32) -> i32;
            }
            mach_vm_allocate(host::task(), &mut a, page, 1)
        };
        assert_eq!(kr, 0);
        let e = host::share_entry(a, page, 3).expect("entry");
        let mut b = 0u64;
        // SAFETY: a fresh mapping anywhere of the entry.
        let kr = unsafe {
            unsafe extern "C" {
                fn mach_vm_map(
                    task: Name,
                    address: *mut u64,
                    size: u64,
                    mask: u64,
                    flags: i32,
                    object: Name,
                    offset: u64,
                    copy: i32,
                    cur: i32,
                    max: i32,
                    inheritance: u32,
                ) -> i32;
            }
            mach_vm_map(host::task(), &mut b, page, 0, 1, e, 0, 0, 3, 3, 1)
        };
        assert_eq!(kr, 0);
        let now = host::regions();
        let r = now.iter().find(|r| r.start == b).expect("the new region");
        assert!(!before.contains(&(r.start, r.end)));
        assert!(matches!(
            r.share_mode,
            host::share::SHARED
                | host::share::TRUESHARED
                | host::share::PRIVATE_ALIASED
                | host::share::SHARED_ALIASED
        ));
        assert_eq!(r.prot, 3);
        // A store through one mapping is seen through a mirror of the other.
        let mirror = HostEntry::new(host::share_entry(b, page, 3).unwrap(), b, page, 3);
        // SAFETY: `a` is the page allocated above.
        unsafe { *(a as *mut u8).add(100) = 0x5a };
        let mut buf = [0u8; 1];
        assert_eq!(mirror.read_at(100, &mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x5a);
        // A service's entry mapped shared: later stores on the service's
        // side are seen, with the protections the entry allows.
        let (anchor, cur, max) = host::map_shared(e, page, 0, 1, 3).expect("mapped");
        assert_eq!((cur, max), (1, 3));
        let shared = HostEntry::new(host::share_entry(anchor, page, 3).unwrap(), anchor, page, 3);
        // SAFETY: `a` is the page allocated above.
        unsafe { *(a as *mut u8).add(200) = 0xa5 };
        assert_eq!(shared.read_at(200, &mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0xa5);
        host::free(anchor, page);
        host::free(a, page);
        host::free(b, page);
        host::deallocate(e);
    }
}
