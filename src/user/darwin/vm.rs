//! Darwin virtual-memory attributes over the OS-neutral address space.
//!
//! A Mach VM entry carries more than its current protection: a maximum
//! protection that `mprotect`/`vm_protect` may not exceed, an inheritance
//! (what `fork` does with it), and a user tag (`VM_MEMORY_*`, set through
//! `mmap`'s descriptor argument or `vm_allocate`'s flags). They are kept in
//! the VMA's personality flags ([`VmFlags`]).
//!
//! Address selection follows `vm_map_enter` with `VM_FLAGS_ANYWHERE`:
//! first fit, bottom-up, from the map's allocation hint (just above the
//! executable and `dyld`), below the maximum user address.

use crate::user::mm::{AddressSpace, Perms};

/// `VM_PROT_NONE`.
pub const VM_PROT_NONE: u32 = 0;
/// `VM_PROT_READ`.
pub const VM_PROT_READ: u32 = 1;
/// `VM_PROT_WRITE`.
pub const VM_PROT_WRITE: u32 = 2;
/// `VM_PROT_EXECUTE`.
pub const VM_PROT_EXECUTE: u32 = 4;
/// `VM_PROT_DEFAULT`: read and write.
pub const VM_PROT_DEFAULT: u32 = VM_PROT_READ | VM_PROT_WRITE;
/// `VM_PROT_ALL`.
pub const VM_PROT_ALL: u32 = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;

/// `VM_INHERIT_SHARE`.
pub const VM_INHERIT_SHARE: u32 = 0;
/// `VM_INHERIT_COPY` (the default).
pub const VM_INHERIT_COPY: u32 = 1;
/// `VM_INHERIT_NONE`.
pub const VM_INHERIT_NONE: u32 = 2;

/// `VM_MEMORY_MALLOC`.
pub const VM_MEMORY_MALLOC: u32 = 1;
/// `VM_MEMORY_STACK`.
pub const VM_MEMORY_STACK: u32 = 30;
/// `VM_MEMORY_DYLD`.
pub const VM_MEMORY_DYLD: u32 = 60;
/// `VM_MEMORY_SHARED_PMAP`.
pub const VM_MEMORY_SHARED_PMAP: u32 = 32;

/// Effective page permissions for a VM protection.
pub fn perms(prot: u32) -> Perms {
    let mut p = Perms::empty();
    if prot & VM_PROT_READ != 0 {
        p |= Perms::READ;
    }
    if prot & VM_PROT_WRITE != 0 {
        p |= Perms::WRITE;
    }
    if prot & VM_PROT_EXECUTE != 0 {
        p |= Perms::EXEC;
    }
    p
}

/// The VM protection of page permissions.
pub fn prot(perms: Perms) -> u32 {
    let mut p = 0;
    if perms.contains(Perms::READ) {
        p |= VM_PROT_READ;
    }
    if perms.contains(Perms::WRITE) {
        p |= VM_PROT_WRITE;
    }
    if perms.contains(Perms::EXEC) {
        p |= VM_PROT_EXECUTE;
    }
    p
}

/// The Mach attributes a VMA carries in its personality flags: bits 0-2
/// the maximum protection, bits 4-5 the inheritance, bits 8-15 the user
/// tag, bit 16 set when the entry is part of the shared region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmFlags(u32);

impl VmFlags {
    /// Attributes with `max` protection, `inheritance`, and `tag`.
    pub fn new(max: u32, inheritance: u32, tag: u32) -> Self {
        VmFlags((max & VM_PROT_ALL) | ((inheritance & 3) << 4) | ((tag & 0xff) << 8))
    }

    /// Decodes a VMA's flags.
    pub fn from_bits(bits: u32) -> Self {
        VmFlags(bits)
    }

    /// The encoded flags.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Maximum protection.
    pub fn max_prot(self) -> u32 {
        self.0 & VM_PROT_ALL
    }

    /// Inheritance.
    pub fn inheritance(self) -> u32 {
        (self.0 >> 4) & 3
    }

    /// User tag.
    pub fn tag(self) -> u32 {
        (self.0 >> 8) & 0xff
    }

    /// Whether the entry belongs to the shared region.
    pub fn shared_region(self) -> bool {
        self.0 & (1 << 16) != 0
    }

    /// These attributes marked as part of the shared region.
    pub fn in_shared_region(self) -> Self {
        VmFlags(self.0 | (1 << 16))
    }

    /// These attributes with another maximum protection.
    pub fn with_max_prot(self, max: u32) -> Self {
        VmFlags((self.0 & !VM_PROT_ALL) | (max & VM_PROT_ALL))
    }

    /// These attributes with another inheritance.
    pub fn with_inheritance(self, inheritance: u32) -> Self {
        VmFlags((self.0 & !(3 << 4)) | ((inheritance & 3) << 4))
    }
}

/// Where a process may map memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmLayout {
    /// The lowest mappable address (the end of page zero).
    pub min: u64,
    /// The allocation hint anywhere-allocations search up from.
    pub hint: u64,
    /// One past the highest mappable address (`MACH_VM_MAX_ADDRESS`).
    pub max: u64,
    /// The allocation granule (the user page size).
    pub page: u64,
}

impl VmLayout {
    /// Rounds `len` up to a page; `None` when it overflows or is zero.
    pub fn round(&self, len: u64) -> Option<u64> {
        let r = len.checked_add(self.page - 1)? & !(self.page - 1);
        (r != 0).then_some(r)
    }

    /// Whether `addr` is page-aligned.
    pub fn aligned(&self, addr: u64) -> bool {
        addr & (self.page - 1) == 0
    }

    /// A free range of `len` bytes aligned to `align` (at least a page):
    /// first fit from the hint up, then from the minimum up to the hint.
    pub fn find_space(&self, space: &AddressSpace, len: u64, align: u64) -> Option<u64> {
        let align = align.max(self.page);
        space
            .find_free_bottom_up(len, align, self.hint, self.max)
            .or_else(|| space.find_free_bottom_up(len, align, self.min, self.hint.min(self.max)))
    }

    /// Whether `[addr, addr + len)` lies in the mappable range.
    pub fn contains(&self, addr: u64, len: u64) -> bool {
        addr >= self.min && addr.checked_add(len).is_some_and(|e| e <= self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_round_trip() {
        let f = VmFlags::new(VM_PROT_ALL, VM_INHERIT_NONE, VM_MEMORY_STACK);
        assert_eq!(f.max_prot(), VM_PROT_ALL);
        assert_eq!(f.inheritance(), VM_INHERIT_NONE);
        assert_eq!(f.tag(), VM_MEMORY_STACK);
        assert!(!f.shared_region());
        let g = f
            .in_shared_region()
            .with_max_prot(VM_PROT_READ)
            .with_inheritance(VM_INHERIT_SHARE);
        assert!(g.shared_region());
        assert_eq!(g.max_prot(), VM_PROT_READ);
        assert_eq!(g.inheritance(), VM_INHERIT_SHARE);
        assert_eq!(g.tag(), VM_MEMORY_STACK);
        assert_eq!(VmFlags::from_bits(g.bits()), g);
    }

    #[test]
    fn protections_convert() {
        for p in 0..8 {
            assert_eq!(prot(perms(p)), p);
        }
    }

    #[test]
    fn layout_rounds_to_pages() {
        let l = VmLayout {
            min: 1 << 32,
            hint: (1 << 32) + 0x10_0000,
            max: 0x7fff_fe00_0000,
            page: 0x4000,
        };
        assert_eq!(l.round(1), Some(0x4000));
        assert_eq!(l.round(0x4000), Some(0x4000));
        assert_eq!(l.round(0), None);
        assert_eq!(l.round(u64::MAX), None);
        assert!(l.aligned(0x8000));
        assert!(!l.aligned(0x1000));
        assert!(l.contains(1 << 32, 0x4000));
        assert!(!l.contains(0, 0x4000));
    }
}
