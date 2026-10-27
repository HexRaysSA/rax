//! Read-only native guest introspection: hardware permission checks are separate.
#[path = "../../../src/backend/hvf/guest_translation.rs"]
mod guest_translation;
use guest_translation::{Paging, PhysicalMemory};
use std::collections::BTreeMap;

#[derive(Default)]
struct Ram {
    bytes: BTreeMap<u64, u8>,
    reads: Vec<(u64, usize)>,
}
impl Ram {
    fn entry(&mut self, addr: u64, value: u64, width: usize) {
        for (i, b) in value.to_le_bytes()[..width].iter().enumerate() {
            self.bytes.insert(addr + i as u64, *b);
        }
    }
}
impl PhysicalMemory for Ram {
    fn contains_ram(&self, addr: u64, size: usize) -> bool {
        (0..size).all(|i| self.bytes.contains_key(&(addr + i as u64)))
    }
    fn read_physical(&mut self, addr: u64, data: &mut [u8]) -> Result<(), String> {
        self.reads.push((addr, data.len()));
        for (i, b) in data.iter_mut().enumerate() {
            *b = *self
                .bytes
                .get(&(addr + i as u64))
                .ok_or_else(|| format!("unmapped physical byte {:#x}", addr + i as u64))?;
        }
        Ok(())
    }
}
fn paging() -> Paging {
    Paging {
        cr0: 1 << 31,
        cr3: 0x1000,
        cr4: 1 << 5,
        efer: (1 << 10) | (1 << 11),
        physical_bits: 40,
        pdpte: [0; 4],
    }
}
fn four_level(v: u64, leaf_shift: u32, leaf: u64) -> (Paging, Ram) {
    let mut r = Ram::default();
    let mut table = 0x1000;
    for shift in [39, 30, 21, 12] {
        let entry = table + ((v >> shift) & 511) * 8;
        if shift == leaf_shift {
            r.entry(entry, leaf | 1 | if shift > 12 { 0x80 } else { 0 }, 8);
            break;
        }
        r.entry(entry, (table + 0x1000) | 1, 8);
        table += 0x1000;
    }
    (paging(), r)
}

#[test]
fn identity_translation_reads_no_tables_and_enforces_physical_width() {
    let mut p = paging();
    p.cr0 = 0;
    p.efer = 0;
    let mut r = Ram::default();
    for a in [0, 1, 0xffff_ffff, (1 << 40) - 1] {
        assert_eq!(p.translate(&mut r, a), Ok(a));
    }
    assert!(p.translate(&mut r, 1 << 40).is_err());
    assert!(r.reads.is_empty());
    for bits in [0, 31, 53, 64] {
        p.physical_bits = bits;
        assert!(p.translate(&mut r, 0).is_err());
    }
}

#[test]
fn four_level_walk_accepts_all_supported_leaf_sizes_without_ad_writes() {
    for v in [0, 0x1234_5678_9abc, 0xffff_ffff_ffff_fabc] {
        for (shift, base) in [(12, 0x1234_5000), (21, 0x2460_0000), (30, 0x4000_0000)] {
            let (p, mut r) = four_level(v, shift, base | if shift > 12 { 1 << 12 } else { 1 << 7 });
            let before = r.bytes.clone();
            assert_eq!(p.translate(&mut r, v), Ok(base | (v & ((1 << shift) - 1))));
            assert_eq!(r.bytes, before);
            assert_eq!(r.reads.len(), ((48 - shift) / 9) as usize);
        }
    }
}

#[test]
fn large_leaf_alignment_and_physical_address_reserved_bits_are_rejected() {
    for shift in [21, 30] {
        let (p, mut r) = four_level(0x1234, shift, 0x4000_0000 | (1 << 13));
        assert!(p.translate(&mut r, 0x1234).is_err());
    }
    let (p, mut r) = four_level(0, 12, 1 << 40);
    assert!(p.translate(&mut r, 0).is_err());
    let (mut p, mut r) = four_level(0, 12, (1 << 63) | 0x5000);
    assert_eq!(p.translate(&mut r, 0), Ok(0x5000));
    p.efer &= !(1 << 11);
    assert!(p.translate(&mut r, 0).is_err());
}

#[test]
fn nonpresent_inaccessible_and_unsupported_modes_cannot_manufacture_addresses() {
    let p = paging();
    let mut r = Ram::default();
    assert!(p.translate(&mut r, 0).is_err());
    r.entry(0x1000, 0x2000, 8);
    assert!(p.translate(&mut r, 0).is_err());
    r.entry(0x1000, 0x2081, 8);
    assert!(p.translate(&mut r, 0).is_err());
    for v in [0x8000_0000_0000, 0xffff_7fff_ffff_ffff] {
        assert!(p.translate(&mut r, v).is_err());
    }
    for cr4 in [0, (1 << 5) | (1 << 12)] {
        let mut q = p;
        q.cr4 = cr4;
        assert!(q.translate(&mut r, 0).is_err());
    }
    let mut q = p;
    q.cr0 = 0;
    assert!(q.translate(&mut r, 0).is_err());
}

#[test]
fn legacy_pae_uses_cached_pdpte_even_when_pdpt_ram_disagrees() {
    for index in 0..4 {
        let v = (index << 30) | 0x1234;
        let mut p = paging();
        p.efer = 1 << 11;
        p.cr3 = 0x8000;
        p.pdpte[index as usize] = 0x2001;
        let mut r = Ram::default();
        r.entry(p.cr3 + index * 8, 0x9001, 8); // Deliberately different; must not read it.
        r.entry(0x2000, 0x3001, 8);
        r.entry(0x3008, 0x1234_5001, 8);
        let before = r.bytes.clone();
        assert_eq!(p.translate(&mut r, v), Ok(0x1234_5234));
        assert_eq!(r.bytes, before);
        assert_eq!(r.reads, [(0x2000, 8), (0x3008, 8)]);
    }
}

#[test]
fn legacy_pae_large_leaves_and_reserved_cached_bits_are_checked() {
    let mut p = paging();
    p.efer = 0;
    p.pdpte[0] = 0x2001;
    let mut r = Ram::default();
    r.entry(0x2000, 0x4000_1081, 8);
    assert_eq!(p.translate(&mut r, 0x1234), Ok(0x4000_1234));
    for bit in [1, 2, 5, 6, 7, 8, 40, 63] {
        let mut q = p;
        q.pdpte[0] |= 1 << bit;
        assert!(q.translate(&mut r, 0x1234).is_err());
    }
    assert!(p.translate(&mut r, 1 << 32).is_err());
}

#[test]
fn legacy_nonpae_walk_and_pse36_large_address_bits_are_exact() {
    let mut p = paging();
    p.efer = 0;
    p.cr4 = 0;
    let mut r = Ram::default();
    r.entry(0x1000, 0x2081, 4); // PDE.PS ignored with PSE0.
    r.entry(0x2004, 0x5678_9081, 4);
    let before = r.bytes.clone();
    assert_eq!(p.translate(&mut r, 0x1234), Ok(0x5678_9234));
    assert_eq!(r.bytes, before);
    p.cr4 = 1 << 4;
    r.entry(0x1000, 0x8040_1081 | (0xab << 13), 4);
    assert_eq!(p.translate(&mut r, 0x1234), Ok(0xab_8040_1234));
    p.physical_bits = 36;
    assert!(p.translate(&mut r, 0x1234).is_err());
    p.physical_bits = 40;
    r.entry(0x1000, 0x8060_0081, 4);
    assert!(p.translate(&mut r, 0x1234).is_err());
    assert!(p.translate(&mut r, 1 << 32).is_err());
}
