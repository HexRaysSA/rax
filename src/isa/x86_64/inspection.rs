//! Nonmutating x86 linear translation for debugger and native exit inspection.
//! Guest privilege checks are separate; this never sets A/D bits or fills a TLB.

pub(crate) trait PhysicalMemory {
    fn contains_ram(&self, address: u64, size: usize) -> bool;
    fn read_physical(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Paging {
    pub(crate) cr0: u64,
    pub(crate) cr3: u64,
    pub(crate) cr4: u64,
    pub(crate) efer: u64,
    pub(crate) physical_bits: u32,
    /// Processor-cached legacy PAE PDPTEs, not a new read of guest PDPT RAM.
    pub(crate) pdpte: [u64; 4],
}

fn read_entry<M: PhysicalMemory>(memory: &mut M, address: u64, wide: bool) -> Result<u64, String> {
    let mut bytes = [0; 8];
    memory.read_physical(address, &mut bytes[..if wide { 8 } else { 4 }])?;
    Ok(u64::from_le_bytes(bytes))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LegacyFeatures {
    pub(crate) pse36: bool,
    pub(crate) pat: bool,
}
impl Paging {
    fn address_mask(self) -> Result<u64, String> {
        if !(32..=52).contains(&self.physical_bits) {
            return Err("unsupported HVF physical-address width".into());
        }
        Ok(((1u64 << self.physical_bits) - 1) & !0xfff)
    }

    fn wide_entry(self, entry: u64) -> Result<u64, String> {
        if entry & 1 == 0 {
            return Err("nonpresent guest page-table entry during HVF inspection".into());
        }
        let mask = self.address_mask()?;
        if entry & 0x000f_ffff_ffff_f000 & !mask != 0
            || (self.efer & (1 << 11) == 0 && entry >> 63 != 0)
        {
            return Err("reserved guest page-table address/NX bits during HVF inspection".into());
        }
        Ok(entry & mask)
    }

    fn leaf(self, entry: u64, linear: u64, shift: u32) -> Result<u64, String> {
        let base = self.wide_entry(entry)?;
        let offset = (1u64 << shift) - 1;
        // Bit12 is PAT in a large leaf; the remaining low address bits are reserved.
        if shift > 12 && base & offset & !(1 << 12) != 0 {
            return Err("misaligned large guest page during HVF inspection".into());
        }
        Ok((base & !offset) | (linear & offset))
    }

    pub(crate) fn translate<M: PhysicalMemory>(
        self,
        memory: &mut M,
        linear: u64,
    ) -> Result<u64, String> {
        self.translate_with_legacy(
            memory,
            linear,
            LegacyFeatures {
                pse36: true,
                pat: true,
            },
        )
    }

    pub(crate) fn translate_with_legacy<M: PhysicalMemory>(
        self,
        memory: &mut M,
        linear: u64,
        features: LegacyFeatures,
    ) -> Result<u64, String> {
        let mask = self.address_mask()?;
        if self.cr0 & (1 << 31) == 0 {
            if self.efer & (1 << 10) != 0 {
                return Err("inconsistent guest LMA/PG state".into());
            }
            if linear & !(mask | 0xfff) != 0 {
                return Err("guest physical address exceeds configured width".into());
            }
            return Ok(linear);
        }
        if self.efer & (1 << 10) != 0 {
            if self.cr4 & (1 << 5) == 0 || self.cr4 & (1 << 12) != 0 {
                return Err(
                    "unsupported HVF guest paging mode (requires four-level IA-32e)".into(),
                );
            }
            if ((linear << 16) as i64 >> 16) as u64 != linear {
                return Err("noncanonical guest linear address during HVF inspection".into());
            }
            let mut table = self.cr3 & mask;
            for shift in [39, 30, 21, 12] {
                let entry = read_entry(memory, table + ((linear >> shift) & 511) * 8, true)?;
                let base = self.wide_entry(entry)?;
                if shift == 12 || (matches!(shift, 30 | 21) && entry & 0x80 != 0) {
                    return self.leaf(entry, linear, shift);
                }
                if shift == 39 && entry & 0x80 != 0 {
                    return Err("reserved PS in guest PML4 entry".into());
                }
                table = base;
            }
        } else if self.cr4 & (1 << 5) != 0 {
            if linear > u64::from(u32::MAX) {
                return Err("legacy PAE linear address exceeds32 bits".into());
            }
            let cached = self.pdpte[(linear >> 30) as usize];
            let mut table = self.wide_entry(cached)?;
            if cached & (0x1e6 | (1 << 63)) != 0 {
                return Err("reserved cached legacy PAE PDPTE bits".into());
            }
            for shift in [21, 12] {
                let entry = read_entry(memory, table + ((linear >> shift) & 511) * 8, true)?;
                let base = self.wide_entry(entry)?;
                if shift == 12 || entry & 0x80 != 0 {
                    return self.leaf(entry, linear, shift);
                }
                table = base;
            }
        } else {
            if linear > u64::from(u32::MAX) {
                return Err("legacy linear address exceeds32 bits".into());
            }
            let mut table = self.cr3 & 0xffff_f000;
            for shift in [22, 12] {
                let entry = read_entry(memory, table + ((linear >> shift) & 1023) * 4, false)?;
                if entry & 1 == 0 {
                    return Err("nonpresent legacy guest page-table entry".into());
                }
                if shift == 22 && self.cr4 & (1 << 4) != 0 && entry & 0x80 != 0 {
                    // PSE-36: PDE20:13 supply PA39:32; PDE21 is reserved.
                    if entry & (1 << 21) != 0 {
                        return Err("reserved legacy large-page bit21".into());
                    }
                    if (!features.pse36 && entry & 0x001f_e000 != 0)
                        || (!features.pat && entry & (1 << 12) != 0)
                    {
                        return Err(
                            "unsupported legacy large-page address/PAT bits during inspection"
                                .into(),
                        );
                    }
                    let base = (entry & 0xffc0_0000) | ((entry & 0x001f_e000) << 19);
                    if base & !mask != 0 {
                        return Err("legacy large-page address exceeds configured width".into());
                    }
                    return Ok(base | (linear & 0x3f_ffff));
                }
                if shift == 12 {
                    if self.cr4 & (1 << 4) != 0 && !features.pat && entry & (1 << 7) != 0 {
                        return Err("unsupported legacy PTE PAT bit during inspection".into());
                    }
                    return Ok((entry & 0xffff_f000) | (linear & 0xfff));
                }
                table = entry & 0xffff_f000;
            }
        }
        Err("incomplete guest translation during HVF inspection".into())
    }
}
