//! Cached physical RAM access and native range admission.
use super::*;

impl Mmu {
    #[inline(always)]
    fn admit_ram_range(&self, _address: u64, _bytes: usize) -> bool {
        #[cfg(windows)]
        {
            // External Windows regions can reserve address space without
            // commitment. Admit the complete span before any cached dereference.
            self.memory
                .get_slice(GuestAddress(_address), _bytes)
                .is_ok()
        }
        #[cfg(not(windows))]
        {
            true
        }
    }
    /// True when `[paddr, paddr+len)` lies entirely within the cached RAM region.
    #[inline(always)]
    pub(super) fn in_ram(&self, paddr: u64, len: usize) -> bool {
        self.ram_len != 0
            && paddr
                .checked_add(len as u64)
                .map_or(false, |end| end <= self.ram_len)
            && self.admit_ram_range(paddr, len)
    }

    /// Host pointer for `[paddr, paddr+LEN)` when it lies wholly within RAM and
    /// outside the LAPIC MMIO window, else `None`.
    ///
    /// Common case is a single comparison: `paddr <= ram_fast_len - LEN`, where
    /// `ram_fast_len` bounds the MMIO-free RAM window, so a pass guarantees the
    /// access is plain RAM. `LEN` is a const so the typed accessors inline to a
    /// bounds-test + pointer read/write. The cold branch handles guests whose
    /// RAM extends past the LAPIC window (access at/above `ram_fast_len`).
    #[inline(always)]
    pub(super) fn ram_ptr<const LEN: u64>(&self, paddr: u64) -> Option<usize> {
        // `checked_sub` yields None when ram_fast_len < LEN (zero/tiny RAM), so an
        // empty or sub-width RAM window can never spuriously pass the bound and
        // hand out a near-null host pointer — the unsafe accessors below rely on
        // this rather than on a non-local invariant (e.g. translate() failing
        // first). For real RAM this is a single compare on the hot path.
        let pointer = match self.ram_fast_len.checked_sub(LEN) {
            Some(bound) if paddr <= bound => Some(self.ram_host_base + paddr as usize),
            _ => self.ram_ptr_high::<LEN>(paddr),
        }?;
        self.admit_ram_range(paddr, LEN as usize).then_some(pointer)
    }

    /// Cold fallback of `ram_ptr` for accesses at or above the fast window:
    /// either above the LAPIC hole (still RAM) or genuinely out of RAM/in MMIO.
    #[cold]
    #[inline(never)]
    fn ram_ptr_high<const LEN: u64>(&self, paddr: u64) -> Option<usize> {
        // Aperture addresses are not RAM: returning None routes the typed
        // accessor through read_phys/write_phys, which dispatch to the bridge.
        if self.in_pci_aperture(paddr) || self.overlaps_ioapic(paddr, LEN) {
            return None;
        }
        match self.ram_len.checked_sub(LEN) {
            Some(bound)
                if paddr <= bound
                    && !(paddr < LAPIC_BASE + LAPIC_SIZE
                        && paddr.wrapping_add(LEN) > LAPIC_BASE) =>
            {
                Some(self.ram_host_base + paddr as usize)
            }
            _ => None,
        }
    }

    /// Read bytes from guest memory (physical address).
    #[inline(always)]
    pub fn read_phys(&self, paddr: u64, buf: &mut [u8]) -> Result<()> {
        if self.read_shared_ioapic(paddr, buf)? {
            return Ok(());
        }
        if self.read_shared_lapic(paddr, buf)? {
            return Ok(());
        }
        // Handle LAPIC MMIO
        if Self::is_lapic_addr(paddr) {
            let offset = paddr - LAPIC_BASE;
            let aligned_offset = offset & !0x3;
            let value = self.lapic.borrow().read(aligned_offset);
            // LAPIC reads are always 32-bit aligned
            match buf.len() {
                1 => {
                    let byte_offset = (offset & 0x3) as usize;
                    buf[0] = ((value >> (byte_offset * 8)) & 0xFF) as u8;
                }
                2 => {
                    let byte_offset = (offset & 0x2) as usize;
                    let word = ((value >> (byte_offset * 8)) & 0xFFFF) as u16;
                    buf[0] = (word & 0xFF) as u8;
                    buf[1] = ((word >> 8) & 0xFF) as u8;
                }
                4 => {
                    buf[0] = (value & 0xFF) as u8;
                    buf[1] = ((value >> 8) & 0xFF) as u8;
                    buf[2] = ((value >> 16) & 0xFF) as u8;
                    buf[3] = ((value >> 24) & 0xFF) as u8;
                }
                8 => {
                    // 64-bit read: read two consecutive 32-bit registers
                    buf[0] = (value & 0xFF) as u8;
                    buf[1] = ((value >> 8) & 0xFF) as u8;
                    buf[2] = ((value >> 16) & 0xFF) as u8;
                    buf[3] = ((value >> 24) & 0xFF) as u8;
                    let value2 = self.lapic.borrow().read(aligned_offset + 0x10);
                    buf[4] = (value2 & 0xFF) as u8;
                    buf[5] = ((value2 >> 8) & 0xFF) as u8;
                    buf[6] = ((value2 >> 16) & 0xFF) as u8;
                    buf[7] = ((value2 >> 24) & 0xFF) as u8;
                }
                _ => buf.fill(0),
            }
            return Ok(());
        }

        // PCI MMIO aperture: route to the device whose BAR covers paddr, else
        // open-bus (0xFF). Trivially skipped when no PCI devices are attached.
        if self.in_pci_aperture(paddr) {
            if let Some(ref pci) = self.pci {
                if let Ok(mut bridge) = pci.lock() {
                    if bridge.mmio_read(paddr, buf) {
                        return Ok(());
                    }
                }
            }
            buf.fill(0xFF);
            return Ok(());
        }

        // Fast path: direct host-pointer copy for in-RAM physical addresses
        // (LAPIC MMIO was already handled above).
        if self.in_ram(paddr, buf.len()) {
            // SAFETY: [paddr, paddr+len) is within the single contiguous RAM mmap
            // region [0, ram_len); ram_host_base is that region's stable host base.
            // `buf` is a caller-owned slice that never aliases guest memory.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (self.ram_host_base + paddr as usize) as *const u8,
                    buf.as_mut_ptr(),
                    buf.len(),
                );
            }
            return Ok(());
        }

        self.memory
            .read_slice(buf, GuestAddress(paddr))
            .map_err(|source| {
                fault::guest_access_fault(MemoryAccessKind::Read, paddr, buf.len(), source)
            })
    }

    /// Write bytes to guest memory (physical address).
    #[inline(always)]
    pub fn write_phys(&self, paddr: u64, buf: &[u8]) -> Result<()> {
        if self.write_shared_ioapic(paddr, buf)? {
            return Ok(());
        }
        if self.write_shared_lapic(paddr, buf)? {
            return Ok(());
        }
        // Handle LAPIC MMIO
        if Self::is_lapic_addr(paddr) {
            let offset = paddr - LAPIC_BASE;
            let aligned_offset = offset & !0x3;
            let value = match buf.len() {
                1 => buf[0] as u32,
                2 => (buf[0] as u32) | ((buf[1] as u32) << 8),
                4 => {
                    (buf[0] as u32)
                        | ((buf[1] as u32) << 8)
                        | ((buf[2] as u32) << 16)
                        | ((buf[3] as u32) << 24)
                }
                8 => {
                    // 64-bit write: write two consecutive 32-bit registers
                    let lo = (buf[0] as u32)
                        | ((buf[1] as u32) << 8)
                        | ((buf[2] as u32) << 16)
                        | ((buf[3] as u32) << 24);
                    let hi = (buf[4] as u32)
                        | ((buf[5] as u32) << 8)
                        | ((buf[6] as u32) << 16)
                        | ((buf[7] as u32) << 24);
                    self.lapic.borrow_mut().write(aligned_offset, lo);
                    self.lapic.borrow_mut().write(aligned_offset + 0x10, hi);
                    return Ok(());
                }
                _ => return Ok(()),
            };
            self.lapic.borrow_mut().write(aligned_offset, value);
            return Ok(());
        }

        // PCI MMIO aperture: route to the device whose BAR covers paddr, else
        // drop the write (open bus). Trivially skipped with no PCI devices.
        if self.in_pci_aperture(paddr) {
            if let Some(ref pci) = self.pci {
                if let Ok(mut bridge) = pci.lock() {
                    bridge.mmio_write(paddr, buf);
                }
            }
            return Ok(());
        }

        // Fast path: direct host-pointer copy for in-RAM physical addresses
        // (LAPIC MMIO was already handled above).
        if self.in_ram(paddr, buf.len()) {
            // SAFETY: [paddr, paddr+len) is within the single contiguous RAM mmap
            // region [0, ram_len); ram_host_base is that region's stable host base.
            // `buf` is a caller-owned slice that never aliases guest memory.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    buf.as_ptr(),
                    (self.ram_host_base + paddr as usize) as *mut u8,
                    buf.len(),
                );
            }
            return Ok(());
        }

        self.memory
            .write_slice(buf, GuestAddress(paddr))
            .map_err(|source| {
                fault::guest_access_fault(MemoryAccessKind::Write, paddr, buf.len(), source)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_ram_accesses_commit_complete_spans_and_remain_visible_to_snapshots() {
        let wrapper = crate::vm::memory::GuestMemoryWrapper::new(65536).unwrap();
        let memory = Arc::new(wrapper.memory().clone());
        let mut mmu = Mmu::new(memory.clone());
        let registers = SystemRegisters::default();
        let mut bytes = [0xff; 8];
        mmu.read_phys(0x4321, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 8]);
        mmu.write_phys(4094, &[1, 2, 3, 4, 5, 6]).unwrap();
        mmu.read_phys(4094, &mut bytes[..6]).unwrap();
        assert_eq!(bytes[..6], [1, 2, 3, 4, 5, 6]);
        mmu.write_u8(0x5001, 0x53, &registers).unwrap();
        mmu.write_u16(0x6002, 0x1234, &registers).unwrap();
        mmu.write_u32(0x7003, 0x12345678, &registers).unwrap();
        mmu.write_u64(0x8fff, 0x123456789abcdef0, &registers)
            .unwrap();
        assert_eq!(mmu.read_u8(0x5001, &registers).unwrap(), 0x53);
        assert_eq!(mmu.read_u16(0x6002, &registers).unwrap(), 0x1234);
        assert_eq!(mmu.read_u32(0x7003, &registers).unwrap(), 0x12345678);
        assert_eq!(
            mmu.read_u64(0x8fff, &registers).unwrap(),
            0x123456789abcdef0
        );
        crate::vm::memory::read_checkpoint_memory(&memory, 0x8fff, &mut bytes).unwrap();
        assert_eq!(bytes, 0x123456789abcdef0u64.to_le_bytes());
    }
}
