pub(crate) mod reservations;

/// Write physical RAM while invalidating registered software exclusive monitors.
/// Raw mmap aliases require callers to provide equivalent writer coordination.
pub fn write_guest_memory(
    memory: &vm_memory::GuestMemoryMmap,
    address: u64,
    bytes: &[u8],
) -> std::result::Result<(), vm_memory::GuestMemoryError> {
    reservations::write(memory, address, bytes)
}

use crate::error::Result;
#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
use kvm_bindings::kvm_userspace_memory_region;
#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
use kvm_ioctls::VmFd;
use tracing::info;
#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
#[cfg(not(all(feature = "kvm", target_os = "linux", target_arch = "x86_64")))]
use vm_memory::{GuestAddress, GuestMemoryMmap};

/// Re-exports of the `vm_memory` types that appear in RAX's public backend API
/// (vCPU construction, physical memory access). External crates such as the C
/// API can name these without taking a direct, version-coupled dependency on
/// `vm_memory`, guaranteeing they use the exact same types as the engine.
pub mod vm {
    pub use vm_memory::{
        Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap,
        GuestMemoryRegion, GuestRegionMmap, MmapRegion,
    };
}

pub const PAGE_SIZE: u64 = 4096;
pub const GUEST_MEMORY_PADDING: u64 = 4 * 1024 * 1024 * 1024u64;
pub const MAX_GUEST_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024u64;

/// Start of the gap for KVM's TSS and identity map (must not be registered as guest memory)
/// This is in the MMIO gap below 4GB. KVM needs space for TSS (3 pages) + identity map pages.
/// We leave a generous gap of 1MB to be safe. Located at 3GB mark to avoid any MMIO conflicts.
pub const KVM_TSS_IDENTITY_GAP_START: u64 = 0xC0000000; // 3GB
/// End of the gap (exclusive) - 1MB gap
pub const KVM_TSS_IDENTITY_GAP_END: u64 = 0xC0100000; // 3GB + 1MB

pub fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    let mask = align - 1;
    (value + mask) & !mask
}

fn checked_align_up(value: u64, align: u64) -> Option<u64> {
    if align == 0 {
        return Some(value);
    }
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|v| v & !mask)
}

pub fn align_down(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value & !(align - 1)
}

pub fn validate_guest_memory_size(size_bytes: u64) -> Result<()> {
    let _ = checked_guest_memory_sizes(size_bytes)?;
    Ok(())
}

fn checked_guest_memory_sizes(size_bytes: u64) -> Result<(u64, u64)> {
    let reported_size = checked_align_up(size_bytes, PAGE_SIZE).ok_or_else(|| {
        crate::error::Error::InvalidConfig("guest memory size overflow".to_string())
    })?;

    if reported_size > MAX_GUEST_MEMORY_BYTES {
        return Err(crate::error::Error::InvalidConfig(format!(
            "guest memory must not exceed {} GiB",
            MAX_GUEST_MEMORY_BYTES >> 30
        )));
    }

    let padded = reported_size
        .checked_add(GUEST_MEMORY_PADDING)
        .ok_or_else(|| {
            crate::error::Error::InvalidConfig("guest memory size overflow".to_string())
        })?;
    let actual_size = checked_align_up(padded, PAGE_SIZE).ok_or_else(|| {
        crate::error::Error::InvalidConfig("guest memory size overflow".to_string())
    })?;

    if actual_size > usize::MAX as u64 {
        return Err(crate::error::Error::InvalidConfig(
            "guest memory does not fit in host address size".to_string(),
        ));
    }

    Ok((reported_size, actual_size))
}

pub struct GuestMemoryWrapper {
    mem: GuestMemoryMmap,
    /// The size reported to the guest via e820
    reported_size: u64,
    /// The actual allocated size (includes reserved backing padding)
    actual_size: u64,
}

impl GuestMemoryWrapper {
    pub fn new(size_bytes: u64) -> Result<Self> {
        let (reported_size, actual_size) = checked_guest_memory_sizes(size_bytes)?;

        // Retain the historical backing allocation independently of the RAM
        // advertised through E820. Extra physical backing does not create a
        // guest virtual mapping: the software MMU always follows guest page
        // tables, including for Linux direct-map addresses.
        info!(
            reported_bytes = reported_size,
            actual_bytes = actual_size,
            padding_bytes = GUEST_MEMORY_PADDING,
            "allocating guest memory with per-CPU padding"
        );
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), actual_size as usize)])?;
        Ok(GuestMemoryWrapper {
            mem,
            reported_size,
            actual_size,
        })
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    pub fn register(&self, vm_fd: &VmFd) -> Result<()> {
        use tracing::debug;

        // Register memory up to (but not past) the KVM TSS/identity gap.
        // KVM's vCPU creation fails with EEXIST if any memory slot is registered
        // at addresses >= the TSS/identity map address. We leave a gap for KVM's
        // internal structures and do NOT register memory above this gap.
        //
        // The backing memory above the gap is still allocated (via mmap), which
        // allows the host to handle any overflow accesses if needed, but KVM
        // won't try to map it as guest RAM.
        let mut slot = 0u32;

        for region in self.mem.iter() {
            let region_start = region.start_addr().raw_value();
            let region_end = region_start + region.len();
            let host_base = region.as_ptr() as u64;

            // Only register memory up to the gap - do NOT register anything at or above it
            let effective_end = region_end.min(KVM_TSS_IDENTITY_GAP_START);

            if region_start >= effective_end {
                // This entire region is at or above the gap, skip it
                debug!(
                    region_start = format!("{:#x}", region_start),
                    region_end = format!("{:#x}", region_end),
                    gap_start = format!("{:#x}", KVM_TSS_IDENTITY_GAP_START),
                    "skipping memory region at/above TSS gap"
                );
                continue;
            }

            let size = effective_end - region_start;
            let host_addr = host_base;

            info!(
                slot,
                guest_start = format!("{:#x}", region_start),
                guest_end = format!("{:#x}", effective_end),
                size = size,
                "registering guest memory"
            );

            let mem_region = kvm_userspace_memory_region {
                slot,
                guest_phys_addr: region_start,
                memory_size: size,
                userspace_addr: host_addr,
                flags: 0,
            };
            debug!(
                slot,
                guest_addr = format!("{:#x}", region_start),
                "calling set_user_memory_region"
            );
            unsafe { vm_fd.set_user_memory_region(mem_region)? };
            debug!(slot, "set_user_memory_region succeeded");

            slot += 1;
        }
        Ok(())
    }

    pub fn memory(&self) -> &GuestMemoryMmap {
        &self.mem
    }

    /// Returns the size reported to the guest via e820.
    /// This is less than the actual allocated size (which includes padding).
    pub fn size(&self) -> u64 {
        self.reported_size
    }

    /// Returns the actual allocated size including padding.
    #[allow(dead_code)]
    pub fn actual_size(&self) -> u64 {
        self.actual_size
    }

    /// Infallible convenience capture of reported RAM (excluding padding).
    /// Panics if complete capture is impossible; checkpoint paths should use
    /// `try_read_all` to return allocation/backing/I/O failures to their caller.
    pub fn read_all(&self) -> Vec<u8> {
        self.try_read_all()
            .expect("failed to capture complete reported guest RAM")
    }

    /// Capture every byte of reported RAM with checked allocation and I/O.
    /// Reserved backing padding is outside the base checkpoint format.
    pub fn try_read_all(&self) -> Result<Vec<u8>> {
        use vm_memory::Bytes;
        let size = usize::try_from(self.reported_size).map_err(|_| {
            crate::error::Error::InvalidConfig(
                "reported RAM does not fit host address size".to_string(),
            )
        })?;
        self.validate_restore_len(size)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|e| {
            crate::error::Error::Emulator(format!("Failed to allocate checkpoint RAM: {e}"))
        })?;
        bytes.resize(size, 0);
        self.mem
            .read_slice(&mut bytes, GuestAddress(0))
            .map_err(|e| {
                crate::error::Error::Emulator(format!("Failed to read checkpoint RAM: {e}"))
            })?;
        Ok(bytes)
    }
    pub(crate) fn validate_restore_len(&self, length: usize) -> Result<()> {
        use vm_memory::GuestMemory;
        if length as u64 != self.reported_size {
            return Err(crate::error::Error::InvalidConfig(format!(
                "checkpoint RAM length mismatch: expected {} bytes, got {}",
                self.reported_size, length
            )));
        }
        if !self.mem.check_range(GuestAddress(0), length) {
            return Err(crate::error::Error::InvalidConfig(
                "checkpoint RAM range is not completely backed".to_string(),
            ));
        }
        Ok(())
    }
    /// Restore exactly the reported RAM extent; reject mismatches before writes.
    pub fn write_all(&self, data: &[u8]) -> Result<()> {
        use vm_memory::Bytes;
        self.validate_restore_len(data.len())?;
        reservations::write(&self.mem, 0, data)
            .map_err(|e| crate::error::Error::Emulator(format!("Failed to write memory: {e}")))
    }
}

/// Linear-address translation supplied by a process-level (user-mode)
/// emulator.
///
/// A vCPU with a flat translation installed does not walk guest paging
/// structures. Each guest linear access is translated by this object, which
/// also enforces per-page read, write, and execute permission, and the
/// returned address indexes the vCPU's guest memory. The translation is
/// consulted one page at a time: `linear` and the returned address share the
/// same offset within the 4 KiB page, so the caller splits page-crossing
/// accesses.
///
/// Implementations must be internally synchronized (`Sync`): several vCPUs of
/// one guest process share a translation.
pub trait FlatTranslation: Send + Sync {
    /// Translates `linear` for an access of kind `access`, returning the
    /// guest-memory address or the fault an ordinary user access would raise.
    fn translate(
        &self,
        linear: u64,
        access: crate::error::MemoryAccessKind,
    ) -> std::result::Result<u64, crate::error::GuestMemoryFault>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallible_capture_and_restore_reject_unbacked_reported_extent() {
        use vm_memory::Bytes;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        mem.write_slice(&[0xa5; 4096], GuestAddress(0)).unwrap();
        let wrapper = GuestMemoryWrapper {
            mem,
            reported_size: 8192,
            actual_size: 4096,
        };
        assert!(wrapper.try_read_all().is_err());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wrapper.read_all())).is_err()
        );
        assert!(wrapper.write_all(&[0x33; 8192]).is_err());
        let mut actual = [0; 4096];
        wrapper
            .mem
            .read_slice(&mut actual, GuestAddress(0))
            .unwrap();
        assert_eq!(actual, [0xa5; 4096]);
    }

    #[test]
    fn align_up_down() {
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_down(4097, 4096), 4096);
    }

    #[test]
    fn guest_memory_size_checks_overflow_before_padding() {
        let err = validate_guest_memory_size(u64::MAX).unwrap_err();
        assert!(err.to_string().contains("guest memory size overflow"));
    }

    #[test]
    fn guest_memory_size_rejects_values_above_cap() {
        let err = validate_guest_memory_size(MAX_GUEST_MEMORY_BYTES + PAGE_SIZE).unwrap_err();
        assert!(err.to_string().contains("guest memory must not exceed"));
    }

    #[test]
    fn guest_memory_size_allows_configured_cap() {
        let (reported, actual) = checked_guest_memory_sizes(MAX_GUEST_MEMORY_BYTES).unwrap();
        assert_eq!(reported, MAX_GUEST_MEMORY_BYTES);
        assert_eq!(actual, MAX_GUEST_MEMORY_BYTES + GUEST_MEMORY_PADDING);
    }
}
