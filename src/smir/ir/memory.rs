//! SMIR memory interface.
//!
//! This module defines the memory trait for SMIR execution and related types.

use crate::smir::ir::types::*;

#[path = "endian_atomic.rs"]
mod endian_atomic;
#[path = "packet_memory.rs"]
mod packet_memory;
pub use packet_memory::{PacketCommitError, PacketWrite};

// ============================================================================
// Memory Error
// ============================================================================

/// Memory access error
#[derive(Clone, Debug)]
pub enum MemoryError {
    /// Page fault (page not present)
    PageFault {
        addr: GuestAddr,
        write: bool,
        user: bool,
    },

    /// Access violation (permission denied)
    AccessViolation { addr: GuestAddr, write: bool },

    /// Alignment fault
    Alignment { addr: GuestAddr, required: usize },

    /// MMIO region (needs special handling)
    Mmio { addr: GuestAddr, size: usize },

    /// Exclusive monitor failure
    ExclusiveFailed,

    /// Address out of bounds
    OutOfBounds { addr: GuestAddr },
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryError::PageFault { addr, write, user } => {
                write!(
                    f,
                    "page fault at {:#x} ({}, {})",
                    addr,
                    if *write { "write" } else { "read" },
                    if *user { "user" } else { "kernel" }
                )
            }
            MemoryError::AccessViolation { addr, write } => {
                write!(
                    f,
                    "access violation at {:#x} ({})",
                    addr,
                    if *write { "write" } else { "read" }
                )
            }
            MemoryError::Alignment { addr, required } => {
                write!(
                    f,
                    "alignment fault at {:#x} (required {} bytes)",
                    addr, required
                )
            }
            MemoryError::Mmio { addr, size } => {
                write!(f, "MMIO access at {:#x} ({} bytes)", addr, size)
            }
            MemoryError::ExclusiveFailed => write!(f, "exclusive monitor failed"),
            MemoryError::OutOfBounds { addr } => write!(f, "address out of bounds: {:#x}", addr),
        }
    }
}

impl std::error::Error for MemoryError {}

// ============================================================================
// Memory Trait
// ============================================================================

/// Memory interface for SMIR execution
pub trait SmirMemory: Send {
    /// Optional authoritative source-page GP lookup at this guest instruction.
    /// A translated backend may return an exact instruction-fetch fault.
    fn aarch64_instruction_guarded(
        &mut self,
        _pc: u64,
        _state: &crate::smir::ir::context::Aarch64RegState,
    ) -> Option<Result<bool, crate::isa::arm::common::cpu::ArmError>> {
        None
    }

    /// Optional architectural AArch64 data-access bridge. Implementations that
    /// translate guest addresses return the exact CPU fault, including stage,
    /// access and fault class. `None` means this backend has no such bridge;
    /// callers must decline translated accesses before performing memory I/O.
    fn aarch64_load64(
        &mut self,
        _address: u64,
        _state: &crate::smir::ir::context::Aarch64RegState,
    ) -> Option<Result<u64, crate::isa::arm::common::cpu::ArmError>> {
        None
    }

    /// Guest-order RMW. Big-endian arithmetic uses a CAS loop over the
    /// backend's indivisible little-endian atomic primitives.
    fn atomic_rmw_endian(
        &mut self,
        addr: GuestAddr,
        op: AtomicOp,
        operand: u64,
        size: MemWidth,
        order: MemoryOrder,
        endian: Endian,
    ) -> Result<u64, MemoryError> {
        endian_atomic::rmw(self, addr, op, operand, size, order, endian)
    }

    /// Guest-order compare/exchange with a write-permission check on failure.
    #[allow(clippy::too_many_arguments)]
    fn compare_and_swap_endian(
        &mut self,
        addr: GuestAddr,
        expected: u64,
        new: u64,
        size: MemWidth,
        success_order: MemoryOrder,
        failure_order: MemoryOrder,
        endian: Endian,
    ) -> Result<(u64, bool), MemoryError> {
        endian_atomic::compare_exchange(
            self,
            addr,
            expected,
            new,
            size,
            success_order,
            failure_order,
            endian,
        )
    }

    /// Read bytes from memory
    fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError>;

    /// Write bytes to memory
    fn write(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), MemoryError>;

    /// Preflight a data write. Packet-capable backends should preserve the
    /// fault-address convention of write(), which can differ from a range probe.
    fn probe_write(&self, addr: GuestAddr, size: usize) -> Result<(), MemoryError> {
        self.probe(addr, size, true)
    }

    /// Publish a complete write set, or return an error without changing any
    /// byte. Backends must opt in to this contract; probing individual stores
    /// does not guarantee that later callback-backed writes cannot fail.
    fn write_packet(&mut self, writes: &[PacketWrite]) -> Result<(), PacketCommitError> {
        if writes.is_empty() {
            Ok(())
        } else {
            Err(PacketCommitError::Unsupported)
        }
    }

    /// Atomic load
    fn atomic_load(
        &mut self,
        addr: GuestAddr,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<u64, MemoryError>;

    /// Atomic store
    fn atomic_store(
        &mut self,
        addr: GuestAddr,
        value: u64,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), MemoryError>;

    /// Atomic compare-and-swap
    fn compare_and_swap(
        &mut self,
        addr: GuestAddr,
        expected: u64,
        new: u64,
        size: MemWidth,
        success_order: MemoryOrder,
        failure_order: MemoryOrder,
    ) -> Result<(u64, bool), MemoryError>;

    /// Compare-and-swap with an architecturally observable write cycle on
    /// both success and failure, as required by CMPXCHG8B. Concurrent memory
    /// implementations should override this to keep the transaction
    /// indivisible across the failure writeback.
    fn compare_and_swap_writeback(
        &mut self,
        addr: GuestAddr,
        expected: u64,
        new: u64,
        size: MemWidth,
        success_order: MemoryOrder,
        failure_order: MemoryOrder,
    ) -> Result<(u64, bool), MemoryError> {
        let (old, success) =
            self.compare_and_swap(addr, expected, new, size, success_order, failure_order)?;
        if !success {
            self.atomic_store(addr, old, size, success_order)?;
        }
        Ok((old, success))
    }

    /// Atomic 128-bit compare-and-swap used by CMPXCHG16B. Concurrent memory
    /// backends should override this default with one indivisible transaction;
    /// the default preserves functional semantics for single-threaded models.
    fn compare_and_swap_128(
        &mut self,
        addr: GuestAddr,
        expected: [u64; 2],
        new: [u64; 2],
        _success_order: MemoryOrder,
        _failure_order: MemoryOrder,
    ) -> Result<([u64; 2], bool), MemoryError> {
        let mut bytes = [0u8; 16];
        self.read(addr, &mut bytes)?;
        let old = [
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        ];
        let success = old == expected;
        let written = if success { new } else { old };
        bytes[0..8].copy_from_slice(&written[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&written[1].to_le_bytes());
        self.write(addr, &bytes)?;
        Ok((old, success))
    }

    /// Atomic 128-bit compare-and-swap without a failure writeback.
    /// Concurrent memory backends should override this default with one
    /// indivisible transaction; the default is exact for single-threaded
    /// memory and performs a write only when both expected words match.
    fn compare_and_swap_pair(
        &mut self,
        addr: GuestAddr,
        expected: [u64; 2],
        new: [u64; 2],
        _success_order: MemoryOrder,
        _failure_order: MemoryOrder,
    ) -> Result<([u64; 2], bool), MemoryError> {
        let mut bytes = [0u8; 16];
        self.read(addr, &mut bytes)?;
        let old = [
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        ];
        let success = old == expected;
        if success {
            bytes[..8].copy_from_slice(&new[0].to_le_bytes());
            bytes[8..].copy_from_slice(&new[1].to_le_bytes());
            self.write(addr, &bytes)?;
        }
        Ok((old, success))
    }

    /// Atomic read-modify-write
    fn atomic_rmw(
        &mut self,
        addr: GuestAddr,
        op: AtomicOp,
        operand: u64,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<u64, MemoryError>;

    /// Load-linked / Load-exclusive
    fn load_exclusive(&mut self, addr: GuestAddr, size: MemWidth) -> Result<u64, MemoryError>;

    /// Store-conditional / Store-exclusive (returns true if succeeded)
    fn store_exclusive(
        &mut self,
        addr: GuestAddr,
        value: u64,
        size: MemWidth,
    ) -> Result<bool, MemoryError>;

    /// Clear exclusive monitor
    fn clear_exclusive(&mut self);

    /// Memory fence
    fn fence(&mut self, kind: FenceKind);

    /// Prefetch hint (optional, default is no-op)
    fn prefetch(&mut self, _addr: GuestAddr, _write: bool) {
        // Default: no-op
    }

    /// Invalidate cached address translations for the page containing `addr`.
    ///
    /// Flat or already-physical memory models need no action. Translated
    /// implementations may override this hook to discard TLB, page-walk, or
    /// equivalent cached mappings. The operation itself performs no memory
    /// access and therefore cannot report a memory fault.
    fn invalidate_translation(&mut self, _addr: GuestAddr) {
        // Default: no translation cache.
    }

    /// Invalidate cached translations according to one x86 INVPCID request.
    ///
    /// `invpcid_type` is in the architecturally defined range 0 through 3,
    /// `pcid` contains descriptor bits 11:0, and `linear` contains descriptor
    /// bits 127:64. Implementations may conservatively invalidate additional
    /// translations, including their complete translation cache. Flat or
    /// already-physical memory models need no action.
    fn invalidate_process_context(&mut self, _invpcid_type: u8, _pcid: u16, _linear: GuestAddr) {
        // Default: no translation cache.
    }

    /// Check if address range is valid
    fn probe(&self, addr: GuestAddr, size: usize, write: bool) -> Result<(), MemoryError>;
}

/// Memory reader interface for lifting (read-only)
pub trait MemoryReader: Send + Sync {
    fn read(&self, addr: GuestAddr, size: usize) -> Result<Vec<u8>, MemoryError>;
}

// ============================================================================
// Simple Memory Implementation
// ============================================================================

/// Simple flat memory implementation for testing
pub struct FlatMemory {
    /// Memory contents
    data: Vec<u8>,
    /// Base address
    base: GuestAddr,
    /// Exclusive monitor address
    exclusive_addr: Option<GuestAddr>,
    /// Exclusive monitor size
    exclusive_size: MemWidth,
}

impl FlatMemory {
    /// Create new flat memory with given size
    pub fn new(size: usize) -> Self {
        FlatMemory {
            data: vec![0; size],
            base: 0,
            exclusive_addr: None,
            exclusive_size: MemWidth::B8,
        }
    }

    /// Create new flat memory with given base address and size
    pub fn with_base(base: GuestAddr, size: usize) -> Self {
        FlatMemory {
            data: vec![0; size],
            base,
            exclusive_addr: None,
            exclusive_size: MemWidth::B8,
        }
    }

    /// Get offset from address
    fn offset(&self, addr: GuestAddr) -> Result<usize, MemoryError> {
        let off = addr
            .checked_sub(self.base)
            .filter(|off| *off < self.data.len() as u64)
            .ok_or(MemoryError::OutOfBounds { addr })?;
        Ok(off as usize)
    }

    /// Exclusive end offset of a `len`-byte access starting at offset `off`
    /// (address `addr`). Bounds use checked u64 arithmetic because guest
    /// addresses span the full 2^64-byte space; an access beyond the store
    /// reports its wrapped end address, as before.
    fn end(&self, off: usize, addr: GuestAddr, len: usize) -> Result<usize, MemoryError> {
        (off as u64)
            .checked_add(len as u64)
            .filter(|end| *end <= self.data.len() as u64)
            .map(|end| end as usize)
            .ok_or(MemoryError::OutOfBounds {
                addr: addr.wrapping_add(len as u64),
            })
    }

    /// Load the memory with initial data
    pub fn load(&mut self, offset: usize, data: &[u8]) {
        let end = offset + data.len();
        if end <= self.data.len() {
            self.data[offset..end].copy_from_slice(data);
        }
    }
}

impl SmirMemory for FlatMemory {
    fn probe_write(&self, addr: GuestAddr, size: usize) -> Result<(), MemoryError> {
        let start = self.offset(addr)?;
        self.end(start, addr, size).map(|_| ())
    }

    fn write_packet(&mut self, writes: &[PacketWrite]) -> Result<(), PacketCommitError> {
        self.publish_packet(writes)
    }

    fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        let off = self.offset(addr)?;
        let end = self.end(off, addr, buf.len())?;
        buf.copy_from_slice(&self.data[off..end]);
        Ok(())
    }

    fn write(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), MemoryError> {
        let off = self.offset(addr)?;
        let end = self.end(off, addr, data.len())?;
        self.data[off..end].copy_from_slice(data);

        // A write overlapping the monitored range clears the reservation.
        // Ranges are compared in u128 because a valid access may end at 2^64.
        if let Some(excl_addr) = self.exclusive_addr {
            let excl_start = u128::from(excl_addr);
            let excl_end = excl_start + self.exclusive_size.bytes() as u128;
            let write_start = u128::from(addr);
            let write_end = write_start + data.len() as u128;
            if !(write_end <= excl_start || write_start >= excl_end) {
                self.exclusive_addr = None;
            }
        }

        Ok(())
    }

    fn atomic_load(
        &mut self,
        addr: GuestAddr,
        size: MemWidth,
        _order: MemoryOrder,
    ) -> Result<u64, MemoryError> {
        let mut buf = [0u8; 8];
        let bytes = size.bytes() as usize;
        self.read(addr, &mut buf[..bytes])?;
        Ok(u64::from_le_bytes(buf))
    }

    fn atomic_store(
        &mut self,
        addr: GuestAddr,
        value: u64,
        size: MemWidth,
        _order: MemoryOrder,
    ) -> Result<(), MemoryError> {
        let bytes = value.to_le_bytes();
        self.write(addr, &bytes[..size.bytes() as usize])
    }

    fn compare_and_swap(
        &mut self,
        addr: GuestAddr,
        expected: u64,
        new: u64,
        size: MemWidth,
        _success_order: MemoryOrder,
        _failure_order: MemoryOrder,
    ) -> Result<(u64, bool), MemoryError> {
        let old = self.atomic_load(addr, size, MemoryOrder::SeqCst)?;
        let mask = match size {
            MemWidth::B1 => 0xFF,
            MemWidth::B2 => 0xFFFF,
            MemWidth::B4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        };
        if (old & mask) == (expected & mask) {
            self.atomic_store(addr, new, size, MemoryOrder::SeqCst)?;
            Ok((old, true))
        } else {
            Ok((old, false))
        }
    }

    fn atomic_rmw(
        &mut self,
        addr: GuestAddr,
        op: AtomicOp,
        operand: u64,
        size: MemWidth,
        _order: MemoryOrder,
    ) -> Result<u64, MemoryError> {
        let old = self.atomic_load(addr, size, MemoryOrder::SeqCst)?;
        // Operate at the access width: mask both operands, and for signed
        // min/max sign-extend from `size` bits so e.g. AMOMAX.W compares the
        // 32-bit values as signed (not the zero-extended 64-bit values).
        let bits = size.bytes() * 8;
        let mask = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let o = operand & mask;
        let old_m = old & mask;
        let sext = |v: u64| -> i64 {
            if bits >= 64 {
                v as i64
            } else {
                ((v << (64 - bits)) as i64) >> (64 - bits)
            }
        };
        let new = match op {
            AtomicOp::Add => old_m.wrapping_add(o),
            AtomicOp::Sub => old_m.wrapping_sub(o),
            AtomicOp::Neg => 0u64.wrapping_sub(old_m),
            AtomicOp::And => old_m & o,
            AtomicOp::Or => old_m | o,
            AtomicOp::Xor => old_m ^ o,
            AtomicOp::Nand => !(old_m & o),
            AtomicOp::Max => std::cmp::max(sext(old_m), sext(o)) as u64,
            AtomicOp::Min => std::cmp::min(sext(old_m), sext(o)) as u64,
            AtomicOp::Umax => std::cmp::max(old_m, o),
            AtomicOp::Umin => std::cmp::min(old_m, o),
            AtomicOp::Swap => o,
        } & mask;
        self.atomic_store(addr, new, size, MemoryOrder::SeqCst)?;
        Ok(old_m)
    }

    fn load_exclusive(&mut self, addr: GuestAddr, size: MemWidth) -> Result<u64, MemoryError> {
        let val = self.atomic_load(addr, size, MemoryOrder::Acquire)?;
        self.exclusive_addr = Some(addr);
        self.exclusive_size = size;
        Ok(val)
    }

    fn store_exclusive(
        &mut self,
        addr: GuestAddr,
        value: u64,
        size: MemWidth,
    ) -> Result<bool, MemoryError> {
        let success = self.exclusive_addr == Some(addr) && self.exclusive_size == size;
        if success {
            self.atomic_store(addr, value, size, MemoryOrder::Release)?;
        }
        self.exclusive_addr = None;
        Ok(success)
    }

    fn clear_exclusive(&mut self) {
        self.exclusive_addr = None;
    }

    fn fence(&mut self, _kind: FenceKind) {
        // No-op for single-threaded interpreter
    }

    fn probe(&self, addr: GuestAddr, size: usize, _write: bool) -> Result<(), MemoryError> {
        self.span(addr, size).map(|_| ())
    }
}

impl FlatMemory {
    /// Offset range of an access for `probe` and code fetch, which report
    /// the start address below the base and the end address beyond the store.
    fn span(&self, addr: GuestAddr, size: usize) -> Result<std::ops::Range<usize>, MemoryError> {
        let off = addr
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds { addr })?;
        let end = off
            .checked_add(size as u64)
            .filter(|end| *end <= self.data.len() as u64)
            .ok_or(MemoryError::OutOfBounds {
                addr: addr.wrapping_add(size as u64),
            })?;
        Ok(off as usize..end as usize)
    }
}

impl MemoryReader for FlatMemory {
    fn read(&self, addr: GuestAddr, size: usize) -> Result<Vec<u8>, MemoryError> {
        let span = self.span(addr, size)?;
        Ok(self.data[span].to_vec())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check alignment for memory access
pub fn check_alignment(addr: GuestAddr, size: MemWidth, strict: bool) -> Result<(), MemoryError> {
    let required = if strict {
        size.bytes() as u64
    } else {
        (size.bytes() as u64).min(8)
    };

    if required > 1 && addr % required != 0 {
        Err(MemoryError::Alignment {
            addr,
            required: required as usize,
        })
    } else {
        Ok(())
    }
}

/// Convert bytes to u64 with specified endianness
pub fn bytes_to_u64(bytes: &[u8], endian: Endian) -> u64 {
    let mut arr = [0u8; 8];
    let len = bytes.len().min(8);
    arr[..len].copy_from_slice(&bytes[..len]);
    match endian {
        Endian::Little => u64::from_le_bytes(arr),
        Endian::Big => u64::from_be_bytes(arr),
    }
}

/// Convert u64 to bytes with specified endianness
pub fn u64_to_bytes(value: u64, endian: Endian) -> [u8; 8] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

// ============================================================================
// Exclusive Monitor
// ============================================================================

/// Exclusive monitor state for ARM LL/SC emulation
#[derive(Clone, Debug, Default)]
pub struct ExclusiveMonitor {
    /// Address being monitored (None if no exclusive)
    pub addr: Option<GuestAddr>,
    /// Size of exclusive region
    pub size: MemWidth,
    /// Value loaded (for comparison on store)
    pub value: u64,
}

impl ExclusiveMonitor {
    /// Create a new monitor
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark exclusive access (LDXR)
    pub fn mark_exclusive(&mut self, addr: GuestAddr, size: MemWidth, value: u64) {
        self.addr = Some(addr);
        self.size = size;
        self.value = value;
    }

    /// Check if exclusive is still valid for this address
    pub fn check_exclusive(&self, addr: GuestAddr, size: MemWidth) -> bool {
        match self.addr {
            Some(excl_addr) => excl_addr == addr && self.size == size,
            None => false,
        }
    }

    /// Clear exclusive monitor
    pub fn clear(&mut self) {
        self.addr = None;
    }

    /// Check if a store to this address should clear the monitor
    pub fn should_clear_for_store(&self, addr: GuestAddr, size: usize) -> bool {
        if let Some(excl_addr) = self.addr {
            let excl_end = excl_addr + self.size.bytes() as u64;
            let store_end = addr + size as u64;
            !(store_end <= excl_addr || addr >= excl_end)
        } else {
            false
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flat_memory() {
        let mut mem = FlatMemory::new(0x1000);

        // Write and read using SmirMemory trait
        SmirMemory::write(&mut mem, 0x100, &[1, 2, 3, 4]).unwrap();
        let mut buf = [0u8; 4];
        SmirMemory::read(&mut mem, 0x100, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);

        // Atomic operations
        mem.atomic_store(0x200, 42, MemWidth::B8, MemoryOrder::SeqCst)
            .unwrap();
        let val = mem
            .atomic_load(0x200, MemWidth::B8, MemoryOrder::SeqCst)
            .unwrap();
        assert_eq!(val, 42);

        // CAS
        let (old, success) = mem
            .compare_and_swap(
                0x200,
                42,
                100,
                MemWidth::B8,
                MemoryOrder::SeqCst,
                MemoryOrder::Relaxed,
            )
            .unwrap();
        assert_eq!(old, 42);
        assert!(success);

        let val = mem
            .atomic_load(0x200, MemWidth::B8, MemoryOrder::SeqCst)
            .unwrap();
        assert_eq!(val, 100);

        let old = mem
            .atomic_rmw(
                0x200,
                AtomicOp::Neg,
                0xDEAD_BEEF,
                MemWidth::B8,
                MemoryOrder::SeqCst,
            )
            .unwrap();
        assert_eq!(old, 100);
        assert_eq!(
            mem.atomic_load(0x200, MemWidth::B8, MemoryOrder::SeqCst)
                .unwrap(),
            0u64.wrapping_sub(100),
        );
    }

    #[test]
    fn test_exclusive_monitor() {
        let mut mem = FlatMemory::new(0x1000);

        // Load exclusive
        mem.atomic_store(0x100, 42, MemWidth::B8, MemoryOrder::SeqCst)
            .unwrap();
        let val = mem.load_exclusive(0x100, MemWidth::B8).unwrap();
        assert_eq!(val, 42);

        // Store exclusive should succeed
        let success = mem.store_exclusive(0x100, 100, MemWidth::B8).unwrap();
        assert!(success);

        // Store exclusive without load should fail
        let success = mem.store_exclusive(0x100, 200, MemWidth::B8).unwrap();
        assert!(!success);
    }

    #[test]
    fn bounds_checks_at_the_top_of_the_address_space_never_overflow() {
        // Guest-controlled addresses near 2^64 must fault, not overflow.
        let mut low = FlatMemory::new(0x1000);
        for addr in [u64::MAX, u64::MAX - 2, u64::MAX - 7] {
            assert!(low.probe(addr, 8, true).is_err());
            assert!(MemoryReader::read(&low, addr, 8).is_err());
            assert!(SmirMemory::read(&mut low, addr, &mut [0; 8]).is_err());
            assert!(SmirMemory::write(&mut low, addr, &[0; 8]).is_err());
        }

        // A region ending at the last address: accesses ending exactly at
        // 2^64 succeed, and one byte further faults.
        let mut high = FlatMemory::with_base(u64::MAX - 0xfff, 0x1000);
        high.probe(u64::MAX - 1, 2, true).unwrap();
        assert_eq!(MemoryReader::read(&high, u64::MAX - 1, 2).unwrap(), [0, 0]);
        high.load_exclusive(u64::MAX - 7, MemWidth::B8).unwrap();
        SmirMemory::write(&mut high, u64::MAX - 1, &[1, 2]).unwrap();
        assert!(!high.store_exclusive(u64::MAX - 7, 9, MemWidth::B8).unwrap());
        for (addr, len) in [(u64::MAX - 1, 4), (u64::MAX, 2)] {
            assert!(high.probe(addr, len, false).is_err());
            assert!(MemoryReader::read(&high, addr, len).is_err());
            assert!(SmirMemory::read(&mut high, addr, &mut vec![0; len]).is_err());
            assert!(SmirMemory::write(&mut high, addr, &vec![0; len]).is_err());
        }
    }

    #[test]
    fn test_alignment_check() {
        assert!(check_alignment(0x100, MemWidth::B4, true).is_ok());
        assert!(check_alignment(0x101, MemWidth::B4, true).is_err());
        assert!(check_alignment(0x101, MemWidth::B1, true).is_ok());
    }

    #[test]
    fn test_bytes_conversion() {
        let val = 0x0102030405060708u64;

        let le_bytes = u64_to_bytes(val, Endian::Little);
        assert_eq!(le_bytes, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);

        let restored = bytes_to_u64(&le_bytes, Endian::Little);
        assert_eq!(restored, val);
    }
}
