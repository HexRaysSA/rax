//! Shared physical-memory exclusive monitors.
//!
//! Views retain their own address maps but share allocation locks. Acquire those
//! locks in host-address order, then monitor slots. No device or translation
//! callback runs under these locks. External raw aliases remain caller-owned.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use vm_memory::{
    Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
};

#[path = "reservation_atomic.rs"]
mod atomic;

/// Matches AArch64 CTR_EL0.ERG=4; RISC-V uses the same 64-byte reservation set.
const GRANULE: usize = 64;
type Identity = Vec<(u64, u64, usize)>;
type PhysicalKey = (usize, usize);
type Slot = Mutex<Option<PhysicalReservation>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Reservation {
    pub address: u64,
    pub size: u8,
}
impl Reservation {
    pub fn valid(self) -> bool {
        matches!(self.size, 1 | 2 | 4 | 8 | 16)
            && self.address & (u64::from(self.size) - 1) == 0
            && self.address.checked_add(u64::from(self.size) - 1).is_some()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PhysicalReservation {
    logical: Reservation,
    // At most 16 distinct allocations/granules for the largest 16-byte access.
    granules: [usize; 16],
    count: u8,
}
impl PhysicalReservation {
    fn overlaps(&self, address: usize, size: usize) -> bool {
        let start = address as u128;
        self.granules[..usize::from(self.count)]
            .iter()
            .any(|&granule| {
                start < granule as u128 + GRANULE as u128 && start + size as u128 > granule as u128
            })
    }
}
fn slot_lock(slot: &Slot) -> MutexGuard<'_, Option<PhysicalReservation>> {
    match slot.lock() {
        Ok(guard) => guard,
        Err(error) => {
            let mut guard = error.into_inner();
            *guard = None;
            slot.clear_poison();
            guard
        }
    }
}
#[derive(Default)]
struct State {
    monitors: Vec<Weak<Slot>>,
}
struct Allocation {
    key: PhysicalKey,
    state: Arc<Mutex<State>>,
}
struct AllocationRange {
    end: usize,
    state: Weak<Mutex<State>>,
}
#[derive(Default)]
struct Registry {
    views: BTreeMap<Identity, Weak<MemoryDomain>>,
    allocations: BTreeMap<usize, AllocationRange>,
}
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

pub(crate) struct MemoryDomain {
    allocations: Vec<Allocation>,
    // Retaining every mapping prevents host-address reuse while locks are live.
    _backing: GuestMemoryMmap,
}
enum DomainGuards<'a> {
    One(MutexGuard<'a, State>),
    Many(Vec<MutexGuard<'a, State>>),
}
impl<'a> DomainGuards<'a> {
    fn states(&mut self) -> &mut [MutexGuard<'a, State>] {
        match self {
            Self::One(state) => std::slice::from_mut(state),
            Self::Many(states) => states,
        }
    }
}
fn physical_key(region: &vm_memory::GuestRegionMmap) -> PhysicalKey {
    let start = region.as_ptr() as usize;
    // A live mapping cannot wrap the host address space. Round only lock
    // coverage, never a guest read/write, to include the reservation granule.
    let end = start
        .checked_add(region.len() as usize)
        .and_then(|end| end.checked_add(GRANULE - 1))
        .expect("live mapping fits the host address space")
        & !(GRANULE - 1);
    (start & !(GRANULE - 1), end)
}

fn identity(memory: &GuestMemoryMmap) -> Identity {
    memory
        .iter()
        .map(|region| {
            (
                region.start_addr().0,
                region.len(),
                region.as_ptr() as usize,
            )
        })
        .collect()
}
impl MemoryDomain {
    pub fn for_memory(memory: &GuestMemoryMmap) -> Arc<Self> {
        let mut registry = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = identity(memory);
        if let Some(domain) = registry.views.get(&key).and_then(Weak::upgrade) {
            return domain;
        }
        registry.views.retain(|_, value| value.strong_count() != 0);
        registry
            .allocations
            .retain(|_, value| value.state.strong_count() != 0);
        let mut allocations = BTreeMap::new();
        for region in memory.iter() {
            let (start, end) = physical_key(region);
            // Existing ranges are disjoint and never resized while live.
            // A larger or sliced view reuses every overlapping range and adds
            // locks only for uncovered gaps; existing owners keep their locks.
            let existing: Vec<_> = registry
                .allocations
                .range(..end)
                .filter(|(_, range)| range.end > start)
                .filter_map(|(&base, range)| {
                    range.state.upgrade().map(|state| (base, range.end, state))
                })
                .collect();
            let mut cursor = start;
            for (base, limit, state) in existing {
                if cursor < base {
                    let fresh = Arc::new(Mutex::new(State::default()));
                    registry.allocations.insert(
                        cursor,
                        AllocationRange {
                            end: base,
                            state: Arc::downgrade(&fresh),
                        },
                    );
                    allocations.insert(cursor, (base, fresh));
                }
                allocations.insert(base, (limit, state));
                cursor = cursor.max(limit.min(end));
            }
            if cursor < end {
                let fresh = Arc::new(Mutex::new(State::default()));
                registry.allocations.insert(
                    cursor,
                    AllocationRange {
                        end,
                        state: Arc::downgrade(&fresh),
                    },
                );
                allocations.insert(cursor, (end, fresh));
            }
        }
        let domain = Arc::new(Self {
            allocations: allocations
                .into_iter()
                .map(|(start, (end, state))| Allocation {
                    key: (start, end),
                    state,
                })
                .collect(),
            _backing: memory.clone(),
        });
        registry.views.insert(key, Arc::downgrade(&domain));
        domain
    }
    fn allocation_lock(allocation: &Allocation) -> MutexGuard<'_, State> {
        match allocation.state.lock() {
            Ok(guard) => guard,
            Err(error) => {
                let guard = error.into_inner();
                for monitor in guard.monitors.iter().filter_map(Weak::upgrade) {
                    *slot_lock(&monitor) = None;
                }
                allocation.state.clear_poison();
                guard
            }
        }
    }
    fn lock(&self) -> DomainGuards<'_> {
        if let [allocation] = self.allocations.as_slice() {
            return DomainGuards::One(Self::allocation_lock(allocation));
        }
        DomainGuards::Many(self.allocations.iter().map(Self::allocation_lock).collect())
    }
    pub(super) fn freeze(&self) -> FrozenDomain<'_> {
        FrozenDomain {
            domain: self,
            state: self.lock(),
        }
    }
    fn physical_address(memory: &GuestMemoryMmap, address: u64) -> Option<usize> {
        let region = memory.find_region(GuestAddress(address))?;
        (region.as_ptr() as usize).checked_add((address - region.start_addr().0) as usize)
    }
    fn physical_reservation(&self, logical: Reservation) -> Option<PhysicalReservation> {
        if !logical.valid() {
            return None;
        }
        let mut result = PhysicalReservation {
            logical,
            granules: [0; 16],
            count: 0,
        };
        for offset in 0..u64::from(logical.size) {
            let physical =
                Self::physical_address(&self._backing, logical.address + offset)? & !(GRANULE - 1);
            if !result.granules[..usize::from(result.count)].contains(&physical) {
                result.granules[usize::from(result.count)] = physical;
                result.count += 1;
            }
        }
        Some(result)
    }
    pub(crate) fn same_backing(&self, other: &GuestMemoryMmap, reservation: Reservation) -> bool {
        reservation.valid()
            && (0..u64::from(reservation.size)).all(|offset| {
                let address = reservation.address + offset;
                let ours = Self::physical_address(&self._backing, address);
                ours.is_some() && ours == Self::physical_address(other, address)
            })
    }
    pub fn register(self: &Arc<Self>) -> Monitor {
        let slot = Arc::new(Mutex::new(None));
        let mut guards = self.lock();
        for state in guards.states() {
            state.monitors.retain(|slot| slot.strong_count() != 0);
            state.monitors.push(Arc::downgrade(&slot));
        }
        Monitor {
            domain: self.clone(),
            slot,
        }
    }
    fn invalidate(&self, guards: &mut DomainGuards<'_>, address: u64, size: usize) {
        let mut done = 0;
        while done < size {
            // Whole-range admission precedes every caller's invalidation.
            let current = address + done as u64;
            let region = self
                ._backing
                .find_region(GuestAddress(current))
                .expect("preflight admitted this immutable backing region");
            let offset = current - region.start_addr().0;
            let count = ((region.len() - offset) as usize).min(size - done);
            let physical = region.as_ptr() as usize + offset as usize;
            for (index, allocation) in self.allocations.iter().enumerate() {
                if physical as u128 >= allocation.key.1 as u128
                    || physical as u128 + count as u128 <= allocation.key.0 as u128
                {
                    continue;
                }
                guards.states()[index].monitors.retain(|monitor| {
                    let Some(monitor) = monitor.upgrade() else {
                        return false;
                    };
                    let mut slot = slot_lock(&monitor);
                    if slot
                        .as_ref()
                        .is_some_and(|reservation| reservation.overlaps(physical, count))
                    {
                        *slot = None;
                    }
                    true
                });
            }
            done += count;
        }
    }
    pub fn write(
        &self,
        memory: &GuestMemoryMmap,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), GuestMemoryError> {
        preflight_write(memory, address, bytes.len())?;
        let mut state = self.lock();
        self.invalidate(&mut state, address, bytes.len());
        memory.write_slice(bytes, GuestAddress(address))
    }
    pub(crate) fn read_modify_write(
        &self,
        memory: &GuestMemoryMmap,
        address: u64,
        size: u8,
        operation: crate::devices::bus::MmioRmwOp,
    ) -> crate::error::Result<Vec<u8>> {
        operation.validate(size)?;
        preflight_write(memory, address, usize::from(size))?;
        let mut state = self.lock();
        let mut old = vec![0; usize::from(size)];
        memory.read_slice(&mut old, GuestAddress(address))?;
        let mut new = old.clone();
        operation.apply(&mut new)?;
        self.invalidate(&mut state, address, new.len());
        memory.write_slice(&new, GuestAddress(address))?;
        Ok(old)
    }
}

pub(super) struct FrozenDomain<'a> {
    domain: &'a MemoryDomain,
    state: DomainGuards<'a>,
}
impl FrozenDomain<'_> {
    pub(super) fn owns(&self, monitor: &Monitor) -> bool {
        std::ptr::eq(self.domain, Arc::as_ptr(&monitor.domain))
    }
    pub(super) fn admits(&self, reservation: Reservation) -> bool {
        if !reservation.valid() {
            return false;
        }
        for offset in 0..u64::from(reservation.size) {
            let Some(region) = self
                .domain
                ._backing
                .find_region(GuestAddress(reservation.address + offset))
            else {
                return false;
            };
            #[cfg(unix)]
            if region.prot() & libc::PROT_READ == 0 {
                return false;
            }
        }
        true
    }
    pub(super) fn restore(&self, monitor: &Monitor, reservation: Option<Reservation>) {
        debug_assert!(self.owns(monitor));
        debug_assert!(reservation.is_none_or(|value| self.admits(value)));
        *slot_lock(&monitor.slot) =
            reservation.and_then(|value| monitor.domain.physical_reservation(value));
    }
    pub(super) fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), GuestMemoryError> {
        preflight_write(&self.domain._backing, address, bytes.len())?;
        self.domain
            .invalidate(&mut self.state, address, bytes.len());
        #[cfg(unix)]
        let readable = self
            .domain
            ._backing
            .iter()
            .all(|region| region.prot() & libc::PROT_READ != 0);
        #[cfg(not(unix))]
        let readable = true;
        const CHUNK: usize = 64 * 1024;
        let mut previous = [0; CHUNK];
        for (index, chunk) in bytes.chunks(CHUNK).enumerate() {
            let current = GuestAddress(address + (index * CHUNK) as u64);
            if readable {
                self.domain
                    ._backing
                    .read_slice(&mut previous[..chunk.len()], current)?;
                if previous[..chunk.len()] == *chunk {
                    continue;
                }
            }
            self.domain._backing.write_slice(chunk, current)?;
        }
        Ok(())
    }
}

pub(crate) fn write(
    memory: &GuestMemoryMmap,
    address: u64,
    bytes: &[u8],
) -> Result<(), GuestMemoryError> {
    MemoryDomain::for_memory(memory).write(memory, address, bytes)
}
#[cfg(feature = "debug")]
pub(crate) fn write_scatter(
    memory: &GuestMemoryMmap,
    pieces: &[(u64, &[u8])],
) -> Result<(), GuestMemoryError> {
    for &(address, bytes) in pieces {
        preflight_write(memory, address, bytes.len())?;
    }
    let domain = MemoryDomain::for_memory(memory);
    let mut state = domain.lock();
    for &(address, bytes) in pieces {
        domain.invalidate(&mut state, address, bytes.len());
    }
    for &(address, bytes) in pieces {
        memory.write_slice(bytes, GuestAddress(address))?;
    }
    Ok(())
}

pub(crate) fn preflight_write(
    memory: &GuestMemoryMmap,
    address: u64,
    size: usize,
) -> Result<(), GuestMemoryError> {
    preflight_access(memory, address, size, true)
}

pub(crate) fn preflight_read(
    memory: &GuestMemoryMmap,
    address: u64,
    size: usize,
) -> Result<(), GuestMemoryError> {
    preflight_access(memory, address, size, false)
}

fn preflight_access(
    memory: &GuestMemoryMmap,
    address: u64,
    size: usize,
    _write: bool,
) -> Result<(), GuestMemoryError> {
    let mut done = 0;
    while done < size {
        let current = address
            .checked_add(done as u64)
            .ok_or(GuestMemoryError::InvalidGuestAddress(GuestAddress(address)))?;
        let region = memory
            .find_region(GuestAddress(current))
            .ok_or(GuestMemoryError::InvalidGuestAddress(GuestAddress(current)))?;
        #[cfg(unix)]
        {
            let required = if _write {
                libc::PROT_WRITE
            } else {
                libc::PROT_READ
            };
            if region.prot() & required == 0 {
                return Err(GuestMemoryError::InvalidGuestAddress(GuestAddress(current)));
            }
        }
        done += ((region.len() - (current - region.start_addr().0)) as usize).min(size - done);
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct Monitor {
    domain: Arc<MemoryDomain>,
    slot: Arc<Slot>,
}
impl std::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Monitor").finish_non_exhaustive()
    }
}

/// An in-process source reservation witness for address-map reconstruction.
/// This retains the source slot, so an intervening writer remains observable.
/// It is deliberately absent from serialized checkpoint formats.
#[derive(Clone)]
pub struct MappingReservation {
    monitor: Monitor,
}
impl Monitor {
    pub(crate) fn mapping_witness(&self) -> MappingReservation {
        MappingReservation {
            monitor: self.clone(),
        }
    }
    pub(crate) fn same_backing(&self, other: &GuestMemoryMmap, reservation: Reservation) -> bool {
        self.domain.same_backing(other, reservation)
    }
    pub(crate) fn retain_from(&self, witness: &MappingReservation) -> bool {
        let _domain = self.domain.lock();
        let source = *slot_lock(&witness.monitor.slot);
        let mut current = slot_lock(&self.slot);
        let keep = current.is_some() && *current == source;
        if !keep {
            *current = None;
        }
        keep
    }
    pub(crate) fn read(
        &self,
        memory: &GuestMemoryMmap,
        address: u64,
        buf: &mut [u8],
    ) -> Result<(), GuestMemoryError> {
        let _domain = self.domain.lock();
        memory.read_slice(buf, GuestAddress(address))
    }
    pub fn get(&self) -> Option<Reservation> {
        slot_lock(&self.slot).as_ref().map(|value| value.logical)
    }
    pub fn clear(&self) {
        let _domain = self.domain.lock();
        *slot_lock(&self.slot) = None;
    }
    pub fn mark(&self, address: u64, size: u8) {
        let _domain = self.domain.lock();
        *slot_lock(&self.slot) = self
            .domain
            .physical_reservation(Reservation { address, size });
    }
    pub fn check(&self, address: u64, size: u8) -> bool {
        let _domain = self.domain.lock();
        slot_lock(&self.slot)
            .take()
            .is_some_and(|value| value.logical == Reservation { address, size })
    }
    pub fn read_exclusive(
        &self,
        memory: &GuestMemoryMmap,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, GuestMemoryError> {
        let _domain = self.domain.lock();
        *slot_lock(&self.slot) = None;
        let logical = Reservation {
            address,
            size: u8::try_from(size).unwrap_or(0),
        };
        let Some(physical) = self.domain.physical_reservation(logical) else {
            return Err(GuestMemoryError::InvalidGuestAddress(GuestAddress(address)));
        };
        let mut bytes = vec![0; size];
        memory.read_slice(&mut bytes, GuestAddress(address))?;
        *slot_lock(&self.slot) = Some(physical);
        Ok(bytes)
    }
    pub fn write_exclusive(
        &self,
        memory: &GuestMemoryMmap,
        address: u64,
        bytes: &[u8],
    ) -> Result<bool, GuestMemoryError> {
        let mut domain = self.domain.lock();
        let expected = Reservation {
            address,
            size: u8::try_from(bytes.len()).unwrap_or(0),
        };
        if !slot_lock(&self.slot)
            .take()
            .is_some_and(|value| value.logical == expected)
        {
            return Ok(false);
        }
        preflight_write(memory, address, bytes.len())?;
        self.domain.invalidate(&mut domain, address, bytes.len());
        memory.write_slice(bytes, GuestAddress(address))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryDomain, write};
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn memory() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap()
    }

    #[test]
    fn cloned_backings_share_monitors_but_equal_guest_addresses_do_not() {
        let memory = memory();
        let domain = MemoryDomain::for_memory(&memory);
        assert!(Arc::ptr_eq(
            &domain,
            &MemoryDomain::for_memory(&memory.clone())
        ));
        let other = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        assert!(!Arc::ptr_eq(&domain, &MemoryDomain::for_memory(&other)));
        let monitor = domain.register();
        monitor.read_exclusive(&memory, 128, 8).unwrap();
        write(&other, 128, &[0; 8]).unwrap();
        assert!(monitor.write_exclusive(&memory, 128, &[1; 8]).unwrap());
    }

    #[test]
    fn identical_and_aba_writes_invalidate_without_value_comparison() {
        for writes in [vec![[0; 8]], vec![[9; 8], [0; 8]]] {
            let memory = memory();
            let monitor = MemoryDomain::for_memory(&memory).register();
            monitor.read_exclusive(&memory, 128, 8).unwrap();
            for bytes in writes {
                write(&memory.clone(), 128, &bytes).unwrap();
            }
            assert!(!monitor.write_exclusive(&memory, 128, &[1; 8]).unwrap());
            let mut bytes = [0; 8];
            memory.read_slice(&mut bytes, GuestAddress(128)).unwrap();
            assert_eq!(bytes, [0; 8]);
        }
    }

    #[test]
    fn collateral_ram_rmw_invalidates_identical_writes_and_preserves_failed_admission() {
        use crate::devices::bus::MmioRmwOp;
        let memory = memory();
        let domain = MemoryDomain::for_memory(&memory);
        let monitor = domain.register();
        for operation in [
            MmioRmwOp::Exchange(0),
            MmioRmwOp::CompareExchange {
                expected: 1,
                replacement: 9,
            },
        ] {
            monitor.read_exclusive(&memory, 128, 4).unwrap();
            assert_eq!(
                domain
                    .read_modify_write(&memory, 128, 4, operation)
                    .unwrap(),
                [0; 4]
            );
            assert!(!monitor.write_exclusive(&memory, 128, &[1; 4]).unwrap());
        }
        monitor.read_exclusive(&memory, 128, 4).unwrap();
        assert!(
            domain
                .read_modify_write(&memory, 128, 1, MmioRmwOp::BitSet(8))
                .is_err()
        );
        assert!(
            domain
                .read_modify_write(&memory, 4095, 4, MmioRmwOp::Not)
                .is_err()
        );
        assert!(monitor.write_exclusive(&memory, 128, &[1; 4]).unwrap());
    }

    #[test]
    fn collateral_ram_rmw_serializes_competing_tracked_writers() {
        let memory = Arc::new(memory());
        let domain = MemoryDomain::for_memory(&memory);
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let memory = memory.clone();
                let domain = domain.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        domain
                            .read_modify_write(
                                &memory,
                                128,
                                4,
                                crate::devices::bus::MmioRmwOp::Add {
                                    value: 1,
                                    carry: false,
                                },
                            )
                            .unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let mut bytes = [0; 4];
        memory.read_slice(&mut bytes, GuestAddress(128)).unwrap();
        assert_eq!(u32::from_le_bytes(bytes), 400);
    }

    #[test]
    fn granule_boundaries_and_failed_crossing_store_preserve_unrelated_leases() {
        let memory = memory();
        let monitor = MemoryDomain::for_memory(&memory).register();
        monitor.read_exclusive(&memory, 128, 8).unwrap();
        write(&memory, 192, &[9]).unwrap();
        assert!(write(&memory, 4095, &[1, 2]).is_err());
        assert!(monitor.write_exclusive(&memory, 128, &[1; 8]).unwrap());
        monitor.read_exclusive(&memory, 128, 8).unwrap();
        write(&memory, 191, &[0]).unwrap();
        assert!(!monitor.write_exclusive(&memory, 128, &[2; 8]).unwrap());
    }

    fn rejected_first_write(expired_domain: bool) {
        let memory = memory();
        if expired_domain {
            drop(MemoryDomain::for_memory(&memory));
        }
        memory.write_slice(&[0x7b], GuestAddress(4095)).unwrap();
        assert!(write(&memory, 4095, &[1, 2]).is_err());
        let mut byte = [0];
        memory.read_slice(&mut byte, GuestAddress(4095)).unwrap();
        assert_eq!(byte, [0x7b], "failed first writer published a RAM prefix");
    }

    #[test]
    fn a_first_writer_without_any_monitor_preserves_ram_on_range_failure() {
        rejected_first_write(false);
    }

    #[test]
    fn a_first_writer_after_the_last_domain_drops_preserves_ram_on_failure() {
        rejected_first_write(true);
    }

    #[test]
    fn the_first_writer_spans_adjacent_regions_before_a_pe_registers() {
        let memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(4096), 4096)])
                .unwrap();
        write(&memory, 4094, &[1, 2, 3, 4]).unwrap();
        let monitor = MemoryDomain::for_memory(&memory).register();
        assert_eq!(monitor.read_exclusive(&memory, 4096, 2).unwrap(), [3, 4]);
        write(&memory.clone(), 4096, &[3, 4]).unwrap();
        assert!(!monitor.write_exclusive(&memory, 4096, &[9, 9]).unwrap());
        let mut bytes = [0; 4];
        memory.read_slice(&mut bytes, GuestAddress(4094)).unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn one_successful_store_cannot_leave_a_second_pe_exclusive() {
        let memory = Arc::new(memory());
        let domain = MemoryDomain::for_memory(&memory);
        let a = domain.register();
        let b = domain.register();
        a.read_exclusive(&memory, 128, 8).unwrap();
        b.read_exclusive(&memory, 128, 8).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for (monitor, byte) in [(a, 1), (b, 2)] {
            let barrier = barrier.clone();
            let memory = memory.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                monitor.write_exclusive(&memory, 128, &[byte; 8]).unwrap()
            }));
        }
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| usize::from(thread.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }
}

#[cfg(all(test, feature = "debug"))]
#[path = "reservations_scatter_tests.rs"]
mod scatter_tests;

#[cfg(test)]
#[path = "reservation_view_tests.rs"]
mod view_tests;
