//! Shared physical-memory exclusive monitors.
//!
//! Lock order is domain, then monitor. Only checked mmap reads/writes run under
//! the domain lock; device and translation callbacks must run before entry.
//! Raw aliases remain the caller's responsibility: RAX writers use `write`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use vm_memory::{
    Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
};

/// Matches the default AArch64 CTR_EL0.ERG=4: 2^4 words, or 64 bytes.
const GRANULE: u64 = 64;
type Identity = Vec<(u64, u64, usize)>;
type Slot = Mutex<Option<Reservation>>;

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

    fn overlaps(self, address: u64, size: usize) -> bool {
        let start = u128::from(self.address & !(GRANULE - 1));
        u128::from(address) < start + u128::from(GRANULE)
            && u128::from(address) + size as u128 > start
    }
}

fn slot_lock(slot: &Slot) -> MutexGuard<'_, Option<Reservation>> {
    match slot.lock() {
        Ok(guard) => guard,
        Err(error) => {
            let mut guard = error.into_inner();
            // A host panic cannot confer an exclusive-store right.
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

pub(crate) struct MemoryDomain {
    state: Mutex<State>,
    // Retaining the backing prevents address reuse while this identity is live.
    _backing: GuestMemoryMmap,
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

fn registry() -> &'static Mutex<BTreeMap<Identity, Weak<MemoryDomain>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<Identity, Weak<MemoryDomain>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

impl MemoryDomain {
    pub(super) fn freeze(&self) -> FrozenDomain<'_> {
        FrozenDomain {
            domain: self,
            state: self.lock(),
        }
    }
    pub fn for_memory(memory: &GuestMemoryMmap) -> Arc<Self> {
        let mut registry = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = identity(memory);
        if let Some(domain) = registry.get(&key).and_then(Weak::upgrade) {
            return domain;
        }
        // Prune expired identities only on creation. Existing-domain writers
        // must not scan every registry entry on their hot path.
        registry.retain(|_, value| value.strong_count() != 0);
        let domain = Arc::new(Self {
            state: Mutex::new(State::default()),
            _backing: memory.clone(),
        });
        registry.insert(key, Arc::downgrade(&domain));
        domain
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(error) => {
                let guard = error.into_inner();
                for monitor in guard.monitors.iter().filter_map(Weak::upgrade) {
                    *slot_lock(&monitor) = None;
                }
                self.state.clear_poison();
                guard
            }
        }
    }

    pub fn register(self: &Arc<Self>) -> Monitor {
        let slot = Arc::new(Mutex::new(None));
        let mut state = self.lock();
        state.monitors.retain(|slot| slot.strong_count() != 0);
        state.monitors.push(Arc::downgrade(&slot));
        Monitor {
            domain: self.clone(),
            slot,
        }
    }

    fn invalidate(state: &mut State, address: u64, size: usize) {
        if size == 0 {
            return;
        }
        state.monitors.retain(|monitor| {
            let Some(monitor) = monitor.upgrade() else {
                return false;
            };
            let mut slot = slot_lock(&monitor);
            if slot.is_some_and(|reservation| reservation.overlaps(address, size)) {
                *slot = None;
            }
            true
        });
    }

    pub fn write(
        &self,
        memory: &GuestMemoryMmap,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), GuestMemoryError> {
        preflight_write(memory, address, bytes.len())?;
        let mut state = self.lock();
        Self::invalidate(&mut state, address, bytes.len());
        memory.write_slice(bytes, GuestAddress(address))
    }

    /// Native collateral RAM is unmapped in every CPU's EPT. Serialize its
    /// complete RMW with tracked DMA/software writers and exclusive monitors.
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
        Self::invalidate(&mut state, address, new.len());
        memory.write_slice(&new, GuestAddress(address))?;
        Ok(old)
    }
}

/// Held only after controller/device publication locks. No callback or ordinary
/// tracked writer may run inside this guard: they would reacquire the domain.
pub(super) struct FrozenDomain<'a> {
    domain: &'a MemoryDomain,
    state: MutexGuard<'a, State>,
}

impl FrozenDomain<'_> {
    pub(super) fn owns(&self, monitor: &Monitor) -> bool {
        std::ptr::eq(self.domain, Arc::as_ptr(&monitor.domain))
    }

    pub(super) fn admits(&self, reservation: Reservation) -> bool {
        if !reservation.valid() {
            return false;
        }
        let mut done = 0;
        while done < usize::from(reservation.size) {
            let Some(address) = reservation.address.checked_add(done as u64) else {
                return false;
            };
            let Some(region) = self.domain._backing.find_region(GuestAddress(address)) else {
                return false;
            };
            #[cfg(unix)]
            if region.prot() & libc::PROT_READ == 0 {
                return false;
            }
            done += ((region.len() - (address - region.start_addr().0)) as usize)
                .min(usize::from(reservation.size) - done);
        }
        true
    }

    /// The publication permit already checked ownership, width and mapping.
    pub(super) fn restore(&self, monitor: &Monitor, reservation: Option<Reservation>) {
        debug_assert!(self.owns(monitor));
        debug_assert!(reservation.is_none_or(|value| self.admits(value)));
        *slot_lock(&monitor.slot) = reservation;
    }

    pub(super) fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), GuestMemoryError> {
        preflight_write(&self.domain._backing, address, bytes.len())?;
        MemoryDomain::invalidate(&mut self.state, address, bytes.len());
        // Avoid materializing unchanged sparse RAM, while the logical write
        // above still invalidates identical-value exclusive reservations.
        // Never inspect a write-only host mapping through the compare path.
        #[cfg(unix)]
        let readable = self
            .domain
            ._backing
            .iter()
            .all(|r| r.prot() & libc::PROT_READ != 0);
        #[cfg(not(unix))]
        let readable = true;
        const CHUNK: usize = 64 * 1024;
        let mut previous = [0u8; CHUNK];
        for (index, chunk) in bytes.chunks(CHUNK).enumerate() {
            // Whole-range preflight admitted this address before mutation.
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

/// Invalidate even identical-value and ABA stores; comparing RAM values is not
/// sufficient evidence that an exclusive reservation survived.
pub(crate) fn write(
    memory: &GuestMemoryMmap,
    address: u64,
    bytes: &[u8],
) -> Result<(), GuestMemoryError> {
    // Retain a domain even before the first PE exists. Any PE registering
    // during this copy joins the same live domain and waits for its RAM lock.
    // The registry is released before the checked copy starts.
    MemoryDomain::for_memory(memory).write(memory, address, bytes)
}

pub(crate) fn preflight_write(
    memory: &GuestMemoryMmap,
    address: u64,
    size: usize,
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
        if region.prot() & libc::PROT_WRITE == 0 {
            return Err(GuestMemoryError::InvalidGuestAddress(GuestAddress(current)));
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

impl Monitor {
    pub fn get(&self) -> Option<Reservation> {
        *slot_lock(&self.slot)
    }
    pub fn clear(&self) {
        let _domain = self.domain.lock();
        *slot_lock(&self.slot) = None;
    }
    pub fn mark(&self, address: u64, size: u8) {
        let _domain = self.domain.lock();
        let reservation = Reservation { address, size };
        *slot_lock(&self.slot) = reservation.valid().then_some(reservation);
    }
    pub fn check(&self, address: u64, size: u8) -> bool {
        let _domain = self.domain.lock();
        slot_lock(&self.slot).take() == Some(Reservation { address, size })
    }
    pub fn read_exclusive(
        &self,
        memory: &GuestMemoryMmap,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, GuestMemoryError> {
        let _domain = self.domain.lock();
        *slot_lock(&self.slot) = None;
        let reservation = Reservation {
            address,
            size: u8::try_from(size).unwrap_or(0),
        };
        if !reservation.valid() {
            return Err(GuestMemoryError::InvalidGuestAddress(GuestAddress(address)));
        }
        let mut bytes = vec![0; size];
        memory.read_slice(&mut bytes, GuestAddress(address))?;
        *slot_lock(&self.slot) = Some(reservation);
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
        if slot_lock(&self.slot).take() != Some(expected) {
            return Ok(false);
        }
        preflight_write(memory, address, bytes.len())?;
        MemoryDomain::invalidate(&mut domain, address, bytes.len());
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
