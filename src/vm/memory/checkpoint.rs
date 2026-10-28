//! Controller admission and RAM/reservation publication at one checkpoint boundary.

use super::reservations::{FrozenDomain, MemoryDomain, Monitor, Reservation};
use crate::error::{Error, Result};
use crate::isa::arm::aarch64::gic::Gic;
use crate::isa::arm::aarch64::gic::checkpoint::GicCheckpoint;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use vm_memory::{GuestMemoryError, GuestMemoryMmap};

pub(crate) struct CheckpointBindings {
    domain: Arc<MemoryDomain>,
    gics: Vec<Arc<Mutex<Gic>>>,
}

impl CheckpointBindings {
    pub(crate) fn new(memory: &GuestMemoryMmap, mut gics: Vec<Arc<Mutex<Gic>>>) -> Self {
        gics.sort_by_key(|handle| Arc::as_ptr(handle) as usize);
        gics.dedup_by(|a, b| Arc::ptr_eq(a, b));
        Self {
            domain: MemoryDomain::for_memory(memory),
            gics,
        }
    }

    /// The caller holds PCI, shared-platform and legacy-device locks already.
    /// Independent owned GICs are ordered before the RAM domain.
    pub(crate) fn enter(&self) -> Result<CheckpointPublication<'_>> {
        let mut gics = Vec::with_capacity(self.gics.len());
        for handle in &self.gics {
            gics.push(RefCell::new(handle.lock().map_err(|_| {
                Error::Emulator("checkpoint owned GIC lock poisoned".into())
            })?));
        }
        Ok(CheckpointPublication {
            bindings: self,
            memory: RefCell::new(self.domain.freeze()),
            gics,
        })
    }
}

/// A stopped VM's admitted controller and physical-memory boundary. Construction
/// is crate-owned; backend hooks receive it without gaining a second RAM lock.
pub struct CheckpointPublication<'bindings> {
    bindings: &'bindings CheckpointBindings,
    memory: RefCell<FrozenDomain<'bindings>>,
    gics: Vec<RefCell<MutexGuard<'bindings, Gic>>>,
}

enum Activation {
    None,
    Aarch64 {
        monitor: Monitor,
        reservation: Option<Reservation>,
        gic: Option<(usize, GicCheckpoint)>,
        completed: Arc<AtomicBool>,
    },
}

/// Admitted bindings for one detached CPU. It borrows only the publication
/// scope, so the CPU can move into the live vector without invalidating it.
pub struct CpuPublication<'scope, 'bindings> {
    scope: &'scope CheckpointPublication<'bindings>,
    activation: Activation,
}

impl<'bindings> CheckpointPublication<'bindings> {
    pub(crate) fn empty(&self) -> CpuPublication<'_, 'bindings> {
        CpuPublication {
            scope: self,
            activation: Activation::None,
        }
    }

    fn gic_index(&self, handle: &Arc<Mutex<Gic>>) -> Result<usize> {
        self.bindings
            .gics
            .iter()
            .position(|other| Arc::ptr_eq(handle, other))
            .ok_or_else(|| Error::InvalidConfig("checkpoint GIC binding differs".into()))
    }

    pub(crate) fn capture_gic(&self, handle: &Arc<Mutex<Gic>>) -> Result<GicCheckpoint> {
        Ok(self.gics[self.gic_index(handle)?].borrow().checkpoint())
    }

    pub(crate) fn prepare_aarch64(
        &self,
        monitor: Monitor,
        reservation: Option<Reservation>,
        owned_gic: Option<(Arc<Mutex<Gic>>, GicCheckpoint)>,
        completed: Arc<AtomicBool>,
    ) -> Result<CpuPublication<'_, 'bindings>> {
        let memory = self.memory.borrow();
        if !memory.owns(&monitor) || reservation.is_some_and(|value| !memory.admits(value)) {
            return Err(Error::InvalidConfig(
                "checkpoint reservation binding or range differs".into(),
            ));
        }
        let gic = owned_gic
            .map(|(handle, state)| {
                let index = self.gic_index(&handle)?;
                self.gics[index].borrow().validate_checkpoint(&state)?;
                Ok::<_, Error>((index, state))
            })
            .transpose()?;
        Ok(CpuPublication {
            scope: self,
            activation: Activation::Aarch64 {
                monitor,
                reservation,
                gic,
                completed,
            },
        })
    }

    pub(crate) fn write(
        &self,
        address: u64,
        bytes: &[u8],
    ) -> std::result::Result<(), GuestMemoryError> {
        self.memory.borrow_mut().write(address, bytes)
    }
}

impl CpuPublication<'_, '_> {
    /// All mapping/controller admission happened before RAM or live CPU state
    /// changed. No callback, allocation, lock acquisition or native setter runs.
    pub fn commit(self) {
        match self.activation {
            Activation::None => {}
            Activation::Aarch64 {
                monitor,
                reservation,
                gic,
                completed,
            } => {
                if let Some((index, state)) = gic {
                    self.scope.gics[index]
                        .borrow_mut()
                        .restore_checkpoint(state);
                }
                self.scope.memory.borrow().restore(&monitor, reservation);
                completed.store(true, Ordering::Release);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;
    use vm_memory::{Bytes, GuestAddress};

    fn memory() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap()
    }

    #[test]
    fn foreign_domain_and_unmapped_rights_fail_before_publication() {
        let memory = memory();
        let foreign = self::memory();
        let monitor = MemoryDomain::for_memory(&memory).register();
        let other = MemoryDomain::for_memory(&foreign).register();
        monitor.mark(64, 4);
        let bindings = CheckpointBindings::new(&memory, vec![]);
        let scope = bindings.enter().unwrap();
        for (target, right) in [
            (other, None),
            (
                monitor.clone(),
                Some(Reservation {
                    address: 4096,
                    size: 4,
                }),
            ),
            (
                monitor.clone(),
                Some(Reservation {
                    address: 3,
                    size: 4,
                }),
            ),
        ] {
            let active = Arc::new(AtomicBool::new(false));
            assert!(
                scope
                    .prepare_aarch64(target, right, None, active.clone())
                    .is_err()
            );
            assert!(!active.load(Ordering::Acquire));
            assert_eq!(
                monitor.get(),
                Some(Reservation {
                    address: 64,
                    size: 4
                })
            );
        }
    }

    #[test]
    fn dropping_a_permit_does_not_activate_or_change_reservations() {
        let memory = memory();
        let monitor = MemoryDomain::for_memory(&memory).register();
        let bindings = CheckpointBindings::new(&memory, vec![]);
        let scope = bindings.enter().unwrap();
        let active = Arc::new(AtomicBool::new(false));
        let permit = scope
            .prepare_aarch64(
                monitor.clone(),
                Some(Reservation {
                    address: 64,
                    size: 4,
                }),
                None,
                active.clone(),
            )
            .unwrap();
        drop(permit);
        assert!(!active.load(Ordering::Acquire));
        assert!(monitor.get().is_none());
    }

    #[test]
    fn skipping_an_identical_ram_copy_still_invalidates_the_old_exclusive_right() {
        let memory = memory();
        let monitor = MemoryDomain::for_memory(&memory).register();
        monitor.mark(64, 4);
        let bindings = CheckpointBindings::new(&memory, vec![]);
        let scope = bindings.enter().unwrap();
        scope.write(64, &[0; 4]).unwrap();
        assert!(monitor.get().is_none());
        let mut bytes = [1; 4];
        memory.read_slice(&mut bytes, GuestAddress(64)).unwrap();
        assert_eq!(bytes, [0; 4]);
    }

    #[test]
    fn controlled_writer_waits_until_the_complete_publication_boundary_ends() {
        let memory = memory();
        let domain = MemoryDomain::for_memory(&memory);
        let monitor = domain.register();
        let bindings = CheckpointBindings::new(&memory, vec![]);
        let scope = bindings.enter().unwrap();
        let active = Arc::new(AtomicBool::new(false));
        let permit = scope
            .prepare_aarch64(
                monitor.clone(),
                Some(Reservation {
                    address: 64,
                    size: 4,
                }),
                None,
                active.clone(),
            )
            .unwrap();
        scope.write(64, &[1; 4]).unwrap();
        permit.commit();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let backing = memory.clone();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            domain.write(&backing, 64, &[2; 4]).unwrap();
            finished_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(active.load(Ordering::Acquire));
        assert!(monitor.get().is_some());
        drop(scope);
        finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        writer.join().unwrap();
        assert!(monitor.get().is_none());
        let mut bytes = [0; 4];
        memory.read_slice(&mut bytes, GuestAddress(64)).unwrap();
        assert_eq!(bytes, [2; 4]);
    }
}
