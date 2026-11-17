//! Broker-owned address spaces and the workers retaining them.
//!
//! There is one record for each MM, including its personality bookkeeping.
//! Shared clones retain that record; private forks snapshot it; exec changes
//! only the caller's reference. A record lives until its last endpoint retires.
//! The broker serializes requests and never takes its own execution lease.
//!
//! A granted turn is not a worker memory view. Before executing, the worker
//! must import the owner's current mappings and backing descriptors and discard
//! translations/code from its previous turn, including inter-MM shared code.
//! Transport dispatch and that import barrier are separate responsibilities.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use super::super::process_lease::ProcessLease;
use super::super::{AddressSpace, MmError};
use super::{Turn, Turns, WorkerId};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SpaceId(u64);

impl SpaceId {
    pub(super) fn number(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Registration {
    pub(crate) worker: WorkerId,
    pub(crate) space: SpaceId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Grant {
    pub(crate) turn: Turn,
    pub(crate) space: SpaceId,
}

#[derive(Debug)]
pub(crate) enum OwnerError {
    Io(io::Error),
    Memory(MmError),
}

impl fmt::Display for OwnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => fmt::Display::fmt(error, f),
            Self::Memory(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for OwnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Memory(error) => Some(error),
        }
    }
}

impl From<io::Error> for OwnerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<MmError> for OwnerError {
    fn from(error: MmError) -> Self {
        Self::Memory(error)
    }
}

struct Managed<M> {
    space: AddressSpace,
    metadata: M,
    workers: usize,
}

pub(crate) struct MemoryOwner<M> {
    lease: Arc<ProcessLease>,
    turns: Turns,
    workers: BTreeMap<WorkerId, SpaceId>,
    spaces: BTreeMap<SpaceId, Managed<M>>,
    last_space: u64,
    available: bool,
}

impl<M> MemoryOwner<M> {
    /// Adopt a quiescent initial MM into independent owner-managed storage.
    /// The initial worker must bind to that storage before its first CPU entry.
    /// The lease Arc keeps one canonical descriptor per host process; do not
    /// duplicate its file when constructing the broker and workers at fork.
    pub(crate) fn new(
        lease: Arc<ProcessLease>,
        initial: &AddressSpace,
        metadata: M,
    ) -> Result<(Self, Registration), OwnerError> {
        let space = initial.process_snapshot()?;
        let mut turns = Turns::new();
        let worker = turns.register()?;
        let id = SpaceId(1);
        let mut owner = Self {
            lease,
            turns,
            workers: BTreeMap::new(),
            spaces: BTreeMap::new(),
            last_space: 1,
            available: true,
        };
        owner.spaces.insert(
            id,
            Managed {
                space,
                metadata,
                workers: 1,
            },
        );
        owner.workers.insert(worker, id);
        Ok((owner, Registration { worker, space: id }))
    }

    pub(crate) fn begin(
        &mut self,
        worker: WorkerId,
        pid: libc::pid_t,
    ) -> Result<Grant, OwnerError> {
        self.check_available()?;
        let space = self.worker_space(worker)?;
        self.check_space(space)?;
        let turn = self.turns.begin(worker, pid, &self.lease)?;
        Ok(Grant { turn, space })
    }

    pub(crate) fn end(&mut self, turn: Turn) -> Result<(), OwnerError> {
        self.check_available()?;
        self.turns.end(turn, &self.lease)?;
        Ok(())
    }

    /// Execute an owner-local MM request. The closure must not block on a
    /// worker, fork, or export an independently mutable AddressSpace handle.
    /// An escaping panic revokes the owner even if its caller catches it.
    /// Ordinary operation errors retain the underlying MM method's semantics;
    /// this wrapper does not promise rollback of arbitrary closures.
    pub(crate) fn with<R>(
        &mut self,
        turn: Turn,
        run: impl FnOnce(&AddressSpace, &mut M) -> R,
    ) -> Result<R, OwnerError> {
        self.transaction(turn, |owner, id| {
            let managed = owner.spaces.get_mut(&id).ok_or_else(invalid_state)?;
            Ok(run(&managed.space, &mut managed.metadata))
        })
    }

    pub(crate) fn fork_shared(&mut self, turn: Turn) -> Result<Registration, OwnerError> {
        self.transaction(turn, |owner, id| {
            let managed = owner.spaces.get(&id).ok_or_else(invalid_state)?;
            let count = managed
                .workers
                .checked_add(1)
                .ok_or_else(|| io::Error::other("memory-owner reference count exhausted"))?;
            let worker = owner.turns.register()?;
            owner.workers.insert(worker, id);
            owner.spaces.get_mut(&id).ok_or_else(invalid_state)?.workers = count;
            Ok(Registration { worker, space: id })
        })
    }

    /// Derive private-fork bookkeeping explicitly. Linux, for example, clears
    /// mapping locks and gives the child a fresh pinned-page counter; blindly
    /// cloning Arc-backed metadata would retain the parent's bookkeeping.
    /// Preparation happens on the unpublished snapshot. Failure registers no
    /// worker and leaves the parent namespace, mappings and references intact.
    pub(crate) fn fork_private(
        &mut self,
        turn: Turn,
        prepare: impl FnOnce(&AddressSpace, &M) -> Result<M, MmError>,
    ) -> Result<Registration, OwnerError> {
        self.transaction(turn, |owner, parent| {
            let id = owner.next_space()?;
            let source = owner.spaces.get(&parent).ok_or_else(invalid_state)?;
            let space = source.space.process_snapshot()?;
            let metadata = prepare(&space, &source.metadata)?;
            let worker = owner.turns.register()?;
            owner.spaces.insert(
                id,
                Managed {
                    space,
                    metadata,
                    workers: 1,
                },
            );
            owner.workers.insert(worker, id);
            owner.last_space = id.0;
            Ok(Registration { worker, space: id })
        })
    }

    /// Publish a prepared exec MM and rotate the caller's turn. Other workers
    /// retain the old MM and its metadata. Old queued requests cannot operate
    /// on the new MM, even though their endpoint still names the same worker.
    pub(crate) fn exec(
        &mut self,
        turn: Turn,
        prepared: &AddressSpace,
        metadata: M,
    ) -> Result<Grant, OwnerError> {
        self.transaction(turn, |owner, old| {
            let id = owner.next_space()?;
            let space = prepared.process_snapshot()?;
            let replacement = owner.turns.renew(turn, &owner.lease)?;
            owner.spaces.insert(
                id,
                Managed {
                    space,
                    metadata,
                    workers: 1,
                },
            );
            owner.workers.insert(turn.worker(), id);
            owner.last_space = id.0;
            owner.release(old)?;
            Ok(Grant {
                turn: replacement,
                space: id,
            })
        })
    }

    /// Called only after the endpoint is permanently closed. Retiring a
    /// shared worker cannot release the MM retained by another endpoint.
    pub(crate) fn retire(&mut self, worker: WorkerId) -> Result<bool, OwnerError> {
        self.check_available()?;
        let Some(id) = self.workers.remove(&worker) else {
            return Ok(false);
        };
        self.available = false;
        if !self.turns.retire(worker) {
            return Err(invalid_state().into());
        }
        self.release(id)?;
        self.available = true;
        Ok(true)
    }

    fn transaction<R>(
        &mut self,
        turn: Turn,
        run: impl FnOnce(&mut Self, SpaceId) -> Result<R, OwnerError>,
    ) -> Result<R, OwnerError> {
        self.check_available()?;
        self.turns.validate(turn, &self.lease)?;
        let id = self.worker_space(turn.worker())?;
        self.check_space(id)?;
        // No automatic recovery after an unwind in an owner mutation. This
        // flag remains false if the closure panics before returning normally.
        self.available = false;
        let result = run(self, id);
        if self
            .spaces
            .values()
            .any(|managed| !managed.space.available())
        {
            return Err(MmError::InvalidArgument("owner arena unavailable").into());
        }
        if result.as_ref().is_err_and(|error| {
            matches!(error, OwnerError::Io(error) if error.kind() == io::ErrorKind::InvalidData)
        }) {
            return result;
        }
        self.available = true;
        result
    }

    fn check_available(&self) -> io::Result<()> {
        if !self.available {
            return Err(io::Error::other("memory owner unavailable"));
        }
        Ok(())
    }

    fn worker_space(&self, worker: WorkerId) -> io::Result<SpaceId> {
        self.workers.get(&worker).copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown memory-owner worker",
            )
        })
    }

    fn check_space(&mut self, id: SpaceId) -> Result<(), OwnerError> {
        let Some(managed) = self.spaces.get(&id) else {
            self.available = false;
            return Err(invalid_state().into());
        };
        if !managed.space.available() {
            self.available = false;
            return Err(MmError::InvalidArgument("owner arena unavailable").into());
        }
        Ok(())
    }

    fn next_space(&self) -> io::Result<SpaceId> {
        self.last_space
            .checked_add(1)
            .map(SpaceId)
            .ok_or_else(|| io::Error::other("memory-owner MM identity exhausted"))
    }

    fn release(&mut self, id: SpaceId) -> io::Result<()> {
        let managed = self.spaces.get_mut(&id).ok_or_else(invalid_state)?;
        managed.workers = managed.workers.checked_sub(1).ok_or_else(invalid_state)?;
        if managed.workers == 0 {
            self.spaces.remove(&id);
        }
        Ok(())
    }
}

fn invalid_state() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "memory-owner reference invariant",
    )
}

#[cfg(test)]
mod tests;
