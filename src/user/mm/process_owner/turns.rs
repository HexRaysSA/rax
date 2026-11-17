//! Broker-side execution turns, independent of guest PID and MM numbering.
//!
//! A worker takes the family lease before requesting a turn and waits for the
//! broker's reply before executing. Every request carries the granted turn.
//! The broker processes requests serially and verifies the native lock holder
//! again before mutation. Thus an old in-flight request completes before a
//! successor's grant, or is rejected; it cannot run after that grant.
//!
//! Worker IDs and turn serials are never reused. The dedicated endpoint binds
//! requests to a worker ID; the first valid begin binds that endpoint to one
//! host PID. Guest fork must register a fresh endpoint and worker ID. EOF
//! retires that ID. These are internal coordination checks, not authentication
//! against arbitrary code already running in the same host process.

use std::collections::BTreeMap;
use std::io;

use super::super::process_lease::ProcessLease;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct WorkerId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Turn {
    worker: WorkerId,
    serial: u64,
}

impl Turn {
    pub(super) fn worker(self) -> WorkerId {
        self.worker
    }

    pub(super) fn serial(self) -> u64 {
        self.serial
    }

    pub(super) fn from_endpoint(worker: WorkerId, serial: u64) -> Self {
        Self { worker, serial }
    }
}

pub(crate) struct Turns {
    broker_pid: libc::pid_t,
    last_worker: u64,
    last_turn: u64,
    workers: BTreeMap<WorkerId, Option<libc::pid_t>>,
    active: Option<Turn>,
}

impl Turns {
    pub(crate) fn new() -> Self {
        Self {
            // SAFETY: getpid takes no pointers and has no mutable caller state.
            broker_pid: unsafe { libc::getpid() },
            last_worker: 0,
            last_turn: 0,
            workers: BTreeMap::new(),
            active: None,
        }
    }

    pub(crate) fn register(&mut self) -> io::Result<WorkerId> {
        let serial = next(self.last_worker)?;
        let worker = WorkerId(serial);
        self.workers.insert(worker, None);
        self.last_worker = serial;
        Ok(worker)
    }

    /// The caller selects worker from the owned endpoint, never from payload.
    /// A repeated begin rotates the token even for the same worker and PID.
    pub(crate) fn begin(
        &mut self,
        worker: WorkerId,
        pid: libc::pid_t,
        lease: &ProcessLease,
    ) -> io::Result<Turn> {
        self.begin_observed(worker, pid, lease.holder()?)
    }

    fn begin_observed(
        &mut self,
        worker: WorkerId,
        pid: libc::pid_t,
        holder: Option<libc::pid_t>,
    ) -> io::Result<Turn> {
        let bound = self.workers.get(&worker).ok_or_else(rejected)?;
        if pid <= 0
            || pid == self.broker_pid
            || holder != Some(pid)
            || bound.is_some_and(|bound| bound != pid)
            || self
                .workers
                .iter()
                .any(|(other, bound)| *other != worker && *bound == Some(pid))
        {
            return Err(rejected());
        }
        let serial = next(self.last_turn)?;
        let turn = Turn { worker, serial };
        self.workers.insert(worker, Some(pid));
        self.last_turn = serial;
        self.active = Some(turn);
        Ok(turn)
    }

    pub(crate) fn validate(&self, turn: Turn, lease: &ProcessLease) -> io::Result<()> {
        self.validate_observed(turn, lease.holder()?)
    }

    fn validate_observed(&self, turn: Turn, holder: Option<libc::pid_t>) -> io::Result<()> {
        if self.active != Some(turn)
            || holder.is_none()
            || self.workers.get(&turn.worker).copied().flatten() != holder
        {
            return Err(rejected());
        }
        Ok(())
    }

    /// The worker waits for this reply before releasing its native lease.
    pub(crate) fn end(&mut self, turn: Turn, lease: &ProcessLease) -> io::Result<()> {
        self.validate(turn, lease)?;
        self.active = None;
        Ok(())
    }

    /// Replace a live turn after its worker switches to a new MM at exec.
    /// Requests queued with the pre-exec token must not address the new MM.
    pub(crate) fn renew(&mut self, turn: Turn, lease: &ProcessLease) -> io::Result<Turn> {
        self.validate(turn, lease)?;
        let pid = self
            .workers
            .get(&turn.worker)
            .copied()
            .flatten()
            .ok_or_else(rejected)?;
        self.begin(turn.worker, pid, lease)
    }

    /// EOF invalidates pending turns even if another worker still owns the MM.
    /// MM-reference removal is the memory owner's separate responsibility.
    pub(crate) fn retire(&mut self, worker: WorkerId) -> bool {
        if self.active.is_some_and(|turn| turn.worker == worker) {
            self.active = None;
        }
        self.workers.remove(&worker).is_some()
    }
}

fn next(previous: u64) -> io::Result<u64> {
    previous
        .checked_add(1)
        .ok_or_else(|| io::Error::other("memory-owner identity exhausted"))
}

fn rejected() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "invalid memory-owner turn")
}

#[cfg(test)]
mod tests;
