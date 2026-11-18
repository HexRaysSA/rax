//! Serial dispatcher for a process family's authoritative memory owner.
//! Construct it in its final broker process, after the startup fork. Worker
//! processes retain only their client channel and canonical execution lease.
//!
//! A blocking framed receive is safe only with exclusive endpoint ownership:
//! workers must close inherited copies of every unrelated client descriptor.
//! Guest waits and host forks take place outside client sessions.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::wire::{PreparationFailure, Request, Response};
use super::{Channel, Client, MemoryOwner, OwnerError, Turn, WorkerId};
use super::{operations, physical};
use crate::user::mm::process_lease::ProcessLease;
use crate::user::mm::{AddressSpace, Backing, MmError};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct BackingId(u64);

/// Personality-specific MM bookkeeping must explicitly derive private-fork
/// state. Shared clones retain the existing metadata record without copying.
pub(crate) trait ForkMetadata: Sized {
    fn fork_private(&self, snapshot: &AddressSpace) -> Result<Self, MmError>;

    /// Execute a personality's complete MM operation while mappings and
    /// bookkeeping are exclusively owned together. Invalid/unsupported input
    /// revokes the endpoint. Guest errors belong in the personality reply.
    fn transact(
        &mut self,
        _space: &AddressSpace,
        _request: &[u8],
        _backings: &BTreeMap<BackingId, Backing>,
    ) -> io::Result<Vec<u8>> {
        Err(invalid())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    Completed,
    Retired,
    Empty,
}

struct PendingFork {
    worker: WorkerId,
    server: Channel,
    peer: UnixStream,
    backings: BTreeMap<BackingId, Backing>,
}

pub(crate) struct Broker<M> {
    pid: libc::pid_t,
    owner: MemoryOwner<M>,
    endpoints: BTreeMap<WorkerId, Channel>,
    backings: BTreeMap<WorkerId, BTreeMap<BackingId, Backing>>,
    pending_forks: BTreeMap<WorkerId, PendingFork>,
    last_backing: u64,
}

impl<M: ForkMetadata> Broker<M> {
    pub(crate) fn new(
        lease: Arc<ProcessLease>,
        initial: &AddressSpace,
        metadata: M,
    ) -> Result<(Self, Client, WorkerId), OwnerError> {
        let (server, client) = Channel::pair()?;
        let (owner, root) = MemoryOwner::new(lease, initial, metadata)?;
        Ok((
            Self {
                pid: pid(),
                owner,
                endpoints: BTreeMap::from([(root.worker, server)]),
                backings: BTreeMap::from([(root.worker, BTreeMap::new())]),
                pending_forks: BTreeMap::new(),
                last_backing: 0,
            },
            Client::new(client),
            root.worker,
        ))
    }

    /// Register an actual source, including its opaque lifetime retention,
    /// in the broker. Forks inherit these handles; EOF drops only that
    /// endpoint's catalog. VMAs retain their own source references afterward.
    /// New mmap/exec descriptor registration belongs to the personality; a
    /// worker must never synthesize a PageSource callback from wire data.
    pub(crate) fn register_backing(
        &mut self,
        worker: WorkerId,
        backing: Backing,
    ) -> io::Result<BackingId> {
        self.check_host()?;
        let catalog = self.backings.get_mut(&worker).ok_or_else(invalid)?;
        let next = self
            .last_backing
            .checked_add(1)
            .ok_or_else(|| io::Error::other("owner backing identity exhausted"))?;
        let id = BackingId(next);
        catalog.insert(id, backing);
        self.last_backing = next;
        Ok(id)
    }

    /// Wait for and dispatch one frame. The event loop can continue after an
    /// endpoint-local protocol/transport error: that endpoint is already
    /// closed and retired. No failed request is retried. Owner unavailability
    /// remains fail-closed for every later request.
    pub(crate) fn serve_one(&mut self) -> Result<Event, OwnerError> {
        self.check_host()?;
        if self.endpoints.is_empty() {
            return Ok(Event::Empty);
        }
        let workers: Vec<_> = self.endpoints.keys().copied().collect();
        let mut poll: Vec<_> = workers
            .iter()
            .map(|worker| {
                Ok(libc::pollfd {
                    fd: self.endpoints[worker].poll_fd()?,
                    events: libc::POLLIN,
                    revents: 0,
                })
            })
            .collect::<io::Result<_>>()?;
        loop {
            // SAFETY: poll owns a live contiguous pollfd array. Each fd is
            // exclusively held by the corresponding endpoint until return.
            let result = unsafe { libc::poll(poll.as_mut_ptr(), poll.len() as libc::nfds_t, -1) };
            if result >= 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        let index = poll
            .iter()
            .position(|item| item.revents != 0)
            .ok_or_else(invalid)?;
        let worker = workers[index];
        let mut channel = self.endpoints.remove(&worker).ok_or_else(invalid)?;
        let result = self.dispatch(worker, &mut channel);
        match result {
            Ok(Event::Retired) => {
                channel.close();
                self.retire(worker)?;
                Ok(Event::Retired)
            }
            Ok(event) => {
                self.endpoints.insert(worker, channel);
                Ok(event)
            }
            Err(error) => {
                channel.close();
                self.retire(worker)?;
                Err(error)
            }
        }
    }

    fn dispatch(&mut self, worker: WorkerId, channel: &mut Channel) -> Result<Event, OwnerError> {
        let frame = match channel.receive() {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(Event::Retired);
            }
            Err(error) => return Err(error.into()),
        };
        if !frame.files.is_empty() {
            return Err(invalid().into());
        }
        let request: Request = serde_json::from_slice(&frame.bytes).map_err(|_| invalid())?;
        if self.pending_forks.contains_key(&worker)
            && !matches!(request, Request::ConfirmFork { .. })
        {
            return Err(invalid().into());
        }
        let reply = match request {
            Request::Begin { pid } => {
                let grant = self.owner.begin(worker, pid)?;
                Response::Grant {
                    serial: grant.turn.serial(),
                    space: grant.space.number(),
                }
            }
            Request::End { serial } => {
                self.owner.end(Turn::from_endpoint(worker, serial))?;
                Response::Ended
            }
            Request::Memory { serial, operation } => {
                if !operation.valid_size() {
                    return Err(invalid().into());
                }
                let backings = self.backings.get_mut(&worker).ok_or_else(invalid)?;
                let result = self
                    .owner
                    .with(Turn::from_endpoint(worker, serial), |space, _| {
                        operations::execute(space, backings, operation)
                    })?;
                Response::Result { result }
            }
            Request::Personality { serial, bytes } => {
                if bytes.len() > super::wire::PERSONALITY_BYTES {
                    return Err(invalid().into());
                }
                let backings = self.backings.get(&worker).ok_or_else(invalid)?;
                let bytes = self
                    .owner
                    .with(Turn::from_endpoint(worker, serial), |space, metadata| {
                        metadata.transact(space, &bytes, backings)
                    })??;
                if bytes.len() > super::wire::PERSONALITY_BYTES {
                    return Err(invalid().into());
                }
                Response::Personality { bytes }
            }
            Request::Fork { serial, private } => {
                return self.fork(
                    worker,
                    Turn::from_endpoint(worker, serial),
                    private,
                    channel,
                );
            }
            Request::ConfirmFork { serial } => {
                return self.confirm_fork(worker, Turn::from_endpoint(worker, serial), channel);
            }
            Request::View { serial, operation } => {
                let export = self
                    .owner
                    .with(Turn::from_endpoint(worker, serial), |space, _| {
                        physical::export(space, operation)
                    })?;
                match export {
                    Ok(export) => {
                        let files: Vec<_> = export.file.iter().map(AsFd::as_fd).collect();
                        send(
                            channel,
                            &Response::View {
                                result: Ok(export.value),
                            },
                            &files,
                        )?;
                    }
                    Err(error) => send(channel, &Response::View { result: Err(error) }, &[])?,
                }
                return Ok(Event::Completed);
            }
        };
        send(channel, &reply, &[])?;
        Ok(Event::Completed)
    }

    fn fork(
        &mut self,
        worker: WorkerId,
        turn: Turn,
        private: bool,
        channel: &mut Channel,
    ) -> Result<Event, OwnerError> {
        // Reject stale/foreign turns even when transport resources are
        // exhausted. Only a validated caller receives recoverable failures.
        self.owner.with(turn, |_, _| ())?;
        // Allocate transport and copy the handle namespace before publishing a
        // worker/MM reference. Preparation failure leaves neither behind.
        let transport = UnixStream::pair()
            .and_then(|(server, client)| Channel::new(server).map(|server| (server, client)));
        let (mut server, client) = match transport {
            Ok(pair) => pair,
            Err(error) => {
                send(
                    channel,
                    &Response::ForkFailed {
                        failure: PreparationFailure::from(error),
                    },
                    &[],
                )?;
                return Ok(Event::Completed);
            }
        };
        let catalog = self.backings.get(&worker).ok_or_else(invalid)?.clone();
        let registration = if private {
            self.owner
                .fork_private(turn, |space, metadata| metadata.fork_private(space))
        } else {
            self.owner.fork_shared(turn)
        };
        let registration = match registration {
            Ok(registration) => registration,
            Err(OwnerError::Memory(error)) => {
                send(
                    channel,
                    &Response::Result {
                        result: Err(error.into()),
                    },
                    &[],
                )?;
                return Ok(Event::Completed);
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = send(channel, &Response::Forked, &[client.as_fd()]) {
            server.close();
            self.owner.retire(registration.worker)?;
            return Err(error.into());
        }
        // On macOS a socket collected via SCM_RIGHTS can report EOF after
        // the sender closes its copy before the receiver collects it.
        // Retain our copy until confirmation and keep the prepared worker
        // out of the poll set until the receiving client can use it.
        self.pending_forks.insert(
            worker,
            PendingFork {
                worker: registration.worker,
                server,
                peer: client,
                backings: catalog,
            },
        );
        Ok(Event::Completed)
    }

    fn confirm_fork(
        &mut self,
        parent: WorkerId,
        turn: Turn,
        channel: &mut Channel,
    ) -> Result<Event, OwnerError> {
        self.owner.with(turn, |_, _| ())?;
        if !self.pending_forks.contains_key(&parent) {
            return Err(invalid().into());
        }
        send(channel, &Response::ForkConfirmed, &[])?;
        let PendingFork {
            worker,
            server,
            peer,
            backings,
        } = self.pending_forks.remove(&parent).ok_or_else(invalid)?;
        drop(peer);
        self.endpoints.insert(worker, server);
        self.backings.insert(worker, backings);
        Ok(Event::Completed)
    }

    fn retire(&mut self, worker: WorkerId) -> Result<(), OwnerError> {
        self.backings.remove(&worker);
        if let Some(mut pending) = self.pending_forks.remove(&worker) {
            pending.server.close();
            self.owner.retire(pending.worker)?;
        }
        self.owner.retire(worker)?;
        Ok(())
    }

    fn check_host(&mut self) -> io::Result<()> {
        if self.pid != pid() {
            // An initialized owner must never be inherited as a new broker.
            // Shutdown would also change the original broker's sockets in
            // its other host process. Reject without touching those sockets.
            return Err(io::Error::other("memory broker inherited across host fork"));
        }
        Ok(())
    }
}

pub(super) fn send(
    channel: &mut Channel,
    response: &Response,
    files: &[std::os::fd::BorrowedFd<'_>],
) -> io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(|_| invalid())?;
    channel.send(&bytes, files)
}

fn pid() -> libc::pid_t {
    // SAFETY: getpid has no pointer or caller-owned mutable state.
    unsafe { libc::getpid() }
}

pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid memory-owner request")
}

#[cfg(test)]
mod tests;
