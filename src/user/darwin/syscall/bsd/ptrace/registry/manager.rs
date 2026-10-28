//! Bounded nonblocking discovery and setup. Established connections leave
//! this owner and enter the tracing router with their stable Link identity.

use super::super::transport::Link;
use super::{Endpoint, Record, Root, Session, socket::Dial};
use std::io;
use std::time::{Duration, Instant};

const MAX_PENDING: usize = 32;
const ACCEPT_BUDGET: usize = 8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Debug)]
enum Setup {
    Dial(Dial),
    Hello(Session),
}

#[derive(Debug)]
struct Pending {
    peer: Record,
    direction: Direction,
    deadline: Instant,
    setup: Option<Setup>,
}

#[derive(Debug)]
pub(in super::super) enum Event {
    Wake {
        peer: Record,
    },
    Connected {
        peer: Record,
        direction: Direction,
        link: Link,
    },
    Failed {
        pid: i32,
        direction: Direction,
        error: io::Error,
    },
}

#[derive(Debug)]
pub(in super::super) struct Registry {
    root: Root,
    endpoint: Endpoint,
    pending: Vec<Pending>,
}

impl Registry {
    /// A single per-account namespace, independent of each launcher's TMPDIR.
    pub fn host() -> io::Result<Self> {
        Self::open(Root::open(std::path::Path::new("/tmp"))?)
    }
    pub fn open(root: Root) -> io::Result<Self> {
        let endpoint = root.publish()?;
        Ok(Self {
            root,
            endpoint,
            pending: Vec::new(),
        })
    }

    pub fn local(&self) -> Record {
        self.endpoint.record
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.pending.iter().map(|pending| pending.deadline).min()
    }

    pub fn has_incoming_wake(&self) -> bool {
        self.pending.iter().any(|pending| pending.direction==Direction::Incoming
            && matches!(pending.setup.as_ref(),Some(Setup::Hello(session)) if session.claims_wakeup()))
    }

    pub fn cancel_outgoing(&mut self, pid: i32) {
        self.pending
            .retain(|pending| pending.direction != Direction::Outgoing || pending.peer.pid != pid);
    }

    /// Coalesces concurrent setup requests for one outbound PID. The caller
    /// separately checks whether it already owns an established target link.
    pub fn connect(&mut self, pid: i32, now: Instant) -> io::Result<()> {
        if self
            .pending
            .iter()
            .any(|p| p.peer.pid == pid && p.direction == Direction::Outgoing)
        {
            return Ok(());
        }
        if self.pending.len() == MAX_PENDING {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let dial = self.root.connect(pid)?;
        let peer = dial.expected;
        self.pending.push(Pending {
            peer,
            direction: Direction::Outgoing,
            deadline: now + CONNECT_TIMEOUT,
            setup: Some(Setup::Dial(dial)),
        });
        Ok(())
    }

    pub fn wait_fds(&self) -> Vec<(i32, bool, bool)> {
        let mut fds = vec![(self.endpoint.fd(), self.pending.len() < MAX_PENDING, false)];
        fds.extend(
            self.pending
                .iter()
                .filter_map(|pending| match pending.setup.as_ref()? {
                    Setup::Dial(dial) => dial.fd().map(|fd| (fd, false, true)),
                    Setup::Hello(session) => {
                        session.fd().map(|fd| (fd, true, session.wants_write()))
                    }
                }),
        );
        fds
    }

    /// `incoming_slots` is the router's remaining established-peer capacity.
    /// At capacity the listener backlog applies backpressure; setup work
    /// never waits on a peer or loops without a fixed bound.
    pub fn pump(&mut self, now: Instant, incoming_slots: usize) -> Vec<Event> {
        let mut events = Vec::new();
        for _ in 0..ACCEPT_BUDGET.min(incoming_slots) {
            if self.pending.len() == MAX_PENDING {
                break;
            }
            match self.endpoint.accept() {
                Ok(Some((peer, stream))) => match Session::new(stream, self.local(), peer, now) {
                    Ok(session) => self.pending.push(Pending {
                        peer,
                        direction: Direction::Incoming,
                        deadline: now + CONNECT_TIMEOUT,
                        setup: Some(Setup::Hello(session)),
                    }),
                    Err(error) => events.push(Event::Failed {
                        pid: peer.pid,
                        direction: Direction::Incoming,
                        error,
                    }),
                },
                Ok(None) => break,
                Err(error) => {
                    events.push(Event::Failed {
                        pid: 0,
                        direction: Direction::Incoming,
                        error,
                    });
                    break;
                }
            }
        }
        let local = self.local();
        let mut retained = Vec::with_capacity(self.pending.len());
        for mut pending in self.pending.drain(..) {
            let setup = pending.setup.take().expect("owned setup state");
            let result = if now >= pending.deadline {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                match setup {
                    Setup::Dial(mut dial) => match dial.finish() {
                        Ok(Some(stream)) => Session::connecting(stream, local, pending.peer, now)
                            .map(|session| {
                                pending.setup = Some(Setup::Hello(session));
                                None
                            }),
                        Ok(None) => {
                            pending.setup = Some(Setup::Dial(dial));
                            Ok(None)
                        }
                        Err(error) => Err(error),
                    },
                    Setup::Hello(mut session) => {
                        let result = session.pump(now);
                        if pending.direction == Direction::Incoming && session.take_wakeup() {
                            events.push(Event::Wake { peer: pending.peer });
                        }
                        match result {
                            Ok(Some((_peer, link))) => Ok(Some(link)),
                            Ok(None) => {
                                pending.setup = Some(Setup::Hello(session));
                                Ok(None)
                            }
                            Err(error) => Err(error),
                        }
                    }
                }
            };
            match result {
                Ok(Some(link)) => events.push(Event::Connected {
                    peer: pending.peer,
                    direction: pending.direction,
                    link,
                }),
                Ok(None) => retained.push(pending),
                Err(error) => events.push(Event::Failed {
                    pid: pending.peer.pid,
                    direction: pending.direction,
                    error,
                }),
            }
        }
        self.pending = retained;
        events
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::Temporary;
    use super::*;

    #[test]
    fn setup_is_bounded_coalesced_and_returns_distinct_connection_owners() {
        let temp = Temporary::new();
        let root = temp.root();
        let mut registry = Registry::open(root).unwrap();
        let now = Instant::now();
        let pid = registry.local().pid;
        registry.connect(pid, now).unwrap();
        registry.connect(pid, now).unwrap();
        assert_eq!(registry.pending.len(), 1);
        let mut connected = Vec::new();
        for _ in 0..8 {
            for event in registry.pump(now, MAX_PENDING) {
                match event {
                    Event::Connected {
                        peer,
                        direction,
                        link,
                    } => {
                        assert_eq!(peer.pid, pid);
                        connected.push((direction, link));
                    }
                    Event::Failed { error, .. } => panic!("{error}"),
                    Event::Wake { .. } => panic!("running peer must not be woken"),
                }
            }
            if connected.len() == 2 {
                break;
            }
        }
        assert_eq!(connected.len(), 2);
        assert_ne!(connected[0].1.identity(), connected[1].1.identity());
        assert_ne!(connected[0].0, connected[1].0);
        assert_eq!(registry.wait_fds().len(), 1);
    }

    #[test]
    fn a_stalled_peer_times_out_without_blocking_registry_work() {
        let temp = Temporary::new();
        let root = temp.root();
        let mut registry = Registry::open(root.clone()).unwrap();
        let now = Instant::now();
        let mut dial = root.connect(registry.local().pid).unwrap();
        let _stalled = dial.finish().unwrap().unwrap();
        assert!(registry.pump(now, 1).is_empty());
        let events = registry.pump(now + CONNECT_TIMEOUT, 1);
        assert!(
            matches!(events.as_slice(),[Event::Failed{direction:Direction::Incoming,error,..}] if error.kind()==io::ErrorKind::TimedOut)
        );
        assert_eq!(registry.wait_fds().len(), 1);
    }
}
