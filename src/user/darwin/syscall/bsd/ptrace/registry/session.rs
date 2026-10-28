//! Exchange process-instance records before admitting ordinary protocol
//! frames. The kernel socket identity is checked before constructing this
//! state; the hello additionally rejects stale publications and PID reuse.

use super::super::transport::Link;
use super::{Record, invalid};
use std::io;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const HELLO_SIZE: usize = super::RECORD_SIZE + 1;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(in super::super) struct Session {
    link: Option<Link>,
    expected: Record,
    received: bool,
    wake: Option<super::wake::Wake>,
    peer_wake: bool,
    wake_claimed: bool,
    deadline: Instant,
}

impl Session {
    pub fn new(
        stream: UnixStream,
        local: Record,
        expected: Record,
        now: Instant,
    ) -> io::Result<Self> {
        Self::start(stream, local, expected, now, None)
    }

    pub fn connecting(
        stream: UnixStream,
        local: Record,
        expected: Record,
        now: Instant,
    ) -> io::Result<Self> {
        let wake = super::wake::Wake::prepare(&stream, expected)?;
        Self::start(stream, local, expected, now, wake)
    }

    fn start(
        stream: UnixStream,
        local: Record,
        expected: Record,
        now: Instant,
        wake: Option<super::wake::Wake>,
    ) -> io::Result<Self> {
        let mut link = Link::new(stream)?;
        let mut hello = local.encode().to_vec();
        hello.push(u8::from(wake.is_some()));
        link.queue(&hello)?;
        Ok(Self {
            link: Some(link),
            expected,
            received: false,
            wake,
            peer_wake: false,
            wake_claimed: false,
            deadline: now + HELLO_TIMEOUT,
        })
    }

    pub fn claims_wakeup(&self) -> bool {
        self.received && self.peer_wake
    }

    pub fn take_wakeup(&mut self) -> bool {
        self.received && self.peer_wake && !std::mem::replace(&mut self.wake_claimed, true)
    }

    pub fn fd(&self) -> Option<i32> {
        self.link.as_ref().map(Link::fd)
    }
    pub fn wants_write(&self) -> bool {
        self.link.as_ref().is_some_and(Link::wants_write)
    }

    pub fn pump(&mut self, now: Instant) -> io::Result<Option<(Record, Link)>> {
        let link = self
            .link
            .as_mut()
            .ok_or_else(|| invalid("registry handshake already consumed"))?;
        if now >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let output = link.flush();
        if output.is_ok()
            && !link.wants_write()
            && let Some(wake) = self.wake.take()
        {
            wake.signal()?;
        }
        if !self.received {
            let (frames, closed) = link.receive_setup_frame(HELLO_SIZE)?;
            for frame in frames {
                if frame.fd.is_some()
                    || frame.payload.len() != HELLO_SIZE
                    || frame.payload[HELLO_SIZE - 1] > 1
                    || Record::decode(&frame.payload[..super::RECORD_SIZE])? != self.expected
                {
                    return Err(invalid("registry peer instance mismatch"));
                }
                self.peer_wake = frame.payload[HELLO_SIZE - 1] != 0;
                self.received = true;
            }
            if closed {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        output?;
        if self.received && !link.wants_write() {
            return Ok(Some((self.expected, self.link.take().unwrap())));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn records() -> (Record, Record) {
        (
            Record {
                pid: 1001,
                uid: 501,
                instance: [1; 16],
            },
            Record {
                pid: 1002,
                uid: 501,
                instance: [2; 16],
            },
        )
    }

    #[test]
    fn reciprocal_hello_keeps_the_next_protocol_frame_in_wire_order() {
        let (a, b) = UnixStream::pair().unwrap();
        let (left, right) = records();
        let now = Instant::now();
        let mut a = Session::new(a, left, right, now).unwrap();
        let mut b = Session::new(b, right, left, now).unwrap();
        assert!(a.pump(now).unwrap().is_none());
        let (peer, mut ready_b) = b.pump(now).unwrap().unwrap();
        assert_eq!(peer, left);
        ready_b.queue(b"next protocol request").unwrap();
        ready_b.flush().unwrap();
        let (peer, mut ready_a) = a.pump(now).unwrap().unwrap();
        assert_eq!(peer, right);
        let (frames, closed) = ready_a.receive_one_frame().unwrap();
        assert!(!closed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"next protocol request");
    }

    #[test]
    fn stale_instance_and_descriptor_bearing_hello_are_rejected() {
        let (local, peer) = records();
        let now = Instant::now();
        for descriptor in [false, true] {
            let (a, b) = UnixStream::pair().unwrap();
            let mut session = Session::new(a, local, peer, now).unwrap();
            let mut remote = Link::new(b).unwrap();
            if descriptor {
                let file = std::fs::File::open("/dev/null").unwrap();
                remote.queue_with_fd(&peer.encode(), file).unwrap();
            } else {
                let mut stale = peer;
                stale.instance = [3; 16];
                remote.queue(&stale.encode()).unwrap();
            }
            remote.flush().unwrap();
            assert_eq!(
                session.pump(now).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn partial_hello_never_promotes_and_has_a_bounded_deadline() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let (local, peer) = records();
        let now = Instant::now();
        let mut session = Session::new(a, local, peer, now).unwrap();
        b.write_all(&(HELLO_SIZE as u32).to_le_bytes()).unwrap();
        b.write_all(&peer.encode()[..3]).unwrap();
        assert!(session.pump(now).unwrap().is_none());
        assert_eq!(
            session.pump(now + HELLO_TIMEOUT).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn an_oversized_hello_is_rejected_from_its_header_without_waiting_for_payload() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let (local, peer) = records();
        let now = Instant::now();
        let mut session = Session::new(a, local, peer, now).unwrap();
        b.write_all(&((HELLO_SIZE + 1) as u32).to_le_bytes())
            .unwrap();
        assert_eq!(
            session.pump(now).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn an_authenticated_wake_is_retained_even_when_the_caller_disconnects() {
        let (local, peer) = records();
        let now = Instant::now();
        let (a, b) = UnixStream::pair().unwrap();
        let mut session = Session::new(a, local, peer, now).unwrap();
        let mut remote = Link::new(b).unwrap();
        let mut hello = peer.encode().to_vec();
        hello.push(1);
        remote.queue(&hello).unwrap();
        remote.flush().unwrap();
        drop(remote);
        let _ = session.pump(now);
        assert!(session.take_wakeup());
        assert!(!session.take_wakeup());
    }

    #[test]
    fn unknown_wake_bits_and_stale_generations_never_claim_a_wake() {
        for flag in [1u8, 2, 255] {
            let (local, peer) = records();
            let (a, b) = UnixStream::pair().unwrap();
            let now = Instant::now();
            let mut session = Session::new(a, local, peer, now).unwrap();
            let mut remote = Link::new(b).unwrap();
            let mut claimed = peer;
            if flag == 1 {
                claimed.instance = [9; 16];
            }
            let mut hello = claimed.encode().to_vec();
            hello.push(flag);
            remote.queue(&hello).unwrap();
            remote.flush().unwrap();
            assert!(session.pump(now).is_err());
            assert!(!session.take_wakeup());
        }
    }
}
