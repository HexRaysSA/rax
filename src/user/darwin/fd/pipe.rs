//! Guest-owned anonymous Darwin pipes. Descriptors share endpoints and
//! scheduler waiters hold the queue without extending an endpoint's lifetime.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::types::Stat;

pub(crate) const PIPE_BUF: usize = 512;
const NORMAL_SIZE: usize = 16 * 1024;
const MAX_SIZE: usize = 64 * 1024;
const PIPE_SIZES: [usize; 7] = [PIPE_BUF, 1024, 2048, 4096, 8192, NORMAL_SIZE, MAX_SIZE];

pub(crate) const POLLIN: i16 = 0x01;
pub(crate) const POLLOUT: i16 = 0x04;
pub(crate) const POLLHUP: i16 = 0x10;
pub(crate) const POLLNVAL: i16 = 0x20;
pub(crate) const POLLRDNORM: i16 = 0x40;
const POLLPRI: i16 = 0x02;
const POLLRDBAND: i16 = 0x80;
const POLLWRBAND: i16 = 0x100;
pub(crate) const POLL_READ: i16 = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
pub(crate) const POLL_WRITE: i16 = POLLOUT | POLLWRBAND;
pub(crate) const POLL_VNODE: i16 = 0x1e00;
pub(crate) const POLL_WATCH: i16 = POLL_READ | POLL_WRITE | POLLHUP | POLL_VNODE;

#[derive(Debug)]
struct State {
    bytes: VecDeque<u8>,
    capacity: usize,
    reader: bool,
    writer: bool,
}

impl State {
    fn poll(&self, read: bool, events: i16) -> i16 {
        if events & POLL_VNODE != 0 {
            return POLLNVAL;
        }
        if events & POLL_WATCH == 0 {
            return 0;
        }
        let peer_open = if read { self.writer } else { self.reader };
        if !peer_open {
            return POLLHUP | (events & POLL_READ);
        }
        if read && !self.bytes.is_empty() {
            return events & POLL_READ;
        }
        if !read && self.capacity.max(NORMAL_SIZE) - self.bytes.len() >= PIPE_BUF {
            return events & POLL_WRITE;
        }
        0
    }
}

/// One open end of an anonymous pipe, shared by duplicated descriptors.
#[derive(Debug)]
pub struct PipeEnd {
    state: Arc<Mutex<State>>,
    inode: u64,
    uid: u32,
    gid: u32,
    read: bool,
    no_sigpipe: AtomicBool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PipeCondition {
    Read,
    Write(usize),
    Poll(i16),
}

#[derive(Clone, Debug)]
pub(crate) struct PipeWait {
    state: Arc<Mutex<State>>,
    read: bool,
    condition: PipeCondition,
}

impl PartialEq for PipeWait {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
            && self.read == other.read
            && self.condition == other.condition
    }
}

impl Eq for PipeWait {}

impl PipeWait {
    pub(crate) fn ready(&self) -> bool {
        let state = self.state.lock().unwrap();
        match self.condition {
            PipeCondition::Read => !state.writer || !state.bytes.is_empty(),
            PipeCondition::Write(space) => {
                !state.reader || space <= state.capacity - state.bytes.len()
            }
            PipeCondition::Poll(events) => state.poll(self.read, events) != 0,
        }
    }
}

impl PipeEnd {
    pub(crate) fn pair(uid: u32, gid: u32) -> (Self, Self) {
        static NEXT_INODE: AtomicU64 = AtomicU64::new(1);
        let state = Arc::new(Mutex::new(State {
            bytes: VecDeque::new(),
            capacity: 0,
            reader: true,
            writer: true,
        }));
        let end = |read| Self {
            state: Arc::clone(&state),
            inode: NEXT_INODE.fetch_add(1, Ordering::Relaxed),
            uid,
            gid,
            read,
            no_sigpipe: AtomicBool::new(false),
        };
        (end(true), end(false))
    }

    pub(crate) fn check(&self, read: bool, offset: Option<i64>) -> Result<(), Errno> {
        if self.read != read {
            return Err(Errno::EBADF);
        }
        if offset.is_some() {
            return Err(Errno::ESPIPE);
        }
        Ok(())
    }

    pub(crate) fn wait(&self, condition: PipeCondition) -> PipeWait {
        PipeWait {
            state: Arc::clone(&self.state),
            read: self.read,
            condition,
        }
    }

    pub(crate) fn poll(&self, events: i16) -> i16 {
        self.state.lock().unwrap().poll(self.read, events)
    }

    pub(crate) fn read_with(
        &self,
        count: usize,
        copy: impl FnOnce(&[u8]) -> Result<(), Errno>,
    ) -> Result<usize, Errno> {
        let mut state = self.state.lock().unwrap();
        if count != 0 && state.bytes.is_empty() && state.writer {
            return Err(Errno::EAGAIN);
        }
        let n = count.min(state.bytes.len());
        if n != 0 {
            let bytes = state.bytes.make_contiguous();
            copy(&bytes[..n])?;
            state.bytes.drain(..n);
        }
        Ok(n)
    }

    pub(crate) fn write_with(
        &self,
        count: usize,
        atomic: bool,
        start: bool,
        copy: impl FnOnce(usize) -> Result<Vec<u8>, Errno>,
    ) -> Result<usize, Errno> {
        let mut state = self.state.lock().unwrap();
        if !state.reader {
            return Err(Errno::EPIPE);
        }
        if count == 0 {
            return Ok(0);
        }
        if start && count > state.capacity - state.bytes.len() {
            let target = state.bytes.len() + count;
            state.capacity = PIPE_SIZES
                .into_iter()
                .find(|&size| size > target)
                .unwrap_or(MAX_SIZE);
        }
        let free = state.capacity - state.bytes.len();
        if free == 0 || (atomic && count > free) {
            return Err(Errno::EAGAIN);
        }
        let n = count.min(free);
        let bytes = copy(n)?;
        debug_assert_eq!(bytes.len(), n);
        state.bytes.extend(bytes);
        Ok(n)
    }

    pub(crate) fn available(&self) -> u64 {
        if self.read {
            self.state.lock().unwrap().bytes.len() as u64
        } else {
            0
        }
    }

    pub(crate) fn stat(&self) -> Stat {
        let state = self.state.lock().unwrap();
        let size = state.bytes.len();
        let block = state.capacity.max(NORMAL_SIZE);
        Stat {
            ino: self.inode,
            mode: 0o010660,
            uid: self.uid,
            gid: self.gid,
            size: size as i64,
            blksize: block as i32,
            blocks: size.div_ceil(block) as i64,
            ..Default::default()
        }
    }

    pub(crate) fn no_sigpipe(&self) -> bool {
        self.no_sigpipe.load(Ordering::Relaxed)
    }

    pub(crate) fn set_no_sigpipe(&self, enabled: bool) {
        self.no_sigpipe.store(enabled, Ordering::Relaxed);
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        if self.read {
            state.reader = false;
            state.capacity = 0;
            state.bytes = VecDeque::new();
        } else {
            state.writer = false;
        }
    }
}
