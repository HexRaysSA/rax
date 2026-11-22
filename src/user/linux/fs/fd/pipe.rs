//! Anonymous pipes for closed guests. Both ends share bounded guest data and
//! the scheduler observes changes without opening a host descriptor.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use super::{EAGAIN, EBUSY, EINVAL, ENFILE, ENOMEM, EPERM, EPIPE};
use super::{Errno, FileObject, FileType, O_RDONLY, O_WRONLY, OpenFile};

const PAGE: usize = 4096;
const DEFAULT_SLOTS: usize = 16;
const MAX_SLOTS: usize = 256;
const PROCESS_SLOTS: usize = DEFAULT_SLOTS * 1024;

#[derive(Debug, Default)]
pub(super) struct PipePool {
    reserved: AtomicUsize,
    next_inode: AtomicU64,
}

impl PipePool {
    /// Reserve the potential buffer space before making it available.
    fn reserve(&self, slots: usize) -> bool {
        self.reserved
            .fetch_update(Relaxed, Relaxed, |used| {
                (used + slots <= PROCESS_SLOTS).then_some(used + slots)
            })
            .is_ok()
    }

    fn release(&self, slots: usize) {
        self.reserved.fetch_sub(slots, Relaxed);
    }

    pub(super) fn open(
        self: &Arc<Self>,
        status: u32,
        packet_flag: u32,
        owner: (u32, u32),
    ) -> Result<(Arc<OpenFile>, Arc<OpenFile>), Errno> {
        if !self.reserve(DEFAULT_SLOTS) {
            return Err(Errno(ENFILE));
        }
        let inode = self.next_inode.fetch_add(1, Relaxed) + 1;
        let pipe = Arc::new(Pipe {
            pool: self.clone(),
            inode,
            owner,
            state: Mutex::new(State {
                buffers: VecDeque::new(),
                slots: DEFAULT_SLOTS,
                readers: true,
                writers: true,
                generation: 0,
            }),
        });
        let name = format!("pipe:[{inode}]");
        let end = |reads, flags| {
            OpenFile::new(
                FileObject::GuestPipe(PipeEnd {
                    pipe: pipe.clone(),
                    reads,
                    packet_flag,
                }),
                FileType::Fifo,
                name.clone(),
                None,
                flags,
            )
        };
        let reader = end(true, O_RDONLY | (status & !packet_flag));
        let writer = end(false, O_WRONLY | status);
        *reader.peer.lock().unwrap() = Arc::downgrade(&writer);
        *writer.peer.lock().unwrap() = Arc::downgrade(&reader);
        Ok((reader, writer))
    }
}

#[derive(Debug)]
struct Buffer {
    bytes: Vec<u8>,
    consumed: usize,
    packet: bool,
}

impl Buffer {
    fn remaining(&self) -> &[u8] {
        &self.bytes[self.consumed..]
    }
}

#[derive(Debug)]
struct State {
    buffers: VecDeque<Buffer>,
    slots: usize,
    readers: bool,
    writers: bool,
    generation: u64,
}

impl State {
    fn changed(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
}

#[derive(Debug)]
struct Pipe {
    pool: Arc<PipePool>,
    inode: u64,
    owner: (u32, u32),
    state: Mutex<State>,
}

impl Drop for Pipe {
    fn drop(&mut self) {
        self.pool.release(self.state.get_mut().unwrap().slots);
    }
}

/// One anonymous pipe endpoint. Duplicate descriptors share the endpoint.
pub struct PipeEnd {
    pipe: Arc<Pipe>,
    reads: bool,
    packet_flag: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct PipeWait {
    pipe: Arc<Pipe>,
    generation: u64,
}

impl PipeWait {
    pub(crate) fn changed(&self) -> bool {
        self.pipe.state.lock().unwrap().generation != self.generation
    }
}

impl PartialEq for PipeWait {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pipe, &other.pipe) && self.generation == other.generation
    }
}

impl Eq for PipeWait {}

impl PipeEnd {
    pub(crate) fn inode(&self) -> u64 {
        self.pipe.inode
    }

    pub(crate) fn owner(&self) -> (u32, u32) {
        self.pipe.owner
    }

    pub(crate) fn packet_flag(&self) -> u32 {
        self.packet_flag
    }

    pub(crate) fn capacity(&self) -> usize {
        self.pipe.state.lock().unwrap().slots * PAGE
    }

    pub(crate) fn resize(&self, requested: u32) -> Result<usize, Errno> {
        let size = requested
            .max(PAGE as u32)
            .checked_next_power_of_two()
            .ok_or(Errno(EINVAL))? as usize;
        let slots = size / PAGE;
        let mut state = self.pipe.state.lock().unwrap();
        if slots < state.buffers.len() {
            return Err(Errno(EBUSY));
        }
        if slots > state.slots {
            if slots > MAX_SLOTS || !self.pipe.pool.reserve(slots - state.slots) {
                return Err(Errno(EPERM));
            }
        } else {
            self.pipe.pool.release(state.slots - slots);
        }
        state.slots = slots;
        state.changed();
        Ok(size)
    }

    pub(crate) fn close(&self) -> u32 {
        let mut state = self.pipe.state.lock().unwrap();
        let wake = if self.reads {
            state.readers = false;
            0x008 // EPOLLERR
        } else {
            state.writers = false;
            0x010 // EPOLLHUP
        };
        state.changed();
        wake
    }

    pub(crate) fn wait(&self) -> PipeWait {
        PipeWait {
            pipe: self.pipe.clone(),
            generation: self.pipe.state.lock().unwrap().generation,
        }
    }

    pub(crate) fn poll(&self) -> (super::super::super::syscall::ready::Polled, PipeWait) {
        use super::super::super::syscall::ready::{Polled, ev};
        let state = self.pipe.state.lock().unwrap();
        let mut result = Polled::default();
        if self.reads {
            result.level = queued(&state) as u64;
            if result.level != 0 {
                result.mask |= ev::IN | ev::RDNORM;
            }
            if !state.writers {
                result.mask |= ev::HUP;
            }
        } else {
            if state.buffers.len() < state.slots {
                result.mask |= ev::OUT | ev::WRNORM;
            }
            if !state.readers {
                result.mask |= ev::ERR;
            }
        }
        let wait = PipeWait {
            pipe: self.pipe.clone(),
            generation: state.generation,
        };
        (result, wait)
    }

    pub(crate) fn queued(&self) -> usize {
        queued(&self.pipe.state.lock().unwrap())
    }

    /// Full buffers that a read can consume before encountering a guest fault.
    pub(crate) fn read_room(&self, room: u64, count: u64) -> u64 {
        let state = self.pipe.state.lock().unwrap();
        if state.buffers.is_empty() {
            return room;
        }
        let mut copied = 0;
        for buffer in &state.buffers {
            let next = copied + (buffer.remaining().len() as u64).min(count - copied);
            if next > room {
                break;
            }
            copied = next;
            if buffer.packet || copied == count {
                break;
            }
        }
        copied
    }

    pub(super) fn read(&self, dest: &mut [u8]) -> Result<usize, Errno> {
        let mut state = self.pipe.state.lock().unwrap();
        if dest.is_empty() || state.buffers.is_empty() && !state.writers {
            return Ok(0);
        }
        if state.buffers.is_empty() {
            return Err(Errno(EAGAIN));
        }
        let mut done = 0;
        while done < dest.len() {
            let Some(buffer) = state.buffers.front_mut() else {
                break;
            };
            let take = buffer.remaining().len().min(dest.len() - done);
            dest[done..done + take].copy_from_slice(&buffer.remaining()[..take]);
            done += take;
            buffer.consumed += take;
            let packet = buffer.packet;
            if packet || buffer.remaining().is_empty() {
                state.buffers.pop_front();
            }
            if packet {
                break;
            }
        }
        state.changed();
        Ok(done)
    }

    pub(super) fn write(&self, input: &[u8], packet: bool) -> Result<usize, Errno> {
        if input.is_empty() {
            return Ok(0);
        }
        let mut state = self.pipe.state.lock().unwrap();
        if !state.readers {
            return Err(Errno(EPIPE));
        }
        let mut done = 0;
        // Linux first tries combining the final partial page with the last
        // buffer, then claims whole slots. A write up to PIPE_BUF is atomic.
        let tail = input.len() % PAGE;
        if tail != 0
            && let Some(last) = state.buffers.back_mut()
            && !last.packet
            && last.bytes.len() + tail <= PAGE
        {
            last.bytes.extend_from_slice(&input[..tail]);
            done = tail;
        }
        while done < input.len() && state.buffers.len() < state.slots {
            let take = (input.len() - done).min(PAGE);
            let mut bytes = Vec::new();
            let allocated =
                state.buffers.try_reserve(1).is_ok() && bytes.try_reserve_exact(PAGE).is_ok();
            if !allocated {
                if done == 0 {
                    return Err(Errno(ENOMEM));
                }
                break;
            }
            bytes.extend_from_slice(&input[done..done + take]);
            state.buffers.push_back(Buffer {
                bytes,
                consumed: 0,
                packet,
            });
            done += take;
        }
        if done == 0 {
            return Err(Errno(EAGAIN));
        }
        state.changed();
        Ok(done)
    }
}

fn queued(state: &State) -> usize {
    state
        .buffers
        .iter()
        .map(|buffer| buffer.remaining().len())
        .sum()
}
