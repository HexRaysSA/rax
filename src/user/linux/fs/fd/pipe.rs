//! Anonymous pipes for closed guests. Both ends share bounded guest data and
//! the scheduler observes changes without opening a host descriptor.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, Weak};

use super::super::super::syscall::ready::{Polled, ev};
use super::{EAGAIN, EBUSY, EINVAL, ENFILE, ENOMEM, EPERM, EPIPE};
use super::{Errno, FileObject, FileType, O_ACCMODE, O_PATH, O_RDONLY, O_RDWR, O_WRONLY, OpenFile};

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
        let inode = self.next_inode.fetch_add(1, Relaxed) + 1;
        let pipe = Arc::new(Pipe {
            pool: self.clone(),
            inode,
            owner,
            state: Mutex::new(State {
                buffers: VecDeque::new(),
                slots: 0,
                readers: 0,
                writers: 0,
                endpoints: Vec::new(),
                generation: 0,
            }),
        });
        let reader = pipe.open_file(O_RDONLY | (status & !packet_flag), packet_flag)?;
        let writer = pipe.open_file(O_WRONLY | status, packet_flag)?;
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
    readers: usize,
    writers: usize,
    endpoints: Vec<Weak<OpenFile>>,
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

impl Pipe {
    fn open_file(self: &Arc<Self>, flags: u32, packet_flag: u32) -> Result<Arc<OpenFile>, Errno> {
        let (reads, writes) = if flags & O_PATH != 0 {
            (false, false)
        } else {
            match flags & O_ACCMODE {
                O_RDONLY => (true, false),
                O_WRONLY => (false, true),
                O_RDWR => (true, true),
                _ => return Err(Errno(EINVAL)),
            }
        };
        let mut state = self.state.lock().unwrap();
        if (reads || writes) && state.slots == 0 {
            if !self.pool.reserve(DEFAULT_SLOTS) {
                return Err(Errno(ENFILE));
            }
            state.slots = DEFAULT_SLOTS;
        }

        let file = OpenFile::new(
            FileObject::GuestPipe(PipeEnd {
                pipe: self.clone(),
                reads,
                writes,
                packet_flag,
            }),
            FileType::Fifo,
            format!("pipe:[{}]", self.inode),
            None,
            flags,
        );
        if reads || writes {
            state.readers += usize::from(reads);
            state.writers += usize::from(writes);
            state.endpoints.push(Arc::downgrade(&file));
            state.changed();
        }
        Ok(file)
    }

    fn wake(&self, readers: bool, key: u32) {
        // A callback may poll this same pipe or drop one of its endpoints.
        // Keep the descriptions alive and release the pipe lock first.
        let endpoints = {
            let state = self.state.lock().unwrap();
            state
                .endpoints
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        for file in endpoints {
            let FileObject::GuestPipe(end) = &file.object else {
                continue;
            };
            if (readers && end.reads) || (!readers && end.writes) {
                file.woke(key);
            }
        }
    }
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
    writes: bool,
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

    /// A reopen gets a new description of the same pipe inode.
    pub(crate) fn reopen(&self, flags: u32) -> Result<Arc<OpenFile>, Errno> {
        self.pipe.open_file(flags, self.packet_flag)
    }

    /// Reopening checks the inode's permissions, independently of the
    /// direction in which the original description was opened.
    pub(crate) fn permits(&self, uid: u32, mode: u32) -> bool {
        mode == 0 || mode & 1 == 0 && (uid == 0 || uid == self.pipe.owner.0)
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

    pub(super) fn close(&self) {
        if !self.reads && !self.writes {
            return;
        }
        let mut state = self.pipe.state.lock().unwrap();
        state.readers -= usize::from(self.reads);
        state.writers -= usize::from(self.writes);
        let last_reader = self.reads && state.readers == 0;
        let last_writer = self.writes && state.writers == 0;
        state.endpoints.retain(|file| file.strong_count() != 0);
        if state.readers == 0 && state.writers == 0 {
            state.buffers = VecDeque::new();
            self.pipe.pool.release(std::mem::take(&mut state.slots));
        }
        state.changed();
        drop(state);
        if last_reader {
            self.pipe.wake(false, ev::ERR);
        }
        if last_writer {
            self.pipe.wake(true, ev::HUP);
        }
    }

    pub(crate) fn wait(&self) -> PipeWait {
        PipeWait {
            pipe: self.pipe.clone(),
            generation: self.pipe.state.lock().unwrap().generation,
        }
    }

    pub(crate) fn poll(&self) -> (Polled, PipeWait) {
        let state = self.pipe.state.lock().unwrap();
        let mut result = Polled::default();
        if self.reads {
            result.level = queued(&state) as u64;
            if result.level != 0 {
                result.mask |= ev::IN | ev::RDNORM;
            }
            if state.writers == 0 {
                result.mask |= ev::HUP;
            }
        }
        if self.writes {
            if state.buffers.len() < state.slots {
                result.mask |= ev::OUT | ev::WRNORM;
            }
            if state.readers == 0 {
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
        if dest.is_empty() || state.buffers.is_empty() && state.writers == 0 {
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
        drop(state);
        self.pipe.wake(false, ev::OUT | ev::WRNORM);
        Ok(done)
    }

    pub(super) fn write(&self, input: &[u8], packet: bool) -> Result<usize, Errno> {
        if input.is_empty() {
            return Ok(0);
        }
        let mut state = self.pipe.state.lock().unwrap();
        if state.readers == 0 {
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
        drop(state);
        self.pipe.wake(true, ev::IN | ev::RDNORM);
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
