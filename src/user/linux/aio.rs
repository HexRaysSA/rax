//! Linux AIO contexts (`fs/aio.c`, Linux 6.19): the completion ring a
//! context maps into the process, and its request accounting.
//!
//! A context's identifier is the user address of its ring, a shared
//! mapping of `/[aio]` that the kernel fills with `struct io_event`s and
//! the process may reap by itself (libaio does). The ring here is an
//! anonymous shared object written through its host file, so the pages
//! the process maps see every completion whatever it does to its mapping.
//! Requests are counted as `get_reqs_available` and `refill_reqs_available`
//! count them, for one CPU: a submission takes a slot, a completion is
//! given back once the process has reaped it. The limit on the requests of
//! all contexts (`aio-max-nr`) counts this process's contexts.

use std::os::unix::fs::FileExt;
use std::sync::Arc;

use crate::user::mm::SharedObject;

/// `AIO_RING_MAGIC`.
pub const RING_MAGIC: u32 = 0xa10a_10a1;
/// `sizeof(struct aio_ring)`: the header before the events.
pub const RING_HEADER: u64 = 32;
/// `sizeof(struct io_event)`.
pub const EVENT_SIZE: u64 = 32;
/// `aio_max_nr` (`/proc/sys/fs/aio-max-nr`).
pub const AIO_MAX_NR: u64 = 0x10000;
/// `num_possible_cpus()`: the emulated CPU.
pub const POSSIBLE_CPUS: u32 = 1;

/// `struct aio_ring` field offsets.
mod ring {
    pub const ID: u64 = 0;
    pub const NR: u64 = 4;
    pub const HEAD: u64 = 8;
    pub const TAIL: u64 = 12;
    pub const MAGIC: u64 = 16;
    pub const COMPAT: u64 = 20;
    pub const INCOMPAT: u64 = 24;
    pub const HEADER_LENGTH: u64 = 28;
}

/// A completion (`struct io_event`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

impl Event {
    /// The event's 32 bytes.
    pub fn encode(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&self.data.to_le_bytes());
        b[8..16].copy_from_slice(&self.obj.to_le_bytes());
        b[16..24].copy_from_slice(&self.res.to_le_bytes());
        b[24..].copy_from_slice(&self.res2.to_le_bytes());
        b
    }
}

/// An `IOCB_CMD_POLL` request waiting for its file.
#[derive(Clone, Debug)]
pub struct PendingPoll {
    /// The user `iocb` (`ki_res.obj`) and its `aio_data`.
    pub obj: u64,
    pub data: u64,
    /// The file and the events asked for (with `EPOLLERR | EPOLLHUP`).
    pub file: Arc<super::fs::fd::OpenFile>,
    pub events: u32,
    /// The `eventfd` to signal (`IOCB_FLAG_RESFD`).
    pub resfd: Option<Arc<super::fs::fd::OpenFile>>,
}

/// A context as a sleeping call holds it (`percpu_ref_get`): its slot in
/// the table and its serial number, which no later context there shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    pub slot: usize,
    pub serial: u64,
}

/// An AIO context (`struct kioctx`).
#[derive(Debug)]
pub struct Context {
    /// `user_id`: the ring's user address.
    pub id: u64,
    /// Its index in the process's table, which the ring's `id` field holds.
    pub index: u32,
    /// Set by [`Table::insert`].
    pub serial: u64,
    /// The ring's backing object and its mapped length.
    pub ring: Arc<SharedObject>,
    pub mmap_size: u64,
    /// `nr_events`: the ring's slots.
    pub nr_events: u32,
    /// `max_reqs`: the events asked for, counted against `aio-max-nr`.
    pub max_reqs: u32,
    /// The kernel's copy of the tail.
    tail: u32,
    /// `reqs_available`, the CPU's cached share, and `req_batch`.
    reqs_available: u32,
    cpu_available: u32,
    req_batch: u32,
    /// `completed_events`: completions not yet given back.
    completed_events: u32,
    /// Poll requests still waiting (`active_reqs`).
    pub polls: Vec<PendingPoll>,
}

impl Context {
    /// `ioctx_alloc` and `aio_setup_ring` for `max_reqs` events: the ring's
    /// slot count and byte size (whole pages), before the ring exists.
    pub fn ring_geometry(max_reqs: u32) -> Option<(u32, u64)> {
        let nr = max_reqs.max(POSSIBLE_CPUS * 4).checked_mul(2)?;
        if u64::from(nr) > 0x1000_0000 / EVENT_SIZE {
            return None;
        }
        let size = RING_HEADER + EVENT_SIZE * (u64::from(nr) + 2);
        let pages = size.div_ceil(4096);
        let slots = ((pages * 4096 - RING_HEADER) / EVENT_SIZE) as u32;
        Some((slots, pages * 4096))
    }

    /// A context whose ring is `ring`, mapped at `id`, with `nr_events`
    /// slots; the header is written as `aio_setup_ring` writes it.
    pub fn new(
        id: u64,
        index: u32,
        ring: Arc<SharedObject>,
        mmap_size: u64,
        nr_events: u32,
        max_reqs: u32,
    ) -> Self {
        let ctx = Context {
            id,
            index,
            serial: 0,
            ring,
            mmap_size,
            nr_events,
            max_reqs,
            tail: 0,
            reqs_available: nr_events - 1,
            cpu_available: 0,
            req_batch: ((nr_events - 1) / (POSSIBLE_CPUS * 4)).max(1),
            completed_events: 0,
            polls: Vec::new(),
        };
        for (off, v) in [
            (ring::ID, index),
            (ring::NR, nr_events),
            (ring::HEAD, 0),
            (ring::TAIL, 0),
            (ring::MAGIC, RING_MAGIC),
            (ring::COMPAT, 1),
            (ring::INCOMPAT, 0),
            (ring::HEADER_LENGTH, RING_HEADER as u32),
        ] {
            ctx.put(off, v);
        }
        ctx
    }

    fn put(&self, off: u64, v: u32) {
        let _ = self.ring.host_file().write_at(&v.to_le_bytes(), off);
    }

    fn get(&self, off: u64) -> u32 {
        let mut b = [0u8; 4];
        let _ = self.ring.read_at(off, &mut b);
        u32::from_le_bytes(b)
    }

    /// The ring's `id` field, which a lookup checks through the mapping.
    pub fn ring_id_offset() -> u64 {
        ring::ID
    }

    /// `__get_reqs_available`, refilling from the ring once
    /// (`user_refill_reqs_available`): a slot for a new request, or none.
    pub fn get_req(&mut self) -> bool {
        if self.take_cached() {
            return true;
        }
        if self.completed_events > 0 {
            let head = self.get(ring::HEAD);
            self.refill(head, self.tail);
        }
        self.take_cached()
    }

    fn take_cached(&mut self) -> bool {
        if self.cpu_available == 0 {
            if self.reqs_available < self.req_batch {
                return false;
            }
            self.reqs_available -= self.req_batch;
            self.cpu_available += self.req_batch;
        }
        self.cpu_available -= 1;
        true
    }

    /// `put_reqs_available`.
    pub fn put_reqs(&mut self, nr: u32) {
        self.cpu_available += nr;
        while self.cpu_available >= self.req_batch * 2 {
            self.cpu_available -= self.req_batch;
            self.reqs_available += self.req_batch;
        }
    }

    /// `refill_reqs_available`: completions the process has reaped give
    /// their slots back.
    fn refill(&mut self, head: u32, tail: u32) {
        let head = head % self.nr_events;
        let in_ring = if head <= tail {
            tail - head
        } else {
            self.nr_events - (head - tail)
        };
        let reaped = self.completed_events.saturating_sub(in_ring);
        if reaped == 0 {
            return;
        }
        self.completed_events -= reaped;
        self.put_reqs(reaped);
    }

    /// `aio_complete`: the event goes after the tail.
    pub fn complete(&mut self, ev: Event) {
        let pos = u64::from(self.tail) + 1;
        let _ = self
            .ring
            .host_file()
            .write_at(&ev.encode(), pos * EVENT_SIZE);
        self.tail += 1;
        if self.tail >= self.nr_events {
            self.tail = 0;
        }
        let head = self.get(ring::HEAD);
        self.put(ring::TAIL, self.tail);
        self.completed_events += 1;
        if self.completed_events > 1 {
            self.refill(head, self.tail);
        }
    }

    /// `aio_read_events_ring`: up to `nr` events from the ring's head, and
    /// the head past them, which the caller writes back once they are
    /// copied out ([`set_head`](Self::set_head)); nothing to write when the
    /// ring's head and tail are equal.
    pub fn peek_events(&self, nr: usize) -> (Vec<Event>, Option<u32>) {
        let mut head = self.get(ring::HEAD);
        let tail = self.get(ring::TAIL);
        let mut out = Vec::new();
        if head == tail {
            return (out, None);
        }
        // Both are clamped: the process can write them.
        head %= self.nr_events;
        let tail = tail % self.nr_events;
        while out.len() < nr && head != tail {
            let mut b = [0u8; 32];
            let _ = self
                .ring
                .read_at((u64::from(head) + 1) * EVENT_SIZE, &mut b);
            let w = |i: usize| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
            out.push(Event {
                data: w(0),
                obj: w(1),
                res: w(2) as i64,
                res2: w(3) as i64,
            });
            head = (head + 1) % self.nr_events;
        }
        (out, Some(head))
    }

    /// Writes the ring's head.
    pub fn set_head(&self, head: u32) {
        self.put(ring::HEAD, head);
    }
}

/// A process's AIO contexts (`mm->ioctx_table`) and the requests they
/// count (`aio_nr`).
#[derive(Debug, Default)]
pub struct Table {
    pub contexts: Vec<Option<Context>>,
    pub aio_nr: u64,
    next_serial: u64,
}

impl Table {
    /// `ioctx_add_table`: `ctx` goes in the slot its ring names.
    pub fn insert(&mut self, mut ctx: Context) -> Handle {
        let slot = ctx.index as usize;
        ctx.serial = self.next_serial;
        self.next_serial += 1;
        let handle = Handle {
            slot,
            serial: ctx.serial,
        };
        if slot == self.contexts.len() {
            self.contexts.push(Some(ctx));
        } else {
            self.contexts[slot] = Some(ctx);
        }
        handle
    }

    /// The context `handle` holds, unless it has been killed since.
    pub fn get(&mut self, handle: Handle) -> Option<&mut Context> {
        self.contexts
            .get_mut(handle.slot)?
            .as_mut()
            .filter(|c| c.serial == handle.serial)
    }

    /// The context with identifier `id` whose ring names index `index`
    /// (`lookup_ioctx`).
    pub fn lookup(&mut self, id: u64, index: u32) -> Option<&mut Context> {
        self.contexts
            .get_mut(index as usize)?
            .as_mut()
            .filter(|c| c.id == id)
    }

    /// `ioctx_add_table`: the first free index.
    pub fn free_index(&self) -> u32 {
        self.contexts
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.contexts.len()) as u32
    }

    /// Whether any poll request waits.
    pub fn polls_pending(&self) -> bool {
        self.contexts.iter().flatten().any(|c| !c.polls.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_geometry_follows_ioctx_alloc_and_aio_setup_ring() {
        // max(n, 4 * CPUs) * 2 events plus two, in whole pages.
        assert_eq!(Context::ring_geometry(1), Some((127, 4096)));
        // 62: 126 + 2 events and the header fill 4096 bytes exactly; 63 do
        // not.
        assert_eq!(Context::ring_geometry(62), Some((127, 4096)));
        assert_eq!(Context::ring_geometry(63), Some((255, 8192)));
        assert_eq!(Context::ring_geometry(64), Some((255, 8192)));
        assert_eq!(Context::ring_geometry(0x1000_0000 / 64 + 1), None);
    }

    #[test]
    fn slots_come_back_once_reaped() {
        let ring = Arc::new(SharedObject::anonymous(4096).unwrap());
        let mut c = Context::new(0x1000, 0, ring, 4096, 127, 1);
        let mut taken = 0;
        while c.get_req() {
            taken += 1;
        }
        // Four batches of (127 - 1) / 4 = 31; the 2 left make no batch.
        assert_eq!(taken, 124);
        for i in 0..taken {
            c.complete(Event {
                data: i,
                obj: 0,
                res: 0,
                res2: 0,
            });
        }
        assert!(!c.get_req(), "nothing reaped yet");
        let (events, head) = c.peek_events(200);
        assert_eq!((events.len(), head), (124, Some(124)));
        assert_eq!(events[123].data, 123);
        assert!(!c.get_req(), "peeking reaps nothing");
        // Reaped: the 124 slots come back, the CPU keeping 31 (below two
        // batches) and the rest going back to the 2 left; again 31 and
        // three batches of the 95.
        c.set_head(124);
        let mut again = 0;
        while c.get_req() {
            again += 1;
        }
        assert_eq!(again, 124);
    }
}
