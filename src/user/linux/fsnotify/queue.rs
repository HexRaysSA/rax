//! An inotify instance's event queue (`fs/notify/notification.c`,
//! `inotify_merge`, and `inotify_read`), kept in a byte region so that it
//! can live in memory every process holding the instance shares.
//!
//! The region starts with a header of little-endian 64-bit words, then
//! a ring of records: a record's size, then the event's descriptor, mask,
//! cookie, name length, and name, padded to 4 bytes. A record that does
//! not fit before the end of the ring starts at its beginning, after a
//! marker where it would have been.

use super::Event;
use super::bits::*;

/// Header words.
const HEAD: usize = 0;
const TAIL: usize = 1;
/// Events queued (`q_len`), the overflow event included.
const LEN: usize = 2;
/// The bytes `read` would return for all of them (`FIONREAD`).
const BYTES: usize = 3;
/// Offset of the newest record, for merging.
const LAST: usize = 4;
/// Whether the overflow event is queued.
const OVERFLOW: usize = 5;
/// `max_events`.
const MAX: usize = 6;
/// Ring bytes in use, markers included.
const USED: usize = 7;
const HEADER: usize = 8 * 8;
/// The marker for a record at the ring's start.
const WRAP: u32 = u32::MAX;
/// A record's fixed part: size, descriptor, mask, cookie, name length.
const FIXED: usize = 20;
/// `NAME_MAX`.
pub const NAME_MAX: usize = 255;
/// The largest record.
const RECORD_MAX: usize = FIXED + NAME_MAX + 1;
/// `sizeof(struct inotify_event)`.
pub const EVENT_SIZE: usize = 16;
/// `inotify_max_queued_events`.
pub const MAX_QUEUED: u64 = 16384;

/// The region a queue of `max_events` events needs.
pub fn region_len(max_events: u64) -> usize {
    HEADER + (max_events as usize + 2) * RECORD_MAX
}

/// The size `read` gives an event: the structure, then the name with its
/// terminator, padded to a multiple of the structure's size.
pub fn read_size(e: &Event) -> usize {
    EVENT_SIZE
        + if e.name.is_empty() {
            0
        } else {
            (e.name.len() + 1).div_ceil(EVENT_SIZE) * EVENT_SIZE
        }
}

/// `copy_event_to_user`: the bytes `read` writes for an event.
pub fn encode(e: &Event) -> Vec<u8> {
    let size = read_size(e);
    let mut b = Vec::with_capacity(size);
    b.extend_from_slice(&e.wd.to_le_bytes());
    b.extend_from_slice(&(e.mask & REPORTED).to_le_bytes());
    b.extend_from_slice(&e.cookie.to_le_bytes());
    b.extend_from_slice(&((size - EVENT_SIZE) as u32).to_le_bytes());
    b.extend_from_slice(&e.name);
    b.resize(size, 0);
    b
}

/// What became of an inserted event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inserted {
    /// Queued.
    Queued,
    /// The same as the newest event: dropped (`inotify_merge`).
    Merged,
    /// The queue is full: the overflow event was queued instead.
    Overflowed,
    /// The queue is full and the overflow event already queued.
    Dropped,
}

/// A queue over its region.
pub struct Queue<'a> {
    b: &'a mut [u8],
}

impl<'a> Queue<'a> {
    /// A queue over an initialized region.
    pub fn new(b: &'a mut [u8]) -> Self {
        Queue { b }
    }

    /// Makes `b` an empty queue of at most `max_events` events.
    pub fn init(b: &'a mut [u8], max_events: u64) -> Self {
        assert!(b.len() >= region_len(max_events));
        b[..HEADER].fill(0);
        let mut q = Queue { b };
        q.set(LAST, u64::MAX);
        q.set(MAX, max_events);
        q
    }

    fn get(&self, i: usize) -> u64 {
        u64::from_le_bytes(self.b[i * 8..i * 8 + 8].try_into().unwrap())
    }

    fn set(&mut self, i: usize, v: u64) {
        self.b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn cap(&self) -> usize {
        self.b.len() - HEADER
    }

    fn word(&self, at: usize) -> u32 {
        let at = HEADER + at;
        u32::from_le_bytes(self.b[at..at + 4].try_into().unwrap())
    }

    /// How many events are queued.
    pub fn len(&self) -> u64 {
        self.get(LEN)
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `FIONREAD`: the bytes `read` would return for every queued event.
    pub fn bytes(&self) -> u64 {
        self.get(BYTES)
    }

    /// The record at ring offset `at`.
    fn record(&self, at: usize) -> Event {
        let name_len = self.word(at + 16) as usize;
        let start = HEADER + at + FIXED;
        Event {
            wd: self.word(at + 4) as i32,
            mask: self.word(at + 8),
            cookie: self.word(at + 12),
            name: self.b[start..start + name_len].to_vec(),
        }
    }

    /// The offset of the oldest record.
    fn first(&self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        let head = self.get(HEAD) as usize;
        Some(if self.cap() - head < 4 || self.word(head) == WRAP {
            0
        } else {
            head
        })
    }

    /// The oldest event.
    pub fn peek(&self) -> Option<Event> {
        self.first().map(|at| self.record(at))
    }

    /// Removes the oldest event.
    pub fn pop(&mut self) -> Option<Event> {
        let at = self.first()?;
        let e = self.record(at);
        let head = self.get(HEAD) as usize;
        let size = self.word(at) as usize;
        // The bytes skipped before a wrapped record are freed with it.
        let freed = if at < head {
            self.cap() - head + size
        } else {
            size
        };
        self.set(HEAD, ((at + size) % self.cap()) as u64);
        self.set(USED, self.get(USED) - freed as u64);
        self.set(LEN, self.len() - 1);
        self.set(BYTES, self.bytes() - read_size(&e) as u64);
        if self.is_empty() {
            self.set(LAST, u64::MAX);
            self.set(HEAD, 0);
            self.set(TAIL, 0);
            self.set(USED, 0);
        }
        if e.mask == IN_Q_OVERFLOW && e.wd == -1 {
            self.set(OVERFLOW, 0);
        }
        Some(e)
    }

    /// `fsnotify_insert_event` with `inotify_merge`.
    pub fn insert(&mut self, e: &Event) -> Inserted {
        if self.len() >= self.get(MAX) {
            if self.get(OVERFLOW) != 0 {
                return Inserted::Dropped;
            }
            self.set(OVERFLOW, 1);
            self.append(&Event {
                wd: -1,
                mask: IN_Q_OVERFLOW,
                cookie: 0,
                name: Vec::new(),
            });
            return Inserted::Overflowed;
        }
        let last = self.get(LAST);
        if last != u64::MAX {
            // event_compare: an IN_IGNORED event merges with nothing.
            let old = self.record(last as usize);
            if old.mask & IN_IGNORED == 0
                && old.mask == e.mask
                && old.wd == e.wd
                && old.name == e.name
            {
                return Inserted::Merged;
            }
        }
        self.append(e);
        Inserted::Queued
    }

    fn append(&mut self, e: &Event) {
        let name = &e.name[..e.name.len().min(NAME_MAX)];
        let size = (FIXED + name.len()).div_ceil(4) * 4;
        let cap = self.cap();
        let mut tail = self.get(TAIL) as usize;
        let mut used = self.get(USED) as usize;
        if cap - tail < size {
            if cap - tail >= 4 {
                self.b[HEADER + tail..HEADER + tail + 4].copy_from_slice(&WRAP.to_le_bytes());
            }
            used += cap - tail;
            tail = 0;
        }
        assert!(used + size <= cap, "queue region sized for max_events");
        let mut rec = Vec::with_capacity(size);
        for w in [
            size as u32,
            e.wd as u32,
            e.mask,
            e.cookie,
            name.len() as u32,
        ] {
            rec.extend_from_slice(&w.to_le_bytes());
        }
        rec.extend_from_slice(name);
        rec.resize(size, 0);
        self.b[HEADER + tail..HEADER + tail + size].copy_from_slice(&rec);
        self.set(LAST, tail as u64);
        self.set(TAIL, ((tail + size) % cap) as u64);
        self.set(USED, (used + size) as u64);
        self.set(LEN, self.len() + 1);
        let stored = EVENT_SIZE
            + if name.is_empty() {
                0
            } else {
                (name.len() + 1).div_ceil(EVENT_SIZE) * EVENT_SIZE
            };
        self.set(BYTES, self.bytes() + stored as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(wd: i32, mask: u32, name: &[u8]) -> Event {
        Event {
            wd,
            mask,
            cookie: 0,
            name: name.to_vec(),
        }
    }

    #[test]
    fn records_follow_copy_event_to_user() {
        let e = ev(3, IN_CREATE | IN_ISDIR | FS_EVENT_ON_CHILD, b"abc");
        let b = encode(&e);
        assert_eq!(b.len(), 32);
        assert_eq!(i32::from_le_bytes(b[0..4].try_into().unwrap()), 3);
        // FS_EVENT_ON_CHILD is the kernel's own.
        assert_eq!(
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
            IN_CREATE | IN_ISDIR
        );
        assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()), 16);
        assert_eq!(&b[16..20], b"abc\0");
        // 15 bytes and a terminator fill 16; 16 bytes need 32.
        assert_eq!(read_size(&ev(1, 1, &[b'x'; 15])), 32);
        assert_eq!(read_size(&ev(1, 1, &[b'x'; 16])), 48);
        assert_eq!(read_size(&ev(1, 1, b"")), 16);
    }

    #[test]
    fn events_merge_only_with_the_newest() {
        let mut b = vec![0u8; region_len(8)];
        let mut q = Queue::init(&mut b, 8);
        assert_eq!(q.insert(&ev(1, IN_MODIFY, b"f")), Inserted::Queued);
        assert_eq!(q.insert(&ev(1, IN_MODIFY, b"f")), Inserted::Merged);
        assert_eq!(q.insert(&ev(1, IN_MODIFY, b"g")), Inserted::Queued);
        assert_eq!(q.insert(&ev(1, IN_MODIFY, b"f")), Inserted::Queued);
        // The cookie is not compared.
        let mut moved = ev(1, IN_MOVED_TO, b"m");
        q.insert(&moved);
        moved.cookie = 9;
        assert_eq!(q.insert(&moved), Inserted::Merged);
        // IN_IGNORED merges with nothing.
        assert_eq!(q.insert(&Event::ignored(1)), Inserted::Queued);
        assert_eq!(q.insert(&Event::ignored(1)), Inserted::Queued);
        assert_eq!(q.len(), 6);
        assert_eq!(q.bytes(), 4 * 32 + 2 * 16);
        assert_eq!(q.pop().unwrap().name, b"f");
        assert_eq!(q.pop().unwrap().name, b"g");
    }

    #[test]
    fn a_full_queue_takes_one_overflow_event() {
        let mut b = vec![0u8; region_len(3)];
        let mut q = Queue::init(&mut b, 3);
        for i in 0..3 {
            assert_eq!(q.insert(&ev(i, IN_OPEN, b"")), Inserted::Queued);
        }
        assert_eq!(q.insert(&ev(9, IN_OPEN, b"")), Inserted::Overflowed);
        assert_eq!(q.insert(&ev(10, IN_OPEN, b"")), Inserted::Dropped);
        assert_eq!(q.len(), 4);
        q.pop();
        // Still full: the overflow event is queued, so this is dropped.
        assert_eq!(q.insert(&ev(11, IN_OPEN, b"")), Inserted::Dropped);
        q.pop();
        assert_eq!(q.insert(&ev(12, IN_OPEN, b"")), Inserted::Queued);
        assert_eq!(q.pop().unwrap().wd, 2);
        let o = q.pop().unwrap();
        assert_eq!((o.wd, o.mask), (-1, IN_Q_OVERFLOW));
        assert_eq!(q.pop().unwrap().wd, 12);
        assert!(q.pop().is_none());
    }

    #[test]
    fn the_ring_wraps_without_losing_order() {
        let mut b = vec![0u8; region_len(4)];
        let mut q = Queue::init(&mut b, 4);
        // One event always queued, so the ring never empties and resets.
        let mut expect = std::collections::VecDeque::new();
        q.insert(&ev(-5, IN_CREATE, b"seed"));
        expect.push_back((-5, 4));
        for round in 0..400i32 {
            let name = vec![b'a' + (round % 26) as u8; (round as usize * 37) % 300];
            q.insert(&ev(round, IN_CREATE, &name));
            expect.push_back((round, name.len().min(NAME_MAX)));
            let e = q.pop().unwrap();
            assert_eq!((e.wd, e.name.len()), expect.pop_front().unwrap());
            assert_eq!(q.len(), 1);
        }
        q.pop();
        assert!(q.is_empty());
        assert_eq!(q.bytes(), 0);
        for i in 0..4 {
            q.insert(&ev(i, IN_CREATE, &[b'n'; NAME_MAX]));
        }
        for i in 0..4 {
            assert_eq!(q.pop().unwrap().wd, i);
        }
    }
}
