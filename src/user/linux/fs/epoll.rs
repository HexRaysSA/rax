//! `epoll` instances (`fs/eventpoll.c`): interest items and the ready list.
//!
//! An item is keyed by the open file description and the descriptor
//! number it was added under (`epoll_filefd`); it holds the description
//! weakly, so it disappears once every descriptor of that description is
//! closed (`eventpoll_release`), not when the descriptor it was added
//! under is. The ready list keeps the kernel's order: items join its tail
//! as they become ready, a wait reports from its head, reported
//! level-triggered items join the tail again, and those a wait had no room
//! for stay at the head (`ep_send_events`, `ep_done_scan`).
//!
//! Readiness is not pushed by wake-ups here: whoever looks at an instance
//! polls its items and links those that became ready. A level-triggered
//! item is linked while it reports a wanted event. An edge-triggered item
//! is linked when a wanted event appears or the file's level (bytes
//! queued, a counter, ticks, signals) grows since it was last looked at,
//! which stands for the wake-up each such change causes in the kernel.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};

use super::fd::OpenFile;
use crate::user::linux::syscall::ready::Polled;

/// `EPOLLEXCLUSIVE`.
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
/// `EPOLLWAKEUP`.
pub const EPOLLWAKEUP: u32 = 1 << 29;
/// `EPOLLONESHOT`.
pub const EPOLLONESHOT: u32 = 1 << 30;
/// `EPOLLET`.
pub const EPOLLET: u32 = 1 << 31;
/// `EP_PRIVATE_BITS`: the bits that are not poll events.
pub const EP_PRIVATE_BITS: u32 = EPOLLWAKEUP | EPOLLONESHOT | EPOLLET | EPOLLEXCLUSIVE;

/// An interest item (`struct epitem`).
#[derive(Debug)]
struct Item {
    id: u64,
    fd: i32,
    file: Weak<OpenFile>,
    /// The events asked for, with `EPOLLERR | EPOLLHUP` and private bits.
    events: u32,
    data: u64,
    /// What the file reported when last looked at (edge detection).
    seen: Polled,
    /// On the ready list.
    linked: bool,
}

impl Item {
    fn matches(&self, file: &Arc<OpenFile>, fd: i32) -> bool {
        self.fd == fd && std::ptr::eq(self.file.as_ptr(), Arc::as_ptr(file))
    }

    /// Disabled by `EPOLLONESHOT` after a report.
    fn disabled(&self) -> bool {
        self.events & !EP_PRIVATE_BITS == 0
    }
}

#[derive(Debug, Default)]
struct State {
    items: Vec<Item>,
    ready: VecDeque<u64>,
    next_id: u64,
}

impl State {
    fn at(&mut self, id: u64) -> Option<&mut Item> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    fn link(&mut self, id: u64) {
        if let Some(item) = self.at(id)
            && !item.linked
        {
            item.linked = true;
            self.ready.push_back(id);
        }
    }
}

/// An `epoll` instance.
#[derive(Debug, Default)]
pub struct Epoll {
    state: Mutex<State>,
}

/// One interest item's file and events, as returned by [`Epoll::items`].
pub type Interest = (u64, Arc<OpenFile>, u32);

impl Epoll {
    /// A new, empty instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an item for `(file, fd)` exists (`ep_find`).
    pub fn contains(&self, file: &Arc<OpenFile>, fd: i32) -> bool {
        let st = self.state.lock().unwrap();
        st.items
            .iter()
            .any(|i| i.matches(file, fd) && i.file.strong_count() > 0)
    }

    /// `ep_insert`: adds an item watching `file` for instance `me`,
    /// already on the ready list if `now` reports a wanted event.
    pub fn insert(
        &self,
        me: &Arc<OpenFile>,
        file: &Arc<OpenFile>,
        fd: i32,
        events: u32,
        data: u64,
        now: Polled,
    ) {
        let mut st = self.state.lock().unwrap();
        st.next_id += 1;
        let id = st.next_id;
        file.watch(super::fd::Watch {
            ep: Arc::downgrade(me),
            id,
        });
        st.items.push(Item {
            id,
            fd,
            file: Arc::downgrade(file),
            events,
            data,
            seen: now,
            linked: false,
        });
        if now.mask & events & !EP_PRIVATE_BITS != 0 {
            st.link(id);
        }
    }

    /// `ep_poll_callback`: a wake-up with events `key` (0: any) of `file`,
    /// which item `id` watches, links the item if it wants one of them
    /// and is not disabled. Returns whether it newly joined the ready
    /// list (so the instance's own waiters wake).
    pub fn callback(&self, id: u64, file: &OpenFile, key: u32) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st.at(id) else {
            return false;
        };
        if !std::ptr::eq(item.file.as_ptr(), file) || item.disabled() {
            return false;
        }
        if key != 0 && key & item.events & !EP_PRIVATE_BITS == 0 {
            return false;
        }
        if item.linked {
            return false;
        }
        st.link(id);
        true
    }

    /// `ep_modify`: new events and data; the item joins the ready list if
    /// `now` reports a wanted event. `None` when there is no such item,
    /// `Some(false)` when it may not be modified (`EPOLLEXCLUSIVE`).
    pub fn modify(
        &self,
        file: &Arc<OpenFile>,
        fd: i32,
        events: u32,
        data: u64,
        now: Polled,
    ) -> Option<bool> {
        let mut st = self.state.lock().unwrap();
        let item = st.items.iter_mut().find(|i| i.matches(file, fd))?;
        if item.events & EPOLLEXCLUSIVE != 0 {
            return Some(false);
        }
        item.events = events;
        item.data = data;
        item.seen = now;
        let id = item.id;
        if now.mask & events & !EP_PRIVATE_BITS != 0 {
            st.link(id);
        }
        Some(true)
    }

    /// `ep_remove`: whether there was such an item.
    pub fn remove(&self, file: &Arc<OpenFile>, fd: i32) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some(pos) = st.items.iter().position(|i| i.matches(file, fd)) else {
            return false;
        };
        let id = st.items.remove(pos).id;
        st.ready.retain(|&r| r != id);
        true
    }

    /// The live items (dropping those whose description is gone), in
    /// insertion order, with the events to poll them for.
    pub fn items(&self) -> Vec<Interest> {
        let mut st = self.state.lock().unwrap();
        let dead: Vec<u64> = st
            .items
            .iter()
            .filter(|i| i.file.strong_count() == 0)
            .map(|i| i.id)
            .collect();
        if !dead.is_empty() {
            st.items.retain(|i| !dead.contains(&i.id));
            st.ready.retain(|r| !dead.contains(r));
        }
        st.items
            .iter()
            .filter_map(|i| i.file.upgrade().map(|f| (i.id, f, i.events)))
            .collect()
    }

    /// Links the items `polled` (one per item of [`Epoll::items`]) shows
    /// ready, as their wake-ups would have, and records what they report.
    pub fn scan(&self, items: &[Interest], polled: &[Polled]) {
        let mut st = self.state.lock().unwrap();
        for ((id, _, _), p) in items.iter().zip(polled) {
            let Some(item) = st.at(*id) else {
                continue;
            };
            let wanted = item.events & !EP_PRIVATE_BITS;
            let ready = p.mask & wanted != 0;
            let wake = if item.events & EPOLLET != 0 {
                p.mask & wanted & !item.seen.mask != 0 || p.level > item.seen.level
            } else {
                true
            };
            item.seen = *p;
            if ready && wake && !item.disabled() {
                st.link(*id);
            }
        }
    }

    /// Whether an item on the ready list reports a wanted event
    /// (`ep_read_events_proc`), given `polled` for [`Epoll::items`].
    pub fn has_ready(&self, items: &[Interest], polled: &[Polled]) -> bool {
        let st = self.state.lock().unwrap();
        items.iter().zip(polled).any(|((id, _, events), p)| {
            st.ready.contains(id) && p.mask & events & !EP_PRIVATE_BITS != 0
        })
    }

    /// `ep_send_events`: up to `max` events from the head of the ready
    /// list, as `(events, data)`, given `polled` for [`Epoll::items`].
    /// Items that no longer report a wanted event leave the list;
    /// one-shot items are disabled; level-triggered items join the tail
    /// again after the items there was no room for.
    pub fn send(&self, max: usize, items: &[Interest], polled: &[Polled]) -> Vec<(u32, u64)> {
        let mut st = self.state.lock().unwrap();
        let mut out = Vec::new();
        let mut again = Vec::new();
        while out.len() < max {
            let Some(id) = st.ready.pop_front() else {
                break;
            };
            let Some(pos) = items.iter().position(|(i, _, _)| *i == id) else {
                if let Some(item) = st.at(id) {
                    item.linked = false;
                }
                continue;
            };
            let p = polled[pos];
            let Some(item) = st.at(id) else {
                continue;
            };
            item.linked = false;
            let revents = p.mask & item.events & !EP_PRIVATE_BITS;
            if revents == 0 {
                continue;
            }
            out.push((revents, item.data));
            if item.events & EPOLLONESHOT != 0 {
                item.events &= EP_PRIVATE_BITS;
            } else if item.events & EPOLLET == 0 {
                again.push(id);
            }
        }
        for id in again {
            st.link(id);
        }
        out
    }

    /// The descriptions of nested instances among the items, for loop and
    /// depth checks.
    pub fn nested(&self) -> Vec<Arc<OpenFile>> {
        self.items()
            .into_iter()
            .filter(|(_, f, _)| is_epoll(f))
            .map(|(_, f, _)| f)
            .collect()
    }
}

/// Whether a description is an `epoll` instance.
pub fn is_epoll(file: &OpenFile) -> bool {
    matches!(
        file.object,
        super::fd::FileObject::Anon(super::anon::Anon::Epoll(_))
    )
}
