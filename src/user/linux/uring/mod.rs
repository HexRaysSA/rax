//! io_uring instances (`io_uring/`, Linux 6.19): the shared rings, the
//! submission and completion bookkeeping, and the kernel-side state an
//! instance keeps.
//!
//! An instance's rings are two shared objects the process maps from the
//! ring file: the ring region (`struct io_rings` with the CQEs and, unless
//! `IORING_SETUP_NO_SQARRAY`, the SQ index array) at `IORING_OFF_SQ_RING`
//! and `IORING_OFF_CQ_RING`, and the SQEs at `IORING_OFF_SQES`. They are
//! anonymous shared objects written and read through their host files, so
//! the process's mappings see every update whatever it does to them, as
//! the kernel's pages are. Head and tail words are read when used and
//! written when committed; the kernel's cached SQ head and CQ tail
//! (`cached_sq_head`, `cached_cq_tail`) are kept here, and a CQE that finds
//! no room joins the overflow list (`IORING_FEAT_NODROP`), marked by
//! `IORING_SQ_CQ_OVERFLOW`, until a wait flushes it.
//!
//! The state lives in this process: a forked child shares the rings'
//! memory with its parent, but not the requests, registrations, or
//! overflow list each then keeps.

pub mod abi;
pub mod rsrc;

use std::collections::VecDeque;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use self::abi::{Cqe, Sqe, rings, setup, sq_flags};
use super::abi::PAGE_SIZE;
use super::abi::errno::Errno;
use super::abi::errno_table::*;
use crate::user::mm::SharedObject;

/// The ring region's layout (`rings_size`): the CQE array's offset is
/// fixed, the SQ index array (if any) follows it at a cache line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// `sq_off.array`, unless `IORING_SETUP_NO_SQARRAY`.
    pub sq_array: Option<u64>,
    /// The ring region's size before page rounding (`rl->rings_size`).
    pub rings_size: u64,
    /// The SQEs' size (`rl->sq_size`).
    pub sq_size: u64,
}

impl Layout {
    /// `rings_size` for `flags` and the rounded entry counts: `EOVERFLOW`
    /// for a mixed-size ring of one entry.
    pub fn new(flags: u32, sq_entries: u32, cq_entries: u32) -> Result<Self, Errno> {
        if flags & setup::CQE_MIXED != 0 && cq_entries < 2 {
            return Err(Errno(EOVERFLOW));
        }
        if flags & setup::SQE_MIXED != 0 && sq_entries < 2 {
            return Err(Errno(EOVERFLOW));
        }
        let sqe = abi::SQE_SIZE * if flags & setup::SQE128 != 0 { 2 } else { 1 };
        let cqe = abi::CQE_SIZE * if flags & setup::CQE32 != 0 { 2 } else { 1 };
        // struct_size(rings, cqes, cq_entries), doubled with CQE32 (which
        // doubles the header too), aligned to SMP_CACHE_BYTES.
        let mut off = rings::CQES + abi::CQE_SIZE * u64::from(cq_entries);
        if cqe > abi::CQE_SIZE {
            off *= 2;
        }
        off = off.next_multiple_of(abi::CACHE_BYTES);
        let sq_array = (flags & setup::NO_SQARRAY == 0).then_some(off);
        if sq_array.is_some() {
            off += 4 * u64::from(sq_entries);
        }
        Ok(Layout {
            sq_array,
            rings_size: off,
            sq_size: sqe * u64::from(sq_entries),
        })
    }
}

/// A wait for completions that slept (`struct io_wait_queue`): what the
/// call submitted before it, the CQ tail that ends it, the tail when it
/// began (for the minimum wait), and its deadlines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiting {
    pub submitted: i64,
    pub target: u32,
    pub min_tail: u32,
    pub deadline: Option<std::time::Instant>,
    pub min_deadline: Option<std::time::Instant>,
}

/// An eventfd registered to count completions (`IORING_REGISTER_EVENTFD`,
/// or `_ASYNC` for those that complete away from a submission).
#[derive(Debug)]
pub struct EventFd {
    pub file: Arc<super::fs::fd::OpenFile>,
    pub async_only: bool,
}

/// `REQ_F_*`: a request's flags. The low bits are the SQE's `IOSQE_*`
/// flags, copied (`io_init_req`).
pub mod req_flags {
    pub const FIXED_FILE: u32 = 1 << 0;
    pub const IO_DRAIN: u32 = 1 << 1;
    pub const LINK: u32 = 1 << 2;
    pub const HARDLINK: u32 = 1 << 3;
    pub const FORCE_ASYNC: u32 = 1 << 4;
    pub const BUFFER_SELECT: u32 = 1 << 5;
    pub const CQE_SKIP: u32 = 1 << 6;
    /// `REQ_F_FAIL`: the request failed; its link fails with it.
    pub const FAIL: u32 = 1 << 8;
    /// `REQ_F_SKIP_LINK_CQES`: a skip-success request failed, and the
    /// requests its failure cancels post no CQEs.
    pub const SKIP_LINK_CQES: u32 = 1 << 9;
    /// `REQ_F_NOWAIT`: a transfer that would wait fails with `EAGAIN`
    /// rather than waiting for its file (`RWF_NOWAIT`).
    pub const NOWAIT: u32 = 1 << 10;
    /// `REQ_F_HAS_METADATA`: a transfer with protection information.
    pub const HAS_METADATA: u32 = 1 << 11;
    /// `REQ_F_CREDS`: the request runs with a registered personality.
    pub const CREDS: u32 = 1 << 12;
    /// `IO_REQ_LINK_FLAGS`.
    pub const LINKS: u32 = LINK | HARDLINK;
}

/// A request (`struct io_kiocb`): its SQE as read at submission
/// (`IORING_FEAT_SUBMIT_STABLE`), its flags, its result, what its
/// preparation read (the vectors of `io_async_rw`, the names of `struct
/// filename`s by address, a value it copied, and the operation's own
/// values), and what it holds until it is freed: a file it looked up by
/// descriptor, and the nodes of the registered file and buffer it uses
/// (`file_node`, `buf_node`).
#[derive(Clone, Debug)]
pub struct Req {
    pub sqe: Sqe,
    pub flags: u32,
    pub res: i32,
    pub cflags: u32,
    pub big: [u64; 2],
    pub vecs: Vec<(u64, u64)>,
    pub names: Vec<(u64, Vec<u8>)>,
    pub data: Vec<u8>,
    pub how: [u64; 4],
    pub file: Option<Arc<super::fs::fd::OpenFile>>,
    pub file_node: Option<rsrc::NodeId>,
    pub buf_node: Option<rsrc::NodeId>,
}

impl Req {
    /// A request for `sqe`, its flags copied.
    pub fn new(sqe: Sqe) -> Self {
        Req {
            sqe,
            flags: u32::from(sqe.flags),
            res: 0,
            cflags: 0,
            big: [0; 2],
            vecs: Vec::new(),
            names: Vec::new(),
            data: Vec::new(),
            how: [0; 4],
            file: None,
            file_node: None,
            buf_node: None,
        }
    }

    /// `req_set_fail`: a failed skip-success request posts its CQE and
    /// the requests its failure cancels do not.
    pub fn set_fail(&mut self) {
        self.flags |= req_flags::FAIL;
        if self.flags & req_flags::CQE_SKIP != 0 {
            self.flags &= !req_flags::CQE_SKIP;
            self.flags |= req_flags::SKIP_LINK_CQES;
        }
    }

    /// `req_fail_link_node`: fails the request with `res`.
    pub fn fail(&mut self, res: i32) {
        self.set_fail();
        self.res = res;
        self.cflags = 0;
    }

    /// Its completion.
    pub fn cqe(&self) -> Cqe {
        Cqe {
            user_data: self.sqe.user_data,
            res: self.res,
            flags: self.cflags,
            big: self.big,
        }
    }
}

/// A request and the ones linked after it (`req->link`), in order.
pub type Chain = VecDeque<Req>;

/// Task work an instance queued for its submitter (`io_req_task_work_add`):
/// run as the task returns to user mode, or, for an
/// `IORING_SETUP_DEFER_TASKRUN` ring, only while it waits for completions.
#[derive(Debug)]
pub enum Work {
    /// Issue a chain's head (`io_req_task_submit`): a link's next request,
    /// or a drained request whose turn came.
    Issue(Chain),
    /// Complete a failed link's requests (`io_req_tw_fail_links`): each
    /// with `-ECANCELED`, or with its own result if it failed itself.
    FailLinks(Chain),
    /// Complete a request whose result is set (`io_req_task_complete`).
    Complete(Chain),
}

/// A chain whose head waits for its file (`io_arm_poll_handler`): it is
/// issued again once the file reports an event of `mask` (or an error or
/// hang-up).
#[derive(Debug)]
pub struct Parked {
    pub chain: Chain,
    pub file: Arc<super::fs::fd::OpenFile>,
    pub mask: u32,
}

/// A registered personality: the credentials a request with its identifier
/// runs with (`IORING_REGISTER_PERSONALITY`), as the process holds them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Personality {
    /// `(uid, euid, gid, egid)`.
    pub creds: (u32, u32, u32, u32),
    /// The supplementary groups.
    pub groups: Vec<u32>,
}

/// What an instance keeps besides its rings (`struct io_ring_ctx`).
#[derive(Debug, Default)]
pub struct State {
    /// `cached_sq_head`: the SQEs consumed, committed as `sq.head`.
    pub cached_sq_head: u32,
    /// `cached_cq_tail`: the CQEs posted, committed as `cq.tail`.
    pub cached_cq_tail: u32,
    /// `cq_overflow_list`, never full (so no CQE is dropped).
    pub overflow: VecDeque<Cqe>,
    /// `IORING_SETUP_R_DISABLED` until `IORING_REGISTER_ENABLE_RINGS`.
    pub disabled: bool,
    /// `submitter_task` of an `IORING_SETUP_SINGLE_ISSUER` ring.
    pub submitter: Option<i32>,
    pub eventfd: Option<EventFd>,
    /// `last_cq_tail` of the eventfd: it counts a commit only when the tail
    /// moved.
    pub eventfd_tail: u32,
    /// `nr_req_allocated`: requests submitted and not yet freed.
    pub live: u64,
    /// `defer_list` and `nr_drained`: chains held back by a drain.
    pub defer: VecDeque<Chain>,
    pub drained: u64,
    /// `drain_active`, `drain_next`, and `drain_disabled`.
    pub drain_active: bool,
    pub drain_next: bool,
    pub drain_disabled: bool,
    /// Task work queued (`io_req_task_work_add`).
    pub task_work: VecDeque<Work>,
    /// Requests punted to the async workers (`io_queue_iowq`), run as a
    /// worker would once the submission is done.
    pub iowq: VecDeque<Chain>,
    /// `personalities` and the next identifier `xa_alloc_cyclic` gives.
    pub personalities: std::collections::BTreeMap<u16, Personality>,
    pub next_personality: u16,
    /// The registered files and buffers.
    pub rsrc: rsrc::Tables,
    /// Chains waiting for their files.
    pub parked: Vec<Parked>,
}

/// An io_uring instance: the object behind an `anon_inode:[io_uring]`
/// file.
#[derive(Debug)]
pub struct Ring {
    /// The setup flags.
    pub flags: u32,
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub layout: Layout,
    /// The ring region, page-rounded (`ring_region`).
    pub rings: Arc<SharedObject>,
    /// The SQEs, page-rounded (`sq_region`).
    pub sqes: Arc<SharedObject>,
    /// Created by a 32-bit call (`ctx->compat`): its structures have the
    /// compatibility layouts.
    pub compat: bool,
    /// Its own anon_inode_fs inode (`anon_inode_create_getfile`).
    pub ino: u64,
    /// What its pinned memory is charged to, and the pages of its two
    /// regions charged to the user (`io_create_region`).
    pub account: rsrc::Account,
    region_pages: u64,
    /// The instance itself, for the lists that name it without keeping it.
    me: Weak<Ring>,
    state: Mutex<State>,
}

impl Drop for Ring {
    /// `io_free_region`: the regions' pages are uncharged.
    fn drop(&mut self) {
        self.account.uncharge_user(self.region_pages);
    }
}

/// `get_next_ino` for the rings' inodes: distinct from the inode the
/// other anonymous files share.
static NEXT_INO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0x5241_5a00);

/// `PAGE_ALIGN`.
fn page_align(n: u64) -> u64 {
    n.next_multiple_of(PAGE_SIZE)
}

impl Ring {
    /// `io_allocate_scq_urings`: zeroed regions with the ring masks and
    /// entry counts written, each region's pages charged to the user
    /// against `memlock` pages (`ENOMEM`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flags: u32,
        sq_entries: u32,
        cq_entries: u32,
        layout: Layout,
        compat: bool,
        account: rsrc::Account,
        memlock: u64,
    ) -> Result<Arc<Self>, Errno> {
        let region = |size: u64| {
            SharedObject::anonymous(page_align(size))
                .map(Arc::new)
                .map_err(|_| Errno(ENOMEM))
        };
        let ring_pages = page_align(layout.rings_size) / PAGE_SIZE;
        let sq_pages = page_align(layout.sq_size) / PAGE_SIZE;
        account.charge_user(ring_pages, memlock)?;
        if let Err(e) = account.charge_user(sq_pages, memlock) {
            account.uncharge_user(ring_pages);
            return Err(e);
        }
        let region_pages = ring_pages + sq_pages;
        let (rings, sqes) = match (region(layout.rings_size), region(layout.sq_size)) {
            (Ok(r), Ok(s)) => (r, s),
            (Err(e), _) | (_, Err(e)) => {
                account.uncharge_user(region_pages);
                return Err(e);
            }
        };
        let ring = Arc::new_cyclic(|me| Ring {
            flags,
            sq_entries,
            cq_entries,
            layout,
            rings,
            sqes,
            compat,
            ino: NEXT_INO.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            account,
            region_pages,
            me: me.clone(),
            state: Mutex::new(State {
                disabled: flags & setup::R_DISABLED != 0,
                ..State::default()
            }),
        });
        ring.put32(rings::SQ_RING_MASK, sq_entries - 1);
        ring.put32(rings::CQ_RING_MASK, cq_entries - 1);
        ring.put32(rings::SQ_RING_ENTRIES, sq_entries);
        ring.put32(rings::CQ_RING_ENTRIES, cq_entries);
        Ok(ring)
    }

    /// A reference to the instance that does not keep it.
    pub fn weak(&self) -> Weak<Ring> {
        self.me.clone()
    }

    /// The instance's state.
    pub fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// Drops what released nodes and freed requests held, with the lock
    /// let go.
    pub fn reap(&self) {
        let dead = std::mem::take(&mut self.state().rsrc.dead);
        drop(dead);
    }

    /// A word of the ring region.
    pub fn get32(&self, off: u64) -> u32 {
        let mut b = [0u8; 4];
        let _ = self.rings.read_at(off, &mut b);
        u32::from_le_bytes(b)
    }

    /// Writes a word of the ring region.
    pub fn put32(&self, off: u64, v: u32) {
        let _ = self.rings.host_file().write_all_at(&v.to_le_bytes(), off);
    }

    /// Sets or clears bits of `sq_flags` (`atomic_or`, `atomic_andnot`).
    pub fn sq_flags_update(&self, set: u32, clear: u32) {
        let v = self.get32(rings::SQ_FLAGS);
        self.put32(rings::SQ_FLAGS, (v | set) & !clear);
    }

    /// `io_sqring_entries`: SQEs the process queued past the cached head.
    pub fn sq_pending(&self, st: &State) -> u32 {
        self.get32(rings::SQ_TAIL).wrapping_sub(st.cached_sq_head)
    }

    /// `io_sqring_full`.
    pub fn sq_full(&self, st: &State) -> bool {
        self.sq_pending(st) == self.sq_entries
    }

    /// `io_get_sqe`: the next SQE, consuming its slot; `None` for an index
    /// array entry past the ring (`sq_dropped` counts it).
    pub fn fetch_sqe(&self, st: &mut State) -> Option<(u32, Sqe)> {
        let mask = self.sq_entries - 1;
        let mut head = st.cached_sq_head & mask;
        st.cached_sq_head = st.cached_sq_head.wrapping_add(1);
        if let Some(array) = self.layout.sq_array {
            head = self.get32(array + 4 * u64::from(head));
            if head >= self.sq_entries {
                let dropped = self.get32(rings::SQ_DROPPED);
                self.put32(rings::SQ_DROPPED, dropped.wrapping_add(1));
                return None;
            }
        }
        Some((head, self.sqe_at(head)))
    }

    /// The SQE in slot `index` (a 128-byte ring's slots are doubled).
    pub fn sqe_at(&self, index: u32) -> Sqe {
        let mut b = [0u8; 64];
        let _ = self.sqes.read_at(self.sqe_offset(index), &mut b);
        Sqe::decode(&b)
    }

    /// The byte offset of SQE slot `index`.
    pub fn sqe_offset(&self, index: u32) -> u64 {
        let shift = u32::from(self.flags & setup::SQE128 != 0);
        u64::from(index << shift) * abi::SQE_SIZE
    }

    /// `io_commit_sqring`: publishes the consumed head.
    pub fn commit_sq(&self, st: &State) {
        self.put32(rings::SQ_HEAD, st.cached_sq_head);
    }

    /// `__io_cqring_events`: posted but not yet consumed.
    pub fn cq_queued(&self, st: &State) -> u32 {
        st.cached_cq_tail.wrapping_sub(self.get32(rings::CQ_HEAD))
    }

    /// `__io_cqring_events_user`: what the process sees in the ring.
    pub fn cq_ready(&self) -> u32 {
        self.get32(rings::CQ_TAIL)
            .wrapping_sub(self.get32(rings::CQ_HEAD))
    }

    fn cqe32(&self) -> bool {
        self.flags & setup::CQE32 != 0
    }

    /// Writes `cqe` at the cached tail if the ring has room
    /// (`io_cqe_cache_refill`, `io_fill_cqe_req`): the whole slot, or
    /// (`whole` false) its first 16 bytes.
    fn fill(&self, st: &mut State, cqe: &Cqe, whole: bool) -> bool {
        // userspace may move the head past the tail: the minimum.
        let queued = self.cq_queued(st).min(self.cq_entries);
        if queued == self.cq_entries {
            return false;
        }
        let slot = st.cached_cq_tail & (self.cq_entries - 1);
        let size = abi::CQE_SIZE * if self.cqe32() { 2 } else { 1 };
        let bytes = cqe.encode();
        let len = if whole { size } else { abi::CQE_SIZE };
        let _ = self
            .rings
            .host_file()
            .write_all_at(&bytes[..len as usize], rings::CQES + u64::from(slot) * size);
        st.cached_cq_tail = st.cached_cq_tail.wrapping_add(1);
        true
    }

    /// Posts a completion: into the ring, or, if it is full or earlier
    /// completions wait on the overflow list (which keeps them ordered),
    /// onto that list (`io_cqring_add_overflow`).
    pub fn post(&self, st: &mut State, cqe: Cqe) {
        self.post_as(st, cqe, true);
    }

    fn post_as(&self, st: &mut State, cqe: Cqe, whole: bool) {
        if st.overflow.is_empty() && self.fill(st, &cqe, whole) {
            return;
        }
        if st.overflow.is_empty() {
            self.sq_flags_update(sq_flags::CQ_OVERFLOW, 0);
        }
        st.overflow.push_back(cqe);
    }

    /// `io_post_aux_cqe`: a completion no request posts (a released
    /// node's tag). Written into the ring it fills only the 16-byte entry,
    /// leaving a 32-byte slot's extra words as they were; an overflowed
    /// one has them zeroed (`io_alloc_ocqe`).
    pub fn post_aux(&self, st: &mut State, user_data: u64, res: i32, flags: u32) {
        self.post_as(st, Cqe::new(user_data, res, flags), false);
    }

    /// `io_commit_cqring`: publishes the posted tail.
    pub fn commit_cq(&self, st: &State) {
        self.put32(rings::CQ_TAIL, st.cached_cq_tail);
    }

    /// `__io_cqring_overflow_flush`: moves overflowed completions into the
    /// ring while it has room; the flag clears once the list is empty.
    pub fn flush_overflow(&self, st: &mut State) {
        if st.overflow.is_empty() {
            return;
        }
        while let Some(cqe) = st.overflow.front().copied() {
            if !self.fill(st, &cqe, true) {
                break;
            }
            st.overflow.pop_front();
        }
        if st.overflow.is_empty() {
            self.sq_flags_update(0, sq_flags::CQ_OVERFLOW);
        }
        self.commit_cq(st);
    }
}
