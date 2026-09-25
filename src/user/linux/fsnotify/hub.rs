//! The emulated backend: inotify instances and watches shared by every
//! `rax-user` process of a host user, so that what any of them does to a
//! file reaches every instance watching it, as the kernel's marks do.
//!
//! The namespace is a directory (per user under the temporary directory,
//! or `LinuxConfig::fsnotify_dir`) holding:
//!
//! | File | Contents |
//! |---|---|
//! | `index` | counters, a hash of watched inodes, and the watch records (the marks) |
//! | `i<id>` | instance `id`: its descriptor cursor, holders, and event [`queue`](super::queue) |
//! | `i<id>.fifo` | a level: one byte while the instance's queue is not empty |
//! | `lock` | the namespace lock (`flock`, which a killed process releases) |
//!
//! The files are mapped shared. Changes happen under the lock; a process
//! about to report an event first reads, without it, whether anything is
//! watched at all and whether the inode's hash bucket holds a watch, so
//! that unwatched files cost two loads. An instance is freed when no live
//! process holds it: holders are host process IDs, and a holder that died
//! without releasing it is found by its absence.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::bits::*;
use super::queue::{self, Inserted, Queue};
use super::sys::{self, Lock, Mapping};
use super::{Action, Event, Hook, Key, Mark, Obj, Watched};

/// `max_user_instances` of a fresh kernel.
pub const MAX_USER_INSTANCES: usize = 128;
/// `max_user_watches`: the kernel's upper bound for it.
pub const MAX_USER_WATCHES: usize = 1 << 20;

const MAGIC: u64 = u64::from_le_bytes(*b"RAXFSN01");
/// Index header words.
const W_MAGIC: usize = 0;
/// Live watches: zero lets every event go unreported at once.
const W_WATCHES: usize = 1;
const W_NEXT_INSTANCE: usize = 2;
/// `fsnotify_sync_cookie`.
const W_COOKIE: usize = 3;
/// First free record plus one.
const W_FREE: usize = 4;
/// Records ever used.
const W_HIGH: usize = 5;
const W_SEQ: usize = 6;
/// Where the search for a free token count starts.
const W_TOKEN_HINT: usize = 7;
/// Instance slots (words from `SLOT_BASE`): an instance identifier each,
/// zero when free.
const SLOTS: usize = 1024;
const SLOT_BASE: usize = 64;
/// Reference counts of open files shared by forked processes (32-bit,
/// from byte `TOKEN_BASE`), zero when free.
const TOKENS: usize = 1 << 16;
const TOKEN_BASE: usize = (SLOT_BASE + SLOTS) * 8;
const BUCKETS: usize = 1 << 16;
const BUCKET_BASE: usize = (TOKEN_BASE + TOKENS * 4).next_multiple_of(4096);
const RECORD_BASE: usize = BUCKET_BASE + BUCKETS * 4;
const RECORD: usize = 64;
const INDEX_LEN: usize = RECORD_BASE + MAX_USER_WATCHES * RECORD;

/// Instance header words.
const I_MAGIC: usize = 0;
/// `idr_next`.
const I_CURSOR: usize = 1;
/// First watch record plus one.
const I_WATCHES: usize = 2;
/// The guest user the instance counts against.
const I_UID: usize = 3;
const I_HOLDERS: usize = 4;
const I_HOLDER_BASE: usize = 5;
const HOLDERS_MAX: usize = 64;
const I_QUEUE: usize = 4096;

/// A watch record in the index.
#[derive(Clone, Copy, Debug, Default)]
struct Record {
    key: Key,
    seq: u64,
    instance: u32,
    wd: i32,
    mask: u32,
    flags: u32,
    bucket_next: u32,
    inst_next: u32,
    uid: u32,
    in_use: bool,
    dir: bool,
}

impl Record {
    fn mark(&self) -> Mark {
        Mark {
            wd: self.wd,
            mask: self.mask,
            flags: self.flags,
        }
    }
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn bucket_of(k: Key) -> usize {
    let h = (k.dev ^ k.ino.rotate_left(17)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (h >> 48) as usize % BUCKETS
}

/// This process's view of an instance: its mapping and FIFO.
struct View {
    map: Mapping,
    fifo: OwnedFd,
}

/// The namespace, as one process sees it.
pub struct Hub {
    dir: PathBuf,
    index: Mapping,
    /// The lock file, opened by the process it names (a forked child
    /// opens its own, since a `flock` belongs to an open file).
    lock: Mutex<Option<(u32, File)>>,
    views: Mutex<HashMap<u32, Arc<View>>>,
    /// The instances this process holds, with how many handles.
    held: Mutex<HashMap<u32, usize>>,
    /// This process's open files, by inode.
    tokens: Mutex<HashMap<Key, Vec<Weak<Token>>>>,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

/// The index under the lock.
struct Index<'a> {
    b: &'a mut [u8],
}

impl Index<'_> {
    fn word(&self, i: usize) -> u64 {
        le64(self.b, i * 8)
    }

    fn set_word(&mut self, i: usize, v: u64) {
        self.b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn bucket(&self, k: Key) -> u32 {
        le32(self.b, BUCKET_BASE + bucket_of(k) * 4)
    }

    fn set_bucket(&mut self, k: Key, v: u32) {
        let at = BUCKET_BASE + bucket_of(k) * 4;
        self.b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn slot(&self, i: usize) -> u32 {
        self.word(SLOT_BASE + i) as u32
    }

    fn count(&self, i: u32) -> u32 {
        le32(self.b, TOKEN_BASE + i as usize * 4)
    }

    fn set_count(&mut self, i: u32, v: u32) {
        let at = TOKEN_BASE + i as usize * 4;
        self.b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A free token count, set to `v`.
    fn alloc_count(&mut self, v: u32) -> Option<u32> {
        let hint = self.word(W_TOKEN_HINT) as usize;
        let i = (0..TOKENS)
            .map(|k| ((hint + k) % TOKENS) as u32)
            .find(|&i| self.count(i) == 0)?;
        self.set_count(i, v);
        self.set_word(W_TOKEN_HINT, u64::from(i) + 1);
        Some(i)
    }

    fn set_slot(&mut self, i: usize, id: u32) {
        self.set_word(SLOT_BASE + i, u64::from(id));
    }

    fn record(&self, i: u32) -> Record {
        let at = RECORD_BASE + i as usize * RECORD;
        let b = &self.b[at..at + RECORD];
        Record {
            key: Key {
                dev: le64(b, 0),
                ino: le64(b, 8),
            },
            seq: le64(b, 16),
            instance: le32(b, 24),
            wd: le32(b, 28) as i32,
            mask: le32(b, 32),
            flags: le32(b, 36),
            bucket_next: le32(b, 40),
            inst_next: le32(b, 44),
            uid: le32(b, 48),
            in_use: b[52] != 0,
            dir: b[53] != 0,
        }
    }

    fn put(&mut self, i: u32, r: &Record) {
        let at = RECORD_BASE + i as usize * RECORD;
        let b = &mut self.b[at..at + RECORD];
        b.fill(0);
        b[0..8].copy_from_slice(&r.key.dev.to_le_bytes());
        b[8..16].copy_from_slice(&r.key.ino.to_le_bytes());
        b[16..24].copy_from_slice(&r.seq.to_le_bytes());
        b[24..28].copy_from_slice(&r.instance.to_le_bytes());
        b[28..32].copy_from_slice(&r.wd.to_le_bytes());
        b[32..36].copy_from_slice(&r.mask.to_le_bytes());
        b[36..40].copy_from_slice(&r.flags.to_le_bytes());
        b[40..44].copy_from_slice(&r.bucket_next.to_le_bytes());
        b[44..48].copy_from_slice(&r.inst_next.to_le_bytes());
        b[48..52].copy_from_slice(&r.uid.to_le_bytes());
        b[52] = u8::from(r.in_use);
        b[53] = u8::from(r.dir);
    }

    /// The records of the watches on `k`.
    fn on(&self, k: Key) -> Vec<(u32, Record)> {
        let mut out = Vec::new();
        let mut i = self.bucket(k);
        while i != 0 {
            let r = self.record(i - 1);
            if r.in_use && r.key == k {
                out.push((i - 1, r));
            }
            i = r.bucket_next;
        }
        out
    }

    /// The records of instance `id`'s watches, from its list head.
    fn of(&self, head: u32) -> Vec<(u32, Record)> {
        let mut out = Vec::new();
        let mut i = head;
        while i != 0 {
            let r = self.record(i - 1);
            out.push((i - 1, r));
            i = r.inst_next;
        }
        out
    }

    fn watches_of(&self, uid: u32) -> usize {
        let high = self.word(W_HIGH) as u32;
        (0..high)
            .map(|i| self.record(i))
            .filter(|r| r.in_use && r.uid == uid)
            .count()
    }

    fn alloc(&mut self) -> Result<u32, Errno> {
        let free = self.word(W_FREE) as u32;
        if free != 0 {
            let next = self.record(free - 1).inst_next;
            self.set_word(W_FREE, u64::from(next));
            return Ok(free - 1);
        }
        let high = self.word(W_HIGH) as u32;
        if high as usize >= MAX_USER_WATCHES {
            return Err(Errno(ENOSPC));
        }
        self.set_word(W_HIGH, u64::from(high) + 1);
        Ok(high)
    }

    /// Unlinks record `i` from its bucket and frees it (the instance list
    /// is the caller's).
    fn free(&mut self, i: u32) {
        let r = self.record(i);
        let mut prev: Option<u32> = None;
        let mut cur = self.bucket(r.key);
        while cur != 0 && cur - 1 != i {
            prev = Some(cur - 1);
            cur = self.record(cur - 1).bucket_next;
        }
        match prev {
            None => self.set_bucket(r.key, r.bucket_next),
            Some(p) => {
                let mut pr = self.record(p);
                pr.bucket_next = r.bucket_next;
                self.put(p, &pr);
            }
        }
        let freed = Record {
            inst_next: self.word(W_FREE) as u32,
            ..Record::default()
        };
        self.put(i, &freed);
        self.set_word(W_FREE, u64::from(i) + 1);
        let n = self.word(W_WATCHES);
        self.set_word(W_WATCHES, n.saturating_sub(1));
    }
}

/// An instance's header under the lock.
struct Header<'a> {
    b: &'a mut [u8],
}

impl Header<'_> {
    fn word(&self, i: usize) -> u64 {
        le64(self.b, i * 8)
    }

    fn set(&mut self, i: usize, v: u64) {
        self.b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn holders(&self) -> Vec<i32> {
        let n = (self.word(I_HOLDERS) as usize).min(HOLDERS_MAX);
        (0..n)
            .map(|i| self.word(I_HOLDER_BASE + i) as i32)
            .collect()
    }

    fn set_holders(&mut self, h: &[i32]) {
        let h = &h[..h.len().min(HOLDERS_MAX)];
        self.set(I_HOLDERS, h.len() as u64);
        for (i, p) in h.iter().enumerate() {
            self.set(I_HOLDER_BASE + i, *p as u32 as u64);
        }
    }
}

/// What reading an instance found.
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    /// The records of the events that fit.
    Events(Vec<u8>),
    /// The first event does not fit (`EINVAL`).
    TooSmall,
    /// Nothing is queued.
    Empty,
}

impl Hub {
    /// The namespace in `dir` (made, owner-only, if missing).
    pub fn open(dir: PathBuf) -> Result<Arc<Hub>, Errno> {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Errno::from(e)),
        }
        let index = Mapping::open(&dir.join("index"), INDEX_LEN)?;
        let hub = Arc::new(Hub {
            dir,
            index,
            lock: Mutex::new(None),
            views: Mutex::new(HashMap::new()),
            held: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
        });
        if hub.index.word(W_MAGIC).load(Ordering::Acquire) != MAGIC {
            hub.locked(|ix| {
                if ix.word(W_MAGIC) != MAGIC {
                    ix.b[..RECORD_BASE].fill(0);
                    ix.set_word(W_MAGIC, MAGIC);
                }
                Ok(())
            })?;
        }
        Ok(hub)
    }

    /// The default namespace directory.
    pub fn default_dir() -> PathBuf {
        // SAFETY: geteuid has no failure mode.
        let uid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("rax-user-fsnotify-{uid}"))
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether anything is watched: when not, no event needs reporting.
    pub fn active(&self) -> bool {
        self.index.word(W_WATCHES).load(Ordering::Acquire) != 0
    }

    /// Whether inode `k` may be watched (its hash bucket holds a watch).
    pub fn maybe(&self, k: Key) -> bool {
        if !self.active() {
            return false;
        }
        let w = self.index.word((BUCKET_BASE + bucket_of(k) * 4) / 8);
        let v = w.load(Ordering::Acquire);
        let shift = if bucket_of(k) % 2 == 0 { 0 } else { 32 };
        (v >> shift) as u32 != 0
    }

    /// Runs `f` on the index under the namespace lock.
    fn locked<R>(&self, f: impl FnOnce(&mut Index<'_>) -> Result<R, Errno>) -> Result<R, Errno> {
        let pid = std::process::id();
        let mut guard = self.lock.lock().unwrap();
        if guard.as_ref().is_none_or(|(p, _)| *p != pid) {
            use std::os::unix::fs::OpenOptionsExt;
            let f = File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC)
                .open(self.dir.join("lock"))?;
            *guard = Some((pid, f));
        }
        let (_, file) = guard.as_ref().unwrap();
        let _held = Lock::new(file)?;
        f(&mut Index {
            b: self.index.bytes(),
        })
    }

    /// This process's view of instance `id`.
    fn view(&self, id: u32) -> Result<Arc<View>, Errno> {
        if let Some(v) = self.views.lock().unwrap().get(&id) {
            return Ok(v.clone());
        }
        let map = Mapping::open(
            &self.dir.join(format!("i{id}")),
            I_QUEUE + queue::region_len(queue::MAX_QUEUED),
        )?;
        let fifo = sys::open_fifo(&self.dir.join(format!("i{id}.fifo")))?;
        let v = Arc::new(View { map, fifo });
        self.views.lock().unwrap().insert(id, v.clone());
        Ok(v)
    }

    /// Queues `e` for instance `id`, setting its level if it was empty.
    fn queue(&self, id: u32, e: &Event) -> Result<(), Errno> {
        let v = self.view(id)?;
        let b = v.map.bytes();
        let mut q = Queue::new(&mut b[I_QUEUE..]);
        let was_empty = q.is_empty();
        if q.insert(e) != Inserted::Dropped && was_empty && !q.is_empty() {
            super::super::host::put_byte(v.fifo.as_raw_fd());
        }
        Ok(())
    }

    /// Removes watch `idx` of instance `id`, queueing its `IN_IGNORED`
    /// (`inotify_ignored_and_remove_idr`).
    fn remove(&self, ix: &mut Index<'_>, idx: u32, ignored: bool) -> Result<(), Errno> {
        let r = ix.record(idx);
        if ignored {
            self.queue(r.instance, &Event::ignored(r.wd))?;
        }
        let v = self.view(r.instance)?;
        let mut h = Header { b: v.map.bytes() };
        let mut cur = h.word(I_WATCHES) as u32;
        let mut prev: Option<u32> = None;
        while cur != 0 && cur - 1 != idx {
            prev = Some(cur - 1);
            cur = ix.record(cur - 1).inst_next;
        }
        match prev {
            None => h.set(I_WATCHES, u64::from(r.inst_next)),
            Some(p) => {
                let mut pr = ix.record(p);
                pr.inst_next = r.inst_next;
                ix.put(p, &pr);
            }
        }
        ix.free(idx);
        Ok(())
    }

    /// Frees instance `id` and its watches.
    fn destroy(&self, ix: &mut Index<'_>, slot: usize, id: u32) -> Result<(), Errno> {
        let v = self.view(id)?;
        let head = Header { b: v.map.bytes() }.word(I_WATCHES) as u32;
        for (i, _) in ix.of(head) {
            ix.free(i);
        }
        ix.set_slot(slot, 0);
        self.views.lock().unwrap().remove(&id);
        let _ = std::fs::remove_file(self.dir.join(format!("i{id}")));
        let _ = std::fs::remove_file(self.dir.join(format!("i{id}.fifo")));
        Ok(())
    }

    /// Frees the instances no live process holds.
    fn prune(&self, ix: &mut Index<'_>) -> Result<(), Errno> {
        for slot in 0..SLOTS {
            let id = ix.slot(slot);
            if id == 0 {
                continue;
            }
            let v = self.view(id)?;
            let holders = Header { b: v.map.bytes() }.holders();
            let live: Vec<i32> = holders.iter().copied().filter(|&p| sys::alive(p)).collect();
            if live.is_empty() {
                self.destroy(ix, slot, id)?;
            } else if live.len() != holders.len() {
                Header { b: v.map.bytes() }.set_holders(&live);
            }
        }
        Ok(())
    }

    /// `inotify_new_group`: a new instance counted against guest user
    /// `uid` (`EMFILE` past `max_user_instances`).
    pub fn create(self: &Arc<Self>, uid: u32) -> Result<Handle, Errno> {
        let id = self.locked(|ix| {
            self.prune(ix)?;
            let mut mine = 0;
            let mut free = None;
            for slot in 0..SLOTS {
                let id = ix.slot(slot);
                if id == 0 {
                    free.get_or_insert(slot);
                    continue;
                }
                let v = self.view(id)?;
                let owner = Header { b: v.map.bytes() }.word(I_UID);
                if owner == u64::from(uid) {
                    mine += 1;
                }
            }
            let Some(slot) = free.filter(|_| mine < MAX_USER_INSTANCES) else {
                return Err(Errno(EMFILE));
            };
            let id = ix.word(W_NEXT_INSTANCE) as u32 + 1;
            ix.set_word(W_NEXT_INSTANCE, u64::from(id));
            sys::mkfifo(&self.dir.join(format!("i{id}.fifo")))?;
            let v = self.view(id)?;
            let b = v.map.bytes();
            b[..I_QUEUE].fill(0);
            Queue::init(&mut b[I_QUEUE..], queue::MAX_QUEUED);
            let mut h = Header { b };
            h.set(I_MAGIC, MAGIC);
            h.set(I_UID, u64::from(uid));
            h.set_holders(&[std::process::id() as i32]);
            ix.set_slot(slot, id);
            Ok(id)
        })?;
        *self.held.lock().unwrap().entry(id).or_default() += 1;
        Ok(Handle {
            hub: self.clone(),
            id,
        })
    }

    /// After `fork`, in the child: it holds what its parent held.
    pub fn forked(&self) {
        let ids: Vec<u32> = self.held.lock().unwrap().keys().copied().collect();
        let pid = std::process::id() as i32;
        let _ = self.locked(|_| {
            for id in ids {
                let v = self.view(id)?;
                let mut h = Header { b: v.map.bytes() };
                let mut holders = h.holders();
                if !holders.contains(&pid) {
                    holders.push(pid);
                    h.set_holders(&holders);
                }
            }
            Ok(())
        });
    }

    /// The last handle of this process to instance `id` is gone.
    fn release(&self, id: u32) {
        {
            let mut held = self.held.lock().unwrap();
            match held.get_mut(&id) {
                Some(n) if *n > 1 => {
                    *n -= 1;
                    return;
                }
                _ => {
                    held.remove(&id);
                }
            }
        }
        let pid = std::process::id() as i32;
        let _ = self.locked(|ix| {
            let Some(slot) = (0..SLOTS).find(|&s| ix.slot(s) == id) else {
                return Ok(());
            };
            let v = self.view(id)?;
            let mut h = Header { b: v.map.bytes() };
            let holders: Vec<i32> = h.holders().into_iter().filter(|&p| p != pid).collect();
            if holders.is_empty() {
                self.destroy(ix, slot, id)
            } else {
                h.set_holders(&holders);
                Ok(())
            }
        });
    }

    /// `fsnotify_get_cookie`.
    pub fn cookie(&self) -> u32 {
        self.locked(|ix| {
            let c = ix.word(W_COOKIE) as u32 + 1;
            ix.set_word(W_COOKIE, u64::from(c));
            Ok(c)
        })
        .unwrap_or(0)
    }

    /// Reports one `fsnotify` call to every instance watching.
    pub fn notify(&self, hook: &Hook<'_>) {
        let (inode, parent) = match *hook {
            Hook::Parent { obj, parent, .. } => (obj.key, parent.map(|p| p.0)),
            Hook::Inode { obj, .. } => (obj.key, None),
            Hook::Name { dir, .. } => (dir, None),
        };
        if !self.maybe(inode) && !parent.is_some_and(|p| self.maybe(p)) {
            return;
        }
        let _ = self.locked(|ix| self.deliver(ix, hook, inode, parent));
    }

    fn deliver(
        &self,
        ix: &mut Index<'_>,
        hook: &Hook<'_>,
        inode: Key,
        parent: Option<Key>,
    ) -> Result<(), Errno> {
        let on_inode = ix.on(inode);
        let on_parent = parent.map(|p| ix.on(p)).unwrap_or_default();
        let w = Watched {
            parent_mask: on_parent.iter().fold(0, |m, (_, r)| m | r.mask),
            parent_marks: !on_parent.is_empty(),
        };
        let (mask, interested) = super::parent_interest(hook, w);
        let mut groups: BTreeMap<u32, (Option<Mark>, Option<Mark>)> = BTreeMap::new();
        for (_, r) in &on_inode {
            groups.entry(r.instance).or_default().0 = Some(r.mark());
        }
        for (_, r) in &on_parent {
            groups.entry(r.instance).or_default().1 = Some(r.mark());
        }
        for (id, (im, pm)) in groups {
            for a in super::deliver(hook, mask, interested, im, pm) {
                match a {
                    Action::Queue(e) => self.queue(id, &e)?,
                    Action::Remove(wd) => {
                        if let Some(idx) = self.find(ix, id, wd)? {
                            self.remove(ix, idx, true)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Watch `wd` of instance `id`.
    fn find(&self, ix: &Index<'_>, id: u32, wd: i32) -> Result<Option<u32>, Errno> {
        let head = Header {
            b: self.view(id)?.map.bytes(),
        }
        .word(I_WATCHES) as u32;
        Ok(ix
            .of(head)
            .into_iter()
            .find(|(_, r)| r.wd == wd)
            .map(|(i, _)| i))
    }

    /// `fsnotify_inoderemove`: inode `obj` is gone. Its watches hear of
    /// it, then are removed.
    pub fn inode_removed(&self, obj: Obj) {
        if !self.maybe(obj.key) {
            return;
        }
        let _ = self.locked(|ix| {
            let hook = Hook::Inode {
                obj,
                mask: IN_DELETE_SELF,
            };
            self.deliver(ix, &hook, obj.key, None)?;
            for (idx, _) in ix.on(obj.key) {
                self.remove(ix, idx, true)?;
            }
            Ok(())
        });
    }

    /// This process's open files of inode `k`.
    fn tokens_of(&self, k: Key) -> Vec<Arc<Token>> {
        let mut t = self.tokens.lock().unwrap();
        let Some(list) = t.get_mut(&k) else {
            return Vec::new();
        };
        list.retain(|w| w.strong_count() > 0);
        list.iter().filter_map(Weak::upgrade).collect()
    }
}

/// A process's handle to an instance, held by its open file description.
#[derive(Debug)]
pub struct Handle {
    hub: Arc<Hub>,
    id: u32,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.hub.release(self.id);
    }
}

impl Handle {
    /// The descriptor that is readable while events are queued.
    pub fn level_fd(&self) -> Result<i32, Errno> {
        Ok(self.hub.view(self.id)?.fifo.as_raw_fd())
    }

    fn with<R>(
        &self,
        f: impl FnOnce(&Hub, &mut Index<'_>, &View) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        self.hub.locked(|ix| {
            let v = self.hub.view(self.id)?;
            f(&self.hub, ix, &v)
        })
    }

    /// `inotify_update_watch` on inode `obj` (whose guest user is `uid`):
    /// the watch descriptor.
    pub fn add_watch(&self, obj: Obj, arg: u32, uid: u32) -> Result<i32, Errno> {
        self.with(|_, ix, v| {
            let head = Header { b: v.map.bytes() }.word(I_WATCHES) as u32;
            let mine = ix.of(head);
            if let Some((idx, mut r)) = mine.iter().copied().find(|(_, r)| r.key == obj.key) {
                if arg & IN_MASK_CREATE != 0 {
                    return Err(Errno(EEXIST));
                }
                let mut m = r.mark();
                m.update(arg, r.dir);
                r.mask = m.mask;
                r.flags = m.flags;
                ix.put(idx, &r);
                return Ok(r.wd);
            }
            // idr_alloc_cyclic from 1: the lowest free descriptor from the
            // cursor, then from 1.
            let used: std::collections::BTreeSet<i32> = mine.iter().map(|(_, r)| r.wd).collect();
            let mut h = Header { b: v.map.bytes() };
            let from = (h.word(I_CURSOR) as i32).max(1);
            let free_from = |start: i32| (start..=i32::MAX).find(|w| !used.contains(w));
            let wd = free_from(from)
                .or_else(|| free_from(1))
                .ok_or(Errno(ENOSPC))?;
            h.set(I_CURSOR, (wd as u32).wrapping_add(1) as u64);
            // inc_inotify_watches after the descriptor is taken.
            if ix.watches_of(uid) >= MAX_USER_WATCHES {
                return Err(Errno(ENOSPC));
            }
            let idx = ix.alloc()?;
            let seq = ix.word(W_SEQ) + 1;
            ix.set_word(W_SEQ, seq);
            let m = Mark::from_arg(wd, arg, obj.dir);
            let r = Record {
                key: obj.key,
                seq,
                instance: self.id,
                wd,
                mask: m.mask,
                flags: m.flags,
                bucket_next: ix.bucket(obj.key),
                inst_next: head,
                uid,
                in_use: true,
                dir: obj.dir,
            };
            ix.put(idx, &r);
            ix.set_bucket(obj.key, idx + 1);
            Header { b: v.map.bytes() }.set(I_WATCHES, u64::from(idx) + 1);
            let n = ix.word(W_WATCHES);
            ix.set_word(W_WATCHES, n + 1);
            Ok(wd)
        })
    }

    /// `inotify_rm_watch`: `EINVAL` for a descriptor the instance lacks.
    pub fn rm_watch(&self, wd: i32) -> Result<(), Errno> {
        self.with(|hub, ix, _| {
            let idx = hub.find(ix, self.id, wd)?.ok_or(Errno(EINVAL))?;
            hub.remove(ix, idx, true)
        })
    }

    /// `inotify_read`'s dequeueing: the events that fit in `count` bytes.
    pub fn read(&self, count: usize) -> Result<Read, Errno> {
        self.with(|_, _, v| {
            let b = v.map.bytes();
            let mut q = Queue::new(&mut b[I_QUEUE..]);
            let mut out = Vec::new();
            while let Some(e) = q.peek() {
                if queue::read_size(&e) > count - out.len() {
                    break;
                }
                q.pop();
                out.extend_from_slice(&queue::encode(&e));
            }
            if q.is_empty() && !out.is_empty() {
                super::super::host::take_byte(v.fifo.as_raw_fd());
            }
            Ok(if !out.is_empty() {
                Read::Events(out)
            } else if q.is_empty() {
                Read::Empty
            } else {
                Read::TooSmall
            })
        })
    }

    /// `INOTIFY_IOC_SETNEXTWD`: the next descriptor is sought from `wd`
    /// (`idr_set_cursor`).
    pub fn set_next_wd(&self, wd: i32) -> Result<(), Errno> {
        self.with(|_, _, v| {
            Header { b: v.map.bytes() }.set(I_CURSOR, wd as u64);
            Ok(())
        })
    }

    /// `FIONREAD`.
    pub fn pending_bytes(&self) -> Result<u64, Errno> {
        self.with(|_, _, v| Ok(Queue::new(&mut v.map.bytes()[I_QUEUE..]).bytes()))
    }

    /// Whether events are queued (`inotify_poll`).
    pub fn ready(&self) -> Result<bool, Errno> {
        self.with(|_, _, v| Ok(!Queue::new(&mut v.map.bytes()[I_QUEUE..]).is_empty()))
    }

    /// The watches, newest first (`inotify_fdinfo`): descriptor, inode,
    /// and mask.
    pub fn watches(&self) -> Result<Vec<(i32, Key, u32)>, Errno> {
        self.with(|_, ix, v| {
            let head = Header { b: v.map.bytes() }.word(I_WATCHES) as u32;
            let mut w = ix.of(head);
            w.sort_by_key(|(_, r)| std::cmp::Reverse(r.seq));
            Ok(w.into_iter()
                .map(|(_, r)| (r.wd, r.key, r.mark().user_mask()))
                .collect())
        })
    }
}

/// An open file as file-system notification sees it: what reports its
/// opens, reads, writes, and, when it and its mappings are all gone, its
/// close (`__fput`).
#[derive(Debug)]
pub struct Token {
    hub: Arc<Hub>,
    obj: Obj,
    /// The host path it was opened by (its directory entry).
    path: Mutex<PathBuf>,
    /// The directory's inode, once looked up.
    parent: Mutex<Option<Key>>,
    /// `FMODE_WRITE`.
    write: bool,
    /// The entry was removed (`d_unlinked`), leaving the inode without
    /// links when `gone`.
    unlinked: std::sync::atomic::AtomicBool,
    gone: std::sync::atomic::AtomicBool,
    /// Its reference count shared with forked processes, once it has one.
    shared: Mutex<Option<u32>>,
    /// Its close was reported or passed on (dropped, or the process
    /// exited).
    released: std::sync::atomic::AtomicBool,
}

impl Hub {
    /// A token for a file this process opened, and its `IN_OPEN`
    /// (`fsnotify_open`; `exec` adds `FS_OPEN_EXEC`).
    pub fn open_file(
        self: &Arc<Self>,
        obj: Obj,
        path: PathBuf,
        write: bool,
        exec: bool,
    ) -> Arc<Token> {
        let t = Arc::new(Token {
            hub: self.clone(),
            obj,
            path: Mutex::new(path),
            parent: Mutex::new(None),
            write,
            unlinked: std::sync::atomic::AtomicBool::new(false),
            gone: std::sync::atomic::AtomicBool::new(false),
            shared: Mutex::new(None),
            released: std::sync::atomic::AtomicBool::new(false),
        });
        self.tokens
            .lock()
            .unwrap()
            .entry(obj.key)
            .or_default()
            .push(Arc::downgrade(&t));
        t.event(IN_OPEN | if exec { FS_OPEN_EXEC } else { 0 });
        t
    }
}

impl Token {
    /// The inode.
    pub fn obj(&self) -> Obj {
        self.obj
    }

    /// Reports `mask` on the open file (`fsnotify_file`).
    pub fn event(&self, mask: u32) {
        self.report(mask, true);
    }

    /// Reports an attribute change through the open file
    /// (`fsnotify_change` on its dentry).
    pub fn change(&self, mask: u32) {
        self.report(mask, false);
    }

    /// Whether the inode has no links left (`IS_DEADDIR` for a
    /// directory).
    pub fn removed(&self) -> bool {
        self.gone.load(Ordering::Relaxed)
    }

    fn report(&self, mask: u32, path_data: bool) {
        if !self.hub.active() {
            return;
        }
        let path = self.path.lock().unwrap().clone();
        let name = path.file_name().map(|n| {
            use std::os::unix::ffi::OsStrExt;
            n.as_bytes().to_vec()
        });
        let parent = {
            let mut p = self.parent.lock().unwrap();
            if p.is_none()
                && let Some(dir) = path.parent()
                && let Ok(m) = std::fs::metadata(dir)
            {
                use std::os::unix::fs::MetadataExt;
                *p = Some(Key {
                    dev: m.dev(),
                    ino: m.ino(),
                });
            }
            *p
        };
        let hook = Hook::Parent {
            obj: self.obj,
            parent: parent.zip(name.as_deref()),
            mask,
            path: path_data,
            unlinked: self.unlinked.load(Ordering::Relaxed),
        };
        self.hub.notify(&hook);
    }
}

impl Token {
    /// This process's reference is gone (`fput`): the last reference of
    /// all reports the close (`__fput`), and the inode's end when it has
    /// no links left (`dentry_unlink_inode`).
    fn release(&self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(i) = *self.shared.lock().unwrap() {
            let last = self
                .hub
                .locked(|ix| {
                    let n = ix.count(i).saturating_sub(1);
                    ix.set_count(i, n);
                    Ok(n == 0)
                })
                .unwrap_or(true);
            if !last {
                return;
            }
        }
        self.event(if self.write {
            IN_CLOSE_WRITE
        } else {
            IN_CLOSE_NOWRITE
        });
        let others = self
            .hub
            .tokens_of(self.obj.key)
            .iter()
            .any(|t| !std::ptr::eq(&**t, self) && !t.released.load(Ordering::Acquire));
        if self.gone.load(Ordering::Relaxed) && !others {
            self.hub.inode_removed(self.obj);
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.release();
    }
}

impl Hub {
    /// This process's open files.
    fn all_tokens(&self) -> Vec<Arc<Token>> {
        let mut t = self.tokens.lock().unwrap();
        t.values_mut()
            .flat_map(|l| {
                l.retain(|w| w.strong_count() > 0);
                l.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
            })
            .filter(|t| !t.released.load(Ordering::Acquire))
            .collect()
    }

    /// Before `fork`: the child will hold every open file too, so each
    /// gets a reference count shared with it.
    pub fn before_fork(&self) {
        let tokens = self.all_tokens();
        if tokens.is_empty() {
            return;
        }
        let _ = self.locked(|ix| {
            for t in &tokens {
                let mut s = t.shared.lock().unwrap();
                match *s {
                    Some(i) => ix.set_count(i, ix.count(i) + 1),
                    None => *s = ix.alloc_count(2),
                }
            }
            Ok(())
        });
    }

    /// The `fork` [`Hub::before_fork`] prepared for failed.
    pub fn fork_failed(&self) {
        let tokens = self.all_tokens();
        let _ = self.locked(|ix| {
            for t in &tokens {
                if let Some(i) = *t.shared.lock().unwrap() {
                    ix.set_count(i, ix.count(i).saturating_sub(1));
                }
            }
            Ok(())
        });
    }

    /// The process exits: its files close (`exit_files`, `exit_mm`).
    pub fn exit(&self) {
        for t in self.all_tokens() {
            t.release();
        }
    }
}

impl Hub {
    /// The entry `path` of inode `obj` was removed, leaving it `nlink`
    /// links: this process's open files by that entry are unlinked, and
    /// when no links are left, the inode goes when the last of its open
    /// files does, or now if there is none.
    pub fn unlinked(&self, obj: Obj, path: &Path, nlink: u64) {
        let open = self.tokens_of(obj.key);
        for t in &open {
            if *t.path.lock().unwrap() == path {
                t.unlinked.store(true, Ordering::Relaxed);
            }
            if nlink == 0 {
                t.gone.store(true, Ordering::Relaxed);
            }
        }
        if nlink == 0 && open.is_empty() {
            self.inode_removed(obj);
        }
    }

    /// Inode `k`'s entry moved from `from` to `to`: this process's open
    /// files by it, and (for a directory) by entries below it, follow
    /// (`d_move`).
    pub fn moved(&self, k: Key, from: &Path, to: &Path) {
        let all: Vec<Arc<Token>> = {
            let mut t = self.tokens.lock().unwrap();
            t.values_mut()
                .flat_map(|l| {
                    l.retain(|w| w.strong_count() > 0);
                    l.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
                })
                .collect()
        };
        for t in all {
            let mut p = t.path.lock().unwrap();
            if t.obj.key == k && *p == from {
                *p = to.to_path_buf();
                *t.parent.lock().unwrap() = None;
            } else if let Ok(rest) = p.strip_prefix(from)
                && !rest.as_os_str().is_empty()
            {
                *p = to.join(rest);
            }
        }
    }
}
