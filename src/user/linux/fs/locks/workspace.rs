//! Advisory locks on regular files in the closed Linux workspace.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use super::{Conflict, F_UNLCK, F_WRLCK, OFFSET_MAX, Owner, Range};
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::{EAGAIN, EDEADLK};
use crate::user::linux::fs::fd::{FileObject, OpenFile};

/// POSIX ownership follows the descriptor table. OFD ownership follows the
/// open file description. Both store their locks in the same process family.
#[derive(Debug, Default)]
pub(crate) struct LockOwner {
    locks: Arc<Mutex<Locks>>,
}

impl LockOwner {
    pub(crate) fn independent(&self) -> Self {
        Self {
            locks: self.locks.clone(),
        }
    }

    fn id(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    pub(crate) fn close(&self, ino: u64) {
        self.locks
            .lock()
            .unwrap()
            .release(LockKey::Record(ino), self.id());
    }

    fn claimant(&self, file: &OpenFile, owner: Owner) -> usize {
        match owner {
            Owner::Process => self.id(),
            Owner::Description => file
                .state
                .lock()
                .unwrap()
                .workspace_lock_owner
                .get_or_insert_with(|| Box::new(self.independent()))
                .id(),
        }
    }

    pub(crate) fn conflict(
        &self,
        file: &OpenFile,
        ino: u64,
        owner: Owner,
        kind: i16,
        range: Range,
    ) -> Option<Conflict> {
        let owner = self.claimant(file, owner);
        self.locks
            .lock()
            .unwrap()
            .conflict(LockKey::Record(ino), owner, kind, range)
            .map(|(_, lock)| lock)
    }

    pub(crate) fn request(
        &self,
        file: &OpenFile,
        ino: u64,
        ownership: Owner,
        lock: Conflict,
    ) -> Request {
        Request {
            key: LockKey::Record(ino),
            owner: self.claimant(file, ownership),
            ownership,
            lock,
        }
    }

    pub(crate) fn flock(&self, file: &OpenFile, ino: u64, kind: i16) -> Request {
        Request {
            key: LockKey::Flock(ino),
            owner: self.claimant(file, Owner::Description),
            ownership: Owner::Description,
            lock: Conflict {
                kind,
                range: Range {
                    start: 0,
                    end: OFFSET_MAX,
                },
                pid: -1,
            },
        }
    }

    pub(crate) fn set(
        self: &Arc<Self>,
        file: &Arc<OpenFile>,
        request: Request,
        sleep: bool,
    ) -> Result<Option<Waiting>, Errno> {
        let mut locks = self.locks.lock().unwrap();
        let lock = request.lock;
        if matches!(request.key, LockKey::Flock(_)) {
            if locks.held_kind(request.key, request.owner) == Some(lock.kind) {
                return Ok(None);
            }
            // Linux drops an existing flock before trying a different mode,
            // including a nonblocking conversion that will fail.
            locks.release(request.key, request.owner);
        }
        if lock.kind != F_UNLCK
            && let Some((blocker, _)) =
                locks.conflict(request.key, request.owner, lock.kind, lock.range)
        {
            if !sleep {
                return Err(Errno(EAGAIN));
            }
            if request.ownership == Owner::Process && locks.deadlock(request.owner, blocker) {
                return Err(Errno(EDEADLK));
            }
            let changed = Arc::new(AtomicBool::new(false));
            let id = Arc::as_ptr(&changed) as usize;
            locks
                .waiting
                .insert(id, (request, Arc::downgrade(&changed)));
            return Ok(Some(Waiting {
                request,
                file: file.clone(),
                table: self.clone(),
                event: Arc::new(Event {
                    changed,
                    locks: Arc::downgrade(&self.locks),
                }),
            }));
        }
        locks.set(request);
        Ok(None)
    }
}

impl Drop for LockOwner {
    fn drop(&mut self) {
        let mut locks = self.locks.lock().unwrap();
        let mut released = Vec::new();
        locks.files.retain(|&key, holders| {
            if remove_owner(holders, self.id()) {
                released.push(key);
            }
            !holders.is_empty()
        });
        for key in released {
            locks.wake(key);
        }
    }
}

/// Inodes are stable across hard links and retained descriptors.
pub(crate) fn inode(file: &OpenFile) -> Option<u64> {
    let FileObject::Supplied(entry) = &file.object else {
        return None;
    };
    entry.workspace_file()?;
    Some(entry.ino)
}

/// Linux applies flock and fcntl locks independently, even on one inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LockKey {
    Record(u64),
    Flock(u64),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Request {
    key: LockKey,
    owner: usize,
    ownership: Owner,
    lock: Conflict,
}

impl Request {
    pub(crate) fn posix_acquisition(self) -> Option<u64> {
        if self.ownership == Owner::Process
            && self.lock.kind != F_UNLCK
            && let LockKey::Record(ino) = self.key
        {
            Some(ino)
        } else {
            None
        }
    }
}

/// The copied request and file reference survive until the lock call resumes.
#[derive(Clone, Debug)]
pub struct Waiting {
    pub(crate) request: Request,
    pub(crate) file: Arc<OpenFile>,
    pub(crate) table: Arc<LockOwner>,
    event: Arc<Event>,
}

impl Waiting {
    pub(crate) fn changed(&self) -> bool {
        self.event.changed.load(Ordering::Acquire)
    }
}

impl PartialEq for Waiting {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.event, &other.event)
    }
}

impl Eq for Waiting {}

#[derive(Debug)]
struct Event {
    changed: Arc<AtomicBool>,
    locks: Weak<Mutex<Locks>>,
}

impl Drop for Event {
    fn drop(&mut self) {
        if let Some(locks) = self.locks.upgrade() {
            locks
                .lock()
                .unwrap()
                .waiting
                .remove(&(Arc::as_ptr(&self.changed) as usize));
        }
    }
}

#[derive(Debug, Default)]
struct Locks {
    files: BTreeMap<LockKey, Vec<Holder>>,
    waiting: BTreeMap<usize, (Request, Weak<AtomicBool>)>,
}

impl Locks {
    fn conflict(
        &self,
        key: LockKey,
        owner: usize,
        kind: i16,
        range: Range,
    ) -> Option<(usize, Conflict)> {
        self.files
            .get(&key)?
            .iter()
            .filter(|holder| holder.owner != owner)
            .find_map(|holder| {
                holder.ranges.iter().find_map(|lock| {
                    ((kind == F_WRLCK || lock.kind == F_WRLCK)
                        && lock.range.start <= range.end
                        && range.start <= lock.range.end)
                        .then_some((holder.owner, *lock))
                })
            })
    }

    fn held_kind(&self, key: LockKey, owner: usize) -> Option<i16> {
        self.files
            .get(&key)?
            .iter()
            .find(|holder| holder.owner == owner)
            .and_then(|holder| holder.ranges.first())
            .map(|lock| lock.kind)
    }

    fn set(&mut self, request: Request) {
        let Request {
            key, owner, lock, ..
        } = request;
        if lock.kind == F_UNLCK && !self.files.contains_key(&key) {
            return;
        }
        let holders = self.files.entry(key).or_default();
        if let Some(index) = holders.iter().position(|holder| holder.owner == owner) {
            holders[index].replace(lock);
            if holders[index].ranges.is_empty() {
                holders.remove(index);
            }
        } else if lock.kind != F_UNLCK {
            holders.push(Holder {
                owner,
                ranges: vec![lock],
            });
        }
        if holders.is_empty() {
            self.files.remove(&key);
        }
        self.wake(key);
    }

    fn release(&mut self, key: LockKey, owner: usize) {
        if let Some(holders) = self.files.get_mut(&key) {
            let released = remove_owner(holders, owner);
            if holders.is_empty() {
                self.files.remove(&key);
            }
            if released {
                self.wake(key);
            }
        }
    }

    fn wake(&self, key: LockKey) {
        for (request, flag) in self.waiting.values() {
            if request.key == key
                && let Some(flag) = flag.upgrade()
            {
                flag.store(true, Ordering::Release);
            }
        }
    }

    fn deadlock(&self, owner: usize, mut blocker: usize) -> bool {
        // Linux limits how far its POSIX deadlock search follows blocked
        // owners and does not include OFD waiters in the POSIX wait graph.
        for _ in 0..=10 {
            let next = self
                .waiting
                .values()
                .filter(|(request, _)| {
                    request.owner == blocker && request.ownership == Owner::Process
                })
                .find_map(|(request, _)| {
                    self.conflict(request.key, blocker, request.lock.kind, request.lock.range)
                });
            let Some((next, _)) = next else { return false };
            if next == owner {
                return true;
            }
            blocker = next;
        }
        false
    }
}

fn remove_owner(holders: &mut Vec<Holder>, owner: usize) -> bool {
    let before = holders.len();
    holders.retain(|holder| holder.owner != owner);
    holders.len() != before
}

#[derive(Debug)]
struct Holder {
    owner: usize,
    ranges: Vec<Conflict>,
}

impl Holder {
    fn replace(&mut self, mut lock: Conflict) {
        let mut merged = false;
        let mut kept = Vec::with_capacity(self.ranges.len() + 2);
        for old in self.ranges.drain(..) {
            let range = lock.range;
            if old.kind == lock.kind
                && old.range.end >= range.start - 1
                && old.range.start - 1 <= range.end
            {
                lock.range.start = range.start.min(old.range.start);
                lock.range.end = range.end.max(old.range.end);
                if !merged {
                    lock.pid = old.pid;
                    merged = true;
                }
                continue;
            }
            if old.range.end < range.start || old.range.start > range.end {
                kept.push(old);
                continue;
            }
            if old.range.start < range.start {
                kept.push(Conflict {
                    range: Range {
                        end: range.start - 1,
                        ..old.range
                    },
                    ..old
                });
            }
            if old.range.end > range.end {
                kept.push(Conflict {
                    range: Range {
                        start: range.end + 1,
                        ..old.range
                    },
                    ..old
                });
            }
        }
        if lock.kind != F_UNLCK {
            let index = kept.partition_point(|old| old.range.start < lock.range.start);
            kept.insert(index, lock);
        }
        self.ranges = kept;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::linux::fs::locks::F_RDLCK;

    fn claim(owner: usize, pid: i32, kind: i16, start: i64, end: i64) -> Request {
        Request {
            key: LockKey::Record(1),
            owner,
            ownership: Owner::Process,
            lock: Conflict {
                kind,
                range: Range { start, end },
                pid,
            },
        }
    }

    #[test]
    fn splits_ranges_and_keeps_the_pid_of_the_first_merged_lock() {
        let mut locks = Locks::default();
        let key = LockKey::Record(1);
        locks.set(claim(1, 100, F_WRLCK, 0, OFFSET_MAX));
        locks.set(claim(1, 101, F_UNLCK, 8, 15));
        let query = |start| Range { start, end: start };
        assert!(locks.conflict(key, 2, F_RDLCK, query(8)).is_none());
        let left = locks.conflict(key, 2, F_RDLCK, query(7)).unwrap().1;
        let right = locks.conflict(key, 2, F_RDLCK, query(16)).unwrap().1;
        assert_eq!(left.range, Range { start: 0, end: 7 });
        assert_eq!(
            right.range,
            Range {
                start: 16,
                end: OFFSET_MAX
            }
        );
        assert_eq!((left.pid, right.pid), (100, 100));
        locks.set(claim(1, 101, F_WRLCK, 8, 16));
        let joined = locks.conflict(key, 2, F_RDLCK, query(8)).unwrap().1;
        assert_eq!(
            joined.range,
            Range {
                start: 0,
                end: OFFSET_MAX
            }
        );
        assert_eq!(joined.pid, 100);
        assert!(locks.conflict(key, 1, F_WRLCK, query(8)).is_none());
    }

    #[test]
    fn follows_three_posix_owners_and_wakes_only_after_change() {
        let mut locks = Locks::default();
        for owner in 1..=3 {
            let offset = i64::try_from(owner * 8).unwrap();
            locks.set(claim(owner, 100, F_WRLCK, offset, offset + 7));
        }
        let a = Arc::new(AtomicBool::new(false));
        let b = Arc::new(AtomicBool::new(false));
        locks
            .waiting
            .insert(1, (claim(1, 100, F_WRLCK, 16, 23), Arc::downgrade(&a)));
        locks
            .waiting
            .insert(2, (claim(2, 101, F_WRLCK, 24, 31), Arc::downgrade(&b)));
        assert!(locks.deadlock(3, 1));
        assert!(!a.load(Ordering::Acquire) && !b.load(Ordering::Acquire));
        locks.release(LockKey::Record(1), 2);
        assert!(!locks.deadlock(3, 1));
        assert!(a.load(Ordering::Acquire) && b.load(Ordering::Acquire));
    }
}
