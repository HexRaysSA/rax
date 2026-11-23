//! POSIX byte-range locks on closed Darwin workspace data files.

use std::collections::{BTreeMap, BTreeSet};

use super::abi::Errno;
use super::arch::{Rv, SysResult};
use super::fd::{FileKind, FileRef, OpenFile};
use super::io::{O_RDONLY, O_WRONLY};
use super::syscall::{self, Ctx, bsd::file::lifetime};
use super::wait::{Wait, WaitKey};

const READ: i16 = 1;
const UNLOCK: i16 = 2;
const WRITE: i16 = 3;
const SEEK_SET: i16 = 0;
const SEEK_CUR: i16 = 1;
const SEEK_END: i16 = 2;

#[derive(Clone, Copy, Debug)]
struct Range {
    start: i64,
    // An inclusive endpoint. None retains the through-EOF form of l_len.
    end: Option<i64>,
}

impl Range {
    fn new(start: i64, len: i64) -> Result<Self, Errno> {
        if start < 0 {
            return Err(Errno::EINVAL);
        }
        let (start, end) = match len.cmp(&0) {
            std::cmp::Ordering::Less => (start + len, Some(start - 1)),
            std::cmp::Ordering::Equal => (start, None),
            std::cmp::Ordering::Greater => (
                start,
                Some(start.checked_add(len - 1).ok_or(Errno::EOVERFLOW)?),
            ),
        };
        if start < 0 {
            return Err(Errno::EINVAL);
        }
        Ok(Self { start, end })
    }

    fn last(self) -> i64 {
        self.end.unwrap_or(i64::MAX)
    }

    fn overlaps(self, other: Self) -> bool {
        self.start <= other.last() && other.start <= self.last()
    }

    fn len(self) -> i64 {
        self.end
            .and_then(|end| (end - self.start).checked_add(1))
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug)]
struct Lock {
    range: Range,
    kind: i16,
}

/// The inode and absolute range copied at entry to F_SETLKW.
#[derive(Clone, Copy, Debug)]
pub(super) struct Request {
    ino: u64,
    lock: Lock,
}

struct OwnerLocks {
    pid: i32,
    // Disjoint, increasing ranges. Adjacent ranges of one kind are coalesced.
    locks: Vec<Lock>,
}

impl OwnerLocks {
    fn replace(&mut self, mut lock: Lock) {
        if lock.kind != UNLOCK
            && let Some(existing) = self.locks.iter().find(|old| {
                old.range.last() == lock.range.last()
                    && old.range.start <= lock.range.start
                    && (old.kind == lock.kind || old.range.start == lock.range.start)
            })
        {
            lock.range.end = existing.range.end;
        }
        let range = lock.range;
        let mut kept = Vec::with_capacity(self.locks.len() + 2);
        for mut old in self.locks.drain(..) {
            if !old.range.overlaps(range) {
                kept.push(old);
                continue;
            }
            if old.range.start < range.start {
                kept.push(Lock {
                    range: Range {
                        start: old.range.start,
                        end: Some(range.start - 1),
                    },
                    kind: old.kind,
                });
            }
            if old.range.last() > range.last() {
                old.range.start = range.last() + 1;
                kept.push(old);
            }
        }
        if lock.kind != UNLOCK {
            let mut index = kept.partition_point(|old| old.range.start < range.start);
            if index > 0
                && kept[index - 1].kind == lock.kind
                && kept[index - 1].range.last().checked_add(1) == Some(lock.range.start)
            {
                index -= 1;
                lock.range.start = kept.remove(index).range.start;
            }
            if index < kept.len()
                && kept[index].kind == lock.kind
                && lock.range.last().checked_add(1) == Some(kept[index].range.start)
            {
                lock.range.end = kept.remove(index).range.end;
            }
            kept.insert(index, lock);
        }
        self.locks = kept;
    }
}

#[derive(Default)]
pub(super) struct Locks {
    files: BTreeMap<u64, Vec<OwnerLocks>>,
    waiting: BTreeMap<(i32, u64), Request>,
    changed: BTreeSet<u64>,
}

impl Locks {
    fn conflict(&self, ino: u64, pid: i32, request: Lock) -> Option<(i32, Lock)> {
        self.files
            .get(&ino)?
            .iter()
            .filter(|owner| owner.pid != pid)
            .find_map(|owner| {
                owner
                    .locks
                    .iter()
                    .find(|lock| {
                        (request.kind == WRITE || lock.kind == WRITE)
                            && lock.range.overlaps(request.range)
                    })
                    .map(|&lock| (owner.pid, lock))
            })
    }

    fn has_locks(&self, ino: u64) -> bool {
        self.files.contains_key(&ino)
    }

    fn set(&mut self, ino: u64, pid: i32, lock: Lock) -> Result<(), Errno> {
        if lock.kind != UNLOCK && self.conflict(ino, pid, lock).is_some() {
            return Err(Errno::EAGAIN);
        }
        if lock.kind == UNLOCK && !self.has_locks(ino) {
            return Ok(());
        }
        let owners = self.files.entry(ino).or_default();
        let index = owners.iter().position(|owner| owner.pid == pid);
        if let Some(index) = index {
            owners[index].replace(lock);
            if owners[index].locks.is_empty() {
                owners.remove(index);
            }
        } else if lock.kind != UNLOCK {
            owners.push(OwnerLocks {
                pid,
                locks: vec![lock],
            });
        }
        if owners.is_empty() {
            self.files.remove(&ino);
        }
        self.changed.insert(ino);
        Ok(())
    }

    fn set_waiting(&mut self, owner: (i32, u64), request: Request) -> Result<bool, Errno> {
        self.waiting.remove(&owner);
        let (pid, _) = owner;
        if request.lock.kind != UNLOCK
            && let Some((blocker, _)) = self.conflict(request.ino, pid, request.lock)
        {
            if self.depends_on(blocker, pid) {
                return Err(Errno::EDEADLK);
            }
            self.waiting.insert(owner, request);
            return Ok(false);
        }
        self.set(request.ino, pid, request.lock)?;
        Ok(true)
    }

    fn depends_on(&self, blocker: i32, requester: i32) -> bool {
        // Darwin detects two owners waiting on each other, even on distinct
        // inodes. An unlock can sever that edge before the next scheduler turn.
        self.waiting
            .range((blocker, 0)..=(blocker, u64::MAX))
            .any(|(_, request)| {
                self.conflict(request.ino, blocker, request.lock)
                    .is_some_and(|(owner, _)| owner == requester)
            })
    }

    pub(super) fn cancel(&mut self, pid: i32, tid: u64) {
        self.waiting.remove(&(pid, tid));
    }

    pub(super) fn take_wakes(&mut self) -> BTreeSet<(i32, u64)> {
        let changed = std::mem::take(&mut self.changed);
        if changed.is_empty() {
            return BTreeSet::new();
        }
        self.waiting
            .iter()
            .filter(|(_, request)| changed.contains(&request.ino))
            .map(|(&(pid, _), request)| (pid, request.ino))
            .collect()
    }

    pub(super) fn close(&mut self, ino: u64, pid: i32) {
        if let Some(owners) = self.files.get_mut(&ino) {
            let previous = owners.len();
            owners.retain(|owner| owner.pid != pid);
            if owners.len() != previous {
                self.changed.insert(ino);
            }
            if owners.is_empty() {
                self.files.remove(&ino);
            }
        }
    }

    pub(super) fn exit(&mut self, pid: i32) {
        self.retain_after_exec(pid, |_| false);
    }

    pub(super) fn retain_after_exec(&mut self, pid: i32, transferred: impl Fn(u64) -> bool) {
        self.waiting.retain(|&(owner, _), _| owner != pid);
        self.files.retain(|&ino, owners| {
            if !transferred(ino) {
                let previous = owners.len();
                owners.retain(|owner| owner.pid != pid);
                if owners.len() != previous {
                    self.changed.insert(ino);
                }
            }
            !owners.is_empty()
        });
    }
}

/// The inode of a private regular data file, common to hard-link aliases.
pub(super) fn inode(file: &OpenFile) -> Option<u64> {
    let FileKind::Embedded(object) = &file.kind else {
        return None;
    };
    object.workspace()?;
    Some(object.entry()?.ino)
}

pub(super) fn fcntl(
    ctx: &mut Ctx<'_>,
    fd: i32,
    command: i32,
    file: &FileRef,
    argument: u64,
) -> SysResult {
    use syscall::bsd::file::cmd::{F_GETLK, F_SETLKW};

    let FileKind::Embedded(object) = &file.kind else {
        return Err(Errno::EBADF);
    };
    let get = command == F_GETLK;
    let (_, access) = object.workspace().ok_or(Errno::EBADF)?;
    let entry = object.entry().expect("workspace file entry");
    let member = ctx.proc.family.as_ref().ok_or(Errno::EBADF)?;
    let mut bytes = ctx.read(argument, 24)?;
    let mut start = i64::from_le_bytes(bytes[..8].try_into().expect("lock start"));
    let len = i64::from_le_bytes(bytes[8..16].try_into().expect("lock length"));
    let kind = i16::from_le_bytes(bytes[20..22].try_into().expect("lock type"));
    let whence = i16::from_le_bytes(bytes[22..24].try_into().expect("lock origin"));
    let early_range = match whence {
        SEEK_SET => Some(Range::new(start, len)?),
        SEEK_CUR => {
            let cursor = object.seek(0, i32::from(SEEK_CUR))? as i64;
            start = start.checked_add(cursor).ok_or(Errno::EOVERFLOW)?;
            bytes[..8].copy_from_slice(&start.to_le_bytes());
            Some(Range::new(start, len)?)
        }
        _ => None,
    };
    if !matches!(kind, READ | UNLOCK | WRITE) {
        return Err(Errno::EINVAL);
    }
    if !get && ((kind == READ && access == O_WRONLY) || (kind == WRITE && access == O_RDONLY)) {
        return Err(Errno::EBADF);
    }
    // The vnode can complete an unlock without resolving the range once the
    // caller's SEEK_SET/SEEK_CUR checks have passed and no locks exist.
    if !get && kind == UNLOCK && member.workspace_locks(|locks| !locks.has_locks(entry.ino)) {
        return Ok(Rv::one(0));
    }
    if whence == SEEK_END {
        // Darwin can answer an empty-inode query before resolving SEEK_END.
        if get && member.workspace_locks(|locks| !locks.has_locks(entry.ino)) {
            bytes[20..22].copy_from_slice(&UNLOCK.to_le_bytes());
            ctx.write(argument, &bytes)?;
            return Ok(Rv::one(0));
        }
        start = start
            .checked_add(entry.len() as i64)
            .ok_or(Errno::EOVERFLOW)?;
    }
    let range = match (early_range, whence) {
        (Some(range), _) => range,
        (None, SEEK_END) => Range::new(start, len)?,
        _ => return Err(Errno::EINVAL),
    };
    let requested = Lock { range, kind };
    let pid = ctx.proc.pid;
    if get {
        let conflict = member.workspace_locks(|locks| locks.conflict(entry.ino, pid, requested));
        let kind = if let Some((owner, lock)) = conflict {
            bytes[..8].copy_from_slice(&lock.range.start.to_le_bytes());
            bytes[8..16].copy_from_slice(&lock.range.len().to_le_bytes());
            bytes[16..20].copy_from_slice(&owner.to_le_bytes());
            bytes[22..24].copy_from_slice(&SEEK_SET.to_le_bytes());
            lock.kind
        } else {
            UNLOCK
        };
        bytes[20..22].copy_from_slice(&kind.to_le_bytes());
        ctx.write(argument, &bytes)?;
    } else if command == F_SETLKW {
        return wait(
            ctx,
            fd,
            file,
            Request {
                ino: entry.ino,
                lock: requested,
            },
        );
    } else {
        member.workspace_locks(|locks| locks.set(entry.ino, pid, requested))?;
    }
    Ok(Rv::one(0))
}

pub(super) fn resume(ctx: &mut Ctx<'_>, fd: i32, file: &FileRef, request: Request) -> SysResult {
    ctx.thread.wait = None;
    ctx.thread.woken = false;
    if let Some(error) = super::signal::sleep_interruption(ctx.proc, ctx.thread) {
        cancel_wait(ctx.proc, ctx.thread.tid);
        return Err(error);
    }
    wait(ctx, fd, file, request)
}

fn wait(ctx: &mut Ctx<'_>, fd: i32, file: &FileRef, request: Request) -> SysResult {
    let owner = (ctx.proc.pid, ctx.thread.tid);
    let member = ctx.proc.family.as_ref().ok_or(Errno::EBADF)?;
    if member.workspace_locks(|locks| locks.set_waiting(owner, request))? {
        return Ok(Rv::one(0));
    }
    let result = syscall::sleep(ctx, Wait::key(WaitKey::WorkspaceLock(request.ino), None));
    if ctx.thread.wait.is_some() {
        lifetime::parked_workspace_lock(ctx, fd, file, request);
    } else {
        cancel_wait(ctx.proc, ctx.thread.tid);
    }
    result
}

pub(super) fn cancel_wait(proc: &super::process::Proc, tid: u64) {
    if let Some(member) = &proc.family {
        member.workspace_locks(|locks| locks.cancel(proc.pid, tid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(kind: i16, start: i64, len: i64) -> Lock {
        Lock {
            kind,
            range: Range::new(start, len).unwrap(),
        }
    }

    #[test]
    fn converts_ranges_at_the_signed_offset_boundary() {
        assert_eq!(Range::new(i64::MAX, 1).unwrap().len(), 1);
        assert_eq!(Range::new(i64::MAX, 0).unwrap().len(), 0);
        assert_eq!(Range::new(i64::MAX, 2).unwrap_err(), Errno::EOVERFLOW);
        assert_eq!(Range::new(0, -1).unwrap_err(), Errno::EINVAL);
        let reverse = Range::new(14, -4).unwrap();
        assert_eq!((reverse.start, reverse.last()), (10, 13));
        let mut locks = Locks::default();
        locks.set(1, 100, lock(WRITE, i64::MAX - 2, 0)).unwrap();
        locks.set(1, 100, lock(WRITE, i64::MAX - 1, 2)).unwrap();
        let (_, kept) = locks.conflict(1, 101, lock(READ, i64::MAX, 1)).unwrap();
        assert_eq!((kept.range.start, kept.range.len()), (i64::MAX - 2, 0));
    }

    #[test]
    fn splits_replaces_and_rejoins_a_processs_ranges() {
        let mut locks = Locks::default();
        locks.set(1, 100, lock(WRITE, 0, 0)).unwrap();
        locks.set(1, 100, lock(UNLOCK, 10, 10)).unwrap();
        let (_, left) = locks.conflict(1, 101, lock(READ, 0, 0)).unwrap();
        assert_eq!((left.range.start, left.range.len()), (0, 10));
        let (_, right) = locks.conflict(1, 101, lock(READ, 20, 0)).unwrap();
        assert_eq!((right.range.start, right.range.len()), (20, 0));
        locks.set(1, 100, lock(READ, 10, 10)).unwrap();
        locks.set(1, 101, lock(READ, 10, 10)).unwrap();
        assert_eq!(locks.set(1, 100, lock(WRITE, 10, 10)), Err(Errno::EAGAIN));
        locks.exit(101);
        locks.set(1, 100, lock(WRITE, 10, 10)).unwrap();
        let (_, joined) = locks.conflict(1, 101, lock(READ, 10, 10)).unwrap();
        assert_eq!((joined.range.start, joined.range.len()), (0, 0));
        locks.set(2, 100, lock(WRITE, 0, 0)).unwrap();
        locks.close(1, 100);
        assert!(locks.conflict(1, 101, lock(READ, 0, 0)).is_none());
        assert!(locks.conflict(2, 101, lock(READ, 0, 0)).is_some());
    }

    #[test]
    fn detects_two_owner_cycles_and_wakes_on_release() {
        let mut locks = Locks::default();
        let a = (100, 1);
        let b = (101, 1);
        let c = (102, 1);
        for (ino, (pid, _)) in [(1, a), (2, b), (3, c)] {
            locks.set(ino, pid, lock(WRITE, 0, 8)).unwrap();
        }
        assert!(locks.take_wakes().is_empty());
        let request = |ino| Request {
            ino,
            lock: lock(WRITE, 0, 8),
        };
        assert_eq!(locks.set_waiting(a, request(2)), Ok(false));
        assert_eq!(locks.set_waiting(b, request(1)), Err(Errno::EDEADLK));
        assert_eq!(locks.set_waiting(b, request(3)), Ok(false));
        assert_eq!(locks.set_waiting(c, request(1)), Ok(false));

        locks.close(2, b.0);
        assert_eq!(locks.take_wakes(), BTreeSet::from([(a.0, 2)]));
        // A has yet to wake; its old edge to B is already severed.
        assert_eq!(locks.set_waiting(b, request(1)), Ok(false));
        locks.cancel(b.0, b.1);
        assert_eq!(locks.set_waiting(b, request(3)), Ok(false));
        assert_eq!(locks.set_waiting(a, request(2)), Ok(true));
        assert!(locks.take_wakes().is_empty());

        locks.cancel(c.0, c.1);
        locks.exit(c.0);
        assert_eq!(locks.take_wakes(), BTreeSet::from([(b.0, 3)]));
        assert_eq!(locks.set_waiting(b, request(3)), Ok(true));
        assert!(locks.take_wakes().is_empty());
    }
}
