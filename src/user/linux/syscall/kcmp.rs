//! `kcmp` (`kernel/kcmp.c`, Linux 6.19): whether two tasks share a kernel
//! object, and an order between the objects when they do not.
//!
//! Both tasks are found before either is checked (`ESRCH`), then both
//! must be inspectable (`EPERM`, see [`task`]), then the type decides. The
//! objects compared are the ones this process models per task: the
//! address space, descriptor table, and file-system context every thread
//! shares (`CLONE_VM`, `CLONE_FILES`, and `CLONE_FS` being required of
//! threads), the signal handlers, each thread's I/O context and semaphore
//! undo list (absent until made, and equal when both are absent), and open
//! file descriptions. The kernel orders objects by their obfuscated
//! addresses; the order here is likewise arbitrary but consistent.
//!
//! [`task`]: super::task

use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::fs::anon::Anon;
use super::super::fs::fd::{FileObject, OpenFile};
use super::task::{self, Task};
use super::{Ctx, SysResult};

/// `enum kcmp_type` (`linux/kcmp.h`).
pub mod kind {
    pub const FILE: i32 = 0;
    pub const VM: i32 = 1;
    pub const FILES: i32 = 2;
    pub const FS: i32 = 3;
    pub const SIGHAND: i32 = 4;
    pub const IO: i32 = 5;
    pub const SYSVSEM: i32 = 6;
    pub const EPOLL_TFD: i32 = 7;
}

/// `kptr_obfuscate`'s per-type cookies: a value to exclusive-or and an odd
/// multiplier with its top bit set (`kcmp_cookies_init`). Fixed here; the
/// kernel draws them at boot.
fn cookies(ty: i32) -> (u64, u64) {
    // splitmix64 of the type.
    let mix = |mut z: u64| {
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let k = ty as u64;
    (mix(2 * k + 1), mix(2 * k + 2) | (1 << 63) | 1)
}

/// `kcmp_ptr`: 0 for the same object, 1 when the first orders before the
/// second, 2 after.
fn order(a: usize, b: usize, ty: i32) -> u64 {
    let (xor, mul) = cookies(ty);
    let t = |v: usize| ((v as u64 ^ xor).wrapping_mul(mul)) as i64;
    let (t1, t2) = (t(a), t(b));
    u64::from(t1 < t2) | (u64::from(t1 > t2) << 1)
}

/// An object shared by a whole process: its identity, the same for every
/// thread and never 0 (a missing object's).
fn process_object(c: &Ctx<'_>) -> usize {
    c.p.pid as usize
}

/// The identity of a task's object of type `ty` (`VM` through `SYSVSEM`);
/// 0 for none.
fn object(c: &Ctx<'_>, t: Task, ty: i32) -> usize {
    let tid = match t {
        Task::Own(tid) => tid,
        // Only the signal handlers outlive the leader's exit.
        Task::ExitedLeader if ty == kind::SIGHAND => return process_object(c),
        Task::ExitedLeader | Task::Other { .. } => return 0,
    };
    match ty {
        kind::IO | kind::SYSVSEM => {
            let th = c
                .thread_refs()
                .into_iter()
                .find(|th| th.tid == tid)
                .expect("own thread");
            if ty == kind::IO {
                th.sched.io.as_ref().map_or(0, |io| io.id())
            } else {
                th.sysvsem.as_ref().map_or(0, |l| l.id())
            }
        }
        _ => process_object(c),
    }
}

/// `get_file_raw_ptr` (`fget_task`): the open file description behind a
/// task's descriptor `idx`, taken as the `unsigned int` the kernel's is;
/// an `O_PATH` description counts.
fn file_of(c: &Ctx<'_>, t: Task, idx: u64) -> Option<Arc<OpenFile>> {
    match t {
        Task::Own(_) => c.p.fds.file(idx as u32 as i32).ok(),
        Task::ExitedLeader | Task::Other { .. } => None,
    }
}

fn id(file: &Arc<OpenFile>) -> usize {
    Arc::as_ptr(file) as usize
}

/// `kcmp`.
pub fn kcmp(c: &mut Ctx<'_>, pid1: i32, pid2: i32, ty: i32, idx1: u64, idx2: u64) -> SysResult {
    let (t1, t2) = (task::find(c, pid1)?, task::find(c, pid2)?);
    if !task::may_inspect(t1) || !task::may_inspect(t2) {
        return Err(Errno(EPERM));
    }
    match ty {
        kind::FILE => match (file_of(c, t1, idx1), file_of(c, t2, idx2)) {
            (Some(a), Some(b)) => Ok(order(id(&a), id(&b), kind::FILE)),
            _ => Err(Errno(EBADF)),
        },
        kind::VM | kind::FILES | kind::FS | kind::SIGHAND | kind::IO | kind::SYSVSEM => {
            Ok(order(object(c, t1, ty), object(c, t2, ty), ty))
        }
        kind::EPOLL_TFD => epoll_target(c, t1, t2, idx1, idx2),
        _ => Err(Errno(EINVAL)),
    }
}

/// `kcmp_epoll_target`: the first task's descriptor `idx1` against the
/// file of an item of the second task's epoll instance, which the
/// `struct kcmp_epoll_slot` at `uslot` names (`efd`, `tfd`, `toff`). The
/// slot is read first (`EFAULT`), then the descriptors (`EBADF`), then the
/// instance: `EINVAL` if not one, `ENOENT` without such an item.
fn epoll_target(c: &Ctx<'_>, t1: Task, t2: Task, idx1: u64, uslot: u64) -> SysResult {
    let slot = c.read_mem(uslot, 12)?;
    let word = |i: usize| u32::from_le_bytes(slot[4 * i..4 * i + 4].try_into().unwrap());
    let (efd, tfd, toff) = (word(0), word(1) as i32, word(2));
    let file = file_of(c, t1, idx1).ok_or(Errno(EBADF))?;
    let ep = file_of(c, t2, u64::from(efd)).ok_or(Errno(EBADF))?;
    let target = tfile(&ep, tfd, toff)?;
    Ok(order(id(&file), id(&target), kind::FILE))
}

/// `get_epoll_tfile_raw_ptr` and `ep_find_tfd`: the file of the `toff`th
/// item added under descriptor `tfd`, the items ordered as the kernel's
/// tree orders them (by file, then descriptor).
fn tfile(ep: &OpenFile, tfd: i32, toff: u32) -> Result<Arc<OpenFile>, Errno> {
    let FileObject::Anon(Anon::Epoll(ep)) = &ep.object else {
        return Err(Errno(EINVAL));
    };
    let mut files: Vec<Arc<OpenFile>> = ep
        .listing()
        .into_iter()
        .filter(|(fd, ..)| *fd == tfd)
        .map(|(.., f)| f)
        .collect();
    files.sort_by_key(id);
    files.into_iter().nth(toff as usize).ok_or(Errno(ENOENT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_order_is_total_and_antisymmetric() {
        for ty in 0..8 {
            let (_, mul) = cookies(ty);
            assert_eq!(mul & 1, 1, "odd: the product is unique");
            assert_ne!(mul & (1 << 63), 0);
            let ids = [0usize, 1, 0x1000, 0x7fff_0000_1234, usize::MAX];
            for &a in &ids {
                assert_eq!(order(a, a, ty), 0);
                for &b in &ids {
                    if a != b {
                        let (x, y) = (order(a, b, ty), order(b, a, ty));
                        assert!(matches!((x, y), (1, 2) | (2, 1)), "{a:#x} {b:#x}");
                    }
                }
            }
        }
    }
}
