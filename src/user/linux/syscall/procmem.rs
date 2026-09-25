//! A process's memory through another task's ID (`mm/process_vm_access.c`,
//! `mm/madvise.c`, Linux 6.19): `process_vm_readv`, `process_vm_writev`,
//! and `process_madvise`.
//!
//! The memory reachable is the calling process's own, named by any of its
//! threads or by a pidfd for it; another process's is refused as a denied
//! `mm_access` is ([`task`]). The remote side is reached as
//! `get_user_pages` reaches it: page by page, a read needing `VM_READ` and
//! a write `VM_WRITE` (no `FOLL_FORCE`), the pages it can reach from the
//! start of a range being transferred before the first it cannot. The
//! local side is an ordinary user copy that stops at its first fault.
//!
//! [`task`]: super::task

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::iov::{import_iovec, iovec_from_user};
use super::mem::vm_read;
use super::task::{self, Task};
use super::{Ctx, SysResult};
use crate::error::MemoryAccessKind;
use crate::user::mm::Perms;

/// `PAGE_SIZE`.
const P: u64 = 4096;
/// `PVM_MAX_USER_PAGES`: the pages pinned at a time.
const PIN_BATCH: u64 = 2 * P / 8;

/// `process_vm_readv`.
pub fn process_vm_readv(
    c: &mut Ctx<'_>,
    pid: i32,
    lvec: u64,
    liovcnt: u64,
    rvec: u64,
    riovcnt: u64,
    flags: u64,
) -> SysResult {
    process_vm_rw(c, pid, lvec, liovcnt, rvec, riovcnt, flags, false)
}

/// `process_vm_writev`.
pub fn process_vm_writev(
    c: &mut Ctx<'_>,
    pid: i32,
    lvec: u64,
    liovcnt: u64,
    rvec: u64,
    riovcnt: u64,
    flags: u64,
) -> SysResult {
    process_vm_rw(c, pid, lvec, liovcnt, rvec, riovcnt, flags, true)
}

/// The pages `[addr, addr + len)` touches, in the kernel's unsigned
/// arithmetic.
fn pages_spanned(addr: u64, len: u64) -> u64 {
    (addr.wrapping_add(len).wrapping_sub(1) / P)
        .wrapping_sub(addr / P)
        .wrapping_add(1)
}

/// `process_vm_rw` and `process_vm_rw_core`, in their order: the flags,
/// the local vectors (an empty transfer ends there), the remote vectors
/// (none with a length ends there), the task (`ESRCH`), and the right to
/// its memory (`EPERM`, `mm_access`'s `EACCES` mapped). The result is the
/// bytes transferred, or the error when there were none.
#[allow(clippy::too_many_arguments)]
fn process_vm_rw(
    c: &mut Ctx<'_>,
    pid: i32,
    lvec: u64,
    liovcnt: u64,
    rvec: u64,
    riovcnt: u64,
    flags: u64,
    write: bool,
) -> SysResult {
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    let local = import_iovec(c, lvec, liovcnt)?;
    let total: u64 = local.iter().map(|&(_, l)| l).sum();
    if total == 0 {
        return Ok(0);
    }
    let remote = iovec_from_user(c, rvec, riovcnt)?;
    let nr_pages = remote
        .iter()
        .filter(|&&(_, l)| l > 0)
        .map(|&(b, l)| pages_spanned(b, l))
        .max()
        .unwrap_or(0);
    if nr_pages == 0 {
        return Ok(0);
    }
    let target = task::find(c, pid)?;
    task::mm_access(target).map_err(|e| if e == Errno(EACCES) { Errno(EPERM) } else { e })?;
    let mut local = Local::new(&local);
    let mut rc = Ok(());
    for &(addr, len) in &remote {
        if local.left == 0 {
            break;
        }
        rc = single_vec(c, addr, len, &mut local, write);
        if rc.is_err() {
            break;
        }
    }
    let done = total - local.left;
    match rc {
        Err(e) if done == 0 => Err(e),
        _ => Ok(done),
    }
}

/// `process_vm_rw_single_vec`: one remote vector, pinned up to
/// [`PIN_BATCH`] pages at a time; `EFAULT` when no page can be reached
/// where a batch starts, or at a local fault.
fn single_vec(
    c: &Ctx<'_>,
    addr: u64,
    mut len: u64,
    local: &mut Local<'_>,
    write: bool,
) -> Result<(), Errno> {
    if len == 0 {
        return Ok(());
    }
    let mut nr_pages = pages_spanned(addr, len);
    let mut page = addr & !(P - 1);
    let mut offset = addr - page;
    while nr_pages > 0 && local.left > 0 {
        let pinned = pin(c, page, nr_pages.min(PIN_BATCH), write);
        if pinned == 0 {
            return Err(Errno(EFAULT));
        }
        let bytes = (pinned * P - offset).min(len);
        copy_pages(c, page + offset, bytes, local, write)?;
        len -= bytes;
        offset = 0;
        nr_pages -= pinned;
        page = page.wrapping_add(pinned * P);
    }
    Ok(())
}

/// `pin_user_pages_remote` without `FOLL_FORCE`: how many of the `n` pages
/// from `page` on can be reached, each in a VMA allowing the access
/// (`check_vma_flags`) and faulted in as the access would.
fn pin(c: &Ctx<'_>, page: u64, n: u64, write: bool) -> u64 {
    let access = if write {
        MemoryAccessKind::Write
    } else {
        MemoryAccessKind::Read
    };
    for i in 0..n {
        let Some(at) = page.checked_add(i * P) else {
            return i;
        };
        let allowed = c.p.space.vma_at(at).is_some_and(|v| {
            if write {
                v.perms.contains(Perms::WRITE)
            } else {
                vm_read(&v)
            }
        });
        if !allowed || c.p.space.probe(at, 1, access).is_err() {
            return i;
        }
    }
    n
}

/// `process_vm_rw_pages`: `bytes` of pinned memory at `remote` to or from
/// the local vectors, until either runs out; `EFAULT` at a local fault
/// with the local side left short.
fn copy_pages(
    c: &Ctx<'_>,
    mut remote: u64,
    mut bytes: u64,
    local: &mut Local<'_>,
    write: bool,
) -> Result<(), Errno> {
    while bytes > 0 {
        let Some((at, n)) = local.piece(bytes.min(P - remote % P)) else {
            return Ok(());
        };
        let fault = Err(Errno(EFAULT));
        if write {
            let Ok(data) = c.read_mem(at, n as usize) else {
                return fault;
            };
            if c.p.space.write(remote, &data).is_err() {
                return fault;
            }
        } else {
            let mut data = vec![0u8; n as usize];
            if c.p.space.read(remote, &mut data).is_err() || c.write_mem(at, &data).is_err() {
                return fault;
            }
        }
        local.advance(n);
        remote += n;
        bytes -= n;
    }
    Ok(())
}

/// The local vectors of a transfer, consumed in order (`iov_iter`).
struct Local<'a> {
    vecs: &'a [(u64, u64)],
    seg: usize,
    off: u64,
    /// Bytes not yet transferred (`iov_iter_count`).
    left: u64,
}

impl<'a> Local<'a> {
    fn new(vecs: &'a [(u64, u64)]) -> Self {
        Local {
            vecs,
            seg: 0,
            off: 0,
            left: vecs.iter().map(|&(_, l)| l).sum(),
        }
    }

    /// The next local range of at most `max` bytes that stays within one
    /// page, so a fault is exact to the page.
    fn piece(&mut self, max: u64) -> Option<(u64, u64)> {
        while self.left > 0 {
            let (base, len) = self.vecs[self.seg];
            if self.off == len {
                self.seg += 1;
                self.off = 0;
                continue;
            }
            let at = base + self.off;
            return Some((at, max.min(len - self.off).min(P - at % P)));
        }
        None
    }

    fn advance(&mut self, n: u64) {
        self.off += n;
        self.left -= n;
    }
}

/// `process_madvise`, in its order: the flags, the vectors, the pidfd's
/// task, and the right to its memory (`mm_access`: `ESRCH`, `EACCES`).
/// The caller's own memory takes any advice (`vector_madvise`).
pub fn process_madvise(
    c: &mut Ctx<'_>,
    pidfd: i32,
    vec: u64,
    vlen: u64,
    behavior: i32,
    flags: u32,
) -> SysResult {
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    let iov = import_iovec(c, vec, vlen)?;
    let target = task::from_pidfd(c, pidfd)?;
    task::mm_access(target)?;
    debug_assert!(matches!(target, Task::Own(_)));
    vector_madvise(c, &iov, behavior)
}

/// `vector_madvise`: the advice for each vector in turn, as `madvise`
/// gives it (a zero length is nothing, but its address must still be page
/// aligned), stopping at the first error. The iterator starts at the first
/// vector even when it is empty, and passing a vector passes the empty
/// ones after it. The result is the bytes advised, or the error when there
/// were none.
fn vector_madvise(c: &mut Ctx<'_>, iov: &[(u64, u64)], behavior: i32) -> SysResult {
    let total: u64 = iov.iter().map(|&(_, l)| l).sum();
    let mut done = 0u64;
    let mut ret = Ok(0);
    let mut i = 0;
    while done < total {
        let (start, len) = iov[i];
        if let Err(e) = super::mem::madvise(c, start, len, behavior as u32) {
            ret = Err(e);
            break;
        }
        done += len;
        i += 1;
        while i < iov.len() && iov[i].1 == 0 {
            i += 1;
        }
    }
    if done > 0 { Ok(done) } else { ret }
}
