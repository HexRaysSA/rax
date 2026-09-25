//! System V IPC system calls: `shmget`, `shmat`, `shmdt`, and `shmctl`
//! (`ipc/shm.c`); `semget`, `semop`, `semtimedop`, and `semctl`
//! (`ipc/sem.c`); `msgget`, `msgsnd`, `msgrcv`, and `msgctl` (`ipc/msg.c`);
//! over the namespace's objects ([`ipc`](super::super::ipc)).
//!
//! `shmat` maps a segment's host file shared, named as Linux names it
//! (`/SYSV<key> (deleted)`); after every call that changes the process's
//! mappings, and at `fork`, `execve`, and exit, the process publishes how
//! many mappings of each segment it has ([`sync_shm`]). A semaphore
//! operation that must wait tries again every [`RETRY`](super::locks::RETRY)
//! until it can, its timeout passes (`EAGAIN`), or a signal ends it
//! (`EINTR`: `semop` is never restarted). A message send or receive that
//! must wait does the same, a signal ending it with `-ERESTARTNOHAND`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::{MMAP_MIN_ADDR, PAGE_SIZE, READ_IMPLIES_EXEC, vma_flags};
use super::super::ipc::msg::{self, Message};
use super::super::ipc::sem::{self, SemBuf};
use super::super::ipc::shm::{self, SHM_EXEC, SHM_RDONLY, SHM_REMAP, SHM_RND};
use super::super::ipc::{Caller, IPC_INFO, IPC_RMID, IPC_SET, IPC_STAT, UndoList};
use super::super::process::ProcState;
use super::super::signal::deliver::restart::ERESTARTNOHAND;
use super::super::wait::{Resume, Wait};
use super::mem::{PAGE_MASK, map_err, mman, page_align, perms, unmapped_area};
use super::{Ctx, SysResult};
use crate::user::mm::{Backing, Mapping, SharedObject};

/// `SHMLBA`: a page on every supported ABI.
const SHMLBA: u64 = PAGE_SIZE;
/// `RLIMIT_MEMLOCK`.
const RLIMIT_MEMLOCK: usize = 8;

/// The caller's credentials.
pub(super) fn caller(p: &ProcState) -> Caller {
    Caller {
        pid: p.pid,
        euid: p.creds.1,
        egid: p.creds.3,
        groups: p.groups.clone(),
    }
}

/// `shmget`.
pub fn shmget(c: &mut Ctx<'_>, key: i32, size: u64, flags: i32) -> SysResult {
    let who = caller(c.p);
    shm::get(&c.p.ipc.ns, key, size, flags, &who).map(|id| id as u64)
}

/// `shmat` (`do_shmat`): the address checks, the segment and access, then
/// the mapping, at the address given (`SHM_RND` rounding it down, and
/// without `SHM_REMAP` only where nothing is mapped) or where `mmap` would
/// place it.
pub fn shmat(c: &mut Ctx<'_>, id: i32, addr: u64, flags: i32) -> SysResult {
    if id < 0 {
        return Err(Errno(EINVAL));
    }
    let mut addr = addr;
    let fixed = addr != 0;
    if fixed {
        if addr & (SHMLBA - 1) != 0 {
            if flags & SHM_RND == 0 {
                return Err(Errno(EINVAL));
            }
            addr &= !(SHMLBA - 1);
            if addr == 0 && flags & SHM_REMAP != 0 {
                return Err(Errno(EINVAL));
            }
        }
    } else if flags & SHM_REMAP != 0 {
        return Err(Errno(EINVAL));
    }
    let (mut prot, mut access, writable) = if flags & SHM_RDONLY != 0 {
        (mman::PROT_READ, 0o444, false)
    } else {
        (mman::PROT_READ | mman::PROT_WRITE, 0o666, true)
    };
    if flags & SHM_EXEC != 0 {
        prot |= mman::PROT_EXEC;
        access |= 0o111;
    }
    let who = caller(c.p);
    let seg = shm::lookup_for_attach(&c.p.ipc.ns, id, access, &who)?;
    let file = std::fs::File::options()
        .read(true)
        .write(writable)
        .open(&seg.path)
        .map_err(|_| Errno(EIDRM))?;
    let len = page_align(seg.segsz).ok_or(Errno(EINVAL))?;
    if fixed
        && flags & SHM_REMAP == 0
        && (addr.checked_add(seg.segsz).is_none() || !c.p.space.is_free(addr, len))
    {
        return Err(Errno(EINVAL));
    }
    // do_mmap.
    if prot & mman::PROT_READ != 0 && c.p.persona & READ_IMPLIES_EXEC != 0 {
        prot |= mman::PROT_EXEC;
    }
    let start = if fixed {
        let task = c.p.abi.task_size();
        if len > task || addr > task - len {
            return Err(Errno(ENOMEM));
        }
        if addr < MMAP_MIN_ADDR {
            return Err(Errno(EPERM));
        }
        addr
    } else {
        unmapped_area(c, 0, len, 0)?
    };
    // do_mmap: under mlockall(MCL_FUTURE) the attach is locked and must
    // fit RLIMIT_MEMLOCK.
    let lock = c.p.mm.def_lock;
    if !super::mlock::future_ok(c.p, lock, len) {
        return Err(Errno(EAGAIN));
    }
    let object = SharedObject::sysv(file, writable, id).map_err(Errno::from)?;
    super::mlock::unmapped(c.p, start, len);
    c.p.space
        .map(
            start,
            len,
            Mapping {
                perms: perms(c.p.abi, prot),
                backing: Backing::Shared {
                    object: Arc::new(object),
                    offset: 0,
                },
                shared: true,
                name: Some(format!("/SYSV{:08x} (deleted)", seg.key as u32).into()),
                flags: (if writable { 0 } else { vma_flags::DENY_WRITE }) | lock,
            },
        )
        .map_err(map_err)?;
    super::mlock::mapped(c.p, lock, len);
    if lock & vma_flags::LOCKED != 0 {
        let _ = super::mlock::populate(c.p, start, start + len, true);
    }
    Ok(start)
}

/// `shmdt` (`ksys_shmdt`): the first segment mapping at or after `addr`
/// that maps its segment from where `addr` would (its offset), then the
/// following ones of the same attach within the segment's size.
pub fn shmdt(c: &mut Ctx<'_>, addr: u64) -> SysResult {
    if addr & PAGE_MASK != 0 {
        return Err(Errno(EINVAL));
    }
    let vmas = c.p.space.vma_snapshot();
    let at_offset = |v: &crate::user::mm::Vma| match &v.backing {
        Backing::Shared { object, offset } if object.sysv_id().is_some() => {
            (v.start >= addr && v.start - addr == *offset).then(|| object.clone())
        }
        _ => None,
    };
    let mut rest = vmas.iter().filter(|v| v.end > addr);
    let mut found = None;
    for v in rest.by_ref() {
        if let Some(object) = at_offset(v) {
            super::mlock::unmapped(c.p, v.start, v.len());
            c.p.space.unmap(v.start, v.len()).map_err(map_err)?;
            found = Some(object);
            break;
        }
    }
    let Some(attach) = found else {
        return Err(Errno(EINVAL));
    };
    let size = page_align(attach.len()).unwrap_or(u64::MAX);
    for v in rest {
        if v.end - addr > size {
            break;
        }
        if at_offset(v).is_some_and(|o| Arc::ptr_eq(&o, &attach)) {
            super::mlock::unmapped(c.p, v.start, v.len());
            c.p.space.unmap(v.start, v.len()).map_err(map_err)?;
        }
    }
    Ok(0)
}

/// `shmctl` (`ksys_shmctl`).
pub fn shmctl(c: &mut Ctx<'_>, id: i32, cmd: i32, buf: u64) -> SysResult {
    if cmd < 0 || id < 0 {
        return Err(Errno(EINVAL));
    }
    let who = caller(c.p);
    let ns = c.p.ipc.ns.clone();
    match cmd {
        IPC_INFO => {
            let (b, r) = shm::ipc_info(&ns)?;
            c.write_mem(buf, &b)?;
            Ok(r as u64)
        }
        shm::SHM_INFO => {
            let (b, r) = shm::shm_info(&ns)?;
            c.write_mem(buf, &b)?;
            Ok(r as u64)
        }
        IPC_STAT | shm::SHM_STAT | shm::SHM_STAT_ANY => {
            let (b, r) = shm::stat(&ns, id, cmd, &who)?;
            c.write_mem(buf, &b)?;
            Ok(r as u64)
        }
        IPC_SET => {
            let b = c.read_mem(buf, shm::SHMID64_DS)?;
            shm::set(&ns, id, &b[..super::super::ipc::IPC64_PERM], &who)?;
            Ok(0)
        }
        IPC_RMID => {
            shm::rmid(&ns, id, &who)?;
            Ok(0)
        }
        shm::SHM_LOCK | shm::SHM_UNLOCK => {
            let memlock = c.p.rlimits[RLIMIT_MEMLOCK].0;
            shm::lock(&ns, id, cmd, &who, memlock)?;
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// Publishes how many mappings of each System V segment the process has,
/// if that changed (`shm_open` and `shm_close` for every mapping the last
/// call made or removed).
pub fn sync_shm(p: &mut ProcState) {
    let mut counts = BTreeMap::new();
    for v in p.space.vma_snapshot() {
        if let Backing::Shared { object, .. } = &v.backing
            && let Some(id) = object.sysv_id()
        {
            *counts.entry(id).or_insert(0u32) += 1;
        }
    }
    if counts == p.ipc.shm_published {
        return;
    }
    let _ = shm::publish(&p.ipc.ns, p.pid, &p.ipc.shm_published, &counts);
    p.ipc.shm_published = counts;
}

/// In a new process: the mappings it inherited are its own attaches, and
/// it has no semaphore undo adjustments (`copy_semundo` without
/// `CLONE_SYSVSEM`).
pub fn forked(p: &mut ProcState) {
    p.ipc.sem_undo = false;
    if p.ipc.shm_published.is_empty() {
        return;
    }
    p.ipc.shm_published.clear();
    sync_shm(p);
}

/// `semget`.
pub fn semget(c: &mut Ctx<'_>, key: i32, nsems: i32, flags: i32) -> SysResult {
    let who = caller(c.p);
    sem::get(&c.p.ipc.ns, key, nsems, flags, &who).map(|id| id as u64)
}

/// `semtimedop` (`ksys_semtimedop`, `do_semtimedop`, `__do_semtimedop`),
/// and `semop` without a timeout: the timeout's copy, the operation count,
/// the operations' copy, the identifier, the timeout's value, then the
/// operations.
pub fn semtimedop(c: &mut Ctx<'_>, id: i32, sops: u64, nsops: u32, timeout: u64) -> SysResult {
    let resumed = c.resume.take();
    let waiting = resumed.is_some();
    let mut time = None;
    if !waiting && timeout != 0 {
        let b = c.read_mem(timeout, 16)?;
        time = Some((
            i64::from_le_bytes(b[..8].try_into().unwrap()),
            i64::from_le_bytes(b[8..].try_into().unwrap()),
        ));
    }
    if nsops > sem::SEMOPM {
        return Err(Errno(E2BIG));
    }
    if nsops < 1 {
        return Err(Errno(EINVAL));
    }
    let raw = c.read_mem(sops, nsops as usize * 6)?;
    if id < 0 {
        return Err(Errno(EINVAL));
    }
    let deadline = match resumed {
        Some(Resume::Until(d)) => d,
        _ => match time {
            // timespec64_valid.
            Some((sec, nsec)) if sec < 0 || !(0..1_000_000_000).contains(&nsec) => {
                return Err(Errno(EINVAL));
            }
            Some((sec, nsec)) => Instant::now().checked_add(Duration::new(sec as u64, nsec as u32)),
            None => None,
        },
    };
    let ops: Vec<SemBuf> = raw
        .chunks_exact(6)
        .map(|b| SemBuf {
            num: u16::from_le_bytes([b[0], b[1]]),
            op: i16::from_le_bytes([b[2], b[3]]),
            flg: i16::from_le_bytes([b[4], b[5]]),
        })
        .collect();
    // find_alloc_undo: the caller's undo list exists from here on, before
    // the set is even looked up.
    if ops.iter().any(|o| o.flg & sem::SEM_UNDO != 0) {
        c.t.sysvsem.get_or_insert_with(UndoList::new);
    }
    let who = caller(c.p);
    let tid = c.t.tid;
    match sem::semop(&c.p.ipc.ns, id, &ops, &who, tid, waiting)? {
        sem::Outcome::Done => {
            if ops.iter().any(|o| o.flg & sem::SEM_UNDO != 0) {
                c.p.ipc.sem_undo = true;
            }
            Ok(0)
        }
        sem::Outcome::Wait => {
            let now = Instant::now();
            if deadline.is_some_and(|d| now >= d) {
                sem::stop_waiting(&c.p.ipc.ns, id, who.pid, tid);
                return Err(Errno(EAGAIN));
            }
            if c.signal_pending() {
                sem::stop_waiting(&c.p.ipc.ns, id, who.pid, tid);
                return Err(Errno(EINTR));
            }
            let soon = now + super::locks::RETRY;
            let until = deadline.map_or(soon, |d| d.min(soon));
            Err(c.block(Wait::until(Some(until)), Resume::Until(deadline)))
        }
    }
}

/// `semctl` (`ksys_semctl`).
pub fn semctl(c: &mut Ctx<'_>, id: i32, num: i32, cmd: i32, arg: u64) -> SysResult {
    if id < 0 {
        return Err(Errno(EINVAL));
    }
    let who = caller(c.p);
    let ns = c.p.ipc.ns.clone();
    let x86_64 = c.p.abi == super::super::abi::LinuxAbi::X86_64;
    match cmd {
        IPC_INFO | sem::SEM_INFO => {
            let (b, r) = sem::info(&ns, cmd)?;
            c.write_mem(arg, &b)?;
            Ok(r as u64)
        }
        IPC_STAT | sem::SEM_STAT | sem::SEM_STAT_ANY => {
            let (b, r) = sem::stat(&ns, id, cmd, &who, x86_64)?;
            c.write_mem(arg, &b)?;
            Ok(r as u64)
        }
        sem::GETALL => {
            let (_, vals) = sem::read(&ns, id, num, cmd, &who)?;
            let b: Vec<u8> = vals.iter().flat_map(|v| v.to_le_bytes()).collect();
            c.write_mem(arg, &b)?;
            Ok(0)
        }
        sem::GETVAL | sem::GETPID | sem::GETNCNT | sem::GETZCNT => {
            sem::read(&ns, id, num, cmd, &who).map(|(v, _)| v as u64)
        }
        sem::SETALL => {
            let n = sem::nsems(&ns, id, &who)?;
            let b = c.read_mem(arg, n * 2)?;
            let vals: Vec<i32> = b
                .chunks_exact(2)
                .map(|w| i32::from(u16::from_le_bytes([w[0], w[1]])))
                .collect();
            sem::write(&ns, id, None, &vals, &who)?;
            Ok(0)
        }
        // A little-endian 64-bit ABI's int in the unsigned long.
        sem::SETVAL => {
            sem::write(&ns, id, Some(num), &[arg as u32 as i32], &who)?;
            Ok(0)
        }
        IPC_SET => {
            let len = if x86_64 { 104 } else { 88 };
            let b = c.read_mem(arg, len)?;
            sem::set(&ns, id, &b[..super::super::ipc::IPC64_PERM], &who)?;
            Ok(0)
        }
        IPC_RMID => {
            sem::rmid(&ns, id, &who)?;
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `msgget`.
pub fn msgget(c: &mut Ctx<'_>, key: i32, flags: i32) -> SysResult {
    let who = caller(c.p);
    msg::get(&c.p.ipc.ns, key, flags, &who).map(|id| id as u64)
}

/// A send or receive that must wait: again shortly, unless a signal ends
/// it (`-ERESTARTNOHAND`).
fn wait_retry(c: &mut Ctx<'_>) -> Errno {
    if c.signal_pending() {
        return Errno(ERESTARTNOHAND);
    }
    c.block(
        Wait::until(Some(Instant::now() + super::locks::RETRY)),
        Resume::Retry,
    )
}

/// `msgsnd` (`ksys_msgsnd`, `do_msgsnd`): the type's copy, the size, the
/// identifier, and the type, the text's copy, then the send.
pub fn msgsnd(c: &mut Ctx<'_>, id: i32, msgp: u64, msgsz: u64, flags: i32) -> SysResult {
    let mtype = c.read_u64(msgp)? as i64;
    if msgsz > msg::MSGMAX as u64 || id < 0 || mtype < 1 {
        return Err(Errno(EINVAL));
    }
    let text = c.read_mem(msgp + 8, msgsz as usize)?;
    let waiting = c.resume.take().is_some();
    let who = caller(c.p);
    let m = Message { mtype, text };
    match msg::send(&c.p.ipc.ns, id, &m, flags, &who, waiting)? {
        msg::Outcome::Done(()) => Ok(0),
        msg::Outcome::Wait => Err(wait_retry(c)),
    }
}

/// `msgrcv` (`do_msgrcv`): the identifier and size, `MSG_COPY`'s flags
/// and its copy of the buffer, then the receive, the message's type and text copied out (a failed copy
/// loses it, as the kernel's does).
pub fn msgrcv(
    c: &mut Ctx<'_>,
    id: i32,
    msgp: u64,
    bufsz: u64,
    msgtyp: i64,
    flags: i32,
) -> SysResult {
    if id < 0 || (bufsz as i64) < 0 {
        return Err(Errno(EINVAL));
    }
    let mut copy = 0;
    if flags & msg::MSG_COPY != 0 {
        if flags & msg::MSG_EXCEPT != 0 || flags & super::super::ipc::IPC_NOWAIT == 0 {
            return Err(Errno(EINVAL));
        }
        // prepare_copy (CONFIG_CHECKPOINT_RESTORE): load_msg of the
        // buffer, at most msg_ctlmax bytes of it, before the queue is
        // looked up.
        copy = bufsz.min(msg::MSGMAX as u64);
        c.read_mem(msgp, copy as usize)?;
    }
    let waiting = c.resume.take().is_some();
    let who = caller(c.p);
    let want = msg::Want {
        bufsz,
        msgtyp,
        flags,
        copy,
    };
    match msg::receive(&c.p.ipc.ns, id, want, &who, waiting)? {
        msg::Outcome::Done(m) => {
            c.write_u64(msgp, m.mtype as u64)?;
            c.write_mem(msgp + 8, &m.text)?;
            Ok(m.text.len() as u64)
        }
        msg::Outcome::Wait => Err(wait_retry(c)),
    }
}

/// `msgctl` (`ksys_msgctl`).
pub fn msgctl(c: &mut Ctx<'_>, id: i32, cmd: i32, buf: u64) -> SysResult {
    if id < 0 || cmd < 0 {
        return Err(Errno(EINVAL));
    }
    let who = caller(c.p);
    let ns = c.p.ipc.ns.clone();
    match cmd {
        IPC_INFO | msg::MSG_INFO => {
            let (b, r) = msg::info(&ns, cmd)?;
            c.write_mem(buf, &b)?;
            Ok(r as u64)
        }
        IPC_STAT | msg::MSG_STAT | msg::MSG_STAT_ANY => {
            let (b, r) = msg::stat(&ns, id, cmd, &who)?;
            c.write_mem(buf, &b)?;
            Ok(r as u64)
        }
        IPC_SET => {
            let b = c.read_mem(buf, msg::MSQID64_DS)?;
            msg::set(&ns, id, &b, &who)?;
            Ok(0)
        }
        IPC_RMID => {
            msg::rmid(&ns, id, &who)?;
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `exit_sem` for a task that left its undo list while its process goes
/// on (`unshare(CLONE_SYSVSEM)`, a thread's exit): a list's adjustments
/// apply when its last holder leaves it. They are recorded per process, so
/// they apply now only when no other task holds a list (`others`), every
/// recorded adjustment then being the left list's; otherwise they wait for
/// the process's exit.
pub fn leave_undo_list(p: &mut ProcState, others: bool) {
    if !others && p.ipc.sem_undo {
        sem::exit(&p.ipc.ns, p.pid);
        p.ipc.sem_undo = false;
    }
}

/// At exit: every mapping goes (`exit_mmap`), and the semaphore undo
/// adjustments are applied (`exit_sem`).
pub fn exit(p: &mut ProcState) {
    if p.ipc.sem_undo {
        sem::exit(&p.ipc.ns, p.pid);
        p.ipc.sem_undo = false;
    }
    if p.ipc.shm_published.is_empty() {
        return;
    }
    let _ = shm::publish(&p.ipc.ns, p.pid, &p.ipc.shm_published, &BTreeMap::new());
    p.ipc.shm_published.clear();
}
