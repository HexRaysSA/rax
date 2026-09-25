//! System V IPC system calls: `shmget`, `shmat`, `shmdt`, and `shmctl`
//! (`ipc/shm.c`), over the namespace's objects ([`ipc`](super::super::ipc)).
//!
//! `shmat` maps a segment's host file shared, named as Linux names it
//! (`/SYSV<key> (deleted)`); after every call that changes the process's
//! mappings, and at `fork`, `execve`, and exit, the process publishes how
//! many mappings of each segment it has ([`sync_shm`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::{MMAP_MIN_ADDR, PAGE_SIZE, READ_IMPLIES_EXEC, vma_flags};
use super::super::ipc::shm::{self, SHM_EXEC, SHM_RDONLY, SHM_REMAP, SHM_RND};
use super::super::ipc::{Caller, IPC_INFO, IPC_RMID, IPC_SET, IPC_STAT};
use super::super::process::ProcState;
use super::mem::{PAGE_MASK, map_err, mman, page_align, perms, unmapped_area};
use super::{Ctx, SysResult};
use crate::user::mm::{Backing, Mapping, SharedObject};

/// `SHMLBA`: a page on every supported ABI.
const SHMLBA: u64 = PAGE_SIZE;
/// `RLIMIT_MEMLOCK`.
const RLIMIT_MEMLOCK: usize = 8;

/// The caller's credentials.
fn caller(p: &ProcState) -> Caller {
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
    let object = SharedObject::sysv(file, writable, id).map_err(Errno::from)?;
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
                flags: if writable { 0 } else { vma_flags::DENY_WRITE },
            },
        )
        .map_err(map_err)?;
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

/// In a new process: the mappings it inherited are its own attaches.
pub fn forked(p: &mut ProcState) {
    if p.ipc.shm_published.is_empty() {
        return;
    }
    p.ipc.shm_published.clear();
    sync_shm(p);
}

/// At exit (`exit_mmap`): every mapping goes.
pub fn exit(p: &mut ProcState) {
    if p.ipc.shm_published.is_empty() {
        return;
    }
    let _ = shm::publish(&p.ipc.ns, p.pid, &p.ipc.shm_published, &BTreeMap::new());
    p.ipc.shm_published.clear();
}
