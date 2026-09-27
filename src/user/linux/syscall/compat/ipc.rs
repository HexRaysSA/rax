//! System V IPC of a compatibility task: the `ipc` multiplexer
//! (`compat_ksys_ipc`, `ipc/syscall.c`) and the calls with compatibility
//! entry points (`compat_sys_semctl`, `compat_sys_msgctl`,
//! `compat_sys_shmctl`, `compat_sys_msgsnd`, `compat_sys_msgrcv`).
//!
//! The direct `*ctl` calls always use the `*64` structures and pass the
//! command on as it is: `compat_ksys_semctl` and `compat_ksys_msgctl`
//! choose the operation by the command without `IPC_64` but hand the
//! whole command to the functions they call, which compare it whole (so
//! `IPC_STAT | IPC_64` returns the identifier, and the `GET*`, `SETALL`,
//! `IPC_SET`, and `IPC_RMID` forms end in `EINVAL` after their lookups),
//! while `compat_ksys_shmctl` refuses any command with `IPC_64`. Through
//! the multiplexer, `compat_ipc_parse_version` takes `IPC_64` off the
//! command and selects the structures by it. The multiplexer's other
//! operations are the native calls, `SEMTIMEDOP`'s timeout a `struct
//! old_timespec32`, and `MSGSND` and `MSGRCV` with a 32-bit message type.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::ipc::compat::{self as layout, IPC_64};
use super::super::super::ipc::{IPC_INFO, IPC_RMID, IPC_SET, IPC_STAT, PermSet, msg, sem, shm};
use super::super::ipc::{self as native, caller};
use super::super::{Ctx, SysResult};

/// The multiplexer's operations (`linux/ipc.h`).
mod op {
    pub const SEMOP: u32 = 1;
    pub const SEMGET: u32 = 2;
    pub const SEMCTL: u32 = 3;
    pub const SEMTIMEDOP: u32 = 4;
    pub const MSGSND: u32 = 11;
    pub const MSGRCV: u32 = 12;
    pub const MSGGET: u32 = 13;
    pub const MSGCTL: u32 = 14;
    pub const SHMAT: u32 = 21;
    pub const SHMDT: u32 = 22;
    pub const SHMGET: u32 = 23;
    pub const SHMCTL: u32 = 24;
}
/// The operations that attach and detach segments (whose mappings the
/// dispatcher publishes).
pub use op::{SHMAT, SHMDT};

/// `compat_ipc_parse_version`: the command without `IPC_64`, and whether it
/// had it.
fn parse_version(cmd: i32) -> (i32, bool) {
    (cmd & !IPC_64, cmd & IPC_64 != 0)
}

/// `compat_ksys_ipc`: `call`'s low 16 bits select the operation and its
/// high ones are the version (`MSGRCV`'s version 0 reads the buffer and
/// type from a `struct compat_ipc_kludge`; `SHMAT`'s version 1 is
/// `EINVAL`). An unknown operation is `ENOSYS`.
pub fn ipc(c: &mut Ctx<'_>, a: [u64; 6]) -> SysResult {
    let version = (a[0] as u32) >> 16;
    let call = a[0] as u32 & 0xFFFF;
    let first = a[1] as u32 as i32;
    let second = a[2] as u32 as i32;
    let third = a[3] as u32;
    let ptr = u64::from(a[4] as u32);
    let fifth = a[5] as u32;
    match call {
        // struct sembuf is the same for both.
        op::SEMOP => native::semtimedop(c, first, ptr, second as u32, 0),
        op::SEMTIMEDOP => {
            c.time32 = true;
            native::semtimedop(c, first, ptr, second as u32, u64::from(fifth))
        }
        op::SEMGET => native::semget(c, first, second, third as i32),
        op::SEMCTL => {
            if ptr == 0 {
                return Err(Errno(EINVAL));
            }
            // The union semun's word: a value or a pointer.
            let pad = c.read_u32(ptr)?;
            let (cmd, v64) = parse_version(third as i32);
            semctl(c, first, second, cmd, u64::from(pad), v64)
        }
        op::MSGSND => native::msgsnd(c, first, ptr, i64::from(second) as u64, third as i32),
        op::MSGRCV => {
            if first < 0 || second < 0 {
                return Err(Errno(EINVAL));
            }
            let (msgp, msgtyp) = if version == 0 {
                if ptr == 0 {
                    return Err(Errno(EINVAL));
                }
                let k = c.read_mem(ptr, 8)?;
                (
                    u64::from(u32::from_le_bytes(k[..4].try_into().unwrap())),
                    i64::from(i32::from_le_bytes(k[4..].try_into().unwrap())),
                )
            } else {
                (ptr, i64::from(fifth as i32))
            };
            native::msgrcv(c, first, msgp, second as u64, msgtyp, third as i32)
        }
        op::MSGGET => native::msgget(c, first, second),
        op::MSGCTL => {
            let (cmd, v64) = parse_version(second);
            msgctl(c, first, cmd, ptr, v64)
        }
        op::SHMAT => {
            if version == 1 {
                return Err(Errno(EINVAL));
            }
            // The address goes to a compat_ulong_t at `third`; a failed
            // store leaves the segment attached.
            let addr = native::shmat(c, first, ptr, second)?;
            c.write_u32(u64::from(third), addr as u32)?;
            Ok(0)
        }
        op::SHMDT => native::shmdt(c, ptr),
        op::SHMGET => native::shmget(c, first, u64::from(second as u32), third as i32),
        op::SHMCTL => {
            let (cmd, v64) = parse_version(second);
            shmctl(c, first, cmd, ptr, v64)
        }
        _ => Err(Errno(ENOSYS)),
    }
}

/// `compat_ksys_semctl`: `arg` is a 32-bit word, `SETVAL`'s value or the
/// buffer's address; `v64` selects `struct compat_semid64_ds` over `struct
/// compat_semid_ds`.
pub fn semctl(c: &mut Ctx<'_>, id: i32, num: i32, cmd: i32, arg: u64, v64: bool) -> SysResult {
    if id < 0 {
        return Err(Errno(EINVAL));
    }
    let who = caller(c.p);
    let ns = c.p.ipc.ns.clone();
    let whole = cmd & !IPC_64 == cmd;
    match cmd & !IPC_64 {
        IPC_INFO | sem::SEM_INFO => {
            // struct seminfo has one layout.
            let (b, r) = sem::info(&ns, cmd)?;
            c.write_mem(arg, &b)?;
            Ok(r as u64)
        }
        IPC_STAT | sem::SEM_STAT | sem::SEM_STAT_ANY => {
            let (ds, r) = sem::stat(&ns, id, cmd, &who)?;
            c.write_mem(arg, &layout::semid_ds(&ds, v64))?;
            Ok(r as u64)
        }
        // The values are unsigned shorts for both.
        sem::GETVAL | sem::GETPID | sem::GETNCNT | sem::GETZCNT | sem::GETALL | sem::SETALL
            if whole =>
        {
            native::semctl(c, id, num, cmd, arg)
        }
        sem::GETVAL | sem::GETPID | sem::GETNCNT | sem::GETZCNT | sem::GETALL | sem::SETALL => {
            sem::read(&ns, id, num, cmd, &who).map(|(v, _)| v as u64)
        }
        // semctl_setval takes no command.
        sem::SETVAL => native::semctl(c, id, num, sem::SETVAL, arg),
        IPC_SET => {
            let perm = read_perm(c, arg, v64)?;
            if !whole {
                sem::check_owner(&ns, id, &who)?;
                return Err(Errno(EINVAL));
            }
            sem::set(&ns, id, &perm, &who)?;
            Ok(0)
        }
        IPC_RMID if whole => native::semctl(c, id, num, IPC_RMID, arg),
        IPC_RMID => {
            sem::check_owner(&ns, id, &who)?;
            Err(Errno(EINVAL))
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `compat_ksys_msgctl`: `v64` selects `struct compat_msqid64_ds` over
/// `struct compat_msqid_ds`.
pub fn msgctl(c: &mut Ctx<'_>, id: i32, cmd: i32, buf: u64, v64: bool) -> SysResult {
    if id < 0 || cmd < 0 {
        return Err(Errno(EINVAL));
    }
    let who = caller(c.p);
    let ns = c.p.ipc.ns.clone();
    let whole = cmd & !IPC_64 == cmd;
    match cmd & !IPC_64 {
        IPC_INFO | msg::MSG_INFO => {
            // struct msginfo has one layout.
            let (b, r) = msg::info(&ns, cmd)?;
            c.write_mem(buf, &b)?;
            Ok(r as u64)
        }
        IPC_STAT | msg::MSG_STAT | msg::MSG_STAT_ANY => {
            let (ds, r) = msg::stat(&ns, id, cmd, &who)?;
            c.write_mem(buf, &layout::msqid_ds(&ds, v64))?;
            Ok(r as u64)
        }
        IPC_SET => {
            // copy_compat_msqid_from_user: the permissions, then msg_qbytes.
            let perm = read_perm(c, buf, v64)?;
            let qbytes = if v64 {
                u64::from(c.read_u32(buf + layout::MSQID64_QBYTES)?)
            } else {
                let b = c.read_mem(buf + layout::MSQID_QBYTES, 2)?;
                u64::from(u16::from_le_bytes([b[0], b[1]]))
            };
            if !whole {
                msg::check_owner(&ns, id, &who)?;
                return Err(Errno(EINVAL));
            }
            msg::set(&ns, id, &perm, qbytes, &who)?;
            Ok(0)
        }
        IPC_RMID if whole => native::msgctl(c, id, IPC_RMID, buf),
        IPC_RMID => {
            msg::check_owner(&ns, id, &who)?;
            Err(Errno(EINVAL))
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `compat_ksys_shmctl`: the command compared whole (`IPC_64` is
/// `EINVAL`); `v64` selects `struct compat_shmid64_ds` and `struct
/// compat_shminfo64` over `struct compat_shmid_ds` and `struct shminfo`.
pub fn shmctl(c: &mut Ctx<'_>, id: i32, cmd: i32, buf: u64, v64: bool) -> SysResult {
    if cmd < 0 || id < 0 {
        return Err(Errno(EINVAL));
    }
    let who = caller(c.p);
    let ns = c.p.ipc.ns.clone();
    match cmd {
        IPC_INFO => {
            let (info, r) = shm::ipc_info(&ns)?;
            c.write_mem(buf, &layout::shminfo(&info, v64))?;
            Ok(r as u64)
        }
        shm::SHM_INFO => {
            let (info, r) = shm::shm_info(&ns)?;
            c.write_mem(buf, &layout::shm_info(&info))?;
            Ok(r as u64)
        }
        IPC_STAT | shm::SHM_STAT | shm::SHM_STAT_ANY => {
            let (ds, r) = shm::stat(&ns, id, cmd, &who)?;
            c.write_mem(buf, &layout::shmid_ds(&ds, v64))?;
            Ok(r as u64)
        }
        IPC_SET => {
            let perm = read_perm(c, buf, v64)?;
            shm::set(&ns, id, &perm, &who)?;
            Ok(0)
        }
        IPC_RMID | shm::SHM_LOCK | shm::SHM_UNLOCK => native::shmctl(c, id, cmd, buf),
        _ => Err(Errno(EINVAL)),
    }
}

/// `get_compat_ipc64_perm` or `get_compat_ipc_perm`: `IPC_SET`'s fields
/// from the structure's leading permissions.
fn read_perm(c: &Ctx<'_>, buf: u64, v64: bool) -> Result<PermSet, Errno> {
    Ok(if v64 {
        layout::ipc64_perm_set(&c.read_mem(buf, layout::IPC64_PERM)?)
    } else {
        layout::ipc_perm_set(&c.read_mem(buf, layout::IPC_PERM)?)
    })
}
