//! A compatibility task's System V IPC structures (`ipc/compat.c` and the
//! `CONFIG_COMPAT` parts of `ipc/sem.c`, `ipc/msg.c`, and `ipc/shm.c`, with
//! the types of `include/asm-generic/compat.h` and x86's 16-bit
//! `compat_mode_t`, `__compat_uid_t`, and `compat_ipc_pid_t`).
//!
//! A command with `IPC_64` reads and writes the `*64` structures: a
//! `struct compat_ipc64_perm` (32-bit IDs, a 16-bit mode), 32-bit words,
//! and times split into low and high halves. One without it (through the
//! `ipc` multiplexer only: `compat_ipc_parse_version`) uses the old
//! layouts: a `struct compat_ipc_perm` whose IDs are 16-bit
//! (`high2lowuid`), `old_time32_t` times, and 16-bit counts and process
//! IDs, each truncated as the kernel's assignments truncate them.

use super::super::abi::types::low_id;
use super::msg::MsqDs;
use super::sem::SemDs;
use super::shm::{ShmDs, ShmInfo, ShmInfo64};
use super::{Perm, PermSet};

/// `IPC_64`: a command's flag for the `*64` structures.
pub const IPC_64: i32 = 0x100;

/// `sizeof(struct compat_ipc64_perm)`, `sizeof(struct compat_ipc_perm)`.
pub const IPC64_PERM: usize = 36;
pub const IPC_PERM: usize = 16;
/// `sizeof(struct compat_semid64_ds)`, `sizeof(struct compat_semid_ds)`.
pub const SEMID64_DS: usize = 64;
pub const SEMID_DS: usize = 44;
/// `sizeof(struct compat_msqid64_ds)`, `sizeof(struct compat_msqid_ds)`.
pub const MSQID64_DS: usize = 88;
pub const MSQID_DS: usize = 56;
/// `offsetof(..., msg_qbytes)` of the two, a 32-bit and a 16-bit field.
pub const MSQID64_QBYTES: u64 = 68;
pub const MSQID_QBYTES: u64 = 48;
/// `sizeof(struct compat_shmid64_ds)`, `sizeof(struct compat_shmid_ds)`.
pub const SHMID64_DS: usize = 84;
pub const SHMID_DS: usize = 48;
/// `sizeof(struct compat_shminfo64)`, `sizeof(struct shminfo)`,
/// `sizeof(struct compat_shm_info)`.
pub const SHMINFO64: usize = 36;
pub const SHMINFO: usize = 20;
pub const SHM_INFO: usize = 24;

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    b[at..at + v.len()].copy_from_slice(v);
}

/// `lower_32_bits` and `upper_32_bits` of a time, at `at` and `at + 4`.
fn put_time(b: &mut [u8], at: usize, t: i64) {
    put(b, at, &(t as u32).to_le_bytes());
    put(b, at + 4, &((t as u64 >> 32) as u32).to_le_bytes());
}

/// `to_compat_ipc64_perm`.
pub fn ipc64_perm(p: &Perm) -> [u8; IPC64_PERM] {
    let mut b = [0u8; IPC64_PERM];
    put(&mut b, 0, &p.key.to_le_bytes());
    put(&mut b, 4, &p.uid.to_le_bytes());
    put(&mut b, 8, &p.gid.to_le_bytes());
    put(&mut b, 12, &p.cuid.to_le_bytes());
    put(&mut b, 16, &p.cgid.to_le_bytes());
    put(&mut b, 20, &(p.mode as u16).to_le_bytes());
    put(&mut b, 24, &(p.seq as u16).to_le_bytes());
    b
}

/// `to_compat_ipc_perm`: the IDs through `high2lowuid`.
pub fn ipc_perm(p: &Perm) -> [u8; IPC_PERM] {
    let mut b = [0u8; IPC_PERM];
    put(&mut b, 0, &p.key.to_le_bytes());
    put(&mut b, 4, &low_id(p.uid).to_le_bytes());
    put(&mut b, 6, &low_id(p.gid).to_le_bytes());
    put(&mut b, 8, &low_id(p.cuid).to_le_bytes());
    put(&mut b, 10, &low_id(p.cgid).to_le_bytes());
    put(&mut b, 12, &(p.mode as u16).to_le_bytes());
    put(&mut b, 14, &(p.seq as u16).to_le_bytes());
    b
}

/// `get_compat_ipc64_perm`: `IPC_SET`'s fields of a `struct
/// compat_ipc64_perm`.
pub fn ipc64_perm_set(b: &[u8]) -> PermSet {
    PermSet {
        uid: u32::from_le_bytes(b[4..8].try_into().unwrap()),
        gid: u32::from_le_bytes(b[8..12].try_into().unwrap()),
        mode: u32::from(u16::from_le_bytes([b[20], b[21]])),
    }
}

/// `get_compat_ipc_perm`: `IPC_SET`'s fields of a `struct
/// compat_ipc_perm`, the 16-bit IDs zero-extended (0xFFFF is user 65535,
/// not -1).
pub fn ipc_perm_set(b: &[u8]) -> PermSet {
    let h = |i: usize| u32::from(u16::from_le_bytes([b[i], b[i + 1]]));
    PermSet {
        uid: h(4),
        gid: h(6),
        mode: h(12),
    }
}

/// `copy_compat_semid_to_user`: `struct compat_semid64_ds` or `struct
/// compat_semid_ds`.
pub fn semid_ds(ds: &SemDs, v64: bool) -> Vec<u8> {
    if v64 {
        let mut b = vec![0u8; SEMID64_DS];
        put(&mut b, 0, &ipc64_perm(&ds.perm));
        put_time(&mut b, 36, ds.otime);
        put_time(&mut b, 44, ds.ctime);
        put(&mut b, 52, &(ds.nsems as u32).to_le_bytes());
        b
    } else {
        // sem_perm, sem_otime, sem_ctime, then sem_base, sem_pending,
        // sem_pending_last, and undo (zero), and the 16-bit sem_nsems.
        let mut b = vec![0u8; SEMID_DS];
        put(&mut b, 0, &ipc_perm(&ds.perm));
        put(&mut b, 16, &(ds.otime as i32).to_le_bytes());
        put(&mut b, 20, &(ds.ctime as i32).to_le_bytes());
        put(&mut b, 40, &(ds.nsems as u16).to_le_bytes());
        b
    }
}

/// `copy_compat_msqid_to_user`: `struct compat_msqid64_ds` or `struct
/// compat_msqid_ds`.
pub fn msqid_ds(ds: &MsqDs, v64: bool) -> Vec<u8> {
    if v64 {
        let mut b = vec![0u8; MSQID64_DS];
        put(&mut b, 0, &ipc64_perm(&ds.perm));
        put_time(&mut b, 36, ds.stime);
        put_time(&mut b, 44, ds.rtime);
        put_time(&mut b, 52, ds.ctime);
        put(&mut b, 60, &(ds.cbytes as u32).to_le_bytes());
        put(&mut b, 64, &(ds.qnum as u32).to_le_bytes());
        put(&mut b, 68, &(ds.qbytes as u32).to_le_bytes());
        put(&mut b, 72, &ds.lspid.to_le_bytes());
        put(&mut b, 76, &ds.lrpid.to_le_bytes());
        b
    } else {
        // msg_perm, msg_first and msg_last (zero), the times, msg_lcbytes
        // and msg_lqbytes (zero), then 16-bit counts and process IDs.
        let mut b = vec![0u8; MSQID_DS];
        put(&mut b, 0, &ipc_perm(&ds.perm));
        put(&mut b, 24, &(ds.stime as i32).to_le_bytes());
        put(&mut b, 28, &(ds.rtime as i32).to_le_bytes());
        put(&mut b, 32, &(ds.ctime as i32).to_le_bytes());
        put(&mut b, 44, &(ds.cbytes as u16).to_le_bytes());
        put(&mut b, 46, &(ds.qnum as u16).to_le_bytes());
        put(&mut b, 48, &(ds.qbytes as u16).to_le_bytes());
        put(&mut b, 50, &(ds.lspid as u16).to_le_bytes());
        put(&mut b, 52, &(ds.lrpid as u16).to_le_bytes());
        b
    }
}

/// `copy_compat_shmid_to_user`: `struct compat_shmid64_ds` or `struct
/// compat_shmid_ds`.
pub fn shmid_ds(ds: &ShmDs, v64: bool) -> Vec<u8> {
    if v64 {
        let mut b = vec![0u8; SHMID64_DS];
        put(&mut b, 0, &ipc64_perm(&ds.perm));
        put(&mut b, 36, &(ds.segsz as u32).to_le_bytes());
        put_time(&mut b, 40, ds.atime);
        put_time(&mut b, 48, ds.dtime);
        put_time(&mut b, 56, ds.ctime);
        put(&mut b, 64, &ds.cpid.to_le_bytes());
        put(&mut b, 68, &ds.lpid.to_le_bytes());
        put(&mut b, 72, &(ds.nattch as u32).to_le_bytes());
        b
    } else {
        let mut b = vec![0u8; SHMID_DS];
        put(&mut b, 0, &ipc_perm(&ds.perm));
        put(&mut b, 16, &(ds.segsz as i32).to_le_bytes());
        put(&mut b, 20, &(ds.atime as i32).to_le_bytes());
        put(&mut b, 24, &(ds.dtime as i32).to_le_bytes());
        put(&mut b, 28, &(ds.ctime as i32).to_le_bytes());
        put(&mut b, 32, &(ds.cpid as u16).to_le_bytes());
        put(&mut b, 34, &(ds.lpid as u16).to_le_bytes());
        put(&mut b, 36, &(ds.nattch as u16).to_le_bytes());
        b
    }
}

/// `copy_compat_shminfo_to_user`: `struct compat_shminfo64` or `struct
/// shminfo`, `shmmax` capped at `INT_MAX` for both.
pub fn shminfo(info: &ShmInfo64, v64: bool) -> Vec<u8> {
    let shmmax = info.shmmax.min(i32::MAX as u64);
    let fields = [shmmax, info.shmmin, info.shmmni, info.shmseg, info.shmall];
    let mut b = vec![0u8; if v64 { SHMINFO64 } else { SHMINFO }];
    for (i, v) in fields.iter().enumerate() {
        put(&mut b, i * 4, &(*v as u32).to_le_bytes());
    }
    b
}

/// `put_compat_shm_info`: `struct compat_shm_info`.
pub fn shm_info(info: &ShmInfo) -> [u8; SHM_INFO] {
    let mut b = [0u8; SHM_INFO];
    put(&mut b, 0, &info.used_ids.to_le_bytes());
    let rest = [
        info.shm_tot,
        info.shm_rss,
        info.shm_swp,
        info.swap_attempts,
        info.swap_successes,
    ];
    for (i, v) in rest.iter().enumerate() {
        put(&mut b, 4 + i * 4, &(*v as u32).to_le_bytes());
    }
    b
}
