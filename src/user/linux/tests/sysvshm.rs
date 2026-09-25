//! System V shared memory against `ipc/shm.c` (Linux 6.19), through the
//! system calls on every ABI: `shmget`, `shmat` (placement, `SHM_RND`,
//! `SHM_REMAP`, `SHM_RDONLY`), `shmdt`, `shmctl`, attach counting by
//! mapping, removal while attached, and `/proc/self/maps`. Each harness
//! has a namespace of its own.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;

const IPC_PRIVATE: u64 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const SHM_STAT: u64 = 13;
const SHM_INFO: u64 = 14;
const SHM_LOCK: u64 = 11;
const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_DEST: u32 = 0o1000;
const SHM_LOCKED: u32 = 0o2000;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// `struct shmid64_ds` of `id`.
fn stat(h: &mut Harness, id: u64, buf: u64) -> Vec<u8> {
    h.ok(Sysno::Shmctl, &[id, IPC_STAT, buf]);
    get(h, buf, 112)
}

fn root() -> bool {
    // SAFETY: geteuid has no failure mode.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn segments_attach_and_detach() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let buf = h.anon(4 * P, 3, false);
        let id = h.ok(Sysno::Shmget, &[IPC_PRIVATE, 5000, 0o600]);
        let ds = stat(&mut h, id, buf);
        assert_eq!(u64_at(&ds, 48), 5000, "shm_segsz");
        assert_eq!(u64_at(&ds, 88), 0, "shm_nattch");
        assert!(u64_at(&ds, 72) > 0, "shm_ctime");
        // Two attaches see each other's stores.
        let a = h.ok(Sysno::Shmat, &[id, 0, 0]);
        let b = h.ok(Sysno::Shmat, &[id, 0, 0]);
        assert_ne!(a, b);
        h.proc.state.space.write(a + 4999, &[0x5A]).unwrap();
        assert_eq!(get(&h, b + 4999, 1), [0x5A]);
        let ds = stat(&mut h, id, buf);
        assert_eq!(u64_at(&ds, 88), 2);
        assert_eq!(u32_at(&ds, 84) as i32, h.proc.state.pid, "shm_lpid");
        assert!(u64_at(&ds, 56) > 0, "shm_atime");
        // A mapping split in two counts twice (shm_open on the split).
        h.ok(Sysno::Mprotect, &[a, P, PROT_READ]);
        assert_eq!(u64_at(&stat(&mut h, id, buf), 88), 3);
        // ... and is not merged again (is_mergeable_vma).
        h.ok(Sysno::Mprotect, &[a, P, PROT_READ | PROT_WRITE]);
        assert_eq!(u64_at(&stat(&mut h, id, buf), 88), 3);
        // shmdt: the attach at that address (all its pieces).
        h.ok(Sysno::Shmdt, &[a]);
        let ds = stat(&mut h, id, buf);
        assert_eq!(u64_at(&ds, 88), 1);
        assert!(u64_at(&ds, 64) > 0, "shm_dtime");
        assert_eq!(h.err(Sysno::Shmdt, &[a]), EINVAL);
        assert_eq!(h.err(Sysno::Shmdt, &[b + 1]), EINVAL);
        // munmap detaches too.
        h.ok(Sysno::Munmap, &[b, 2 * P]);
        assert_eq!(u64_at(&stat(&mut h, id, buf), 88), 0);
        // /proc/self/maps: shmem, the identifier as inode.
        let c = h.ok(Sysno::Shmat, &[id, 0, SHM_RDONLY]);
        let maps = String::from_utf8(crate::user::linux::procfs::maps(&h.proc.state)).unwrap();
        let line = maps
            .lines()
            .find(|l| l.starts_with(&format!("{c:08x}-")))
            .unwrap();
        assert!(line.contains(" r--s 00000000 00:01 "), "{line}");
        assert!(line.ends_with(" /SYSV00000000 (deleted)"), "{line}");
        assert!(line.contains(&format!(" {id} ")), "{line}");
        // Read-only: never writable.
        assert_eq!(h.err(Sysno::Mprotect, &[c, P, PROT_WRITE]), EACCES);
        h.ok(Sysno::Shmdt, &[c]);
    });
}

#[test]
fn shmat_places_as_do_shmat() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let id = h.ok(Sysno::Shmget, &[IPC_PRIVATE, 2 * P, 0o600]);
        let free = h.anon(4 * P, 3, false);
        h.ok(Sysno::Munmap, &[free, 4 * P]);
        // An unaligned address: EINVAL, or rounded down with SHM_RND.
        assert_eq!(h.err(Sysno::Shmat, &[id, free + 1, 0]), EINVAL);
        assert_eq!(h.call(Sysno::Shmat, &[id, free + 1, SHM_RND]), free as i64);
        // Over a mapping: EINVAL, unless SHM_REMAP.
        assert_eq!(h.err(Sysno::Shmat, &[id, free, 0]), EINVAL);
        assert_eq!(h.call(Sysno::Shmat, &[id, free, SHM_REMAP]), free as i64);
        assert_eq!(h.err(Sysno::Shmat, &[id, 0, SHM_REMAP]), EINVAL);
        assert_eq!(h.err(Sysno::Shmat, &[id, 1, SHM_RND | SHM_REMAP]), EINVAL);
        // Unknown and negative identifiers.
        assert_eq!(h.err(Sysno::Shmat, &[id + 1, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Shmat, &[u32::MAX as u64, 0, 0]), EINVAL);
    });
}

#[test]
fn shmctl_follows_ksys_shmctl() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let buf = h.anon(4 * P, 3, false);
        let id = h.ok(Sysno::Shmget, &[42, 100, IPC_CREAT | 0o640]);
        assert_eq!(h.call(Sysno::Shmget, &[42, 50, 0]), id as i64);
        assert_eq!(h.err(Sysno::Shmget, &[42, 101, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Shmget, &[42, 1, IPC_CREAT | IPC_EXCL]), EEXIST);
        assert_eq!(h.err(Sysno::Shmget, &[43, 1, 0]), ENOENT);
        assert_eq!(h.err(Sysno::Shmget, &[IPC_PRIVATE, 0, 0]), EINVAL);
        // SHM_STAT takes an index, and returns the identifier.
        assert_eq!(h.call(Sysno::Shmctl, &[0, SHM_STAT, buf]), id as i64);
        assert!(h.call(Sysno::Shmctl, &[0, IPC_INFO, buf]) >= 0);
        assert_eq!(u64_at(&get(&h, buf, 72), 16), 4096, "shmmni");
        assert!(h.call(Sysno::Shmctl, &[0, SHM_INFO, buf]) >= 0);
        assert_eq!(u32_at(&get(&h, buf, 4), 0), 1, "used_ids");
        assert_eq!(h.err(Sysno::Shmctl, &[id, 99, buf]), EINVAL);
        assert_eq!(h.err(Sysno::Shmctl, &[id, IPC_STAT, 8]), EFAULT);
        assert_eq!(
            h.err(Sysno::Shmctl, &[u32::MAX as u64, IPC_STAT, buf]),
            EINVAL
        );
        // IPC_SET: the permission bits and owner; ctime moves.
        let mut ds = stat(&mut h, id, buf);
        ds[20..24].copy_from_slice(&0o600u32.to_le_bytes());
        h.proc.state.space.write(buf, &ds).unwrap();
        h.ok(Sysno::Shmctl, &[id, IPC_SET, buf]);
        assert_eq!(u32_at(&stat(&mut h, id, buf), 20), 0o600);
        if !root() {
            // No memory-lock limit: SHM_LOCK is refused.
            h.proc.state.rlimits[8] = (0, 0);
            assert_eq!(h.err(Sysno::Shmctl, &[id, SHM_LOCK, 0]), EPERM);
        }
        h.proc.state.rlimits[8] = (65536, 65536);
        h.ok(Sysno::Shmctl, &[id, SHM_LOCK, 0]);
        assert_eq!(u32_at(&stat(&mut h, id, buf), 20) & SHM_LOCKED, SHM_LOCKED);
        // Removal while attached: marked, the key private; the last
        // detach removes it.
        let a = h.ok(Sysno::Shmat, &[id, 0, 0]);
        h.ok(Sysno::Shmctl, &[id, IPC_RMID, 0]);
        let ds = stat(&mut h, id, buf);
        assert_eq!(u32_at(&ds, 20) & SHM_DEST, SHM_DEST);
        assert_eq!(u32_at(&ds, 0), 0, "the key is IPC_PRIVATE");
        assert_eq!(h.err(Sysno::Shmget, &[42, 1, 0]), ENOENT);
        // Still attachable by its identifier.
        let b = h.ok(Sysno::Shmat, &[id, 0, 0]);
        h.ok(Sysno::Shmdt, &[a]);
        h.ok(Sysno::Shmdt, &[b]);
        assert_eq!(h.err(Sysno::Shmctl, &[id, IPC_STAT, buf]), EINVAL);
        // A new segment by the same key is another one.
        let again = h.ok(Sysno::Shmget, &[42, 1, IPC_CREAT | 0o600]);
        assert_ne!(again, id);
    });
}
