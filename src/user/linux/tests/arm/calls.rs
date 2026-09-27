//! An ARM EABI task's calls whose conversions differ from i386's
//! (`arch/arm64/kernel/sys32.c`, `arch/arm64/tools/syscall_32.tbl`): the
//! `aarch32_*` wrappers' register pairs and reordered arguments,
//! `statfs64`'s size fixup, the EABI `struct stat64` (`asm/stat.h`,
//! `cp_new_stat64`) and naturally aligned `struct compat_flock64`
//! (`linux/compat.h` without `__ARCH_NEED_COMPAT_FLOCK64_PACKED`), System V
//! IPC's direct calls with `ipc_parse_version` and the 16 KiB
//! `COMPAT_SHMLBA` (`asm/shmparam.h`), `accept`, `send`, and `recv`,
//! `uname` under `PER_LINUX32` (`COMPAT_UTS_MACHINE`), and `CLONE_SETTLS`'s
//! thread ID register.

use super::super::harness::Harness;
use super::{get, put, u32_at, words};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::syscall::thread::cf::*;

const O_RDWR: u64 = 2;
const AT_FDCWD: u64 = -100i32 as u32 as u64;

fn u64_at(h: &Harness, at: u64) -> u64 {
    u64::from_le_bytes(get(h, at, 8).try_into().unwrap())
}

/// A guest path of a host file of `len` bytes, open read-write.
fn file(h: &mut Harness, name: &str, len: usize) -> (u64, u64) {
    let fd = h.file(name, len, b'x', O_RDWR);
    // Harness::file leaves the path at the scratch page's start; keep it.
    let path = h.scratch + 0xE00;
    let bytes = get(h, h.scratch, 0x200);
    put(h, path, &bytes);
    (fd, path)
}

#[test]
fn the_aarch32_wrappers_take_64_bit_arguments_in_register_pairs() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let (fd, path) = file(&mut h, "pairs", 32);
    let buf = h.scratch + 0x400;
    put(&h, buf, b"XYZ");
    // pread64/pwrite64 (fd, buf, count, pad, lo, hi).
    assert_eq!(h.call(Sysno::Pwrite64, &[fd, buf, 3, 0xDEAD, 4, 0]), 3);
    assert_eq!(h.call(Sysno::Pread64, &[fd, buf + 8, 3, 0xDEAD, 4, 0]), 3);
    assert_eq!(get(&h, buf + 8, 3), b"XYZ");
    assert_eq!(
        h.call(Sysno::Pread64, &[fd, buf + 8, 3, 0, 4, 1]),
        0,
        "4 GiB on"
    );
    assert_eq!(
        h.err(Sysno::Pread64, &[fd, buf, 3, 0, 0, 0x8000_0000]),
        EINVAL
    );
    // truncate64/ftruncate64 (path or fd, pad, lo, hi).
    assert_eq!(h.call(Sysno::Truncate64, &[path, 0xDEAD, 10, 0]), 0);
    let size = |h: &mut Harness| h.call(Sysno::Llseek, &[fd, 0, 0, h.scratch + 0x300, 2]);
    let _ = size(&mut h);
    assert_eq!(u64_at(&h, h.scratch + 0x300), 10);
    assert_eq!(h.call(Sysno::Ftruncate64, &[fd, 0xDEAD, 5, 0]), 0);
    let _ = size(&mut h);
    assert_eq!(u64_at(&h, h.scratch + 0x300), 5);
    assert_eq!(h.err(Sysno::Ftruncate64, &[fd, 0, 0, 0x8000_0000]), EINVAL);
    // readahead (fd, pad, lo, hi, count).
    assert_eq!(h.call(Sysno::Readahead, &[fd, 0xDEAD, 0, 0, 4096]), 0);
    // arm_fadvise64_64 (fd, advice, offset lo/hi, len lo/hi).
    assert_eq!(h.call(Sysno::ArmFadvise6464, &[fd, 0, 0, 0, 16, 0]), 0);
    assert_eq!(h.err(Sysno::ArmFadvise6464, &[fd, 99, 0, 0, 16, 0]), EINVAL);
    let neg = u64::from(u32::MAX);
    assert_eq!(
        h.err(Sysno::ArmFadvise6464, &[fd, 0, 0, 0, neg, neg]),
        EINVAL
    );
    // arm_sync_file_range (fd, flags, offset lo/hi, nbytes lo/hi).
    assert_eq!(h.call(Sysno::ArmSyncFileRange, &[fd, 1, 0, 0, 16, 0]), 0);
    assert_eq!(
        h.err(Sysno::ArmSyncFileRange, &[fd, 8, 0, 0, 16, 0]),
        EINVAL
    );
    assert_eq!(
        h.err(Sysno::ArmSyncFileRange, &[fd, 1, 0, 0x8000_0000, 16, 0]),
        EINVAL
    );
}

#[test]
fn stat64_is_the_eabi_layout_written_whole() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let (fd, path) = file(&mut h, "stat64", 32);
    let buf = h.scratch + 0x400;
    for (s, args) in [
        (Sysno::Fstat64, [fd, buf, 0, 0]),
        (Sysno::Stat64, [path, buf, 0, 0]),
        (Sysno::Fstatat64, [AT_FDCWD, path, buf, 0]),
    ] {
        put(&h, buf, &[0xEE; 120]);
        assert_eq!(h.call(s, &args), 0, "{s:?}");
        // st_mode at 16 (a regular file), st_size at 48, st_blocks at 64,
        // st_ino at 96 with its low half in __st_ino at 12.
        assert_eq!(u32_at(&h, buf + 16) & 0o170000, 0o100000, "{s:?}");
        assert_eq!(u64_at(&h, buf + 48), 32, "{s:?}");
        assert_eq!(u64_at(&h, buf + 96) as u32, u32_at(&h, buf + 12));
        // __pad0, __pad3 and the alignment after it, and the padding
        // after st_blksize are zero; nothing past the 104 bytes is written.
        for (at, len) in [(8, 4), (40, 8), (60, 4)] {
            assert_eq!(get(&h, buf + at, len), vec![0; len], "{s:?} +{at}");
        }
        assert_eq!(get(&h, buf + 104, 16), [0xEE; 16]);
    }
    // fstat is struct compat_stat (64 bytes, i386's layout): st_size at 20.
    put(&h, buf, &[0xEE; 72]);
    assert_eq!(h.call(Sysno::Fstat, &[fd, buf]), 0);
    assert_eq!(u32_at(&h, buf + 20), 32);
    assert_eq!(get(&h, buf + 64, 8), [0xEE; 8]);
}

#[test]
fn fcntl64_locks_are_the_aligned_compat_flock64() {
    const F_GETLK64: u64 = 12;
    const F_SETLK64: u64 = 13;
    let mut h = Harness::new(LinuxAbi::Arm);
    let (fd, _) = file(&mut h, "flock64", 64);
    let lk = h.scratch + 0x400;
    // l_type, l_whence, then l_start at 8, l_len at 16, l_pid at 24.
    let flock = |kind: u16, start: u64, len: u64| {
        let mut b = vec![0xEEu8; 40];
        b[..2].copy_from_slice(&kind.to_le_bytes());
        b[2..4].copy_from_slice(&0u16.to_le_bytes());
        b[8..16].copy_from_slice(&start.to_le_bytes());
        b[16..24].copy_from_slice(&len.to_le_bytes());
        b[24..28].copy_from_slice(&0u32.to_le_bytes());
        b
    };
    put(&h, lk, &flock(1, 0x1_0000_0000, 16));
    assert_eq!(h.call(Sysno::Fcntl64, &[fd, F_SETLK64, lk]), 0);
    // One's own lock never conflicts: F_UNLCK, the rest of the request
    // echoed, the structure written whole (put_compat_flock64).
    put(&h, lk, &flock(0, 0x1_0000_0000, 16));
    assert_eq!(h.call(Sysno::Fcntl64, &[fd, F_GETLK64, lk]), 0);
    assert_eq!(u32_at(&h, lk) & 0xFFFF, 2, "F_UNLCK");
    assert_eq!(
        (u64_at(&h, lk + 8), u64_at(&h, lk + 16)),
        (0x1_0000_0000, 16)
    );
    assert_eq!((u32_at(&h, lk + 4), u32_at(&h, lk + 28)), (0, 0));
    assert_eq!(get(&h, lk + 32, 8), [0xEE; 8]);
    // A negative start is EINVAL: it is read at offset 8.
    put(&h, lk, &flock(1, u64::MAX, 16));
    assert_eq!(h.err(Sysno::Fcntl64, &[fd, F_SETLK64, lk]), EINVAL);
}

#[test]
fn statfs64_takes_the_eabi_size_88_as_84() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let (fd, path) = file(&mut h, "statfs64", 8);
    let buf = h.scratch + 0x400;
    for (s, a) in [(Sysno::Statfs64, path), (Sysno::Fstatfs64, fd)] {
        for size in [84, 88] {
            put(&h, buf, &[0xEE; 96]);
            assert_eq!(h.call(s, &[a, size, buf]), 0, "{s:?} {size}");
            assert_ne!(get(&h, buf, 4), [0xEE; 4]);
            assert_eq!(get(&h, buf + 84, 12), [0xEE; 12], "84 bytes written");
        }
        assert_eq!(h.err(s, &[a, 80, buf]), EINVAL);
    }
}

#[test]
fn system_v_ipc_has_direct_calls_and_the_old_ctl_forms() {
    const IPC_PRIVATE: u64 = 0;
    const IPC_NOWAIT: u16 = 0o4000;
    const IPC_STAT: u64 = 2;
    const IPC_64: u64 = 0x100;
    const GETVAL: u64 = 12;
    let mut h = Harness::new(LinuxAbi::Arm);
    let (sops, ts, buf) = (h.scratch + 0x400, h.scratch + 0x440, h.scratch + 0x500);
    let sembuf = |num: u16, op: i16, flg: u16| {
        [num.to_le_bytes(), op.to_le_bytes(), flg.to_le_bytes()].concat()
    };
    let id = h.ok(Sysno::Semget, &[IPC_PRIVATE, 1, 0o600]);
    // semop, direct.
    put(&h, sops, &sembuf(0, 1, 0));
    assert_eq!(h.call(Sysno::Semop, &[id, sops, 1]), 0);
    assert_eq!(h.call(Sysno::Semctl, &[id, 0, GETVAL, 0]), 1);
    // semtimedop takes a struct old_timespec32: {0, 10^9} is EINVAL, and
    // {0, 1000} times out (EAGAIN).
    put(&h, sops, &sembuf(0, -2, 0));
    put(&h, ts, &words(&[0, 1_000_000_000]));
    assert_eq!(h.err(Sysno::Semtimedop, &[id, sops, 1, ts]), EINVAL);
    put(&h, ts, &words(&[0, 1000]));
    assert_eq!(h.err(Sysno::Semtimedop, &[id, sops, 1, ts]), EAGAIN);
    put(&h, sops, &sembuf(0, -2, IPC_NOWAIT));
    assert_eq!(h.err(Sysno::Semop, &[id, sops, 1]), EAGAIN);
    // compat_sys_old_semctl: IPC_64 selects struct compat_semid64_ds (the
    // mode at 20, sem_nsems at 52), else struct compat_semid_ds (the mode
    // at 12, the 16-bit sem_nsems at 40).
    put(&h, buf, &[0xEE; 72]);
    assert_eq!(h.call(Sysno::Semctl, &[id, 0, IPC_STAT | IPC_64, buf]), 0);
    assert_eq!(
        (u32_at(&h, buf + 20) & 0xFFFF, u32_at(&h, buf + 52)),
        (0o600, 1)
    );
    put(&h, buf, &[0xEE; 72]);
    assert_eq!(h.call(Sysno::Semctl, &[id, 0, IPC_STAT, buf]), 0);
    assert_eq!(
        (u32_at(&h, buf + 12) & 0xFFFF, u32_at(&h, buf + 40) & 0xFFFF),
        (0o600, 1)
    );
    assert_eq!(get(&h, buf + 44, 8), [0xEE; 8]);
    // compat_sys_old_msgctl and compat_sys_old_shmctl parse IPC_64 too
    // (i386's direct shmctl takes it as part of the command: EINVAL).
    let mid = h.ok(Sysno::Msgget, &[IPC_PRIVATE, 0o600]);
    assert_eq!(h.call(Sysno::Msgctl, &[mid, IPC_STAT | IPC_64, buf]), 0);
    let sid = h.ok(Sysno::Shmget, &[IPC_PRIVATE, 4096, 0o600]);
    assert_eq!(h.call(Sysno::Shmctl, &[sid, IPC_STAT | IPC_64, buf]), 0);
    // shm_segsz follows the 36-byte struct compat_ipc64_perm.
    assert_eq!(u32_at(&h, buf + 36), 4096, "shm_segsz of compat_shmid64_ds");
}

/// A free, 64 KiB-aligned 64 KiB window of a compatibility task
/// (`mmap2`, then `munmap`).
fn window(h: &mut Harness) -> u64 {
    const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;
    let hole = h.ok(
        Sysno::Mmap2,
        &[
            0,
            0x2_0000,
            3,
            MAP_PRIVATE_ANONYMOUS,
            u64::from(u32::MAX),
            0,
        ],
    );
    h.ok(Sysno::Munmap, &[hole, 0x2_0000]);
    (hole + 0xFFFF) & !0xFFFF
}

#[test]
fn shmat_aligns_to_the_compat_shmlba_of_16_kib() {
    const SHM_RND: u64 = 0o20000;
    let mut h = Harness::new(LinuxAbi::Arm);
    let id = h.ok(Sysno::Shmget, &[0, 4096, 0o600]);
    let base = window(&mut h);
    // Page-aligned but not 16 KiB-aligned: attached there without SHM_RND
    // (no __ARCH_FORCE_SHMLBA on arm64).
    assert_eq!(h.ok(Sysno::Shmat, &[id, base + 4096, 0]), base + 4096);
    h.ok(Sysno::Shmdt, &[base + 4096]);
    // SHM_RND rounds down to 16 KiB, not to the page.
    assert_eq!(h.ok(Sysno::Shmat, &[id, base + 4096 + 1, SHM_RND]), base);
    h.ok(Sysno::Shmdt, &[base]);
    assert_eq!(h.err(Sysno::Shmat, &[id, base + 1, 0]), EINVAL);
    // An i386 task's SHMLBA is the page.
    let mut i = Harness::new(LinuxAbi::I386);
    let id = i.ok(Sysno::Shmget, &[0, 4096, 0o600]);
    let base = window(&mut i);
    assert_eq!(
        i.ok(Sysno::Shmat, &[id, base + 4096 + 1, SHM_RND]),
        base + 4096
    );
}

#[test]
fn accept_send_and_recv_are_direct_calls() {
    const AF_UNIX: u64 = 1;
    const SOCK_STREAM: u64 = 1;
    let mut h = Harness::new(LinuxAbi::Arm);
    let fds = h.scratch + 0x400;
    h.ok(Sysno::Socketpair, &[AF_UNIX, SOCK_STREAM, 0, fds]);
    let (a, b) = (u64::from(u32_at(&h, fds)), u64::from(u32_at(&h, fds + 4)));
    let buf = h.scratch + 0x500;
    put(&h, buf, b"arm");
    assert_eq!(h.call(Sysno::Send, &[a, buf, 3, 0]), 3);
    assert_eq!(h.call(Sysno::Recv, &[b, buf + 16, 16, 0]), 3);
    assert_eq!(get(&h, buf + 16, 3), b"arm");
    // accept: a connected socket is not listening (EINVAL); a file is not
    // a socket.
    assert_eq!(h.err(Sysno::Accept, &[a, 0, 0]), EINVAL);
    let (fd, _) = file(&mut h, "accept", 1);
    assert_eq!(h.err(Sysno::Accept, &[fd, 0, 0]), ENOTSOCK);
}

#[test]
fn uname_shows_armv8l_under_per_linux32() {
    const PER_LINUX32: u64 = 8;
    for abi in [LinuxAbi::Arm, LinuxAbi::Aarch64] {
        let mut h = Harness::new(abi);
        let buf = h.scratch + 0x400;
        let machine = |h: &mut Harness| {
            h.ok(Sysno::Uname, &[buf]);
            let b = get(h, buf + 4 * 65, 65);
            String::from_utf8(b[..b.iter().position(|&c| c == 0).unwrap()].to_vec()).unwrap()
        };
        assert_eq!(machine(&mut h), "aarch64", "{abi:?}");
        h.ok(Sysno::Personality, &[PER_LINUX32]);
        assert_eq!(machine(&mut h), "armv8l", "{abi:?}");
    }
}

#[test]
fn clone_settls_sets_tpidruro_and_keeps_the_arguments_backwards() {
    const THREAD: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
    let mut h = Harness::new(LinuxAbi::Arm);
    h.proc.threads[0].cpu.set_thread_pointer(0x1000);
    // (flags, newsp, parent_tid, tls, child_tid): the TLS value is r3.
    let flags = THREAD | CLONE_SETTLS;
    let tid = h.ok(Sysno::Clone, &[flags, 0, 0, 0xABCD_0000, 0x1234]) as i32;
    let w = h.index_of(tid);
    assert_eq!(h.proc.threads[w].cpu.thread_pointer(), 0xABCD_0000);
    assert_eq!(h.proc.threads[0].cpu.thread_pointer(), 0x1000);
    // clone3's tls too.
    let args = h.scratch + 0x500;
    let b: Vec<u8> = [THREAD | CLONE_SETTLS, 0, 0, 0, 0, 0, 0, 0x5000]
        .iter()
        .flat_map(|v: &u64| v.to_le_bytes())
        .collect();
    put(&h, args, &b);
    let tid = h.ok(Sysno::Clone3, &[args, 64]) as i32;
    assert_eq!(h.proc.threads[h.index_of(tid)].cpu.thread_pointer(), 0x5000);
}
