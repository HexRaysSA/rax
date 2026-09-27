//! i386 System V IPC against Linux 6.19 on x86-64 (`ipc/syscall.c`'s
//! `compat_ksys_ipc`, `ipc/compat.c`, and the `CONFIG_COMPAT` parts of
//! `ipc/sem.c`, `ipc/msg.c`, and `ipc/shm.c`): the `ipc` multiplexer with
//! and without `IPC_64`, the direct calls' `*64` structures and whole
//! commands, 32-bit message types, 16-bit IDs in the old permissions, and
//! `struct old_timespec32` timeouts.

use super::super::harness::Harness;
use super::{put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const IPC_PRIVATE: u64 = 0;
const IPC_NOWAIT: u64 = 0o4000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const IPC_64: u64 = 0x100;
const GETVAL: u64 = 12;
const SETVAL: u64 = 16;
const SEM_INFO: u64 = 19;
const SHM_INFO: u64 = 14;
/// The `ipc` multiplexer's operations.
const SEMOP: u64 = 1;
const SEMGET: u64 = 2;
const SEMCTL: u64 = 3;
const SEMTIMEDOP: u64 = 4;
const MSGSND: u64 = 11;
const MSGRCV: u64 = 12;
const MSGCTL: u64 = 14;
const SHMAT: u64 = 21;
const SHMDT: u64 = 22;
const SHMGET: u64 = 23;
const SHMCTL: u64 = 24;
/// An operation's version, in `call`'s high 16 bits.
const VERSION_1: u64 = 1 << 16;

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn read(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn u16_at(h: &Harness, at: u64) -> u16 {
    let b = read(h, at, 2);
    u16::from_le_bytes([b[0], b[1]])
}

#[test]
fn ipc_semctl_selects_the_layout_by_ipc_64() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (arg, buf) = (h.scratch, h.scratch + 0x100);
    let id = h.ok(Sysno::Ipc, &[SEMGET, IPC_PRIVATE, 3, 0o600]);
    // SETVAL's value is the union's word.
    put(&h, arg, &7u32.to_le_bytes());
    assert_eq!(h.call(Sysno::Ipc, &[SEMCTL, id, 1, SETVAL, arg, 0]), 0);
    assert_eq!(h.call(Sysno::Ipc, &[SEMCTL, id, 1, GETVAL, arg, 0]), 7);
    // IPC_STAT | IPC_64: struct compat_semid64_ds (64 bytes), the mode at
    // 20 and sem_nsems at 52.
    put(&h, arg, &(buf as u32).to_le_bytes());
    put(&h, buf, &[0xEE; 72]);
    let stat64 = IPC_STAT | IPC_64;
    assert_eq!(h.call(Sysno::Ipc, &[SEMCTL, id, 0, stat64, arg, 0]), 0);
    assert_eq!((u16_at(&h, buf + 20), u32_at(&h, buf + 52)), (0o600, 3));
    assert_eq!(read(&h, buf + 64, 8), [0xEE; 8]);
    // Without it: struct compat_semid_ds (44 bytes), the mode at 12 and
    // the 16-bit sem_nsems at 40.
    put(&h, buf, &[0xEE; 72]);
    assert_eq!(h.call(Sysno::Ipc, &[SEMCTL, id, 0, IPC_STAT, arg, 0]), 0);
    assert_eq!((u16_at(&h, buf + 12), u16_at(&h, buf + 40)), (0o600, 3));
    assert_eq!(read(&h, buf + 44, 8), [0xEE; 8]);
    // The union's word is read first, and there must be one.
    assert_eq!(h.err(Sysno::Ipc, &[SEMCTL, id, 0, IPC_STAT, 0, 0]), EINVAL);
    assert_eq!(
        h.err(Sysno::Ipc, &[SEMCTL, id, 0, IPC_STAT, 0x10, 0]),
        EFAULT
    );
    // An unknown operation.
    assert_eq!(h.err(Sysno::Ipc, &[99, 0, 0, 0, 0, 0]), ENOSYS);
}

#[test]
fn direct_semctl_hands_the_whole_command_on() {
    let mut h = Harness::new(LinuxAbi::I386);
    let buf = h.scratch;
    let id = h.ok(Sysno::Semget, &[IPC_PRIVATE, 2, 0o600]);
    // compat_sys_semctl always uses struct compat_semid64_ds;
    // IPC_STAT | IPC_64 finds the set as IPC_STAT does but returns its
    // identifier as SEM_STAT does.
    assert_eq!(h.call(Sysno::Semctl, &[id, 0, IPC_STAT, buf]), 0);
    assert_eq!(u32_at(&h, buf + 52), 2);
    assert_eq!(
        h.call(Sysno::Semctl, &[id, 0, IPC_STAT | IPC_64, buf]),
        id as i64
    );
    // semctl_setval takes no command; semctl_main refuses GETVAL | IPC_64
    // after checking the semaphore number.
    assert_eq!(h.call(Sysno::Semctl, &[id, 1, SETVAL | IPC_64, 9]), 0);
    assert_eq!(h.call(Sysno::Semctl, &[id, 1, GETVAL, 0]), 9);
    assert_eq!(h.err(Sysno::Semctl, &[id, 1, GETVAL | IPC_64, 0]), EINVAL);
    // SEM_INFO | IPC_64 is IPC_INFO to semctl_info: semaem is SEMAEM, not
    // the semaphores in use.
    assert!(h.call(Sysno::Semctl, &[0, 0, SEM_INFO, buf]) >= 0);
    assert_eq!(u32_at(&h, buf + 36), 2);
    assert!(h.call(Sysno::Semctl, &[0, 0, SEM_INFO | IPC_64, buf]) >= 0);
    assert_eq!(u32_at(&h, buf + 36), 32767);
    // semctl_down refuses IPC_RMID | IPC_64 after its lookup.
    assert_eq!(h.err(Sysno::Semctl, &[id, 0, IPC_RMID | IPC_64, 0]), EINVAL);
    assert_eq!(h.call(Sysno::Semctl, &[id, 0, IPC_RMID, 0]), 0);
    assert_eq!(h.err(Sysno::Semctl, &[id, 0, IPC_RMID | IPC_64, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Semctl, &[id, 0, IPC_STAT, buf]), EINVAL);
}

#[test]
fn old_permissions_hold_16_bit_ids() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (arg, ds) = (h.scratch, h.scratch + 0x100);
    let id = h.ok(Sysno::Semget, &[IPC_PRIVATE, 1, 0o600]);
    // The creator may give the set to user 70000 and still control it.
    assert_eq!(h.call(Sysno::Semctl, &[id, 0, IPC_STAT, ds]), 0);
    put(&h, ds + 4, &70000u32.to_le_bytes());
    assert_eq!(h.call(Sysno::Semctl, &[id, 0, IPC_SET, ds]), 0);
    // struct compat_ipc_perm shows it through high2lowuid.
    put(&h, arg, &(ds as u32).to_le_bytes());
    assert_eq!(h.call(Sysno::Ipc, &[SEMCTL, id, 0, IPC_STAT, arg, 0]), 0);
    assert_eq!(u16_at(&h, ds + 4), 65534);
    // An old IPC_SET's 0xFFFF is user 65535, not the invalid -1.
    put(&h, ds + 4, &0xFFFFu16.to_le_bytes());
    assert_eq!(h.call(Sysno::Ipc, &[SEMCTL, id, 0, IPC_SET, arg, 0]), 0);
    assert_eq!(h.call(Sysno::Semctl, &[id, 0, IPC_STAT, ds]), 0);
    assert_eq!(u32_at(&h, ds + 4), 65535);
    put(&h, ds + 4, &u32::MAX.to_le_bytes());
    assert_eq!(h.err(Sysno::Semctl, &[id, 0, IPC_SET, ds]), EINVAL);
}

#[test]
fn semop_timeouts_are_old_timespec32_through_ipc() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (sops, ts) = (h.scratch, h.scratch + 0x100);
    let id = h.ok(Sysno::Semget, &[IPC_PRIVATE, 1, 0o600]);
    // A decrement of a zero semaphore with IPC_NOWAIT: EAGAIN, once the
    // timeout is found valid.
    put(&h, sops, &[0, 0, 0xFF, 0xFF, 0x00, 0x08]);
    // SEMTIMEDOP reads { 5, 1000 }; a struct __kernel_timespec there would
    // be invalid.
    put(&h, ts, &words(&[5, 1000, 0x7FFF_FFFF, 0x7FFF_FFFF]));
    assert_eq!(h.err(Sysno::Ipc, &[SEMTIMEDOP, id, 1, 0, sops, ts]), EAGAIN);
    put(&h, ts, &words(&[0, 1_000_000_000]));
    assert_eq!(h.err(Sysno::Ipc, &[SEMTIMEDOP, id, 1, 0, sops, ts]), EINVAL);
    // semtimedop_time64 clears the padding above tv_nsec.
    put(&h, ts, &words(&[0, 0, 1000, 0xFFFF_FFFF]));
    assert_eq!(h.err(Sysno::SemtimedopTime64, &[id, sops, 1, ts]), EAGAIN);
    // SEMOP has no timeout.
    assert_eq!(h.err(Sysno::Ipc, &[SEMOP, id, 1, 0, sops, 0]), EAGAIN);
    put(&h, sops, &[0, 0, 1, 0, 0, 0]);
    assert_eq!(h.call(Sysno::Ipc, &[SEMOP, id, 1, 0, sops, 0]), 0);
}

#[test]
fn messages_have_32_bit_types() {
    let mut h = Harness::new(LinuxAbi::I386);
    let pid = h.proc.state.pid as u32;
    let m = h.scratch;
    let (msg, kludge, ds) = (m, m + 0x100, m + 0x200);
    let id = h.ok(Sysno::Msgget, &[IPC_PRIVATE, 0o600]);
    // struct compat_msgbuf: a 32-bit type, then the text.
    put(&h, msg, &[words(&[3]), b"abc".to_vec()].concat());
    assert_eq!(h.call(Sysno::Msgsnd, &[id, msg, 3, 0]), 0);
    put(&h, msg, &[words(&[5]), b"de".to_vec()].concat());
    assert_eq!(h.call(Sysno::Ipc, &[MSGSND, id, 2, 0, msg, 0]), 0);
    // A negative type, sign-extended: the lowest type up to 5.
    put(&h, msg, &[0xEE; 16]);
    let below5 = u64::from(-5i32 as u32);
    assert_eq!(h.call(Sysno::Msgrcv, &[id, msg, 8, below5, IPC_NOWAIT]), 3);
    assert_eq!(
        read(&h, msg, 8),
        [words(&[3]), b"abc".to_vec(), vec![0xEE]].concat()
    );
    // MSGRCV's version 0 reads struct compat_ipc_kludge { msgp, msgtyp }.
    put(&h, kludge, &words(&[msg as u32, 5]));
    assert_eq!(
        h.call(Sysno::Ipc, &[MSGRCV, id, 8, IPC_NOWAIT, kludge, 0]),
        2
    );
    assert_eq!(read(&h, msg, 6), [words(&[5]), b"de".to_vec()].concat());
    // Version 1 takes them as arguments; a negative size is EINVAL.
    let rcv1 = MSGRCV | VERSION_1;
    assert_eq!(
        h.err(Sysno::Ipc, &[rcv1, id, 8, IPC_NOWAIT, msg, 5]),
        ENOMSG
    );
    let huge = u64::from(u32::MAX);
    assert_eq!(h.err(Sysno::Ipc, &[MSGRCV, id, huge, 0, kludge, 0]), EINVAL);
    assert_eq!(
        h.err(Sysno::Msgrcv, &[id, msg, huge, 0, IPC_NOWAIT]),
        EINVAL
    );
    assert_eq!(
        h.err(Sysno::Ipc, &[MSGRCV, id, 8, IPC_NOWAIT, 0, 0]),
        EINVAL
    );
    // struct compat_msqid64_ds from the direct call.
    assert_eq!(h.call(Sysno::Msgsnd, &[id, msg, 2, 0]), 0);
    assert_eq!(h.call(Sysno::Msgctl, &[id, IPC_STAT, ds]), 0);
    assert_eq!(
        (
            u32_at(&h, ds + 60),
            u32_at(&h, ds + 64),
            u32_at(&h, ds + 68),
            u32_at(&h, ds + 72)
        ),
        (2, 1, 16384, pid)
    );
    // struct compat_msqid_ds through ipc without IPC_64: 16-bit fields.
    put(&h, ds, &[0xEE; 96]);
    assert_eq!(h.call(Sysno::Ipc, &[MSGCTL, id, IPC_STAT, 0, ds, 0]), 0);
    assert_eq!(
        (
            u16_at(&h, ds + 44),
            u16_at(&h, ds + 46),
            u16_at(&h, ds + 48),
            u16_at(&h, ds + 50)
        ),
        (2, 1, 16384, pid as u16)
    );
    assert_eq!(read(&h, ds + 56, 4), [0xEE; 4]);
    // Its IPC_SET reads the 16-bit msg_qbytes.
    put(&h, ds + 48, &100u16.to_le_bytes());
    assert_eq!(h.call(Sysno::Ipc, &[MSGCTL, id, IPC_SET, 0, ds, 0]), 0);
    assert_eq!(h.call(Sysno::Msgctl, &[id, IPC_STAT, ds]), 0);
    assert_eq!(u32_at(&h, ds + 68), 100);
    // The direct call passes IPC_STAT | IPC_64 on whole.
    assert_eq!(
        h.call(Sysno::Msgctl, &[id, IPC_STAT | IPC_64, ds]),
        id as i64
    );
    assert_eq!(h.err(Sysno::Msgctl, &[id, IPC_SET | IPC_64, ds]), EINVAL);
    assert_eq!(h.call(Sysno::Msgctl, &[id, IPC_RMID, 0]), 0);
}

#[test]
fn shm_attach_and_status_use_32_bit_layouts() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (raddr, ds) = (h.scratch, h.scratch + 0x100);
    let id = h.ok(Sysno::Ipc, &[SHMGET, IPC_PRIVATE, 5000, 0o600, 0, 0]);
    // SHMAT stores the address in a compat_ulong_t at `third`; version 1
    // is EINVAL.
    assert_eq!(h.call(Sysno::Ipc, &[SHMAT, id, 0, raddr, 0, 0]), 0);
    let at = u64::from(u32_at(&h, raddr));
    assert!(at != 0);
    assert_eq!(
        h.err(Sysno::Ipc, &[SHMAT | VERSION_1, id, 0, raddr, 0, 0]),
        EINVAL
    );
    // struct compat_shmid64_ds: shm_segsz at 36, shm_nattch at 72.
    assert_eq!(h.call(Sysno::Shmctl, &[id, IPC_STAT, ds]), 0);
    assert_eq!((u32_at(&h, ds + 36), u32_at(&h, ds + 72)), (5000, 1));
    // struct compat_shmid_ds through ipc without IPC_64.
    put(&h, ds, &[0xEE; 96]);
    assert_eq!(h.call(Sysno::Ipc, &[SHMCTL, id, IPC_STAT, 0, ds, 0]), 0);
    assert_eq!((u32_at(&h, ds + 16), u16_at(&h, ds + 36)), (5000, 1));
    assert_eq!(read(&h, ds + 48, 4), [0xEE; 4]);
    // compat_ksys_shmctl compares the command whole.
    assert_eq!(h.err(Sysno::Shmctl, &[id, IPC_STAT | IPC_64, ds]), EINVAL);
    // IPC_INFO: struct compat_shminfo64 or struct shminfo, shmmax capped
    // at INT_MAX.
    put(&h, ds, &[0xEE; 48]);
    assert!(h.call(Sysno::Shmctl, &[0, IPC_INFO, ds]) >= 0);
    assert_eq!(u32_at(&h, ds), i32::MAX as u32);
    assert_eq!(read(&h, ds + 36, 4), [0xEE; 4]);
    put(&h, ds, &[0xEE; 48]);
    assert!(h.call(Sysno::Ipc, &[SHMCTL, 0, IPC_INFO, 0, ds, 0]) >= 0);
    assert_eq!(u32_at(&h, ds), i32::MAX as u32);
    assert_eq!(read(&h, ds + 20, 4), [0xEE; 4]);
    // SHM_INFO: struct compat_shm_info, 24 bytes.
    put(&h, ds, &[0xEE; 48]);
    assert!(h.call(Sysno::Shmctl, &[0, SHM_INFO, ds]) >= 0);
    assert_eq!((u32_at(&h, ds), u32_at(&h, ds + 4)), (1, 2));
    assert_eq!(read(&h, ds + 24, 4), [0xEE; 4]);
    // Attaches end through ipc's SHMDT, and under a mapping (mmap2) over
    // them.
    assert_eq!(h.call(Sysno::Ipc, &[SHMDT, 0, 0, 0, at, 0]), 0);
    assert_eq!(h.call(Sysno::Shmctl, &[id, IPC_STAT, ds]), 0);
    assert_eq!(u32_at(&h, ds + 72), 0);
    let at = h.ok(Sysno::Shmat, &[id, 0, 0]);
    assert_eq!(h.call(Sysno::Shmctl, &[id, IPC_STAT, ds]), 0);
    assert_eq!(u32_at(&h, ds + 72), 1);
    let anon_fixed = 0x32;
    let no_fd = u64::from(u32::MAX);
    h.ok(Sysno::Mmap2, &[at, 8192, 3, anon_fixed, no_fd, 0]);
    assert_eq!(h.call(Sysno::Shmctl, &[id, IPC_STAT, ds]), 0);
    assert_eq!(u32_at(&h, ds + 72), 0);
    assert_eq!(h.call(Sysno::Shmctl, &[id, IPC_RMID, 0]), 0);
}
