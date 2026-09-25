//! System V semaphores against `ipc/sem.c` (Linux 6.19), through the
//! system calls on every ABI: `semget`, `semctl` (values, status in each
//! ABI's layout, limits), `semop`/`semtimedop` (all or nothing, the
//! argument checks in order, timeouts), waiting (counted by `GETNCNT`,
//! ended by the value, a removal, or a signal), and `SEM_UNDO` at exit.

use std::time::{Duration, Instant};

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::*;
use crate::user::linux::syscall::thread::cf::*;

const IPC_PRIVATE: u64 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_NOWAIT: i16 = 0o4000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const GETPID: u64 = 11;
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const GETNCNT: u64 = 14;
const GETZCNT: u64 = 15;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;
const SEM_STAT: u64 = 18;
const SEM_INFO: u64 = 19;
const SEM_UNDO: i16 = 0x1000;
const THREAD: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

/// `struct sembuf`s at `at`.
fn sembufs(h: &Harness, at: u64, ops: &[(u16, i16, i16)]) -> u64 {
    let b: Vec<u8> = ops
        .iter()
        .flat_map(|&(n, o, f)| {
            let mut v = n.to_le_bytes().to_vec();
            v.extend_from_slice(&o.to_le_bytes());
            v.extend_from_slice(&f.to_le_bytes());
            v
        })
        .collect();
    put(h, at, &b);
    ops.len() as u64
}

fn semctl(h: &mut Harness, id: u64, num: u64, cmd: u64, arg: u64) -> i64 {
    h.call(Sysno::Semctl, &[id, num, cmd, arg])
}

/// A thread of thread 0: its list index.
fn spawn(h: &mut Harness) -> usize {
    // No stack, TID words, or TLS: the same arguments on every ABI.
    let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
    h.index_of(tid)
}

#[test]
fn semctl_follows_ksys_semctl() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        assert_eq!(h.err(Sysno::Semget, &[IPC_PRIVATE, 0, 0o600]), EINVAL);
        assert_eq!(h.err(Sysno::Semget, &[IPC_PRIVATE, 32001, 0o600]), EINVAL);
        assert_eq!(
            h.err(Sysno::Semget, &[IPC_PRIVATE, u32::MAX as u64, 0o600]),
            EINVAL
        );
        let id = h.ok(Sysno::Semget, &[99, 3, IPC_CREAT | 0o600]);
        assert_eq!(h.call(Sysno::Semget, &[99, 2, 0]), id as i64);
        assert_eq!(h.err(Sysno::Semget, &[99, 4, 0]), EINVAL);
        // Values.
        assert_eq!(semctl(&mut h, id, 1, SETVAL, 7), 0);
        assert_eq!(semctl(&mut h, id, 1, GETVAL, 0), 7);
        assert_eq!(semctl(&mut h, id, 1, GETPID, 0), h.proc.state.pid as i64);
        assert_eq!(semctl(&mut h, id, 3, GETVAL, 0), -(EINVAL as i64));
        assert_eq!(semctl(&mut h, id, 0, SETVAL, 32768), -(ERANGE as i64));
        assert_eq!(
            semctl(&mut h, id, 0, SETVAL, u32::MAX as u64),
            -(ERANGE as i64)
        );
        put(&h, m, &[1, 0, 2, 0, 3, 0]);
        assert_eq!(semctl(&mut h, id, 0, SETALL, m), 0);
        put(&h, m, &[0; 6]);
        assert_eq!(semctl(&mut h, id, 0, GETALL, m), 0);
        assert_eq!(get(&h, m, 6), [1, 0, 2, 0, 3, 0]);
        put(&h, m, &[0, 0x80, 0, 0, 0, 0]);
        assert_eq!(semctl(&mut h, id, 0, SETALL, m), -(ERANGE as i64));
        assert_eq!(semctl(&mut h, id, 0, GETALL, 8), -(EFAULT as i64));
        assert_eq!(semctl(&mut h, id, 0, GETNCNT, 0), 0);
        assert_eq!(semctl(&mut h, id, 0, GETZCNT, 0), 0);
        // Status, in each ABI's layout.
        assert_eq!(semctl(&mut h, id, 0, IPC_STAT, m), 0);
        let nsems_at = if abi == LinuxAbi::X86_64 { 80 } else { 64 };
        let ds = get(&h, m, 104);
        assert_eq!(
            u64::from_le_bytes(ds[nsems_at..nsems_at + 8].try_into().unwrap()),
            3
        );
        assert_eq!(i32::from_le_bytes(ds[..4].try_into().unwrap()), 99);
        assert_eq!(semctl(&mut h, 0, 0, SEM_STAT, m), id as i64);
        assert!(semctl(&mut h, 0, 0, IPC_INFO, m) >= 0);
        let info = get(&h, m, 40);
        assert_eq!(
            i32::from_le_bytes(info[16..20].try_into().unwrap()),
            32000,
            "semmsl"
        );
        assert_eq!(
            i32::from_le_bytes(info[20..24].try_into().unwrap()),
            500,
            "semopm"
        );
        assert!(semctl(&mut h, 0, 0, SEM_INFO, m) >= 0);
        assert_eq!(
            i32::from_le_bytes(get(&h, m + 28, 4).try_into().unwrap()),
            1,
            "semusz"
        );
        // IPC_SET.
        let len = if abi == LinuxAbi::X86_64 { 104 } else { 88 };
        semctl(&mut h, id, 0, IPC_STAT, m);
        let mut ds = get(&h, m, len);
        ds[20..24].copy_from_slice(&0o640u32.to_le_bytes());
        put(&h, m, &ds);
        assert_eq!(semctl(&mut h, id, 0, IPC_SET, m), 0);
        semctl(&mut h, id, 0, IPC_STAT, m);
        assert_eq!(
            u32::from_le_bytes(get(&h, m + 20, 4).try_into().unwrap()),
            0o640
        );
        assert_eq!(semctl(&mut h, id, 0, 99, m), -(EINVAL as i64));
        assert_eq!(
            semctl(&mut h, u32::MAX as u64, 0, IPC_STAT, m),
            -(EINVAL as i64)
        );
        assert_eq!(semctl(&mut h, id, 0, IPC_RMID, 0), 0);
        assert_eq!(semctl(&mut h, id, 0, GETVAL, 0), -(EINVAL as i64));
    });
}

#[test]
fn semop_follows_do_semtimedop() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        let id = h.ok(Sysno::Semget, &[IPC_PRIVATE, 2, 0o600]);
        // All or nothing.
        let n = sembufs(&h, m, &[(0, 1, 0), (1, -1, IPC_NOWAIT)]);
        assert_eq!(h.err(Sysno::Semop, &[id, m, n]), EAGAIN);
        assert_eq!(semctl(&mut h, id, 0, GETVAL, 0), 0);
        let n = sembufs(&h, m, &[(0, 2, SEM_UNDO), (0, -1, 0), (1, 5, 0)]);
        assert_eq!(h.call(Sysno::Semop, &[id, m, n]), 0);
        assert_eq!(semctl(&mut h, id, 0, GETVAL, 0), 1);
        // The checks, in order.
        assert_eq!(h.err(Sysno::Semop, &[id, m, 501]), E2BIG);
        assert_eq!(h.err(Sysno::Semop, &[id, m, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Semop, &[id, 8, 1]), EFAULT);
        assert_eq!(h.err(Sysno::Semop, &[u32::MAX as u64, m, 1]), EINVAL);
        let n = sembufs(&h, m, &[(2, 1, 0)]);
        assert_eq!(h.err(Sysno::Semop, &[id, m, n]), EFBIG);
        let n = sembufs(&h, m, &[(1, 32767, 0)]);
        assert_eq!(h.err(Sysno::Semop, &[id, m, n]), ERANGE);
        // A timeout: its copy first, its value after the operations'.
        let n = sembufs(&h, m, &[(0, -5, 0)]);
        assert_eq!(h.err(Sysno::Semtimedop, &[id, m, n, 8]), EFAULT);
        let ts = m + 0x100;
        put(&h, ts, &[0u8; 8]);
        put(&h, ts + 8, &(-1i64).to_le_bytes());
        assert_eq!(h.err(Sysno::Semtimedop, &[id, m, n, ts]), EINVAL);
        put(&h, ts + 8, &30_000_000i64.to_le_bytes());
        let t = Instant::now();
        assert_eq!(h.err(Sysno::Semtimedop, &[id, m, n, ts]), EAGAIN);
        assert!(t.elapsed() >= Duration::from_millis(30));
        assert_eq!(semctl(&mut h, id, 0, GETNCNT, 0), 0);
        // SEM_UNDO at exit (exit_sem): +2 undone.
        crate::user::linux::syscall::ipc::exit(&mut h.proc.state);
        assert_eq!(semctl(&mut h, id, 0, GETVAL, 0), 0);
    });
}

#[test]
fn waits_end_by_value_removal_or_signal() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        let w = spawn(&mut h);
        let id = h.ok(Sysno::Semget, &[IPC_PRIVATE, 1, 0o600]);
        let n = sembufs(&h, m, &[(0, -1, 0)]);
        // A decrement waits, counted by GETNCNT; a value ends it.
        assert_eq!(h.start(w, Sysno::Semop, &[id, m, n]), None);
        assert_eq!(semctl(&mut h, id, 0, GETNCNT, 0), 1);
        assert_eq!(semctl(&mut h, id, 0, SETVAL, 1), 0);
        std::thread::sleep(Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), 0);
        assert_eq!(semctl(&mut h, id, 0, GETVAL, 0), 0);
        assert_eq!(semctl(&mut h, id, 0, GETNCNT, 0), 0);
        // A wait for zero, counted by GETZCNT; removal ends it (EIDRM).
        semctl(&mut h, id, 0, SETVAL, 2);
        let z = sembufs(&h, m + 0x80, &[(0, 0, 0)]);
        assert_eq!(h.start(w, Sysno::Semop, &[id, m + 0x80, z]), None);
        assert_eq!(semctl(&mut h, id, 0, GETZCNT, 0), 1);
        assert_eq!(semctl(&mut h, id, 0, IPC_RMID, 0), 0);
        std::thread::sleep(Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), -(EIDRM as i64));
        // A signal ends a wait with EINTR, never restarted.
        let id = h.ok(Sysno::Semget, &[IPC_PRIVATE, 1, 0o600]);
        assert_eq!(h.start(w, Sysno::Semop, &[id, m, n]), None);
        let tid = h.proc.threads[w].tid as u64;
        let act = m + 0x200;
        let mut words = vec![0x40_1000u64];
        if h.abi().has_sa_restorer() {
            words.extend([sa::RESTORER, 0x40_1100]);
        } else {
            words.push(0);
        }
        words.push(0);
        let b: Vec<u8> = words.iter().flat_map(|x| x.to_le_bytes()).collect();
        put(&h, act, &b);
        h.ok(Sysno::RtSigaction, &[SIGUSR1 as u64, act, 0, 8]);
        h.ok(
            Sysno::Tgkill,
            &[h.proc.state.pid as u64, tid, SIGUSR1 as u64],
        );
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), -(EINTR as i64));
        assert_eq!(semctl(&mut h, id, 0, GETNCNT, 0), 0);
    });
}
