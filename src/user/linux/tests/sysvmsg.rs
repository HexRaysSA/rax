//! System V message queues against `ipc/msg.c` (Linux 6.19), through the
//! system calls on every ABI: `msgget`, `msgsnd` and `msgrcv` (their checks
//! in order, message types, `MSG_EXCEPT`, `MSG_NOERROR`, `E2BIG`, a full
//! queue), waiting receivers (ended by a message, a removal, or a signal),
//! and `msgctl`.

use std::time::Duration;

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::signal::deliver::restart::ERESTARTNOHAND;
use crate::user::linux::signal::*;
use crate::user::linux::syscall::thread::cf::*;

const IPC_PRIVATE: u64 = 0;
const IPC_NOWAIT: u64 = 0o4000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const MSG_STAT: u64 = 11;
const MSG_INFO: u64 = 12;
const MSG_NOERROR: u64 = 0o10000;
const MSG_EXCEPT: u64 = 0o20000;
const MSG_COPY: u64 = 0o40000;
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

/// A `struct msgbuf` of `mtype` and `text` at `at`.
fn msgbuf(h: &Harness, at: u64, mtype: i64, text: &[u8]) {
    let mut b = mtype.to_le_bytes().to_vec();
    b.extend_from_slice(text);
    put(h, at, &b);
}

/// Receives into `at` with a buffer of `size`: the type and text.
fn rcv(
    h: &mut Harness,
    id: u64,
    at: u64,
    size: u64,
    typ: i64,
    flags: u64,
) -> Result<(i64, Vec<u8>), i32> {
    let r = h.call(Sysno::Msgrcv, &[id, at, size, typ as u64, flags]);
    if r < 0 {
        return Err(-r as i32);
    }
    let b = get(h, at, 8 + r as usize);
    Ok((
        i64::from_le_bytes(b[..8].try_into().unwrap()),
        b[8..].to_vec(),
    ))
}

fn root() -> bool {
    // SAFETY: geteuid has no failure mode.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn messages_follow_do_msgsnd_and_do_msgrcv() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(8 * P, 3, false);
        let id = h.ok(Sysno::Msgget, &[IPC_PRIVATE, 0o600]);
        // msgsnd's checks: the type's copy first, then size, id, and type.
        assert_eq!(h.err(Sysno::Msgsnd, &[id, 8, 1, 0]), EFAULT);
        msgbuf(&h, m, 0, b"x");
        assert_eq!(h.err(Sysno::Msgsnd, &[id, m, 1, 0]), EINVAL);
        msgbuf(&h, m, 1, b"x");
        assert_eq!(h.err(Sysno::Msgsnd, &[id, m, 8193, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Msgsnd, &[u32::MAX as u64, m, 1, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Msgsnd, &[id, m, 5 * P, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Msgsnd, &[id + 1, m, 1, 0]), EINVAL);
        for (t, s) in [(3i64, b"ccc"), (1, b"aaa"), (2, b"bbb"), (1, b"ddd")] {
            msgbuf(&h, m, t, s);
            assert_eq!(h.call(Sysno::Msgsnd, &[id, m, 3, 0]), 0);
        }
        let r = m + 0x2000;
        assert_eq!(rcv(&mut h, id, r, 16, -2, 0), Ok((1, b"aaa".to_vec())));
        assert_eq!(rcv(&mut h, id, r, 16, 2, 0), Ok((2, b"bbb".to_vec())));
        assert_eq!(
            rcv(&mut h, id, r, 16, 1, MSG_EXCEPT),
            Ok((3, b"ccc".to_vec()))
        );
        assert_eq!(rcv(&mut h, id, r, 16, 7, IPC_NOWAIT), Err(ENOMSG));
        // Too big: E2BIG, the message kept; cut with MSG_NOERROR.
        assert_eq!(rcv(&mut h, id, r, 2, 0, 0), Err(E2BIG));
        assert_eq!(
            rcv(&mut h, id, r, 2, 0, MSG_NOERROR),
            Ok((1, b"dd".to_vec()))
        );
        assert_eq!(h.err(Sysno::Msgrcv, &[id, r, u64::MAX, 0, 0]), EINVAL);
        // MSG_COPY (CONFIG_CHECKPOINT_RESTORE): its flags, then the copy
        // of the buffer (before the queue is looked up), then the message
        // at a position, left queued.
        const COPY: u64 = MSG_COPY | IPC_NOWAIT;
        assert_eq!(h.err(Sysno::Msgrcv, &[id, r, 16, 0, MSG_COPY]), EINVAL);
        assert_eq!(
            h.err(Sysno::Msgrcv, &[id, r, 16, 0, COPY | MSG_EXCEPT]),
            EINVAL
        );
        assert_eq!(h.err(Sysno::Msgrcv, &[id + 1, 8, 16, 0, COPY]), EFAULT);
        assert_eq!(h.err(Sysno::Msgrcv, &[id + 1, r, 16, 0, COPY]), EINVAL);
        assert_eq!(h.err(Sysno::Msgrcv, &[id, r, 16, 0, COPY]), ENOMSG);
        msgbuf(&h, m, 5, b"five");
        assert_eq!(h.call(Sysno::Msgsnd, &[id, m, 4, 0]), 0);
        msgbuf(&h, m, 6, b"sixth");
        assert_eq!(h.call(Sysno::Msgsnd, &[id, m, 5, 0]), 0);
        assert_eq!(
            rcv(&mut h, id, r, 16, 1, COPY as u64),
            Ok((6, b"sixth".to_vec()))
        );
        assert_eq!(
            rcv(&mut h, id, r, 16, 0, COPY as u64),
            Ok((5, b"five".to_vec()))
        );
        assert_eq!(rcv(&mut h, id, r, 16, 2, COPY as u64), Err(ENOMSG));
        assert_eq!(rcv(&mut h, id, r, 16, -1, COPY as u64), Err(ENOMSG));
        // Too big: E2BIG, and with MSG_NOERROR the copy's own EINVAL.
        assert_eq!(rcv(&mut h, id, r, 4, 1, COPY as u64), Err(E2BIG));
        assert_eq!(
            rcv(&mut h, id, r, 4, 1, COPY as u64 | MSG_NOERROR),
            Err(EINVAL)
        );
        assert_eq!(rcv(&mut h, id, r, 16, 0, 0), Ok((5, b"five".to_vec())));
        assert_eq!(rcv(&mut h, id, r, 16, 0, 0), Ok((6, b"sixth".to_vec())));
        // A full queue.
        msgbuf(&h, m, 1, &[7u8; 8192]);
        assert_eq!(h.call(Sysno::Msgsnd, &[id, m, 8192, 0]), 0);
        assert_eq!(h.call(Sysno::Msgsnd, &[id, m, 8192, 0]), 0);
        assert_eq!(h.err(Sysno::Msgsnd, &[id, m, 1, IPC_NOWAIT]), EAGAIN);
        // Status.
        let s = m + 0x4000;
        assert_eq!(h.call(Sysno::Msgctl, &[id, IPC_STAT, s]), 0);
        let ds = get(&h, s, 120);
        assert_eq!(
            u64::from_le_bytes(ds[72..80].try_into().unwrap()),
            16384,
            "msg_cbytes"
        );
        assert_eq!(
            u64::from_le_bytes(ds[80..88].try_into().unwrap()),
            2,
            "msg_qnum"
        );
        assert_eq!(
            u64::from_le_bytes(ds[88..96].try_into().unwrap()),
            16384,
            "msg_qbytes"
        );
        assert_eq!(
            i32::from_le_bytes(ds[96..100].try_into().unwrap()),
            h.proc.state.pid
        );
        assert_eq!(h.call(Sysno::Msgctl, &[0, MSG_STAT, s]), id as i64);
        assert!(h.call(Sysno::Msgctl, &[0, IPC_INFO, s]) >= 0);
        assert_eq!(
            i32::from_le_bytes(get(&h, s + 8, 4).try_into().unwrap()),
            8192,
            "msgmax"
        );
        assert!(h.call(Sysno::Msgctl, &[0, MSG_INFO, s]) >= 0);
        assert_eq!(
            i32::from_le_bytes(get(&h, s + 4, 4).try_into().unwrap()),
            2,
            "msgmap"
        );
        // IPC_SET: a bigger queue needs CAP_SYS_RESOURCE.
        h.call(Sysno::Msgctl, &[id, IPC_STAT, s]);
        put(&h, s + 88, &20000u64.to_le_bytes());
        if !root() {
            assert_eq!(h.err(Sysno::Msgctl, &[id, IPC_SET, s]), EPERM);
        }
        put(&h, s + 88, &100u64.to_le_bytes());
        assert_eq!(h.call(Sysno::Msgctl, &[id, IPC_SET, s]), 0);
        assert_eq!(h.err(Sysno::Msgctl, &[id, 99, s]), EINVAL);
        assert_eq!(h.call(Sysno::Msgctl, &[id, IPC_RMID, 0]), 0);
        assert_eq!(h.err(Sysno::Msgctl, &[id, IPC_STAT, s]), EINVAL);
    });
}

#[test]
fn receivers_wait_for_a_message() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        let id = h.ok(Sysno::Msgget, &[IPC_PRIVATE, 0o600]);
        let r = m + 0x1000;
        // A receiver waits for the type it wants.
        assert_eq!(h.start(w, Sysno::Msgrcv, &[id, r, 16, 5, 0]), None);
        msgbuf(&h, m, 4, b"no");
        assert_eq!(h.call(Sysno::Msgsnd, &[id, m, 2, 0]), 0);
        std::thread::sleep(Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert!(h.proc.threads[w].blocked.is_some());
        msgbuf(&h, m, 5, b"yes");
        assert_eq!(h.call(Sysno::Msgsnd, &[id, m, 3, 0]), 0);
        std::thread::sleep(Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), 3);
        assert_eq!(get(&h, r + 8, 3), b"yes");
        // Removal ends a wait with EIDRM.
        assert_eq!(h.start(w, Sysno::Msgrcv, &[id, r, 16, 5, 0]), None);
        assert_eq!(h.call(Sysno::Msgctl, &[id, IPC_RMID, 0]), 0);
        std::thread::sleep(Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), -(EIDRM as i64));
        // A signal with a handler ends one with -ERESTARTNOHAND.
        let id = h.ok(Sysno::Msgget, &[IPC_PRIVATE, 0o600]);
        assert_eq!(h.start(w, Sysno::Msgrcv, &[id, r, 16, 0, 0]), None);
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
        let pid = h.proc.state.pid as u64;
        h.ok(Sysno::Tgkill, &[pid, tid as u64, SIGUSR1 as u64]);
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), -(ERESTARTNOHAND as i64));
    });
}
