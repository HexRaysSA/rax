//! Who sent a signal between `rax-user` processes.
//!
//! A host reports a `kill`'s sender in the signal's `siginfo`, but XNU
//! keeps that `siginfo` in per-process fields (`p->si_pid`, `p->si_code`)
//! which a child's exit overwrites for its `SIGCHLD`: a signal whose sender
//! exits at once can arrive as `CLD_EXITED` from whichever child exited.
//! So a `rax-user` process posts, before its host `kill`, who sends which
//! signal to whom, in a table every process forked from the first shares (a
//! `MAP_SHARED` page made before any fork); the target's signal handler
//! claims the record. The record also carries the sender's guest UID, which
//! the host does not know.
//!
//! A record is ignored when it is older than its target process (a PID the
//! host reused: each process's floor is the table's stamp when it was
//! forked) or than [`TTL_MS`] (a second sending the target's pending signal
//! absorbed, as a pending standard signal absorbs another). A sender outside
//! the tree posts nothing, and its signal keeps the host's report.
//!
//! Everything here is lock-free and async-signal-safe: the handler claims
//! records with atomic operations, `getpid`, and `clock_gettime`.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use super::abi::errno::Errno;
use super::host::SharedWords;

/// Records the table holds.
const SLOTS: usize = 64;
/// A slot being written.
const BUSY: u64 = u64::MAX;
/// How long a record waits for its signal.
pub const TTL_MS: u64 = 2000;

/// Word 0: the last stamp given; then per slot: state (0 free, [`BUSY`], or
/// the record's stamp), `target << 32 | sig`, `sender pid << 32 | uid`, and
/// the posting time in milliseconds of the monotonic clock.
static TABLE: OnceLock<SharedWords> = OnceLock::new();
/// This process's floor: records stamped at or below it predate it.
static FLOOR: AtomicU64 = AtomicU64::new(0);

/// Makes the table (once, before any fork).
pub fn init() -> Result<(), Errno> {
    if TABLE.get().is_none() {
        let _ = TABLE.set(SharedWords::new(1 + 4 * SLOTS)?);
    }
    Ok(())
}

fn now_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one timespec; async-signal-safe.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

fn key(target: i32, sig: i32) -> u64 {
    (u64::from(target as u32) << 32) | u64::from(sig as u32)
}

/// The last stamp given (a child's floor, read before it is forked).
pub fn stamp() -> u64 {
    TABLE
        .get()
        .map_or(0, |t| t.words()[0].load(Ordering::SeqCst))
}

/// Sets this process's floor (in a new child).
pub fn set_floor(stamp: u64) {
    FLOOR.store(stamp, Ordering::SeqCst);
}

/// A posted record, withdrawn if its signal is not sent.
#[derive(Debug)]
pub struct Post {
    slot: usize,
    stamp: u64,
}

/// Posts that process `sender` (`(pid, uid)`) sends `sig` to `target`.
/// `None` without a table or a free slot.
pub fn post(target: i32, sig: i32, sender: (i32, u32)) -> Option<Post> {
    let t = TABLE.get()?.words();
    let stamp = t[0].fetch_add(1, Ordering::SeqCst) + 1;
    let now = now_ms();
    for slot in 0..SLOTS {
        let w = &t[1 + 4 * slot..5 + 4 * slot];
        let state = w[0].load(Ordering::Acquire);
        let expired = state != 0
            && state != BUSY
            && now.saturating_sub(w[3].load(Ordering::Relaxed)) > TTL_MS;
        if (state == 0 || expired)
            && w[0]
                .compare_exchange(state, BUSY, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            w[1].store(key(target, sig), Ordering::Relaxed);
            w[2].store(
                (u64::from(sender.0 as u32) << 32) | u64::from(sender.1),
                Ordering::Relaxed,
            );
            w[3].store(now, Ordering::Relaxed);
            w[0].store(stamp, Ordering::Release);
            return Some(Post { slot, stamp });
        }
    }
    None
}

/// Withdraws a record whose signal was not sent.
pub fn withdraw(p: Post) {
    if let Some(t) = TABLE.get() {
        let _ = t.words()[1 + 4 * p.slot].compare_exchange(
            p.stamp,
            0,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
}

/// Claims the oldest current record of `sig` sent to this process: its
/// sender's `(pid, uid)`. Stale records met on the way are freed.
pub fn claim(sig: i32) -> Option<(i32, u32)> {
    let t = TABLE.get()?.words();
    // SAFETY: getpid has no failure mode and is async-signal-safe.
    let me = unsafe { libc::getpid() };
    let want = key(me, sig);
    let floor = FLOOR.load(Ordering::Relaxed);
    let now = now_ms();
    loop {
        let mut best: Option<(usize, u64)> = None;
        for slot in 0..SLOTS {
            let w = &t[1 + 4 * slot..5 + 4 * slot];
            let state = w[0].load(Ordering::Acquire);
            if state == 0 || state == BUSY || w[1].load(Ordering::Relaxed) != want {
                continue;
            }
            if state <= floor || now.saturating_sub(w[3].load(Ordering::Relaxed)) > TTL_MS {
                let _ = w[0].compare_exchange(state, 0, Ordering::AcqRel, Ordering::Relaxed);
                continue;
            }
            if best.is_none_or(|(_, s)| state < s) {
                best = Some((slot, state));
            }
        }
        let (slot, state) = best?;
        let w = &t[1 + 4 * slot..5 + 4 * slot];
        let sender = w[2].load(Ordering::Relaxed);
        if w[0]
            .compare_exchange(state, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Some(((sender >> 32) as u32 as i32, sender as u32));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, as the table and floor are per process.
    #[test]
    fn records_are_claimed_oldest_first_and_only_by_their_target() {
        init().unwrap();
        // SAFETY: getpid has no failure mode.
        let me = unsafe { libc::getpid() };
        // A signal real-time enough not to be used by other tests.
        let sig = 60;
        assert_eq!(claim(sig), None);
        post(me, sig, (11, 1000)).unwrap();
        post(me, sig, (22, 2000)).unwrap();
        post(me + 1, sig, (33, 3000)).unwrap();
        assert_eq!(claim(sig), Some((11, 1000)));
        assert_eq!(claim(sig), Some((22, 2000)));
        assert_eq!(claim(sig), None, "another process's record");
        // A withdrawn record is gone.
        let p = post(me, sig, (44, 4000)).unwrap();
        withdraw(p);
        assert_eq!(claim(sig), None);
        // Records at or below the floor predate this process.
        post(me, sig, (55, 5000)).unwrap();
        let old = FLOOR.load(Ordering::SeqCst);
        set_floor(stamp());
        assert_eq!(claim(sig), None);
        post(me, sig, (66, 6000)).unwrap();
        assert_eq!(claim(sig), Some((66, 6000)));
        set_floor(old);
    }
}
