//! Seccomp (`kernel/seccomp.c`): a thread's system calls checked before
//! they run, by strict mode or by filters.
//!
//! | Module | Contents |
//! |---|---|
//! | this one | a thread's mode and filters, and the verdict on a call |
//! | [`bpf`] | classic BPF: the checks a filter passes, and running one |
//!
//! Filters form a chain, newest first, shared (by reference) with the
//! threads and processes that inherited them: `clone` and `fork` copy the
//! calling thread's chain, `execve` keeps it, and a filter installed with
//! `SECCOMP_FILTER_FLAG_TSYNC` becomes every thread's. Every filter of the
//! chain runs on a call; the result whose action ranks lowest wins, the
//! newest on a tie (`seccomp_run_filters`), and decides it as
//! `__seccomp_filter` does. `SECCOMP_RET_TRACE` finds no tracer (`ENOSYS`)
//! and `SECCOMP_RET_USER_NOTIF` no listener (`ENOSYS`), as no filter can
//! have one here.

pub mod bpf;

use std::sync::Arc;

/// `SECCOMP_MODE_*`.
pub const MODE_DISABLED: u32 = 0;
pub const MODE_STRICT: u32 = 1;
pub const MODE_FILTER: u32 = 2;
/// `SECCOMP_MODE_DEAD`: after a kill, before the thread is gone.
pub const MODE_DEAD: u32 = 3;
/// `SECCOMP_RET_*`.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_KILL_THREAD: u32 = 0x0000_0000;
pub const RET_TRAP: u32 = 0x0003_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_USER_NOTIF: u32 = 0x7FC0_0000;
pub const RET_TRACE: u32 = 0x7FF0_0000;
pub const RET_LOG: u32 = 0x7FFC_0000;
pub const RET_ALLOW: u32 = 0x7FFF_0000;
const RET_ACTION_FULL: u32 = 0xFFFF_0000;
const RET_DATA: u32 = 0x0000_FFFF;
/// `MAX_ERRNO`.
const MAX_ERRNO: u32 = 4095;
/// `MAX_INSNS_PER_PATH`: a chain's instructions, as converted to eBPF
/// ([`bpf::converted_len`]), each filter counting 4 more.
pub const MAX_INSNS_PER_PATH: usize = (1 << 18) / 8;

/// A filter (`struct seccomp_filter`).
#[derive(Debug)]
pub struct Filter {
    prog: Vec<bpf::Insn>,
    /// `prog->len`: its length as converted to eBPF.
    len: usize,
    prev: Option<Arc<Filter>>,
    /// `SECCOMP_FILTER_FLAG_LOG`.
    pub log: bool,
}

/// A thread's seccomp state (`struct seccomp`).
#[derive(Clone, Debug, Default)]
pub struct Seccomp {
    pub mode: u32,
    /// The newest filter.
    pub filter: Option<Arc<Filter>>,
}

/// What becomes of a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// It runs (`SECCOMP_RET_ALLOW`, `SECCOMP_RET_LOG`).
    Allow,
    /// It returns this error without running.
    Errno(i32),
    /// It does not run; `SIGSYS` (`SYS_SECCOMP`) reports it, with this
    /// datum.
    Trap(u16),
    /// The thread dies of `SIGSYS` (the process with it if the thread is
    /// its last).
    KillThread(u16),
    /// The process dies of `SIGSYS`.
    KillProcess(u16),
    /// Strict mode: the thread dies of `SIGKILL`.
    StrictKill,
}

/// The `struct seccomp_data` of a call: its number, architecture, the
/// address after the calling instruction, and its arguments.
pub fn data(nr: i32, arch: u32, ip: u64, args: [u64; 6]) -> [u8; bpf::SECCOMP_DATA as usize] {
    let mut d = [0u8; bpf::SECCOMP_DATA as usize];
    d[0..4].copy_from_slice(&nr.to_le_bytes());
    d[4..8].copy_from_slice(&arch.to_le_bytes());
    d[8..16].copy_from_slice(&ip.to_le_bytes());
    for (i, a) in args.iter().enumerate() {
        d[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
    }
    d
}

/// `ACTION_ONLY`: an action as `seccomp_run_filters` ranks it (signed).
fn rank(ret: u32) -> i32 {
    (ret & RET_ACTION_FULL) as i32
}

impl Seccomp {
    /// How many filters the chain has (`filter_count`).
    pub fn count(&self) -> usize {
        std::iter::successors(self.filter.as_deref(), |f| f.prev.as_deref()).count()
    }

    /// `seccomp_attach_filter`'s bound: the chain's instructions with
    /// `prog` added, each filter counting 4 more.
    pub fn fits(&self, prog: &[bpf::Insn]) -> bool {
        let chain: usize = std::iter::successors(self.filter.as_deref(), |f| f.prev.as_deref())
            .map(|f| f.len + 4)
            .sum();
        chain + bpf::converted_len(prog) <= MAX_INSNS_PER_PATH
    }

    /// Adds a filter (`seccomp_attach_filter`, `seccomp_assign_mode`).
    pub fn attach(&mut self, prog: Vec<bpf::Insn>, log: bool) {
        self.filter = Some(Arc::new(Filter {
            len: bpf::converted_len(&prog),
            prog,
            prev: self.filter.take(),
            log,
        }));
        self.mode = MODE_FILTER;
    }

    /// `is_ancestor`: whether `self`'s chain ends in `other`'s (a thread
    /// that may take `other`'s chain with `SECCOMP_FILTER_FLAG_TSYNC`).
    pub fn within(&self, other: &Seccomp) -> bool {
        let Some(mine) = &self.filter else {
            return true;
        };
        std::iter::successors(other.filter.as_ref(), |f| f.prev.as_ref())
            .any(|f| Arc::ptr_eq(f, mine))
    }

    /// `seccomp_run_filters`: the winning result.
    fn run(&self, d: &[u8; bpf::SECCOMP_DATA as usize]) -> u32 {
        let mut ret = RET_ALLOW;
        for f in std::iter::successors(self.filter.as_deref(), |f| f.prev.as_deref()) {
            let r = bpf::run(&f.prog, d);
            if rank(r) < rank(ret) {
                ret = r;
            }
        }
        ret
    }

    /// The verdict on call `nr` (`__secure_computing`): strict mode allows
    /// only the calls `strict_allows`; filters decide as `__seccomp_filter`
    /// does.
    pub fn verdict(
        &self,
        nr: i32,
        arch: u32,
        ip: u64,
        args: [u64; 6],
        strict_allows: impl Fn(i32) -> bool,
    ) -> Verdict {
        match self.mode {
            MODE_DISABLED => Verdict::Allow,
            MODE_STRICT if strict_allows(nr) => Verdict::Allow,
            MODE_STRICT | MODE_DEAD => Verdict::StrictKill,
            _ => {
                let ret = self.run(&data(nr, arch, ip, args));
                let datum = (ret & RET_DATA) as u16;
                match ret & RET_ACTION_FULL {
                    RET_ERRNO => Verdict::Errno((ret & RET_DATA).min(MAX_ERRNO) as i32),
                    RET_TRAP => Verdict::Trap(datum),
                    RET_TRACE | RET_USER_NOTIF => Verdict::Errno(super::abi::errno_table::ENOSYS),
                    RET_LOG | RET_ALLOW => Verdict::Allow,
                    RET_KILL_THREAD => Verdict::KillThread(datum),
                    // SECCOMP_RET_KILL_PROCESS, and actions the kernel does
                    // not know.
                    _ => Verdict::KillProcess(datum),
                }
            }
        }
    }
}

/// `seccomp_get_action_avail`: the actions a filter may return.
pub fn action_known(action: u32) -> bool {
    matches!(
        action,
        RET_KILL_PROCESS
            | RET_KILL_THREAD
            | RET_TRAP
            | RET_ERRNO
            | RET_USER_NOTIF
            | RET_TRACE
            | RET_LOG
            | RET_ALLOW
    )
}

#[cfg(test)]
mod tests {
    use super::bpf::*;
    use super::*;

    fn ret(k: u32) -> Insn {
        Insn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Returns `hit` for call `nr`, `RET_ALLOW` for the others.
    fn on(nr: u32, hit: u32) -> Vec<Insn> {
        vec![
            Insn {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            Insn {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 1,
                k: nr,
            },
            ret(hit),
            ret(RET_ALLOW),
        ]
    }

    #[test]
    fn verdicts_follow_seccomp_run_filters() {
        let mut s = Seccomp::default();
        let v = |s: &Seccomp, nr| s.verdict(nr, 0xC000_003E, 0x1000, [0; 6], |_| false);
        assert_eq!(v(&s, 1), Verdict::Allow);
        s.attach(on(1, RET_ERRNO | 13), false);
        assert_eq!(v(&s, 1), Verdict::Errno(13));
        assert_eq!(v(&s, 2), Verdict::Allow);
        // The lowest action wins whichever filter returns it; the newest on
        // a tie.
        s.attach(on(1, RET_TRAP | 7), false);
        assert_eq!(v(&s, 1), Verdict::Trap(7));
        s.attach(on(1, RET_ERRNO | 99), false);
        assert_eq!(v(&s, 1), Verdict::Trap(7));
        s.attach(on(2, RET_TRAP | 5), false);
        s.attach(on(2, RET_TRAP | 6), false);
        assert_eq!(v(&s, 2), Verdict::Trap(6));
        assert_eq!(s.count(), 5);
        // Errno is capped; kill, trace, notify, log, and unknown actions.
        let mut t = Seccomp::default();
        t.attach(on(3, RET_ERRNO | 0xFFFF), false);
        t.attach(on(4, RET_KILL_THREAD | 2), false);
        t.attach(on(5, RET_KILL_PROCESS), false);
        t.attach(on(6, RET_TRACE), false);
        t.attach(on(7, RET_USER_NOTIF), false);
        t.attach(on(8, RET_LOG), false);
        t.attach(on(9, 0x0001_0000), false);
        assert_eq!(v(&t, 3), Verdict::Errno(4095));
        assert_eq!(v(&t, 4), Verdict::KillThread(2));
        assert_eq!(v(&t, 5), Verdict::KillProcess(0));
        assert_eq!(v(&t, 6), Verdict::Errno(38));
        assert_eq!(v(&t, 7), Verdict::Errno(38));
        assert_eq!(v(&t, 8), Verdict::Allow);
        assert_eq!(v(&t, 9), Verdict::KillProcess(0));
        // Strict mode.
        let strict = Seccomp {
            mode: MODE_STRICT,
            filter: None,
        };
        assert_eq!(strict.verdict(0, 0, 0, [0; 6], |n| n < 2), Verdict::Allow);
        assert_eq!(
            strict.verdict(2, 0, 0, [0; 6], |n| n < 2),
            Verdict::StrictKill
        );
    }

    #[test]
    fn chains_are_shared_and_bounded() {
        let mut a = Seccomp::default();
        a.attach(on(1, RET_ERRNO | 1), false);
        let b = a.clone();
        a.attach(on(2, RET_ERRNO | 2), false);
        // b's chain is a prefix of a's: TSYNC may give b a's chain.
        assert!(b.within(&a));
        assert!(!a.within(&b));
        assert!(Seccomp::default().within(&a));
        // 4096 returns of K convert to 3 + 2 * 4096 = 8195 instructions:
        // 3 * (8195 + 4) + 8195 > 32768.
        let big = vec![ret(RET_ALLOW); 4096];
        let mut c = Seccomp::default();
        for _ in 0..3 {
            assert!(c.fits(&big));
            c.attach(big.clone(), false);
        }
        assert!(!c.fits(&big));
        // 32768 - 3 * 8199 = 8171 = 3 + 2 * 4084.
        let mut exact = vec![ret(RET_ALLOW); 4084];
        assert!(c.fits(&exact));
        exact.push(Insn {
            code: BPF_RET | BPF_A,
            jt: 0,
            jf: 0,
            k: 0,
        });
        assert!(!c.fits(&exact));
        let d = data(59, 0xC000_003E, 0x40_1000, [1, 2, 3, 4, 5, 6]);
        assert_eq!(u32::from_le_bytes(d[0..4].try_into().unwrap()), 59);
        assert_eq!(u64::from_le_bytes(d[8..16].try_into().unwrap()), 0x40_1000);
        assert_eq!(u64::from_le_bytes(d[56..64].try_into().unwrap()), 6);
    }
}
