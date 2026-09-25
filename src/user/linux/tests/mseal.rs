//! Memory sealing against `mm/mseal.c` and the checks of `mm/vma.c`,
//! `mm/mprotect.c`, `mm/mremap.c`, `mm/madvise.c`, `mm/mmap.c`, and
//! `ipc/shm.c` (Linux 6.19), through the system calls on every ABI:
//! `mseal`'s checks in order and what a seal refuses or leaves alone.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{Sysno, vma_flags};

const RW: u64 = 3;
const MAP_FIXED_ANON: u64 = 0x32;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_DONTFORK: u64 = 10;
const MADV_COLD: u64 = 20;
const MADV_DONTNEED_LOCKED: u64 = 24;
const SHM_REMAP: u64 = 0o40000;

fn sealed(h: &Harness, addr: u64) -> bool {
    let v = h.proc.state.space.vma_at(addr).unwrap();
    v.flags & vma_flags::SEALED != 0
}

fn mapped(h: &Harness, addr: u64) -> bool {
    h.proc.state.space.vma_at(addr).is_some()
}

#[test]
fn mseal_checks_in_the_kernels_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(8 * P, RW, false);
        assert_eq!(h.err(Sysno::Mseal, &[m, P, 1]), EINVAL);
        assert_eq!(h.err(Sysno::Mseal, &[m + 1, P, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Mseal, &[m, u64::MAX, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Mseal, &[P.wrapping_neg(), 2 * P, 0]), EINVAL);
        assert_eq!(h.call(Sysno::Mseal, &[m, 0, 0]), 0);
        assert_eq!(h.call(Sysno::Mseal, &[P, 0, 0]), 0, "empty, unmapped");
        h.ok(Sysno::Munmap, &[m + 4 * P, P]);
        for (at, len) in [(3, 3), (4, 2), (3, 2)] {
            let r = [m + at * P, len * P, 0];
            assert_eq!(h.err(Sysno::Mseal, &r), ENOMEM, "{at} {len}");
        }
        assert!(!sealed(&h, m + 3 * P), "nothing sealed by a failure");
        h.ok(Sysno::Mseal, &[m, 2 * P, 0]);
        h.ok(Sysno::Mseal, &[m, P + 1, 0]);
        assert!(sealed(&h, m) && sealed(&h, m + P) && !sealed(&h, m + 2 * P));
    });
}

#[test]
fn a_seal_refuses_unmapping_remapping_and_reprotecting() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, RW, false);
        h.fill(m, 4 * P, 1);
        h.ok(Sysno::Mseal, &[m + P, 2 * P, 0]);
        assert_eq!(h.err(Sysno::Munmap, &[m, 4 * P]), EPERM);
        assert!(mapped(&h, m) && mapped(&h, m + 3 * P), "nothing unmapped");
        assert_eq!(h.err(Sysno::Munmap, &[m + 2 * P, P]), EPERM);
        h.ok(Sysno::Munmap, &[m + 3 * P, P]);
        let fixed = [m, 2 * P, 1, MAP_FIXED_ANON, u64::MAX, 0];
        assert_eq!(h.err(Sysno::Mmap, &fixed), EPERM);
        assert_eq!(h.byte(m + P), 1);
        let grow = [m + P, 2 * P, 3 * P, MREMAP_MAYMOVE, 0];
        assert_eq!(h.err(Sysno::Mremap, &grow), EPERM);
        let far = m + 8 * P;
        let mv = [m + P, P, P, MREMAP_MAYMOVE | MREMAP_FIXED, far];
        assert_eq!(h.err(Sysno::Mremap, &mv), EPERM);
        let other = h.anon(P, RW, false);
        let onto = [other, P, P, MREMAP_MAYMOVE | MREMAP_FIXED, m + P];
        assert_eq!(h.err(Sysno::Mremap, &onto), EPERM);
        assert!(mapped(&h, other));
        // mprotect goes VMA by VMA: the unsealed one before changes.
        assert_eq!(h.err(Sysno::Mprotect, &[m, 3 * P, 1]), EPERM);
        assert_eq!(h.perms(m), crate::user::mm::Perms::READ);
        assert_eq!(h.err(Sysno::Mprotect, &[m + P, P, RW]), EPERM, "the same");
        // mlock is not refused.
        h.ok(Sysno::Mlock, &[m + P, P]);
        h.ok(Sysno::Munlock, &[m + P, P]);
    });
}

#[test]
fn a_seal_keeps_what_could_not_be_written() {
    // can_madvise_modify: discarding advice on sealed private anonymous
    // memory without write permission.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let w = h.anon(P, RW, false);
        h.fill(w, P, 1);
        h.ok(Sysno::Mseal, &[w, P, 0]);
        h.ok(Sysno::Madvise, &[w, P, MADV_DONTNEED]);
        assert_eq!(h.byte(w), 0, "writable: discarded");
        let r = h.anon(2 * P, RW, false);
        h.fill(r, 2 * P, 2);
        h.ok(Sysno::Mprotect, &[r, 2 * P, 1]);
        h.ok(Sysno::Mseal, &[r, 2 * P, 0]);
        for advice in [
            MADV_DONTNEED,
            MADV_FREE,
            MADV_DONTNEED_LOCKED,
            MADV_DONTFORK,
        ] {
            assert_eq!(h.err(Sysno::Madvise, &[r, P, advice]), EPERM, "{advice}");
        }
        h.ok(Sysno::Madvise, &[r, P, MADV_COLD]);
        assert_eq!(h.byte(r), 2);
        // A shared mapping is not anonymous memory.
        let s = h.anon(P, 1, true);
        h.ok(Sysno::Mseal, &[s, P, 0]);
        h.ok(Sysno::Madvise, &[s, P, MADV_DONTNEED]);
    });
}

#[test]
fn brk_and_shmdt_keep_sealed_pages() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let brk = h.call(Sysno::Brk, &[0]) as u64;
        let top = (brk + P - 1) & !(P - 1);
        assert_eq!(h.call(Sysno::Brk, &[top + 2 * P]) as u64, top + 2 * P);
        h.ok(Sysno::Mseal, &[top, 2 * P, 0]);
        assert_eq!(h.call(Sysno::Brk, &[top]) as u64, top + 2 * P, "kept");
        assert_eq!(h.call(Sysno::Brk, &[top + 3 * P]) as u64, top + 3 * P);
        let id = h.ok(Sysno::Shmget, &[0, P, 0o600]);
        let s = h.ok(Sysno::Shmat, &[id, 0, 0]);
        h.ok(Sysno::Mseal, &[s, P, 0]);
        assert_eq!(h.call(Sysno::Shmdt, &[s]), 0);
        assert!(mapped(&h, s), "the seal holds");
        assert_eq!(h.err(Sysno::Shmat, &[id, s, SHM_REMAP]), EPERM);
        h.ok(Sysno::Shmctl, &[id, 0, 0]);
    });
}
