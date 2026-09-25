//! Memory locking against `mm/mlock.c`, `mm/gup.c`, `mm/mmap.c`,
//! `mm/mremap.c`, and `mm/madvise.c` (Linux 6.19), through the system calls
//! on every ABI: `mlock`, `mlock2`, and `munlock` (the right, the limit
//! less what is already locked, holes, `PROT_NONE`, the kernel's length
//! arithmetic), populating or not (`MLOCK_ONFAULT`), `mlockall` and
//! `MCL_FUTURE` for `mmap`, `brk`, and `mremap`, `MAP_LOCKED`, `madvise`'s
//! refusals, `VmLck`, and a new process.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno, vma_flags};

const NOBODY: u32 = 65534;
const RW: u64 = 3;
const MAP_PRIVATE_ANON: u64 = 0x22;
const MAP_LOCKED: u64 = 0x2000;
const MLOCK_ONFAULT: u64 = 1;
const MCL_CURRENT: u64 = 1;
const MCL_FUTURE: u64 = 2;
const MCL_ONFAULT: u64 = 4;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_COLD: u64 = 20;
const MADV_DONTNEED_LOCKED: u64 = 24;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_DONTUNMAP: u64 = 4;

fn creds(h: &mut Harness, id: u32) {
    h.proc.state.creds = (id, id, id, id);
    h.proc.state.groups = Vec::new();
}

/// `RLIMIT_MEMLOCK` of `pages` pages.
fn memlock(h: &mut Harness, pages: u64) {
    h.proc.state.rlimits[8] = (pages * P, pages * P);
}

/// `mm->locked_vm`, in pages.
fn locked(h: &Harness) -> u64 {
    crate::user::linux::syscall::mlock::locked_pages(&h.proc.state)
}

fn is_locked(h: &Harness, addr: u64) -> bool {
    let v = h.proc.state.space.vma_at(addr).unwrap();
    v.flags & vma_flags::LOCKED != 0
}

#[test]
fn mlock_checks_the_right_the_limit_and_the_range() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = h.anon(32 * P, RW, false);
        assert_eq!(h.err(Sysno::Mlock2, &[m, P, 2]), EINVAL);
        // can_do_mlock: no limit and no CAP_IPC_LOCK.
        memlock(&mut h, 0);
        assert_eq!(h.err(Sysno::Mlock, &[m, P]), EPERM);
        assert_eq!(h.err(Sysno::Mlockall, &[MCL_CURRENT]), EPERM);
        let fixed = [0, P, RW, MAP_PRIVATE_ANON | MAP_LOCKED, u64::MAX, 0];
        assert_eq!(h.err(Sysno::Mmap, &fixed), EPERM);
        assert_eq!(h.call(Sysno::Munlock, &[m, P]), 0, "no right needed");
        // The limit counts what the range does not already hold locked.
        memlock(&mut h, 16);
        assert_eq!(h.call(Sysno::Mlock, &[m, 8 * P]), 0);
        assert_eq!(locked(&h), 8);
        assert_eq!(h.err(Sysno::Mlock, &[m + 8 * P, 16 * P]), ENOMEM);
        assert_eq!(h.call(Sysno::Mlock, &[m, 8 * P]), 0, "already locked");
        assert_eq!(h.call(Sysno::Mlock, &[m + 4 * P, 12 * P]), 0);
        assert_eq!(locked(&h), 16);
        // Whole pages around the range.
        assert_eq!(h.call(Sysno::Munlock, &[m + 2 * P + 1, P]), 0);
        assert_eq!(locked(&h), 14);
        assert!(!is_locked(&h, m + 3 * P) && is_locked(&h, m + 4 * P));
        // The kernel's arithmetic: SIZE_MAX pages round to nothing.
        assert_eq!(h.call(Sysno::Mlock, &[m + 20 * P, u64::MAX]), 0);
        assert!(!is_locked(&h, m + 20 * P));
        // Holes: none at the start, then ENOMEM after the VMAs before it.
        creds(&mut h, 0);
        h.ok(Sysno::Munmap, &[m + 25 * P, P]);
        assert_eq!(h.err(Sysno::Mlock, &[m + 25 * P, 2 * P]), ENOMEM);
        assert!(!is_locked(&h, m + 26 * P));
        assert_eq!(h.err(Sysno::Mlock, &[m + 24 * P, 3 * P]), ENOMEM);
        assert!(is_locked(&h, m + 24 * P) && !is_locked(&h, m + 26 * P));
        // PROT_NONE is locked but cannot be brought in: ENOMEM.
        h.ok(Sysno::Mprotect, &[m + 28 * P, P, 0]);
        let before = locked(&h);
        assert_eq!(h.err(Sysno::Mlock, &[m + 28 * P, P]), ENOMEM);
        assert_eq!(locked(&h), before + 1);
    });
}

#[test]
fn locking_brings_pages_in_unless_on_fault() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, RW, false);
        let space = &h.proc.state.space;
        assert!(!space.is_resident(m));
        h.ok(Sysno::Mlock2, &[m, 2 * P, MLOCK_ONFAULT]);
        assert!(!h.proc.state.space.is_resident(m), "on fault");
        assert_eq!(locked(&h), 2);
        h.ok(Sysno::Mlock, &[m + 2 * P, 2 * P]);
        assert!(h.proc.state.space.is_resident(m + 3 * P));
        // A write-only or execute-only mapping is still read in.
        let w = h.anon(P, 2, false);
        h.ok(Sysno::Mlock, &[w, P]);
        assert!(h.proc.state.space.is_resident(w));
        let x = h.anon(P, 4, false);
        h.ok(Sysno::Mlock, &[x, P]);
        assert!(h.proc.state.space.is_resident(x));
    });
}

#[test]
fn locked_pages_are_not_discarded() {
    // madvise_dontneed_free_valid_vma, can_madv_lru_vma.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(2 * P, RW, false);
        h.fill(m, 2 * P, 7);
        h.ok(Sysno::Mlock, &[m, P]);
        for advice in [MADV_DONTNEED, MADV_FREE, MADV_COLD] {
            assert_eq!(h.err(Sysno::Madvise, &[m, 2 * P, advice]), EINVAL);
        }
        assert_eq!(h.byte(m), 7);
        h.ok(Sysno::Madvise, &[m, P, MADV_DONTNEED_LOCKED]);
        assert_eq!(h.byte(m), 0);
        h.ok(Sysno::Munlock, &[m, P]);
        h.ok(Sysno::Madvise, &[m + P, P, MADV_DONTNEED]);
        assert_eq!(h.byte(m + P), 0);
    });
}

#[test]
fn mlockall_locks_what_is_and_what_will_be() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        memlock(&mut h, 16);
        for bad in [0, 8, MCL_ONFAULT] {
            assert_eq!(h.err(Sysno::Mlockall, &[bad]), EINVAL, "{bad}");
        }
        assert_eq!(h.err(Sysno::Mlockall, &[MCL_CURRENT]), ENOMEM, "too big");
        h.ok(Sysno::Mlockall, &[MCL_FUTURE]);
        assert_eq!(locked(&h), 0);
        let m = h.anon(4 * P, RW, false);
        assert!(is_locked(&h, m));
        assert!(h.proc.state.space.is_resident(m + 3 * P));
        let big = [0, 16 * P, RW, MAP_PRIVATE_ANON, u64::MAX, 0];
        assert_eq!(h.err(Sysno::Mmap, &big), EAGAIN);
        // The break grows locked, within the limit.
        let brk = h.call(Sysno::Brk, &[0]) as u64;
        let top = (brk + P - 1) & !(P - 1);
        assert_eq!(h.call(Sysno::Brk, &[top + 2 * P]) as u64, top + 2 * P);
        assert!(is_locked(&h, top));
        assert_eq!(h.call(Sysno::Brk, &[top + 64 * P]) as u64, top + 2 * P);
        // mremap: growth within the limit, then beyond it.
        let grown = h.ok(Sysno::Mremap, &[m, 4 * P, 6 * P, MREMAP_MAYMOVE, 0]);
        assert_eq!(locked(&h), 8);
        assert!(h.proc.state.space.is_resident(grown + 5 * P));
        assert_eq!(
            h.err(Sysno::Mremap, &[grown, 6 * P, 16 * P, MREMAP_MAYMOVE, 0]),
            EAGAIN
        );
        // MREMAP_DONTUNMAP leaves the old range unlocked but still counted
        // (move_vma counts the new VMA and never unmaps the old one).
        let moved = h.ok(
            Sysno::Mremap,
            &[grown, 6 * P, 6 * P, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0],
        );
        assert!(is_locked(&h, moved) && !is_locked(&h, grown));
        assert_eq!(locked(&h), 14);
        // munlockall ends both, the count keeping what the move left.
        h.ok(Sysno::Munlockall, &[]);
        assert_eq!(locked(&h), 6);
        let n = h.anon(P, RW, false);
        assert!(!is_locked(&h, n));
        // MCL_CURRENT locks every VMA but a special mapping.
        creds(&mut h, 0);
        h.ok(Sysno::Mlockall, &[MCL_CURRENT | MCL_ONFAULT]);
        for v in h.proc.state.space.vma_snapshot() {
            let special = v.flags & vma_flags::SPECIAL != 0;
            assert_eq!(v.flags & vma_flags::LOCKED != 0, !special, "{v:?}");
        }
        assert_eq!(
            abi != LinuxAbi::X86_64,
            h.proc
                .state
                .space
                .vma_snapshot()
                .iter()
                .any(|v| v.name.as_deref() == Some("[vdso]")),
        );
    });
}

#[test]
fn a_special_mapping_is_not_resized_or_kept() {
    // check_prep_vma: VM_DONTEXPAND.
    for abi in [LinuxAbi::Aarch64, LinuxAbi::Riscv64] {
        let mut h = Harness::new(abi);
        let vdso = h
            .proc
            .state
            .space
            .vma_snapshot()
            .into_iter()
            .find(|v| v.name.as_deref() == Some("[vdso]"))
            .unwrap()
            .start;
        let grow = [vdso, P, 2 * P, MREMAP_MAYMOVE, 0];
        assert_eq!(h.err(Sysno::Mremap, &grow), EFAULT);
        let keep = [vdso, P, P, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0];
        assert_eq!(h.err(Sysno::Mremap, &keep), EINVAL);
        h.ok(Sysno::Mlock, &[vdso, P]);
        assert!(!is_locked(&h, vdso));
    }
}

#[test]
fn status_shows_vmlck_and_a_new_process_has_none() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(3 * P, RW, false);
        h.ok(Sysno::Mlock, &[m, 3 * P]);
        let status = crate::user::linux::procfs::status(&h.proc.state, &h.proc.threads[0], 1);
        let text = String::from_utf8(status).unwrap();
        assert!(text.contains("\nVmLck:\t      12 kB\n"), "{text}");
        h.ok(Sysno::Mlockall, &[MCL_FUTURE]);
        crate::user::linux::syscall::mlock::forked(&mut h.proc.state);
        assert_eq!(locked(&h), 0);
        let n = h.anon(P, RW, false);
        assert!(!is_locked(&h, n), "MCL_FUTURE is not inherited");
    });
}
