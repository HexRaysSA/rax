//! i386 threads against Linux 6.19 on x86-64: `clone`'s `CLONE_SETTLS` as
//! a `struct user_desc` (`set_new_tls`, `do_set_thread_area` for the child,
//! checked by `copy_thread` before a TID exists), `clone3` likewise, the
//! separate 32-bit robust list (`compat_sys_set_robust_list`,
//! `compat_sys_get_robust_list`, `compat_exit_robust_list` with its 32-bit
//! address arithmetic), and `futex_time32`/`futex_time64` timeouts.

use super::super::harness::Harness;
use super::{LIMIT_IN_PAGES, SEG_32BIT, SEG_NOT_PRESENT, USEABLE, gdt, put, u32_at, user_desc};
use crate::isa::x86_64::X86UserSegment;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::futex::{FUTEX_OWNER_DIED, FUTEX_WAITERS};
use crate::user::linux::syscall::thread::cf::*;

const THREAD: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn gs_base(h: &Harness, idx: usize) -> (u16, u64) {
    let GuestCpu::X86_64(cpu) = &h.proc.threads[idx].cpu else {
        panic!("an x86 CPU");
    };
    let v = cpu.vcpu();
    (v.user_selector(X86UserSegment::Gs), v.gs_base())
}

/// The base of a GDT descriptor.
fn base_of(d: u64) -> u64 {
    (d >> 16) & 0xFF_FFFF | ((d >> 56) & 0xFF) << 24
}

/// A flat, page-granular, 32-bit data `user_desc` for `entry` at `base`.
fn tls_desc(entry: u32, base: u32) -> Vec<u8> {
    user_desc(entry, base, 0xFFFFF, SEG_32BIT | LIMIT_IN_PAGES | USEABLE)
}

/// The caller's GS on TLS entry 12 with base 0x1000, as a threads library
/// sets it up.
fn with_tls(h: &mut Harness) {
    let at = h.scratch + 0x900;
    put(h, at, &tls_desc(u32::MAX, 0x1000));
    h.ok(Sysno::SetThreadArea, &[at]);
    assert_eq!(u32_at(h, at), 12);
    let GuestCpu::X86_64(cpu) = &mut h.proc.threads[0].cpu else {
        panic!("an x86 CPU");
    };
    cpu.vcpu_mut()
        .load_user_segment(X86UserSegment::Gs, 0x63)
        .unwrap();
}

#[test]
fn clone_settls_gives_the_child_a_tls_descriptor() {
    let mut h = Harness::new(LinuxAbi::I386);
    with_tls(&mut h);
    let desc = h.scratch + 0xA00;
    put(&h, desc, &tls_desc(12, 0x0020_0000));
    // sys_ia32_clone: (flags, newsp, parent_tid, tls, child_tid).
    let tid = h.ok(Sysno::Clone, &[THREAD | CLONE_SETTLS, 0, 0, desc, 0]) as i32;
    let w = h.index_of(tid);
    // The child's entry 12 and its GS, which held the entry, reloaded; the
    // caller's are unchanged (each task has its own TLS entries).
    assert_eq!(gs_base(&h, w), (0x63, 0x0020_0000));
    assert_eq!(gs_base(&h, 0), (0x63, 0x1000));
    let GuestCpu::X86_64(child) = &h.proc.threads[w].cpu else {
        panic!("an x86 CPU");
    };
    assert_eq!(
        base_of(child.vcpu().user_gdt_entry(12).unwrap()),
        0x0020_0000
    );
    assert_eq!(base_of(gdt(&h, 12)), 0x1000);
    // clone3's tls is a user_desc for a 32-bit caller as well.
    put(&h, desc, &tls_desc(12, 0x0030_0000));
    let args = h.scratch + 0xB00;
    let mut b = Vec::new();
    for v in [THREAD | CLONE_SETTLS, 0, 0, 0, 0, 0, 0, desc] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    put(&h, args, &b);
    let tid = h.ok(Sysno::Clone3, &[args, 64]) as i32;
    assert_eq!(gs_base(&h, h.index_of(tid)), (0x63, 0x0030_0000));
}

#[test]
fn a_bad_user_desc_fails_the_clone_before_a_tid_is_taken() {
    let mut h = Harness::new(LinuxAbi::I386);
    let desc = h.scratch + 0xA00;
    let next = h.proc.state.next_tid;
    // set_new_tls does not allocate: entry -1 is refused, as are entries
    // outside 12-14 and a segment tls_desc_okay refuses; an unreadable
    // descriptor is EFAULT.
    for (d, errno) in [
        (tls_desc(u32::MAX, 0x1000), EINVAL),
        (tls_desc(11, 0x1000), EINVAL),
        (tls_desc(15, 0x1000), EINVAL),
        (
            user_desc(13, 0, 0xFFFFF, SEG_32BIT | SEG_NOT_PRESENT | USEABLE),
            EINVAL,
        ),
    ] {
        put(&h, desc, &d);
        assert_eq!(
            h.err(Sysno::Clone, &[THREAD | CLONE_SETTLS, 0, 0, desc, 0]),
            errno
        );
    }
    assert_eq!(
        h.err(Sysno::Clone, &[THREAD | CLONE_SETTLS, 0, 0, 0x10_0000, 0]),
        EFAULT
    );
    assert_eq!(h.proc.threads.len(), 1);
    assert_eq!(h.proc.state.next_tid, next, "no TID was taken");
    // Without CLONE_SETTLS the argument is not read.
    h.ok(Sysno::Clone, &[THREAD, 0, 0, 0x10_0000, 0]);
}

#[test]
fn the_32_bit_robust_list_is_a_separate_head() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (head, out) = (h.scratch + 0x100, h.scratch + 0x200);
    // struct compat_robust_list_head is 12 bytes.
    assert_eq!(h.err(Sysno::SetRobustList, &[head, 24]), EINVAL);
    assert_eq!(h.call(Sysno::SetRobustList, &[head, 12]), 0);
    let t = &h.proc.threads[0];
    assert_eq!((t.compat_robust_list, t.robust_list), (head, (0, 0)));
    put(&h, out, &[0xEE; 16]);
    assert_eq!(h.call(Sysno::GetRobustList, &[0, out, out + 8]), 0);
    let mut b = [0u8; 16];
    h.proc.state.space.read(out, &mut b).unwrap();
    assert_eq!(
        b.to_vec(),
        [words(&[head as u32, 0xEEEE_EEEE, 12, 0xEEEE_EEEE])].concat()
    );
    assert_eq!(h.err(Sysno::GetRobustList, &[99_999, out, out + 8]), ESRCH);
}

#[test]
fn thread_exit_releases_the_32_bit_robust_list() {
    let mut h = Harness::new(LinuxAbi::I386);
    let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
    let w = h.index_of(tid);
    // A list with one held lock and a pending one; futex_offset -8 is added
    // to each entry's 32-bit address (compat_ptr(base + futex_offset)).
    let base = h.scratch;
    let (head, entry, pending) = (base + 0x100, base + 0x140, base + 0x180);
    let offset = -8i32 as u32;
    put(&h, head, &words(&[entry as u32, offset, pending as u32]));
    put(&h, entry, &words(&[head as u32]));
    let (lock, lock2) = (entry - 8, pending - 8);
    put(&h, lock, &(tid as u32 | FUTEX_WAITERS).to_le_bytes());
    put(&h, lock2, &(tid as u32).to_le_bytes());
    assert_eq!(h.start(w, Sysno::SetRobustList, &[head, 12]), Some(0));
    assert_eq!(h.start(w, Sysno::Exit, &[0]), None);
    assert_eq!(u32_at(&h, lock), FUTEX_WAITERS | FUTEX_OWNER_DIED);
    assert_eq!(u32_at(&h, lock2), FUTEX_OWNER_DIED);
}

#[test]
fn futex_time32_and_time64_read_their_timeouts() {
    const WAIT: u64 = 0;
    let mut h = Harness::new(LinuxAbi::I386);
    let (word, ts) = (h.scratch + 0x100, h.scratch + 0x200);
    put(&h, word, &5u32.to_le_bytes());
    assert_eq!(h.err(Sysno::Futex, &[word, WAIT, 6, 0, 0, 0]), EAGAIN);
    // futex_time32: struct old_timespec32.
    put(&h, ts, &words(&[0, 0]));
    assert_eq!(h.err(Sysno::Futex, &[word, WAIT, 5, ts, 0, 0]), ETIMEDOUT);
    put(&h, ts, &words(&[0, 1_000_000_000]));
    assert_eq!(h.err(Sysno::Futex, &[word, WAIT, 5, ts, 0, 0]), EINVAL);
    // futex_time64: struct __kernel_timespec, the padding above the
    // nanoseconds ignored for a 32-bit caller.
    put(&h, ts, &words(&[0, 0, 0, 0xFFFF_FFFF]));
    assert_eq!(
        h.err(Sysno::FutexTime64, &[word, WAIT, 5, ts, 0, 0]),
        ETIMEDOUT
    );
    put(&h, ts, &words(&[0, 0, 1_000_000_000, 0]));
    assert_eq!(
        h.err(Sysno::FutexTime64, &[word, WAIT, 5, ts, 0, 0]),
        EINVAL
    );
}
