//! Restartable sequences against `kernel/rseq.c` and
//! `include/linux/rseq_entry.h` (Linux 6.19) on every ABI: `rseq`'s checks
//! in order and the fields it writes, and the return to user mode driven
//! directly: IDs after registration, a preempted or signalled critical
//! section resuming at its abort handler, a section only cleared when the
//! instruction pointer is outside it or the thread entered by a system
//! call, and the failures that force `SIGSEGV`.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::rseq;

const SIG: u64 = 0x5305_3053;
const UNREGISTER: u64 = 1;

fn u32_at(h: &Harness, at: u64) -> u32 {
    let mut b = [0u8; 4];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    u32::from_le_bytes(b)
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    let mut b = [0u8; 8];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    u64::from_le_bytes(b)
}

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

/// A `struct rseq_cs` at `at` for `[start, start + len)` aborting to
/// `abort`, whose preceding word is `sig`.
fn descriptor(h: &Harness, at: u64, start: u64, len: u64, abort: u64, sig: u32) {
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&start.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(&abort.to_le_bytes());
    put(h, at, &b);
    put(h, abort - 4, &sig.to_le_bytes());
}

#[test]
fn rseq_checks_in_the_kernels_order_and_writes_its_fields() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let (area, spare) = (m, m + 0x100);
        let e = |v: i32| -(v as i64);
        let rs = |h: &mut Harness, a: u64, len: u64, flags: u64, sig: u64| {
            h.call(Sysno::Rseq, &[a, len, flags, sig])
        };
        assert_eq!(rs(&mut h, area, 32, 0x100, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, area, 31, 0, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, area + 8, 32, 0, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, area + 8, 64, 0, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, 0xffff_8000_0000_0000, 32, 0, SIG), e(EFAULT));
        assert_eq!(rs(&mut h, 32, 32, 0, SIG), e(EFAULT), "unmapped");
        assert_eq!(rs(&mut h, area, 32, UNREGISTER, SIG), e(EINVAL));
        put(&h, area, &[0x77; 32]);
        assert_eq!(rs(&mut h, area, 32, 0, SIG), 0);
        assert_eq!(u32_at(&h, area), u32::MAX, "cpu_id_start");
        assert_eq!(u32_at(&h, area + 4), u32::MAX, "cpu_id");
        assert_eq!(u64_at(&h, area + 8), 0, "rseq_cs");
        assert_eq!(u32_at(&h, area + 16), 0x7777_7777, "flags untouched");
        assert_eq!((u32_at(&h, area + 20), u32_at(&h, area + 24)), (0, 0));
        assert_eq!(rs(&mut h, area, 32, 0, SIG), e(EBUSY));
        assert_eq!(rs(&mut h, area, 32, 0, SIG + 1), e(EPERM));
        assert_eq!(rs(&mut h, spare, 32, 0, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, area, 64, 0, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, area, 32, UNREGISTER | 0x100, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, spare, 32, UNREGISTER, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, area, 64, UNREGISTER, SIG), e(EINVAL));
        assert_eq!(rs(&mut h, area, 32, UNREGISTER, SIG + 1), e(EPERM));
        assert_eq!(rs(&mut h, area, 32, UNREGISTER, SIG), 0);
        assert_eq!(
            (u32_at(&h, area), u32_at(&h, area + 4)),
            (u32::MAX, u32::MAX)
        );
        assert!(h.proc.threads[0].rseq.is_none());
        // A larger area: aligned and at least the known fields.
        assert_eq!(rs(&mut h, spare, 64, 0, SIG), 0);
    });
}

#[test]
fn the_return_to_user_mode_fills_in_ids_and_aborts_sections() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let (area, cs) = (m, m + 0x100);
        h.ok(Sysno::Rseq, &[area, 32, 0, SIG]);
        let task = h.proc.state.abi.task_size();
        let space = &h.proc.state.space;
        let t = &mut h.proc.threads[0];
        // Registration forces the IDs on the way out.
        assert!(rseq::exit_to_user(space, abi, task, t));
        assert_eq!((u32_at(&h, area), u32_at(&h, area + 4)), (0, 0));
        // A thread interrupted inside a section and switched out resumes
        // at its abort handler; rseq_cs is cleared.
        let (start, abort) = (0x40_1000, m + 0x204);
        descriptor(&h, cs, start, 0x10, abort, SIG as u32);
        put(&h, area + 8, &cs.to_le_bytes());
        let space = &h.proc.state.space;
        let t = &mut h.proc.threads[0];
        t.cpu.set_pc(start + 8);
        rseq::left_user(t, true);
        rseq::switched(t);
        assert!(rseq::exit_to_user(space, abi, task, t));
        assert_eq!(t.cpu.pc(), abort);
        assert_eq!(u64_at(&h, area + 8), 0);
        // Not switched out: nothing to do.
        put(&h, area + 8, &cs.to_le_bytes());
        let space = &h.proc.state.space;
        let t = &mut h.proc.threads[0];
        t.cpu.set_pc(start);
        rseq::left_user(t, true);
        assert!(rseq::exit_to_user(space, abi, task, t));
        assert_eq!(t.cpu.pc(), start);
        // Entered by a system call: the section is left alone.
        rseq::left_user(t, false);
        rseq::switched(t);
        assert!(rseq::exit_to_user(space, abi, task, t));
        assert_eq!((t.cpu.pc(), u64_at(&h, area + 8)), (start, cs));
        // Signal delivery to an interrupted thread aborts too; outside the
        // section rseq_cs is only cleared.
        let space = &h.proc.state.space;
        let t = &mut h.proc.threads[0];
        rseq::left_user(t, true);
        assert!(rseq::signal_deliver(space, task, t));
        assert_eq!(t.cpu.pc(), abort);
        put(&h, area + 8, &cs.to_le_bytes());
        let space = &h.proc.state.space;
        let t = &mut h.proc.threads[0];
        t.cpu.set_pc(start + 0x10);
        assert!(rseq::signal_deliver(space, task, t));
        assert_eq!((t.cpu.pc(), u64_at(&h, area + 8)), (start + 0x10, 0));
    });
}

#[test]
fn a_bad_descriptor_or_signature_is_fatal() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let (area, cs) = (m, m + 0x100);
        h.ok(Sysno::Rseq, &[area, 32, 0, SIG]);
        let task = h.proc.state.abi.task_size();
        let start = 0x40_1000;
        let mut check = |h: &mut Harness, csaddr: u64, abort: u64, sig: u32| {
            if abort > 4 && abort < m + P && abort > m {
                descriptor(h, cs, start, 0x10, abort, sig);
            } else {
                let mut b = vec![0u8; 8];
                b.extend_from_slice(&start.to_le_bytes());
                b.extend_from_slice(&0x10u64.to_le_bytes());
                b.extend_from_slice(&abort.to_le_bytes());
                put(h, cs, &b);
            }
            put(h, area + 8, &csaddr.to_le_bytes());
            let space = &h.proc.state.space;
            let t = &mut h.proc.threads[0];
            t.cpu.set_pc(start);
            rseq::left_user(t, true);
            rseq::signal_deliver(space, task, t)
        };
        assert!(!check(&mut h, cs, m + 0x204, SIG as u32 + 1), "signature");
        assert!(!check(&mut h, cs, task, SIG as u32), "abort outside");
        assert!(!check(&mut h, cs, 2, SIG as u32), "abort below 4");
        assert!(
            !check(&mut h, task, m + 0x204, SIG as u32),
            "descriptor outside"
        );
        assert!(
            !check(&mut h, 0x10, m + 0x204, SIG as u32),
            "descriptor unmapped"
        );
        assert!(check(&mut h, cs, m + 0x204, SIG as u32), "then fine");
    });
}
