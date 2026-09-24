//! Signal records, queues, and alternate stacks. Expected values follow
//! `asm-generic/siginfo.h` and `kernel/signal.c` (Linux 6.19).

use super::*;

// ------------------------------------------------------------- siginfo_t

#[test]
fn siginfo_encoding_matches_the_uapi_layout() {
    // si_signo @0, si_errno @4, si_code @8, _sifields @16; 128 bytes total
    // with everything past kernel_siginfo (48 bytes) zero.
    let kill = SigInfo::kill(SIGUSR1, code::SI_TKILL, 1234, 1000).encode();
    assert_eq!(kill.len(), 128);
    assert_eq!(i32::from_le_bytes(kill[0..4].try_into().unwrap()), SIGUSR1);
    assert_eq!(i32::from_le_bytes(kill[4..8].try_into().unwrap()), 0);
    assert_eq!(i32::from_le_bytes(kill[8..12].try_into().unwrap()), -6);
    assert_eq!(&kill[12..16], &[0; 4], "padding before the union");
    assert_eq!(i32::from_le_bytes(kill[16..20].try_into().unwrap()), 1234);
    assert_eq!(u32::from_le_bytes(kill[20..24].try_into().unwrap()), 1000);
    assert!(kill[24..].iter().all(|&b| b == 0));

    let fault = SigInfo::fault(SIGSEGV, code::SEGV_ACCERR, 0xdead_beef_0000).encode();
    assert_eq!(
        u64::from_le_bytes(fault[16..24].try_into().unwrap()),
        0xdead_beef_0000
    );

    let queued = SigInfo::queued(SIGRTMIN + 3, code::SI_QUEUE, 7, 8, 0x1122_3344_5566_7788);
    let b = queued.encode();
    assert_eq!(
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
        0x1122_3344_5566_7788
    );
    assert_eq!(SigInfo::decode(&b), queued);

    // SIGCHLD: si_status @24, si_utime @32, si_stime @40.
    let chld = SigInfo::child(code::CLD_EXITED, 99, 5, 3, 11, 12).encode();
    assert_eq!(i32::from_le_bytes(chld[24..28].try_into().unwrap()), 3);
    assert_eq!(i64::from_le_bytes(chld[32..40].try_into().unwrap()), 11);
    assert_eq!(i64::from_le_bytes(chld[40..48].try_into().unwrap()), 12);

    let kernel = SigInfo::kernel(SIGSEGV);
    assert_eq!((kernel.code, kernel.pid(), kernel.uid()), (0x80, 0, 0));
}

#[test]
fn known_siginfo_layouts_follow_the_kernel() {
    let k = |sig, code| SigInfo::kill(sig, code, 0, 0).known_layout();
    assert!(k(SIGSEGV, code::SI_KERNEL));
    assert!(k(SIGSEGV, 10) && !k(SIGSEGV, 11), "NSIGSEGV = 10");
    assert!(k(SIGSYS, 2) && !k(SIGSYS, 3), "NSIGSYS = 2");
    assert!(k(SIGUSR1, 6) && !k(SIGUSR1, 7), "other signals: NSIGPOLL");
    assert!(k(SIGUSR1, 0) && k(SIGUSR1, -7) && !k(SIGUSR1, -8));
    assert!(k(SIGUSR1, -60), "SI_ASYNCNL");
    assert!(!k(SIGUSR1, 0x81));
}

// ------------------------------------------------------------ sigpending

fn user(sig: i32) -> SigInfo {
    SigInfo::kill(sig, code::SI_USER, 1, 0)
}

#[test]
fn standard_signals_coalesce_and_realtime_signals_queue() {
    let mut p = SigPending::new();
    assert!(p.enqueue(user(SIGUSR1)));
    assert!(!p.enqueue(user(SIGUSR1)), "legacy_queue: one instance");
    let rt = SIGRTMIN + 1;
    assert!(p.enqueue(SigInfo::queued(rt, code::SI_QUEUE, 1, 0, 1)));
    assert!(p.enqueue(SigInfo::queued(rt, code::SI_QUEUE, 1, 0, 2)));
    assert_eq!(p.queued(), 3);
    assert_eq!(p.set(), sigmask(SIGUSR1) | sigmask(rt));
    // Real-time instances come out in order and the bit stays set until
    // the last one is collected.
    assert_eq!(p.dequeue(sigmask(SIGUSR1)).unwrap().value(), 1);
    assert!(p.contains(rt));
    assert_eq!(p.dequeue(sigmask(SIGUSR1)).unwrap().value(), 2);
    assert!(!p.contains(rt));
    assert_eq!(p.dequeue(sigmask(SIGUSR1)), None, "blocked");
    assert_eq!(p.dequeue(0).unwrap().signo, SIGUSR1);
}

#[test]
fn dequeue_prefers_synchronous_signals_then_lowest_number() {
    // next_signal: synchronous signals in the first word first, then the
    // lowest-numbered.
    let mut p = SigPending::new();
    for sig in [SIGTERM, SIGHUP, SIGSEGV, SIGUSR2] {
        p.enqueue(user(sig));
    }
    let order: Vec<i32> = std::iter::from_fn(|| p.dequeue(0).map(|i| i.signo)).collect();
    assert_eq!(order, vec![SIGSEGV, SIGHUP, SIGUSR2, SIGTERM]);
}

#[test]
fn synchronous_dequeue_takes_the_first_kernel_generated_fault() {
    let mut p = SigPending::new();
    p.enqueue(user(SIGBUS)); // a kill(): not from the kernel
    p.enqueue(SigInfo::fault(SIGSEGV, code::SEGV_MAPERR, 8));
    p.enqueue(SigInfo::fault(SIGFPE, code::FPE_INTDIV, 16));
    assert_eq!(p.dequeue_synchronous(0).unwrap().signo, SIGSEGV);
    assert_eq!(p.dequeue_synchronous(0).unwrap().signo, SIGFPE);
    assert_eq!(p.dequeue_synchronous(0), None, "SIGBUS came from kill()");
    // Nothing unblocked and synchronous: no dequeue at all.
    p.enqueue(SigInfo::fault(SIGILL, code::ILL_ILLOPC, 0));
    assert_eq!(p.dequeue_synchronous(SYNCHRONOUS_MASK), None);
}

#[test]
fn flush_discards_every_instance() {
    let mut p = SigPending::new();
    let rt = SIGRTMIN;
    p.enqueue(SigInfo::queued(rt, code::SI_QUEUE, 1, 0, 1));
    p.enqueue(SigInfo::queued(rt, code::SI_QUEUE, 1, 0, 2));
    p.enqueue(user(SIGINT));
    p.flush(sigmask(rt));
    assert_eq!((p.set(), p.queued()), (sigmask(SIGINT), 1));
}

// -------------------------------------------------------------- altstack

#[test]
fn alternate_stack_membership_and_flags() {
    let mut a = AltStack::DISABLED;
    assert_eq!(a.ss_flags(0x1000), ss::DISABLE);
    assert_eq!(a.sigsp(0x9000, sa::ONSTACK), 0x9000, "no stack: unchanged");
    a.install((0x1000, 0, 0x2000), 0x9000, 2048).unwrap();
    // __on_sig_stack: sp in (ss_sp, ss_sp + ss_size].
    assert!(!a.on_stack(0x1000) && a.on_stack(0x1001) && a.on_stack(0x3000));
    assert!(!a.on_stack(0x3001));
    assert_eq!(a.ss_flags(0x2000), ss::ONSTACK);
    assert_eq!(a.sigsp(0x9000, sa::ONSTACK), 0x3000);
    assert_eq!(a.sigsp(0x9000, 0), 0x9000, "SA_ONSTACK not set");
    assert_eq!(a.sigsp(0x2000, sa::ONSTACK), 0x2000, "already on it");
    // Changing the stack while on it fails; the size must reach MINSIGSTKSZ.
    use crate::user::linux::abi::errno_table::{EINVAL, ENOMEM, EPERM};
    assert_eq!(a.install((0x5000, 0, 0x2000), 0x2000, 2048), Err(EPERM));
    assert_eq!(a.install((0x5000, 0, 100), 0x9000, 2048), Err(ENOMEM));
    assert_eq!(a.install((0x5000, 4, 0x2000), 0x9000, 2048), Err(EINVAL));
    // SS_DISABLE clears the stack whatever the other fields hold.
    a.install((0x5000, ss::DISABLE, 1), 0x9000, 2048).unwrap();
    assert_eq!(a, AltStack::DISABLED);
}

#[test]
fn autodisarm_stacks_are_never_in_use() {
    let mut a = AltStack::DISABLED;
    a.install((0x1000, ss::AUTODISARM, 0x2000), 0x9000, 2048)
        .unwrap();
    assert!(
        !a.on_stack(0x2000),
        "on_sig_stack ignores SS_AUTODISARM stacks"
    );
    assert!(a.contains(0x2000));
    assert_eq!(
        a.sigsp(0x2000, sa::ONSTACK),
        0x3000,
        "re-entered from the top"
    );
    // sigaltstack reports the computed flags plus SS_AUTODISARM.
    assert_eq!(a.report(0x2000), (0x1000, ss::AUTODISARM, 0x2000));
    // It can be replaced even while the thread runs on it.
    a.install((0x5000, 0, 0x2000), 0x2000, 2048).unwrap();
}

#[test]
fn stack_t_encoding_is_24_bytes() {
    let b = AltStack::encode_stack_t(0x1122, ss::AUTODISARM | ss::ONSTACK, 0x3344);
    assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), 0x1122);
    assert_eq!(
        u32::from_le_bytes(b[8..12].try_into().unwrap()),
        0x8000_0001
    );
    assert_eq!(&b[12..16], &[0; 4]);
    assert_eq!(u64::from_le_bytes(b[16..24].try_into().unwrap()), 0x3344);
    assert_eq!(
        AltStack::decode_stack_t(&b),
        (0x1122, ss::AUTODISARM | ss::ONSTACK, 0x3344)
    );
}

#[test]
fn uapi_flags_depend_on_sa_restorer() {
    use crate::user::linux::abi::LinuxAbi;
    assert_ne!(uapi_sa_flags(LinuxAbi::X86_64) & sa::RESTORER, 0);
    assert_ne!(uapi_sa_flags(LinuxAbi::Aarch64) & sa::RESTORER, 0);
    assert_eq!(uapi_sa_flags(LinuxAbi::Riscv64) & sa::RESTORER, 0);
    assert_eq!(uapi_sa_flags(LinuxAbi::X86_64) & 0x400, 0, "SA_UNSUPPORTED");
}
