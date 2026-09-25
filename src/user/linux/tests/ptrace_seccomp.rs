//! Seccomp under tracing against `kernel/ptrace.c` and `kernel/seccomp.c`
//! (Linux 6.19, `CONFIG_CHECKPOINT_RESTORE`): `PTRACE_O_SUSPEND_SECCOMP`
//! (`check_ptrace_options`: `CAP_SYS_ADMIN`, a tracer without seccomp and
//! not itself suspended; `__secure_computing` skipping every check while
//! it is set), and `PTRACE_SECCOMP_GET_FILTER` and
//! `PTRACE_SECCOMP_GET_METADATA` (the tracer's checks, `get_nth_filter`'s
//! order from the oldest filter, the copies into the tracer).

use super::harness::{Harness, each_abi};
use super::ptrace_regsets::{e, fake_tracee, tracer_call};
use super::ptrace_stops::{ask, traced};
use super::seccomp::{fprog, nnp, on};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::ptrace::{Msg, opt, req};
use crate::user::linux::seccomp::bpf::Insn;
use crate::user::linux::seccomp::{RET_ALLOW, RET_ERRNO};

/// `SECCOMP_FILTER_FLAG_LOG`.
const FLAG_LOG: u64 = 2;

/// Makes the harness process root (`CAP_SYS_ADMIN`) or not.
fn as_root(h: &mut Harness, root: bool) {
    h.proc.state.creds.1 = if root { 0 } else { 1000 };
}

/// Installs `prog` with `flags` on thread 0.
fn install(h: &mut Harness, flags: u64, prog: &[Insn]) {
    let at = h.scratch + 0x400;
    let fp = fprog(h, at, prog);
    assert_eq!(h.call(Sysno::Seccomp, &[1, flags, fp]), 0);
}

fn bytes(prog: &[Insn]) -> Vec<u8> {
    prog.iter().flat_map(|i| i.encode()).collect()
}

#[test]
fn suspending_seccomp_needs_an_unconfined_admin_tracer() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let tid = h.proc.state.ppid;
    let mut tracee = fake_tracee(&mut h, tid);
    let t = tid as u64;
    let setopts = |suspend: u64| [req::SETOPTIONS, t, 0, suspend];
    // Without CAP_SYS_ADMIN: EPERM, before anything reaches the tracee.
    as_root(&mut h, false);
    let got = tracer_call(
        &mut h,
        &mut tracee,
        setopts(opt::SUSPEND_SECCOMP),
        0,
        vec![],
    );
    assert_eq!(got, (e(EPERM), None));
    // Unknown options first: EINVAL.
    let bad = opt::SUSPEND_SECCOMP | 0x40_0000;
    assert_eq!(
        tracer_call(&mut h, &mut tracee, setopts(bad), 0, vec![]),
        (e(EINVAL), None)
    );
    // As root: passed on.
    as_root(&mut h, true);
    let (ret, m) = tracer_call(
        &mut h,
        &mut tracee,
        setopts(opt::SUSPEND_SECCOMP),
        0,
        vec![],
    );
    assert_eq!(ret, 0);
    assert!(matches!(
        m,
        Some(Msg::Request {
            req: req::SETOPTIONS,
            data: opt::SUSPEND_SECCOMP,
            ..
        })
    ));
    // A tracer itself traced with seccomp suspended: EPERM.
    let tracer = h.proc.state.ppid;
    let me = crate::user::linux::ptrace::Traced::new(
        tracer,
        crate::user::linux::ptrace::LinkId::Parent,
        false,
        opt::SUSPEND_SECCOMP,
    );
    h.proc.threads[0].ptrace = Some(me);
    let got = tracer_call(
        &mut h,
        &mut tracee,
        setopts(opt::SUSPEND_SECCOMP),
        0,
        vec![],
    );
    assert_eq!(got, (e(EPERM), None));
    h.proc.threads[0].ptrace = None;
    // A tracer under seccomp: EPERM.
    nnp(&mut h);
    let allow = [Insn {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: RET_ALLOW,
    }];
    install(&mut h, 0, &allow);
    let got = tracer_call(
        &mut h,
        &mut tracee,
        setopts(opt::SUSPEND_SECCOMP),
        0,
        vec![],
    );
    assert_eq!(got, (e(EPERM), None));
    // PTRACE_SEIZE checks its options the same way, before it attaches.
    as_root(&mut h, false);
    h.proc.state.tracees.remove(tid);
    let seize = [req::SEIZE, t, 0, opt::SUSPEND_SECCOMP];
    assert_eq!(
        tracer_call(&mut h, &mut tracee, seize, 0, vec![]),
        (e(EPERM), None)
    );
}

#[test]
fn a_suspended_tracee_skips_seccomp() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        nnp(&mut h);
        let prog = on(&h, Sysno::Getpid, RET_ERRNO | EPERM as u32);
        install(&mut h, 0, &prog);
        assert_eq!(h.call(Sysno::Getpid, &[]), e(EPERM));
        // Traced with the option: the filter is not run.
        let _tr = traced(&mut h, opt::SUSPEND_SECCOMP);
        let t = h.proc.threads[0].ptrace.as_mut().unwrap();
        t.stop = None;
        let pid = h.proc.state.pid as i64;
        assert_eq!(h.call(Sysno::Getpid, &[]), pid);
        // The option cleared: checked again.
        h.proc.threads[0].ptrace.as_mut().unwrap().options = 0;
        assert_eq!(h.call(Sysno::Getpid, &[]), e(EPERM));
        // Strict mode too.
        h.proc.threads[0].ptrace.as_mut().unwrap().options = opt::SUSPEND_SECCOMP;
        h.proc.threads[0].seccomp.mode = crate::user::linux::seccomp::MODE_STRICT;
        assert_eq!(h.call(Sysno::Getpid, &[]), pid);
    });
}

#[test]
fn a_tracee_gives_its_filters_oldest_first() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        nnp(&mut h);
        // No filters: EINVAL (not in filter mode).
        let mut tr = traced(&mut h, 0);
        let (ret, _) = ask(&mut h, &mut tr, req::SECCOMP_GET_FILTER, 0, 0, &[]);
        assert_eq!(ret, e(EINVAL));
        // Two filters, the first with SECCOMP_FILTER_FLAG_LOG.
        let first = on(&h, Sysno::Getpid, RET_ALLOW);
        let second = on(&h, Sysno::Getppid, RET_ERRNO | 1);
        let mut seccomp = crate::user::linux::seccomp::Seccomp::default();
        seccomp.attach(first.clone(), true);
        seccomp.attach(second.clone(), false);
        h.proc.threads[0].seccomp = seccomp;
        for (off, prog) in [(0, &first), (1, &second)] {
            let (ret, b) = ask(&mut h, &mut tr, req::SECCOMP_GET_FILTER, off, 0, &[]);
            assert_eq!((ret, b), (prog.len() as i64, bytes(prog)), "{off}");
        }
        let (ret, _) = ask(&mut h, &mut tr, req::SECCOMP_GET_FILTER, 2, 0, &[]);
        assert_eq!(ret, e(ENOENT));
        // The metadata: the offset and the filter's flags.
        for (off, flags) in [(0u64, FLAG_LOG), (1, 0)] {
            let (ret, b) = ask(
                &mut h,
                &mut tr,
                req::SECCOMP_GET_METADATA,
                16,
                0,
                &off.to_le_bytes(),
            );
            let mut want = off.to_le_bytes().to_vec();
            want.extend(flags.to_le_bytes());
            assert_eq!((ret, b), (0, want));
        }
        let (ret, _) = ask(
            &mut h,
            &mut tr,
            req::SECCOMP_GET_METADATA,
            16,
            0,
            &5u64.to_le_bytes(),
        );
        assert_eq!(ret, e(ENOENT));
    });
}

#[test]
fn a_tracer_checks_and_copies_seccomp_queries() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let tid = h.proc.state.ppid;
    let mut tracee = fake_tracee(&mut h, tid);
    let t = tid as u64;
    let buf = h.scratch;
    // Without CAP_SYS_ADMIN: EACCES first.
    as_root(&mut h, false);
    for request in [req::SECCOMP_GET_FILTER, req::SECCOMP_GET_METADATA] {
        let got = tracer_call(&mut h, &mut tracee, [request, t, 0, buf], 0, vec![]);
        assert_eq!(got, (e(EACCES), None));
    }
    as_root(&mut h, true);
    // The count alone without a buffer; with one, the instructions.
    let prog: Vec<u8> = (0u8..16).collect();
    let (ret, m) = tracer_call(
        &mut h,
        &mut tracee,
        [req::SECCOMP_GET_FILTER, t, 1, 0],
        2,
        prog.clone(),
    );
    assert_eq!(ret, 2);
    assert!(matches!(m, Some(Msg::Request { addr: 1, .. })));
    h.fill(buf, 16, 0);
    let (ret, _) = tracer_call(
        &mut h,
        &mut tracee,
        [req::SECCOMP_GET_FILTER, t, 1, buf],
        2,
        prog.clone(),
    );
    assert_eq!(ret, 2);
    let mut got = [0u8; 16];
    h.proc.state.space.read_raw(buf, &mut got).unwrap();
    assert_eq!(got.to_vec(), prog);
    // An unwritable buffer: EFAULT after the tracee answered.
    let (ret, m) = tracer_call(
        &mut h,
        &mut tracee,
        [req::SECCOMP_GET_FILTER, t, 1, 8],
        2,
        prog,
    );
    assert_eq!(ret, e(EFAULT));
    assert!(m.is_some());
    // The metadata: a size below filter_off's (EINVAL), filter_off read
    // from the tracer (EFAULT), and as much as the size allows.
    let (ret, m) = tracer_call(
        &mut h,
        &mut tracee,
        [req::SECCOMP_GET_METADATA, t, 7, buf],
        0,
        vec![],
    );
    assert_eq!((ret, m), (e(EINVAL), None));
    let (ret, m) = tracer_call(
        &mut h,
        &mut tracee,
        [req::SECCOMP_GET_METADATA, t, 16, 8],
        0,
        vec![],
    );
    assert_eq!((ret, m), (e(EFAULT), None));
    h.proc
        .state
        .space
        .write_raw(buf, &3u64.to_le_bytes())
        .unwrap();
    let mut md = 3u64.to_le_bytes().to_vec();
    md.extend(FLAG_LOG.to_le_bytes());
    h.fill(buf + 8, 8, 0xee);
    let (ret, m) = tracer_call(
        &mut h,
        &mut tracee,
        [req::SECCOMP_GET_METADATA, t, 12, buf],
        0,
        md.clone(),
    );
    assert_eq!(ret, 12);
    assert!(matches!(&m, Some(Msg::Request { payload, .. }) if payload == &3u64.to_le_bytes()));
    h.proc.state.space.read_raw(buf, &mut got).unwrap();
    assert_eq!(&got[..12], &md[..12]);
    assert_eq!(&got[12..], &[0xee; 4]);
    let (ret, _) = tracer_call(
        &mut h,
        &mut tracee,
        [req::SECCOMP_GET_METADATA, t, 64, buf],
        0,
        md,
    );
    assert_eq!(ret, 16);
    // A tracer under seccomp: EACCES.
    nnp(&mut h);
    let allow = [Insn {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: RET_ALLOW,
    }];
    install(&mut h, 0, &allow);
    let got = tracer_call(
        &mut h,
        &mut tracee,
        [req::SECCOMP_GET_FILTER, t, 0, 0],
        0,
        vec![],
    );
    assert_eq!(got, (e(EACCES), None));
}
