//! Register sets, pending signals, and the other queries of a stopped
//! tracee, against `kernel/ptrace.c`, `arch/x86/kernel/fpu/regset.c`,
//! `arch/x86/kernel/fpu/xstate.c`, and the architectures' `ptrace.c`
//! (Linux 6.19): the floating-point registers of each architecture
//! (`NT_PRFPREG`, x86-64's `PTRACE_GETFPREGS` and `PTRACE_SETFPREGS` with
//! `xfpregs_set`'s whole-area and MXCSR checks, AArch64's and RISC-V's
//! partial writes), x86-64's XSAVE area (`NT_X86_XSTATE`: the software
//! bytes, the header, `EFAULT` for a partial write, `EINVAL` for a
//! compacted header), AArch64's `NT_ARM_TLS`, x86-64's `PTRACE_ARCH_PRCTL`,
//! `PTRACE_PEEKSIGINFO` over either queue (checks, order, offsets, a fault
//! after some records), and `PTRACE_GET_RSEQ_CONFIGURATION`. Both sides are
//! exercised: the tracee answering over its link, and the tracer's checks
//! and copies against a tracee the test plays.

use super::harness::{Harness, each_abi};
use super::ptrace_stops::{Tracer, ask, traced};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::ptrace::{Link, LinkId, Msg, regs, req};
use crate::user::linux::signal::{SIGRTMIN, SIGUSR1, SIGUSR2, SigInfo, code};

fn e(errno: i32) -> i64 {
    -(errno as i64)
}

/// `PTRACE_GETREGSET` of `nt` for `len` bytes, as the tracee answers it.
fn get(h: &mut Harness, tr: &mut Tracer, nt: u64, len: u64) -> Vec<u8> {
    let (ret, b) = ask(h, tr, req::GETREGSET, nt, len, &[]);
    assert_eq!(ret, 0);
    b
}

/// `PTRACE_SETREGSET` of `nt` with `bytes`.
fn set(h: &mut Harness, tr: &mut Tracer, nt: u64, bytes: &[u8]) -> i64 {
    ask(h, tr, req::SETREGSET, nt, bytes.len() as u64, bytes).0
}

/// A tracee the test plays: thread `tid` of the process at the other end
/// of the harness's parent link, stopped. Returns the test's end.
fn fake_tracee(h: &mut Harness, tid: i32) -> Link {
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let me = h.proc.threads[0].tid;
    h.proc.state.tracees.add(tid, me, LinkId::Parent, false);
    h.proc.state.tracees.get_mut(tid).unwrap().stopped = Some(19);
    theirs
}

/// A `ptrace` call of the harness (the tracer) answered by the test with
/// `ret` and `payload`, if it reaches the tracee: the call's result and the
/// request that came.
fn tracer_call(
    h: &mut Harness,
    tracee: &mut Link,
    args: [u64; 4],
    ret: i64,
    payload: Vec<u8>,
) -> (i64, Option<Msg>) {
    let Some(early) = h.start(0, Sysno::Ptrace, &args) else {
        let request = loop {
            if let Some(m) = tracee.recv().into_iter().next() {
                break m;
            }
            std::thread::yield_now();
        };
        assert!(tracee.send(&Msg::Reply { ret, payload }));
        while h.proc.threads[0].blocked.is_some() {
            h.proc.wake_sleepers();
        }
        return (h.result(0), Some(request));
    };
    (early, None)
}

/// The value of a vector register the test writes: register `n` in each
/// architecture's floating-point set.
fn put_vector(cpu: &mut GuestCpu, n: u8, v: u128) {
    match cpu {
        GuestCpu::X86_64(c) => {
            let mut image = c.vcpu().xsave_image(0x3).bytes[..512].to_vec();
            let at = 160 + 16 * n as usize;
            image[at..at + 16].copy_from_slice(&v.to_le_bytes());
            c.vcpu_mut().fxrstor_image(&image).unwrap();
        }
        GuestCpu::Aarch64(c) => c.core_mut().set_simd(n, v),
        GuestCpu::Riscv64(c) => c.core_mut().set_f(n, v as u64),
    }
}

#[test]
fn floating_point_registers_as_each_architecture_lays_them_out() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (unit, size, reg0, ctl) = match abi {
            // fxregs_state: xmm0 at 160, MXCSR at 24.
            LinuxAbi::X86_64 => (8, 512, 160, 24),
            // user_fpsimd_state: v0 at 0, fpsr at 512, fpcr at 516.
            LinuxAbi::Aarch64 => (4, 528, 0, 516),
            // __riscv_d_ext_state: f0 at 0, fcsr at 256.
            LinuxAbi::Riscv64 => (8, 264, 0, 256),
        };
        assert_eq!(
            regs::layout(&h.proc.threads[0].cpu, regs::NT_PRFPREG),
            Ok((unit, size))
        );
        let value = 0x0123_4567_89ab_cdef_0f1e_2d3c_4b5a_6978u128;
        put_vector(&mut h.proc.threads[0].cpu, 0, value);
        let mut tr = traced(&mut h, 0);
        let b = get(&mut h, &mut tr, regs::NT_PRFPREG, size);
        assert_eq!(b.len(), size as usize);
        let width = if abi == LinuxAbi::Riscv64 { 8 } else { 16 };
        assert_eq!(b[reg0..reg0 + width], value.to_le_bytes()[..width]);
        // The reserved tail is zero.
        let tail = match abi {
            LinuxAbi::X86_64 => 416,
            LinuxAbi::Aarch64 => 520,
            LinuxAbi::Riscv64 => 260,
        };
        assert!(b[tail..].iter().all(|&x| x == 0));
        // Written back with register 1 and a rounding control changed.
        let mut w = b.clone();
        w[reg0 + width..reg0 + 2 * width].fill(0x5a);
        let rounding: u32 = match abi {
            LinuxAbi::X86_64 => 0x3f80,   // MXCSR round down.
            LinuxAbi::Aarch64 => 1 << 22, // FPCR.RMode: +inf.
            LinuxAbi::Riscv64 => 2 << 5,  // frm: round down.
        };
        w[ctl..ctl + 4].copy_from_slice(&rounding.to_le_bytes());
        assert_eq!(set(&mut h, &mut tr, regs::NT_PRFPREG, &w), 0);
        assert_eq!(get(&mut h, &mut tr, regs::NT_PRFPREG, size), w);
        match abi {
            LinuxAbi::X86_64 => {
                // Only the whole area (EINVAL), and no reserved MXCSR bit.
                assert_eq!(set(&mut h, &mut tr, regs::NT_PRFPREG, &w[..256]), e(EINVAL));
                let mut bad = w.clone();
                bad[ctl..ctl + 4].copy_from_slice(&0x1_0000u32.to_le_bytes());
                assert_eq!(set(&mut h, &mut tr, regs::NT_PRFPREG, &bad), e(EINVAL));
                // PTRACE_GETFPREGS and PTRACE_SETFPREGS are the same set.
                assert_eq!(ask(&mut h, &mut tr, req::GETFPREGS, 0, 0, &[]).1, w);
                assert_eq!(ask(&mut h, &mut tr, req::SETFPREGS, 0, 0, &b).0, 0);
                assert_eq!(get(&mut h, &mut tr, regs::NT_PRFPREG, size), b);
            }
            _ => {
                // A prefix: register 0 only.
                assert_eq!(set(&mut h, &mut tr, regs::NT_PRFPREG, &b[..8]), 0);
                let now = get(&mut h, &mut tr, regs::NT_PRFPREG, size);
                assert_eq!(now[..8], b[..8]);
                assert_eq!(now[8..], w[8..]);
            }
        }
    });
}

#[test]
fn x86_64_xsave_area() {
    use crate::user::linux::signal::frame::x86_64::{FP_XSTATE_MAGIC1, SW_RESERVED};
    let mut h = Harness::new(LinuxAbi::X86_64);
    let GuestCpu::X86_64(c) = &h.proc.threads[0].cpu else {
        unreachable!()
    };
    let (size, xcr0) = (c.vcpu().xsave_standard_size(), c.vcpu().xcr0());
    assert_eq!(
        regs::layout(&h.proc.threads[0].cpu, regs::NT_X86_XSTATE),
        Ok((8, size as u64))
    );
    let mut tr = traced(&mut h, 0);
    let b = get(&mut h, &mut tr, regs::NT_X86_XSTATE, size as u64);
    let word = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let at = SW_RESERVED as usize;
    // xstate_fx_sw_bytes: magic, extended size, features, XSAVE size.
    assert_eq!(word(at) as u32, FP_XSTATE_MAGIC1);
    assert_eq!((word(at) >> 32) as usize, size + 4);
    assert_eq!(word(at + 8), xcr0);
    assert_eq!(word(at + 16) as u32 as usize, size);
    // The header: the features, a standard-format area.
    assert_eq!((word(512), word(520)), (xcr0, 0));
    // The legacy part agrees with NT_PRFPREG.
    let fp = get(&mut h, &mut tr, regs::NT_PRFPREG, 512);
    assert_eq!(b[..416], fp[..416]);
    // Written back whole; partial writes are EFAULT, compacted EINVAL.
    assert_eq!(set(&mut h, &mut tr, regs::NT_X86_XSTATE, &b), 0);
    assert_eq!(
        set(&mut h, &mut tr, regs::NT_X86_XSTATE, &b[..size - 8]),
        e(EFAULT)
    );
    let mut compact = b.clone();
    compact[520..528].copy_from_slice(&(xcr0 | (1 << 63)).to_le_bytes());
    assert_eq!(
        set(&mut h, &mut tr, regs::NT_X86_XSTATE, &compact),
        e(EINVAL)
    );
    // Other architectures have neither set.
    let h = Harness::new(LinuxAbi::Aarch64);
    let cpu = &h.proc.threads[0].cpu;
    assert_eq!(
        regs::layout(cpu, regs::NT_X86_XSTATE).map_err(|e| e.0),
        Err(EINVAL)
    );
}

#[test]
fn aarch64_tls_register_set() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    h.proc.threads[0].cpu.set_thread_pointer(0x7000_1000);
    let mut tr = traced(&mut h, 0);
    let b = get(&mut h, &mut tr, regs::NT_ARM_TLS, 16);
    assert_eq!(b[..8], 0x7000_1000u64.to_le_bytes());
    assert_eq!(b[8..], [0; 8], "TPIDR2_EL0 without SME");
    assert_eq!(
        set(
            &mut h,
            &mut tr,
            regs::NT_ARM_TLS,
            &0x7000_2000u64.to_le_bytes()
        ),
        0
    );
    assert_eq!(h.proc.threads[0].cpu.thread_pointer(), 0x7000_2000);
    for abi in [LinuxAbi::X86_64, LinuxAbi::Riscv64] {
        let h = Harness::new(abi);
        let cpu = &h.proc.threads[0].cpu;
        assert_eq!(
            regs::layout(cpu, regs::NT_ARM_TLS).map_err(|e| e.0),
            Err(EINVAL)
        );
    }
}

#[test]
fn x86_64_arch_prctl_on_a_tracee() {
    const SET_FS: u64 = 0x1002;
    const GET_FS: u64 = 0x1003;
    const GET_GS: u64 = 0x1004;
    let mut h = Harness::new(LinuxAbi::X86_64);
    let mut tr = traced(&mut h, 0);
    // The tracee's side: the arguments swapped (the code in `data`).
    assert_eq!(
        ask(&mut h, &mut tr, req::ARCH_PRCTL, 0x5000, SET_FS, &[]).0,
        0
    );
    let (ret, b) = ask(&mut h, &mut tr, req::ARCH_PRCTL, 0, GET_FS, &[]);
    assert_eq!((ret, b), (0, 0x5000u64.to_le_bytes().to_vec()));
    let beyond = LinuxAbi::X86_64.task_size();
    assert_eq!(
        ask(&mut h, &mut tr, req::ARCH_PRCTL, beyond, SET_FS, &[]).0,
        e(EPERM)
    );
    assert_eq!(
        ask(&mut h, &mut tr, req::ARCH_PRCTL, 0, 0x1011, &[]).0,
        e(EINVAL)
    );
    // The tracer's side: the base stored at `addr`, or EFAULT.
    let mut h = Harness::new(LinuxAbi::X86_64);
    let mut tracee = fake_tracee(&mut h, 4242);
    let at = h.scratch;
    let base = 0x6000u64.to_le_bytes().to_vec();
    let args = [req::ARCH_PRCTL, 4242, at, GET_GS];
    let (ret, m) = tracer_call(&mut h, &mut tracee, args, 0, base.clone());
    assert!(
        matches!(m, Some(Msg::Request { req: req::ARCH_PRCTL, addr, data: GET_GS, .. }) if addr == at)
    );
    assert_eq!(ret, 0);
    let mut got = [0u8; 8];
    h.proc.state.space.read_raw(at, &mut got).unwrap();
    assert_eq!(got.to_vec(), base);
    let args = [req::ARCH_PRCTL, 4242, 16, GET_GS];
    assert_eq!(tracer_call(&mut h, &mut tracee, args, 0, base).0, e(EFAULT));
    // Other architectures have no PTRACE_ARCH_PRCTL (nor GETFPREGS).
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let mut tracee = fake_tracee(&mut h, 4242);
    for request in [req::ARCH_PRCTL, req::GETFPREGS] {
        let args = [request, 4242, 0, 0];
        assert_eq!(
            tracer_call(&mut h, &mut tracee, args, 0, vec![]),
            (e(EIO), None)
        );
    }
}

/// `struct ptrace_peeksiginfo_args`.
fn peek_args(off: u64, flags: u32, nr: i32) -> Vec<u8> {
    let mut b = off.to_le_bytes().to_vec();
    b.extend_from_slice(&flags.to_le_bytes());
    b.extend_from_slice(&nr.to_le_bytes());
    b
}

#[test]
fn peeksiginfo_walks_either_queue_in_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let me = h.proc.state.pid;
        let queued = [
            SigInfo::kill(SIGUSR2, code::SI_USER, me, 0),
            SigInfo::kill(SIGRTMIN, code::SI_QUEUE, me, 0),
            SigInfo::kill(SIGRTMIN, code::SI_QUEUE, 77, 0),
            SigInfo::kill(SIGUSR1, code::SI_USER, me, 0),
        ];
        // Queued while the thread is stopped (its stop took the first
        // deliverable signal otherwise).
        let mut tr = traced(&mut h, 0);
        for info in queued {
            h.proc.threads[0].pending.enqueue(info);
        }
        h.proc
            .state
            .shared_pending
            .enqueue(SigInfo::kernel(SIGUSR1));
        let peek = |h: &mut Harness, tr: &mut Tracer, off, flags, nr| {
            let (ret, b) = ask(h, tr, req::PEEKSIGINFO, 0, 0, &peek_args(off, flags, nr));
            let infos: Vec<SigInfo> = b.chunks_exact(128).map(SigInfo::decode).collect();
            (ret, infos)
        };
        // The thread's own queue in order, from an offset, up to a count.
        let (n, infos) = peek(&mut h, &mut tr, 0, 0, 16);
        assert_eq!(n, 4);
        assert_eq!(infos, queued.to_vec());
        let (n, infos) = peek(&mut h, &mut tr, 1, 0, 2);
        assert_eq!((n, infos), (2, queued[1..3].to_vec()));
        assert_eq!(peek(&mut h, &mut tr, 9, 0, 4).0, 0, "past the end");
        assert_eq!(peek(&mut h, &mut tr, 0, 0, 0).0, 0, "none asked for");
        // The process's shared queue.
        let (n, infos) = peek(&mut h, &mut tr, 0, 1, 8);
        assert_eq!(
            (n, infos[0].signo, infos[0].code),
            (1, SIGUSR1, code::SI_KERNEL)
        );
    });
}

#[test]
fn peeksiginfo_checks_and_copies_as_the_tracer() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let mut tracee = fake_tracee(&mut h, 4242);
    let args_at = h.scratch;
    let out = h.scratch + 0x100;
    let write_args = |h: &mut Harness, b: &[u8]| h.proc.state.space.write_raw(args_at, b).unwrap();
    // The arguments: unreadable (EFAULT), unknown flags or a negative count
    // (EINVAL); none of them reaches the tracee.
    let call = [req::PEEKSIGINFO, 4242, 16, out];
    assert_eq!(
        tracer_call(&mut h, &mut tracee, call, 0, vec![]),
        (e(EFAULT), None)
    );
    let call = [req::PEEKSIGINFO, 4242, args_at, out];
    write_args(&mut h, &peek_args(0, 2, 1));
    assert_eq!(
        tracer_call(&mut h, &mut tracee, call, 0, vec![]),
        (e(EINVAL), None)
    );
    write_args(&mut h, &peek_args(0, 0, -1));
    assert_eq!(
        tracer_call(&mut h, &mut tracee, call, 0, vec![]),
        (e(EINVAL), None)
    );
    // Records copied in turn; a fault after the first ends the copy.
    write_args(&mut h, &peek_args(0, 0, 3));
    let records: Vec<u8> = (0..3)
        .flat_map(|i| SigInfo::kill(SIGUSR1, code::SI_USER, i, 0).encode())
        .collect();
    let (ret, _) = tracer_call(&mut h, &mut tracee, call, 3, records.clone());
    assert_eq!(ret, 3);
    let mut got = vec![0u8; 3 * 128];
    h.proc.state.space.read_raw(out, &mut got).unwrap();
    assert_eq!(got, records);
    // Straddling the end of the scratch mapping: one record fits.
    let edge = h.scratch + 0x1000 - 128;
    let call = [req::PEEKSIGINFO, 4242, args_at, edge];
    let scratch_end = h
        .proc
        .state
        .space
        .read_raw(edge + 128, &mut [0u8; 1])
        .is_err();
    if scratch_end {
        assert_eq!(
            tracer_call(&mut h, &mut tracee, call, 3, records.clone()).0,
            1
        );
    }
    let call = [req::PEEKSIGINFO, 4242, args_at, 16];
    assert_eq!(
        tracer_call(&mut h, &mut tracee, call, 3, records).0,
        e(EFAULT)
    );
}

#[test]
fn rseq_configuration() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = traced(&mut h, 0);
        let (ret, b) = ask(&mut h, &mut tr, req::GET_RSEQ_CONFIGURATION, 24, 0, &[]);
        assert_eq!((ret, b), (24, vec![0; 24]), "not registered");
        h.proc.threads[0].rseq = Some(crate::user::linux::rseq::Rseq::new(
            0x7000_0040,
            32,
            0x5305_3053,
        ));
        let (_, b) = ask(&mut h, &mut tr, req::GET_RSEQ_CONFIGURATION, 24, 0, &[]);
        assert_eq!(b[..8], 0x7000_0040u64.to_le_bytes());
        assert_eq!(b[8..16], [32, 0, 0, 0, 0x53, 0x30, 0x05, 0x53]);
        assert_eq!(b[16..], [0; 8]);
    });
}
