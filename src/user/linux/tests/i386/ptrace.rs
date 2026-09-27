//! Tracing an i386 thread against Linux 6.19 on x86-64
//! (`arch/x86/kernel/ptrace.c`'s `ia32_arch_ptrace`, `getreg32`,
//! `putreg32`, and `user_x86_32_view`; `fpu/regset.c`; `tls.c`): the
//! answers a 32-bit tracer gets (32-bit words, `struct
//! user_regs_struct32`, `struct user32` offsets, the FSAVE environment,
//! the TLS entries), the i386 register sets any tracer gets of a thread
//! running 32-bit code, and the x86-64 view's real selectors for it. The
//! tracer's own side (`struct compat_iovec`, `struct compat_siginfo`) is
//! the fixture `ptrace32`'s.

use super::super::harness::Harness;
use super::super::ptrace_stops::{Tracer, traced};
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::ptrace::{Msg, regs, req};

fn e(errno: i32) -> i64 {
    -(errno as i64)
}

/// A request to thread 0, asked in a 32-bit call when `compat`.
fn ask(
    h: &mut Harness,
    tr: &mut Tracer,
    compat: bool,
    request: u64,
    addr: u64,
    data: u64,
    payload: &[u8],
) -> (i64, Vec<u8>) {
    let m = Msg::Request {
        tid: h.proc.threads[0].tid,
        req: request,
        addr,
        data,
        compat,
        payload: payload.to_vec(),
    };
    assert!(tr.link.send(&m));
    loop {
        h.proc.collect_async(None);
        for m in tr.link.recv() {
            if let Msg::Reply { ret, payload } = m {
                return (ret, payload);
            }
        }
    }
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

#[test]
fn a_32_bit_tracer_gets_the_i386_forms() {
    let mut h = Harness::new(LinuxAbi::I386);
    let mut tr = traced(&mut h, 0);
    let t = &mut tr;
    // struct user_regs_struct32: eip at 48, cs at 52, ss at 64, and
    // orig_eax -1 outside a call.
    let (r, regs) = ask(&mut h, t, true, req::GETREGS, 0, 0, &[]);
    assert_eq!((r, regs.len()), (0, 68));
    assert_eq!((word(&regs, 52), word(&regs, 64)), (0x23, 0x2b));
    assert_eq!(word(&regs, 44), u32::MAX);
    // struct user32's words: its end reads as zero, past it and
    // misaligned are EIO.
    let (r, eip) = ask(&mut h, t, true, req::PEEKUSR, 48, 0, &[]);
    assert_eq!((r, eip), (0, regs[48..52].to_vec()));
    assert_eq!(
        ask(&mut h, t, true, req::PEEKUSR, 284, 0, &[]),
        (0, vec![0; 4])
    );
    assert_eq!(ask(&mut h, t, true, req::PEEKUSR, 288, 0, &[]).0, e(EIO));
    assert_eq!(ask(&mut h, t, true, req::PEEKUSR, 2, 0, &[]).0, e(EIO));
    // Selectors: user privilege, and the code segment it runs with.
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 52, 0x20, &[]).0, e(EIO));
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 52, 0x33, &[]).0, e(EIO));
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 64, 0, &[]).0, e(EIO));
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 0, 0x1234, &[]).0, 0);
    let (_, ebx) = ask(&mut h, t, true, req::PEEKUSR, 0, 0, &[]);
    assert_eq!(ebx, 0x1234u32.to_le_bytes());
    assert_eq!(ask(&mut h, t, true, req::SETREGS, 0, 0, &regs).0, 0);
    let (_, ebx) = ask(&mut h, t, true, req::PEEKUSR, 0, 0, &[]);
    assert_eq!(ebx, regs[..4]);
    // The FSAVE environment: the control word's upper half set, fcs the
    // code selector; and the FXSAVE area, MXCSR at 24.
    let (r, fp) = ask(&mut h, t, true, req::GETFPREGS, 0, 0, &[]);
    assert_eq!((r, fp.len()), (0, 108));
    assert_eq!((word(&fp, 0), word(&fp, 16)), (0xFFFF_037F, 0x23));
    assert_eq!(ask(&mut h, t, true, req::SETFPREGS, 0, 0, &fp).0, 0);
    let (r, fx) = ask(&mut h, t, true, req::GETFPXREGS, 0, 0, &[]);
    assert_eq!((r, fx.len(), word(&fx, 24)), (0, 512, 0x1F80));
    // The TLS entries, 12 to 14.
    let (r, desc) = ask(&mut h, t, true, req::GET_THREAD_AREA, 12, 0, &[]);
    assert_eq!((r, word(&desc, 0)), (0, 12));
    assert_eq!(
        ask(&mut h, t, true, req::GET_THREAD_AREA, 5, 0, &[]).0,
        e(EINVAL)
    );
    let mut bad = [0u8; 16];
    bad[12] = 1 << 5;
    assert_eq!(
        ask(&mut h, t, true, req::SET_THREAD_AREA, 13, 0, &bad).0,
        e(EINVAL)
    );
    // PEEKDATA's word is 32 bits.
    let at = h.scratch;
    h.proc.state.space.write_raw(at, b"abcdefgh").unwrap();
    assert_eq!(
        ask(&mut h, t, true, req::PEEKDATA, at, 0, &[]),
        (0, b"abcd".to_vec())
    );
}

#[test]
fn a_32_bit_threads_sets_are_the_i386_views() {
    let mut h = Harness::new(LinuxAbi::I386);
    let mut tr = traced(&mut h, 0);
    let t = &mut tr;
    let get =
        |h: &mut Harness, t: &mut Tracer, nt: u64| ask(h, t, false, req::GETREGSET, nt, 8192, &[]);
    assert_eq!(get(&mut h, t, regs::NT_PRSTATUS).1.len(), 68);
    assert_eq!(get(&mut h, t, regs::NT_PRFPREG).1.len(), 108);
    assert_eq!(get(&mut h, t, regs::NT_PRXFPREG).1.len(), 512);
    let (r, tls) = get(&mut h, t, regs::NT_386_TLS);
    assert_eq!((r, tls.len(), word(&tls, 32)), (0, 48, 14));
    assert_eq!(get(&mut h, t, regs::NT_X86_SHSTK).0, e(EINVAL));
    assert_eq!(get(&mut h, t, regs::NT_386_IOPERM).0, e(ENXIO));
    // regset_tls_set: every descriptor checked first; empty ones clear
    // their entries.
    let mut set = tls.clone();
    set[12 + 16] = 1 << 5;
    let (r, _) = ask(&mut h, t, false, req::SETREGSET, regs::NT_386_TLS, 48, &set);
    assert_eq!(r, e(EINVAL));
    let empty: Vec<u8> = (0..3)
        .flat_map(|i| {
            let mut d = [0u8; 16];
            d[0..4].copy_from_slice(&(12u32 + i).to_le_bytes());
            d
        })
        .collect();
    let (r, _) = ask(
        &mut h,
        t,
        false,
        req::SETREGSET,
        regs::NT_386_TLS,
        48,
        &empty,
    );
    assert_eq!(r, 0);
    // fill_user_desc of a clear entry: read_exec_only and seg_not_present.
    let cleared: Vec<u8> = empty
        .chunks(16)
        .flat_map(|d| [&d[..12], &0x28u32.to_le_bytes()[..]].concat())
        .collect();
    assert_eq!(get(&mut h, t, regs::NT_386_TLS).1, cleared);
    // The x86-64 view of a 32-bit thread (a 64-bit tracer's GETREGS):
    // its own selectors.
    let (_, regs64) = ask(&mut h, t, false, req::GETREGS, 0, 0, &[]);
    let at = |i: usize| u64::from_le_bytes(regs64[i * 8..i * 8 + 8].try_into().unwrap());
    assert_eq!((at(17), at(20), at(23)), (0x23, 0x2b, 0x2b));
}
