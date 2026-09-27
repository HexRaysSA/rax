//! The ARM EABI compatibility ABI against Linux 6.19 on arm64
//! (`CONFIG_COMPAT`): the layout of an AArch32 task (`processor.h`
//! `TASK_SIZE_32`, `STACK_TOP`, `elf.h` `COMPAT_ELF_ET_DYN_BASE`), EABI
//! admission (`compat_elf_check_arch`), the `syscall_32.tbl` numbers,
//! `compat_start_thread`, the initial stack in 4-byte words with the
//! compat capabilities and platform (`cpufeature.c`, `compat_binfmt_elf.c`),
//! the `[vectors]` and `[sigpage]` pages (`vdso.c`, `kuser32.S`,
//! `sigreturn32.S`), `SVC` as the system call with R7's number
//! (`el0_svc_compat`), the AArch32 exceptions' signals (`entry-common.c`,
//! `traps.c`, `debug-monitors.c`, `armv8_deprecated.c`), and the ARM private
//! calls past the table (`sys_compat.c`).
//!
//! | Module | Contents |
//! |---|---|
//! | this one | the task, its entry, exceptions, and the private calls |
//! | [`calls`] | the `aarch32_*` wrappers, EABI layouts, System V IPC's direct calls, sockets, `uname`, `CLONE_SETTLS` |
//! | [`signals`] | the AArch32 signal frames, `sigreturn`, `rt_sigreturn` |
//! | [`ptrace`] | the AArch32 register views a 32-bit and a 64-bit tracer get |

mod calls;
mod ptrace;
mod signals;

use super::harness::{CODE, Harness};
use crate::user::image::elf::ElfClass;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{AARCH32_VECTORS_BASE, LinuxAbi, Sysno};
use crate::user::linux::arch::{CpuEvent, GuestCpu};
use crate::user::linux::signal::frame::FaultUpdate;
use crate::user::linux::signal::{SIGBUS, SIGILL, SIGSEGV, SIGTRAP, SigInfo, code};
use crate::user::linux::syscall::Outcome;
use crate::user::linux::syscall::compat::arm::{ARM_NR_BASE, ARM_NR_CACHEFLUSH, ARM_NR_SET_TLS};

pub(super) fn put(h: &Harness, at: u64, bytes: &[u8]) {
    h.proc.state.space.write_raw(at, bytes).unwrap();
}

pub(super) fn get(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    b
}

pub(super) fn u32_at(h: &Harness, at: u64) -> u32 {
    u32::from_le_bytes(get(h, at, 4).try_into().unwrap())
}

pub(super) fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

pub(super) fn halves(hs: &[u16]) -> Vec<u8> {
    hs.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn cstr(h: &Harness, at: u64) -> String {
    let mut out = Vec::new();
    let mut p = at;
    loop {
        let b = get(h, p, 1)[0];
        if b == 0 {
            break;
        }
        out.push(b);
        p += 1;
    }
    String::from_utf8(out).unwrap()
}

pub(super) fn arm(h: &mut Harness) -> &mut crate::user::cpu::arm::A32UserCpu {
    match &mut h.proc.threads[0].cpu {
        GuestCpu::Arm(c) => c,
        _ => panic!("an ARM task has an AArch32 CPU"),
    }
}

/// Places `code` at [`CODE`] and runs it from there in A32 (or T32) state.
fn run_code(h: &mut Harness, code: &[u8], thumb: bool) -> CpuEvent {
    put(h, CODE, code);
    let cpu = arm(h);
    cpu.core_mut().cpsr.t = thumb;
    cpu.set_pc(CODE);
    h.proc.threads[0].cpu.run(100)
}

/// A raw system call `nr` of thread 0.
fn raw(h: &mut Harness, nr: u64, args: &[u64]) -> Outcome {
    let mut a = [0u64; 6];
    a[..args.len()].copy_from_slice(args);
    h.proc.dispatch_to_completion(0, nr, a)
}

fn ret(o: Outcome) -> i64 {
    match o {
        Outcome::Return(v) => v as i32 as i64,
        other => panic!("no result: {other:?}"),
    }
}

const MOV_R7_20: u32 = 0xe3a0_7014;
const MOV_R0_7: u32 = 0xe3a0_0007;
const SVC_0: u32 = 0xef00_0000;
const MRC_R0_TPIDRURO: u32 = 0xee1d_0f70;
const STR_R0_R1: u32 = 0xe581_0000;
const BX_R0: u32 = 0xe12f_ff10;
const CP15DMB_R0: u32 = 0xee07_0fba;

#[test]
fn an_arm_task_has_the_arm64_compat_layout_and_numbers() {
    let a = LinuxAbi::Arm;
    // TASK_SIZE_32 leaves the top page; STACK_TOP is the vectors page.
    assert_eq!((a.task_size(), a.stack_top()), (0xFFFF_F000, 0xFFFF_0000));
    assert_eq!(a.elf_et_dyn_base(), 0x40_0000);
    // max(8 MiB + stack_guard_gap, 128 MiB) below STACK_TOP.
    assert_eq!(a.mmap_base(8 << 20), 0xF7FF_0000);
    assert_eq!((a.word_size(), a.audit_arch()), (4, 0x4000_0028));
    assert_eq!(a.machine(), "aarch64");
    // compat_elf_check_arch: EM_ARM, ELFCLASS32, an EABI version.
    let eabi5 = super::harness::ARM_EABI5_HARD_FLOAT;
    assert_eq!(
        LinuxAbi::from_elf(40, Some(ElfClass::Elf32), eabi5),
        Some(a)
    );
    assert_eq!(LinuxAbi::from_elf(40, Some(ElfClass::Elf32), 0x400), None);
    assert_eq!(LinuxAbi::from_elf(40, Some(ElfClass::Elf64), eabi5), None);
    // syscall_32.tbl.
    for (nr, s) in [
        (1, Sysno::Exit),
        (4, Sysno::Write),
        (120, Sysno::Clone),
        (192, Sysno::Mmap2),
        (285, Sysno::Accept),
        (270, Sysno::ArmFadvise6464),
        (341, Sysno::ArmSyncFileRange),
        (398, Sysno::Rseq),
    ] {
        assert_eq!(a.sysno(nr), Some(s));
        assert_eq!(a.number(s), Some(nr));
    }
    // No old mmap, socketcall, or ipc in EABI; the private calls are past
    // the table.
    for s in [Sysno::Mmap, Sysno::Socketcall, Sysno::Ipc] {
        assert_eq!(a.number(s), None, "{s:?}");
    }
    assert_eq!(a.sysno(u64::from(ARM_NR_SET_TLS)), None);
}

#[test]
fn an_arm_program_starts_in_user_mode_with_the_compat_auxv() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let cpu = arm(&mut h);
    let core = cpu.core();
    assert_eq!(core.cpsr.to_u32(), 0x10, "User mode, A32, flags clear");
    assert_eq!(core.regs[..13], [0; 13]);
    assert_eq!((core.cp15.tpidrurw, core.cp15.tpidruro), (0, 0));
    assert_eq!(cpu.pc(), 0x40_1000);
    // argc, argv[0], NULL, envp NULL, then auxv pairs of 4-byte words.
    let sp = cpu.sp();
    assert!(sp < 0xFFFF_0000 && sp % 8 == 0, "{sp:#x}");
    assert_eq!(u32_at(&h, sp), 1);
    assert_eq!(cstr(&h, u64::from(u32_at(&h, sp + 4))), "prog");
    let mut aux = std::collections::BTreeMap::new();
    let mut at = sp + 16;
    loop {
        let (tag, val) = (u32_at(&h, at), u32_at(&h, at + 4));
        if tag == 0 {
            break;
        }
        aux.insert(tag, val);
        at += 8;
    }
    // COMPAT_ELF_HWCAP_DEFAULT (HALF, THUMB, FAST_MULT, EDSP, TLS, IDIVA,
    // IDIVT, LPAE) with VFP, VFPv3, VFPv4, and NEON.
    assert_eq!(aux[&16], 0x0017_B0D6, "AT_HWCAP");
    assert_eq!((aux[&26], aux[&29]), (0, 0), "AT_HWCAP2, AT_HWCAP3");
    assert_eq!(cstr(&h, u64::from(aux[&15])), "v8l", "AT_PLATFORM");
    // COMPAT_ARCH_DLINFO without a compat vDSO is empty.
    assert!(!aux.contains_key(&33) && !aux.contains_key(&51));
    // A Thumb entry point (bit 0) starts in T32 state.
    let cpu = arm(&mut h);
    crate::user::linux::arch::arm::start(cpu, 0x40_1001, 0x1000_0000);
    assert!(cpu.thumb());
    assert_eq!((cpu.pc(), cpu.sp()), (0x40_1000, 0x1000_0000));
}

#[test]
fn execve_maps_the_vectors_page_and_the_sigpage() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let vma = |h: &Harness, at: u64| h.proc.state.space.vmas_in(at, at + 1)[0].clone();
    let v = vma(&h, AARCH32_VECTORS_BASE);
    assert_eq!(
        (v.start, v.end, v.name.as_deref()),
        (0xFFFF_0000, 0xFFFF_1000, Some("[vectors]"))
    );
    // The kuser helpers end the page: __kuser_cmpxchg64's push at
    // 0xffff0f60, __kuser_get_tls's mrc at 0xffff0fe0, version 5.
    assert_eq!(u32_at(&h, 0xFFFF_0F60), 0xe92d_00f0);
    assert_eq!(u32_at(&h, 0xFFFF_0FA0), 0xf57f_f05b);
    assert_eq!(u32_at(&h, 0xFFFF_0FE0), 0xee1d_0f70);
    assert_eq!(u32_at(&h, 0xFFFF_0FFC), 5);
    assert_eq!(get(&h, 0xFFFF_0000, 0xF60), vec![0; 0xF60]);
    // No VM_MAYWRITE: mprotect cannot make it writable.
    let e = h.err(Sysno::Mprotect, &[AARCH32_VECTORS_BASE, 4096, 3]);
    assert_eq!(e, EACCES);
    // The [sigpage]: sigreturn and rt_sigreturn in A32 and T32, then the
    // poison word.
    let page = h.proc.state.sigtramp;
    assert_eq!(vma(&h, page).name.as_deref(), Some("[sigpage]"));
    assert_eq!(
        get(&h, page, 28),
        [
            words(&[0xe3a0_7077, 0xef00_0077]),
            halves(&[0x2777, 0xdf77]),
            words(&[0xe3a0_70ad, 0xef00_00ad]),
            halves(&[0x27ad, 0xdfad]),
            words(&[0xe7fd_def1]),
        ]
        .concat()
    );
    assert_eq!(u32_at(&h, page + 4092), 0xe7fd_def1);
    // The helpers run: __kuser_get_tls returns TPIDRURO.
    arm(&mut h).core_mut().cp15.tpidruro = 0x1234_5678;
    arm(&mut h).core_mut().regs[14] = CODE as u32;
    put(&h, CODE, &words(&[SVC_0]));
    arm(&mut h).set_pc(0xFFFF_0FE0);
    assert!(matches!(
        h.proc.threads[0].cpu.run(10),
        CpuEvent::Syscall { .. }
    ));
    assert_eq!(arm(&mut h).core().regs[0], 0x1234_5678);
}

/// The kuser helpers run as `kuser32.S` writes them (their ARMv8
/// `STLEX`/`STLEXD` included): `__kuser_cmpxchg` and `__kuser_cmpxchg64`
/// store the new value when memory holds the old one and return 0 (C set),
/// else leave it and return nonzero (C clear).
#[test]
fn the_kuser_cmpxchg_helpers_compare_and_exchange() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let s = h.scratch;
    put(&h, CODE, &words(&[MOV_R7_20, SVC_0]));
    let call = |h: &mut Harness, entry: u64, r: [u32; 3]| {
        let core = arm(h).core_mut();
        core.regs[..3].copy_from_slice(&r);
        core.regs[14] = CODE as u32;
        arm(h).set_pc(entry);
        assert!(matches!(
            h.proc.threads[0].cpu.run(100),
            CpuEvent::Syscall { nr: 20, .. }
        ));
        let core = arm(h).core();
        (core.regs[0], core.cpsr.c)
    };
    // __kuser_cmpxchg (0xffff0fc0): r0 old, r1 new, r2 the word.
    put(&h, s, &7u32.to_le_bytes());
    assert_eq!(call(&mut h, 0xFFFF_0FC0, [7, 9, s as u32]), (0, true));
    assert_eq!(u32_at(&h, s), 9);
    let (r0, c) = call(&mut h, 0xFFFF_0FC0, [7, 11, s as u32]);
    assert!(r0 != 0 && !c);
    assert_eq!(u32_at(&h, s), 9);
    // __kuser_cmpxchg64 (0xffff0f60): r0 and r1 point at the old and new
    // doublewords, r2 at the target.
    let (old, new, target) = (s + 0x10, s + 0x18, s + 0x20);
    put(&h, old, &0x1111_2222_3333_4444u64.to_le_bytes());
    put(&h, new, &0x5555_6666_7777_8888u64.to_le_bytes());
    put(&h, target, &0x1111_2222_3333_4444u64.to_le_bytes());
    let r = [old as u32, new as u32, target as u32];
    assert_eq!(call(&mut h, 0xFFFF_0F60, r), (0, true));
    assert_eq!(get(&h, target, 8), 0x5555_6666_7777_8888u64.to_le_bytes());
    let (r0, c) = call(&mut h, 0xFFFF_0F60, r);
    assert!(r0 != 0 && !c);
    // __kuser_memory_barrier returns.
    let _ = call(&mut h, 0xFFFF_0FA0, [0, 0, 0]);
}

#[test]
fn svc_is_the_system_call_with_the_number_in_r7() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let event = run_code(&mut h, &words(&[MOV_R7_20, MOV_R0_7, SVC_0]), false);
    assert_eq!(
        event,
        CpuEvent::Syscall {
            nr: 20,
            args: [7, 0, 0, 0, 0, 0]
        }
    );
    assert_eq!(h.proc.threads[0].cpu.pc(), CODE + 12);
    assert_eq!(h.proc.threads[0].cpu.syscall_insn_len(), 4);
    // T32: movs r7, #20; svc #1 (the immediate is ignored).
    let event = run_code(&mut h, &halves(&[0x2714, 0xdf01]), true);
    assert!(matches!(event, CpuEvent::Syscall { nr: 20, .. }));
    assert_eq!(h.proc.threads[0].cpu.pc(), CODE + 4);
    assert_eq!(h.proc.threads[0].cpu.syscall_insn_len(), 2);
    // The result is R0's low 32 bits, read back sign-extended.
    h.proc.threads[0]
        .cpu
        .set_syscall_result(-(EINTR as i64) as u64);
    assert_eq!(arm(&mut h).core().regs[0], (-(EINTR as i32)) as u32);
    let back = h.proc.threads[0].cpu.syscall_return_value() as i64;
    assert_eq!(back, -(EINTR as i64));
}

#[test]
fn the_aarch32_exceptions_become_their_signals() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let sig = |signo, code, addr, fault| CpuEvent::Signal(SigInfo::fault(signo, code, addr), fault);
    let cleared = FaultUpdate::Arm64 { address: 0, esr: 0 };
    // BKPT #0x1234: do_bkpt32, the ESR of EC 0x38 with IL and the comment.
    let bkpt = words(&[0xe121_2374]);
    let esr = (0x38 << 26) | (1 << 25) | 0x1234;
    let esr = FaultUpdate::Arm64 { address: 0, esr };
    assert_eq!(
        run_code(&mut h, &bkpt, false),
        sig(SIGTRAP, code::TRAP_BRKPT, CODE, esr)
    );
    // A T32 BKPT has IL clear.
    let esr = FaultUpdate::Arm64 {
        address: 0,
        esr: (0x38 << 26) | 0x34,
    };
    assert_eq!(
        run_code(&mut h, &halves(&[0xbe34]), true),
        sig(SIGTRAP, code::TRAP_BRKPT, CODE, esr)
    );
    // The AArch32 breakpoint encodings (any condition in A32; EQ passes
    // with Z set: a conditional UNDEFINED encoding whose condition fails
    // need not trap).
    arm(&mut h).core_mut().cpsr.z = true;
    for (code_bytes, thumb) in [
        (words(&[0xe7f0_01f0]), false),
        (words(&[0x07f0_01f0]), false),
        (halves(&[0xde01]), true),
        (halves(&[0xf7f0, 0xa000]), true),
    ] {
        let e = run_code(&mut h, &code_bytes, thumb);
        assert_eq!(e, sig(SIGTRAP, code::TRAP_BRKPT, CODE, FaultUpdate::None));
    }
    // Other UNDEFINED encodings: UDF #0, SWP (not in ARMv8), T16 UDF #2,
    // PL1's FPEXC.
    for (code_bytes, thumb) in [
        (words(&[0xe7f0_00f0]), false),
        (words(&[0xe101_2092]), false),
        (halves(&[0xde02]), true),
        (words(&[0xeef8_0a10]), false),
    ] {
        let e = run_code(&mut h, &code_bytes, thumb);
        assert_eq!(e, sig(SIGILL, code::ILL_ILLOPC, CODE, cleared));
    }
    // The A32 CP15 barriers are emulated: the thread goes on.
    let e = run_code(&mut h, &words(&[CP15DMB_R0, MOV_R7_20, SVC_0]), false);
    assert!(matches!(e, CpuEvent::Syscall { nr: 20, .. }));
    // A write to an unmapped page: SEGV_MAPERR, and the abort's ESR with
    // WnR in the fault record.
    arm(&mut h).core_mut().regs[1] = 0x1000;
    let esr = (0x24 << 26) | (1 << 25) | (1 << 6) | 0x07;
    let fault = FaultUpdate::Arm64 {
        address: 0x1000,
        esr,
    };
    assert_eq!(
        run_code(&mut h, &words(&[STR_R0_R1]), false),
        sig(SIGSEGV, code::SEGV_MAPERR, 0x1000, fault)
    );
    // An unaligned exclusive load: do_alignment_fault's SIGBUS, the ESR's
    // alignment fault status (0x21).
    arm(&mut h).core_mut().regs[1] = (h.scratch + 2) as u32;
    let esr = (0x24 << 26) | (1 << 25) | 0x21;
    let fault = FaultUpdate::Arm64 {
        address: h.scratch + 2,
        esr,
    };
    assert_eq!(
        run_code(&mut h, &words(&[0xe191_0f9f]), false),
        sig(SIGBUS, code::BUS_ADRALN, h.scratch + 2, fault)
    );
    // A branch to an A32 address that is not word-aligned: a PC alignment
    // fault, SIGBUS at the PC.
    arm(&mut h).core_mut().regs[0] = (CODE + 0x102) as u32;
    let fault = FaultUpdate::Arm64 {
        address: 0,
        esr: (0x22 << 26) | (1 << 25),
    };
    assert_eq!(
        run_code(&mut h, &words(&[BX_R0]), false),
        sig(SIGBUS, code::BUS_ADRALN, CODE + 0x102, fault)
    );
}

#[test]
fn the_private_calls_set_tls_and_flush_and_the_rest_are_enosys_or_sigill() {
    let mut h = Harness::new(LinuxAbi::Arm);
    // set_tls: TPIDRURO, which the thread reads with MRC.
    assert_eq!(
        ret(raw(&mut h, u64::from(ARM_NR_SET_TLS), &[0xCAFE_F00D])),
        0
    );
    assert_eq!(h.proc.threads[0].cpu.thread_pointer(), 0xCAFE_F00D);
    let e = run_code(&mut h, &words(&[MRC_R0_TPIDRURO, MOV_R7_20, SVC_0]), false);
    assert!(matches!(
        e,
        CpuEvent::Syscall {
            args: [0xCAFE_F00D, ..],
            ..
        }
    ));
    // cacheflush: [start, end) with zero flags, every page mapped.
    let s = h.scratch;
    let flush = |h: &mut Harness, a: &[u64]| ret(raw(h, u64::from(ARM_NR_CACHEFLUSH), a));
    assert_eq!(flush(&mut h, &[s, s + 4096, 0]), 0);
    assert_eq!(flush(&mut h, &[s + 8, s + 8, 0]), 0);
    assert_eq!(flush(&mut h, &[s + 8, s, 0]), -i64::from(EINVAL));
    assert_eq!(flush(&mut h, &[s, s + 16, 1]), -i64::from(EINVAL));
    assert_eq!(flush(&mut h, &[0x1000, 0x1010, 0]), -i64::from(EFAULT));
    // Unknown numbers up to __ARM_NR_COMPAT_END, those past the table, and
    // negative ones are ENOSYS.
    let past = crate::user::linux::syscall::compat::arm::compat32_syscalls();
    assert_eq!(past, 471);
    for nr in [
        u64::from(ARM_NR_BASE + 1),
        u64::from(ARM_NR_BASE + 6),
        past,
        0xFFFF_FFFF,
    ] {
        assert_eq!(ret(raw(&mut h, nr, &[])), -i64::from(ENOSYS), "{nr:#x}");
    }
    // Past it: SIGILL (ILL_ILLTRP at the SVC), and a result of 0.
    arm(&mut h).set_pc(CODE + 0x24);
    assert_eq!(ret(raw(&mut h, 0xF_0800, &[])), 0);
    let t = &mut h.proc.threads[0];
    let info = t.pending.dequeue(0).expect("SIGILL forced");
    assert_eq!(info, SigInfo::fault(SIGILL, code::ILL_ILLTRP, CODE + 0x20));
}
