//! Register sets a tracer reads and writes: `NT_PRSTATUS` (and, on
//! x86-64, `PTRACE_GETREGS` and the `struct user` of `PTRACE_PEEKUSR`) and
//! AArch64's `NT_ARM_SYSTEM_CALL`, laid out as each architecture's
//! `ptrace.h` defines them and checked on writing as its `ptrace.c` checks
//! them.

use super::super::abi::LinuxAbi;
use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::arch::GuestCpu;
use super::super::signal::deliver::SyscallEntry;
use super::super::signal::frame::aarch64::valid_user_pstate;
use crate::isa::x86_64::{LINUX_USER_CS, LINUX_USER_DS};

/// `NT_PRSTATUS`.
pub const NT_PRSTATUS: u64 = 1;
/// `NT_ARM_SYSTEM_CALL`: AArch64's `syscallno`, an `int`.
pub const NT_ARM_SYSTEM_CALL: u64 = 0x404;

/// `sizeof(struct user_regs_struct)` on x86-64: 27 registers.
const X86_REGS: usize = 27 * 8;
/// `sizeof(struct user)` on x86-64.
const X86_USER: u64 = 928;
/// `offsetof(struct user, u_debugreg)`.
const X86_DEBUGREG: u64 = 848;
/// `FLAG_MASK`: the RFLAGS bits a tracer may change (CF, PF, AF, ZF, SF,
/// TF, DF, OF, NT, RF, AC).
const X86_FLAG_MASK: u64 =
    0x1 | 0x4 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400 | 0x800 | 0x4000 | 0x1_0000 | 0x4_0000;
/// `TASK_SIZE_MAX` on x86-64 (4-level paging).
const X86_TASK_SIZE_MAX: u64 = (1 << 47) - 4096;

/// The size of the general registers' set (`NT_PRSTATUS`).
pub fn prstatus_size(cpu: &GuestCpu) -> usize {
    match cpu {
        GuestCpu::X86_64(_) => X86_REGS,
        // user_pt_regs: x0-x30, sp, pc, pstate.
        GuestCpu::Aarch64(_) => 34 * 8,
        // user_regs_struct: pc, then x1-x31.
        GuestCpu::Riscv64(_) => 32 * 8,
    }
}

/// A register set's element size and whole size on `abi` (its `struct
/// user_regset`'s `size` and `n * size`), `EINVAL` for one it does not
/// have (`find_regset`).
pub fn layout(abi: LinuxAbi, nt: u64) -> Result<(u64, u64), Errno> {
    Ok(match (nt, abi) {
        (NT_PRSTATUS, LinuxAbi::X86_64) => (8, X86_REGS as u64),
        (NT_PRSTATUS, LinuxAbi::Aarch64) => (8, 34 * 8),
        (NT_PRSTATUS, LinuxAbi::Riscv64) => (8, 32 * 8),
        (NT_ARM_SYSTEM_CALL, LinuxAbi::Aarch64) => (4, 4),
        _ => return Err(Errno(EINVAL)),
    })
}

/// Register set `nt` as a whole (`regset_get`).
pub fn get(cpu: &GuestCpu, syscall: Option<SyscallEntry>, nt: u64) -> Vec<u8> {
    match nt {
        NT_ARM_SYSTEM_CALL => syscall.map_or(-1, |s| s.nr as i32).to_le_bytes().to_vec(),
        _ => prstatus(cpu, syscall),
    }
}

/// Writes a prefix of register set `nt` (`regset->set`):
/// `system_call_set` takes `syscallno` as it is.
pub fn set(
    cpu: &mut GuestCpu,
    syscall: &mut Option<SyscallEntry>,
    nt: u64,
    bytes: &[u8],
) -> Result<(), Errno> {
    match nt {
        NT_ARM_SYSTEM_CALL => {
            if let Some(b) = bytes.get(..4) {
                let nr = i32::from_le_bytes(b.try_into().unwrap());
                *syscall = Some(SyscallEntry {
                    nr: nr as i64 as u64,
                    arg0: syscall.map_or(0, |s| s.arg0),
                });
            }
            Ok(())
        }
        _ => set_prstatus(cpu, syscall, bytes),
    }
}

/// `orig_rax`: the system call the thread is in, else -1.
fn orig(syscall: Option<SyscallEntry>) -> u64 {
    syscall.map_or(u64::MAX, |s| s.nr)
}

/// The general registers (`NT_PRSTATUS`), with `syscall` the call the
/// thread is in (x86-64's `orig_rax`).
pub fn prstatus(cpu: &GuestCpu, syscall: Option<SyscallEntry>) -> Vec<u8> {
    let words: Vec<u64> = match cpu {
        GuestCpu::X86_64(c) => {
            let v = c.vcpu();
            let r = v.user_regs();
            vec![
                r.r15,
                r.r14,
                r.r13,
                r.r12,
                r.rbp,
                r.rbx,
                r.r11,
                r.r10,
                r.r9,
                r.r8,
                r.rax,
                r.rcx,
                r.rdx,
                r.rsi,
                r.rdi,
                orig(syscall),
                r.rip,
                u64::from(LINUX_USER_CS),
                v.user_rflags(),
                r.rsp,
                u64::from(LINUX_USER_DS),
                v.fs_base(),
                v.gs_base(),
                // ds, es, fs, gs: a 64-bit process's null selectors.
                0,
                0,
                0,
                0,
            ]
        }
        GuestCpu::Aarch64(c) => {
            let core = c.core();
            let mut w: Vec<u64> = (0..31).map(|r| core.get_x(r)).collect();
            w.extend([c.sp(), c.pc(), core.el0_spsr()]);
            w
        }
        GuestCpu::Riscv64(c) => {
            let core = c.core();
            let mut w = vec![c.pc()];
            w.extend((1..32).map(|r| core.x(r)));
            w
        }
    };
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Writes the general registers from `bytes`, a prefix of the set (whole
/// words), as `genregs_set`, `gpr_set`, and `riscv_gpr_set` do: an x86-64
/// word the kernel refuses is `EIO` (the earlier ones stay written); an
/// AArch64 PSTATE that is not EL0t with DAIF clear is `EINVAL` (nothing
/// written).
pub fn set_prstatus(
    cpu: &mut GuestCpu,
    syscall: &mut Option<SyscallEntry>,
    bytes: &[u8],
) -> Result<(), Errno> {
    let words: Vec<u64> = bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let pc = match cpu {
        GuestCpu::X86_64(_) => {
            for (i, &w) in words.iter().enumerate() {
                poke_user(cpu, syscall, 8 * i as u64, w)?;
            }
            return Ok(());
        }
        GuestCpu::Aarch64(c) => {
            let mut cur: Vec<u64> = (0..31).map(|r| c.core().get_x(r)).collect();
            cur.extend([c.sp(), c.pc(), c.core().el0_spsr()]);
            cur[..words.len()].copy_from_slice(&words);
            let (pstate, ok) = valid_user_pstate(cur[33]);
            if !ok {
                return Err(Errno(EINVAL));
            }
            let core = c.core_mut();
            for (r, &v) in cur.iter().enumerate().take(31) {
                core.set_x(r as u8, v);
            }
            core.set_el0_spsr(pstate);
            c.set_sp(cur[31]);
            Some(cur[32])
        }
        GuestCpu::Riscv64(c) => {
            for (i, &w) in words.iter().enumerate().skip(1) {
                c.core_mut().set_x(i as u8, w);
            }
            words.first().copied()
        }
    };
    if let Some(pc) = pc {
        cpu.set_pc(pc);
    }
    Ok(())
}

/// `PTRACE_PEEKUSR` on x86-64: a word of `struct user` (the registers, the
/// debug registers, which read as zero here, and zero elsewhere); a
/// misaligned or outside offset is `EIO`. Other architectures have no user
/// area (`EIO`).
pub fn peek_user(cpu: &GuestCpu, syscall: Option<SyscallEntry>, off: u64) -> Result<u64, Errno> {
    if !matches!(cpu, GuestCpu::X86_64(_)) || off % 8 != 0 || off >= X86_USER {
        return Err(Errno(EIO));
    }
    if off < X86_REGS as u64 {
        let regs = prstatus(cpu, syscall);
        let at = off as usize;
        return Ok(u64::from_le_bytes(regs[at..at + 8].try_into().unwrap()));
    }
    Ok(0)
}

/// `PTRACE_POKEUSR` on x86-64 (`putreg`): a register, checked as the
/// kernel checks it (`EIO`: a selector not of user privilege, a null CS or
/// SS, a segment base beyond user space); a debug register, which only
/// zero may be written to here; elsewhere nothing. The emulated CPU keeps
/// no selectors: a valid one is accepted and not kept.
pub fn poke_user(
    cpu: &mut GuestCpu,
    syscall: &mut Option<SyscallEntry>,
    off: u64,
    value: u64,
) -> Result<(), Errno> {
    let GuestCpu::X86_64(c) = cpu else {
        return Err(Errno(EIO));
    };
    if off % 8 != 0 || off >= X86_USER {
        return Err(Errno(EIO));
    }
    if off >= X86_REGS as u64 {
        let debug = (X86_DEBUGREG..X86_DEBUGREG + 64).contains(&off);
        return if debug && value != 0 {
            Err(Errno(EIO))
        } else {
            Ok(())
        };
    }
    let v = c.vcpu_mut();
    let selector = |value: u64| -> Result<(), Errno> {
        let s = value as u16;
        if s != 0 && s & 3 != 3 {
            return Err(Errno(EIO));
        }
        Ok(())
    };
    match off / 8 {
        // cs, ss: never null.
        17 | 20 => {
            selector(value)?;
            if value as u16 == 0 {
                return Err(Errno(EIO));
            }
        }
        // ds, es, fs, gs.
        23..=26 => selector(value)?,
        18 => {
            let cur = v.user_rflags();
            v.set_user_rflags((cur & !X86_FLAG_MASK) | (value & X86_FLAG_MASK));
        }
        21 | 22 => {
            if value >= X86_TASK_SIZE_MAX {
                return Err(Errno(EIO));
            }
            if off / 8 == 21 {
                v.set_fs_base(value);
            } else {
                v.set_gs_base(value);
            }
        }
        15 => {
            *syscall = if value == u64::MAX {
                None
            } else {
                Some(SyscallEntry {
                    nr: value,
                    arg0: syscall.map_or(0, |s| s.arg0),
                })
            };
        }
        n => {
            let r = v.user_regs_mut();
            let slot = match n {
                0 => &mut r.r15,
                1 => &mut r.r14,
                2 => &mut r.r13,
                3 => &mut r.r12,
                4 => &mut r.rbp,
                5 => &mut r.rbx,
                6 => &mut r.r11,
                7 => &mut r.r10,
                8 => &mut r.r9,
                9 => &mut r.r8,
                10 => &mut r.rax,
                11 => &mut r.rcx,
                12 => &mut r.rdx,
                13 => &mut r.rsi,
                14 => &mut r.rdi,
                16 => &mut r.rip,
                _ => &mut r.rsp,
            };
            *slot = value;
        }
    }
    Ok(())
}
