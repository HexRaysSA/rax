//! Register sets a tracer reads and writes: `NT_PRSTATUS` (and, on
//! x86-64, `PTRACE_GETREGS` and the `struct user` of `PTRACE_PEEKUSR`),
//! the floating-point registers (`NT_PRFPREG`; x86-64's
//! `PTRACE_GETFPREGS`), x86-64's whole XSAVE area (`NT_X86_XSTATE`), and
//! AArch64's `NT_ARM_TLS` and `NT_ARM_SYSTEM_CALL`, laid out as each
//! architecture's `ptrace.h` and `asm/user.h` define them and checked on
//! writing as its `ptrace.c` (x86-64's `fpu/regset.c`) checks them; and
//! x86-64's sets that no thread here has contents for: the I/O permission
//! bitmap (`NT_386_IOPERM`) and the shadow-stack pointer (`NT_X86_SHSTK`).

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::arch::GuestCpu;
use super::super::signal::deliver::SyscallEntry;
use super::super::signal::frame::aarch64::valid_user_pstate;
use crate::isa::x86_64::{LINUX_USER_CS, LINUX_USER_DS};

/// `NT_PRSTATUS`.
pub const NT_PRSTATUS: u64 = 1;
/// `NT_PRFPREG`: x86-64's `FXSAVE` area (`struct user_i387_struct`),
/// AArch64's `struct user_fpsimd_state`, RISC-V's
/// `struct __riscv_d_ext_state`.
pub const NT_PRFPREG: u64 = 2;
/// `NT_X86_XSTATE`: x86-64's XSAVE area in the standard format.
pub const NT_X86_XSTATE: u64 = 0x202;
/// `NT_ARM_TLS`: `TPIDR_EL0`, then `TPIDR2_EL0` (zero without SME).
pub const NT_ARM_TLS: u64 = 0x401;
/// `NT_ARM_SYSTEM_CALL`: AArch64's `syscallno`, an `int`.
pub const NT_ARM_SYSTEM_CALL: u64 = 0x404;
/// `NT_386_IOPERM`: x86-64's I/O permission bitmap. No thread has one
/// (`ioperm` is refused), so reading it is `ENXIO` (`ioperm_get`); it has
/// no writer (`EOPNOTSUPP`).
pub const NT_386_IOPERM: u64 = 0x201;
/// `NT_X86_SHSTK`: x86-64's shadow-stack pointer. The emulated CPU has no
/// user shadow stacks (`X86_FEATURE_USER_SHSTK`), so both ways are
/// `ENODEV` (`ssp_get`, `ssp_set`, before copying anything).
pub const NT_X86_SHSTK: u64 = 0x204;
/// `IO_BITMAP_BYTES`.
const IO_BITMAP_BYTES: u64 = 65536 / 8;

/// `sizeof(struct fxregs_state)`.
const X86_FXSAVE: usize = 512;
/// The part of the `FXSAVE` area `XSTATE_COPY_FX` fills: up to the end of
/// `xmm_space` (the reserved tail is zero).
const X86_FX_USED: usize = 416;
/// `sizeof(struct user_fpsimd_state)`: 32 128-bit registers, FPSR, FPCR,
/// two reserved words.
const ARM_FPSIMD: usize = 32 * 16 + 16;
/// `sizeof(struct __riscv_d_ext_state)`: `f[32]`, `fcsr`, padded to 8.
const RISCV_FP: usize = 32 * 8 + 8;

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

/// A register set's element size and whole size on `cpu`'s architecture
/// (its `struct user_regset`'s `size` and `n * size`), `EINVAL` for one it
/// does not have (`find_regset`).
pub fn layout(cpu: &GuestCpu, nt: u64) -> Result<(u64, u64), Errno> {
    Ok(match (nt, cpu) {
        (NT_PRSTATUS, _) => (8, prstatus_size(cpu) as u64),
        (NT_PRFPREG, GuestCpu::X86_64(_)) => (8, X86_FXSAVE as u64),
        // fpsr and fpcr are 32 bits wide, so the set is of words.
        (NT_PRFPREG, GuestCpu::Aarch64(_)) => (4, ARM_FPSIMD as u64),
        (NT_PRFPREG, GuestCpu::Riscv64(_)) => (8, RISCV_FP as u64),
        (NT_X86_XSTATE, GuestCpu::X86_64(c)) => (8, c.vcpu().xsave_standard_size() as u64),
        (NT_ARM_TLS, GuestCpu::Aarch64(_)) => (8, 16),
        (NT_ARM_SYSTEM_CALL, GuestCpu::Aarch64(_)) => (4, 4),
        (NT_386_IOPERM, GuestCpu::X86_64(_)) => (8, IO_BITMAP_BYTES),
        (NT_X86_SHSTK, GuestCpu::X86_64(_)) => (8, 8),
        _ => return Err(Errno(EINVAL)),
    })
}

/// Whether set `nt` has a writer (`copy_regset_from_user` refuses one
/// without, `EOPNOTSUPP`, before looking at the tracer's buffer).
pub fn writable(nt: u64) -> bool {
    nt != NT_386_IOPERM
}

/// Whether writing set `nt` copies the tracer's bytes in (`ssp_set`
/// refuses first).
pub fn copies_in(nt: u64) -> bool {
    nt != NT_X86_SHSTK
}

/// Register set `nt` as a whole (`regset_get`), or why it cannot be read.
pub fn get(cpu: &GuestCpu, syscall: Option<SyscallEntry>, nt: u64) -> Result<Vec<u8>, Errno> {
    Ok(match nt {
        NT_386_IOPERM => return Err(Errno(ENXIO)),
        NT_X86_SHSTK => return Err(Errno(ENODEV)),
        NT_PRFPREG => fpregs(cpu),
        NT_X86_XSTATE => xstate(cpu),
        NT_ARM_TLS => {
            let mut b = cpu.thread_pointer().to_le_bytes().to_vec();
            b.extend_from_slice(&[0; 8]);
            b
        }
        NT_ARM_SYSTEM_CALL => syscall.map_or(-1, |s| s.nr as i32).to_le_bytes().to_vec(),
        _ => prstatus(cpu, syscall),
    })
}

/// Writes a prefix of register set `nt` (`regset->set`):
/// `system_call_set` takes `syscallno` as it is; `tls_set` the thread
/// pointer (`TPIDR2_EL0` is not there without SME).
pub fn set(
    cpu: &mut GuestCpu,
    syscall: &mut Option<SyscallEntry>,
    nt: u64,
    bytes: &[u8],
) -> Result<(), Errno> {
    match nt {
        NT_386_IOPERM => Err(Errno(EOPNOTSUPP)),
        NT_X86_SHSTK => Err(Errno(ENODEV)),
        NT_PRFPREG => set_fpregs(cpu, bytes),
        NT_X86_XSTATE => set_xstate(cpu, bytes),
        NT_ARM_TLS => {
            if let Some(b) = bytes.get(..8) {
                cpu.set_thread_pointer(u64::from_le_bytes(b.try_into().unwrap()));
            }
            Ok(())
        }
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

/// The floating-point registers (`xfpregs_get` in `XSTATE_COPY_FX` mode,
/// `fpr_get`, `riscv_fpr_get`).
pub fn fpregs(cpu: &GuestCpu) -> Vec<u8> {
    match cpu {
        GuestCpu::X86_64(c) => {
            // The x87 and SSE parts of the XSAVE image; the reserved tail
            // (the padding and software bytes) is zero.
            let image = c.vcpu().xsave_image(0x3);
            let mut b = image.bytes[..X86_FXSAVE].to_vec();
            b[X86_FX_USED..].fill(0);
            b
        }
        GuestCpu::Aarch64(c) => fpsimd(c),
        GuestCpu::Riscv64(c) => {
            let core = c.core();
            let mut b = Vec::with_capacity(RISCV_FP);
            for r in 0..32 {
                b.extend_from_slice(&core.f(r).to_le_bytes());
            }
            b.extend_from_slice(&core.fcsr().to_le_bytes());
            b.extend_from_slice(&[0; 4]);
            b
        }
    }
}

/// Writes the floating-point registers: x86-64's `xfpregs_set` takes the
/// whole area only (`EINVAL`) and refuses reserved MXCSR bits (`EINVAL`);
/// AArch64's `fpr_set` and RISC-V's `riscv_fpr_set` take a prefix (the
/// reserved words and padding are not kept).
pub fn set_fpregs(cpu: &mut GuestCpu, bytes: &[u8]) -> Result<(), Errno> {
    match cpu {
        GuestCpu::X86_64(c) => {
            if bytes.len() != X86_FXSAVE {
                return Err(Errno(EINVAL));
            }
            c.vcpu_mut().fxrstor_image(bytes).map_err(|_| Errno(EINVAL))
        }
        GuestCpu::Aarch64(c) => {
            let mut all = fpsimd(c);
            let n = bytes.len().min(ARM_FPSIMD);
            all[..n].copy_from_slice(&bytes[..n]);
            let core = c.core_mut();
            for v in 0..32 {
                let at = 16 * v;
                core.set_simd(
                    v as u8,
                    u128::from_le_bytes(all[at..at + 16].try_into().unwrap()),
                );
            }
            let word = |at: usize| u32::from_le_bytes(all[at..at + 4].try_into().unwrap());
            core.set_fpsr_value(word(512));
            core.set_fpcr_value(word(516));
            Ok(())
        }
        GuestCpu::Riscv64(c) => {
            let core = c.core_mut();
            for (r, w) in bytes.chunks_exact(8).take(32).enumerate() {
                core.set_f(r as u8, u64::from_le_bytes(w.try_into().unwrap()));
            }
            if let Some(f) = bytes.get(256..260) {
                core.set_fcsr(u32::from_le_bytes(f.try_into().unwrap()));
            }
            Ok(())
        }
    }
}

/// AArch64's `struct user_fpsimd_state`.
fn fpsimd(c: &crate::user::cpu::aarch64::A64UserCpu) -> Vec<u8> {
    let core = c.core();
    let mut b = Vec::with_capacity(ARM_FPSIMD);
    for v in 0..32 {
        b.extend_from_slice(&core.get_simd(v).to_le_bytes());
    }
    b.extend_from_slice(&core.fpsr_value().to_le_bytes());
    b.extend_from_slice(&core.fpcr_value().to_le_bytes());
    b.extend_from_slice(&[0; 8]);
    b
}

/// x86-64's XSAVE area (`xstateregs_get`, `copy_xstate_to_uabi_buf` in
/// `XSTATE_COPY_XSAVE` mode): the image of every enabled component, the
/// software bytes `xstate_fx_sw_bytes` in the legacy area's reserved tail,
/// and the header's feature bitmap. Other architectures have none.
pub fn xstate(cpu: &GuestCpu) -> Vec<u8> {
    use super::super::signal::frame::x86_64::{FP_XSTATE_MAGIC1, SW_RESERVED};
    let GuestCpu::X86_64(c) = cpu else {
        return Vec::new();
    };
    let v = c.vcpu();
    let size = v.xsave_standard_size();
    let image = v.xsave_image(v.xcr0());
    let mut b = image.bytes;
    b.truncate(size);
    let at = SW_RESERVED as usize;
    b[at..at + 4].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
    b[at + 4..at + 8].copy_from_slice(&((size + 4) as u32).to_le_bytes());
    b[at + 8..at + 16].copy_from_slice(&v.xcr0().to_le_bytes());
    b[at + 16..at + 20].copy_from_slice(&(size as u32).to_le_bytes());
    b
}

/// `xstateregs_set`: the whole standard-format area only (`EFAULT`
/// otherwise, as the kernel answers), loaded as `copy_uabi_to_xstate` does:
/// a header naming features that are not enabled or with reserved bits
/// set, or reserved MXCSR bits, are refused (`EINVAL`), and components the
/// header leaves out are initialized.
pub fn set_xstate(cpu: &mut GuestCpu, bytes: &[u8]) -> Result<(), Errno> {
    let GuestCpu::X86_64(c) = cpu else {
        return Err(Errno(EINVAL));
    };
    let v = c.vcpu_mut();
    if bytes.len() != v.xsave_standard_size() {
        return Err(Errno(EFAULT));
    }
    // validate_user_xstate_header: only the standard format.
    if bytes[520..528] != [0; 8] {
        return Err(Errno(EINVAL));
    }
    let all = v.xcr0();
    v.xrstor_image(bytes, all).map_err(|_| Errno(EINVAL))
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
