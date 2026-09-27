//! The AArch32 register views of an arm64 kernel (`arch/arm64/kernel/ptrace.c`,
//! Linux 6.19): `compat_elf_gregset_t` (r0-r15, the CPSR, `orig_r0`;
//! `compat_gpr_get`, `compat_gpr_set`), the VFP set (D0-D31 and an FPSCR
//! assembled from FPSR and FPCR; `compat_vfp_get`, `compat_vfp_set`), the
//! TLS word (`compat_tls_get`, `compat_tls_set`), and the `struct user`
//! words of a 32-bit tracer's `PTRACE_PEEKUSR` and `PTRACE_POKEUSR`
//! (`compat_ptrace_read_user`, `compat_ptrace_write_user`).
//!
//! A 32-bit tracer sees `user_aarch32_view` (the general and VFP sets) of
//! any thread, an AArch64 one's registers truncated to 32 bits; a 64-bit
//! tracer sees `user_aarch32_ptrace_view` of an AArch32 thread (also the
//! TLS word and `NT_ARM_SYSTEM_CALL`). The hardware breakpoint sets and
//! requests are not modelled, as in a kernel without
//! `CONFIG_HAVE_HW_BREAKPOINT` (the emulated CPU has no debug registers).
//! A written CPSR is checked as `valid_compat_regs` checks it (an AArch64
//! thread's PSTATE as `valid_native_regs` does): a refused one is `EINVAL`
//! and nothing is written.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::arch::GuestCpu;
use super::super::signal::deliver::SyscallEntry;
use super::super::signal::frame::aarch64::valid_user_pstate;
use super::super::signal::frame::arm::{FPSCR_CTRL_MASK, FPSCR_STAT_MASK, valid_user_psr};
use crate::isa::arm::Psr;
use crate::isa::arm::vfp::Fpscr;

/// `NT_ARM_VFP`.
pub const NT_ARM_VFP: u64 = 0x400;
/// `COMPAT_ELF_NGREG`: r0-r15, the CPSR, `orig_r0`.
const NGREG: usize = 18;
/// `sizeof(compat_elf_gregset_t)`.
pub const GREGS: usize = NGREG * 4;
/// `VFP_STATE_SIZE`: 32 doublewords and the FPSCR.
pub const VFP: usize = 32 * 8 + 4;
/// `COMPAT_USER_SZ`: 32-bit ARM's `sizeof(struct user)`.
const USER_SZ: u64 = 296;
/// `COMPAT_PT_TEXT_ADDR`, `COMPAT_PT_DATA_ADDR`, and
/// `COMPAT_PT_TEXT_END_ADDR`: the `struct user` offsets that read the
/// image's code and data addresses.
const TEXT_ADDR: u64 = 0x1_0000;
const DATA_ADDR: u64 = 0x1_0004;
const TEXT_END_ADDR: u64 = 0x1_0008;
/// `COMPAT_PSR_DIT_BIT` and `PSR_AA32_DIT_BIT`: DIT's place in an AArch32
/// CPSR and in an SPSR (`pstate_to_compat_psr`, `compat_psr_to_pstate`).
const COMPAT_PSR_DIT: u64 = 1 << 21;
const PSTATE_DIT: u64 = 1 << 24;

/// The image's addresses `PTRACE_PEEKUSR` reads (`mm->start_code`,
/// `mm->start_data`, `mm->end_code`).
#[derive(Clone, Copy, Debug)]
pub struct Image {
    pub start_code: u64,
    pub start_data: u64,
    pub end_code: u64,
}

/// Whether a thread has these views: an arm64 kernel runs AArch64 and
/// AArch32 threads only.
pub fn has_view(cpu: &GuestCpu) -> bool {
    matches!(cpu, GuestCpu::Arm(_) | GuestCpu::Aarch64(_))
}

/// `compat_get_user_reg`: word `idx` of `compat_elf_gregset_t`.
fn reg(cpu: &GuestCpu, syscall: Option<SyscallEntry>, idx: usize) -> u32 {
    let orig = syscall.map_or(0, |s| s.arg0) as u32;
    match cpu {
        GuestCpu::Arm(c) => match idx {
            16 => c.core().cpsr.to_u32(),
            17 => orig,
            r => c.core().regs[r],
        },
        GuestCpu::Aarch64(c) => match idx {
            15 => c.pc() as u32,
            16 => {
                let pstate = c.core().el0_spsr();
                let mut psr = pstate & !PSTATE_DIT;
                if pstate & PSTATE_DIT != 0 {
                    psr |= COMPAT_PSR_DIT;
                }
                psr as u32
            }
            17 => orig,
            r => c.core().get_x(r as u8) as u32,
        },
        _ => 0,
    }
}

/// `compat_gpr_get`: the whole set.
pub fn gregs(cpu: &GuestCpu, syscall: Option<SyscallEntry>) -> Vec<u8> {
    (0..NGREG)
        .flat_map(|i| reg(cpu, syscall, i).to_le_bytes())
        .collect()
}

/// `compat_gpr_set` from word `start` on: the words of `bytes` replace a
/// copy of the registers, which is written back only if its PSR is valid
/// (`valid_user_regs`, `EINVAL`); past the set is `EIO`.
pub fn set_gregs(
    cpu: &mut GuestCpu,
    syscall: &mut Option<SyscallEntry>,
    start: usize,
    bytes: &[u8],
) -> Result<(), Errno> {
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .collect();
    if start + words.len() > NGREG {
        return Err(Errno(EIO));
    }
    let mut all: Vec<u32> = (0..NGREG).map(|i| reg(cpu, *syscall, i)).collect();
    all[start..start + words.len()].copy_from_slice(&words);
    match cpu {
        // The CPSR as the thread keeps it (valid_compat_regs, as
        // sigreturn checks it).
        GuestCpu::Arm(c) => {
            let (psr, ok) = valid_user_psr(all[16]);
            if !ok {
                return Err(Errno(EINVAL));
            }
            let core = c.core_mut();
            core.regs[..16].copy_from_slice(&all[..16]);
            core.cpsr = Psr::from_u32(psr);
        }
        // compat_psr_to_pstate, then valid_native_regs.
        GuestCpu::Aarch64(c) => {
            let mut psr = u64::from(all[16]) & !COMPAT_PSR_DIT;
            if u64::from(all[16]) & COMPAT_PSR_DIT != 0 {
                psr |= PSTATE_DIT;
            }
            let (pstate, ok) = valid_user_pstate(psr);
            if !ok {
                return Err(Errno(EINVAL));
            }
            let core = c.core_mut();
            for (r, &v) in all.iter().enumerate().take(15) {
                core.set_x(r as u8, u64::from(v));
            }
            core.set_el0_spsr(pstate);
            cpu.set_pc(u64::from(all[15]));
        }
        _ => return Err(Errno(EIO)),
    }
    // orig_r0 is the system call's first argument, which a restart puts
    // back; outside a system call there is none to keep.
    if start + words.len() > 17
        && let Some(s) = syscall.as_mut()
    {
        s.arg0 = u64::from(all[17]);
    }
    Ok(())
}

/// `compat_ptrace_read_user`: the word at offset `off` of 32-bit ARM's
/// `struct user`: unaligned or past it is `EIO`; the image's addresses at
/// their offsets, the general registers, and zero for the rest.
pub fn peek_user(
    cpu: &GuestCpu,
    syscall: Option<SyscallEntry>,
    image: Image,
    off: u64,
) -> Result<u32, Errno> {
    if off & 3 != 0 {
        return Err(Errno(EIO));
    }
    Ok(match off {
        TEXT_ADDR => image.start_code as u32,
        DATA_ADDR => image.start_data as u32,
        TEXT_END_ADDR => image.end_code as u32,
        o if o < GREGS as u64 => reg(cpu, syscall, (o / 4) as usize),
        o if o >= USER_SZ => return Err(Errno(EIO)),
        _ => 0,
    })
}

/// `compat_ptrace_write_user`: unaligned or past `struct user` is `EIO`;
/// a word past the general registers is taken and dropped.
pub fn poke_user(
    cpu: &mut GuestCpu,
    syscall: &mut Option<SyscallEntry>,
    off: u64,
    value: u32,
) -> Result<(), Errno> {
    if off & 3 != 0 || off >= USER_SZ {
        return Err(Errno(EIO));
    }
    if off >= GREGS as u64 {
        return Ok(());
    }
    set_gregs(cpu, syscall, (off / 4) as usize, &value.to_le_bytes())
}

/// `compat_vfp_get`: D0-D31 (an AArch64 thread's V0-V15, which hold them
/// in pairs), then the FPSCR's status bits from FPSR and control bits from
/// FPCR.
pub fn vfp(cpu: &GuestCpu) -> Vec<u8> {
    let mut b = Vec::with_capacity(VFP);
    let fpscr = match cpu {
        GuestCpu::Arm(c) => {
            let v = &c.core().vfp;
            for d in v.dregs {
                b.extend_from_slice(&d.to_le_bytes());
            }
            v.fpscr.bits() & (FPSCR_STAT_MASK | FPSCR_CTRL_MASK)
        }
        GuestCpu::Aarch64(c) => {
            let core = c.core();
            for v in 0..16 {
                b.extend_from_slice(&core.get_simd(v).to_le_bytes());
            }
            (core.fpsr_value() & FPSCR_STAT_MASK) | (core.fpcr_value() & FPSCR_CTRL_MASK)
        }
        _ => 0,
    };
    b.extend_from_slice(&fpscr.to_le_bytes());
    b
}

/// `compat_vfp_set`: a prefix of the doublewords, then, if the tracer's
/// bytes reach it, the FPSCR (split into FPSR and FPCR).
pub fn set_vfp(cpu: &mut GuestCpu, bytes: &[u8]) -> Result<(), Errno> {
    let mut all = vfp(cpu);
    let n = bytes.len().min(VFP);
    all[..n].copy_from_slice(&bytes[..n]);
    let fpscr = (n > VFP - 4).then(|| u32::from_le_bytes(all[VFP - 4..].try_into().unwrap()));
    match cpu {
        GuestCpu::Arm(c) => {
            let v = &mut c.core_mut().vfp;
            for (d, w) in v.dregs.iter_mut().zip(all.chunks_exact(8)) {
                *d = u64::from_le_bytes(w.try_into().unwrap());
            }
            if let Some(f) = fpscr {
                v.fpscr = Fpscr::from_bits(f & (FPSCR_STAT_MASK | FPSCR_CTRL_MASK));
            }
        }
        GuestCpu::Aarch64(c) => {
            let core = c.core_mut();
            for (v, w) in all[..256].chunks_exact(16).enumerate() {
                core.set_simd(v as u8, u128::from_le_bytes(w.try_into().unwrap()));
            }
            if let Some(f) = fpscr {
                core.set_fpsr_value(f & FPSCR_STAT_MASK);
                core.set_fpcr_value(f & FPSCR_CTRL_MASK);
            }
        }
        _ => return Err(Errno(EIO)),
    }
    Ok(())
}
