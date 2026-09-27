//! The i386 register view of an x86 thread (`arch/x86/kernel/ptrace.c`'s
//! `user_x86_32_view`, `getreg32`, `putreg32`, and `ia32_arch_ptrace`;
//! `fpu/regset.c`'s `fpregs_get` and `fpregs_set`; `tls.c`'s TLS
//! regset): `struct user_regs_struct32`, the `struct user32` of a 32-bit
//! tracer's `PTRACE_PEEKUSR`, the FSAVE environment (`struct
//! user_i387_ia32_struct`), and the TLS entries as `struct user_desc`s.
//!
//! A tracer sees this view of a thread running 32-bit code through
//! `PTRACE_GETREGSET` (`task_user_regset_view`), and a 32-bit tracer sees
//! it of any thread through `PTRACE_GETREGS` and the other `ia32_arch_ptrace`
//! requests. Writing a general register writes the whole 64-bit register
//! (zero-extended), as `regs->bx = value` does. A code selector other
//! than the one the thread runs with is refused (`EIO`): the kernel would
//! take it and switch or fault on the return to user mode, which the
//! emulated thread cannot do while stopped.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::signal::deliver::SyscallEntry;
use super::super::signal::frame::ia32::{convert_to_fxsr, fsave_header};
use super::super::syscall::compat::tls::UserDesc;
use crate::isa::x86_64::{GDT_ENTRY_TLS_MAX, GDT_ENTRY_TLS_MIN, X86UserSegment};
use crate::user::cpu::x86_64::X86UserCpu;

/// `sizeof(struct user_regs_struct32)`: 17 words.
pub const REGS32: usize = 17 * 4;
/// `sizeof(struct user_i387_ia32_struct)`.
pub const I387_32: usize = 108;
/// `sizeof(struct user32)`, and `offsetof(struct user32, u_debugreg)`.
const USER32: u64 = 284;
const USER32_DEBUGREG: u64 = 252;
/// `sizeof(struct user_desc)`, and the TLS entries.
pub const USER_DESC: usize = 16;
pub const TLS_ENTRIES: usize = 3;
/// `FLAG_MASK` (the flags a tracer may change).
const FLAG_MASK: u32 =
    0x1 | 0x4 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400 | 0x800 | 0x4000 | 0x1_0000 | 0x4_0000;

/// Offsets of `struct user_regs_struct32`.
mod off {
    pub const EBX: u64 = 0;
    pub const ECX: u64 = 4;
    pub const EDX: u64 = 8;
    pub const ESI: u64 = 12;
    pub const EDI: u64 = 16;
    pub const EBP: u64 = 20;
    pub const EAX: u64 = 24;
    pub const DS: u64 = 28;
    pub const ES: u64 = 32;
    pub const FS: u64 = 36;
    pub const GS: u64 = 40;
    pub const ORIG_EAX: u64 = 44;
    pub const EIP: u64 = 48;
    pub const CS: u64 = 52;
    pub const EFLAGS: u64 = 56;
    pub const ESP: u64 = 60;
    pub const SS: u64 = 64;
}

/// `getreg32`: the word of `struct user32` at `off` (the debug registers
/// read as zero: no thread has hardware breakpoints); a misaligned offset,
/// or one past the structure, is `EIO` (its end itself is not).
pub fn getreg32(cpu: &X86UserCpu, syscall: Option<SyscallEntry>, off: u64) -> Result<u32, Errno> {
    let v = cpu.vcpu();
    let r = v.user_regs();
    let sel = |s| u32::from(v.user_selector(s));
    Ok(match off {
        off::EBX => r.rbx as u32,
        off::ECX => r.rcx as u32,
        off::EDX => r.rdx as u32,
        off::ESI => r.rsi as u32,
        off::EDI => r.rdi as u32,
        off::EBP => r.rbp as u32,
        off::EAX => r.rax as u32,
        off::DS => sel(X86UserSegment::Ds),
        off::ES => sel(X86UserSegment::Es),
        off::FS => sel(X86UserSegment::Fs),
        off::GS => sel(X86UserSegment::Gs),
        off::ORIG_EAX => syscall.map_or(u32::MAX, |s| s.nr as u32),
        off::EIP => r.rip as u32,
        off::CS => sel(X86UserSegment::Cs),
        off::EFLAGS => v.user_rflags() as u32,
        off::ESP => r.rsp as u32,
        off::SS => sel(X86UserSegment::Ss),
        _ if off > USER32 || off & 3 != 0 => return Err(Errno(EIO)),
        _ => 0,
    })
}

/// `putreg32`: a register, checked as `set_segment_reg` and `set_flags`
/// check it (`EIO`: a selector not of user privilege, a null CS or SS);
/// `orig_eax` -1 ends the call (no restart); a debug register takes only
/// zero; other words of `struct user32` are ignored.
pub fn putreg32(
    cpu: &mut X86UserCpu,
    syscall: &mut Option<SyscallEntry>,
    off: u64,
    value: u32,
) -> Result<(), Errno> {
    let v = cpu.vcpu_mut();
    // set_segment_reg: the value truncated to 16 bits, of user privilege
    // or null.
    let selector = value as u16;
    let user = selector == 0 || selector & 3 == 3;
    match off {
        off::DS | off::ES | off::FS | off::GS | off::SS | off::CS if !user => Err(Errno(EIO)),
        off::CS | off::SS if selector == 0 => Err(Errno(EIO)),
        off::CS => {
            if selector != v.user_selector(X86UserSegment::Cs) {
                return Err(Errno(EIO));
            }
            Ok(())
        }
        off::DS | off::ES | off::FS | off::GS | off::SS => {
            let seg = match off {
                off::DS => X86UserSegment::Ds,
                off::ES => X86UserSegment::Es,
                off::FS => X86UserSegment::Fs,
                off::GS => X86UserSegment::Gs,
                _ => X86UserSegment::Ss,
            };
            // The load happens on the way back to user mode, where a
            // selector that cannot be loaded leaves a data register null
            // (the loadsegment fixup).
            if v.load_user_segment(seg, selector).is_err() && seg != X86UserSegment::Ss {
                let _ = v.load_user_segment(seg, 0);
            }
            Ok(())
        }
        off::EFLAGS => {
            let cur = v.user_rflags();
            v.set_user_rflags((cur & !u64::from(FLAG_MASK)) | u64::from(value & FLAG_MASK));
            Ok(())
        }
        off::ORIG_EAX => {
            *syscall = (value != u32::MAX).then(|| SyscallEntry {
                nr: u64::from(value),
                arg0: syscall.map_or(0, |s| s.arg0),
            });
            Ok(())
        }
        _ if (USER32_DEBUGREG..USER32_DEBUGREG + 32).contains(&off) => {
            if value == 0 {
                Ok(())
            } else {
                Err(Errno(EIO))
            }
        }
        off::EBX
        | off::ECX
        | off::EDX
        | off::ESI
        | off::EDI
        | off::EBP
        | off::EAX
        | off::EIP
        | off::ESP => {
            let r = v.user_regs_mut();
            let slot = match off {
                off::EBX => &mut r.rbx,
                off::ECX => &mut r.rcx,
                off::EDX => &mut r.rdx,
                off::ESI => &mut r.rsi,
                off::EDI => &mut r.rdi,
                off::EBP => &mut r.rbp,
                off::EAX => &mut r.rax,
                off::EIP => &mut r.rip,
                _ => &mut r.rsp,
            };
            *slot = u64::from(value);
            Ok(())
        }
        _ if off > USER32 || off & 3 != 0 => Err(Errno(EIO)),
        _ => Ok(()),
    }
}

/// `genregs32_get`: `struct user_regs_struct32`.
pub fn prstatus32(cpu: &X86UserCpu, syscall: Option<SyscallEntry>) -> Vec<u8> {
    (0..REGS32 as u64 / 4)
        .flat_map(|i| getreg32(cpu, syscall, i * 4).unwrap_or(0).to_le_bytes())
        .collect()
}

/// `genregs32_set`: each whole word of `bytes` in turn, until one is
/// refused (the earlier ones stay written).
pub fn set_prstatus32(
    cpu: &mut X86UserCpu,
    syscall: &mut Option<SyscallEntry>,
    bytes: &[u8],
) -> Result<(), Errno> {
    for (i, w) in bytes.chunks_exact(4).enumerate() {
        putreg32(
            cpu,
            syscall,
            4 * i as u64,
            u32::from_le_bytes(w.try_into().unwrap()),
        )?;
    }
    Ok(())
}

/// `fpregs_get` with FXSR: the FSAVE environment `__convert_from_fxsr`
/// makes of the x87 state, `fcs` the code selector and `fos` the data
/// selector.
pub fn fpregs32(cpu: &X86UserCpu) -> Vec<u8> {
    let v = cpu.vcpu();
    let image = v.xsave_image(0x3);
    let cs = v.user_selector(X86UserSegment::Cs);
    let ds = v.user_selector(X86UserSegment::Ds);
    fsave_header(&image.bytes[..512], cs, ds)[..I387_32].to_vec()
}

/// `fpregs_set`: the whole environment only (`EINVAL`), folded into the
/// x87 state (`convert_to_fxsr`).
pub fn set_fpregs32(cpu: &mut X86UserCpu, bytes: &[u8]) -> Result<(), Errno> {
    if bytes.len() != I387_32 {
        return Err(Errno(EINVAL));
    }
    let v = cpu.vcpu_mut();
    let mut legacy = v.xsave_image(0x3).bytes[..512].to_vec();
    convert_to_fxsr(&mut legacy, bytes);
    v.fxrstor_image(&legacy).map_err(|_| Errno(EINVAL))
}

/// `regset_tls_get`: the TLS entries as `struct user_desc`s.
pub fn tls(cpu: &X86UserCpu) -> Vec<u8> {
    (0..TLS_ENTRIES)
        .flat_map(|i| {
            let idx = GDT_ENTRY_TLS_MIN + i;
            let d = cpu.vcpu().user_gdt_entry(idx).unwrap_or(0);
            UserDesc::from_descriptor(idx as u32, d).encode()
        })
        .collect()
}

/// `regset_tls_set` from the first entry: every descriptor checked
/// (`tls_desc_okay`, `EINVAL`) before any is set; the segment registers
/// holding a changed entry load it again, as they would on the way back to
/// user mode.
pub fn set_tls(cpu: &mut X86UserCpu, bytes: &[u8]) -> Result<(), Errno> {
    if bytes.len() % USER_DESC != 0 {
        return Err(Errno(EINVAL));
    }
    let infos: Vec<UserDesc> = bytes
        .chunks_exact(USER_DESC)
        .map(UserDesc::decode)
        .collect();
    if !infos.iter().all(UserDesc::okay) {
        return Err(Errno(EINVAL));
    }
    for (i, info) in infos.iter().enumerate() {
        super::super::syscall::compat::tls::install(cpu, GDT_ENTRY_TLS_MIN + i, info.descriptor());
    }
    Ok(())
}

/// `PTRACE_GET_THREAD_AREA` (`do_get_thread_area`): entry `idx` as a
/// `struct user_desc`, `EINVAL` outside the TLS entries.
pub fn get_thread_area(cpu: &X86UserCpu, idx: u64) -> Result<Vec<u8>, Errno> {
    let idx = idx as i32;
    if !(GDT_ENTRY_TLS_MIN as i32..=GDT_ENTRY_TLS_MAX as i32).contains(&idx) {
        return Err(Errno(EINVAL));
    }
    let d = cpu.vcpu().user_gdt_entry(idx as usize).unwrap_or(0);
    Ok(UserDesc::from_descriptor(idx as u32, d).encode().to_vec())
}

/// `PTRACE_SET_THREAD_AREA` (`do_set_thread_area` for another task): the
/// descriptor checked (`tls_desc_okay`), then the entry (`EINVAL`).
pub fn set_thread_area(cpu: &mut X86UserCpu, idx: u64, bytes: &[u8]) -> Result<(), Errno> {
    let info = UserDesc::decode(bytes);
    if !info.okay() {
        return Err(Errno(EINVAL));
    }
    let idx = idx as i32;
    if !(GDT_ENTRY_TLS_MIN as i32..=GDT_ENTRY_TLS_MAX as i32).contains(&idx) {
        return Err(Errno(EINVAL));
    }
    super::super::syscall::compat::tls::install(cpu, idx as usize, info.descriptor());
    Ok(())
}
