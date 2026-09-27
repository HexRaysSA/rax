//! Signals of an ARM EABI task on arm64 (`arch/arm64/kernel/signal32.c`,
//! `sigreturn32.S`, `kuser32.S`, `vdso.c`'s `aarch32_setup_additional_pages`,
//! `ptrace.c`'s `valid_compat_regs`).
//!
//! `execve` maps two special pages (`aarch32_setup_additional_pages`): the
//! `[vectors]` page at [`AARCH32_VECTORS_BASE`] with the kuser helpers at
//! its end (`CONFIG_KUSER_HELPERS`), and the `[sigpage]`, placed top-down
//! as the vDSO would be, whose return code a handler without
//! `SA_RESTORER` returns through.
//!
//! A handler runs on a `struct compat_sigframe` (without `SA_SIGINFO`) or a
//! `struct compat_rt_sigframe` (`asm/signal32.h`), 8-byte aligned below the
//! stack pointer (`compat_get_sigframe`):
//!
//! ```text
//! rt + 0     struct compat_siginfo            (128; the RT frame only)
//! uc + 0     uc_flags, uc_link                (the RT frame's are 0; the
//!                                              other's flags 0x5ac3c35a)
//! uc + 8     uc_stack (compat_stack_t, 12)    (the RT frame only)
//! uc + 20    struct compat_sigcontext (84)    trap_no, error_code, oldmask,
//!                                              r0-r10, fp, ip, sp, lr, pc,
//!                                              cpsr, fault_address
//! uc + 104   uc_sigmask (8), __unused (120)
//! uc + 232   uc_regspace (512)                struct compat_vfp_sigframe
//!                                              (288), end_magic (8)
//! uc + 744   retcode[2]                       (not written)
//! ```
//!
//! The kernel stores the fields one by one, so the bytes it does not store
//! (`__unused`, the VFP record's padding, the rest of `uc_regspace`, and
//! the non-RT frame's `uc_link` and `uc_stack`) keep what the stack held.

use super::super::{AltStack, SIGSEGV, SigInfo, code, sa};
use super::{Delivery, FaultState, FaultUpdate, FrameFault, SigreturnError, SigreturnState, put};
use crate::isa::arm::Psr;
use crate::isa::arm::vfp::Fpscr;
use crate::user::cpu::arm::A32UserCpu;
use crate::user::linux::abi::{AARCH32_VECTORS_BASE, MMAP_MIN_ADDR, PAGE_SIZE, vma_flags};
use crate::user::mm::{AddressSpace, Mapping, MmError, Perms};

/// `sizeof(struct compat_sigframe)`.
pub const SIGFRAME_SIZE: u64 = 752;
/// `sizeof(struct compat_rt_sigframe)`.
pub const RT_SIGFRAME_SIZE: u64 = 128 + SIGFRAME_SIZE;

/// Offsets within a `struct compat_ucontext`.
pub mod uc {
    /// `uc_flags`.
    pub const FLAGS: u64 = 0;
    /// `uc_link`.
    pub const LINK: u64 = 4;
    /// `uc_stack`.
    pub const STACK: u64 = 8;
    /// `uc_mcontext` (`trap_no`).
    pub const MCONTEXT: u64 = 20;
    /// `uc_mcontext.arm_r0`.
    pub const R0: u64 = MCONTEXT + 12;
    /// `uc_mcontext.arm_cpsr`.
    pub const CPSR: u64 = MCONTEXT + 76;
    /// `uc_sigmask`.
    pub const SIGMASK: u64 = 104;
    /// `uc_regspace`.
    pub const REGSPACE: u64 = 232;
}

/// `uc_flags` of a non-RT frame (`compat_setup_frame`).
pub const NON_RT_UC_FLAGS: u32 = 0x5ac3_c35a;
/// `VFP_MAGIC`.
pub const VFP_MAGIC: u32 = 0x5646_5001;
/// `VFP_STORAGE_SIZE`: `sizeof(struct compat_vfp_sigframe)`.
pub const VFP_STORAGE_SIZE: u32 = 288;
/// `VFP_FPSCR_STAT_MASK` (`asm/fpsimd.h`): the FPSCR bits kept in FPSR.
pub const FPSCR_STAT_MASK: u32 = 0xf800_009f;
/// `VFP_FPSCR_CTRL_MASK`: the FPSCR bits kept in FPCR.
pub const FPSCR_CTRL_MASK: u32 = 0x07f7_9f00;
/// `FSR_WRITE_SHIFT`: the compat FSR's WnR bit in `error_code`.
const FSR_WRITE_SHIFT: u32 = 11;
/// `ESR_ELx_WNR`.
const ESR_WNR: u64 = 1 << 6;

/// AArch32 PSR bits (`arch/arm64/include/asm/ptrace.h`).
mod psr {
    /// `PSR_AA32_MODE_MASK`.
    pub const MODE_MASK: u32 = 0x1f;
    /// `PSR_AA32_MODE_USR`.
    pub const MODE_USR: u32 = 0x10;
    /// `PSR_AA32_T_BIT`.
    pub const T: u32 = 1 << 5;
    /// `PSR_AA32_F_BIT`, `PSR_AA32_I_BIT`, `PSR_AA32_A_BIT`.
    pub const AIF: u32 = 0x1c0;
    /// `PSR_AA32_E_BIT`.
    pub const E: u32 = 1 << 9;
    /// `PSR_AA32_IT_MASK`.
    pub const IT: u32 = 0x0600_fc00;
    /// `PSR_AA32_GE_MASK`.
    pub const GE: u32 = 0x000f_0000;
    /// `PSR_f`: N, Z, C, V, Q, IT[1:0], and bit 24.
    pub const F: u32 = 0xff00_0000;
    /// N, Z, C, V, Q.
    pub const NZCVQ: u32 = 0xf800_0000;
    /// Bits the emulated core has no state for (IL, `COMPAT_PSR_DIT_BIT`,
    /// PAN, SSBS, bit 24): read as zero, dropped on restore.
    pub const NONE: u32 = 0x01f0_0000;
}

/// `__kuser_helper_start` to `__kuser_helper_end` (`kuser32.S`): the
/// helpers at `0xffff0f60` (`__kuser_cmpxchg64`), `0xffff0fa0`
/// (`__kuser_memory_barrier`), `0xffff0fc0` (`__kuser_cmpxchg`), and
/// `0xffff0fe0` (`__kuser_get_tls`), each in a 32-byte slot padded with
/// zeros, and `__kuser_helper_version` (5, the slot count) at `0xffff0ffc`.
pub const KUSER_HELPERS: [u32; 40] = [
    // __kuser_cmpxchg64
    0xe92d_00f0, // push {r4, r5, r6, r7}
    0xe1c0_40d0, // ldrd r4, r5, [r0]
    0xe1c1_60d0, // ldrd r6, r7, [r1]
    0xe1b2_0f9f, // 1: ldrexd r0, r1, [r2]
    0xe030_3004, // eors r3, r0, r4
    0x0031_3005, // eoreqs r3, r1, r5
    0x01a2_3e96, // stlexdeq r3, r6, [r2]
    0x0333_0001, // teqeq r3, #1
    0x0aff_fff9, // beq 1b
    0xf57f_f05b, // dmb ish
    0xe273_0000, // rsbs r0, r3, #0
    0xe8bd_00f0, // pop {r4, r5, r6, r7}
    0xe12f_ff1e, // bx lr
    0,
    0,
    0,
    // __kuser_memory_barrier
    0xf57f_f05b, // dmb ish
    0xe12f_ff1e, // bx lr
    0,
    0,
    0,
    0,
    0,
    0,
    // __kuser_cmpxchg
    0xe192_3f9f, // 1: ldrex r3, [r2]
    0xe053_3000, // subs r3, r3, r0
    0x0182_3e91, // stlexeq r3, r1, [r2]
    0x0333_0001, // teqeq r3, #1
    0x0aff_fffa, // beq 1b
    0xf57f_f05b, // dmb ish
    0xe273_0000, // rsbs r0, r3, #0
    0xe12f_ff1e, // bx lr
    // __kuser_get_tls
    0xee1d_0f70, // mrc p15, 0, r0, c13, c0, 3
    0xe12f_ff1e, // bx lr
    0,
    0,
    0,
    0,
    0,
    // __kuser_helper_version
    5,
];

/// `__aarch32_sigret_code_start` (`sigreturn32.S`): at the start of the
/// `[sigpage]`, `sigreturn` (119) in A32 (`mov r7, #119; svc #119`) and
/// T32 (`movs r7, #119; svc #119`), then `rt_sigreturn` (173) in both.
/// `compat_setup_return` picks word `2 * thumb + 3 * siginfo`.
pub const SIGRET_CODE: [u8; 24] = [
    0x77, 0x70, 0xa0, 0xe3, 0x77, 0x00, 0x00, 0xef, // A32 sigreturn
    0x77, 0x27, 0x77, 0xdf, // T32 sigreturn
    0xad, 0x70, 0xa0, 0xe3, 0xad, 0x00, 0x00, 0xef, // A32 rt_sigreturn
    0xad, 0x27, 0xad, 0xdf, // T32 rt_sigreturn
];

/// `COMPAT_SIGPAGE_POISON_WORD`: the rest of the `[sigpage]` (a permanently
/// UNDEFINED A32 encoding).
pub const SIGPAGE_POISON: u32 = 0xe7fd_def1;

/// `aarch32_setup_additional_pages`: maps `[vectors]` (read and execute,
/// never writable: no `VM_MAYWRITE`) and `[sigpage]` (read and execute;
/// `VM_MAYWRITE` so a debugger may write it), and returns the
/// `[sigpage]`'s address.
pub fn map_pages(space: &AddressSpace, mmap_base: u64) -> Result<u64, MmError> {
    let words = |ws: &[u32]| -> Vec<u8> { ws.iter().flat_map(|w| w.to_le_bytes()).collect() };
    let mut vectors = Mapping::anonymous(Perms::READ | Perms::EXEC).named("[vectors]");
    vectors.flags = vma_flags::SPECIAL | vma_flags::DENY_WRITE;
    space.map(AARCH32_VECTORS_BASE, PAGE_SIZE, vectors)?;
    let helpers = words(&KUSER_HELPERS);
    space
        .write_raw(
            AARCH32_VECTORS_BASE + PAGE_SIZE - helpers.len() as u64,
            &helpers,
        )
        .map_err(|_| MmError::OutOfMemory)?;

    let page = space
        .find_free_top_down(PAGE_SIZE, PAGE_SIZE, MMAP_MIN_ADDR, mmap_base)
        .ok_or(MmError::OutOfMemory)?;
    let mut sigpage = Mapping::anonymous(Perms::READ | Perms::EXEC).named("[sigpage]");
    sigpage.flags = vma_flags::SPECIAL;
    space.map(page, PAGE_SIZE, sigpage)?;
    let mut image = words(&[SIGPAGE_POISON; (PAGE_SIZE / 4) as usize]);
    image[..SIGRET_CODE.len()].copy_from_slice(&SIGRET_CODE);
    space
        .write_raw(page, &image)
        .map_err(|_| MmError::OutOfMemory)?;
    Ok(page)
}

/// `compat_setup_sigframe` and the VFP record (`compat_preserve_vfp_context`)
/// of the frame whose `struct compat_ucontext` is at `ucp`.
fn setup_sigframe(
    cpu: &A32UserCpu,
    fault: &FaultState,
    space: &AddressSpace,
    ucp: u64,
    set: u64,
) -> Result<(), FrameFault> {
    let core = cpu.core();
    let wnr = u32::from(fault.fault_code & ESR_WNR != 0) << FSR_WRITE_SHIFT;
    let mut mc = Vec::with_capacity(84);
    for w in [0, wnr, set as u32] {
        mc.extend_from_slice(&w.to_le_bytes());
    }
    for r in 0..16 {
        mc.extend_from_slice(&core.regs[r].to_le_bytes());
    }
    mc.extend_from_slice(&core.cpsr.to_u32().to_le_bytes());
    mc.extend_from_slice(&(fault.fault_address as u32).to_le_bytes());
    put(space, ucp + uc::MCONTEXT, &mc)?;
    put(space, ucp + uc::SIGMASK, &set.to_le_bytes())?;

    // The VFP record: D0-D31 and an FPSCR assembled from FPSR and FPCR;
    // FPEXC is faked (EN set), FPINST and FPINST2 zero.
    let vfp = ucp + uc::REGSPACE;
    let mut head = [0u8; 8];
    head[..4].copy_from_slice(&VFP_MAGIC.to_le_bytes());
    head[4..].copy_from_slice(&VFP_STORAGE_SIZE.to_le_bytes());
    put(space, vfp, &head)?;
    let regs: Vec<u8> = core
        .vfp
        .dregs
        .iter()
        .flat_map(|d| d.to_le_bytes())
        .collect();
    put(space, vfp + 8, &regs)?;
    let fpscr = core.vfp.fpscr.bits() & (FPSCR_STAT_MASK | FPSCR_CTRL_MASK);
    put(space, vfp + 264, &fpscr.to_le_bytes())?;
    let mut exc = [0u8; 12];
    exc[..4].copy_from_slice(&(1u32 << 30).to_le_bytes());
    put(space, vfp + 272, &exc)?;
    // end_magic, an arm64 unsigned long.
    put(space, vfp + u64::from(VFP_STORAGE_SIZE), &[0; 8])
}

/// `compat_setup_frame` (without `SA_SIGINFO`) and `compat_setup_rt_frame`,
/// then `compat_setup_return`: the handler runs in the instruction set
/// its address's bit 0 selects, with the flags byte, IT, and E cleared;
/// LR is `SA_RESTORER`'s restorer or the `[sigpage]` word `2 * thumb + 3 *
/// siginfo` (plus the Thumb bit).
pub fn setup_frame(
    cpu: &mut A32UserCpu,
    alt: &AltStack,
    fault: &FaultState,
    space: &AddressSpace,
    d: &Delivery,
    sigpage: u64,
) -> Result<(), FrameFault> {
    let rt = d.action.flags & sa::SIGINFO != 0;
    let size = if rt { RT_SIGFRAME_SIZE } else { SIGFRAME_SIZE };
    // compat_get_sigframe: ATPCS 8-byte alignment.
    let sp = alt.sigsp(cpu.sp(), d.action.flags) as u32;
    let frame = u64::from(sp.wrapping_sub(size as u32) & !7);
    let ucp = if rt { frame + 128 } else { frame };
    if rt {
        put(space, frame, &d.info.encode_compat())?;
        put(space, ucp + uc::FLAGS, &[0; 8])?;
        put(
            space,
            ucp + uc::STACK,
            &AltStack::encode_compat_stack_t(alt.sp, alt.flags, alt.size),
        )?;
    } else {
        put(space, ucp + uc::FLAGS, &NON_RT_UC_FLAGS.to_le_bytes())?;
    }
    setup_sigframe(cpu, fault, space, ucp, d.saved_mask)?;

    let handler = d.action.handler as u32;
    let thumb = handler & 1;
    let mut spsr = cpu.core().cpsr.to_u32() & !(psr::F | psr::E);
    if thumb != 0 {
        spsr |= psr::T;
    } else {
        spsr &= !psr::T;
    }
    spsr &= !psr::IT;
    let retcode = if d.action.flags & sa::RESTORER != 0 {
        d.action.restorer as u32
    } else {
        let idx = (thumb << 1) + if rt { 3 } else { 0 };
        sigpage as u32 + (idx << 2) + thumb
    };
    let core = cpu.core_mut();
    core.regs[0] = d.sig as u32;
    if rt {
        core.regs[1] = frame as u32;
        core.regs[2] = ucp as u32;
    }
    core.regs[13] = frame as u32;
    core.regs[14] = retcode;
    core.cpsr = Psr::from_u32(spsr);
    cpu.set_pc(u64::from(handler));
    Ok(())
}

/// `valid_compat_regs`: the bits without state and E (no mixed-endian EL0)
/// are cleared; the result must be User mode with A, I, and F clear,
/// otherwise the PSR is forced to a User one keeping NZCVQ, IT, GE, and T,
/// and the frame is invalid.
pub fn valid_user_psr(psr: u32) -> (u32, bool) {
    let p = psr & !psr::NONE & !psr::E;
    if p & psr::MODE_MASK == psr::MODE_USR && p & psr::AIF == 0 {
        (p, true)
    } else {
        (
            p & (psr::NZCVQ | psr::IT | psr::GE | psr::T) | psr::MODE_USR,
            false,
        )
    }
}

/// `arm64_notify_segfault(sp)`, as for AArch64.
fn notify_segfault(space: &AddressSpace, sp: u64) -> SigreturnError {
    let mapped_above = !space.vmas_in(sp, space.va_limit()).is_empty();
    let code = if mapped_above {
        code::SEGV_ACCERR
    } else {
        code::SEGV_MAPERR
    };
    SigreturnError::Bad(super::BadFrame {
        info: SigInfo::fault(SIGSEGV, code, sp),
        fault: FaultUpdate::Arm64 { address: 0, esr: 0 },
    })
}

/// `compat_restore_sigframe`: the mask first, then every register (a word
/// that cannot be read loads as zero and makes the frame bad), the PSR
/// check, and, for a valid frame, the VFP record, whose magic and size
/// must match. False for a bad frame.
fn restore_sigframe(
    cpu: &mut A32UserCpu,
    st: &mut SigreturnState<'_>,
    space: &AddressSpace,
    ucp: u64,
) -> bool {
    let mut ok = true;
    match super::get_u64(space, ucp + uc::SIGMASK) {
        Some(mask) => st.set_blocked(mask),
        None => ok = false,
    }
    let mut w = [0u32; 17];
    for (i, word) in w.iter_mut().enumerate() {
        match super::get_u32(space, ucp + uc::R0 + 4 * i as u64) {
            Some(v) => *word = v,
            None => ok = false,
        }
    }
    let (cpsr, valid) = valid_user_psr(w[16]);
    ok &= valid;
    let core = cpu.core_mut();
    core.regs.copy_from_slice(&w[..16]);
    core.regs[15] &= !1;
    core.cpsr = Psr::from_u32(cpsr);
    if !ok {
        return false;
    }
    let vfp = ucp + uc::REGSPACE;
    let (Some(magic), Some(size)) = (super::get_u32(space, vfp), super::get_u32(space, vfp + 4))
    else {
        return false;
    };
    if magic != VFP_MAGIC || size != VFP_STORAGE_SIZE {
        return false;
    }
    let (Some(regs), Some(fpscr)) = (
        super::get::<256>(space, vfp + 8),
        super::get_u32(space, vfp + 264),
    ) else {
        return false;
    };
    let core = cpu.core_mut();
    for (d, b) in core.vfp.dregs.iter_mut().zip(regs.chunks_exact(8)) {
        *d = u64::from_le_bytes(b.try_into().unwrap());
    }
    core.vfp.fpscr = Fpscr::from_bits(fpscr & (FPSCR_STAT_MASK | FPSCR_CTRL_MASK));
    true
}

/// `compat_sys_sigreturn` (`rt` false) and `compat_sys_rt_sigreturn`: the
/// frame at SP, which must be 8-byte aligned; the RT frame's alternate
/// stack is restored after the registers, for the restored stack pointer.
pub fn sigreturn(
    cpu: &mut A32UserCpu,
    st: &mut SigreturnState<'_>,
    space: &AddressSpace,
    rt: bool,
) -> Result<(), SigreturnError> {
    let frame = cpu.sp();
    if frame & 7 != 0 {
        return Err(notify_segfault(space, frame));
    }
    let ucp = if rt { frame + 128 } else { frame };
    if !restore_sigframe(cpu, st, space, ucp) {
        return Err(notify_segfault(space, cpu.sp()));
    }
    if rt {
        let sp = cpu.sp();
        st.restore_altstack32(space, ucp + uc::STACK, sp)
            .map_err(|()| notify_segfault(space, sp))?;
    }
    Ok(())
}
