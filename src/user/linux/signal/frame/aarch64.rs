//! AArch64 signal frames (`arch/arm64/kernel/signal.c`).
//!
//! ```text
//! frame + 0     struct siginfo           (128; written only with SA_SIGINFO)
//! frame + 128   struct ucontext          uc_flags, uc_link, uc_stack (24),
//!                                        uc_sigmask (8), padding to 1024 bits
//! frame + 304   struct sigcontext        fault_address, regs[31], sp, pc,
//!                                        pstate, __reserved[4096]
//! frame + 592   __reserved: records      fpsimd_context (528), esr_context
//!                                        (16, after a fault), terminator
//! frame + 4688  struct frame_record      {x29, x30}, 16-byte aligned, below
//!                                        the stack top
//! ```
//!
//! The emulated core has FP/SIMD and none of SVE, SME, GCS, POE, FPMR, or
//! TPIDR2, so the records are the ones `setup_sigframe_layout` lays out for
//! such a CPU and `parse_user_sigframe` rejects the others.

use super::super::{AltStack, SIGSEGV, SigInfo, code, sa};
use super::{
    Delivery, FaultState, FaultUpdate, FrameFault, SigreturnError, SigreturnState, get, get_u32,
    get_u64, put,
};
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::cpu::aarch64::A64UserCpu;
use crate::user::mm::AddressSpace;

/// `sizeof(struct rt_sigframe)`; the records always fit in `__reserved`.
pub const RT_SIGFRAME_SIZE: u64 = 4688;

/// Offsets within the frame.
pub mod off {
    /// `info`.
    pub const INFO: u64 = 0;
    /// `uc`.
    pub const UC: u64 = 128;
    /// `uc.uc_flags`.
    pub const UC_FLAGS: u64 = 128;
    /// `uc.uc_stack`.
    pub const UC_STACK: u64 = 144;
    /// `uc.uc_sigmask`.
    pub const UC_SIGMASK: u64 = 168;
    /// `uc.uc_mcontext.fault_address`.
    pub const FAULT_ADDRESS: u64 = 304;
    /// `uc.uc_mcontext.regs[0]`.
    pub const REGS: u64 = 312;
    /// `uc.uc_mcontext.sp`.
    pub const SP: u64 = 560;
    /// `uc.uc_mcontext.pc`.
    pub const PC: u64 = 568;
    /// `uc.uc_mcontext.pstate`.
    pub const PSTATE: u64 = 576;
    /// `uc.uc_mcontext.__reserved`.
    pub const RESERVED: u64 = 592;
}

/// Size of `__reserved`.
const RESERVED_SIZE: u64 = 4096;
/// `FPSIMD_MAGIC`.
pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
/// `sizeof(struct fpsimd_context)`.
pub const FPSIMD_SIZE: u32 = 528;
/// `ESR_MAGIC`.
pub const ESR_MAGIC: u32 = 0x4553_5201;
/// `EXTRA_MAGIC`.
pub const EXTRA_MAGIC: u32 = 0x4558_5401;
/// `TERMINATOR_SIZE`.
const TERMINATOR_SIZE: u64 = 16;
/// `SIGFRAME_MAXSZ`.
const SIGFRAME_MAXSZ: u64 = 256 * 1024;

/// PSTATE bits (`asm/ptrace.h`).
mod psr {
    /// N, Z, C, V.
    pub const NZCV: u64 = 0xF000_0000;
    /// TCO.
    pub const TCO: u64 = 1 << 25;
    /// SS (software step).
    pub const SS: u64 = 1 << 21;
    /// D, A, I, F.
    pub const DAIF: u64 = 0xF << 6;
    /// M[4] (AArch32) and M[3:0] (EL and SP selection).
    pub const MODE: u64 = 0x1F;
    /// `SPSR_EL1_AARCH64_RES0_BITS` (`arch/arm64/kernel/ptrace.c`).
    pub const RES0: u64 =
        !((1u64 << 32) - 1) | (0b11 << 26) | (0b11 << 22) | (0xFF << 13) | (1 << 5);
}

/// `valid_user_regs` for a native task: RES0 bits and SS are cleared; the
/// result must be AArch64 EL0t with DAIF clear, otherwise PSTATE is forced
/// to NZCV only and the frame is invalid.
pub fn valid_user_pstate(pstate: u64) -> (u64, bool) {
    let p = pstate & !psr::RES0 & !psr::SS;
    if p & psr::MODE == 0 && p & psr::DAIF == 0 {
        (p, true)
    } else {
        (p & psr::NZCV, false)
    }
}

/// The ESR record's offset when the frame carries one.
const ESR_OFFSET: u64 = off::RESERVED + FPSIMD_SIZE as u64;

/// `setup_rt_frame` and `setup_return`.
pub fn setup_rt_frame(
    cpu: &mut A64UserCpu,
    alt: &AltStack,
    fault: &FaultState,
    space: &AddressSpace,
    d: &Delivery,
    sigtramp: u64,
) -> Result<(), FrameFault> {
    // get_sigframe.
    let sp_top = alt.sigsp(cpu.sp(), d.action.flags);
    let next_frame = sp_top.wrapping_sub(16) & !15;
    let frame = (next_frame & !15).wrapping_sub(RT_SIGFRAME_SIZE);
    if !space.range_ok(frame, sp_top.wrapping_sub(frame)) {
        return Err(FrameFault);
    }
    let core = cpu.core();
    put(space, frame + off::UC_FLAGS, &[0u8; 16])?;
    put(
        space,
        frame + off::UC_STACK,
        &AltStack::encode_stack_t(alt.sp, alt.flags, alt.size),
    )?;

    // setup_sigframe.
    let mut record = [0u8; 16];
    record[..8].copy_from_slice(&core.get_x(29).to_le_bytes());
    record[8..].copy_from_slice(&core.get_x(30).to_le_bytes());
    put(space, next_frame, &record)?;
    let mut mc = Vec::with_capacity(288);
    mc.extend_from_slice(&fault.fault_address.to_le_bytes());
    for r in 0..31 {
        mc.extend_from_slice(&core.get_x(r).to_le_bytes());
    }
    mc.extend_from_slice(&cpu.sp().to_le_bytes());
    mc.extend_from_slice(&cpu.pc().to_le_bytes());
    mc.extend_from_slice(&core.el0_spsr().to_le_bytes());
    put(space, frame + off::FAULT_ADDRESS, &mc)?;
    put(space, frame + off::UC_SIGMASK, &d.saved_mask.to_le_bytes())?;
    let mut fp = Vec::with_capacity(FPSIMD_SIZE as usize);
    fp.extend_from_slice(&FPSIMD_MAGIC.to_le_bytes());
    fp.extend_from_slice(&FPSIMD_SIZE.to_le_bytes());
    fp.extend_from_slice(&core.fpsr_value().to_le_bytes());
    fp.extend_from_slice(&core.fpcr_value().to_le_bytes());
    for v in 0..32 {
        fp.extend_from_slice(&core.get_simd(v).to_le_bytes());
    }
    put(space, frame + off::RESERVED, &fp)?;
    let mut end = ESR_OFFSET;
    if fault.fault_code != 0 {
        let mut esr = [0u8; 16];
        esr[..4].copy_from_slice(&ESR_MAGIC.to_le_bytes());
        esr[4..8].copy_from_slice(&16u32.to_le_bytes());
        esr[8..].copy_from_slice(&fault.fault_code.to_le_bytes());
        put(space, frame + ESR_OFFSET, &esr)?;
        end += 16;
    }
    put(space, frame + end, &[0u8; 8])?;
    if d.action.flags & sa::SIGINFO != 0 {
        put(space, frame + off::INFO, &d.info.encode())?;
    }

    // setup_return.
    let tramp = if d.action.flags & sa::RESTORER != 0 {
        d.action.restorer
    } else {
        sigtramp
    };
    let spsr = cpu.core().el0_spsr() & !psr::TCO;
    let core = cpu.core_mut();
    core.set_x(0, d.sig as u64);
    if d.action.flags & sa::SIGINFO != 0 {
        core.set_x(1, frame + off::INFO);
        core.set_x(2, frame + off::UC);
    }
    core.set_x(29, next_frame);
    core.set_x(30, tramp);
    core.set_pc(d.action.handler);
    core.set_el0_spsr(spsr);
    cpu.set_sp(frame);
    Ok(())
}

/// `arm64_notify_segfault(sp)`: SEGV_MAPERR when no mapping ends above
/// `sp` (`find_vma` fails), SEGV_ACCERR otherwise, at address `sp`; the
/// fault record is cleared (`arm64_notify_die`).
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

/// `parse_user_sigframe`: the address of the FP/SIMD record and its size,
/// or `None` for an invalid frame. Unreadable records are also invalid.
fn find_fpsimd(space: &AddressSpace, frame: u64) -> Option<Option<(u64, u32)>> {
    let mut base = frame + off::RESERVED;
    let mut offset = 0u64;
    let mut limit = RESERVED_SIZE;
    let mut have_extra = false;
    let mut fpsimd = None;
    loop {
        if limit.checked_sub(offset)? < 8 || offset % 16 != 0 {
            return None;
        }
        let head = base + offset;
        let magic = get_u32(space, head)?;
        let size = u64::from(get_u32(space, head + 4)?);
        if limit - offset < size {
            return None;
        }
        match magic {
            0 => {
                return if size == 0 { Some(fpsimd) } else { None };
            }
            FPSIMD_MAGIC => {
                if fpsimd.is_some() {
                    return None;
                }
                fpsimd = Some((head, size as u32));
            }
            ESR_MAGIC => {}
            EXTRA_MAGIC => {
                if have_extra || size < 32 {
                    return None;
                }
                let datap = get_u64(space, head + 8)?;
                let extra_size = u64::from(get_u32(space, head + 16)?);
                if limit - offset - size < TERMINATOR_SIZE {
                    return None;
                }
                let terminator = head + size;
                if get_u32(space, terminator)? != 0 || get_u32(space, terminator + 4)? != 0 {
                    return None;
                }
                have_extra = true;
                let userp = terminator + TERMINATOR_SIZE;
                if datap % 16 != 0 || extra_size % 16 != 0 || datap != userp {
                    return None;
                }
                if extra_size > (frame + SIGFRAME_MAXSZ).checked_sub(userp)? {
                    return None;
                }
                base = datap;
                offset = 0;
                limit = extra_size;
                if !space.range_ok(base, limit) {
                    return None;
                }
                continue;
            }
            // SVE, SME, GCS, POE, FPMR, and TPIDR2 records need features
            // the core does not have; anything else is unknown.
            _ => return None,
        }
        if size < 8 || limit - offset < size {
            return None;
        }
        offset += size;
    }
}

/// `rt_sigreturn` (AArch64). The frame is at SP.
pub fn rt_sigreturn(
    cpu: &mut A64UserCpu,
    st: &mut SigreturnState<'_>,
    space: &AddressSpace,
) -> Result<(), SigreturnError> {
    let frame = cpu.sp();
    if frame % 16 != 0 || !space.range_ok(frame, RT_SIGFRAME_SIZE) {
        return Err(notify_segfault(space, frame));
    }
    // restore_sigframe: the mask first, then every register, then PSTATE
    // validation and the records.
    let mut ok = true;
    match get_u64(space, frame + off::UC_SIGMASK) {
        Some(mask) => st.set_blocked(mask),
        None => ok = false,
    }
    // __get_user_error: a word that faults reads as zero and marks the
    // frame bad; the others are still loaded.
    let mut w = [0u64; 34];
    for (i, word) in w.iter_mut().enumerate() {
        match get_u64(space, frame + off::REGS + 8 * i as u64) {
            Some(v) => *word = v,
            None => ok = false,
        }
    }
    let w = |i: usize| w[i];
    let core = cpu.core_mut();
    for r in 0..31 {
        core.set_x(r, w(r as usize));
    }
    core.set_pc(w(32));
    let (pstate, valid) = valid_user_pstate(w(33));
    ok &= valid;
    core.set_el0_spsr(pstate);
    cpu.set_sp(w(31));
    if ok {
        ok = match find_fpsimd(space, frame) {
            Some(Some((rec, size))) if size == FPSIMD_SIZE => {
                match get::<{ FPSIMD_SIZE as usize }>(space, rec) {
                    Some(b) => {
                        let core = cpu.core_mut();
                        core.set_fpsr_value(u32::from_le_bytes(b[8..12].try_into().unwrap()));
                        core.set_fpcr_value(u32::from_le_bytes(b[12..16].try_into().unwrap()));
                        for v in 0..32 {
                            let at = 16 + v * 16;
                            core.set_simd(
                                v as u8,
                                u128::from_le_bytes(b[at..at + 16].try_into().unwrap()),
                            );
                        }
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        };
    }
    if !ok {
        return Err(notify_segfault(space, cpu.sp()));
    }
    let sp = cpu.sp();
    st.restore_altstack(space, frame + off::UC_STACK, sp)
        .map_err(|()| notify_segfault(space, sp))?;
    Ok(())
}
