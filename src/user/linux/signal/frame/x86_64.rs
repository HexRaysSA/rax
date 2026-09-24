//! x86-64 signal frames (`arch/x86/kernel/signal_64.c`, `signal.c`,
//! `fpu/signal.c`).
//!
//! ```text
//! frame + 0    pretcode            (sa_restorer; the handler's return address)
//! frame + 8    struct ucontext     uc_flags, uc_link, uc_stack (24),
//!                                  uc_mcontext (struct sigcontext, 256),
//!                                  uc_sigmask (8)
//! frame + 312  struct siginfo      (128)
//! frame + 440  padding up to the 64-byte-aligned XSAVE area, which is
//!              user_size bytes plus the 4-byte FP_XSTATE_MAGIC2
//! ```
//!
//! `get_sigframe` places the XSAVE area below the 128-byte red zone (or at
//! the top of the alternate stack), 64-byte aligned, and the frame below it
//! so that `(frame + 8) % 16 == 0`, the alignment a handler sees after a
//! `call`.

use super::super::{AltStack, SIGSEGV, SigInfo, sa};
use super::{
    Delivery, FaultState, FaultUpdate, FrameFault, SigreturnError, SigreturnState, get, get_u32,
    get_u64, put,
};
use crate::isa::x86_64::{LINUX_USER_CS, LINUX_USER_DS, LINUX_USER32_CS};
use crate::user::cpu::x86_64::X86UserCpu;
use crate::user::mm::AddressSpace;

/// `sizeof(struct rt_sigframe)`.
pub const RT_SIGFRAME_SIZE: u64 = 440;

/// Offsets within the frame.
pub mod off {
    /// `pretcode`.
    pub const PRETCODE: u64 = 0;
    /// `uc` (`struct ucontext`).
    pub const UC: u64 = 8;
    /// `uc.uc_flags`.
    pub const UC_FLAGS: u64 = 8;
    /// `uc.uc_link`.
    pub const UC_LINK: u64 = 16;
    /// `uc.uc_stack`.
    pub const UC_STACK: u64 = 24;
    /// `uc.uc_mcontext` (`struct sigcontext`).
    pub const MCONTEXT: u64 = 48;
    /// `uc.uc_sigmask`.
    pub const UC_SIGMASK: u64 = 304;
    /// `info`.
    pub const INFO: u64 = 312;
}

/// Offsets within `struct sigcontext` (`asm/sigcontext.h`).
pub mod sc {
    /// `r8` .. `r15` at 0, 8, ..., 56.
    pub const R8: u64 = 0;
    /// `rdi`.
    pub const RDI: u64 = 64;
    /// `rsi`.
    pub const RSI: u64 = 72;
    /// `rbp`.
    pub const RBP: u64 = 80;
    /// `rbx`.
    pub const RBX: u64 = 88;
    /// `rdx`.
    pub const RDX: u64 = 96;
    /// `rax`.
    pub const RAX: u64 = 104;
    /// `rcx`.
    pub const RCX: u64 = 112;
    /// `rsp`.
    pub const RSP: u64 = 120;
    /// `rip`.
    pub const RIP: u64 = 128;
    /// `eflags`.
    pub const EFLAGS: u64 = 136;
    /// `cs` (u16), then `gs`, `fs`, `ss`.
    pub const CS: u64 = 144;
    /// `ss` (u16).
    pub const SS: u64 = 150;
    /// `err`.
    pub const ERR: u64 = 152;
    /// `trapno`.
    pub const TRAPNO: u64 = 160;
    /// `oldmask`.
    pub const OLDMASK: u64 = 168;
    /// `cr2`.
    pub const CR2: u64 = 176;
    /// `fpstate`.
    pub const FPSTATE: u64 = 184;
    /// `reserved1[8]`: the bytes after it are not read back.
    pub const RESERVED1: u64 = 192;
}

/// `uc_flags` bits (`asm/ucontext.h`).
pub mod uc {
    /// `UC_FP_XSTATE`: the XSAVE area follows the legacy region.
    pub const FP_XSTATE: u64 = 0x1;
    /// `UC_SIGCONTEXT_SS`: `sigcontext.ss` is saved.
    pub const SIGCONTEXT_SS: u64 = 0x2;
    /// `UC_STRICT_RESTORE_SS`: restore SS exactly.
    pub const STRICT_RESTORE_SS: u64 = 0x4;
}

/// `FP_XSTATE_MAGIC1`, in `sw_reserved.magic1`.
pub const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
/// `FP_XSTATE_MAGIC2`, after the XSAVE area.
pub const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// Offset of `struct _fpx_sw_bytes` in the legacy region.
pub const SW_RESERVED: u64 = 464;

/// `FIX_EFLAGS`: the RFLAGS bits `rt_sigreturn` takes from the frame.
pub const FIX_EFLAGS: u64 = (1 << 18) // AC
    | (1 << 11) // OF
    | (1 << 10) // DF
    | (1 << 8) // TF
    | (1 << 7) // SF
    | (1 << 6) // ZF
    | (1 << 4) // AF
    | (1 << 2) // PF
    | 1 // CF
    | (1 << 16); // RF

const REDZONE: u64 = 128;
const XFEATURE_MASK_FPSSE: u64 = 0x3;
const EFLAGS_TF: u64 = 1 << 8;
const EFLAGS_DF: u64 = 1 << 10;
const EFLAGS_RF: u64 = 1 << 16;

/// `fpstate->user_size`: the standard XSAVE size for XCR0.
fn user_size(cpu: &X86UserCpu) -> u64 {
    cpu.vcpu().xsave_standard_size() as u64
}

/// `copy_fpstate_to_sigframe` for a 64-bit frame: clear the XSAVE header,
/// `XSAVE` the user features, then `save_xstate_epilog`.
fn copy_fpstate(cpu: &X86UserCpu, space: &AddressSpace, buf: u64) -> Result<(), FrameFault> {
    let v = cpu.vcpu();
    let size = user_size(cpu);
    put(space, buf + 512, &[0u8; 64])?;
    let image = v.xsave_image(v.xcr0());
    for &(lo, hi) in &image.written {
        put(space, buf + lo as u64, &image.bytes[lo..hi])?;
    }
    let mut sw = [0u8; 48];
    sw[0..4].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
    sw[4..8].copy_from_slice(&((size + 4) as u32).to_le_bytes());
    sw[8..16].copy_from_slice(&v.xcr0().to_le_bytes());
    sw[16..20].copy_from_slice(&(size as u32).to_le_bytes());
    put(space, buf + SW_RESERVED, &sw)?;
    put(space, buf + size, &FP_XSTATE_MAGIC2.to_le_bytes())?;
    let xfeatures = get_u64(space, buf + 512).ok_or(FrameFault)?;
    put(
        space,
        buf + 512,
        &(xfeatures | XFEATURE_MASK_FPSSE).to_le_bytes(),
    )
}

/// `get_sigframe`: the frame address and the XSAVE area address, or a
/// fault when the frame would overflow the alternate stack.
fn get_sigframe(
    cpu: &X86UserCpu,
    alt: &AltStack,
    space: &AddressSpace,
    d: &Delivery,
) -> Result<(u64, u64), FrameFault> {
    let regs_sp = cpu.vcpu().user_regs().rsp;
    let nested = alt.on_stack(regs_sp);
    let mut sp = regs_sp.wrapping_sub(REDZONE);
    let mut entering = false;
    if d.action.flags & sa::ONSTACK != 0 && alt.ss_flags(sp) == 0 {
        sp = alt.sp.wrapping_add(alt.size);
        entering = true;
    }
    // fpu__alloc_mathframe.
    let buf_fx = sp.wrapping_sub(user_size(cpu) + 4) & !63;
    sp = buf_fx.wrapping_sub(RT_SIGFRAME_SIZE);
    sp = (sp & !15).wrapping_sub(8);
    if (nested || entering) && !alt.contains(sp) {
        return Err(FrameFault);
    }
    copy_fpstate(cpu, space, buf_fx)?;
    Ok((sp, buf_fx))
}

/// `x64_setup_rt_frame` and the register effects of `handle_signal`.
pub fn setup_rt_frame(
    cpu: &mut X86UserCpu,
    alt: &AltStack,
    fault: &FaultState,
    space: &AddressSpace,
    d: &Delivery,
) -> Result<(), FrameFault> {
    // "x86-64 should always use SA_RESTORER."
    if d.action.flags & sa::RESTORER == 0 {
        return Err(FrameFault);
    }
    let (frame, fpstate) = get_sigframe(cpu, alt, space, d)?;
    let v = cpu.vcpu();
    let r = v.user_regs();
    let mut uc_head = [0u8; 40];
    uc_head[0..8].copy_from_slice(
        &(uc::FP_XSTATE | uc::SIGCONTEXT_SS | uc::STRICT_RESTORE_SS).to_le_bytes(),
    );
    let (ss_sp, ss_flags, ss_size) = (alt.sp, alt.flags, alt.size);
    uc_head[16..40].copy_from_slice(&AltStack::encode_stack_t(ss_sp, ss_flags, ss_size));
    put(space, frame + off::UC_FLAGS, &uc_head)?;
    put(
        space,
        frame + off::PRETCODE,
        &d.action.restorer.to_le_bytes(),
    )?;

    let mut mc = [0u8; 192];
    let mut q =
        |at: u64, v: u64| mc[at as usize..at as usize + 8].copy_from_slice(&v.to_le_bytes());
    for (i, v) in [r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15]
        .into_iter()
        .enumerate()
    {
        q(sc::R8 + 8 * i as u64, v);
    }
    q(sc::RDI, r.rdi);
    q(sc::RSI, r.rsi);
    q(sc::RBP, r.rbp);
    q(sc::RBX, r.rbx);
    q(sc::RDX, r.rdx);
    q(sc::RAX, r.rax);
    q(sc::RCX, r.rcx);
    q(sc::RSP, r.rsp);
    q(sc::RIP, r.rip);
    q(sc::EFLAGS, v.user_rflags());
    q(sc::ERR, fault.error_code);
    q(sc::TRAPNO, fault.trap_nr);
    q(sc::OLDMASK, d.saved_mask);
    q(sc::CR2, fault.cr2);
    q(sc::FPSTATE, fpstate);
    mc[sc::CS as usize..sc::CS as usize + 2].copy_from_slice(&LINUX_USER_CS.to_le_bytes());
    // gs and fs are written as zero.
    mc[sc::SS as usize..sc::SS as usize + 2].copy_from_slice(&LINUX_USER_DS.to_le_bytes());
    put(space, frame + off::MCONTEXT, &mc)?;
    put(space, frame + off::UC_SIGMASK, &d.saved_mask.to_le_bytes())?;
    if d.action.flags & sa::SIGINFO != 0 {
        put(space, frame + off::INFO, &d.info.encode())?;
    }

    let v = cpu.vcpu_mut();
    let rflags = v.user_rflags() & !(EFLAGS_DF | EFLAGS_RF | EFLAGS_TF);
    let r = v.user_regs_mut();
    r.rdi = d.sig as u64;
    r.rax = 0;
    r.rsi = frame + off::INFO;
    r.rdx = frame + off::UC;
    r.rip = d.action.handler;
    r.rsp = frame;
    v.set_user_rflags(rflags);
    // fpu__clear_user_states: the handler starts with the initial state.
    v.init_user_xstate(u64::MAX);
    Ok(())
}

/// The `SIGSEGV` `signal_fault` forces for a bad frame.
fn bad_frame() -> SigreturnError {
    SigreturnError::Bad(super::BadFrame {
        info: SigInfo::kernel(SIGSEGV),
        fault: FaultUpdate::None,
    })
}

/// `fpu__restore_sig` for a 64-bit frame. On failure the user state is
/// reset to its initial configuration, as the kernel does.
fn restore_fpstate(cpu: &mut X86UserCpu, space: &AddressSpace, buf: u64) -> bool {
    let v = cpu.vcpu_mut();
    if buf == 0 {
        v.init_user_xstate(u64::MAX);
        return true;
    }
    let size = v.xsave_standard_size() as u64;
    let user_xfeatures = v.xcr0();
    let restored = (|| {
        // check_xstate_in_sigframe.
        let magic1 = get_u32(space, buf + SW_RESERVED)?;
        let sw_xfeatures = get_u64(space, buf + SW_RESERVED + 8)?;
        let fx_only = if magic1 != FP_XSTATE_MAGIC1 {
            true
        } else {
            get_u32(space, buf + size)? != FP_XSTATE_MAGIC2
        };
        let xrestore = if fx_only {
            XFEATURE_MASK_FPSSE
        } else {
            sw_xfeatures
        } & user_xfeatures;
        let mut image = vec![0u8; if fx_only { 512 } else { size as usize }];
        space.read(buf, &mut image).ok()?;
        let v = cpu.vcpu_mut();
        let loaded = if fx_only {
            v.fxrstor_image(&image)
        } else {
            v.xrstor_image(&image, xrestore)
        };
        loaded.ok()?;
        // Features the frame does not restore return to their initial
        // state (`init_bv`).
        v.init_user_xstate(user_xfeatures & !xrestore);
        Some(())
    })();
    if restored.is_none() {
        cpu.vcpu_mut().init_user_xstate(u64::MAX);
    }
    restored.is_some()
}

/// `rt_sigreturn` (x86-64). The frame is at RSP - 8: `ret` from the handler
/// popped `pretcode`.
pub fn rt_sigreturn(
    cpu: &mut X86UserCpu,
    st: &mut SigreturnState<'_>,
    space: &AddressSpace,
) -> Result<(), SigreturnError> {
    let frame = cpu.vcpu().user_regs().rsp.wrapping_sub(8);
    let (Some(mask), Some(uc_flags)) = (
        get_u64(space, frame.wrapping_add(off::UC_SIGMASK)),
        get_u64(space, frame.wrapping_add(off::UC_FLAGS)),
    ) else {
        return Err(bad_frame());
    };
    st.set_blocked(mask);
    let sp = cpu.vcpu().user_regs().rsp;
    st.restore_altstack(space, frame.wrapping_add(off::UC_STACK), sp)
        .map_err(|()| bad_frame())?;

    // restore_sigcontext: the fields up to reserved1.
    let Some(mc) = get::<192>(space, frame.wrapping_add(off::MCONTEXT)) else {
        return Err(bad_frame());
    };
    let q = |at: u64| u64::from_le_bytes(mc[at as usize..at as usize + 8].try_into().unwrap());
    let h = |at: u64| u16::from_le_bytes(mc[at as usize..at as usize + 2].try_into().unwrap());
    let v = cpu.vcpu_mut();
    let rflags = (v.user_rflags() & !FIX_EFLAGS) | (q(sc::EFLAGS) & FIX_EFLAGS);
    let r = v.user_regs_mut();
    for (i, reg) in [
        &mut r.r8, &mut r.r9, &mut r.r10, &mut r.r11, &mut r.r12, &mut r.r13, &mut r.r14,
        &mut r.r15,
    ]
    .into_iter()
    .enumerate()
    {
        *reg = q(sc::R8 + 8 * i as u64);
    }
    r.rdi = q(sc::RDI);
    r.rsi = q(sc::RSI);
    r.rbp = q(sc::RBP);
    r.rbx = q(sc::RBX);
    r.rdx = q(sc::RDX);
    r.rax = q(sc::RAX);
    r.rcx = q(sc::RCX);
    r.rsp = q(sc::RSP);
    r.rip = q(sc::RIP);
    v.set_user_rflags(rflags);
    // CS and SS are forced to CPL 3. The emulated GDT holds only the
    // Linux selectors: SS must be __USER_DS (repaired without
    // UC_STRICT_RESTORE_SS, as force_valid_ss does), CS __USER_CS.
    let cs = h(sc::CS) | 3;
    let mut ss = h(sc::SS) | 3;
    if uc_flags & uc::STRICT_RESTORE_SS == 0 && ss != LINUX_USER_DS {
        ss = LINUX_USER_DS;
    }
    if !restore_fpstate(cpu, space, q(sc::FPSTATE)) {
        return Err(bad_frame());
    }
    if cs == LINUX_USER32_CS {
        return Err(SigreturnError::Unsupported(
            "rt_sigreturn to 32-bit compatibility mode (CS = __USER32_CS)",
        ));
    }
    if cs != LINUX_USER_CS || ss != LINUX_USER_DS {
        // The return to user mode loads an invalid selector: #GP with the
        // selector as the error code.
        let selector = if cs != LINUX_USER_CS { cs } else { ss };
        return Err(SigreturnError::Bad(super::BadFrame {
            info: SigInfo::kernel(SIGSEGV),
            fault: FaultUpdate::X86 {
                trap_nr: 13,
                error_code: u64::from(selector & !3),
                cr2: None,
            },
        }));
    }
    Ok(())
}
