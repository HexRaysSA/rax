//! i386 signal frames of a compatibility task on an x86-64 kernel
//! (`arch/x86/kernel/signal_32.c` with `CONFIG_IA32_EMULATION`;
//! `get_sigframe` in `signal.c`; `fpu/signal.c`; the FSAVE conversions of
//! `fpu/regset.c`; `asm/sigframe.h`, `asm/ia32.h`,
//! `uapi/asm/sigcontext.h`).
//!
//! A handler installed by a 32-bit call (`SA_IA32_ABI`) runs on `struct
//! sigframe_ia32`, or with `SA_SIGINFO` on `struct rt_sigframe_ia32`:
//!
//! ```text
//! sigframe_ia32 (732 bytes)           rt_sigframe_ia32 (268 bytes)
//! +0    pretcode                      +0    pretcode
//! +4    sig                           +4    sig
//! +8    struct sigcontext_32 (88)     +8    pinfo (&info)
//! +96   fpstate_unused (624)          +12   puc (&uc)
//! +720  extramask[1]                  +16   struct compat_siginfo (128)
//! +724  retcode[8]                    +144  struct ucontext_ia32: uc_flags,
//!                                           uc_link, uc_stack (12),
//!                                           uc_mcontext (88) at +164,
//!                                           uc_sigmask (8) at +252
//!                                     +260  retcode[8]
//! ```
//!
//! Above the frame lies the FPU state: the 112-byte FSAVE-format header
//! (`struct fregs_state`, converted from the FXSAVE image, its `magic` 0
//! marking FXSR data to follow), then the 64-byte-aligned XSAVE area of the
//! 64-bit frame, whose extended size counts the header. There is no red
//! zone, and the frame is aligned for an i386 function entry:
//! `(frame + 4) % 16 == 0`. `retcode` is no longer executed but kept for
//! debuggers; a handler without `SA_RESTORER` returns through the `[vdso]`
//! trampolines ([`VDSO_SIGRETURN`], [`VDSO_RT_SIGRETURN`]).

use super::super::{AltStack, SIGBUS, SIGSEGV, SigInfo, sa};
use super::x86_64::{
    self as x64, FIX_EFLAGS, FP_XSTATE_MAGIC1, FP_XSTATE_MAGIC2, HANDLER_CLEARED_EFLAGS,
    SW_RESERVED, XFEATURE_MASK_FPSSE,
};
use super::{
    BadFrame, Delivery, FaultState, FaultUpdate, FrameFault, SigreturnError, SigreturnState, get,
    get_u32, get_u64, put,
};
use crate::isa::x86_64::{
    LINUX_USER_CS, LINUX_USER_DS, LINUX_USER32_CS, X86SegmentFault, X86UserSegment,
};
use crate::user::cpu::x86_64::X86UserCpu;
use crate::user::mm::AddressSpace;

/// `sizeof(struct sigframe_ia32)`.
pub const SIGFRAME_SIZE: u64 = 732;
/// `sizeof(struct rt_sigframe_ia32)`.
pub const RT_SIGFRAME_SIZE: u64 = 268;
/// `sizeof(struct fregs_state)`: the FSAVE header below the XSAVE area.
pub const FSAVE_SIZE: u64 = 112;

/// Offsets within `struct sigframe_ia32`.
pub mod off {
    /// `pretcode`.
    pub const PRETCODE: u64 = 0;
    /// `sig`.
    pub const SIG: u64 = 4;
    /// `sc` (`struct sigcontext_32`).
    pub const SC: u64 = 8;
    /// `extramask[0]`: the upper half of the saved mask.
    pub const EXTRAMASK: u64 = 720;
    /// `retcode`.
    pub const RETCODE: u64 = 724;
}

/// Offsets within `struct rt_sigframe_ia32`.
pub mod rt {
    /// `pretcode`.
    pub const PRETCODE: u64 = 0;
    /// `sig`.
    pub const SIG: u64 = 4;
    /// `pinfo`, then `puc`.
    pub const PINFO: u64 = 8;
    /// `info` (`struct compat_siginfo`).
    pub const INFO: u64 = 16;
    /// `uc` (`struct ucontext_ia32`), starting with `uc_flags`.
    pub const UC: u64 = 144;
    /// `uc.uc_stack` (`compat_stack_t`).
    pub const UC_STACK: u64 = 152;
    /// `uc.uc_mcontext` (`struct sigcontext_32`).
    pub const MCONTEXT: u64 = 164;
    /// `uc.uc_sigmask`.
    pub const UC_SIGMASK: u64 = 252;
    /// `retcode`.
    pub const RETCODE: u64 = 260;
}

/// Offsets within `struct sigcontext_32`. The selectors are 16-bit fields
/// written as 32-bit words (their `__*h` halves zero).
pub mod sc {
    /// `gs`.
    pub const GS: usize = 0;
    /// `fs`.
    pub const FS: usize = 4;
    /// `es`.
    pub const ES: usize = 8;
    /// `ds`.
    pub const DS: usize = 12;
    /// `di`.
    pub const DI: usize = 16;
    /// `si`.
    pub const SI: usize = 20;
    /// `bp`.
    pub const BP: usize = 24;
    /// `sp`.
    pub const SP: usize = 28;
    /// `bx`.
    pub const BX: usize = 32;
    /// `dx`.
    pub const DX: usize = 36;
    /// `cx`.
    pub const CX: usize = 40;
    /// `ax`.
    pub const AX: usize = 44;
    /// `trapno`.
    pub const TRAPNO: usize = 48;
    /// `err`.
    pub const ERR: usize = 52;
    /// `ip`.
    pub const IP: usize = 56;
    /// `cs`.
    pub const CS: usize = 60;
    /// `flags`.
    pub const FLAGS: usize = 64;
    /// `sp_at_signal`.
    pub const SP_AT_SIGNAL: usize = 68;
    /// `ss`.
    pub const SS: usize = 72;
    /// `fpstate`.
    pub const FPSTATE: usize = 76;
    /// `oldmask`: the lower half of the saved mask.
    pub const OLDMASK: usize = 80;
    /// `cr2`.
    pub const CR2: usize = 84;
    /// `sizeof(struct sigcontext_32)`.
    pub const SIZE: usize = 88;
}

/// `__NR_ia32_sigreturn`.
pub const NR_SIGRETURN: u8 = 119;
/// `__NR_ia32_rt_sigreturn`.
pub const NR_RT_SIGRETURN: u8 = 173;

/// `sigframe_ia32.retcode`: `popl %eax; movl $__NR_ia32_sigreturn, %eax;
/// int $0x80`.
pub const SIGRETURN_CODE: [u8; 8] = [0x58, 0xB8, NR_SIGRETURN, 0, 0, 0, 0xCD, 0x80];
/// `rt_sigframe_ia32.retcode`: `movl $__NR_ia32_rt_sigreturn, %eax; int
/// $0x80`, padded.
pub const RT_SIGRETURN_CODE: [u8; 8] = [0xB8, NR_RT_SIGRETURN, 0, 0, 0, 0xCD, 0x80, 0];

/// Offset of `__kernel_sigreturn` in the `[vdso]` page.
pub const VDSO_SIGRETURN: u64 = 0x10;
/// Offset of `__kernel_rt_sigreturn` in the `[vdso]` page.
pub const VDSO_RT_SIGRETURN: u64 = 0x20;

/// The `[vdso]` page's code (`arch/x86/entry/vdso/vdso32/sigreturn.S`):
/// padding `nop`s, `__kernel_sigreturn` (the non-RT `retcode`) and
/// `__kernel_rt_sigreturn`, each followed by its landing-pad `nop` and
/// aligned to 16 bytes. Unwinders recognize the two sequences by their
/// bytes.
pub fn vdso_code() -> [u8; 0x30] {
    let mut code = [0x90u8; 0x30];
    let (s, r) = (VDSO_SIGRETURN as usize, VDSO_RT_SIGRETURN as usize);
    code[s..s + 8].copy_from_slice(&SIGRETURN_CODE);
    code[r..r + 7].copy_from_slice(&RT_SIGRETURN_CODE[..7]);
    code
}

/// `uc_flags`: `UC_FP_XSTATE`, the XSAVE area follows the legacy region.
const UC_FP_XSTATE: u32 = 0x1;
/// `X86_FXSR_MAGIC`: `_fpstate_32.magic` for FXSR data.
const X86_FXSR_MAGIC: u16 = 0x0000;
/// `sizeof(struct user_i387_ia32_struct)`: the FSAVE environment and
/// registers, as the kernel copies them (`status` and `magic` follow).
const I387_ENV_SIZE: usize = 108;
/// The components with their own ranges in the legacy region
/// (`xstate_offsets`, `xstate_sizes`): x87 (0-159, MXCSR included) and SSE
/// (the XMM registers, 160-415).
const LEGACY_COMPONENTS: [(usize, usize); 2] = [(0, 160), (160, 256)];
/// `XFEATURE_MASK_YMM`.
const XFEATURE_MASK_YMM: u64 = 1 << 2;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `twd_fxsr_to_i387`: the full x87 tag word from FXSAVE's abridged one
/// and the registers' contents (valid 0, zero 1, special 2, empty 3), the
/// upper half set.
pub fn twd_fxsr_to_i387(legacy: &[u8]) -> u32 {
    let tos = u32::from((u16_at(legacy, 2) >> 11) & 7);
    let abridged = legacy[4];
    let mut twd = 0xFFFF_0000u32;
    for i in 0..8u32 {
        let tag = if abridged >> i & 1 != 0 {
            // Physical register i is ST((i - TOP) & 7), FXSAVE's slot.
            let st = 32 + 16 * (i.wrapping_sub(tos) & 7) as usize;
            let significand = (0..4).map(|w| u16_at(legacy, st + 2 * w));
            match u16_at(legacy, st + 8) & 0x7FFF {
                0x7FFF => 2,
                0 if significand.clone().all(|w| w == 0) => 1,
                0 => 2,
                _ if u16_at(legacy, st + 6) & 0x8000 != 0 => 0,
                _ => 2,
            }
        } else {
            3
        };
        twd |= tag << (2 * i);
    }
    twd
}

/// `twd_i387_to_fxsr`: the abridged tag word (one bit per register, set
/// unless the register is empty).
pub fn twd_i387_to_fxsr(twd: u16) -> u8 {
    let mut tmp = u32::from(!twd);
    tmp = (tmp | (tmp >> 1)) & 0x5555;
    tmp = (tmp | (tmp >> 1)) & 0x3333;
    tmp = (tmp | (tmp >> 2)) & 0x0F0F;
    tmp = (tmp | (tmp >> 4)) & 0x00FF;
    tmp as u8
}

/// `save_fsave_header` on an x86-64 kernel: `convert_from_fxsr` of the
/// legacy region (64-bit `FXSAVE` format, so the instruction and operand
/// pointers are the 32-bit offsets, `fcs` the user code selector, and
/// `fos` the data selector), then `status` and the FXSR `magic`.
pub fn fsave_header(legacy: &[u8], cs: u16, ds: u16) -> [u8; FSAVE_SIZE as usize] {
    let mut h = [0u8; FSAVE_SIZE as usize];
    let mut w = |at: usize, v: u32| h[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let swd = u16_at(legacy, 2);
    w(0, u32::from(u16_at(legacy, 0)) | 0xFFFF_0000);
    w(4, u32::from(swd) | 0xFFFF_0000);
    w(8, twd_fxsr_to_i387(legacy));
    w(12, u64_at(legacy, 8) as u32);
    w(16, u32::from(cs));
    w(20, u64_at(legacy, 16) as u32);
    w(24, u32::from(ds) | 0xFFFF_0000);
    for i in 0..8 {
        h[28 + 10 * i..38 + 10 * i].copy_from_slice(&legacy[32 + 16 * i..42 + 16 * i]);
    }
    h[108..110].copy_from_slice(&swd.to_le_bytes());
    h[110..112].copy_from_slice(&X86_FXSR_MAGIC.to_le_bytes());
    h
}

/// `convert_to_fxsr` on an x86-64 kernel: folds the FSAVE environment and
/// registers into the legacy region, the code and data selectors ignored
/// and the opcode taken from the upper half of `fcs`.
pub fn convert_to_fxsr(legacy: &mut [u8], env: &[u8]) {
    legacy[0..2].copy_from_slice(&env[0..2]);
    legacy[2..4].copy_from_slice(&env[4..6]);
    legacy[4] = twd_i387_to_fxsr(u16_at(env, 8));
    legacy[5] = 0;
    legacy[6..8].copy_from_slice(&env[18..20]);
    legacy[8..16].copy_from_slice(&u64::from(u32_at(env, 12)).to_le_bytes());
    legacy[16..24].copy_from_slice(&u64::from(u32_at(env, 20)).to_le_bytes());
    for i in 0..8 {
        legacy[32 + 16 * i..42 + 16 * i].copy_from_slice(&env[28 + 10 * i..38 + 10 * i]);
    }
}

/// `copy_fpstate_to_sigframe` for a 32-bit frame: the XSAVE area at
/// `buf_fx`, the FSAVE header at `buf` below it, then the epilog.
fn copy_fpstate(
    cpu: &X86UserCpu,
    space: &AddressSpace,
    buf: u64,
    buf_fx: u64,
) -> Result<(), FrameFault> {
    x64::xsave_to_frame(cpu, space, buf_fx)?;
    let v = cpu.vcpu();
    let legacy = v.xsave_image(v.xcr0()).bytes;
    let cs = v.user_selector(X86UserSegment::Cs);
    let ds = v.user_selector(X86UserSegment::Ds);
    put(space, buf, &fsave_header(&legacy[..512], cs, ds))?;
    x64::save_xstate_epilog(cpu, space, buf_fx, true)
}

/// `get_sigframe` for a 32-bit frame of `frame_size` bytes: the frame's
/// address and the FPU state's (the FSAVE header's), which it writes; a
/// fault when the frame would overflow the alternate stack.
fn get_sigframe(
    cpu: &X86UserCpu,
    alt: &AltStack,
    space: &AddressSpace,
    d: &Delivery,
    frame_size: u64,
) -> Result<(u64, u64), FrameFault> {
    let v = cpu.vcpu();
    let regs_sp = v.user_regs().rsp;
    let nested = alt.on_stack(regs_sp);
    let mut sp = regs_sp;
    let mut entering = false;
    let flags = d.action.flags;
    if flags & sa::ONSTACK != 0 {
        if alt.ss_flags(sp) == 0 {
            sp = alt.sp.wrapping_add(alt.size);
            entering = true;
        }
    } else if !nested
        && v.user_selector(X86UserSegment::Ss) != LINUX_USER_DS
        && flags & sa::RESTORER == 0
        && d.action.restorer != 0
    {
        // The legacy stack switch: with a stack segment of its own, the
        // thread's sa_restorer names the stack.
        sp = d.action.restorer;
        entering = true;
    }
    // fpu__alloc_mathframe.
    let buf_fx = sp.wrapping_sub(x64::user_size(cpu) + 4) & !63;
    let buf = buf_fx.wrapping_sub(FSAVE_SIZE);
    let frame = (buf.wrapping_sub(frame_size).wrapping_add(4) & !15).wrapping_sub(4);
    if (nested || entering) && !alt.contains(frame) {
        return Err(FrameFault);
    }
    copy_fpstate(cpu, space, buf, buf_fx)?;
    Ok((frame, buf))
}

/// `__unsafe_setup_sigcontext32`: every register as a 32-bit word, the
/// selectors the thread holds, the fault record, the FPU state's address,
/// and the lower half of the saved mask.
fn sigcontext(cpu: &X86UserCpu, fault: &FaultState, fpstate: u64, mask: u64) -> [u8; sc::SIZE] {
    let v = cpu.vcpu();
    let r = v.user_regs();
    let seg = |s| u32::from(v.user_selector(s));
    let mut b = [0u8; sc::SIZE];
    for (at, value) in [
        (sc::GS, seg(X86UserSegment::Gs)),
        (sc::FS, seg(X86UserSegment::Fs)),
        (sc::ES, seg(X86UserSegment::Es)),
        (sc::DS, seg(X86UserSegment::Ds)),
        (sc::DI, r.rdi as u32),
        (sc::SI, r.rsi as u32),
        (sc::BP, r.rbp as u32),
        (sc::SP, r.rsp as u32),
        (sc::BX, r.rbx as u32),
        (sc::DX, r.rdx as u32),
        (sc::CX, r.rcx as u32),
        (sc::AX, r.rax as u32),
        (sc::TRAPNO, fault.trap_nr as u32),
        (sc::ERR, fault.error_code as u32),
        (sc::IP, r.rip as u32),
        (sc::CS, seg(X86UserSegment::Cs)),
        (sc::FLAGS, v.user_rflags() as u32),
        (sc::SP_AT_SIGNAL, r.rsp as u32),
        (sc::SS, seg(X86UserSegment::Ss)),
        (sc::FPSTATE, fpstate as u32),
        (sc::OLDMASK, mask as u32),
        (sc::CR2, fault.cr2 as u32),
    ] {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    b
}

/// The register effects of `ia32_setup_frame`/`ia32_setup_rt_frame` and
/// `handle_signal`: the handler at `frame` with `-mregparm=3` arguments,
/// DS and ES reloaded, `__USER32_CS` and `__USER_DS`, DF, RF, and TF
/// clear, and the initial FPU state.
fn enter_handler(cpu: &mut X86UserCpu, d: &Delivery, frame: u64, dx: u64, cx: u64) {
    if !cpu.compat() {
        cpu.set_compat(true);
    }
    let v = cpu.vcpu_mut();
    let rflags = v.user_rflags() & !HANDLER_CLEARED_EFLAGS;
    let r = v.user_regs_mut();
    r.rsp = frame;
    r.rip = d.action.handler;
    r.rax = d.sig as u64;
    r.rdx = dx;
    r.rcx = cx;
    v.set_user_rflags(rflags);
    for seg in [X86UserSegment::Ds, X86UserSegment::Es, X86UserSegment::Ss] {
        v.load_user_segment(seg, LINUX_USER_DS)
            .expect("__USER_DS is a valid user data segment");
    }
    v.init_user_xstate(u64::MAX);
}

/// `ia32_setup_frame`: the non-RT frame (a handler without `SA_SIGINFO`).
/// Without `SA_RESTORER` the handler returns through the `[vdso]`
/// trampoline at `vdso` (the frame's own `retcode` when there is none).
pub fn setup_frame(
    cpu: &mut X86UserCpu,
    alt: &AltStack,
    fault: &FaultState,
    space: &AddressSpace,
    d: &Delivery,
    vdso: u64,
) -> Result<(), FrameFault> {
    let (frame, fpstate) = get_sigframe(cpu, alt, space, d, SIGFRAME_SIZE)?;
    let restorer = if d.action.flags & sa::RESTORER != 0 {
        d.action.restorer
    } else if vdso != 0 {
        vdso + VDSO_SIGRETURN
    } else {
        frame + off::RETCODE
    };
    let mask = d.saved_mask;
    put(space, frame + off::SIG, &(d.sig as u32).to_le_bytes())?;
    let context = sigcontext(cpu, fault, fpstate, mask);
    put(space, frame + off::SC, &context)?;
    put(
        space,
        frame + off::EXTRAMASK,
        &((mask >> 32) as u32).to_le_bytes(),
    )?;
    put(
        space,
        frame + off::PRETCODE,
        &(restorer as u32).to_le_bytes(),
    )?;
    put(space, frame + off::RETCODE, &SIGRETURN_CODE)?;
    enter_handler(cpu, d, frame, 0, 0);
    Ok(())
}

/// `ia32_setup_rt_frame`: the `SA_SIGINFO` frame with the `struct
/// compat_siginfo` and `struct ucontext_ia32`. Without `SA_RESTORER` the
/// handler returns through `__kernel_rt_sigreturn` in the `[vdso]` page at
/// `vdso`.
pub fn setup_rt_frame(
    cpu: &mut X86UserCpu,
    alt: &AltStack,
    fault: &FaultState,
    space: &AddressSpace,
    d: &Delivery,
    vdso: u64,
) -> Result<(), FrameFault> {
    let (frame, fpstate) = get_sigframe(cpu, alt, space, d, RT_SIGFRAME_SIZE)?;
    let (info, uc) = (frame + rt::INFO, frame + rt::UC);
    let mut head = [0u8; 12];
    head[0..4].copy_from_slice(&(d.sig as u32).to_le_bytes());
    head[4..8].copy_from_slice(&(info as u32).to_le_bytes());
    head[8..12].copy_from_slice(&(uc as u32).to_le_bytes());
    put(space, frame + rt::SIG, &head)?;
    // uc_flags, uc_link, and uc_stack (unsafe_compat_save_altstack).
    let mut uc_head = [0u8; 20];
    uc_head[0..4].copy_from_slice(&UC_FP_XSTATE.to_le_bytes());
    uc_head[8..20].copy_from_slice(&AltStack::encode_compat_stack_t(
        alt.sp, alt.flags, alt.size,
    ));
    put(space, uc, &uc_head)?;
    let restorer = if d.action.flags & sa::RESTORER != 0 {
        d.action.restorer
    } else {
        vdso + VDSO_RT_SIGRETURN
    };
    put(
        space,
        frame + rt::PRETCODE,
        &(restorer as u32).to_le_bytes(),
    )?;
    put(space, frame + rt::RETCODE, &RT_SIGRETURN_CODE)?;
    let context = sigcontext(cpu, fault, fpstate, d.saved_mask);
    put(space, frame + rt::MCONTEXT, &context)?;
    put(space, frame + rt::UC_SIGMASK, &d.saved_mask.to_le_bytes())?;
    put(space, info, &d.info.encode_compat())?;
    enter_handler(cpu, d, frame, info, uc);
    Ok(())
}

/// `fpu__restore_sig` for a 32-bit frame (`__fpu_restore_sig` with
/// `ia32_fxstate`): the FSAVE header at `buf` and the FXSAVE or XSAVE image
/// after it are folded into the thread's state, which `XRSTOR` then loads.
/// A null `buf` restores the initial state. On failure the state is reset
/// to its initial configuration, as the kernel does.
pub fn restore_fpstate(cpu: &mut X86UserCpu, space: &AddressSpace, buf: u64) -> bool {
    if buf == 0 {
        cpu.vcpu_mut().init_user_xstate(u64::MAX);
        return true;
    }
    let restored = fold_fpstate(cpu, space, buf)
        .and_then(|image| cpu.vcpu_mut().xrstor_image(&image, u64::MAX).ok());
    if restored.is_none() {
        cpu.vcpu_mut().init_user_xstate(u64::MAX);
    }
    restored.is_some()
}

/// The kernel's copy of the state after `__fpu_restore_sig` has read the
/// frame at `buf`, as a standard XSAVE image; `None` for a fault or an
/// invalid image. The thread's current state stands for the parts the
/// frame does not supply.
fn fold_fpstate(cpu: &X86UserCpu, space: &AddressSpace, buf: u64) -> Option<Vec<u8>> {
    let v = cpu.vcpu();
    let size = v.xsave_standard_size();
    let buf_fx = buf.wrapping_add(FSAVE_SIZE);
    // check_xstate_in_sigframe.
    let sw = get::<48>(space, buf_fx.wrapping_add(SW_RESERVED))?;
    let fx_only = u32_at(&sw, 0) != FP_XSTATE_MAGIC1
        || get_u32(space, buf_fx.wrapping_add(size as u64))? != FP_XSTATE_MAGIC2;
    let user_xfeatures = if fx_only {
        XFEATURE_MASK_FPSSE
    } else {
        u64_at(&sw, 8)
    };
    let env = get::<I387_ENV_SIZE>(space, buf)?;
    let mut image = v.xsave_image(v.xcr0()).bytes;
    let valid_mxcsr = |m: u32| crate::isa::x86_64::mxcsr_value_is_valid(m);
    if fx_only {
        let fx = get::<512>(space, buf_fx)?;
        if !valid_mxcsr(u32_at(&fx, 24)) {
            return None;
        }
        image[..512].copy_from_slice(&fx);
        let xfeatures = u64_at(&image, 512) | XFEATURE_MASK_FPSSE;
        image[512..520].copy_from_slice(&xfeatures.to_le_bytes());
    } else {
        // copy_uabi_to_xstate: validate_user_xstate_header, then MXCSR and
        // each component the header names.
        let hdr = get::<64>(space, buf_fx.wrapping_add(512))?;
        let xfeatures = u64_at(&hdr, 0);
        if xfeatures & !v.xcr0() != 0 || hdr[8..].iter().any(|&b| b != 0) {
            return None;
        }
        if xfeatures & (XFEATURE_MASK_FPSSE | XFEATURE_MASK_YMM) != 0 {
            let mxcsr = get::<8>(space, buf_fx.wrapping_add(24))?;
            if !valid_mxcsr(u32_at(&mxcsr, 0)) {
                return None;
            }
            if xfeatures & 1 == 0 {
                image[24..32].copy_from_slice(&mxcsr);
            }
        }
        for c in (0..64).filter(|c| xfeatures >> c & 1 != 0) {
            let (offset, len) = match LEGACY_COMPONENTS.get(c) {
                Some(&range) => range,
                None => {
                    let (eax, ebx, _, _) = v.cpuid(0xD, c as u32);
                    (ebx as usize, eax as usize)
                }
            };
            let mut bytes = vec![0u8; len];
            space
                .read(buf_fx.wrapping_add(offset as u64), &mut bytes)
                .ok()?;
            image[offset..offset + len].copy_from_slice(&bytes);
        }
        image[512..576].fill(0);
        image[512..520].copy_from_slice(&xfeatures.to_le_bytes());
    }
    // Fold the legacy FP storage, then keep only the frame's features.
    convert_to_fxsr(&mut image[..512], &env);
    let xfeatures = u64_at(&image, 512) & user_xfeatures;
    image[512..520].copy_from_slice(&xfeatures.to_le_bytes());
    Some(image)
}

/// `fixup_rpl`: the null selectors 0-3 unchanged, any other at RPL 3.
fn fixup_rpl(selector: u16) -> u16 {
    if selector <= 3 {
        selector
    } else {
        selector | 3
    }
}

/// A fault the return to user mode (`IRET`) raises with the restored
/// state: `#GP` forces `SIGSEGV`, `#SS` `SIGBUS`, each with the trap
/// recorded.
fn iret_fault(fault: X86SegmentFault) -> SigreturnError {
    let (signo, trap_nr, error_code) = match fault {
        X86SegmentFault::GeneralProtection(e) => (SIGSEGV, 13, e),
        X86SegmentFault::NotPresent(e) => (SIGBUS, 11, e),
        X86SegmentFault::StackSegment(e) => (SIGBUS, 12, e),
    };
    SigreturnError::Fault(BadFrame {
        info: SigInfo::kernel(signo),
        fault: FaultUpdate::X86 {
            trap_nr,
            error_code: u64::from(error_code),
            cr2: None,
        },
    })
}

/// `ia32_restore_sigcontext`: the 32-bit registers (their upper halves
/// cleared; R8-R15 unchanged), the `FIX_EFLAGS` bits, the data selectors
/// that changed (`reload_segments`; one that does not load becomes null),
/// and the FPU state. Returns the CS and SS the return to user mode loads.
fn restore_sigcontext(
    cpu: &mut X86UserCpu,
    space: &AddressSpace,
    addr: u64,
) -> Result<(u16, u16), SigreturnError> {
    let Some(b) = get::<{ sc::SIZE }>(space, addr) else {
        return Err(x64::bad_frame());
    };
    let w = |at: usize| u64::from(u32_at(&b, at));
    let v = cpu.vcpu_mut();
    let rflags = (v.user_rflags() & !FIX_EFLAGS) | (w(sc::FLAGS) & FIX_EFLAGS);
    let r = v.user_regs_mut();
    r.rbx = w(sc::BX);
    r.rcx = w(sc::CX);
    r.rdx = w(sc::DX);
    r.rsi = w(sc::SI);
    r.rdi = w(sc::DI);
    r.rbp = w(sc::BP);
    r.rax = w(sc::AX);
    r.rsp = w(sc::SP);
    r.rip = w(sc::IP);
    v.set_user_rflags(rflags);
    for (seg, at) in [
        (X86UserSegment::Gs, sc::GS),
        (X86UserSegment::Fs, sc::FS),
        (X86UserSegment::Ds, sc::DS),
        (X86UserSegment::Es, sc::ES),
    ] {
        let selector = fixup_rpl(u16_at(&b, at));
        if selector != v.user_selector(seg) && v.load_user_segment(seg, selector).is_err() {
            v.load_user_segment(seg, 0)
                .expect("a null data selector always loads");
        }
    }
    let cs = u16_at(&b, sc::CS) | 3;
    let ss = u16_at(&b, sc::SS) | 3;
    if !restore_fpstate(cpu, space, w(sc::FPSTATE)) {
        return Err(x64::bad_frame());
    }
    Ok((cs, ss))
}

/// The return to user mode with the restored CS and SS: `IRET`'s checks of
/// the code selector, then of the stack selector.
fn iret(cpu: &mut X86UserCpu, cs: u16, ss: u16) -> Result<(), SigreturnError> {
    match cs {
        LINUX_USER32_CS => {}
        LINUX_USER_CS => {
            return Err(SigreturnError::Unsupported(
                "sigreturn of a compatibility task to 64-bit mode (CS = __USER_CS)",
            ));
        }
        _ => return Err(iret_fault(X86SegmentFault::GeneralProtection(cs & !3))),
    }
    cpu.vcpu_mut()
        .load_user_segment(X86UserSegment::Ss, ss)
        .map_err(iret_fault)?;
    if !cpu.compat() {
        cpu.set_compat(true);
    }
    Ok(())
}

/// `sigreturn` (i386): the non-RT frame is at ESP - 8, below the
/// `pretcode` the handler's `ret` and the `sig` `__kernel_sigreturn`'s
/// `popl` removed.
pub fn sigreturn(
    cpu: &mut X86UserCpu,
    st: &mut SigreturnState<'_>,
    space: &AddressSpace,
) -> Result<(), SigreturnError> {
    let frame = cpu.vcpu().user_regs().rsp.wrapping_sub(8);
    let (Some(lo), Some(hi)) = (
        get_u32(space, frame.wrapping_add(off::SC + sc::OLDMASK as u64)),
        get_u32(space, frame.wrapping_add(off::EXTRAMASK)),
    ) else {
        return Err(x64::bad_frame());
    };
    st.set_blocked(u64::from(lo) | u64::from(hi) << 32);
    let (cs, ss) = restore_sigcontext(cpu, space, frame.wrapping_add(off::SC))?;
    iret(cpu, cs, ss)
}

/// `rt_sigreturn` (i386): the frame is at ESP - 4, below the `pretcode`
/// the handler's `ret` removed. The alternate stack is restored after the
/// registers, for the restored stack pointer.
pub fn rt_sigreturn(
    cpu: &mut X86UserCpu,
    st: &mut SigreturnState<'_>,
    space: &AddressSpace,
) -> Result<(), SigreturnError> {
    let frame = cpu.vcpu().user_regs().rsp.wrapping_sub(4);
    let Some(mask) = get_u64(space, frame.wrapping_add(rt::UC_SIGMASK)) else {
        return Err(x64::bad_frame());
    };
    st.set_blocked(mask);
    let (cs, ss) = restore_sigcontext(cpu, space, frame.wrapping_add(rt::MCONTEXT))?;
    let sp = cpu.vcpu().user_regs().rsp;
    st.restore_altstack32(space, frame.wrapping_add(rt::UC_STACK), sp)
        .map_err(|()| x64::bad_frame())?;
    iret(cpu, cs, ss)
}
