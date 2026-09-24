//! RV64 signal frames (`arch/riscv/kernel/signal.c`).
//!
//! ```text
//! frame + 0     struct siginfo           (128; always written)
//! frame + 128   struct ucontext          uc_flags, uc_link, uc_stack (24),
//!                                        uc_sigmask (8), padding to 1024 bits
//! frame + 304   struct sigcontext        sc_regs: pc, x1..x31 (256)
//! frame + 560                            sc_fpregs: f0..f31, fcsr (the D
//!                                        layout) in a 528-byte union whose
//!                                        last 12 bytes are sc_extdesc's
//!                                        reserved word (1076) and first
//!                                        extension header (1080)
//! frame + 1088  extension records        the vector state, when present
//! ```
//!
//! A handler returns through the vDSO's `__vdso_rt_sigreturn` (riscv has
//! no `SA_RESTORER`). Linux saves the vector state only once a thread has
//! used the vector unit (`riscv_v_vstate_query`); the emulated core has no
//! lazy enable, so a core configured with V always records it.

use super::super::{AltStack, SIGSEGV, SigInfo};
use super::{
    Delivery, FaultUpdate, FrameFault, SigreturnError, SigreturnState, get_u32, get_u64, put,
};
use crate::isa::riscv::cpu::VLENB;
use crate::user::cpu::riscv64::RvUserCpu;
use crate::user::mm::AddressSpace;

/// `sizeof(struct rt_sigframe)` without extension records.
pub const RT_SIGFRAME_SIZE: u64 = 1088;

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
    /// `uc.uc_mcontext.sc_regs.pc`, followed by x1..x31.
    pub const REGS: u64 = 304;
    /// `uc.uc_mcontext.sc_fpregs.d.f[0]`.
    pub const FPREGS: u64 = 560;
    /// `uc.uc_mcontext.sc_fpregs.d.fcsr`.
    pub const FCSR: u64 = 816;
    /// `uc.uc_mcontext.sc_extdesc.reserved`.
    pub const EXT_RESERVED: u64 = 1076;
    /// `uc.uc_mcontext.sc_extdesc.hdr`.
    pub const EXT_HDR: u64 = 1080;
}

/// `RISCV_V_MAGIC`.
pub const RISCV_V_MAGIC: u32 = 0x5346_5457;

/// Size of the vector record: header (8), `struct __sc_riscv_v_state`
/// (48), and the 32 vector registers (`riscv_v_sc_size`).
pub const V_RECORD_SIZE: u64 = 8 + 48 + 32 * VLENB;

fn has_fpu(cpu: &RvUserCpu) -> bool {
    let isa = &cpu.core().config().isa;
    isa.f || isa.d
}

fn has_vector(cpu: &RvUserCpu) -> bool {
    cpu.core().config().isa.v
}

/// `get_rt_frame_size`.
pub fn frame_size(cpu: &RvUserCpu) -> u64 {
    let mut size = RT_SIGFRAME_SIZE;
    if has_vector(cpu) {
        size += V_RECORD_SIZE;
    }
    size.div_ceil(16) * 16
}

/// `setup_rt_frame`.
pub fn setup_rt_frame(
    cpu: &mut RvUserCpu,
    alt: &AltStack,
    space: &AddressSpace,
    d: &Delivery,
    sigtramp: u64,
) -> Result<(), FrameFault> {
    let size = frame_size(cpu);
    // get_sigframe: a frame that would overflow the alternate stack the
    // thread is already on goes to an always-bogus address.
    let sp = cpu.core().x(2);
    if alt.on_stack(sp) && !alt.on_stack(sp.wrapping_sub(size)) {
        return Err(FrameFault);
    }
    let frame = alt.sigsp(sp, d.action.flags).wrapping_sub(size) & !0xF;
    if !space.range_ok(frame, size) {
        return Err(FrameFault);
    }
    let core = cpu.core();
    put(space, frame + off::INFO, &d.info.encode())?;
    put(space, frame + off::UC_FLAGS, &[0u8; 16])?;
    put(
        space,
        frame + off::UC_STACK,
        &AltStack::encode_stack_t(alt.sp, alt.flags, alt.size),
    )?;
    // setup_sigcontext.
    let mut regs = Vec::with_capacity(256);
    regs.extend_from_slice(&core.pc().to_le_bytes());
    for r in 1..32 {
        regs.extend_from_slice(&core.x(r).to_le_bytes());
    }
    put(space, frame + off::REGS, &regs)?;
    if has_fpu(cpu) {
        let mut fp = Vec::with_capacity(260);
        for r in 0..32 {
            fp.extend_from_slice(&core.f(r).to_le_bytes());
        }
        fp.extend_from_slice(&core.fcsr().to_le_bytes());
        put(space, frame + off::FPREGS, &fp)?;
    }
    let mut end = off::EXT_HDR;
    if has_vector(cpu) {
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&RISCV_V_MAGIC.to_le_bytes());
        hdr[4..].copy_from_slice(&(V_RECORD_SIZE as u32).to_le_bytes());
        put(space, frame + off::EXT_HDR, &hdr)?;
        let state = frame + off::EXT_HDR + 8;
        let datap = state + 48;
        let mut v = Vec::with_capacity(48);
        for w in [
            core.vstart(),
            core.vl(),
            core.vtype(),
            core.vcsr(),
            VLENB,
            datap,
        ] {
            v.extend_from_slice(&w.to_le_bytes());
        }
        put(space, state, &v)?;
        let mut regs = Vec::with_capacity(32 * VLENB as usize);
        for r in 0..32 {
            regs.extend_from_slice(&core.vreg(r));
        }
        put(space, datap, &regs)?;
        end += V_RECORD_SIZE;
    }
    put(space, frame + off::EXT_RESERVED, &[0u8; 4])?;
    put(space, frame + end, &[0u8; 8])?;
    put(space, frame + off::UC_SIGMASK, &d.saved_mask.to_le_bytes())?;

    // Registers the handler starts with; the others keep their values.
    let core = cpu.core_mut();
    core.set_x(1, sigtramp);
    core.set_pc(d.action.handler);
    core.set_x(2, frame);
    core.set_x(10, d.sig as u64);
    core.set_x(11, frame + off::INFO);
    core.set_x(12, frame + off::UC);
    Ok(())
}

/// The `SIGSEGV` riscv's `badframe` path forces (`force_sig`).
fn bad_frame() -> SigreturnError {
    SigreturnError::Bad(super::BadFrame {
        info: SigInfo::kernel(SIGSEGV),
        fault: FaultUpdate::None,
    })
}

/// `restore_sigcontext`; registers are loaded before the extension checks,
/// as in the kernel.
fn restore_sigcontext(cpu: &mut RvUserCpu, space: &AddressSpace, frame: u64) -> Option<()> {
    let mut regs = [0u8; 256];
    space.read(frame + off::REGS, &mut regs).ok()?;
    let w = |i: usize| u64::from_le_bytes(regs[i * 8..i * 8 + 8].try_into().unwrap());
    let core = cpu.core_mut();
    core.set_pc(w(0));
    for r in 1..32 {
        core.set_x(r, w(r as usize));
    }
    if has_fpu(cpu) {
        let mut fp = [0u8; 260];
        space.read(frame + off::FPREGS, &mut fp).ok()?;
        let core = cpu.core_mut();
        for r in 0..32 {
            let at = r * 8;
            core.set_f(
                r as u8,
                u64::from_le_bytes(fp[at..at + 8].try_into().unwrap()),
            );
        }
        core.set_fcsr(u32::from_le_bytes(fp[256..260].try_into().unwrap()));
    }
    if get_u32(space, frame + off::EXT_RESERVED)? != 0 {
        return None;
    }
    let mut head = frame + off::EXT_HDR;
    loop {
        let magic = get_u32(space, head)?;
        let size = u64::from(get_u32(space, head + 4)?);
        match magic {
            0 => return (size == 0).then_some(()),
            RISCV_V_MAGIC if has_vector(cpu) && size == V_RECORD_SIZE => {
                let state = head + 8;
                let w = |i: u64| get_u64(space, state + 8 * i);
                let (vstart, vl, vtype, vcsr) = (w(0)?, w(1)?, w(2)?, w(3)?);
                let datap = w(5)?;
                let mut regs = vec![0u8; 32 * VLENB as usize];
                space.read(datap, &mut regs).ok()?;
                let core = cpu.core_mut();
                core.set_vstart(vstart);
                core.set_vl_vtype(vl, vtype);
                core.set_vcsr(vcsr);
                for (r, chunk) in regs.chunks_exact(VLENB as usize).enumerate() {
                    core.set_vreg(r as u8, chunk.try_into().unwrap());
                }
            }
            _ => return None,
        }
        head += size;
    }
}

/// `rt_sigreturn` (RV64). The frame is at sp.
pub fn rt_sigreturn(
    cpu: &mut RvUserCpu,
    st: &mut SigreturnState<'_>,
    space: &AddressSpace,
) -> Result<(), SigreturnError> {
    let frame = cpu.core().x(2);
    if !space.range_ok(frame, frame_size(cpu)) {
        return Err(bad_frame());
    }
    let mask = get_u64(space, frame + off::UC_SIGMASK).ok_or_else(bad_frame)?;
    st.set_blocked(mask);
    restore_sigcontext(cpu, space, frame).ok_or_else(bad_frame)?;
    let sp = cpu.core().x(2);
    st.restore_altstack(space, frame + off::UC_STACK, sp)
        .map_err(|()| bad_frame())?;
    Ok(())
}
