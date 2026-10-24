//! arm64e's opaque thread-state pointer representation.

use super::{ARM_THREAD_STATE64_SIZE, arm64_thread_state, get32, get64, put32, put64};
use crate::isa::arm::aarch64::pauth::PauthKeyKind;
use crate::user::cpu::aarch64::A64UserCpu;
use crate::user::darwin::pauth::{
    FP_DISCRIMINATOR, LR_DISCRIMINATOR, PC_DISCRIMINATOR, SP_DISCRIMINATOR, UserPauth, blend,
};

pub(crate) const NO_PTRAUTH: u32 = 1;
pub(crate) const IB_SIGNED_LR: u32 = 2;
pub(crate) const KERNEL_SIGNED_PC: u32 = 4;
pub(crate) const KERNEL_SIGNED_LR: u32 = 8;
pub(crate) const USER_DIVERSIFIER_MASK: u32 = 0xff00_0000;

/// Convert a raw saved state to the representation exported by XNU.
pub(crate) fn to_user(
    cpu: &A64UserCpu,
    ptrauth: bool,
    diversifier: u32,
) -> [u8; ARM_THREAD_STATE64_SIZE] {
    if !ptrauth {
        return arm64_thread_state(cpu, NO_PTRAUTH);
    }
    let auth = UserPauth::from_cpu(cpu);
    let mut state = arm64_thread_state(cpu, 0);
    let mut flags = KERNEL_SIGNED_PC | KERNEL_SIGNED_LR | (diversifier & USER_DIVERSIFIER_MASK);
    let lr = get64(&state, 240);
    if lr != auth.strip(lr, PauthKeyKind::Ib) {
        flags |= IB_SIGNED_LR;
    }
    for (offset, kind, discriminator) in [
        (256, PauthKeyKind::Ia, PC_DISCRIMINATOR),
        (240, PauthKeyKind::Ia, LR_DISCRIMINATOR),
        (248, PauthKeyKind::Da, SP_DISCRIMINATOR),
        (232, PauthKeyKind::Da, FP_DISCRIMINATOR),
    ] {
        let value = get64(&state, offset);
        if value != 0 && !(offset == 240 && flags & IB_SIGNED_LR != 0) {
            put64(&mut state, offset, auth.sign(value, kind, discriminator));
        }
    }
    put32(&mut state, 268, flags);
    state
}

/// Convert user pointers before installing registers. Kernel pmap authentication
/// poisons bad pointers and does not inject a guest AUT instruction exception.
/// `diversifier` comes from trusted thread state for sigreturn, or zero for the
/// ordinary Mach thread_set_state contract; supplied flag bits cannot select it.
pub(crate) fn from_user(
    cpu: &A64UserCpu,
    state: &[u8],
    diversifier: u32,
) -> Option<[u8; ARM_THREAD_STATE64_SIZE]> {
    let mut result: [u8; ARM_THREAD_STATE64_SIZE] = state.try_into().ok()?;
    let auth = UserPauth::from_cpu(cpu);
    if !auth.enabled() {
        return Some(result);
    }
    // NO_PTRAUTH cannot bypass authentication on a JOP-enabled task.
    let flags = get32(&result, 268) & !NO_PTRAUTH;
    let lr = get64(&result, 240);
    let preserve_lr = flags & IB_SIGNED_LR != 0 && lr != auth.strip(lr, PauthKeyKind::Ib);
    let user_diversifier = u64::from(diversifier & USER_DIVERSIFIER_MASK);
    for (offset, kind, discriminator, kernel_flag) in [
        (256, PauthKeyKind::Ia, PC_DISCRIMINATOR, KERNEL_SIGNED_PC),
        (240, PauthKeyKind::Ia, LR_DISCRIMINATOR, KERNEL_SIGNED_LR),
        (248, PauthKeyKind::Da, SP_DISCRIMINATOR, 0),
        (232, PauthKeyKind::Da, FP_DISCRIMINATOR, 0),
    ] {
        let value = get64(&result, offset);
        if value == 0 || (offset == 240 && preserve_lr) {
            continue;
        }
        let modifier = if kernel_flag != 0 && flags & kernel_flag == 0 && user_diversifier != 0 {
            blend(user_diversifier, discriminator as u16)
        } else {
            discriminator
        };
        put64(
            &mut result,
            offset,
            auth.authenticate(value, kind, modifier),
        );
    }
    Some(result)
}
