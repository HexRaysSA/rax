//! Darwin task key domains and kernel-produced user pointers.
//!
//! XNU 12377.121.6 `machine_thread_state_convert_{to,from}_user`,
//! `thread_generate_sigreturn_token`, `ml_poison_ptr`, and shared-region v5
//! rebasing define the ABI. RAX uses its architected QARMA implementation;
//! Apple's private hardware key-diversification algorithm is not reproduced.

use super::arch::DarwinCpu;
use super::process::Entropy;
use crate::isa::arm::aarch64::pauth::{
    PauthConfig, PauthControls, PauthFailure, PauthKey, PauthKeyKind, PauthKeys,
};
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::cpu::aarch64::A64UserCpu;

#[cfg(test)]
pub(crate) mod tests;

// Clang's __builtin_ptrauth_string_discriminator, checked for the arm64e target.
pub(super) const PC_DISCRIMINATOR: u64 = 0x7481;
pub(super) const LR_DISCRIMINATOR: u64 = 0x77d3;
pub(super) const SP_DISCRIMINATOR: u64 = 0xcbed;
pub(super) const FP_DISCRIMINATOR: u64 = 0x4517;
const NONCE_DISCRIMINATOR: u64 = 0xb743;
const UCTX_DISCRIMINATOR: u64 = 0xd4a6;

/// `ptrauth_blend_discriminator`: replace the address's high 16 bits.
pub(super) fn blend(address: u64, diversity: u16) -> u64 {
    (address & 0x0000_ffff_ffff_ffff) | (u64::from(diversity) << 48)
}

/// Whether this image selects XNU's arm64e pointer-authentication ABI.
pub(super) fn uses_abi(cpusubtype: u32) -> bool {
    use crate::user::image::macho::{
        CPU_SUBTYPE_ARM64_PTR_AUTH_MASK, CPU_SUBTYPE_ARM64_PTR_AUTH_MAX_PREFERRED_VERSION,
        CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK,
    };
    // kern_exec.c: arm64_cpusubtype_uses_ptrauth. The versioned-ABI
    // capability bit is not an additional requirement for JOP enablement.
    cpusubtype & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E
        && (cpusubtype & CPU_SUBTYPE_ARM64_PTR_AUTH_MASK) >> 24
            <= CPU_SUBTYPE_ARM64_PTR_AUTH_MAX_PREFERRED_VERSION
}

/// Immutable per-exec keys, inherited by every thread and by `fork`.
/// The personality owns a private shared region, so its A-key domain is also
/// private. A later exec generates a fresh domain from the advanced entropy.
#[derive(Clone)]
pub(crate) struct TaskPauth {
    keys: PauthKeys,
    jop: bool,
}

impl TaskPauth {
    pub(super) fn new(entropy: &mut Entropy, jop: bool) -> std::io::Result<Self> {
        let mut bytes = [0u8; 80];
        entropy.try_fill(&mut bytes)?;
        let mut key = bytes.chunks_exact(16).map(|bytes| PauthKey {
            lo: u64::from_le_bytes(bytes[..8].try_into().expect("8-byte key half")),
            hi: u64::from_le_bytes(bytes[8..].try_into().expect("8-byte key half")),
        });
        // The fixed 80-byte input contains precisely five 128-bit keys.
        Ok(Self {
            keys: PauthKeys {
                ia: key.next().expect("IA key"),
                ib: key.next().expect("IB key"),
                da: key.next().expect("DA key"),
                db: key.next().expect("DB key"),
                ga: key.next().expect("GA key"),
            },
            jop,
        })
    }

    pub(super) fn install(&self, cpu: &mut DarwinCpu) {
        let DarwinCpu::Arm64(cpu) = cpu else {
            return;
        };
        let core = cpu.core_mut();
        core.set_pauth_keys(self.keys);
        let mut controls = core.pauth_controls();
        // User personality execution has no EL2/EL3 monitor handling PAC use.
        controls.hcr_el2 |= (1 << 40) | (1 << 41);
        controls.scr_el3 |= (1 << 16) | (1 << 17);
        // B keys implement return-address signing. A keys follow NOJOP.
        controls.sctlr[1] |= (1 << 13) | (1 << 30);
        let a_keys = (1 << 31) | (1 << 27);
        if self.jop {
            controls.sctlr[1] |= a_keys;
        } else {
            controls.sctlr[1] &= !a_keys;
        }
        core.set_pauth_controls(controls)
            .expect("only writable EL1 key-enable bits changed");
    }
}

/// A snapshot for kernel ABI conversion or a demand-paged shared-cache source.
/// It contains guest keys only; it never uses the host's PAC instructions.
#[derive(Clone, Copy)]
pub(crate) struct UserPauth {
    config: PauthConfig,
    controls: PauthControls,
    keys: PauthKeys,
}

impl UserPauth {
    pub(super) fn from_cpu(cpu: &A64UserCpu) -> Self {
        let core = cpu.core();
        Self {
            config: core.config().pauth,
            controls: core.pauth_controls(),
            keys: core.pauth_keys(),
        }
    }

    pub(super) fn enabled(self) -> bool {
        self.controls.key_enabled(PauthKeyKind::Ia) == Ok(true)
    }

    pub(super) fn sign(self, pointer: u64, kind: PauthKeyKind, modifier: u64) -> u64 {
        self.controls.layout(pointer, kind.data()).sign(
            self.config.algorithm,
            self.config.profile,
            pointer,
            modifier,
            self.keys.get(kind),
        )
    }

    pub(super) fn strip(self, pointer: u64, kind: PauthKeyKind) -> u64 {
        self.controls.layout(pointer, kind.data()).strip(pointer)
    }

    /// XNU's pmap ABI returns a poisoned pointer on failure, including when
    /// the guest instruction profile would raise an immediate FPAC exception.
    pub(super) fn authenticate(self, pointer: u64, kind: PauthKeyKind, modifier: u64) -> u64 {
        let layout = self.controls.layout(pointer, kind.data());
        let result = layout.authenticate(
            self.config.algorithm,
            self.config.profile,
            pointer,
            modifier,
            self.keys.get(kind),
            PauthFailure {
                data: kind.data(),
                key_b: kind.key_b(),
            },
            false,
        );
        if result == Ok(layout.strip(pointer)) {
            return layout.strip(pointer);
        }
        // ml_poison_ptr preserves the input PAC outside the two poison bits.
        let tbi = kind.data() && pointer & (1 << 55) == 0;
        let shift = if tbi { 53 } else { 61 };
        let code = if kind.key_b() { 2 } else { 1 };
        (pointer & !(3 << shift)) | (code << shift)
    }

    pub(super) fn pointer_token(self, pointer: u64, secret: u64) -> u32 {
        (self.sign(pointer ^ secret, PauthKeyKind::Da, NONCE_DISCRIMINATOR) >> 32) as u32
    }

    pub(super) fn ucontext_token(self, pointer: u64, secret: u64) -> u64 {
        let signed = if self.enabled() && pointer != 0 {
            self.sign(pointer, PauthKeyKind::Da, UCTX_DISCRIMINATOR)
        } else {
            pointer
        };
        signed ^ secret
    }

    pub(super) fn function_pointer(self, pointer: u64) -> u64 {
        if !self.enabled() || pointer == 0 {
            pointer
        } else {
            self.authenticate(pointer, PauthKeyKind::Ia, 0)
        }
    }
}
