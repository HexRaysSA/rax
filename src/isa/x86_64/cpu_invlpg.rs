//! Direct and helper-backed INVLPG translation-cache invalidation.

use super::X86_64Vcpu;

impl X86_64Vcpu {
    /// Read one complete 128-bit INVPCID descriptor. The logical verifier
    /// trace uses two adjacent 64-bit reads, while the MMU observes one
    /// all-or-fault byte-buffer operation.
    pub(in crate::isa::x86_64) fn read_invpcid_descriptor(
        &mut self,
        addr: u64,
    ) -> crate::error::Result<(u64, u64)> {
        let mut payload = [0_u8; 16];
        self.mmu.read(addr, &mut payload, &self.sregs)?;
        let low = u64::from_le_bytes(payload[..8].try_into().unwrap());
        let linear = u64::from_le_bytes(payload[8..].try_into().unwrap());
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            self.push_jit_mem_trace((0, addr, 8, low));
            self.push_jit_mem_trace((0, addr.wrapping_add(8), 8, linear));
        }
        Ok((low, linear))
    }

    /// Apply one architectural INVLPG invalidation to every translation-
    /// dependent software cache. The MMU may conservatively flush more than the
    /// named page, so decode/JIT caches follow the same full-flush policy; this
    /// also covers large-page aliases whose extent cannot be recovered after a
    /// page-table entry changes. Callers must already have handled the 64-bit
    /// non-canonical-address no-op rule.
    pub(in crate::isa::x86_64) fn invalidate_linear_translation(&mut self, addr: u64) {
        self.mmu.invlpg(addr);
        self.invalidate_translation_dependent_caches();
    }

    /// Apply one validated INVPCID request. RAX does not currently retain
    /// PCID or global-translation distinctions, so every defined type uses the
    /// architecturally permitted conservative full-flush policy.
    pub(in crate::isa::x86_64) fn invalidate_process_context(
        &mut self,
        _invpcid_type: u64,
        _pcid: u16,
        linear: u64,
    ) {
        self.mmu.invlpg(linear);
        self.invalidate_translation_dependent_caches();
    }

    pub(in crate::isa::x86_64) fn invalidate_translation_dependent_caches(&mut self) {
        self.decode_cache.iter_mut().for_each(|entry| {
            entry.rip = 0;
            entry.bytes_len = 0;
        });
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.jit_cache.clear();
            self.jit_hot.clear();
            self.jit_ineligible.clear();
            self.jit_ineligible_dirty.clear();
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use crate::isa::x86_64::execute::system::is_canonical_48;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use crate::smir::lower::runtime::GuestRegs;

/// Validate and apply one native INVLPG operation.
///
/// The helper returns zero without changing any cache when APX is unavailable,
/// the runtime state is not 64-bit mode, or effective CPL is nonzero. A
/// non-canonical 64-bit address succeeds without invalidating anything, as
/// required by the architectural NOP rule.
///
/// # Safety
///
/// `state` must reference the live [`GuestRegs`] image for the owning
/// [`X86_64Vcpu`], and `state.ctx` must contain that vCPU's valid address.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
pub(super) unsafe extern "C" fn rax_jit_invlpg(
    state: *mut GuestRegs,
    addr: u64,
    requires_apx: u64,
) -> u64 {
    if requires_apx > 1 {
        return 0;
    }
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    if (requires_apx != 0 && state.apx_enabled == 0) || state.cs_l == 0 || state.cpl != 0 {
        return 0;
    }
    if !is_canonical_48(addr) {
        return 1;
    }
    let Some(vcpu) = (unsafe { (state.ctx as *mut X86_64Vcpu).as_mut() }) else {
        return 0;
    };
    vcpu.invalidate_linear_translation(addr);
    1
}

/// Validate, read, and apply one native INVPCID operation.
///
/// Returning zero requests exact direct replay before any translation cache is
/// changed. The helper therefore treats malformed ABI inputs, mode/privilege
/// mismatches, noncanonical source ranges, descriptor faults, and descriptor
/// validation failures uniformly as non-committing failures.
///
/// # Safety
///
/// `state` must reference the live [`GuestRegs`] image for the owning
/// [`X86_64Vcpu`], and `state.ctx` must contain that vCPU's valid address.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
pub(super) unsafe extern "C" fn rax_jit_invpcid(
    state: *mut GuestRegs,
    addr: u64,
    invpcid_type: u64,
    requires_apx: u64,
) -> u64 {
    if requires_apx > 1 {
        return 0;
    }
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    if (requires_apx != 0 && state.apx_enabled == 0) || state.cs_l == 0 || state.cpl != 0 {
        return 0;
    }
    if !addr
        .checked_add(15)
        .is_some_and(|last| is_canonical_48(addr) && is_canonical_48(last))
    {
        return 0;
    }
    let Some(vcpu) = (unsafe { (state.ctx as *mut X86_64Vcpu).as_mut() }) else {
        return 0;
    };
    // A zero return replays the instruction at its original guest PC. Any
    // speculative descriptor trace must therefore roll back with the helper;
    // the eventual direct execution owns the architecturally observed read.
    let saved_trace = vcpu.jit_mem_trace.clone();
    let Ok((descriptor_low, descriptor_linear)) = vcpu.read_invpcid_descriptor(addr) else {
        vcpu.jit_mem_trace = saved_trace;
        return 0;
    };
    let Ok(descriptor) = crate::isa::x86_64::execute::system::validate_x86_invpcid(
        invpcid_type,
        descriptor_low,
        descriptor_linear,
        state.cr4,
    ) else {
        vcpu.jit_mem_trace = saved_trace;
        return 0;
    };
    vcpu.invalidate_process_context(invpcid_type, descriptor.pcid, descriptor.linear);
    1
}
