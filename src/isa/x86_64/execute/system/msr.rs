//! MSR instructions: RDMSR, WRMSR.

use crate::error::Result;
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::vm::vcpu::VcpuExit;

use super::control_regs::{is_cpl0, raise_gp0};

pub(crate) const IA32_TSC: u32 = 0x10;
pub(crate) const IA32_PLATFORM_ID: u32 = 0x17;
pub(crate) const IA32_APIC_BASE: u32 = 0x1B;
pub(crate) const IA32_TSC_ADJUST: u32 = 0x3B;
pub(crate) const IA32_BIOS_SIGN_ID: u32 = 0x8B;
pub(crate) const IA32_UMWAIT_CONTROL: u32 = 0xE1;
pub(crate) const IA32_SYSENTER_CS: u32 = 0x174;
pub(crate) const IA32_SYSENTER_ESP: u32 = 0x175;
pub(crate) const IA32_SYSENTER_EIP: u32 = 0x176;
pub(crate) const IA32_MISC_ENABLE: u32 = 0x1A0;
pub(crate) const IA32_PAT: u32 = 0x277;
pub(crate) const IA32_TSC_DEADLINE: u32 = 0x6E0;
pub(crate) const IA32_XSS: u32 = 0xDA0;
pub(crate) const IA32_EFER: u32 = 0xC000_0080;
pub(crate) const IA32_STAR: u32 = 0xC000_0081;
pub(crate) const IA32_LSTAR: u32 = 0xC000_0082;
pub(crate) const IA32_CSTAR: u32 = 0xC000_0083;
pub(crate) const IA32_FMASK: u32 = 0xC000_0084;
pub(crate) const IA32_FS_BASE: u32 = 0xC000_0100;
pub(crate) const IA32_GS_BASE: u32 = 0xC000_0101;
pub(crate) const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub(crate) const IA32_TSC_AUX: u32 = 0xC000_0103;

const CR0_PE: u64 = 1 << 0;
const CR0_PG: u64 = 1 << 31;
const EFER_SCE: u64 = 1 << 0;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const EFER_NXE: u64 = 1 << 11;
const EFER_WRITABLE: u64 = EFER_SCE | EFER_LME | EFER_NXE;
const EFER_DEFINED: u64 = EFER_WRITABLE | EFER_LMA;

// The deterministic Intel family-6 profile has no architectural PMU, BTS, or
// PEBS state, so the two corresponding IA32_MISC_ENABLE availability bits are
// read-only one. MONITOR/MWAIT and fast strings are implemented and enabled at
// reset. The register remains fixed until each writable bit is wired to its
// owning execution and CPUID behavior; accepting inert writes would expose a
// dishonest model-specific profile.
const MISC_ENABLE_FAST_STRING: u64 = 1 << 0;
const MISC_ENABLE_BTS_UNAVAILABLE: u64 = 1 << 11;
const MISC_ENABLE_PEBS_UNAVAILABLE: u64 = 1 << 12;
const MISC_ENABLE_MONITOR: u64 = 1 << 18;
const MISC_ENABLE_READ_ONLY: u64 = MISC_ENABLE_BTS_UNAVAILABLE | MISC_ENABLE_PEBS_UNAVAILABLE;
pub(crate) const IA32_MISC_ENABLE_RESET: u64 =
    MISC_ENABLE_FAST_STRING | MISC_ENABLE_READ_ONLY | MISC_ENABLE_MONITOR;

/// Architectural IA32_PAT reset image: WB, WT, UC-, UC repeated twice.
pub(crate) const IA32_PAT_RESET: u64 = 0x0007_0406_0007_0406;

/// IA32_UMWAIT_CONTROL defines bit 0 (C0.2 disable) and bits 31:2 (maximum
/// time). Bit 1 and the high 32 bits are reserved.
const UMWAIT_CONTROL_RESERVED: u64 = (1 << 1) | 0xFFFF_FFFF_0000_0000;

/// Architectural MSR state shared by direct execution, standalone SMIR
/// interpretation, and helper-backed native execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86MsrState {
    pub apic_base: u64,
    pub cr0: u64,
    pub tsc_adjust: u64,
    pub tsc_aux: u32,
    pub efer: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub fmask: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub misc_enable: u64,
    pub pat: u64,
    pub umwait_control: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
}

impl Default for X86MsrState {
    fn default() -> Self {
        Self {
            apic_base: crate::isa::x86_64::identity::initial_apic_base(0),
            cr0: 0,
            tsc_adjust: 0,
            tsc_aux: 0,
            efer: 0,
            star: 0,
            lstar: 0,
            cstar: 0,
            fmask: 0,
            sysenter_cs: 0,
            sysenter_esp: 0,
            sysenter_eip: 0,
            misc_enable: IA32_MISC_ENABLE_RESET,
            pat: IA32_PAT_RESET,
            umwait_control: 0,
            fs_base: 0,
            gs_base: 0,
            kernel_gs_base: 0,
        }
    }
}

/// Fully validated result of one WRMSR. Validation is pure and completes
/// before any caller-visible state is committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86MsrWriteEffect {
    pub state: X86MsrState,
    /// WRMSR is serializing except for IA32_TSC_DEADLINE and x2APIC MSRs. The
    /// deterministic profile exposes no x2APIC MSRs.
    pub serializing: bool,
    /// Invalidate cached translations when a translation-relevant EFER bit
    /// changes. Validation remains non-committing; callers apply this effect
    /// only after the complete WRMSR candidate has been accepted.
    pub flush_tlb: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86MsrFault {
    GeneralProtection,
}

#[inline]
pub(crate) fn is_canonical_48(value: u64) -> bool {
    let upper = value >> 48;
    upper == if value & (1 << 47) != 0 { 0xFFFF } else { 0 }
}

/// IA32_PAT contains eight independent eight-bit memory-type fields. Bits
/// 7:3 of each field are reserved, and encodings 2 and 3 are reserved.
#[inline]
pub(crate) fn is_valid_pat(value: u64) -> bool {
    (0..8).all(|index| {
        let entry = ((value >> (index * 8)) & 0xFF) as u8;
        entry & !0x07 == 0 && entry != 2 && entry != 3
    })
}

/// Read one implemented MSR. `tsc` is the caller's current architectural TSC,
/// including IA32_TSC_ADJUST.
pub(crate) fn read_x86_msr(
    index: u32,
    state: X86MsrState,
    tsc: u64,
) -> core::result::Result<u64, X86MsrFault> {
    let value = match index {
        IA32_TSC => tsc,
        // Platform zero is the sole microcode platform in this virtual CPU.
        IA32_PLATFORM_ID => 0,
        IA32_APIC_BASE => state.apic_base,
        IA32_TSC_ADJUST => state.tsc_adjust,
        // The deterministic profile has no updatable microcode image. Intel's
        // discovery sequence writes zero, executes CPUID, then reads this MSR;
        // a zero signature accurately reports that no revision is installed.
        IA32_BIOS_SIGN_ID => 0,
        IA32_UMWAIT_CONTROL => state.umwait_control,
        IA32_SYSENTER_CS => state.sysenter_cs,
        IA32_SYSENTER_ESP => state.sysenter_esp,
        IA32_SYSENTER_EIP => state.sysenter_eip,
        IA32_MISC_ENABLE => state.misc_enable,
        IA32_PAT => state.pat,
        // The base profile does not latch a deadline because it does not expose
        // LAPIC deadline mode. Retaining the established zero value keeps the
        // hidden compatibility MSR deterministic.
        IA32_TSC_DEADLINE => 0,
        // CPUID.(EAX=0DH,ECX=1):ECX:EDX exposes no supervisor components.
        IA32_XSS => 0,
        IA32_EFER => state.efer,
        IA32_STAR => state.star,
        IA32_LSTAR => state.lstar,
        IA32_CSTAR => state.cstar,
        IA32_FMASK => state.fmask,
        IA32_FS_BASE => state.fs_base,
        IA32_GS_BASE => state.gs_base,
        IA32_KERNEL_GS_BASE => state.kernel_gs_base,
        IA32_TSC_AUX => u64::from(state.tsc_aux),
        _ => return Err(X86MsrFault::GeneralProtection),
    };
    Ok(value)
}

/// Validate and normalize one WRMSR candidate. `tsc` is the current
/// architectural TSC, including the old IA32_TSC_ADJUST value.
pub(crate) fn validate_x86_msr_write(
    index: u32,
    value: u64,
    mut state: X86MsrState,
    tsc: u64,
) -> core::result::Result<X86MsrWriteEffect, X86MsrFault> {
    let gp = || Err(X86MsrFault::GeneralProtection);
    let mut flush_tlb = false;

    match index {
        IA32_TSC => {
            // Writing IA32_TSC changes the local offset without changing the
            // invariant clock source: new_adjust = old_adjust + (value-old_tsc).
            state.tsc_adjust = state.tsc_adjust.wrapping_add(value.wrapping_sub(tsc));
        }
        IA32_PLATFORM_ID => return gp(),
        IA32_APIC_BASE => {
            if !crate::isa::x86_64::identity::valid_apic_base(value) {
                return gp();
            }
            state.apic_base = value;
        }
        IA32_TSC_ADJUST => state.tsc_adjust = value,
        IA32_BIOS_SIGN_ID => {
            // Software clears the latch before CPUID. Non-zero writes are not
            // part of the architectural discovery protocol and remain #GP.
            if value != 0 {
                return gp();
            }
        }
        IA32_UMWAIT_CONTROL => {
            if value & UMWAIT_CONTROL_RESERVED != 0 {
                return gp();
            }
            state.umwait_control = value;
        }
        IA32_SYSENTER_CS => {
            if value >> 32 != 0 {
                return gp();
            }
            state.sysenter_cs = value;
        }
        IA32_SYSENTER_ESP => {
            if !is_canonical_48(value) {
                return gp();
            }
            state.sysenter_esp = value;
        }
        IA32_SYSENTER_EIP => {
            if !is_canonical_48(value) {
                return gp();
            }
            state.sysenter_eip = value;
        }
        IA32_MISC_ENABLE => {
            if value != state.misc_enable {
                return gp();
            }
        }
        IA32_PAT => {
            if !is_valid_pat(value) {
                return gp();
            }
            flush_tlb = value != state.pat;
            state.pat = value;
        }
        IA32_TSC_DEADLINE => {
            // Compatibility MSR: accepted but intentionally not latched.
        }
        IA32_XSS => {
            if value != 0 {
                return gp();
            }
        }
        IA32_EFER => {
            if value & !EFER_DEFINED != 0 {
                return gp();
            }
            if state.cr0 & CR0_PG != 0 && (value ^ state.efer) & EFER_LME != 0 {
                return gp();
            }
            // LMA is processor-maintained and ignores software writes. This
            // permits the standard read/modify/write sequence while active.
            let normalized = (value & EFER_WRITABLE) | (state.efer & EFER_LMA);
            flush_tlb = (normalized ^ state.efer) & (EFER_LME | EFER_NXE) != 0;
            state.efer = normalized;
        }
        IA32_STAR => state.star = value,
        IA32_LSTAR => {
            if !is_canonical_48(value) {
                return gp();
            }
            state.lstar = value;
        }
        IA32_CSTAR => state.cstar = value,
        IA32_FMASK => {
            if value >> 32 != 0 {
                return gp();
            }
            state.fmask = value;
        }
        IA32_FS_BASE => {
            if !is_canonical_48(value) {
                return gp();
            }
            state.fs_base = value;
        }
        IA32_GS_BASE => {
            if !is_canonical_48(value) {
                return gp();
            }
            state.gs_base = value;
        }
        IA32_KERNEL_GS_BASE => {
            if !is_canonical_48(value) {
                return gp();
            }
            state.kernel_gs_base = value;
        }
        IA32_TSC_AUX => {
            if value >> 32 != 0 {
                return gp();
            }
            state.tsc_aux = value as u32;
        }
        _ => return gp(),
    }

    Ok(X86MsrWriteEffect {
        state,
        serializing: index != IA32_TSC_DEADLINE,
        flush_tlb,
    })
}

fn vcpu_msr_state(vcpu: &X86_64Vcpu) -> X86MsrState {
    X86MsrState {
        apic_base: vcpu.apic_base,
        cr0: vcpu.sregs.cr0,
        tsc_adjust: vcpu.tsc_adjust,
        tsc_aux: vcpu.tsc_aux,
        efer: vcpu.sregs.efer,
        star: vcpu.sregs.star,
        lstar: vcpu.sregs.lstar,
        cstar: vcpu.sregs.cstar,
        fmask: vcpu.sregs.fmask,
        sysenter_cs: vcpu.sregs.sysenter_cs,
        sysenter_esp: vcpu.sregs.sysenter_esp,
        sysenter_eip: vcpu.sregs.sysenter_eip,
        misc_enable: vcpu.misc_enable,
        pat: vcpu.pat,
        umwait_control: vcpu.umwait_control,
        fs_base: vcpu.sregs.fs.base,
        gs_base: vcpu.sregs.gs.base,
        kernel_gs_base: vcpu.kernel_gs_base,
    }
}

fn commit_vcpu_msr_state(vcpu: &mut X86_64Vcpu, state: X86MsrState) {
    vcpu.apic_base = state.apic_base;
    vcpu.tsc_adjust = state.tsc_adjust;
    vcpu.tsc_aux = state.tsc_aux;
    vcpu.sregs.efer = state.efer;
    vcpu.sregs.star = state.star;
    vcpu.sregs.lstar = state.lstar;
    vcpu.sregs.cstar = state.cstar;
    vcpu.sregs.fmask = state.fmask;
    vcpu.sregs.sysenter_cs = state.sysenter_cs;
    vcpu.sregs.sysenter_esp = state.sysenter_esp;
    vcpu.sregs.sysenter_eip = state.sysenter_eip;
    vcpu.misc_enable = state.misc_enable;
    vcpu.pat = state.pat;
    vcpu.umwait_control = state.umwait_control;
    vcpu.sregs.fs.base = state.fs_base;
    vcpu.sregs.gs.base = state.gs_base;
    vcpu.kernel_gs_base = state.kernel_gs_base;
}

#[inline]
fn msr_access_allowed(vcpu: &X86_64Vcpu) -> bool {
    vcpu.sregs.cr0 & CR0_PE == 0 || is_cpl0(vcpu)
}

/// WRMSR (`0F 30`).
pub fn wrmsr(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    if !msr_access_allowed(vcpu) {
        return raise_gp0(vcpu);
    }
    let index = vcpu.regs.rcx as u32;
    let value =
        ((vcpu.regs.rdx & u64::from(u32::MAX)) << 32) | (vcpu.regs.rax & u64::from(u32::MAX));
    let tsc = vcpu.tsc();
    let effect = match validate_x86_msr_write(index, value, vcpu_msr_state(vcpu), tsc) {
        Ok(effect) => effect,
        Err(X86MsrFault::GeneralProtection) => return raise_gp0(vcpu),
    };

    commit_vcpu_msr_state(vcpu, effect.state);
    if effect.flush_tlb {
        vcpu.mmu.flush_tlb();
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// RDMSR (`0F 32`).
pub fn rdmsr(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    if !msr_access_allowed(vcpu) {
        return raise_gp0(vcpu);
    }
    let index = vcpu.regs.rcx as u32;
    let value = match read_x86_msr(index, vcpu_msr_state(vcpu), vcpu.tsc()) {
        Ok(value) => value,
        Err(X86MsrFault::GeneralProtection) => return raise_gp0(vcpu),
    };

    vcpu.regs.rax = u64::from(value as u32);
    vcpu.regs.rdx = u64::from((value >> 32) as u32);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_48_boundaries_are_exact() {
        for value in [0, 0x0000_7FFF_FFFF_FFFF, 0xFFFF_8000_0000_0000, u64::MAX] {
            assert!(is_canonical_48(value), "{value:#018x}");
        }
        for value in [0x0000_8000_0000_0000, 0xFFFF_7FFF_FFFF_FFFF] {
            assert!(!is_canonical_48(value), "{value:#018x}");
        }
    }

    #[test]
    fn efer_writes_preserve_lma_and_reject_reserved_or_live_lme_changes() {
        let state = X86MsrState {
            cr0: CR0_PG,
            efer: EFER_LME | EFER_LMA | EFER_NXE,
            ..Default::default()
        };
        let effect = validate_x86_msr_write(
            IA32_EFER,
            EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE,
            state,
            0,
        )
        .unwrap();
        assert_eq!(effect.state.efer, EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE);
        assert!(!effect.flush_tlb, "SCE alone does not affect translation");
        let nxe_effect = validate_x86_msr_write(IA32_EFER, EFER_LME | EFER_LMA, state, 0).unwrap();
        assert!(nxe_effect.flush_tlb, "NXE changes invalidate translations");
        assert_eq!(
            validate_x86_msr_write(IA32_EFER, EFER_SCE | EFER_NXE, state, 0),
            Err(X86MsrFault::GeneralProtection)
        );
        assert_eq!(
            validate_x86_msr_write(IA32_EFER, state.efer | (1 << 12), state, 0),
            Err(X86MsrFault::GeneralProtection)
        );
    }

    #[test]
    fn unknown_and_noncanonical_msr_accesses_fault_without_state() {
        let state = X86MsrState {
            fs_base: 0x1234,
            ..Default::default()
        };
        assert_eq!(
            read_x86_msr(0xDEAD_BEEF, state, 0),
            Err(X86MsrFault::GeneralProtection)
        );
        assert_eq!(
            validate_x86_msr_write(IA32_FS_BASE, 0x0000_8000_0000_0000, state, 0),
            Err(X86MsrFault::GeneralProtection)
        );
        assert_eq!(state.fs_base, 0x1234);
    }

    #[test]
    fn misc_enable_reset_and_read_only_profile_bits_are_exact() {
        let state = X86MsrState::default();
        assert_eq!(
            read_x86_msr(IA32_MISC_ENABLE, state, 0),
            Ok(IA32_MISC_ENABLE_RESET)
        );

        let effect = validate_x86_msr_write(IA32_MISC_ENABLE, state.misc_enable, state, 0).unwrap();
        assert_eq!(effect.state.misc_enable, state.misc_enable);
        assert!(!effect.flush_tlb);

        for fixed_bit in [
            MISC_ENABLE_FAST_STRING,
            MISC_ENABLE_BTS_UNAVAILABLE,
            MISC_ENABLE_PEBS_UNAVAILABLE,
            MISC_ENABLE_MONITOR,
            1 << 34,
        ] {
            assert_eq!(
                validate_x86_msr_write(IA32_MISC_ENABLE, state.misc_enable ^ fixed_bit, state, 0,),
                Err(X86MsrFault::GeneralProtection)
            );
        }
    }

    #[test]
    fn bios_signature_discovery_accepts_only_the_architectural_clear() {
        let state = X86MsrState::default();
        assert_eq!(read_x86_msr(IA32_BIOS_SIGN_ID, state, 0), Ok(0));
        assert_eq!(
            validate_x86_msr_write(IA32_BIOS_SIGN_ID, 0, state, 0)
                .unwrap()
                .state,
            state
        );
        assert_eq!(
            validate_x86_msr_write(IA32_BIOS_SIGN_ID, 1, state, 0),
            Err(X86MsrFault::GeneralProtection)
        );
    }

    #[test]
    fn platform_and_supervisor_xstate_msrs_match_cpuid_profile() {
        let state = X86MsrState::default();
        assert_eq!(read_x86_msr(IA32_PLATFORM_ID, state, 0), Ok(0));
        assert_eq!(read_x86_msr(IA32_XSS, state, 0), Ok(0));
        assert_eq!(
            validate_x86_msr_write(IA32_PLATFORM_ID, 0, state, 0),
            Err(X86MsrFault::GeneralProtection)
        );
        assert!(validate_x86_msr_write(IA32_XSS, 0, state, 0).is_ok());
        assert_eq!(
            validate_x86_msr_write(IA32_XSS, 1, state, 0),
            Err(X86MsrFault::GeneralProtection)
        );
    }

    #[test]
    fn umwait_control_matches_advertised_waitpkg_profile() {
        let state = X86MsrState::default();
        assert_eq!(read_x86_msr(IA32_UMWAIT_CONTROL, state, 0), Ok(0));

        for value in [1, 4, 0x0000_0000_FFFF_FFFD] {
            let effect = validate_x86_msr_write(IA32_UMWAIT_CONTROL, value, state, 0).unwrap();
            assert_eq!(effect.state.umwait_control, value);
            assert_eq!(
                read_x86_msr(IA32_UMWAIT_CONTROL, effect.state, 0),
                Ok(value)
            );
        }
        for reserved in [2, 0x1_0000_0000, u64::MAX] {
            assert_eq!(
                validate_x86_msr_write(IA32_UMWAIT_CONTROL, reserved, state, 0),
                Err(X86MsrFault::GeneralProtection)
            );
        }
    }

    #[test]
    fn pat_accepts_all_memory_types_and_rejects_every_reserved_encoding() {
        let state = X86MsrState::default();
        assert_eq!(read_x86_msr(IA32_PAT, state, 0), Ok(IA32_PAT_RESET));

        let all_defined = 0x0706_0504_0100_0706;
        let effect = validate_x86_msr_write(IA32_PAT, all_defined, state, 0).unwrap();
        assert_eq!(effect.state.pat, all_defined);
        assert!(effect.flush_tlb);
        assert!(
            !validate_x86_msr_write(IA32_PAT, IA32_PAT_RESET, state, 0)
                .unwrap()
                .flush_tlb
        );

        for byte_index in 0..8 {
            for reserved in [2_u64, 3, 8, 0x80, 0xFF] {
                let value =
                    (IA32_PAT_RESET & !(0xFF << (byte_index * 8))) | (reserved << (byte_index * 8));
                assert!(
                    !is_valid_pat(value),
                    "entry {byte_index}, value {value:#018x}"
                );
                assert_eq!(
                    validate_x86_msr_write(IA32_PAT, value, state, 0),
                    Err(X86MsrFault::GeneralProtection),
                    "entry {byte_index}, value {value:#018x}"
                );
            }
        }
    }

    #[test]
    fn write_effects_classify_serialization_and_gs_base_state_exactly() {
        let state = X86MsrState::default();
        assert!(
            validate_x86_msr_write(IA32_STAR, 0x1234, state, 0)
                .unwrap()
                .serializing
        );
        assert!(
            !validate_x86_msr_write(IA32_TSC_DEADLINE, u64::MAX, state, 0)
                .unwrap()
                .serializing
        );
        for base in [0, 0x1000] {
            let effect = validate_x86_msr_write(IA32_GS_BASE, base, state, 0).unwrap();
            assert_eq!(effect.state.gs_base, base);
            assert_eq!(effect.state.cr0, state.cr0);
            assert!(!effect.flush_tlb);
        }
    }
}
