//! CPUID instruction.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};

const XCR0_X87: u64 = 1 << 0;
const XCR0_SSE: u64 = 1 << 1;
const XCR0_AVX: u64 = 1 << 2;
const XCR0_OPMASK: u64 = 1 << 5;
const XCR0_ZMM_HI256: u64 = 1 << 6;
const XCR0_HI16_ZMM: u64 = 1 << 7;
const XCR0_PKRU: u64 = 1 << 9;
const XCR0_APX_F: u64 = 1 << 19;

const XSAVE_LEGACY_SIZE: u32 = 512;
const XSAVE_HEADER_SIZE: u32 = 64;
const XSAVE_AVX_OFFSET: u32 = XSAVE_LEGACY_SIZE + XSAVE_HEADER_SIZE;
const XSAVE_AVX_SIZE: u32 = 256;
const XSAVE_APX_OFFSET: u32 = 0x3C0;
const XSAVE_APX_SIZE: u32 = 128;
const XSAVE_OPMASK_OFFSET: u32 = 0x440;
const XSAVE_OPMASK_SIZE: u32 = 64;
const XSAVE_ZMM_HI256_OFFSET: u32 = 0x480;
const XSAVE_ZMM_HI256_SIZE: u32 = 512;
const XSAVE_HI16_ZMM_OFFSET: u32 = 0x680;
const XSAVE_HI16_ZMM_SIZE: u32 = 1024;
const XSAVE_PKRU_OFFSET: u32 = 0xA80;
const XSAVE_PKRU_SIZE: u32 = 8;
const XSAVE_MAX_SIZE: u32 = XSAVE_PKRU_OFFSET + XSAVE_PKRU_SIZE;

fn standard_xsave_area_size(xcr0: u64) -> u32 {
    let mut size = XSAVE_LEGACY_SIZE + XSAVE_HEADER_SIZE;
    if xcr0 & XCR0_AVX != 0 {
        size = XSAVE_AVX_OFFSET + XSAVE_AVX_SIZE;
    }
    if xcr0 & XCR0_OPMASK != 0 {
        size = size.max(XSAVE_OPMASK_OFFSET + XSAVE_OPMASK_SIZE);
    }
    if xcr0 & XCR0_ZMM_HI256 != 0 {
        size = size.max(XSAVE_ZMM_HI256_OFFSET + XSAVE_ZMM_HI256_SIZE);
    }
    if xcr0 & XCR0_HI16_ZMM != 0 {
        size = size.max(XSAVE_HI16_ZMM_OFFSET + XSAVE_HI16_ZMM_SIZE);
    }
    if xcr0 & XCR0_PKRU != 0 {
        size = size.max(XSAVE_PKRU_OFFSET + XSAVE_PKRU_SIZE);
    }
    if xcr0 & XCR0_APX_F != 0 {
        size = size.max(XSAVE_APX_OFFSET + XSAVE_APX_SIZE);
    }
    size
}

fn compacted_xsave_area_size(xcr0: u64) -> u32 {
    let mut size = XSAVE_LEGACY_SIZE + XSAVE_HEADER_SIZE;
    if xcr0 & XCR0_AVX != 0 {
        size += XSAVE_AVX_SIZE;
    }
    if xcr0 & XCR0_OPMASK != 0 {
        size += XSAVE_OPMASK_SIZE;
    }
    if xcr0 & XCR0_ZMM_HI256 != 0 {
        size += XSAVE_ZMM_HI256_SIZE;
    }
    if xcr0 & XCR0_HI16_ZMM != 0 {
        size += XSAVE_HI16_ZMM_SIZE;
    }
    if xcr0 & XCR0_PKRU != 0 {
        size += XSAVE_PKRU_SIZE;
    }
    if xcr0 & XCR0_APX_F != 0 {
        size += XSAVE_APX_SIZE;
    }
    size
}

/// Mutable guest-profile inputs that affect `CPUID` enumeration.
///
/// The leaf/subleaf operands and four output registers remain explicit at the
/// call site. Keeping the profile in a value type lets the direct interpreter,
/// SMIR interpreter, and helper-backed JIT execute one shared implementation
/// without ever exposing the host processor's CPUID leaves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct X86CpuidState {
    pub cr4: u64,
    pub xcr0: u64,
    pub xeon_phi_avx512: bool,
    pub vp2intersect: bool,
    pub sse4a: bool,
    pub tbm: bool,
    pub xop: bool,
    pub apx: bool,
}

/// Evaluate the emulator's deterministic CPUID profile.
pub(crate) fn evaluate_cpuid(
    leaf: u32,
    subleaf: u32,
    state: X86CpuidState,
) -> (u32, u32, u32, u32) {
    match leaf {
        0 => {
            // Return max leaf and vendor string "GenuineIntel"
            // x86 vendor string format: EBX + EDX + ECX (not EBX + ECX + EDX!)
            // "GenuineIntel" = "Genu" (EBX) + "ineI" (EDX) + "ntel" (ECX)
            // EBX = "Genu" = 0x756e6547 (little-endian: G=0x47, e=0x65, n=0x6e, u=0x75)
            // EDX = "ineI" = 0x49656e69 (little-endian: i=0x69, n=0x6e, e=0x65, I=0x49)
            // ECX = "ntel" = 0x6c65746e (little-endian: n=0x6e, t=0x74, e=0x65, l=0x6c)
            // Note: Our tuple is (eax, ebx, ecx, edx) so we must swap ecx and edx values!
            (0x29, 0x756e6547, 0x6c65746e, 0x49656e69)
        }
        1 => {
            // Processor signature and features
            // EAX: Stepping=1, Model=15, Family=6 => 0x6F1 (typical x86-64)
            let signature: u32 = 0x000006F1;
            // EDX features (required by Linux: 0x0700a169)
            // bit 0: FPU, bit 2: DE, bit 3: PSE, bit 4: TSC, bit 5: MSR, bit 6: PAE, bit 8: CX8
            // bit 9: APIC, bit 13: PGE, bit 15: CMOV, bit 19: CLFLUSH
            // bit 23: MMX, bit 24: FXSR, bit 25: SSE, bit 26: SSE2
            let features_edx: u32 = (1 << 0)   // FPU
                                  | (1 << 2)   // DE (CR4.DE and DR4/DR5 behavior)
                                  | (1 << 3)   // PSE
                                  | (1 << 4)   // TSC - Time Stamp Counter
                                  | (1 << 5)   // MSR
                                  | (1 << 6)   // PAE
                                  | (1 << 8)   // CX8 (CMPXCHG8B) - REQUIRED
                                  | (1 << 9)   // APIC
                                  | (1 << 11)  // SEP (SYSENTER/SYSEXIT)
                                  | (1 << 13)  // PGE - REQUIRED
                                  | (1 << 15)  // CMOV
                                  | (1 << 19)  // CLFLUSH
                                  | (1 << 23)  // MMX
                                  | (1 << 24)  // FXSR - REQUIRED
                                  | (1 << 25)  // SSE - REQUIRED
                                  | (1 << 26); // SSE2 - REQUIRED
            // ECX: SSE3(0), MONITOR/MWAIT(3), SSSE3(9), SSE4.1(19), SSE4.2(20), POPCNT(23)
            // Note: TSC_DEADLINE (bit 24) NOT advertised - LAPIC only supports oneshot/periodic modes
            // XSAVE (26), OSXSAVE (27, reflects CR4) and AVX (28) ARE advertised:
            // XGETBV/XSETBV/XSAVE/XRSTOR + XCR0 are implemented (see group7.rs, leaf 0xD).
            let osxsave = ((state.cr4 >> 18) & 1) as u32; // CR4.OSXSAVE
            let features_ecx: u32 = (1 << 0)   // SSE3
                                  | (1 << 1)   // PCLMULQDQ
                                  | (1 << 3)   // MONITOR/MWAIT
                                  | (1 << 9)   // SSSE3
                                  | (1 << 12)  // FMA
                                  | (1 << 13)  // CMPXCHG16B
                                  | (1 << 17)  // PCID
                                  | (1 << 19)  // SSE4.1
                                  | (1 << 20)  // SSE4.2
                                  | (1 << 22)  // MOVBE
                                  | (1 << 23)  // POPCNT
                                  | (1 << 25)  // AESNI
                                  | (1 << 26)  // XSAVE
                                  | (osxsave << 27) // OSXSAVE (reflects CR4.OSXSAVE)
                                  | (1 << 28)  // AVX
                                  | (1 << 29)  // F16C
                                  | (1 << 30); // RDRAND
            (signature, 0x00000000, features_ecx, features_edx)
        }
        0x0A => {
            // Architectural performance monitoring version zero selects the
            // legacy RDPMC format. The deterministic profile exposes eight
            // model-specific 40-bit reference-clock PMCs but deliberately does
            // not claim architectural PMU counter/control-MSR facilities.
            (0, 0, 0, 0)
        }
        0x15 => {
            // TSC/Crystal ratio - helps kernel determine TSC frequency
            // Return: EAX = denominator, EBX = numerator, ECX = crystal frequency in Hz
            // TSC_freq = crystal_freq * EBX / EAX
            // We'll say 3 GHz TSC with 25 MHz crystal: 3000000000 = 25000000 * 120 / 1
            (1, 120, 25_000_000, 0)
        }
        0x16 => {
            // Processor frequency info (MHz)
            // EAX = base freq, EBX = max freq, ECX = bus/ref freq
            (3000, 3000, 100, 0) // 3 GHz base, 3 GHz max, 100 MHz bus
        }
        2 => {
            // Cache and TLB information
            // AL = iteration count (always 1 for modern CPUs)
            // Format: each byte is a descriptor. 0 = null descriptor
            // Return a simple valid response
            (0x01, 0, 0, 0) // AL=1 = single iteration required
        }
        5 => {
            // MONITOR/MWAIT enumeration. The deterministic emulator profile
            // models a 64-byte monitor line and no MWAIT extensions or C-state
            // sub-state enumeration. In particular ECX[1]=0 means MWAIT must
            // reject RCX[0]=1 with #GP(0).
            (64, 64, 0, 0)
        }
        7 => {
            // Structured extended feature flags.
            if subleaf == 0 {
                // AVX2 IS advertised now that XSAVE/XCR0 are implemented.
                let mut ebx = (1u32 << 31) // AVX512VL
                        | (1u32 << 30) // AVX512BW
                        | (1u32 << 29) // SHA-NI
                        | (1u32 << 28) // AVX512CD
                        | (1u32 << 24) // CLWB
                        | (1u32 << 23) // CLFLUSHOPT
                        | (1u32 << 21) // AVX512IFMA
                        | (1u32 << 20) // SMAP
                        | (1u32 << 19) // ADX
                        | (1u32 << 18) // RDSEED
                        | (1u32 << 17) // AVX512DQ
                        | (1u32 << 16) // AVX512F
                        | (1u32 << 10) // INVPCID
                        | (1u32 << 9) // ERMS
                        | (1u32 << 8) // BMI2
                        | (1u32 << 5) // AVX2
                        | (1u32 << 3) // BMI1
                        | (1u32 << 1) // TSC_ADJUST (IA32_TSC_ADJUST implemented)
                        | (1u32 << 0); // FSGSBASE
                if state.xeon_phi_avx512 {
                    ebx |= (1u32 << 26) // AVX512PF
                         | (1u32 << 27); // AVX512ER
                }
                let ecx = (1u32 << 28) // MOVDIR64B
                        | (1u32 << 27) // MOVDIRI
                        | (1u32 << 25) // CLDEMOTE
                        | (1u32 << 22) // RDPID
                        | (1u32 << 14) // AVX512VPOPCNTDQ
                        | (1u32 << 12) // AVX512BITALG
                        | (1u32 << 11) // AVX512VNNI
                        | (1u32 << 10) // VPCLMULQDQ
                        | (1u32 << 9) // VAES
                        | (1u32 << 8) // GFNI (GF2P8MULB / GF2P8AFFINE[INV]QB)
                        | (1u32 << 6) // AVX512VBMI2
                        | (1u32 << 5) // WAITPKG
                        | (((state.cr4 >> 22) as u32 & 1) << 4) // OSPKE
                        | (1u32 << 3) // PKU (RDPKRU/WRPKRU implemented)
                        | (1u32 << 2) // UMIP
                        | (1u32 << 1); // AVX512VBMI
                // Do NOT advertise IBT (CET Indirect Branch Tracking, bit 20):
                // the emulator does not enforce it (ENDBR is a NOP, indirect
                // CALL/JMP/RET are unchecked), so claiming it would mislead a
                // guest into believing hardware-enforced CFI is active and
                // silently weaken intra-guest control-flow protections.
                let mut edx = (1u32 << 23) // AVX512FP16
                            | (1u32 << 14); // SERIALIZE
                // WBNOINVD is enumerated in CPUID.80000008H:EBX[9],
                // not here: leaf 7 EDX bit 9 is SRBDS_CTRL.
                if state.xeon_phi_avx512 {
                    edx |= (1u32 << 2) // AVX512_4VNNIW
                         | (1u32 << 3); // AVX512_4FMAPS
                }
                if state.vp2intersect {
                    edx |= 1u32 << 8; // AVX512_VP2INTERSECT
                }
                (1, ebx, ecx, edx)
            } else if subleaf == 1 {
                let eax = (1u32 << 7) // CMPCCXADD
                        | (1u32 << 5) // AVX512_BF16
                        | (1u32 << 4); // AVX_VNNI
                let edx = if state.apx {
                    1u32 << 21 // APX_F
                } else {
                    0
                };
                (eax, 0, 0, edx)
            } else {
                (0, 0, 0, 0)
            }
        }
        0x80000000 => {
            // Extended CPUID Information - max extended leaf
            (0x80000008u32, 0, 0, 0)
        }
        0x80000001 => {
            // Extended features - CRITICAL for efficient identity mapping
            // EAX: Same signature as leaf 1 (extended signature)
            let signature: u32 = 0x000006F1;
            let features_ecx = (1u32 << 5)  // LZCNT/ABM
                             | ((state.sse4a as u32) << 6) // SSE4A
                             | (1u32 << 8)  // PREFETCHW / 3DNow! PREFETCH
                             | ((state.xop as u32) << 11) // XOP
                             | ((state.tbm as u32) << 21) // TBM
                             | (1u32 << 0); // LAHF/SAHF in long mode
            let features_edx = (1u32 << 29)  // LM (Long Mode)
                             | (1u32 << 27)  // RDTSCP instruction available
                             // Removed PDPE1GB - causes issues with direct mapping
                             | (1u32 << 20)  // NX (No Execute)
                             | (1u32 << 11); // SYSCALL/SYSRET
            (signature, 0, features_ecx, features_edx)
        }
        0x80000007 => {
            // Advanced power management
            // EDX bit 8 = Invariant TSC (TSC rate is constant regardless of P-states)
            (0, 0, 0, 1u32 << 8)
        }
        // Brand string: "Rax Emulator" padded to 48 bytes (3 leaves x 16 bytes)
        0x80000002 => {
            // "Rax Emulato" (first 12 chars = 3x u32)
            (0x20786152, 0x6c756d45, 0x726f7461, 0x00000000) // "Rax Emulator\0\0\0\0"
        }
        0x80000003 => {
            (0, 0, 0, 0) // Second part (empty/null)
        }
        0x80000004 => {
            (0, 0, 0, 0) // Third part (empty/null)
        }
        0x80000008 => {
            // Address sizes: physical bits, linear bits, number of cores
            // Use 48 bits for physical address space (common for real systems)
            let phys_bits: u32 = 48;
            let linear_bits: u32 = 48;
            // EBX bit 9 = WBNOINVD (CPUID.80000008H:EBX[9] per SDM).
            let features_ebx = 1u32 << 9;
            (phys_bits | (linear_bits << 8), features_ebx, 0, 0)
        }
        0xD => {
            // XSAVE feature enumeration leaf.
            match subleaf {
                // Subleaf 0: EAX/EDX = supported XCR0 bits; EBX = area size for the
                // currently-enabled features; ECX = max area size for all supported.
                0 => {
                    let mut xcr0_valid = XCR0_X87
                        | XCR0_SSE
                        | XCR0_AVX
                        | XCR0_OPMASK
                        | XCR0_ZMM_HI256
                        | XCR0_HI16_ZMM
                        | XCR0_PKRU;
                    if state.apx {
                        xcr0_valid |= XCR0_APX_F;
                    }
                    (
                        xcr0_valid as u32,
                        standard_xsave_area_size(state.xcr0),
                        XSAVE_MAX_SIZE,
                        (xcr0_valid >> 32) as u32,
                    )
                }
                // Subleaf 1: XSAVEOPT, XSAVEC/compacted XRSTOR, XGETBV(ECX=1),
                // and XSAVES/XRSTORS are implemented. IA32_XSS defaults to zero.
                1 => (0xF, compacted_xsave_area_size(state.xcr0), 0, 0),
                // Subleaf 2: AVX (YMM_Hi128) component size + offset.
                2 => (XSAVE_AVX_SIZE, XSAVE_AVX_OFFSET, 0, 0),
                // Subleaf 5: opmask component.
                5 => (XSAVE_OPMASK_SIZE, XSAVE_OPMASK_OFFSET, 0, 0),
                // Subleaf 6: upper 256 bits of ZMM0-15.
                6 => (XSAVE_ZMM_HI256_SIZE, XSAVE_ZMM_HI256_OFFSET, 0, 0),
                // Subleaf 7: full ZMM16-31.
                7 => (XSAVE_HI16_ZMM_SIZE, XSAVE_HI16_ZMM_OFFSET, 0, 0),
                // Subleaf 9: user protection-key rights register.
                9 => (XSAVE_PKRU_SIZE, XSAVE_PKRU_OFFSET, 0, 0),
                // Subleaf 19: APX_F EGPR component (R16-R31).
                19 if state.apx => (XSAVE_APX_SIZE, XSAVE_APX_OFFSET, 0, 0),
                _ => (0, 0, 0, 0),
            }
        }
        0x29 => {
            // Intel APX leaf. APX_F guarantees subleaf 0 with APX_NCI_NDD_NF.
            if subleaf == 0 && state.apx {
                (0, 1, 0, 0)
            } else {
                (0, 0, 0, 0)
            }
        }

        _ => (0, 0, 0, 0),
    }
}

/// CPUID (0x0F 0xA2)
pub fn cpuid(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let (eax, ebx, ecx, edx) = evaluate_cpuid(
        vcpu.regs.rax as u32,
        vcpu.regs.rcx as u32,
        X86CpuidState {
            cr4: vcpu.sregs.cr4,
            xcr0: vcpu.xcr0,
            xeon_phi_avx512: vcpu.xeon_phi_avx512,
            vp2intersect: vcpu.vp2intersect,
            sse4a: vcpu.sse4a_enabled(),
            tbm: vcpu.tbm_enabled(),
            xop: vcpu.xop_enabled(),
            apx: vcpu.apx_enabled(),
        },
    );

    vcpu.regs.rax = eax as u64;
    vcpu.regs.rbx = ebx as u64;
    vcpu.regs.rcx = ecx as u64;
    vcpu.regs.rdx = edx as u64;
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::isa::x86_64::cpu::MAX_INSN_LEN;

    fn vcpu() -> X86_64Vcpu {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        X86_64Vcpu::new(0, mem)
    }

    fn cpuid_ctx() -> InsnContext {
        let instruction = [0x0f, 0xa2];
        let mut bytes = [0; MAX_INSN_LEN];
        bytes[..instruction.len()].copy_from_slice(&instruction);
        InsnContext {
            bytes,
            bytes_len: instruction.len(),
            cursor: 2,
            rex: None,
            rex2: None,
            operand_size_override: false,
            address_size_override: false,
            rep_prefix: None,
            op_size: 4,
            rip_relative_offset: 0,
            segment_override: None,
            evex: None,
            opcode: 0xa2,
            boundary_gp: false,
            boundary_fault: None,
        }
    }

    #[test]
    fn cpuid_sse4a_bit_tracks_feature_gate() {
        let mut vcpu = vcpu();
        let mut ctx = cpuid_ctx();
        vcpu.regs.rax = 0x8000_0001;

        cpuid(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(vcpu.regs.rcx & (1 << 6), 0);

        let mut ctx = cpuid_ctx();
        vcpu.set_sse4a_enabled(true);
        vcpu.regs.rax = 0x8000_0001;

        cpuid(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(vcpu.regs.rcx & (1 << 6), 1 << 6);
    }

    #[test]
    fn cpuid_tbm_bit_tracks_feature_gate() {
        let mut vcpu = vcpu();
        let mut ctx = cpuid_ctx();
        vcpu.regs.rax = 0x8000_0001;

        cpuid(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(vcpu.regs.rcx & (1 << 21), 0);

        let mut ctx = cpuid_ctx();
        vcpu.set_tbm_enabled(true);
        vcpu.regs.rax = 0x8000_0001;

        cpuid(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(vcpu.regs.rcx & (1 << 21), 1 << 21);
        assert_eq!(
            vcpu.regs.rcx & (1 << 11),
            0,
            "the independent XOP bit must remain clear unless explicitly enabled"
        );
    }

    #[test]
    fn cpuid_xop_bit_tracks_feature_gate_independently_from_tbm() {
        let mut vcpu = vcpu();
        let mut ctx = cpuid_ctx();
        vcpu.regs.rax = 0x8000_0001;

        cpuid(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(vcpu.regs.rcx & (1 << 11), 0);
        assert_eq!(vcpu.regs.rcx & (1 << 21), 0);

        let mut ctx = cpuid_ctx();
        vcpu.set_xop_enabled(true);
        vcpu.regs.rax = 0x8000_0001;

        cpuid(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(vcpu.regs.rcx & (1 << 11), 1 << 11);
        assert_eq!(vcpu.regs.rcx & (1 << 21), 0);
    }

    #[test]
    fn cpuid_advertises_implemented_hint_and_cache_features() {
        let mut vcpu = vcpu();

        let mut ctx = cpuid_ctx();
        vcpu.regs.rax = 1;
        vcpu.regs.rcx = 0;
        cpuid(&mut vcpu, &mut ctx).unwrap();
        assert_eq!(vcpu.regs.rcx & (1 << 3), 1 << 3);

        let mut ctx = cpuid_ctx();
        vcpu.regs.rax = 7;
        vcpu.regs.rcx = 0;
        cpuid(&mut vcpu, &mut ctx).unwrap();
        assert_eq!(vcpu.regs.rcx & (1 << 2), 1 << 2);
        assert_eq!(vcpu.regs.rbx & (1 << 9), 1 << 9);
        assert_eq!(vcpu.regs.rdx & (1 << 9), 0);

        let mut ctx = cpuid_ctx();
        vcpu.regs.rax = 0x8000_0001;
        vcpu.regs.rcx = 0;
        cpuid(&mut vcpu, &mut ctx).unwrap();
        assert_eq!(vcpu.regs.rcx & (1 << 8), 1 << 8);

        let mut ctx = cpuid_ctx();
        vcpu.regs.rax = 0x8000_0008;
        vcpu.regs.rcx = 0;
        cpuid(&mut vcpu, &mut ctx).unwrap();
        assert_eq!(vcpu.regs.rbx & (1 << 9), 1 << 9);
    }

    #[test]
    fn cpuid_advertises_implemented_debug_extensions_control() {
        let mut vcpu = vcpu();
        let mut ctx = cpuid_ctx();
        vcpu.regs.rax = 1;
        vcpu.regs.rcx = 0;

        cpuid(&mut vcpu, &mut ctx).unwrap();

        assert_eq!(vcpu.regs.rdx & (1 << 2), 1 << 2);
    }
}
