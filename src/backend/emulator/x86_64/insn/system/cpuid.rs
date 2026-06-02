//! CPUID instruction.

use crate::cpu::VcpuExit;
use crate::error::Result;

use super::super::super::cpu::{InsnContext, X86_64Vcpu};

/// CPUID (0x0F 0xA2)
pub fn cpuid(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let leaf = vcpu.regs.rax as u32;
    let subleaf = vcpu.regs.rcx as u32;

    let (eax, ebx, ecx, edx) = match leaf {
        0 => {
            // Return max leaf and vendor string "GenuineIntel"
            // x86 vendor string format: EBX + EDX + ECX (not EBX + ECX + EDX!)
            // "GenuineIntel" = "Genu" (EBX) + "ineI" (EDX) + "ntel" (ECX)
            // EBX = "Genu" = 0x756e6547 (little-endian: G=0x47, e=0x65, n=0x6e, u=0x75)
            // EDX = "ineI" = 0x49656e69 (little-endian: i=0x69, n=0x6e, e=0x65, I=0x49)
            // ECX = "ntel" = 0x6c65746e (little-endian: n=0x6e, t=0x74, e=0x65, l=0x6c)
            // Note: Our tuple is (eax, ebx, ecx, edx) so we must swap ecx and edx values!
            (0x16, 0x756e6547, 0x6c65746e, 0x49656e69)
        }
        1 => {
            // Processor signature and features
            // EAX: Stepping=1, Model=15, Family=6 => 0x6F1 (typical x86-64)
            let signature: u32 = 0x000006F1;
            // EDX features (required by Linux: 0x0700a169)
            // bit 0: FPU, bit 3: PSE, bit 4: TSC, bit 5: MSR, bit 6: PAE, bit 8: CX8
            // bit 9: APIC, bit 13: PGE, bit 15: CMOV, bit 19: CLFLUSH
            // bit 23: MMX, bit 24: FXSR, bit 25: SSE, bit 26: SSE2
            let features_edx: u32 = (1 << 0)   // FPU
                                  | (1 << 3)   // PSE
                                  | (1 << 4)   // TSC - Time Stamp Counter
                                  | (1 << 5)   // MSR
                                  | (1 << 6)   // PAE
                                  | (1 << 8)   // CX8 (CMPXCHG8B) - REQUIRED
                                  | (1 << 9)   // APIC
                                  | (1 << 13)  // PGE - REQUIRED
                                  | (1 << 15)  // CMOV
                                  | (1 << 19)  // CLFLUSH
                                  | (1 << 23)  // MMX
                                  | (1 << 24)  // FXSR - REQUIRED
                                  | (1 << 25)  // SSE - REQUIRED
                                  | (1 << 26); // SSE2 - REQUIRED
                                               // ECX: SSE3(0), SSSE3(9), SSE4.1(19), SSE4.2(20), POPCNT(23)
                                               // Note: TSC_DEADLINE (bit 24) NOT advertised - LAPIC only supports oneshot/periodic modes
                                               // XSAVE (26), OSXSAVE (27, reflects CR4) and AVX (28) ARE advertised:
                                               // XGETBV/XSETBV/XSAVE/XRSTOR + XCR0 are implemented (see group7.rs, leaf 0xD).
            let osxsave = ((vcpu.sregs.cr4 >> 18) & 1) as u32; // CR4.OSXSAVE
            let features_ecx: u32 = (1 << 0)   // SSE3
                                  | (1 << 9)   // SSSE3
                                  | (1 << 19)  // SSE4.1
                                  | (1 << 20)  // SSE4.2
                                  | (1 << 23)  // POPCNT
                                  | (1 << 26)  // XSAVE
                                  | (osxsave << 27) // OSXSAVE (reflects CR4.OSXSAVE)
                                  | (1 << 28); // AVX
            (signature, 0x00000000, features_ecx, features_edx)
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
        7 => {
            // Extended feature flags (subleaf 0)
            if subleaf == 0 {
                // AVX2 IS advertised now that XSAVE/XCR0 are implemented.
                let ebx = (1u32 << 20) // SMAP
                        | (1u32 << 5); // AVX2
                let ecx = 1u32 << 8; // GFNI (GF2P8MULB / GF2P8AFFINE[INV]QB)
                // IBT (bit 20): advertise Indirect Branch Tracking so a FineIBT
                // kernel resolves cfi_mode=CFI_FINEIBT (alternative.c:1745) and
                // its apply_retpolines BUG_ON(cfi_mode != CFI_FINEIBT) passes.
                // endbr64 is already a NOP here, so IBT enforcement is moot; the
                // kernel only needs the feature bit + to set CR4.CET / the CET
                // MSRs (which the emulator accepts).
                let edx = (1u32 << 14) // SERIALIZE
                        | (1u32 << 20); // IBT (CET indirect branch tracking)
                (0, ebx, ecx, edx)
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
            let features_edx = (1u32 << 29)  // LM (Long Mode)
                             | (1u32 << 27)  // RDTSCP instruction available
                             // Removed PDPE1GB - causes issues with direct mapping
                             | (1u32 << 20); // NX (No Execute)
            (signature, 0, 0, features_edx)
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
            (phys_bits | (linear_bits << 8), 0, 0, 0)
        }
        0xD => {
            // XSAVE feature enumeration leaf.
            match subleaf {
                // Subleaf 0: EAX/EDX = supported XCR0 bits; EBX = area size for the
                // currently-enabled features; ECX = max area size for all supported.
                0 => {
                    let xcr0_valid_lo = 0x7u32; // x87 | SSE | AVX
                    let max_size = 832u32; // legacy 512 + header 64 + YMM_Hi128 256
                    let cur_size = if vcpu.xcr0 & 0x4 != 0 { 832 } else { 576 };
                    (xcr0_valid_lo, cur_size, max_size, 0)
                }
                // Subleaf 1: XSAVEOPT/XSAVEC/XSAVES not supported.
                1 => (0, 0, 0, 0),
                // Subleaf 2: AVX (YMM_Hi128) component size + offset.
                2 => (256, 576, 0, 0),
                _ => (0, 0, 0, 0),
            }
        }

        _ => (0, 0, 0, 0),
    };

    vcpu.regs.rax = eax as u64;
    vcpu.regs.rbx = ebx as u64;
    vcpu.regs.rcx = ecx as u64;
    vcpu.regs.rdx = edx as u64;
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}
