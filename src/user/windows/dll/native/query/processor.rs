//! Twelve-byte processor records, selected by kernel, caller and query view.
//!
//! Layout and entry probing are bound to the native processor-information
//! controls. The virtual x86 signature/features come from its own CPUID.

use super::*;
use crate::user::windows::arch::WinCpu;
use crate::user::windows::process::processor::native_arch;

pub(super) fn query(
    c: &mut Ctx,
    class: u32,
    output: u64,
    length: u32,
    returned: u64,
    native_entry: bool,
) -> ApiResult {
    const REQUIRED: u32 = 12;
    if length < REQUIRED {
        return_length(c, returned, REQUIRED)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let native = native_arch(c.p)
        .map_err(|status| c.unsupported(format!("native system architecture: {status:#x}")))?;
    let ordinary_x86 = c.arch() == WinArch::X86 && !native_entry;
    let architecture = if ordinary_x86 {
        0
    } else if class == SYSTEM_EMULATION_PROCESSOR_INFORMATION {
        // Legacy ARM is a query descriptor, not an executable ISA supported
        // by this process. AMD64's corresponding descriptor is Intel.
        if native == WinArch::Arm64 { 5 } else { 0 }
    } else if native_entry {
        native.processor_architecture()
    } else {
        c.arch().processor_architecture()
    };
    let (level, revision) = if matches!(architecture, 0 | 9) {
        match &c.t.cpu {
            WinCpu::X86(cpu, _) => signature(cpu.vcpu().cpuid(1, 0).0),
            _ => return Err(c.unsupported("x86 processor identity without an x86 CPU")),
        }
    } else {
        (0, 0)
    };
    let features = if native == WinArch::Arm64 {
        // The measured ARM64 kernel's low 32 bits describe NX support and
        // its enabled kernel policy. The x86 translator clears this field.
        if ordinary_x86 { 0 } else { 0xa000_0000 }
    } else {
        match &c.t.cpu {
            WinCpu::X86(cpu, _) => x86_features(|leaf, subleaf| cpu.vcpu().cpuid(leaf, subleaf)),
            _ => return Err(c.unsupported("AMD64 kernel features without an x86 CPU")),
        }
    };
    let mut bytes = [0u8; REQUIRED as usize];
    for (index, value) in [architecture, level, revision, 1u16]
        .into_iter()
        .enumerate()
    {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[8..].copy_from_slice(&features.to_le_bytes());
    c.mem().wr(output, &bytes)?;
    return_length(c, returned, REQUIRED)?;
    if native == WinArch::Arm64
        && !native_entry
        && (ordinary_x86 || (c.arch() == WinArch::X64 && class == SYSTEM_PROCESSOR_INFORMATION))
    {
        // The compatibility translator updates processor identity/features
        // after the native query. MaximumProcessors is not a translated field.
        c.mem().wr(output, &bytes[..6])?;
        if ordinary_x86 {
            c.mem().wr(output + 8, &bytes[8..])?;
        }
    }
    Flow::ret(0)
}

fn signature(value: u32) -> (u16, u16) {
    let family = (value >> 8) & 15;
    let level = family + if family == 15 { (value >> 20) & 255 } else { 0 };
    let model = ((value >> 4) & 15)
        | if matches!(family, 6 | 15) {
            ((value >> 16) & 15) << 4
        } else {
            0
        };
    (level as u16, ((model << 8) | (value & 15)) as u16)
}

/// Low 32 KF bits for this virtual AMD64 kernel, not the host's KeFeatureBits.
/// Unknown/private policy bits stay absent. SDK 10.0.26100 ksamd64.inc binds
/// CR4/TSC/large-page/CX8/syscall/XSTATE/XSAVEOPT/FSGSBASE positions; remaining
/// architectural positions are corroborated by the pinned ReactOS NDK record.
fn x86_features(cpuid: impl Fn(u32, u32) -> (u32, u32, u32, u32)) -> u32 {
    let (_, vendor_b, vendor_c, vendor_d) = cpuid(0, 0);
    let (_, _, ecx, edx) = cpuid(1, 0);
    let (_, ebx7, _, _) = cpuid(7, 0);
    let (_, _, _, extended) = cpuid(0x8000_0001, 0);
    let mut features = 0;
    for (source, from, to) in [
        (edx, 4, 1),               // RDTSC
        (edx, 2, 2),               // CR4 debug extensions
        (edx, 15, 3),              // CMOV
        (edx, 13, 4),              // global pages
        (edx, 3, 5),               // large pages
        (edx, 12, 6),              // MTRR
        (edx, 8, 7),               // CMPXCHG8B
        (edx, 23, 8),              // MMX
        (edx, 16, 10),             // PAT
        (edx, 24, 11),             // FXSAVE
        (edx, 11, 12),             // fast syscall
        (edx, 25, 13),             // SSE
        (extended, 31, 14),        // 3DNow
        (cpuid(0x0d, 1).0, 0, 15), // XSAVEOPT
        (edx, 26, 16),             // SSE2
        (ecx, 0, 19),              // SSE3
        (ecx, 13, 20),             // CMPXCHG16B
        (ebx7, 0, 28),             // FSGSBASE
    ] {
        features |= ((source >> from) & 1) << to;
    }
    if ecx & (1 << 26 | 1 << 27) == (1 << 26 | 1 << 27) {
        features |= 1 << 23;
    }
    let vendor = [
        vendor_b.to_le_bytes(),
        vendor_d.to_le_bytes(),
        vendor_c.to_le_bytes(),
    ]
    .concat();
    if vendor == b"GenuineIntel" {
        features |= 1 << 24;
    } else if vendor == b"AuthenticAMD" {
        features |= 1 << 21;
    }
    if extended & (1 << 20) != 0 {
        // Windows guest mappings enforce execute protection.
        features |= 1 << 29 | 1 << 31;
    }
    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_include_extended_family_and_model_without_host_identity() {
        for (input, expected) in [
            (0x6f1, (6, 0x0f01)),
            (0xf4a, (15, 0x040a)),
            (0x600f01, (21, 1)),
            (0xa00f11, (25, 0x0101)),
            (0x123, (1, 0x0203)),
            (0x0003_06a9, (6, 0x3a09)),
        ] {
            assert_eq!(signature(input), expected);
        }
    }

    #[test]
    fn kernel_feature_bits_require_their_virtual_cpu_capabilities() {
        assert_eq!(x86_features(|_, _| (0, 0, 0, 0)), 0);
        let nx = |leaf, _| {
            if leaf == 0x8000_0001 {
                (0, 0, 0, 1 << 20)
            } else {
                (0, 0, 0, 0)
            }
        };
        assert_eq!(x86_features(nx), 0xa000_0000);
        let without_os = |leaf, _| {
            if leaf == 1 {
                (0, 0, 1 << 26, 0)
            } else {
                (0, 0, 0, 0)
            }
        };
        assert_eq!(x86_features(without_os), 0);
        let with_os = |leaf, _| {
            if leaf == 1 {
                (0, 0, 1 << 26 | 1 << 27, 0)
            } else {
                (0, 0, 0, 0)
            }
        };
        assert_eq!(x86_features(with_os), 0x0080_0000);
        let fsgs = |leaf, _| {
            if leaf == 7 {
                (0, 1, 0, 0)
            } else {
                (0, 0, 0, 0)
            }
        };
        assert_eq!(x86_features(fsgs), 0x1000_0000);
    }
}
