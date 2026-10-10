//! Processor-feature and system-time queries the MSVC CRT makes at startup and
//! on its fail-fast paths.
//!
//! `IsProcessorFeaturePresent` answers from the guest CPU this process runs
//! on: the x86 answers are read from the vCPU's own CPUID model, so code that
//! asks Windows and code that executes CPUID see the same machine. A feature
//! the model cannot vouch for answers FALSE. `GetSystemTimeAsFileTime`
//! samples the host's wall clock, as the existing tick and performance
//! counters sample the host's clocks; the process seed does not make clocks
//! deterministic.

use super::super::arch::{WinArch, WinCpu};
use super::super::hle::{ApiErr, ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::Mem;

/// Appended to KERNEL32 and KERNELBASE after the existing tables, so their
/// synthetic ordinals and trap slots keep their indices.
pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "IsProcessorFeaturePresent",
        Stdcall,
        &[I32],
        is_processor_feature_present,
    ),
    Export::func(
        "GetSystemTimeAsFileTime",
        Stdcall,
        &[Ptr],
        system_time_as_file_time,
    ),
];

/// `RtlCaptureContext` is an NTDLL export that KERNEL32 forwards; KERNELBASE
/// reaches it through the rtlsupport API set, which already resolves to NTDLL.
pub(super) static KERNEL32_FORWARDS: &[Export] = &[Export::forward(
    "RtlCaptureContext",
    "NTDLL.RtlCaptureContext",
)];

// The PF_* indices from winnt.h that this implementation answers.
const PF_COMPARE_EXCHANGE_DOUBLE: u32 = 2;
const PF_MMX_INSTRUCTIONS_AVAILABLE: u32 = 3;
const PF_XMMI_INSTRUCTIONS_AVAILABLE: u32 = 6;
const PF_3DNOW_INSTRUCTIONS_AVAILABLE: u32 = 7;
const PF_RDTSC_INSTRUCTION_AVAILABLE: u32 = 8;
const PF_PAE_ENABLED: u32 = 9;
const PF_XMMI64_INSTRUCTIONS_AVAILABLE: u32 = 10;
const PF_NX_ENABLED: u32 = 12;
const PF_SSE3_INSTRUCTIONS_AVAILABLE: u32 = 13;
const PF_COMPARE_EXCHANGE128: u32 = 14;
const PF_XSAVE_ENABLED: u32 = 17;
const PF_ARM_VFP_32_REGISTERS_AVAILABLE: u32 = 18;
const PF_ARM_NEON_INSTRUCTIONS_AVAILABLE: u32 = 19;
const PF_FASTFAIL_AVAILABLE: u32 = 23;
const PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE: u32 = 24;
const PF_ARM_64BIT_LOADSTORE_ATOMIC: u32 = 25;
const PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE: u32 = 27;
const PF_RDRAND_INSTRUCTION_AVAILABLE: u32 = 28;
const PF_ARM_V8_INSTRUCTIONS_AVAILABLE: u32 = 29;
const PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE: u32 = 30;
const PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE: u32 = 31;
const PF_RDTSCP_INSTRUCTION_AVAILABLE: u32 = 32;
const PF_RDPID_INSTRUCTION_AVAILABLE: u32 = 33;
const PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE: u32 = 34;
const PF_SSSE3_INSTRUCTIONS_AVAILABLE: u32 = 36;
const PF_SSE4_1_INSTRUCTIONS_AVAILABLE: u32 = 37;
const PF_SSE4_2_INSTRUCTIONS_AVAILABLE: u32 = 38;
const PF_AVX_INSTRUCTIONS_AVAILABLE: u32 = 39;
const PF_AVX2_INSTRUCTIONS_AVAILABLE: u32 = 40;
const PF_AVX512F_INSTRUCTIONS_AVAILABLE: u32 = 41;

/// Seconds between 1601-01-01 (the FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_EPOCH_SECONDS: i128 = 11_644_473_600;

fn bit(value: u32, index: u32) -> bool {
    value & (1 << index) != 0
}

/// The answer for an x86 or x64 guest, from `cpuid(leaf, subleaf)`.
pub(super) fn x86_feature(
    feature: u32,
    x64: bool,
    cpuid: impl Fn(u32, u32) -> (u32, u32, u32, u32),
) -> bool {
    let (_, _, ecx1, edx1) = cpuid(1, 0);
    let (_, ebx7, ecx7, _) = cpuid(7, 0);
    let (_, _, _, edx_ext) = cpuid(0x8000_0001, 0);
    let os_xsave = bit(ecx1, 27);
    let avx = bit(ecx1, 28) && os_xsave;
    match feature {
        PF_COMPARE_EXCHANGE_DOUBLE => bit(edx1, 8),
        PF_MMX_INSTRUCTIONS_AVAILABLE => bit(edx1, 23),
        PF_XMMI_INSTRUCTIONS_AVAILABLE => bit(edx1, 25),
        PF_3DNOW_INSTRUCTIONS_AVAILABLE => bit(edx_ext, 31),
        PF_RDTSC_INSTRUCTION_AVAILABLE => bit(edx1, 4),
        // Windows enforces NX, and PAE with it, on every supported build.
        PF_PAE_ENABLED | PF_NX_ENABLED => true,
        PF_XMMI64_INSTRUCTIONS_AVAILABLE => bit(edx1, 26),
        PF_SSE3_INSTRUCTIONS_AVAILABLE => bit(ecx1, 0),
        PF_COMPARE_EXCHANGE128 => x64 && bit(ecx1, 13),
        PF_XSAVE_ENABLED => bit(ecx1, 26) && os_xsave,
        // `int 0x29` fails fast in this personality, as on Windows 8 and later.
        PF_FASTFAIL_AVAILABLE => true,
        PF_RDRAND_INSTRUCTION_AVAILABLE => bit(ecx1, 30),
        PF_RDTSCP_INSTRUCTION_AVAILABLE => bit(edx_ext, 27),
        PF_RDPID_INSTRUCTION_AVAILABLE => bit(ecx7, 22),
        PF_SSSE3_INSTRUCTIONS_AVAILABLE => bit(ecx1, 9),
        PF_SSE4_1_INSTRUCTIONS_AVAILABLE => bit(ecx1, 19),
        PF_SSE4_2_INSTRUCTIONS_AVAILABLE => bit(ecx1, 20),
        PF_AVX_INSTRUCTIONS_AVAILABLE => avx,
        PF_AVX2_INSTRUCTIONS_AVAILABLE => avx && bit(ebx7, 5),
        PF_AVX512F_INSTRUCTIONS_AVAILABLE => avx && bit(ebx7, 16),
        _ => false,
    }
}

/// The answer for an ARM64 guest: the ARMv8 baseline Windows requires plus
/// what the A64 user CPU implements (FP and Advanced SIMD, AES and SHA,
/// CRC32, and the LSE atomics).
pub(super) fn arm64_feature(feature: u32) -> bool {
    matches!(
        feature,
        PF_ARM_VFP_32_REGISTERS_AVAILABLE
            | PF_ARM_NEON_INSTRUCTIONS_AVAILABLE
            | PF_FASTFAIL_AVAILABLE
            | PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE
            | PF_ARM_64BIT_LOADSTORE_ATOMIC
            | PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE
            | PF_ARM_V8_INSTRUCTIONS_AVAILABLE
            | PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE
            | PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE
            | PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE
    )
}

fn is_processor_feature_present(c: &mut Ctx) -> ApiResult {
    let feature = c.u32(0)?;
    Flow::bool(processor_feature_present(&c.t.cpu, feature))
}

/// One guest CPU policy for the API, shared-data bytes, and extended bitmap.
/// Unrecognized indices, including the currently unadvertised extended
/// features 64 and above, are false. Never import host CPU capabilities.
pub(crate) fn processor_feature_present(cpu: &WinCpu, feature: u32) -> bool {
    match cpu {
        WinCpu::X86(cpu, arch) => {
            let vcpu = cpu.vcpu();
            x86_feature(feature, *arch == WinArch::X64, |leaf, sub| {
                vcpu.cpuid(leaf, sub)
            })
        }
        WinCpu::Arm64(_) => arm64_feature(feature),
    }
}

/// 100-nanosecond intervals since 1601-01-01 UTC for a Unix-epoch sample.
pub(super) fn file_time(seconds: i64, nanoseconds: i64) -> Option<u64> {
    let ticks = (i128::from(seconds) + FILETIME_UNIX_EPOCH_SECONDS) * 10_000_000
        + i128::from(nanoseconds) / 100;
    u64::try_from(ticks).ok()
}

fn system_time_as_file_time(c: &mut Ctx) -> ApiResult {
    let out = c.ptr(0)?;
    let (seconds, nanoseconds) = crate::user::clock::read(crate::user::clock::HostClock::Realtime)
        .map_err(|error| ApiErr::Internal(format!("GetSystemTimeAsFileTime: {error}")))?;
    let ticks = file_time(seconds, nanoseconds).ok_or_else(|| {
        ApiErr::Internal("GetSystemTimeAsFileTime: the host clock is before 1601".into())
    })?;
    c.mem().w64(out, ticks)?;
    Flow::void()
}

#[cfg(test)]
mod tests;
