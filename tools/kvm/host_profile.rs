//! Read-only Linux x86-64 XSAVE host-profile diagnostics for the KVM CI job.
//!
//! Compile directly with rustc; no dependency resolution or guest entry is
//! required. Intel SDM Vol.1 Chapters 10 and 13 and Vol.2 FXSAVE define the
//! CPUID.0DH values and the 512-byte, 16-byte-aligned legacy save area.
//! All queries take O(1) time and storage.
use std::arch::asm;
use std::arch::x86_64::{__cpuid_count, _fxsave64};

#[repr(C, align(16))]
struct Legacy([u8; 512]);

fn intrinsic_mask() -> u32 {
    let mut legacy = Legacy([0; 512]);
    // SAFETY: main checks FXSAVE support. The destination owns 512 initialized
    // bytes at the required alignment; the instruction retains no pointer and
    // does not change host FP state.
    unsafe { _fxsave64(legacy.0.as_mut_ptr()) };
    u32::from_le_bytes(legacy.0[28..32].try_into().unwrap())
}

fn assembly_mask() -> u32 {
    let mut legacy = Legacy([0; 512]);
    // SAFETY: the same supported instruction writes the exclusively owned,
    // aligned 512-byte area. The assembly permits memory effects, preserves
    // flags and FP state, and retains no pointer into Rust storage.
    unsafe {
        asm!(
            "fxsave64 [{area}]",
            area = in(reg) legacy.0.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
    }
    u32::from_le_bytes(legacy.0[28..32].try_into().unwrap())
}

fn main() {
    let capabilities = __cpuid_count(1, 0);
    assert_ne!(capabilities.edx & (1 << 24), 0, "FXSAVE is unavailable");
    let state = __cpuid_count(0x0d, 0);
    let intrinsic = intrinsic_mask();
    let assembly = assembly_mask();
    println!(
        "xsave_host_mask={:08x}{:08x} enabled_bytes={} maximum_bytes={} \
         intrinsic_mxcsr_mask={intrinsic:08x} assembly_mxcsr_mask={assembly:08x}",
        state.edx, state.eax, state.ebx, state.ecx,
    );
}
