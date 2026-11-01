//! Stable host compatibility fields for Intel native checkpoint profiles.
//!
//! Intel SDM CPUID.0DH.00H/01H: EBX depends on currently enabled XCR0/XSS
//! state. Component offsets and maximum supported size are separate fields.
pub(crate) fn normalize(leaf: u32, subleaf: u32, mut words: [u32; 4]) -> [u32; 4] {
    if leaf == 1 {
        words[1] &= 0x00ff_ffff; // Per-host-CPU initial APIC ID is not compatibility.
    }
    if leaf == 0x0d && matches!(subleaf, 0 | 1) {
        words[1] = 0; // Current enabled lengths are not the supported layout.
    }
    words
}
