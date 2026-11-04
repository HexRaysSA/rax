//! Initial APIC identity and represented IA32_APIC_BASE state.
pub(crate) const APIC_BASE_BSP: u64 = 1 << 8;
pub(crate) const APIC_BASE_ENABLED: u64 = 0xfee0_0800;

pub(crate) fn initial_apic_base(id: u32) -> u64 {
    APIC_BASE_ENABLED | if id == 0 { APIC_BASE_BSP } else { 0 }
}

/// The current fixed-address xAPIC profile represents the writable BSP flag.
/// Mode, enable and relocation changes require their complete device semantics.
pub(crate) fn valid_apic_base(value: u64) -> bool {
    value & !APIC_BASE_BSP == APIC_BASE_ENABLED
}

/// Preserve a profile's feature and topology geometry while supplying identity.
/// Callers apply extended-leaf projection only to their supported topology leaf.
pub(crate) fn project_cpuid(
    leaf: u32,
    mut value: (u32, u32, u32, u32),
    id: u32,
) -> (u32, u32, u32, u32) {
    match leaf {
        1 => value.1 = (value.1 & 0x00ff_ffff) | ((id & 255) << 24),
        0x0b | 0x1f => value.3 = id,
        _ => {}
    }
    value
}
