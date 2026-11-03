//! Admit native LAPIC features from the VM controller and kernel capability.
use kvm_bindings::CpuId;

const X2APIC: u32 = 1 << 21;
const TSC_DEADLINE: u32 = 1 << 24;
const PV_UNHALT: u32 = 1 << 7;

/// GET_SUPPORTED_CPUID deliberately omits TSC_DEADLINE; the separate kernel
/// capability permits it only with an in-kernel LAPIC. The same LAPIC is also
/// required for the supplied X2APIC and KVM PV_UNHALT features. Raw SDK CPUs
/// retain explicit CPUID ownership for callers implementing a userspace LAPIC.
pub(super) fn admit(cpuid: &mut CpuId, irqchip: bool, deadline_capability: bool) {
    let kvm = super::cpuid::has_kvm_signature(cpuid.as_slice());
    for entry in cpuid.as_mut_slice() {
        match entry.function {
            1 => {
                entry.ecx &= !TSC_DEADLINE;
                if irqchip && deadline_capability {
                    entry.ecx |= TSC_DEADLINE;
                }
                if !irqchip {
                    entry.ecx &= !X2APIC;
                }
            }
            0x4000_0001 if kvm && !irqchip => entry.eax &= !PV_UNHALT,
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "cpuid_apic_tests.rs"]
mod tests;
