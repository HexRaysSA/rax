//! Admit native LAPIC features from the VM controller and kernel capability.
use kvm_bindings::CpuId;

const X2APIC: u32 = 1 << 21;
const TSC_DEADLINE: u32 = 1 << 24;
const PV_ASYNC_PF: u32 = 1 << 4;
const PV_UNHALT: u32 = 1 << 7;
const PV_ASYNC_PF_VMEXIT: u32 = 1 << 10;
const PV_SEND_IPI: u32 = 1 << 11;
const PV_ASYNC_PF_INT: u32 = 1 << 14;

/// GET_SUPPORTED_CPUID deliberately omits TSC_DEADLINE; the separate kernel
/// capability permits it only with an in-kernel LAPIC. The same LAPIC is also
/// required for X2APIC, KVM PV_UNHALT, paravirtual IPIs and asynchronous
/// page faults, including their VM-exit and interrupt delivery modes.
/// Linux 6.8 kvm_pv_enable_async_pf rejects nonzero enable values without
/// that LAPIC, and kvm_pv_enable_async_pf_int rejects interrupt control.
/// kvm_pv_send_ipi also requires the in-kernel APIC map.
/// Raw SDK CPUs retain explicit CPUID ownership for callers implementing
/// a userspace LAPIC.
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
            0x4000_0001 if kvm && !irqchip => {
                entry.eax &=
                    !(PV_ASYNC_PF | PV_UNHALT | PV_ASYNC_PF_VMEXIT | PV_SEND_IPI | PV_ASYNC_PF_INT)
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "cpuid_apic_tests.rs"]
mod tests;
