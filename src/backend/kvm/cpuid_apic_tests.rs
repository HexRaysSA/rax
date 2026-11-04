use super::*;
use kvm_bindings::kvm_cpuid_entry2;

fn fixture(kvm: bool, features: u32) -> CpuId {
    CpuId::from_entries(&[
        kvm_cpuid_entry2 {
            function: 1,
            ecx: features,
            eax: 0x306f2,
            ebx: 0x10203040,
            edx: 0x178bfbff,
            ..Default::default()
        },
        kvm_cpuid_entry2 {
            function: 0x4000_0000,
            eax: 0x4000_0001,
            ebx: if kvm { 0x4b4d_564b } else { 0 },
            ecx: 0x564b_4d56,
            edx: 0x4d,
            ..Default::default()
        },
        kvm_cpuid_entry2 {
            function: 0x4000_0001,
            eax: 0x0100_7efb,
            ..Default::default()
        },
        kvm_cpuid_entry2 {
            function: 7,
            eax: 0x42,
            ebx: 0x1234,
            ..Default::default()
        },
    ])
    .unwrap()
}

#[test]
fn deadline_requires_both_native_lapic_and_separate_kernel_capability() {
    for irqchip in [false, true] {
        for capability in [false, true] {
            for features in [0, X2APIC, TSC_DEADLINE, u32::MAX] {
                let mut cpuid = fixture(true, features);
                admit(&mut cpuid, irqchip, capability);
                let ecx = cpuid.as_slice()[0].ecx;
                assert_eq!(ecx & TSC_DEADLINE != 0, irqchip && capability);
                assert_eq!(ecx & X2APIC != 0, irqchip && features & X2APIC != 0);
                assert_eq!(
                    ecx & !(TSC_DEADLINE | X2APIC),
                    features & !(TSC_DEADLINE | X2APIC)
                );
            }
        }
    }
}

#[test]
fn no_lapic_masks_only_controller_dependent_kvm_features() {
    for irqchip in [false, true] {
        let mut cpuid = fixture(true, u32::MAX);
        let original = cpuid.clone();
        admit(&mut cpuid, irqchip, true);
        assert_eq!(
            cpuid.as_slice()[2].eax,
            original.as_slice()[2].eax
                & if irqchip {
                    u32::MAX
                } else {
                    !((1 << 4) | PV_UNHALT | (1 << 10) | (1 << 11) | PV_ASYNC_PF_INT)
                }
        );
        for index in [1, 3] {
            assert_eq!(cpuid.as_slice()[index], original.as_slice()[index]);
        }
        let first = cpuid.as_slice()[0];
        let original = original.as_slice()[0];
        assert_eq!(
            (first.eax, first.ebx, first.edx),
            (original.eax, original.ebx, original.edx)
        );
    }
}

#[test]
fn unrelated_hypervisor_records_are_not_interpreted_as_kvm_features() {
    let mut cpuid = fixture(false, u32::MAX);
    let original = cpuid.as_slice()[2];
    admit(&mut cpuid, false, false);
    assert_eq!(cpuid.as_slice()[2], original);
}

#[test]
fn paravirtual_interrupt_and_page_fault_helpers_require_the_kernel_lapic() {
    for irqchip in [false, true] {
        for features in [
            0,
            1 << 4,
            1 << 7,
            1 << 10,
            1 << 11,
            1 << 14,
            (1 << 7) | (1 << 14),
            (1 << 11) | (1 << 14),
            (1 << 4) | (1 << 10) | (1 << 14),
            u32::MAX,
        ] {
            let mut cpuid = fixture(true, 0);
            cpuid.as_mut_slice()[2].eax = features;
            admit(&mut cpuid, irqchip, false);
            let expected = if irqchip {
                features
            } else {
                features & !((1 << 4) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14))
            };
            assert_eq!(cpuid.as_slice()[2].eax, expected);
        }
    }
}
