//! Runtime CPUID changes admitted by Linux v6.8 __kvm_update_cpuid_runtime.
//! The managed VM keeps the default MISC_ENABLE_NO_MWAIT quirk. A caller that
//! disables it requires another profile; MONITOR is immutable in this one.
use crate::backend::intel_hvf_xsave::Layout;
use crate::error::{Error, Result};
use kvm_bindings::{CpuId, kvm_cpuid_entry2, kvm_sregs, kvm_xcrs};

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("native KVM CPU profile: {message}"))
}

fn entry(table: &CpuId, leaf: u32, index: u32) -> Option<&kvm_cpuid_entry2> {
    table
        .as_slice()
        .iter()
        .find(|e| e.function == leaf && e.index == index)
}

fn runtime_canonical(table: &CpuId, allow_pv_unhalt_clear: bool) -> Vec<kvm_cpuid_entry2> {
    let kvm = super::super::cpuid::has_kvm_signature(table.as_slice());
    let host = std::arch::x86_64::__cpuid_count(1, 0);
    let host7 = std::arch::x86_64::__cpuid_count(7, 0);
    let mut entries = table.as_slice().to_vec();
    for e in &mut entries {
        match (e.function, e.index) {
            (1, 0) => {
                if host.ecx & (1 << 26) != 0 {
                    e.ecx &= !(1 << 27); // OSXSAVE follows CR4.OSXSAVE.
                }
                e.edx &= !(1 << 9); // APIC follows APIC_BASE.EN.
            }
            (7, 0) if host7.ecx & (1 << 3) != 0 => e.ecx &= !(1 << 4), // OSPKE follows CR4.PKE.
            (0xd, 0) => e.ebx = 0,
            (0xd, 1) if e.eax & ((1 << 1) | (1 << 3)) != 0 => e.ebx = 0,
            (0x4000_0001, 0) if kvm && allow_pv_unhalt_clear => e.eax &= !(1 << 7),
            _ => {}
        }
    }
    entries
}

fn size(layout: &Layout, xcr0: u64, compact: bool) -> Result<u32> {
    let mut size: u32 = 576;
    for component in &layout.components {
        if xcr0 & (1u64 << component.bit) == 0 {
            continue;
        }
        let offset = if compact {
            if component.align64 {
                size.checked_add(63)
                    .ok_or_else(|| invalid("XSAVE size overflow"))?
                    & !63
            } else {
                size
            }
        } else {
            component.offset
        };
        size = size.max(
            offset
                .checked_add(component.size)
                .ok_or_else(|| invalid("XSAVE size overflow"))?,
        );
    }
    Ok(size)
}

fn first_difference(saved: &[kvm_cpuid_entry2], current: &[kvm_cpuid_entry2]) -> Option<String> {
    if saved.len() != current.len() {
        return Some(format!(
            "entry count saved={}, current={}",
            saved.len(),
            current.len()
        ));
    }
    saved
        .iter()
        .zip(current)
        .enumerate()
        .find(|(_, (saved, current))| saved != current)
        .map(|(position, (saved, current))| {
            format!("entry {position} (hex) saved={saved:x?}, current={current:x?}")
        })
}

pub(in crate::backend::kvm) fn destination_difference(
    saved_profile: &CpuId,
    configured: &CpuId,
    observed: &CpuId,
    destination: impl FnOnce() -> Result<CpuId>,
) -> Result<Option<String>> {
    if let Some(difference) = first_difference(saved_profile.as_slice(), configured.as_slice()) {
        return Ok(Some(format!("configured CPUID {difference}")));
    }
    let current = destination()?;
    Ok(first_difference(
        &runtime_canonical(observed, false),
        &runtime_canonical(&current, false),
    )
    .map(|difference| format!("observed CPUID {difference}")))
}

/// Repair the host identity in the old producer's inactive 1FH subleaf.
/// Only a matching pair of zero-domain entries can be a captured legacy
/// record. The destination profile comparison still checks all other fields.
pub(super) fn project_legacy_v2_id(configured: &mut CpuId, observed: &mut CpuId, id: u32) {
    for (configured, observed) in configured
        .as_mut_slice()
        .iter_mut()
        .zip(observed.as_mut_slice())
    {
        if configured == observed
            && (
                configured.function,
                configured.index,
                configured.eax,
                configured.ebx,
                configured.ecx,
            ) == (0x1f, 0, 0, 0, 0)
        {
            configured.edx = id;
            observed.edx = id;
        }
    }
}

/// Validate observed fields, rather than masking arbitrary differences and
/// silently accepting a forged profile. O(n + c), with n bounded CPUID entries
/// and c at most 61 architectural user-state component descriptors.
pub(in crate::backend::kvm) fn validate(
    configured: &CpuId,
    observed: &CpuId,
    special: &kvm_sregs,
    xcrs: Option<&kvm_xcrs>,
    layout: &Layout,
) -> Result<()> {
    if runtime_canonical(configured, true) != runtime_canonical(observed, true) {
        return Err(invalid("immutable CPUID differs from configured profile"));
    }
    layout.validate()?;
    // x86-64 guarantees CPUID. No feature-dependent instruction or
    // host state mutation occurs; the intrinsic returns an owned value.
    let host = std::arch::x86_64::__cpuid_count(1, 0);
    // CPUID is available on x86-64; unsupported leaves return data
    // without memory access or a pointer retained by the processor.
    let host7 = std::arch::x86_64::__cpuid_count(7, 0);
    if let Some(e) = entry(observed, 1, 0) {
        if host.ecx & (1 << 26) != 0 && ((e.ecx >> 27) & 1 != (special.cr4 >> 18) as u32 & 1) {
            return Err(invalid("OSXSAVE does not match CR4"));
        }
        if (e.edx >> 9) & 1 != (special.apic_base >> 11) as u32 & 1 {
            return Err(invalid("APIC does not match APIC_BASE"));
        }
    }
    if let Some(e) = entry(observed, 7, 0)
        && host7.ecx & (1 << 3) != 0
        && (e.ecx >> 4) & 1 != (special.cr4 >> 22) as u32 & 1
    {
        return Err(invalid("OSPKE does not match CR4"));
    }
    let xcr0 = match xcrs {
        Some(bank) => {
            if bank.nr_xcrs > bank.xcrs.len() as u32 || bank.flags != 0 {
                return Err(invalid("XCR bank count or flags are unsupported"));
            }
            let active = &bank.xcrs[..bank.nr_xcrs as usize];
            if active.len() != 1 || active[0].xcr != 0 || active[0].reserved != 0 {
                return Err(invalid("XCR bank is not the admitted XCR0 profile"));
            }
            active[0].value
        }
        None => 1,
    };
    if xcr0 & 1 == 0 || xcr0 & !layout.mask != 0 || xcr0 & 4 != 0 && xcr0 & 2 == 0 {
        return Err(invalid("XCR0 is outside the admitted host layout"));
    }
    if let Some(e) = entry(observed, 0xd, 0) {
        let advertised = u64::from(e.eax) | (u64::from(e.edx) << 32);
        if xcr0 & !advertised != 0 || e.ebx != size(layout, xcr0, false)? {
            return Err(invalid("standard XSAVE size or XCR0 differs from CPUID"));
        }
    }
    if let Some(e) = entry(observed, 0xd, 1)
        && e.eax & ((1 << 1) | (1 << 3)) != 0
        && e.ebx != size(layout, xcr0, true)?
    {
        return Err(invalid("compacted XSAVE size differs from XCR0"));
    }
    if super::super::cpuid::has_kvm_signature(configured.as_slice())
        && let (Some(before), Some(after)) = (
            entry(configured, 0x4000_0001, 0),
            entry(observed, 0x4000_0001, 0),
        )
        && after.eax & (1 << 7) != 0
        && before.eax & (1 << 7) == 0
    {
        return Err(invalid(
            "runtime CPUID added an unconfigured PV_UNHALT feature",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_diagnostic_retains_cpuid_equality_and_comparison_order() {
        let saved_entry = kvm_cpuid_entry2 {
            function: 1,
            edx: 1 << 9,
            ..Default::default()
        };
        let saved = CpuId::from_entries(&[saved_entry]).unwrap();
        let empty = CpuId::from_entries(&[]).unwrap();
        let diagnostic = destination_difference(&saved, &empty, &saved, || {
            panic!("configured mismatch must precede the native CPUID read")
        })
        .unwrap();
        assert_eq!(
            diagnostic.as_deref(),
            Some("configured CPUID entry count saved=1, current=0")
        );

        let current_entry = kvm_cpuid_entry2 {
            edx: 0,
            ..saved_entry
        };
        let current = CpuId::from_entries(&[current_entry]).unwrap();
        assert!(
            destination_difference(&saved, &saved, &saved, || Ok(current))
                .unwrap()
                .is_none()
        );
        let current = CpuId::from_entries(&[kvm_cpuid_entry2 {
            eax: 0x42,
            ..current_entry
        }])
        .unwrap();
        let diagnostic = destination_difference(&saved, &saved, &saved, || Ok(current))
            .unwrap()
            .unwrap();
        assert!(diagnostic.starts_with("observed CPUID entry 0"));
        assert!(diagnostic.contains("eax: 42"));
    }

    #[test]
    fn legacy_v2_host_id_projection_keeps_all_other_profile_checks() {
        let inactive = kvm_cpuid_entry2 {
            function: 0x1f,
            flags: kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
            edx: 2,
            ..Default::default()
        };
        let expected = kvm_cpuid_entry2 { edx: 3, ..inactive };
        let current = CpuId::from_entries(&[expected]).unwrap();
        let saved = CpuId::from_entries(&[inactive]).unwrap();
        assert!(
            destination_difference(&saved, &current, &saved, || Ok(current.clone()))
                .unwrap()
                .is_some()
        );
        let mut configured = saved.clone();
        let mut observed = saved;
        project_legacy_v2_id(&mut configured, &mut observed, 3);
        assert_eq!(configured.as_slice(), &[expected]);
        assert_eq!(observed.as_slice(), &[expected]);
        assert!(
            destination_difference(&configured, &current, &observed, || Ok(current.clone()))
                .unwrap()
                .is_none()
        );

        let active = kvm_cpuid_entry2 {
            ebx: 1,
            ecx: 0x100,
            ..inactive
        };
        let inconsistent = kvm_cpuid_entry2 { edx: 0, ..inactive };
        for (configured_entry, observed_entry) in [(active, active), (inactive, inconsistent)] {
            let mut configured = CpuId::from_entries(&[configured_entry]).unwrap();
            let mut observed = CpuId::from_entries(&[observed_entry]).unwrap();
            project_legacy_v2_id(&mut configured, &mut observed, 3);
            assert_eq!(configured.as_slice(), &[configured_entry]);
            assert_eq!(observed.as_slice(), &[observed_entry]);
        }
    }
}
