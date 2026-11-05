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

pub(in crate::backend::kvm) fn immutable_equal(left: &CpuId, right: &CpuId) -> bool {
    runtime_canonical(left, false) == runtime_canonical(right, false)
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
