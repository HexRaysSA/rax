//! Validate Intel VMX capability masks before programming guest controls.
//! SDM086 Vol.3D AppendixA.3/A.4:low32 are required-one;high32 permit-one.
use super::bindings::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlError<E> {
    Host(E),
    Inconsistent { capability: u32, bits: u64 },
    Unsupported { capability: u32, bits: u64 },
}

pub(crate) trait ControlAccess {
    type Error;
    fn capability(&mut self, field: hv_vmx_capability_t) -> Result<u64, Self::Error>;
    fn write(&mut self, field: hv_vmx_vmcs_field_t, value: u64) -> Result<(), Self::Error>;
}

/// Keep requested controls mandatory:omitting EPT, required intercepts or an
/// advertised instruction control changes the execution contract.
pub(crate) const REQUESTS: [(hv_vmx_capability_t, hv_vmx_vmcs_field_t, u64); 4] = [
    (
        HV_VMX_CAP_PINBASED,
        hv_vmx_vmcs_field_t::VMCS_CTRL_PIN_BASED,
        PIN_BASED_EXT_INTR_EXIT | PIN_BASED_NMI_EXIT,
    ),
    (
        HV_VMX_CAP_PROCBASED,
        hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED,
        CPU_BASED_HLT_EXIT
            | CPU_BASED_TSC_OFFSET
            | CPU_BASED_CR8_LOAD_EXIT
            | CPU_BASED_CR8_STORE_EXIT
            | CPU_BASED_UNCOND_IO_EXIT
            | CPU_BASED_SECONDARY_CONTROLS,
    ),
    (
        HV_VMX_CAP_PROCBASED2,
        hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED2,
        CPU_BASED2_EPT | CPU_BASED2_UNRESTRICTED_GUEST | CPU_BASED2_RDTSCP,
    ),
    (
        HV_VMX_CAP_ENTRY,
        hv_vmx_vmcs_field_t::VMCS_CTRL_VMENTRY_CONTROLS,
        VMENTRY_LOAD_IA32_EFER | VMENTRY_GUEST_IA32E,
    ),
];

pub(crate) fn value<E>(
    field: u32,
    capability: u64,
    requested: u64,
) -> Result<u64, ControlError<E>> {
    let required = capability as u32;
    let allowed = (capability >> 32) as u32;
    let inconsistent = required & !allowed;
    if inconsistent != 0 {
        return Err(ControlError::Inconsistent {
            capability: field,
            bits: u64::from(inconsistent),
        });
    }
    let missing = requested & !u64::from(allowed);
    if missing != 0 {
        return Err(ControlError::Unsupported {
            capability: field,
            bits: missing,
        });
    }
    Ok(requested | u64::from(required))
}

/// Read and validate every used capability before the first VMCS write.
/// A later write failure propagates with prior successful writes still visible;
/// the owning vCPU is destroyed by its constructor's error path.
/// There are four banks and nine writes:O(1) time and auxiliary space.
pub(crate) fn initialize<T: ControlAccess>(host: &mut T) -> Result<(), ControlError<T::Error>> {
    let mut capabilities = [0; 4];
    for (index, (capability, _, _)) in REQUESTS.iter().enumerate() {
        capabilities[index] = host.capability(*capability).map_err(ControlError::Host)?;
    }
    let mut values = [0; 4];
    for (index, (capability, _, requested)) in REQUESTS.iter().enumerate() {
        values[index] = value(*capability, capabilities[index], *requested)?;
    }
    for (index, (_, field, _)) in REQUESTS.iter().enumerate() {
        host.write(*field, values[index])
            .map_err(ControlError::Host)?;
    }
    // The SDK owns the VMCS link pointer; it is outside its client write interface.
    for (field, data) in [
        (hv_vmx_vmcs_field_t::VMCS_CTRL_EXC_BITMAP, 0),
        (hv_vmx_vmcs_field_t::VMCS_CTRL_CR0_MASK, CR0_NE),
        (hv_vmx_vmcs_field_t::VMCS_CTRL_CR0_SHADOW, CR0_NE),
        (hv_vmx_vmcs_field_t::VMCS_CTRL_CR4_MASK, 0),
        (hv_vmx_vmcs_field_t::VMCS_CTRL_CR4_SHADOW, 0),
    ] {
        host.write(field, data).map_err(ControlError::Host)?;
    }
    Ok(())
}
