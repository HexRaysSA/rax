//! Intel SDK bridge for host-owned monitor-trap control.
use super::{bindings::*, convert::*, native_step};

pub(super) struct Host(pub hv_vcpuid_t);

fn capability(field: hv_vmx_capability_t) -> Result<u64, String> {
    let mut value = 0;
    // SAFETY: the SDK initializes a valid exclusive u64 output pointer;
    // the call is synchronous and no reference escapes across the FFI.
    let result = unsafe { hv_vmx_read_capability(field, &mut value) };
    if result != HV_SUCCESS {
        return Err(format!(
            "HVF capability {field} read failed: {}",
            hv_error_string(result)
        ));
    }
    Ok(value)
}

/// The native profile enters HLT after emulating its intercept. SDM Appendix
/// A.6 requires IA32_VMX_MISC[6] before admitting that guest activity state.
pub(super) fn validate_halt_activity() -> Result<(), String> {
    if capability(HV_VMX_CAP_MISC)? & (1 << 6) == 0 {
        return Err("HVF native profile requires VM-entry HLT activity support".into());
    }
    Ok(())
}

impl native_step::Access for Host {
    fn capability(&mut self) -> Result<u64, String> {
        capability(HV_VMX_CAP_PROCBASED)
    }

    fn read_control(&mut self) -> Result<u64, String> {
        vmcs_read(self.0, hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED)
            .map_err(|error| error.to_string())
    }

    fn write_control(&mut self, value: u64) -> Result<(), String> {
        vmcs_write(self.0, hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED, value)
            .map_err(|error| error.to_string())
    }
}
