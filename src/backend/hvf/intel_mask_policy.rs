//! Finalize the constructor's mask policy before freezing its private profile.
use super::super::{bindings::*, convert::*};
use crate::error::{Error, Result};
use std::sync::OnceLock;

type GetConstraints = unsafe extern "C" fn(hv_vcpuid_t, u32, *mut u64, *mut u64) -> hv_return_t;

fn api() -> Result<GetConstraints> {
    static API: OnceLock<std::result::Result<GetConstraints, String>> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: constant NUL-terminated symbol; the linked framework remains
        // loaded. Late lookup preserves loading on hosts predating SDK 11.0.
        let address = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"hv_vmx_vcpu_get_cap_write_vmcs".as_ptr(),
            )
        };
        if address.is_null() {
            return Err("native Intel VMCS mask-constraint API unavailable".into());
        }
        // SAFETY: exact hv_vmx.h SDK signature: creator-owned CPU, u32 field,
        // two exclusive u64 output words, synchronous signed hv_return_t.
        Ok(unsafe { std::mem::transmute::<*mut libc::c_void, GetConstraints>(address) })
    })
    .as_ref()
    .copied()
    .map_err(|message| Error::InvalidConfig(message.clone()))
}

pub(super) fn initialize(id: hv_vcpuid_t) -> Result<()> {
    use hv_vmx_vmcs_field_t::{VMCS_CTRL_CR0_MASK, VMCS_CTRL_CR4_MASK};

    let query = api()?;
    let mut plans = [(VMCS_CTRL_CR0_MASK, 0), (VMCS_CTRL_CR4_MASK, 0)];
    // Query and validate both fields before the first policy-finalization write.
    // SDK 15.5 adds these mandatory bits at entry even after accepting writes
    // without them. A profile frozen before that change cannot capture itself.
    for (field, desired) in &mut plans {
        let mut required = 0;
        let mut allowed = 0;
        // SAFETY: live creator-thread CPU, SDK field encoding, two initialized
        // exclusive output words retained for the synchronous call only.
        let status = unsafe { query(id, *field as u32, &mut required, &mut allowed) };
        if status != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "native Intel mask constraints {field:?}: {}",
                hv_error_string(status)
            )));
        }
        let requested = vmcs_read(id, *field)?;
        if required & !allowed != 0 || requested & !allowed != 0 {
            return Err(Error::InvalidConfig(format!(
                "native Intel mask {field:?}: incompatible required={required:#x}, \
                 allowed={allowed:#x}, requested={requested:#x}"
            )));
        }
        *desired = requested | required;
    }
    for (field, desired) in plans {
        vmcs_write(id, field, desired)?;
    }
    for (field, desired) in plans {
        if vmcs_read(id, field)? != desired {
            return Err(Error::Emulator(format!(
                "native Intel mask {field:?} did not retain its constructor policy"
            )));
        }
    }
    Ok(())
}
