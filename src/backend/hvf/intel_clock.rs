//! Late-bound Intel guest-clock APIs; older SDK symbols are not imported at load time.
use super::bindings::{HV_SUCCESS, hv_error_string, hv_return_t, hv_vcpuid_t};
use crate::error::{Error, Result};
use std::ffi::{CStr, c_void};
use std::sync::OnceLock;

type Clock = unsafe extern "C" fn() -> u64;
type SetRelative = unsafe extern "C" fn(hv_vcpuid_t, i64) -> hv_return_t;

pub(super) struct Api {
    clock: Clock,
    set_relative: SetRelative,
}

fn symbol(name: &'static CStr) -> std::result::Result<*mut c_void, String> {
    // SAFETY: the linked Hypervisor framework remains loaded for the process;
    // call sites below use the exact declarations retained in SDK hv.h.
    let value = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if value.is_null() {
        Err(format!(
            "native Intel clock API unavailable: {}",
            name.to_string_lossy()
        ))
    } else {
        Ok(value)
    }
}

impl Api {
    pub(super) fn load() -> Result<&'static Self> {
        static API: OnceLock<std::result::Result<Api, String>> = OnceLock::new();
        API.get_or_init(|| {
            let clock = symbol(c"hv_tsc_clock")?;
            let set_relative = symbol(c"hv_vcpu_set_tsc_relative")?;
            // SAFETY: exact SDK signatures, checked independently by the ABI
            // probe. Dynamic lookup preserves older-host loader compatibility.
            Ok(Api {
                clock: unsafe { std::mem::transmute::<*mut c_void, Clock>(clock) },
                set_relative: unsafe {
                    std::mem::transmute::<*mut c_void, SetRelative>(set_relative)
                },
            })
        })
        .as_ref()
        .map_err(|error| Error::InvalidConfig(error.clone()))
    }

    pub(super) fn now(&self) -> u64 {
        // SAFETY: callers retain a live SDK VM; the SDK abstract clock has no
        // owning-vCPU restriction and returns one initialized scalar.
        unsafe { (self.clock)() }
    }

    pub(super) fn set(&self, id: hv_vcpuid_t, offset: i64) -> Result<()> {
        // SAFETY: live SDK handle on its permanent owner. Offsets are the SDK's
        // signed, two's-complement representation of a modulo-2^64 difference.
        let status = unsafe { (self.set_relative)(id, offset) };
        if status == HV_SUCCESS {
            Ok(())
        } else {
            Err(Error::Emulator(format!(
                "native Intel TSC offset: {}",
                hv_error_string(status)
            )))
        }
    }
}
