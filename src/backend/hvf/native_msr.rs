//! SDK-managed syscall, SWAPGS and RDTSCP auxiliary state.
//! The SDK switches these MSRs on native entry/exit; a Rust-only shadow would
//! disagree with SYSCALL, SYSRET, SWAPGS and RDTSCP executed by the guest.
use super::bindings::{
    HV_SUCCESS, hv_error_string, hv_return_t, hv_vcpu_enable_native_msr, hv_vcpu_read_msr,
    hv_vcpu_write_msr, hv_vcpuid_t,
};
use crate::error::{Error, Result};

pub(super) const STAR: u32 = 0xc000_0081;
pub(super) const LSTAR: u32 = 0xc000_0082;
pub(super) const CSTAR: u32 = 0xc000_0083;
pub(super) const FMASK: u32 = 0xc000_0084;
pub(super) const KERNEL_GS_BASE: u32 = 0xc000_0102;
pub(super) const TSC_AUX: u32 = 0xc000_0103;
const NATIVE: [u32; 6] = [STAR, LSTAR, CSTAR, FMASK, KERNEL_GS_BASE, TSC_AUX];

fn check(status: hv_return_t, operation: &str, msr: u32) -> Result<()> {
    if status == HV_SUCCESS {
        Ok(())
    } else {
        Err(Error::Emulator(format!(
            "Intel HVF {operation} MSR {msr:#010x}: {}",
            hv_error_string(status)
        )))
    }
}

/// Admit the complete advertised native group before returning the CPU. A
/// failed binding/write/readback destroys the partially constructed owner;
/// no guest can enter with a silently omitted syscall or SWAPGS register.
/// Six fixed MSRs: O(1) work and storage.
pub(super) fn initialize(id: hv_vcpuid_t) -> Result<()> {
    for msr in NATIVE {
        // SAFETY: permanent creator thread and a live SDK handle. The ABI is
        // checked against retained hv.h; no pointers or callbacks cross FFI.
        check(
            unsafe { hv_vcpu_enable_native_msr(id, msr, true) },
            "bind native",
            msr,
        )?;
        write(id, msr, 0)?;
        if read(id, msr)? != 0 {
            return Err(Error::Emulator(format!(
                "Intel HVF initial MSR {msr:#010x} readback differs from zero"
            )));
        }
    }
    Ok(())
}

pub(super) fn read(id: hv_vcpuid_t, msr: u32) -> Result<u64> {
    let mut value = 0;
    // SAFETY: live handle on its permanent owner; one initialized exclusive
    // output word, retained for the synchronous call only. Exact SDK ABI.
    check(
        unsafe { hv_vcpu_read_msr(id, msr, &mut value) },
        "read",
        msr,
    )?;
    Ok(value)
}

pub(super) fn write(id: hv_vcpuid_t, msr: u32, value: u64) -> Result<()> {
    // SAFETY: live handle on its permanent creator thread, admitted native
    // MSR and scalar values only. SDK failures propagate to the owning path.
    check(unsafe { hv_vcpu_write_msr(id, msr, value) }, "write", msr)
}
