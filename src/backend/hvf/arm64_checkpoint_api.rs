//! Late-bound checkpoint APIs from the retained macOS 27.2 SDK headers.
//!
//! Availability is checked when complete checkpointing is requested. Loading
//! the existing native backend on an older host does not import newer symbols.

use super::super::arm64_bindings::{HV_SUCCESS, hv_error_string, hv_return_t, hv_vcpu_t};
use crate::error::{Error, Result};
use std::ffi::{CStr, c_void};
use std::sync::OnceLock;

#[repr(C)]
#[derive(Default)]
pub(super) struct SmeState {
    pub streaming: bool,
    pub za: bool,
}

#[repr(C, align(64))]
pub(super) struct Zt(pub [u8; 64]);

type GetBool = unsafe extern "C" fn(hv_vcpu_t, *mut bool) -> hv_return_t;
type SetBool = unsafe extern "C" fn(hv_vcpu_t, bool) -> hv_return_t;
type GetSme = unsafe extern "C" fn(hv_vcpu_t, *mut SmeState) -> hv_return_t;
type SetSme = unsafe extern "C" fn(hv_vcpu_t, *const SmeState) -> hv_return_t;
type GetVector = unsafe extern "C" fn(hv_vcpu_t, u32, *mut u8, usize) -> hv_return_t;
type SetVector = unsafe extern "C" fn(hv_vcpu_t, u32, *const u8, usize) -> hv_return_t;
type GetZa = unsafe extern "C" fn(hv_vcpu_t, *mut u8, usize) -> hv_return_t;
type SetZa = unsafe extern "C" fn(hv_vcpu_t, *const u8, usize) -> hv_return_t;
type GetZt = unsafe extern "C" fn(hv_vcpu_t, *mut Zt) -> hv_return_t;
type SetZt = unsafe extern "C" fn(hv_vcpu_t, *const Zt) -> hv_return_t;
type GetMaximumSvl = unsafe extern "C" fn(*mut usize) -> hv_return_t;
type GetIcc = unsafe extern "C" fn(hv_vcpu_t, u16, *mut u64) -> hv_return_t;
type SetIcc = unsafe extern "C" fn(hv_vcpu_t, u16, u64) -> hv_return_t;
type InvalidateTlb = unsafe extern "C" fn(hv_vcpu_t, u16, u64) -> hv_return_t;
type CreateGicState = unsafe extern "C" fn() -> *mut c_void;
type GicStateSize = unsafe extern "C" fn(*mut c_void, *mut usize) -> hv_return_t;
type GicStateData = unsafe extern "C" fn(*mut c_void, *mut c_void) -> hv_return_t;
type SetGicState = unsafe extern "C" fn(*const c_void, usize) -> hv_return_t;

pub(super) struct Api {
    pub get_serror: GetBool,
    pub set_serror: SetBool,
    pub get_trap_exceptions: GetBool,
    pub set_trap_exceptions: SetBool,
    pub get_trap_registers: GetBool,
    pub set_trap_registers: SetBool,
    pub get_sme: GetSme,
    pub set_sme: SetSme,
    pub get_z: GetVector,
    pub set_z: SetVector,
    pub get_p: GetVector,
    pub set_p: SetVector,
    pub get_za: GetZa,
    pub set_za: SetZa,
    pub get_zt: GetZt,
    pub set_zt: SetZt,
    pub maximum_svl: GetMaximumSvl,
    pub get_icc: GetIcc,
    pub set_icc: SetIcc,
    pub invalidate_tlb: InvalidateTlb,
    pub create_gic: CreateGicState,
    pub gic_size: GicStateSize,
    pub gic_data: GicStateData,
    pub set_gic: SetGicState,
}

fn symbol(name: &'static CStr) -> std::result::Result<*mut c_void, String> {
    // SAFETY: the statically linked framework stays loaded for the process
    // lifetime, and each call site supplies its exact SDK declaration below.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if address.is_null() {
        Err(format!(
            "native checkpoint API unavailable: {}",
            name.to_string_lossy()
        ))
    } else {
        Ok(address)
    }
}

/// Startup needs only these operations, independently of complete checkpoint
/// support. A never-entered CPU has no stale stage-1 translations to discard.
pub(super) fn prepare_cpu_start(vcpu: hv_vcpu_t, entered: bool, sme: bool) -> Result<()> {
    if sme {
        let address = symbol(c"hv_vcpu_set_sme_state").map_err(Error::Emulator)?;
        // SAFETY: exact retained hv_vcpu.h function type, owner-thread caller.
        let set = unsafe { std::mem::transmute::<*mut c_void, SetSme>(address) };
        check(
            unsafe { set(vcpu, &SmeState::default()) },
            "CPU_ON SME reset",
        )?;
    }
    if entered {
        let address = symbol(c"hv_vcpu_invalidate_tlb").map_err(Error::Emulator)?;
        // SAFETY: SDK function signature; 0x18 is VMALLE1IS, parameter ignored.
        let invalidate = unsafe { std::mem::transmute::<*mut c_void, InvalidateTlb>(address) };
        check(
            unsafe { invalidate(vcpu, 0x18, 0) },
            "CPU_ON translation reset",
        )?;
    }
    if let Ok(address) = symbol(c"hv_vcpu_set_serror") {
        // SAFETY: exact SDK bool setter; older SDKs cannot expose this injection API.
        let set = unsafe { std::mem::transmute::<*mut c_void, SetBool>(address) };
        check(unsafe { set(vcpu, false) }, "CPU_ON pending SError reset")?;
    }
    Ok(())
}

impl Api {
    pub fn load() -> Result<&'static Self> {
        static API: OnceLock<std::result::Result<Api, String>> = OnceLock::new();
        API.get_or_init(Self::resolve)
            .as_ref()
            .map_err(|message| Error::Emulator(message.clone()))
    }

    fn resolve() -> std::result::Result<Self, String> {
        macro_rules! load {
            ($name:literal, $kind:ty) => {{
                let pointer = symbol($name)?;
                // SAFETY: the concrete function type is copied from the named
                // SDK declaration; no Rust aggregate is passed as a C vector.
                unsafe { std::mem::transmute::<*mut c_void, $kind>(pointer) }
            }};
        }
        Ok(Self {
            get_serror: load!(c"hv_vcpu_get_serror", GetBool),
            set_serror: load!(c"hv_vcpu_set_serror", SetBool),
            get_trap_exceptions: load!(c"hv_vcpu_get_trap_debug_exceptions", GetBool),
            set_trap_exceptions: load!(c"hv_vcpu_set_trap_debug_exceptions", SetBool),
            get_trap_registers: load!(c"hv_vcpu_get_trap_debug_reg_accesses", GetBool),
            set_trap_registers: load!(c"hv_vcpu_set_trap_debug_reg_accesses", SetBool),
            get_sme: load!(c"hv_vcpu_get_sme_state", GetSme),
            set_sme: load!(c"hv_vcpu_set_sme_state", SetSme),
            get_z: load!(c"hv_vcpu_get_sme_z_reg", GetVector),
            set_z: load!(c"hv_vcpu_set_sme_z_reg", SetVector),
            get_p: load!(c"hv_vcpu_get_sme_p_reg", GetVector),
            set_p: load!(c"hv_vcpu_set_sme_p_reg", SetVector),
            get_za: load!(c"hv_vcpu_get_sme_za_reg", GetZa),
            set_za: load!(c"hv_vcpu_set_sme_za_reg", SetZa),
            get_zt: load!(c"hv_vcpu_get_sme_zt0_reg", GetZt),
            set_zt: load!(c"hv_vcpu_set_sme_zt0_reg", SetZt),
            maximum_svl: load!(c"hv_sme_config_get_max_svl_bytes", GetMaximumSvl),
            get_icc: load!(c"hv_gic_get_icc_reg", GetIcc),
            set_icc: load!(c"hv_gic_set_icc_reg", SetIcc),
            invalidate_tlb: load!(c"hv_vcpu_invalidate_tlb", InvalidateTlb),
            create_gic: load!(c"hv_gic_state_create", CreateGicState),
            gic_size: load!(c"hv_gic_state_get_size", GicStateSize),
            gic_data: load!(c"hv_gic_state_get_data", GicStateData),
            set_gic: load!(c"hv_gic_set_state", SetGicState),
        })
    }
}

pub(super) fn check(status: hv_return_t, operation: &str) -> Result<()> {
    if status == HV_SUCCESS {
        Ok(())
    } else {
        Err(Error::Emulator(format!(
            "{operation}: {} ({status:#x})",
            hv_error_string(status)
        )))
    }
}
