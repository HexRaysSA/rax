//! What this runtime is, for a launcher that has found it installed and
//! has to decide whether it is the one its program needs:
//! `rax_portable_x1_runtime`.

use rax_smir_portable::runtime::describe;

use super::{EINVAL, EIO, Status, guarded};

/// The major version of the host interface: that of the contract's
/// functions, `rax_portable_v1_*`.
pub const RAX_PORTABLE_ABI_MAJOR: u32 = 1;

/// The minor version: 0 is the contract's functions alone, and 1 adds the
/// extensions `rax_portable_x1_context_files`, `rax_portable_x1_module_link`
/// and `rax_portable_x1_runtime`.
pub const RAX_PORTABLE_ABI_MINOR: u32 = 1;

/// How many catalogs of services a description has room for.
pub const RAX_PORTABLE_SERVICE_CATALOGS: usize = 4;

/// A runtime, as it describes itself.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RaxPortableRuntimeX1 {
    /// The size of this structure and 1, set by the caller.
    pub size: u32,
    pub version: u32,
    pub abi_major: u32,
    pub abi_minor: u32,
    /// The implementation's revision, and the executable profile of the
    /// objects it runs.
    pub revision: u32,
    pub profile: u32,
    /// What tells this implementation from another.
    pub implementation: [u8; 32],
    /// The identity of the catalog of helpers.
    pub helpers: [u8; 32],
    /// How many catalogs of services there are, and their identities, the
    /// first catalog first; zeros in the rest.
    pub service_catalogs: u32,
    pub reserved0: u32,
    pub services: [[u8; 32]; RAX_PORTABLE_SERVICE_CATALOGS],
}

const _: () = assert!(size_of::<RaxPortableRuntimeX1>() == 224);

/// Describe this runtime. See `rax_portable_extensions_v1.h`.
///
/// `EINVAL` for a size or version that is not this structure's.
///
/// # Safety
///
/// `runtime` points to a `RaxPortableRuntimeX1`, or to at least the eight
/// bytes of its size and version if those are not this structure's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_x1_runtime(runtime: *mut RaxPortableRuntimeX1) -> Status {
    guarded(|| {
        if runtime.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: the caller's promise covers at least these two fields.
        let (size, version) = unsafe { ((*runtime).size, (*runtime).version) };
        if size as usize != size_of::<RaxPortableRuntimeX1>() || version != 1 {
            return Err(EINVAL);
        }
        let described = describe().map_err(|_| EIO)?;
        if described.services.len() > RAX_PORTABLE_SERVICE_CATALOGS {
            return Err(EIO);
        }
        let mut services = [[0; 32]; RAX_PORTABLE_SERVICE_CATALOGS];
        services[..described.services.len()].copy_from_slice(&described.services);
        // SAFETY: the structure is this one.
        unsafe {
            runtime.write(RaxPortableRuntimeX1 {
                size,
                version,
                abi_major: RAX_PORTABLE_ABI_MAJOR,
                abi_minor: RAX_PORTABLE_ABI_MINOR,
                revision: described.revision,
                profile: described.profile,
                implementation: described.implementation,
                helpers: described.helpers,
                service_catalogs: described.services.len() as u32,
                reserved0: 0,
                services,
            });
        }
        Ok(())
    })
}
