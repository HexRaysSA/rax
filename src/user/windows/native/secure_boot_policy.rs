//! Read-only selection of the installed pointer-free secure boot policy.

pub(crate) const SYSTEM_SECURE_BOOT_POLICY_INFORMATION: u32 = 143;
pub(crate) const SECURE_BOOT_POLICY_BYTES: usize = 24;

#[cfg(all(windows, target_arch = "aarch64"))]
pub(super) fn capture() -> Result<[u8; SECURE_BOOT_POLICY_BYTES], String> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            output: *mut std::ffi::c_void,
            bytes: u32,
            returned: *mut u32,
        ) -> i32;
    }
    #[repr(align(8))]
    struct Buffer([u8; SECURE_BOOT_POLICY_BYTES]);

    let query = |poison| {
        let mut data = Buffer([poison; SECURE_BOOT_POLICY_BYTES]);
        let mut returned = u32::MAX;
        // SAFETY: the fixed query receives private aligned writable storage
        // and a live ULONG. No guest pointer, length, or class is forwarded.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_SECURE_BOOT_POLICY_INFORMATION,
                data.0.as_mut_ptr().cast(),
                SECURE_BOOT_POLICY_BYTES as u32,
                &mut returned,
            )
        };
        if status != 0 || returned != SECURE_BOOT_POLICY_BYTES as u32 {
            return Err(format!(
                "native SystemSecureBootPolicyInformation status={status:#010x}, returned={returned}"
            ));
        }
        Ok(data.0)
    };
    let first = query(0xA5)?;
    if first == query(0x5A)? {
        Ok(first)
    } else {
        Err("native SystemSecureBootPolicyInformation changed or left undefined bytes".into())
    }
}

#[cfg(not(all(windows, target_arch = "aarch64")))]
pub(super) fn capture() -> Result<[u8; SECURE_BOOT_POLICY_BYTES], String> {
    Err("native SystemSecureBootPolicyInformation requires a Windows ARM64 host".into())
}
