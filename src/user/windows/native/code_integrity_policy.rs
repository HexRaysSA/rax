//! Fixed, pointer-free SystemCodeIntegrityPolicyInformation snapshot.
//!
//! PHNT's pinned layout and native three-ABI controls live under
//! `docs/specifications/windows/native-code-integrity-policy/`.

#[cfg(windows)]
pub(super) fn capture() -> Result<[u8; 32], String> {
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
    struct Buffer([u8; 32]);
    let query = |poison| {
        let mut data = Buffer([poison; 32]);
        let mut returned = 0;
        // SAFETY: fixed read-only class164, exclusive initialized aligned
        // 32-byte buffer and ULONG result, live for the synchronous call.
        // Guest class, length and pointers never reach this host query.
        let status =
            unsafe { NtQuerySystemInformation(164, data.0.as_mut_ptr().cast(), 32, &mut returned) };
        if status != 0 || returned != 32 {
            return Err(format!(
                "native SystemCodeIntegrityPolicyInformation status={status:#010x}, returned={returned}"
            ));
        }
        Ok(data.0)
    };
    for _ in 0..3 {
        let first = query(0xA5)?;
        if query(0x5A)? == first {
            return Ok(first);
        }
    }
    Err(
        "native code integrity policy changed or left undefined bytes during bounded capture"
            .into(),
    )
}

#[cfg(not(windows))]
pub(super) fn capture() -> Result<[u8; 32], String> {
    Err("native code integrity policy requires a Windows host".into())
}
