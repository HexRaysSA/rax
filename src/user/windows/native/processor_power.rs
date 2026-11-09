//! Fixed read-only processor metadata; no guest argument enters a host call.

#[cfg(windows)]
pub(crate) fn capture() -> Result<[u32; 6], String> {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemInfo(output: *mut c_void);
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtPowerInformation(
            level: u32,
            input: *const c_void,
            input_bytes: u32,
            output: *mut c_void,
            output_bytes: u32,
        ) -> i32;
    }
    #[repr(align(8))]
    struct SystemInfo([u8; 48]);
    let mut system = SystemInfo([0; 48]);
    // SAFETY: exclusive buffer covers both SDK SYSTEM_INFO layouts, with native
    // pointer alignment. Processor count is DWORD32 at offset32/20 respectively.
    unsafe { GetSystemInfo(system.0.as_mut_ptr().cast()) };
    let offset = if cfg!(target_pointer_width = "64") {
        32
    } else {
        20
    };
    let count = u32::from_le_bytes(system.0[offset..offset + 4].try_into().unwrap());
    if !(1..=64).contains(&count) {
        return Err(format!(
            "native processor group size {count} is outside 1..=64"
        ));
    }
    let mut records = [[0u32; 6]; 64];
    // SAFETY: fixed query11, no input, exclusive bounded native output. Neither
    // the query class, host buffer nor its size comes from the guest request.
    let status = unsafe {
        NtPowerInformation(
            11,
            std::ptr::null(),
            0,
            records.as_mut_ptr().cast(),
            count * 24,
        )
    } as u32;
    if status != 0 {
        return Err(format!("native ProcessorInformation status={status:#010x}"));
    }
    if records[0][0] != 0 {
        return Err("native ProcessorInformation did not identify processor0".into());
    }
    // Guest topology is one CPU. Do not expose the remaining host processors.
    Ok(records[0])
}

#[cfg(not(windows))]
pub(crate) fn capture() -> Result<[u32; 6], String> {
    Err("installed processor power metadata requires a Windows host".into())
}
