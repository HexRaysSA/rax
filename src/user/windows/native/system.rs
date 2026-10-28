//! Fixed pointer-free system metadata; guest arguments never enter host queries.

fn flush_profile(version: &super::WinVersion, machine: Option<u16>) -> bool {
    version.major == 10
        && version.minor == 0
        && matches!(
            (machine, version.build),
            (Some(0x8664), 20348 | 26100) | (Some(0xAA64), 29695)
        )
}

#[cfg(windows)]
pub(super) fn capture_flush(
    version: &super::WinVersion,
    machine: Option<u16>,
) -> Result<[u8; 32], String> {
    if !flush_profile(version, machine) {
        return Err("native SystemFlushInformation kernel profile is unmeasured".into());
    }
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
        // SAFETY: a fixed metadata class, exclusive aligned native buffer and
        // ULONG result. No guest pointer, size or class reaches this call.
        let status =
            unsafe { NtQuerySystemInformation(192, data.0.as_mut_ptr().cast(), 32, &mut returned) };
        if status != 0 || returned != 32 {
            return Err(format!(
                "native SystemFlushInformation status={status:#010x}, returned={returned}"
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
    Err("native SystemFlushInformation changed or left undefined bytes".into())
}

#[cfg(not(windows))]
pub(super) fn capture_flush(_: &super::WinVersion, _: Option<u16>) -> Result<[u8; 32], String> {
    Err("native SystemFlushInformation requires a Windows host".into())
}

#[cfg(test)]
mod flush_tests {
    use super::*;

    #[test]
    fn system_flush_admission_binds_exact_kernel_and_native_machine() {
        for (machine, build, expected) in [
            (Some(0x8664), 20348, true),
            (Some(0x8664), 26100, true),
            (Some(0xAA64), 29695, true),
            (Some(0xAA64), 20348, false),
            (Some(0x8664), 29695, false),
            (Some(0xAA64), 29694, false),
            (Some(0xAA64), 29696, false),
            (Some(0x14C), 20348, false),
            (None, 20348, false),
        ] {
            let mut version = super::super::WinVersion {
                major: 10,
                minor: 0,
                build,
                ..Default::default()
            };
            assert_eq!(flush_profile(&version, machine), expected);
            version.minor = 1;
            assert!(!flush_profile(&version, machine));
            version.minor = 0;
            version.major = 11;
            assert!(!flush_profile(&version, machine));
        }
    }
}

#[cfg(windows)]
pub(super) fn capture() -> Result<u32, String> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            output: *mut std::ffi::c_void,
            bytes: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let query = || {
        let mut words = [8u32, 0];
        let mut returned = 0;
        // SAFETY: fixed SystemCodeIntegrityInformation query (observed class103),
        // exclusive aligned eight-byte
        // structure with caller Length8, and exclusive ULONG ReturnLength.
        let status =
            unsafe { NtQuerySystemInformation(103, words.as_mut_ptr().cast(), 8, &mut returned) };
        if status != 0 || words[0] != 8 || returned != 8 {
            return Err(format!(
                "native code integrity query status={status:#010x}, length={}, returned={returned}",
                words[0]
            ));
        }
        Ok(words[1])
    };
    for _ in 0..3 {
        let before = query()?;
        if query()? == before {
            return Ok(before);
        }
    }
    Err("native code integrity changed during bounded capture".into())
}

#[cfg(not(windows))]
pub(super) fn capture() -> Result<u32, String> {
    Err("native Windows code integrity requires a Windows host".into())
}
