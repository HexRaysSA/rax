//! Fixed pointer-free system metadata; guest arguments never enter host queries.

pub(crate) const SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES2: u32 = 230;
pub(crate) const SYSTEM_CURRENT_TIME_ZONE_INFORMATION: u32 = 44;
pub(crate) const CURRENT_TIME_ZONE_INFORMATION_BYTES: usize = 172;

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        output: *mut std::ffi::c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}

#[cfg(windows)]
pub(crate) fn capture_current_time_zone()
-> Result<[u8; CURRENT_TIME_ZONE_INFORMATION_BYTES], String> {
    #[repr(align(4))]
    struct Buffer([u8; CURRENT_TIME_ZONE_INFORMATION_BYTES]);

    let query = |sentinel| {
        let mut record = Buffer([sentinel; CURRENT_TIME_ZONE_INFORMATION_BYTES]);
        let mut returned = 0;
        // SAFETY: fixed pointer-free host class and exclusively owned aligned
        // output buffers. No guest parameter is passed to the host service.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_CURRENT_TIME_ZONE_INFORMATION,
                record.0.as_mut_ptr().cast(),
                CURRENT_TIME_ZONE_INFORMATION_BYTES as u32,
                &mut returned,
            )
        };
        if status != 0 || returned as usize != CURRENT_TIME_ZONE_INFORMATION_BYTES {
            return Err(format!(
                "native time-zone query status={status:#010x}, returned={returned}"
            ));
        }
        Ok(record.0)
    };
    for _ in 0..3 {
        let record = query(0xA5)?;
        if query(0x5A)? == record {
            return Ok(record);
        }
    }
    Err("native time-zone information changed or left undefined bytes".into())
}

#[cfg(not(windows))]
pub(crate) fn capture_current_time_zone()
-> Result<[u8; CURRENT_TIME_ZONE_INFORMATION_BYTES], String> {
    Err("native time-zone information requires a Windows host".into())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SupportedArchitectures {
    pub(crate) system: [u8; 16],
    pub(crate) current_process: [u8; 16],
}

#[cfg(any(test, all(windows, target_arch = "aarch64")))]
const PROCESS_ARCHITECTURE_FLAG: u32 = 1 << 19;

#[cfg(any(test, all(windows, target_arch = "aarch64")))]
impl SupportedArchitectures {
    pub(crate) fn for_guest(system: [u32; 4], arch: super::WinArch) -> Option<Self> {
        let index = system
            .iter()
            .position(|word| *word as u16 == arch.machine())?;
        let mut current_process = system;
        current_process[index] |= PROCESS_ARCHITECTURE_FLAG;
        let encode = |words: [u32; 4]| {
            let mut bytes = [0; 16];
            for (field, word) in bytes.chunks_exact_mut(4).zip(words) {
                field.copy_from_slice(&word.to_le_bytes());
            }
            bytes
        };
        Some(Self {
            system: encode(system),
            current_process: encode(current_process),
        })
    }
}

#[cfg(all(windows, target_arch = "aarch64"))]
pub(super) fn capture_supported_architectures(
    runtime: &super::NativeRuntime,
    arch: super::WinArch,
) -> Result<SupportedArchitectures, String> {
    if runtime.object_namespace.native_machine != Some(0xAA64)
        || (
            runtime.version.major,
            runtime.version.minor,
            runtime.version.build,
        ) != (10, 0, 29708)
    {
        return Err("unmeasured Windows supported processor architectures profile".into());
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformationEx(
            class: u32,
            input: *const usize,
            input_bytes: u32,
            output: *mut u32,
            output_bytes: u32,
            returned: *mut u32,
        ) -> i32;
    }
    fn capture(subject: usize, poison: u32) -> Result<[u32; 4], String> {
        let mut words = [poison; 4];
        let mut returned = 0;
        // SAFETY: fixed metadata class and selector, naturally aligned
        // native input/output, and an exclusive ULONG result. The guest
        // cannot supply a host handle, address, length, or class.
        let status = unsafe {
            NtQuerySystemInformationEx(
                SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES2,
                &subject,
                8,
                words.as_mut_ptr(),
                16,
                &mut returned,
            )
        };
        if status != 0 || returned != 16 {
            return Err(format!(
                "native supported processor architectures status={status:#010x}, returned={returned}"
            ));
        }
        Ok(words)
    }
    let stable = |subject| -> Result<[u32; 4], String> {
        let first = capture(subject, 0xA5A5_A5A5)?;
        if capture(subject, 0x5A5A_5A5A)? != first {
            return Err("native supported processor architectures left unstable bytes".into());
        }
        Ok(first)
    };
    let system = stable(0)?;
    let current_process = stable(usize::MAX)?;
    // The admitted profile returns three nonzero machine entries and a zero
    // terminator. A process query differs only by the ARM64 Process flag.
    if system[0] as u16 != 0xAA64
        || system[1] as u16 != 0x014C
        || system[2] as u16 != 0x8664
        || system[3] != 0
        || system
            .iter()
            .any(|word| word & PROCESS_ARCHITECTURE_FLAG != 0)
        || current_process
            != [
                system[0] | PROCESS_ARCHITECTURE_FLAG,
                system[1],
                system[2],
                0,
            ]
    {
        return Err("native supported processor architecture records changed shape".into());
    }
    SupportedArchitectures::for_guest(system, arch)
        .ok_or_else(|| "selected guest machine is missing from the native architecture list".into())
}

#[cfg(not(all(windows, target_arch = "aarch64")))]
pub(super) fn capture_supported_architectures(
    _: &super::NativeRuntime,
    _: super::WinArch,
) -> Result<SupportedArchitectures, String> {
    Err("native supported processor architectures requires an ARM64 Windows host".into())
}

fn flush_profile(version: &super::WinVersion, machine: Option<u16>) -> bool {
    version.major == 10
        && version.minor == 0
        && matches!(
            (machine, version.build),
            (Some(0x8664), 20348 | 26100) | (Some(0xAA64), 29695 | 29698)
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
            (Some(0xAA64), 29698, true),
            (Some(0xAA64), 20348, false),
            (Some(0x8664), 29695, false),
            (Some(0xAA64), 29694, false),
            (Some(0xAA64), 29696, false),
            (Some(0xAA64), 29697, false),
            (Some(0xAA64), 29699, false),
            (Some(0x8664), 29698, false),
            (Some(0x14C), 29698, false),
            (None, 29698, false),
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
