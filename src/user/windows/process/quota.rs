//! Installed native process-quota baseline, captured before guests execute.

use crate::user::windows::{arch::WinArch, native::NativeRuntime};

pub(crate) const CLASS: u32 = 1;
pub(crate) const BASIC_BYTES: u32 = 48;
pub(crate) const EXTENDED_BYTES: u32 = 88;
pub(crate) const WOW64_BASIC_BYTES: u32 = 32;
pub(crate) const WOW64_EXTENDED_BYTES: u32 = 56;
pub(crate) const WOW64_PADDING: std::ops::Range<usize> = 20..24;

pub(crate) struct Limits([u64; 11]);

impl Limits {
    pub(crate) fn select(runtime: Option<&NativeRuntime>, arch: WinArch) -> Option<Self> {
        let runtime = runtime?;
        let host_arch = runtime
            .object_namespace
            .native_machine
            .and_then(WinArch::from_machine);
        if (runtime.version.major, runtime.version.minor) != (10, 0)
            || !matches!(
                (arch, host_arch, runtime.version.build),
                (WinArch::Arm64, Some(WinArch::Arm64), 26200 | 29708)
                    | (WinArch::X86, Some(WinArch::Arm64), 29708)
                    | (WinArch::X64, Some(WinArch::X64), 26100)
            )
        {
            return None;
        }
        let limits = capture()?;
        // The measured 32-bit profile accepts representable SIZE_T values
        // and the all-ones sentinel. Other oversized values remain unqualified.
        if arch == WinArch::X86 && limits.wow64_encoded().is_none() {
            return None;
        }
        Some(limits)
    }

    pub(crate) fn encoded(&self) -> [u8; EXTENDED_BYTES as usize] {
        let mut bytes = [0; EXTENDED_BYTES as usize];
        for (out, value) in bytes.chunks_exact_mut(8).zip(self.0) {
            out.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn wow64_encoded(&self) -> Option<[u8; WOW64_EXTENDED_BYTES as usize]> {
        let mut bytes = [0; WOW64_EXTENDED_BYTES as usize];
        let sizes = self.0[..5].iter().chain(&self.0[6..10]);
        let (basic, extended) = bytes.split_at_mut(WOW64_BASIC_BYTES as usize);
        let fields = basic[..WOW64_PADDING.start]
            .chunks_exact_mut(4)
            .chain(extended[..16].chunks_exact_mut(4));
        for (value, out) in sizes.zip(fields) {
            let value = match *value {
                u64::MAX => u32::MAX,
                value => u32::try_from(value).ok()?,
            };
            out.copy_from_slice(&value.to_le_bytes());
        }
        basic[WOW64_PADDING.end..].copy_from_slice(&self.0[5].to_le_bytes());
        extended[16..].copy_from_slice(&self.0[10].to_le_bytes());
        Some(bytes)
    }

    #[cfg(test)]
    pub(crate) fn replay(words: [u64; 11]) -> Self {
        Self(words)
    }
}

#[cfg(windows)]
fn capture() -> Option<Limits> {
    use std::ffi::c_void;

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process: *mut c_void,
            class: u32,
            output: *mut c_void,
            bytes: u32,
            returned: *mut u32,
        ) -> i32;
    }

    let mut output = [0u64; 11];
    let mut returned = 0;
    // SAFETY: the fixed creator pseudo-handle and both private destinations
    // stay live through the read-only query. Guest requests use a guest copy.
    let status = unsafe {
        NtQueryInformationProcess(
            -1isize as *mut c_void,
            CLASS,
            output.as_mut_ptr().cast(),
            EXTENDED_BYTES,
            &mut returned,
        )
    };
    (status == 0 && returned == EXTENDED_BYTES).then_some(Limits(output))
}

#[cfg(not(windows))]
fn capture() -> Option<Limits> {
    None
}
