//! Installed native process-quota baseline, captured before guests execute.

use crate::user::windows::{arch::WinArch, native::NativeRuntime};

pub(crate) const CLASS: u32 = 1;
pub(crate) const BASIC_BYTES: u32 = 48;
pub(crate) const EXTENDED_BYTES: u32 = 88;

pub(crate) struct Limits([u64; 11]);

impl Limits {
    pub(crate) fn select(runtime: Option<&NativeRuntime>, arch: WinArch) -> Option<Self> {
        let runtime = runtime?;
        if arch != WinArch::Arm64
            || runtime.object_namespace.native_machine != Some(0xAA64)
            || (
                runtime.version.major,
                runtime.version.minor,
                runtime.version.build,
            ) != (10, 0, 29708)
        {
            return None;
        }
        capture()
    }

    pub(crate) fn encoded(&self) -> [u8; EXTENDED_BYTES as usize] {
        let mut bytes = [0; EXTENDED_BYTES as usize];
        for (out, value) in bytes.chunks_exact_mut(8).zip(self.0) {
            out.copy_from_slice(&value.to_le_bytes());
        }
        bytes
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
