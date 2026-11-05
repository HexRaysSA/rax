//! Process-owned NT flags and the Win32 bit0/sticky-alignment translation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct State(u32);

impl Default for State {
    fn default() -> Self {
        // CREATE_DEFAULT_ERROR_MODE: native hard errors enabled, Win32 mode0.
        Self(1)
    }
}

impl State {
    pub(crate) fn select(native: bool) -> std::io::Result<Self> {
        if native {
            capture().map(Self)
        } else {
            Ok(Self::default())
        }
    }

    pub(crate) fn native(self) -> u32 {
        self.0
    }

    pub(crate) fn set_native(&mut self, mode: u32) {
        // The native setter preserves all ULONG bits and can clear mask 0x4.
        self.0 = mode;
    }

    pub(crate) fn public(self) -> u32 {
        self.0 ^ 1
    }

    pub(crate) fn set_public(&mut self, mode: u32) -> u32 {
        let previous = self.public();
        // SEM_NOALIGNMENTFAULTEXCEPT is sticky in the Win32 wrapper only.
        self.0 = (mode | (previous & 4)) ^ 1;
        previous
    }
}

#[cfg(windows)]
fn capture() -> std::io::Result<u32> {
    use std::ffi::c_void;
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process: *mut c_void,
            class: u32,
            output: *mut u32,
            bytes: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut mode = 0;
    let mut returned = 0;
    // SAFETY: the current creator pseudo-handle and two private aligned ULONG
    // destinations remain live through this synchronous read-only native query.
    // No guest pointer, handle or setter is passed to the host kernel.
    let status = unsafe {
        NtQueryInformationProcess((-1isize) as *mut c_void, 12, &mut mode, 4, &mut returned)
    };
    if status != 0 || returned != 4 {
        return Err(std::io::Error::other(format!(
            "creator error-mode query status={status:#010x} returned={returned}"
        )));
    }
    Ok(mode)
}

#[cfg(not(windows))]
fn capture() -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native Windows creator error mode requires a Windows host",
    ))
}
