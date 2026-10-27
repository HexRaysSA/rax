//! Readonly metadata from this initialized host process, bound to the captured
//! section alias. Neither guest values nor connection requests enter this path.
use crate::user::windows::object_namespace::csr::CsrMetadata;
use crate::user::windows::object_namespace::data::DataRegion;
use std::io;

#[cfg(target_arch = "aarch64")]
mod client_data;

pub(super) fn capture_client_data(
    metadata: &CsrMetadata,
) -> io::Result<
    Option<std::sync::Arc<crate::user::windows::object_namespace::csr::client_data::CsrClientData>>,
> {
    #[cfg(target_arch = "aarch64")]
    return client_data::capture(metadata).map(Some);
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = metadata;
        Ok(None)
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub(super) fn capture(_: &[DataRegion]) -> io::Result<Option<CsrMetadata>> {
    Ok(None)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn capture(regions: &[DataRegion]) -> io::Result<Option<CsrMetadata>> {
    use crate::user::windows::arch::WinArch;
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn GetCurrentProcessId() -> u32;
        fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
        fn ReadProcessMemory(
            process: *mut c_void,
            address: *const c_void,
            output: *mut c_void,
            bytes: usize,
            returned: *mut usize,
        ) -> i32;
    }
    fn read(address: u64, output: &mut [u8]) -> io::Result<()> {
        let mut got = 0usize;
        // SAFETY: current-process pseudo handle, bounded exclusive initialized
        // destination and SIZE_T output. RPM validates the opaque host address;
        // it is never dereferenced directly or derived from guest input.
        let ok = unsafe {
            ReadProcessMemory(
                (-1isize) as *mut c_void,
                address as *const c_void,
                output.as_mut_ptr().cast(),
                output.len(),
                &mut got,
            )
        };
        if ok == 0 || got != output.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn word(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("fixed host metadata span"),
        )
    }
    if regions.len() != 2
        || regions[0].offset != 0
        || regions[0].size != 5 * 4096
        || regions[1].offset != 5 * 4096
        || regions[1].size != (1 << 20) - 5 * 4096
        || regions[1].bytes.is_some()
    {
        return Ok(None);
    }
    let Some(prefix) = regions
        .first()
        .and_then(|r| r.bytes.as_ref())
        .and_then(|bytes| bytes.get(..128))
    else {
        return Ok(None);
    };
    let mut session = 0;
    // SAFETY: no inputs from guest; current host PID and initialized DWORD.
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if session != 0 {
        return Ok(None);
    }
    const NTDLL: [u16; 10] = [110, 116, 100, 108, 108, 46, 100, 108, 108, 0];
    // SAFETY: fixed terminated names in the process-lifetime installed NTDLL.
    let module = unsafe { GetModuleHandleW(NTDLL.as_ptr()) };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    let peb_getter = unsafe { GetProcAddress(module, c"RtlGetCurrentPeb".as_ptr().cast()) };
    let pid_getter = unsafe { GetProcAddress(module, c"CsrGetProcessId".as_ptr().cast()) };
    if peb_getter.is_null() || pid_getter.is_null() {
        return Ok(None);
    }
    // SAFETY: named no-argument NTDLL exports. The PEB getter returns a host
    // pointer; the CSR getter returns a pointer-width PID on this measured A64
    // ABI. The latter is invoked only after the build/layout/profile checks.
    let get_peb: unsafe extern "system" fn() -> *const c_void =
        unsafe { std::mem::transmute(peb_getter) };
    let get_pid: unsafe extern "system" fn() -> usize = unsafe { std::mem::transmute(pid_getter) };
    let peb_address = unsafe { get_peb() } as u64;
    let mut peb = [0; 0x388];
    read(peb_address, &mut peb)?;
    if !crate::user::windows::object_namespace::csr::supports_kernel(
        u32::from_le_bytes(peb[0x118..0x11C].try_into().expect("fixed major span")),
        u32::from_le_bytes(peb[0x11C..0x120].try_into().expect("fixed minor span")),
        u16::from_le_bytes(peb[0x120..0x122].try_into().expect("fixed build span")).into(),
    ) || u32::from_le_bytes(peb[0x2C0..0x2C4].try_into().expect("fixed session span")) != session
    {
        return Ok(None);
    }
    let local_base = word(&peb, 0x88);
    let Some(statics_offset) = word(&peb, 0x98).checked_sub(local_base) else {
        return Ok(None);
    };
    let server_base = word(&peb, 0x380);
    if local_base == 0
        || statics_offset != 0x750
        || server_base == 0
        || server_base % 65536 != 0
        || server_base
            .checked_add(1 << 20)
            .is_none_or(|end| end > 1 << 47)
        || prefix[40..48] != server_base.to_le_bytes()
        || prefix[48..56] != server_base.to_le_bytes()
    {
        return Ok(None);
    }
    let mut own_prefix = [0; 128];
    read(local_base, &mut own_prefix)?;
    if own_prefix.as_slice() != prefix {
        return Ok(None);
    }
    // SAFETY: verified current-process A64 build29683/29695 NTDLL export, no arguments
    // or guest callbacks. The independently observed implementation is a bounded
    // readonly load/CSEL/RET returning the pointer-width process identifier.
    let pid = unsafe { get_pid() };
    let Ok(server_pid) = u32::try_from(pid) else {
        return Ok(None);
    };
    if server_pid == 0 || server_pid % 4 != 0 {
        return Ok(None);
    }
    Ok(Some(CsrMetadata {
        arch: WinArch::Arm64,
        kernel: (
            u32::from_le_bytes(peb[0x118..0x11C].try_into().expect("fixed major span")),
            u32::from_le_bytes(peb[0x11C..0x120].try_into().expect("fixed minor span")),
            u16::from_le_bytes(peb[0x120..0x122].try_into().expect("fixed build span")).into(),
        ),
        session,
        server_base,
        statics_offset,
        server_pid,
    }))
}
