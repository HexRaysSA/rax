//! Native AMD64 own-process CSR metadata, with bounded readonly PID decoding.
use crate::user::windows::object_namespace::csr::CsrMetadata;
use crate::user::windows::object_namespace::data::DataRegion;
use std::io;

pub(super) fn capture(regions: &[DataRegion]) -> io::Result<Option<CsrMetadata>> {
    // A compatibility x64 view of an ARM64 kernel cannot select this profile.
    if super::super::section::native_machine()? != Some(0x8664) {
        return Ok(None);
    }
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
    // SAFETY: named no-argument PEB getter in the already-loaded system NTDLL.
    // The PID export is decoded below and is never invoked.
    let get_peb: unsafe extern "system" fn() -> *const c_void =
        unsafe { std::mem::transmute(peb_getter) };
    let peb_address = unsafe { get_peb() } as u64;
    let mut peb = [0; 0x388];
    read(peb_address, &mut peb)?;
    if !crate::user::windows::object_namespace::csr::supports_profile(
        WinArch::X64,
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
    let base = module as u64;
    let mut dos = [0; 64];
    read(base, &mut dos)?;
    if dos[..2] != *b"MZ" {
        return Ok(None);
    }
    let offset = u32::from_le_bytes(dos[60..64].try_into().expect("fixed PE offset"));
    if !(64..=1_048_576).contains(&offset) {
        return Ok(None);
    }
    let Some(header_address) = base.checked_add(u64::from(offset)) else {
        return Ok(None);
    };
    let mut header = [0; 88];
    read(header_address, &mut header)?;
    if header[..4] != *b"PE\0\0"
        || u16::from_le_bytes(header[4..6].try_into().expect("fixed PE machine")) != 0x8664
        || u16::from_le_bytes(header[24..26].try_into().expect("fixed PE magic")) != 0x20B
    {
        return Ok(None);
    }
    let size = u32::from_le_bytes(header[80..84].try_into().expect("fixed image size"));
    if !(4096..=64 * 1024 * 1024).contains(&size) {
        return Ok(None);
    }
    let Some(end) = base.checked_add(u64::from(size)) else {
        return Ok(None);
    };
    let entry = pid_getter as u64;
    let mut code = [0; 20];
    if entry < base || entry.checked_add(20).is_none_or(|next| next > end) {
        return Ok(None);
    }
    read(entry, &mut code)?;
    let Some(globals) =
        crate::user::windows::object_namespace::csr::pid_export::decode(&code, entry, base..end)
    else {
        return Ok(None);
    };
    let mut pid_bytes = [0; 8];
    let mut flag = [0; 1];
    read(globals.pid, &mut pid_bytes)?;
    read(globals.flag, &mut flag)?;
    let pid = if flag[0] == 0 {
        u64::from_le_bytes(pid_bytes)
    } else {
        0
    };
    let Ok(server_pid) = u32::try_from(pid) else {
        return Ok(None);
    };
    if server_pid == 0 || server_pid % 4 != 0 {
        return Ok(None);
    }
    Ok(Some(CsrMetadata {
        arch: WinArch::X64,
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
