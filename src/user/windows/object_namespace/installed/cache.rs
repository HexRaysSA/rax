//! Select the cache service by its fixed namespace and account identity.
use super::super::cache::{CacheMetadata, CacheServer, PORT_NAME, SERVICE_SID};
use super::*;

#[cfg(target_pointer_width = "64")]
mod lookup;

pub(in crate::user::windows::object_namespace) fn lookup_file(
    file: &std::fs::File,
) -> io::Result<Option<Arc<super::super::FileSection>>> {
    #[cfg(target_pointer_width = "64")]
    return lookup::file(file);
    #[cfg(not(target_pointer_width = "64"))]
    {
        let _ = file;
        Err(invalid(
            "translation-cache lookup requires a 64-bit host process",
        ))
    }
}

#[link(name = "advapi32")]
// SAFETY: Windows SDK SCM/account signatures; each call below supplies fixed
// local names, bounded initialized outputs and explicitly owned native handles.
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
    fn OpenServiceW(manager: Handle, name: *const u16, access: u32) -> Handle;
    fn QueryServiceStatusEx(
        service: Handle,
        class: u32,
        output: *mut u8,
        capacity: u32,
        returned: *mut u32,
    ) -> i32;
    fn CloseServiceHandle(handle: Handle) -> i32;
    fn LookupAccountNameW(
        system: *const u16,
        name: *const u16,
        sid: *mut c_void,
        sid_bytes: *mut u32,
        domain: *mut u16,
        domain_characters: *mut u32,
        kind: *mut u32,
    ) -> i32;
}

struct ServiceHandle(Handle);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: sole ownership of a successful SCM/service open. These are
        // SCM handles, so the object-manager NtClose adapter is not used.
        unsafe { CloseServiceHandle(self.0) };
    }
}

pub(in super::super) fn select(
    namespace: &mut Namespace,
    kernel: (u32, u32, u32),
) -> io::Result<()> {
    if kernel != (10, 0, 29704) || namespace.native_machine != Some(0xAA64) {
        // Other profiles remain explicitly unselected at guest connect time.
        return Ok(());
    }
    match namespace.lookup_port(&PORT_NAME.encode_utf16().collect::<Vec<_>>()) {
        Ok(()) => {}
        Err(LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND)) => {
            return Ok(());
        }
        Err(_) => {
            return Err(invalid(
                "translation-cache namespace identity is unavailable",
            ));
        }
    }
    // SAFETY: fixed local SCM, no caller-supplied machine/database or access.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), 1) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = ServiceHandle(manager);
    let name: Vec<u16> = "XtaCache\0".encode_utf16().collect();
    // SAFETY: live SCM handle, fixed NUL-terminated service name and query-only
    // SERVICE_QUERY_STATUS. Returned ownership is local and closes on all paths.
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), 4) };
    if service.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = ServiceHandle(service);
    let mut status = [0u32; 9];
    let mut returned = 0;
    // SAFETY: owned query-only service, SC_STATUS_PROCESS_INFO and initialized
    // exclusive SERVICE_STATUS_PROCESS (nine DWORDs, 36 bytes) output.
    if unsafe { QueryServiceStatusEx(service.0, 0, status.as_mut_ptr().cast(), 36, &mut returned) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // pcbBytesNeeded is specified for an insufficient-buffer failure; do not
    // require a particular value after a successful fixed-size status query.
    if status[1] != 4 || status[7] == 0 || status[7] % 4 != 0 {
        return Err(invalid(
            "translation-cache port has no captured running service identity",
        ));
    }
    let account: Vec<u16> = "NT SERVICE\\XtaCache\0".encode_utf16().collect();
    let mut sid = [0u64; 9];
    let mut sid_bytes = 72;
    let mut domain = [0u16; 256];
    let mut domain_characters = 256;
    let mut kind = 0;
    // SAFETY: fixed local account name and initialized, aligned, exclusively
    // owned bounded SID/domain buffers. Native code retains no pointers.
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_bytes,
            domain.as_mut_ptr(),
            &mut domain_characters,
            &mut kind,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the full 72-byte initialized local SID scratch is readable for
    // this borrow, which does not escape or alias any mutable native call.
    let sid = unsafe { std::slice::from_raw_parts(sid.as_ptr().cast::<u8>(), 72) };
    // LookupAccountNameW may preserve input capacity. The SID header, rather
    // than that in/out capacity, determines the complete returned SID length.
    if sid_bytes > 72 || sid[0] != 1 || sid[1] != 6 || sid[..32] != SERVICE_SID || kind != 5 {
        return Err(invalid(
            "translation-cache service account SID differs from selected protocol",
        ));
    }
    namespace.select_cache_server(CacheServer::selected(CacheMetadata {
        kernel,
        native_machine: 0xAA64,
        server_pid: status[7],
    })?)
}
