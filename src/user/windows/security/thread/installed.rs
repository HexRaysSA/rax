//! No guest identifier, handle, pointer or access request enters this adapter.
use super::Access;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_NO_TOKEN, STATUS_PRIVILEGE_NOT_HELD,
};
use std::ffi::c_void;
use std::ptr::null_mut;

type Handle = *mut c_void;
#[repr(C)]
struct Attributes {
    length: u32,
    root: Handle,
    name: *mut c_void,
    flags: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
#[repr(C)]
struct Client {
    process: Handle,
    thread: Handle,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcessId() -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn CreateThread(
        attrs: *const c_void,
        stack: usize,
        start: unsafe extern "system" fn(*mut c_void) -> u32,
        parameter: *mut c_void,
        flags: u32,
        tid: *mut u32,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenThreadToken(
        thread: Handle,
        desired: u32,
        open_as_self: u8,
        output: *mut Handle,
    ) -> i32;
    fn NtOpenThread(
        output: *mut Handle,
        desired: u32,
        attrs: *const Attributes,
        client: *const Client,
    ) -> i32;
    fn NtQueryObject(
        handle: Handle,
        class: u32,
        output: *mut c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}

struct Owned(Handle);
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: this private owner is created only from a successful native
        // open and is never copied into the emulated handle table.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn open(client: &Client, desired: u32) -> Result<Result<Owned, u32>, String> {
    let attrs = Attributes {
        length: size_of::<Attributes>() as u32,
        root: null_mut(),
        name: null_mut(),
        flags: 0,
        security: null_mut(),
        qos: null_mut(),
    };
    let mut handle = null_mut();
    // SAFETY: fully initialized native structures with exclusive HANDLE output;
    // `desired` is one of four fixed adapter masks, never a guest request.
    let status = unsafe { NtOpenThread(&mut handle, desired, &attrs, client) };
    if status < 0 {
        if !handle.is_null() {
            let _unexpected = Owned(handle);
            return Err("failed thread access capture returned a handle".into());
        }
        return Ok(Err(status as u32));
    }
    if handle.is_null() {
        return Err("thread access capture returned no handle".into());
    }
    Ok(Ok(Owned(handle)))
}

fn granted(handle: &Owned) -> Result<u32, String> {
    let mut data = [0u32; 14];
    let mut bytes = 0;
    // SAFETY: live private handle, initialized 56-byte output and ULONG slot.
    let status = unsafe { NtQueryObject(handle.0, 0, data.as_mut_ptr().cast(), 56, &mut bytes) };
    if status < 0 || bytes != 56 {
        return Err("thread opening grant is unavailable".into());
    }
    Ok(data[1])
}

pub(super) fn capture() -> Result<Access, String> {
    let mut token = null_mut();
    // SAFETY: fixed real current-thread pseudo-handle, TOKEN_QUERY and an
    // exclusive initialized output. Impersonation is not the primary subject.
    let status = unsafe { NtOpenThreadToken(-2isize as Handle, 8, 1, &mut token) };
    if !token.is_null() {
        let _token = Owned(token);
    }
    if status as u32 != STATUS_NO_TOKEN {
        return Err(
            "default-thread opening capture requires the primary subject without impersonation"
                .into(),
        );
    }
    unsafe extern "system" fn complete(_: *mut c_void) -> u32 {
        0
    }
    let mut tid = 0;
    // SAFETY: default security/stack, fixed no-argument callback returning zero,
    // no borrowed callback state. This adapter owns and joins the new thread.
    let handle = unsafe { CreateThread(std::ptr::null(), 0, complete, null_mut(), 0, &mut tid) };
    if handle.is_null() {
        return Err(format!(
            "default-thread access control: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _selected = Owned(handle);
    // SAFETY: private live thread handle; the fixed callback never blocks. Keep
    // the handle afterwards so the exited object's CLIENT_ID remains retained.
    if unsafe { WaitForSingleObject(handle, u32::MAX) } != 0 {
        return Err("default-thread access control did not join".into());
    }
    // SAFETY: no-argument identity query and the adapter's own returned TID.
    let client = unsafe {
        Client {
            process: GetCurrentProcessId() as usize as Handle,
            thread: tid as usize as Handle,
        }
    };
    let maximum = open(&client, 0x0200_0000)?
        .map_err(|status| format!("thread maximum access: {status:#010x}"))?;
    let value = granted(&maximum)?;
    let security = match open(&client, 0x0100_0000)? {
        Ok(handle) => {
            if granted(&handle)? != 0x0100_0000 {
                return Err("thread system-security grant changed".into());
            }
            0
        }
        Err(status @ (STATUS_ACCESS_DENIED | STATUS_PRIVILEGE_NOT_HELD)) => status,
        Err(status) => return Err(format!("thread system-security capture: {status:#010x}")),
    };
    let bypass = match open(&client, 0x0040_0000)? {
        Ok(handle) => {
            if granted(&handle)? != 0 {
                return Err("thread reserved-bit grant changed".into());
            }
            true
        }
        Err(STATUS_ACCESS_DENIED) => false,
        Err(status) => return Err(format!("thread reserved-bit capture: {status:#010x}")),
    };
    let maximum_security = match open(&client, 0x0300_0000)? {
        Ok(handle) if security == 0 => Some(granted(&handle)?),
        Err(status) if status == security => None,
        _ => return Err("thread security privilege changed during capture".into()),
    };
    if granted(&maximum)? != value {
        return Err("thread grant changed during capture".into());
    }
    Access::new(value, security, bypass, maximum_security)
        .ok_or_else(|| "thread opening ceiling is outside the supported mask".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn GetProcessHandleCount(process: Handle, count: *mut u32) -> i32;
    }
    fn handles() -> u32 {
        let mut count = 0;
        // SAFETY: fixed current-process pseudo-handle and exclusive DWORD output.
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
            0
        );
        count
    }
    #[test]
    fn native_thread_open_capture_joins_controls_and_closes_all_native_handles() {
        // Other Windows tests open real host handles. Use a dedicated test
        // process so their concurrent activity cannot invalidate this count.
        let qualified = concat!(
            module_path!(),
            "::native_thread_open_capture_joins_controls_and_closes_all_native_handles"
        );
        let name = qualified.split_once("::").unwrap().1;
        let exact = ["--exact", name, "--test-threads=1", "--nocapture"];
        if std::env::args().skip(1).collect::<Vec<_>>() != exact {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(exact)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("RAX_THREAD_CAPTURE_HANDLES_BALANCED")
            );
            return;
        }
        capture().unwrap(); // Resolve first-use native imports before counting.
        let before = handles();
        for _ in 0..8 {
            capture().unwrap();
        }
        assert_eq!(handles(), before);
        println!("RAX_THREAD_CAPTURE_HANDLES_BALANCED");
    }
}
