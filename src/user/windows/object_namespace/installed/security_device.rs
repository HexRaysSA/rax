//! Capture only fixed device identity; no guest argument reaches a native API.
use super::{Attributes, Handle, Owned, Unicode};
use crate::user::windows::nt::status::STATUS_OBJECT_NAME_NOT_FOUND;
use crate::user::windows::object_namespace::security_device::{
    CNG_NAME, KSEC_DEVICE_TYPE, NAME, SRP_NAME, SecurityDevice,
};
use crate::user::windows::object_namespace::{Namespace, invalid};
use std::ffi::c_void;
use std::io;

#[repr(C)]
struct IoStatus {
    status: usize,
    information: usize,
}

// SAFETY: Windows SDK NT signatures with native pointer-width IO_STATUS_BLOCK.
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenFile(
        output: *mut Handle,
        access: u32,
        attributes: *const Attributes,
        io: *mut IoStatus,
        share: u32,
        options: u32,
    ) -> i32;
    fn NtQueryVolumeInformationFile(
        handle: Handle,
        io: *mut IoStatus,
        output: *mut c_void,
        bytes: u32,
        class: u32,
    ) -> i32;
}

// SAFETY: SDK registry ABI; all calls below are fixed, local, read-only queries.
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegGetValueW(
        key: Handle,
        subkey: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        output: *mut c_void,
        bytes: *mut u32,
    ) -> i32;
}

pub(in super::super) fn select(
    namespace: &mut Namespace,
    kernel: (u32, u32, u32),
) -> io::Result<()> {
    let Some(native_machine) = namespace.native_machine else {
        return Ok(());
    };
    let expected_revision = SecurityDevice::expected_revision(kernel, Some(native_machine));
    let server_2022 = SecurityDevice::supports_server_2022(kernel, native_machine);
    if expected_revision.is_none() && !server_2022 {
        return Ok(());
    }
    let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0"
        .encode_utf16()
        .collect();
    let value: Vec<u16> = "UBR\0".encode_utf16().collect();
    let mut revision = 0u32;
    let mut bytes = 4;
    // SAFETY: SDK HKEY_LOCAL_MACHINE pseudo-handle, fixed terminated names,
    // RRF_RT_REG_DWORD and exclusive initialized DWORD output. No guest data.
    let status = unsafe {
        RegGetValueW(
            0x8000_0002u32 as i32 as isize as Handle,
            subkey.as_ptr(),
            value.as_ptr(),
            0x10,
            std::ptr::null_mut(),
            (&mut revision as *mut u32).cast(),
            &mut bytes,
        )
    };
    if status != 0 || bytes != 4 {
        if server_2022 {
            return Ok(());
        }
        return Err(invalid("kernel security-device revision is unavailable"));
    }
    if server_2022 {
        // Only retain the identity fields obtained from a fixed read-only
        // open. Startup may proceed if this optional device is unavailable.
        if let Ok(device) = capture(NAME, kernel, revision, native_machine)
            && device.device_type == KSEC_DEVICE_TYPE
        {
            namespace.select_security_device(device)?;
        }
        return Ok(());
    }
    if Some(revision) != expected_revision {
        return Ok(());
    }
    namespace.select_security_device(capture(NAME, kernel, revision, native_machine)?)?;
    if kernel == (10, 0, 29708)
        && let Ok(device) = capture(CNG_NAME, kernel, revision, native_machine)
        && device.cng_profile()
    {
        namespace.select_cng_device(device)?;
    }
    Ok(())
}

fn open_readonly(path: &'static str, access: u32, options: u32, io: &mut IoStatus) -> (i32, Owned) {
    let mut units: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut name = Unicode {
        length: ((units.len() - 1) * 2) as u16,
        maximum: (units.len() * 2) as u16,
        buffer: units.as_mut_ptr(),
    };
    let attributes = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: std::ptr::null_mut(),
        name: &mut name,
        flags: 0x40,
        security: std::ptr::null_mut(),
        qos: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    // SAFETY: initialized native records, a fixed counted device name and
    // exclusive outputs. Callers supply fixed read-only access and options.
    let status = unsafe { NtOpenFile(&mut handle, access, &attributes, io, 7, options) };
    (status, Owned(handle))
}

pub(in super::super) fn srp_device_absent() -> bool {
    (0..2).all(|_| {
        let mut io = IoStatus {
            status: usize::MAX - 1,
            information: usize::MAX - 2,
        };
        let (status, handle) = open_readonly(SRP_NAME, 1, 0, &mut io);
        status.cast_unsigned() == STATUS_OBJECT_NAME_NOT_FOUND
            && handle.0.is_null()
            && io.status == usize::MAX - 1
            && io.information == usize::MAX - 2
    })
}

fn capture(
    path: &'static str,
    kernel: (u32, u32, u32),
    revision: u32,
    native_machine: u16,
) -> io::Result<SecurityDevice> {
    let mut io = IoStatus {
        status: 0,
        information: 0,
    };
    let (status, handle) = open_readonly(path, 0x100001, 0x20, &mut io);
    if status != 0 || handle.0.is_null() {
        return Err(invalid("selected kernel security-device open failed"));
    }
    let mut information = [0u32; 2];
    // SAFETY: owned synchronous file, aligned initialized eight-byte record,
    // exclusive IOSB and fixed FileFsDeviceInformation class. This synchronous
    // query finishes before the scratch or owned handle can be released.
    let status = unsafe {
        NtQueryVolumeInformationFile(handle.0, &mut io, information.as_mut_ptr().cast(), 8, 4)
    };
    if status != 0 || io.information != 8 {
        return Err(invalid("selected kernel security-device metadata changed"));
    }
    handle.close()?;
    Ok(SecurityDevice {
        kernel,
        revision,
        native_machine,
        device_type: information[0],
        characteristics: information[1],
    })
}
