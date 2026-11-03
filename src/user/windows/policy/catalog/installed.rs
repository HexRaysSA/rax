//! Fixed, read-only host inputs; every host handle closes during selection.

use super::{Catalog, MAX_BLOB, capture_with, names};
use std::ffi::c_void;
use std::sync::Arc;

type Hkey = *mut c_void;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(key: Hkey, name: *const u16, options: u32, access: u32, out: *mut Hkey)
    -> i32;
    fn RegQueryValueExW(
        key: Hkey,
        name: *const u16,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        bytes: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}

#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryLicenseValue(
        name: *const Unicode,
        kind: *mut u32,
        data: *mut c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtQuerySystemInformation(
        class: u32,
        output: *mut c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}

fn qualify(catalog: &Catalog) -> Result<(), String> {
    let request = super::super::qualification_request();
    let expected = super::super::query(catalog, &request).map_err(|error| {
        format!("fixed native software-policy qualification request: {error:?}")
    })?;
    let mut output = vec![0xA5; expected.len()];
    #[repr(align(8))]
    struct Descriptor([u8; 32]);
    let mut descriptor = Descriptor([0; 32]);
    let ptr = std::mem::size_of::<usize>();
    descriptor.0[..ptr].copy_from_slice(&(request.as_ptr() as usize).to_le_bytes());
    descriptor.0[ptr..2 * ptr].copy_from_slice(&(output.as_mut_ptr() as usize).to_le_bytes());
    descriptor.0[2 * ptr..2 * ptr + 4].copy_from_slice(&(request.len() as u32).to_le_bytes());
    descriptor.0[2 * ptr + 4..2 * ptr + 8].copy_from_slice(&(output.len() as u32).to_le_bytes());
    let mut returned = 0;
    // SAFETY: fixed read-only class134 and QueryPolicy0 with a fixed system
    // name and zero data capacity. Descriptor and nested buffers are private,
    // initialized, aligned, bounded, and live for this synchronous call.
    // No guest name, operation, pointer, descriptor, or size is forwarded.
    let status = unsafe {
        NtQuerySystemInformation(
            134,
            descriptor.0.as_mut_ptr().cast(),
            if ptr == 4 { 20 } else { 32 },
            &mut returned,
        )
    };
    if status != 0 || returned != 32 || output != expected {
        return Err(format!(
            "native software-policy protocol qualification failed: status={status:#010x}, returned={returned}, reply_matches={}",
            output == expected
        ));
    }
    Ok(())
}

struct OwnedKey(Hkey);

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the successfully opened HKEY.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn raw(key: &OwnedKey) -> Result<Vec<u8>, String> {
    let name: Vec<_> = "ProductPolicy".encode_utf16().chain(Some(0)).collect();
    for _ in 0..3 {
        let (mut kind, mut size) = (0, 0);
        // SAFETY: live owned host key, fixed terminated value name, and
        // exclusive scalar outputs. No guest data reaches this operation.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status != 0 || kind != 3 || !(24..=MAX_BLOB).contains(&(size as usize)) {
            return Err(format!(
                "native ProductPolicy size query status={status}, kind={kind}, bytes={size}"
            ));
        }
        let mut data = vec![0; size as usize];
        // SAFETY: same fixed host name and key; initialized exclusive data is
        // bounded by MAX_BLOB and size is its actual available byte count.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut size,
            )
        };
        if status == 234 {
            continue;
        }
        if status != 0 || kind != 3 || size as usize != data.len() {
            return Err(format!(
                "native ProductPolicy capture status={status}, kind={kind}, bytes={size}"
            ));
        }
        return Ok(data);
    }
    Err("native ProductPolicy size changed during bounded capture".into())
}

// The selected kernel's native software-policy callback table also declares
// these names. They need not occur in the serialized ProductPolicy catalog.
const NATIVE_NAMES: &[&str] = &[
    "Kernel-Session-Machine-Identifier",
    "Security-SPP-GenuineLocalStatus",
    "Security-SPP-Reserved-TBLState",
    "Security-SPP-Reserved-TBLRemainingTime",
    "Security-SPP-Reserved-LocalHardwareId",
    "9882750d-0aa7-4801-bb9b-90ae56b7c2ab",
    "Kernel-OsProduct-PFN",
    "Kernel-OsProduct-ContentId",
    "Kernel-ExpirationDate",
    "ConsumeAddonPolicySet",
    "FDE6DEB3-F790-48FF-8F27-43461944FD3E",
    "CE163B38-1AEC-47AF-854D-FC90ABD6951C",
    "Microsoft-Reserved-24C26ACC-DE62-4303-88AD-6CD4F1447F18",
    "BF319B54-49B5-412B-8CC8-FC2C003D31AF",
];

pub(crate) fn capture() -> Result<Arc<Catalog>, String> {
    let path: Vec<_> = "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut handle = std::ptr::null_mut();
    // SAFETY: fixed terminated HKLM path, KEY_QUERY_VALUE|KEY_WOW64_64KEY;
    // exclusive output, with no guest path or access mask involved.
    let status = unsafe {
        RegOpenKeyExW(
            (-2_147_483_646isize) as Hkey,
            path.as_ptr(),
            0,
            0x101,
            &mut handle,
        )
    };
    if status != 0 {
        return Err(format!("native ProductOptions open status={status}"));
    }
    let key = OwnedKey(handle);
    for _ in 0..3 {
        let before = raw(&key)?;
        let mut selected = names(&before)?;
        selected.extend(
            NATIVE_NAMES
                .iter()
                .map(|name| name.encode_utf16().collect::<Vec<_>>()),
        );
        let catalog = capture_with(&selected, |name, data, kind, returned| {
            let name = Unicode {
                length: (name.len() * 2) as u16,
                maximum: (name.len() * 2) as u16,
                buffer: name.as_ptr(),
            };
            let output = if data.is_empty() {
                std::ptr::null_mut()
            } else {
                data.as_mut_ptr().cast()
            };
            // SAFETY: name comes from the bounded fixed host catalog or the
            // fixed native name list, and all pointers address live host-owned
            // initialized storage. This runs before guest execution; no guest
            // operation, policy name, pointer, or requested size is forwarded.
            unsafe { NtQueryLicenseValue(&name, kind, output, data.len() as u32, returned) as u32 }
        })?;
        if raw(&key)? == before {
            qualify(&catalog)?;
            return Ok(Arc::new(catalog));
        }
    }
    Err("native ProductPolicy changed during bounded native query capture".into())
}
