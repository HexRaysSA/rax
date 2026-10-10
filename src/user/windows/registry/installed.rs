//! Fixed system NLS metadata acquisition during native runtime selection only.
//! No guest name reaches a host registry operation. All HKEYs close before
//! selection returns, and the kernel reads the resulting immutable records.
use super::{MAX_NAME_UNITS, MAX_VALUE_BYTES, MAX_VALUES, Registry, Value, invalid};
use std::ffi::c_void;
use std::io;
use std::ptr::null_mut;

type Hkey = *mut c_void;
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(key: Hkey, name: *const u16, options: u32, access: u32, out: *mut Hkey)
    -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
    fn RegQueryInfoKeyW(
        key: Hkey,
        class: *mut u16,
        class_len: *mut u32,
        reserved: *mut u32,
        children: *mut u32,
        max_child: *mut u32,
        max_class: *mut u32,
        values: *mut u32,
        max_name: *mut u32,
        max_data: *mut u32,
        security: *mut u32,
        time: *mut [u32; 2],
    ) -> i32;
    fn RegEnumValueW(
        key: Hkey,
        index: u32,
        name: *mut u16,
        name_len: *mut u32,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlUpcaseUnicodeChar(value: u16) -> u16;
}
struct OwnedKey(Hkey);
impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: this exclusive HKEY came from a successful fixed-key open.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Info {
    children: u32,
    values: u32,
    max_name: u32,
    max_data: u32,
    time: [u32; 2],
}
fn info(key: &OwnedKey) -> io::Result<Info> {
    let mut i = Info {
        children: 0,
        values: 0,
        max_name: 0,
        max_data: 0,
        time: [0; 2],
    };
    // SAFETY: live owned key; all optional pointers are NULL or exclusive,
    // correctly sized DWORD/FILETIME outputs. No reference survives this call.
    let s = unsafe {
        RegQueryInfoKeyW(
            key.0,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut i.children,
            null_mut(),
            null_mut(),
            &mut i.values,
            &mut i.max_name,
            &mut i.max_data,
            null_mut(),
            &mut i.time,
        )
    };
    if s != 0 {
        return Err(io::Error::from_raw_os_error(s));
    }
    if i.values as usize > MAX_VALUES
        || i.max_name as usize > MAX_NAME_UNITS
        || i.max_data as usize > MAX_VALUE_BYTES
    {
        return Err(invalid("installed NLS registry metadata exceeds bounds"));
    }
    Ok(i)
}
fn values(key: &OwnedKey, i: &Info) -> io::Result<Vec<Value>> {
    let mut result = Vec::new();
    let mut total = 0usize;
    for index in 0..i.values {
        let mut name = vec![0u16; i.max_name as usize + 1];
        let mut data = vec![0u8; i.max_data as usize];
        let (mut name_len, mut data_len, mut kind) = (name.len() as u32, data.len() as u32, 0);
        // SAFETY: exclusive output buffers with exact capacities in WCHARs
        // and bytes, live query-only key, and no retained pointers.
        let s = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if s != 0 {
            return Err(io::Error::from_raw_os_error(s));
        }
        if name_len as usize >= name.len() || data_len as usize > data.len() {
            return Err(invalid("installed NLS enumeration exceeded its buffers"));
        }
        name.truncate(name_len as usize);
        data.truncate(data_len as usize);
        total = total
            .checked_add(name.len() * 2 + data.len())
            .ok_or_else(|| invalid("installed NLS snapshot size overflow"))?;
        if total > super::MAX_TOTAL_BYTES {
            return Err(invalid("installed NLS snapshot too large"));
        }
        result.push(Value { name, kind, data });
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}
pub(crate) fn snapshot() -> io::Result<Registry> {
    const PATH: &str = "SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage";
    let path: Vec<u16> = PATH.encode_utf16().chain(Some(0)).collect();
    let mut handle = null_mut();
    // SAFETY: the predefined HKLM value is pointer-width sign extended;
    // path is terminated and fixed, output is exclusive, KEY_QUERY_VALUE=1.
    let s = unsafe {
        RegOpenKeyExW(
            (-2_147_483_646isize) as Hkey,
            path.as_ptr(),
            0,
            1,
            &mut handle,
        )
    };
    if s != 0 {
        return Err(io::Error::from_raw_os_error(s));
    }
    let key = OwnedKey(handle);
    for _ in 0..3 {
        let before = info(&key)?;
        let first = match values(&key, &before) {
            Ok(values) => values,
            Err(error) if matches!(error.raw_os_error(), Some(234 | 259)) => continue,
            Err(error) => return Err(error),
        };
        let second = match values(&key, &before) {
            Ok(values) => values,
            Err(error) if matches!(error.raw_os_error(), Some(234 | 259)) => continue,
            Err(error) => return Err(error),
        };
        let after = info(&key)?;
        if before == after && first == second {
            // SAFETY: pure one-WCHAR NTDLL case lookup, no pointers, retention
            // or mutation. Capture every UTF-16 code unit, including surrogates.
            let upcase = (0..=u16::MAX)
                .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
                .collect();
            return Registry::nls(upcase, first, before.children);
        }
    }
    Err(invalid(
        "installed NLS registry changed during bounded snapshot",
    ))
}

#[cfg(test)]
#[path = "installed_tests.rs"]
mod tests;
