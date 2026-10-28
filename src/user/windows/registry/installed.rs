//! Fixed SYSTEM values and complete fixed subtrees during native selection.
//! No guest name reaches a host registry operation. All HKEYs close before
//! selection returns, and the kernel reads the resulting immutable records.
#[path = "installed/appmodel.rs"]
mod appmodel;
#[path = "installed/machine_hive.rs"]
mod machine_hive;
#[path = "installed/primary_hive.rs"]
mod primary_hive;
#[path = "installed/tree.rs"]
mod tree;
#[path = "installed/user_policy.rs"]
mod user_policy;
use super::SEGMENT_HEAP_KEY;
use super::{
    MAX_NAME_UNITS, MAX_VALUE_BYTES, MAX_VALUES, NLS_KEY, Registry, SESSION_MANAGER_KEY,
    SelectedKey, Value, WNF_KEY, invalid,
};
pub(crate) use primary_hive::capture as capture_primary_user;
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
    fn RegEnumKeyExW(
        key: Hkey,
        index: u32,
        name: *mut u16,
        length: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        class_length: *mut u32,
        time: *mut [u32; 2],
    ) -> i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlUpcaseUnicodeChar(value: u16) -> u16;
    fn NtQueryKey(
        key: Hkey,
        class: u32,
        information: *mut u32,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

fn canonical_hive_name(key: &OwnedKey, subject: &str) -> io::Result<Vec<u16>> {
    let mut words = vec![0u32; (4 + MAX_NAME_UNITS * 2).div_ceil(4)];
    let mut returned = 0xCCCC_CCCC;
    let capacity = (words.len() * 4) as u32;
    // SAFETY: live owned HKEY, KeyNameInformation=3, exclusive initialized
    // ULONG-aligned bounded output and result length; no retained pointers.
    let status = unsafe { NtQueryKey(key.0, 3, words.as_mut_ptr(), capacity, &mut returned) };
    if status != 0 {
        return Err(invalid(&format!(
            "{subject} hive name query failed: 0x{:08X}",
            status as u32
        )));
    }
    let bytes = words[0] as usize;
    if returned > capacity
        || returned < 4
        || bytes % 2 != 0
        || bytes > MAX_NAME_UNITS * 2
        || bytes + 4 > returned as usize
    {
        return Err(invalid(&format!(
            "native {subject} hive name exceeded its returned buffer"
        )));
    }
    Ok(words[1..]
        .iter()
        .flat_map(|&word| [word as u16, (word >> 16) as u16])
        .take(bytes / 2)
        .collect())
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
    max_child: u32,
    values: u32,
    max_name: u32,
    max_data: u32,
    time: [u32; 2],
}
fn info(key: &OwnedKey) -> io::Result<Info> {
    let mut i = Info {
        children: 0,
        max_child: 0,
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
            &mut i.max_child,
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
        return Err(invalid(
            "installed runtime registry metadata exceeds bounds",
        ));
    }
    Ok(i)
}
fn values(key: &OwnedKey, i: &Info, limit: usize) -> io::Result<Vec<Value>> {
    let mut result = Vec::new();
    let mut total = 0usize;
    // Reuse bounded enumeration scratch. Retained values copy only returned
    // units/bytes, so truncation cannot multiply maximum capacity by count.
    let mut name = vec![0u16; i.max_name as usize + 1];
    let mut data = vec![0u8; i.max_data as usize];
    for index in 0..i.values {
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
            return Err(invalid(
                "installed registry enumeration exceeded its buffers",
            ));
        }
        total = total
            .checked_add(name_len as usize * 2 + data_len as usize)
            .ok_or_else(|| invalid("installed registry snapshot size overflow"))?;
        if total > limit {
            return Err(invalid("installed registry snapshot too large"));
        }
        result.push(Value {
            name: name[..name_len as usize].to_vec(),
            kind,
            data: data[..data_len as usize].to_vec(),
        });
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}
fn capture(path: &'static str) -> io::Result<SelectedKey> {
    capture_values(path, open_fixed(path)?, MAX_VALUES, super::MAX_TOTAL_BYTES)
}
fn open_fixed(path: &'static str) -> io::Result<OwnedKey> {
    if !matches!(
        path,
        NLS_KEY | SESSION_MANAGER_KEY | SEGMENT_HEAP_KEY | WNF_KEY
    ) {
        return Err(invalid("native registry path outside fixed selection"));
    }
    let host = path
        .strip_prefix("\\Registry\\Machine\\")
        .ok_or_else(|| invalid("fixed registry path lacks HKLM root"))?;
    let name: Vec<u16> = host.encode_utf16().chain(Some(0)).collect();
    let mut handle = null_mut();
    // SAFETY: the predefined HKLM value is pointer-width sign extended;
    // path is terminated and fixed, output is exclusive, KEY_QUERY_VALUE=1.
    let s = unsafe {
        RegOpenKeyExW(
            (-2_147_483_646isize) as Hkey,
            name.as_ptr(),
            0,
            1,
            &mut handle,
        )
    };
    if s != 0 {
        return Err(io::Error::from_raw_os_error(s));
    }
    Ok(OwnedKey(handle))
}
fn capture_values(
    path: &'static str,
    key: OwnedKey,
    count_limit: usize,
    byte_limit: usize,
) -> io::Result<SelectedKey> {
    let (children, values) = capture_stable_values(&key, count_limit, byte_limit)?;
    Ok(SelectedKey {
        path,
        children,
        values,
    })
}

fn capture_stable_values(
    key: &OwnedKey,
    count_limit: usize,
    byte_limit: usize,
) -> io::Result<(u32, Vec<Value>)> {
    for _ in 0..3 {
        let before = info(key)?;
        if before.values as usize > count_limit {
            return Err(invalid(
                "installed fixed registry value count exceeds remaining budget",
            ));
        }
        let first = match values(key, &before, byte_limit) {
            Ok(values) => values,
            Err(error) if matches!(error.raw_os_error(), Some(234 | 259)) => continue,
            Err(error) => return Err(error),
        };
        let second = match values(key, &before, byte_limit) {
            Ok(values) => values,
            Err(error) if matches!(error.raw_os_error(), Some(234 | 259)) => continue,
            Err(error) => return Err(error),
        };
        let after = info(key)?;
        if before == after && first == second {
            return Ok((before.children, first));
        }
    }
    Err(invalid(
        "installed runtime registry key changed during bounded snapshot",
    ))
}

fn segment_heap(registry: &Registry) -> io::Result<Option<SelectedKey>> {
    segment_heap_with(registry, open_fixed)
}

/// Separate immutable WNF provisioning metadata; it does not expose another
/// guest registry key or retain the query-only native HKEY.
pub(crate) fn wnf_values() -> io::Result<Vec<Value>> {
    Ok(capture(WNF_KEY)?.values)
}
fn segment_heap_with(
    registry: &Registry,
    mut opener: impl FnMut(&'static str) -> io::Result<OwnedKey>,
) -> io::Result<Option<SelectedKey>> {
    let key = match opener(SEGMENT_HEAP_KEY) {
        Ok(key) => key,
        Err(error) if error.raw_os_error() == Some(2) => return Ok(None),
        Err(error) => return Err(error),
    };
    let budget = registry.value_budget()?;
    capture_values(
        SEGMENT_HEAP_KEY,
        key,
        MAX_VALUES - budget.count,
        super::MAX_TOTAL_BYTES - budget.bytes,
    )
    .map(Some)
}

pub(crate) fn snapshot() -> io::Result<Registry> {
    // Fixed shared SYSTEM keys and the complete IFEO subtree. Handles close in capture,
    // including error/retry paths; no native operation survives selection.
    let selected = [NLS_KEY, SESSION_MANAGER_KEY]
        .into_iter()
        .map(capture)
        .collect::<io::Result<Vec<_>>>()?;
    // SAFETY: pure one-WCHAR NTDLL lookup, no retained pointers or mutation.
    // One immutable table is shared by all selected keys, including surrogates.
    let upcase = (0..=u16::MAX)
        .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
        .collect();
    let registry = Registry::selected(upcase, selected)?;
    let segment = segment_heap(&registry)?;
    let registry = registry.with_segment_heap(segment)?;
    let registry = match tree::capture(&registry)? {
        Some(tree) => registry.with_ifeo(tree),
        None => registry.with_absent_ifeo(),
    }?;
    let root = super::TreeRoot::RedirectionKeys;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::SafeBootOption;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::SrpDll;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::SaferCodeIdentifiers;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::FileSystem;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::NlsSortingVersions;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::ErrorMessageInstrument;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::DisplayPolicy;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::GreInitialize;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::CommonGlobUserSettings;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::MuiSettings;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::MuiSystem;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    let root = super::TreeRoot::LanguageOverlayPackages;
    let selected = tree::capture_root(&registry, root)?;
    let registry = registry.with_tree(root, selected)?;
    machine_hive::capture(appmodel::capture(registry)?)
}

#[cfg(test)]
#[path = "installed_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "installed/redirection_tests.rs"]
mod redirection_tests;

#[cfg(test)]
#[path = "installed/safeboot_tests.rs"]
mod safeboot_tests;

#[cfg(test)]
#[path = "installed/srp_tests.rs"]
mod srp_tests;

#[cfg(test)]
#[path = "installed/safer_tests.rs"]
mod safer_tests;

#[cfg(test)]
#[path = "installed/user_policy_tests.rs"]
mod user_policy_tests;

#[cfg(test)]
#[path = "installed/filesystem_tests.rs"]
mod filesystem_tests;

#[cfg(test)]
#[path = "installed/nls_sorting_tests.rs"]
mod nls_sorting_tests;

#[cfg(test)]
#[path = "installed/error_message_instrument_tests.rs"]
mod error_message_instrument_tests;

#[cfg(test)]
#[path = "installed/display_policy_tests.rs"]
mod display_policy_tests;

#[cfg(test)]
#[path = "installed/gre_initialize_tests.rs"]
mod gre_initialize_tests;

#[cfg(test)]
#[path = "installed/common_glob_user_settings_tests.rs"]
mod common_glob_user_settings_tests;

#[cfg(test)]
#[path = "installed/mui_settings_tests.rs"]
mod mui_settings_tests;

#[cfg(test)]
#[path = "installed/mui_system_tests.rs"]
mod mui_system_tests;

#[cfg(test)]
#[path = "installed/language_overlay_packages_tests.rs"]
mod language_overlay_packages_tests;
