//! Query fixed startup values once during library selection.
use super::super::process_config::{
    CLR_ENABLE_64_BIT, CLR_USE_RYU_JIT, LEGACY_EXTENSION_FLAG, ProcessConfigKey,
    SYSTEM_SETUP_VALUES,
};
use super::super::{CommandHeader, RegistryView, SnapshotRoot};
use super::*;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

pub(super) fn capture(mut registry: Registry) -> io::Result<Registry> {
    for subject in ProcessConfigKey::ALL {
        let root = SnapshotRoot::ProcessConfig(subject);
        if subject.captures_subtree() {
            registry = super::command_processor::capture_process_config_subtree(registry, root)?;
            continue;
        }
        let path = root.path(&[])?;
        // CMD uses the native view for these two distinct AppCompatFlags paths.
        let views: &[_] = match subject {
            ProcessConfigKey::MachineAppCompatFlags | ProcessConfigKey::OsDataAppCompatFlags => {
                &[RegistryView::Native64]
            }
            _ => &[RegistryView::Native64, RegistryView::Wow32],
        };
        for &view in views {
            let opened = if subject.uses_win32_framework_view() {
                // The Win32 HKLM open applies the WOW64 view to this redirected
                // key even when the snapshot is collected by an ARM64 process.
                match super::command_processor::open_snapshot(root, &[], view) {
                    Ok(key) => Ok(key),
                    Err(error) => Err(match error.raw_os_error() {
                        Some(2) => STATUS_OBJECT_NAME_NOT_FOUND,
                        Some(3) => STATUS_OBJECT_PATH_NOT_FOUND,
                        Some(5) => STATUS_ACCESS_DENIED,
                        _ => return Err(error),
                    }),
                }
            } else {
                super::native_key::open_view(&path, view)
            };
            let selected = match opened {
                Ok(key) => {
                    let canonical = canonical_hive_name(&key, subject.label())?;
                    subject.check_name(&registry, view, &canonical)?;
                    let mut build_key_record = None;
                    let header = capture_header(&registry, subject, &key, canonical, || {
                        if subject == ProcessConfigKey::DotNetFusion {
                            return capture_values_with(&key, || {
                                verify_fusion_values_absent(&key, subject.values())
                            });
                        }
                        if !subject.preserves_value_order() {
                            return capture_values(&key, subject.values());
                        }
                        let before = super::key_information::cached_record(&key)?;
                        let values = if subject == ProcessConfigKey::DotNetFramework {
                            capture_values_with(&key, || {
                                let values = query_selected(&key, subject.values())?;
                                order_framework_values(&key, &registry, &before, values)
                            })?
                        } else {
                            capture_values(&key, subject.values())?
                        };
                        if super::key_information::cached_record(&key)? != before {
                            return Err(invalid(
                                ".NET Framework policy values changed during capture",
                            ));
                        }
                        build_key_record = Some(before);
                        Ok(values)
                    });
                    let header = match header {
                        Err(error)
                            if subject == ProcessConfigKey::DotNetFusion
                                && error.raw_os_error() == Some(5) =>
                        {
                            Err(STATUS_ACCESS_DENIED)
                        }
                        result => result?,
                    };
                    if subject.captures_cached_record()
                        && let Ok(header) = header
                    {
                        let cached = match build_key_record {
                            Some(record) => record,
                            None => super::key_information::cached_record(&key)?,
                        };
                        registry =
                            registry.with_cached_process_config(subject, view, header, cached)?;
                        continue;
                    }
                    header.map(|header| (header, None))
                }
                Err(
                    status @ (STATUS_OBJECT_NAME_NOT_FOUND
                    | STATUS_OBJECT_PATH_NOT_FOUND
                    | STATUS_ACCESS_DENIED),
                ) => Err(status),
                Err(status) => {
                    return Err(invalid(&format!(
                        "{} native open failed: 0x{status:08X}",
                        subject.label()
                    )));
                }
            };
            registry = registry.with_snapshot_selection(root, &[], view, selected)?;
        }
    }
    capture_disabled_extensions(registry)
}

fn verify_fusion_values_absent(key: &OwnedKey, names: &[&str]) -> io::Result<Vec<Value>> {
    for name in names {
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let mut bytes = 0;
        // SAFETY: a live selection-owned handle, a fixed NUL-terminated name,
        // and a size output. No value bytes are requested.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut bytes,
            )
        };
        match status {
            2 => {}
            // A configured setting is outside the default startup snapshot.
            0 => return Err(io::Error::from_raw_os_error(5)),
            status => return Err(io::Error::from_raw_os_error(status)),
        }
    }
    Ok(Vec::new())
}

fn capture_disabled_extensions(registry: Registry) -> io::Result<Registry> {
    let subject = ProcessConfigKey::DisabledLegacyExtensions;
    let root = SnapshotRoot::ProcessConfig(subject);
    let view = RegistryView::Native64;
    let path = root.path(&[])?;
    let Ok(key) = super::native_key::open_view(&path, view) else {
        return Ok(registry);
    };
    let canonical = canonical_hive_name(&key, subject.label())?;
    subject.check_name(&registry, view, &canonical)?;
    let Ok(header) = capture_header(&registry, subject, &key, canonical, || {
        capture_values_with(&key, || Ok(disabled_extension_flag(&key)))
    })?
    else {
        return Ok(registry);
    };
    if !subject.accepts_values(view, &header.values) {
        return Ok(registry);
    }
    registry.with_snapshot_selection(root, &[], view, Ok((header, None)))
}

fn disabled_extension_flag(key: &OwnedKey) -> Vec<Value> {
    let name: Vec<_> = LEGACY_EXTENSION_FLAG
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let (mut kind, mut size, mut data) = (0, 4, [0_u8; 4]);
    // SAFETY: live read-only query of a fixed terminated name and four-byte
    // buffer. The guest projection contains exclusively the disabled DWORD.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null_mut(),
            &mut kind,
            data.as_mut_ptr(),
            &mut size,
        )
    };
    if status == 0 && kind == 4 && size == 4 && data == [0; 4] {
        vec![Value {
            name: name[..name.len() - 1].to_vec(),
            kind,
            data: data.to_vec(),
        }]
    } else {
        Vec::new()
    }
}

fn capture_header(
    registry: &Registry,
    subject: ProcessConfigKey,
    key: &OwnedKey,
    canonical: Vec<u16>,
    values: impl FnOnce() -> io::Result<(u32, Vec<Value>)>,
) -> io::Result<Result<CommandHeader, u32>> {
    let access = super::command_processor::subtree::access(key, &canonical)?;
    if access.maximum_access & 1 == 0 {
        return Ok(Err(STATUS_ACCESS_DENIED));
    }
    const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
    let (children, values, enumeration) = if subject.captures_child_membership()
        && access.maximum_access & KEY_ENUMERATE_SUB_KEYS != 0
    {
        let entries =
            super::key_enumeration::stable_child_membership(key, &registry.value_budget()?)?;
        (entries.len() as u32, Vec::new(), Some(entries))
    } else {
        let (children, values) = values()?;
        (children, values, None)
    };
    if canonical_hive_name(key, subject.label())? != canonical
        || super::native_key::basic(key, subject.label())? != access.maximum_access
    {
        return Err(invalid("process configuration key changed during capture"));
    }
    Ok(Ok(CommandHeader {
        canonical,
        children,
        enumeration,
        access,
        values,
    }))
}

pub(super) fn system_setup() -> io::Result<Option<SelectedKey>> {
    let key = match open_fixed(SYSTEM_SETUP_KEY) {
        Ok(key) => key,
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let (children, values) = capture_values(&key, SYSTEM_SETUP_VALUES)?;
    if values
        .iter()
        .any(|value| value.kind != 4 || value.data.len() != 4)
    {
        return Ok(None);
    }
    Ok(Some(SelectedKey {
        path: SYSTEM_SETUP_KEY,
        children,
        values,
    }))
}

fn capture_values(key: &OwnedKey, names: &[&str]) -> io::Result<(u32, Vec<Value>)> {
    capture_values_with(key, || query_selected(key, names))
}

fn query_selected(key: &OwnedKey, names: &[&str]) -> io::Result<Vec<Value>> {
    names
        .iter()
        .filter_map(|name| query(key, name).transpose())
        .collect()
}

fn order_framework_values(
    key: &OwnedKey,
    registry: &Registry,
    cached: &[u8],
    mut values: Vec<Value>,
) -> io::Result<Vec<Value>> {
    let native_count = u32::from_le_bytes(cached[20..24].try_into().expect("cached value count"));
    if native_count as usize != values.len() || values.is_empty() {
        return Ok(values);
    }
    let mut ordered = Vec::with_capacity(values.len());
    let capacity = values
        .iter()
        .map(|value| value.name.len())
        .max()
        .unwrap_or(0)
        + 1;
    let mut name = vec![0u16; capacity];
    for index in 0..native_count {
        let mut length = name.len() as u32;
        // SAFETY: the query-only handle and exclusive name/length buffer are
        // valid. Enumeration requests no value type, size or data.
        let status = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut length,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        let reported = name
            .get(..length as usize)
            .filter(|reported| reported.len() < name.len())
            .ok_or_else(|| invalid("CLR registry enumeration exceeded its name buffer"))?;
        let fold = |unit: u16| registry.upcase[usize::from(unit)];
        let matches = |value: &Value| {
            value
                .name
                .iter()
                .copied()
                .map(fold)
                .eq(reported.iter().copied().map(fold))
        };
        let Some(selected) = values.iter().position(matches) else {
            return Err(invalid("CLR registry value order changed during capture"));
        };
        let mut value = values.swap_remove(selected);
        value.name = reported.to_vec();
        ordered.push(value);
    }
    Ok(ordered)
}

fn capture_values_with(
    key: &OwnedKey,
    sample: impl Fn() -> io::Result<Vec<Value>>,
) -> io::Result<(u32, Vec<Value>)> {
    for _ in 0..3 {
        let before = stamp(key)?;
        let (first, second) = match sample().and_then(|first| Ok((first, sample()?))) {
            Ok(pair) => pair,
            Err(error) if error.raw_os_error() == Some(234) => continue,
            Err(error) => return Err(error),
        };
        let after = stamp(key)?;
        if before == after && first == second {
            return Ok((before.0, first));
        }
    }
    Err(invalid(
        "process configuration values changed during capture",
    ))
}

fn stamp(key: &OwnedKey) -> io::Result<(u32, [u32; 2])> {
    let (mut children, mut time) = (0, [0; 2]);
    // SAFETY: live selection-owned handle and independent DWORD/FILETIME outputs.
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut children,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut time,
        )
    };
    if status == 0 {
        Ok((children, time))
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

fn query(key: &OwnedKey, name: &str) -> io::Result<Option<Value>> {
    let dword_only = matches!(name, CLR_ENABLE_64_BIT | CLR_USE_RYU_JIT);
    let mut name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
    let (mut kind, mut bytes) = (0, 0);
    let query = |kind: &mut u32, bytes: &mut u32, data: Option<&mut [u8]>| {
        let data = data.map_or(null_mut(), |buffer| buffer.as_mut_ptr());
        // SAFETY: the fixed name is terminated and the length and kind outputs
        // are exclusive. The optional slice has at least the declared capacity.
        unsafe { RegQueryValueExW(key.0, name.as_ptr(), null_mut(), kind, data, bytes) }
    };
    match query(&mut kind, &mut bytes, None) {
        0 => {}
        2 => return Ok(None),
        status => return Err(io::Error::from_raw_os_error(status)),
    }
    if dword_only && (kind != 4 || bytes != 4) {
        return Ok(None);
    }
    let capacity = bytes as usize;
    if capacity > MAX_VALUE_BYTES {
        return Err(invalid(
            "installed process configuration value exceeds bounds",
        ));
    }
    // A non-null buffer for zero bytes distinguishes a data query from a size query.
    let mut data = vec![0; capacity.max(1)];
    let status = query(&mut kind, &mut bytes, Some(&mut data));
    match status {
        0 if dword_only && (kind != 4 || bytes != 4) => Ok(None),
        0 if bytes as usize <= capacity => {
            name.pop();
            data.truncate(bytes as usize);
            Ok(Some(Value { name, kind, data }))
        }
        0 => Err(invalid("process configuration query exceeded its capacity")),
        2 => Ok(None),
        status => Err(io::Error::from_raw_os_error(status)),
    }
}
