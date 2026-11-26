//! Query fixed startup values once during library selection.
use super::super::process_config::{LEGACY_EXTENSION_FLAG, ProcessConfigKey, SYSTEM_SETUP_VALUES};
use super::super::{CommandHeader, RegistryView, SnapshotRoot};
use super::*;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

pub(super) fn capture(mut registry: Registry) -> io::Result<Registry> {
    for subject in ProcessConfigKey::ALL {
        let root = SnapshotRoot::ProcessConfig(subject);
        if subject.winsock_catalog().is_some() {
            registry = super::command_processor::capture_winsock_catalog(registry, root)?;
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
            let opened = if subject.uses_dot_net_framework_view() {
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
                        if !subject.preserves_value_order() {
                            return capture_values(&key, subject.values());
                        }
                        let before = super::key_information::cached_record(&key)?;
                        let values = capture_values(&key, subject.values())?;
                        if super::key_information::cached_record(&key)? != before {
                            return Err(invalid(
                                ".NET Framework policy values changed during capture",
                            ));
                        }
                        build_key_record = Some(before);
                        Ok(values)
                    })?;
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
    capture_values_with(key, || {
        names
            .iter()
            .filter_map(|name| query(key, name).transpose())
            .collect()
    })
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
