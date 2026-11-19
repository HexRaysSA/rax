//! Query fixed startup values once during library selection.
use super::super::process_config::{ProcessConfigKey, SYSTEM_SETUP_VALUES};
use super::super::{CommandHeader, RegistryView, SnapshotRoot};
use super::*;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

pub(super) fn capture(mut registry: Registry) -> io::Result<Registry> {
    for subject in ProcessConfigKey::ALL {
        let root = SnapshotRoot::ProcessConfig(subject);
        let path = root.path(&[])?;
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let selected = match super::native_key::open_view(&path, view) {
                Ok(key) => {
                    let canonical = canonical_hive_name(&key, subject.label())?;
                    subject.check_name(&registry, view, &canonical)?;
                    capture_header(subject, &key, canonical)?.map(|header| (header, None))
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
    Ok(registry)
}

fn capture_header(
    subject: ProcessConfigKey,
    key: &OwnedKey,
    canonical: Vec<u16>,
) -> io::Result<Result<CommandHeader, u32>> {
    let access = super::command_processor::subtree::access(key, &canonical)?;
    if access.maximum_access & 1 == 0 {
        return Ok(Err(STATUS_ACCESS_DENIED));
    }
    let (children, values) = capture_values(key, subject.values())?;
    if canonical_hive_name(key, subject.label())? != canonical
        || super::native_key::basic(key, subject.label())? != access.maximum_access
    {
        return Err(invalid("process configuration key changed during capture"));
    }
    Ok(Ok(CommandHeader {
        canonical,
        children,
        enumeration: None,
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
    for _ in 0..3 {
        let before = stamp(key)?;
        let sample = || -> io::Result<Vec<Value>> {
            names
                .iter()
                .filter_map(|name| query(key, name).transpose())
                .collect()
        };
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
