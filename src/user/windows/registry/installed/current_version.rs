//! Fixed read-only acquisition of CurrentVersion values and both view headers.
//! Every HKEY closes before guest execution; no descendant path is walked.
use super::super::{
    CURRENT_VERSION_KEY, CurrentVersionHeader, KeyAccess, RegistryView, WINDOWS_NT_KEY,
};
use super::*;

fn open(view: RegistryView) -> io::Result<OwnedKey> {
    open_subject(false, view)
}

fn open_subject(parent: bool, view: RegistryView) -> io::Result<OwnedKey> {
    let path = if parent {
        WINDOWS_NT_KEY
    } else {
        CURRENT_VERSION_KEY
    };
    let suffix = path
        .strip_prefix("\\Registry\\Machine\\")
        .expect("fixed HKLM subject");
    let name: Vec<_> = suffix.encode_utf16().chain(Some(0)).collect();
    let mut handle = null_mut();
    // SAFETY: fixed terminated path, fixed MAXIMUM_ALLOWED/view selection,
    // borrowed predefined HKLM and exclusive owned output. Native NtOpenKey
    // from a 64-bit caller does not apply Win32 view redirection itself.
    let status = unsafe {
        RegOpenKeyExW(
            (-2_147_483_646isize) as Hkey,
            name.as_ptr(),
            0,
            0x0200_0000 | view.flag(),
            &mut handle,
        )
    };
    if status == 0 && !handle.is_null() {
        Ok(OwnedKey(handle))
    } else {
        if !handle.is_null() {
            drop(OwnedKey(handle));
        }
        if status == 0 {
            Err(invalid("CurrentVersion open returned no owned handle"))
        } else {
            Err(io::Error::from_raw_os_error(status))
        }
    }
}

pub(super) fn capture(registry: Registry) -> io::Result<Registry> {
    let registry = capture_with(registry, open)?;
    capture_subject_with(registry, true, |view| open_subject(true, view))
}

fn capture_with(
    registry: Registry,
    opener: impl FnMut(RegistryView) -> io::Result<OwnedKey>,
) -> io::Result<Registry> {
    capture_subject_with(registry, false, opener)
}

fn capture_subject_with(
    mut registry: Registry,
    parent: bool,
    mut opener: impl FnMut(RegistryView) -> io::Result<OwnedKey>,
) -> io::Result<Registry> {
    let kind = if parent {
        super::super::ViewRoot::WindowsNt
    } else {
        super::super::ViewRoot::CurrentVersion
    };
    if registry.upcase.len() != 65_536
        || [RegistryView::Native64, RegistryView::Wow32]
            .iter()
            .any(|view| registry.views.roots.contains_key(&(kind, *view)))
    {
        return Err(invalid("invalid or duplicate CurrentVersion acquisition"));
    }
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let key = match opener(view) {
            Ok(key) => key,
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => {
                let status = if error.raw_os_error() == Some(2) {
                    0xC000_0034
                } else {
                    0xC000_003A
                };
                registry = if parent {
                    registry.with_current_version_parent(view, Err(status))?
                } else {
                    registry.with_current_version(view, Err(status))?
                };
                continue;
            }
            Err(error) => return Err(error),
        };
        let header = header(&registry, &key)?;
        drop(key);
        registry = if parent {
            registry.with_current_version_parent(view, Ok(header))?
        } else {
            registry.with_current_version(view, Ok(header))?
        };
    }
    Ok(registry)
}

fn header(registry: &Registry, key: &OwnedKey) -> io::Result<CurrentVersionHeader> {
    let budget = registry.value_budget()?;
    for _ in 0..3 {
        let canonical = canonical_hive_name(key, "CurrentVersion")?;
        let maximum_access = native_key::basic(key, "CurrentVersion")?;
        let system_security_status = match native_key::open(&canonical, 0x0100_0000) {
            Ok(security) => {
                if native_key::basic(&security, "CurrentVersion security")? & 0x0100_0000 == 0 {
                    return Err(invalid(
                        "CurrentVersion security grant lacks requested access",
                    ));
                }
                0
            }
            Err(0) => return Err(invalid("CurrentVersion security open returned no handle")),
            Err(status) => status,
        };
        let first = key_information::records(key)?;
        let (values, enumeration) = key_enumeration::stable(key, &budget, 0)?;
        let second = key_information::records(key)?;
        if first != second
            || canonical_hive_name(key, "CurrentVersion")? != canonical
            || native_key::basic(key, "CurrentVersion")? != maximum_access
        {
            continue;
        }
        return Ok(CurrentVersionHeader {
            key: super::super::CommandHeader {
                canonical,
                children: enumeration.len() as u32,
                enumeration: Some(enumeration),
                values,
                access: KeyAccess {
                    maximum_access,
                    system_security_status,
                },
            },
            information: first,
        });
    }
    Err(invalid(
        "CurrentVersion metadata changed during bounded capture",
    ))
}

#[cfg(test)]
#[path = "current_version_tests.rs"]
mod tests;
