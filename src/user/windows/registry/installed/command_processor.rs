//! Acquire only the fixed CMD leaves, with a captured creator SID for HKU.
//! No guest path, view, access mask, callback or native handle survives capture.
use super::super::{CommandHeader, CommandRoot, KeyAccess, RegistryView};
use super::*;
use crate::user::windows::nt::status::{
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

pub(super) fn capture_machine(registry: Registry) -> io::Result<Registry> {
    capture_with(registry, CommandRoot::Machine, &[], open)
}
pub(super) fn capture_user(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    capture_with(registry, CommandRoot::User, sid, open)
}

fn capture_with(
    mut registry: Registry,
    root: CommandRoot,
    sid: &[u8],
    mut opener: impl FnMut(CommandRoot, &[u8], RegistryView) -> io::Result<OwnedKey>,
) -> io::Result<Registry> {
    if registry.upcase.len() != 65_536
        || [RegistryView::Native64, RegistryView::Wow32]
            .iter()
            .any(|&view| registry.views.roots.contains_key(&(root.selection(), view)))
    {
        return Err(invalid(
            "invalid or duplicate Command Processor acquisition",
        ));
    }
    root.path(sid)?;
    if root == CommandRoot::User {
        registry.check_primary_hive_sid(sid)?;
    }
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let key = match opener(root, sid, view) {
            Ok(key) => key,
            Err(error) if error.raw_os_error() == Some(2) => {
                registry = registry.with_command_view(
                    root,
                    sid,
                    view,
                    Err(STATUS_OBJECT_NAME_NOT_FOUND),
                )?;
                continue;
            }
            Err(error) if error.raw_os_error() == Some(3) => {
                registry = registry.with_command_view(
                    root,
                    sid,
                    view,
                    Err(STATUS_OBJECT_PATH_NOT_FOUND),
                )?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let canonical = canonical_hive_name(&key, "Command Processor")?;
        registry.check_command_name(root, sid, view, &canonical)?;
        let maximum_access = super::native_key::basic(&key, "Command Processor")?;
        let system_security_status = match super::native_key::open(&canonical, 0x01000000) {
            Ok(security) => {
                if super::native_key::basic(&security, "Command Processor security")? & 0x01000000
                    == 0
                {
                    return Err(invalid(
                        "Command Processor security grant lacks requested access",
                    ));
                }
                0
            }
            Err(0) => {
                return Err(invalid(
                    "Command Processor security open returned no handle",
                ));
            }
            Err(status) => status,
        };
        let budget = registry.value_budget()?;
        let (children, values) = capture_stable_values(
            &key,
            MAX_VALUES - budget.count,
            super::super::MAX_TOTAL_BYTES - budget.bytes,
        )?;
        if super::native_key::basic(&key, "Command Processor")? != maximum_access {
            return Err(invalid("Command Processor grant changed during capture"));
        }
        registry = registry.with_command_view(
            root,
            sid,
            view,
            Ok(CommandHeader {
                canonical,
                children,
                values,
                access: KeyAccess {
                    maximum_access,
                    system_security_status,
                },
            }),
        )?;
    }
    Ok(registry)
}

fn open(root: CommandRoot, sid: &[u8], view: RegistryView) -> io::Result<OwnedKey> {
    let fixed = root.path(sid)?;
    let (hive, prefix) = match root {
        CommandRoot::Machine => (-2_147_483_646isize, "\\Registry\\Machine\\"),
        CommandRoot::User => (-2_147_483_645isize, "\\Registry\\User\\"),
    };
    let prefix: Vec<_> = prefix.encode_utf16().collect();
    let relative = fixed
        .strip_prefix(prefix.as_slice())
        .ok_or_else(|| invalid("fixed Command Processor path lacks native hive root"))?;
    let name: Vec<_> = relative.iter().copied().chain(Some(0)).collect();
    let mut handle = null_mut();
    // SAFETY: compile-time suffix, validated captured SID for HKU, fixed view
    // and access probe, terminated WCHAR storage and exclusive owned output.
    let status = unsafe {
        RegOpenKeyExW(
            hive as Hkey,
            name.as_ptr(),
            0,
            0x02000000 | view.flag(),
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
            Err(invalid("Command Processor open returned no handle"))
        } else {
            Err(io::Error::from_raw_os_error(status))
        }
    }
}

#[cfg(test)]
#[path = "command_processor_tests.rs"]
mod tests;
