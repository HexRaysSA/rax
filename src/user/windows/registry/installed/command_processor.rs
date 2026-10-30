//! Acquire complete fixed CMD subtrees, with a captured creator SID for HKU.
//! No guest path, view, access mask, callback or native handle survives capture.
use super::super::SnapshotRoot;
use super::super::{CommandHeader, CommandRoot, KeyAccess, RegistryView};
use super::*;
use crate::user::windows::nt::status::{
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

#[path = "command_processor_tree.rs"]
mod subtree;

pub(super) fn capture_machine(registry: Registry) -> io::Result<Registry> {
    capture_with(registry, CommandRoot::Machine, &[], open)
}
pub(super) fn capture_system(registry: Registry) -> io::Result<Registry> {
    capture_with(registry, CommandRoot::System, &[], open)
}
pub(super) fn capture_user(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    capture_with(registry, CommandRoot::User, sid, open)
}

fn capture_with(
    registry: Registry,
    root: CommandRoot,
    sid: &[u8],
    mut opener: impl FnMut(CommandRoot, &[u8], RegistryView) -> io::Result<OwnedKey>,
) -> io::Result<Registry> {
    capture_snapshot_with(
        registry,
        SnapshotRoot::Command(root),
        sid,
        |_, sid, view| opener(root, sid, view),
    )
}

pub(super) fn capture_ole(registry: Registry) -> io::Result<Registry> {
    capture_snapshot_with(registry, SnapshotRoot::Ole, &[], open_snapshot)
}

pub(super) fn capture_local_settings(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    capture_snapshot_with(registry, SnapshotRoot::LocalSettings, sid, open_snapshot)
}

fn capture_snapshot_with(
    mut registry: Registry,
    root: SnapshotRoot,
    sid: &[u8],
    mut opener: impl FnMut(SnapshotRoot, &[u8], RegistryView) -> io::Result<OwnedKey>,
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
    if root.is_user() {
        registry.check_primary_hive_sid(sid)?;
    }
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let key = match opener(root, sid, view) {
            Ok(key) => key,
            Err(error) if error.raw_os_error() == Some(2) => {
                registry = registry.with_snapshot_selection(
                    root,
                    sid,
                    view,
                    Err(STATUS_OBJECT_NAME_NOT_FOUND),
                )?;
                continue;
            }
            Err(error) if error.raw_os_error() == Some(3) => {
                registry = registry.with_snapshot_selection(
                    root,
                    sid,
                    view,
                    Err(STATUS_OBJECT_PATH_NOT_FOUND),
                )?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let selected = subtree::capture(&registry, root, sid, view, key)?;
        registry = registry.with_snapshot_selection(
            root,
            sid,
            view,
            Ok((selected.header, Some(selected.children))),
        )?;
    }
    Ok(registry)
}

fn open(root: CommandRoot, sid: &[u8], view: RegistryView) -> io::Result<OwnedKey> {
    open_snapshot(SnapshotRoot::Command(root), sid, view)
}
fn open_path(
    root: CommandRoot,
    sid: &[u8],
    view: RegistryView,
    path: &[u16],
) -> io::Result<OwnedKey> {
    open_snapshot_path(SnapshotRoot::Command(root), sid, view, path)
}
fn open_snapshot(root: SnapshotRoot, sid: &[u8], view: RegistryView) -> io::Result<OwnedKey> {
    let path = root.path(sid)?;
    open_snapshot_path(root, sid, view, &path)
}

fn open_snapshot_path(
    root: SnapshotRoot,
    sid: &[u8],
    view: RegistryView,
    path: &[u16],
) -> io::Result<OwnedKey> {
    let fixed = root.path(sid)?;
    if path.len() > super::super::MAX_NAME_UNITS
        || path.contains(&0)
        || path != fixed && (!path.starts_with(&fixed) || path.get(fixed.len()) != Some(&92))
    {
        return Err(invalid("Command Processor path escapes fixed subtree"));
    }
    if root == SnapshotRoot::LocalSettings {
        return super::native_key::open_view(path, view).map_err(|status| match status {
            STATUS_OBJECT_NAME_NOT_FOUND => io::Error::from_raw_os_error(2),
            STATUS_OBJECT_PATH_NOT_FOUND => io::Error::from_raw_os_error(3),
            _ => invalid(&format!(
                "Local Settings native open failed: 0x{status:08X}"
            )),
        });
    }
    let (hive, prefix) = match root {
        SnapshotRoot::Command(CommandRoot::Machine | CommandRoot::System) | SnapshotRoot::Ole => {
            (-2_147_483_646isize, "\\Registry\\Machine\\")
        }
        SnapshotRoot::Command(CommandRoot::User) | SnapshotRoot::LocalSettings => {
            (-2_147_483_645isize, "\\Registry\\User\\")
        }
    };
    let prefix: Vec<_> = prefix.encode_utf16().collect();
    let relative = path
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

#[cfg(test)]
#[path = "command_processor_system_tests.rs"]
mod system_tests;

#[cfg(test)]
#[path = "ole_tests.rs"]
mod ole_tests;
