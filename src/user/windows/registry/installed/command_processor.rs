//! Acquire complete fixed CMD subtrees, with a captured creator SID for HKU.
//! No guest path, view, access mask, callback or native handle survives capture.
use super::super::SnapshotRoot;
use super::super::{CommandHeader, CommandRoot, CommandTree, KeyAccess, RegistryView};
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
    registry: Registry,
    root: SnapshotRoot,
    sid: &[u8],
    opener: impl FnMut(SnapshotRoot, &[u8], RegistryView) -> io::Result<OwnedKey>,
) -> io::Result<Registry> {
    super::super::snapshot_root::capture::capture(
        registry,
        root,
        sid,
        &mut NativeSource { root, sid, opener },
    )
}

struct NativeSource<'a, F> {
    root: SnapshotRoot,
    sid: &'a [u8],
    opener: F,
}

impl<F> super::super::snapshot_root::capture::Source for NativeSource<'_, F>
where
    F: FnMut(SnapshotRoot, &[u8], RegistryView) -> io::Result<OwnedKey>,
{
    type Key = OwnedKey;

    fn open(&mut self, view: RegistryView) -> io::Result<OwnedKey> {
        (self.opener)(self.root, self.sid, view)
    }

    fn identity(&mut self, key: &OwnedKey) -> io::Result<(Vec<u16>, KeyAccess)> {
        let canonical = canonical_hive_name(key, self.root.label())?;
        let access = subtree::access(key, &canonical)?;
        Ok((canonical, access))
    }

    fn tree(
        &mut self,
        registry: &Registry,
        view: RegistryView,
        key: OwnedKey,
    ) -> io::Result<CommandTree> {
        subtree::capture(registry, self.root, self.sid, view, key)
    }
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
