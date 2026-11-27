//! Acquire complete fixed CMD subtrees, with a captured creator SID for HKU.
//! No guest path, view, access mask, callback or native handle survives capture.
use super::super::SnapshotRoot;
use super::super::snapshot_root::capture::SnapshotTree;
use super::super::{CommandHeader, CommandRoot, KeyAccess, RegistryView};
use super::*;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

#[path = "command_processor_tree.rs"]
pub(super) mod subtree;

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
    let registry = capture_snapshot_with(registry, SnapshotRoot::Ole, &[], open_snapshot)?;
    capture_snapshot_with(registry, SnapshotRoot::OleAutomation, &[], open_snapshot)
}

pub(super) fn capture_wow64_amd64(registry: Registry) -> io::Result<Registry> {
    capture_snapshot_with(registry, SnapshotRoot::Wow64Amd64, &[], open_snapshot)
}

pub(super) fn capture_wow64_x86_jit(registry: Registry) -> io::Result<Registry> {
    capture_snapshot_with(registry, SnapshotRoot::Wow64X86Jit, &[], open_snapshot)
}

pub(super) fn capture_processor0(registry: Registry) -> io::Result<Registry> {
    capture_snapshot_with(registry, SnapshotRoot::Processor0, &[], open_snapshot)
}

pub(super) fn capture_process_config_subtree(
    registry: Registry,
    root: SnapshotRoot,
) -> io::Result<Registry> {
    capture_snapshot_with(registry, root, &[], open_snapshot)
}

pub(super) fn capture_root_header(
    mut registry: Registry,
    root: SnapshotRoot,
) -> io::Result<Registry> {
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let selected = match open_snapshot(root, &[], view) {
            Ok(key) => {
                let canonical = canonical_hive_name(&key, root.label())?;
                root.check_name(&registry, &[], view, &canonical)?;
                Ok((
                    snapshot_header_for_key(&registry, &key, root.label(), canonical)?,
                    None,
                ))
            }
            Err(error) if error.raw_os_error() == Some(2) => Err(STATUS_OBJECT_NAME_NOT_FOUND),
            Err(error) if error.raw_os_error() == Some(3) => Err(STATUS_OBJECT_PATH_NOT_FOUND),
            Err(error) => return Err(error),
        };
        registry = registry.with_snapshot_selection(root, &[], view, selected)?;
    }
    Ok(registry)
}

pub(super) fn capture_local_settings(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    capture_snapshot_with(registry, SnapshotRoot::LocalSettings, sid, open_snapshot)
}

pub(super) fn capture_shell_folders(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    capture_snapshot_with(registry, SnapshotRoot::ShellFolders, sid, open_snapshot)
}

pub(super) fn capture_user_registry_policy(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    capture_user_header(registry, sid, SnapshotRoot::UserRegistryPolicy)
}

pub(super) fn capture_user_theme(registry: Registry, sid: &[u8]) -> io::Result<Registry> {
    let registry = capture_user_header(registry, sid, SnapshotRoot::ThemeManager)?;
    capture_user_header(registry, sid, SnapshotRoot::ThemePersonalize)
}

fn capture_user_header(
    mut registry: Registry,
    sid: &[u8],
    root: SnapshotRoot,
) -> io::Result<Registry> {
    let path = root.path(sid)?;
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let selected = match super::native_key::open_view(&path, view) {
            Ok(key) => {
                let canonical = canonical_hive_name(&key, root.label())?;
                root.check_name(&registry, sid, view, &canonical)?;
                Ok((
                    snapshot_header_for_key(&registry, &key, root.label(), canonical)?,
                    None,
                ))
            }
            Err(
                status @ (STATUS_OBJECT_NAME_NOT_FOUND
                | STATUS_OBJECT_PATH_NOT_FOUND
                | STATUS_ACCESS_DENIED),
            ) => Err(status),
            Err(status) => {
                return Err(invalid(&format!(
                    "{} native open failed: 0x{status:08X}",
                    root.label()
                )));
            }
        };
        registry = registry.with_snapshot_selection(root, sid, view, selected)?;
    }
    Ok(registry)
}

pub(super) fn capture_user_nt_current_version(
    mut registry: Registry,
    sid: &[u8],
) -> io::Result<Registry> {
    let root = SnapshotRoot::UserNtCurrentVersion;
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let (header, layers) = match open_snapshot(root, sid, view) {
            Ok(key) => {
                let header = snapshot_header(&registry, &key, root.label())?;
                root.check_name(&registry, sid, view, &header.canonical)?;
                let path: Vec<_> = header
                    .canonical
                    .iter()
                    .copied()
                    .chain(Some(92))
                    .chain(super::super::snapshot_root::CREATOR_COMPAT_LAYERS.encode_utf16())
                    .collect();
                let layers = match super::native_key::open_view(&path, view) {
                    Ok(owned) => Ok(snapshot_header(
                        &registry,
                        &owned,
                        "creator AppCompat Layers",
                    )?),
                    Err(code @ (STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND)) => {
                        Err(code)
                    }
                    Err(code) => {
                        return Err(invalid(&format!(
                            "creator Layers native open failed: 0x{code:08X}"
                        )));
                    }
                };
                (Ok(header), Some(layers))
            }
            Err(error) if error.raw_os_error() == Some(2) => {
                (Err(STATUS_OBJECT_NAME_NOT_FOUND), None)
            }
            Err(error) if error.raw_os_error() == Some(3) => {
                (Err(STATUS_OBJECT_PATH_NOT_FOUND), None)
            }
            Err(error) => return Err(error),
        };
        registry = registry.with_creator_current_version(sid, view, header, layers)?;
    }
    Ok(registry)
}

fn snapshot_header(registry: &Registry, key: &OwnedKey, label: &str) -> io::Result<CommandHeader> {
    let canonical = canonical_hive_name(key, label)?;
    snapshot_header_for_key(registry, key, label, canonical)
}

fn snapshot_header_for_key(
    registry: &Registry,
    key: &OwnedKey,
    label: &str,
    canonical: Vec<u16>,
) -> io::Result<CommandHeader> {
    let access = subtree::access(key, &canonical)?;
    let budget = registry.value_budget()?;
    let (values, children) = super::key_enumeration::stable(key, &budget, 0)?;
    if canonical_hive_name(key, label)? != canonical
        || super::native_key::basic(key, label)? != access.maximum_access
    {
        return Err(invalid(
            "registry key identity or grant changed during capture",
        ));
    }
    Ok(CommandHeader {
        canonical,
        children: children.len() as u32,
        enumeration: Some(children),
        values,
        access,
    })
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
    ) -> io::Result<SnapshotTree> {
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
pub(super) fn open_snapshot(
    root: SnapshotRoot,
    sid: &[u8],
    view: RegistryView,
) -> io::Result<OwnedKey> {
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
    if matches!(
        root,
        SnapshotRoot::LocalSettings | SnapshotRoot::Wow64Amd64 | SnapshotRoot::Wow64X86Jit
    ) {
        return super::native_key::open_view(path, view).map_err(|status| match status {
            STATUS_OBJECT_NAME_NOT_FOUND => io::Error::from_raw_os_error(2),
            STATUS_OBJECT_PATH_NOT_FOUND => io::Error::from_raw_os_error(3),
            _ => invalid(&format!(
                "{} native open failed: 0x{status:08X}",
                root.label()
            )),
        });
    }
    let (hive, prefix) = match root {
        SnapshotRoot::Command(CommandRoot::Machine | CommandRoot::System)
        | SnapshotRoot::Ole
        | SnapshotRoot::OleAutomation
        | SnapshotRoot::AutoEnrollment
        | SnapshotRoot::SideBySide
        | SnapshotRoot::Processor0
        | SnapshotRoot::Wow64Amd64
        | SnapshotRoot::Wow64X86Jit
        | SnapshotRoot::ProcessConfig(_) => (-2_147_483_646isize, "\\Registry\\Machine\\"),
        SnapshotRoot::Command(CommandRoot::User)
        | SnapshotRoot::LocalSettings
        | SnapshotRoot::ShellFolders
        | SnapshotRoot::UserNtCurrentVersion
        | SnapshotRoot::UserRegistryPolicy
        | SnapshotRoot::ThemeManager
        | SnapshotRoot::ThemePersonalize => (-2_147_483_645isize, "\\Registry\\User\\"),
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

#[cfg(test)]
#[path = "shell_folders_tests.rs"]
mod shell_folders_tests;

#[cfg(test)]
#[path = "wow64_amd64_tests.rs"]
mod wow64_amd64_tests;

#[cfg(test)]
#[path = "processor0_tests.rs"]
mod processor0_tests;

#[cfg(test)]
#[test]
fn installed_side_by_side_headers_match_fresh_native_views() {
    use crate::user::windows::registry::Lookup;

    let selected = super::snapshot().unwrap();
    let subject = SnapshotRoot::SideBySide;
    let path = subject.path(&[]).unwrap();
    let baseline = Registry::selected(selected.upcase_table().to_vec(), vec![]).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        match open_snapshot(subject, &[], view) {
            Ok(native) => {
                let header = snapshot_header(&baseline, &native, subject.label()).unwrap();
                let Lookup::Present(key) = selected.lookup_view(&path, view) else {
                    panic!("installed SideBySide header");
                };
                assert_eq!(header.canonical, key.path);
                assert_eq!(header.access, key.captured_access().unwrap());
                assert_eq!(header.enumeration.as_deref(), key.child_metadata());
                assert_eq!(header.values.len(), key.values.len());
                for value in header.values {
                    assert_eq!(key.value(&value.name), Some(&value));
                }
            }
            Err(error) => assert!(matches!(
                (error.raw_os_error(), selected.lookup_view(&path, view)),
                (Some(2), Lookup::Missing) | (Some(3), Lookup::MissingPath)
            )),
        }
    }
}

#[cfg(test)]
#[path = "child_image_keys_tests.rs"]
mod child_image_keys_tests;

#[cfg(test)]
#[test]
fn installed_user_nt_current_version_selects_the_creator_key_in_each_view() {
    use crate::user::windows::registry::Lookup;
    let context = crate::user::windows::wnf::snapshot().unwrap();
    let sid = &context.primary_subject().unwrap().user;
    // SAFETY: the same native one-WCHAR mapping used for acquired keys.
    let upcase = (0..=u16::MAX)
        .map(|unit| unsafe { RtlUpcaseUnicodeChar(unit) })
        .collect();
    let registry = Registry::selected(upcase, vec![]).unwrap();
    let registry = super::primary_hive::capture_header(registry, sid).unwrap();
    let selected = capture_user_nt_current_version(registry, sid).unwrap();
    let subject = SnapshotRoot::UserNtCurrentVersion;
    let path = subject.path(sid).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        match open_snapshot(subject, sid, view) {
            Ok(native) => {
                let Lookup::Present(key) = selected.lookup_view(&path, view) else {
                    panic!("native creator CurrentVersion exists");
                };
                assert_eq!(
                    canonical_hive_name(&native, subject.label()).unwrap(),
                    key.path
                );
                let (_, expected) =
                    super::key_enumeration::stable(&native, &Default::default(), 0).unwrap();
                assert_eq!(key.child_metadata(), Some(expected.as_slice()));
                assert!(key.captured_access().unwrap().grant(8).is_ok());
            }
            Err(error) => assert!(matches!(
                (error.raw_os_error(), selected.lookup_view(&path, view)),
                (Some(2), Lookup::Missing) | (Some(3), Lookup::MissingPath)
            )),
        }
    }
}

#[cfg(test)]
#[test]
fn installed_creator_compat_layers_matches_the_fixed_native_leaf() {
    use crate::user::windows::registry::Lookup;
    let context = crate::user::windows::wnf::snapshot().unwrap();
    let sid = &context.primary_subject().unwrap().user;
    // SAFETY: the same one-WCHAR native mapping used by the installed registry.
    let upcase = (0..=u16::MAX)
        .map(|unit| unsafe { RtlUpcaseUnicodeChar(unit) })
        .collect();
    let registry = Registry::selected(upcase, vec![]).unwrap();
    let registry = super::primary_hive::capture_header(registry, sid).unwrap();
    let selected = capture_user_nt_current_version(registry, sid).unwrap();
    let path = SnapshotRoot::UserNtCurrentVersion.path(sid).unwrap();
    let route: Vec<_> = super::super::snapshot_root::CREATOR_COMPAT_LAYERS
        .encode_utf16()
        .collect();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let Lookup::Present(parent) = selected.lookup_view(&path, view) else {
            // The native parent can be absent under a new user profile.
            assert!(open_snapshot(SnapshotRoot::UserNtCurrentVersion, sid, view).is_err());
            continue;
        };
        let native: Vec<_> = parent
            .path
            .iter()
            .copied()
            .chain(Some(92))
            .chain(route.iter().copied())
            .collect();
        let child = parent.relative(&route);
        match super::native_key::open_view(&native, view) {
            Ok(handle) => {
                let Lookup::Present(child) = child else {
                    panic!("native creator Layers exists");
                };
                let (values, children) =
                    super::key_enumeration::stable(&handle, &Default::default(), 0).unwrap();
                assert_eq!(
                    child.path,
                    canonical_hive_name(&handle, "creator Layers").unwrap()
                );
                assert_eq!(child.child_metadata(), Some(children.as_slice()));
                assert_eq!(child.values.len(), values.len());
                assert!(
                    values
                        .iter()
                        .all(|value| child.value(&value.name) == Some(value))
                );
            }
            Err(code) => assert!(matches!(
                (code, child),
                (STATUS_OBJECT_NAME_NOT_FOUND, Lookup::Missing)
                    | (STATUS_OBJECT_PATH_NOT_FOUND, Lookup::MissingPath)
            )),
        }
    }
}
