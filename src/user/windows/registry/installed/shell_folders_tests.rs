use super::*;
use crate::user::windows::registry::{Key, Lookup, SnapshotRoot};
use std::sync::Arc;

fn compare(tree: CommandTree, key: Arc<Key>) -> usize {
    assert_eq!(tree.header.canonical, key.path);
    assert_eq!(tree.header.children, key.children);
    assert_eq!(tree.header.access, key.captured_access().unwrap());
    assert_eq!(tree.header.enumeration.as_deref(), key.child_metadata());
    assert_eq!(tree.header.values.len(), key.values.len());
    for value in tree.header.values {
        assert_eq!(key.value(&value.name), Some(&value));
    }
    let mut count = 1;
    for (name, child) in tree.children {
        let Lookup::Present(selected) = key.relative(&name) else {
            panic!("captured native child");
        };
        count += compare(child, selected);
    }
    count
}

#[test]
fn installed_shell_folders_capture_matches_native_views_and_retained_routes() {
    let context = crate::user::windows::wnf::snapshot().unwrap();
    let subject = context.primary_subject().unwrap().user.clone();
    let registry =
        crate::user::windows::registry::installed::shell_folders_subject(&subject).unwrap();
    let path = SnapshotRoot::ShellFolders.path(&subject).unwrap();
    let primary_path =
        crate::user::windows::registry::user_policy::user_hive_path(&subject).unwrap();
    let primary = registry.key(&primary_path);
    let relative = crate::user::windows::registry::shell_folders::SUFFIX
        .encode_utf16()
        .skip(1)
        .collect::<Vec<_>>();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        match open_snapshot(SnapshotRoot::ShellFolders, &subject, view) {
            Ok(native) => {
                let Lookup::Present(key) = registry.lookup_view(&path, view) else {
                    panic!("native Shell Folders exists");
                };
                let base = Registry::selected(registry.upcase_table().to_vec(), vec![]).unwrap();
                let tree =
                    subtree::capture(&base, SnapshotRoot::ShellFolders, &subject, view, native)
                        .unwrap();
                assert!(compare(tree, key) > 0);
                assert!(matches!(
                    primary.as_ref().unwrap().relative_in_view(&relative, view),
                    Lookup::Present(_)
                ));
            }
            Err(error) => assert!(matches!(
                (error.raw_os_error(), registry.lookup_view(&path, view)),
                (Some(2), Lookup::Missing) | (Some(3), Lookup::MissingPath)
            )),
        }
    }
    drop(registry);
    if let Some(primary) = primary {
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            assert!(!matches!(
                primary.relative_in_view(&relative, view),
                Lookup::Unselected
            ));
        }
    }
}

#[test]
fn installed_full_primary_capture_selects_shell_folders() {
    let context = crate::user::windows::wnf::snapshot().unwrap();
    let subject = context.primary_subject().unwrap().user.clone();
    let selected = crate::user::windows::registry::capture_primary_user(
        crate::user::windows::registry::snapshot().unwrap(),
        &subject,
    )
    .unwrap();
    let path = SnapshotRoot::ShellFolders.path(&subject).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        assert!(!matches!(
            selected.lookup_view(&path, view),
            Lookup::Unselected
        ));
    }
}
