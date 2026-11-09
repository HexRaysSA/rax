//! Actual fixed-subject acquisition, with no unrelated registry fixture source.
use super::*;
use crate::user::windows::registry::{Key, Lookup};
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
            panic!("native descendant")
        };
        count += compare(child, selected);
    }
    count
}

#[test]
fn installed_wow64_amd64_capture_matches_native_data_or_exact_absence_in_both_views() {
    let registry = crate::user::windows::registry::installed::wow64_amd64_subject().unwrap();
    let root = SnapshotRoot::Wow64Amd64;
    let path = root.path(&[]).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        match open_snapshot(root, &[], view) {
            Ok(native) => {
                let Lookup::Present(key) = registry.lookup_view(&path, view) else {
                    panic!("native subject exists")
                };
                let base = Registry::selected(registry.upcase_table().to_vec(), vec![]).unwrap();
                let tree = subtree::capture(&base, root, &[], view, native).unwrap();
                assert!(compare(tree, key) > 0);
            }
            Err(error) => assert!(matches!(
                (error.raw_os_error(), registry.lookup_view(&path, view)),
                (Some(2), Lookup::Missing) | (Some(3), Lookup::MissingPath)
            )),
        }
    }
}

#[test]
fn installed_full_startup_capture_selects_wow64_amd64_in_both_views() {
    let selected = crate::user::windows::registry::snapshot().unwrap();
    let path = SnapshotRoot::Wow64Amd64.path(&[]).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        assert!(!matches!(
            selected.lookup_view(&path, view),
            Lookup::Unselected
        ));
    }
}
