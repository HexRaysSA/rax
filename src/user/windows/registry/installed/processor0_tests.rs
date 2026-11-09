//! Matching-host comparison uses an independent retained native registry handle.
use super::*;
use crate::user::windows::registry::{Key, Lookup, PROCESSOR0_KEY};
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
fn installed_processor0_capture_matches_fixed_native_values_grants_and_shared_views() {
    let upcase = (0..=u16::MAX)
        .map(|u| {
            // SAFETY: Windows NTDLL takes and returns one initialized WCHAR by
            // value, with no pointers, retained state, mutation or unwind.
            // Each input is within the u16 ABI and this loop is thread-local.
            unsafe { RtlUpcaseUnicodeChar(u) }
        })
        .collect();
    let selected = capture_processor0(Registry::selected(upcase, vec![]).unwrap()).unwrap();
    let root = SnapshotRoot::Processor0;
    let path: Vec<_> = PROCESSOR0_KEY.encode_utf16().collect();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        match open_snapshot(root, &[], view) {
            Ok(native) => {
                let Lookup::Present(key) = selected.lookup_view(&path, view) else {
                    panic!("native subject exists")
                };
                let base = Registry::selected(selected.upcase_table().to_vec(), vec![]).unwrap();
                let tree = subtree::capture(&base, root, &[], view, native).unwrap();
                assert!(compare(tree, key) > 0);
            }
            Err(error) => assert!(matches!(
                (error.raw_os_error(), selected.lookup_view(&path, view)),
                (Some(2), Lookup::Missing) | (Some(3), Lookup::MissingPath)
            )),
        }
    }
}

#[test]
fn installed_processor0_full_startup_capture_selects_only_the_fixed_subject() {
    let selected = crate::user::windows::registry::snapshot().unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        assert!(!matches!(
            selected.lookup_view(&PROCESSOR0_KEY.encode_utf16().collect::<Vec<_>>(), view),
            Lookup::Unselected
        ));
        assert!(matches!(
            selected.lookup_view(
                &(PROCESSOR0_KEY.to_owned() + "Other")
                    .encode_utf16()
                    .collect::<Vec<_>>(),
                view
            ),
            Lookup::Unselected
        ));
    }
}
