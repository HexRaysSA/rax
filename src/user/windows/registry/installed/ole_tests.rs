use super::*;
use crate::user::windows::registry::{CommandTree, Lookup, MACHINE_HIVE_KEY, OLE_KEY};
fn compare(tree: CommandTree, key: std::sync::Arc<crate::user::windows::registry::Key>) -> usize {
    assert_eq!(tree.header.canonical, key.path);
    assert_eq!(tree.header.children, key.children);
    assert_eq!(tree.header.access, key.captured_access().unwrap());
    assert_eq!(tree.header.values.len(), key.values.len());
    assert_eq!(
        tree.header.enumeration.as_deref(),
        key.enumeration.as_deref()
    );
    for value in tree.header.values {
        assert_eq!(key.value(&value.name), Some(&value));
    }
    let mut count = 1;
    for (name, child) in tree.children {
        let Lookup::Present(selected) = key.relative(&name) else {
            panic!("captured native OLE child")
        };
        count += compare(child, selected);
    }
    count
}
#[test]
fn installed_ole_snapshot_matches_native_views_and_retains_machine_routes() {
    let registry = crate::user::windows::registry::snapshot().unwrap();
    let machine = registry
        .key(&MACHINE_HIVE_KEY.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let path = OLE_KEY.encode_utf16().collect::<Vec<_>>();
        match open_snapshot(SnapshotRoot::Ole, &[], view) {
            Ok(native) => {
                let Lookup::Present(key) = registry.lookup_view(&path, view) else {
                    panic!("native OLE")
                };
                let base = Registry::selected(registry.upcase_table().to_vec(), vec![]).unwrap();
                let tree = subtree::capture(&base, SnapshotRoot::Ole, &[], view, native).unwrap();
                let count = compare(tree, key);
                assert!(count > 0);
                eprintln!("native OLE {view:?}: {count} complete nodes");
                assert!(matches!(
                    machine.relative_in_view(
                        &"Software\\Microsoft\\OLE"
                            .encode_utf16()
                            .collect::<Vec<_>>(),
                        view
                    ),
                    Lookup::Present(_)
                ));
            }
            Err(e) => assert!(matches!(
                (e.raw_os_error(), registry.lookup_view(&path, view)),
                (Some(2), Lookup::Missing) | (Some(3), Lookup::MissingPath)
            )),
        }
    }
}
