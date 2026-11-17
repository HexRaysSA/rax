use super::*;
use crate::user::windows::registry::{Lookup, TreeRoot};

#[test]
fn child_image_registry_installed_startup_selection_matches_native_keys() {
    let selected = crate::user::windows::registry::snapshot().unwrap();
    let memory = TreeRoot::MemoryManagement;
    let memory_name: Vec<_> = memory.path().encode_utf16().collect();
    let memory_key = super::super::tree::open(memory, &memory_name).unwrap();
    let metadata = super::super::info(&memory_key).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let Lookup::Present(key) = selected.lookup_view(&memory_name, view) else {
            panic!("installed Memory Management key");
        };
        assert_eq!(key.children, metadata.children);
        assert_eq!(key.values.len(), metadata.values as usize);
        let jit = SnapshotRoot::Wow64X86Jit;
        let name = jit.path(&[]).unwrap();
        match open_snapshot(jit, &[], view) {
            Ok(native) => {
                let Lookup::Present(key) = selected.lookup_view(&name, view) else {
                    panic!("installed XtaJit subject");
                };
                let canonical = canonical_hive_name(&native, jit.label()).unwrap();
                let access = subtree::access(&native, &canonical).unwrap();
                assert_eq!(key.path, canonical);
                assert_eq!(key.captured_access(), Some(access));
            }
            Err(error) => assert!(matches!(
                (error.raw_os_error(), selected.lookup_view(&name, view)),
                (Some(2), Lookup::Missing) | (Some(3), Lookup::MissingPath)
            )),
        }
    }
}
