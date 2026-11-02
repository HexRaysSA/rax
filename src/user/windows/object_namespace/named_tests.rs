//! Parent-directory failures differ from a private final synchronization name.
use super::*;

#[test]
fn native_named_objects_distinguish_missing_parent_from_private_leaf() {
    for session in [0, 42] {
        let namespace = super::super::reparse_tests::sample(session);
        let base = if session == 0 {
            "\\BaseNamedObjects".to_owned()
        } else {
            format!("\\Sessions\\{session}\\BaseNamedObjects")
        };
        let directory = namespace
            .lookup(None, &base.encode_utf16().collect::<Vec<_>>(), 0)
            .unwrap();
        for name in [
            format!("{base}\\MissingParent\\Leaf"),
            "MissingParent\\Leaf".to_owned(),
        ] {
            let root = (!name.starts_with('\\')).then(|| directory.clone());
            assert_eq!(
                namespace
                    .named(root, &name.encode_utf16().collect::<Vec<_>>(), 0)
                    .unwrap_err(),
                LookupError::Status(STATUS_OBJECT_PATH_NOT_FOUND)
            );
        }
        for name in [format!("{base}\\PrivateLeaf"), "PrivateLeaf".to_owned()] {
            let root = (!name.starts_with('\\')).then(|| directory.clone());
            // Existence and type of this final component belong to the private
            // object table. The immutable directory snapshot only resolves its parent.
            assert!(
                namespace
                    .named(root, &name.encode_utf16().collect::<Vec<_>>(), 0)
                    .is_ok()
            );
        }
    }
}
