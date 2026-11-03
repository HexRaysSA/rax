//! Partial session membership keeps independently captured routes and grants.
use super::base_named_object_tests::table;
use super::*;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn entry(name: &str) -> CapturedEntry {
    CapturedEntry {
        name: wide(name),
        kind: wide("Directory"),
        target: None,
        link_access: None,
        section: None,
    }
}

fn directory(path: &str, access: u32, entries: Vec<CapturedEntry>) -> SelectedDirectory {
    SelectedDirectory {
        path: wide(path),
        maximum_access: access,
        force_case_insensitive: true,
        system_security_status: STATUS_PRIVILEGE_NOT_HELD,
        entries,
    }
}

fn captures(session: u32) -> Vec<SelectedDirectory> {
    let parent = format!("\\Sessions\\{session}");
    let mut children = vec![entry("Windows")];
    if session != 0 {
        children.push(entry("BaseNamedObjects"));
    }
    let mut records = vec![
        directory("\\", 0x20003, vec![entry("Sessions")]),
        directory("\\Sessions", 0x20003, vec![entry(&session.to_string())]),
        directory(&parent, 2, children),
        directory(&format!("{parent}\\Windows"), 0x20003, vec![]),
    ];
    if session != 0 {
        records.push(directory(
            &format!("{parent}\\BaseNamedObjects"),
            ALL_ACCESS,
            vec![],
        ));
    }
    records
}

pub(crate) fn sample(session: u32) -> Namespace {
    Namespace::selected_for_session_partial(
        table(),
        captures(session),
        Some(session),
        &[wide(&format!("\\Sessions\\{session}"))],
    )
    .unwrap()
}

#[test]
fn traverse_only_session_keeps_native_grants_and_unknown_membership() {
    for session in [0, 1, 42, u32::MAX] {
        let namespace = sample(session);
        let path = format!("\\Sessions\\{session}");
        let parent = namespace.lookup(None, &wide(&path), 0).unwrap();
        assert_eq!(parent.grant(0, false), Err(STATUS_ACCESS_DENIED));
        assert_eq!(parent.grant(2, false), Ok(2));
        assert_eq!(parent.grant(0x02000000, false), Ok(2));
        for access in [1, 3, 0x20000, 0xF000F] {
            assert_eq!(parent.grant(access, false), Err(STATUS_ACCESS_DENIED));
        }
        assert_eq!(
            parent.grant(0x01000000, false),
            Err(STATUS_PRIVILEGE_NOT_HELD)
        );
        assert_eq!(
            namespace
                .lookup(Some(parent.clone()), &wide("Uncaptured"), 0)
                .unwrap_err(),
            LookupError::Unselected
        );
        assert_eq!(
            namespace
                .lookup(None, &wide(&format!("{path}\\Uncaptured\\Child")), 0)
                .unwrap_err(),
            LookupError::Unselected
        );
        let windows = namespace.lookup(Some(parent), &wide("Windows"), 0).unwrap();
        assert_eq!(
            namespace
                .lookup(Some(windows), &wide("Missing"), 0)
                .unwrap_err(),
            LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }
}

#[test]
fn traverse_only_session_routes_keep_identity_after_catalog_drop() {
    for session in [0, 1, 42, u32::MAX] {
        let namespace = sample(session);
        let path = format!("\\Sessions\\{session}");
        let parent = namespace.lookup(None, &wide(&path), 0).unwrap();
        let absolute = namespace
            .lookup(None, &wide(&format!("{path}\\Windows")), 0)
            .unwrap();
        drop(namespace);
        let relative = Namespace::default()
            .lookup(Some(parent.clone()), &wide("wINDOWS"), 0)
            .unwrap();
        assert!(Arc::ptr_eq(&absolute, &relative));
        assert_eq!(relative.grant(3, false), Ok(3));
        assert_eq!(relative.grant(0, false), Err(STATUS_ACCESS_DENIED));
        if session != 0 {
            let child = Namespace::default()
                .lookup(Some(parent), &wide("basenamedobjects"), 0)
                .unwrap();
            assert_eq!(child.grant(0xF, false), Ok(0xF));
        }
    }
}
