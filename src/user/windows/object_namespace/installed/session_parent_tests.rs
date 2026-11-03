//! Native fixed-subject acquisition and canonical-name boundary checks.
use super::*;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn table() -> Vec<u16> {
    (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect()
}

#[test]
fn fixed_session_child_canonical_names_preserve_type_and_reject_escape() {
    for session in [0, 1, 42, u32::MAX] {
        let parent = wide(&format!("\\Sessions\\{session}"));
        let name = wide("Windows");
        let expected: Vec<_> = parent
            .iter()
            .copied()
            .chain([92])
            .chain(name.iter().copied())
            .collect();
        for link in [false, true] {
            let actual = entry(&parent, &name, expected.clone(), link).unwrap();
            assert_eq!(actual.name, name);
            assert_eq!(
                actual.kind,
                wide(if link { "SymbolicLink" } else { "Directory" })
            );
            assert!(
                actual.target.is_none() && actual.link_access.is_none() && actual.section.is_none()
            );
        }
        for bad in [
            vec![],
            wide("\\Windows"),
            wide("\\Sessions\\1Suffix\\Windows"),
            wide(&format!("\\Sessions\\{session}\\Other")),
            wide(&format!("\\Sessions\\{session}\\Windows\\Child")),
            vec![0; expected.len()],
        ] {
            assert!(entry(&parent, &name, bad, false).is_err());
        }
    }
}

#[test]
fn fixed_session_capture_rejects_other_subjects_before_native_calls() {
    let unused = Owned(null_mut());
    for path in [
        "\\",
        "\\Sessions",
        "\\Sessions\\0",
        "\\Sessions\\1\\Windows",
    ] {
        let error = capture(&table(), &unused, &wide(path), 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid fixed session parent capture subject")
        );
    }
    assert!(capture(&[], &unused, &wide("\\Sessions\\1"), 1).is_err());
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcessId() -> u32;
    fn ProcessIdToSessionId(process: u32, session: *mut u32) -> i32;
}

#[test]
fn installed_fixed_session_children_capture_from_current_native_parent() {
    let mut session = u32::MAX;
    // SAFETY: current process ID, exclusive initialized DWORD output, no
    // retained pointer, token mutation or privilege change.
    assert_ne!(
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) },
        0
    );
    let path = wide(&format!("\\Sessions\\{session}"));
    let parent = open(&path, null_mut(), 0x02000000, false, 0x40)
        .unwrap()
        .unwrap();
    let access_before = basic(&parent).unwrap();
    let entries = capture(&table(), &parent, &path, session).unwrap();
    assert_eq!(entries.len(), if session == 0 { 1 } else { 2 });
    assert_eq!(basic(&parent).unwrap(), access_before);
    for captured in &entries {
        assert!(
            captured.name == wide("Windows")
                || session != 0 && captured.name == wide("BaseNamedObjects")
        );
        let link = is(&captured.kind, "SymbolicLink");
        assert!(link || is(&captured.kind, "Directory"));
        // A second typed native open checks the retained record through the
        // same pinned parent. The child remains a native object, not a fixture.
        let handle = open(&captured.name, parent.0, 0x02000000, link, 0x40)
            .unwrap()
            .unwrap();
        assert_eq!(
            canonical_name(&handle).unwrap(),
            path.iter()
                .copied()
                .chain([92])
                .chain(captured.name.iter().copied())
                .collect::<Vec<_>>()
        );
        handle.close().unwrap();
    }
    assert!(forced_case(&path, &parent, &entries).is_ok());
    parent.close().unwrap();
}
