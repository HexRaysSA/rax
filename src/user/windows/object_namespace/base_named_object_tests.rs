use super::*;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[test]
fn native_mutant_captured_counted_names_preserve_nuls_surrogates_and_literals() {
    for name in [
        vec![65, 0, 66],
        vec![0xD800],
        vec![0xDC00],
        units("Raw/Name"),
        units("."),
        units(".."),
    ] {
        let mut values = captures(0);
        values[1].entries.push(CapturedEntry {
            name: name.clone(),
            kind: units("Mutant"),
            target: None,
            link_access: None,
            section: None,
        });
        let namespace = Namespace::selected(table(), values).unwrap();
        let root = namespace
            .lookup(None, &units("\\BaseNamedObjects"), 0)
            .unwrap();
        assert_eq!(
            root.entries
                .get(&fold(&root.upcase, &name))
                .unwrap()
                .captured
                .name,
            name
        );
        assert_eq!(
            namespace.lookup(Some(root), &name, 0).unwrap_err(),
            LookupError::Status(STATUS_OBJECT_TYPE_MISMATCH)
        );
    }
}
pub(crate) fn table() -> Arc<[u16]> {
    (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect::<Vec<_>>()
        .into()
}
fn entry(name: &str, kind: &str) -> CapturedEntry {
    CapturedEntry {
        name: units(name),
        kind: units(kind),
        target: None,
        link_access: None,
        section: None,
    }
}
fn directory(path: &str, entries: Vec<CapturedEntry>) -> SelectedDirectory {
    SelectedDirectory {
        path: units(path),
        maximum_access: ALL_ACCESS,
        force_case_insensitive: false,
        system_security_status: STATUS_PRIVILEGE_NOT_HELD,
        entries,
    }
}
pub(crate) fn captures(session: u32) -> Vec<SelectedDirectory> {
    let mut dirs = vec![
        directory(
            "\\",
            vec![
                entry("BaseNamedObjects", "Directory"),
                entry("Sessions", "Directory"),
                entry("Other", "Directory"),
            ],
        ),
        directory(
            "\\BaseNamedObjects",
            vec![
                entry("ExistingEvent", "Event"),
                entry("OpaqueSection", "Section"),
                entry("Child", "Directory"),
            ],
        ),
    ];
    if session != 0 {
        dirs.extend([
            directory(
                "\\Sessions",
                vec![
                    entry(&session.to_string(), "Directory"),
                    entry("other", "Directory"),
                ],
            ),
            directory(
                &format!("\\Sessions\\{session}"),
                vec![entry("BaseNamedObjects", "Directory")],
            ),
            directory(
                &format!("\\Sessions\\{session}\\BaseNamedObjects"),
                vec![entry("LocalEvent", "Event")],
            ),
        ]);
    }
    dirs
}
pub(crate) fn sample(session: u32) -> Namespace {
    Namespace::selected_for_session(table(), captures(session), Some(session)).unwrap()
}

#[test]
fn native_base_named_object_selection_paths_are_canonical_and_bounded() {
    assert_eq!(selection_paths(None).len(), 6);
    for session in [0, 1, 42, u32::MAX] {
        let paths = selection_paths(Some(session));
        assert_eq!(paths.len(), if session == 0 { 9 } else { 10 });
        assert_eq!(
            paths.last().unwrap(),
            &units(&format!("\\Sessions\\{session}\\Windows"))
        );
        if session != 0 {
            assert!(paths.contains(&units(&format!("\\Sessions\\{session}\\BaseNamedObjects"))));
        } else {
            assert!(!paths.contains(&units("\\Sessions\\0\\BaseNamedObjects")));
        }
        assert!(paths.iter().all(|p| p.len() < 64));
        for known in &PATHS[1..4] {
            assert!(image_directory(&units(known)));
        }
        assert!(!image_directory(&units("\\BaseNamedObjects")));
        assert!(!image_directory(paths.last().unwrap()));
    }
}

#[test]
fn native_base_named_object_nested_paths_preserve_absolute_relative_identity() {
    for session in [1, 42, u32::MAX] {
        let namespace = sample(session);
        let prefix = format!("\\Sessions\\{session}");
        let root = namespace.lookup(None, &units(&prefix), 0x40).unwrap();
        let absolute = namespace
            .lookup(None, &units(&format!("{prefix}\\BaseNamedObjects")), 0x40)
            .unwrap();
        let relative = namespace
            .lookup(Some(root), &units("BaseNamedObjects"), 0x40)
            .unwrap();
        assert!(Arc::ptr_eq(&absolute, &relative));
        assert_eq!(absolute.grant(0xF, false), Ok(0xF));
        assert_eq!(
            absolute.grant(0x0100_0000, false),
            Err(STATUS_PRIVILEGE_NOT_HELD)
        );
        assert_eq!(
            namespace
                .lookup(None, &units(&format!("{prefix}\\Missing")), 0x40)
                .unwrap_err(),
            LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            namespace
                .lookup(None, &units("\\Other\\Missing"), 0x40)
                .unwrap_err(),
            LookupError::Unselected
        );
    }
}

#[test]
fn native_base_named_object_tree_rejects_missing_ancestors_wrong_types_and_sessions() {
    for removed in [0, 2, 3] {
        let mut dirs = captures(42);
        dirs.remove(removed);
        assert!(Namespace::selected_for_session(table(), dirs, Some(42)).is_err());
    }
    let dirs = captures(42);
    assert!(Namespace::selected_for_session(table(), dirs.clone(), Some(41)).is_err());
    assert!(Namespace::selected(table(), dirs).is_err());
    let mut dirs = captures(42);
    dirs[2].entries[0].kind = units("Event");
    assert!(Namespace::selected_for_session(table(), dirs, Some(42)).is_err());
    let mut dirs = captures(42);
    dirs[3].path = units("\\Sessions\\042");
    assert!(Namespace::selected_for_session(table(), dirs, Some(42)).is_err());
    let mut dirs = captures(42);
    dirs.push(dirs.last().unwrap().clone());
    assert!(Namespace::selected_for_session(table(), dirs, Some(42)).is_err());
}

#[test]
fn native_base_named_object_selection_keeps_uncaptured_resources_explicit() {
    let namespace = sample(0);
    assert_eq!(
        namespace
            .lookup(None, &units("\\BaseNamedObjects\\Child"), 0x40)
            .unwrap_err(),
        LookupError::Unselected
    );
    assert_eq!(
        namespace
            .lookup_section(
                None,
                &units("\\BaseNamedObjects\\OpaqueSection"),
                0x40,
                false
            )
            .unwrap_err(),
        LookupError::Unselected
    );
    assert_eq!(
        namespace
            .lookup(None, &units("\\BaseNamedObjects\\ExistingEvent"), 0x40)
            .unwrap_err(),
        LookupError::Status(STATUS_OBJECT_TYPE_MISMATCH)
    );
    assert_eq!(
        namespace
            .lookup(None, &units("\\basenamedobjects"), 0)
            .unwrap_err(),
        LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert!(
        namespace
            .lookup(None, &units("\\basenamedobjects"), 0x40)
            .is_ok()
    );
}

#[test]
fn native_base_named_object_snapshot_coherence_rejects_live_duplicates_and_changes() {
    let upper = table();
    let first = vec![entry("A", "Event"), entry("B", "Semaphore")];
    assert!(entries_coherent(&upper, &first, &first));
    assert!(entries_coherent(&upper, &[], &[]));
    assert!(!entries_coherent(&[], &first, &first));
    let mut changed = first.clone();
    changed[1].kind = units("Mutant");
    assert!(!entries_coherent(&upper, &first, &changed));
    assert!(!entries_coherent(&upper, &first, &first[..1]));
    for repeated in [
        vec![entry("A", "Event"), entry("A", "Event")],
        vec![entry("A", "Event"), entry("A", "Semaphore")],
        vec![entry("A", "Event"), entry("a", "Event")],
    ] {
        assert!(!entries_coherent(&upper, &repeated, &repeated));
    }
}

#[test]
fn native_base_named_object_case_probe_never_admits_a_disappeared_sample() {
    for original in [STATUS_SUCCESS, STATUS_OBJECT_TYPE_MISMATCH] {
        assert_eq!(case_probe_policy(original, original, original), Some(true));
        assert_eq!(
            case_probe_policy(original, STATUS_OBJECT_NAME_NOT_FOUND, original),
            Some(false)
        );
        assert_eq!(
            case_probe_policy(original, STATUS_ACCESS_DENIED, original),
            None
        );
        assert_eq!(
            case_probe_policy(original, original, STATUS_OBJECT_NAME_NOT_FOUND),
            None
        );
    }
    for status in [
        STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_OBJECT_PATH_NOT_FOUND,
        STATUS_ACCESS_DENIED,
    ] {
        assert_eq!(case_probe_policy(status, status, status), None);
    }
}

#[test]
fn native_base_named_object_partial_capture_keeps_only_unique_stable_names() {
    let first = vec![
        entry("Stable", "Event"),
        entry("Gone", "Event"),
        entry("Changing", "Event"),
        entry("Dupe", "Event"),
        entry("DUPE", "Event"),
    ];
    let second = vec![
        entry("Stable", "Event"),
        entry("Added", "Event"),
        entry("Changing", "Semaphore"),
        entry("Dupe", "Event"),
    ];
    let result = stable_volatile_entries(&table(), &first, &second).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, units("Stable"));
    assert!(stable_volatile_entries(&[], &first, &second).is_none());
    assert!(
        stable_volatile_entries(
            &table(),
            &vec![entry("A", "Event"); MAX_ENTRIES + 1],
            &second
        )
        .is_none()
    );
}

#[test]
fn native_base_named_object_partial_capture_refuses_uncaptured_names() {
    let n = Namespace::selected_for_session_partial(
        table(),
        captures(1),
        Some(1),
        &[units("\\BaseNamedObjects")],
    )
    .unwrap();
    let root = n.lookup(None, &units("\\BaseNamedObjects"), 0x40).unwrap();
    assert_eq!(root.grant(15, false), Ok(15));
    assert_eq!(
        n.lookup(Some(root.clone()), &units("Missing"), 0x40)
            .unwrap_err(),
        LookupError::Unselected
    );
    assert_eq!(
        n.lookup_link(Some(root.clone()), &units("Missing"), 0x40)
            .unwrap_err(),
        LookupError::Unselected
    );
    assert_eq!(
        n.lookup(None, &units("\\Missing"), 0x40).unwrap_err(),
        LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(
        n.lookup(Some(root), &units("ExistingEvent"), 0x40)
            .unwrap_err(),
        LookupError::Status(STATUS_OBJECT_TYPE_MISMATCH)
    );
}

#[test]
fn native_base_named_object_partial_ancestors_keep_selected_identity() {
    let n = Namespace::selected_for_session_partial(
        table(),
        captures(1),
        Some(1),
        &[units("\\"), units("\\Sessions")],
    )
    .unwrap();
    assert_eq!(
        n.lookup(None, &units("\\Missing"), 0x40).unwrap_err(),
        LookupError::Unselected
    );
    let session = n.lookup(None, &units("\\Sessions\\1"), 0x40).unwrap();
    let absolute = n
        .lookup(None, &units("\\Sessions\\1\\BaseNamedObjects"), 0x40)
        .unwrap();
    let relative = n
        .lookup(Some(session), &units("BaseNamedObjects"), 0x40)
        .unwrap();
    assert!(Arc::ptr_eq(&absolute, &relative));
    for paths in [
        vec![units("\\KnownDlls")],
        vec![units("\\unknown")],
        vec![units("\\"), units("\\")],
    ] {
        assert!(
            Namespace::selected_for_session_partial(table(), captures(1), Some(1), &paths).is_err()
        );
    }
}

#[test]
fn native_namespace_parent_identity_error_reports_type_and_name_mismatches() {
    for (captured_name, captured_type) in [
        ("BaseNamedObjects", "SymbolicLink"),
        ("BASENAMEDOBJECTS", "Directory"),
    ] {
        let mut selected = captures(0);
        let parent_entry = &mut selected[0].entries[0];
        parent_entry.name = units(captured_name);
        parent_entry.kind = units(captured_type);
        let error = Namespace::selected(table(), selected)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("selected NT directory parent type/name changed"));
        for required in [
            format!("selected_path={:?}", "\\BaseNamedObjects"),
            format!("parent_path={:?}", "\\"),
            format!("selected_name={:?}", "BaseNamedObjects"),
            format!("captured_name={captured_name:?}"),
            format!("captured_type={captured_type:?}"),
            "existing_child=false".to_owned(),
        ] {
            assert!(error.contains(&required), "missing {required} in {error}");
        }
    }
}

#[test]
fn session_directory_alias_preserves_symbolic_and_selected_target_identity() {
    let source = units("\\Sessions\\7\\BaseNamedObjects");
    let target = units("\\BaseNamedObjects");
    let opaque_target = units("\\OpaqueSiloRoot\\BaseNamedObjects");
    let mut values = captures(7);
    let parent = values
        .iter_mut()
        .find(|dir| dir.path == units("\\Sessions\\7"))
        .unwrap();
    let entry = parent
        .entries
        .iter_mut()
        .find(|entry| entry.name == units("BaseNamedObjects"))
        .unwrap();
    entry.kind = units("SymbolicLink");
    entry.target = Some(opaque_target.clone());
    entry.link_access = Some(LinkAccess {
        maximum_access: 0x000F_0001,
        system_security_status: STATUS_PRIVILEGE_NOT_HELD,
    });
    assert!(Namespace::selected_for_session(table(), values.clone(), Some(7)).is_err());
    let namespace = Namespace::selected_with_directory_aliases(
        table(),
        values,
        Some(7),
        &[],
        &[(source.clone(), target.clone())],
    )
    .unwrap();
    let global = namespace.lookup(None, &target, 0x40).unwrap();
    let aliased = namespace.lookup(None, &source, 0x40).unwrap();
    assert!(Arc::ptr_eq(&global, &aliased));
    assert_eq!(aliased.path, target);
    assert_eq!(
        namespace.lookup_link(None, &source, 0x40).unwrap().target,
        opaque_target
    );
    assert_eq!(
        namespace.lookup(None, &source, 0x1040).unwrap_err(),
        LookupError::Status(STATUS_REPARSE_POINT_ENCOUNTERED)
    );
    let owned = namespace.named_win32(7, &units("OwnedAliasName")).unwrap();
    let direct = namespace
        .named(Some(global), &units("OwnedAliasName"), 0)
        .unwrap();
    assert!(owned.matches(&direct));
}

fn alias_captures() -> Vec<SelectedDirectory> {
    let mut values = captures(7);
    let parent = values
        .iter_mut()
        .find(|value| value.path == units("\\Sessions\\7"))
        .unwrap();
    let entry = &mut parent.entries[0];
    entry.kind = units("SymbolicLink");
    entry.target = Some(units("\\OpaqueSiloRoot\\BaseNamedObjects"));
    entry.link_access = Some(LinkAccess {
        maximum_access: 0x000F_0001,
        system_security_status: STATUS_PRIVILEGE_NOT_HELD,
    });
    values
}

#[test]
fn session_directory_alias_rejects_unselected_pairs_and_incoherent_evidence() {
    let source = units("\\Sessions\\7\\BaseNamedObjects");
    let target = units("\\BaseNamedObjects");
    for (session, aliases) in [
        (None, vec![(source.clone(), target.clone())]),
        (Some(0), vec![(source.clone(), target.clone())]),
        (Some(8), vec![(source.clone(), target.clone())]),
        (Some(7), vec![(target.clone(), source.clone())]),
        (Some(7), vec![(source.clone(), units("\\Unselected"))]),
        (Some(7), vec![(source.clone(), target.clone()); 2]),
    ] {
        assert!(
            Namespace::selected_with_directory_aliases(
                table(),
                alias_captures(),
                session,
                &[],
                &aliases
            )
            .is_err()
        );
    }
    for role in 0..8 {
        let mut values = alias_captures();
        match role {
            0 => values.retain(|value| value.path != target),
            1 => values.retain(|value| value.path != source),
            2 => {
                values
                    .iter_mut()
                    .find(|value| value.path == source)
                    .unwrap()
                    .maximum_access ^= 1
            }
            3 => {
                values
                    .iter_mut()
                    .find(|value| value.path == source)
                    .unwrap()
                    .force_case_insensitive = true
            }
            4 => {
                values
                    .iter_mut()
                    .find(|value| value.path == source)
                    .unwrap()
                    .system_security_status = STATUS_ACCESS_DENIED
            }
            5 => {
                values
                    .iter_mut()
                    .find(|value| value.path == units("\\Sessions\\7"))
                    .unwrap()
                    .entries[0]
                    .name = units("BASENAMEDOBJECTS")
            }
            6 => {
                values
                    .iter_mut()
                    .find(|value| value.path == units("\\Sessions\\7"))
                    .unwrap()
                    .entries[0]
                    .link_access = None
            }
            7 => {
                values
                    .iter_mut()
                    .find(|value| value.path == units("\\Sessions\\7"))
                    .unwrap()
                    .entries[0]
                    .target = Some(units("UnselectedRelativeTarget"))
            }
            _ => unreachable!(),
        }
        assert!(
            Namespace::selected_with_directory_aliases(
                table(),
                values,
                Some(7),
                &[],
                &[(source.clone(), target.clone())]
            )
            .is_err(),
            "role={role}"
        );
    }
}

#[test]
fn session_directory_alias_preserves_partial_capture_name_grammar_and_reparse_budget() {
    let source = units("\\Sessions\\7\\BaseNamedObjects");
    let target = units("\\BaseNamedObjects");
    let namespace = Namespace::selected_with_directory_aliases(
        table(),
        alias_captures(),
        Some(7),
        &[source.clone()],
        &[(source.clone(), target)],
    )
    .unwrap();
    let resolved = namespace.lookup(None, &source, 0x40).unwrap();
    assert_eq!(
        namespace
            .lookup(Some(resolved), &units("Missing"), 0x40)
            .unwrap_err(),
        LookupError::Unselected
    );
    for suffix in ["\\", "\\\\Missing"] {
        assert_eq!(
            namespace
                .lookup(
                    None,
                    &units(&format!("\\Sessions\\7\\BaseNamedObjects{suffix}")),
                    0x40
                )
                .unwrap_err(),
            LookupError::Status(STATUS_OBJECT_NAME_INVALID)
        );
    }
    assert_eq!(
        namespace
            .lookup(
                None,
                &units("\\Sessions\\7\\BaseNamedObjects\\Missing\\"),
                0x40
            )
            .unwrap_err(),
        LookupError::Unselected,
    );
    assert_eq!(
        namespace
            .lookup_object_reparsed(None, &source, 0x40, false, false, false, 63)
            .err(),
        Some(LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND))
    );
    assert!(matches!(
        namespace.lookup_object_reparsed(None, &source, 0x40, false, false, false, 62),
        Ok(SelectedObject::Directory(_))
    ));
    assert!(matches!(
        namespace.lookup_object_reparsed(None, &source, 0x40, true, false, false, 63),
        Ok(SelectedObject::Link(_))
    ));
    assert_eq!(
        namespace
            .lookup_object_reparsed(None, &source, 0x1040, false, false, false, 63)
            .err(),
        Some(LookupError::Status(STATUS_REPARSE_POINT_ENCOUNTERED))
    );
}
