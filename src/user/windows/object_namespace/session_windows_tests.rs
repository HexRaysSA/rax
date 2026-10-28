//! Independent native directory/section observations, with distinct CSR owners.
use super::*;
use serde_json::Value;

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
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

fn directory(path: &str, entries: Vec<CapturedEntry>, access: u32) -> SelectedDirectory {
    SelectedDirectory {
        path: units(path),
        maximum_access: access,
        force_case_insensitive: true,
        system_security_status: STATUS_PRIVILEGE_NOT_HELD,
        entries,
    }
}

fn data(session: Option<u32>, marker: u8) -> Arc<DataSection> {
    DataSection::selected_for_session(
        session,
        0x20004,
        STATUS_PRIVILEGE_NOT_HELD,
        false,
        4096,
        vec![data::DataRegion {
            offset: 0,
            size: 4096,
            bytes: Some(vec![marker; 4096].into()),
        }],
    )
    .unwrap()
}

fn fixture(session: u32, global_access: u32, current_access: u32) -> Namespace {
    let mut windows = entry(
        "Windows",
        if session == 0 {
            "SymbolicLink"
        } else {
            "Directory"
        },
    );
    if session == 0 {
        windows.target = Some(units("\\Windows"));
        windows.link_access = Some(LinkAccess {
            maximum_access: 0xF0001,
            system_security_status: STATUS_PRIVILEGE_NOT_HELD,
        });
    }
    let other = if session == u32::MAX { 3 } else { u32::MAX };
    let mut captured = vec![
        directory(
            "\\",
            vec![
                entry("Windows", "Directory"),
                entry("Sessions", "Directory"),
            ],
            ALL_ACCESS,
        ),
        directory(
            "\\Windows",
            vec![entry("SharedSection", "Section")],
            global_access,
        ),
        directory(
            "\\Sessions",
            vec![
                entry(&session.to_string(), "Directory"),
                entry(&other.to_string(), "Directory"),
            ],
            ALL_ACCESS,
        ),
        directory(&format!("\\Sessions\\{session}"), vec![windows], ALL_ACCESS),
    ];
    if session != 0 {
        captured.push(directory(
            &format!("\\Sessions\\{session}\\Windows"),
            vec![entry("SharedSection", "Section")],
            current_access,
        ));
    }
    let mut namespace =
        Namespace::selected_for_session(base_named_object_tests::table(), captured, Some(session))
            .unwrap();
    namespace.select_data_section(data(None, 0x11)).unwrap();
    if session != 0 {
        namespace
            .select_data_section(data(Some(session), 0x22))
            .unwrap();
    }
    namespace
}

fn section(
    namespace: &Namespace,
    path: &str,
    flags: u32,
    wow: bool,
) -> Result<Arc<DataSection>, LookupError> {
    match namespace.lookup_installed_section(None, &units(path), flags, wow)? {
        SelectedSection::Data(section) => Ok(section),
        SelectedSection::Image(_) => panic!("data section expected"),
    }
}

#[test]
fn session_windows_replays_all_96_native_directory_section_opens_and_identities() {
    let sources = [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-session-windows-directory/local-29695-v2.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-session-windows-directory/hosted-2022-v2.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-session-windows-directory/hosted-2025-v2.json"
        )),
    ];
    let mut count = 0;
    for source in sources {
        let capture: Value = serde_json::from_str(source).unwrap();
        let session = capture["session"].as_u64().unwrap() as u32;
        let access = |index| {
            capture["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| {
                    row["kind"] == "directory"
                        && row["path_index"] == index
                        && row["altered_case"] == false
                        && row["flags"] == 64
                })
                .unwrap()["information"]["granted_access"]
                .as_u64()
                .unwrap() as u32
        };
        let namespace = fixture(session, access(0), access(1));
        let reference_directory = namespace.lookup(None, &units("\\Windows"), 0x40).unwrap();
        let reference_section =
            section(&namespace, "\\Windows\\SharedSection", 0x40, false).unwrap();
        for row in capture["rows"].as_array().unwrap() {
            let path = row["path"].as_str().unwrap();
            let flags = row["flags"].as_u64().unwrap() as u32;
            let requested = row["requested_access"].as_u64().unwrap() as u32;
            let expected = row["status"].as_u64().unwrap() as u32;
            let label = format!("session{session}/{}/{path}/{flags:#x}", row["kind"]);
            if row["kind"] == "directory" {
                match namespace.lookup(None, &units(path), flags) {
                    Ok(directory) => {
                        assert_eq!(expected, 0, "{label}");
                        assert_eq!(
                            directory.path,
                            row["information"]["name"]["units"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|x| x.as_u64().unwrap() as u16)
                                .collect::<Vec<_>>(),
                            "{label}"
                        );
                        assert_eq!(
                            directory.grant(requested, false).unwrap(),
                            row["information"]["granted_access"].as_u64().unwrap() as u32,
                            "{label}"
                        );
                        assert_eq!(
                            if Arc::ptr_eq(&directory, &reference_directory) {
                                0
                            } else {
                                0xC000_01AC
                            },
                            row["same_reference_status"].as_u64().unwrap() as u32,
                            "{label}"
                        );
                    }
                    Err(LookupError::Status(status)) => assert_eq!(status, expected, "{label}"),
                    Err(error) => panic!("{label}: {error:?}"),
                }
            } else {
                for wow in [false, true] {
                    match section(&namespace, path, flags, wow) {
                        Ok(section) => {
                            assert_eq!(expected, 0, "{label}");
                            assert_eq!(
                                section.path,
                                row["information"]["name"]["units"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|x| x.as_u64().unwrap() as u16)
                                    .collect::<Vec<_>>(),
                                "{label}"
                            );
                            assert_eq!(
                                section.grant(requested, false).unwrap(),
                                row["information"]["granted_access"].as_u64().unwrap() as u32,
                                "{label}"
                            );
                            assert_eq!(
                                if Arc::ptr_eq(&section, &reference_section) {
                                    0
                                } else {
                                    0xC000_01AC
                                },
                                row["same_reference_status"].as_u64().unwrap() as u32,
                                "{label}"
                            );
                        }
                        Err(LookupError::Status(status)) => assert_eq!(status, expected, "{label}"),
                        Err(error) => panic!("{label}: {error:?}"),
                    }
                }
            }
            count += 1;
        }
    }
    assert_eq!(count, 96);
}

#[test]
fn session_windows_keeps_distinct_data_views_and_rejects_unselected_subjects() {
    for session in [0, 2, u32::MAX] {
        let mut namespace = fixture(session, ALL_ACCESS, ALL_ACCESS);
        let global = section(&namespace, "\\Windows\\SharedSection", 0x40, false).unwrap();
        let current = section(
            &namespace,
            &format!("\\Sessions\\{session}\\Windows\\SharedSection"),
            0x40,
            false,
        )
        .unwrap();
        assert_eq!(Arc::ptr_eq(&global, &current), session == 0);
        assert_eq!(global.regions[0].bytes.as_ref().unwrap()[0], 0x11);
        assert_eq!(
            current.regions[0].bytes.as_ref().unwrap()[0],
            if session == 0 { 0x11 } else { 0x22 }
        );
        let foreign = if session == u32::MAX { 3 } else { u32::MAX };
        assert!(matches!(
            section(
                &namespace,
                &format!("\\Sessions\\{foreign}\\Windows\\SharedSection"),
                0x40,
                false
            ),
            Err(LookupError::Unselected)
        ));
        assert!(
            namespace
                .select_data_section(data(Some(foreign), 0x33))
                .is_err()
        );
        assert!(Arc::ptr_eq(
            &section(&namespace, "\\Windows\\SharedSection", 0x40, false).unwrap(),
            &global
        ));
        assert!(Arc::ptr_eq(
            &section(
                &namespace,
                &format!("\\Sessions\\{session}\\Windows\\SharedSection"),
                0x40,
                false
            )
            .unwrap(),
            &current
        ));
    }
}
