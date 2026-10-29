use super::*;
use crate::user::windows::registry::Lookup;

fn registry() -> Registry {
    // SAFETY: native scalar ordinal mapping; no pointers or retained handles.
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
            .collect(),
        vec![],
    )
    .unwrap()
}
fn sid() -> Vec<u8> {
    crate::user::windows::wnf::snapshot()
        .unwrap()
        .primary_subject()
        .unwrap()
        .user
        .clone()
}

fn compare_node(
    selected: &Registry,
    root: CommandRoot,
    sid: &[u8],
    view: RegistryView,
    logical: Vec<u16>,
    native: OwnedKey,
) -> usize {
    let metadata = info(&native).unwrap();
    let raw = values(&native, &metadata, super::super::super::MAX_TOTAL_BYTES).unwrap();
    let canonical = canonical_hive_name(&native, "Command Processor").unwrap();
    let Lookup::Present(key) = selected.lookup_view(&logical, view) else {
        panic!("present native subtree node");
    };
    assert_eq!(key.path, canonical);
    assert_eq!(key.children, metadata.children);
    assert_eq!(
        key.subkeys.as_ref().unwrap().len(),
        metadata.children as usize
    );
    assert_eq!(key.values.len(), raw.len());
    let access = key.captured_access().unwrap();
    assert_eq!(
        access.grant(0x02000000),
        Ok(super::super::native_key::basic(&native, "Command Processor").unwrap())
    );
    let security = super::super::native_key::open(&canonical, 0x01000000).map(|security| {
        super::super::native_key::basic(&security, "Command Processor security").unwrap()
    });
    assert_eq!(access.grant(0x01000000), security);
    for value in raw {
        assert_eq!(key.value(&value.name), Some(&value));
    }
    let mut names = vec![];
    for index in 0..metadata.children {
        let mut buffer = vec![0; metadata.max_child as usize + 1];
        let mut length = buffer.len() as u32;
        // SAFETY: owned enumerate-capable key and exclusive bounded outputs;
        // optional native outputs are NULL and returned length is checked.
        assert_eq!(
            unsafe {
                RegEnumKeyExW(
                    native.0,
                    index,
                    buffer.as_mut_ptr(),
                    &mut length,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            },
            0
        );
        assert!((length as usize) < buffer.len());
        buffer.truncate(length as usize);
        names.push(buffer);
    }
    drop(native);
    let mut count = 1;
    for name in names {
        let next = crate::user::windows::registry::tree::child_path(&logical, &name).unwrap();
        let native = open_path(root, sid, view, &next).unwrap();
        count += compare_node(selected, root, sid, view, next, native);
    }
    count
}

#[test]
fn installed_command_capture_validates_subject_and_preserves_native_absence_errors() {
    assert!(
        capture_with(
            Registry::default(),
            CommandRoot::Machine,
            &[],
            |_, _, _| panic!("invalid table reached native opener")
        )
        .is_err()
    );
    assert!(
        capture_with(registry(), CommandRoot::User, &[], |_, _, _| panic!(
            "invalid SID reached native opener"
        ))
        .is_err()
    );
    for code in [2, 3] {
        let mut calls = vec![];
        let captured = capture_with(registry(), CommandRoot::Machine, &[], |root, sid, view| {
            assert_eq!(root, CommandRoot::Machine);
            assert!(sid.is_empty());
            calls.push(view);
            Err(io::Error::from_raw_os_error(code))
        })
        .unwrap();
        assert_eq!(calls, [RegistryView::Native64, RegistryView::Wow32]);
        for view in calls {
            let result = captured.lookup_view(&CommandRoot::Machine.path(&[]).unwrap(), view);
            if code == 2 {
                assert!(matches!(result, Lookup::Missing));
            } else {
                assert!(matches!(result, Lookup::MissingPath));
            }
        }
    }
    for code in [5, 234, 259] {
        for failure in [1, 2] {
            let mut calls = 0;
            let error = capture_with(registry(), CommandRoot::Machine, &[], |_, _, _| {
                calls += 1;
                Err(io::Error::from_raw_os_error(if calls == failure {
                    code
                } else {
                    2
                }))
            })
            .unwrap_err();
            assert_eq!(calls, failure);
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }
    let duplicate = registry()
        .with_command_view(
            CommandRoot::Machine,
            &[],
            RegistryView::Native64,
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
        )
        .unwrap();
    assert!(
        capture_with(duplicate, CommandRoot::Machine, &[], |_, _, _| panic!(
            "duplicate reached opener"
        ))
        .is_err()
    );
}

#[test]
fn installed_command_capture_matches_independent_native_values_and_access() {
    let sid = sid();
    for root in [CommandRoot::Machine, CommandRoot::User] {
        let base = if root == CommandRoot::User {
            super::super::primary_hive::capture_header(registry(), &sid).unwrap()
        } else {
            registry()
        };
        let selected = capture_with(base, root, &sid, open).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            match open(root, &sid, view) {
                Ok(native) => {
                    let count = compare_node(
                        &selected,
                        root,
                        &sid,
                        view,
                        root.path(&sid).unwrap(),
                        native,
                    );
                    assert!(count > 0);
                    eprintln!("native CMD {root:?}/{view:?}: {count} complete nodes");
                }
                Err(error) => match error.raw_os_error() {
                    Some(2) => assert!(matches!(
                        selected.lookup_view(&root.path(&sid).unwrap(), view),
                        Lookup::Missing
                    )),
                    Some(3) => assert!(matches!(
                        selected.lookup_view(&root.path(&sid).unwrap(), view),
                        Lookup::MissingPath
                    )),
                    _ => panic!("unexpected native selection failure: {error}"),
                },
            }
        }
    }
}

#[test]
fn installed_command_capture_closes_owned_handles() {
    const MARKER: &str = "RAX_COMMAND_CAPTURE_COUNT_CHILD";
    if std::env::var_os(MARKER).as_deref() != Some(std::ffi::OsStr::new("1")) {
        let child=std::process::Command::new(std::env::current_exe().unwrap()).args(["user::windows::registry::installed::command_processor::tests::installed_command_capture_closes_owned_handles","--exact","--test-threads=1"]).env(MARKER,"1").output().unwrap();
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success() && stdout.contains("1 passed; 0 failed;"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&child.stderr)
        );
        return;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Hkey;
        fn GetProcessHandleCount(process: Hkey, count: *mut u32) -> i32;
    }
    let count = || {
        let mut n = 0;
        // SAFETY: process pseudo-handle and exclusive DWORD output.
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut n) },
            0
        );
        n
    };
    let sid = sid();
    let base = super::super::primary_hive::capture_header(registry(), &sid).unwrap();
    drop(capture_machine(base.clone()).unwrap());
    drop(capture_user(base.clone(), &sid).unwrap());
    let before = count();
    for _ in 0..8 {
        drop(capture_machine(base.clone()).unwrap());
        drop(capture_user(base.clone(), &sid).unwrap());
        let mut calls = 0;
        assert!(
            capture_with(
                base.clone(),
                CommandRoot::Machine,
                &[],
                |root, sid, view| {
                    calls += 1;
                    if calls == 1 {
                        open(root, sid, view)
                    } else {
                        Err(io::Error::from_raw_os_error(5))
                    }
                }
            )
            .is_err()
        );
        assert_eq!(calls, 2);
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let key = open(CommandRoot::Machine, &[], view).unwrap();
            if info(&key).unwrap().children != 0 {
                let mut descendants = 0;
                let error =
                    subtree::capture_with(&base, CommandRoot::Machine, &[], view, key, |path| {
                        // No parent HKEY may survive into a descendant open.
                        assert_eq!(count(), before);
                        descendants += 1;
                        assert!(path.len() > CommandRoot::Machine.path(&[]).unwrap().len());
                        Err(io::Error::from_raw_os_error(5))
                    })
                    .err()
                    .unwrap();
                assert_eq!(error.raw_os_error(), Some(5));
                assert_eq!(descendants, 1);
            }
        }
        assert!(
            open_path(
                CommandRoot::Machine,
                &[],
                RegistryView::Native64,
                &"\\Registry\\Machine\\Software\\Microsoft\\Command ProcessorOther"
                    .encode_utf16()
                    .collect::<Vec<_>>(),
            )
            .is_err()
        );
    }
    assert_eq!(count(), before);
}
