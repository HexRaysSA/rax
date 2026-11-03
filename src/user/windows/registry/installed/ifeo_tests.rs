//! Controlled read-only NLS handles exercise denial capture without ACL writes.
use super::*;
use crate::user::windows::registry::{IFEO_KEY, Lookup, TreeRoot};
use std::cell::Cell;

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn registry() -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|unit| {
                if (97..=122).contains(&unit) {
                    unit - 32
                } else {
                    unit
                }
            })
            .collect(),
        vec![],
    )
    .unwrap()
}

fn controlled_open(path: &[u16]) -> io::Result<OwnedKey> {
    let fixed = units(IFEO_KEY);
    let relative = path
        .strip_prefix(fixed.as_slice())
        .expect("controlled IFEO prefix");
    assert!(relative.is_empty() || relative.first() == Some(&92));
    let name: Vec<_> = "SYSTEM\\CurrentControlSet\\Control\\Nls"
        .encode_utf16()
        .chain(relative.iter().copied())
        .chain(Some(0))
        .collect();
    let mut handle = null_mut();
    // SAFETY: fixed read-only fixture root and bounded enumerated descendants,
    // terminated native name and exclusive output. No registry mutation.
    let status = unsafe {
        RegOpenKeyExW(
            (-2_147_483_646isize) as Hkey,
            name.as_ptr(),
            0,
            9,
            &mut handle,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(OwnedKey(handle))
}

#[test]
fn installed_ifeo_denial_root_absence_and_unrelated_errors_keep_original_meaning() {
    for status in [2, 5, 234, 259] {
        let calls = Cell::new(0);
        let actual = capture_with(
            &registry(),
            |_| {
                calls.set(calls.get() + 1);
                Err(io::Error::from_raw_os_error(status))
            },
            |_, _| panic!("root errors cannot claim descendant denials"),
        );
        assert_eq!(calls.get(), 1);
        if status == 2 {
            assert!(actual.unwrap().is_none());
        } else {
            assert_eq!(actual.err().unwrap().raw_os_error(), Some(status));
        }
    }
}

#[test]
fn installed_ifeo_denial_capture_retains_parent_metadata_and_does_not_read_denied_body() {
    let registry = registry();
    let denied = units(&format!("{IFEO_KEY}\\CodePage"));
    let independent = controlled_open(&denied).unwrap();
    let expected_children = info(&independent).unwrap().children;
    drop(independent);
    let denied_reads = Cell::new(0);
    let maximum_calls = Cell::new(0);
    let captured = capture_with(
        &registry,
        |path| {
            if path == denied {
                denied_reads.set(denied_reads.get() + 1);
                Err(io::Error::from_raw_os_error(5))
            } else {
                controlled_open(path)
            }
        },
        |path, access| {
            assert_eq!(path, denied);
            assert_eq!(
                access,
                [0x0200_0000, 0x0100_0000, 0x0200_0000][maximum_calls.get()]
            );
            maximum_calls.set(maximum_calls.get() + 1);
            Err(STATUS_ACCESS_DENIED)
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(denied_reads.get(), 1);
    assert_eq!(maximum_calls.get(), 3);
    let selected = registry
        .with_captured_tree(TreeRoot::Ifeo, Some(captured))
        .unwrap();
    let key = selected.key(&denied).unwrap();
    assert_eq!(key.children, expected_children);
    assert_eq!(key.open_denial(), Some(STATUS_ACCESS_DENIED));
    let parent = selected.key(&units(IFEO_KEY)).unwrap();
    assert!(
        parent
            .child_metadata()
            .unwrap()
            .iter()
            .any(|entry| entry.name == units("CodePage"))
    );
    assert!(matches!(
        selected.lookup(&units(&format!("{IFEO_KEY}\\unlisted"))),
        Lookup::Missing
    ));
}

#[test]
fn installed_ifeo_denial_capture_rejects_partial_grants_or_changed_maximum_access() {
    let denied = units(&format!("{IFEO_KEY}\\CodePage"));
    for partial in [false, true] {
        let actual = capture_with(
            &registry(),
            |path| {
                if path == denied {
                    Err(io::Error::from_raw_os_error(5))
                } else {
                    controlled_open(path)
                }
            },
            |path, _| {
                assert_eq!(path, denied);
                if partial {
                    Ok(controlled_open(path).unwrap())
                } else {
                    Err(0xC000_0034)
                }
            },
        );
        let error = actual.err().expect("uncaptured access cannot claim denial");
        assert_eq!(
            error.kind(),
            if partial {
                io::ErrorKind::Unsupported
            } else {
                io::ErrorKind::InvalidData
            }
        );
    }
}

#[test]
fn installed_ifeo_denial_does_not_replace_a_distinct_system_security_failure() {
    let denied = units(&format!("{IFEO_KEY}\\CodePage"));
    let actual = capture_with(
        &registry(),
        |path| {
            if path == denied {
                Err(io::Error::from_raw_os_error(5))
            } else {
                controlled_open(path)
            }
        },
        |path, access| {
            assert_eq!(path, denied);
            Err(if access == 0x0100_0000 {
                0xC000_0061
            } else {
                STATUS_ACCESS_DENIED
            })
        },
    );
    assert_eq!(
        actual
            .err()
            .expect("distinct privilege status is not uniform denial")
            .kind(),
        io::ErrorKind::Unsupported
    );
}
