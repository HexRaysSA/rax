use super::*;
use crate::user::windows::registry::Lookup;

fn sid() -> Vec<u8> {
    vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}
fn registry() -> Registry {
    // SAFETY: native one-WCHAR ordinal mapping; no pointers or retained state.
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
            .collect(),
        vec![],
    )
    .unwrap()
}

#[test]
fn installed_primary_hive_only_root_file_not_found_establishes_absence() {
    let fixed = user_hive_path(&sid()).unwrap();
    let mut calls = 0;
    let selected = capture_with(registry(), &sid(), |path| {
        calls += 1;
        assert_eq!(path, fixed);
        Err(io::Error::from_raw_os_error(2))
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert!(matches!(selected.lookup(&fixed), Lookup::Missing));
    for code in [3, 5, 234, 259] {
        let error = capture_with(registry(), &sid(), |_| {
            Err(io::Error::from_raw_os_error(code))
        })
        .err()
        .expect("only root file-not-found establishes absence");
        assert_eq!(error.raw_os_error(), Some(code));
    }
    assert!(
        capture_with(registry(), &[], |_| panic!(
            "invalid SID reached host opener"
        ))
        .is_err()
    );
    for path in [
        "\\Registry\\User\\S-1-5-19",
        "\\Registry\\User\\S-1-5-18\\Software",
    ] {
        assert!(open(&sid(), &path.encode_utf16().collect::<Vec<_>>()).is_err());
    }
}

#[test]
fn installed_primary_hive_capture_matches_native_header_values_and_canonical_alias() {
    let catalog = crate::user::windows::wnf::snapshot().unwrap();
    let subject = catalog.primary_subject().unwrap();
    let fixed = user_hive_path(&subject.user).unwrap();
    let native = open(&subject.user, &fixed).unwrap();
    let metadata = info(&native).unwrap();
    let raw = values(&native, &metadata, super::super::super::MAX_TOTAL_BYTES).unwrap();
    let canonical = canonical_name(&native).unwrap();
    let selected = capture(registry(), &subject.user).unwrap();
    let primary = selected.key(&fixed).unwrap();
    let alias = selected.key(&canonical).unwrap();
    assert!(std::sync::Arc::ptr_eq(&primary, &alias));
    assert_eq!(primary.path, canonical);
    assert_eq!(primary.children, metadata.children);
    for value in &raw {
        assert_eq!(primary.value(&value.name), Some(value));
    }
    assert_eq!(primary.values.len(), raw.len());
    drop(selected);
    drop(native);
    for value in &raw {
        assert_eq!(primary.value(&value.name), Some(value));
    }
}
