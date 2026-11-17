use crate::metadata::requirements::verify;
use crate::wire::RecordValue as V;
use crate::{Limits, limits::Budget};
use std::collections::BTreeMap;

fn root(caps: &[&str], support: Vec<V>, limits: Vec<V>) -> V {
    V::Record(BTreeMap::from([
        ("payload_revision".into(), V::Unsigned(1)),
        (
            "capabilities".into(),
            V::Vector(caps.iter().map(|c| V::Text((*c).into())).collect()),
        ),
        ("requirements".into(), V::Vector(support)),
        ("limits".into(), V::Vector(limits)),
    ]))
}

fn support(kind: &str, name: &str, version: u64) -> V {
    V::Record(BTreeMap::from([
        ("kind".into(), V::Text(kind.into())),
        ("name".into(), V::Text(name.into())),
        ("version".into(), V::Unsigned(version)),
    ]))
}

#[test]
fn requests_are_retained_without_grant_or_support_fabrication() {
    let value = root(
        &["file", "memory"],
        vec![support("library", "libc", 1)],
        vec![],
    );
    let facts = verify(&value, &mut Budget::new(&Limits::default())).unwrap();
    assert!(facts.requests("file"));
    assert!(!facts.requests("foreign"));
    assert_eq!(facts.support()[0].name, "libc");
    assert_eq!(facts.support()[0].version, 1);
    assert!(facts.limits().is_empty());
}

#[test]
fn capability_duplicate_order_and_unknown_reject() {
    for caps in [
        vec!["file", "file"],
        vec!["memory", "file"],
        vec!["invented"],
    ] {
        let e = verify(
            &root(&caps, vec![], vec![]),
            &mut Budget::new(&Limits::default()),
        )
        .unwrap_err();
        assert_eq!(e.code(), "RT_CAPABILITIES");
    }
}

#[test]
fn support_identity_and_native_image_syntax_reject() {
    for record in [
        support("unknown", "x", 1),
        support("library", "x", 0),
        support("native_image", &"F".repeat(64), 1),
        support("library", "x\0y", 1),
    ] {
        assert!(
            verify(
                &root(&[], vec![record], vec![]),
                &mut Budget::new(&Limits::default())
            )
            .is_err()
        );
    }
}

#[test]
fn support_same_name_different_version_still_duplicate() {
    let value = root(
        &[],
        vec![support("library", "x", 1), support("library", "x", 2)],
        vec![],
    );
    assert_eq!(
        verify(&value, &mut Budget::new(&Limits::default()))
            .unwrap_err()
            .code(),
        "RT_REQUIREMENT_ORDER"
    );
}

#[test]
fn derived_budget_is_charged_before_requirements_allocation() {
    let value = root(&["file"], vec![], vec![]);
    let limits = Limits {
        max_derived_bytes: 0,
        ..Limits::default()
    };
    assert_eq!(
        verify(&value, &mut Budget::new(&limits))
            .unwrap_err()
            .class(),
        crate::ErrorClass::Resource
    );
}
