use super::catalog::*;
use crate::user::windows::registry::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

const REGISTRY: &str = include_str!(
    "../../../../docs/specifications/windows/native-wnf-subscribe/native-wnf-subscribe-registry.json"
);
const SUBJECT: &str = include_str!(
    "../../../../docs/specifications/windows/native-wnf-subscribe/native-wnf-subscribe-subject-arm64.log"
);
pub(crate) fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}
pub(crate) fn rows(text: &str) -> Vec<HashMap<&str, &str>> {
    text.lines()
        .filter(|line| line.starts_with("case=") || line.contains("-case="))
        .map(|line| {
            line.split_whitespace()
                .map(|field| field.split_once('=').unwrap())
                .collect()
        })
        .collect()
}
fn subject() -> Subject {
    let mut subject = Subject {
        statistics: None,
        attributes: None,
        user_attributes: 0,
        user: Vec::new(),
        groups: Vec::new(),
        restricted: Vec::new(),
        app_container: false,
        privileges: Vec::new(),
    };
    for line in SUBJECT.lines().filter(|line| line.starts_with("sid ")) {
        let row: HashMap<_, _> = line
            .split_whitespace()
            .skip(1)
            .map(|field| field.split_once('=').unwrap())
            .collect();
        let group = Group {
            sid: hex(row["bytes"]),
            attributes: u32::from_str_radix(row["attributes"], 16).unwrap(),
        };
        match row["kind"] {
            "user" => {
                subject.user_attributes = group.attributes;
                subject.user = group.sid;
            }
            "group" => subject.groups.push(group),
            "restricted" => subject.restricted.push(group),
            _ => panic!("unknown native token record"),
        }
    }
    assert!(SUBJECT.contains("app-container=0"));
    assert!(SUBJECT.contains("handles-before=59 handles-after=59"));
    subject
}

pub(crate) fn empty_subject_catalog(app_container: bool) -> Catalog {
    let mut selected = subject();
    selected.app_container = app_container;
    Catalog::selected(Vec::new(), selected).unwrap()
}

#[test]
fn primary_token_property_is_retained_independently_of_catalog_records() {
    assert_eq!(Catalog::default().primary_app_container(), None);
    for flag in [false, true] {
        let catalog = empty_subject_catalog(flag);
        assert_eq!(catalog.primary_app_container(), Some(flag));
        assert_eq!(catalog.clone().primary_app_container(), Some(flag));
    }
}
pub(crate) fn values() -> Vec<Value> {
    let json: serde_json::Value =
        serde_json::from_str(REGISTRY.trim_start_matches('\u{feff}')).unwrap();
    let values = json.as_array().unwrap();
    assert_eq!(values.len(), 1613);
    values
        .iter()
        .map(|value| {
            assert_eq!(value["kind"], "Binary");
            Value {
                name: value["name"].as_str().unwrap().encode_utf16().collect(),
                kind: 3,
                data: hex(value["data"].as_str().unwrap()),
            }
        })
        .collect()
}
pub(crate) fn catalog() -> Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG
        .get_or_init(|| Catalog::selected(values(), subject()).unwrap())
        .clone()
}

#[test]
fn native_wnf_subscription_name_capture_replays_all_8192_domain_rows() {
    for text in [
        include_str!(
            "../../../../docs/specifications/windows/native-wnf-subscribe/native-wnf-subscribe-domain-arm64.log"
        ),
        include_str!(
            "../../../../docs/specifications/windows/native-wnf-subscribe/native-wnf-subscribe-domain-x64.log"
        ),
        include_str!(
            "../../../../docs/specifications/windows/native-wnf-subscribe/native-wnf-subscribe-domain-x86.log"
        ),
        include_str!(
            "../../../../docs/specifications/windows/native-wnf-subscribe/native-wnf-subscribe-domain-x86-laa.log"
        ),
    ] {
        assert!(text.contains("complete cases=2048"));
        let observed = rows(text);
        assert_eq!(observed.len(), 2048);
        for row in observed {
            let name = u64::from_str_radix(row["name"], 16).unwrap();
            assert_eq!(
                Name::decode(name).is_none(),
                row["status"] == "C000000D",
                "{row:?}"
            );
        }
    }
}
#[test]
fn native_wnf_subscription_catalog_access_matches_all_72_process_name_calls() {
    let text = include_str!(
        "../../../../docs/specifications/windows/native-wnf-subscribe/native-wnf-subscribe-process-names-arm64.log"
    );
    assert!(text.contains("complete names=9 data-pairs=72"));
    let catalog = catalog();
    let mut count = 0;
    for line in text.lines().filter(|line| line.starts_with("data-after ")) {
        let row: HashMap<_, _> = line
            .split_whitespace()
            .skip(1)
            .map(|field| field.split_once('=').unwrap())
            .collect();
        let name = u64::from_str_radix(row["name"], 16).unwrap();
        let mask = u32::from_str_radix(row["mask"], 16).unwrap();
        assert_eq!(
            catalog.permission(name, mask),
            match row["subscribed"] {
                "00000000" => Permission::Allowed,
                "C0000022" => Permission::Denied,
                _ => panic!("unrecognized native status"),
            },
            "{row:?}"
        );
        count += 1;
    }
    assert_eq!(count, 72);
}
#[test]
fn native_wnf_subscription_catalog_rejects_unmodeled_security_and_malformed_values() {
    let known = 0x41911A28A3BC10B5;
    let mut value = values()
        .into_iter()
        .find(|v| v.name == "41911A28A3BC10B5".encode_utf16().collect::<Vec<_>>())
        .unwrap();
    for at in [0, 2, 4, 8, 12, 16, 20, 21, 22, 26, 28, 29, 30, 32, 36, 37] {
        let mut corrupted = value.clone();
        corrupted.data[at] ^= 0x80;
        let c = Catalog::selected(vec![corrupted], subject()).unwrap();
        assert_eq!(
            c.permission(known, 0x11),
            Permission::Unmodeled,
            "byte {at}"
        );
    }
    let mut app = subject();
    app.app_container = true;
    assert_eq!(
        Catalog::selected(vec![value.clone()], app)
            .unwrap()
            .permission(known, 0),
        Permission::Unmodeled
    );
    let mut restricted = subject();
    restricted.restricted.push(restricted.groups[0].clone());
    assert_eq!(
        Catalog::selected(vec![value.clone()], restricted)
            .unwrap()
            .permission(known, 0),
        Permission::Unmodeled
    );
    assert!(Catalog::selected(vec![value.clone(), value.clone()], subject()).is_err());
    value.kind = 1;
    assert!(Catalog::selected(vec![value], subject()).is_err());
    assert_eq!(
        catalog().permission(known ^ 0x800, 0x11),
        Permission::Missing
    );
    assert_eq!(
        catalog().permission(0x41911A28A3BC0875, 0x11),
        Permission::Unmodeled
    );
}
