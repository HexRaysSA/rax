//! Guard evidence while catalog source-kind predicates remain unqualified.
//! Passing this test does not establish the missing atomic_flag semantic rule.
use crate::{ErrorClass, Limits};

#[test]
fn known_wrong_flag_source_records_cannot_issue_object_facts() {
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/helper-catalog-fixtures");
    for name in [
        "atomic_flag_test",
        "atomic_flag_test_and_set",
        "atomic_flag_clear",
    ] {
        let data = std::fs::read(folder.join(format!("{name}--default.smo"))).unwrap();
        let error = crate::verify_object(&data, Limits::default())
            .err()
            .unwrap_or_else(|| panic!("known wrong Int32 source issued facts for {name}"));
        // Source-kind validation is still pending. Current conservative
        // coverage rejection is guard evidence, never a semantic-conformance pass.
        assert!(
            matches!(
                error.class(),
                ErrorClass::UnavailableEvidence | ErrorClass::Semantic
            ),
            "{name}: {error:?}"
        );
    }
}

#[test]
fn exact_legacy_flag_objects_reject_at_raw_revision_only() {
    use sha2::{Digest, Sha256};
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/legacy-abi1");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let data = std::fs::read(folder.join(format!("{name}.smo"))).unwrap();
        let digest = Sha256::digest(&data).iter()
            .map(|value| format!("{value:02x}")).collect::<String>();
        assert_eq!(digest, case["sha256"].as_str().unwrap());
        assert_eq!(data.len() as u64, case["bytes"].as_u64().unwrap());
        let error = crate::verify_object(&data, Limits::default()).err().unwrap();
        assert_eq!(error.class(), ErrorClass::Wire);
        assert_eq!(error.code(), "WIRE-REVISION");
    }
}
