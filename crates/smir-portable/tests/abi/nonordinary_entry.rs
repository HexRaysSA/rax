//! Source-authored static entry witnesses through the genuine public factory.
use crate::{ErrorClass, Limits, verify_object};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/abi/nonordinary-entry-fixtures")
}
fn manifest() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(directory().join("manifest.json")).unwrap()).unwrap()
}
fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(directory().join(format!("{name}.smo"))).unwrap()
}
fn hash(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn covered_entries_and_boundaries_obtain_genuine_all_phase_object_facts() {
    for row in manifest()["positives"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let data = bytes(name);
        assert_eq!(hash(&data), row["sha256"].as_str().unwrap(), "{name}");
        let object =
            verify_object(&data, Limits::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(object.requirements().iter().count(), 7, "{name}");
        for root in object.requirements().iter() {
            assert_eq!(
                root.canonical_bytes().unwrap().len(),
                root.encoded_length().unwrap()
            );
        }
    }
}

#[test]
fn malformed_entries_reject_at_actual_abi_program_and_source_call_gates() {
    for row in manifest()["negatives"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let data = bytes(name);
        assert_eq!(hash(&data), row["sha256"].as_str().unwrap(), "{name}");
        let error = match verify_object(&data, Limits::default()) {
            Ok(_) => panic!("{name}: known negative issued an object proof"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            row["code"].as_str().unwrap(),
            "{name}: {error}"
        );
        let expected = if row["class_"] == "semantic" {
            ErrorClass::Semantic
        } else {
            ErrorClass::UnavailableEvidence
        };
        assert_eq!(error.class(), expected, "{name}: {error}");
    }
}

#[test]
fn entry_coverage_does_not_bypass_the_original_cumulative_resource_gate() {
    let data = bytes("constructor-vtt");
    for limits in [
        Limits {
            max_semantic_work: 0,
            ..Limits::default()
        },
        Limits {
            max_graph_edges: 0,
            ..Limits::default()
        },
        Limits {
            max_derived_bytes: 0,
            ..Limits::default()
        },
    ] {
        match verify_object(&data, limits) {
            Err(error) => assert_eq!(error.class(), ErrorClass::Resource),
            Ok(_) => panic!("exhausted canonical ledger issued an object proof"),
        }
    }
}

#[test]
fn explicit_unknown_profile_forms_are_not_reclassified_as_malformed() {
    for name in [
        "unsupported-union",
        "missing-entry-association",
        "unmatched-method-declaration",
    ] {
        match verify_object(&bytes(name), Limits::default()) {
            Err(error) => {
                assert_eq!(error.class(), ErrorClass::UnavailableEvidence, "{name}");
                assert_eq!(error.code(), "P2_ABI_VERIFIER_INCOMPLETE", "{name}");
            }
            Ok(_) => panic!("{name}: profile boundary disappeared"),
        }
    }
}
