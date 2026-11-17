//! Source-authored finite scalar ABI coverage through the real phase factory.
use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/abi/ordinary-scalar-fixtures")
}

fn manifest() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(directory().join("manifest.json")).unwrap()).unwrap()
}

fn input(name: &str) -> Vec<u8> {
    std::fs::read(directory().join(format!("{name}.smo"))).unwrap()
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn original_scalar_objects_reach_actual_abi_factory() {
    let manifest = manifest();
    let mut failures = Vec::new();
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let bytes = input(name);
        assert_eq!(sha(&bytes), case["sha256"].as_str().unwrap(), "{name}");
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        let ctx =
            ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget).unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let result = crate::abi::verify(&ctx, &types, &mut budget);
        println!("scalar ABI factory {name}: {:?}", result.as_ref().err());
        match (case["expected_abi"].as_str().unwrap(), result) {
            ("verified-abi", Ok(facts)) => {
                facts.assert_context(&ctx).unwrap();
                assert_eq!(facts.identity(), ctx.identity());
                assert!(facts.requirements().is_empty(), "{name}");
            }
            ("verified-abi", Err(error)) => failures.push(format!("{name}: {error:?}")),
            (_, Ok(_)) => failures.push(format!("{name}: excluded or malformed ABI issued facts")),
            (expected, Err(error)) => {
                if error.code() != expected {
                    failures.push(format!("{name}: expected {expected}, {error:?}"));
                }
                let class = if expected == "P2_ABI_VERIFIER_INCOMPLETE" {
                    ErrorClass::UnavailableEvidence
                } else {
                    ErrorClass::Semantic
                };
                if error.class() != class {
                    failures.push(format!("{name}: {error:?}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn original_current_scalar_control_transitions_are_actual_facts() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    for name in ["unused-valid-extra-nominal", "unused-valid-extra-signature"] {
        let case = cases["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        assert_eq!(case["expected"], "P2_ABI_VERIFIER_INCOMPLETE"); // Historical bytes/expectation retained.
        let text = case["encoded_hex"].as_str().unwrap();
        let bytes = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(sha(&bytes), case["sha256"].as_str().unwrap());
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        let ctx =
            ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget).unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let facts = crate::abi::verify(&ctx, &types, &mut budget)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        facts.assert_context(&ctx).unwrap();
        println!("current scalar coverage transition {name}: genuine ABI facts");
    }
}

#[test]
fn scalar_facts_keep_actual_context_and_cumulative_resource_refusals() {
    for name in ["cpp-long", "c-mixed", "cpp-void"] {
        let bytes = input(name);
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        let ctx =
            ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget).unwrap();
        let other =
            ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget).unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let facts = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
        assert_eq!(
            facts.assert_context(&other).unwrap_err().class(),
            ErrorClass::Semantic
        );
        assert_eq!(
            crate::abi::verify(&other, &types, &mut budget)
                .err()
                .unwrap()
                .class(),
            ErrorClass::Semantic
        );
        for edge_limit in [false, true] {
            let mut exhausted = Limits::default();
            if edge_limit {
                exhausted.max_graph_edges = 0;
            } else {
                exhausted.max_semantic_work = 0;
            }
            let error = match crate::verify_object(&bytes, exhausted) {
                Ok(_) => panic!("exhausted cumulative budget issued proof {name}"),
                Err(error) => error,
            };
            assert_eq!(error.class(), ErrorClass::Resource, "{name}: {error:?}");
        }
    }
}

#[test]
fn independent_scalar_fixture_source_and_bytes_remain_reproducible() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let recipe = root.join(manifest["generator"].as_str().unwrap());
    assert_eq!(
        sha(&std::fs::read(recipe).unwrap()),
        manifest["generator_sha256"].as_str().unwrap()
    );
    for (name, expected) in manifest["input_sha256"].as_object().unwrap() {
        assert_eq!(
            sha(&std::fs::read(root.join(name)).unwrap()),
            expected.as_str().unwrap(),
            "{name}"
        );
    }
    let mut total = 0usize;
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let bytes = input(name);
        total += bytes.len();
        assert_eq!(sha(&bytes), case["sha256"].as_str().unwrap(), "{name}");
        assert_eq!(bytes.len() as u64, case["bytes"].as_u64().unwrap());
    }
    assert_eq!(
        total as u64,
        manifest["encoded_object_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        manifest["cases"].as_object().unwrap().len() as u64,
        manifest["object_count"].as_u64().unwrap()
    );
}
