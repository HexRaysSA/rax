//! Genuine whole-object factories and an independent authored pointer corpus.
use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};
fn input(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/ordinary-pointer-fixtures").join(format!("{name}.smo"))).unwrap()
}
#[test]
fn complete_original_pointer_factories_and_exact_rejections() {
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/metadata/ordinary-pointer-fixtures/manifest.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let result = crate::verify_object(&input(name), Limits::default());
        println!("ordinary pointer original complete factory {name}: {:?}", result.as_ref().err());
        match (case["expected"].as_str().unwrap(), result) {
            ("static", Ok(_)) => {}
            ("static", Err(error)) => failures.push(format!("{name}: {error:?}")),
            (_, Ok(_)) => failures.push(format!("{name}: unsupported/invalid issued facts")),
            (expected, Err(error)) => {
                let class = if expected == "semantic" { ErrorClass::Semantic }
                    else { ErrorClass::UnavailableEvidence };
                if error.class() != class { failures.push(format!("{name}: {error:?}")); }
                if let Some(code) = case["code"].as_str() {
                    if error.code() != code { failures.push(format!("{name}: expected {code}, actual {error:?}")); }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn pointer_metadata_preserves_original_context_and_runtime_obligations() {
    use crate::metadata::requirements::RuntimeRequirement;
    let bytes = input("undefined-original-source-obligations");
    let mut budget = Budget::new(&Limits::default());
    let a = ObjectContext::new(crate::decode_object(&bytes, Limits::default()).unwrap(), &mut budget).unwrap();
    let b = ObjectContext::new(crate::decode_object(&bytes, Limits::default()).unwrap(), &mut budget).unwrap();
    let types = crate::execution::verify_types(&a, &mut budget).unwrap();
    let abi = crate::abi::verify(&a, &types, &mut budget).unwrap();
    let facts = crate::metadata::verify(&a, &types, &abi, &mut budget).unwrap();
    facts.assert_context(&a).unwrap();
    assert_eq!(facts.assert_context(&b).unwrap_err().class(), ErrorClass::Semantic);
    let obligations = facts.requirements().obligations();
    assert!(obligations.contains(&RuntimeRequirement::ProcessProfile));
    assert!(obligations.iter().any(|r| matches!(r, RuntimeRequirement::SymbolBinding { .. })));
    assert_eq!(crate::metadata::verify(&b, &types, &abi, &mut budget).err().unwrap().class(), ErrorClass::Semantic);
}
#[test]
fn pointer_original_factories_refuse_exhaustion() {
    for name in ["cpp-int-pointer", "c-void-return", "cpp-mixed"] {
        for edges in [false, true] {
            let mut limits = Limits::default();
            if edges { limits.max_graph_edges = 0; } else { limits.max_semantic_work = 0; }
            let error = crate::verify_object(&input(name), limits).err().expect("quota must not issue facts");
            assert_eq!(error.class(), ErrorClass::Resource, "{name}: {error:?}");
        }
    }
}
#[test]
fn pointer_generator_nonwriting_byte_reproduction() {
    let output = std::process::Command::new("python3").arg("-B")
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/metadata/ordinary_pointer_fixtures.py"))
        .arg("--check").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}
#[test]
fn unchanged_original_pointer_diamond_crosses_whole_object_gates() {
    use sha2::{Digest, Sha256};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/abi/ordinary-pointer-fixtures/original-pointer-diamond.smo");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes.len(), 6558);
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)),
        "aa1261d85724c84b880d3ea37f24692710b1b31ab32c9bb829d57449d5017e3c");
    crate::verify_object(&bytes, Limits::default()).unwrap();
}
