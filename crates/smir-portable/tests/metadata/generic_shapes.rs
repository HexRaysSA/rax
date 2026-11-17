//! Genuine complete factories for original generic full Fn shapes.
use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};

fn input(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/generic-shape-fixtures").join(format!("{name}.smo"))).unwrap()
}

#[test]
fn complete_generic_shape_factories_and_typed_rejections() {
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/metadata/generic-shape-fixtures/manifest.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let result = crate::verify_object(&input(name), Limits::default());
        println!("generic complete factory {name}: {:?}", result.as_ref().err());
        // Only this original C control has an explicitly released current map.
        let expected = if name == "retained-c-source-abi-limit" { "static" }
            else { case["expected"].as_str().unwrap() };
        match (expected, result) {
            ("static", Ok(_)) => {}
            ("static", Err(error)) => failures.push(format!("{name}: {error:?}")),
            (_, Ok(_)) => failures.push(format!("{name}: malformed or unaudited object issued proof")),
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
fn generic_shape_proofs_keep_original_context_and_runtime_requirements() {
    use crate::metadata::requirements::RuntimeRequirement;
    for (name, dependency) in [("undefined-original-requirement", false),
                               ("original-generic-declaration-expectation", true)] {
        let bytes = input(name); let mut budget = Budget::new(&Limits::default());
        let ctx = ObjectContext::new(crate::decode_object(&bytes, Limits::default()).unwrap(), &mut budget).unwrap();
        let other = ObjectContext::new(crate::decode_object(&bytes, Limits::default()).unwrap(), &mut budget).unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
        let facts = crate::metadata::verify(&ctx, &types, &abi, &mut budget).unwrap();
        facts.assert_context(&ctx).unwrap();
        assert_eq!(facts.assert_context(&other).unwrap_err().class(), ErrorClass::Semantic);
        let obligations = facts.requirements().obligations();
        assert!(obligations.contains(&RuntimeRequirement::ProcessProfile));
        assert!(obligations.iter().any(|r| matches!(r, RuntimeRequirement::SymbolBinding { .. })));
        assert_eq!(obligations.contains(&RuntimeRequirement::Dependency { slot: 7 }), dependency);
    }
}

#[test]
fn complete_generic_factories_refuse_exhausted_cumulative_budgets() {
    for name in ["void", "multiresult", "code-address-identity", "struct-identity"] {
        for edges in [false, true] {
            let mut limits = Limits::default();
            if edges { limits.max_graph_edges = 0; } else { limits.max_semantic_work = 0; }
            let error = match crate::verify_object(&input(name), limits) {
                Ok(_) => panic!("exhausted budget issued proof: {name}"), Err(error) => error,
            };
            assert_eq!(error.class(), ErrorClass::Resource, "{name}: {error:?}");
        }
    }
}
