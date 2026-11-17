//! Actual all-phase source scalar factories; no manufactured ABI/program facts.
use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};
fn input(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/ordinary-scalar-fixtures").join(format!("{name}.smo"))).unwrap()
}
#[test]
fn complete_source_scalar_factories_and_exact_rejections() {
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/metadata/ordinary-scalar-fixtures/manifest.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let result = crate::verify_object(&input(name), Limits::default());
        println!("ordinary source complete factory {name}: {:?}", result.as_ref().err());
        match (case["expected"].as_str().unwrap(), result) {
            ("static", Ok(_)) => {}
            ("static", Err(error)) => failures.push(format!("{name}: {error:?}")),
            (_, Ok(_)) => failures.push(format!("{name}: malformed/unaudited form issued facts")),
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
fn original_source_context_and_unresolved_runtime_requirements_survive() {
    use crate::metadata::requirements::RuntimeRequirement;
    for (name, dependency) in [("undefined-retains-source-obligations", false),
                               ("original-dependency-source-expectation", true)] {
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
fn actual_factories_refuse_cumulative_budget_exhaustion() {
    for name in ["cpp-long", "c-unsigned-char", "cpp-void-zero", "multiple-original-source-plans"] {
        for edges in [false, true] {
            let mut limits = Limits::default();
            if edges { limits.max_graph_edges = 0; } else { limits.max_semantic_work = 0; }
            let error = match crate::verify_object(&input(name), limits) {
                Ok(_) => panic!("resource exhaustion issued proof: {name}"), Err(error) => error,
            };
            assert_eq!(error.class(), ErrorClass::Resource, "{name}: {error:?}");
        }
    }
}
#[test]
fn exactly_released_original_c_controls_now_have_complete_static_proofs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/metadata");
    for name in ["manifest-symbol-fixtures/c-source-abi-unavailable.smo",
                 "generic-shape-fixtures/retained-c-source-abi-limit.smo"] {
        let bytes = std::fs::read(root.join(name)).unwrap();
        assert!(crate::verify_object(&bytes, Limits::default()).is_ok(), "{name}");
    }
}
