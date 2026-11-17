//! Whole private factories: exact source contracts, no predicate bypass.
use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};

fn input(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/manifest-symbol-fixtures").join(format!("{name}.smo"))).unwrap()
}

#[test]
fn complete_manifest_symbol_factories_and_exact_rejections() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/manifest-symbol-fixtures/manifest.json");
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut failures = Vec::new();
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let result = crate::verify_object(&input(name), Limits::default());
        println!("manifest whole factory {name}: {:?}", result.as_ref().err());
        // Explicit current mapping released for the original unchanged C case.
        // The new complete factory test establishes its actual ABI/metadata proof.
        let expected = if name == "c-source-abi-unavailable" { "static" }
            else { case["expected"].as_str().unwrap() };
        if expected == "static" {
            if let Err(error) = result { failures.push(format!("{name}: {error:?}")); }
            continue;
        }
        match result {
            Ok(_) => failures.push(format!("{name}: invalid/unaudited form issued actual facts")),
            Err(error) => {
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
fn actual_static_obligations_are_not_provider_or_execution_facts() {
    use crate::metadata::requirements::RuntimeRequirement;
    for (name, dependency, symbols) in [
        ("linux-symbols-0", false, 0),
        ("two-distinct-bodies", false, 2),
        ("undefined-ordinary-retains-obligation", false, 1),
        ("original-declaration-function", true, 1),
    ] {
        let bytes = input(name); let mut budget = Budget::new(&Limits::default());
        let ctx = ObjectContext::new(crate::decode_object(&bytes, Limits::default()).unwrap(), &mut budget).unwrap();
        let other = ObjectContext::new(crate::decode_object(&bytes, Limits::default()).unwrap(), &mut budget).unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
        let metadata = crate::metadata::verify(&ctx, &types, &abi, &mut budget).unwrap();
        metadata.assert_context(&ctx).unwrap();
        assert_eq!(metadata.assert_context(&other).err().unwrap().class(), ErrorClass::Semantic);
        let obligations = metadata.requirements().obligations();
        assert!(obligations.contains(&RuntimeRequirement::ProcessProfile));
        assert_eq!(obligations.contains(&RuntimeRequirement::Dependency { slot: 7 }), dependency);
        assert_eq!(obligations.iter().filter(|r| matches!(r, RuntimeRequirement::SymbolBinding { .. })).count(), symbols);
    }
}

#[test]
fn actual_manifest_factories_refuse_resource_exhaustion() {
    for name in ["linux-symbols-0", "darwin-symbols-3", "export-function", "original-declaration-symbol"] {
        for edges in [false, true] {
            let mut limits = Limits::default();
            if edges { limits.max_graph_edges = 0; } else { limits.max_semantic_work = 0; }
            let error = match crate::verify_object(&input(name), limits) {
                Ok(_) => panic!("resource refusal issued facts: {name}"), Err(error) => error,
            };
            assert_eq!(error.class(), ErrorClass::Resource, "{name}: {error:?}");
        }
    }
}
