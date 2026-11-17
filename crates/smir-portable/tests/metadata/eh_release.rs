//! Actual static Ex-parameter helper eligibility; no Ex creation or execution.
use crate::context::{field, list, text};
use crate::metadata::imports::{Catalogs, ImportKind};
use crate::metadata::requirements::RuntimeRequirement;
use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};

fn context(bytes: &[u8]) -> ObjectContext {
    ObjectContext::new(
        crate::decode_object(bytes, Limits::default()).unwrap(),
        &mut Budget::new(&Limits::default()),
    )
    .unwrap()
}

#[test]
fn exact_eh_release_static_cases_reach_real_factories_and_semantic_checks() {
    let folder =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/metadata/eh-release-fixtures");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
    let mut counts = [0usize; 3];
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let bytes = std::fs::read(folder.join(format!("{name}.smo"))).unwrap();
        let actual = crate::verify_object(&bytes, Limits::default());
        match case["expected_class"].as_str().unwrap() {
            "ok" => {
                assert!(actual.is_ok(), "{name}: {:?}", actual.err());
                counts[0] += 1;
            }
            "semantic" | "unavailable-evidence" => {
                let error = actual
                    .err()
                    .unwrap_or_else(|| panic!("{name} unexpectedly issued facts"));
                let expected = if case["expected_class"] == "semantic" {
                    counts[1] += 1;
                    ErrorClass::Semantic
                } else {
                    counts[2] += 1;
                    ErrorClass::UnavailableEvidence
                };
                assert_eq!(error.class(), expected, "{name}: {error:?}");
                assert_eq!(
                    error.code(),
                    case["expected_code"].as_str().unwrap(),
                    "{name}"
                );
            }
            other => panic!("unknown test class {other}"),
        }
    }
    assert_eq!(counts, [2, 8, 1]);
}

#[test]
fn real_eh_release_metadata_retains_owner_conditions_context_and_budget() {
    let bytes = include_bytes!("eh-release-fixtures/ordinary-call-ex-parameter.smo");
    let ctx = context(bytes);
    let other = context(bytes);
    let mut budget = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
    let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
    let metadata = crate::metadata::verify(&ctx, &types, &abi, &mut budget).unwrap();
    let program =
        crate::execution::verify_program(&ctx, &types, &abi, &metadata, &mut budget).unwrap();
    crate::metadata::verify_program_joins(&ctx, &types, &abi, &metadata, &program, &mut budget)
        .unwrap();
    assert!(
        metadata
            .requirements()
            .obligations()
            .iter()
            .any(|v| matches!(v, RuntimeRequirement::InternalHelper { import: 0 }))
    );
    let import = metadata.import(0).unwrap();
    assert_eq!(import.kind, ImportKind::Internal);
    assert!(import.abi.is_none());
    assert_eq!(import.completion, "returns");
    let record = &list(field(ctx.root(6).unwrap(), "imports").unwrap()).unwrap()[0];
    assert_eq!(text(field(record, "name").unwrap()).unwrap(), "eh_release");
    let catalogs = Catalogs::load(&mut budget).unwrap();
    let spec = catalogs.helper("eh_release").unwrap();
    assert!(
        spec["leases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "exception_owner_and_frames")
    );
    assert!(
        spec["effects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "exception_control_and_ownership")
    );
    assert_eq!(spec["reentry"], "guest");
    assert_eq!(spec["cancellation"], "defer_after_effect");
    assert_eq!(
        metadata.assert_context(&other).err().unwrap().class(),
        ErrorClass::Semantic
    );
    for which in 0..3 {
        let mut limits = Limits::default();
        match which {
            0 => limits.max_semantic_work = 0,
            1 => limits.max_graph_edges = 0,
            _ => limits.max_derived_bytes = 0,
        };
        assert_eq!(
            crate::verify_object(bytes, limits).err().unwrap().class(),
            ErrorClass::Resource
        );
    }
}
