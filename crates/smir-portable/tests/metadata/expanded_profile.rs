//! Genuine static factories for the accepted R-PROD005 REV2 profile.
use crate::metadata::{records::StorageKind, requirements::RuntimeRequirement};
use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/metadata/profile-fixtures")
            .join(format!("{name}.smo")),
    )
    .unwrap()
}
fn context(bytes: &[u8]) -> ObjectContext {
    ObjectContext::new(
        crate::decode_object(bytes, Limits::default()).unwrap(),
        &mut Budget::new(&Limits::default()),
    )
    .unwrap()
}

#[test]
fn newly_audited_complete_objects_reach_actual_final_factory() {
    for name in [
        "stack-allocation",
        "typed-handler",
        "service",
        "unused-service",
        "storage",
        "storage-prefix-zero-tail",
        "storage-readonly",
        "constant-initializer",
        "dependency-type",
        "dependency-nominal",
        "dependency-function",
        "dependency-recipe",
        "external-cleanup-journal",
    ] {
        let input = bytes(name);
        let verified = crate::verify_object(&input, Limits::default());
        assert!(verified.is_ok(), "{name}: {:?}", verified.err());
    }
}

#[test]
fn actual_storage_and_future_requirements_are_retained_without_execution() {
    let input = bytes("storage-prefix-zero-tail");
    let ctx = context(&input);
    let mut budget = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
    let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
    let metadata = crate::metadata::verify(&ctx, &types, &abi, &mut budget).unwrap();
    let data = metadata.storage(StorageKind::Data, 0).unwrap();
    assert_eq!(data.key.context_id(), ctx.context_id());
    assert_eq!(data.extent, 4);
    let raw = data.bytes(0, 4).unwrap();
    assert_eq!(raw.initial, &[7]);
    assert_eq!(raw.zero_tail_bytes, 3);
    assert_eq!(
        metadata.tls(0).unwrap().bytes(0, 4).unwrap().initial,
        &[8, 0, 0, 0]
    );
    let obligations = metadata.requirements().obligations();
    for requirement in [
        RuntimeRequirement::Capability { index: 0 },
        RuntimeRequirement::DataSegment { segment: 0 },
        RuntimeRequirement::DataSegment { segment: 1 },
        RuntimeRequirement::TlsSegment { segment: 0 },
        RuntimeRequirement::LeafRelocation { index: 0 },
        RuntimeRequirement::InternalHelper { import: 0 },
    ] {
        assert!(
            obligations.contains(&requirement),
            "missing {requirement:?}"
        );
    }
    let input = bytes("dependency-function");
    let ctx = context(&input);
    let mut budget = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
    let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
    let metadata = crate::metadata::verify(&ctx, &types, &abi, &mut budget).unwrap();
    assert!(
        metadata
            .requirements()
            .obligations()
            .contains(&RuntimeRequirement::Dependency { slot: 7 })
    );
    assert_eq!(
        ctx.declaration(7, 99).unwrap(),
        ctx.declaration(7, 99).unwrap()
    );
    assert!(ctx.declaration(7, 0).is_err());
}

#[test]
fn malformed_unused_metadata_reaches_actual_semantic_predicates() {
    for name in [
        "storage-orphan",
        "unused-service-bad-catalog",
        "storage-patch-width",
        "storage-patch-overflow",
        "storage-patch-function-target",
        "storage-poison-conflict",
        "storage-missing-layout",
        "storage-bad-binding",
        "storage-extra-extent",
        "service-bad-catalog",
        "service-bad-version",
        "service-bad-capability",
        "service-bad-descriptor",
        "service-missing-capability",
        "tls-helper-missing-target",
        "tls-helper-unused-alignment",
        "dependency-version-range",
        "constant-bad-noundef",
        "constant-patch-overlap",
    ] {
        let error = crate::verify_object(&bytes(name), Limits::default())
            .err()
            .unwrap_or_else(|| panic!("malformed {name} accepted"));
        assert_eq!(error.class(), ErrorClass::Semantic, "{name}: {error:?}");
        assert_ne!(
            error.code(),
            "P2_METADATA_PROFILE_UNAUDITED",
            "{name}: {error:?}"
        );
    }
}

#[test]
fn otherwise_valid_uncovered_runtime_forms_stay_unknown() {
    for name in [
        "storage-valid-poison",
        "storage-valid-undef",
        "storage-valid-namespace-tls",
        "storage-patch-valid-unsupported-addend",
    ] {
        let error = crate::verify_object(&bytes(name), Limits::default())
            .err()
            .unwrap_or_else(|| panic!("unaudited {name} accepted"));
        assert_eq!(
            error.class(),
            ErrorClass::UnavailableEvidence,
            "{name}: {error:?}"
        );
    }
}

#[test]
fn metadata_phase_precharges_work_edges_and_derived_copies() {
    let input = bytes("storage");
    let ctx = context(&input);
    let mut full = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&ctx, &mut full).unwrap();
    let abi = crate::abi::verify(&ctx, &types, &mut full).unwrap();
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
        let error = match crate::metadata::verify(&ctx, &types, &abi, &mut Budget::new(&limits)) {
            Err(error) => error,
            Ok(_) => panic!("exhausted metadata budget issued facts"),
        };
        assert_eq!(error.class(), ErrorClass::Resource);
    }
}

#[test]
fn actual_local_journal_and_external_recipe_retain_distinct_obligations() {
    let input = bytes("external-cleanup-journal");
    let ctx = context(&input);
    let mut budget = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
    let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
    let metadata = crate::metadata::verify(&ctx, &types, &abi, &mut budget).unwrap();
    let program =
        crate::execution::verify_program(&ctx, &types, &abi, &metadata, &mut budget).unwrap();
    crate::metadata::verify_program_joins(&ctx, &types, &abi, &metadata, &program, &mut budget)
        .unwrap();
    assert_eq!(
        program.requirements(),
        &[
            crate::execution::ProgramRequirement::ExternalCleanupRecipe {
                function: 1,
                action: 0,
                slot: 0,
                declaration: 9
            }
        ]
    );
    assert!(
        metadata
            .requirements()
            .obligations()
            .contains(&RuntimeRequirement::Dependency { slot: 0 })
    );
    let journal = ctx.local(crate::context::Namespace::Journal, 0).unwrap();
    assert!(abi.journal(journal).is_ok());
    assert!(ctx.local(crate::context::Namespace::Recipe, 9).is_err());
    assert!(ctx.declaration(0, 9).is_ok());
    crate::verify_object(&input, Limits::default()).unwrap();
}
