//! Actual whole-object regression and same-context/budget checks for INT032.
use crate::context::{Namespace, field, list};
use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};

fn context(data: &[u8]) -> ObjectContext {
    ObjectContext::new(
        crate::decode_object(data, Limits::default()).unwrap(),
        &mut Budget::new(&Limits::default()),
    )
    .unwrap()
}

#[test]
fn original_int32_va_and_jump_sources_are_semantic_rejections() {
    use sha2::{Digest, Sha256};
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/source-role-fixtures");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["cases"].as_object().unwrap().len(), 5);
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let data = std::fs::read(folder.join(format!("{name}.smo"))).unwrap();
        let digest = Sha256::digest(&data)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        assert_eq!(digest, case["sha256"].as_str().unwrap());
        let error = crate::verify_object(&data, Limits::default())
            .err()
            .unwrap_or_else(|| panic!("wrong Int32 source issued facts: {name}"));
        assert_eq!(error.class(), ErrorClass::Semantic, "{name}: {error:?}");
        assert_eq!(error.code(), "RT_HELPER_SOURCE_ROLE", "{name}");
    }
}

#[test]
fn source_checks_keep_context_and_resource_failures_distinct() {
    let data = include_bytes!("source-role-fixtures/va_start.smo");
    let first = context(data);
    let second = context(data);
    let mut budget = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&first, &mut budget).unwrap();
    let abi = crate::abi::verify(&first, &types, &mut budget).unwrap();
    let key = first.local(Namespace::Nominal, 1).unwrap();
    let import = &list(field(first.root(6).unwrap(), "imports").unwrap()).unwrap()[0];
    let error =
        crate::metadata::source_roles::verify(&second, &types, &abi, key, import, &mut budget)
            .err()
            .expect("same bytes in another context must not share source facts");
    assert_eq!(error.class(), ErrorClass::Semantic);
    assert_ne!(error.code(), "RT_HELPER_SOURCE_ROLE");
    let mut limits = Limits::default();
    limits.max_semantic_work = 0;
    let error = crate::metadata::source_roles::verify(
        &first,
        &types,
        &abi,
        key,
        import,
        &mut Budget::new(&limits),
    )
    .err()
    .unwrap();
    assert_eq!(error.class(), ErrorClass::Resource);
}

#[test]
fn canonical_binding_proofs_do_not_expand_r005_data_symbol_coverage() {
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/canonical-profile-fixtures");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["cases"].as_object().unwrap().len(), 4);
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let bytes = std::fs::read(folder.join(format!("{name}.smo"))).unwrap();
        let ctx = context(&bytes);
        let mut budget = Budget::new(&Limits::default());
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let abi = crate::abi::verify(&ctx, &types, &mut budget)
            .unwrap_or_else(|e| panic!("actual canonical ABI proof {name}: {e:?}"));
        for field in ["allocation_binding", "object_bytes_binding"] {
            let key = ctx
                .local(
                    Namespace::StorageBinding,
                    case[field].as_u64().unwrap() as u32,
                )
                .unwrap();
            abi.storage_binding(key).unwrap();
        }
        let error = crate::metadata::verify(&ctx, &types, &abi, &mut budget)
            .err()
            .unwrap_or_else(|| panic!("32-byte symbol profile widened for {name}"));
        assert_eq!(
            error.class(),
            ErrorClass::UnavailableEvidence,
            "{name}: {error:?}"
        );
        assert_eq!(error.code(), "P2_METADATA_PROFILE_UNAUDITED");
    }
}

#[test]
fn canonical_source_checks_require_real_context_and_cumulative_budget() {
    let bytes = include_bytes!("state-helper-fixtures/va_start.smo");
    let ctx = context(bytes);
    let other = context(bytes);
    let mut full = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&ctx, &mut full).unwrap();
    let abi = crate::abi::verify(&ctx, &types, &mut full).unwrap();
    let import = &list(field(ctx.root(6).unwrap(), "imports").unwrap()).unwrap()[0];
    let source = crate::context::optional(field(import, "abi").unwrap())
        .unwrap()
        .unwrap();
    let key = crate::metadata::imports::nominal_expectation(&ctx, source).unwrap();
    crate::metadata::source_roles::verify(&ctx, &types, &abi, key, import, &mut full).unwrap();
    let error = crate::metadata::source_roles::verify(&other, &types, &abi, key, import, &mut full)
        .err()
        .unwrap();
    assert_eq!(error.class(), ErrorClass::Semantic);
    for edges in [false, true] {
        let mut limits = Limits::default();
        if edges {
            limits.max_graph_edges = 0;
        } else {
            limits.max_semantic_work = 0;
        }
        let error = crate::metadata::source_roles::verify(
            &ctx,
            &types,
            &abi,
            key,
            import,
            &mut Budget::new(&limits),
        )
        .err()
        .unwrap();
        assert_eq!(error.class(), ErrorClass::Resource);
    }
}
