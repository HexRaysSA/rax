//! Complete catalog binding subphase; this does not issue whole-object facts.
use crate::{Limits, context::ObjectContext, limits::Budget};

#[test]
fn every_service_signature_uses_actual_type_and_source_abi_facts() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("service-fixtures/manifest.json")).unwrap();
    let folder =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/metadata/service-fixtures");
    let mut count = 0;
    for (name, _) in manifest["cases"].as_object().unwrap() {
        let input = std::fs::read(folder.join(format!("{name}.smo"))).unwrap();
        let mut budget = Budget::new(&Limits::default());
        let ctx = ObjectContext::new(
            crate::decode_object(&input, Limits::default()).unwrap(),
            &mut budget,
        )
        .unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
        let requirements =
            crate::metadata::requirements::verify(ctx.root(9).unwrap(), &mut budget).unwrap();
        let bindings =
            crate::metadata::imports::verify(&ctx, &types, &abi, &requirements, &mut budget)
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[&0].kind,
            crate::metadata::imports::ImportKind::Service
        );
        assert!(bindings[&0].signature.id() > 0);
        // The actual import binding subphase succeeds. Whole MetadataFacts and
        // process support/grants/execution are separately restricted/required.
        println!("service-binding {name}: actual-type-abi-checked");
        count += 1;
    }
    assert_eq!(count, 59);
}
