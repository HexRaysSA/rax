//! All helper catalog templates at the type/option subphases only.
//! ABI/target/registration joins and whole MetadataFacts remain separate gates.
use crate::metadata::imports::{Catalogs, verify_helper_types, verify_options_with_abi};
use crate::{
    ErrorClass, Limits, RecordValue,
    context::{Namespace, ObjectContext, field, list},
    limits::Budget,
};
use std::collections::{BTreeMap, BTreeSet};

fn set(record: &mut RecordValue, key: &str, value: RecordValue) {
    let RecordValue::Record(fields) = record else {
        panic!("record")
    };
    fields.insert(key.to_owned(), value);
}
fn reference(id: u64) -> RecordValue {
    RecordValue::Record(BTreeMap::from([
        (
            "module".into(),
            RecordValue::Record(BTreeMap::from([(
                "kind".into(),
                RecordValue::Text("self".into()),
            )])),
        ),
        ("id".into(), RecordValue::Unsigned(id)),
    ]))
}

#[test]
fn every_helper_contract_has_actual_type_and_option_predicate_witnesses() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("helper-catalog-fixtures/manifest.json")).unwrap();
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/helper-catalog-fixtures");
    let catalogs = Catalogs::load(&mut Budget::new(&Limits::default())).unwrap();
    let mut names = BTreeSet::new();
    let mut count = 0;
    for (label, case) in manifest["cases"].as_object().unwrap() {
        let data = std::fs::read(folder.join(format!("{label}.smo"))).unwrap();
        let mut budget = Budget::new(&Limits::default());
        let ctx = ObjectContext::new(
            crate::decode_object(&data, Limits::default()).unwrap(),
            &mut budget,
        )
        .unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
        let record = &list(field(ctx.root(6).unwrap(), "imports").unwrap()).unwrap()[0];
        let name = case["name"].as_str().unwrap();
        let spec = catalogs.helper(name).unwrap();
        verify_helper_types(&ctx, &types, record, spec, &mut budget)
            .unwrap_or_else(|e| panic!("{label}: {e:?}"));
        let binding = abi
            .storage_binding(ctx.local(Namespace::StorageBinding, 1).unwrap())
            .unwrap();
        verify_options_with_abi(record, spec, Some(binding), &mut budget)
            .unwrap_or_else(|e| panic!("{label}: {e:?}"));
        // Mutation inputs remain untrusted standalone records, checked against
        // real immutable TypeFacts. They do not issue any object-phase proof.
        let mut non_function = record.clone();
        set(&mut non_function, "signature", reference(1));
        let error =
            verify_helper_types(&ctx, &types, &non_function, spec, &mut budget).unwrap_err();
        assert_eq!(error.class(), ErrorClass::Semantic);
        assert_eq!(error.code(), "RT_HELPER_SIGNATURE");
        let mut extra = record.clone();
        let RecordValue::Vector(mut args) = field(record, "types").unwrap().clone() else {
            panic!()
        };
        args.push(reference(1));
        set(&mut extra, "types", RecordValue::Vector(args));
        assert_eq!(
            verify_helper_types(&ctx, &types, &extra, spec, &mut budget)
                .unwrap_err()
                .code(),
            "RT_HELPER_TYPE_ARITY"
        );
        let mut invalid = record.clone();
        let mut options = field(record, "options").unwrap().clone();
        set(&mut options, "alignment", RecordValue::Unsigned(0));
        set(&mut invalid, "options", options);
        assert_eq!(
            verify_options_with_abi(&invalid, spec, Some(binding), &mut budget)
                .unwrap_err()
                .code(),
            "RT_HELPER_ALIGNMENT"
        );
        names.insert(name.to_owned());
        count += 1;
    }
    assert_eq!(names.len(), 177);
    assert_eq!(count, 368);
}
