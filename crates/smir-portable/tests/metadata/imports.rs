use crate::metadata::imports::{Catalogs, verify_options};
use crate::{Limits, limits::Budget, wire::RecordValue as V};
use std::collections::BTreeMap;

fn record(contract: &str) -> V {
    V::Record(BTreeMap::from([
        ("contract".into(), V::Text(contract.into())),
        (
            "options".into(),
            V::Record(BTreeMap::from([
                ("alignment".into(), V::Unsigned(1)),
                ("scope".into(), V::Text("process".into())),
                ("order".into(), V::Text("none".into())),
                ("failure_order".into(), V::Text("none".into())),
                ("weak".into(), V::Boolean(false)),
                ("comparison".into(), V::Text("none".into())),
                ("mask".into(), V::Bytes(vec![])),
                ("rounding".into(), V::Text("none".into())),
                ("exceptions".into(), V::Text("none".into())),
                ("predicate".into(), V::Text("none".into())),
                ("target".into(), V::Option(None)),
                ("flags".into(), V::Vector(vec![])),
            ])),
        ),
    ]))
}
fn option(value: &mut V, key: &str, replacement: V) {
    let V::Record(r) = value else { panic!() };
    let V::Record(options) = r.get_mut("options").unwrap() else {
        panic!()
    };
    options.insert(key.into(), replacement);
}
fn text(value: &str) -> V {
    V::Text(value.into())
}

#[test]
fn catalog_digests_match_independent_python_receipts() {
    let catalogs = Catalogs::load(&mut Budget::new(&Limits::default())).unwrap();
    let hex = |bytes: [u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(catalogs.helper_digest()),
        "e10b8e8df7a6bb46023be33fb175e67ffdb39cca9467d8b3388a2dd78b2ff54a"
    );
    // A service of the first catalog is imported with that catalog's
    // identity, which adding a second catalog has not changed.
    assert_eq!(
        hex(catalogs.service("memory.map").unwrap().1),
        "7cbbc87ceb70207fbc59dfe3fa3882d8ea50c8c9d1cf39c585d3b1c8780c15d6"
    );
    assert_eq!(
        hex(catalogs.service("thread.concurrency").unwrap().1),
        "57a97ffa99c314db7f8ecee461d2ea6873c65e67ffdc6341932077513bfb2d0c"
    );
    assert!(catalogs.helper("unknown").is_err());
    assert!(catalogs.service("memory.load").is_err());
}

#[test]
fn memory_options_and_duplicate_flags() {
    let mut budget = Budget::new(&Limits::default());
    let catalogs = Catalogs::load(&mut budget).unwrap();
    let spec = catalogs.helper("memory_load").unwrap();
    let mut value = record("ordinary");
    option(&mut value, "alignment", V::Unsigned(8));
    option(&mut value, "flags", V::Vector(vec![text("volatile")]));
    verify_options(&value, spec, None, &mut budget).unwrap();
    option(
        &mut value,
        "flags",
        V::Vector(vec![text("volatile"), text("volatile")]),
    );
    assert_eq!(
        verify_options(&value, spec, None, &mut budget)
            .unwrap_err()
            .code(),
        "RT_HELPER_FLAGS"
    );
    option(&mut value, "flags", V::Vector(vec![text("elementwise")]));
    assert_eq!(
        verify_options(&value, spec, None, &mut budget)
            .unwrap_err()
            .code(),
        "RT_HELPER_ELEMENTWISE_POLICY"
    );
}

#[test]
fn atomic_compare_failure_order_and_mask_require_actual_binding() {
    let mut budget = Budget::new(&Limits::default());
    let catalogs = Catalogs::load(&mut budget).unwrap();
    let spec = catalogs.helper("atomic_cmpxchg").unwrap();
    let mut value = record("value_mask");
    option(&mut value, "order", text("seq_cst"));
    option(&mut value, "failure_order", text("acquire"));
    option(&mut value, "comparison", text("value_mask"));
    assert_eq!(
        verify_options(&value, spec, None, &mut budget)
            .unwrap_err()
            .code(),
        "RT_HELPER_ABI_MASK"
    );
    verify_options(&value, spec, Some(&[0xff, 0x01]), &mut budget).unwrap();
    option(&mut value, "mask", V::Bytes(vec![0xff, 0xff]));
    assert_eq!(
        verify_options(&value, spec, Some(&[0xff, 0x01]), &mut budget)
            .unwrap_err()
            .code(),
        "RT_HELPER_ABI_MASK"
    );
    option(&mut value, "mask", V::Bytes(vec![]));
    option(&mut value, "failure_order", text("release"));
    assert_eq!(
        verify_options(&value, spec, Some(&[]), &mut budget)
            .unwrap_err()
            .code(),
        "RT_HELPER_FAILURE_ORDER"
    );
}

#[test]
fn floating_context_predicate_and_fixed_rounding() {
    let mut budget = Budget::new(&Limits::default());
    let catalogs = Catalogs::load(&mut budget).unwrap();
    let mut value = record("constrained");
    assert_eq!(
        verify_options(
            &value,
            catalogs.helper("fp_add").unwrap(),
            None,
            &mut budget
        )
        .unwrap_err()
        .code(),
        "RT_HELPER_FP_CONTEXT"
    );
    option(&mut value, "rounding", text("dynamic"));
    option(&mut value, "exceptions", text("strict"));
    verify_options(
        &value,
        catalogs.helper("fp_add").unwrap(),
        None,
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        verify_options(
            &value,
            catalogs.helper("fp_compare").unwrap(),
            None,
            &mut budget
        )
        .unwrap_err()
        .code(),
        "RT_HELPER_PREDICATE"
    );
    option(&mut value, "predicate", text("oeq"));
    verify_options(
        &value,
        catalogs.helper("fp_compare").unwrap(),
        None,
        &mut budget,
    )
    .unwrap();
    option(&mut value, "predicate", text("none"));
    assert_eq!(
        verify_options(
            &value,
            catalogs.helper("fp_lround").unwrap(),
            None,
            &mut budget
        )
        .unwrap_err()
        .code(),
        "RT_HELPER_ROUND_FIXED"
    );
    option(&mut value, "rounding", text("nearest_away"));
    verify_options(
        &value,
        catalogs.helper("fp_lround").unwrap(),
        None,
        &mut budget,
    )
    .unwrap();
}

#[test]
fn catalog_allocation_refusal_is_resource_failure() {
    let limits = Limits {
        max_derived_bytes: 1,
        ..Limits::default()
    };
    assert!(
        matches!(Catalogs::load(&mut Budget::new(&limits)), Err(error) if error.class() == crate::ErrorClass::Resource)
    );
}

#[test]
fn actual_helper_type_instantiation_uses_complete_context_and_promises() {
    use crate::context::{ObjectContext, field, list};
    use crate::metadata::imports::verify_helper_types;
    for (input, expected) in [
        (include_bytes!("fixtures/helper-load.smo").as_slice(), None),
        (
            include_bytes!("fixtures/helper-load-noundef.smo").as_slice(),
            Some("RT_HELPER_NOUNDEF"),
        ),
        (
            include_bytes!("fixtures/helper-load-type.smo").as_slice(),
            Some("RT_HELPER_TYPE"),
        ),
    ] {
        let object = crate::decode_object(input, Limits::default()).unwrap();
        let mut budget = Budget::new(&Limits::default());
        let ctx = ObjectContext::new(object, &mut budget).unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let catalogs = Catalogs::load(&mut budget).unwrap();
        let record = &list(field(ctx.root(6).unwrap(), "imports").unwrap()).unwrap()[0];
        let result = verify_helper_types(
            &ctx,
            &types,
            record,
            catalogs.helper("memory_load").unwrap(),
            &mut budget,
        );
        if let Some(expected) = expected {
            assert_eq!(result.unwrap_err().code(), expected);
        } else {
            assert!(result.is_ok());
        }
    }
}
