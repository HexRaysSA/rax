use crate::metadata::symbols::{SymbolKind, verify_local, verify_manifest};
use crate::{Limits, context::ObjectContext, decode_object, limits::Budget};

fn context(input: &[u8]) -> ObjectContext {
    ObjectContext::new(
        decode_object(input, Limits::default()).unwrap(),
        &mut Budget::new(&Limits::default()),
    )
    .unwrap()
}

#[test]
fn actual_alias_owner_and_local_snapshot_are_preserved() {
    let ctx = context(include_bytes!("fixtures/base.smo"));
    let symbols = verify_local(&ctx, &mut Budget::new(&Limits::default())).unwrap();
    assert_eq!(symbols.identity(), ctx.identity());
    assert_eq!(symbols.context_id(), ctx.context_id());
    assert_eq!(symbols.physical(1), Some((SymbolKind::Data, 12)));
    assert_eq!(symbols.physical(2), Some((SymbolKind::Data, 12)));
    assert_eq!(symbols.physical(3), Some((SymbolKind::Tls, 12)));
    assert_eq!(symbols.physical(4), None);
    assert_eq!(symbols.symbol(4).unwrap().binding, "weak");
    assert!(symbols.symbol(99).is_err());
}

#[test]
fn real_local_alias_and_fallback_cycles_reject() {
    for input in [
        include_bytes!("fixtures/alias-cycle.smo").as_slice(),
        include_bytes!("fixtures/fallback-cycle.smo").as_slice(),
    ] {
        let ctx = context(input);
        assert!(
            matches!(verify_local(&ctx,&mut Budget::new(&Limits::default())),Err(e) if e.code()=="RT_ALIAS_CYCLE")
        );
    }
    let ctx = context(include_bytes!("fixtures/alias-kind.smo"));
    assert!(
        matches!(verify_local(&ctx,&mut Budget::new(&Limits::default())),Err(e) if e.code()=="RT_ALIAS_KIND")
    );
}

#[test]
fn comdat_actual_membership_includes_aliases() {
    let ctx = context(include_bytes!("fixtures/comdat.smo"));
    let symbols = verify_local(&ctx, &mut Budget::new(&Limits::default())).unwrap();
    assert_eq!(symbols.symbol(2).unwrap().comdat, Some(0));
    let ctx = context(include_bytes!("fixtures/comdat-missing-member.smo"));
    assert!(
        matches!(verify_local(&ctx,&mut Budget::new(&Limits::default())),Err(e) if e.code()=="RT_COMDAT_MEMBERSHIP")
    );
}

#[test]
fn static_manifest_keeps_valid_unresolved_consumer_declarations() {
    let ctx = context(include_bytes!("fixtures/base.smo"));
    let mut budget = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
    verify_manifest(&ctx, &types, &mut budget).unwrap();
    // There is no provider in this object. Declared ID99 is not local segment12.
    assert!(ctx.declaration(3, 99).is_ok());
    assert!(ctx.declaration(3, 12).is_err());
}

#[test]
fn function_definition_cannot_be_admitted_as_data_tls_or_import() {
    for input in [
        include_bytes!("fixtures/function-as-data.smo").as_slice(),
        include_bytes!("fixtures/function-as-tls.smo").as_slice(),
        include_bytes!("fixtures/function-as-import.smo").as_slice(),
    ] {
        let ctx = context(input);
        assert!(
            matches!(verify_local(&ctx,&mut Budget::new(&Limits::default())),Err(e) if e.code()=="RT_DEFINITION_DOMAIN")
        );
    }
}

#[test]
fn common_objects_cannot_retain_function_execution_or_source_type() {
    use crate::context::{field, list, optional};
    use crate::metadata::{
        imports::nominal_expectation,
        linking::{verify_execution_category, verify_nominal_category},
    };
    for (input, expected) in [
        (
            include_bytes!("fixtures/common-function-type.smo").as_slice(),
            Some("RT_SYMBOL_SIGNATURE"),
        ),
        (
            include_bytes!("fixtures/common-function-nominal.smo").as_slice(),
            Some("RT_SOURCE_FUNCTION_NOMINAL"),
        ),
        (
            include_bytes!("fixtures/common-untyped.smo").as_slice(),
            None,
        ),
    ] {
        let ctx = context(input);
        let mut budget = Budget::new(&Limits::default());
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let symbol = &list(field(ctx.root(2).unwrap(), "symbols").unwrap()).unwrap()[0];
        let execution = types
            .type_record(
                types
                    .type_reference(field(symbol, "execution").unwrap())
                    .unwrap(),
            )
            .unwrap();
        let result = verify_execution_category("data", execution).and_then(|()| {
            if let Some(nominal) = optional(field(symbol, "nominal").unwrap()).unwrap() {
                verify_nominal_category(
                    symbol,
                    ctx.entity(nominal_expectation(&ctx, nominal).unwrap())
                        .unwrap(),
                )
            } else {
                Ok(())
            }
        });
        if let Some(expected) = expected {
            assert_eq!(result.unwrap_err().code(), expected);
        } else {
            result.unwrap();
        }
    }
}

#[test]
fn function_pointer_values_are_objects_in_the_category_predicate() {
    use crate::metadata::linking::{verify_execution_category, verify_nominal_category};
    use crate::wire::RecordValue as V;
    use std::collections::BTreeMap;
    // This unit tests only the category predicate, not complete ABI record admission.
    let pointer = V::Record(BTreeMap::from([(
        "kind".into(),
        V::Text("code_ptr".into()),
    )]));
    let nominal = V::Record(BTreeMap::from([("kind".into(), V::Text("pointer".into()))]));
    for kind in ["data", "tls"] {
        verify_execution_category(kind, &pointer).unwrap();
        let symbol = V::Record(BTreeMap::from([("kind".into(), V::Text(kind.into()))]));
        verify_nominal_category(&symbol, &nominal).unwrap();
    }
    assert!(verify_execution_category("function", &pointer).is_err());
}
