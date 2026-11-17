use crate::metadata::relocations::{RelocationKind, verify_shape};
use crate::{Limits, limits::Budget, wire::RecordValue as V};
use std::collections::BTreeMap;

fn leaf(kind: &str, width: u64, bits: u64, check_base: bool, flags: &[&str]) -> V {
    V::Record(BTreeMap::from([
        ("kind".into(), V::Text(kind.into())),
        ("width".into(), V::Unsigned(width)),
        ("integer_bits".into(), V::Unsigned(bits)),
        ("derivation".into(), V::Vector(vec![])),
        ("addend".into(), V::Signed(0)),
        ("check_base".into(), V::Boolean(check_base)),
        (
            "flags".into(),
            V::Vector(flags.iter().map(|v| V::Text((*v).into())).collect()),
        ),
        ("inrange".into(), V::Option(None)),
    ]))
}

#[test]
fn all_eight_relocation_kinds_and_integer_precision() {
    for (name, width, bits, result) in [
        ("data_address", 8, 0, RelocationKind::DataAddress),
        ("code_address", 8, 0, RelocationKind::CodeAddress),
        ("data_integer", 9, 65, RelocationKind::DataInteger),
        ("tls_offset", 4, 0, RelocationKind::TlsOffset),
        ("function_token", 8, 0, RelocationKind::FunctionToken),
        ("import_token", 8, 0, RelocationKind::ImportToken),
        ("function_integer", 1, 1, RelocationKind::FunctionInteger),
        ("import_integer", 8192, 65535, RelocationKind::ImportInteger),
    ] {
        assert_eq!(
            verify_shape(
                &leaf(name, width, bits, false, &[]),
                &mut Budget::new(&Limits::default())
            )
            .unwrap(),
            result
        );
    }
}

#[test]
fn strict_base_check_requires_inbounds_even_for_zero_addend() {
    let error = verify_shape(
        &leaf("data_address", 8, 0, true, &[]),
        &mut Budget::new(&Limits::default()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "RT_PATCH_CHECK_BASE");
    verify_shape(
        &leaf("data_address", 8, 0, true, &["inbounds"]),
        &mut Budget::new(&Limits::default()),
    )
    .unwrap();
}

#[test]
fn integer_width_and_unused_pointer_options_reject() {
    for value in [
        leaf("data_integer", 8, 65, false, &[]),
        leaf("data_address", 4, 0, false, &[]),
        leaf("function_token", 8, 0, true, &["inbounds"]),
        leaf("tls_offset", 4, 0, false, &["nuw"]),
        leaf("data_integer", 1, 0, false, &[]),
    ] {
        assert!(verify_shape(&value, &mut Budget::new(&Limits::default())).is_err());
    }
}

#[test]
fn relocation_flags_are_sorted_unique_closed() {
    for flags in [
        vec!["nuw", "inbounds"],
        vec!["inbounds", "inbounds"],
        vec!["unknown"],
    ] {
        assert_eq!(
            verify_shape(
                &leaf("data_address", 8, 0, false, &flags),
                &mut Budget::new(&Limits::default())
            )
            .unwrap_err()
            .code(),
            "RT_PATCH_FLAGS"
        );
    }
}

fn contextual_patches(
    input: &[u8],
) -> Result<Vec<crate::metadata::relocations::ConstantInitializerFact>, crate::Error> {
    let mut budget = Budget::new(&Limits::default());
    let ctx = crate::context::ObjectContext::new(
        crate::decode_object(input, Limits::default())?,
        &mut budget,
    )?;
    let types = crate::execution::verify_types(&ctx, &mut budget)?;
    let symbols = crate::metadata::symbols::verify_local(&ctx, &mut budget)?;
    crate::metadata::relocations::verify(&ctx, &types, &symbols, &mut budget)
}

#[test]
fn real_leaf_and_constant_headers_use_actual_layout_and_owner_context() {
    assert!(
        contextual_patches(include_bytes!("fixtures/base.smo"))
            .unwrap()
            .is_empty()
    );
    let constant = contextual_patches(include_bytes!("fixtures/constant-header.smo")).unwrap();
    assert_eq!(constant.len(), 1);
    assert_eq!(
        (
            constant[0].source,
            constant[0].offset,
            constant[0].access_bytes
        ),
        (12, 2, 1)
    );
    assert_eq!(constant[0].association, None);
    // This proves the runtime header/patch predicate, not the final ProgramFacts whitelist.
}

#[test]
fn contextual_leaf_overlap_and_function_data_domain_reject() {
    for (input, code) in [
        (
            include_bytes!("fixtures/leaf-overlap.smo").as_slice(),
            "RT_RELOCATION_OVERLAP",
        ),
        (
            include_bytes!("fixtures/leaf-function-as-data.smo").as_slice(),
            "RT_RELOCATION_DOMAIN",
        ),
    ] {
        assert!(matches!(contextual_patches(input),Err(e)if e.code()==code));
    }
}

#[test]
fn contextual_constant_overlap_promises_and_alias_selection_reject() {
    for (input, code) in [
        (
            include_bytes!("fixtures/constant-overlap.smo").as_slice(),
            "RT_INITIALIZER_OVERLAP",
        ),
        (
            include_bytes!("fixtures/constant-noundef.smo").as_slice(),
            "RT_INITIALIZER_SIGNATURE",
        ),
        (
            include_bytes!("fixtures/constant-alias-owner.smo").as_slice(),
            "RT_INITIALIZER_SHARED_SELECTION",
        ),
        (
            include_bytes!("fixtures/constant-split-selection.smo").as_slice(),
            "RT_INITIALIZER_SHARED_SELECTION",
        ),
    ] {
        assert!(matches!(contextual_patches(input),Err(e)if e.code()==code));
    }
}
