//! Independent Python-authored static cases; no runtime/native execution claims.

use super::unhex;
use crate::{Limits, limits::Budget};
use serde_json::Value;

#[test]
fn code_address_local_and_genuine_source_plan_cases() {
    let corpus: Value = serde_json::from_str(include_str!("function-address-cases.json")).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 23);
    let mut local = 0;
    let mut source = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = case["rust_expected"].as_str().unwrap();
        let limits = Limits::default();
        let wire = unhex(case["encoded_hex"].as_str().unwrap());
        let mut budget = Budget::new(&limits);
        let object =
            crate::decode_object(&wire, limits).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let ctx = crate::context::ObjectContext::new(object, &mut budget)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let actual = (|| -> Result<(), crate::Error> {
            let types = crate::execution::verify_types(&ctx, &mut budget)?;
            if case["oracle_scope"] == "execution-local" {
                local += 1;
                crate::execution::check_function_core(&ctx, &types, 0, &mut budget)
            } else {
                source += 1;
                let abi = crate::abi::verify(&ctx, &types, &mut budget)?;
                crate::execution::check_function_source_and_eh(&ctx, &types, &abi, 0, &mut budget)
            }
        })();
        if expected == "ok" {
            assert!(actual.is_ok(), "{name}: {actual:?}");
        } else {
            let error = actual
                .err()
                .unwrap_or_else(|| panic!("{name}: invalid static case accepted"));
            assert_eq!(
                error.class(),
                crate::ErrorClass::Semantic,
                "{name}: {error:?}"
            );
            assert_eq!(error.code(), expected, "{name}: {error:?}");
        }
    }
    assert_eq!((local, source), (13, 10));
}

/// Independent ordered-byte decode and real type/body predicate. No Rust engine
/// or runtime authority is asserted by these local execution-only fixtures.
#[test]
fn code_address_bit_literals_keep_other_pointer_rejections() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/smir/portable/conformance/execution/function-addresses/literal-values/cases.json"
    )).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let name = case["id"].as_str().unwrap();
        let expected = case["rust_expected"].as_str().unwrap();
        let limits = Limits::default();
        let wire = unhex(case["encoded_hex"].as_str().unwrap());
        let mut budget = Budget::new(&limits);
        let object = crate::decode_object(&wire, limits).unwrap();
        let ctx = crate::context::ObjectContext::new(object, &mut budget).unwrap();
        let result = (|| -> Result<(), crate::Error> {
            let types = crate::execution::verify_types(&ctx, &mut budget)?;
            crate::execution::check_function_core(&ctx, &types, 0, &mut budget)
        })();
        if expected == "ok" {
            assert!(result.is_ok(), "{name}: {result:?}");
        } else {
            let error = result.err().unwrap_or_else(|| panic!("{name}: accepted"));
            assert_eq!(error.class(), crate::ErrorClass::Semantic, "{name}: {error:?}");
            assert_eq!(error.code(), expected, "{name}: {error:?}");
        }
    }
}
