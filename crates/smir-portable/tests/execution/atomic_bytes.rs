//! Independent ordered-byte static checks, without a Rust runtime claim.
use super::unhex;
use crate::{Limits, limits::Budget};
use serde_json::Value;

#[test]
fn scalar_raw8_exchange_and_independent_cas_order_sets() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/smir/portable/conformance/execution/atomic-bytes/cases.json"
    )).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 67);
    for case in cases {
        let name = case["id"].as_str().unwrap();
        let expected = case["rust_expected"].as_str().unwrap();
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        let object = crate::decode_object(&unhex(case["encoded_hex"].as_str().unwrap()), limits).unwrap();
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
