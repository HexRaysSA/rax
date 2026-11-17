//! Loading real objects: what lowers, what is refused, and how.

use super::{Module, Type, Value};
use crate::interp::{Exit, Policy, run};
use crate::{ErrorClass, Limits};

fn object(relative: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../docs/specifications/smir/portable/conformance/{relative}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn generic(name: &str) -> Vec<u8> {
    object(&format!("llvm/generic-functions/{name}.smo"))
}

#[test]
fn valid_modules_outside_the_scalar_subset_are_refused_whole_before_running() {
    for (name, kind) in [
        ("struct", "struct"),
        ("raw256", "raw"),
        ("vector", "vector"),
        ("array", "array"),
    ] {
        // The static verifier accepts these objects; only execution is missing.
        crate::verify_object(&generic(name), Limits::default())
            .unwrap_or_else(|error| panic!("{name} should verify: {error}"));
        let error = Module::load(&generic(name), Limits::default()).expect_err(name);
        assert_eq!(error.class(), ErrorClass::Unimplemented, "{name}");
        assert_eq!(error.code(), "EXEC_UNIMPLEMENTED", "{name}");
        assert_eq!(error.context(), format!("value type {kind}"), "{name}");
    }
}

#[test]
fn objects_the_verifier_rejects_keep_the_verifier_s_error() {
    let error = Module::load(&[0; 4], Limits::default()).expect_err("four zero bytes");
    assert_eq!(error.class(), ErrorClass::Framing);
    let mut truncated = generic("int64");
    truncated.truncate(truncated.len() - 8);
    let error = Module::load(&truncated, Limits::default()).expect_err("truncated object");
    assert_ne!(error.class(), ErrorClass::Unimplemented);
}

#[test]
fn integers_wider_than_the_reference_runner_s_limit_execute() {
    // The reference command-line runner stops at 64 bits; the format does not.
    let module = Module::load(&generic("int65"), Limits::default()).expect("int65 lowers");
    let entry = module.function(0).expect("function 0");
    assert!(matches!(
        module.ty(module.signature(entry).params()[0]),
        Type::Int { bits: 65 }
    ));
    for argument in [0, 1, 1 << 64, (1 << 65) - 1] {
        let outcome = run(&module, entry, &[Value::Int(argument)], Policy::default()).unwrap();
        assert_eq!(outcome.exit, Exit::Return(vec![Value::Int(argument)]));
    }
    // A value that needs 66 bits is not a 65-bit integer.
    let error = run(&module, entry, &[Value::Int(1 << 65)], Policy::default()).unwrap_err();
    assert_eq!(error.code(), "EXEC_ENTRY");
}

#[test]
fn functions_may_return_nothing_or_several_values() {
    let module = Module::load(&generic("void"), Limits::default()).expect("void lowers");
    let outcome = run(&module, module.function(0).unwrap(), &[], Policy::default()).unwrap();
    assert_eq!((outcome.exit, outcome.steps), (Exit::Return(vec![]), 2));

    let module = Module::load(&generic("mixed-multi-results"), Limits::default()).expect("lowers");
    let entry = module.function(0).unwrap();
    assert_eq!(module.signature(entry).results().len(), 2);
    let arguments = [Value::Int(7), Value::Int(9)];
    let outcome = run(&module, entry, &arguments, Policy::default()).unwrap();
    assert_eq!(outcome.exit, Exit::Return(arguments.to_vec()));
}

#[test]
fn types_with_different_identifiers_and_the_same_structure_are_the_same_type() {
    let module = Module::load(
        &object("envelope/candidate/reference-execution/call42.smo"),
        Limits::default(),
    )
    .expect("call42 lowers");
    let of_width = |bits: u32| -> Vec<super::TypeId> {
        (0..module.types.len() as u32)
            .map(super::TypeId)
            .filter(|id| matches!(module.ty(*id), Type::Int { bits: width } if *width == bits))
            .collect()
    };
    let (narrow, wide) = (of_width(32), of_width(64));
    // The object declares 32-bit integers under three identifiers.
    assert!(narrow.len() >= 3 && !wide.is_empty());
    for left in &narrow {
        for right in &narrow {
            assert!(module.same_type(*left, *right));
        }
        assert!(!module.same_type(*left, wide[0]));
    }
}
