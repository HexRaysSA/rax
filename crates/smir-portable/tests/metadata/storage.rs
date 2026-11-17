use crate::context::{ContextId, EntityRef, ModuleRef, Namespace, ObjectContext};
use crate::metadata::storage::{DeclaredMetadataRange, declared_metadata_range, static_raw_range};
use crate::{Limits, decode_object, limits::Budget, wire::RecordValue as V};
use std::collections::BTreeMap;

fn context(input: &[u8]) -> ObjectContext {
    let object = decode_object(input, Limits::default()).unwrap();
    ObjectContext::new(object, &mut Budget::new(&Limits::default())).unwrap()
}
fn reference(module: ModuleRef, id: u32) -> V {
    let fields = match module {
        ModuleRef::SelfModule => BTreeMap::from([("kind".into(), V::Text("self".into()))]),
        ModuleRef::Dependency { slot } => BTreeMap::from([
            ("kind".into(), V::Text("dependency".into())),
            ("slot".into(), V::Unsigned(slot.into())),
        ]),
    };
    V::Record(BTreeMap::from([
        ("module".into(), V::Record(fields)),
        ("id".into(), V::Unsigned(id.into())),
    ]))
}

#[test]
fn direct_metadata_raw_hash_keeps_patch_obligation() {
    let ctx = context(include_bytes!("fixtures/base.smo"));
    let mut budget = Budget::new(&Limits::default());
    let DeclaredMetadataRange::Local(bytes) = declared_metadata_range(
        &ctx,
        &reference(ModuleRef::SelfModule, 1),
        1,
        3,
        &mut budget,
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(bytes.bytes().initial, &[2, 3]);
    assert_eq!(bytes.bytes().zero_tail_bytes, 1);
    assert_eq!(
        bytes.source(),
        Some(EntityRef {
            module: ModuleRef::SelfModule,
            id: 1
        })
    );
    assert_eq!(bytes.offset(), 1);
    assert_eq!(bytes.length(), 3);
    assert_eq!(bytes.identity(), ctx.identity());
    assert_eq!(bytes.context_id(), ctx.context_id());
    assert_eq!(bytes.patches().len(), 1);
    let digest = bytes.sha256(&mut budget).unwrap();
    assert_eq!(
        digest
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>(),
        "01ac26723cbcba804b62c46419db1c078912c2905c421b5be95ed5b3523cb78b"
    );
    assert!(!bytes.mutable());
}

#[test]
fn mutable_poison_undef_and_wrong_full_symbol_size_reject() {
    for input in [
        include_bytes!("fixtures/mutable.smo").as_slice(),
        include_bytes!("fixtures/poison.smo").as_slice(),
        include_bytes!("fixtures/undef.smo").as_slice(),
        include_bytes!("fixtures/wrong-size.smo").as_slice(),
    ] {
        let ctx = context(input);
        assert!(
            declared_metadata_range(
                &ctx,
                &reference(ModuleRef::SelfModule, 1),
                0,
                1,
                &mut Budget::new(&Limits::default())
            )
            .is_err()
        );
    }
}

#[test]
fn aliases_tls_and_missing_weak_are_not_native_metadata() {
    let ctx = context(include_bytes!("fixtures/base.smo"));
    for id in [2, 3, 4] {
        assert!(
            declared_metadata_range(
                &ctx,
                &reference(ModuleRef::SelfModule, id),
                0,
                1,
                &mut Budget::new(&Limits::default())
            )
            .is_err()
        );
    }
    let tls = ctx.local(Namespace::Tls, 12).unwrap();
    let raw = static_raw_range(&ctx, tls, 0, 4, &mut Budget::new(&Limits::default())).unwrap();
    assert_eq!(raw.bytes().initial, &[1, 2, 3]);
    assert_eq!(raw.storage().namespace(), Namespace::Tls);
}

#[test]
fn dependency_is_the_actual_consumer_declaration_and_has_no_bytes() {
    let ctx = context(include_bytes!("fixtures/base.smo"));
    match declared_metadata_range(
        &ctx,
        &reference(ModuleRef::Dependency { slot: 3 }, 99),
        123,
        7,
        &mut Budget::new(&Limits::default()),
    )
    .unwrap()
    {
        DeclaredMetadataRange::Dependency {
            slot,
            declaration,
            offset,
            length,
            expected,
        } => {
            assert_eq!((slot, declaration, offset, length), (3, 99, 123, 7));
            assert_eq!(
                crate::context::unsigned(crate::context::field(expected, "id").unwrap()).unwrap(),
                99
            );
        }
        DeclaredMetadataRange::Local(_) => {
            panic!("external declarations have no local source bytes")
        }
    }
    assert!(
        declared_metadata_range(
            &ctx,
            &reference(ModuleRef::Dependency { slot: 3 }, 12),
            0,
            1,
            &mut Budget::new(&Limits::default())
        )
        .is_err()
    );
}

#[test]
fn metadata_endpoints_and_actual_snapshot_brand_reject() {
    let input = include_bytes!("fixtures/base.smo");
    let first = context(input);
    let second = context(input);
    assert_eq!(first.identity(), second.identity());
    let _: ContextId = first.context_id();
    assert_ne!(first.context_id(), second.context_id());
    let key = first.local(Namespace::Data, 12).unwrap();
    assert!(static_raw_range(&second, key, 0, 1, &mut Budget::new(&Limits::default())).is_err());
    for (offset, length) in [(4, 1), (0, 0), (u64::MAX, 1)] {
        assert!(
            declared_metadata_range(
                &first,
                &reference(ModuleRef::SelfModule, 1),
                offset,
                length,
                &mut Budget::new(&Limits::default())
            )
            .is_err()
        );
    }
}

#[test]
fn huge_zero_tail_hash_exhausts_work_before_hashing_or_materializing() {
    let ctx = context(include_bytes!("fixtures/huge-tail.smo"));
    let extent = (1_u64 << 61) - 1;
    let mut budget = Budget::new(&Limits::default());
    let DeclaredMetadataRange::Local(bytes) = declared_metadata_range(
        &ctx,
        &reference(ModuleRef::SelfModule, 1),
        0,
        extent,
        &mut budget,
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(bytes.bytes().initial, &[1, 2, 3]);
    assert_eq!(bytes.bytes().zero_tail_bytes, extent - 3);
    assert_eq!(
        bytes.sha256(&mut budget).unwrap_err().class(),
        crate::ErrorClass::Resource
    );
}

#[test]
fn source_data_reference_range_and_absolute_patch_oracles() {
    use crate::context::{field, list, unsigned};
    use crate::metadata::records::StorageKind;
    use crate::metadata::storage::PatchKind;

    let ctx = context(include_bytes!("fixtures/constant-header.smo"));
    let DeclaredMetadataRange::Local(bytes) = declared_metadata_range(
        &ctx,
        &reference(ModuleRef::SelfModule, 1),
        1,
        2,
        &mut Budget::new(&Limits::default()),
    )
    .unwrap() else {
        panic!("actual local declared syntax expected")
    };
    assert_eq!(bytes.bytes().initial, &[2, 3]);
    assert_eq!(bytes.bytes().zero_tail_bytes, 0);
    assert_eq!(bytes.storage(), ctx.local(Namespace::Data, 12).unwrap());
    assert_eq!(
        unsigned(field(ctx.entity(bytes.storage()).unwrap(), "alignment").unwrap()).unwrap(),
        1
    );
    let symbol = ctx
        .entity(ctx.local(Namespace::Symbol, 1).unwrap())
        .unwrap();
    assert_eq!(unsigned(field(symbol, "alignment").unwrap()).unwrap(), 1);
    let patches = bytes.patches();
    assert_eq!(patches.len(), 2);
    for (index, name, kind, start, end) in [
        (0, "relocations", PatchKind::Leaf, 1, 2),
        (
            1,
            "constant_initializers",
            PatchKind::ConstantInitializer,
            2,
            3,
        ),
    ] {
        let patch = &patches[index];
        assert_eq!(patch.kind, kind);
        assert_eq!(patch.interval.kind, StorageKind::Data);
        assert_eq!(patch.interval.source, 12);
        assert_eq!((patch.interval.start, patch.interval.end), (start, end));
        let original = &list(field(ctx.root(5).unwrap(), name).unwrap()).unwrap()[0];
        assert!(std::ptr::eq(patch.record, original));
    }
    // Declared bytes remain 2,3. The constant function's 0x2a was not executed,
    // and neither absolute interval was rebased to this query's start.
    assert_eq!(bytes.bytes().initial, &[2, 3]);

    let huge = context(include_bytes!("fixtures/huge-tail.smo"));
    let extent = (1_u64 << 61) - 1;
    let DeclaredMetadataRange::Local(tail) = declared_metadata_range(
        &huge,
        &reference(ModuleRef::SelfModule, 1),
        extent - 8,
        8,
        &mut Budget::new(&Limits::default()),
    )
    .unwrap() else {
        panic!("bounded local zero tail expected")
    };
    assert!(tail.bytes().initial.is_empty());
    assert_eq!(tail.bytes().zero_tail_bytes, 8);
    assert!(tail.patches().is_empty());
    assert_eq!((tail.offset(), tail.length()), (extent - 8, 8));
}
