use crate::Limits;
use crate::limits::Budget;
use crate::metadata::records::{
    PatchInterval, StorageKind, StorageView, ZeroShadow, reject_overlaps,
};
use crate::wire::RecordValue as V;
use std::collections::BTreeMap;

fn segment(initial: &[u8], poison: &[u8], undef: &[u8], zero_fill: u64, shadow: &str) -> V {
    V::Record(BTreeMap::from([
        ("id".into(), V::Unsigned(7)),
        ("alignment".into(), V::Unsigned(8)),
        ("mutable".into(), V::Boolean(false)),
        ("initial".into(), V::Bytes(initial.to_vec())),
        ("poison".into(), V::Bytes(poison.to_vec())),
        ("undef".into(), V::Bytes(undef.to_vec())),
        ("zero_fill".into(), V::Unsigned(zero_fill)),
        ("zero_shadow".into(), V::Text(shadow.into())),
    ]))
}

#[test]
fn symbolic_tail_and_clipped_shadow_ranges() {
    let record = segment(
        &[1, 2, 3],
        &[0, 0, 0],
        &[0, 0, 0],
        (1_u64 << 61) - 4,
        "defined",
    );
    let mut budget = Budget::new(&Limits::default());
    let storage = StorageView::parse(&record, &mut budget).unwrap();
    assert_eq!(storage.extent, (1_u64 << 61) - 1);
    let range = storage.range(1, 5).unwrap();
    assert_eq!(range.initial, &[2, 3]);
    assert_eq!(range.zero_tail_bytes, 3);
    assert_eq!(range.zero_tail_shadow, ZeroShadow::Defined);
    let range = storage.range(storage.extent, 0).unwrap();
    assert!(range.initial.is_empty());
    assert_eq!(range.zero_tail_bytes, 0);
    assert!(storage.range(storage.extent, 1).is_err());
    assert!(storage.range(u64::MAX, 1).is_err());
    assert!(storage.fully_defined_readonly(&mut budget).unwrap());
}

#[test]
fn shadow_conflict_and_length_mismatch_reject() {
    for record in [
        segment(&[1], &[], &[0], 0, "defined"),
        segment(&[1], &[1], &[1], 0, "defined"),
    ] {
        let mut budget = Budget::new(&Limits::default());
        assert_eq!(
            StorageView::parse(&record, &mut budget).unwrap_err().code(),
            "RT_SEGMENT_SHADOW"
        );
    }
}

#[test]
fn undefined_tail_is_not_native_metadata() {
    for shadow in ["poison", "undef"] {
        let record = segment(&[], &[], &[], 1_u64 << 61, shadow);
        let mut budget = Budget::new(&Limits::default());
        let storage = StorageView::parse(&record, &mut budget).unwrap();
        assert!(!storage.fully_defined_readonly(&mut budget).unwrap());
        let range = storage.range(123, 1000).unwrap();
        assert!(range.initial.is_empty());
        assert_eq!(range.zero_tail_bytes, 1000);
    }
}

#[test]
fn extent_overflow_and_invalid_shadow_reject() {
    for record in [
        segment(&[1], &[0], &[0], u64::MAX, "defined"),
        segment(&[], &[], &[], 0, "other"),
    ] {
        assert!(StorageView::parse(&record, &mut Budget::new(&Limits::default())).is_err());
    }
}

#[test]
fn patch_boundaries_and_storage_namespaces() {
    let data = StorageKind::Data;
    let tls = StorageKind::Tls;
    let mut patches = [
        PatchInterval::new(data, 1, 8, 8, 16).unwrap(),
        PatchInterval::new(tls, 1, 0, 16, 16).unwrap(),
        PatchInterval::new(data, 1, 0, 8, 16).unwrap(),
    ];
    reject_overlaps(&mut patches, &mut Budget::new(&Limits::default())).unwrap();
    assert!(PatchInterval::new(data, 1, 0, 0, 1).is_err());
    assert!(PatchInterval::new(data, 1, u64::MAX, 1, u64::MAX).is_err());
    assert!(patches[0].intersects(data, 1, 7, 9));
    assert!(!patches[0].intersects(tls, 1, 0, 8));
}

#[test]
fn nested_and_partial_patch_overlap_reject() {
    for (start, length) in [(2, 1), (7, 2), (0, 8)] {
        let mut patches = [
            PatchInterval::new(StorageKind::Data, 1, 0, 8, 16).unwrap(),
            PatchInterval::new(StorageKind::Data, 1, start, length, 16).unwrap(),
        ];
        assert_eq!(
            reject_overlaps(&mut patches, &mut Budget::new(&Limits::default()))
                .unwrap_err()
                .code(),
            "RT_INITIALIZER_OVERLAP"
        );
    }
}

#[test]
fn work_exhaustion_precedes_shadow_scan() {
    let record = segment(&[0; 64], &[0; 64], &[0; 64], 0, "defined");
    let limits = Limits {
        max_semantic_work: 12,
        ..Limits::default()
    };
    assert_eq!(
        StorageView::parse(&record, &mut Budget::new(&limits))
            .unwrap_err()
            .class(),
        crate::ErrorClass::Resource
    );
}
