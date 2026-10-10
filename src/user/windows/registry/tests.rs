use super::*;

fn upcase() -> Vec<u16> {
    (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect()
}
fn value(name: &[u16], data: Vec<u8>) -> Value {
    Value {
        name: name.to_vec(),
        kind: 0xFFFF_FFFF,
        data,
    }
}
#[test]
fn registry_preserves_raw_type_bytes_surrogates_and_snapshot_handle_ownership() {
    let original = value(&[0xD800, 0x61, 0, 0xDC00], vec![0xFF, 0, 1]);
    let registry = Registry::nls(upcase(), vec![original.clone()], 7).unwrap();
    let key = registry
        .key(&NLS_KEY.to_lowercase().encode_utf16().collect::<Vec<_>>())
        .unwrap();
    assert_eq!(key.children, 7);
    assert_eq!(key.value(&[0xD800, 0x41, 0, 0xDC00]), Some(&original));
    let weak = Arc::downgrade(&key);
    drop(registry);
    assert!(weak.upgrade().is_some());
    drop(key);
    assert!(weak.upgrade().is_none());
    assert!(
        Registry::default()
            .key(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
            .is_none()
    );
}
#[test]
fn registry_snapshot_rejects_table_count_name_data_total_and_case_collisions() {
    assert!(Registry::nls(vec![0; 65_535], vec![], 0).is_err());
    assert!(Registry::nls(upcase(), vec![value(&[], vec![]); MAX_VALUES + 1], 0).is_err());
    assert!(
        Registry::nls(
            upcase(),
            vec![value(&vec![1; MAX_NAME_UNITS + 1], vec![])],
            0
        )
        .is_err()
    );
    assert!(Registry::nls(upcase(), vec![value(&[], vec![0; MAX_VALUE_BYTES + 1])], 0).is_err());
    assert!(
        Registry::nls(
            upcase(),
            vec![value(&[97], vec![]), value(&[65], vec![])],
            0
        )
        .is_err()
    );
    let values = (0..17)
        .map(|u| value(&[u], vec![0; MAX_VALUE_BYTES]))
        .collect();
    assert!(Registry::nls(upcase(), values, 0).is_err());
    let values = (0..MAX_VALUES)
        .map(|u| value(&[u as u16], vec![]))
        .collect();
    assert!(Registry::nls(upcase(), values, 0).is_err()); // ASCII folded duplicates.
    let values = (0..MAX_VALUES)
        .map(|u| value(&[0x8000 + u as u16], vec![]))
        .collect();
    assert!(Registry::nls(upcase(), values, 0).is_ok());
    assert!(
        Registry::nls(
            upcase(),
            vec![value(
                &vec![0xD800; MAX_NAME_UNITS],
                vec![0; MAX_VALUE_BYTES]
            )],
            0
        )
        .is_ok()
    );
}
