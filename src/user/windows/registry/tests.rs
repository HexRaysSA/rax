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

fn selected(path: &'static str, values: Vec<Value>) -> SelectedKey {
    SelectedKey {
        path,
        values,
        children: 3,
    }
}

#[test]
fn selected_runtime_registry_namespace_is_scoped_shares_collation_and_retains_owners() {
    let registry = Registry::selected(
        upcase(),
        vec![
            selected(NLS_KEY, vec![value(&[49, 50, 53, 50], vec![1])]),
            selected(
                SESSION_MANAGER_KEY,
                vec![
                    value(&[49, 50, 51, 52], vec![2]),
                    value(&[0xD800, 97], vec![0xFF, 0]),
                ],
            ),
        ],
    )
    .unwrap();
    let nls = registry
        .key(&NLS_KEY.to_lowercase().encode_utf16().collect::<Vec<_>>())
        .unwrap();
    let session = registry
        .key(
            &SESSION_MANAGER_KEY
                .to_lowercase()
                .encode_utf16()
                .collect::<Vec<_>>(),
        )
        .unwrap();
    assert!(Arc::ptr_eq(&nls.upcase, &session.upcase));
    assert_eq!(
        registry.codepages().into_iter().collect::<Vec<_>>(),
        vec![1252]
    );
    assert_eq!(session.value(&[0xD800, 65]).unwrap().data, vec![0xFF, 0]);
    assert!(
        registry
            .key(
                &"\\Registry\\Machine\\unknown"
                    .encode_utf16()
                    .collect::<Vec<_>>()
            )
            .is_none()
    );
    let weak = Arc::downgrade(&session);
    let collation = Arc::downgrade(&session.upcase);
    drop(registry);
    drop(nls);
    assert!(weak.upgrade().is_some());
    assert!(collation.upgrade().is_some());
    drop(session);
    assert!(weak.upgrade().is_none());
    assert!(collation.upgrade().is_none());
}

#[test]
fn selected_runtime_registry_rejects_key_scope_duplicates_and_aggregate_exhaustion() {
    assert!(
        Registry::selected(
            upcase(),
            vec![selected("\\Registry\\Machine\\arbitrary", vec![])]
        )
        .is_err()
    );
    assert!(
        Registry::selected(
            upcase(),
            vec![selected(NLS_KEY, vec![]), selected(NLS_KEY, vec![])]
        )
        .is_err()
    );
    assert!(
        Registry::selected(
            upcase(),
            vec![
                selected(NLS_KEY, vec![]),
                selected(SESSION_MANAGER_KEY, vec![]),
                selected(NLS_KEY, vec![])
            ]
        )
        .is_err()
    );
    let values = |count: usize| {
        (0..count)
            .map(|i| value(&[0x8000 + i as u16], vec![]))
            .collect()
    };
    assert!(
        Registry::selected(
            upcase(),
            vec![
                selected(NLS_KEY, values(MAX_VALUES)),
                selected(SESSION_MANAGER_KEY, values(1))
            ]
        )
        .is_err()
    );
    assert!(
        Registry::selected(
            upcase(),
            vec![
                selected(NLS_KEY, values(MAX_VALUES / 2)),
                selected(SESSION_MANAGER_KEY, values(MAX_VALUES / 2))
            ]
        )
        .is_ok()
    );
    let payloads = |count: usize| {
        (0..count)
            .map(|i| value(&[0x8000 + i as u16], vec![0; MAX_VALUE_BYTES]))
            .collect()
    };
    assert!(
        Registry::selected(
            upcase(),
            vec![
                selected(NLS_KEY, payloads(8)),
                selected(SESSION_MANAGER_KEY, payloads(9))
            ]
        )
        .is_err()
    );
    assert!(
        Registry::selected(
            upcase(),
            vec![
                selected(NLS_KEY, vec![value(&[97], vec![1])]),
                selected(SESSION_MANAGER_KEY, vec![value(&[65], vec![2])])
            ]
        )
        .is_ok()
    ); // Same value name belongs to distinct keys.
    assert!(
        Registry::selected(upcase(), vec![])
            .unwrap()
            .key(&[])
            .is_none()
    );
}
