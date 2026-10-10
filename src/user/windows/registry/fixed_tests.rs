use super::*;

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}
fn registry(children: u32) -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![SelectedKey {
            path: SESSION_MANAGER_KEY,
            children,
            values: vec![Value {
                name: units("Parent"),
                kind: 4,
                data: vec![1],
            }],
        }],
    )
    .unwrap()
}
fn selected() -> SelectedKey {
    SelectedKey {
        path: SEGMENT_HEAP_KEY,
        children: 1,
        values: vec![Value {
            name: units("Enabled"),
            kind: 4,
            data: vec![0, 0, 0, 0],
        }],
    }
}

#[test]
fn segment_heap_partial_selection_preserves_present_absent_scope_and_old_parent() {
    for present in [false, true] {
        let old = registry(3);
        let old_parent = old.key(&units(SESSION_MANAGER_KEY)).unwrap();
        let current = old
            .clone()
            .with_segment_heap(present.then(selected))
            .unwrap();
        let parent = current.key(&units(SESSION_MANAGER_KEY)).unwrap();
        assert!(Arc::ptr_eq(&old_parent.values, &parent.values));
        assert!(matches!(
            old_parent.relative(&units("Segment Heap")),
            Lookup::Unselected
        ));
        assert!(matches!(
            current.lookup(&units(&format!("{SEGMENT_HEAP_KEY}Suffix"))),
            Lookup::Unselected
        ));
        assert!(matches!(
            parent.relative(&units("unknown")),
            Lookup::Unselected
        ));
        let budget = current.value_budget().unwrap();
        assert_eq!(budget.count, if present { 2 } else { 1 });
        drop(old);
        drop(current);
        if present {
            let Lookup::Present(child) = parent.relative(&units("segment heap\\\\")) else {
                panic!("lost child")
            };
            assert!(Arc::ptr_eq(&parent.upcase, &child.upcase));
            assert_eq!(child.value(&units("ENABLED")).unwrap().data, [0, 0, 0, 0]);
            assert!(matches!(
                child.relative(&units("unknown")),
                Lookup::Unselected
            ));
            drop(parent);
            assert!(child.value(&units("Enabled")).is_some());
        } else {
            assert!(matches!(
                parent.relative(&units("segment heap\\nested")),
                Lookup::Missing
            ));
        }
    }
    let absent = registry(3).with_segment_heap(None).unwrap();
    for suffix in ["", "\\", "\\nested"] {
        assert!(matches!(
            absent.lookup(&units(&format!("{SEGMENT_HEAP_KEY}{suffix}"))),
            Lookup::Missing
        ));
    }
    let present = registry(3).with_segment_heap(Some(selected())).unwrap();
    assert!(matches!(
        present.lookup(&units(SEGMENT_HEAP_KEY)),
        Lookup::Present(_)
    ));
    assert!(matches!(
        present.lookup(&units(&format!("{SEGMENT_HEAP_KEY}\\unknown"))),
        Lookup::Unselected
    ));
}

#[test]
fn segment_heap_rejects_invalid_parent_scope_duplicate_and_shared_value_exhaustion() {
    assert!(Registry::default().with_segment_heap(None).is_err());
    assert!(registry(0).with_segment_heap(Some(selected())).is_err());
    assert!(
        registry(3)
            .with_segment_heap(None)
            .unwrap()
            .with_segment_heap(None)
            .is_err()
    );
    let mut invalid = selected();
    invalid.path = NLS_KEY;
    assert!(registry(3).with_segment_heap(Some(invalid)).is_err());
    let mut invalid = selected();
    invalid.values.push(invalid.values[0].clone());
    assert!(registry(3).with_segment_heap(Some(invalid)).is_err());
    let mut invalid = selected();
    invalid.values[0].data = vec![0; MAX_VALUE_BYTES + 1];
    assert!(registry(3).with_segment_heap(Some(invalid)).is_err());
    let mut full = registry(3);
    let parent = full.keys.values().next().unwrap();
    full = Registry::selected(
        parent.upcase.to_vec(),
        vec![SelectedKey {
            path: SESSION_MANAGER_KEY,
            children: 3,
            values: (0..MAX_VALUES)
                .map(|i| Value {
                    name: vec![0x8000 + i as u16],
                    kind: 4,
                    data: vec![],
                })
                .collect(),
        }],
    )
    .unwrap();
    assert!(full.with_segment_heap(Some(selected())).is_err());
}
