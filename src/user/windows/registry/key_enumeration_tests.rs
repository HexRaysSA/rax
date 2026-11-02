use super::*;

fn upcase() -> Vec<u16> {
    (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect()
}
fn child(name: &str, last_write: u64) -> BasicChild {
    BasicChild {
        name: name.encode_utf16().collect(),
        last_write,
    }
}

#[test]
fn enumeration_keeps_native_order_case_time_and_unknown_distinct_from_empty() {
    let table = upcase();
    let entries = vec![child("z-last", 0x1122_3344_5566_7788), child("A-first", 9)];
    let mut budget = ValueBudget::default();
    let selected = bounded(&table, Some(entries.clone()), 2, &mut budget)
        .unwrap()
        .unwrap();
    assert_eq!(&*selected, entries.as_slice());
    assert_eq!(budget.enumeration_count, 2);
    assert!(bounded(&table, None, 2, &mut budget).unwrap().is_none());
    assert!(
        bounded(&table, Some(vec![]), 0, &mut budget)
            .unwrap()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn enumeration_rejects_count_grammar_ordinal_duplicates_and_aggregate_exhaustion() {
    let table = upcase();
    for (entries, count) in [
        (vec![child("one", 1)], 2),
        (vec![child("", 1)], 1),
        (vec![child("a\\b", 1)], 1),
        (vec![child("a\0b", 1)], 1),
        (vec![child(&"x".repeat(256), 1)], 1),
        (vec![child("Same", 1), child("same", 2)], 2),
    ] {
        assert!(bounded(&table, Some(entries), count, &mut ValueBudget::default()).is_err());
    }
    let mut budget = ValueBudget::default();
    budget.enumeration_count = 2 * tree::MAX_TREE_KEYS;
    assert!(bounded(&table, Some(vec![child("one", 1)]), 1, &mut budget).is_err());
    let mut budget = ValueBudget::default();
    budget.enumeration_bytes = 1 << 20;
    assert!(bounded(&table, Some(vec![child("one", 1)]), 1, &mut budget).is_err());
}
