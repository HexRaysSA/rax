use super::*;

fn blob() -> Vec<u8> {
    let name: Vec<_> = "Native-Test"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let size = (16 + name.len() + 4).next_multiple_of(4);
    let mut data: Vec<_> = [24 + size as u32, size as u32, 4, 0, 1]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    for n in [size as u16, name.len() as u16, 4, 4] {
        data.extend_from_slice(&n.to_le_bytes());
    }
    data.extend_from_slice(&[0; 8]);
    data.extend_from_slice(&name);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.resize(20 + size, 0);
    data.extend_from_slice(&69u32.to_le_bytes());
    data
}

#[test]
fn catalog_names_have_checked_extents_and_exact_case() {
    let original = blob();
    let parsed = names(&original).unwrap();
    assert_eq!(
        parsed,
        BTreeSet::from(["Native-Test".encode_utf16().collect()])
    );
    for end in 0..original.len() {
        assert!(names(&original[..end]).is_err());
    }
    for (at, value) in [(0, 0), (4, u32::MAX), (8, u32::MAX), (12, 1), (16, 2)] {
        let mut bytes = original.clone();
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(names(&bytes).is_err(), "header offset {at}");
    }
    let catalog = Catalog::fixture([("Native-Test", 4, 17u32.to_le_bytes().to_vec())]);
    assert_eq!(
        catalog
            .value(&"Native-Test".encode_utf16().collect::<Vec<_>>())
            .unwrap()
            .kind,
        4
    );
    assert_eq!(
        catalog
            .value(&"native-test".encode_utf16().collect::<Vec<_>>())
            .unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[test]
fn capture_uses_native_override_bytes_and_preserves_native_errors() {
    let names = BTreeSet::from([vec![65], vec![66]]);
    let catalog = capture_with(&names, |name, data, kind, required| {
        if name == [66] {
            *required = 0;
            return 0xC000_0272;
        }
        *required = 3;
        *kind = 3;
        if data.is_empty() {
            return STATUS_BUFFER_TOO_SMALL;
        }
        data.copy_from_slice(&[9, 8, 7]);
        0
    })
    .unwrap();
    assert_eq!(&*catalog.value(&[65]).unwrap().data, [9, 8, 7]);
    assert_eq!(catalog.value(&[66]).unwrap_err(), 0xC000_0272);
}

#[test]
fn changing_or_undefined_native_bytes_do_not_enter_the_snapshot() {
    let names = BTreeSet::from([vec![65]]);
    for changing in [false, true] {
        let mut calls = 0;
        let result = capture_with(&names, |_, data, kind, required| {
            calls += 1;
            *required = 4;
            *kind = 4;
            if data.is_empty() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if changing {
                data.fill(calls);
            } else {
                data[..3].fill(0);
            }
            0
        });
        assert!(result.is_err());
        assert_eq!(calls, 9);
    }
}

#[test]
fn size_bound_prevents_value_allocation_and_data_query() {
    let names = BTreeSet::from([vec![65]]);
    for required in [0, MAX_VALUE as u32 + 1, u32::MAX] {
        let mut calls = 0;
        assert!(
            capture_with(&names, |_, data, _, size| {
                calls += 1;
                assert!(data.is_empty());
                *size = required;
                STATUS_BUFFER_TOO_SMALL
            })
            .is_err()
        );
        assert_eq!(calls, 1);
    }
}

#[test]
fn native_private_names_may_leave_type_untouched_on_the_size_query() {
    let selected = BTreeSet::from([vec![65]]);
    let captured = capture_with(&selected, |_, data, kind, size| {
        *size = 4;
        if data.is_empty() {
            return STATUS_BUFFER_TOO_SMALL;
        }
        *kind = 3;
        data.copy_from_slice(&[1, 2, 3, 4]);
        0
    })
    .unwrap();
    assert_eq!(captured.value(&[65]).unwrap().kind, 3);
    assert_eq!(&*captured.value(&[65]).unwrap().data, [1, 2, 3, 4]);
    assert!(
        capture_with(&selected, |_, data, _, size| {
            *size = 4;
            if data.is_empty() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            data.fill(0);
            0
        })
        .is_err()
    );
}
