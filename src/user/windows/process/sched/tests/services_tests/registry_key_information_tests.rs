//! Actual guest service calls against independently frozen native records.
use super::*;
use crate::user::windows::registry::{NLS_CUSTOM_LOCALE_KEY, TreeRoot, nls_tree_fixture};

#[path = "registry_key_information_guard_tests.rs"]
mod guards;

#[path = "registry_key_information_tags_tests.rs"]
mod tags;

#[test]
fn native_key_information_guest_classes_lengths_aliases_and_snapshot_lifetime_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = p
            .registry
            .clone()
            .with_information_tree(TreeRoot::NlsCustomLocale, Some(nls_tree_fixture()))
            .unwrap();
        let path: Vec<_> = NLS_CUSTOM_LOCALE_KEY.encode_utf16().collect();
        let key = p.registry.key(&path).unwrap();
        let attrs = base + 2 * PAGE_SIZE;
        unicode(p, attrs + 64, attrs + 256, NLS_CUSTOM_LOCALE_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x240);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
            STATUS_SUCCESS
        );
        let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
        let duplicate = p.objects.duplicate(handle, false).unwrap() as u64;
        assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
        p.registry = Registry::default();
        for class in [0, 1, 2, 3, 4, 5, 6, 8] {
            let information = key.information().unwrap();
            let record = information.record(class).unwrap();
            let minimum = crate::user::windows::registry::KeyInformation::minimum(class).unwrap();
            for length in (0..=record.len() + 3).chain([256]) {
                for alias in [None, Some(0), Some(4), Some(28), Some(32)] {
                    let output = base + 128;
                    let returned = alias.map_or(base + 64, |offset| output + offset);
                    p.space.wr(base + 64, &[0xA5; 384]).unwrap();
                    let status = call(
                        p,
                        &mut t,
                        "NtQueryKey",
                        &[duplicate, u64::from(class), output, length as u64, returned],
                    );
                    let mut expected = vec![0xA5; 256];
                    if let Some(offset) = alias {
                        expected[offset as usize..offset as usize + 4]
                            .copy_from_slice(&(record.len() as u32).to_le_bytes());
                    }
                    let expected_status = if length < minimum {
                        STATUS_BUFFER_TOO_SMALL
                    } else {
                        let copied = record.len().min(length);
                        expected[..copied].copy_from_slice(&record[..copied]);
                        if information.zero_partial_name_tail(class, length) {
                            expected[copied - 1] = 0;
                        }
                        if length < record.len() {
                            STATUS_BUFFER_OVERFLOW
                        } else {
                            STATUS_SUCCESS
                        }
                    };
                    assert_eq!(
                        status, expected_status,
                        "{arch}/class{class}/len{length}/alias{alias:?}"
                    );
                    assert_eq!(
                        p.space.bytes(output, 256).unwrap(),
                        expected,
                        "{arch}/class{class}/len{length}/alias{alias:?}"
                    );
                    let expected_returned = alias.map_or(record.len() as u32, |offset| {
                        u32::from_le_bytes(
                            expected[offset as usize..offset as usize + 4]
                                .try_into()
                                .unwrap(),
                        )
                    });
                    assert_eq!(p.space.u32(returned).unwrap(), expected_returned);
                }
            }
        }
        assert_eq!(call(p, &mut t, "NtClose", &[duplicate]), STATUS_SUCCESS);
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryKey",
                &[duplicate, 3, base + 128, 256, base + 64]
            ),
            STATUS_INVALID_HANDLE
        );
    }
}
