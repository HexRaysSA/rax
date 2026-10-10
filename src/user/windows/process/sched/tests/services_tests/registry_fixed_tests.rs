use super::*;
use crate::user::windows::registry::{SEGMENT_HEAP_KEY, SESSION_MANAGER_KEY, SelectedKey};

fn prepare_parent(p: &mut Proc) {
    p.registry = Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![SelectedKey {
            path: SESSION_MANAGER_KEY,
            children: 3,
            values: vec![],
        }],
    )
    .unwrap();
}

#[test]
fn native_segment_heap_absent_absolute_relative_and_partial_parent_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        prepare_parent(p);
        p.registry = p.registry.clone().with_segment_heap(None).unwrap();
        let attrs = base + PAGE_SIZE * 2;
        for view in [0, 0x100, 0x200] {
            unicode(p, attrs + 64, attrs + 128, SEGMENT_HEAP_KEY);
            attributes(p, attrs, attrs + 64, 0, 0x240);
            assert_eq!(
                call(p, &mut t, "NtOpenKey", &[base, 1 | view, attrs]),
                STATUS_OBJECT_NAME_NOT_FOUND
            );
            assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
        }
        unicode(p, attrs + 64, attrs + 128, SESSION_MANAGER_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x240);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 9, attrs]),
            STATUS_SUCCESS
        );
        let parent = p.space.ptr(base, arch.ptr_size()).unwrap();
        p.registry = Registry::default();
        for name in ["Segment Heap", "segment heap\\", "Segment Heap\\nested"] {
            unicode(p, attrs + 64, attrs + 128, name);
            attributes(p, attrs, attrs + 64, parent, 0x240);
            assert_eq!(
                call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
                STATUS_OBJECT_NAME_NOT_FOUND
            );
        }
        unicode(p, attrs + 64, attrs + 128, "unknown-sibling");
        attributes(p, attrs, attrs + 64, parent, 0x240);
        arguments(p, &mut t, &[base, 1, attrs]);
        assert!(
            matches!(dispatch(p, &mut t), Outcome::Fail(reason) if reason.contains("unsnapshotted registry subkey"))
        );
        assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
    }
}

#[test]
fn native_segment_heap_present_raw_values_and_descendant_handle_lifetime_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        prepare_parent(p);
        p.registry = p
            .registry
            .clone()
            .with_segment_heap(Some(SelectedKey {
                path: SEGMENT_HEAP_KEY,
                children: 0,
                values: vec![Value {
                    name: "Enabled".encode_utf16().collect(),
                    kind: 4,
                    data: 0xA1B2_C3D4u32.to_le_bytes().to_vec(),
                }],
            }))
            .unwrap();
        let attrs = base + PAGE_SIZE * 2;
        unicode(p, attrs + 64, attrs + 128, SESSION_MANAGER_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x240);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 9, attrs]),
            STATUS_SUCCESS
        );
        let parent = p.space.ptr(base, arch.ptr_size()).unwrap();
        p.registry = Registry::default();
        unicode(p, attrs + 64, attrs + 128, "segment heap");
        attributes(p, attrs, attrs + 64, parent, 0x240);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 2, attrs]),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
            STATUS_SUCCESS
        );
        let child = p.space.ptr(base, arch.ptr_size()).unwrap();
        assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
        unicode(p, attrs + 64, attrs + 128, "enabled");
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryValueKey",
                &[child, attrs + 64, 2, base + 128, 16, base + PAGE_SIZE]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(base + 132).unwrap(), 4);
        assert_eq!(p.space.u32(base + 136).unwrap(), 4);
        assert_eq!(p.space.u32(base + 140).unwrap(), 0xA1B2_C3D4);
        assert_eq!(p.space.u32(base + PAGE_SIZE).unwrap(), 16);
        assert_eq!(call(p, &mut t, "NtClose", &[child]), STATUS_SUCCESS);
    }
}
