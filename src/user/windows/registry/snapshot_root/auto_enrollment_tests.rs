use super::*;

#[test]
fn auto_enrollment_snapshot_replays_native_absence_and_keeps_views_independent() {
    let wide = |text: &str| text.encode_utf16().collect::<Vec<_>>();
    let subject = SnapshotRoot::AutoEnrollment;
    let native = RegistryView::Native64;
    let wow = RegistryView::Wow32;
    let access = KeyAccess {
        maximum_access: 0x20019,
        system_security_status: crate::user::windows::nt::status::STATUS_PRIVILEGE_NOT_HELD,
    };
    let initial = Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap();
    let header = |path: &str, values| CommandHeader {
        canonical: wide(path),
        children: 1,
        enumeration: None,
        values,
        access,
    };
    let value = Value {
        name: wide("RawHex"),
        kind: 4,
        data: 1u32.to_le_bytes().to_vec(),
    };
    let logical = wide(AUTO_ENROLLMENT_KEY);
    let physical = wide(AUTO_ENROLLMENT_WOW_KEY);
    let base = initial
        .with_snapshot_selection(
            subject,
            &[],
            native,
            Ok((header(AUTO_ENROLLMENT_KEY, vec![]), None)),
        )
        .unwrap();
    assert!(
        base.clone()
            .with_snapshot_selection(
                subject,
                &[],
                wow,
                Ok((header(AUTO_ENROLLMENT_KEY, vec![]), None)),
            )
            .is_err()
    );
    let r = base
        .clone()
        .with_snapshot_selection(
            subject,
            &[],
            wow,
            Ok((header(AUTO_ENROLLMENT_WOW_KEY, vec![value.clone()]), None)),
        )
        .unwrap();
    let r = r
        .with_machine_hive(MachineHeader {
            enumeration: None,
            canonical: wide(MACHINE_HIVE_KEY),
            children: 1,
            values: vec![],
            access,
        })
        .unwrap();
    let machine = r.key(&wide(MACHINE_HIVE_KEY)).unwrap();
    let relative = wide("Software\\Microsoft\\Cryptography\\AutoEnrollment");
    let Lookup::Present(native_key) = machine.relative_in_view(&relative, native) else {
        panic!("native AutoEnrollment root");
    };
    assert_eq!(native_key.path, logical);
    for name in ["Debug", "RawHex", "Unicode"] {
        assert!(native_key.value(&wide(name)).is_none());
    }
    let Lookup::Present(wow_key) = machine.relative_in_view(&relative, wow) else {
        panic!("x86 AutoEnrollment root");
    };
    assert_eq!(wow_key.path, physical);
    assert_eq!(wow_key.value(&wide("rawHEX")), Some(&value));
    for view in [native, wow] {
        let Lookup::Present(physical_key) = r.lookup_view(&physical, view) else {
            panic!("explicit physical AutoEnrollment");
        };
        assert!(Arc::ptr_eq(&physical_key, &wow_key));
        assert!(matches!(
            machine.relative_in_view(&wide("Software\\Microsoft\\Cryptography\\OID"), view),
            Lookup::Unselected
        ));
    }
    assert!(matches!(
        native_key.relative(&wide("Child")),
        Lookup::Unselected
    ));
    let missing = base
        .with_snapshot_selection(subject, &[], wow, Err(STATUS_OBJECT_NAME_NOT_FOUND))
        .unwrap();
    assert!(matches!(
        missing.lookup_view(&logical, wow),
        Lookup::Missing
    ));
    assert!(matches!(
        missing.lookup_view(&physical, native),
        Lookup::Missing
    ));
}
