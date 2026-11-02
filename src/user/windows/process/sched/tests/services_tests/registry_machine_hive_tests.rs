//! MACHINE-root controls reach the guest NT dispatcher on every guest ABI.
use super::*;
use crate::user::windows::registry::{
    AppModelRoot, KeyAccess, KeyTree, MACHINE_HIVE_KEY, MachineHeader, RegistryView,
};

#[path = "registry_machine_hive_replay.rs"]
mod replay;

fn captured(p: &mut Proc, present_appmodel: bool) {
    for (view, byte) in [(RegistryView::Native64, 64), (RegistryView::Wow32, 32)] {
        p.registry = p
            .registry
            .clone()
            .with_appmodel_view(
                AppModelRoot::Machine,
                view,
                present_appmodel.then(|| KeyTree {
                    values: vec![Value {
                        name: "View".encode_utf16().collect(),
                        kind: 3,
                        data: vec![byte],
                    }],
                    children: vec![],
                }),
            )
            .unwrap();
    }
    p.registry = p
        .registry
        .clone()
        .with_machine_hive(MachineHeader {
            enumeration: None,
            canonical: "\\REGISTRY\\MACHINE".encode_utf16().collect(),
            children: 6,
            values: vec![Value {
                name: "ServiceLastKnownStatus".encode_utf16().collect(),
                kind: 4,
                data: 2u32.to_le_bytes().to_vec(),
            }],
            access: KeyAccess {
                maximum_access: 0x000F_003F,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        })
        .unwrap();
}

fn open(
    p: &mut Proc,
    t: &mut Thread,
    base: u64,
    service: &str,
    name: &str,
    root: u64,
    access: u32,
) -> (u32, u64) {
    let attrs = base + 2 * PAGE_SIZE;
    unicode(p, attrs + 64, attrs + 128, name);
    attributes(p, attrs, attrs + 64, root, 0x40);
    let args = [base, u64::from(access), attrs, 0];
    let status = call(
        p,
        t,
        service,
        &args[..if service == "NtOpenKey" { 3 } else { 4 }],
    );
    (status, p.space.ptr(base, p.arch.ptr_size()).unwrap())
}

fn tags(p: &mut Proc, t: &mut Thread, base: u64, h: u64) -> u32 {
    assert_eq!(
        call(p, t, "NtQueryKey", &[h, 7, base + 128, 4, base + 64]),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u32(base + 64).unwrap(), 4);
    p.space.u32(base + 128).unwrap()
}

#[test]
fn machine_root_ordinary_grants_and_key_tags_match_native_controls_all_abis() {
    let cases = [
        (0, None),
        (1, Some(1)),
        (2, Some(2)),
        (8, Some(8)),
        (0x20, Some(0x20)),
        (0x20019, Some(0x20019)),
        (0xF003F, Some(0xF003F)),
        (0x02000000, Some(0xF003F)),
        (0x80000000, Some(0x20019)),
        (0x40000000, Some(0x20006)),
        (0x20000000, Some(0x20039)),
        (0x10000000, Some(0xF003F)),
        (0x82000000, Some(0xF003F)),
        (0x100000, None),
        (0x1000000, None),
        (0x3000000, None),
        (0x4000000, None),
    ];
    for arch in WinArch::ALL {
        for service in ["NtOpenKey", "NtOpenKeyEx"] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            captured(p, false);
            for view in [0, 0x100, 0x200, 0x300] {
                for (request, grant) in cases {
                    let (status, h) = open(
                        p,
                        &mut t,
                        base,
                        service,
                        MACHINE_HIVE_KEY,
                        0,
                        request | view,
                    );
                    if arch == WinArch::X86 && view == 0x300 {
                        assert_eq!((status, h), (STATUS_INVALID_PARAMETER, 0));
                    } else if let Some(grant) = grant {
                        assert_eq!(
                            status, STATUS_SUCCESS,
                            "{arch}/{service}/{request:x}/{view:x}"
                        );
                        assert_eq!(p.objects.access(h), Some(grant));
                        assert_eq!(
                            tags(p, &mut t, base, h),
                            if arch == WinArch::X86 { view } else { 0 }
                        );
                        assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                    } else {
                        assert_eq!((status, h), (STATUS_ACCESS_DENIED, 0));
                    }
                }
            }
            // Other selected keys retain their own measured access profile.
            let (status, h) = open(p, &mut t, base, service, NLS_KEY, 0, 0x02000000);
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(p.objects.access(h), Some(0x20019));
            assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        }
    }
}

#[test]
fn machine_relative_views_and_duplicated_root_survive_catalog_replacement_all_abis() {
    // Rows are parent view 0/64/32, columns are requested view 0/64/32.
    // Expected values are the independent native x86 control transcript.
    let root_tags = [
        [0, 0x100, 0x200],
        [0x100, 0x100, 0x200],
        [0x200, 0x100, 0x200],
    ];
    let nls_tags = [[0x400, 0x100, 0x600], [0, 0, 0x600], [0x600, 0x100, 0x600]];
    let nls_suffix = NLS_KEY
        .strip_prefix(MACHINE_HIVE_KEY)
        .unwrap()
        .trim_start_matches('\\');
    let appmodel_suffix = AppModelRoot::Machine
        .path()
        .strip_prefix(MACHINE_HIVE_KEY)
        .unwrap()
        .trim_start_matches('\\');
    for arch in WinArch::ALL {
        for service in ["NtOpenKey", "NtOpenKeyEx"] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            captured(p, false);
            let mut roots = Vec::new();
            for view in [0, 0x100, 0x200] {
                let (status, h) = open(p, &mut t, base, service, MACHINE_HIVE_KEY, 0, 1 | view);
                assert_eq!(status, STATUS_SUCCESS);
                let duplicate = u64::from(p.objects.duplicate(h, false).unwrap());
                assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                roots.push(duplicate);
            }
            p.registry = Registry::default();
            for (parent, h) in roots.into_iter().enumerate() {
                for (column, view) in [0, 0x100, 0x200, 0x300].into_iter().enumerate() {
                    for (suffix, expected) in [
                        ("", root_tags[parent]),
                        (nls_suffix, nls_tags[parent]),
                        (appmodel_suffix, [0; 3]),
                    ] {
                        let (status, child) = open(p, &mut t, base, service, suffix, h, 1 | view);
                        if arch == WinArch::X86 && view == 0x300 {
                            assert_eq!((status, child), (STATUS_INVALID_PARAMETER, 0));
                        } else if suffix == appmodel_suffix {
                            assert_eq!((status, child), (STATUS_OBJECT_NAME_NOT_FOUND, 0));
                        } else {
                            assert_eq!(
                                status, STATUS_SUCCESS,
                                "{arch}/{service}/{parent}/{view:x}/{suffix}"
                            );
                            assert_eq!(
                                tags(p, &mut t, base, child),
                                if arch == WinArch::X86 {
                                    expected[column]
                                } else {
                                    0
                                }
                            );
                            assert_eq!(call(p, &mut t, "NtClose", &[child]), STATUS_SUCCESS);
                        }
                    }
                }
                unicode(p, base + 64, base + 256, "servicelastknownstatus");
                assert_eq!(
                    call(
                        p,
                        &mut t,
                        "NtQueryValueKey",
                        &[h, base + 64, 2, base + 128, 32, base + 192]
                    ),
                    STATUS_SUCCESS
                );
                assert_eq!(p.space.u32(base + 132).unwrap(), 4);
                assert_eq!(p.space.u32(base + 136).unwrap(), 4);
                assert_eq!(p.space.u32(base + 140).unwrap(), 2);
                assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
            }
        }
    }
}

#[test]
fn machine_relative_appmodel_keeps_both_selected_views_all_abis() {
    let suffix = AppModelRoot::Machine
        .path()
        .strip_prefix(MACHINE_HIVE_KEY)
        .unwrap()
        .trim_start_matches('\\');
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        captured(p, true);
        let mut roots = Vec::new();
        for view in [0, 0x100, 0x200] {
            let (status, h) = open(
                p,
                &mut t,
                base,
                "NtOpenKeyEx",
                MACHINE_HIVE_KEY,
                0,
                1 | view,
            );
            assert_eq!(status, STATUS_SUCCESS);
            roots.push((view, h));
        }
        p.registry = Registry::default();
        for (parent, h) in roots {
            for view in [0, 0x100, 0x200] {
                let (status, child) = open(p, &mut t, base, "NtOpenKeyEx", suffix, h, 1 | view);
                assert_eq!(status, STATUS_SUCCESS);
                unicode(p, base + 64, base + 256, "View");
                assert_eq!(
                    call(
                        p,
                        &mut t,
                        "NtQueryValueKey",
                        &[child, base + 64, 2, base + 128, 32, base + 192]
                    ),
                    STATUS_SUCCESS
                );
                let effective = if view == 0 { parent } else { view };
                let expected = if arch == WinArch::X86 && effective != 0x100 {
                    32
                } else {
                    64
                };
                assert_eq!(p.space.bytes(base + 140, 1).unwrap(), [expected]);
                assert_eq!(call(p, &mut t, "NtClose", &[child]), STATUS_SUCCESS);
            }
            assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        }
    }
}
