//! Distinct controlled view data exercises the guest NT service path; native
//! control transcripts independently establish view-selection behavior.
use super::*;
use crate::user::windows::registry::{AppModelRoot, KeyTree, RegistryView};

fn tree(byte: u8) -> KeyTree {
    let leaf = || KeyTree {
        values: vec![Value {
            name: "View".encode_utf16().collect(),
            kind: 3,
            data: vec![byte],
        }],
        children: vec![],
    };
    KeyTree {
        children: vec![("Child".encode_utf16().collect(), leaf())],
        ..leaf()
    }
}
fn captured(p: &mut Proc) {
    for selected in AppModelRoot::ALL {
        let bias = if selected == AppModelRoot::User {
            100
        } else {
            0
        };
        p.registry = p
            .registry
            .clone()
            .with_appmodel_view(selected, RegistryView::Native64, Some(tree(64 + bias)))
            .unwrap()
            .with_appmodel_view(selected, RegistryView::Wow32, Some(tree(32 + bias)))
            .unwrap();
    }
}
fn open(
    p: &mut Proc,
    t: &mut Thread,
    base: u64,
    name: &str,
    root: u64,
    view: u32,
    service: &str,
) -> u64 {
    let attrs = base + 2 * PAGE_SIZE;
    unicode(p, attrs + 64, attrs + 128, name);
    attributes(p, attrs, attrs + 64, root, 0x40);
    let args = [base, u64::from(1 | view), attrs, 0];
    assert_eq!(
        call(
            p,
            t,
            service,
            &args[..if service == "NtOpenKey" { 3 } else { 4 }]
        ),
        STATUS_SUCCESS
    );
    p.space.ptr(base, p.arch.ptr_size()).unwrap()
}
fn value(p: &mut Proc, t: &mut Thread, base: u64, handle: u64) -> u8 {
    let descriptor = base + 64;
    unicode(p, descriptor, base + 128, "view");
    assert_eq!(
        call(
            p,
            t,
            "NtQueryValueKey",
            &[handle, descriptor, 2, base + 256, 32, base + 192]
        ),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u32(base + 192).unwrap(), 13);
    p.space.bytes(base + 268, 1).unwrap()[0]
}

#[test]
fn appmodel_absolute_and_relative_views_follow_native_controls_all_abis() {
    for selected in AppModelRoot::ALL {
        let bias = if selected == AppModelRoot::User {
            100
        } else {
            0
        };
        for arch in WinArch::ALL {
            for (build, machine) in [(20348, 0x8664), (26100, 0x8664), (29695, 0xAA64)] {
                for service in ["NtOpenKey", "NtOpenKeyEx"] {
                    let (mut process, mut t, base) = setup(arch);
                    let p = process.state_mut();
                    super::super::native_profile::kernel_profile(p, build, machine);
                    captured(p);
                    let mut roots = Vec::new();
                    for view in [0, 0x100, 0x200] {
                        let handle = open(p, &mut t, base, selected.path(), 0, view, service);
                        let expected = if arch == WinArch::X86 && view != 0x100 {
                            32 + bias
                        } else {
                            64 + bias
                        };
                        assert_eq!(value(p, &mut t, base, handle), expected);
                        let duplicate = p.objects.duplicate(handle, false).unwrap() as u64;
                        assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
                        roots.push((duplicate, expected));
                    }
                    // Relative opens must keep the captured pair after catalog
                    // replacement and original-handle close, without host queries.
                    p.registry = Registry::default();
                    for (root, original) in roots {
                        for view in [0, 0x100, 0x200] {
                            for suffix in ["", "Child", "Child\\\\"] {
                                let handle = open(p, &mut t, base, suffix, root, view, service);
                                let expected = if arch == WinArch::X86 && view == 0x200 {
                                    32 + bias
                                } else {
                                    original
                                };
                                assert_eq!(
                                    value(p, &mut t, base, handle),
                                    expected,
                                    "{arch}/{build}/{service}/{original}/{view:x}/{suffix}"
                                );
                                assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
                            }
                        }
                        assert_eq!(call(p, &mut t, "NtClose", &[root]), STATUS_SUCCESS);
                    }
                }
            }
        }
    }
}

#[test]
fn appmodel_absence_selection_and_invalid_view_preserve_status_and_output() {
    for selected in AppModelRoot::ALL {
        for arch in WinArch::ALL {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            p.registry = p
                .registry
                .clone()
                .with_appmodel_view(selected, RegistryView::Native64, Some(tree(64)))
                .unwrap()
                .with_appmodel_view(selected, RegistryView::Wow32, None)
                .unwrap();
            let attrs = base + 2 * PAGE_SIZE;
            unicode(p, attrs + 64, attrs + 128, selected.path());
            attributes(p, attrs, attrs + 64, 0, 0x40);
            let count = p.objects.handle_count();
            for service in ["NtOpenKey", "NtOpenKeyEx"] {
                for view in [0, 0x100, 0x200, 0x300] {
                    let args = [base, 1 | view, attrs, 0];
                    let status = call(
                        p,
                        &mut t,
                        service,
                        &args[..if service == "NtOpenKey" { 3 } else { 4 }],
                    );
                    if arch == WinArch::X86 && view == 0x300 {
                        assert_eq!(status, STATUS_INVALID_PARAMETER);
                    } else if arch == WinArch::X86 && view != 0x100 {
                        assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);
                    } else {
                        assert_eq!(status, STATUS_SUCCESS);
                        let h = p.space.ptr(base, arch.ptr_size()).unwrap();
                        assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                        continue;
                    }
                    assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
                    assert_eq!(p.objects.handle_count(), count);
                }
            }
        }
    }
}

#[test]
fn appmodel_uncaptured_wow64_key_tags_do_not_publish_invented_bytes() {
    for selected in AppModelRoot::ALL {
        for arch in WinArch::ALL {
            for offset in [0, 1, 4] {
                let (mut process, mut t, base) = setup(arch);
                let p = process.state_mut();
                captured(p);
                let handle = open(p, &mut t, base, selected.path(), 0, 0, "NtOpenKey");
                let output = base + 256 + offset;
                let returned = base + 192;
                p.space.wr(base + 256, &[0xA5; 16]).unwrap();
                p.space.w32(returned, 0xA5A5_A5A5).unwrap();
                if arch == WinArch::X86 {
                    let module = p.modules.nt_services.as_ref().unwrap().0;
                    p.modules.nt_services = Some((module, table(arch, "NtQueryKey", 0x12)));
                    arguments(p, &mut t, &[handle, 7, output, 4, returned]);
                    let outcome = dispatch(p, &mut t);
                    assert!(
                        matches!(outcome, Outcome::Fail(ref text) if text.contains("registry key-body tags are not captured")),
                        "{outcome:?}"
                    );
                    assert_eq!(p.space.bytes(base + 256, 16).unwrap(), [0xA5; 16]);
                    assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
                } else {
                    let status = call(p, &mut t, "NtQueryKey", &[handle, 7, output, 4, returned]);
                    assert_eq!(
                        status,
                        if offset == 1 {
                            STATUS_DATATYPE_MISALIGNMENT
                        } else {
                            STATUS_SUCCESS
                        }
                    );
                    if status == STATUS_SUCCESS {
                        assert_eq!(p.space.u32(output).unwrap(), 0);
                    }
                }
            }
        }
    }
}
