//! Named pagefile sections use the same guest identity through native calls.
use super::super::event_tests::{handle, setup, status};
use super::super::section_map_tests as map;
use super::super::semaphore_tests::named;
use super::*;
use crate::user::windows::object_namespace::reparse_tests;

#[test]
fn native_named_pagefile_section_preserves_alias_and_view_lifetime_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, b) = setup(arch);
        let p = process.state_mut();
        p.object_namespace = reparse_tests::sample(42);
        let base = "\\Sessions\\42\\BaseNamedObjects";
        let directory = p
            .object_namespace
            .lookup(None, &base.encode_utf16().collect::<Vec<_>>(), 0)
            .unwrap();
        let root = u64::from(
            p.objects
                .open_directory(directory.clone(), false, 0)
                .unwrap(),
        );
        let out = b;
        let maximum = b + 64;
        let attrs = b + 256;
        let create = [out, 7, attrs, maximum, 4, 0x0800_0000, 0];
        let open = [out, 4, attrs];
        p.space.w64(maximum, 4097).unwrap();

        let path = format!("{base}\\RaxNamedPagefileControl");
        named(p, attrs, 0, &path, 0x40);
        assert_eq!(status(p, &mut t, "NtCreateSection", &create), 0);
        let creator = handle(p, out);
        let id = p.objects.id(creator).unwrap();
        let sentinel = 0x1122_3344;
        map::ptr(p, out, sentinel);
        assert_eq!(
            status(p, &mut t, "NtCreateSection", &create),
            STATUS_OBJECT_NAME_COLLISION,
        );
        assert_eq!(handle(p, out), if arch.is64() { sentinel } else { 0 });

        p.space.w64(maximum, 65536).unwrap();
        named(p, attrs, root, "Local\\RaxNamedPagefileControl", 0x82);
        assert_eq!(status(p, &mut t, "NtCreateSection", &create), 0x4000_0000);
        let repeated = handle(p, out);
        assert_ne!(creator, repeated);
        assert_eq!(p.objects.id(repeated), Some(id));
        assert_eq!(p.objects.flags(repeated), Some(1));
        let Object::Mapping { size, .. } = p.objects.get(repeated).unwrap() else {
            panic!("expected the original section");
        };
        assert_eq!(*size, 8192);

        named(p, attrs, root, "raxNamedPagefileControl", 0x40);
        assert_eq!(status(p, &mut t, "NtOpenSection", &open), 0);
        let reader = handle(p, out);
        assert_eq!(p.objects.id(reader), Some(id));
        assert_eq!(p.objects.access(reader), Some(4));

        let slot = b + 512;
        p.modules.nt_services = Some((
            p.modules.nt_services.as_ref().unwrap().0,
            table(arch, "NtMapViewOfSection", 0x28),
        ));
        let mut views = Vec::new();
        for (section, page) in [(creator, 4), (repeated, 4), (reader, 2)] {
            map::ptr(p, slot, 0);
            map::ptr(p, slot + 16, 0);
            assert_eq!(
                map::call(
                    p,
                    &mut t,
                    &[
                        section,
                        arch.ptr(u64::MAX),
                        slot,
                        0,
                        0,
                        0,
                        slot + 16,
                        2,
                        0,
                        page
                    ]
                ),
                STATUS_SUCCESS,
            );
            assert_eq!(map::get(p, slot + 16), 8192);
            views.push(map::get(p, slot));
        }
        assert_eq!(p.space.u8(views[1]).unwrap(), 0);
        assert_eq!(p.space.u8(views[2] + 4096).unwrap(), 0);
        p.space.wr(views[0], &[0x5A]).unwrap();
        p.space.wr(views[0] + 4096, &[0xA5]).unwrap();
        assert_eq!(p.space.u8(views[1]).unwrap(), 0x5A);

        for handle in [creator, repeated, reader] {
            p.objects.close(handle).unwrap();
        }
        let leaf = "RaxNamedPagefileControl".encode_utf16().collect::<Vec<_>>();
        let name = p
            .object_namespace
            .named(Some(directory), &leaf, 0x40)
            .unwrap();
        assert!(p.objects.by_native_name(&name).is_none());
        assert_eq!(p.space.u8(views[2] + 4096).unwrap(), 0xA5);

        named(p, attrs, 0, &path, 0x40);
        assert_eq!(
            status(p, &mut t, "NtCreateSemaphore", &[out, 3, attrs, 0, 1]),
            0
        );
        let semaphore = handle(p, out);
        map::ptr(p, out, sentinel);
        assert_eq!(
            status(p, &mut t, "NtOpenSection", &open),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(handle(p, out), 0);
        named(p, attrs, 0, &path, 0xC0);
        map::ptr(p, out, sentinel);
        assert_eq!(
            status(p, &mut t, "NtCreateSection", &create),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(handle(p, out), if arch.is64() { sentinel } else { 0 });
        p.objects.close(semaphore).unwrap();
        p.objects.close(root).unwrap();
    }
}
