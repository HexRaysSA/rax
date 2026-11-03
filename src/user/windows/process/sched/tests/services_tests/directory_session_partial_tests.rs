//! Enter the existing directory service with a traversal-only partial parent.
use super::*;
use crate::user::windows::object_namespace::traverse_only_tests::sample;

fn named(p: &mut Proc, t: &mut Thread, b: u64, path: &str, root: u64, access: u32) -> u32 {
    let name: Vec<_> = path.encode_utf16().collect();
    p.space.put_wunits(b + 128, &name).unwrap();
    descriptor(
        p,
        b + 64,
        b + 128,
        (name.len() * 2) as u16,
        (name.len() * 2 + 2) as u16,
    );
    attributes(
        p,
        b + 16,
        b + 64,
        root,
        0x40,
        if p.arch.is64() { 48 } else { 24 },
    );
    p.space
        .wptr(b, p.arch.ptr_size(), p.arch.ptr(u64::MAX))
        .unwrap();
    call(p, t, [b, access.into(), b + 16])
}

#[test]
fn native_directory_partial_session_preserves_access_and_retained_routes_all_abis() {
    for arch in WinArch::ALL {
        for session in [0, 1, 42, u32::MAX] {
            let (mut process, mut t, b) = setup(arch, 3);
            let p = process.state_mut();
            p.object_namespace = sample(session);
            let path = format!("\\Sessions\\{session}");
            let baseline = (p.objects.handle_count(), p.objects.iter().count());
            for (access, status, granted) in [
                (0, STATUS_ACCESS_DENIED, 0),
                (1, STATUS_ACCESS_DENIED, 0),
                (2, 0, 2),
                (3, STATUS_ACCESS_DENIED, 0),
                (0x20000, STATUS_ACCESS_DENIED, 0),
                (0x02000000, 0, 2),
                (0x01000000, STATUS_PRIVILEGE_NOT_HELD, 0),
                (0x03000000, STATUS_PRIVILEGE_NOT_HELD, 0),
            ] {
                assert_eq!(
                    named(p, &mut t, b, &path, 0, access),
                    status,
                    "{arch}/{session}/{access:x}"
                );
                let handle = p.space.ptr(b, arch.ptr_size()).unwrap();
                if status == 0 {
                    assert_eq!(p.objects.access(handle), Some(granted));
                    p.objects.close(handle).unwrap();
                } else {
                    assert_eq!(handle, 0);
                }
                assert_eq!(
                    (p.objects.handle_count(), p.objects.iter().count()),
                    baseline
                );
            }
            let original = opened(p, &mut t, b, &path, 0x02000000);
            let parent = p.objects.duplicate(original, false).unwrap() as u64;
            p.objects.close(original).unwrap();
            let absolute = opened(p, &mut t, b, &format!("{path}\\Windows"), 3);
            p.object_namespace = Namespace::default();
            assert_eq!(named(p, &mut t, b, "wINDOWS", parent, 3), 0);
            let relative = p.space.ptr(b, arch.ptr_size()).unwrap();
            match (p.objects.get(absolute), p.objects.get(relative)) {
                (Some(Object::Directory(a)), Some(Object::Directory(b))) => {
                    assert!(Arc::ptr_eq(a, b))
                }
                pair => panic!("unexpected retained directory pair {pair:?}"),
            }
            p.objects.close(parent).unwrap();
            p.objects.close(absolute).unwrap();
            assert_eq!(p.objects.access(relative), Some(3));
            p.objects.close(relative).unwrap();
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
        }
    }
}
