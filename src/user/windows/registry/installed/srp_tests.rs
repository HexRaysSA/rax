use super::*;

#[test]
fn installed_loader_registry_srp_snapshot_matches_independent_native_presence_all_views() {
    let registry = snapshot().unwrap();
    let path = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Srp\\GP\\DLL";
    let guest: Vec<_> = path.encode_utf16().collect();
    let host: Vec<_> = path
        .strip_prefix("\\Registry\\Machine\\")
        .unwrap()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    for view in [0, 0x100, 0x200] {
        let mut handle = null_mut();
        // SAFETY: fixed terminated SYSTEM path, query/enumerate-only access,
        // exclusive owned HKEY output; no registry mutation or guest input.
        let status = unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as Hkey,
                host.as_ptr(),
                0,
                9 | view,
                &mut handle,
            )
        };
        if status == 2 {
            assert!(matches!(
                registry.lookup(&guest),
                super::super::Lookup::Missing
            ));
        } else {
            assert_eq!(status, 0);
            let host = OwnedKey(handle);
            let selected = registry.key(&guest).expect("present native fixed key");
            assert_eq!(selected.children, info(&host).unwrap().children);
            super::tests::check_ifeo(&registry, &host, &guest, 0);
        }
    }
}

#[test]
fn installed_loader_registry_srp_capture_distinguishes_root_absence_from_other_errors() {
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let root = super::super::TreeRoot::SrpDll;
    let mut opens = 0;
    assert!(
        tree::capture_root_with(&registry, root, |path| {
            opens += 1;
            assert_eq!(path, root.path().encode_utf16().collect::<Vec<_>>());
            Err(io::Error::from_raw_os_error(2))
        })
        .unwrap()
        .is_none()
    );
    assert_eq!(opens, 1);
    for status in [3, 5, 234, 259] {
        let error = tree::capture_root_with(&registry, root, |_| {
            Err(io::Error::from_raw_os_error(status))
        })
        .err()
        .expect("only the fixed root ERROR_FILE_NOT_FOUND establishes absence");
        assert_eq!(error.raw_os_error(), Some(status));
    }
}

#[test]
fn installed_loader_registry_srp_present_capture_uses_controlled_read_only_native_subtree() {
    // Capture a private volatile HKCU fixture through a read-only opener.
    // This does not change fixed system keys or claim this host's real Srp/GP/DLL root is present.
    // SAFETY: pure one-WCHAR native ordinal lookup, with no pointers retained.
    let upcase = (0..=u16::MAX)
        .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
        .collect();
    let registry = Registry::selected(upcase, vec![]).unwrap();
    let root = super::super::TreeRoot::SrpDll;
    let prefix: Vec<_> = root.path().encode_utf16().collect();
    let fixture = super::native_fixture::Tree::new();
    let opens = std::cell::Cell::new(0);
    let mut acquire = |path: &[u16]| {
        opens.set(opens.get() + 1);
        assert!(path.starts_with(&prefix));
        fixture.open(&path[prefix.len()..], 0)
    };
    let selected = tree::capture_root_with(&registry, root, &mut acquire)
        .unwrap()
        .expect("controlled present read-only subtree");
    let captured = registry.with_tree(root, Some(selected)).unwrap();
    let native = acquire(&prefix).unwrap();
    let (keys, values, bytes) = super::tests::check_ifeo(&captured, &native, &prefix, 0);
    assert_eq!(keys, 4);
    assert_eq!(values, 4);
    assert!(
        keys > 1 && opens.get() > 1,
        "controlled adapter must traverse descendants"
    );
    eprintln!("native controlled srp_dll capture: {keys} keys, {values} values, {bytes} bytes");
    drop(native);
    // Inject disappearance after the successfully opened root. Root not-found
    // is absence; a previously enumerated child disappearing is acquisition failure.
    let mut attempts = 0;
    let error = tree::capture_root_with(&captured, root, |path| {
        attempts += 1;
        if attempts > 1 {
            Err(io::Error::from_raw_os_error(2))
        } else {
            acquire(path)
        }
    })
    .err()
    .expect("enumerated child disappearance aborts capture");
    assert_eq!(attempts, 2);
    assert_eq!(error.raw_os_error(), Some(2));
}
