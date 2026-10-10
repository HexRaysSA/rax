use super::*;

fn check_raw_values<'a>(host: &OwnedKey, values: impl IntoIterator<Item = &'a Value>) {
    for value in values {
        let name: Vec<_> = value.name.iter().copied().chain(Some(0)).collect();
        let mut data = vec![0; MAX_VALUE_BYTES];
        let (mut kind, mut length) = (0, data.len() as u32);
        // SAFETY: live read-only HKEY, terminated captured native value name,
        // exclusive bounded outputs; returned byte count validated below.
        assert_eq!(
            unsafe {
                RegQueryValueExW(
                    host.0,
                    name.as_ptr(),
                    null_mut(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut length,
                )
            },
            0
        );
        assert!(length as usize <= data.len());
        data.truncate(length as usize);
        assert_eq!((kind, data), (value.kind, value.data.clone()));
    }
}

#[test]
fn installed_segment_heap_present_capture_adapter_reads_controlled_native_key() {
    // Controlled opener supplies a live query-only Session Manager handle:
    // this exercises present-key acquisition without creating a Segment Heap
    // key or claiming this host has a configured present Segment Heap profile.
    let host: Vec<_> = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\0"
        .encode_utf16()
        .collect();
    let mut handle = null_mut();
    // SAFETY: fixed terminated fixture path, query-only access, exclusive HKEY.
    assert_eq!(
        unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as Hkey,
                host.as_ptr(),
                0,
                1,
                &mut handle,
            )
        },
        0
    );
    let independent = OwnedKey(handle);
    let metadata = info(&independent).unwrap();
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let captured = segment_heap_with(&registry, |path| {
        assert_eq!(path, super::super::SEGMENT_HEAP_KEY);
        let mut handle = null_mut();
        // SAFETY: controlled fixed fixture, query-only access, exclusive HKEY.
        let status = unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as Hkey,
                host.as_ptr(),
                0,
                1,
                &mut handle,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        Ok(OwnedKey(handle))
    })
    .unwrap()
    .expect("controlled present native fixture");
    assert_eq!(captured.path, super::super::SEGMENT_HEAP_KEY);
    assert_eq!(captured.children, metadata.children);
    assert_eq!(captured.values.len(), metadata.values as usize);
    check_raw_values(&independent, &captured.values);
}

#[test]
fn installed_segment_heap_root_absence_is_distinct_from_other_open_errors() {
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let mut opens = 0;
    assert!(
        segment_heap_with(&registry, |path| {
            opens += 1;
            assert_eq!(path, super::super::SEGMENT_HEAP_KEY);
            Err(io::Error::from_raw_os_error(2))
        })
        .unwrap()
        .is_none()
    );
    assert_eq!(opens, 1);
    for status in [5, 234, 259] {
        let error = segment_heap_with(&registry, |_| Err(io::Error::from_raw_os_error(status)))
            .err()
            .expect("only the fixed root error 2 is known absence");
        assert_eq!(error.raw_os_error(), Some(status));
    }
}

#[test]
fn installed_segment_heap_snapshot_matches_optional_native_root_presence() {
    let registry = snapshot().unwrap();
    let path =
        "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Segment Heap";
    let guest: Vec<_> = path.encode_utf16().collect();
    let host: Vec<_> = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Segment Heap\0"
        .encode_utf16()
        .collect();
    for view in [0, 0x100, 0x200] {
        let mut handle = null_mut();
        // SAFETY: fixed terminated system path, query-only native access and
        // exclusive HKEY output. No mutation or guest-provided key string.
        let status = unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as Hkey,
                host.as_ptr(),
                0,
                1 | view,
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
            let captured = registry
                .key(&guest)
                .expect("independently present fixed key");
            let metadata = info(&host).unwrap();
            assert_eq!(captured.children, metadata.children);
            assert_eq!(captured.values.len(), metadata.values as usize);
            check_raw_values(&host, captured.values.values());
        }
    }
}

#[test]
fn installed_ifeo_only_root_not_found_is_known_absence() {
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let mut opens = 0;
    let absent = tree::capture_with(&registry, |path| {
        opens += 1;
        assert_eq!(
            path,
            super::super::IFEO_KEY.encode_utf16().collect::<Vec<_>>()
        );
        Err(io::Error::from_raw_os_error(2))
    })
    .unwrap();
    assert!(absent.is_none());
    assert_eq!(opens, 1);
    for status in [5, 234, 259] {
        let error = tree::capture_with(&registry, |_| Err(io::Error::from_raw_os_error(status)))
            .err()
            .expect("only ERROR_FILE_NOT_FOUND at the fixed root establishes absence");
        assert_eq!(error.raw_os_error(), Some(status));
    }
}

#[repr(C)]
struct Unicode {
    length: u16,
    capacity: u16,
    buffer: *const u16,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlEqualUnicodeString(a: *const Unicode, b: *const Unicode, insensitive: u8) -> u8;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegQueryValueExW(
        key: Hkey,
        name: *const u16,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        length: *mut u32,
    ) -> i32;
}
#[test]
fn installed_nls_snapshot_matches_independent_raw_queries_and_rtl_case_comparison() {
    let registry = snapshot().unwrap();
    let key = registry
        .key(&super::super::NLS_KEY.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    let path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage\0"
        .encode_utf16()
        .collect();
    let mut hkey = null_mut();
    // SAFETY: fixed terminated system path, query-only access, exclusive HKEY
    // output, no retained pointer, Windows system ABI without unwinding.
    assert_eq!(
        unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as Hkey,
                path.as_ptr(),
                0,
                1,
                &mut hkey,
            )
        },
        0
    );
    let hkey = OwnedKey(hkey);
    for text in ["ACP", "OEMCP", "MACCP"] {
        let value = key
            .value(&text.encode_utf16().collect::<Vec<_>>())
            .expect("installed bootstrap value");
        let name: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
        let mut data = vec![0; MAX_VALUE_BYTES];
        let (mut length, mut kind) = (data.len() as u32, 0);
        // SAFETY: live query-only key and fixed terminated value name; all
        // mutable outputs are exclusive initialized buffers with exact byte
        // capacity. The result length is checked before truncation/comparison.
        assert_eq!(
            unsafe {
                RegQueryValueExW(
                    hkey.0,
                    name.as_ptr(),
                    null_mut(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut length,
                )
            },
            0
        );
        assert!(length as usize <= data.len());
        data.truncate(length as usize);
        assert_eq!(value.kind, kind);
        assert_eq!(value.data, data);
    }
    for u in 0..=u16::MAX {
        let folded = key.fold(&[u]);
        let a = Unicode {
            length: 2,
            capacity: 2,
            buffer: &u,
        };
        let b = Unicode {
            length: 2,
            capacity: 2,
            buffer: folded.as_ptr(),
        };
        // SAFETY: repr(C) native UNICODE_STRING with two-byte initialized
        // WCHAR buffers alive for the call, read-only aliases, no retention
        // or mutation; one BOOLEAN input/output through the system ABI.
        assert_ne!(
            unsafe { RtlEqualUnicodeString(&a, &b, 1) },
            0,
            "UTF-16 {u:#06x}"
        );
    }
}

#[test]
fn installed_runtime_snapshot_includes_session_manager_raw_values() {
    let registry = snapshot().unwrap();
    // The byte budget must bound retained storage, not only truncated lengths.
    // A short value must not retain the maximum-sized enumeration scratch.
    for path in [NLS_KEY, SESSION_MANAGER_KEY] {
        let captured = registry
            .key(&path.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        for value in captured.values.values() {
            assert_eq!(
                value.name.capacity(),
                value.name.len(),
                "{path}: name storage"
            );
            assert_eq!(
                value.data.capacity(),
                value.data.len(),
                "{path}: data storage"
            );
        }
    }
    let key = registry
        .key(
            &"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager"
                .encode_utf16()
                .collect::<Vec<_>>(),
        )
        .expect("selected native loader Session Manager key");
    let path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\0"
        .encode_utf16()
        .collect();
    let mut handle = null_mut();
    // SAFETY: fixed terminated system path, KEY_QUERY_VALUE, exclusive handle
    // destination; no guest-provided name or retained native pointer.
    assert_eq!(
        unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as Hkey,
                path.as_ptr(),
                0,
                1,
                &mut handle,
            )
        },
        0
    );
    let handle = OwnedKey(handle);
    for text in [
        "GlobalFlag",
        "CriticalSectionTimeout",
        "HeapSegmentReserve",
        "missing-rax-value",
    ] {
        let name: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let mut data = vec![0; MAX_VALUE_BYTES];
        let (mut length, mut kind) = (data.len() as u32, 0);
        // SAFETY: live query-only handle, fixed terminated name and exclusive
        // bounded output bytes/DWORDs. Returned byte count is checked below.
        let status = unsafe {
            RegQueryValueExW(
                handle.0,
                name.as_ptr(),
                null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut length,
            )
        };
        let selected = key.value(&text.encode_utf16().collect::<Vec<_>>());
        if status == 2 {
            assert!(selected.is_none(), "{text}");
        } else {
            assert_eq!(status, 0, "{text}");
            assert!(length as usize <= data.len());
            data.truncate(length as usize);
            let selected = selected.expect("independently present native value");
            assert_eq!(selected.kind, kind, "{text}");
            assert_eq!(selected.data, data, "{text}");
        }
    }
}

#[test]
fn installed_ifeo_snapshot_matches_independent_complete_tree_and_raw_queries() {
    let registry = snapshot().unwrap();
    let path: Vec<_> = super::super::IFEO_KEY.encode_utf16().collect();
    let host: Vec<_> =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\0"
            .encode_utf16()
            .collect();
    let mut handle = null_mut();
    // SAFETY: fixed, terminated loader-metadata path and query/enumerate-only
    // access, exclusive HKEY output with no retained pointers.
    let status = unsafe {
        RegOpenKeyExW(
            (-2_147_483_646isize) as Hkey,
            host.as_ptr(),
            0,
            9,
            &mut handle,
        )
    };
    if status == 2 {
        assert!(matches!(
            registry.lookup(&path),
            super::super::Lookup::Missing
        ));
        assert!(registry.key(&path).is_none());
        return;
    }
    assert_eq!(status, 0);
    registry
        .key(&path)
        .expect("selected complete native IFEO subtree");
    let key = OwnedKey(handle);
    let (keys, values, bytes) = check_ifeo(&registry, &key, &path, 0);
    eprintln!("native IFEO independently checked: {keys} keys, {values} values, {bytes} raw bytes");
    if info(&key).unwrap().children != 0 {
        let acquisition_base = Registry::selected(registry.upcase.to_vec(), vec![]).unwrap();
        let mut opens = 0;
        let error = tree::capture_with(&acquisition_base, |_| {
            opens += 1;
            if opens != 1 {
                return Err(io::Error::from_raw_os_error(2));
            }
            let mut handle = null_mut();
            // SAFETY: same fixed terminated root and query/enumerate access,
            // exclusive owned HKEY output. No registry mutation by injection.
            let status = unsafe {
                RegOpenKeyExW(
                    (-2_147_483_646isize) as Hkey,
                    host.as_ptr(),
                    0,
                    9,
                    &mut handle,
                )
            };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status));
            }
            Ok(OwnedKey(handle))
        })
        .err()
        .expect("an enumerated child disappearing must abort acquisition");
        assert_eq!(opens, 2);
        assert_eq!(error.raw_os_error(), Some(2));
        eprintln!("native IFEO disappearing-child injection: 2 opens, acquisition error 2");
    }
}
fn check_ifeo(
    registry: &Registry,
    host: &OwnedKey,
    path: &[u16],
    depth: usize,
) -> (usize, usize, usize) {
    assert!(depth <= super::super::tree::MAX_TREE_DEPTH);
    let selected = registry.key(path).expect("captured native descendant");
    let metadata = info(host).unwrap();
    assert_eq!(selected.children, metadata.children);
    assert_eq!(selected.values.len(), metadata.values as usize);
    let mut totals = (
        1,
        selected.values.len(),
        selected
            .values
            .values()
            .map(|v| v.name.len() * 2 + v.data.len())
            .sum(),
    );
    for value in selected.values.values() {
        let name: Vec<_> = value.name.iter().copied().chain(Some(0)).collect();
        let mut data = vec![0; MAX_VALUE_BYTES];
        let (mut length, mut kind) = (data.len() as u32, 0);
        // SAFETY: live query-only HKEY, terminated captured native value name,
        // exact exclusive byte/DWORD outputs, checked returned byte count.
        assert_eq!(
            unsafe {
                RegQueryValueExW(
                    host.0,
                    name.as_ptr(),
                    null_mut(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut length,
                )
            },
            0
        );
        assert!(length as usize <= data.len());
        data.truncate(length as usize);
        assert_eq!((value.kind, &value.data), (kind, &data));
        assert_eq!(value.data.capacity(), value.data.len());
        assert_eq!(value.name.capacity(), value.name.len());
    }
    for index in 0..metadata.children {
        let mut name = vec![0; metadata.max_child as usize + 1];
        let mut length = name.len() as u32;
        // SAFETY: live enumerate-only HKEY, exclusive WCHAR/DWORD output of
        // declared capacity; optional outputs NULL, returned length checked.
        assert_eq!(
            unsafe {
                RegEnumKeyExW(
                    host.0,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            },
            0
        );
        assert!((length as usize) < name.len());
        name.truncate(length as usize);
        let child_path = super::super::tree::child_path(path, &name).unwrap();
        name.push(0);
        let mut handle = null_mut();
        // SAFETY: exclusively owned parent HKEY, terminated enumerated native
        // component, query/enumerate-only open and exclusive child HKEY output.
        assert_eq!(
            unsafe { RegOpenKeyExW(host.0, name.as_ptr(), 0, 9, &mut handle) },
            0
        );
        let child = check_ifeo(registry, &OwnedKey(handle), &child_path, depth + 1);
        totals.0 += child.0;
        totals.1 += child.1;
        totals.2 += child.2;
    }
    totals
}
