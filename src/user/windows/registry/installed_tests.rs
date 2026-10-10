use super::*;

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
