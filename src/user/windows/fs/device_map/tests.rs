use super::DriveMap;

#[test]
fn replacing_a_captured_drive_changes_only_its_kind_and_logon_visibility() {
    let mut drives = DriveMap::empty();
    drives.set('C', "mapped-c");
    drives.set('Z', "mapped-z");
    let mut all = [0; 36];
    all[..4].copy_from_slice(&(4u32 | (1 << 25)).to_le_bytes());
    all[6] = 3;
    all[29] = 4;
    let mut logon = [0; 36];
    logon[..4].copy_from_slice(&(1u32 << 25).to_le_bytes());
    logon[29] = 4;
    drives.apply_device_maps(all, logon).unwrap();
    assert_eq!(drives.device_map(false), all);
    assert_eq!(drives.device_map(true), logon);
    drives.set('z', "replacement");
    all[29] = 3;
    assert_eq!(drives.device_map(false), all);
    assert_eq!(drives.device_map(true), [0; 36]);
    drives.set('\u{e9}', "not-an-ascii-drive");
    assert_eq!(drives.device_map(false), all);
    assert_eq!(drives.device_map(true), [0; 36]);
    assert!(drives.apply_device_maps([0; 36], [0; 36]).is_err());
    assert_eq!(drives.device_map(false), all);
}

#[cfg(windows)]
#[test]
fn native_drive_selection_matches_independent_win32_roots_and_types() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLogicalDrives() -> u32;
        fn GetDriveTypeW(root: *const u16) -> u32;
    }
    let drives = DriveMap::from_host().unwrap();
    let record = drives.device_map(false);
    // SAFETY: no pointer arguments or retained resources.
    let mask = unsafe { GetLogicalDrives() };
    assert_ne!(mask, 0, "{}", std::io::Error::last_os_error());
    assert_eq!(u32::from_le_bytes(record[..4].try_into().unwrap()), mask);
    for index in 0..26 {
        let letter = char::from(b'A' + index);
        if mask & (1 << index) == 0 {
            assert!(drives.root(letter).is_none());
            continue;
        }
        let root = [
            u16::from(b'A' + index),
            u16::from(b':'),
            u16::from(b'\\'),
            0,
        ];
        // SAFETY: live NUL-terminated UTF-16 root; synchronous read-only API.
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        assert_eq!(u32::from(record[4 + usize::from(index)]), kind, "{letter}");
        assert_eq!(
            drives.root(letter).unwrap(),
            std::path::Path::new(&format!("{letter}:\\"))
        );
    }
}
