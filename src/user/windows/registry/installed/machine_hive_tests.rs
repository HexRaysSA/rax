use super::*;
use crate::user::windows::registry::Lookup;

fn registry() -> Registry {
    // SAFETY: pure scalar ordinal mapping; no pointers or retained state.
    let table = (0..=u16::MAX)
        .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
        .collect();
    Registry::selected(table, vec![]).unwrap()
}

#[test]
fn installed_machine_capture_rejects_invalid_selection_before_opening() {
    assert!(
        capture_with(Registry::default(), |_| panic!(
            "invalid table reached native opener"
        ))
        .is_err()
    );
    let mut calls = vec![];
    let error = capture_with(registry(), |access| {
        calls.push(access);
        Err(0xC0000022)
    })
    .err()
    .unwrap();
    assert_eq!(calls, [0x02000000]);
    assert!(error.to_string().contains("0xC0000022"));
    assert!(open(1).is_err());
}

#[test]
fn installed_machine_capture_matches_native_values_and_access() {
    let native = open(0x02000000).unwrap();
    let metadata = info(&native).unwrap();
    let raw = values(&native, &metadata, super::super::super::MAX_TOTAL_BYTES).unwrap();
    let canonical = canonical_hive_name(&native, "MACHINE").unwrap();
    let maximum = basic(&native).unwrap();
    let mut calls = vec![];
    let selected = capture_with(registry(), |access| {
        calls.push(access);
        open(access)
    })
    .unwrap();
    assert_eq!(calls, [0x02000000, 0x01000000]);
    let Lookup::Present(root) =
        selected.lookup(&MACHINE_HIVE_KEY.encode_utf16().collect::<Vec<_>>())
    else {
        panic!("fixed root");
    };
    assert_eq!(root.path, canonical);
    assert_eq!(root.children, metadata.children);
    assert_eq!(
        root.captured_access().unwrap().grant(0x02000000),
        Ok(maximum)
    );
    assert_eq!(root.values.len(), raw.len());
    for value in raw {
        assert_eq!(root.value(&value.name), Some(&value));
    }
}

#[test]
fn installed_machine_capture_closes_every_owned_handle() {
    const MARKER: &str = "RAX_MACHINE_CAPTURE_COUNT_CHILD";
    if std::env::var_os(MARKER).as_deref() != Some(std::ffi::OsStr::new("1")) {
        // Process handle totals are only meaningful without concurrent tests.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["user::windows::registry::installed::machine_hive::tests::installed_machine_capture_closes_every_owned_handle", "--exact", "--test-threads=1"])
            .env(MARKER, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Hkey;
        fn GetProcessHandleCount(process: Hkey, count: *mut u32) -> i32;
    }
    let count = || {
        let mut result = 0;
        // SAFETY: process pseudo-handle and exclusive DWORD output.
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut result) },
            0
        );
        result
    };
    // Initialize the Win32 registry adapter before comparing retained handles.
    drop(capture(registry()).unwrap());
    let before = count();
    for _ in 0..8 {
        let captured = capture(registry()).unwrap();
        assert!(captured.machine_hive.is_some());
        drop(captured);
    }
    assert_eq!(count(), before);
}
