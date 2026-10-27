//! Exercise the actual acquisition adapter with private temporary NT objects.
use std::ptr::null_mut;
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::{Attributes, Handle, Owned, Unicode, basic, check, open, target};
use super::{verified, verified_windows};
use crate::user::windows::nt::status::STATUS_PRIVILEGE_NOT_HELD;
use crate::user::windows::object_namespace::{CapturedEntry, SelectedDirectory};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateDirectoryObject(out: *mut Handle, access: u32, attributes: *mut Attributes) -> i32;
    fn NtCreateSymbolicLinkObject(
        out: *mut Handle,
        access: u32,
        attributes: *mut Attributes,
        target: *mut Unicode,
    ) -> i32;
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn create(path: &[u16], root: Handle, destination: Option<&[u16]>) -> Owned {
    let mut name_units = path.to_vec();
    let mut name = Unicode {
        length: (name_units.len() * 2) as u16,
        maximum: (name_units.len() * 2) as u16,
        buffer: name_units.as_mut_ptr(),
    };
    let mut attributes = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root,
        name: &mut name,
        flags: 0x40,
        security: null_mut(),
        qos: null_mut(),
    };
    let mut output = null_mut();
    let mut target_units = destination.unwrap_or_default().to_vec();
    let mut target = Unicode {
        length: (target_units.len() * 2) as u16,
        maximum: (target_units.len() * 2) as u16,
        buffer: target_units.as_mut_ptr(),
    };
    // SAFETY: initialized current-native-ABI structures and live bounded UTF-16
    // buffers; optional owned parent remains live. Unique names are temporary,
    // not permanent/open-if objects. APIs retain no caller pointer. Successful
    // exclusive output is immediately owned; errors publish no object handle.
    let status = unsafe {
        if destination.is_some() {
            NtCreateSymbolicLinkObject(&mut output, 0x000F_0001, &mut attributes, &mut target)
        } else {
            NtCreateDirectoryObject(&mut output, 0x000F_000F, &mut attributes)
        }
    };
    check(status, "create private selected-alias test object").unwrap();
    assert!(!output.is_null());
    Owned(output)
}

#[test]
fn installed_session_directory_alias_compares_pinned_objects_and_rejects_distinct_target() {
    let unique = format!(
        "\\BaseNamedObjects\\AssistRaxDirectoryAlias-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    );
    let parent = create(&units(&unique), null_mut(), None);
    let child = create(&units("ActualTarget"), parent.0, None);
    let other = create(&units("OtherTarget"), parent.0, None);
    let absolute_target = units(&format!("{unique}\\ActualTarget"));
    let link = create(&units("BaseNamedObjects"), parent.0, Some(&absolute_target));
    let (captured_target, access) = target(&parent, &units("BaseNamedObjects")).unwrap();
    let source = units("\\Sessions\\7\\BaseNamedObjects");
    let destination = units("\\BaseNamedObjects");
    let selected = vec![SelectedDirectory {
        path: units("\\Sessions\\7"),
        maximum_access: basic(&parent).unwrap(),
        force_case_insensitive: false,
        system_security_status: STATUS_PRIVILEGE_NOT_HELD,
        entries: vec![CapturedEntry {
            name: units("BaseNamedObjects"),
            kind: units("SymbolicLink"),
            target: Some(captured_target),
            link_access: Some(access),
            section: None,
        }],
    }];
    let alias = open(
        &units("BaseNamedObjects"),
        parent.0,
        0x0200_0000,
        false,
        0x40,
    )
    .unwrap()
    .unwrap();
    let handles = vec![
        (units("\\Sessions\\7"), parent),
        (source.clone(), alias),
        (destination.clone(), child),
    ];
    assert_eq!(
        verified(&selected, &handles, 7).unwrap(),
        [(source, destination.clone())]
    );
    let mut wrong_handles = handles;
    let correct = std::mem::replace(&mut wrong_handles[2].1, other);
    let error = verified(&selected, &wrong_handles, 7)
        .unwrap_err()
        .to_string();
    assert!(error.contains("comparison=0xc00001ac"), "{error}");
    assert!(verified(&selected, &wrong_handles, 0).unwrap().is_empty());
    link.close().unwrap();
    correct.close().unwrap();
    for (_, handle) in wrong_handles.into_iter().rev() {
        handle.close().unwrap();
    }
}

#[test]
fn installed_session_windows_link_requires_global_identity_and_retains_zero_session() {
    let unique = format!(
        "\\BaseNamedObjects\\AssistRaxWindowsAlias-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let parent = create(&units(&unique), null_mut(), None);
    let other = create(&units("Other"), parent.0, None);
    let link = create(&units("Windows"), parent.0, Some(&units("\\Windows")));
    let global = open(&units("\\Windows"), null_mut(), 0x0200_0000, false, 0x40)
        .unwrap()
        .unwrap();
    let (captured_target, access) = target(&parent, &units("Windows")).unwrap();
    let mut selected = vec![SelectedDirectory {
        path: units("\\Sessions\\0"),
        maximum_access: basic(&parent).unwrap(),
        force_case_insensitive: true,
        system_security_status: STATUS_PRIVILEGE_NOT_HELD,
        entries: vec![CapturedEntry {
            name: units("Windows"),
            kind: units("SymbolicLink"),
            target: Some(captured_target),
            link_access: Some(access),
            section: None,
        }],
    }];
    let mut handles = vec![
        (units("\\Sessions\\0"), parent),
        (units("\\Windows"), global),
    ];
    assert!(verified_windows(&selected, &handles, 0).unwrap());
    selected[0].path = units("\\Sessions\\7");
    handles[0].0 = units("\\Sessions\\7");
    assert!(verified_windows(&selected, &handles, 7).unwrap());
    selected[0].entries[0].kind = units("Directory");
    assert!(!verified_windows(&selected, &handles, 7).unwrap());
    selected[0].entries[0].kind = units("SymbolicLink");
    let correct = std::mem::replace(&mut handles[1].1, other);
    assert!(
        verified_windows(&selected, &handles, 7)
            .unwrap_err()
            .to_string()
            .contains("identity/grant changed")
    );
    link.close().unwrap();
    correct.close().unwrap();
    for (_, handle) in handles.into_iter().rev() {
        handle.close().unwrap();
    }
}
