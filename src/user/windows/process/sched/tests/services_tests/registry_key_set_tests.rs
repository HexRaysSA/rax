//! Native key-body tag replacement and four-slot service identity.
use super::*;

#[path = "registry_key_set_replay.rs"]
mod replay;

#[path = "registry_key_set_post_replay.rs"]
mod post;

#[cfg(windows)]
#[path = "registry_key_set_installed_tests.rs"]
mod installed;

#[test]
fn native_set_key_appends_four_slot_family_without_moving_prior_exports_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::hle::Arg;
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtSetInformationKey"))
        .expect("installed CMD needs NtSetInformationKey");
    assert_eq!(current.exports[family - 1][0].name, "NtEnumerateKey");
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    let appended = BuiltinDll {
        exports: &current.exports[..=family],
        ..previous
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(&appended, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(
            &after.symbols[..before.symbols.len()],
            before.symbols.as_slice()
        );
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert_eq!(
            dll::nt_service("NtSetInformationKey", arch).unwrap().args,
            &[Arg::Ptr, Arg::I32, Arg::Ptr, Arg::I32]
        );
    }
}

#[test]
fn native_set_key_keeps_uncaptured_valid_classes_explicit_and_unknown_metadata_replaceable() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let key = p
            .registry
            .key(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let id = p.objects.create_registry_key_metadata(key, None).unwrap();
        let handle = p.objects.open_access(id, false, 0).unwrap() as u64;
        for class in [0, 1, 2, 3, 4, 6] {
            let module = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((module, table(arch, "NtSetInformationKey", 0x12)));
            arguments(p, &mut t, &[handle, class, 0, 4]);
            assert!(matches!(dispatch(p, &mut t), Outcome::Fail(ref text)
                if text.contains("uncaptured registry key set information class")));
            assert_eq!(p.objects.registry_tags(handle), None);
        }
        p.space.w32(base, 0x1234_5678).unwrap();
        assert_eq!(
            call(p, &mut t, "NtSetInformationKey", &[handle, 5, base, 4]),
            STATUS_SUCCESS
        );
        assert_eq!(p.objects.registry_tags(handle), Some(0x5678));
    }
}
