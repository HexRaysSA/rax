//! Native registry notification admission and pending request ownership.
use super::*;

#[path = "registry_key_notify_replay.rs"]
mod replay;

#[path = "registry_key_notify_lifetime.rs"]
mod lifetime;

#[path = "registry_key_notify_thread.rs"]
mod thread_lifetime;

#[cfg(windows)]
#[path = "registry_key_notify_installed_tests.rs"]
mod installed;

#[test]
fn native_notify_key_appends_ten_slot_family_without_moving_prior_exports_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::hle::Arg;
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtNotifyChangeKey"))
        .expect("installed CMD needs NtNotifyChangeKey");
    assert_eq!(current.exports[family - 1][0].name, "NtSetInformationKey");
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
            dll::nt_service("NtNotifyChangeKey", arch).unwrap().args,
            &[
                Arg::Ptr,
                Arg::Ptr,
                Arg::Ptr,
                Arg::Ptr,
                Arg::Ptr,
                Arg::I32,
                Arg::I32,
                Arg::Ptr,
                Arg::I32,
                Arg::I32
            ]
        );
    }
}
