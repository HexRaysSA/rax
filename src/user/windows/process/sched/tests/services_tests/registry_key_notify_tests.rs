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

#[test]
fn native_notify_key_uncaptured_io_profile_keeps_memory_events_and_objects_unarmed_all_abis() {
    for arch in WinArch::ALL {
        for (build, machine) in [
            (20347, Some(0x8664)),
            (20348, Some(0xAA64)),
            (20348, Some(0x14c)),
            (20348, None),
            (29694, Some(0xAA64)),
            (29695, Some(0x8664)),
        ] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            super::super::native_profile::kernel_profile(p, build, machine.unwrap_or(0));
            p.native.as_mut().unwrap().object_namespace.native_machine = machine;
            let key = replay::body(p);
            let event = replay::event(p);
            let before = (p.objects.handle_count(), p.objects.iter().count());
            let initial = vec![0xcc; arch.ptr_size() as usize * 2];
            p.space.wr(base, &initial).unwrap();
            let module = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((module, table(arch, "NtNotifyChangeKey", 0x12)));
            arguments(p, &mut t, &[key, event, 0, 0, base, 1, 0, 0, 0, 1]);
            assert!(matches!(dispatch(p, &mut t), Outcome::Fail(message)
                if message.contains("registry notification kernel profile is not captured")));
            assert_eq!(p.space.bytes(base, initial.len()).unwrap(), initial);
            assert_eq!(replay::signal(p, event), 0);
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
            // Thread-agnostic registrations do not use the caller IOSB.
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtNotifyChangeKey",
                    &[key, event, 0, 0, 0, 0x10000001, 0, 0, 0, 1]
                ),
                STATUS_PENDING
            );
            assert_eq!(call(p, &mut t, "NtClose", &[key]), 0);
            assert_eq!(replay::signal(p, event), 0);
            assert_eq!(call(p, &mut t, "NtClose", &[event]), 0);
        }
    }
}
