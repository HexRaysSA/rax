//! Synthetic PE/HLE consumers share the installed-service timer state machine.
use super::*;

#[test]
fn native_timer2_arm_hle_cancellation_and_duplicate_handle_state_all_abis() {
    use crate::user::windows::objects::Object;
    for arch in WinArch::ALL {
        with_context(arch, |c, out| {
            let before = (c.p.objects.handle_count(), c.p.objects.iter().count());
            assert_eq!(integer(c, "NtCreateTimer2", &[out, 0, 0, 8, 0x1f0003]), 0);
            let handle = c.read_ptr(out).unwrap();
            let id = c.p.objects.id(handle).unwrap();
            let alias = u64::from(c.p.objects.open_access(id, false, 2).unwrap());
            c.mem().w64(out + 32, (-3_000_000_000i64) as u64).unwrap();
            assert_eq!(integer(c, "NtSetTimer2", &[alias, out + 32, 0, 0]), 0);
            assert!(matches!(
                c.p.objects.obj(id),
                Some(Object::IrTimer {
                    schedule: Some(_),
                    signaled: false,
                    ..
                })
            ));
            c.p.objects.close(handle).unwrap();
            assert_eq!(
                integer(c, "NtCancelTimer2", &[alias, arch.ptr(u64::MAX)]),
                0
            );
            assert!(matches!(
                c.p.objects.obj(id),
                Some(Object::IrTimer { schedule: None, .. })
            ));
            c.p.objects.close(alias).unwrap();
            assert!(c.p.objects.obj(id).is_none());
            assert_eq!(
                (c.p.objects.handle_count(), c.p.objects.iter().count()),
                before
            );
        });
    }
}

#[test]
fn native_timer2_arm_preserves_every_prior_ntdll_ordinal_and_trap_rva_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let names = ["NtSetTimer2", "NtCancelTimer2"];
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == names[0]))
        .unwrap();
    assert_eq!(
        current.exports[family]
            .iter()
            .map(|e| e.name)
            .collect::<Vec<_>>(),
        names
    );
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(current, arch, 0, &[]);
        let added: Vec<_> = current.exports[family]
            .iter()
            .filter(|e| e.archs.has(arch))
            .map(|e| e.name)
            .collect();
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert!(after.symbols.len() >= before.symbols.len() + added.len());
        assert_eq!(
            &after.symbols[..before.symbols.len()],
            before.symbols.as_slice(),
            "{arch}: prior ordinals or trap RVAs moved"
        );
        assert_eq!(
            after.symbols[before.symbols.len()..before.symbols.len() + added.len()]
                .iter()
                .map(|row| row.0)
                .collect::<Vec<_>>(),
            added
        );
    }
}
