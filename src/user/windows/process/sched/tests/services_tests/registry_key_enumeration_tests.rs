//! Entered six-argument native service, ordered records, and handle lifetime.
use super::*;
use crate::user::windows::registry::{BasicChild, KeyAccess, MACHINE_HIVE_KEY, MachineHeader};

#[cfg(windows)]
#[path = "registry_key_enumeration_installed_tests.rs"]
mod installed;

#[path = "registry_key_enumeration_replay.rs"]
mod replay;

fn metadata() -> Vec<BasicChild> {
    [
        ("Zulu_🔬", 0x1122_3344_5566_7788),
        ("Alpha", 0x8877_6655_4433_2211),
    ]
    .into_iter()
    .map(|(name, last_write)| BasicChild {
        name: name.encode_utf16().collect(),
        last_write,
    })
    .collect()
}
fn machine(entries: Option<Vec<BasicChild>>, count: u32) -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
    .with_machine_hive(MachineHeader {
        enumeration: entries,
        canonical: MACHINE_HIVE_KEY.encode_utf16().collect(),
        children: count,
        values: vec![],
        access: KeyAccess {
            maximum_access: 0xf003f,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    })
    .unwrap()
}
fn machine_handle(p: &mut Proc, t: &mut Thread, base: u64, access: u64) -> u64 {
    let attrs = base + PAGE_SIZE * 2;
    unicode(p, attrs + 64, attrs + 128, MACHINE_HIVE_KEY);
    attributes(p, attrs, attrs + 64, 0, 0x40);
    assert_eq!(
        call(p, t, "NtOpenKey", &[base, access, attrs]),
        STATUS_SUCCESS
    );
    p.space.ptr(base, p.arch.ptr_size()).unwrap()
}

#[test]
fn native_enumerate_key_six_slot_family_preserves_prior_exports_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::{hle::Arg, loader::builtin};
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtEnumerateKey"))
        .expect("installed CMD needs NtEnumerateKey");
    assert_eq!(current.exports[family - 1][0].name, "NtOpenKeyEx");
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
            dll::nt_service("NtEnumerateKey", arch).unwrap().args,
            &[Arg::Ptr, Arg::I32, Arg::I32, Arg::Ptr, Arg::I32, Arg::Ptr]
        );
    }
}

#[test]
fn native_enumerate_key_keeps_order_utf16_time_and_duplicate_owned_snapshot_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let entries = metadata();
        p.registry = machine(Some(entries.clone()), 2);
        let original = machine_handle(p, &mut t, base, 0x20019);
        let h = p.objects.duplicate(original, false).unwrap() as u64;
        assert_eq!(call(p, &mut t, "NtClose", &[original]), STATUS_SUCCESS);
        p.registry = Registry::default();
        for (index, entry) in entries.iter().enumerate() {
            let mut record = entry.last_write.to_le_bytes().to_vec();
            record.extend(0u32.to_le_bytes());
            record.extend((entry.name.len() as u32 * 2).to_le_bytes());
            record.extend(entry.name.iter().flat_map(|u| u.to_le_bytes()));
            for length in 0..=record.len() + 2 {
                p.space.wr(base + 128, &[0xa5; 64]).unwrap();
                p.space.w32(base + 64, 0xcccccccc).unwrap();
                let actual = call(
                    p,
                    &mut t,
                    "NtEnumerateKey",
                    &[h, index as u64, 0, base + 128, length as u64, base + 64],
                );
                let expected = if length < 16 {
                    STATUS_BUFFER_TOO_SMALL
                } else if length < record.len() {
                    STATUS_BUFFER_OVERFLOW
                } else {
                    STATUS_SUCCESS
                };
                assert_eq!(actual, expected, "{arch}/{index}/{length}");
                assert_eq!(p.space.u32(base + 64).unwrap(), record.len() as u32);
                let mut output = vec![0xa5; 64];
                if length >= 16 {
                    let n = length.min(record.len());
                    output[..n].copy_from_slice(&record[..n]);
                    if n % 2 != 0 {
                        output[n - 1] = 0;
                    }
                }
                assert_eq!(
                    p.space.bytes(base + 128, 64).unwrap(),
                    output,
                    "{arch}/{index}/{length}"
                );
            }
        }
        for index in [2, u32::MAX] {
            p.space.w32(base + 64, 0xcccccccc).unwrap();
            p.space.wr(base + 128, &[0xa5; 64]).unwrap();
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtEnumerateKey",
                    &[h, u64::from(index), 0, base + 128, 64, base + 64]
                ),
                STATUS_NO_MORE_ENTRIES
            );
            assert_eq!(p.space.u32(base + 64).unwrap(), 0xcccccccc);
            assert_eq!(p.space.bytes(base + 128, 64).unwrap(), vec![0xa5; 64]);
        }
        assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        assert_eq!(
            call(
                p,
                &mut t,
                "NtEnumerateKey",
                &[h, 0, 0, base + 128, 64, base + 64]
            ),
            STATUS_INVALID_HANDLE
        );
    }
}

#[test]
fn native_enumerate_key_keeps_missing_metadata_and_valid_uncaptured_classes_explicit() {
    for arch in WinArch::ALL {
        for (entries, count, class, expected) in [
            (None, 1, 0, "registry child metadata is not captured"),
            (
                Some(metadata()),
                2,
                1,
                "registry enumeration class 1 is not captured",
            ),
            (
                Some(metadata()),
                2,
                2,
                "registry enumeration class 2 is not captured",
            ),
        ] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            p.registry = machine(entries, count);
            let h = machine_handle(p, &mut t, base, 8);
            p.space.w32(base + 64, 0xcccccccc).unwrap();
            p.space.wr(base + 128, &[0xa5; 64]).unwrap();
            let module = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((module, table(arch, "NtEnumerateKey", 0x12)));
            arguments(p, &mut t, &[h, 0, class, base + 128, 64, base + 64]);
            let outcome = dispatch(p, &mut t);
            assert!(
                matches!(outcome,Outcome::Fail(ref text) if text.contains(expected)),
                "{arch}/{class}/{outcome:?}"
            );
            assert_eq!(p.space.u32(base + 64).unwrap(), 0xcccccccc);
            assert_eq!(p.space.bytes(base + 128, 64).unwrap(), vec![0xa5; 64]);
        }
    }
}
