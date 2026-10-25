//! Native reference binds shared Win32/native semaphore state and PE identity.
use super::*;

#[test]
fn native_semaphore_win32_native_names_counts_and_cross_type_lifetime_all_abis() {
    use crate::user::windows::nt::status::*;
    use crate::user::windows::object_namespace::reparse_tests;
    for arch in WinArch::ALL {
        for session in [0, 42] {
            with_context(arch, |c, data| {
                c.p.object_namespace = reparse_tests::sample(session);
                c.p.objects.select_wnf_catalog(
                    crate::user::windows::wnf::tests::empty_subject_catalog(false)
                        .with_primary_token_session_id(session)
                        .with_primary_token_bno(
                            crate::user::windows::security::token::bno::Isolation::new(None)
                                .unwrap(),
                        ),
                );
                put_name(c, data, "Local\\SharedSemaphore");
                let first = integer(c, "CreateSemaphoreW", &[0, 1, 3, data]);
                assert_ne!(first, 0);
                let base = if session == 0 {
                    "\\BaseNamedObjects".to_owned()
                } else {
                    format!("\\Sessions\\{session}\\BaseNamedObjects")
                };
                let name = format!("{base}\\SharedSemaphore");
                let oa = data + 512;
                let descriptor = data + 576;
                let text = data + 640;
                put_name(c, text, &name);
                let width = c.psize();
                c.mem().wr(oa, &[0; 48]).unwrap();
                c.mem().w32(oa, if arch.is64() { 48 } else { 24 }).unwrap();
                c.write_ptr(oa + 2 * width, descriptor).unwrap();
                c.mem().wr(descriptor, &[0; 16]).unwrap();
                c.mem()
                    .w16(descriptor, (name.encode_utf16().count() * 2) as u16)
                    .unwrap();
                c.write_ptr(descriptor + width, text).unwrap();
                assert_eq!(
                    integer(c, "NtOpenSemaphore", &[data + 256, 0x1F0003, oa]),
                    0
                );
                let alias = c.read_ptr(data + 256).unwrap();
                assert_eq!(c.p.objects.id(alias), c.p.objects.id(first));
                assert_eq!(integer(c, "WaitForSingleObject", &[first, 0]), 0);
                assert_eq!(integer(c, "NtReleaseSemaphore", &[alias, 2, data + 320]), 0);
                assert_eq!(c.mem().u32(data + 320).unwrap(), 0);
                assert_eq!(integer(c, "ReleaseSemaphore", &[first, 1, data + 320]), 1);
                assert_eq!(c.mem().u32(data + 320).unwrap(), 2);
                assert_eq!(
                    integer(c, "NtQuerySemaphore", &[alias, 0, data + 352, 8, 0]),
                    0
                );
                assert_eq!(c.mem().u32(data + 352).unwrap(), 3);
                assert_eq!(c.mem().u32(data + 356).unwrap(), 3);
                // Win32 opens an existing name without validating these counts;
                // native creation validates them even when OBJ_OPENIF is set.
                let same = integer(c, "CreateSemaphoreW", &[0, u64::MAX, 0, data]);
                assert_eq!(c.p.objects.id(same), c.p.objects.id(first));
                assert_eq!(c.last_error().unwrap(), ERROR_ALREADY_EXISTS);
                c.mem().w32(oa + 3 * width, 0x80).unwrap();
                assert_eq!(
                    integer(c, "NtCreateSemaphore", &[data + 256, 1, oa, u64::MAX, 0]),
                    u64::from(STATUS_INVALID_PARAMETER)
                );
                for h in [same, alias, first] {
                    c.p.objects.close(h).unwrap();
                }
                let event = integer(c, "CreateEventW", &[0, 1, 0, data]);
                assert_ne!(event, 0);
                assert_eq!(
                    integer(c, "NtCreateSemaphore", &[data + 256, 1, oa, 0, 1]),
                    u64::from(STATUS_OBJECT_TYPE_MISMATCH)
                );
                c.p.objects.close(event).unwrap();
            });
        }
    }
}

#[test]
fn native_semaphore_preserves_every_prior_ntdll_ordinal_and_trap_rva_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let names = [
        "NtCreateSemaphore",
        "NtOpenSemaphore",
        "NtReleaseSemaphore",
        "NtQuerySemaphore",
    ];
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
