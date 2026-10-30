//! Win32 creation and NT opening retain one event and captured directory identity.
use super::*;

fn named_attributes(c: &Ctx, at: u64, root: u64, name: &str) {
    let width = c.psize();
    c.mem().wr(at, &[0; 48]).unwrap();
    c.mem()
        .w32(at, if c.arch().is64() { 48 } else { 24 })
        .unwrap();
    c.write_ptr(at + width, root).unwrap();
    c.write_ptr(at + 2 * width, at + 64).unwrap();
    c.mem().w32(at + 3 * width, 0x42).unwrap();
    c.mem().wr(at + 64, &[0; 16]).unwrap();
    c.mem()
        .w16(at + 64, (name.encode_utf16().count() * 2) as u16)
        .unwrap();
    c.write_ptr(at + 64 + width, at + 128).unwrap();
    put_name(c, at + 128, name);
}

#[test]
fn native_open_event_win32_state_and_retired_directory_routes_share_identity_all_abis() {
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
                put_name(c, data, "Local\\SharedOpenEvent");
                let first = integer(c, "CreateEventW", &[0, 1, 0, data]);
                assert_ne!(first, 0);
                let base = if session == 0 {
                    "\\BaseNamedObjects".to_owned()
                } else {
                    format!("\\Sessions\\{session}\\BaseNamedObjects")
                };
                let directory =
                    c.p.object_namespace
                        .lookup(None, &base.encode_utf16().collect::<Vec<_>>(), 0)
                        .unwrap();
                let root = c.p.objects.open_directory(directory, false, 0xF).unwrap() as u64;
                let attrs = data + 512;
                named_attributes(c, attrs, 0, &format!("{base}\\SharedOpenEvent"));
                c.set_last_error(0x7654_3210).unwrap();
                assert_eq!(integer(c, "NtOpenEvent", &[data + 256, 0x1F0003, attrs]), 0);
                assert_eq!(c.last_error().unwrap(), 0x7654_3210);
                let alias = c.read_ptr(data + 256).unwrap();
                let id = c.p.objects.id(first).unwrap();
                assert_eq!(c.p.objects.id(alias), Some(id));
                assert_eq!(c.p.objects.flags(alias), Some(1));
                assert_eq!(integer(c, "NtSetEvent", &[alias, data + 320]), 0);
                assert_eq!(c.mem().u32(data + 320).unwrap(), 0);
                assert_eq!(integer(c, "WaitForSingleObject", &[first, 0]), 0);
                assert_eq!(integer(c, "ResetEvent", &[first]), 1);
                assert_eq!(
                    integer(c, "WaitForSingleObject", &[alias, 0]),
                    u64::from(0x102u32)
                );
                c.p.objects.close(first).unwrap();
                c.p.object_namespace = Default::default();
                named_attributes(c, attrs, root, "SharedOpenEvent");
                assert_eq!(integer(c, "NtOpenEvent", &[data + 256, 0x100000, attrs]), 0);
                let retained = c.read_ptr(data + 256).unwrap();
                assert_eq!(c.p.objects.id(retained), Some(id));
                c.p.objects.close(root).unwrap();
                c.p.objects.close(alias).unwrap();
                assert!(c.p.objects.obj(id).is_some());
                c.p.objects.close(retained).unwrap();
                assert!(c.p.objects.obj(id).is_none());
            });
        }
    }
}
