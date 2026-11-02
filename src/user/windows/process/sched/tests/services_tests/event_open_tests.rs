//! Native opening retains the existing guest event rather than copying state.
#[path = "event_open_replay.rs"]
mod replay;

use super::*;
use crate::user::windows::object_namespace::reparse_tests;
use crate::user::windows::sync;

fn named(p: &mut Proc, address: u64, root: u64, name: &str, flags: u32) {
    let width = p.arch.ptr_size();
    let text: Vec<_> = name.encode_utf16().collect();
    attrs(p, address, if p.arch.is64() { 48 } else { 24 }, flags, root);
    p.space
        .wptr(address + 2 * width, width, address + 64)
        .unwrap();
    p.space.wr(address + 64, &[0; 16]).unwrap();
    p.space.w16(address + 64, (text.len() * 2) as u16).unwrap();
    p.space
        .wptr(address + 64 + width, width, address + 128)
        .unwrap();
    p.space.put_wstr(address + 128, &text).unwrap();
}

#[test]
fn native_open_event_shares_named_identity_and_last_handle_lifetime_all_abis() {
    for arch in WinArch::ALL {
        for session in [0, 42] {
            let (mut process, mut thread, out) = setup(arch);
            let p = process.state_mut();
            p.object_namespace = reparse_tests::sample(session);
            let base = if session == 0 {
                "\\BaseNamedObjects".to_owned()
            } else {
                format!("\\Sessions\\{session}\\BaseNamedObjects")
            };
            let directory = p
                .object_namespace
                .lookup(None, &base.encode_utf16().collect::<Vec<_>>(), 0)
                .unwrap();
            let root = p.objects.open_directory(directory, false, 0xF).unwrap() as u64;
            let selected = p
                .object_namespace
                .named_win32(
                    session,
                    &"MeasuredOpenEvent".encode_utf16().collect::<Vec<_>>(),
                )
                .unwrap();
            let (id, existed) = p
                .objects
                .try_create_native_named(
                    selected,
                    Object::Event {
                        manual: false,
                        signaled: 1,
                    },
                )
                .unwrap();
            assert!(!existed);
            let creator = p.objects.open_access(id, false, 0x1F0003).unwrap() as u64;
            named(p, out + 256, root, "MeasuredOpenEvent", 2);
            assert_eq!(
                status(p, &mut thread, "NtOpenEvent", &[out, 0x100000, out + 256]),
                0
            );
            let alias = handle(p, out);
            assert_eq!(p.objects.id(alias), Some(id));
            assert_eq!(p.objects.access(alias), Some(0x100000));
            assert_eq!(p.objects.flags(alias), Some(1));
            p.objects.close(creator).unwrap();
            p.objects.close(root).unwrap();
            assert_eq!(
                sync::try_objects(p, thread.tid, &[id], false).unwrap(),
                Some(0)
            );
            assert_eq!(
                sync::try_objects(p, thread.tid, &[id], false).unwrap(),
                None
            );
            p.objects.close(alias).unwrap();
            assert!(p.objects.obj(id).is_none());
        }
    }
}

#[test]
fn native_open_event_preserves_prior_ntdll_ordinals_and_trap_addresses_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|export| export.name == "NtOpenEvent"))
        .unwrap();
    assert_eq!(
        family, 16,
        "the sixteen preceding export families retain their order"
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
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert!(after.symbols.len() > before.symbols.len());
        assert_eq!(
            &after.symbols[..before.symbols.len()],
            before.symbols.as_slice(),
            "{arch}"
        );
    }
}
