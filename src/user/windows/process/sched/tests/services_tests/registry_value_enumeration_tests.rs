//! Entry and record tests for ordinal snapshot-backed registry values.
use super::*;
use crate::user::windows::registry::{CapturedTree, CapturedTreeNode, KeyTree, TreeRoot};
use std::collections::BTreeMap;

#[cfg(windows)]
#[path = "registry_value_enumeration_installed_tests.rs"]
mod installed;

const SERVICE: &str = "NtEnumerateValueKey";
const UNCAPTURED: &str = crate::user::windows::registry::NLS_KEY;

fn registry() -> Registry {
    let path = TreeRoot::MuiSystem.path().encode_utf16().collect();
    let values = [("Zulu", [17, 34, 51, 68]), ("A🌍", [85, 102, 119, 136])]
        .into_iter()
        .map(|(name, data)| Value {
            name: name.encode_utf16().collect(),
            kind: 4,
            data: data.to_vec(),
        })
        .collect();
    Registry::nls((0..=u16::MAX).collect(), vec![], 0)
        .unwrap()
        .with_captured_tree(
            TreeRoot::MuiSystem,
            Some(CapturedTree {
                tree: KeyTree {
                    values,
                    children: vec![],
                },
                nodes: BTreeMap::from([(path, CapturedTreeNode::Readable(vec![]))]),
            }),
        )
        .unwrap()
}

fn open(p: &mut Proc, t: &mut Thread, base: u64, path: &str, rights: u64) -> u64 {
    let attrs = base + PAGE_SIZE * 2;
    unicode(p, attrs + 64, attrs + 128, path);
    attributes(p, attrs, attrs + 64, 0, 0x40);
    assert_eq!(
        call(p, t, "NtOpenKey", &[base, rights, attrs]),
        STATUS_SUCCESS
    );
    p.space.ptr(base, p.arch.ptr_size()).unwrap()
}

#[test]
fn native_enumerate_values_preserves_synthetic_ordinals_and_entered_abi() {
    use crate::user::windows::{
        dll::{self, BuiltinDll},
        hle::Arg,
        loader::builtin,
    };
    let full = dll::find("ntdll.dll").unwrap();
    let table = full
        .exports
        .iter()
        .position(|group| group.iter().any(|export| export.name == SERVICE))
        .unwrap();
    let old = BuiltinDll {
        name: full.name,
        display: full.display,
        subsystem: full.subsystem,
        exports: &full.exports[..table],
    };
    let introduced = BuiltinDll {
        exports: &full.exports[..=table],
        ..old
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&old, arch, 0, &[]);
        let after = builtin::build(&introduced, arch, 0, &[]);
        let current = builtin::build(full, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert_eq!(&after.symbols[..before.symbols.len()], &before.symbols);
        assert_eq!(after.symbols.last().unwrap().0, SERVICE);
        assert_eq!(current.ordinal_base, after.ordinal_base);
        assert!(current.symbols.len() >= after.symbols.len());
        // Later exports may move RVAs but must preserve the ordinal order.
        assert!(
            after
                .symbols
                .iter()
                .zip(&current.symbols)
                .all(|((before, _), (after, _))| before == after)
        );
        assert_eq!(
            dll::nt_service(SERVICE, arch).unwrap().args,
            &[Arg::Ptr, Arg::I32, Arg::I32, Arg::Ptr, Arg::I32, Arg::Ptr]
        );
    }
}

#[test]
fn native_enumerate_values_preserves_order_records_and_duplicated_snapshot() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = registry();
        let original = open(p, &mut t, base, TreeRoot::MuiSystem.path(), 1);
        let h = u64::from(p.objects.duplicate(original, false).unwrap());
        assert_eq!(call(p, &mut t, "NtClose", &[original]), STATUS_SUCCESS);
        p.registry = Registry::default();

        for (index, (name, data)) in [("Zulu", [17, 34, 51, 68]), ("A🌍", [85, 102, 119, 136])]
            .into_iter()
            .enumerate()
        {
            let name: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            for (class, header) in [(0, 12), (1, 20), (2, 12)] {
                let words = match class {
                    0 => vec![0, 4, name.len() as u32],
                    1 => vec![0, 4, 32, 4, name.len() as u32],
                    2 => vec![0, 4, 4],
                    _ => unreachable!(),
                };
                let mut expected: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
                if class != 2 {
                    expected.extend_from_slice(&name);
                }
                if class == 1 {
                    expected.resize(32, 0);
                }
                if class != 0 {
                    expected.extend(data);
                }
                let required = expected.len();
                for n in [
                    0,
                    header - 1,
                    header,
                    header + 1,
                    required - 1,
                    required,
                    64,
                ] {
                    let (out, ret) = (base + 132, base + 65);
                    p.space.wr(out, &[0xa5; 64]).unwrap();
                    p.space.w32(ret, 0xcccccccc).unwrap();
                    let result = call(
                        p,
                        &mut t,
                        SERVICE,
                        &[h, index as u64, class, out, n as u64, ret],
                    );
                    let (status, count) = if n < header {
                        (STATUS_BUFFER_TOO_SMALL, 0)
                    } else if n < required {
                        (STATUS_BUFFER_OVERFLOW, n)
                    } else {
                        (STATUS_SUCCESS, required)
                    };
                    let mut bytes = [0xa5; 64];
                    bytes[..count].copy_from_slice(&expected[..count]);
                    if class != 2
                        && count > header
                        && count < header + name.len()
                        && (count - header) % 2 != 0
                    {
                        bytes[count - 1] = 0;
                    }
                    assert_eq!(result, status, "{arch}/{index}/{class}/{n}");
                    assert_eq!(p.space.u32(ret).unwrap(), required as u32);
                    assert_eq!(p.space.bytes(out, 64).unwrap(), bytes);
                }
            }
        }
        assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
    }
}

#[test]
fn native_enumerate_values_status_precedence_and_no_entries_leave_canaries() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = registry();
        let h = open(p, &mut t, base, TreeRoot::MuiSystem.path(), 1);
        let no_query = open(p, &mut t, base, TreeRoot::MuiSystem.path(), 8);
        let (out, ret) = (base + 128, base + 64);
        p.space.wr(out, &[0xa5; 64]).unwrap();
        p.space.w32(ret, 0xcccccccc).unwrap();
        for (args, expected) in [
            ([0, 0, 3, 0, 64, 0], STATUS_INVALID_PARAMETER),
            ([0, 0, 1, out + 1, 64, 0], STATUS_INVALID_HANDLE),
            ([no_query, 0, 1, out + 1, 64, 0], STATUS_ACCESS_DENIED),
            ([h, 0, 1, out + 1, 64, 0], STATUS_DATATYPE_MISALIGNMENT),
            ([h, 2, 1, out, 64, 0], STATUS_ACCESS_VIOLATION),
            ([h, 2, 1, out, 64, ret], STATUS_NO_MORE_ENTRIES),
            (
                [h, u64::from(u32::MAX), 1, 0, 64, ret],
                STATUS_NO_MORE_ENTRIES,
            ),
        ] {
            assert_eq!(call(p, &mut t, SERVICE, &args), expected, "{arch}/{args:?}");
            assert_eq!(p.space.u32(ret).unwrap(), 0xcccccccc);
            assert_eq!(p.space.bytes(out, 64).unwrap(), [0xa5; 64]);
        }
        assert_eq!(
            call(p, &mut t, SERVICE, &[h, 0, 1, 0, 64, ret]),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(p.space.u32(ret).unwrap(), 36);

        let uncaptured = open(p, &mut t, base, UNCAPTURED, 1);
        let module = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.nt_services = Some((module, table(arch, SERVICE, 0x12)));
        arguments(p, &mut t, &[uncaptured, 0, 1, out, 64, ret]);
        let outcome = dispatch(p, &mut t);
        assert!(
            matches!(
                &outcome,
                Outcome::Fail(message) if message.contains("value enumeration order is not captured")
            ),
            "{arch}/{outcome:?}"
        );
    }
}
