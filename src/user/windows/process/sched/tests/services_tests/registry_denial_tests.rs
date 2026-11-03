//! Denied bodies retain their names; missing descendants keep lookup precedence.
use super::*;
use crate::user::windows::registry::{
    BasicChild, CapturedTree, CapturedTreeNode, IFEO_KEY, KeyTree, TreeRoot,
};
use std::collections::BTreeMap;

const DENIED: &str = "DefenderAgentScan.exe";
const TIME: u64 = 0x01DD_6AD7_9543_EEAA;

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn selection(p: &mut Proc) {
    let root = units(IFEO_KEY);
    let denied = [root.clone(), units(DENIED)].join(&92);
    let allowed = [root.clone(), units("Allowed.exe")].join(&92);
    p.registry = p
        .registry
        .clone()
        .with_captured_tree(
            TreeRoot::Ifeo,
            Some(CapturedTree {
                tree: KeyTree {
                    values: vec![],
                    children: vec![
                        (units(DENIED), KeyTree::default()),
                        (
                            units("Allowed.exe"),
                            KeyTree {
                                values: vec![Value {
                                    name: units("Flag"),
                                    kind: 4,
                                    data: 42u32.to_le_bytes().to_vec(),
                                }],
                                children: vec![],
                            },
                        ),
                    ],
                },
                nodes: BTreeMap::from([
                    (
                        root,
                        CapturedTreeNode::Readable(vec![
                            BasicChild {
                                name: units(DENIED),
                                last_write: TIME,
                            },
                            BasicChild {
                                name: units("Allowed.exe"),
                                last_write: 7,
                            },
                        ]),
                    ),
                    (denied, CapturedTreeNode::Denied { children: 0 }),
                    (allowed, CapturedTreeNode::Readable(vec![])),
                ]),
            }),
        )
        .unwrap();
}

#[test]
fn native_registry_denial_distinguishes_final_key_missing_descendants_and_output_fault_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        selection(p);
        let attrs = base + PAGE_SIZE * 2;
        unicode(p, attrs + 64, attrs + 128, IFEO_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x40);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 9, attrs]),
            STATUS_SUCCESS
        );
        let root = p.space.ptr(base, arch.ptr_size()).unwrap();
        for relative in [false, true] {
            for (suffix, expected) in [
                (DENIED.to_owned(), STATUS_ACCESS_DENIED),
                ("defenderagentscan.EXE\\".to_owned(), STATUS_ACCESS_DENIED),
                (format!("{DENIED}\\missing"), STATUS_OBJECT_NAME_NOT_FOUND),
                ("cmd.exe".to_owned(), STATUS_OBJECT_NAME_NOT_FOUND),
                ("cmd.exe\\missing".to_owned(), STATUS_OBJECT_NAME_NOT_FOUND),
            ] {
                let path = if relative {
                    suffix
                } else {
                    format!("{IFEO_KEY}\\{suffix}")
                };
                unicode(p, attrs + 64, attrs + 128, &path);
                attributes(p, attrs, attrs + 64, if relative { root } else { 0 }, 0x40);
                for access in [0, 1, 8, 9, 0x20000, 0x20019, 0x0200_0000] {
                    let handles = p.objects.handle_count();
                    p.space
                        .wptr(base, arch.ptr_size(), arch.ptr(u64::MAX))
                        .unwrap();
                    assert_eq!(
                        call(p, &mut t, "NtOpenKey", &[base, access, attrs]),
                        expected,
                        "{arch}/{relative}/{path}/{access:x}"
                    );
                    assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
                    assert_eq!(p.objects.handle_count(), handles);
                }
            }
        }
        unicode(p, attrs + 64, attrs + 128, &format!("{IFEO_KEY}\\{DENIED}"));
        attributes(p, attrs, attrs + 64, 0, 0x40);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[0, 9, attrs]),
            if arch == WinArch::X86 {
                STATUS_ACCESS_DENIED
            } else {
                STATUS_ACCESS_VIOLATION
            }
        );
        assert_eq!(call(p, &mut t, "NtClose", &[root]), STATUS_SUCCESS);
    }
}

#[test]
fn native_registry_denial_keeps_parent_enumeration_and_accessible_sibling_after_catalog_drop_all_abis()
 {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        selection(p);
        let attrs = base + PAGE_SIZE * 2;
        unicode(p, attrs + 64, attrs + 128, IFEO_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x40);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 9, attrs]),
            STATUS_SUCCESS
        );
        let original = p.space.ptr(base, arch.ptr_size()).unwrap();
        let parent = p.objects.duplicate(original, false).unwrap() as u64;
        assert_eq!(call(p, &mut t, "NtClose", &[original]), STATUS_SUCCESS);
        p.registry = Registry::default();
        let mut record = TIME.to_le_bytes().to_vec();
        record.extend(0u32.to_le_bytes());
        record.extend((DENIED.encode_utf16().count() as u32 * 2).to_le_bytes());
        record.extend(DENIED.encode_utf16().flat_map(u16::to_le_bytes));
        for length in [0, 15, 16, 55, 56, 57, 58, 63, 64, 65, 128] {
            p.space.wr(base + 128, &[0xA5; 128]).unwrap();
            let expected = if length < 16 {
                STATUS_BUFFER_TOO_SMALL
            } else if length < record.len() as u64 {
                STATUS_BUFFER_OVERFLOW
            } else {
                STATUS_SUCCESS
            };
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtEnumerateKey",
                    &[parent, 0, 0, base + 128, length, base + 64]
                ),
                expected
            );
            assert_eq!(p.space.u32(base + 64).unwrap(), record.len() as u32);
            let mut output = vec![0xA5; 128];
            if length >= 16 {
                let count = (length as usize).min(record.len());
                output[..count].copy_from_slice(&record[..count]);
                if count % 2 != 0 {
                    output[count - 1] = 0;
                }
            }
            assert_eq!(
                p.space.bytes(base + 128, 128).unwrap(),
                output,
                "{arch}/{length}"
            );
        }
        unicode(p, attrs + 64, attrs + 128, "Allowed.exe");
        attributes(p, attrs, attrs + 64, parent, 0x40);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
            STATUS_SUCCESS
        );
        let sibling = p.space.ptr(base, arch.ptr_size()).unwrap();
        assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
        unicode(p, attrs + 64, attrs + 128, "Flag");
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryValueKey",
                &[sibling, attrs + 64, 2, base + 128, 32, base + 64]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(base + 140).unwrap(), 42);
        assert_eq!(call(p, &mut t, "NtClose", &[sibling]), STATUS_SUCCESS);
    }
}
