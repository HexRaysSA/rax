use super::*;
use crate::user::windows::registry::{KeyTree, RegistryView, TreeRoot};

#[derive(serde::Deserialize)]
struct Controls {
    rows: Vec<Observation>,
}

#[derive(serde::Deserialize)]
struct Observation {
    view: u32,
    memory_open: u32,
    relative_children: std::collections::BTreeMap<String, u32>,
    translation_open: u32,
}

#[test]
fn child_image_registry_replays_native_fixed_and_relative_opens() {
    let controls: Controls = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-child-image-keys/arm64-29708.json"
    )))
    .unwrap();
    assert_eq!(controls.rows.len(), 2);
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        prepare_parent(p);
        let memory = TreeRoot::MemoryManagement;
        p.registry = p
            .registry
            .clone()
            .with_tree(
                memory,
                Some(KeyTree {
                    values: Vec::new(),
                    children: vec![(
                        "OtherImage.exe".encode_utf16().collect(),
                        KeyTree::default(),
                    )],
                }),
            )
            .unwrap();
        let jit_name = "\\Registry\\Machine\\Software\\Microsoft\\Wow64\\x86\\xtajit";
        for row in &controls.rows {
            let view = if row.view == 0x100 {
                RegistryView::Native64
            } else {
                assert_eq!(row.view, 0x200);
                RegistryView::Wow32
            };
            p.registry = p
                .registry
                .clone()
                .with_wow64_x86_jit_absence(view, row.translation_open)
                .unwrap();
        }
        let attrs = base + PAGE_SIZE * 2;
        let name = attrs + 64;
        let storage = attrs + 128;
        for row in &controls.rows {
            unicode(p, name, storage, memory.path());
            attributes(p, attrs, name, 0, 0x240);
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    "NtOpenKey",
                    &[base, u64::from(1 | row.view), attrs]
                ),
                row.memory_open
            );
            let parent = p.space.ptr(base, arch.ptr_size()).unwrap();
            for (image, status) in &row.relative_children {
                unicode(p, name, storage, image);
                attributes(p, attrs, name, parent, 0x240);
                assert_eq!(
                    call(p, &mut thread, "NtOpenKey", &[base, 9, attrs]),
                    *status
                );
                assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
            }
            assert_eq!(call(p, &mut thread, "NtClose", &[parent]), STATUS_SUCCESS);
            unicode(p, name, storage, jit_name);
            attributes(p, attrs, name, 0, 0x240);
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    "NtOpenKey",
                    &[base, u64::from(1 | row.view), attrs]
                ),
                row.translation_open
            );
        }
    }
}
