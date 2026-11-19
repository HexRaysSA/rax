use super::*;
use crate::user::windows::gui::cursor_icons::{Catalog, Resource};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::prot;
use crate::user::windows::registry::Registry;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

const NATIVE_LOOKUP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-cursor-icon-cache/native-29708-v6.json"
));
const NATIVE_BOUNDARIES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-cursor-icon-cache/native-29708-v7.json"
));
const SERVICE: u32 = 0x1039;
const LAST_ERROR: u32 = 0x5aa5;
const LAST_STATUS: u32 = 0xc000_0034;

fn scalar(value: &Value) -> u32 {
    value.as_u64().unwrap().try_into().unwrap()
}

fn name(length: u16, maximum: u16, buffer: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..2].copy_from_slice(&length.to_le_bytes());
    bytes[2..4].copy_from_slice(&maximum.to_le_bytes());
    bytes[8..].copy_from_slice(&buffer.to_le_bytes());
    bytes
}

fn request(words: [u32; 6]) -> [u8; 24] {
    std::array::from_fn(|index| words[index / 4].to_le_bytes()[index % 4])
}

#[test]
fn cursor_icons_replay_selected_windows_lookup_and_user_buffer_boundaries() {
    let lookup: Vec<Value> = serde_json::from_str(NATIVE_LOOKUP).unwrap();
    let boundaries: Vec<Value> = serde_json::from_str(NATIVE_BOUNDARIES).unwrap();
    assert_eq!(lookup.len(), 1215);
    assert_eq!(boundaries.len(), 663);
    let catalog: BTreeMap<_, _> = lookup
        .iter()
        .filter(|row| row["label"][0] == "catalog" && scalar(&row["value"]) != 0)
        .map(|row| {
            let id = scalar(&row["label"][1]) as u16;
            let selector = scalar(&row["label"][2]);
            let native = scalar(&row["value"]);
            let depths = match (id, selector) {
                (32512 | 32516, 1) | (32512..=32516, 3) => 1 << 31,
                (32515, 1) => 1,
                _ => 0,
            };
            (
                native,
                Resource {
                    ordinal: id,
                    selector,
                    depths,
                    any_format: (id, selector) == (32514, 1),
                },
            )
        })
        .collect();

    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut thread, entry) = setup(arch);
        let p = process.state_mut();
        let index = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.win32u_services = Some((
            index,
            named_table(arch, "NtUserFindExistingCursorIcon", SERVICE),
        ));
        let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
            unreachable!();
        };
        let local = Catalog::new(catalog.values().copied().collect());
        let handles: BTreeMap<_, _> = catalog
            .iter()
            .map(|(&native, entry)| {
                (
                    native,
                    local.find(Some(entry.ordinal), entry.selector, [0; 3], None),
                )
            })
            .collect();
        let by_id: BTreeMap<_, _> = catalog
            .iter()
            .map(|(&native, entry)| ((u32::from(entry.ordinal), entry.selector), handles[&native]))
            .collect();
        Arc::get_mut(inputs).unwrap().cursor_icons = Ok(local);
        p.registry = Registry::selected(
            (0..=u16::MAX)
                .map(|unit| {
                    if (97..=122).contains(&unit) {
                        unit - 32
                    } else {
                        unit
                    }
                })
                .collect(),
            vec![],
        )
        .unwrap();

        let dispatch = super::super::super::super::super::services::dispatch;
        let error = thread.teb + offsets(arch).teb_last_error;
        let status = thread.teb + offsets(arch).teb_last_status;
        let resume = entry + 0x4000;
        let slots = [entry + 0x5020, entry + 0x5060, entry + 0x50a0];
        let text = entry + 0x5100;
        let wrong = entry + 0x5140;
        let page_end = entry + 0x7000;
        let unreadable = entry + 0x9000;
        p.vm.protect(unreadable, 4096, prot::NOACCESS).unwrap();
        p.space
            .put_wstr(text, &"usER32".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        p.space
            .put_wstr(wrong, &"missing".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let mut first = true;
        let mut performed = 0;
        for row in lookup.iter().chain(&boundaries) {
            let fields = row["label"].as_array().unwrap();
            let mut pointers = slots;
            let mut module = name(12, 14, text);
            let mut resource = name(0, 0, 32512);
            let mut words = [0, 0, 1, 0, 0, 0];
            let mut edge = None;
            match fields[0].as_str().unwrap() {
                "catalog" => {
                    resource = name(0, 0, u64::from(scalar(&fields[1])));
                    words[2] = scalar(&fields[2]);
                }
                "hint" | "wrong-module" => {
                    resource = name(0, 0, u64::from(scalar(&fields[1])));
                    words[2] = scalar(&fields[2]);
                    words[0] = if fields[3] == "absent" {
                        0xffff_1234
                    } else {
                        by_id[&(scalar(&fields[3]), scalar(&fields[4]))]
                    };
                    words[3..6].copy_from_slice(&[
                        scalar(&fields[5]),
                        scalar(&fields[6]),
                        scalar(&fields[7]),
                    ]);
                    if fields[0] == "wrong-module" {
                        module = name(14, 16, wrong);
                    }
                }
                "unaligned" => {
                    let slot = match fields[1].as_str().unwrap() {
                        "module" => 0,
                        "resource" => 1,
                        "request" => 2,
                        _ => unreachable!(),
                    };
                    pointers[slot] += u64::from(scalar(&fields[2]));
                }
                "module-shape" | "resource-shape" => {
                    let shaped = name(scalar(&fields[1]) as u16, scalar(&fields[2]) as u16, text);
                    if fields[0] == "module-shape" {
                        module = shaped;
                    } else {
                        resource = shaped;
                        words[0] = by_id[&(32512, 1)];
                    }
                }
                "arrow" => {}
                "selector" => {
                    words[2] = scalar(&fields[1]);
                    words[0] = handles.get(&scalar(&fields[2])).copied().unwrap_or(0);
                }
                "properties" => {
                    let id = scalar(&fields[1]);
                    let selector = scalar(&fields[2]);
                    if id > 32516 {
                        continue;
                    }
                    resource = name(0, 0, u64::from(id));
                    words[2] = selector;
                    words[3..6].copy_from_slice(&[
                        scalar(&fields[3]),
                        scalar(&fields[4]),
                        scalar(&fields[5]),
                    ]);
                }
                "order" => {
                    match fields[1].as_str().unwrap() {
                        "good" => {}
                        "bad-name" => resource = name(1, 2, text),
                        "bad-addr" => resource = name(2, 2, unreadable),
                        "bad-desc" => pointers[1] = 0,
                        _ => unreachable!(),
                    }
                    match fields[2].as_str().unwrap() {
                        "good" => {}
                        "null" => pointers[0] = 0,
                        "null-buf" => module = name(0, 0, 0),
                        "unmapped" => pointers[0] = unreadable,
                        "empty" => module = name(0, 0, text),
                        "odd" => module = name(1, 2, text),
                        _ => unreachable!(),
                    }
                    match fields[3].as_str().unwrap() {
                        "no-hint" => {}
                        "valid" => words[0] = by_id[&(32512, 1)],
                        "invalid" => words[0] = 0xffff_1234,
                        "null" => pointers[2] = 0,
                        _ => unreachable!(),
                    }
                }
                "boundary" => {
                    let slot = match fields[2].as_str().unwrap() {
                        "module" => 0,
                        "resource" => 1,
                        "request" => 2,
                        _ => unreachable!(),
                    };
                    let at = page_end - u64::from(scalar(&fields[3]));
                    pointers[slot] = at;
                    edge = Some(scalar(&fields[1]));
                }
                _ => unreachable!(),
            }
            for (at, bytes) in
                pointers
                    .into_iter()
                    .zip([&module[..], &resource[..], &request(words)[..]])
            {
                if at >= slots[0] && at < unreadable {
                    p.space.wr(at, bytes).unwrap();
                }
            }
            if let Some(protection) = edge {
                p.vm.protect(page_end, 4096, protection).unwrap();
            }
            p.space.w32(error, LAST_ERROR).unwrap();
            p.space.w32(status, LAST_STATUS).unwrap();
            arguments(p, &mut thread, pointers);
            thread.cpu.set_pc(resume);
            assert_eq!(
                dispatch(p, &mut thread, SERVICE, resume - 4),
                Some(Outcome::Continue),
                "{arch} {fields:?}"
            );
            if first {
                assert_eq!(
                    p.gui.threads[&thread.tid].callbacks[0].completion,
                    Completion::FindCursorIcon(pointers)
                );
                assert_eq!(thread.cpu.pc(), entry);
                arguments(p, &mut thread, [0, 0, 0]);
                assert_eq!(
                    dispatch(p, &mut thread, 5, entry + 0x100),
                    Some(Outcome::Continue)
                );
                assert_eq!(thread.cpu.pc(), resume);
                first = false;
            }
            let value = scalar(&row["value"]);
            let expected = if value == 0 { 0 } else { handles[&value] };
            assert_eq!(thread.cpu.gpr(0), u64::from(expected), "{arch} {fields:?}");
            assert_eq!(
                p.space.u32(error).unwrap(),
                scalar(&row["error"]),
                "{arch} {fields:?}"
            );
            assert_eq!(
                p.space.u32(status).unwrap(),
                scalar(&row["status"]),
                "{arch} {fields:?}"
            );
            if edge.is_some() {
                p.vm.protect(page_end, 4096, prot::EXECUTE_READWRITE)
                    .unwrap();
            }
            performed += 1;
        }
        assert_eq!(performed, lookup.len() + boundaries.len() - 216);
    }
}
