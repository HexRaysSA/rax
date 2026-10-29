//! Replay independent native input and write-order observations.
use super::*;
use serde_json::Value as Json;

pub(super) fn number(row: &Json, field: &str) -> u64 {
    row[field].as_u64().unwrap()
}

pub(super) fn corpus() -> Json {
    let text = std::env::var_os("RAX_KEY_NOTIFY_CORPUS")
        .map(|path| std::fs::read_to_string(path).unwrap())
        .unwrap_or_else(|| {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-key-notify/controls-v1.json"
            ))
            .to_owned()
        });
    let result: Json = serde_json::from_str(&text).unwrap();
    assert_eq!(result["schema"], "rax-native-key-notify-v1");
    assert_eq!(result["state"], "complete");
    result
}

pub(super) fn rows<'a>(corpus: &'a Json, report: &Json, kind: &str) -> &'a Vec<Json> {
    let identity = report["datasets"][kind].as_str().unwrap();
    corpus["datasets"][identity]["rows"].as_array().unwrap()
}

pub(super) fn architecture(report: &Json) -> WinArch {
    match report["architecture"].as_str().unwrap() {
        "arm64" => WinArch::Arm64,
        "x64" => WinArch::X64,
        "x86" => WinArch::X86,
        _ => panic!("unknown native process ABI"),
    }
}

pub(super) fn bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub(super) fn body(p: &mut Proc) -> u64 {
    let key = p
        .registry
        .key(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    let id = p.objects.create_registry_key(key, 0).unwrap();
    p.objects.open_access(id, false, 0x20019).unwrap().into()
}

pub(super) fn event(p: &mut Proc) -> u64 {
    let id = p.objects.create(Object::Event {
        manual: true,
        signaled: 1,
    });
    p.objects.open_access(id, false, 0x1f0003).unwrap().into()
}

pub(super) fn signal(p: &Proc, handle: u64) -> u64 {
    match p.objects.get(handle).unwrap() {
        Object::Event { signaled, .. } => {
            if *signaled == 0 {
                258
            } else {
                0
            }
        }
        _ => panic!("event observer"),
    }
}

#[test]
fn native_notify_key_replays_input_probe_order_flags_grants_and_async_admission_all_abis() {
    let data = corpus();
    let mut count = 0;
    for report in data["reports"].as_array().unwrap() {
        let arch = architecture(report);
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let original_handles = p.objects.handle_count();
        let original_objects = p.objects.iter().count();
        for kind in ["admission", "flags"] {
            for row in rows(&data, report, kind) {
                p.vm.protect(base, PAGE_SIZE * 2, prot::READWRITE).unwrap();
                p.space
                    .wr(base, &vec![0xcc; PAGE_SIZE as usize * 2])
                    .unwrap();
                let key = body(p);
                let event = event(p);
                let key_kind = number(row, "key_kind");
                let event_kind = number(row, "event_kind");
                let restricted_key = if matches!(key_kind, 4 | 5) {
                    Some(u64::from(
                        p.objects
                            .open_access(
                                p.objects.id(key).unwrap(),
                                false,
                                if key_kind == 4 { 1 } else { 0x10 },
                            )
                            .unwrap(),
                    ))
                } else {
                    None
                };
                let restricted_event = if matches!(event_kind, 4 | 5) {
                    Some(u64::from(
                        p.objects
                            .open_access(
                                p.objects.id(event).unwrap(),
                                false,
                                if event_kind == 4 { 2 } else { 0x100000 },
                            )
                            .unwrap(),
                    ))
                } else {
                    None
                };
                let key_argument = match key_kind {
                    0 => key,
                    1 => 0,
                    2 => 0x12345678,
                    3 => event,
                    4 | 5 => restricted_key.unwrap(),
                    6 => arch.ptr(u64::MAX),
                    7 => arch.ptr(u64::MAX - 1),
                    _ => panic!("key kind"),
                };
                let event_argument = match event_kind {
                    0 => 0,
                    1 => event,
                    2 => 0x12345678,
                    3 => key,
                    4 | 5 => restricted_event.unwrap(),
                    6 => arch.ptr(u64::MAX),
                    7 => arch.ptr(u64::MAX - 1),
                    _ => panic!("event kind"),
                };
                let memory = number(row, "memory_kind");
                let io = match memory {
                    0 | 3 | 4 | 6 => base,
                    1 => 0,
                    2 => base + 1,
                    5 => base + PAGE_SIZE - arch.ptr_size(),
                    7 => 0x123,
                    8..=15 => base + memory - 8,
                    _ => panic!("memory case"),
                };
                match memory {
                    3 => {
                        p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
                    }
                    4 => {
                        p.vm.protect(base, PAGE_SIZE, prot::NOACCESS).unwrap();
                    }
                    5 => {
                        p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                            .unwrap();
                    }
                    6 => {
                        p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    _ => {}
                }
                let buffer_kind = number(row, "buffer_kind");
                let buffer = match buffer_kind {
                    1 => base + 6000,
                    2 => 1,
                    _ => 0,
                };
                let length = match buffer_kind {
                    0 => 0,
                    3 => 0xffff_ffff,
                    _ => 1,
                };
                let apc = if number(row, "apc") == 0 { 0 } else { 0x50000 };
                let status = call(
                    p,
                    &mut t,
                    "NtNotifyChangeKey",
                    &[
                        key_argument,
                        event_argument,
                        apc,
                        0,
                        io,
                        number(row, "filter"),
                        0,
                        buffer,
                        length,
                        1,
                    ],
                );
                assert_eq!(
                    u64::from(status),
                    number(row, "status"),
                    "{arch:?} {kind} {row}"
                );
                p.vm.protect(base, PAGE_SIZE * 2, prot::READWRITE).unwrap();
                assert_eq!(
                    p.space.bytes(base, arch.ptr_size() as usize * 2).unwrap(),
                    bytes(row["iosb_armed"].as_str().unwrap()),
                    "{arch:?} {kind} {row}"
                );
                assert_eq!(signal(p, event), number(row, "event_armed"), "{row}");
                if let Some(handle) = restricted_key {
                    assert_eq!(call(p, &mut t, "NtClose", &[handle]), 0);
                }
                assert_eq!(call(p, &mut t, "NtClose", &[key]), 0);
                assert_eq!(signal(p, event), number(row, "event_final"), "{row}");
                assert_eq!(
                    p.space.bytes(base, arch.ptr_size() as usize * 2).unwrap(),
                    bytes(row["iosb_final"].as_str().unwrap()),
                    "{arch:?} {kind} {row}"
                );
                // The native producer leaves APCs undelivered until process
                // exit; retire this isolated row before reusing its storage.
                crate::user::windows::process::registry_notify::retire_thread(p, &mut t).unwrap();
                if let Some(handle) = restricted_event {
                    assert_eq!(call(p, &mut t, "NtClose", &[handle]), 0);
                }
                assert_eq!(call(p, &mut t, "NtClose", &[event]), 0);
                assert_eq!(p.objects.handle_count(), original_handles);
                assert_eq!(
                    p.objects.iter().count(),
                    original_objects,
                    "retained completion leak"
                );
                count += 1;
            }
        }
    }
    assert_eq!(
        count,
        data["reports"].as_array().unwrap().len() * (184 + 208)
    );
}
