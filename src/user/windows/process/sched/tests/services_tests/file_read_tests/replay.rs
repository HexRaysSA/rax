use super::*;
use serde_json::{Value, json};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn snapshot(p: &mut Proc, t: &mut Thread, h: u64, base: u64) -> Value {
    p.space.wr(base + 512, &[0xa5; 96]).unwrap();
    let code = service(
        p,
        t,
        "NtQueryInformationFile",
        0x11,
        &[h, base + 512, base + 544, 8, 14],
    );
    json!([code, hex(&p.space.bytes(base + 544, 8).unwrap())])
}

struct Resource {
    handle: u64,
    parent: Option<u64>,
    independent: Option<u64>,
}

fn resource(p: &mut Proc, role: &str, root: &std::path::Path) -> Resource {
    let mut result = Resource {
        handle: 0,
        parent: None,
        independent: None,
    };
    let file_path = root.join("read.bin");
    if role.starts_with("file.") {
        let mut seed = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        seed.write_all(&[0x41, 0, 0x42, 0x7f, 0x80, 0xfe, 0xff, 0x5a])
            .unwrap();
        let mut original = if role == "file.sync.rw" {
            seed
        } else {
            drop(seed);
            std::fs::File::open(&file_path).unwrap()
        };
        if role != "file.sync.attributes" {
            original.seek(SeekFrom::Start(2)).unwrap();
        }
        let access = if role == "file.sync.rw" {
            0x12019f
        } else if role == "file.sync.attributes" {
            0x80
        } else {
            0x120089
        };
        let create = |host: std::fs::File| {
            let identity =
                FileIdentity::of_open(&file_path, Some(&host), &host.metadata().unwrap()).unwrap();
            Object::File(FileObj {
                host: Some(host),
                host_path: file_path.clone(),
                path: "C:\\read.bin".into(),
                access,
                share: 7,
                lifetime: Arc::new(FileLifetime::new(identity)),
                null: false,
                append: false,
                delete_on_close: false,
                directory: false,
                overlapped: false,
            })
        };
        let id = p.objects.create(create(original));
        let h = u64::from(p.objects.open_access(id, false, access).unwrap());
        if role == "file.sync.rw" {
            p.objects.note_file_io(h);
        }
        result.handle = if role == "file.duplicate.read" {
            result.parent = Some(h);
            u64::from(p.objects.open_access(id, false, 1).unwrap())
        } else {
            h
        };
        result.independent = Some(u64::from(
            p.objects
                .insert(create(std::fs::File::open(&file_path).unwrap())),
        ));
    } else {
        result.handle = match role {
            "invalid" => 0x1234,
            "process.pseudo" => p.arch.ptr(u64::MAX),
            "thread.pseudo" => p.arch.ptr(u64::MAX - 1),
            "event" => u64::from(p.objects.insert(Object::Event {
                manual: true,
                signaled: 0,
            })),
            "null.read" => u64::from(p.objects.insert(Object::Null)),
            "console.in" => u64::from(p.objects.insert(Object::Console(StdStream::In))),
            "console.out" => u64::from(p.objects.insert(Object::Console(StdStream::Out))),
            "pipe.write" => {
                let id = p.objects.create(Object::Pipe {
                    pipe: 1,
                    write: true,
                });
                u64::from(p.objects.open_access(id, false, 0x120196).unwrap())
            }
            "directory.read" => {
                let id = p.objects.create(Object::File(FileObj {
                    host: None,
                    host_path: root.into(),
                    path: "C:\\directory".into(),
                    access: 0x120089,
                    share: 7,
                    lifetime: Arc::new(FileLifetime::new(FileIdentity::Path(root.into()))),
                    null: false,
                    append: false,
                    delete_on_close: false,
                    directory: true,
                    overlapped: false,
                }));
                u64::from(p.objects.open_access(id, false, 0x120089).unwrap())
            }
            other => panic!("unselected native resource {other}"),
        };
    }
    result
}

fn fixture_with_resource(
    arch: WinArch,
    role: &str,
    index: usize,
) -> (
    super::super::super::super::super::WindowsProcess,
    Thread,
    u64,
    Resource,
    std::path::PathBuf,
) {
    let root = std::env::temp_dir().join(format!(
        "rax-read-replay-{}-{arch}-{index}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let (mut process, t) = fixture(arch, "NtReadFile", 6);
    let p = process.state_mut();
    let base = pages(p);
    Arc::make_mut(&mut p.cfg).console =
        Console::Captured(CapturedConsole::new(vec![b'R'; 16], 32).unwrap());
    let resource = resource(p, role, &root);
    (process, t, base, resource, root)
}

#[test]
fn nt_read_file_replays_native_scalar_and_cached_cursor_observations() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-file-read/observations-v1.json"
    )))
    .unwrap();
    assert_eq!(corpus["observations"], 1980);
    let mut scalar_count = 0;
    let mut transition_count = 0;
    for capture in corpus["captures"].as_array().unwrap() {
        let arch = match capture["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        let kind = capture["kind"].as_str().unwrap();
        let rows = capture["cases"].as_array().unwrap();
        if kind == "scalars" {
            assert_eq!(rows.len(), 540);
            for (index, row) in rows.iter().enumerate().filter(|(_, row)| {
                !matches!(
                    row["role"].as_str().unwrap(),
                    "file.async.read" | "pipe.read"
                )
            }) {
                let role = row["role"].as_str().unwrap();
                let (mut process, mut t, base, resource, root) =
                    fixture_with_resource(arch, role, index);
                let p = process.state_mut();
                p.space.wr(base, &[0xa5; 256]).unwrap();
                let event = u64::from(p.objects.insert(Object::Event {
                    manual: true,
                    signaled: 1,
                }));
                let offsets = [0, -3, -2, -1, 0, 2, 7, 8, 9];
                let which = row["offset_case"].as_u64().unwrap() as usize;
                let offset = if which == 0 {
                    0
                } else {
                    p.space.w64(base + 128, offsets[which] as u64).unwrap();
                    base + 128
                };
                let last = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
                p.space.w32(last, 0x6a1b_2c3d).unwrap();
                let code = call(
                    p,
                    &mut t,
                    &[
                        resource.handle,
                        event,
                        0,
                        0,
                        base,
                        base + 64,
                        row["length"].as_u64().unwrap(),
                        offset,
                        0,
                    ],
                );
                assert_eq!(json!(code), row["initial_status"], "{arch} {row}");
                assert_eq!(
                    hex(&p.space.bytes(base, 2 * arch.ptr_size() as usize).unwrap()),
                    row["io"].as_str().unwrap(),
                    "{arch} {row}"
                );
                assert_eq!(
                    hex(&p.space.bytes(base + 64, 32).unwrap()),
                    row["buffer"].as_str().unwrap(),
                    "{arch} {row}"
                );
                assert_eq!(p.space.u32(last).unwrap(), 0x6a1b_2c3d);
                let signaled = matches!(
                    p.objects.get(event),
                    Some(Object::Event { signaled: 1, .. })
                );
                assert_eq!(
                    if signaled { 0 } else { 258 },
                    row["event_wait"].as_u64().unwrap()
                );
                assert_eq!(
                    snapshot(p, &mut t, resource.handle, base),
                    row["position"],
                    "{arch} {row}"
                );
                if let Some(h) = resource.parent {
                    assert_eq!(snapshot(p, &mut t, h, base), row["parent_position"]);
                }
                if let Some(h) = resource.independent {
                    assert_eq!(snapshot(p, &mut t, h, base), row["independent_position"]);
                }
                drop(process);
                if role.starts_with("file.") {
                    std::fs::remove_file(root.join("read.bin")).unwrap();
                }
                std::fs::remove_dir(root).unwrap();
                scalar_count += 1;
            }
        } else {
            assert_eq!(kind, "transitions");
            assert_eq!(rows.len(), 120);
            for group in rows
                .chunks_exact(8)
                .filter(|g| g[0]["role"] != "file.async.read")
            {
                let role = group[0]["role"].as_str().unwrap();
                let sequence = group[0]["sequence"].as_u64().unwrap();
                let (mut process, mut t, base, resource, root) =
                    fixture_with_resource(arch, role, 1000 + transition_count);
                let p = process.state_mut();
                if sequence != 0 && role != "file.sync.attributes" {
                    p.space.w64(base + 128, 0).unwrap();
                    assert_eq!(
                        call(
                            p,
                            &mut t,
                            &[resource.handle, 0, 0, 0, base, base + 64, 1, base + 128, 0]
                        ),
                        STATUS_SUCCESS
                    );
                    let Some(Object::File(file)) = p.objects.get_mut(resource.handle) else {
                        panic!()
                    };
                    file.host
                        .as_mut()
                        .unwrap()
                        .seek(SeekFrom::Start(2))
                        .unwrap();
                }
                let positions = [-2, 0, 2, 8, 9, 7, -2, 9];
                for row in group {
                    p.space.wr(base, &[0xa5; 256]).unwrap();
                    let step = row["step"].as_u64().unwrap() as usize;
                    let offset = if step == 0 || step == 6 {
                        0
                    } else {
                        p.space.w64(base + 128, positions[step] as u64).unwrap();
                        base + 128
                    };
                    let code = call(
                        p,
                        &mut t,
                        &[
                            resource.handle,
                            0,
                            0,
                            0,
                            base,
                            base + 64,
                            row["length"].as_u64().unwrap(),
                            offset,
                            0,
                        ],
                    );
                    assert_eq!(json!(code), row["initial_status"], "{arch} {row}");
                    assert_eq!(
                        hex(&p.space.bytes(base, 2 * arch.ptr_size() as usize).unwrap()),
                        row["io"].as_str().unwrap(),
                        "{arch} {row}"
                    );
                    assert_eq!(
                        hex(&p.space.bytes(base + 64, 32).unwrap()),
                        row["buffer"].as_str().unwrap(),
                        "{arch} {row}"
                    );
                    assert_eq!(
                        snapshot(p, &mut t, resource.handle, base),
                        row["position"],
                        "{arch} {row}"
                    );
                    transition_count += 1;
                }
                drop(process);
                std::fs::remove_file(root.join("read.bin")).unwrap();
                std::fs::remove_dir(root).unwrap();
            }
        }
    }
    // Selection is explicit: the remaining288 observations describe pending
    // file and pipe capabilities, not a successful synchronous replay claim.
    assert_eq!(scalar_count, 1404);
    assert_eq!(transition_count, 288);
}
