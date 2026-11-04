//! Native scalar transitions and fault effects through the actual service router.
use super::*;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{FileObj, Object, StdStream};
use serde_json::{Value, json};

#[cfg(windows)]
#[path = "file_state_set_tests/installed.rs"]
mod installed;
#[path = "file_state_set_tests/replay.rs"]
mod replay;
#[path = "file_state_set_tests/retained.rs"]
mod retained;

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtSetInformationFile", 0x27);
    let base = process
        .state_mut()
        .vm
        .allocate(
            None,
            6 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    (process, t, base)
}

fn call(p: &mut Proc, t: &mut Thread, name: &str, number: u32, args: &[u64]) -> u32 {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, number)));
    if p.arch == WinArch::Arm64 {
        super::nls_tests::arguments(p, t, &args[..args.len().min(8)]);
        for (index, value) in args.iter().enumerate().skip(8) {
            p.space
                .w64(t.cpu.sp() + (index - 8) as u64 * 8, *value)
                .unwrap();
        }
    } else {
        super::nls_tests::arguments(p, t, args);
    }
    if p.arch != WinArch::Arm64 {
        t.cpu.set_gpr(0, u64::from(number));
    }
    let sp = t.cpu.sp();
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, number))
    };
    assert_eq!(result, Outcome::Continue, "{} {name} {args:x?}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> u32 {
    call(p, t, "NtSetInformationFile", 0x27, args)
}

fn snapshot(p: &mut Proc, t: &mut Thread, handle: u64, base: u64) -> Value {
    let mut rows = Vec::new();
    for (class, length) in [(14, 8), (16, 4), (41, 4), (43, 4)] {
        p.space.wr(base, &[0xA5; 64]).unwrap();
        let status = call(
            p,
            t,
            "NtQueryInformationFile",
            0x11,
            &[handle, base, base + 32, length, class],
        );
        rows.push(json!([
            status,
            hex(&p.space.bytes(base + 32, length as usize).unwrap())
        ]));
    }
    Value::Array(rows)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(encoded: &str) -> Vec<u8> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

struct Resource {
    handle: u64,
    parent: Option<u64>,
    independent: Option<u64>,
    owned: Vec<u64>,
}

fn resource(p: &mut Proc, role: &str) -> Resource {
    let mut r = Resource {
        handle: 0,
        parent: None,
        independent: None,
        owned: Vec::new(),
    };
    let mut insert = |object, grant| {
        let id = p.objects.create(object);
        let h = u64::from(p.objects.open_access(id, false, grant).unwrap());
        r.owned.push(h);
        h
    };
    r.handle = match role {
        "invalid" => 0x1234,
        "process.pseudo" => p.arch.ptr(u64::MAX),
        "thread.pseudo" => p.arch.ptr(u64::MAX - 1),
        "event" => insert(
            Object::Event {
                manual: true,
                signaled: 0,
            },
            u32::MAX,
        ),
        "null.rw" => insert(Object::Null, 0x12019f),
        "console.in" => insert(Object::Console(StdStream::In), 0x12019f),
        "console.out" => insert(Object::Console(StdStream::Out), 0x12019f),
        "pipe.read" => insert(
            Object::Pipe {
                pipe: 1,
                write: false,
            },
            0x120189,
        ),
        "pipe.write" => insert(
            Object::Pipe {
                pipe: 1,
                write: true,
            },
            0x120196,
        ),
        _ => {
            drop(insert);
            let file = |overlapped, directory| {
                Object::File(FileObj {
                    host: None,
                    host_path: std::path::PathBuf::new(),
                    path: "C:\\state-control.bin".into(),
                    access: 0x12019f,
                    share: 7,
                    lifetime: Arc::new(FileLifetime::new(FileIdentity::Path(
                        std::path::PathBuf::new(),
                    ))),
                    null: false,
                    append: false,
                    delete_on_close: false,
                    directory,
                    overlapped,
                })
            };
            let id = p.objects.create(file(false, role == "directory.read"));
            let parent = u64::from(p.objects.open_access(id, false, 0x12019f).unwrap());
            r.owned.push(parent);
            if role != "directory.read" {
                r.parent = Some(parent);
                p.objects.file_state_mut(parent).unwrap().position = 7;
            }
            let handle = if matches!(role, "file.sync.rw" | "directory.read") {
                parent
            } else if role == "file.duplicate.attributes" {
                let h = u64::from(p.objects.open_access(id, false, 0x80).unwrap());
                r.owned.push(h);
                h
            } else {
                let asynchronous = matches!(role, "file.async.rw" | "file.async.attributes");
                let id = p.objects.create(file(asynchronous, false));
                let grant = if matches!(role, "file.sync.attributes" | "file.async.attributes") {
                    0x80
                } else if role == "file.sync.read" {
                    0x120089
                } else {
                    0x12019f
                };
                let h = u64::from(p.objects.open_access(id, false, grant).unwrap());
                r.owned.push(h);
                let mode = match role {
                    "file.no-buffering" => 0x28,
                    "file.write-through" => 0x22,
                    "file.sequential" => 0x24,
                    _ => {
                        if asynchronous {
                            0
                        } else {
                            0x20
                        }
                    }
                };
                p.objects.set_file_mode(id, mode);
                h
            };
            if role != "directory.read" {
                let id = p.objects.create(file(false, false));
                let h = u64::from(p.objects.open_access(id, false, 0x12019f).unwrap());
                r.owned.push(h);
                r.independent = Some(h);
            }
            handle
        }
    };
    r
}

fn release(p: &mut Proc, resource: Resource) {
    for h in resource.owned {
        p.objects.close(h).unwrap();
    }
}
