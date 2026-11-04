//! Independent native directory-event observations exercised through public HLE contexts.
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rax::user::windows::dll;
use rax::user::windows::fs::DriveMap;
use rax::user::windows::hle::{Api, Ctx, Flow, Item, Value};
use rax::user::windows::memory::Mem;
use rax::user::windows::objects::Object;
use rax::user::windows::process::{Proc, Thread};
use rax::user::windows::{WinArch, WindowsConfig, WindowsProcess};

const PAGE_BYTES: u64 = 4096;
const RESERVE_COMMIT: u32 = 0x3000;
const READ_WRITE: u32 = 4;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "rax-directory-event-profile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("alpha.txt"), b"owned fixture").unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn export(name: &str, arch: WinArch) -> &'static Api {
    dll::find("ntdll.dll")
        .unwrap()
        .exports
        .iter()
        .flat_map(|table| table.iter())
        .find_map(|export| match &export.item {
            Item::Func(api) if export.name == name && export.archs.has(arch) => Some(api),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} for {arch}"))
}

fn invoke(p: &mut Proc, thread: &mut Thread, stack: u64, name: &str, args: &[u64]) -> u64 {
    let api = export(name, p.arch);
    assert_eq!(api.args.len(), args.len());
    thread.cpu.set_sp(stack);
    for (index, &argument) in args.iter().enumerate() {
        match p.arch {
            WinArch::Arm64 if index < 8 => thread.cpu.set_gpr(index, argument),
            WinArch::Arm64 => p
                .space
                .w64(stack + (index - 8) as u64 * 8, argument)
                .unwrap(),
            WinArch::X64 if index < 4 => thread.cpu.set_gpr([1, 2, 8, 9][index], argument),
            WinArch::X64 => p.space.w64(stack + 8 + index as u64 * 8, argument).unwrap(),
            WinArch::X86 => p
                .space
                .w32(stack + 4 + index as u64 * 4, argument as u32)
                .unwrap(),
        }
    }
    let mut context = Ctx {
        p,
        t: thread,
        api,
        entry_pc: 0x1234_0000,
        entry_sp: stack,
        ret_addr: 0x1234_0004,
        cursor: stack,
    };
    match (api.imp)(&mut context).unwrap() {
        Flow::Ret(Value::Int(value)) => value,
        _ => panic!("{name} did not return synchronously"),
    }
}

fn unicode(p: &Proc, at: u64, buffer: u64, value: &str) {
    let bytes: Vec<_> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    p.space.wr(at, &[0; 16]).unwrap();
    p.space.w16(at, bytes.len() as u16).unwrap();
    p.space.w16(at + 2, bytes.len() as u16).unwrap();
    p.space
        .wptr(at + p.arch.ptr_size(), p.arch.ptr_size(), buffer)
        .unwrap();
    p.space.wr(buffer, &bytes).unwrap();
}

fn image(arch: WinArch) -> &'static [u8] {
    match arch {
        WinArch::X86 => include_bytes!("../../../fixtures/user/windows/bin/x86/smoke.exe"),
        WinArch::X64 => include_bytes!("../../../fixtures/user/windows/bin/x64/smoke.exe"),
        WinArch::Arm64 => include_bytes!("../../../fixtures/user/windows/bin/arm64/smoke.exe"),
    }
}

#[test]
fn directory_events_match_native_profiles_for_all_guest_abis() {
    let profiles = [
        include_str!(
            "../../../../docs/specifications/windows/native-directory-enumeration/event-arm64-v1.json"
        ),
        include_str!(
            "../../../../docs/specifications/windows/native-directory-enumeration/event-x64-v1.json"
        ),
    ];
    let mut calls = 0;
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        let root = Directory::new();
        let mut config =
            WindowsConfig::embedded(r"C:\profile.exe", Vec::new(), Vec::new(), 4096).unwrap();
        config.host_filesystem = true;
        config.arena_bytes = 64 << 20;
        config.drives = DriveMap::empty();
        config.drives.set('C', root.0.clone());
        let mut process = WindowsProcess::spawn_image(config, image(arch).to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let base =
            p.vm.allocate(None, 4 * PAGE_BYTES, RESERVE_COMMIT, READ_WRITE)
                .unwrap()
                .0;
        let stack = base + 3 * PAGE_BYTES;
        for text in profiles {
            let profile: serde_json::Value = serde_json::from_str(text).unwrap();
            let rows = profile["rows"].as_array().unwrap();
            assert_eq!(rows.len(), 12);
            for row in rows {
                let legacy = row["legacy"].as_bool().unwrap();
                let initial = row["initial"].as_bool().unwrap();
                let case = row["case"].as_str().unwrap();
                let expected = row["returned"].as_u64().unwrap();
                let pointer_bytes = p.arch.ptr_size();
                let attributes = base + 0x80;
                let path = base + 0x200;
                unicode(p, path, base + 0x240, r"\??\C:\");
                p.space.wr(attributes, &[0; 48]).unwrap();
                p.space
                    .w32(attributes, if pointer_bytes == 4 { 24 } else { 48 })
                    .unwrap();
                p.space
                    .wptr(attributes + 2 * pointer_bytes, pointer_bytes, path)
                    .unwrap();
                p.space.w32(attributes + 3 * pointer_bytes, 0x40).unwrap();
                assert_eq!(
                    invoke(
                        p,
                        &mut thread,
                        stack,
                        "NtOpenFile",
                        &[base, 0x100001, attributes, base + 0x40, 7, 0x21]
                    ),
                    0
                );
                let file = p.space.ptr(base, pointer_bytes).unwrap();
                assert_eq!(
                    invoke(
                        p,
                        &mut thread,
                        stack,
                        "NtCreateEvent",
                        &[base + 0x20, 0x1f0003, 0, 0, u64::from(initial)]
                    ),
                    0
                );
                let event = p.space.ptr(base + 0x20, pointer_bytes).unwrap();
                let pattern = base + 0x300;
                unicode(
                    p,
                    pattern,
                    base + 0x340,
                    if case == "missing" {
                        "absent.bin"
                    } else {
                        "alpha.txt"
                    },
                );
                let io = base + PAGE_BYTES;
                let output = base + 0x800;
                let length = if case == "overflow" { 96 } else { 616 };
                p.space.wr(io, &[0xa5; 16]).unwrap();
                p.space.wr(output, &[0xa5; 616]).unwrap();
                let mut args = vec![
                    file,
                    event,
                    0,
                    0,
                    io,
                    output,
                    length,
                    3,
                    if legacy { 1 } else { 2 },
                    pattern,
                ];
                if legacy {
                    args.push(0);
                }
                let name = if legacy {
                    "NtQueryDirectoryFile"
                } else {
                    "NtQueryDirectoryFileEx"
                };
                assert_eq!(
                    invoke(p, &mut thread, stack, name, &args),
                    expected,
                    "{arch}/{case}/{initial}/{legacy}"
                );
                match p.objects.get(event).unwrap() {
                    Object::Event { signaled, .. } => {
                        assert_eq!(
                            *signaled != 0,
                            row["event_signaled"].as_bool().unwrap(),
                            "{arch}/{case}/initial={initial}/legacy={legacy}: IOSB={:?}; expected={row}",
                            p.space.bytes(io, 16).unwrap()
                        )
                    }
                    _ => panic!("directory query changed the event object type"),
                }
                assert_eq!(
                    u64::from(p.space.u32(io).unwrap()),
                    row["io_status"].as_u64().unwrap() & 0xffff_ffff
                );
                if pointer_bytes == 8 {
                    assert_eq!(p.space.u32(io + 4).unwrap(), 0xa5a5_a5a5);
                }
                let information = row["information"].as_u64().unwrap();
                let projected = if pointer_bytes == 4 {
                    u64::from(information as u32)
                } else {
                    information
                };
                assert_eq!(
                    p.space.ptr(io + pointer_bytes, pointer_bytes).unwrap(),
                    projected
                );
                if case == "missing" {
                    assert_eq!(p.space.bytes(io, 16).unwrap(), [0xa5; 16]);
                    assert_eq!(p.space.bytes(output, 616).unwrap(), [0xa5; 616]);
                } else {
                    assert!(information <= length);
                    assert_eq!(
                        p.space
                            .bytes(output + information, 616 - information as usize)
                            .unwrap(),
                        vec![0xa5; 616 - information as usize]
                    );
                }
                assert_eq!(invoke(p, &mut thread, stack, "NtClose", &[file]), 0);
                assert_eq!(invoke(p, &mut thread, stack, "NtClose", &[event]), 0);
                calls += 1;
            }
        }
    }
    assert_eq!(calls, 72);
}
