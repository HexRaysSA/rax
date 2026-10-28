//! Execute NtWriteFile through service dispatch against frozen native results.
use super::*;
use crate::user::console::{CapturedConsole, Console, OutputStream};
use crate::user::windows::objects::{Object, StdStream};

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> u32 {
    super::nls_tests::arguments(p, t, &args[..args.len().min(8)]);
    if p.arch == WinArch::Arm64 {
        for (index, value) in args.iter().enumerate().skip(8) {
            p.space
                .w64(t.cpu.sp() + (index - 8) as u64 * 8, *value)
                .unwrap();
        }
    } else {
        super::nls_tests::arguments(p, t, args);
        t.cpu.set_gpr(0, 0x18);
    }
    let sp = t.cpu.sp();
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x18))
    };
    assert_eq!(result, Outcome::Continue, "{}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.gpr(0) as u32
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn nt_write_file_replays_native_pipe_status_publication_and_wow64_side_effects() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-file-write/observations-v3.json"
    )))
    .unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 54);
    for row in cases {
        let arch = match row["arch"].as_str().unwrap() {
            "x86" => WinArch::X86,
            "x64" => WinArch::X64,
            "arm64" => WinArch::Arm64,
            other => panic!("unknown captured architecture {other}"),
        };
        let which = row["case"].as_u64().unwrap();
        let (mut process, mut thread) = fixture(arch, "NtWriteFile", 0x18);
        let p = process.state_mut();
        let base =
            p.vm.allocate(
                None,
                6 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        p.space
            .wr(base, &vec![0xCC; 6 * PAGE_SIZE as usize])
            .unwrap();
        let console = CapturedConsole::new(Vec::new(), 64).unwrap();
        Arc::make_mut(&mut p.cfg).console = Console::Captured(console.clone());
        let mut handle = u64::from(p.objects.insert(Object::Console(StdStream::Out)));
        let (mut event, mut io, mut buffer, mut length, mut offset, mut key) =
            (0, base, base + 3 * PAGE_SIZE, 2, 0, 0);
        p.space.wr(buffer, b"XY").unwrap();
        match which {
            0 => {}
            1 => io = 0,
            2 => handle = 0x1234,
            3 => buffer = 0,
            4 => {
                buffer = 0;
                length = 0;
            }
            5 => {
                handle = 0x1234;
                buffer = 0;
            }
            6 => {
                io = 0;
                handle = 0x1234;
            }
            7 => event = 0x1234,
            8 => {
                event = 0x1234;
                buffer = 0;
            }
            9 => offset = 1,
            10 => key = 1,
            11 => io = 1,
            12 => {
                io = base + PAGE_SIZE - arch.ptr_size();
                p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
            }
            13 => io = base + 33,
            14 => {
                handle = 0x1234;
                offset = 1;
            }
            15 => {
                handle = 0x1234;
                key = 1;
            }
            16 => {
                handle = 0x1234;
                event = 0x1234;
                offset = 1;
            }
            17 => {
                event = 0x1234;
                io = 0;
            }
            _ => panic!("unknown native case {which}"),
        }
        let last_error = thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0x1234_5678).unwrap();
        let status = invoke(
            p,
            &mut thread,
            &[handle, event, 0, 0, io, buffer, length, offset, key],
        );
        let expected = row["stderr"].as_str().unwrap().trim();
        let actual_io = hex(&p.space.bytes(base, 2 * arch.ptr_size() as usize).unwrap());
        let prefix = match which {
            12 => hex(&p
                .space
                .bytes(base + PAGE_SIZE - arch.ptr_size(), arch.ptr_size() as usize)
                .unwrap()),
            13 => hex(&p
                .space
                .bytes(base + 32, 2 * arch.ptr_size() as usize + 2)
                .unwrap()),
            _ => String::new(),
        };
        assert_eq!(
            format!("status={status:08x};iosb={actual_io};prefix={prefix}"),
            expected,
            "{arch} case {which}"
        );
        let mut bytes = [0; 64];
        let count = console.drain(OutputStream::Stdout, &mut bytes).unwrap();
        assert_eq!(
            hex(&bytes[..count]),
            row["stdout_hex"].as_str().unwrap(),
            "{arch} case {which}"
        );
        assert_eq!(
            p.space.u32(last_error).unwrap(),
            0x1234_5678,
            "{arch} case {which}"
        );
    }
}

#[test]
fn nt_write_file_owned_file_offsets_append_grants_and_completion_event() {
    use crate::user::windows::fs::{FileIdentity, FileLifetime};
    use crate::user::windows::objects::FileObj;
    for arch in WinArch::ALL {
        let path = std::env::temp_dir().join(format!(
            "rax-native-write-{}-{arch}.bin",
            std::process::id()
        ));
        let host = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let identity =
            FileIdentity::of_open(&path, Some(&host), &host.metadata().unwrap()).unwrap();
        let (mut process, mut thread) = fixture(arch, "NtWriteFile", 0x18);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let object = p.objects.create(Object::File(FileObj {
            host: Some(host),
            host_path: path.clone(),
            path: "C:\\fixture.bin".into(),
            access: 6,
            share: 7,
            lifetime: Arc::new(FileLifetime::new(identity)),
            null: false,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        }));
        let write = u64::from(p.objects.open_access(object, false, 2).unwrap());
        let append = u64::from(p.objects.open_access(object, false, 4).unwrap());
        let denied = u64::from(p.objects.open_access(object, false, 0).unwrap());
        let event = u64::from(p.objects.insert(Object::Event {
            manual: true,
            signaled: 0,
        }));
        p.space.wr(base + 64, b"AB").unwrap();
        p.space.w64(base + 128, 2).unwrap();
        assert_eq!(
            invoke(
                p,
                &mut thread,
                &[write, event, 0, 0, base, base + 64, 2, base + 128, 0]
            ),
            0
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"\0\0AB");
        assert!(matches!(
            p.objects.get(event),
            Some(Object::Event { signaled: 1, .. })
        ));
        assert_eq!(
            p.space
                .ptr(base + arch.ptr_size(), arch.ptr_size())
                .unwrap(),
            2
        );
        p.space.w64(base + 128, 0).unwrap();
        assert_eq!(
            invoke(
                p,
                &mut thread,
                &[append, 0, 0, 0, base, base + 64, 2, base + 128, 0]
            ),
            0
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"\0\0ABAB");
        assert_eq!(
            invoke(p, &mut thread, &[denied, 0, 0, 0, base, base + 64, 2, 0, 0]),
            crate::user::windows::nt::status::STATUS_ACCESS_DENIED
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"\0\0ABAB");
        drop(process);
        std::fs::remove_file(path).unwrap();
    }
}
