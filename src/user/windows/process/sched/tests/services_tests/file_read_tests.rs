//! Documented read semantics through actual NT service dispatch on every guest ABI.
use super::*;
use crate::user::console::{CapturedConsole, Console};
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{FileObj, Object, StdStream};
use std::io::{Seek, SeekFrom, Write};

#[cfg(windows)]
#[path = "file_read_tests/installed.rs"]
mod installed;

#[path = "file_read_tests/replay.rs"]
mod replay;

fn call(p: &mut Proc, t: &mut Thread, args: &[u64]) -> u32 {
    service(p, t, "NtReadFile", 6, args)
}

fn service(p: &mut Proc, t: &mut Thread, name: &str, number: u32, args: &[u64]) -> u32 {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, number)));
    super::nls_tests::arguments(p, t, &args[..args.len().min(8)]);
    if p.arch == WinArch::Arm64 {
        for (index, arg) in args.iter().enumerate().skip(8) {
            p.space
                .w64(t.cpu.sp() + (index - 8) as u64 * 8, *arg)
                .unwrap();
        }
    } else {
        super::nls_tests::arguments(p, t, args);
        t.cpu.set_gpr(0, u64::from(number));
    }
    let sp = t.cpu.sp();
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, number))
    };
    assert_eq!(outcome, Outcome::Continue, "{}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

fn pages(p: &mut Proc) -> u64 {
    p.vm.allocate(
        None,
        2 * PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap()
    .0
}

#[test]
fn nt_read_file_console_null_permissions_and_ninth_argument() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        let (mut process, mut t) = fixture(arch, "NtReadFile", 6);
        let p = process.state_mut();
        let base = pages(p);
        let console = CapturedConsole::new(b"abc".to_vec(), 32).unwrap();
        Arc::make_mut(&mut p.cfg).console = Console::Captured(console.clone());
        let input = u64::from(p.objects.insert(Object::Console(StdStream::In)));
        let null = u64::from(p.objects.insert(Object::Null));
        let output = u64::from(p.objects.insert(Object::Console(StdStream::Out)));
        let event = u64::from(p.objects.insert(Object::Event {
            manual: true,
            signaled: 0,
        }));
        let last = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        p.space.w32(last, 0x6a1b_2c3d).unwrap();
        p.space.wr(base, &[0xa5; 256]).unwrap();
        let args = [input, event, 0, 0, base, base + 64, 2, 0, 0];
        assert_eq!(call(p, &mut t, &args), STATUS_SUCCESS);
        assert_eq!(p.space.bytes(base + 64, 4).unwrap(), b"ab\xa5\xa5");
        assert_eq!(
            p.space
                .ptr(base + arch.ptr_size(), arch.ptr_size())
                .unwrap(),
            2
        );
        assert!(matches!(
            p.objects.get(event),
            Some(Object::Event { signaled: 1, .. })
        ));
        assert_eq!(console.pending().unwrap().0, 1);
        assert_eq!(p.space.u32(last).unwrap(), 0x6a1b_2c3d);
        assert_eq!(
            call(p, &mut t, &[input, 0, 0, 0, base, base + 64, 0, 0, 0]),
            0xc007_0023
        );
        assert_eq!(
            call(p, &mut t, &[null, 0, 0, 0, base, base + 64, 0, 0, 0]),
            STATUS_END_OF_FILE
        );
        assert_eq!(
            call(p, &mut t, &[output, 0, 0, 0, base, base + 64, 1, 0, 0]),
            0xc007_0006
        );
        // The installed nine-slot ABI reaches the key argument on the stack.
        assert_eq!(
            call(p, &mut t, &[input, 0, 0, 0, base, base + 64, 1, 0, 1]),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(console.pending().unwrap().0, 1);
        assert_eq!(
            call(p, &mut t, &[0x1234, 0, 0, 0, 0, 0, 1, 0, 0]),
            STATUS_INVALID_HANDLE
        );
    }
}

#[test]
fn nt_read_file_retained_bytes_shared_cursor_partial_eof_and_independent_open() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        let root =
            std::env::temp_dir().join(format!("rax-native-read-{}-{arch}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("input.bin");
        let mut seed = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        seed.write_all(b"abcdefgh").unwrap();
        drop(seed);
        let (mut process, mut t) = fixture(arch, "NtReadFile", 6);
        let p = process.state_mut();
        let base = pages(p);
        let make = || {
            let host = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
            let identity =
                FileIdentity::of_open(&path, Some(&host), &host.metadata().unwrap()).unwrap();
            Object::File(FileObj {
                host: Some(host),
                host_path: path.clone(),
                path: "C:\\input.bin".into(),
                access: 0x120089,
                share: 7,
                lifetime: Arc::new(FileLifetime::new(identity)),
                null: false,
                append: false,
                delete_on_close: false,
                directory: false,
                overlapped: false,
            })
        };
        let id = p.objects.create(make());
        let first = u64::from(p.objects.open_access(id, false, 0x120089).unwrap());
        let duplicate = u64::from(p.objects.open_access(id, false, 1).unwrap());
        let independent = u64::from(p.objects.insert(make()));
        let denied = u64::from(p.objects.open_access(id, false, 0x80).unwrap());
        p.space.wr(base, &[0xa5; 256]).unwrap();
        assert_eq!(
            call(p, &mut t, &[first, 0, 0, 0, base, base + 64, 3, 0, 0]),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.bytes(base + 64, 3).unwrap(), b"abc");
        assert_eq!(
            call(p, &mut t, &[duplicate, 0, 0, 0, base, base + 64, 16, 0, 0]),
            STATUS_SUCCESS
        );
        assert_eq!(
            p.space
                .ptr(base + arch.ptr_size(), arch.ptr_size())
                .unwrap(),
            5
        );
        assert_eq!(p.space.bytes(base + 64, 5).unwrap(), b"defgh");
        assert_eq!(
            call(p, &mut t, &[first, 0, 0, 0, base, base + 64, 1, 0, 0]),
            STATUS_END_OF_FILE
        );
        assert_eq!(
            call(p, &mut t, &[independent, 0, 0, 0, base, base + 64, 1, 0, 0]),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.bytes(base + 64, 1).unwrap(), b"a");
        assert_eq!(
            call(p, &mut t, &[denied, 0, 0, 0, base, base + 64, 1, 0, 0]),
            STATUS_ACCESS_DENIED
        );
        p.space.w64(base + 128, 2).unwrap();
        assert_eq!(
            call(
                p,
                &mut t,
                &[first, 0, 0, 0, base, base + 64, 2, base + 128, 0]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.bytes(base + 64, 2).unwrap(), b"cd");
        let Some(Object::File(file)) = p.objects.get_mut(duplicate) else {
            panic!()
        };
        assert_eq!(
            file.host
                .as_mut()
                .unwrap()
                .seek(SeekFrom::Current(0))
                .unwrap(),
            4
        );
        drop(process);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
